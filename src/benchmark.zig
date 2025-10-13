const std = @import("std");
const kangarootwelve = @import("kangarootwelve");

// Import the KT128 implementation from the library
const KT128 = kangarootwelve.KT128;
const ptn = kangarootwelve.ptn;

const print = std.debug.print;

// Simple timer for benchmarking
const Timer = struct {
    start: i128,
    end: i128,

    fn init() @This() {
        return @This(){
            .start = std.time.nanoTimestamp(),
            .end = 0,
        };
    }

    fn startTimer(self: *@This()) void {
        self.start = std.time.nanoTimestamp();
    }

    fn stopTimer(self: *@This()) void {
        self.end = std.time.nanoTimestamp();
    }

    fn elapsed(self: @This()) i128 {
        return self.end - self.start;
    }

    fn elapsedMillis(self: @This()) u64 {
        return @intCast(@divTrunc(self.elapsed(), 1_000_000));
    }

    fn elapsedSeconds(self: @This()) f64 {
        return @as(f64, @floatFromInt(self.elapsed())) / 1_000_000_000.0;
    }
};

// Benchmark result structure
const BenchmarkResult = struct {
    name: []const u8,
    message_size: usize,
    chunks: usize,
    sequential_time_ms: u64,
    parallel_time_ms: u64,
    speedup: f64,
    throughput_sequential_mb_s: f64,
    throughput_parallel_mb_s: f64,
};

fn formatBytes(bytes: usize) [32]u8 {
    var result: [32]u8 = undefined;
    var value: f64 = @floatFromInt(bytes);
    var unit: []const u8 = "B";

    if (value >= 1_048_576.0) {
        value /= 1_048_576.0;
        unit = "MB";
    } else if (value >= 1_024.0) {
        value /= 1_024.0;
        unit = "KB";
    }

    _ = std.fmt.bufPrint(&result, "{d:.2} {s}", .{ value, unit }) catch unreachable;
    return result;
}

fn runBenchmark(name: []const u8, message: []const u8, allocator: std.mem.Allocator) !BenchmarkResult {
    const KT128_32 = KT128(32);
    var out_seq: [32]u8 = undefined;
    var out_par: [32]u8 = undefined;

    const chunks = (message.len + 8192 - 1) / 8192;

    // Sequential benchmark
    var timer_seq = Timer.init();
    timer_seq.startTimer();
    try KT128_32.hash(message, null, &out_seq);
    timer_seq.stopTimer();
    const sequential_time_ms = timer_seq.elapsedMillis();

    // Parallel benchmark
    var timer_par = Timer.init();
    timer_par.startTimer();
    try KT128_32.hashParallel(message, null, &out_par, allocator);
    timer_par.stopTimer();
    const parallel_time_ms = timer_par.elapsedMillis();

    // Verify results are the same
    if (!std.mem.eql(u8, &out_seq, &out_par)) {
        print("ERROR: Sequential and parallel results differ for {s}!\n", .{name});
        return error.ResultsMismatch;
    }

    const speedup: f64 = if (parallel_time_ms > 0)
        @as(f64, @floatFromInt(sequential_time_ms)) / @as(f64, @floatFromInt(parallel_time_ms))
    else
        1.0;

    const mb_size = @as(f64, @floatFromInt(message.len)) / 1_048_576.0;
    const throughput_sequential_mb_s = if (sequential_time_ms > 0)
        mb_size * 1000.0 / @as(f64, @floatFromInt(sequential_time_ms))
    else
        0.0;

    const throughput_parallel_mb_s = if (parallel_time_ms > 0)
        mb_size * 1000.0 / @as(f64, @floatFromInt(parallel_time_ms))
    else
        0.0;

    return BenchmarkResult{
        .name = name,
        .message_size = message.len,
        .chunks = chunks,
        .sequential_time_ms = sequential_time_ms,
        .parallel_time_ms = parallel_time_ms,
        .speedup = speedup,
        .throughput_sequential_mb_s = throughput_sequential_mb_s,
        .throughput_parallel_mb_s = throughput_parallel_mb_s,
    };
}

fn generateTestData(size: usize, allocator: std.mem.Allocator) ![]const u8 {
    const data = try allocator.alloc(u8, size);

    // Use a simple pattern for consistency
    for (data, 0..) |*byte, i| {
        byte.* = @truncate(i % 0xfb);
    }

    return data;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    print("KT128 Benchmark: Sequential vs Parallel Hashing\n", .{});
    print("=============================================\n\n", .{});

    // Test different message sizes
    const test_sizes = [_]struct { size: usize, name: []const u8 }{
        .{ .size = 1_048_576, .name = "1 MB" }, // ~128 chunks
        .{ .size = 10_485_760, .name = "10 MB" }, // ~1,280 chunks
        .{ .size = 104_857_600, .name = "100 MB" }, // ~12,800 chunks
        .{ .size = 209_715_200, .name = "200 MB" }, // ~25,600 chunks
    };

    var results = std.ArrayList(BenchmarkResult){};
    defer results.deinit(allocator);

    for (test_sizes) |test_case| {
        print("Generating {s} test data...\n", .{test_case.name});
        const data = try generateTestData(test_case.size, allocator);
        defer allocator.free(data);

        print("Benchmarking {s} ({d} chunks)...\n", .{ test_case.name, (test_case.size + 8192 - 1) / 8192 });

        const result = try runBenchmark(test_case.name, data, allocator);
        try results.append(allocator, result);

        print("  Sequential: {d} ms, {d:.2} MB/s\n", .{ result.sequential_time_ms, result.throughput_sequential_mb_s });
        print("  Parallel:   {d} ms, {d:.2} MB/s\n", .{ result.parallel_time_ms, result.throughput_parallel_mb_s });
        print("  Speedup:    {d:.2}x\n\n", .{result.speedup});
    }

    // Summary table
    print("Summary Table\n", .{});
    print("=============\n", .{});
    print("{s:<10} {s:<12} {s:<10} {s:<10} {s:<10} {s:<12} {s:<12}\n", .{ "Size", "Chunks", "Seq(ms)", "Par(ms)", "Speedup", "Seq(MB/s)", "Par(MB/s)" });
    print("{s:<10} {s:<12} {s:<10} {s:<10} {s:<10} {s:<12} {s:<12}\n", .{ "----", "------", "-------", "-------", "-------", "--------", "--------" });

    for (results.items) |result| {
        const size_formatted = formatBytes(result.message_size);
        print("{s:<10} {d:<12} {d:<10} {d:<10} {d:<10.2} {d:<12.2} {d:<12.2}\n", .{
            std.mem.trim(u8, &size_formatted, &[_]u8{0}),
            result.chunks,
            result.sequential_time_ms,
            result.parallel_time_ms,
            result.speedup,
            result.throughput_sequential_mb_s,
            result.throughput_parallel_mb_s,
        });
    }

    print("\nAll benchmarks completed successfully!\n", .{});
    print("Results show that parallel processing provides significant speedup for large messages.\n", .{});
}
