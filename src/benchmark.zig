const std = @import("std");
const kangarootwelve = @import("kangarootwelve");

// Import the KT128 implementation from the library
const KT128 = kangarootwelve.KT128;
const TurboSHAKE128State = kangarootwelve.TurboSHAKE128State;
const Blake3 = std.crypto.hash.Blake3;
const Sha256 = std.crypto.hash.sha2.Sha256;

const print = std.debug.print;

// Helper function for TurboSHAKE128
fn turboShake128Hash(message: []const u8, output: []u8) void {
    var state = TurboSHAKE128State.init();
    state.update(message);
    state.finalize(0x1F, output);
}

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

    fn elapsedMillisFloat(self: @This()) f64 {
        return @as(f64, @floatFromInt(self.elapsed())) / 1_000_000.0;
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
    kt128_sequential_time_ms: f64,
    kt128_parallel_time_ms: f64,
    turboshake128_time_ms: f64,
    blake3_time_ms: f64,
    sha256_time_ms: f64,
    kt128_sequential_mb_s: f64,
    kt128_parallel_mb_s: f64,
    turboshake128_mb_s: f64,
    blake3_mb_s: f64,
    sha256_mb_s: f64,
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
    var out_kt128_seq: [32]u8 = undefined;
    var out_kt128_par: [32]u8 = undefined;
    var out_turboshake128: [32]u8 = undefined;
    var out_blake3: [32]u8 = undefined;
    var out_sha256: [32]u8 = undefined;

    const chunks = (message.len + 8192 - 1) / 8192;

    // For small inputs, run multiple iterations to get accurate timing
    const min_runtime_ns: i128 = 50_000_000; // 50ms minimum for better precision
    var iterations: usize = 1;

    // Do quick tests of all algorithms to determine iterations needed
    var quick_timer = Timer.init();
    var min_elapsed: i128 = std.math.maxInt(i128);

    // Test KT128 sequential
    quick_timer.startTimer();
    try KT128.hash(message, null, &out_kt128_seq);
    quick_timer.stopTimer();
    std.mem.doNotOptimizeAway(&out_kt128_seq);
    min_elapsed = @min(min_elapsed, quick_timer.elapsed());

    // Test TurboSHAKE128
    quick_timer.startTimer();
    turboShake128Hash(message, &out_turboshake128);
    quick_timer.stopTimer();
    std.mem.doNotOptimizeAway(&out_turboshake128);
    min_elapsed = @min(min_elapsed, quick_timer.elapsed());

    // Test BLAKE3
    quick_timer.startTimer();
    Blake3.hash(message, &out_blake3, .{});
    quick_timer.stopTimer();
    std.mem.doNotOptimizeAway(&out_blake3);
    min_elapsed = @min(min_elapsed, quick_timer.elapsed());

    // Test SHA256
    quick_timer.startTimer();
    Sha256.hash(message, &out_sha256, .{});
    quick_timer.stopTimer();
    std.mem.doNotOptimizeAway(&out_sha256);
    min_elapsed = @min(min_elapsed, quick_timer.elapsed());

    // Calculate iterations based on fastest algorithm
    if (min_elapsed < min_runtime_ns) {
        iterations = @intCast(@divTrunc(min_runtime_ns, @max(min_elapsed, 1)) + 1);
    }

    // KT128 Sequential benchmark
    var timer_kt128_seq = Timer.init();
    timer_kt128_seq.startTimer();
    for (0..iterations) |_| {
        try KT128.hash(message, null, &out_kt128_seq);
        std.mem.doNotOptimizeAway(&out_kt128_seq);
    }
    timer_kt128_seq.stopTimer();
    const kt128_sequential_time_ms = timer_kt128_seq.elapsedMillisFloat();

    // KT128 Parallel benchmark
    var timer_kt128_par = Timer.init();
    timer_kt128_par.startTimer();
    for (0..iterations) |_| {
        try KT128.hashParallel(message, null, &out_kt128_par, allocator);
        std.mem.doNotOptimizeAway(&out_kt128_par);
    }
    timer_kt128_par.stopTimer();
    const kt128_parallel_time_ms = timer_kt128_par.elapsedMillisFloat();

    // TurboSHAKE128 benchmark
    var timer_turboshake128 = Timer.init();
    timer_turboshake128.startTimer();
    for (0..iterations) |_| {
        turboShake128Hash(message, &out_turboshake128);
        std.mem.doNotOptimizeAway(&out_turboshake128);
    }
    timer_turboshake128.stopTimer();
    const turboshake128_time_ms = timer_turboshake128.elapsedMillisFloat();

    // BLAKE3 benchmark
    var timer_blake3 = Timer.init();
    timer_blake3.startTimer();
    for (0..iterations) |_| {
        Blake3.hash(message, &out_blake3, .{});
        std.mem.doNotOptimizeAway(&out_blake3);
    }
    timer_blake3.stopTimer();
    const blake3_time_ms = timer_blake3.elapsedMillisFloat();

    // SHA256 benchmark
    var timer_sha256 = Timer.init();
    timer_sha256.startTimer();
    for (0..iterations) |_| {
        Sha256.hash(message, &out_sha256, .{});
        std.mem.doNotOptimizeAway(&out_sha256);
    }
    timer_sha256.stopTimer();
    const sha256_time_ms = timer_sha256.elapsedMillisFloat();

    // Verify KT128 sequential and parallel results are the same
    if (!std.mem.eql(u8, &out_kt128_seq, &out_kt128_par)) {
        print("ERROR: KT128 Sequential and parallel results differ for {s}!\n", .{name});
        return error.ResultsMismatch;
    }

    const mb_size = @as(f64, @floatFromInt(message.len)) / 1_048_576.0;
    const total_mb = mb_size * @as(f64, @floatFromInt(iterations));

    const kt128_sequential_mb_s = if (kt128_sequential_time_ms > 0)
        total_mb * 1000.0 / kt128_sequential_time_ms
    else
        0.0;

    const kt128_parallel_mb_s = if (kt128_parallel_time_ms > 0)
        total_mb * 1000.0 / kt128_parallel_time_ms
    else
        0.0;

    const turboshake128_mb_s = if (turboshake128_time_ms > 0)
        total_mb * 1000.0 / turboshake128_time_ms
    else
        0.0;

    const blake3_mb_s = if (blake3_time_ms > 0)
        total_mb * 1000.0 / blake3_time_ms
    else
        0.0;

    const sha256_mb_s = if (sha256_time_ms > 0)
        total_mb * 1000.0 / sha256_time_ms
    else
        0.0;

    return BenchmarkResult{
        .name = name,
        .message_size = message.len,
        .chunks = chunks,
        .kt128_sequential_time_ms = kt128_sequential_time_ms,
        .kt128_parallel_time_ms = kt128_parallel_time_ms,
        .turboshake128_time_ms = turboshake128_time_ms,
        .blake3_time_ms = blake3_time_ms,
        .sha256_time_ms = sha256_time_ms,
        .kt128_sequential_mb_s = kt128_sequential_mb_s,
        .kt128_parallel_mb_s = kt128_parallel_mb_s,
        .turboshake128_mb_s = turboshake128_mb_s,
        .blake3_mb_s = blake3_mb_s,
        .sha256_mb_s = sha256_mb_s,
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

    print("Hash Algorithm Benchmark: KT128 vs TurboSHAKE128 vs BLAKE3 vs SHA256\n", .{});
    print("======================================================================\n\n", .{});

    // Test different message sizes (from small to very large)
    const test_sizes = [_]struct { size: usize, name: []const u8 }{
        .{ .size = 64, .name = "64 B" },
        .{ .size = 1_024, .name = "1 KB" },
        .{ .size = 8_192, .name = "8 KB" },
        .{ .size = 65_536, .name = "64 KB" },
        .{ .size = 1_048_576, .name = "1 MB" },
        .{ .size = 10_485_760, .name = "10 MB" },
        .{ .size = 104_857_600, .name = "100 MB" },
        .{ .size = 209_715_200, .name = "200 MB" },
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

        print("  SHA256:           {d:.2} ms, {d:.2} MB/s\n", .{ result.sha256_time_ms, result.sha256_mb_s });
        print("  BLAKE3:           {d:.2} ms, {d:.2} MB/s\n", .{ result.blake3_time_ms, result.blake3_mb_s });
        print("  TurboSHAKE128:    {d:.2} ms, {d:.2} MB/s\n", .{ result.turboshake128_time_ms, result.turboshake128_mb_s });
        print("  KT128 Sequential: {d:.2} ms, {d:.2} MB/s\n", .{ result.kt128_sequential_time_ms, result.kt128_sequential_mb_s });
        print("  KT128 Parallel:   {d:.2} ms, {d:.2} MB/s\n\n", .{ result.kt128_parallel_time_ms, result.kt128_parallel_mb_s });
    }

    // Summary table
    print("\n", .{});
    print("=" ** 92 ++ "\n", .{});
    print("SUMMARY TABLE - All throughput values in MB/s\n", .{});
    print("=" ** 92 ++ "\n", .{});
    print("{s:<10} {s:>8} | {s:>11} {s:>11} {s:>11} {s:>11} {s:>11}\n", .{ "Size", "Chunks", "SHA256", "BLAKE3", "TurboSH128", "KT128-Seq", "KT128-Par" });
    print("{s:-<10} {s:->8} + {s:->11} {s:->11} {s:->11} {s:->11} {s:->11}\n", .{ "", "", "", "", "", "", "" });

    for (results.items) |result| {
        var size_buf: [16]u8 = undefined;
        const size_str = blk: {
            if (result.message_size >= 1_048_576) {
                break :blk std.fmt.bufPrint(&size_buf, "{d} MB", .{result.message_size / 1_048_576}) catch "?";
            } else if (result.message_size >= 1_024) {
                break :blk std.fmt.bufPrint(&size_buf, "{d} KB", .{result.message_size / 1_024}) catch "?";
            } else {
                break :blk std.fmt.bufPrint(&size_buf, "{d} B", .{result.message_size}) catch "?";
            }
        };

        print("{s:<10} {d:>8} | {d:>11.2} {d:>11.2} {d:>11.2} {d:>11.2} {d:>11.2}\n", .{
            size_str,
            result.chunks,
            result.sha256_mb_s,
            result.blake3_mb_s,
            result.turboshake128_mb_s,
            result.kt128_sequential_mb_s,
            result.kt128_parallel_mb_s,
        });
    }

    print("=" ** 92 ++ "\n", .{});
    print("\nAll benchmarks completed successfully!\n", .{});
}
