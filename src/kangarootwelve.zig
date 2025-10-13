const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const sha3 = std.crypto.hash.sha3;

const chunk_size = 8192;

fn getChunkFromCombinedInput(message: []const u8, customization: []const u8, encoded_len: []const u8, pos: usize, len: usize) []const u8 {
    const msg_len = message.len;
    const custom_len = customization.len;
    const enc_len = encoded_len.len;

    if (pos < msg_len) {
        // Chunk starts in message
        const msg_end = @min(pos + len, msg_len);
        const msg_part_len = msg_end - pos;
        if (msg_part_len == len) {
            // Chunk is entirely within message
            return message[pos..msg_end];
        }
        // Chunk spans into customization
        return message[pos..msg_end]; // Return just the message part for now
    } else if (pos < msg_len + custom_len) {
        // Chunk starts in customization
        const custom_start = pos - msg_len;
        const custom_end = @min(custom_start + len, custom_len);
        return customization[custom_start..custom_end];
    } else {
        // Chunk starts in encoded length
        const enc_start = pos - msg_len - custom_len;
        const enc_end = @min(enc_start + len, enc_len);
        return encoded_len[enc_start..enc_end];
    }
}

fn encodeLength(buf: *[9]u8, len: usize) usize {
    var x: u64 = @intCast(len);
    var temp: [8]u8 = undefined;
    var i: usize = 0;

    while (x > 0) : (i += 1) {
        temp[i] = @truncate(x);
        x >>= 8;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = temp[i - 1 - j];
    }
    buf[i] = @intCast(i);
    return i + 1;
}

pub const KTInput = struct {
    m: []const u8,
    c: []const u8,
    len_buf: [9]u8 = undefined,
    len_len: usize = 0,
    pos: usize = 0,

    pub fn init(m: []const u8, c: []const u8) KTInput {
        var self = KTInput{
            .m = m,
            .c = c,
        };
        self.len_len = encodeLength(&self.len_buf, c.len);
        return self;
    }

    pub fn len(self: KTInput) usize {
        return self.m.len + self.c.len + self.len_len;
    }

    pub fn remaining(self: KTInput) usize {
        return self.len() - self.pos;
    }

    pub fn read(self: *KTInput, out: []u8) []const u8 {
        const c_pos = self.m.len;
        const len_slice_pos = c_pos + self.c.len;
        var out_idx: usize = 0;
        var left = out.len;

        if (self.pos < c_pos) {
            @branchHint(.likely);
            if (self.pos + out.len <= c_pos) {
                @branchHint(.likely);
                const ret = self.m[self.pos..][0..out.len];
                self.pos += out.len;
                return ret;
            }
            const to_read = @min(left, c_pos - self.pos);
            @memcpy(out[out_idx..][0..to_read], self.m[self.pos..][0..to_read]);
            self.pos += to_read;
            out_idx += to_read;
            left -= to_read;
        }
        if (self.pos >= c_pos and self.pos < len_slice_pos) {
            const to_read = @min(left, len_slice_pos - self.pos);
            @memcpy(out[out_idx..][0..to_read], self.c[self.pos - c_pos ..][0..to_read]);
            self.pos += to_read;
            out_idx += to_read;
            left -= to_read;
        }
        if (self.pos >= len_slice_pos) {
            const to_read = @min(left, self.len() - self.pos);
            @memcpy(out[out_idx..][0..to_read], self.len_buf[self.pos - len_slice_pos ..][0..to_read]);
            self.pos += to_read;
            out_idx += to_read;
        }
        return out[0..out_idx];
    }
};

/// KT128 (KangarooTwelve) is a tree-hashing mode on top of TurboSHAKE128
pub fn KT128(comptime output_len: usize) type {
    return KTGeneric(sha3.TurboShake128, 32, output_len);
}

/// KT256 (KangarooTwelve) is a tree-hashing mode on top of TurboSHAKE256
pub fn KT256(comptime output_len: usize) type {
    return KTGeneric(sha3.TurboShake256, 64, output_len);
}

pub fn KTGeneric(comptime Shaker: fn (?u7) type, comptime cv_len: comptime_int, comptime output_len: usize) type {
    return struct {
        const Self = @This();

        /// Hash a message with an optional customization string
        pub fn hash(message: []const u8, customization: ?[]const u8, out: *[output_len]u8) !void {
            var chunk_buf: [chunk_size]u8 = undefined;
            var kti = KTInput.init(message, customization orelse "");
            const total_len = kti.len();

            if (total_len <= chunk_size) {
                const z = kti.read(&chunk_buf);
                return Shaker(0x07).hash(z, out, .{});
            }

            var ts_final = Shaker(0x06).init(.{});
            // Process first chunk
            const first_chunk = kti.read(&chunk_buf);
            ts_final.update(first_chunk);
            ts_final.update(&[8]u8{ 0x03, 0, 0, 0, 0, 0, 0, 0 });

            // Process remaining chunks
            var num_blocks: usize = 0; // Count of chunks after the first
            while (true) {
                const chunk = kti.read(&chunk_buf);
                if (chunk.len == 0) break;
                var cv: [cv_len]u8 = undefined;
                Shaker(0x0B).hash(chunk, &cv, .{});
                ts_final.update(&cv);
                num_blocks += 1;
            }

            // Encode number of blocks (chunks after the first)
            var encoded_len_buf: [9]u8 = undefined;
            const encoded_len = encodeLength(&encoded_len_buf, num_blocks);
            ts_final.update(encoded_len_buf[0..encoded_len]);
            ts_final.update(&[2]u8{ 0xff, 0xff });
            ts_final.final(out);
        }

        /// Context for parallel chunk processing
        const ChunkContext = struct {
            kti: KTInput,
            end_chunk: usize,
            start_chunk_idx: usize,
            results: [][cv_len]u8,

            fn processChunkRange(ctx: *@This()) void {
                var chunk_buf: [chunk_size]u8 = undefined;

                // Process our assigned chunks starting from the pre-positioned KTInput
                var current_chunk = ctx.start_chunk_idx;
                while (current_chunk < ctx.end_chunk) {
                    const chunk = ctx.kti.read(&chunk_buf);
                    if (chunk.len == 0) break; // Should not happen in normal operation
                    Shaker(0x0B).hash(chunk, &ctx.results[current_chunk], .{});
                    current_chunk += 1;
                }
            }
        };

        /// Hash a message with an optional customization string using parallel chunk processing
        pub fn hashParallel(message: []const u8, customization: ?[]const u8, out: *[output_len]u8, allocator: std.mem.Allocator) !void {
            var chunk_buf: [chunk_size]u8 = undefined;
            var kti = KTInput.init(message, customization orelse "");
            const total_len = kti.len();

            // For small inputs, sequential processing is faster (avoids thread pool overhead)
            // Threshold based on ReleaseFast benchmark: parallel only beneficial for very large inputs (50MB+)
            // Set conservative threshold based on comprehensive benchmark results
            const parallel_threshold = 50 * 1024 * 1024; // 50MB - where parallel starts showing benefits
            if (total_len <= parallel_threshold) {
                return hash(message, customization, out);
            }

            var ts_final = Shaker(0x06).init(.{});
            // Process first chunk
            const first_chunk = kti.read(&chunk_buf);
            ts_final.update(first_chunk);
            ts_final.update(&[8]u8{ 0x03, 0, 0, 0, 0, 0, 0, 0 });

            // Calculate remaining chunks directly from remaining bytes
            const remaining_bytes = kti.remaining();
            const num_chunks = (remaining_bytes + chunk_size - 1) / chunk_size; // Round up division

            if (num_chunks == 0) {
                // No additional chunks
                var encoded_len_buf: [9]u8 = undefined;
                const encoded_num = encodeLength(&encoded_len_buf, 0);
                ts_final.update(encoded_len_buf[0..encoded_num]);
                ts_final.update(&[2]u8{ 0xff, 0xff });
                ts_final.final(out);
                return;
            }

            // Create results array only (no need to copy chunks)
            const results = try allocator.alloc([cv_len]u8, num_chunks);
            defer allocator.free(results);

            // Use fixed maximum of 256 threads with stack allocation
            const max_threads = 256;
            const num_threads = @min(num_chunks, max_threads);
            const chunks_per_thread = (num_chunks + num_threads - 1) / num_threads;

            // Create thread contexts on stack (no heap allocation)
            var contexts: [max_threads]ChunkContext = undefined;
            var actual_threads: usize = 0;

            // Create contexts with pre-positioned KTInput for each thread
            // kti is already positioned after the first chunk from line 199
            for (0..num_threads) |thread_idx| {
                const start_chunk = thread_idx * chunks_per_thread;
                const end_chunk = @min(start_chunk + chunks_per_thread, num_chunks);

                // Only initialize contexts that will actually be used
                if (start_chunk < num_chunks) {
                    // Create KTInput view positioned at this thread's start chunk
                    const start_pos = kti.pos + (start_chunk * chunk_size);
                    var thread_kti = kti;
                    thread_kti.pos = start_pos;

                    contexts[thread_idx] = .{
                        .kti = thread_kti,
                        .end_chunk = end_chunk,
                        .start_chunk_idx = start_chunk,
                        .results = results,
                    };
                    actual_threads += 1;
                }
            }

            // Process chunks in parallel using thread pool
            var pool: std.Thread.Pool = undefined;
            pool.init(std.Thread.Pool.Options{ .allocator = allocator, .n_jobs = @intCast(actual_threads) }) catch return;
            defer pool.deinit();

            var wait_group: std.Thread.WaitGroup = .{};
            for (0..actual_threads) |thread_idx| {
                pool.spawnWg(&wait_group, ChunkContext.processChunkRange, .{&contexts[thread_idx]});
            }
            wait_group.wait();

            // Combine results in order
            for (results) |result| {
                ts_final.update(&result);
            }

            // Encode number of blocks (chunks after the first)
            var encoded_len_buf: [9]u8 = undefined;
            const encoded_len = encodeLength(&encoded_len_buf, num_chunks);
            ts_final.update(encoded_len_buf[0..encoded_len]);
            ts_final.update(&[2]u8{ 0xff, 0xff });
            ts_final.final(out);
        }
    };
}

const testing = std.testing;

test "reader 1" {
    const input = "Hello, world!";
    const customization = "Zig";
    var buf: [32]u8 = undefined;
    var encoded_len_buf: [9]u8 = undefined;
    const encoded_len = encodeLength(&encoded_len_buf, customization.len);
    var kti = KTInput.init(input, customization);
    const out = kti.read(buf[0..]);
    try testing.expectEqual(out.len, input.len + customization.len + encoded_len);
    try testing.expectEqualSlices(u8, out[0..input.len], input);
    try testing.expectEqualSlices(u8, out[input.len .. input.len + customization.len], customization);
}

test "reader 2" {
    const input = "Hello, world!";
    const customization = "Zig";
    var buf: [32]u8 = undefined;
    var encoded_len_buf: [9]u8 = undefined;
    const encoded_len = encodeLength(&encoded_len_buf, customization.len);
    var kti = KTInput.init(input, customization);
    try testing.expectEqualSlices(u8, kti.read(buf[0..7]), input[0..7]);
    try testing.expectEqualSlices(u8, kti.read(buf[0..6]), input[7..]);
    try testing.expectEqualSlices(u8, kti.read(buf[0..3]), customization[0..]);
    try testing.expectEqualSlices(u8, kti.read(buf[0..]), encoded_len_buf[0..encoded_len]);
}

fn ptn(x: []u8) void {
    for (x, 0..) |*p, i| {
        p.* = @truncate(i % 0xfb);
    }
}

test "KT128 - empty message and customization (32 bytes)" {
    const KT128_32 = KT128(32);
    var out: [32]u8 = undefined;
    try KT128_32.hash("", "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x1A, 0xC2, 0xD4, 0x50, 0xFC, 0x3B, 0x42, 0x05,
        0xD1, 0x9D, 0xA7, 0xBF, 0xCA, 0x1B, 0x37, 0x51,
        0x3C, 0x08, 0x03, 0x57, 0x7A, 0xC7, 0x16, 0x7F,
        0x06, 0xFE, 0x2C, 0xE1, 0xF0, 0xEF, 0x39, 0xE5,
    });
}

test "KT128 - empty message and customization (64 bytes)" {
    const KT128_64 = KT128(64);
    var out: [64]u8 = undefined;
    try KT128_64.hash("", "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x1A, 0xC2, 0xD4, 0x50, 0xFC, 0x3B, 0x42, 0x05,
        0xD1, 0x9D, 0xA7, 0xBF, 0xCA, 0x1B, 0x37, 0x51,
        0x3C, 0x08, 0x03, 0x57, 0x7A, 0xC7, 0x16, 0x7F,
        0x06, 0xFE, 0x2C, 0xE1, 0xF0, 0xEF, 0x39, 0xE5,
        0x42, 0x69, 0xC0, 0x56, 0xB8, 0xC8, 0x2E, 0x48,
        0x27, 0x60, 0x38, 0xB6, 0xD2, 0x92, 0x96, 0x6C,
        0xC0, 0x7A, 0x3D, 0x46, 0x45, 0x27, 0x2E, 0x31,
        0xFF, 0x38, 0x50, 0x81, 0x39, 0xEB, 0x0A, 0x71,
    });
}

test "KT128 - empty message and customization (10032 bytes)" {
    const KT128_10032 = KT128(10032);
    var out: [10032]u8 = undefined;
    try KT128_10032.hash("", "", &out);
    try testing.expectEqualSlices(u8, out[10000..], &[_]u8{
        0xE8, 0xDC, 0x56, 0x36, 0x42, 0xF7, 0x22, 0x8C,
        0x84, 0x68, 0x4C, 0x89, 0x84, 0x05, 0xD3, 0xA8,
        0x34, 0x79, 0x91, 0x58, 0xC0, 0x79, 0xB1, 0x28,
        0x80, 0x27, 0x7A, 0x1D, 0x28, 0xE2, 0xFF, 0x6D,
    });
}

test "KT128 - 1 byte message" {
    const KT128_32 = KT128(32);
    var out: [32]u8 = undefined;
    var msg: [1]u8 = undefined;
    ptn(&msg);
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x2B, 0xDA, 0x92, 0x45, 0x0E, 0x8B, 0x14, 0x7F,
        0x8A, 0x7C, 0xB6, 0x29, 0xE7, 0x84, 0xA0, 0x58,
        0xEF, 0xCA, 0x7C, 0xF7, 0xD8, 0x21, 0x8E, 0x02,
        0xD3, 0x45, 0xDF, 0xAA, 0x65, 0x24, 0x4A, 0x1F,
    });
}

test "KT128 - 17 bytes message" {
    const KT128_32 = KT128(32);
    var out: [32]u8 = undefined;
    var msg: [17]u8 = undefined;
    ptn(&msg);
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x6B, 0xF7, 0x5F, 0xA2, 0x23, 0x91, 0x98, 0xDB,
        0x47, 0x72, 0xE3, 0x64, 0x78, 0xF8, 0xE1, 0x9B,
        0x0F, 0x37, 0x12, 0x05, 0xF6, 0xA9, 0xA9, 0x3A,
        0x27, 0x3F, 0x51, 0xDF, 0x37, 0x12, 0x28, 0x88,
    });
}

test "KT128 - 289 bytes message" {
    const KT128_32 = KT128(32);
    var msg: [289]u8 = undefined;
    ptn(&msg);
    var out: [32]u8 = undefined;
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x0C, 0x31, 0x5E, 0xBC, 0xDE, 0xDB, 0xF6, 0x14,
        0x26, 0xDE, 0x7D, 0xCF, 0x8F, 0xB7, 0x25, 0xD1,
        0xE7, 0x46, 0x75, 0xD7, 0xF5, 0x32, 0x7A, 0x50,
        0x67, 0xF3, 0x67, 0xB1, 0x08, 0xEC, 0xB6, 0x7C,
    });
}

test "KT128 - 4913 bytes message" {
    const KT128_32 = KT128(32);
    var msg: [4913]u8 = undefined;
    ptn(&msg);
    var out: [32]u8 = undefined;
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0xCB, 0x55, 0x2E, 0x2E, 0xC7, 0x7D, 0x99, 0x10,
        0x70, 0x1D, 0x57, 0x8B, 0x45, 0x7D, 0xDF, 0x77,
        0x2C, 0x12, 0xE3, 0x22, 0xE4, 0xEE, 0x7F, 0xE4,
        0x17, 0xF9, 0x2C, 0x75, 0x8F, 0x0D, 0x59, 0xD0,
    });
}

test "KT128 - empty message with 1 byte customization" {
    const KT128_32 = KT128(32);
    var out: [32]u8 = undefined;
    var customization: [1]u8 = undefined;
    ptn(&customization);
    try KT128_32.hash("", &customization, &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0xFA, 0xB6, 0x58, 0xDB, 0x63, 0xE9, 0x4A, 0x24,
        0x61, 0x88, 0xBF, 0x7A, 0xF6, 0x9A, 0x13, 0x30,
        0x45, 0xF4, 0x6E, 0xE9, 0x84, 0xC5, 0x6E, 0x3C,
        0x33, 0x28, 0xCA, 0xAF, 0x1A, 0xA1, 0xA5, 0x83,
    });
}

test "KT128 - 1 byte message with 41 bytes customization" {
    const KT128_32 = KT128(32);
    var msg = [_]u8{0xFF};
    var out: [32]u8 = undefined;
    var customization: [41]u8 = undefined;
    ptn(&customization);
    try KT128_32.hash(&msg, &customization, &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0xD8, 0x48, 0xC5, 0x06, 0x8C, 0xED, 0x73, 0x6F, 0x44, 0x62, 0x15, 0x9B, 0x98, 0x67, 0xFD, 0x4C, 0x20, 0xB8, 0x08, 0xAC, 0xC3,
        0xD5, 0xBC, 0x48, 0xE0, 0xB0, 0x6B, 0xA0, 0xA3, 0x76, 0x2E, 0xC4,
    });
}

test "KT128 - 8191 bytes message" {
    const KT128_32 = KT128(32);
    var msg: [8191]u8 = undefined;
    ptn(&msg);
    var out: [32]u8 = undefined;
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x1B, 0x57, 0x76, 0x36, 0xF7, 0x23, 0x64, 0x3E,
        0x99, 0x0C, 0xC7, 0xD6, 0xA6, 0x59, 0x83, 0x74,
        0x36, 0xFD, 0x6A, 0x10, 0x36, 0x26, 0x60, 0x0E,
        0xB8, 0x30, 0x1C, 0xD1, 0xDB, 0xE5, 0x53, 0xD6,
    });
}

test "KT128 - 8192 bytes message (chunk size)" {
    const KT128_32 = KT128(32);
    var msg: [8192]u8 = undefined;
    ptn(&msg);
    var out: [32]u8 = undefined;
    try KT128_32.hash(&msg, "", &out);
    try testing.expectEqualSlices(u8, &out, &[_]u8{
        0x48, 0xF2, 0x56, 0xF6, 0x77, 0x2F, 0x9E, 0xDF,
        0xB6, 0xA8, 0xB6, 0x61, 0xEC, 0x92, 0xDC, 0x93,
        0xB9, 0x5E, 0xBD, 0x05, 0xA0, 0x8A, 0x17, 0xB3,
        0x9A, 0xE3, 0x49, 0x08, 0x70, 0xC9, 0x26, 0xC3,
    });
}

// Test parallel vs sequential consistency
test "KT128 - parallel vs sequential consistency - small message" {
    const KT128_32 = KT128(32);
    var msg: [100]u8 = undefined;
    ptn(&msg);
    var out_seq: [32]u8 = undefined;
    var out_par: [32]u8 = undefined;

    try KT128_32.hash(&msg, "", &out_seq);
    try KT128_32.hashParallel(&msg, "", &out_par, std.testing.allocator);

    try testing.expectEqualSlices(u8, &out_seq, &out_par);
}

test "KT128 - parallel vs sequential consistency - multi-chunk message" {
    const KT128_32 = KT128(32);
    var msg: [20000]u8 = undefined;
    ptn(&msg);
    var out_seq: [32]u8 = undefined;
    var out_par: [32]u8 = undefined;

    try KT128_32.hash(&msg, "", &out_seq);
    try KT128_32.hashParallel(&msg, "", &out_par, std.testing.allocator);

    try testing.expectEqualSlices(u8, &out_seq, &out_par);
}

test "KT128 - parallel vs sequential consistency - with customization" {
    const KT128_32 = KT128(32);
    var msg: [25000]u8 = undefined;
    var customization: [50]u8 = undefined;
    ptn(&msg);
    ptn(&customization);
    var out_seq: [32]u8 = undefined;
    var out_par: [32]u8 = undefined;

    try KT128_32.hash(&msg, &customization, &out_seq);
    try KT128_32.hashParallel(&msg, &customization, &out_par, std.testing.allocator);

    try testing.expectEqualSlices(u8, &out_seq, &out_par);
}

test "KT128 - parallel vs sequential consistency - exact chunk boundaries" {
    const KT128_32 = KT128(32);

    // Test exactly 2 chunks
    var msg2: [16384]u8 = undefined;
    ptn(&msg2);
    var out_seq2: [32]u8 = undefined;
    var out_par2: [32]u8 = undefined;

    try KT128_32.hash(&msg2, "", &out_seq2);
    try KT128_32.hashParallel(&msg2, "", &out_par2, std.testing.allocator);

    try testing.expectEqualSlices(u8, &out_seq2, &out_par2);

    // Test exactly 3 chunks
    var msg3: [24576]u8 = undefined;
    ptn(&msg3);
    var out_seq3: [32]u8 = undefined;
    var out_par3: [32]u8 = undefined;

    try KT128_32.hash(&msg3, "", &out_seq3);
    try KT128_32.hashParallel(&msg3, "", &out_par3, std.testing.allocator);

    try testing.expectEqualSlices(u8, &out_seq3, &out_par3);
}

test "KT128 - parallel produces same results as existing tests" {
    const KT128_32 = KT128(32);

    // Test empty message
    var out_empty: [32]u8 = undefined;
    try KT128_32.hashParallel("", "", &out_empty, std.testing.allocator);
    try testing.expectEqualSlices(u8, &out_empty, &[_]u8{
        0x1A, 0xC2, 0xD4, 0x50, 0xFC, 0x3B, 0x42, 0x05,
        0xD1, 0x9D, 0xA7, 0xBF, 0xCA, 0x1B, 0x37, 0x51,
        0x3C, 0x08, 0x03, 0x57, 0x7A, 0xC7, 0x16, 0x7F,
        0x06, 0xFE, 0x2C, 0xE1, 0xF0, 0xEF, 0x39, 0xE5,
    });

    // Test 8192 bytes message
    var msg: [8192]u8 = undefined;
    ptn(&msg);
    var out_8192: [32]u8 = undefined;
    try KT128_32.hashParallel(&msg, "", &out_8192, std.testing.allocator);
    try testing.expectEqualSlices(u8, &out_8192, &[_]u8{
        0x48, 0xF2, 0x56, 0xF6, 0x77, 0x2F, 0x9E, 0xDF,
        0xB6, 0xA8, 0xB6, 0x61, 0xEC, 0x92, 0xDC, 0x93,
        0xB9, 0x5E, 0xBD, 0x05, 0xA0, 0x8A, 0x17, 0xB3,
        0x9A, 0xE3, 0x49, 0x08, 0x70, 0xC9, 0x26, 0xC3,
    });
}
