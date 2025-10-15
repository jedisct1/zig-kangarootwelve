const std = @import("std");
const builtin = @import("builtin");
const Thread = std.Thread;
const Pool = Thread.Pool;
const WaitGroup = Thread.WaitGroup;

const B: usize = 8192; // Chunk size for tree hashing (8 KiB)
const CACHE_LINE_SIZE = 64; // Common cache line size for x86_64 and ARM

// Optimal SIMD vector length for u64 on this target platform
const optimal_vector_len = std.simd.suggestVectorLength(u64) orelse 1;

// Dynamic multi-threading threshold based on CPU count
fn getLargeFileThreshold() usize {
    const cpu_count = Thread.getCpuCount() catch 1;
    if (cpu_count >= 8) {
        return 3 * 1024 * 1024; // 3 MB for 8+ cores
    } else if (cpu_count >= 4) {
        return 5 * 1024 * 1024; // 5 MB for 4-7 cores
    } else {
        return 10 * 1024 * 1024; // 10 MB for 1-3 cores
    }
}

// Round constants for Keccak-p[1600,12]
const RC = [12]u64{
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

/// KangarooTwelve with 128-bit security parameters
const KT128Variant = struct {
    const rate = 168; // TurboSHAKE128 rate in bytes
    const rate_in_lanes = 21; // 168 bytes / 8
    const cv_size = 32; // Chaining value size in bytes
    const StateType = TurboSHAKE128State;
    const separation_byte_pos = .{ .x = 1, .y = 3 }; // lane 11 (88 bytes into 168-byte rate)
    const padding_pos = .{ .x = 0, .y = 4 }; // lane 20 (last lane of 168-byte rate)

    inline fn turboSHAKEToBuffer(view: *const MultiSliceView, separation_byte: u8, output: []u8) void {
        turboSHAKE128MultiSliceToBuffer(view, separation_byte, output);
    }

    inline fn turboSHAKEMultiSliceAlloc(allocator: std.mem.Allocator, view: *const MultiSliceView, separation_byte: u8, output_len: usize) ![]u8 {
        return turboSHAKE128MultiSlice(allocator, view, separation_byte, output_len);
    }
};

/// KangarooTwelve with 256-bit security parameters
const KT256Variant = struct {
    const rate = 136; // TurboSHAKE256 rate in bytes
    const rate_in_lanes = 17; // 136 bytes / 8
    const cv_size = 64; // Chaining value size in bytes
    const StateType = TurboSHAKE256State;
    const separation_byte_pos = .{ .x = 4, .y = 0 }; // lane 4 (32 bytes into 136-byte rate)
    const padding_pos = .{ .x = 1, .y = 3 }; // lane 16 (last lane of 136-byte rate)

    inline fn turboSHAKEToBuffer(view: *const MultiSliceView, separation_byte: u8, output: []u8) void {
        turboSHAKE256MultiSliceToBuffer(view, separation_byte, output);
    }

    inline fn turboSHAKEMultiSliceAlloc(allocator: std.mem.Allocator, view: *const MultiSliceView, separation_byte: u8, output_len: usize) ![]u8 {
        return turboSHAKE256MultiSlice(allocator, view, separation_byte, output_len);
    }
};

/// Rotate left for u64 vector
inline fn rol64Vec(comptime N: usize, v: @Vector(N, u64), comptime n: u6) @Vector(N, u64) {
    if (n == 0) return v;
    const left: @Vector(N, u64) = @splat(n);
    const right_shift: u64 = 64 - @as(u64, n);
    const right: @Vector(N, u64) = @splat(right_shift);
    return (v << left) | (v >> right);
}

/// Load a 64-bit little-endian value
inline fn load64(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= 8);
    return std.mem.readInt(u64, bytes[0..8], .little);
}

/// Store a 64-bit little-endian value
inline fn store64(value: u64, bytes: []u8) void {
    std.debug.assert(bytes.len >= 8);
    std.mem.writeInt(u64, bytes[0..8], value, .little);
}

/// Right-encode result type (max 9 bytes for 64-bit usize)
const RightEncoded = struct {
    bytes: [9]u8,
    len: u8,

    fn slice(self: *const RightEncoded) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Right-encode: encodes a number as bytes with length suffix (no allocation)
fn rightEncode(x: usize) RightEncoded {
    var result: RightEncoded = undefined;

    if (x == 0) {
        result.bytes[0] = 0;
        result.len = 1;
        return result;
    }

    var temp: [9]u8 = undefined;
    var len: usize = 0;
    var val = x;

    while (val > 0) : (val /= 256) {
        temp[len] = @intCast(val % 256);
        len += 1;
    }

    // Reverse bytes (MSB first)
    for (0..len) |i| {
        result.bytes[i] = temp[len - 1 - i];
    }
    result.bytes[len] = @intCast(len);
    result.len = @intCast(len + 1);

    return result;
}

/// Virtual contiguous view over multiple slices (zero-copy)
const MultiSliceView = struct {
    slices: [3][]const u8,
    offsets: [4]usize,

    fn init(s1: []const u8, s2: []const u8, s3: []const u8) MultiSliceView {
        return .{
            .slices = .{ s1, s2, s3 },
            .offsets = .{
                0,
                s1.len,
                s1.len + s2.len,
                s1.len + s2.len + s3.len,
            },
        };
    }

    fn totalLen(self: *const MultiSliceView) usize {
        return self.offsets[3];
    }

    /// Get byte at position (zero-copy)
    fn getByte(self: *const MultiSliceView, pos: usize) u8 {
        for (0..3) |i| {
            if (pos >= self.offsets[i] and pos < self.offsets[i + 1]) {
                return self.slices[i][pos - self.offsets[i]];
            }
        }
        unreachable;
    }

    /// Try to get a contiguous slice [start..end) - returns null if spans boundaries
    fn tryGetSlice(self: *const MultiSliceView, start: usize, end: usize) ?[]const u8 {
        for (0..3) |i| {
            if (start >= self.offsets[i] and end <= self.offsets[i + 1]) {
                const local_start = start - self.offsets[i];
                const local_end = end - self.offsets[i];
                return self.slices[i][local_start..local_end];
            }
        }
        return null;
    }

    /// Copy range [start..end) to buffer (used when slice spans boundaries)
    fn copyRange(self: *const MultiSliceView, start: usize, end: usize, buffer: []u8) void {
        var pos: usize = 0;
        for (start..end) |i| {
            buffer[pos] = self.getByte(i);
            pos += 1;
        }
    }
};

/// Apply Keccak-p[1600,12] to N states in parallel - optimized version
fn keccakP1600timesN(comptime N: usize, states: *[5][5]@Vector(N, u64)) void {
    @setEvalBranchQuota(10000);

    // Pre-computed rotation offsets for rho-pi step
    const rho_offsets = comptime blk: {
        var offsets: [24]u6 = undefined;
        var px: usize = 1;
        var py: usize = 0;
        for (0..24) |t| {
            const rot_amount = ((t + 1) * (t + 2) / 2) % 64;
            offsets[t] = @intCast(rot_amount);
            const temp_x = py;
            py = (2 * px + 3 * py) % 5;
            px = temp_x;
        }
        break :blk offsets;
    };

    inline for (RC) |rc| {
        // θ (theta) - fully unrolled
        var C: [5]@Vector(N, u64) = undefined;
        inline for (0..5) |x| {
            C[x] = states[x][0] ^ states[x][1] ^ states[x][2] ^ states[x][3] ^ states[x][4];
        }

        var D: [5]@Vector(N, u64) = undefined;
        // Unrolled computation avoiding modulo operations
        D[0] = C[4] ^ rol64Vec(N, C[1], 1);
        D[1] = C[0] ^ rol64Vec(N, C[2], 1);
        D[2] = C[1] ^ rol64Vec(N, C[3], 1);
        D[3] = C[2] ^ rol64Vec(N, C[4], 1);
        D[4] = C[3] ^ rol64Vec(N, C[0], 1);

        // Apply D to all lanes - fully unrolled
        inline for (0..5) |x| {
            states[x][0] ^= D[x];
            states[x][1] ^= D[x];
            states[x][2] ^= D[x];
            states[x][3] ^= D[x];
            states[x][4] ^= D[x];
        }

        // ρ (rho) and π (pi) - optimized with pre-computed offsets
        var current = states[1][0];
        var px: usize = 1;
        var py: usize = 0;
        inline for (rho_offsets) |rot| {
            const next_y = (2 * px + 3 * py) % 5;
            const next = states[py][next_y];
            states[py][next_y] = rol64Vec(N, current, rot);
            current = next;
            px = py;
            py = next_y;
        }

        // χ (chi) - optimized with better register usage
        inline for (0..5) |y| {
            const t0 = states[0][y];
            const t1 = states[1][y];
            const t2 = states[2][y];
            const t3 = states[3][y];
            const t4 = states[4][y];

            states[0][y] = t0 ^ (~t1 & t2);
            states[1][y] = t1 ^ (~t2 & t3);
            states[2][y] = t2 ^ (~t3 & t4);
            states[3][y] = t3 ^ (~t4 & t0);
            states[4][y] = t4 ^ (~t0 & t1);
        }

        // ι (iota)
        const rc_splat: @Vector(N, u64) = @splat(rc);
        states[0][0] ^= rc_splat;
    }
}

/// Add lanes from data to N states in parallel with stride - optimized version
fn addLanesAll(comptime N: usize, states: *[5][5]@Vector(N, u64), data: []const u8, lane_count: usize, lane_offset: usize) void {
    std.debug.assert(data.len >= 8 * ((N - 1) * lane_offset + lane_count));

    // Process lanes (at most 25 lanes in Keccak state)
    inline for (0..25) |xy| {
        if (xy < lane_count) {
            const x = xy % 5;
            const y = xy / 5;

            // Load N lanes with stride - optimized memory access pattern
            var loaded_data: @Vector(N, u64) = undefined;

            // Manual unroll for common N values
            if (N == 2) {
                loaded_data[0] = load64(data[8 * xy ..]);
                loaded_data[1] = load64(data[8 * (lane_offset + xy) ..]);
            } else if (N == 4) {
                loaded_data[0] = load64(data[8 * xy ..]);
                loaded_data[1] = load64(data[8 * (lane_offset + xy) ..]);
                loaded_data[2] = load64(data[8 * (2 * lane_offset + xy) ..]);
                loaded_data[3] = load64(data[8 * (3 * lane_offset + xy) ..]);
            } else if (N == 8) {
                inline for (0..8) |i| {
                    loaded_data[i] = load64(data[8 * (i * lane_offset + xy) ..]);
                }
            } else {
                // Generic fallback
                inline for (0..N) |i| {
                    loaded_data[i] = load64(data[8 * (i * lane_offset + xy) ..]);
                }
            }

            states[x][y] ^= loaded_data;
        }
    }
}

// ============================================================================
// TurboSHAKE with multi-slice support (zero-copy)
// ============================================================================

/// Apply Keccak-p[1600,12] to a single state (byte representation)
fn keccakP(state: *[200]u8) void {
    @setEvalBranchQuota(10000);
    var lanes: [5][5]u64 = undefined;

    // Load state into lanes
    inline for (0..5) |x| {
        inline for (0..5) |y| {
            lanes[x][y] = load64(state[8 * (x + 5 * y) ..]);
        }
    }

    // Apply 12 rounds
    inline for (RC) |rc| {
        // θ
        var C: [5]u64 = undefined;
        inline for (0..5) |x| {
            C[x] = lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4];
        }
        var D: [5]u64 = undefined;
        inline for (0..5) |x| {
            D[x] = C[(x + 4) % 5] ^ std.math.rotl(u64, C[(x + 1) % 5], 1);
        }
        inline for (0..5) |x| {
            inline for (0..5) |y| {
                lanes[x][y] ^= D[x];
            }
        }

        // ρ and π
        var current = lanes[1][0];
        var px: usize = 1;
        var py: usize = 0;
        inline for (0..24) |t| {
            const temp = lanes[py][(2 * px + 3 * py) % 5];
            const rot_amount = ((t + 1) * (t + 2) / 2) % 64;
            lanes[py][(2 * px + 3 * py) % 5] = std.math.rotl(u64, current, @as(u6, @intCast(rot_amount)));
            current = temp;
            const temp_x = py;
            py = (2 * px + 3 * py) % 5;
            px = temp_x;
        }

        // χ
        inline for (0..5) |y| {
            const T = [5]u64{ lanes[0][y], lanes[1][y], lanes[2][y], lanes[3][y], lanes[4][y] };
            inline for (0..5) |x| {
                lanes[x][y] = T[x] ^ (~T[(x + 1) % 5] & T[(x + 2) % 5]);
            }
        }

        // ι
        lanes[0][0] ^= rc;
    }

    // Store lanes back to state
    inline for (0..5) |x| {
        inline for (0..5) |y| {
            store64(lanes[x][y], state[8 * (x + 5 * y) ..]);
        }
    }
}

/// Apply Keccak-p[1600,12] to a single state (u64 lane representation)
fn keccakPLanes(lanes: *[25]u64) void {
    @setEvalBranchQuota(10000);

    // Apply 12 rounds
    inline for (RC) |rc| {
        // θ
        var C: [5]u64 = undefined;
        inline for (0..5) |x| {
            C[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
        }
        var D: [5]u64 = undefined;
        inline for (0..5) |x| {
            D[x] = C[(x + 4) % 5] ^ std.math.rotl(u64, C[(x + 1) % 5], 1);
        }
        inline for (0..5) |x| {
            inline for (0..5) |y| {
                lanes[x + 5 * y] ^= D[x];
            }
        }

        // ρ and π
        var current = lanes[1];
        var px: usize = 1;
        var py: usize = 0;
        inline for (0..24) |t| {
            const next_y = (2 * px + 3 * py) % 5;
            const next_idx = py + 5 * next_y;
            const temp = lanes[next_idx];
            const rot_amount = ((t + 1) * (t + 2) / 2) % 64;
            lanes[next_idx] = std.math.rotl(u64, current, @as(u6, @intCast(rot_amount)));
            current = temp;
            px = py;
            py = next_y;
        }

        // χ
        inline for (0..5) |y| {
            const idx = 5 * y;
            const T = [5]u64{ lanes[idx], lanes[idx + 1], lanes[idx + 2], lanes[idx + 3], lanes[idx + 4] };
            inline for (0..5) |x| {
                lanes[idx + x] = T[x] ^ (~T[(x + 1) % 5] & T[(x + 2) % 5]);
            }
        }

        // ι
        lanes[0] ^= rc;
    }
}

/// Generic non-allocating TurboSHAKE: write output to provided buffer
fn turboSHAKEMultiSliceToBuffer(comptime rate: usize, view: *const MultiSliceView, separation_byte: u8, output: []u8) void {
    var state = [_]u8{0} ** 200;
    var state_pos: usize = 0;

    // Absorb all bytes from the multi-slice view
    const total = view.totalLen();
    var pos: usize = 0;
    while (pos < total) {
        state[state_pos] ^= view.getByte(pos);
        state_pos += 1;
        pos += 1;

        if (state_pos == rate) {
            keccakP(&state);
            state_pos = 0;
        }
    }

    // Add separation byte and padding
    state[state_pos] ^= separation_byte;
    state[rate - 1] ^= 0x80;
    keccakP(&state);

    // Squeeze
    var out_offset: usize = 0;
    while (out_offset < output.len) {
        const chunk = @min(rate, output.len - out_offset);
        @memcpy(output[out_offset..][0..chunk], state[0..chunk]);
        out_offset += chunk;
        if (out_offset < output.len) {
            keccakP(&state);
        }
    }
}

/// Generic allocating TurboSHAKE
fn turboSHAKEMultiSlice(comptime rate: usize, allocator: std.mem.Allocator, view: *const MultiSliceView, separation_byte: u8, output_len: usize) ![]u8 {
    const output = try allocator.alloc(u8, output_len);
    turboSHAKEMultiSliceToBuffer(rate, view, separation_byte, output);
    return output;
}

/// Non-allocating TurboSHAKE128: write output to provided buffer
fn turboSHAKE128MultiSliceToBuffer(view: *const MultiSliceView, separation_byte: u8, output: []u8) void {
    turboSHAKEMultiSliceToBuffer(168, view, separation_byte, output);
}

/// Allocating TurboSHAKE128
fn turboSHAKE128MultiSlice(allocator: std.mem.Allocator, view: *const MultiSliceView, separation_byte: u8, output_len: usize) ![]u8 {
    return turboSHAKEMultiSlice(168, allocator, view, separation_byte, output_len);
}

/// Non-allocating TurboSHAKE256: write output to provided buffer
fn turboSHAKE256MultiSliceToBuffer(view: *const MultiSliceView, separation_byte: u8, output: []u8) void {
    turboSHAKEMultiSliceToBuffer(136, view, separation_byte, output);
}

/// Allocating TurboSHAKE256
fn turboSHAKE256MultiSlice(allocator: std.mem.Allocator, view: *const MultiSliceView, separation_byte: u8, output_len: usize) ![]u8 {
    return turboSHAKEMultiSlice(136, allocator, view, separation_byte, output_len);
}

/// Generic streaming TurboSHAKE state for incremental hashing
fn TurboSHAKEState(comptime rate: usize) type {
    return struct {
        lanes: [25]u64,
        buf: [rate]u8,
        buf_pos: usize,

        const Self = @This();

        /// Initialize a new TurboSHAKE state
        pub fn init() Self {
            return .{
                .lanes = [_]u64{0} ** 25,
                .buf = undefined,
                .buf_pos = 0,
            };
        }

        /// Absorb data incrementally (can be called multiple times)
        pub fn update(self: *Self, data: []const u8) void {
            var i: usize = 0;

            // Fill partial buffer first
            if (self.buf_pos > 0) {
                const remaining = rate - self.buf_pos;
                const to_copy = @min(remaining, data.len);
                @memcpy(self.buf[self.buf_pos..][0..to_copy], data[0..to_copy]);
                self.buf_pos += to_copy;
                i = to_copy;

                if (self.buf_pos == rate) {
                    // XOR buffer into state and permute
                    var lane_idx: usize = 0;
                    while (lane_idx * 8 < rate) : (lane_idx += 1) {
                        self.lanes[lane_idx] ^= load64(self.buf[lane_idx * 8 ..]);
                    }
                    keccakPLanes(&self.lanes);
                    self.buf_pos = 0;
                }

                if (i == data.len) return;
            }

            // Process complete blocks
            while (i + rate <= data.len) {
                var lane_idx: usize = 0;
                while (lane_idx * 8 < rate) : (lane_idx += 1) {
                    self.lanes[lane_idx] ^= load64(data[i + lane_idx * 8 ..]);
                }
                keccakPLanes(&self.lanes);
                i += rate;
            }

            // Buffer remaining bytes
            if (i < data.len) {
                const remaining = data.len - i;
                @memcpy(self.buf[0..remaining], data[i..]);
                self.buf_pos = remaining;
            }
        }

        /// Finalize and squeeze output (consumes the state)
        pub fn finalize(self: *Self, separation_byte: u8, output: []u8) void {
            // Pad and finalize absorption
            self.buf[self.buf_pos] = separation_byte;
            @memset(self.buf[self.buf_pos + 1 .. rate], 0);
            self.buf[rate - 1] |= 0x80;

            // XOR final buffer into state
            var lane_idx: usize = 0;
            while (lane_idx * 8 < rate) : (lane_idx += 1) {
                self.lanes[lane_idx] ^= load64(self.buf[lane_idx * 8 ..]);
            }
            keccakPLanes(&self.lanes);

            // Squeeze
            var out_offset: usize = 0;
            while (out_offset < output.len) {
                const chunk = @min(rate, output.len - out_offset);

                // Extract lanes to output
                var byte_idx: usize = 0;
                while (byte_idx < chunk) {
                    const lane = byte_idx / 8;
                    const lane_byte = byte_idx % 8;
                    output[out_offset + byte_idx] = @truncate(self.lanes[lane] >> @as(u6, @intCast(lane_byte * 8)));
                    byte_idx += 1;
                }

                out_offset += chunk;
                if (out_offset < output.len) {
                    keccakPLanes(&self.lanes);
                }
            }
        }
    };
}

/// Streaming TurboSHAKE128 state for incremental hashing.
/// Allows processing data in chunks without buffering everything in memory.
/// Usage: init() -> update() (multiple times) -> finalize().
pub const TurboSHAKE128State = TurboSHAKEState(168);

/// Streaming TurboSHAKE256 state for incremental hashing.
/// Allows processing data in chunks without buffering everything in memory.
/// Usage: init() -> update() (multiple times) -> finalize().
pub const TurboSHAKE256State = TurboSHAKEState(136);

/// Process N leaves (8KiB chunks) in parallel - generic version
fn processLeaves(comptime Variant: type, comptime N: usize, data: []const u8, result: *[N * Variant.cv_size]u8) void {
    std.debug.assert(data.len >= N * B);

    const rate_in_lanes: usize = Variant.rate_in_lanes;
    const rate_in_bytes: usize = rate_in_lanes * 8;
    const cv_size: usize = Variant.cv_size;

    // Initialize N all-zero states with cache alignment
    var states: [5][5]@Vector(N, u64) align(CACHE_LINE_SIZE) = undefined;
    inline for (0..5) |x| {
        inline for (0..5) |y| {
            states[x][y] = @splat(0);
        }
    }

    // Process complete blocks
    var j: usize = 0;
    while (j + rate_in_bytes <= B) : (j += rate_in_bytes) {
        addLanesAll(N, &states, data[j..], rate_in_lanes, B / 8);
        keccakP1600timesN(N, &states);
    }

    // Process last incomplete block
    const remaining_lanes = (B - j) / 8;
    if (remaining_lanes > 0) {
        addLanesAll(N, &states, data[j..], remaining_lanes, B / 8);
    }

    // Add suffix 0x0B and padding
    const suffix_pos = Variant.separation_byte_pos;
    const padding_pos = Variant.padding_pos;

    const suffix_splat: @Vector(N, u64) = @splat(0x0B);
    states[suffix_pos.x][suffix_pos.y] ^= suffix_splat;
    const padding_splat: @Vector(N, u64) = @splat(0x8000000000000000);
    states[padding_pos.x][padding_pos.y] ^= padding_splat;

    keccakP1600timesN(N, &states);

    // Extract chaining values from each state
    const lanes_to_extract = cv_size / 8;
    comptime var lane_idx: usize = 0;
    inline while (lane_idx < lanes_to_extract) : (lane_idx += 1) {
        const x = lane_idx % 5;
        const y = lane_idx / 5;
        inline for (0..N) |i| {
            store64(states[x][y][i], result[i * cv_size + lane_idx * 8 ..]);
        }
    }
}

/// Context for processing a batch of leaves in a thread
const LeafBatchContext = struct {
    output_cvs: []u8,
    batch_start: usize,
    batch_count: usize,
    kt_variant: enum { kt128, kt256 },
    view: *const MultiSliceView,
    scratch_buffer: []u8, // Pre-allocated scratch space (no allocations in worker!)
    total_len: usize, // Total length of input data (for boundary checking)
};

/// Helper function to process N leaves in parallel, reducing code duplication
inline fn processNLeaves(
    comptime Variant: type,
    comptime N: usize,
    view: *const MultiSliceView,
    j: usize,
    leaf_buffer: []u8,
    output: []u8,
) void {
    const cv_size = Variant.cv_size;
    if (view.tryGetSlice(j, j + N * B)) |leaf_data| {
        var leaf_cvs: [N * cv_size]u8 = undefined;
        processLeaves(Variant, N, leaf_data, &leaf_cvs);
        @memcpy(output[0..leaf_cvs.len], &leaf_cvs);
    } else {
        view.copyRange(j, j + N * B, leaf_buffer[0 .. N * B]);
        var leaf_cvs: [N * cv_size]u8 = undefined;
        processLeaves(Variant, N, leaf_buffer[0 .. N * B], &leaf_cvs);
        @memcpy(output[0..leaf_cvs.len], &leaf_cvs);
    }
}

/// Process a batch of leaves in a single thread using SIMD (NO ALLOCATIONS!)
fn processLeafBatch(ctx: LeafBatchContext) void {
    const leaf_buffer = ctx.scratch_buffer[0 .. 8 * B];
    const cv_size: usize = if (ctx.kt_variant == .kt128) 32 else 64;
    const cv_scratch = ctx.scratch_buffer[8 * B .. 8 * B + cv_size];

    var cvs_offset: usize = 0;
    var j: usize = ctx.batch_start;
    const batch_end = @min(ctx.batch_start + ctx.batch_count * B, ctx.total_len);

    // Process leaves using SIMD (8x, 4x, 2x, 1x) based on optimal vector length
    while (j < batch_end) {
        const remaining = batch_end - j;

        if (optimal_vector_len >= 8 and remaining >= 8 * B) {
            if (ctx.kt_variant == .kt128) {
                processNLeaves(KT128Variant, 8, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 8 * 32;
            } else {
                processNLeaves(KT256Variant, 8, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 8 * 64;
            }
            j += 8 * B;
        } else if (optimal_vector_len >= 4 and remaining >= 4 * B) {
            if (ctx.kt_variant == .kt128) {
                processNLeaves(KT128Variant, 4, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 4 * 32;
            } else {
                processNLeaves(KT256Variant, 4, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 4 * 64;
            }
            j += 4 * B;
        } else if (optimal_vector_len >= 2 and remaining >= 2 * B) {
            if (ctx.kt_variant == .kt128) {
                processNLeaves(KT128Variant, 2, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 2 * 32;
            } else {
                processNLeaves(KT256Variant, 2, ctx.view, j, leaf_buffer, ctx.output_cvs[cvs_offset..]);
                cvs_offset += 2 * 64;
            }
            j += 2 * B;
        } else {
            // Process single leaf
            const chunk_len = @min(B, batch_end - j);
            if (ctx.view.tryGetSlice(j, j + chunk_len)) |leaf_data| {
                const cv_slice = MultiSliceView.init(leaf_data, &[_]u8{}, &[_]u8{});
                if (ctx.kt_variant == .kt128) {
                    turboSHAKE128MultiSliceToBuffer(&cv_slice, 0x0B, cv_scratch[0..32]);
                    @memcpy(ctx.output_cvs[cvs_offset..][0..32], cv_scratch[0..32]);
                    cvs_offset += 32;
                } else {
                    turboSHAKE256MultiSliceToBuffer(&cv_slice, 0x0B, cv_scratch[0..64]);
                    @memcpy(ctx.output_cvs[cvs_offset..][0..64], cv_scratch[0..64]);
                    cvs_offset += 64;
                }
            } else {
                ctx.view.copyRange(j, j + chunk_len, leaf_buffer[0..chunk_len]);
                const cv_slice = MultiSliceView.init(leaf_buffer[0..chunk_len], &[_]u8{}, &[_]u8{});
                if (ctx.kt_variant == .kt128) {
                    turboSHAKE128MultiSliceToBuffer(&cv_slice, 0x0B, cv_scratch[0..32]);
                    @memcpy(ctx.output_cvs[cvs_offset..][0..32], cv_scratch[0..32]);
                    cvs_offset += 32;
                } else {
                    turboSHAKE256MultiSliceToBuffer(&cv_slice, 0x0B, cv_scratch[0..64]);
                    @memcpy(ctx.output_cvs[cvs_offset..][0..64], cv_scratch[0..64]);
                    cvs_offset += 64;
                }
            }
            j += B;
        }
    }
}

/// Generic single-threaded implementation
fn ktSingleThreaded(comptime Variant: type, view: *const MultiSliceView, total_len: usize, output: []u8) void {
    const cv_size = Variant.cv_size;
    const StateType = Variant.StateType;

    // Initialize streaming TurboSHAKE state for final node
    var final_state = StateType.init();

    // Absorb first B bytes from input
    var first_b_buffer: [B]u8 = undefined;
    if (view.tryGetSlice(0, B)) |first_chunk| {
        final_state.update(first_chunk);
    } else {
        view.copyRange(0, B, &first_b_buffer);
        final_state.update(&first_b_buffer);
    }

    // Absorb padding bytes (8 bytes: 0x03 followed by 7 zeros)
    const padding = [_]u8{ 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    final_state.update(&padding);

    var j: usize = B;
    var n: usize = 0;

    // Temporary buffers for boundary-spanning leaves and CV computation
    var leaf_buffer: [B * 8]u8 align(CACHE_LINE_SIZE) = undefined;
    var cv_buffer: [64]u8 = undefined; // Max CV size is 64 bytes

    // Process 8 leaves in parallel (if optimal for this platform)
    while (optimal_vector_len >= 8 and j + 8 * B <= total_len) {
        if (view.tryGetSlice(j, j + 8 * B)) |leaf_data| {
            var leaf_cvs: [8 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 8, leaf_data, &leaf_cvs);
            final_state.update(&leaf_cvs); // Absorb all 8 CVs at once
        } else {
            view.copyRange(j, j + 8 * B, leaf_buffer[0 .. 8 * B]);
            var leaf_cvs: [8 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 8, leaf_buffer[0 .. 8 * B], &leaf_cvs);
            final_state.update(&leaf_cvs);
        }
        j += 8 * B;
        n += 8;
    }

    // Process 4 leaves in parallel (if optimal for this platform)
    while (optimal_vector_len >= 4 and j + 4 * B <= total_len) {
        if (view.tryGetSlice(j, j + 4 * B)) |leaf_data| {
            var leaf_cvs: [4 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 4, leaf_data, &leaf_cvs);
            final_state.update(&leaf_cvs);
        } else {
            view.copyRange(j, j + 4 * B, leaf_buffer[0 .. 4 * B]);
            var leaf_cvs: [4 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 4, leaf_buffer[0 .. 4 * B], &leaf_cvs);
            final_state.update(&leaf_cvs);
        }
        j += 4 * B;
        n += 4;
    }

    // Process 2 leaves in parallel (if optimal for this platform)
    while (optimal_vector_len >= 2 and j + 2 * B <= total_len) {
        if (view.tryGetSlice(j, j + 2 * B)) |leaf_data| {
            var leaf_cvs: [2 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 2, leaf_data, &leaf_cvs);
            final_state.update(&leaf_cvs);
        } else {
            view.copyRange(j, j + 2 * B, leaf_buffer[0 .. 2 * B]);
            var leaf_cvs: [2 * cv_size]u8 align(CACHE_LINE_SIZE) = undefined;
            processLeaves(Variant, 2, leaf_buffer[0 .. 2 * B], &leaf_cvs);
            final_state.update(&leaf_cvs);
        }
        j += 2 * B;
        n += 2;
    }

    // Process remaining leaves one at a time
    while (j < total_len) {
        const chunk_len = @min(B, total_len - j);
        if (view.tryGetSlice(j, j + chunk_len)) |leaf_data| {
            const cv_slice = MultiSliceView.init(leaf_data, &[_]u8{}, &[_]u8{});
            Variant.turboSHAKEToBuffer(&cv_slice, 0x0B, cv_buffer[0..cv_size]);
            final_state.update(cv_buffer[0..cv_size]); // Absorb CV immediately
        } else {
            view.copyRange(j, j + chunk_len, leaf_buffer[0..chunk_len]);
            const cv_slice = MultiSliceView.init(leaf_buffer[0..chunk_len], &[_]u8{}, &[_]u8{});
            Variant.turboSHAKEToBuffer(&cv_slice, 0x0B, cv_buffer[0..cv_size]);
            final_state.update(cv_buffer[0..cv_size]);
        }
        j += B;
        n += 1;
    }

    // Absorb right_encode(n) and terminator
    const n_enc = rightEncode(n);
    final_state.update(n_enc.slice());
    const terminator = [_]u8{ 0xFF, 0xFF };
    final_state.update(&terminator);

    // Finalize and squeeze output
    final_state.finalize(0x06, output);
}

/// Generic multi-threaded implementation
fn ktMultiThreaded(comptime Variant: type, allocator: std.mem.Allocator, view: *const MultiSliceView, total_len: usize, output: []u8) !void {
    const cv_size = Variant.cv_size;

    // Calculate total number of leaves
    const total_leaves: usize = (total_len - 1) / B;

    // Allocate buffer for all chaining values
    const cvs = try allocator.alloc(u8, total_leaves * cv_size);
    defer allocator.free(cvs);

    // Initialize thread pool
    var pool: Pool = undefined;
    try pool.init(.{ .allocator = allocator });
    defer pool.deinit();

    const thread_count = pool.threads.len;
    if (thread_count == 0) {
        // Single-threaded fallback
        ktSingleThreaded(Variant, view, total_len, output);
        return;
    }

    // Divide work among threads
    const leaves_per_thread = (total_leaves + thread_count - 1) / thread_count;

    // Pre-allocate scratch buffers for all threads (8 leaves + CV size)
    const scratch_size = 8 * B + cv_size;
    const all_scratch = try allocator.alloc(u8, thread_count * scratch_size);
    defer allocator.free(all_scratch);

    var wait_group: WaitGroup = .{};
    var leaves_assigned: usize = 0;
    var thread_idx: usize = 0;

    while (leaves_assigned < total_leaves) {
        const batch_count = @min(leaves_per_thread, total_leaves - leaves_assigned);
        const batch_start = B + leaves_assigned * B;
        const cvs_offset = leaves_assigned * cv_size;

        const ctx = LeafBatchContext{
            .output_cvs = cvs[cvs_offset .. cvs_offset + batch_count * cv_size],
            .batch_start = batch_start,
            .batch_count = batch_count,
            .kt_variant = if (Variant == KT128Variant) .kt128 else .kt256,
            .view = view,
            .scratch_buffer = all_scratch[thread_idx * scratch_size .. (thread_idx + 1) * scratch_size],
            .total_len = total_len,
        };

        pool.spawnWg(&wait_group, processLeafBatch, .{ctx});

        leaves_assigned += batch_count;
        thread_idx += 1;
    }

    // Wait for all threads to complete
    pool.waitAndWork(&wait_group);

    // Build final node
    const n_enc = rightEncode(total_leaves);
    const final_node_len = B + 8 + total_leaves * cv_size + n_enc.len + 2;
    const final_node = try allocator.alloc(u8, final_node_len);
    defer allocator.free(final_node);

    // Copy first B bytes
    if (view.tryGetSlice(0, B)) |first_chunk| {
        @memcpy(final_node[0..B], first_chunk);
    } else {
        view.copyRange(0, B, final_node[0..B]);
    }

    @memset(final_node[B..][0..8], 0);
    final_node[B] = 0x03;
    @memcpy(final_node[B + 8 ..][0 .. total_leaves * cv_size], cvs);
    @memcpy(final_node[B + 8 + total_leaves * cv_size ..][0..n_enc.len], n_enc.slice());
    final_node[final_node_len - 2] = 0xFF;
    final_node[final_node_len - 1] = 0xFF;

    const final_view = MultiSliceView.init(final_node, &[_]u8{}, &[_]u8{});
    Variant.turboSHAKEToBuffer(&final_view, 0x06, output);
}

/// KangarooTwelve with 128-bit security (based on TurboSHAKE128).
/// Provides 128-bit collision and preimage resistance.
pub const KT128 = struct {
    /// Hash a message using sequential processing with SIMD acceleration.
    /// Best performance for inputs under 10MB. Never allocates memory.
    ///
    /// Parameters:
    ///   - message: Input data to hash (any length)
    ///   - customization: Optional domain separation string (or null)
    ///   - out: Output buffer (any length, arbitrary output sizes supported)
    pub fn hash(message: []const u8, customization: ?[]const u8, out: []u8) !void {
        const custom = customization orelse &[_]u8{};

        // Right-encode customization length (stack-allocated, no heap!)
        const custom_len_enc = rightEncode(custom.len);

        // Create zero-copy multi-slice view (no concatenation!)
        const view = MultiSliceView.init(message, custom, custom_len_enc.slice());
        const total_len = view.totalLen();

        // Single chunk case - zero-copy absorption!
        if (total_len <= B) {
            turboSHAKE128MultiSliceToBuffer(&view, 0x07, out);
            return;
        }

        // Tree mode - single-threaded SIMD processing
        ktSingleThreaded(KT128Variant, &view, total_len, out);
    }

    /// Hash with automatic parallelization for large inputs (>3-10MB depending on CPU count).
    /// Automatically uses sequential processing for smaller inputs to avoid thread overhead.
    /// Allocator required for thread pool and temporary buffers.
    pub fn hashParallel(message: []const u8, customization: ?[]const u8, out: []u8, allocator: std.mem.Allocator) !void {
        const custom = customization orelse &[_]u8{};

        const custom_len_enc = rightEncode(custom.len);
        const view = MultiSliceView.init(message, custom, custom_len_enc.slice());
        const total_len = view.totalLen();

        // Single chunk case
        if (total_len <= B) {
            turboSHAKE128MultiSliceToBuffer(&view, 0x07, out);
            return;
        }

        // Use single-threaded processing if below threshold
        const threshold = getLargeFileThreshold();
        if (total_len < threshold) {
            ktSingleThreaded(KT128Variant, &view, total_len, out);
            return;
        }

        // Tree mode - multi-threaded processing
        try ktMultiThreaded(KT128Variant, allocator, &view, total_len, out);
    }
};

/// KangarooTwelve with 256-bit security (based on TurboSHAKE256).
/// Provides 256-bit collision and preimage resistance. Use when you need
/// post-quantum security (NIST level 2) or extra conservative margins.
/// For most applications, KT128 offers better performance with adequate security.
pub const KT256 = struct {
    /// Hash a message using sequential processing with SIMD acceleration.
    /// Best performance for inputs under 10MB. Never allocates memory.
    ///
    /// Parameters:
    ///   - message: Input data to hash (any length)
    ///   - customization: Optional domain separation string (or null)
    ///   - out: Output buffer (any length, arbitrary output sizes supported)
    pub fn hash(message: []const u8, customization: ?[]const u8, out: []u8) !void {
        const custom = customization orelse &[_]u8{};

        const custom_len_enc = rightEncode(custom.len);
        const view = MultiSliceView.init(message, custom, custom_len_enc.slice());
        const total_len = view.totalLen();

        if (total_len <= B) {
            turboSHAKE256MultiSliceToBuffer(&view, 0x07, out);
            return;
        }

        ktSingleThreaded(KT256Variant, &view, total_len, out);
    }

    /// Hash with automatic parallelization for large inputs (>3-10MB depending on CPU count).
    /// Automatically uses sequential processing for smaller inputs to avoid thread overhead.
    /// Allocator required for thread pool and temporary buffers.
    pub fn hashParallel(message: []const u8, customization: ?[]const u8, out: []u8, allocator: std.mem.Allocator) !void {
        const custom = customization orelse &[_]u8{};

        const custom_len_enc = rightEncode(custom.len);
        const view = MultiSliceView.init(message, custom, custom_len_enc.slice());
        const total_len = view.totalLen();

        if (total_len <= B) {
            turboSHAKE256MultiSliceToBuffer(&view, 0x07, out);
            return;
        }

        // Use single-threaded processing if below threshold
        const threshold = getLargeFileThreshold();
        if (total_len < threshold) {
            ktSingleThreaded(KT256Variant, &view, total_len, out);
            return;
        }

        try ktMultiThreaded(KT256Variant, allocator, &view, total_len, out);
    }
};
