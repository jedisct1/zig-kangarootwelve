# KangarooTwelve for Zig

A pure Zig implementation of the KangarooTwelve (K12) cryptographic hash function with support for both sequential and parallel processing.

## About KangarooTwelve

KangarooTwelve is a fast, secure cryptographic hash function based on Keccak (SHA-3). It uses a tree-hashing mode on top of TurboSHAKE, providing both high security and excellent performance, especially on large inputs. K12 supports arbitrary-length output and optional customization strings.

This implementation provides both KT128 (based on TurboSHAKE128) and KT256 (based on TurboSHAKE256).

## Installation

Add this package to your `build.zig.zon`:

```zig
.dependencies = .{
    .kangarootwelve = .{
        .url = "https://github.com/jedisct1/zig-kangarootwelve/archive/refs/tags/v0.0.1.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const kangarootwelve = b.dependency("kangarootwelve", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("kangarootwelve", kangarootwelve.module("kangarootwelve"));
```

## Usage

### Basic Hashing

```zig
const std = @import("std");
const kangarootwelve = @import("kangarootwelve");
const KT128 = kangarootwelve.KT128;

var output: [32]u8 = undefined;
const message = "Hello, KangarooTwelve!";

// Hash with no customization string
try KT128.hash(message, null, &output);

// Or with a customization string
try KT128.hash(message, "my-app-v1", &output);
```

### Variable Output Length

```zig
const KT128 = kangarootwelve.KT128;

// 64-byte output
var output: [64]u8 = undefined;
try KT128.hash(message, null, &output);

// Any output length you need
var large_output: [128]u8 = undefined;
try KT128.hash(message, null, &large_output);
```

### Parallel Hashing

For large inputs (>25-50MB depending on CPU count), parallel processing can significantly improve performance:

```zig
const KT128 = kangarootwelve.KT128;
const allocator = std.heap.page_allocator;
const large_data = try allocator.alloc(u8, 100 * 1024 * 1024); // 100MB
defer allocator.free(large_data);

var output: [32]u8 = undefined;
try KT128.hashParallel(large_data, null, &output, allocator);
```

The implementation automatically adjusts the threshold for parallel processing based on CPU count (25MB for 8+ cores, 35MB for 4-7 cores, 50MB for 1-3 cores).

### Using KT256

```zig
const KT256 = kangarootwelve.KT256;
var output: [64]u8 = undefined;
try KT256.hash(message, null, &output);
```

## API

### `KT128`

A struct providing KangarooTwelve with 128-bit security based on TurboSHAKE128.

#### `hash(message: []const u8, customization: ?[]const u8, out: []u8) !void`

Hashes a message using sequential processing with SIMD optimizations.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null`)
- `out`: Output buffer of any length

#### `hashParallel(message: []const u8, customization: ?[]const u8, out: []u8, allocator: std.mem.Allocator) !void`

Hashes a message with parallel chunk processing. Automatically uses sequential processing for smaller inputs to avoid thread pool overhead.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null`)
- `out`: Output buffer of any length
- `allocator`: Memory allocator for thread pool and intermediate buffers

### `KT256`

Same API as `KT128`, but uses TurboSHAKE256 internally for 256-bit security.

## Performance

The implementation includes optimizations for both small and large inputs:

- Small inputs (≤8KB): Single-pass processing with no chunking overhead
- Medium inputs (8KB - ~50MB): Sequential chunked processing with SIMD acceleration
- Large inputs (>~25-50MB): Parallel processing with dynamic thread pool sizing

Benchmark your specific use case with:

```bash
zig build bench
```

This runs benchmarks on various input sizes and compares sequential vs parallel performance.

## Building and Testing

Build the library:
```bash
zig build
```

Run tests:
```bash
zig build test
```

Run benchmarks:
```bash
zig build bench
```

Build with optimizations:
```bash
zig build -Doptimize=ReleaseFast
```

## References

- [RFC9861 - KangarooTwelve and TurboSHAKE](https://www.rfc-editor.org/info/rfc9861)
