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

// Create a KT128 hasher with 32-byte output
const KT128_32 = kangarootwelve.KT128(32);

var output: [32]u8 = undefined;
const message = "Hello, KangarooTwelve!";

// Hash with no customization string
try KT128_32.hash(message, null, &output);

// Or with a customization string
try KT128_32.hash(message, "my-app-v1", &output);
```

### Variable Output Length

```zig
// 64-byte output
const KT128_64 = kangarootwelve.KT128(64);
var output: [64]u8 = undefined;
try KT128_64.hash(message, null, &output);

// Any output length you need
const KT128_128 = kangarootwelve.KT128(128);
var large_output: [128]u8 = undefined;
try KT128_128.hash(message, null, &large_output);
```

### Parallel Hashing

For large inputs (>50MB), parallel processing can significantly improve performance:

```zig
const allocator = std.heap.page_allocator;
const large_data = try allocator.alloc(u8, 100 * 1024 * 1024); // 100MB
defer allocator.free(large_data);

var output: [32]u8 = undefined;
try KT128_32.hashParallel(large_data, null, &output, allocator);
```

The implementation automatically uses sequential processing for smaller inputs (≤50MB) to avoid thread pool overhead.

### Using KT256

```zig
const KT256_64 = kangarootwelve.KT256(64);
var output: [64]u8 = undefined;
try KT256_64.hash(message, null, &output);
```

## API

### `KT128(comptime output_len: usize)`

Returns a type with the following methods:

#### `hash(message: []const u8, customization: ?[]const u8, out: *[output_len]u8) !void`

Hashes a message using sequential processing.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null` or empty)
- `out`: Output buffer of the specified length

#### `hashParallel(message: []const u8, customization: ?[]const u8, out: *[output_len]u8, allocator: std.mem.Allocator) !void`

Hashes a message with parallel chunk processing. Automatically falls back to sequential processing for inputs ≤50MB.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null` or empty)
- `out`: Output buffer of the specified length
- `allocator`: Memory allocator for thread pool and intermediate buffers

### `KT256(comptime output_len: usize)`

Same API as `KT128`, but uses TurboSHAKE256 internally for higher security margin.

## Performance

The implementation includes optimizations for both small and large inputs:

- Small inputs (≤8KB): Single-pass processing with no chunking overhead
- Medium inputs (8KB-50MB): Sequential chunked processing
- Large inputs (>50MB): Parallel processing with up to 256 threads

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
