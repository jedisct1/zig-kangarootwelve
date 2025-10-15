# KangarooTwelve for Zig

A pure Zig implementation of the KangarooTwelve (K12, RFC9861) cryptographic hash function with support for both sequential and parallel processing.

## About KangarooTwelve

KangarooTwelve is a fast, secure cryptographic hash function based on Keccak (SHA-3). It uses a tree-hashing mode on top of TurboSHAKE, providing both high security and excellent performance, especially on large inputs. K12 supports arbitrary-length output and optional customization strings.

This implementation follows the specification from [RFC9861](https://www.rfc-editor.org/info/rfc9861) and provides both KT128 (based on TurboSHAKE128) and KT256 (based on TurboSHAKE256).

## Installation

Add this package to your `build.zig.zon`:

```zig
.dependencies = .{
    .kangarootwelve = .{
        .url = "https://github.com/jedisct1/zig-kangarootwelve/archive/refs/tags/v0.0.3.tar.gz",
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

For large inputs (>3-10MB depending on CPU count), parallel processing can significantly improve performance:

```zig
const KT128 = kangarootwelve.KT128;
const allocator = std.heap.page_allocator;
const large_data = try allocator.alloc(u8, 100 * 1024 * 1024); // 100MB
defer allocator.free(large_data);

var output: [32]u8 = undefined;
try KT128.hashParallel(large_data, null, &output, allocator);
```

The implementation automatically adjusts the threshold for parallel processing based on CPU count (3MB for 8+ cores, 5MB for 4-7 cores, 10MB for 1-3 cores).

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
- Medium inputs (8KB - ~10MB): Sequential chunked processing with SIMD acceleration
- Large inputs (>~3-10MB depending on CPU count): Parallel processing with dynamic thread pool sizing

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

## Benchmarks

### AMD Zen4

```
============================================================================================
SUMMARY TABLE - All throughput values in MB/s
============================================================================================
Size         Chunks |      SHA256      BLAKE3  TurboSH128   KT128-Seq   KT128-Par
---------- -------- + ----------- ----------- ----------- ----------- -----------
64 B              1 |      877.62      470.51       61.89       59.48       59.80
1 KB              1 |     1484.82      714.74      136.46      126.45      126.48
8 KB              1 |     1559.00     3709.25      154.39      149.12      147.54
64 KB             8 |     1559.35     5036.71      154.60      520.04      508.55
1 MB            128 |     1567.01     5144.95      154.76     2941.47     2936.58
10 MB          1280 |     1565.84     5108.57      154.89     4087.65     8793.01
100 MB        12800 |     1566.07     3498.71      154.84     4160.97    16311.17
200 MB        25600 |     1566.67     3407.62      155.04     4162.84    16945.26
============================================================================================
```

### Apple M1

```
============================================================================================
SUMMARY TABLE - All throughput values in MB/s
============================================================================================
Size         Chunks |      SHA256      BLAKE3  TurboSH128   KT128-Seq   KT128-Par
---------- -------- + ----------- ----------- ----------- ----------- -----------
64 B              1 |     1123.23      454.68       52.52       51.18       51.58
1 KB              1 |     2152.39      709.82      116.86      111.26      111.89
8 KB              1 |     2237.38     1431.75      130.85      125.93      122.94
64 KB             8 |     2243.63     1486.59      131.17      434.18      429.40
1 MB            128 |     2275.36     1450.53      131.27     1866.78     1873.17
10 MB          1280 |     2207.42     1448.12      131.43     2333.22     4696.49
100 MB        12800 |     2228.88     1466.28      131.13     2357.10     9633.45
200 MB        25600 |     2269.14     1469.63      131.17     2373.58     9726.21
============================================================================================
```
