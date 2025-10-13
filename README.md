# KangarooTwelve for Zig

A pure Zig implementation of the KangarooTwelve cryptographic hash function with support for both sequential and parallel processing.

## About KangarooTwelve

KangarooTwelve is a fast, secure cryptographic hash function based on Keccak (SHA-3). It uses a tree-hashing mode on top of TurboSHAKE, providing both high security and excellent performance, especially on large inputs. K12 supports arbitrary-length output and optional customization strings.

This implementation follows the specification from [RFC9861](https://www.rfc-editor.org/info/rfc9861) and provides both KT128 (based on TurboSHAKE128) and KT256 (based on TurboSHAKE256).

## Security

KangarooTwelve inherits its security foundation from over 15 years of intensive cryptanalysis of the Keccak permutation, the same primitive underlying SHA-3. This is not a new untested algorithm, but rather a performance-optimized variant of one of the most scrutinized cryptographic primitives in history.

### Proven Cryptographic Foundation

Keccak underwent rigorous analysis during the SHA-3 competition (2008-2012), where it was evaluated by the world's leading cryptographers before being selected by NIST as the SHA-3 standard. The scrutiny hasn't stopped: cryptanalysts continue to study Keccak-based functions, with the most recent significant analysis published at CRYPTO 2024. After all these years of analysis, Keccak's security remains solid.

KangarooTwelve uses the Keccak-p[1600,12] permutation with 12 rounds, exactly half the 24 rounds used in SHA-3. This design choice was made by the original Keccak team themselves, who leveraged their deep understanding of the permutation's security properties. Any cryptanalysis of Keccak directly applies to understanding K12's security.

### Security Strength and Margin

K12 provides 128-bit security strength, equivalent to AES-128 and SHAKE128, which is sufficient for virtually all applications. For post-quantum security, K12 achieves NIST's security level 2 when using at least 256-bit outputs.

The current state of cryptanalysis shows attacks reaching 6 rounds of the Keccak permutation, leaving K12's 12 rounds with a substantial security margin. While this margin is smaller than SHA-3's (which has 24 rounds), it reflects a deliberate engineering trade-off: K12 sacrifices some conservative margin for significantly better performance, while maintaining strong practical security.

### Standardization

The KangarooTwelve draft was proposed in 2016 and underwent 8 years of public scrutiny before being standardized as RFC 9861 in 2025.

## Installation

Add this package to your `build.zig.zon`:

```zig
.dependencies = .{
    .kangarootwelve = .{
        .url = "https://github.com/jedisct1/zig-kangarootwelve/archive/refs/tags/v0.0.4.tar.gz",
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
==========================================================================================================
SUMMARY TABLE - All throughput values in MB/s
==========================================================================================================
Size         Chunks |      SHA256      BLAKE3  BLAKE3-Par  TurboSH128   KT128-Seq   KT128-Par
---------- -------- + ----------- ----------- ----------- ----------- ----------- -----------
64 B              1 |      886.45      493.15       97.05       61.67       60.28       59.82
1 KB              1 |     1480.55      716.32      522.03      135.59      129.36      126.47
8 KB              1 |     1552.79     3710.38     2939.49      153.36      149.21      147.78
64 KB             8 |     1560.26     5055.30     4841.84      153.82      520.00      519.01
1 MB            128 |     1553.59     5154.53     5135.42      154.09     2951.80     2943.77
10 MB          1280 |     1552.22     5120.61     9290.73      154.10     4095.22     8772.59
100 MB        12800 |     1550.26     3472.76    14522.02      154.13     4175.98    16303.21
200 MB        25600 |     1552.33     3364.33    16828.39      154.07     4177.91    17415.85
==========================================================================================================
```

### Apple M1

```
==========================================================================================================
SUMMARY TABLE - All throughput values in MB/s
==========================================================================================================
Size         Chunks |      SHA256      BLAKE3  BLAKE3-Par  TurboSH128   KT128-Seq   KT128-Par
---------- -------- + ----------- ----------- ----------- ----------- ----------- -----------
64 B              1 |     1176.04      579.42       61.24       54.67       38.57       53.16
1 KB              1 |     2192.50      749.92      444.65      120.36      115.74      115.73
8 KB              1 |     2311.35     1482.12     1272.15      136.64      131.97      129.82
64 KB             8 |     2316.64     1507.86     1476.09      136.43      453.05      450.06
1 MB            128 |     2316.87     1516.27     1506.68      136.56     1921.60     1917.15
10 MB          1280 |     2293.97     1510.00     5164.18      136.35     2377.08     7515.50
100 MB        12800 |     2321.91     1518.90     7087.93      136.21     2444.09     9870.69
200 MB        25600 |     2309.76     1518.42     8022.78      136.58     2468.34     9471.04
==========================================================================================================
```
