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
        .url = "https://github.com/jedisct1/zig-kangarootwelve/archive/refs/tags/v0.0.5.tar.gz",
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

### Incremental Hashing

For streaming data or when you need to hash data incrementally:

```zig
const KT128 = kangarootwelve.KT128;

// Initialize with optional customization string (no allocator needed)
var hasher = KT128.init(null);

// Add data incrementally
hasher.update("Hello, ");
hasher.update("Kangaroo");
hasher.update("Twelve!");

// Finalize and get output
var output: [32]u8 = undefined;
hasher.final(&output);
```

The incremental API requires no allocator and uses only fixed-size stack buffers. You can hash arbitrarily large messages by calling `update()` multiple times.

### Using KT256

```zig
const KT256 = kangarootwelve.KT256;
var output: [64]u8 = undefined;
try KT256.hash(message, null, &output);
```

KT256 also supports the incremental API:

```zig
var hasher = KT256.init("optional-customization");
hasher.update(data);
var output: [64]u8 = undefined;
hasher.final(&output);
```

## API

### `KT128`

KT128 is a stateful type providing KangarooTwelve with 128-bit security based on TurboSHAKE128.

#### Incremental Hashing API

##### `init(customization: ?[]const u8) KT128`

Initialize a new hashing context. No allocator required.

- `customization`: Optional customization string for domain separation (can be `null`)
- Returns: A new `KT128` instance

##### `update(self: *KT128, data: []const u8) void`

Absorb data into the hash state. Can be called multiple times to incrementally add data.

- `data`: Input data to absorb

##### `final(self: *KT128, out: []u8) void`

Finalize the hash and produce output. After calling this, the context should not be reused.

- `out`: Output buffer of any length (arbitrary sizes supported)

#### One-Shot Hashing API

##### `hash(message: []const u8, customization: ?[]const u8, out: []u8) !void`

Hashes a message using sequential processing with SIMD optimizations.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null`)
- `out`: Output buffer of any length

##### `hashParallel(message: []const u8, customization: ?[]const u8, out: []u8, allocator: std.mem.Allocator) !void`

Hashes a message with parallel chunk processing. Automatically uses sequential processing for smaller inputs to avoid thread pool overhead.

- `message`: Input data to hash
- `customization`: Optional customization string (can be `null`)
- `out`: Output buffer of any length
- `allocator`: Memory allocator for thread pool and intermediate buffers

### `KT256`

KT256 is a stateful type with the same API as `KT128`, but uses TurboSHAKE256 internally for 256-bit security. All methods (`init`, `update`, `final`, `hash`, `hashParallel`) work identically.

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
64 B              1 |      878.24      523.53       97.42      395.50      293.91      295.34
1 KB              1 |     1486.90      720.74      521.66      931.96      477.53      478.87
8 KB              1 |     1553.39     3691.62     2924.73     1070.49      993.06      919.36
64 KB             8 |     1566.99     5020.52     4800.96     1075.00     1681.94     1656.39
1 MB            128 |     1565.47     5133.86     5113.38     1073.80     4219.76     4204.44
10 MB          1280 |     1561.68     5120.92     9344.03     1074.22     4627.68    11656.27
100 MB        12800 |     1563.46     3481.63    14390.99     1074.64     4560.84    24914.64
200 MB        25600 |     1563.00     3380.68    16670.07     1075.43     4557.86    26870.09
==========================================================================================================
```

### Apple M1

```
==========================================================================================================
SUMMARY TABLE - All throughput values in MB/s
==========================================================================================================
Size         Chunks |      SHA256      BLAKE3  BLAKE3-Par  TurboSH128   KT128-Seq   KT128-Par
---------- -------- + ----------- ----------- ----------- ----------- ----------- -----------
64 B              1 |     1172.13      574.66       60.64      506.88      356.59      356.00
1 KB              1 |     2179.96      747.71      440.60     1262.64      598.69      598.90
8 KB              1 |     2294.30     1465.83     1241.32     1452.02     1337.35     1150.79
64 KB             8 |     2311.54     1508.80     1471.13     1464.32     1713.64     1665.33
1 MB            128 |     2309.67     1511.87     1504.40     1453.29     2572.95     2561.34
10 MB          1280 |     2307.63     1509.54     5229.25     1442.97     2626.67     9356.03
100 MB        12800 |     2310.07     1508.31     7632.71     1443.38     2643.04    12152.51
200 MB        25600 |     2311.98     1509.60     8419.46     1443.25     2601.17    13479.36
==========================================================================================================
```
