const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("kangarootwelve", .{
        .root_source_file = b.path("src/kangarootwelve.zig"),
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/kangarootwelve.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "kangarootwelve",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const test_step = b.step("test", "Run unit tests");
    const kangarootwelve_test_mod = b.createModule(.{
        .root_source_file = b.path("src/kangarootwelve.zig"),
        .target = target,
        .optimize = optimize,
    });
    const kangarootwelve_tests = b.addTest(.{
        .name = "kangarootwelve_test",
        .root_module = kangarootwelve_test_mod,
    });
    const run_kangarootwelve_tests = b.addRunArtifact(kangarootwelve_tests);
    test_step.dependOn(&run_kangarootwelve_tests.step);

    const benchmark_step = b.step("bench", "Run benchmarks");
    const benchmark_mod = b.createModule(.{
        .root_source_file = b.path("src/benchmark.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    benchmark_mod.addImport("kangarootwelve", lib_mod);
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_mod,
    });
    const run_benchmark = b.addRunArtifact(benchmark_exe);
    benchmark_step.dependOn(&run_benchmark.step);
    const install_benchmark = b.addInstallArtifact(benchmark_exe, .{});
    b.getInstallStep().dependOn(&install_benchmark.step);
}
