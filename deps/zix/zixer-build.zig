const std = @import("std");

/// Wire every zixer build step: the executable, its demo upstreams, its unit
/// tests, and its example runner.
///
/// Note:
/// - zixer is a standalone executable rooted at src/zixer. It links the zix
///   module and never joins the library surface, so its build lives in its own
///   zixer-build-*.zig files rather than in zix's.
/// - The installed binary carries the target triplet and the optimize mode
///   (zixer-<arch>-<os>-<optimize>) like the examples, so building several
///   targets or several modes in a row never overwrites a prior binary in
///   zig-out/bin. The step name stays `zixer`.
///
/// Param:
/// zix - *std.Build.Module (the engine module zixer links)
/// have_examples - bool (examples/ is present, so the demo steps can be wired)
/// have_tests - bool (tests/ is present, so the test steps can be wired)
///
/// Return:
/// - void
pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
    have_examples: bool,
    have_tests: bool,
) void {
    const triple = b.fmt("{s}-{s}", .{ @tagName(target.result.cpu.arch), @tagName(target.result.os.tag) });

    // The optimize mode, lowercased, is the last part of every installed name.
    // No -Doptimize means Debug, so a plain `zig build zixer` writes -debug.
    // Spelled out rather than lowercased at runtime so a new mode is a compile
    // error here.
    const mode = switch (optimize) {
        .Debug => "debug",
        .ReleaseSafe => "releasesafe",
        .ReleaseFast => "releasefast",
        .ReleaseSmall => "releasesmall",
    };

    const zixer_mod = b.createModule(.{
        .root_source_file = b.path("src/zixer/zixer.zig"),
        .target = target,
        .optimize = optimize,
    });
    zixer_mod.addImport("zix", zix);

    const exe = b.addExecutable(.{
        .name = b.fmt("zixer-{s}-{s}", .{ triple, mode }),
        .root_module = zixer_mod,
    });

    const install = b.addInstallArtifact(exe, .{});
    const build_step = b.step("zixer", "Build the zixer proxy gateway executable (run it from zig-out/bin)");
    build_step.dependOn(&install.step);

    // --------------------------------------------------------- //

    if (have_examples) {
        @import("zixer-build-examples.zig").addSteps(b, target, optimize, zix);
    } else {
        std.log.info("zixer build: examples/ not found, skipping the proxy demo steps", .{});
    }

    if (have_tests) {
        @import("zixer-build-tests.zig").addSteps(b, target, optimize, zix);
    } else {
        std.log.info("zixer build: tests/ not found, skipping zixer-unit-test", .{});
    }

    // The runner starts real sites in front of real upstreams, so it needs both
    // directories.
    if (have_examples and have_tests) {
        @import("zixer-build-test_runner.zig").addSteps(b, target, optimize, zix, exe);
    } else {
        std.log.info("zixer build: tests/ + examples/ required for zixer-test-runner-all, skipping", .{});
    }
}
