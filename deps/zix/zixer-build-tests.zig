const std = @import("std");

/// Wrap a compiled test artifact in a Run step when the target can execute on
/// this host, otherwise return the compile step directly. Deterministic
/// compile-only coverage for a foreign target regardless of host binfmt_misc /
/// qemu registration making execution technically possible.
///
/// Note:
/// - name tags the step with its source path, so `--summary all` shows which
///   test file a pending or hung step belongs to.
fn testRunStep(b: *std.Build, exe: *std.Build.Step.Compile, foreign: bool, name: []const u8) *std.Build.Step {
    if (foreign) {
        exe.step.name = name;
        return &exe.step;
    }

    const run = b.addRunArtifact(exe);
    run.setName(name);

    return &run.step;
}

/// Wire `zig build zixer-unit-test`: every in-file test under src/zixer.
///
/// Note:
/// - zixer is its own executable root, not reachable from the zix module, so
///   its tests get their own module with the zix import. A new src/zixer file
///   with tests needs a refAllDecls line in src/zixer/zixer.zig to be found.
///
/// Param:
/// zix - *std.Build.Module (the engine module zixer links)
///
/// Return:
/// - void
pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
) void {
    // Foreign target (e.g. -Dtarget=x86_64-windows on a Linux host): the suite
    // still compiles for the target, so the step is compile coverage there.
    const host = b.graph.host.result;
    const foreign_target = target.result.os.tag != host.os.tag or target.result.cpu.arch != host.cpu.arch;
    if (foreign_target) {
        std.log.info("zixer tests: target {s}-{s} is foreign to this host, the suite compiles but execution is skipped", .{
            @tagName(target.result.cpu.arch), @tagName(target.result.os.tag),
        });
    }

    const zixer_mod = b.createModule(.{
        .root_source_file = b.path("src/zixer/zixer.zig"),
        .target = target,
        .optimize = optimize,
    });
    zixer_mod.addImport("zix", zix);

    const zixer_tests = b.addTest(.{ .root_module = zixer_mod });

    const test_step = b.step("zixer-unit-test", "Run the zixer unit tests");
    test_step.dependOn(testRunStep(b, zixer_tests, foreign_target, "src/zixer/zixer.zig"));

    // The proxy runner's own helpers carry their tests in file. They import std
    // only, not zix, so each gets its own module rather than riding on the
    // zixer one.
    inline for (.{
        "tests/zixer/child_stderr.zig",
        "tests/zixer/root_setup.zig",
        "tests/zixer/row_isolate.zig",
    }) |src| {
        const helper_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });

        const helper_tests = b.addTest(.{ .root_module = helper_mod });
        test_step.dependOn(testRunStep(b, helper_tests, foreign_target, src));
    }
}
