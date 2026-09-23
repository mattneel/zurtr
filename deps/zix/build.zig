const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for zix source.
///
/// Note:
/// - Do not create in other place!
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

// --------------------------------------------------------- //

/// Fail the build with a readable message when the compiler is neither Zig 0.16.x
/// nor 0.17.x, instead of a deep version-specific type error.
///
/// Note:
/// - The std.Build API around the build root moved between these two versions, so
///   dirExists below comptime-branches on the same check. Anything outside this
///   range needs its own port first (see the Zig version decision in the roadmap).
fn ensureSupportedZig() void {
    if (ZIG_SEMVER.MAJOR == 0 and (ZIG_SEMVER.MINOR == 16 or ZIG_SEMVER.MINOR == 17)) return;

    @compileError(std.fmt.comptimePrint(
        "zix build requires Zig 0.16.x or 0.17.x, found {d}.{d}.{d}. " ++
            "Use zig-0.16 (or a 0.17 toolchain).",
        .{ ZIG_SEMVER.MAJOR, ZIG_SEMVER.MINOR, ZIG_SEMVER.PATCH },
    ));
}

/// Whether a directory exists under the build root. Gates the dev-only steps so
/// the package builds cleanly as a fetched dependency that ships only src/.
///
/// Note:
/// - The build-root handle moved between Zig versions: 0.16 exposes b.build_root
///   (a Cache.Directory), 0.17 exposes b.root (a Cache.Path) whose root_dir holds
///   the handle. The comptime branch picks the right field so the same
///   Io.Dir.access call serves both. It uses the build root, not cwd, so the check
///   stays correct when zix is a fetched dependency.
fn dirExists(b: *std.Build, sub_path: []const u8) bool {
    const root_handle = if (comptime ZIG_SEMVER.MINOR == 16)
        b.build_root.handle
    else
        b.root.root_dir.handle;

    root_handle.access(b.graph.io, sub_path, .{}) catch return false;

    return true;
}

// --------------------------------------------------------- //

pub fn build(b: *std.Build) void {
    ensureSupportedZig();

    const zon = @import("build.zig.zon");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zix = b.addModule("zix", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --------------------------------------------------------- //

    const zon_options = b.addOptions();
    zon_options.addOption([]const u8, "user_agent", zon.user_agent);
    zon_options.addOption([]const u8, "version", zon.version);
    zix.addOptions("zon_options", zon_options);

    // --------------------------------------------------------- //

    // Brotli's static dictionary (RFC 7932 Appendix A) is generated at build time into the
    // cache by brotli_dictionary.gen.zig and bound to the @embedFile import in brotli.zig, so
    // no binary asset is tracked and no .gitignore exception is needed. Compiling the codec
    // depends on this run through the import, so any `zig build` target that builds zix
    // regenerates the dictionary first.
    const brotli_dict_gen = b.addExecutable(.{
        .name = "brotli_dictionary_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/utils/compression/brotli_dictionary.gen.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const brotli_dict_run = b.addRunArtifact(brotli_dict_gen);
    const brotli_dict = brotli_dict_run.addOutputFileArg("brotli_dictionary.bin");
    zix.addAnonymousImport("brotli_dictionary.bin", .{ .root_source_file = brotli_dict });

    // --------------------------------------------------------- //

    // Dev-only steps (tests, examples, test-runners) are wired only when their
    // source directories are present. When zix is consumed as a fetched
    // dependency the package ships src/ plus these build helpers but not tests/
    // or examples/, so the helper imports still resolve (compile-time) while the
    // steps that reference the missing directories are skipped (run-time).
    const have_tests = dirExists(b, "tests");
    const have_examples = dirExists(b, "examples");

    if (have_tests) {
        @import("zix-build-tests.zig").addSteps(b, target, optimize, zix);
    } else {
        std.log.info("zix build: tests/ not found, skipping test steps (unit/integration/behaviour/edge)", .{});
    }

    if (have_examples) {
        @import("zix-build-examples.zig").addSteps(b, target, optimize, zix);
    } else {
        std.log.info("zix build: examples/ not found, skipping example steps", .{});
    }

    // The test-runners spawn example servers, so they need both directories.
    if (have_tests and have_examples) {
        @import("zix-build-test_runner.zig").addSteps(b, target, optimize, zix);
    } else {
        std.log.info("zix build: tests/ + examples/ required for test-runner steps, skipping", .{});
    }

    // --------------------------------------------------------- //

    // zixer keeps its own build files (zixer-build*.zig): the executable ships
    // with the package, its demo upstreams and runner are gated on the same
    // directories zix gates on.
    @import("zixer-build.zig").addSteps(b, target, optimize, zix, have_examples, have_tests);

    // --------------------------------------------------------- //

    // Per-test bound handed to every nested package suite that runs without a container.
    // A test hung mid-body waits forever on its own, and a nested zig build buffers the child's
    // stderr until it finishes, so a hang inside such a suite reports nothing at all: one CI leg
    // sat 27 minutes on a driver suite and the log never named a test. With this, zig kills the
    // hung test, prints its name and captured stderr, and carries on to the next one.
    // The container suites (test-integration, test-runner) are left alone: they own a container
    // lifecycle and are legitimately slower than any bound that fits an in-process test.
    // Same value the zix suites carry in the native workflows, and for the same reason. A leg on a
    // slow host (the qemu CI VMs) widens it with -Ddriver-test-timeout, native legs keep the default.
    // The option keeps its original name because the CI legs pass it by that name.
    const package_test_timeout = b.option(
        []const u8,
        "driver-test-timeout",
        "Per-test bound for the container-free driver suites and jzon (default 15s)",
    ) orelse "15s";

    // --------------------------------------------------------- //

    // jzon is a standalone package (src/jzon, own build.zig): these steps
    // delegate into it with the same compiler. It needs no server and no
    // container, so every tier runs on every supported target.
    if (dirExists(b, "src/jzon")) {
        const jzon_unit = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-unit", "--test-timeout", package_test_timeout });
        jzon_unit.setCwd(b.path("src/jzon"));

        const jzon_unit_step = b.step("jzon-test-unit", "Run the jzon in-file tests (src/jzon/src)");
        jzon_unit_step.dependOn(&jzon_unit.step);

        const jzon_behaviour = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-behaviour", "--test-timeout", package_test_timeout });
        jzon_behaviour.setCwd(b.path("src/jzon"));

        const jzon_behaviour_step = b.step("jzon-test-behaviour", "Run the jzon behaviour tests");
        jzon_behaviour_step.dependOn(&jzon_behaviour.step);

        const jzon_edge = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-edge", "--test-timeout", package_test_timeout });
        jzon_edge.setCwd(b.path("src/jzon"));

        const jzon_edge_step = b.step("jzon-test-edge", "Run the jzon edge tests");
        jzon_edge_step.dependOn(&jzon_edge.step);

        const jzon_all = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-all", "--test-timeout", package_test_timeout });
        jzon_all.setCwd(b.path("src/jzon"));

        const jzon_all_step = b.step("jzon-test-all", "Run every jzon test: in-file, behaviour and edge");
        jzon_all_step.dependOn(&jzon_all.step);

        const jzon_examples = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "examples" });
        jzon_examples.setCwd(b.path("src/jzon"));

        const jzon_examples_step = b.step("jzon-examples", "Build every jzon example into src/jzon/zig-out/bin");
        jzon_examples_step.dependOn(&jzon_examples.step);
    }

    // postgrez is a standalone package (src/driver/postgrez, own build.zig):
    // these steps delegate into it with the same compiler.
    if (dirExists(b, "src/driver/postgrez")) {
        const postgrez_unit = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-unit", "--test-timeout", package_test_timeout });
        postgrez_unit.setCwd(b.path("src/driver/postgrez"));

        const postgrez_unit_step = b.step("postgrez-test-unit", "Run the postgrez driver unit tests (no server needed)");
        postgrez_unit_step.dependOn(&postgrez_unit.step);

        const postgrez_behaviour = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-behaviour", "--test-timeout", package_test_timeout });
        postgrez_behaviour.setCwd(b.path("src/driver/postgrez"));

        const postgrez_behaviour_step = b.step("postgrez-test-behaviour", "Run the postgrez driver behaviour tests against its in-process server (no container)");
        postgrez_behaviour_step.dependOn(&postgrez_behaviour.step);

        const postgrez_edge = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-edge", "--test-timeout", package_test_timeout });
        postgrez_edge.setCwd(b.path("src/driver/postgrez"));

        const postgrez_edge_step = b.step("postgrez-test-edge", "Run the postgrez driver edge tests against its in-process server (no container)");
        postgrez_edge_step.dependOn(&postgrez_edge.step);

        const postgrez_integration = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-integration" });
        postgrez_integration.setCwd(b.path("src/driver/postgrez"));

        const postgrez_integration_step = b.step("postgrez-test-integration", "Run the postgrez driver integration tests (owns the PG 18 container lifecycle)");
        postgrez_integration_step.dependOn(&postgrez_integration.step);

        const postgrez_runner = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-runner" });
        postgrez_runner.setCwd(b.path("src/driver/postgrez"));

        const postgrez_runner_step = b.step("postgrez-test-runner", "Run every postgrez example against the PG 18 container (owns the lifecycle)");
        postgrez_runner_step.dependOn(&postgrez_runner.step);
    }

    // --------------------------------------------------------- //

    // rediz is a standalone package (src/driver/rediz, own build.zig):
    // these steps delegate into it with the same compiler.
    if (dirExists(b, "src/driver/rediz")) {
        const rediz_unit = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-unit", "--test-timeout", package_test_timeout });
        rediz_unit.setCwd(b.path("src/driver/rediz"));

        const rediz_unit_step = b.step("rediz-test-unit", "Run the rediz driver unit tests (no server needed)");
        rediz_unit_step.dependOn(&rediz_unit.step);

        const rediz_behaviour = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-behaviour", "--test-timeout", package_test_timeout });
        rediz_behaviour.setCwd(b.path("src/driver/rediz"));

        const rediz_behaviour_step = b.step("rediz-test-behaviour", "Run the rediz driver behaviour tests against its in-process server (no container)");
        rediz_behaviour_step.dependOn(&rediz_behaviour.step);

        const rediz_edge = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-edge", "--test-timeout", package_test_timeout });
        rediz_edge.setCwd(b.path("src/driver/rediz"));

        const rediz_edge_step = b.step("rediz-test-edge", "Run the rediz driver edge tests against its in-process server (no container)");
        rediz_edge_step.dependOn(&rediz_edge.step);

        const rediz_integration = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-integration" });
        rediz_integration.setCwd(b.path("src/driver/rediz"));

        const rediz_integration_step = b.step("rediz-test-integration", "Run the rediz driver integration tests (owns the Redis 8 container lifecycle)");
        rediz_integration_step.dependOn(&rediz_integration.step);

        const rediz_runner = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-runner" });
        rediz_runner.setCwd(b.path("src/driver/rediz"));

        const rediz_runner_step = b.step("rediz-test-runner", "Run every rediz example against the Redis 8 container (owns the lifecycle)");
        rediz_runner_step.dependOn(&rediz_runner.step);
    }

    // --------------------------------------------------------- //

    // prometheuz is a standalone package (src/driver/prometheuz, own build.zig):
    // these steps delegate into it with the same compiler. It has no
    // test-integration: its container coverage lives in test-runner, and the
    // docker-free behaviour and edge suites cover the rest.
    if (dirExists(b, "src/driver/prometheuz")) {
        const prometheuz_unit = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-unit", "--test-timeout", package_test_timeout });
        prometheuz_unit.setCwd(b.path("src/driver/prometheuz"));

        const prometheuz_unit_step = b.step("prometheuz-test-unit", "Run the prometheuz driver unit tests (no server needed)");
        prometheuz_unit_step.dependOn(&prometheuz_unit.step);

        const prometheuz_behaviour = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-behaviour", "--test-timeout", package_test_timeout });
        prometheuz_behaviour.setCwd(b.path("src/driver/prometheuz"));

        const prometheuz_behaviour_step = b.step("prometheuz-test-behaviour", "Run the prometheuz driver behaviour tests against its in-process server (no container)");
        prometheuz_behaviour_step.dependOn(&prometheuz_behaviour.step);

        const prometheuz_edge = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test-edge", "--test-timeout", package_test_timeout });
        prometheuz_edge.setCwd(b.path("src/driver/prometheuz"));

        const prometheuz_edge_step = b.step("prometheuz-test-edge", "Run the prometheuz driver edge tests against its in-process server (no container)");
        prometheuz_edge_step.dependOn(&prometheuz_edge.step);
    }
}
