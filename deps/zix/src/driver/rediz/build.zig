const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for the rediz build.
///
/// Note:
/// - Mirror of the check in src/lib.zig, kept local because build.zig cannot
///   import the module it builds.
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

/// Examples built into zig-out/bin and verified by tests/runner.zig.
const example_names = [_][]const u8{
    "basic_connect",
    "url_connect",
    "strings_keyspace",
    "typed_json",
    "raw_command",
    "connection_pool",
    "pipeline_batch",
    "tls_connect",
    "error_handling",
};

// --------------------------------------------------------- //

/// Fail the build with a readable message when the compiler is neither Zig 0.16.x
/// nor 0.17.x, instead of a deep version-specific type error.
fn ensureSupportedZig() void {
    if (ZIG_SEMVER.MAJOR == 0 and (ZIG_SEMVER.MINOR == 16 or ZIG_SEMVER.MINOR == 17)) return;

    @compileError(std.fmt.comptimePrint(
        "rediz build requires Zig 0.16.x or 0.17.x, found {d}.{d}.{d}. " ++
            "Use zig-0.16 (or a 0.17 toolchain).",
        .{ ZIG_SEMVER.MAJOR, ZIG_SEMVER.MINOR, ZIG_SEMVER.PATCH },
    ));
}

/// Container start pipeline: build the image, replace any old container,
/// run detached. Rootless podman through the docker compat. The returned
/// step is the running container, callers hang their suite on it and hang a
/// teardown (addContainerTeardown) after the suite.
///
/// Note:
/// - test-integration and test-runner each get their OWN pipeline but share
///   the container name and ports: run them in separate invocations. On a
///   failed run the container stays up, the next run's pre-clean (or
///   `docker rm -f zix-rediz-r8`) removes it.
fn addContainerStart(b: *std.Build) *std.Build.Step.Run {
    const image_build = b.addSystemCommand(&.{
        "docker", "build", "-t", "zix-rediz-r8-img", "../../../containers/redis",
    });

    const pre_clean = b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-rediz-r8 >/dev/null 2>&1 || true",
    });
    pre_clean.step.dependOn(&image_build.step);

    const container_run = b.addSystemCommand(&.{
        "docker",           "run",
        "--rm",             "-d",
        "--name",           "zix-rediz-r8",
        "-p",               "127.0.0.1:63980:6379",
        "-p",               "127.0.0.1:63981:6390",
        "zix-rediz-r8-img",
    });
    container_run.step.dependOn(&pre_clean.step);

    return container_run;
}

fn addContainerTeardown(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-rediz-r8 >/dev/null 2>&1 || true",
    });
}

/// Wrap a compiled test artifact in a Run step when the target can execute on this host,
/// otherwise return the compile step directly. Deterministic compile-only coverage for a
/// foreign target regardless of host binfmt_misc / qemu registration making execution
/// technically possible (e.g. aarch64-linux under a registered qemu-user interpreter).
fn testRunStep(b: *std.Build, exe: *std.Build.Step.Compile, foreign: bool) *std.Build.Step {
    if (foreign) return &exe.step;

    const run = b.addRunArtifact(exe);
    return &run.step;
}

/// Wire one docker-free suite: a test root that drives the in-process server
/// server under tests/inproc, so it needs no container and no daemon and runs
/// on every supported target.
///
/// Note:
/// - The server binds port 0 and each test starts its own, so several of these
///   suites can run at once without a port agreement between them.
///
/// Param:
/// rediz - *std.Build.Module (the driver under test, imported as "rediz")
/// foreign - bool (compile only, do not execute)
/// step_name - []const u8 (the `zig build <name>` step to create)
/// root_path - []const u8 (test root, relative to this package)
fn addInprocSuite(
    b: *std.Build,
    rediz: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    foreign: bool,
    step_name: []const u8,
    root_path: []const u8,
    description: []const u8,
) void {
    const suite_module = b.createModule(.{
        .root_source_file = b.path(root_path),
        .target = target,
        .optimize = optimize,
    });
    suite_module.addImport("rediz", rediz);

    const suite_tests = b.addTest(.{ .root_module = suite_module });

    const step = b.step(step_name, description);
    step.dependOn(testRunStep(b, suite_tests, foreign));
}

// --------------------------------------------------------- //

pub fn build(b: *std.Build) void {
    ensureSupportedZig();

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Installed example binaries carry the target triple and the optimize mode
    // so per-target and per-mode builds coexist in zig-out/bin. A foreign target
    // (cross build) compiles every suite and example but skips execution and the
    // container lifecycle.
    const triple = b.fmt("{s}-{s}", .{ @tagName(target.result.cpu.arch), @tagName(target.result.os.tag) });

    // The optimize mode, lowercased, is the last part of every installed name.
    // No -Doptimize means Debug, so a plain build writes -debug. Spelled out
    // rather than lowercased at runtime so a new mode is a compile error here.
    const mode = switch (optimize) {
        .Debug => "debug",
        .ReleaseSafe => "releasesafe",
        .ReleaseFast => "releasefast",
        .ReleaseSmall => "releasesmall",
    };

    const host = b.graph.host.result;
    const foreign_target = target.result.os.tag != host.os.tag or target.result.cpu.arch != host.cpu.arch;
    if (foreign_target) {
        std.log.info("rediz: target {s} is foreign to this host, tests and runner compile but execution is skipped", .{triple});
    }

    const rediz = b.addModule("rediz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --------------------------------------------------------- //

    // In-file tests live in the rediz module, scenario tests in tests/unit.zig.
    // Zig collects tests per module, so each needs its own addTest.
    const module_tests = b.addTest(.{ .root_module = rediz });
    const module_run_step = testRunStep(b, module_tests, foreign_target);

    const unit_module = b.createModule(.{
        .root_source_file = b.path("tests/unit.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_module.addImport("rediz", rediz);

    const unit_tests = b.addTest(.{ .root_module = unit_module });
    const unit_run_step = testRunStep(b, unit_tests, foreign_target);
    unit_run_step.dependOn(module_run_step);

    const unit_step = b.step("test-unit", "Run rediz unit tests (no server needed)");
    unit_step.dependOn(module_run_step);
    unit_step.dependOn(unit_run_step);

    // --------------------------------------------------------- //

    // Docker-free suites: the driver against the in-process server, so
    // they run everywhere test-integration cannot. They cover what the
    // container suite covers, split by nature: behaviour takes the happy
    // paths, edge takes the refusals, bounds and broken connections.
    addInprocSuite(
        b,
        rediz,
        target,
        optimize,
        foreign_target,
        "test-behaviour",
        "tests/behaviour.zig",
        "Run rediz behaviour tests against the in-process server (no container)",
    );
    addInprocSuite(
        b,
        rediz,
        target,
        optimize,
        foreign_target,
        "test-edge",
        "tests/edge.zig",
        "Run rediz edge tests against the in-process server (no container)",
    );

    // --------------------------------------------------------- //

    const integration_module = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_module.addImport("rediz", rediz);

    const integration_tests = b.addTest(.{ .root_module = integration_module });

    const integration_step = b.step("test-integration", "Run rediz integration tests (owns the Redis 8 container lifecycle)");
    if (foreign_target) {
        // Foreign target: compile the suite, skip the run and the container.
        integration_step.dependOn(&integration_tests.step);
    } else {
        const integration_run = b.addRunArtifact(integration_tests);
        // the suite talks to a fresh container every run: never cache-skip it
        integration_run.has_side_effects = true;
        integration_run.step.dependOn(&addContainerStart(b).step);

        const integration_teardown = addContainerTeardown(b);
        integration_teardown.step.dependOn(&integration_run.step);

        integration_step.dependOn(&integration_teardown.step);
    }

    // --------------------------------------------------------- //

    // Examples: `zig build examples` builds them all into zig-out/bin,
    // `zig build example-<name>` builds one (run it from zig-out/bin).
    const examples_step = b.step("examples", "Build every rediz example into zig-out/bin");

    var example_exes: [example_names.len]*std.Build.Step.Compile = undefined;
    inline for (example_names, 0..) |name, index| {
        const example_module = b.createModule(.{
            .root_source_file = b.path("examples/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        example_module.addImport("rediz", rediz);

        const example_exe = b.addExecutable(.{
            .name = b.fmt("rediz-example-{s}-{s}-{s}", .{ name, triple, mode }),
            .root_module = example_module,
        });
        example_exes[index] = example_exe;

        const example_install = b.addInstallArtifact(example_exe, .{});
        examples_step.dependOn(&example_install.step);

        const single_step = b.step("example-" ++ name, "Build the " ++ name ++ " example into zig-out/bin");
        single_step.dependOn(&example_install.step);
    }

    // --------------------------------------------------------- //

    // Example runner: verifies every example against a fresh container.
    const runner_module = b.createModule(.{
        .root_source_file = b.path("tests/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner_module.addImport("rediz", rediz);

    const runner_exe = b.addExecutable(.{
        .name = "rediz-runner",
        .root_module = runner_module,
    });

    const runner_step = b.step("test-runner", "Run every rediz example against the Redis 8 container (owns the lifecycle)");
    if (foreign_target) {
        // Foreign target: compile the runner and every example, skip the run
        // and the container.
        runner_step.dependOn(&runner_exe.step);
        for (example_exes) |example_exe| runner_step.dependOn(&example_exe.step);
    } else {
        const runner_run = b.addRunArtifact(runner_exe);
        runner_run.has_side_effects = true;
        for (example_exes) |example_exe| runner_run.addArtifactArg(example_exe);
        runner_run.step.dependOn(&addContainerStart(b).step);

        const runner_teardown = addContainerTeardown(b);
        runner_teardown.step.dependOn(&runner_run.step);

        runner_step.dependOn(&runner_teardown.step);
    }
}
