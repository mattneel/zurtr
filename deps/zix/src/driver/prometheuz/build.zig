const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for the prometheuz build.
///
/// Note:
/// - Mirror of the check in src/lib.zig, kept local because build.zig cannot
///   import the module it builds.
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

/// One-shot, runner-verified examples: built into zig-out/bin and checked
/// by tests/runner.zig. registry_live_demo.zig is deliberately NOT in this
/// list, see the plan doc's "## Examples" section (long-running, manual,
/// self-manages its own container lifecycle).
const example_names = [_][]const u8{
    "basic_scrape",
    "url_target",
    "background_scraper",
    "query_samples",
    "error_handling",
    "registry_counter_gauge",
    "remote_write_forward",
    "registry_remote_write_push",
    "promql_query",
};

// --------------------------------------------------------- //

/// Fail the build with a readable message when the compiler is neither Zig 0.16.x
/// nor 0.17.x, instead of a deep version-specific type error.
fn ensureSupportedZig() void {
    if (ZIG_SEMVER.MAJOR == 0 and (ZIG_SEMVER.MINOR == 16 or ZIG_SEMVER.MINOR == 17)) return;

    @compileError(std.fmt.comptimePrint(
        "prometheuz build requires Zig 0.16.x or 0.17.x, found {d}.{d}.{d}. " ++
            "Use zig-0.16 (or a 0.17 toolchain).",
        .{ ZIG_SEMVER.MAJOR, ZIG_SEMVER.MINOR, ZIG_SEMVER.PATCH },
    ));
}

/// Container start pipeline for node-exporter: build the image, replace any
/// old container, run detached, bridge-mode with an explicit host port
/// publish (matches the postgrez/rediz convention). Returned step is the
/// running container. Callers hang their suite on it and a teardown after.
fn addNodeExporterStart(b: *std.Build) *std.Build.Step.Run {
    const image_build = b.addSystemCommand(&.{
        "docker", "build", "-t", "zix-prometheuz-node-exporter-img", "../../../containers/node-exporter",
    });

    const pre_clean = b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-prometheuz-node-exporter >/dev/null 2>&1 || true",
    });
    pre_clean.step.dependOn(&image_build.step);

    const container_run = b.addSystemCommand(&.{
        "docker",                           "run",
        "--rm",                             "-d",
        "--name",                           "zix-prometheuz-node-exporter",
        "-p",                               "127.0.0.1:19100:9100",
        "zix-prometheuz-node-exporter-img",
    });
    container_run.step.dependOn(&pre_clean.step);

    return container_run;
}

fn addNodeExporterTeardown(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-prometheuz-node-exporter >/dev/null 2>&1 || true",
    });
}

/// Same pipeline for prometheus (remote-write receiver on, scrapes
/// node-exporter per containers/prometheus/prometheus.yml).
fn addPrometheusStart(b: *std.Build) *std.Build.Step.Run {
    const image_build = b.addSystemCommand(&.{
        "docker", "build", "-t", "zix-prometheuz-prometheus-img", "../../../containers/prometheus",
    });

    const pre_clean = b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-prometheuz-prometheus >/dev/null 2>&1 || true",
    });
    pre_clean.step.dependOn(&image_build.step);

    const container_run = b.addSystemCommand(&.{
        "docker",                        "run",
        "--rm",                          "-d",
        "--name",                        "zix-prometheuz-prometheus",
        "-p",                            "127.0.0.1:19090:9090",
        "zix-prometheuz-prometheus-img",
    });
    container_run.step.dependOn(&pre_clean.step);

    return container_run;
}

fn addPrometheusTeardown(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "sh", "-c", "docker rm -f zix-prometheuz-prometheus >/dev/null 2>&1 || true",
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
/// endpoint under tests/inproc, so it needs no container and no daemon and runs
/// on every supported target.
///
/// Note:
/// - The server binds port 0 and each test starts its own, so several of these
///   suites can run at once without a port agreement between them.
///
/// Param:
/// prometheuz - *std.Build.Module (the driver under test, imported as "prometheuz")
/// foreign - bool (compile only, do not execute)
/// step_name - []const u8 (the `zig build <name>` step to create)
/// root_path - []const u8 (test root, relative to this package)
fn addInprocSuite(
    b: *std.Build,
    prometheuz: *std.Build.Module,
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
    suite_module.addImport("prometheuz", prometheuz);

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
        std.log.info("prometheuz: target {s} is foreign to this host, tests and runner compile but execution is skipped", .{triple});
    }

    const prometheuz = b.addModule("prometheuz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --------------------------------------------------------- //

    // In-file tests live in the prometheuz module.
    const module_tests = b.addTest(.{ .root_module = prometheuz });
    const module_run_step = testRunStep(b, module_tests, foreign_target);

    const unit_step = b.step("test-unit", "Run prometheuz unit tests (no server needed)");
    unit_step.dependOn(module_run_step);

    // --------------------------------------------------------- //

    // Docker-free suites: the driver against the in-process endpoint, so
    // they run everywhere the container-backed runner cannot. One endpoint
    // stands in for all three servers the driver talks to: the exporter it
    // scrapes,
    // the receiver it writes to, and the query API it reads from.
    addInprocSuite(
        b,
        prometheuz,
        target,
        optimize,
        foreign_target,
        "test-behaviour",
        "tests/behaviour.zig",
        "Run prometheuz behaviour tests against the in-process endpoint (no container)",
    );
    addInprocSuite(
        b,
        prometheuz,
        target,
        optimize,
        foreign_target,
        "test-edge",
        "tests/edge.zig",
        "Run prometheuz edge tests against the in-process endpoint (no container)",
    );

    // --------------------------------------------------------- //

    // Examples: `zig build examples` builds them all into zig-out/bin,
    // `zig build example-<name>` builds one (run it from zig-out/bin).
    const examples_step = b.step("examples", "Build every prometheuz example into zig-out/bin");

    var example_exes: [example_names.len]*std.Build.Step.Compile = undefined;
    inline for (example_names, 0..) |name, index| {
        const example_module = b.createModule(.{
            .root_source_file = b.path("examples/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        example_module.addImport("prometheuz", prometheuz);

        const example_exe = b.addExecutable(.{
            .name = b.fmt("prometheuz-example-{s}-{s}-{s}", .{ name, triple, mode }),
            .root_module = example_module,
        });
        example_exes[index] = example_exe;

        const example_install = b.addInstallArtifact(example_exe, .{});
        examples_step.dependOn(&example_install.step);

        const single_step = b.step("example-" ++ name, "Build the " ++ name ++ " example into zig-out/bin");
        single_step.dependOn(&example_install.step);
    }

    // registry_live_demo.zig: built, but deliberately outside example_names
    // (not part of `examples`, not runner-checked - see its own doc
    // comment for why).
    const live_demo_module = b.createModule(.{
        .root_source_file = b.path("examples/registry_live_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    live_demo_module.addImport("prometheuz", prometheuz);

    const live_demo_exe = b.addExecutable(.{
        .name = b.fmt("prometheuz-example-registry_live_demo-{s}-{s}", .{ triple, mode }),
        .root_module = live_demo_module,
    });

    const live_demo_install = b.addInstallArtifact(live_demo_exe, .{});
    const live_demo_step = b.step("example-registry_live_demo", "Build the registry_live_demo example into zig-out/bin");
    live_demo_step.dependOn(&live_demo_install.step);

    // --------------------------------------------------------- //

    // Example runner: verifies every one-shot example against fresh
    // node-exporter + prometheus containers. registry_live_demo.zig is not
    // built here, see examples/registry_live_demo.zig's own doc comment.
    const runner_module = b.createModule(.{
        .root_source_file = b.path("tests/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner_module.addImport("prometheuz", prometheuz);

    const runner_exe = b.addExecutable(.{
        .name = "prometheuz-runner",
        .root_module = runner_module,
    });

    const runner_step = b.step("test-runner", "Run every prometheuz example against the node-exporter+prometheus containers (owns the lifecycle)");
    if (foreign_target) {
        // Foreign target: compile the runner and every example, skip the run
        // and the containers.
        runner_step.dependOn(&runner_exe.step);
        for (example_exes) |example_exe| runner_step.dependOn(&example_exe.step);
    } else {
        const runner_run = b.addRunArtifact(runner_exe);
        runner_run.has_side_effects = true;
        for (example_exes) |example_exe| runner_run.addArtifactArg(example_exe);
        runner_run.step.dependOn(&addNodeExporterStart(b).step);
        runner_run.step.dependOn(&addPrometheusStart(b).step);

        const node_exporter_teardown = addNodeExporterTeardown(b);
        node_exporter_teardown.step.dependOn(&runner_run.step);
        const prometheus_teardown = addPrometheusTeardown(b);
        prometheus_teardown.step.dependOn(&runner_run.step);

        runner_step.dependOn(&node_exporter_teardown.step);
        runner_step.dependOn(&prometheus_teardown.step);
    }
}
