const std = @import("std");

/// Wrap a compiled test artifact in a Run step when the target can execute on this host,
/// otherwise return the compile step directly. Deterministic compile-only coverage for a
/// foreign target regardless of host binfmt_misc / qemu registration making execution
/// technically possible (e.g. aarch64-linux under a registered qemu-user interpreter).
///
/// Note:
/// - name tags the step with its source path, so `--summary all` shows which
///   test file a pending or hung step belongs to instead of a generic "run test".
fn testRunStep(b: *std.Build, exe: *std.Build.Step.Compile, foreign: bool, name: []const u8) *std.Build.Step {
    if (foreign) {
        exe.step.name = name;
        return &exe.step;
    }

    const run = b.addRunArtifact(exe);
    run.setName(name);
    return &run.step;
}

pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
) void {
    // Foreign target (e.g. -Dtarget=x86_64-windows on a Linux host): every suite
    // still compiles for the target, and the run steps report skipped instead of
    // failing to spawn, so `zig build test-all -Dtarget=<t>` passes as a
    // compile-coverage pass. On the target's own machine the suites run for real.
    const host = b.graph.host.result;
    const foreign_target = target.result.os.tag != host.os.tag or target.result.cpu.arch != host.cpu.arch;
    if (foreign_target) {
        std.log.info("zix tests: target {s}-{s} is foreign to this host, suites compile but execution is skipped", .{
            @tagName(target.result.cpu.arch), @tagName(target.result.os.tag),
        });
    }

    const zix_tests = b.addTest(.{ .root_module = zix });
    const zix_tests_step = testRunStep(b, zix_tests, foreign_target, "unit-test");

    // The test runner's check isolation helper carries its own unit tests. It imports std only, not
    // zix, so it gets its own module rather than a slot in the suite lists below.
    const isolate_mod = b.createModule(.{
        .root_source_file = b.path("tests/runner/isolate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const isolate_tests = b.addTest(.{ .root_module = isolate_mod });
    const isolate_step = testRunStep(b, isolate_tests, foreign_target, "tests/runner/isolate.zig");
    isolate_step.dependOn(zix_tests_step);

    // The bounded child process the isolation helper runs each check in, same again: std only.
    const group_run_mod = b.createModule(.{
        .root_source_file = b.path("tests/runner/group_run.zig"),
        .target = target,
        .optimize = optimize,
    });
    const group_run_tests = b.addTest(.{ .root_module = group_run_mod });
    const group_run_step = testRunStep(b, group_run_tests, foreign_target, "tests/runner/group_run.zig");
    group_run_step.dependOn(isolate_step);

    // The name a check reports itself as, for the same reason: std only, so it needs no slot in the
    // suite lists below.
    const report_name_mod = b.createModule(.{
        .root_source_file = b.path("tests/runner/report_name.zig"),
        .target = target,
        .optimize = optimize,
    });
    const report_name_tests = b.addTest(.{ .root_module = report_name_mod });
    const report_name_step = testRunStep(b, report_name_tests, foreign_target, "tests/runner/report_name.zig");
    report_name_step.dependOn(group_run_step);

    // zixer is its own executable root (src/zixer) with its own build files, so
    // its unit tests are `zig build zixer-unit-test`, not part of this step.
    const test_step = b.step("unit-test", "Run unit tests");
    test_step.dependOn(zix_tests_step);
    test_step.dependOn(isolate_step);
    test_step.dependOn(group_run_step);
    test_step.dependOn(report_name_step);

    // --------------------------------------------------------- //

    const integration_test_step = b.step("integration-test", "Run integration tests");

    const integration_tests = .{
        // tcp
        "tests/integration/tcp/config_test.zig",
        // http
        "tests/integration/http/request_test.zig",
        "tests/integration/http/router_test.zig",
        "tests/integration/http/context_test.zig",
        "tests/integration/http/header_index_test.zig",
        "tests/integration/http/sse_test.zig",
        "tests/integration/http/client_test.zig",
        "tests/integration/http/ws_client_test.zig",
        "tests/integration/http/sse_client_test.zig",
        "tests/integration/http/tls_dual_test.zig",
        "tests/integration/http/handler_error_test.zig",
        // http1
        "tests/integration/http1/server_test.zig",
        "tests/integration/http1/router_test.zig",
        "tests/integration/http1/tls_dual_test.zig",
        "tests/integration/http1/static_cache_test.zig",
        // http2
        "tests/integration/http2/server_test.zig",
        "tests/integration/http2/static_test.zig",
        "tests/integration/http2/tls_dual_test.zig",
        // http3
        "tests/integration/http3/static_test.zig",
        "tests/integration/http3/webtransport_test.zig",
        // webrtc
        "tests/integration/webrtc/exchange_test.zig",
        // websocket
        "tests/integration/websocket/websocket_test.zig",
        // fix
        "tests/integration/fix/server_test.zig",
        // grpc
        "tests/integration/grpc/server_test.zig",
        "tests/integration/grpc/tls_dual_test.zig",
        // udp
        "tests/integration/udp/packet_test.zig",
        "tests/integration/udp/config_test.zig",
        // uds
        "tests/integration/uds/config_test.zig",
        // channel
        "tests/integration/channel/channel_test.zig",
        // logger
        "tests/integration/logger/logger_test.zig",
        // tls
        "tests/integration/tls/large_response_test.zig",
        "tests/integration/tls/rsa_test.zig",
    };

    var prev_integ: ?*std.Build.Step = null;
    inline for (integration_tests) |src| {
        const t_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });
        t_mod.addImport("zix", zix);

        const t_exe = b.addTest(.{ .root_module = t_mod });
        const t_step = testRunStep(b, t_exe, foreign_target, src);
        if (prev_integ) |p| t_step.dependOn(p);
        prev_integ = t_step;
        integration_test_step.dependOn(t_step);
    }

    // --------------------------------------------------------- //

    // The durable-slice acceptance suite. Kept out of `test-all` on purpose: it runs against a real
    // PostgreSQL (`ZIX_TASKS_DSN`, or `DATABASE_URL`), because its scenarios are about the SQL the slice
    // runs — a unique index, a rollback, a `SKIP LOCKED` lease — and a wire-protocol fake cannot fail them
    // the way a database does.
    {
        const durable_tasks_mod = b.createModule(.{
            .root_source_file = b.path("examples/durable/tasks.zig"),
            .target = target,
            .optimize = optimize,
        });
        durable_tasks_mod.addImport("zix", zix);

        const durable_options = b.addOptions();
        durable_options.addOption([]const u8, "dsn", b.option([]const u8, "durable-dsn", "PostgreSQL DSN the durable acceptance suite runs against") orelse
            "postgres://zix:zix@127.0.0.1:5432/zix_durable_test");

        const durable_mod = b.createModule(.{
            .root_source_file = b.path("tests/integration/durable/tasks_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        durable_mod.addImport("zix", zix);
        durable_mod.addImport("durable_tasks", durable_tasks_mod);
        durable_mod.addOptions("durable_options", durable_options);

        const durable_step = b.step("test-durable", "Run the durable CreateTask acceptance suite (needs PostgreSQL)");
        durable_step.dependOn(testRunStep(b, b.addTest(.{ .root_module = durable_mod }), foreign_target, "tests/integration/durable/tasks_test.zig"));
    }

    const behaviour_test_step = b.step("behaviour-test", "Run behaviour tests");

    const behaviour_tests = .{
        // dispatch
        "tests/behaviour/dispatch/platform_gate_test.zig",
        // tcp
        "tests/behaviour/tcp/config_test.zig",
        // http
        "tests/behaviour/http/request_test.zig",
        "tests/behaviour/http/router_test.zig",
        "tests/behaviour/http/content_test.zig",
        "tests/behaviour/http/config_test.zig",
        "tests/behaviour/http/sse_test.zig",
        "tests/behaviour/http/client_test.zig",
        "tests/behaviour/http/query_test.zig",
        // http1
        "tests/behaviour/http1/config_test.zig",
        "tests/behaviour/http1/core_test.zig",
        "tests/behaviour/http1/query_test.zig",
        // http2
        "tests/behaviour/http2/config_test.zig",
        // http3
        "tests/behaviour/http3/config_test.zig",
        "tests/behaviour/http3/body_test.zig",
        "tests/behaviour/http3/webtransport_test.zig",
        // webrtc
        "tests/behaviour/webrtc/session_test.zig",
        // websocket
        "tests/behaviour/websocket/websocket_test.zig",
        // fix
        "tests/behaviour/fix/session_test.zig",
        // grpc
        "tests/behaviour/grpc/config_test.zig",
        // udp
        "tests/behaviour/udp/packet_test.zig",
        "tests/behaviour/udp/config_test.zig",
        // uds
        "tests/behaviour/uds/config_test.zig",
        // channel
        "tests/behaviour/channel/channel_test.zig",
        // logger
        "tests/behaviour/logger/logger_test.zig",
    };

    var prev_behav: ?*std.Build.Step = null;
    inline for (behaviour_tests) |src| {
        const t_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });
        t_mod.addImport("zix", zix);

        const t_exe = b.addTest(.{ .root_module = t_mod });
        const t_step = testRunStep(b, t_exe, foreign_target, src);
        if (prev_behav) |p| t_step.dependOn(p);
        prev_behav = t_step;
        behaviour_test_step.dependOn(t_step);
    }

    // --------------------------------------------------------- //

    const edge_test_step = b.step("edge-test", "Run edge tests");

    const edge_tests = .{
        // tcp
        "tests/edge/tcp/config_test.zig",
        // http
        "tests/edge/http/request_test.zig",
        "tests/edge/http/router_test.zig",
        "tests/edge/http/response_test.zig",
        "tests/edge/http/content_test.zig",
        "tests/edge/http/client_test.zig",
        "tests/edge/http/ws_client_test.zig",
        "tests/edge/http/sse_client_test.zig",
        "tests/edge/http/query_test.zig",
        // http1
        "tests/edge/http1/core_test.zig",
        "tests/edge/http1/body_test.zig",
        "tests/edge/http1/query_test.zig",
        "tests/edge/http1/static_cache_test.zig",
        // http2
        "tests/edge/http2/server_test.zig",
        "tests/edge/http2/static_test.zig",
        // http3
        "tests/edge/http3/static_test.zig",
        "tests/edge/http3/body_test.zig",
        "tests/edge/http3/webtransport_test.zig",
        // webrtc
        "tests/edge/webrtc/session_test.zig",
        // websocket
        "tests/edge/websocket/websocket_test.zig",
        // fix
        "tests/edge/fix/session_test.zig",
        // grpc
        "tests/edge/grpc/server_test.zig",
        // udp
        "tests/edge/udp/packet_test.zig",
        "tests/edge/udp/config_test.zig",
        // uds
        "tests/edge/uds/config_test.zig",
        // channel
        "tests/edge/channel/channel_test.zig",
        // logger
        "tests/edge/logger/logger_test.zig",
    };

    var prev_edge: ?*std.Build.Step = null;
    inline for (edge_tests) |src| {
        const t_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });
        t_mod.addImport("zix", zix);

        const t_exe = b.addTest(.{ .root_module = t_mod });
        const t_step = testRunStep(b, t_exe, foreign_target, src);
        if (prev_edge) |p| t_step.dependOn(p);
        prev_edge = t_step;
        edge_test_step.dependOn(t_step);
    }

    // --------------------------------------------------------- //

    // Run tiers sequentially so zig 0.16 IPC sends ".exit" before the next tier starts.
    behaviour_test_step.dependOn(integration_test_step);
    edge_test_step.dependOn(behaviour_test_step);

    const all_test_step = b.step("test-all", "Run unit, integration, behaviour, and edge tests");
    all_test_step.dependOn(zix_tests_step);
    all_test_step.dependOn(isolate_step);
    all_test_step.dependOn(group_run_step);
    all_test_step.dependOn(report_name_step);
    all_test_step.dependOn(integration_test_step);
    all_test_step.dependOn(behaviour_test_step);
    all_test_step.dependOn(edge_test_step);
}
