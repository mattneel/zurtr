const std = @import("std");
const builtin = @import("builtin");

/// Upstream sources handed to the runner as argv, in this exact order. The
/// runner's UPSTREAMS table mirrors it, so a row added here needs the matching
/// row there. argv[1] is the zixer binary itself, these follow.
const upstream_srcs = [_]struct { name: []const u8, path: []const u8 }{
    .{ .name = "zixer-tr-http1", .path = "examples/proxies/http1.zig" },
    .{ .name = "zixer-tr-http1-sse", .path = "examples/proxies/http1_sse.zig" },
    .{ .name = "zixer-tr-http1-ws", .path = "examples/proxies/http1_ws.zig" },
    .{ .name = "zixer-tr-http2", .path = "examples/proxies/http2.zig" },
    .{ .name = "zixer-tr-grpc", .path = "examples/proxies/grpc.zig" },
    .{ .name = "zixer-tr-http3", .path = "examples/proxies/http3.zig" },
    .{ .name = "zixer-tr-udp", .path = "examples/proxies/udp.zig" },
    .{ .name = "zixer-tr-mixed", .path = "examples/proxies/mixed.zig" },
    .{ .name = "zixer-tr-round-robin", .path = "examples/proxies/round_robin.zig" },
    .{ .name = "zixer-tr-tls", .path = "examples/proxies/tls.zig" },
    .{ .name = "zixer-tr-bounds", .path = "examples/proxies/bounds.zig" },
    .{ .name = "zixer-tr-headers", .path = "examples/proxies/headers.zig" },
    // The media demo fronts a zix.Webrtc answering peer, which lives with the
    // webrtc examples rather than with the proxy demos.
    .{ .name = "zixer-tr-webrtc", .path = "examples/webrtc/webrtc_datachannel_echo.zig" },
};

/// Wire `zig build zixer-test-runner-all`: one binary that starts the daemon,
/// brings up each demo site in front of its real upstream, drives a real
/// client through it, and reports one row per demo.
///
/// Note:
/// - The runner takes the zixer binary and every upstream binary as argv, so
///   it never guesses a path in zig-out/bin.
/// - A foreign target compiles the runner and every upstream, then stops:
///   nothing can be spawned for another platform.
///
/// Param:
/// zix - *std.Build.Module (the engine module the runner and upstreams link)
/// zixer_exe - *std.Build.Step.Compile (the gateway binary under test)
///
/// Return:
/// - void
pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
    zixer_exe: *std.Build.Step.Compile,
) void {
    const host = b.graph.host.result;
    const foreign_target = target.result.os.tag != host.os.tag or target.result.cpu.arch != host.cpu.arch;

    const runner_mod = b.createModule(.{
        .root_source_file = b.path("tests/zixer/all_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner_mod.addImport("zix", zix);

    // Client-side helpers the zix runner already owns: the process and TLS
    // plumbing, the h2 frame scanner, the hand-rolled QUIC client, and the
    // webrtc dialer. They are named imports because a relative import cannot
    // reach outside the runner module's own directory.
    inline for (.{
        .{ "runner_common", "tests/runner/common.zig" },
        .{ "runner_wire", "tests/runner/wire.zig" },
        .{ "runner_http3_client", "tests/runner/http3_client.zig" },
        .{ "runner_webrtc_client", "tests/runner/webrtc_client.zig" },
    }) |shared| {
        const shared_mod = b.createModule(.{
            .root_source_file = b.path(shared[1]),
            .target = target,
            .optimize = optimize,
        });
        shared_mod.addImport("zix", zix);
        runner_mod.addImport(shared[0], shared_mod);
    }

    const runner_exe = b.addExecutable(.{
        .name = "zixer-test-runner-all",
        .root_module = runner_mod,
    });

    const all_step = b.step("zixer-test-runner-all", "Run every zixer proxy demo end to end");

    const run_all = b.addRunArtifact(runner_exe);
    run_all.has_side_effects = true;
    run_all.addArtifactArg(zixer_exe);

    inline for (upstream_srcs) |upstream| {
        const upstream_mod = b.createModule(.{
            .root_source_file = b.path(upstream.path),
            .target = target,
            .optimize = optimize,
        });
        upstream_mod.addImport("zix", zix);

        const upstream_exe = b.addExecutable(.{
            .name = upstream.name,
            .root_module = upstream_mod,
        });

        run_all.addFileArg(upstream_exe.getEmittedBin());
        if (foreign_target) all_step.dependOn(&upstream_exe.step);
    }

    // Trailing args reach the runner, so one row can be rerun on its own:
    // `zig build zixer-test-runner-all -- --only http3`. Zig 0.17 dropped
    // b.args, so there the runner takes every row and the filter is only
    // available by invoking the built binary directly.
    if (comptime builtin.zig_version.minor == 16) {
        if (b.args) |extra| run_all.addArgs(extra);
    }

    if (foreign_target) {
        all_step.dependOn(&runner_exe.step);
        all_step.dependOn(&zixer_exe.step);
    } else {
        all_step.dependOn(&run_all.step);
    }
}
