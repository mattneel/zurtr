const std = @import("std");

pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
) void {
    // Examples: not built by default. Third field is the group tag used to wire
    // per-category steps. `zig build examples` builds all, `zig build example-<group>`
    // builds one category, `zig build example-<name>` builds a single one (run the
    // built binary from zig-out/bin).
    const examples = .{
        .{ "example-tcp_server", "examples/tcp_server.zig", "tcp" },
        .{ "example-tcp_client", "examples/tcp_client.zig", "tcp" },
        .{ "example-http1_basic", "examples/http1_basic.zig", "http1" },
        .{ "example-http1_cache", "examples/http1_cache.zig", "http1" },
        .{ "example-http1_compression", "examples/http1_compression.zig", "http1" },
        .{ "example-http1_json", "examples/http1_json.zig", "http1" },
        .{ "example-http1_jzon", "examples/http1_jzon.zig", "http1" },
        .{ "example-http1_middleware", "examples/http1_middleware.zig", "http1" },
        .{ "example-http1_params", "examples/http1_params.zig", "http1" },
        .{ "example-http1_paths", "examples/http1_paths.zig", "http1" },
        .{ "example-http1_query", "examples/http1_query.zig", "http1" },
        .{ "example-http1_static", "examples/http1_static.zig", "http1" },
        .{ "example-http1_static_cached", "examples/http1_static_cached.zig", "http1" },
        .{ "example-http1_manual_concurrent", "examples/http1_manual_concurrent.zig", "http1" },
        .{ "example-http1_sse", "examples/http1_sse.zig", "http1" },
        .{ "example-http1_xtra_headers", "examples/http1_xtra_headers.zig", "http1" },
        .{ "example-http1_client", "examples/http1_client.zig", "http1" },
        .{ "example-http1_timeout_resp", "examples/http1_timeout_resp.zig", "http1" },
        .{ "example-http1_websocket", "examples/http1_websocket.zig", "http1" },
        .{ "example-tls_http_basic", "examples/tls/tls_http_basic.zig", "tls" },
        .{ "example-tls_http_sse", "examples/tls/tls_http_sse.zig", "tls" },
        .{ "example-tls_http_ws", "examples/tls/tls_http_ws.zig", "tls" },
        .{ "example-tls_http1_basic", "examples/tls/tls_http1_basic.zig", "tls" },
        .{ "example-tls_http1_sse", "examples/tls/tls_http1_sse.zig", "tls" },
        .{ "example-tls_http1_ws", "examples/tls/tls_http1_ws.zig", "tls" },
        .{ "example-tls_http1_ed25519", "examples/tls/tls_http1_ed25519.zig", "tls" },
        .{ "example-tls_http1_dual", "examples/tls/tls_http1_dual.zig", "tls" },
        .{ "example-tls_http2_basic", "examples/tls/tls_http2_basic.zig", "tls" },
        .{ "example-tls_grpc_basic", "examples/tls/tls_grpc_basic.zig", "tls" },
        .{ "example-http_basic", "examples/http_basic.zig", "http" },
        .{ "example-http_client", "examples/http_client.zig", "http" },
        .{ "example-http_compression", "examples/http_compression.zig", "http" },
        .{ "example-http_json", "examples/http_json.zig", "http" },
        .{ "example-http_manual_concurrent", "examples/http_manual_concurrent.zig", "http" },
        .{ "example-http_middleware", "examples/http_middleware.zig", "http" },
        .{ "example-http_params", "examples/http_params.zig", "http" },
        .{ "example-http_paths", "examples/http_paths.zig", "http" },
        .{ "example-http_query", "examples/http_query.zig", "http" },
        .{ "example-http_static", "examples/http_static.zig", "http" },
        .{ "example-http_timeout_resp", "examples/http_timeout_resp.zig", "http" },
        .{ "example-http_sse", "examples/http_sse.zig", "http" },
        .{ "example-http_sse_client", "examples/http_sse_client.zig", "http" },
        .{ "example-http_websocket", "examples/http_websocket.zig", "http" },
        .{ "example-http_ws_client", "examples/http_ws_client.zig", "http" },
        .{ "example-http_uds_client", "examples/http_uds_client.zig", "http" },
        .{ "example-http_xtra_headers", "examples/http_xtra_headers.zig", "http" },
        .{ "example-fix_server", "examples/fix_server.zig", "fix" },
        .{ "example-fix_client", "examples/fix_client.zig", "fix" },
        .{ "example-fix_client_raw", "examples/fix_client_raw.zig", "fix" },
        .{ "example-fix_server_trading", "examples/fix_server_trading.zig", "fix" },
        .{ "example-fix_client_trading", "examples/fix_client_trading.zig", "fix" },
        .{ "example-udp_server", "examples/udp_server.zig", "udp" },
        .{ "example-udp_client", "examples/udp_client.zig", "udp" },
        .{ "example-udp_server_raw", "examples/udp_server_raw.zig", "udp" },
        .{ "example-udp_server_tickrate", "examples/udp_server_tickrate.zig", "udp" },
        .{ "example-udp_client_tickrate", "examples/udp_client_tickrate.zig", "udp" },
        .{ "example-http3_basic", "examples/tls/http3_basic.zig", "http3" },
        .{ "example-http3_static", "examples/tls/http3_static.zig", "http3" },
        .{ "example-http3_webtransport", "examples/tls/http3_webtransport.zig", "http3" },
        .{ "example-webtransport_live", "examples/tls/webtransport_live.zig", "http3" },
        .{ "example-webtransport_tasks", "examples/tls/webtransport_tasks.zig", "http3" },
        .{ "example-webrtc_datachannel_echo", "examples/webrtc/webrtc_datachannel_echo.zig", "webrtc" },
        .{ "example-webrtc_native_pair", "examples/webrtc/webrtc_native_pair.zig", "webrtc" },
        .{ "example-webrtc_signaling", "examples/webrtc/webrtc_signaling.zig", "webrtc" },
        .{ "example-webrtc_stun", "examples/webrtc/webrtc_stun.zig", "webrtc" },
        .{ "example-webrtc_datachannel_chat", "examples/webrtc/webrtc_datachannel_chat.zig", "webrtc" },
        .{ "example-webrtc_file_transfer", "examples/webrtc/webrtc_file_transfer.zig", "webrtc" },
        .{ "example-webrtc_video_call", "examples/webrtc/webrtc_video_call.zig", "webrtc" },
        .{ "example-webrtc_sfu_broadcast", "examples/webrtc/webrtc_sfu_broadcast.zig", "webrtc" },
        .{ "example-uds_server", "examples/uds_server.zig", "uds" },
        .{ "example-uds_client", "examples/uds_client.zig", "uds" },
        .{ "example-uds_http", "examples/uds_http.zig", "uds" },
        .{ "example-channel_basic", "examples/channel_basic.zig", "channel" },
        .{ "example-channel_worker_pool", "examples/channel_worker_pool.zig", "channel" },
        .{ "example-channel_pipeline", "examples/channel_pipeline.zig", "channel" },
        .{ "example-channel_ipc_a", "examples/channel_ipc_a.zig", "channel" },
        .{ "example-channel_ipc_b", "examples/channel_ipc_b.zig", "channel" },
        .{ "example-http2_basic", "examples/http2_basic.zig", "http2" },
        .{ "example-grpc_server", "examples/grpc_server.zig", "grpc" },
        .{ "example-grpc_client", "examples/grpc_client.zig", "grpc" },
        .{ "example-grpc_location_server", "examples/grpc_location_server.zig", "grpc" },
        .{ "example-grpc_location_client", "examples/grpc_location_client.zig", "grpc" },
        .{ "example-grpc_timeout", "examples/grpc_timeout.zig", "grpc" },
        .{ "example-grpc_multi_server", "examples/grpc_multi_server.zig", "grpc" },
        .{ "example-grpc_multi_client", "examples/grpc_multi_client.zig", "grpc" },
    };

    // Installed binaries carry the zix- prefix, the target triple, and the
    // optimize mode (zix-example-<name>-<arch>-<os>-<optimize>), so a zig-out/bin
    // listing reads as zix output and building several targets or several modes
    // in a row never overwrites a prior binary. Step names stay unprefixed and
    // unsuffixed.
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

    const examples_step = b.step("examples", "Build all examples");

    const group_tcp = b.step("example-tcp", "Build all tcp examples");
    const group_http1 = b.step("example-http1", "Build all http1 examples");
    const group_http = b.step("example-http", "Build all http examples");
    const group_http2 = b.step("example-http2", "Build all http2 examples");
    const group_fix = b.step("example-fix", "Build all fix examples");
    const group_grpc = b.step("example-grpc", "Build all grpc examples");
    const group_channel = b.step("example-channel", "Build all channel examples");
    const group_udp = b.step("example-udp", "Build all udp examples");
    const group_uds = b.step("example-uds", "Build all uds examples");
    const group_tls = b.step("example-tls", "Build all tls examples");
    const group_http3 = b.step("example-http3", "Build all http3 examples");
    const group_webrtc = b.step("example-webrtc", "Build all webrtc examples");

    examples_step.dependOn(group_tcp);
    examples_step.dependOn(group_http1);
    examples_step.dependOn(group_http);
    examples_step.dependOn(group_http2);
    examples_step.dependOn(group_fix);
    examples_step.dependOn(group_grpc);
    examples_step.dependOn(group_channel);
    examples_step.dependOn(group_udp);
    examples_step.dependOn(group_uds);
    examples_step.dependOn(group_tls);
    examples_step.dependOn(group_http3);
    examples_step.dependOn(group_webrtc);

    // The durable CreateTask slice the tasks example and its acceptance suite both build on. It is a
    // module of its own rather than a library export: it is an application-shaped slice over
    // `zix.Driver.postgrez`, not part of the network backend's surface.
    const durable_tasks_mod = b.createModule(.{
        .root_source_file = b.path("examples/durable/tasks.zig"),
        .target = target,
        .optimize = optimize,
    });
    durable_tasks_mod.addImport("zix", zix);

    inline for (examples) |pair| {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path(pair[1]),
            .target = target,
            .optimize = optimize,
        });
        exe_mod.addImport("zix", zix);
        exe_mod.addImport("durable_tasks", durable_tasks_mod);

        const exe = b.addExecutable(.{
            .name = b.fmt("zix-{s}-{s}-{s}", .{ pair[0], triple, mode }),
            .root_module = exe_mod,
        });

        const group = if (comptime std.mem.eql(u8, pair[2], "tcp"))
            group_tcp
        else if (comptime std.mem.eql(u8, pair[2], "http1"))
            group_http1
        else if (comptime std.mem.eql(u8, pair[2], "http"))
            group_http
        else if (comptime std.mem.eql(u8, pair[2], "http2"))
            group_http2
        else if (comptime std.mem.eql(u8, pair[2], "fix"))
            group_fix
        else if (comptime std.mem.eql(u8, pair[2], "grpc"))
            group_grpc
        else if (comptime std.mem.eql(u8, pair[2], "channel"))
            group_channel
        else if (comptime std.mem.eql(u8, pair[2], "udp"))
            group_udp
        else if (comptime std.mem.eql(u8, pair[2], "uds"))
            group_uds
        else if (comptime std.mem.eql(u8, pair[2], "tls"))
            group_tls
        else if (comptime std.mem.eql(u8, pair[2], "http3"))
            group_http3
        else if (comptime std.mem.eql(u8, pair[2], "webrtc"))
            group_webrtc
        else
            @compileError("unknown example group tag: " ++ pair[2]);

        const install = b.addInstallArtifact(exe, .{});
        group.dependOn(&install.step);

        // `example-<name>` builds and installs the binary to zig-out/bin. It does not run it, so
        // building one (or all, via `zig build examples`) never blocks on a server example. Run a
        // built example with `./zig-out/bin/zix-example-<name>-<arch>-<os>`.
        const build_step = b.step(pair[0], "Build " ++ pair[0]);
        build_step.dependOn(&install.step);
    }
}
