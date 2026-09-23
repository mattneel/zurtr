const std = @import("std");

pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
) void {
    // Foreign target: a runner cannot spawn on this host, so each test-runner-*
    // step compiles the runner and its server binaries for the target and skips
    // execution with a warning. On the target's own machine the runners execute.
    const host = b.graph.host.result;
    const foreign_target = target.result.os.tag != host.os.tag or target.result.cpu.arch != host.cpu.arch;
    if (foreign_target) {
        std.log.info("zix test-runner: target {s}-{s} is foreign to this host, runners compile but execution is skipped", .{
            @tagName(target.result.cpu.arch), @tagName(target.result.os.tag),
        });
    }

    // Each runner spawns a server as a child process and exercises the protocol via the
    // zix client. Steps are independent and not part of test-all (see zig build --help).
    //
    // Row: { step-name, runner-src, server-exe-name, server-src, port, arg4, arg5, arg6 }
    // argv[1]: server binary (FileArg). argv[2]: label. argv[3]: port.
    // argv[4]: route/filename/ws-route. argv[5]: origin/file-content. argv[6]: expected substr.
    // Unused argv are passed as empty string and ignored by the runner.
    const runner_table = .{
        // basic per-engine runners (one unified example each, dispatch model picked per target)
        .{ "test-runner-http", "tests/runner/http_runner.zig", "tr-server-http", "examples/http_basic.zig", "9000", "", "", "" },
        .{ "test-runner-http1", "tests/runner/http1_runner.zig", "tr-server-http1", "examples/http1_basic.zig", "9015", "", "", "" },
        .{ "test-runner-http1-compression", "tests/runner/http1_compression_runner.zig", "tr-server-http1-compression", "examples/http1_compression.zig", "9058", "", "", "" },
        .{ "test-runner-http-compression", "tests/runner/http1_compression_runner.zig", "tr-server-http-compression", "examples/http_compression.zig", "9059", "", "", "" },
        .{ "test-runner-tls-http1", "tests/runner/tls_http1_basic_runner.zig", "tr-server-tls-http1", "examples/tls/tls_http1_basic.zig", "9060", "", "", "" },
        .{ "test-runner-tls-http1-ed25519", "tests/runner/tls_http1_ed25519_runner.zig", "tr-server-tls-http1-ed25519", "examples/tls/tls_http1_ed25519.zig", "9062", "", "", "" },
        .{ "test-runner-tls-http2", "tests/runner/tls_http2_basic_runner.zig", "tr-server-tls-http2", "examples/tls/tls_http2_basic.zig", "9061", "", "", "" },
        .{ "test-runner-tls-http2-client", "tests/runner/tls_http2_client_runner.zig", "tr-server-tls-http2-client", "examples/tls/tls_http2_basic.zig", "9061", "", "", "" },
        .{ "test-runner-tls-grpc", "tests/runner/tls_grpc_basic_runner.zig", "tr-server-tls-grpc", "examples/tls/tls_grpc_basic.zig", "9070", "", "", "" },
        // sse over tls runners (ADR-054): native zix.Tls client reads the first event over TLS
        .{ "test-runner-tls-http-sse", "tests/runner/tls_sse_runner.zig", "tr-server-tls-http-sse", "examples/tls/tls_http_sse.zig", "9072", "", "", "" },
        .{ "test-runner-tls-http1-sse", "tests/runner/tls_sse_runner.zig", "tr-server-tls-http1-sse", "examples/tls/tls_http1_sse.zig", "9073", "", "", "" },
        // websocket over tls runners (ADR-055): native zix.Tls client echoes one frame over TLS
        .{ "test-runner-tls-http1-ws", "tests/runner/tls_ws_runner.zig", "tr-server-tls-http1-ws", "examples/tls/tls_http1_ws.zig", "9074", "", "", "" },
        .{ "test-runner-tls-http-ws", "tests/runner/tls_ws_runner.zig", "tr-server-tls-http-ws", "examples/tls/tls_http_ws.zig", "9075", "", "", "" },
        .{ "test-runner-http2", "tests/runner/http2_runner.zig", "tr-server-http2", "examples/http2_basic.zig", "9065", "", "", "" },
        .{ "test-runner-grpc", "tests/runner/grpc_runner.zig", "tr-server-grpc", "examples/grpc_server.zig", "9032", "", "", "" },
        .{ "test-runner-grpc-stream", "tests/runner/grpc_stream_runner.zig", "tr-server-grpc-stream", "examples/grpc_server.zig", "9032", "", "", "" },
        .{ "test-runner-tcp", "tests/runner/tcp_runner.zig", "tr-server-tcp", "examples/tcp_server.zig", "9043", "", "", "" },
        .{ "test-runner-fix", "tests/runner/fix_runner.zig", "tr-server-fix", "examples/fix_server.zig", "9048", "", "", "" },
        .{ "test-runner-udp", "tests/runner/udp_runner.zig", "tr-server-udp", "examples/udp_server.zig", "9054", "", "", "" },
        .{ "test-runner-udp-raw", "tests/runner/udp_raw_runner.zig", "tr-server-udp-raw", "examples/udp_server_raw.zig", "9064", "", "", "" },
        .{ "test-runner-http3", "tests/runner/http3_runner.zig", "tr-server-http3", "examples/tls/http3_basic.zig", "9063", "", "", "" },
        .{ "test-runner-webtransport", "tests/runner/webtransport_runner.zig", "tr-server-webtransport", "examples/tls/http3_webtransport.zig", "9089", "", "", "" },
        .{ "test-runner-webrtc", "tests/runner/webrtc_datachannel_runner.zig", "tr-server-webrtc", "examples/webrtc/webrtc_datachannel_echo.zig", "9083", "", "", "" },
        .{ "test-runner-uds", "tests/runner/uds_runner.zig", "tr-server-uds", "examples/uds_server.zig", "0", "", "", "" },
        // http feature runners (http_get_runner: arg4=route, arg5=origin, arg6=expected)
        .{ "test-runner-http-json", "tests/runner/http_get_runner.zig", "tr-server-http-json", "examples/http_json.zig", "9005", "/status", "", "server" },
        .{ "test-runner-http-middleware", "tests/runner/http_get_runner.zig", "tr-server-http-middleware", "examples/http_middleware.zig", "9006", "/public", "http://127.0.0.1", "public" },
        .{ "test-runner-http-params", "tests/runner/http_get_runner.zig", "tr-server-http-params", "examples/http_params.zig", "9007", "/echo?foo=bar", "", "foo" },
        .{ "test-runner-http-paths", "tests/runner/http_get_runner.zig", "tr-server-http-paths", "examples/http_paths.zig", "9008", "/path", "", "" },
        .{ "test-runner-http-query", "tests/runner/http_query_runner.zig", "tr-server-http-query", "examples/http_query.zig", "9080", "", "", "" },
        .{ "test-runner-http-timeout-resp", "tests/runner/http_get_runner.zig", "tr-server-http-timeout-resp", "examples/http_timeout_resp.zig", "9010", "/ping", "", "pong" },
        .{ "test-runner-http-xtra-headers", "tests/runner/http_get_runner.zig", "tr-server-http-xtra-headers", "examples/http_xtra_headers.zig", "9011", "/info", "", "" },
        .{ "test-runner-http-manual-concurrent", "tests/runner/http_get_runner.zig", "tr-server-http-manual-concurrent", "examples/http_manual_concurrent.zig", "9014", "/", "", "hello" },
        // http static runner (arg4=filename, arg5=file content)
        .{ "test-runner-http-static", "tests/runner/http_static_runner.zig", "tr-server-http-static", "examples/http_static.zig", "9009", "http_text_file.txt", "this is http text file example.", "" },
        // http sse runner
        .{ "test-runner-http-sse", "tests/runner/sse_runner.zig", "tr-server-http-sse", "examples/http_sse.zig", "9012", "", "", "" },
        // http websocket runner (arg4=ws route)
        .{ "test-runner-http-websocket", "tests/runner/ws_runner.zig", "tr-server-http-websocket", "examples/http_websocket.zig", "9013", "/ws/lobby", "", "" },
        // http1 feature runners
        .{ "test-runner-http1-json", "tests/runner/http_get_runner.zig", "tr-server-http1-json", "examples/http1_json.zig", "9020", "/status", "", "server" },
        .{ "test-runner-http1-middleware", "tests/runner/http_get_runner.zig", "tr-server-http1-middleware", "examples/http1_middleware.zig", "9021", "/public", "http://127.0.0.1", "public" },
        .{ "test-runner-http1-params", "tests/runner/http_get_runner.zig", "tr-server-http1-params", "examples/http1_params.zig", "9022", "/echo?foo=bar", "", "foo" },
        .{ "test-runner-http1-paths", "tests/runner/http_get_runner.zig", "tr-server-http1-paths", "examples/http1_paths.zig", "9023", "/path", "", "" },
        .{ "test-runner-http1-query", "tests/runner/http_query_runner.zig", "tr-server-http1-query", "examples/http1_query.zig", "9079", "", "", "" },
        .{ "test-runner-http1-timeout-resp", "tests/runner/http_get_runner.zig", "tr-server-http1-timeout-resp", "examples/http1_timeout_resp.zig", "9025", "/ping", "", "pong" },
        .{ "test-runner-http1-xtra-headers", "tests/runner/http_get_runner.zig", "tr-server-http1-xtra-headers", "examples/http1_xtra_headers.zig", "9026", "/info", "", "" },
        .{ "test-runner-http1-manual-concurrent", "tests/runner/http_get_runner.zig", "tr-server-http1-manual-concurrent", "examples/http1_manual_concurrent.zig", "9030", "/", "", "hello" },
        // http1 static runner
        .{ "test-runner-http1-static", "tests/runner/http_static_runner.zig", "tr-server-http1-static", "examples/http1_static.zig", "9024", "http1_text_file.txt", "this is http1 text file example.", "" },
        // http1 sse runner
        .{ "test-runner-http1-sse", "tests/runner/sse_runner.zig", "tr-server-http1-sse", "examples/http1_sse.zig", "9027", "", "", "" },
        // http1 websocket runner
        .{ "test-runner-http1-websocket", "tests/runner/ws_runner.zig", "tr-server-http1-websocket", "examples/http1_websocket.zig", "9028", "/ws/lobby", "", "" },
        // http1 websocket runner on the io_uring (.URING) dispatch model
        .{ "test-runner-http1-websocket-echo", "tests/runner/ws_runner.zig", "tr-server-http1-websocket-echo", "examples/http1_websocket.zig", "9028", "/ws", "", "" },
        // jzon runner: a rendered record leaves the server and comes back in as a request body
        .{ "test-runner-http1-jzon", "tests/runner/jzon_runner.zig", "tr-server-http1-jzon", "examples/http1_jzon.zig", "9033", "", "", "" },
        // http1 response-cache runner (unique port, small body so the GET is bounded)
        .{ "test-runner-http1-cache", "tests/runner/http_get_runner.zig", "tr-server-http1-cache", "examples/http1_cache.zig", "9031", "/cache?kb=1", "", "ok" },
        // http1 over-large request-body drain runner. Only the multiplexed models drain the
        // body instead of truncating it, so this rides the unified example's Linux pick (.URING).
        .{ "test-runner-http1-drain", "tests/runner/http1_drain_runner.zig", "tr-server-http1-drain", "examples/http1_basic.zig", "9015", "", "", "" },
        // grpc location runners
        .{ "test-runner-grpc-location", "tests/runner/grpc_location_runner.zig", "tr-server-grpc-location", "examples/grpc_location_server.zig", "9038", "", "", "" },
        // grpc multi and timeout runners
        .{ "test-runner-grpc-multi", "tests/runner/grpc_multi_runner.zig", "tr-server-grpc-multi", "examples/grpc_multi_server.zig", "9042", "", "", "" },
        .{ "test-runner-grpc-timeout", "tests/runner/grpc_timeout_runner.zig", "tr-server-grpc-timeout", "examples/grpc_timeout.zig", "9037", "", "", "" },
        // fix trading runner
        .{ "test-runner-fix-trading", "tests/runner/fix_trading_runner.zig", "tr-server-fix-trading", "examples/fix_server_trading.zig", "9053", "", "", "" },
        // channel self-terminating runners
        .{ "test-runner-channel-basic", "tests/runner/channel_selfterm_runner.zig", "tr-server-channel-basic", "examples/channel_basic.zig", "0", "", "", "" },
        .{ "test-runner-channel-pipeline", "tests/runner/channel_selfterm_runner.zig", "tr-server-channel-pipeline", "examples/channel_pipeline.zig", "0", "", "", "" },
        .{ "test-runner-channel-worker-pool", "tests/runner/channel_selfterm_runner.zig", "tr-server-channel-worker-pool", "examples/channel_worker_pool.zig", "0", "", "", "" },
    };

    inline for (runner_table) |row| {
        const server_mod = b.createModule(.{
            .root_source_file = b.path(row[3]),
            .target = target,
            .optimize = optimize,
        });
        server_mod.addImport("zix", zix);
        const server_exe = b.addExecutable(.{
            .name = row[2],
            .root_module = server_mod,
        });

        const runner_mod = b.createModule(.{
            .root_source_file = b.path(row[1]),
            .target = target,
            .optimize = optimize,
        });
        runner_mod.addImport("zix", zix);
        const runner_exe = b.addExecutable(.{
            .name = row[0],
            .root_module = runner_mod,
        });

        const run_runner = b.addRunArtifact(runner_exe);
        run_runner.addFileArg(server_exe.getEmittedBin()); // argv[1]: server path
        run_runner.addArg(row[0][comptime "test-runner-".len..]); // argv[2]: label
        run_runner.addArg(row[4]); // argv[3]: port
        run_runner.addArg(row[5]); // argv[4]: extra (route, filename, ws-route)
        run_runner.addArg(row[6]); // argv[5]: extra (origin, file content)
        run_runner.addArg(row[7]); // argv[6]: extra (expected substr)

        const runner_step = b.step(row[0], "Run " ++ row[0]);
        if (foreign_target) {
            runner_step.dependOn(&server_exe.step);
            runner_step.dependOn(&runner_exe.step);
        } else {
            runner_step.dependOn(&run_runner.step);
        }
    }

    // --------------------------------------------------------- //

    // test-runner-uds-http: two server processes.
    // argv[1]: uds_server path. argv[2]: uds_http path. argv[3]: label.
    {
        const uds_srv_mod = b.createModule(.{
            .root_source_file = b.path("examples/uds_server.zig"),
            .target = target,
            .optimize = optimize,
        });
        uds_srv_mod.addImport("zix", zix);
        const uds_srv_exe = b.addExecutable(.{ .name = "tr-server-uds-http-a", .root_module = uds_srv_mod });

        const uds_http_mod = b.createModule(.{
            .root_source_file = b.path("examples/uds_http.zig"),
            .target = target,
            .optimize = optimize,
        });
        uds_http_mod.addImport("zix", zix);
        const uds_http_exe = b.addExecutable(.{ .name = "tr-server-uds-http-b", .root_module = uds_http_mod });

        const uds_http_runner_mod = b.createModule(.{
            .root_source_file = b.path("tests/runner/uds_http_runner.zig"),
            .target = target,
            .optimize = optimize,
        });
        uds_http_runner_mod.addImport("zix", zix);

        const uds_http_runner_exe = b.addExecutable(.{ .name = "test-runner-uds-http", .root_module = uds_http_runner_mod });

        const run_uds_http = b.addRunArtifact(uds_http_runner_exe);
        run_uds_http.addFileArg(uds_srv_exe.getEmittedBin()); // argv[1]: uds_server path
        run_uds_http.addFileArg(uds_http_exe.getEmittedBin()); // argv[2]: uds_http path
        run_uds_http.addArg("uds-http"); // argv[3]: label

        const uds_http_step = b.step("test-runner-uds-http", "Run test-runner-uds-http");
        if (foreign_target) {
            uds_http_step.dependOn(&uds_srv_exe.step);
            uds_http_step.dependOn(&uds_http_exe.step);
            uds_http_step.dependOn(&uds_http_runner_exe.step);
        } else {
            uds_http_step.dependOn(&run_uds_http.step);
        }
    }

    // --------------------------------------------------------- //

    // test-runner-channel-ipc: two processes (ipc_a + ipc_b).
    // argv[1]: ipc_a path. argv[2]: ipc_b path. argv[3]: label.
    {
        const ipc_a_mod = b.createModule(.{
            .root_source_file = b.path("examples/channel_ipc_a.zig"),
            .target = target,
            .optimize = optimize,
        });
        ipc_a_mod.addImport("zix", zix);
        const ipc_a_exe = b.addExecutable(.{ .name = "tr-server-channel-ipc-a", .root_module = ipc_a_mod });

        const ipc_b_mod = b.createModule(.{
            .root_source_file = b.path("examples/channel_ipc_b.zig"),
            .target = target,
            .optimize = optimize,
        });
        ipc_b_mod.addImport("zix", zix);
        const ipc_b_exe = b.addExecutable(.{ .name = "tr-server-channel-ipc-b", .root_module = ipc_b_mod });

        const ipc_runner_mod = b.createModule(.{
            .root_source_file = b.path("tests/runner/channel_ipc_runner.zig"),
            .target = target,
            .optimize = optimize,
        });
        ipc_runner_mod.addImport("zix", zix);
        const ipc_runner_exe = b.addExecutable(.{ .name = "test-runner-channel-ipc", .root_module = ipc_runner_mod });

        const run_ipc = b.addRunArtifact(ipc_runner_exe);
        run_ipc.addFileArg(ipc_a_exe.getEmittedBin()); // argv[1]: ipc_a path
        run_ipc.addFileArg(ipc_b_exe.getEmittedBin()); // argv[2]: ipc_b path
        run_ipc.addArg("channel-ipc"); // argv[3]: label

        const ipc_step = b.step("test-runner-channel-ipc", "Run test-runner-channel-ipc");
        if (foreign_target) {
            ipc_step.dependOn(&ipc_a_exe.step);
            ipc_step.dependOn(&ipc_b_exe.step);
            ipc_step.dependOn(&ipc_runner_exe.step);
        } else {
            ipc_step.dependOn(&run_ipc.step);
        }
    }

    // --------------------------------------------------------- //

    // test-runner-udp-tickrate: server + client executables.
    // argv[1]: udp_server_tickrate path. argv[2]: udp_client_tickrate path. argv[3]: label.
    {
        const tick_srv_mod = b.createModule(.{
            .root_source_file = b.path("examples/udp_server_tickrate.zig"),
            .target = target,
            .optimize = optimize,
        });
        tick_srv_mod.addImport("zix", zix);
        const tick_srv_exe = b.addExecutable(.{ .name = "tr-server-udp-tickrate", .root_module = tick_srv_mod });

        const tick_cli_mod = b.createModule(.{
            .root_source_file = b.path("examples/udp_client_tickrate.zig"),
            .target = target,
            .optimize = optimize,
        });
        tick_cli_mod.addImport("zix", zix);
        const tick_cli_exe = b.addExecutable(.{ .name = "tr-client-udp-tickrate", .root_module = tick_cli_mod });

        const tick_runner_mod = b.createModule(.{
            .root_source_file = b.path("tests/runner/udp_tickrate_runner.zig"),
            .target = target,
            .optimize = optimize,
        });
        tick_runner_mod.addImport("zix", zix);
        const tick_runner_exe = b.addExecutable(.{ .name = "test-runner-udp-tickrate", .root_module = tick_runner_mod });

        const run_tick = b.addRunArtifact(tick_runner_exe);
        run_tick.addFileArg(tick_srv_exe.getEmittedBin()); // argv[1]: server path
        run_tick.addFileArg(tick_cli_exe.getEmittedBin()); // argv[2]: client path
        run_tick.addArg("udp-tickrate"); // argv[3]: label

        const tick_step = b.step("test-runner-udp-tickrate", "Run test-runner-udp-tickrate");
        if (foreign_target) {
            tick_step.dependOn(&tick_srv_exe.step);
            tick_step.dependOn(&tick_cli_exe.step);
            tick_step.dependOn(&tick_runner_exe.step);
        } else {
            tick_step.dependOn(&run_tick.step);
        }
    }

    // --------------------------------------------------------- //

    // test-runner-all: one binary, all 60 server paths as argv.
    // Independent of the individual test-runner-* steps above.
    // argv order matches the path declarations in all_runner.zig.
    {
        const all_server_srcs = .{
            // basic dispatch-model servers (23)
            .{ "tr-all-server-http", "examples/http_basic.zig" },
            .{ "tr-all-server-http1", "examples/http1_basic.zig" },
            .{ "tr-all-server-grpc", "examples/grpc_server.zig" },
            .{ "tr-all-server-tcp", "examples/tcp_server.zig" },
            .{ "tr-all-server-fix", "examples/fix_server.zig" },
            .{ "tr-all-server-http2", "examples/http2_basic.zig" },
            .{ "tr-all-server-udp", "examples/udp_server.zig" },
            .{ "tr-all-server-udp-raw", "examples/udp_server_raw.zig" },
            .{ "tr-all-server-uds", "examples/uds_server.zig" },
            // http feature servers (12)
            .{ "tr-all-server-http-json", "examples/http_json.zig" },
            .{ "tr-all-server-http-middleware", "examples/http_middleware.zig" },
            .{ "tr-all-server-http-params", "examples/http_params.zig" },
            .{ "tr-all-server-http-paths", "examples/http_paths.zig" },
            .{ "tr-all-server-http-query", "examples/http_query.zig" },
            .{ "tr-all-server-http-timeout-resp", "examples/http_timeout_resp.zig" },
            .{ "tr-all-server-http-xtra-headers", "examples/http_xtra_headers.zig" },
            .{ "tr-all-server-http-manual-concurrent", "examples/http_manual_concurrent.zig" },
            .{ "tr-all-server-http-static", "examples/http_static.zig" },
            .{ "tr-all-server-http-sse", "examples/http_sse.zig" },
            .{ "tr-all-server-http-websocket", "examples/http_websocket.zig" },
            .{ "tr-all-server-http-compression", "examples/http_compression.zig" },
            // http1 feature servers (13)
            .{ "tr-all-server-http1-json", "examples/http1_json.zig" },
            .{ "tr-all-server-http1-middleware", "examples/http1_middleware.zig" },
            .{ "tr-all-server-http1-params", "examples/http1_params.zig" },
            .{ "tr-all-server-http1-paths", "examples/http1_paths.zig" },
            .{ "tr-all-server-http1-query", "examples/http1_query.zig" },
            .{ "tr-all-server-http1-timeout-resp", "examples/http1_timeout_resp.zig" },
            .{ "tr-all-server-http1-xtra-headers", "examples/http1_xtra_headers.zig" },
            .{ "tr-all-server-http1-manual-concurrent", "examples/http1_manual_concurrent.zig" },
            .{ "tr-all-server-http1-static", "examples/http1_static.zig" },
            .{ "tr-all-server-http1-sse", "examples/http1_sse.zig" },
            .{ "tr-all-server-http1-websocket", "examples/http1_websocket.zig" },
            .{ "tr-all-server-http1-cache", "examples/http1_cache.zig" },
            .{ "tr-all-server-http1-compression", "examples/http1_compression.zig" },
            // grpc location + multi + timeout (6)
            .{ "tr-all-server-grpc-location", "examples/grpc_location_server.zig" },
            .{ "tr-all-server-grpc-multi", "examples/grpc_multi_server.zig" },
            .{ "tr-all-server-grpc-timeout", "examples/grpc_timeout.zig" },
            // fix trading (1)
            .{ "tr-all-server-fix-trading", "examples/fix_server_trading.zig" },
            // uds-http pair (2 paths for one test)
            .{ "tr-all-server-uds-http-a", "examples/uds_server.zig" },
            .{ "tr-all-server-uds-http-b", "examples/uds_http.zig" },
            // channel self-terminating (3)
            .{ "tr-all-server-channel-basic", "examples/channel_basic.zig" },
            .{ "tr-all-server-channel-pipeline", "examples/channel_pipeline.zig" },
            .{ "tr-all-server-channel-worker-pool", "examples/channel_worker_pool.zig" },
            // channel ipc pair (2 paths for one test)
            .{ "tr-all-server-channel-ipc-a", "examples/channel_ipc_a.zig" },
            .{ "tr-all-server-channel-ipc-b", "examples/channel_ipc_b.zig" },

            // tls (https/1.1 + ed25519 cert variant + h2, over TLS 1.3)
            .{ "tr-all-server-tls-http1", "examples/tls/tls_http1_basic.zig" },
            .{ "tr-all-server-tls-http1-ed25519", "examples/tls/tls_http1_ed25519.zig" },
            .{ "tr-all-server-tls-http2", "examples/tls/tls_http2_basic.zig" },
            .{ "tr-all-server-tls-grpc", "examples/tls/tls_grpc_basic.zig" },

            // http3 (QUIC over TLS 1.3, driven by the hand-rolled native client)
            .{ "tr-all-server-http3", "examples/tls/http3_basic.zig" },

            // sse over tls (ADR-054): appended last so the argv order in all_runner stays stable
            .{ "tr-all-server-tls-http-sse", "examples/tls/tls_http_sse.zig" },
            .{ "tr-all-server-tls-http1-sse", "examples/tls/tls_http1_sse.zig" },

            // websocket over tls (ADR-055): appended after the sse servers, argv order stays stable
            .{ "tr-all-server-tls-http1-ws", "examples/tls/tls_http1_ws.zig" },
            .{ "tr-all-server-tls-http-ws", "examples/tls/tls_http_ws.zig" },

            // https/1.1 over TLS on the arena engine: appended last so existing argv order is stable
            .{ "tr-all-server-tls-http", "examples/tls/tls_http_basic.zig" },

            // dual listener (config.tls_port, ADR-060): appended last, argv order stays stable
            .{ "tr-all-server-tls-http1-dual", "examples/tls/tls_http1_dual.zig" },

            // webrtc data channel: appended last, argv order stays stable
            .{ "tr-all-server-webrtc", "examples/webrtc/webrtc_datachannel_echo.zig" },

            // jzon over http1: appended last, argv order stays stable
            .{ "tr-all-server-http1-jzon", "examples/http1_jzon.zig" },

            // udp tickrate pair (2 paths for one test): appended last, argv order stays stable
            .{ "tr-all-server-udp-tickrate", "examples/udp_server_tickrate.zig" },
            .{ "tr-all-server-udp-tickrate-client", "examples/udp_client_tickrate.zig" },

            // webtransport over http3: appended last, argv order stays stable
            .{ "tr-all-server-webtransport", "examples/tls/http3_webtransport.zig" },
        };

        const all_runner_mod = b.createModule(.{
            .root_source_file = b.path("tests/runner/all_runner.zig"),
            .target = target,
            .optimize = optimize,
        });
        all_runner_mod.addImport("zix", zix);
        const all_runner_exe = b.addExecutable(.{
            .name = "test-runner-all",
            .root_module = all_runner_mod,
        });

        const all_step = b.step("test-runner-all", "Run test-runner-all");

        const run_all = b.addRunArtifact(all_runner_exe);
        inline for (all_server_srcs) |srv| {
            const srv_mod = b.createModule(.{
                .root_source_file = b.path(srv[1]),
                .target = target,
                .optimize = optimize,
            });
            srv_mod.addImport("zix", zix);
            const srv_exe = b.addExecutable(.{
                .name = srv[0],
                .root_module = srv_mod,
            });
            run_all.addFileArg(srv_exe.getEmittedBin());
            if (foreign_target) all_step.dependOn(&srv_exe.step);
        }

        if (foreign_target) {
            all_step.dependOn(&all_runner_exe.step);
        } else {
            all_step.dependOn(&run_all.step);
        }
    }
}
