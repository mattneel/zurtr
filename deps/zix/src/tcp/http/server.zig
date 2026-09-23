//! zix http server: the public Server type and the dispatch_model switch. The
//! shared request pipeline and the per-model dispatch loops live under dispatch/
//! (ADR-043). The server holds the handler plus the connection registry, run()
//! spawns the date/eviction timer and hands off to the model.

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig").HttpServerConfig;
const DispatchModel = @import("config.zig").DispatchModel;
const HandlerFn = @import("router.zig").HandlerFn;
const Route = @import("router.zig").Route;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const rcache = @import("../../utils/response_cache.zig");
const static_cache = @import("../../utils/static_cache.zig");
const ignoreSigpipe = @import("../../utils/ignore_sigpipe.zig").ignoreSigpipe;
const dispatch_support = @import("../../utils/dispatch_support.zig");
const setCache = @import("response.zig").setCache;
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");
const tls_serve = @import("tls_serve.zig");
const tls_mux = @import("tls_mux.zig");

// --------------------------------------------------------- //

/// HTTP server: initialize with a handler built via Router(routes).dispatch.
///
/// Note:
/// - workers = 0 (default): one shared-nothing worker per available CPU under .EPOLL / .URING
/// - workers = N: exactly N workers, ignored by .ASYNC (always one accept thread)
/// - If config.public_dir is non-empty, validates the directory exists. Yields error.ZixPublicDirNotFound if absent
/// - Each .EPOLL / .URING worker owns its own SO_REUSEPORT listener, so the kernel load-balances
///   new connections with no shared queue and no cross-thread fd handoff
/// - .EPOLL / .URING are Linux-only: run() returns error.ZixDispatchModelUnsupported elsewhere (ADR-065)
///
/// Usage:
/// ```zig
/// const router = zix.Http.Router(&[_]zix.Http.Route{
///     .{ .path = "/",      .handler = homeHandler },
///     .{ .path = "/api",   .handler = apiHandler,  .kind = .PREFIX },
///     .{ .path = "/u/:id", .handler = userHandler, .kind = .PARAM },
/// });
/// var server = zix.Http.Server.init(router.dispatch, .{ .ip = "0.0.0.0", .port = 8080, ... });
/// ```
pub const Server = struct {
    handler: HandlerFn,
    config: Config,
    registry: common.ConnRegistry = .{},

    const Self = @This();

    // --------------------------------------------------------- //

    /// Parse and dispatch one complete HTTP request from buf. Thin delegate to
    /// the shared pipeline (dispatch/common.processRequest), kept as a method so
    /// callers and tests can drive a single request without a live socket loop.
    ///
    /// Return:
    /// - .keep_alive when the connection may serve another request
    /// - .close on error, streaming, unconsumed body, Connection: close, or peer hangup
    pub fn processRequest(
        self: *Self,
        stream: std.Io.net.Stream,
        fd: std.posix.fd_t,
        io: std.Io,
        buf: []u8,
        arena: *std.heap.ArenaAllocator,
    ) common.ReqOutcome {
        return common.processRequest(self, stream, fd, io, buf, arena);
    }

    /// Initialize the HTTP server
    ///
    /// Param:
    /// handler - HandlerFn (built via Router(&[_]Route{...}).dispatch)
    /// config - HttpServerConfig
    ///
    /// Return:
    /// - Self
    pub fn init(handler: HandlerFn, config: Config) Self {
        return .{ .handler = handler, .config = config };
    }

    /// Free registry storage
    pub fn deinit(self: *Self) void {
        self.registry.deinit();
    }

    /// Dual-listener TLS accept thread for the thread model (.ASYNC): serves https on config.port
    /// (already overridden to tls_port by the caller) while the cleartext model runs on the
    /// original port.
    fn serveTlsThread(server_copy: Self, tls_io: std.Io) void {
        tls_serve.runTls(&server_copy, tls_io) catch |err| {
            // The cleartext listener keeps serving on its own thread, so without this the https
            // side is dead and the server still looks healthy.
            common.logSystem(server_copy.config, .ERROR, "the https listener on {s}:{d} stopped ({s}), cleartext is still serving", .{ server_copy.config.ip, server_copy.config.tls_port, @errorName(err) });
        };
    }

    /// Start listening and accepting connections
    ///
    /// Return:
    /// - !void
    pub fn run(self: *Self) !void {
        const cfg = self.config;

        // A forgotten port used to reach the bind and come back as whatever std called it, so the
        // config mistake read as a network failure. Rejected here like every other engine.
        if (cfg.port == 0) return error.ZixPortNotConfigured;

        // Reject an impossible dual-listener bind before the timer thread spawns, so an
        // error return leaves no detached thread reading this server's registry.
        if (cfg.tls != null and cfg.tls_port != 0 and cfg.tls_port == cfg.port) return error.ZixTlsPortConflict;

        // Reject an unrunnable model before the timer thread spawns, so a rejected config leaves
        // nothing behind (ADR-065).
        if (!dispatch_support.isSupported(cfg.dispatch_model)) {
            common.logSystem(cfg, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(cfg.dispatch_model)});

            return error.ZixDispatchModelUnsupported;
        }

        ignoreSigpipe();

        const thread_io: std.Io = cfg.io;

        if (cfg.public_dir.len > 0) {
            // One name used to cover missing, not-a-directory and permission-denied alike, so
            // a public_dir the process cannot enter reported as one that is not there.
            const dir = std.Io.Dir.openDir(std.Io.Dir.cwd(), thread_io, cfg.public_dir, .{}) catch |err| return switch (err) {
                error.FileNotFound => error.ZixPublicDirNotFound,
                error.NotDir => error.ZixPublicDirNotADirectory,
                else => error.ZixPublicDirUnreadable,
            };
            dir.close(thread_io);

            // A failed install used to look exactly like caching being off, so a box out of
            // memory served every static file through the slow path and said nothing.
            const installed = static_cache.install(cfg.public_dir_cache_max_entries, cfg.public_dir_cache_ttl_ms) catch |err| downgrade: {
                common.logSystem(cfg, .WARN, "the static cache could not be installed ({s}), every static request re-opens its file", .{@errorName(err)});

                break :downgrade .DISABLED;
            };
            if (installed == .MISMATCHED) {
                common.logSystem(cfg, .WARN, "a static cache is already installed in this process with different settings, keeping it", .{});
            }
        }

        // Background timer: updates date cache every 500ms, evicts timed-out connections.
        const timer_thread = try std.Thread.spawn(.{}, common.timerLoop, .{ thread_io, &self.registry });
        defer timer_thread.detach();

        const is_linux = comptime builtin.target.os.tag == .linux;

        // https opt-in (config.tls): terminate TLS on a gated path, the cleartext models above
        // are untouched. EPOLL / URING multiplex TLS in the event-driven worker (one SO_REUSEPORT
        // epoll worker per core, many connections each), the thread model hands each connection to
        // its own worker thread.
        if (cfg.tls != null) {
            // Dual listener (tls_port): cleartext on port + TLS on tls_port from ONE worker
            // fleet, instead of a second server launch.
            if (cfg.tls_port != 0) {
                if (is_linux and cfg.dispatch_model == .EPOLL) return epoll_model.runEpoll(self, thread_io);
                if (is_linux and cfg.dispatch_model == .URING) return uring_model.runUring(self, thread_io);

                // Thread model (.ASYNC): one extra accept thread terminates TLS on tls_port
                // (thread-per-connection, WebSocket + SSE included, ADR-054 / ADR-055), the
                // cleartext model runs below unchanged.
                var tls_server = self.*;
                tls_server.config.port = cfg.tls_port;
                tls_server.config.tls_port = 0;

                const tls_thread = try std.Thread.spawn(.{}, serveTlsThread, .{ tls_server, thread_io });
                tls_thread.detach();
            } else {
                if (is_linux and (cfg.dispatch_model == .EPOLL or cfg.dispatch_model == .URING)) {
                    return tls_mux.runTlsMux(self, thread_io);
                }
                return tls_serve.runTls(self, thread_io);
            }
        }

        // The guard at the top already rejected .EPOLL / .URING off Linux, the comptime gate here
        // only keeps the Linux-only loops out of analysis there.
        switch (cfg.dispatch_model) {
            .ASYNC => try async_model.runAsync(self, thread_io),
            .EPOLL => if (comptime is_linux) try epoll_model.runEpoll(self, thread_io) else return error.ZixDispatchModelUnsupported,
            // Native io_uring ring path (ADR-037 Phase 4 step 4).
            .URING => if (comptime is_linux) try uring_model.runUring(self, thread_io) else return error.ZixDispatchModelUnsupported,
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: EpollConnTable slab alloc and free lifecycle" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("EPOLL conn table indexes integer descriptors, Windows handles are opaque, test skipped", .{});
        return;
    }

    var table = try common.EpollConnTable.init(256);
    defer table.deinit();

    try std.testing.expectEqual(@as(?*common.EpollConn, null), table.get(5));

    const conn = table.alloc(5).?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 5), conn.fd);
    try std.testing.expectEqual(@as(usize, 256), conn.buf.len);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    const got = table.get(5).?;
    try std.testing.expectEqual(conn, got);

    table.free(5);
    try std.testing.expectEqual(@as(?*common.EpollConn, null), table.get(5));

    table.free(5);
}

test "zix http: EpollConnTable filled tracks accumulated bytes" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("EPOLL conn table indexes integer descriptors, Windows handles are opaque, test skipped", .{});
        return;
    }

    var table = try common.EpollConnTable.init(512);
    defer table.deinit();

    const conn = table.alloc(10).?;
    conn.filled = 42;
    try std.testing.expectEqual(@as(usize, 42), table.get(10).?.filled);

    table.free(10);
    try std.testing.expectEqual(@as(?*common.EpollConn, null), table.get(10));
}

test "zix http: EpollConnTable get returns null for out-of-range fd" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("EPOLL conn table indexes integer descriptors, Windows handles are opaque, test skipped", .{});
        return;
    }

    var table = try common.EpollConnTable.init(64);
    defer table.deinit();

    try std.testing.expectEqual(@as(?*common.EpollConn, null), table.get(common.MAX_FD));
    try std.testing.expectEqual(@as(?*common.EpollConn, null), table.alloc(common.MAX_FD));
}

test "zix http: EpollConnTable packs recv buffers into compact slots, not the fd range" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("EPOLL conn table indexes integer descriptors, Windows handles are opaque, test skipped", .{});
        return;
    }

    var table = try common.EpollConnTable.init(4096);
    defer table.deinit();

    // Two connections on far-apart fds still draw adjacent low slab slots, so the
    // resident recv slab tracks the live count, not the fd values.
    const first = table.alloc(5000).?;
    const second = table.alloc(60000).?;

    const base = @intFromPtr(table.slab.ptr);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(first.buf.ptr) - base);
    try std.testing.expectEqual(table.stride, @intFromPtr(second.buf.ptr) - base);

    // A closed slot returns to the free-list and is reused before a never-used one.
    table.free(5000);
    const reused = table.alloc(123).?;
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(reused.buf.ptr) - base);
}

test "zix http: getAvailableCpuCount returns at least 1" {
    const count = common.getAvailableCpuCount();
    try std.testing.expect(count >= 1);
}

test "zix http: effectiveCacheEntries honors the memory ceiling" {
    const base = Config{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .cache_max_entries = 1024, .cache_max_value_bytes = 16 * 1024 };

    // no ceiling: the configured entry count passes through unchanged
    try std.testing.expectEqual(@as(u32, 1024), common.effectiveCacheEntries(base));

    // ceiling caps the entry count so entries * value_bytes fits
    var capped = base;
    capped.cache_max_total_bytes = 256 * 1024;
    try std.testing.expectEqual(@as(u32, 16), common.effectiveCacheEntries(capped));

    // a tiny ceiling still yields at least one slot
    var tiny = base;
    tiny.cache_max_total_bytes = 1;
    try std.testing.expectEqual(@as(u32, 1), common.effectiveCacheEntries(tiny));
}

/// What bodyComplete() answered on the last request either test handler served.
var test_seen_body_complete: bool = false;

/// Answer without touching the body, the shape a handler takes when it only
/// cares about the route. The body stays on the socket, which is what makes
/// bodyComplete() false here.
fn testBodyIgnoringHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    test_seen_body_complete = req.bodyComplete();

    try res.send("ok");
}

/// Body size the last testBodyReadingHandler call was given.
var test_seen_body_len: usize = 0;

fn testBodyReadingHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    const seen = try req.body();
    test_seen_body_len = seen.len;
    test_seen_body_complete = req.bodyComplete();

    try res.send("ok");
}

test "zix http: bodyComplete is true once a Content-Length body is fully read" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // The guard tests below read the connection outcome, which would still look
    // right if the flag were stuck false. This asserts the flag itself.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    test_seen_body_complete = false;

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd";

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expect(test_seen_body_complete);
    try std.testing.expectEqual(@as(usize, 4), test_seen_body_len);
    try std.testing.expectEqual(common.ReqOutcome.keep_alive, outcome);
}

test "zix http: bodyComplete is true once a chunked body reaches its terminator" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    test_seen_body_complete = false;

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

    // Chunked carries no declared length, so completeness is the terminator and
    // nothing else.
    const chunked_body = "5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(chunked_body.len, std.os.linux.write(fds[0], chunked_body, chunked_body.len));

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expect(test_seen_body_complete);
    try std.testing.expectEqual(@as(usize, 5), test_seen_body_len);
    try std.testing.expectEqual(common.ReqOutcome.keep_alive, outcome);
}

test "zix http: bodyComplete is false when the handler never reads the body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // zix.Http reads lazily, so an untouched body is an unread body. This is the
    // case zix.Http1 cannot have, since its engine reads before the handler runs.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyIgnoringHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    test_seen_body_complete = true;

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd";

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expect(!test_seen_body_complete);
    try std.testing.expectEqual(common.ReqOutcome.close, outcome);
}

test "zix http: processRequest refuses a declared body past the limit with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // The allocation for a Content-Length body was sized straight from the header,
    // so a claimed length was a claim on server memory. The limit is checked before
    // a Request is even built.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .max_request_body = 8 });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n";

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);
    try std.testing.expectEqual(common.ReqOutcome.close, outcome);

    var resp: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &resp);
    try std.testing.expectStringStartsWith(resp[0..n], "HTTP/1.1 413 ");
}

test "zix http: processRequest refuses a chunked body past the limit with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // Chunked declares no length, so the limit has to be a running total the read
    // loop aborts on rather than a check before it starts.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .max_request_body = 16 });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

    const oversized: [64]u8 = @splat('A');
    const chunked_body = "40\r\n".* ++ oversized ++ "\r\n0\r\n\r\n".*;
    try std.testing.expectEqual(chunked_body.len, std.os.linux.write(fds[0], &chunked_body, chunked_body.len));

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);
    try std.testing.expectEqual(common.ReqOutcome.close, outcome);

    var resp: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &resp);
    try std.testing.expectStringStartsWith(resp[0..n], "HTTP/1.1 413 ");
}

test "zix http: processRequest sends 100 Continue before reading a body that expects it" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // The client will not send the body until the server agrees to take it. This
    // engine never parsed the header, so every such request paid the client's own
    // timeout before the body moved. zix.Http1 has answered it from the start.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\nabcd";

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);
    try std.testing.expectEqual(common.ReqOutcome.keep_alive, outcome);

    var resp: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &resp);
    try std.testing.expectStringStartsWith(resp[0..n], "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Ok");
}

test "zix http: processRequest sends no 100 Continue for a request without a body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyIgnoringHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "GET /sink HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n";

    var buf: [160]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    _ = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    var resp: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &resp);
    try std.testing.expectStringStartsWith(resp[0..n], "HTTP/1.1 200 Ok");
}

test "zix http: processRequest closes when a chunked body is left unread" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // The unconsumed-body guard keys on content_length, which a chunked request
    // leaves at zero. Keeping the connection alive hands the unread chunked body
    // to the next parse, where it is read as a second request.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyIgnoringHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

    // The chunked body waits on the socket, unread by the handler.
    const chunked_body = "4\r\nabcd\r\n0\r\n\r\n";
    try std.testing.expectEqual(chunked_body.len, std.os.linux.write(fds[0], chunked_body, chunked_body.len));

    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expectEqual(common.ReqOutcome.close, outcome);
}

test "zix http: processRequest closes when a coding-list chunked body is left unread" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // Same hazard reached through the Transfer-Encoding coding list: the parser
    // has to see chunked past the leading codings, otherwise the request frames
    // as bodyless and the body becomes the next request.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyIgnoringHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";

    const chunked_body = "4\r\nabcd\r\n0\r\n\r\n";
    try std.testing.expectEqual(chunked_body.len, std.os.linux.write(fds[0], chunked_body, chunked_body.len));

    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expectEqual(common.ReqOutcome.close, outcome);
}

test "zix http: processRequest delivers a chunked body that arrives after the head" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // readChunkedBody sizes its raw buffer from the bytes that happened to
    // arrive with the head, not from max_recv_buf. A body that lands in a later
    // segment has almost no room, so it is silently cut short.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

    // One 64-byte chunk plus the terminator, all waiting on the socket.
    var chunked_buf: [96]u8 = undefined;
    var chunked_len: usize = 0;
    const opener = "40\r\n";
    @memcpy(chunked_buf[0..opener.len], opener);
    chunked_len += opener.len;
    @memset(chunked_buf[chunked_len..][0..64], 'A');
    chunked_len += 64;
    const closer = "\r\n0\r\n\r\n";
    @memcpy(chunked_buf[chunked_len..][0..closer.len], closer);
    chunked_len += closer.len;
    try std.testing.expectEqual(chunked_len, std.os.linux.write(fds[0], &chunked_buf, chunked_len));

    test_seen_body_len = 0;
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    _ = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expectEqual(@as(usize, 64), test_seen_body_len);
}

test "zix http: processRequest closes when the peer stops before Content-Length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // A body cut short still caches a slice, so the unconsumed-body guard reads
    // it as consumed. The request was never completed, so the connection cannot
    // be trusted for another one.
    const routes = [_]Route{.{ .path = "/sink", .handler = testBodyReadingHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n";

    // Three of the ten declared bytes, then the peer goes away.
    try std.testing.expectEqual(@as(usize, 3), std.os.linux.write(fds[0], "abc", 3));
    _ = std.os.linux.close(fds[0]);

    test_seen_body_len = 0;
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const outcome = server.processRequest(stream, fds[1], undefined, buf[0..raw.len], &arena);

    try std.testing.expectEqual(@as(usize, 3), test_seen_body_len);
    try std.testing.expectEqual(common.ReqOutcome.close, outcome);
}

fn cacheRouteHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    if (res.sendFromCache(req)) return;

    try res.sendCached(req, "cached-body", 0);
}

test "zix http: EPOLL processRequest serves a cache miss then a hit" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var cache = try rcache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    const routes = [_]Route{.{ .path = "/cached", .handler = cacheRouteHandler }};
    const router = @import("router.zig").Router(&routes);
    var server = Server.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .response_cache = true });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const stream = std.Io.net.Stream{ .socket = .{ .handle = fds[1], .address = undefined } };
    const raw = "GET /cached HTTP/1.1\r\nHost: x\r\n\r\n";

    // first request: cache miss, handler builds and stores the response
    var buf1: [128]u8 = undefined;
    @memcpy(buf1[0..raw.len], raw);
    _ = arena.reset(.retain_capacity);
    _ = server.processRequest(stream, fds[1], undefined, buf1[0..raw.len], &arena);

    var first: [256]u8 = undefined;
    const n1 = try std.posix.read(fds[0], &first);
    try std.testing.expect(std.mem.endsWith(u8, first[0..n1], "\r\n\r\ncached-body"));

    // second request: cache hit, identical bytes served with no rebuild
    var buf2: [128]u8 = undefined;
    @memcpy(buf2[0..raw.len], raw);
    _ = arena.reset(.retain_capacity);
    _ = server.processRequest(stream, fds[1], undefined, buf2[0..raw.len], &arena);

    var second: [256]u8 = undefined;
    const n2 = try std.posix.read(fds[0], &second);
    try std.testing.expectEqualStrings(first[0..n1], second[0..n2]);

    // the entry is present and fresh
    try std.testing.expect(cache.lookup(rcache.hashKey("GET", "/cached", ""), rcache.nowMillis()) != null);
}
