//! zix tcp server: the public Server type and the dispatch_model switch. Each
//! dispatch model lives in its own file under dispatch/ (ADR-043). The
//! per-connection handler runs on every model (.URING folds to .EPOLL), the
//! framed callback runs natively on the io_uring ring under .URING.

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const TcpServerConfig = Config.TcpServerConfig;
const DispatchModel = Config.DispatchModel;
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");
const ignoreSigpipe = @import("../utils/ignore_sigpipe.zig").ignoreSigpipe;
const dispatch_support = @import("../utils/dispatch_support.zig");

// --------------------------------------------------------- //
// Public surface re-exported from the dispatch helpers.

pub const HandlerFn = common.HandlerFn;
pub const FrameFn = common.FrameFn;
pub const RespSink = common.RespSink;
pub const writeAllFD = common.writeAllFD;
pub const frameRespond = common.frameRespond;
pub const FRAME_LEN_PREFIX = common.FRAME_LEN_PREFIX;
pub const FRAME_MAX_PAYLOAD = common.FRAME_MAX_PAYLOAD;

// --------------------------------------------------------- //

/// Dispatch core: listen and serve connections with handler, selecting the
/// concurrency model from cfg.dispatch_model. handler(stream, io) runs once per
/// accepted connection and owns the stream (it must close it before returning).
/// Shared by the per-connection server (TcpServerImpl) and the framed adapter
/// fallback (TcpFramedServerImpl on every model except .URING).
fn serveDispatch(cfg: TcpServerConfig, handler: HandlerFn) !void {
    ignoreSigpipe();

    // Reject an unrunnable model before binding, so a rejected config leaves nothing behind (ADR-065).
    if (!dispatch_support.isSupported(cfg.dispatch_model)) {
        common.logSystem(cfg, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(cfg.dispatch_model)});

        return error.ZixDispatchModelUnsupported;
    }

    return switch (cfg.dispatch_model) {
        .ASYNC => async_model.runAsync(cfg, handler),
        // The per-connection blocking handler cannot run on the single-threaded
        // .URING ring, so .URING folds to the .EPOLL shared-nothing loop here.
        // The framed callback path (Server.initFramed) does run natively on the
        // ring (ADR-037, ADR-038). The comptime guard stays because the epoll
        // loop only compiles on Linux: the check above already rejected it here.
        .EPOLL, .URING => if (comptime builtin.target.os.tag == .linux)
            epoll_model.runEpoll(cfg, handler)
        else
            error.ZixDispatchModelUnsupported,
    };
}

/// Per-connection TCP server specialized over a comptime handler. The handler
/// is baked into the type at init, so run takes no handler argument (matching
/// the zix.Http1 / zix.Grpc shape). The handler owns each accepted stream and
/// must close it before returning.
fn TcpServerImpl(comptime handler: HandlerFn) type {
    return struct {
        config: TcpServerConfig,

        const Self = @This();

        pub fn init(config: TcpServerConfig) !Self {
            if (config.port == 0) return error.ZixPortNotConfigured;

            return .{ .config = config };
        }

        pub fn deinit(_: *Self) void {}

        /// Listen and serve. Selects the concurrency model from config.dispatch_model.
        /// io is taken from config.io (caller-provided, must outlive the server).
        pub fn run(self: *const Self) !void {
            return serveDispatch(self.config, handler);
        }
    };
}

/// Framed TCP server specialized over a comptime per-frame callback. On .URING
/// the engine owns the connection and runs frame_fn on the io_uring ring. On
/// the remaining models frame_fn is wrapped in a blocking per-connection adapter
/// and served through serveDispatch. run takes no callback argument: it is
/// baked into the type at init.
fn TcpFramedServerImpl(comptime frame_fn: FrameFn) type {
    return struct {
        config: TcpServerConfig,

        const Self = @This();

        pub fn init(config: TcpServerConfig) !Self {
            if (config.port == 0) return error.ZixPortNotConfigured;

            return .{ .config = config };
        }

        pub fn deinit(_: *Self) void {}

        pub fn run(self: *const Self) !void {
            const io = self.config.io;
            if (comptime builtin.target.os.tag == .linux) {
                if (self.config.dispatch_model == .URING) {
                    // Runtime probe: native ring only when io_uring is usable on
                    // this host, otherwise serve the framed adapter over EPOLL so
                    // the server does not vanish right after binding.
                    if (uring_model.uringUnavailableReason()) |reason| {
                        common.logSystem(self.config, .WARN, "io_uring unavailable ({s}): not suited to this environment (commonly RLIMIT_MEMLOCK, the ulimit -l cap, too low for the ring size). Falling back to EPOLL (framed adapter).", .{reason});
                    } else {
                        return uring_model.runFramedUring(self.config, io, frame_fn);
                    }
                }
            }

            return serveDispatch(self.config, common.frameAdapter(frame_fn));
        }
    };
}

/// Apply --ip and --port CLI overrides onto a config, falling back to the
/// config defaults when an arg is absent.
fn applyArgs(config: TcpServerConfig, args: anytype) TcpServerConfig {
    // std.process.Args.Iterator is POSIX-only in Zig 0.16: CLI overrides are
    // skipped on Windows, the config values stay.
    if (comptime @import("builtin").target.os.tag == .windows) return config;

    var cfg = config;
    var it = std.process.Args.Iterator.init(args);
    _ = it.skip();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ip")) {
            if (it.next()) |val| cfg.ip = val;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (it.next()) |val| cfg.port = std.fmt.parseInt(u16, val, 10) catch cfg.port;
        }
    }

    return cfg;
}

/// TCP stream server. The handler (or framed callback) is baked into the
/// server type at init (comptime), so run takes no handler argument. io is a
/// config field (config.io), so run takes no argument either, matching the
/// zix.Http1 / zix.Grpc server shape.
///
/// Usage:
/// ```zig
/// // per-connection handler (owns the stream)
/// var server = try zix.Tcp.Server.init(myHandler, config); // config.io required
/// defer server.deinit();
/// try server.run();
///
/// // the built-in echo handler, passed explicitly
/// var server = try zix.Tcp.Server.init(zix.Tcp.echoHandler, config);
///
/// // per-frame callback (engine owns the connection, runs on .URING)
/// var server = try zix.Tcp.Server.initFramed(myFrameFn, config);
/// try server.run();
/// ```
pub const Server = struct {
    /// Initialize a per-connection server with a comptime handler.
    ///
    /// Param:
    /// handler - comptime HandlerFn (baked into the server type)
    /// config - TcpServerConfig
    ///
    /// Return:
    /// - !TcpServerImpl(handler)
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn init(comptime handler: HandlerFn, config: TcpServerConfig) !TcpServerImpl(handler) {
        return TcpServerImpl(handler).init(config);
    }

    /// Like init, but applies --ip and --port CLI overrides from args.
    pub fn initArgs(comptime handler: HandlerFn, config: TcpServerConfig, args: anytype) !TcpServerImpl(handler) {
        return TcpServerImpl(handler).init(applyArgs(config, args));
    }

    /// Initialize a framed server with a comptime per-frame callback. The
    /// callback never owns the connection, so it can run on the .URING ring.
    ///
    /// Param:
    /// frame_fn - comptime FrameFn (baked into the server type)
    /// config - TcpServerConfig
    ///
    /// Return:
    /// - !TcpFramedServerImpl(frame_fn)
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn initFramed(comptime frame_fn: FrameFn, config: TcpServerConfig) !TcpFramedServerImpl(frame_fn) {
        return TcpFramedServerImpl(frame_fn).init(config);
    }

    /// Like initFramed, but applies --ip and --port CLI overrides from args.
    pub fn initFramedArgs(comptime frame_fn: FrameFn, config: TcpServerConfig, args: anytype) !TcpFramedServerImpl(frame_fn) {
        return TcpFramedServerImpl(frame_fn).init(applyArgs(config, args));
    }
};

// --------------------------------------------------------- //

/// Max payload the built-in echo handler buffers. A frame whose payload exceeds
/// this closes the connection. The read and write buffers add the 4-byte length prefix.
const ECHO_PAYLOAD_SIZE: usize = 4096;

/// Built-in echo handler. Reads length-prefixed frames and echoes each back unchanged.
/// Frame format: [u32 payload_len, 4 bytes, big-endian] [payload bytes]
/// Payloads larger than ECHO_PAYLOAD_SIZE close the connection.
pub fn echoHandler(stream: std.Io.net.Stream, io: std.Io) void {
    defer stream.close(io);

    var read_buf: [ECHO_PAYLOAD_SIZE + 4]u8 = undefined;
    var write_buf: [ECHO_PAYLOAD_SIZE + 4]u8 = undefined;
    var payload_buf: [ECHO_PAYLOAD_SIZE]u8 = undefined;

    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    while (true) {
        const len = reader.interface.takeVarInt(u32, .big, 4) catch return;
        if (len == 0 or len > payload_buf.len) return;

        reader.interface.readSliceAll(payload_buf[0..len]) catch return;

        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, len, .big);
        writer.interface.writeAll(&hdr) catch return;
        writer.interface.writeAll(payload_buf[0..len]) catch return;
        writer.interface.flush() catch return;
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix tcp: TcpServer init, port zero returns PortNotConfigured" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    try std.testing.expectError(
        error.ZixPortNotConfigured,
        Server.init(echoHandler, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC }),
    );
}

test "zix tcp: TcpServer init, valid config succeeds and deinit is safe" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var server = try Server.init(echoHandler, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9300, .dispatch_model = .ASYNC });
    server.deinit();
}

test "zix tcp: TcpServer init with EPOLL dispatch model succeeds and deinit is safe" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var server = try Server.init(echoHandler, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9300, .dispatch_model = .EPOLL });
    server.deinit();
}

test "zix tcp: TcpServer EPOLL uses the workers field for worker count" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try Server.init(echoHandler, .{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 9300,
        .dispatch_model = .EPOLL,
        .workers = 4,
    });
    try std.testing.expectEqual(@as(usize, 4), server.config.workers);
}

test "zix tcp: TcpServer init, timeout fields default to zero" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try Server.init(echoHandler, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9300, .dispatch_model = .ASYNC });
    try std.testing.expectEqual(@as(u32, 0), server.config.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), server.config.send_timeout_ms);
}

test "zix tcp: TcpServer init, timeout fields stored from config" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try Server.init(echoHandler, .{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 9300,
        .dispatch_model = .ASYNC,
        .recv_timeout_ms = 5000,
        .send_timeout_ms = 3000,
    });
    try std.testing.expectEqual(@as(u32, 5000), server.config.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 3000), server.config.send_timeout_ms);
}

fn testTcpHandler(stream: std.Io.net.Stream, io: std.Io) void {
    stream.close(io);
}

fn testTcpFrame(payload: []const u8, fd: std.posix.fd_t) void {
    _ = payload;
    _ = fd;
}

test "zix tcp: Tcp.Server.init bakes a comptime handler and stores config" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try Server.init(testTcpHandler, .{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 9300,
        .dispatch_model = .EPOLL,
        .workers = 3,
    });
    try std.testing.expectEqual(@as(usize, 3), server.config.workers);
    try std.testing.expectEqual(DispatchModel.EPOLL, server.config.dispatch_model);
}

test "zix tcp: Tcp.Server.initFramed, port zero returns PortNotConfigured" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    try std.testing.expectError(
        error.ZixPortNotConfigured,
        Server.initFramed(testTcpFrame, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC }),
    );
}

test "zix tcp: Tcp.Server.initFramed, valid config succeeds and deinit is safe" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var server = try Server.initFramed(testTcpFrame, .{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9304, .dispatch_model = .URING });
    server.deinit();
}

test "zix tcp: applyConnTimeout, zero ms is no-op on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    common.applyConnTimeout(sock_fd, 0, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 0), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 0), recv_tv.usec);
}

test "zix tcp: applyConnTimeout, sets SO_RCVTIMEO on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    common.applyConnTimeout(sock_fd, 2500, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 2), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 500_000), recv_tv.usec);
}

test "zix tcp: applyConnTimeout, sets SO_SNDTIMEO on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    common.applyConnTimeout(sock_fd, 0, 1000);

    var send_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, @ptrCast(&send_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 1), send_tv.sec);
    try std.testing.expectEqual(@as(i64, 0), send_tv.usec);
}
