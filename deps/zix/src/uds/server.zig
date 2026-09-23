//! zix uds server

const std = @import("std");
const Config = @import("config.zig");
const UdsServerConfig = Config.UdsServerConfig;
const Logger = @import("../logger/logger.zig").Logger;
const ignoreSigpipe = @import("../utils/ignore_sigpipe.zig").ignoreSigpipe;

const log = std.log.scoped(.zix_uds);

/// Read, write, and payload buffer size for the default echo handler. A frame
/// whose payload exceeds this closes the connection.
const ECHO_BUF_SIZE: usize = 4096;

/// Emit a server line at the given level. Routes through config.logger when present.
///
/// Note:
/// - Without a logger the line still reaches std.log, so a release build never loses a failure.
///   std.log's own default level does the filtering: .ERROR and .WARN survive a release build,
///   .INFO and .DEBUG do not, and a caller who sets std.options.logFn can route or silence all
///   of them.
///
/// Param:
/// level - Logger.Level (.ERROR for a failure the reader must act on, .INFO for a lifecycle line)
fn logSystem(config: UdsServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "uds", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

fn applyConnTimeout(sock_fd: std.posix.fd_t, recv_ms: u32, send_ms: u32) void {
    if (comptime @import("builtin").target.os.tag == .windows) return;

    if (recv_ms == 0 and send_ms == 0) return;

    if (recv_ms > 0) {
        const recv_tv = std.posix.timeval{ .sec = @intCast(recv_ms / 1000), .usec = @intCast((recv_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv)) catch {};
    }

    if (send_ms > 0) {
        const send_tv = std.posix.timeval{ .sec = @intCast(send_ms / 1000), .usec = @intCast((send_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv)) catch {};
    }
}

// --------------------------------------------------------- //

/// Per-connection handler. Owns the accepted stream and must call
/// stream.close(io) before returning.
pub const HandlerFn = fn (std.Io.net.Stream, std.Io) void;

/// UDS server specialized over a comptime handler. The handler is baked into
/// the type at init, so run takes no argument. io comes from config.io.
fn UdsServerImpl(comptime handler: HandlerFn) type {
    return struct {
        const Self = @This();

        config: UdsServerConfig,

        pub fn init(config: UdsServerConfig) !Self {
            if (comptime !std.Io.net.has_unix_sockets) return error.ZixUdsNotSupported;
            if (config.path.len == 0) return error.ZixPathEmpty;

            return .{ .config = config };
        }

        /// No-op: resources are released inside run() via defer.
        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Listen and serve. The comptime handler is called for each accepted
        /// connection (it owns the stream and must close it). io is taken from
        /// config.io (caller-provided, must outlive the server).
        pub fn run(self: *Self) !void {
            if (comptime !std.Io.net.has_unix_sockets) return error.ZixUdsNotSupported;

            ignoreSigpipe();

            const io = self.config.io;

            // Remove stale socket from a previous run before binding.
            std.Io.Dir.cwd().deleteFile(io, self.config.path) catch {};

            // The bare std error names neither the socket nor what went wrong with it, and a unix
            // socket fails in ways a tcp port does not: a path too long for sun_path, a directory
            // that is not there, a stale socket the process may not remove.
            const unix_addr = std.Io.net.UnixAddress.init(self.config.path) catch |err| {
                logSystem(self.config, .ERROR, "the socket path is not usable: {s} ({s})", .{ self.config.path, @errorName(err) });

                return error.ZixUdsPathInvalid;
            };
            var net_server = unix_addr.listen(io, .{ .kernel_backlog = self.config.kernel_backlog }) catch |err| {
                logSystem(self.config, .ERROR, "could not listen on {s} ({s})", .{ self.config.path, @errorName(err) });

                return error.ZixUdsListenFailed;
            };
            defer {
                net_server.deinit(io);
                std.Io.Dir.cwd().deleteFile(io, self.config.path) catch {};
            }

            logSystem(self.config, .INFO, "listening on {s}", .{self.config.path});

            const ConnTask = struct {
                stream: std.Io.net.Stream,
                io: std.Io,
                logger: ?*Logger,
            };

            const dispatch = struct {
                fn call(task: ConnTask) void {
                    if (task.logger) |lg| lg.system(.INFO, "uds", "connection accepted", .{});
                    handler(task.stream, task.io);
                }
            }.call;

            while (true) {
                const stream = net_server.accept(io) catch |err| {
                    if (self.config.logger) |lg| lg.system(.WARN, "uds", "accept error: {}", .{err});
                    continue;
                };
                applyConnTimeout(stream.socket.handle, self.config.recv_timeout_ms, self.config.send_timeout_ms);

                const task = ConnTask{ .stream = stream, .io = io, .logger = self.config.logger };
                if (io.concurrent(dispatch, .{task})) |_| {} else |_| {
                    dispatch(task);
                }
            }
        }
    };
}

/// UDS stream server. The handler is baked into the server type at init
/// (comptime), so run takes no argument, matching the zix.Tcp server shape.
///
/// Usage:
/// ```zig
/// var server = try zix.Uds.Server.init(myHandler, config); // config.io required
/// defer server.deinit();
/// try server.run();
///
/// // the built-in echo handler, passed explicitly
/// var server = try zix.Uds.Server.init(zix.Uds.echoHandler, config);
/// ```
pub const UdsServer = struct {
    /// Initialize a UDS server with a comptime handler.
    ///
    /// Param:
    /// handler - comptime HandlerFn (baked into the server type)
    /// config - UdsServerConfig
    ///
    /// Return:
    /// - !UdsServerImpl(handler)
    /// - error.ZixPathEmpty if config.path is empty
    pub fn init(comptime handler: HandlerFn, config: UdsServerConfig) !UdsServerImpl(handler) {
        return UdsServerImpl(handler).init(config);
    }
};

// --------------------------------------------------------- //

// Default handler: reads length-prefixed frames and echoes each back unchanged.
// Frame format: [u32 payload_len, 4 bytes, big-endian] [payload bytes]
// Payloads larger than ECHO_BUF_SIZE close the connection.
pub fn echoHandler(stream: std.Io.net.Stream, io: std.Io) void {
    defer stream.close(io);

    var read_buf: [ECHO_BUF_SIZE]u8 = undefined;
    var write_buf: [ECHO_BUF_SIZE]u8 = undefined;
    var payload_buf: [ECHO_BUF_SIZE]u8 = undefined;

    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    while (true) {
        var hdr: [4]u8 = undefined;
        var n: usize = 0;
        while (n < 4) {
            const got = reader.interface.readSliceShort(hdr[n..]) catch return;
            if (got == 0) return;
            n += got;
        }

        const len = std.mem.readInt(u32, &hdr, .big);
        if (len > payload_buf.len) return;

        n = 0;
        while (n < len) {
            const got = reader.interface.readSliceShort(payload_buf[n..len]) catch return;
            if (got == 0) return;
            n += got;
        }

        writer.interface.writeAll(&hdr) catch return;
        writer.interface.writeAll(payload_buf[0..len]) catch return;
        writer.interface.flush() catch return;
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix uds: UdsServer init, empty path returns PathEmpty" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    try std.testing.expectError(
        error.ZixPathEmpty,
        UdsServer.init(echoHandler, .{ .io = threaded.io(), .path = "", .allocator = std.testing.allocator }),
    );
}

test "zix uds: UdsServer init, valid path succeeds" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var server = try UdsServer.init(echoHandler, .{ .io = threaded.io(), .path = "zix_test.sock", .allocator = std.testing.allocator });
    server.deinit();
}

test "zix uds: UdsServer init, timeout fields default to zero" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try UdsServer.init(echoHandler, .{ .io = threaded.io(), .path = "zix_test.sock", .allocator = std.testing.allocator });
    try std.testing.expectEqual(@as(u32, 0), server.config.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), server.config.send_timeout_ms);
}

test "zix uds: echoHandler echoes big-endian frame" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_stream = std.Io.net.Stream{
        .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } },
    };

    const handler_thread = try std.Thread.spawn(.{}, echoHandler, .{ server_stream, io });

    const frame = [_]u8{ 0, 0, 0, 4, 't', 'e', 's', 't' };
    _ = std.os.linux.write(fds[1], &frame, frame.len);

    var reply: [8]u8 = undefined;
    var n: usize = 0;
    while (n < 8) {
        const got = std.os.linux.read(fds[1], reply[n..].ptr, 8 - n);
        if (got == 0 or std.posix.errno(got) != .SUCCESS) break;
        n += got;
    }

    _ = std.os.linux.close(fds[1]);
    handler_thread.join();

    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqual(@as(u8, 0), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);
    try std.testing.expectEqual(@as(u8, 0), reply[2]);
    try std.testing.expectEqual(@as(u8, 4), reply[3]);
    try std.testing.expectEqualSlices(u8, "test", reply[4..8]);
}

test "zix uds: UdsServer init, timeout fields stored from config" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const server = try UdsServer.init(echoHandler, .{
        .io = threaded.io(),
        .path = "zix_test.sock",
        .allocator = std.testing.allocator,
        .recv_timeout_ms = 5000,
        .send_timeout_ms = 3000,
    });
    try std.testing.expectEqual(@as(u32, 5000), server.config.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 3000), server.config.send_timeout_ms);
}

test "zix uds: applyConnTimeout uds, zero ms is no-op on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    applyConnTimeout(sock_fd, 0, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 0), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 0), recv_tv.usec);
}

test "zix uds: applyConnTimeout uds, sets SO_RCVTIMEO on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    applyConnTimeout(sock_fd, 2500, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 2), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 500_000), recv_tv.usec);
}

test "zix uds: applyConnTimeout uds, sets SO_SNDTIMEO on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    applyConnTimeout(sock_fd, 0, 1000);

    var send_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, @ptrCast(&send_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 1), send_tv.sec);
    try std.testing.expectEqual(@as(i64, 0), send_tv.usec);
}
