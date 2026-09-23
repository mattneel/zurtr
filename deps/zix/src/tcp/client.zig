//! zix tcp client

const std = @import("std");
const Config = @import("config.zig");
const TcpClientConfig = Config.TcpClientConfig;
const win_io = @import("../utils/windows_io.zig");

// --------------------------------------------------------- //

/// Poll fd for the given event with a millisecond timeout.
///
/// Return:
/// - true when the event is ready
/// - false when the timeout elapsed first
/// poll event bits, mirrored locally: std.posix.POLL is not defined for Windows.
const POLL_IN: i16 = if (@import("builtin").target.os.tag == .windows) win_io.POLLIN else std.posix.POLL.IN;
const POLL_OUT: i16 = if (@import("builtin").target.os.tag == .windows) win_io.POLLOUT else std.posix.POLL.OUT;

fn pollReady(sock_fd: std.posix.fd_t, events: i16, timeout_ms: u32) !bool {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.pollReady(sock_fd, events, timeout_ms);

    var pfd = [1]std.posix.pollfd{.{ .fd = sock_fd, .events = events, .revents = 0 }};
    const ms: i32 = @intCast(@min(timeout_ms, @as(u32, std.math.maxInt(i32))));

    return try std.posix.poll(&pfd, ms) > 0;
}

// --------------------------------------------------------- //

/// TCP stream client.
///
/// Usage:
/// ```zig
/// var client = try TcpClient.connect(config, io);
/// defer client.deinit(io);
/// try client.sendMsg(io, "hello");
/// var buf: [4096]u8 = undefined;
/// const reply = try client.recvMsg(io, &buf);
/// ```
pub const TcpClient = struct {
    const Self = @This();

    stream: std.Io.net.Stream,
    config: TcpClientConfig,

    // --------------------------------------------------------- //

    /// Connect to the server at config.ip:config.port.
    ///
    /// Return:
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn connect(config: TcpClientConfig, io: std.Io) !Self {
        if (config.port == 0) return error.ZixPortNotConfigured;

        const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
        const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });

        return .{ .stream = stream, .config = config };
    }

    /// Connect with CLI arg overrides for --ip and --port.
    /// Falls back to config defaults when args are absent.
    pub fn connectArgs(config: TcpClientConfig, io: std.Io, args: anytype) !Self {
        // std.process.Args.Iterator is POSIX-only in Zig 0.16: CLI overrides
        // are skipped on Windows, the config values stay.
        if (comptime @import("builtin").target.os.tag == .windows) return connect(config, io);

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
        return Self.connect(cfg, io);
    }

    /// Close the connection.
    pub fn deinit(self: *Self, io: std.Io) void {
        self.stream.close(io);
    }

    /// Send a message as a length-prefixed frame.
    /// Frame format: [u32 payload_len, 4 bytes, big-endian] [payload bytes]
    ///
    /// Return:
    /// - error.ZixMessageTooLarge if msg.len exceeds config.max_recv_buf
    /// - error.ZixSendTimeout if send_timeout_ms is set and the socket is not writable in time
    pub fn sendMsg(self: *Self, io: std.Io, msg: []const u8) !void {
        if (msg.len > self.config.max_recv_buf) return error.ZixMessageTooLarge;

        if (self.config.send_timeout_ms > 0) {
            // std.Io.Threaded panics on EAGAIN, so use poll instead of SO_SNDTIMEO.
            if (!try pollReady(self.stream.socket.handle, POLL_OUT, self.config.send_timeout_ms)) {
                return error.ZixSendTimeout;
            }
        }

        var write_buf: [4096 + 4]u8 = undefined;
        var writer = self.stream.writer(io, &write_buf);
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(msg.len), .big);
        try writer.interface.writeAll(&hdr);
        try writer.interface.writeAll(msg);
        try writer.interface.flush();
    }

    /// Receive a length-prefixed frame into buf.
    ///
    /// Return:
    /// - payload slice on success
    /// - error.ZixRecvTimeout if recv_timeout_ms is set and no data arrives in time
    /// - error.ZixMessageTooLarge if the frame payload exceeds buf.len
    /// - error.ZixConnectionClosed if the server closed the connection
    pub fn recvMsg(self: *Self, io: std.Io, buf: []u8) ![]u8 {
        if (self.config.recv_timeout_ms > 0) {
            // std.Io.Threaded panics on EAGAIN, so use poll instead of SO_RCVTIMEO.
            if (!try pollReady(self.stream.socket.handle, POLL_IN, self.config.recv_timeout_ms)) {
                return error.ZixRecvTimeout;
            }
        }

        var read_buf: [4096 + 4]u8 = undefined;
        var reader = self.stream.reader(io, &read_buf);
        const len = reader.interface.takeVarInt(u32, .big, 4) catch return error.ZixConnectionClosed;
        if (len > buf.len) return error.ZixMessageTooLarge;
        reader.interface.readSliceAll(buf[0..len]) catch return error.ZixConnectionClosed;

        return buf[0..len];
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix tcp: TcpClient.recvMsg does not time out when data arrives immediately" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const frame = [_]u8{ 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' };
    _ = std.os.linux.write(fds[1], &frame, frame.len);

    var client = TcpClient{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .config = .{ .ip = "127.0.0.1", .port = 9300, .recv_timeout_ms = 50 },
    };

    var buf: [8]u8 = undefined;
    const reply = try client.recvMsg(io, &buf);
    try std.testing.expectEqualSlices(u8, "hello", reply);
}

test "zix tcp: TcpClient.recvMsg returns error.ZixRecvTimeout when nothing arrives" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = TcpClient{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .config = .{ .ip = "127.0.0.1", .port = 9300, .recv_timeout_ms = 50 },
    };

    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.ZixRecvTimeout, client.recvMsg(io, &buf));
}

test "zix tcp: TcpClient.sendMsg succeeds within send_timeout_ms when the peer drains" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = TcpClient{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .config = .{ .ip = "127.0.0.1", .port = 9300, .send_timeout_ms = 50 },
    };

    try client.sendMsg(io, "hello");

    var wire: [9]u8 = undefined;
    const n: usize = @intCast(std.os.linux.read(fds[1], &wire, wire.len));
    try std.testing.expectEqual(@as(usize, 9), n);
}

test "zix tcp: TcpClient.sendMsg returns error.ZixSendTimeout when the peer's buffer is full" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    // Fill fds[0]'s send buffer so poll(POLLOUT) reports not-ready: switch to
    // non-blocking, write until the kernel refuses more (the peer never
    // reads), then restore blocking mode for the client under test.
    const linux = std.os.linux;
    const flags = linux.fcntl(fds[0], std.posix.F.GETFL, 0);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fds[0], std.posix.F.SETFL, flags | @as(usize, nonblock_bit));

    var chunk: [4096]u8 = undefined;
    while (std.posix.errno(linux.write(fds[0], &chunk, chunk.len)) == .SUCCESS) {}

    _ = linux.fcntl(fds[0], std.posix.F.SETFL, flags);

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = TcpClient{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .config = .{ .ip = "127.0.0.1", .port = 9300, .send_timeout_ms = 50 },
    };

    try std.testing.expectError(error.ZixSendTimeout, client.sendMsg(io, "hello"));
}
