//! zix fix client: FIX 4.x session client.

const std = @import("std");
const core = @import("core.zig");
const FixClientConfig = @import("config.zig").FixClientConfig;
const win_io = @import("../../utils/windows_io.zig");

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

/// FIX 4.x session client.
///
/// Usage:
/// ```zig
/// var client = try FixClient.connect(.{
///     .ip = "127.0.0.1", .port = 9500,
///     .comp_id = "CLIENT", .target_comp_id = "SERVER",
/// }, io);
/// defer client.deinit(io);
/// try client.logon(io, 30);
/// try client.sendMessage(io, "D", &extra_fields);
/// const raw = try client.recvMessage(io);
/// try client.logout(io);
/// ```
pub const FixClient = struct {
    const Self = @This();

    stream: std.Io.net.Stream,
    comp_id: []const u8,
    target_comp_id: []const u8,
    seq_out: u32,
    recv_buf: [core.MAX_MSG_SIZE * 2]u8,
    recv_len: usize,
    recv_timeout_ms: u32,
    send_timeout_ms: u32,

    // --------------------------------------------------------- //

    /// Connect to a FIX server.
    ///
    /// Return:
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn connect(config: FixClientConfig, io: std.Io) !Self {
        if (config.port == 0) return error.ZixPortNotConfigured;

        const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
        const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });

        return .{
            .stream = stream,
            .comp_id = config.comp_id,
            .target_comp_id = config.target_comp_id,
            .seq_out = 1,
            .recv_buf = undefined,
            .recv_len = 0,
            .recv_timeout_ms = config.recv_timeout_ms,
            .send_timeout_ms = config.send_timeout_ms,
        };
    }

    /// Close the TCP connection.
    pub fn deinit(self: *Self, io: std.Io) void {
        self.stream.close(io);
    }

    // --------------------------------------------------------- //

    /// Send Logon (35=A) and wait for the server's Logon response.
    /// heart_bt_int: HeartBtInt value in seconds (tag 108).
    pub fn logon(self: *Self, io: std.Io, heart_bt_int: u16) !void {
        var hbt_buf: [8]u8 = undefined;
        const hbt_str = std.fmt.bufPrint(&hbt_buf, "{d}", .{heart_bt_int}) catch return error.ZixInvalidHeartbeatInterval;
        const extra = [_]core.BuildField{
            .{ .tag = .EncryptMethod, .value = "0" },
            .{ .tag = .HeartBtInt, .value = hbt_str },
        };

        try self.sendMessage(io, core.MsgType.Logon, &extra);

        const raw = try self.recvMessage(io);
        var fields: [core.MAX_FIELDS]core.Field = undefined;
        const field_count = try core.parseFields(raw, &fields);
        const msg_type = core.getField(fields[0..field_count], .MsgType) orelse return error.ZixMissingMsgType;
        if (!std.mem.eql(u8, msg_type, core.MsgType.Logon)) return error.ZixExpectedLogon;
    }

    /// Send Logout (35=5) and wait for the server's Logout response.
    pub fn logout(self: *Self, io: std.Io) !void {
        try self.sendMessage(io, core.MsgType.Logout, &.{});

        const raw = try self.recvMessage(io);
        var fields: [core.MAX_FIELDS]core.Field = undefined;
        const field_count = try core.parseFields(raw, &fields);
        const msg_type = core.getField(fields[0..field_count], .MsgType) orelse return error.ZixMissingMsgType;
        if (!std.mem.eql(u8, msg_type, core.MsgType.Logout)) return error.ZixExpectedLogout;
    }

    /// Build and send a FIX message. Increments the outgoing sequence number.
    ///
    /// Return:
    /// - error.ZixSendTimeout if send_timeout_ms is set and the socket is not writable in time
    pub fn sendMessage(self: *Self, io: std.Io, msg_type: []const u8, extra: []const core.BuildField) !void {
        var out_buf: [core.MAX_MSG_SIZE]u8 = undefined;
        const n = try core.buildMessage(&out_buf, self.comp_id, self.target_comp_id, self.seq_out, msg_type, extra);
        self.seq_out += 1;

        if (self.send_timeout_ms > 0) {
            // std.Io.Threaded panics on EAGAIN, so use poll instead of SO_SNDTIMEO.
            if (!try pollReady(self.stream.socket.handle, POLL_OUT, self.send_timeout_ms)) {
                return error.ZixSendTimeout;
            }
        }

        var wr_buf: [core.MAX_MSG_SIZE]u8 = undefined;
        var writer = self.stream.writer(io, &wr_buf);
        try writer.interface.writeAll(out_buf[0..n]);
        try writer.interface.flush();
    }

    /// Receive the next complete FIX message.
    ///
    /// Return:
    /// - slice into the internal buffer (valid until the next recvMessage call)
    /// - error.ZixRecvTimeout if recv_timeout_ms is set and no data arrives in time
    /// - error.ZixConnectionClosed if the peer closes the connection before a full message arrives
    pub fn recvMessage(self: *Self, io: std.Io) ![]const u8 {
        _ = io;
        const fd = self.stream.socket.handle;

        while (true) {
            if (core.findMessageEnd(self.recv_buf[0..self.recv_len])) |end| {
                const msg = self.recv_buf[0..end];
                const remaining = self.recv_len - end;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, self.recv_buf[0..remaining], self.recv_buf[end..self.recv_len]);
                }
                self.recv_len = remaining;
                return msg;
            }

            if (self.recv_len >= self.recv_buf.len) return error.ZixMessageTooLarge;

            if (self.recv_timeout_ms > 0) {
                if (!try pollReady(fd, POLL_IN, self.recv_timeout_ms)) {
                    return error.ZixRecvTimeout;
                }
            }

            const n = if (comptime @import("builtin").target.os.tag == .windows)
                try win_io.readOnce(fd, self.recv_buf[self.recv_len..])
            else
                try std.posix.read(fd, self.recv_buf[self.recv_len..]);
            if (n == 0) return error.ZixConnectionClosed;
            self.recv_len += n;
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix fix: FixClient.connect port zero returns PortNotConfigured" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.ZixPortNotConfigured,
        FixClient.connect(.{
            .ip = "127.0.0.1",
            .port = 0,
            .comp_id = "CLIENT",
            .target_comp_id = "SERVER",
        }, io),
    );
}

test "zix fix: FixClient.recvMessage reassembles message split across two reads" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds),
    );
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [core.MAX_MSG_SIZE]u8 = undefined;
    const extra = [_]core.BuildField{
        .{ .tag = .EncryptMethod, .value = "0" },
        .{ .tag = .HeartBtInt, .value = "30" },
    };
    const msg_len = try core.buildMessage(&out_buf, "SERVER", "CLIENT", 1, core.MsgType.Logon, &extra);
    const full_msg = out_buf[0..msg_len];

    const half = msg_len / 2;

    var client = FixClient{
        .stream = .{ .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        } },
        .comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .seq_out = 1,
        .recv_buf = undefined,
        .recv_len = 0,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 0,
    };
    @memcpy(client.recv_buf[0..half], full_msg[0..half]);
    client.recv_len = half;

    _ = std.os.linux.write(fds[1], full_msg[half..].ptr, msg_len - half);

    const msg = try client.recvMessage(io);

    try std.testing.expectEqualSlices(u8, full_msg, msg);
}

test "zix fix: FixClient.recvMessage returns error.ZixRecvTimeout when nothing arrives" {
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

    var client = FixClient{
        .stream = .{ .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        } },
        .comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .seq_out = 1,
        .recv_buf = undefined,
        .recv_len = 0,
        .recv_timeout_ms = 50,
        .send_timeout_ms = 0,
    };

    try std.testing.expectError(error.ZixRecvTimeout, client.recvMessage(io));
}

test "zix fix: FixClient.sendMessage succeeds within send_timeout_ms when the peer drains" {
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

    var client = FixClient{
        .stream = .{ .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        } },
        .comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .seq_out = 1,
        .recv_buf = undefined,
        .recv_len = 0,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 50,
    };

    const extra = [_]core.BuildField{
        .{ .tag = .EncryptMethod, .value = "0" },
        .{ .tag = .HeartBtInt, .value = "30" },
    };
    try client.sendMessage(io, core.MsgType.Logon, &extra);

    var wire: [core.MAX_MSG_SIZE]u8 = undefined;
    const n: usize = @intCast(std.os.linux.read(fds[1], &wire, wire.len));
    try std.testing.expect(n > 0);
}

test "zix fix: FixClient.sendMessage returns error.ZixSendTimeout when the peer's buffer is full" {
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

    var client = FixClient{
        .stream = .{ .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        } },
        .comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .seq_out = 1,
        .recv_buf = undefined,
        .recv_len = 0,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 50,
    };

    const extra = [_]core.BuildField{
        .{ .tag = .EncryptMethod, .value = "0" },
        .{ .tag = .HeartBtInt, .value = "30" },
    };
    try std.testing.expectError(error.ZixSendTimeout, client.sendMessage(io, core.MsgType.Logon, &extra));
}
