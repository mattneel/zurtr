//! zixer control client: send one request line, read one reply line

const std = @import("std");

const control = @import("control.zig");

pub const CallError = error{
    ZixerUdsNotSupported,
    ZixerControlPathTooLong,
    ZixerDaemonNotRunning,
    ZixerConnectionLost,
    BadReply,
};

/// One request to the daemon over the control socket.
///
/// Note:
/// - The connection lives for exactly one exchange: send the line, read the
///   reply, close.
///
/// Param:
/// io - std.Io
/// socket_path - []const u8 (as control.socketPath built it)
/// request_line - []const u8 (one request, no trailing newline)
/// reply_buf - []u8 (receives the reply line, control.MAX_LINE covers any)
///
/// Return:
/// - control.Reply, text is a slice of reply_buf
/// - error.ZixerDaemonNotRunning when nothing answers on socket_path
/// - error.BadReply when the answer carries neither ok nor error prefix
pub fn call(io: std.Io, socket_path: []const u8, request_line: []const u8, reply_buf: []u8) CallError!control.Reply {
    if (comptime !std.Io.net.has_unix_sockets) return error.ZixerUdsNotSupported;
    if (!control.fitsSocket(socket_path)) return error.ZixerControlPathTooLong;

    const unix_addr = std.Io.net.UnixAddress.init(socket_path) catch return error.ZixerControlPathTooLong;
    const stream = unix_addr.connect(io) catch return error.ZixerDaemonNotRunning;
    defer stream.close(io);

    var write_buf: [control.MAX_LINE]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(request_line) catch return error.ZixerConnectionLost;
    writer.interface.writeAll("\n") catch return error.ZixerConnectionLost;
    writer.interface.flush() catch return error.ZixerConnectionLost;

    var read_buf: [control.MAX_LINE]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var len: usize = 0;
    while (len < reply_buf.len) {
        const got = reader.interface.readSliceShort(reply_buf[len .. len + 1]) catch return error.ZixerConnectionLost;
        if (got == 0) break;
        if (reply_buf[len] == '\n') break;
        len += got;
    }

    return control.parseReply(reply_buf[0..len]) orelse error.BadReply;
}

/// True when a daemon answers ping on socket_path.
pub fn ping(io: std.Io, socket_path: []const u8) bool {
    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = call(io, socket_path, "ping", &reply_buf) catch return false;

    return reply.ok;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: control client, dead socket path reports DaemonNotRunning" {
    if (comptime !std.Io.net.has_unix_sockets) {
        std.log.info("unix sockets are unavailable on this target, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const dead_path = if (@import("builtin").os.tag == .windows) "C:\\zix_absent\\control.sock" else "/tmp/zix_absent_zixer/control.sock";
    try std.testing.expectError(error.ZixerDaemonNotRunning, call(io, dead_path, "ping", &reply_buf));
}

test "zix zixer: control client, over-long socket path reports ControlPathTooLong" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var long_path: [std.Io.net.UnixAddress.max_len + 1]u8 = @splat('a');
    long_path[0] = '/';

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expectError(error.ZixerControlPathTooLong, call(io, &long_path, "ping", &reply_buf));
}

test "zix zixer: control client, ping on a dead socket is false" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const dead_path = if (@import("builtin").os.tag == .windows) "C:\\zix_absent\\control.sock" else "/tmp/zix_absent_zixer/control.sock";
    try std.testing.expect(!ping(io, dead_path));
}
