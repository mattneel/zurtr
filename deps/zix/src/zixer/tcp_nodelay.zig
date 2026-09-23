//! zixer socket option: disable Nagle on one tcp connection

const std = @import("std");
const builtin = @import("builtin");

/// Turn Nagle's algorithm off on a tcp connection.
///
/// Note:
/// - A reply that leaves as more than one small write (an h2 HEADERS frame
///   then a DATA frame, a grpc message then its trailers) has everything
///   after the first segment held until the peer acknowledges. The peer's
///   delayed acknowledgement waits up to 40 ms on linux, so the whole
///   exchange pays that floor once per request.
/// - Best effort by design: a socket that does not speak tcp answers
///   error.InvalidProtocolOption and keeps its default, which is the right
///   outcome for a unix socket. Windows has no std.posix.setsockopt since
///   the std.Io migration, so a Windows socket keeps the kernel default.
///
/// Param:
/// stream - std.Io.net.Stream (accepted edge conn, or a connected upstream leg)
///
/// Return:
/// - void
pub fn apply(stream: std.Io.net.Stream) void {
    if (comptime builtin.os.tag == .windows) return;

    // std.posix.TCP is void on the BSDs in Zig 0.16: TCP_NODELAY is 1 there.
    const optname: u32 = if (comptime std.posix.TCP != void) std.posix.TCP.NODELAY else 1;

    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        optname,
        std.mem.asBytes(&@as(c_int, 1)),
    ) catch {};
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Read TCP_NODELAY back off a socket, null where it cannot be read.
///
/// Note:
/// - Linux only: std.posix has no getsockopt in Zig 0.16, and the libc
///   form carries a different errno convention per target. A null answer
///   means "not checkable here", never "the option is off".
fn readNoDelay(handle: std.posix.fd_t) ?c_int {
    if (comptime builtin.os.tag != .linux) return null;

    var value: c_int = -1;
    var value_len: std.os.linux.socklen_t = @sizeOf(c_int);

    const rc = std.os.linux.getsockopt(
        handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&value),
        &value_len,
    );
    if (std.os.linux.errno(rc) != .SUCCESS) return null;

    return value;
}

test "zix zixer: tcp nodelay, apply turns the option on for both ends of a connection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18940);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    // A fresh tcp socket has Nagle on, which is what the 40 ms floor needs.
    if (readNoDelay(client.socket.handle)) |before| {
        try std.testing.expectEqual(@as(c_int, 0), before);
    }

    apply(client);
    apply(accepted);

    // The accepted end is the one that matters: it writes the reply.
    if (readNoDelay(accepted.socket.handle)) |after| {
        try std.testing.expect(after != 0);
    } else {
        std.log.info("tcp nodelay readback needs linux, option was set but not verified", .{});

        return;
    }

    const client_after = readNoDelay(client.socket.handle).?;
    try std.testing.expect(client_after != 0);
}

test "zix zixer: tcp nodelay, apply twice keeps the option on" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18941);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    apply(accepted);
    apply(accepted);

    const value = readNoDelay(accepted.socket.handle) orelse {
        std.log.info("tcp nodelay readback needs linux, idempotence not verified", .{});

        return;
    };
    try std.testing.expect(value != 0);
}

test "zix zixer: tcp nodelay, apply on a unix socket is a no-op the socket survives" {
    if (comptime builtin.os.tag != .linux) {
        // non-linux region: socketpair is reached through std.os.linux here,
        // and nothing is bound, so there is nothing to clean up.
        std.log.info("tcp nodelay unix-socket case needs linux", .{});

        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const unix_stream = std.Io.net.Stream{
        .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } },
    };

    // A unix socket answers ENOPROTOOPT and keeps its default: the call
    // must swallow that rather than fail the connection.
    apply(unix_stream);

    const sent = std.os.linux.write(fds[0], "ping", 4);
    try std.testing.expectEqual(@as(usize, 4), sent);

    var got: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), std.os.linux.read(fds[1], &got, got.len));
    try std.testing.expectEqualStrings("ping", &got);
}
