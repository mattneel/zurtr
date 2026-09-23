//! Portable socket cut: wake a thread parked on a socket from outside its dispatch loop.
//!
//! What:
//!   One helper, one concern. A shutdown of the read side wakes a blocking read, an epoll wait, or an
//!   io_uring recv the same way, because none of them special-case a peer half-close. A shutdown of
//!   both sides is the escalation for the one shape that cut does not reach. The caller acts on the
//!   descriptor from outside, the loop parked on it is never told anything.
//!
//! Note:
//! - The read-side cut comes first, always. A full shutdown wakes the same read but also takes the
//!   send side away, which is the difference between a caller that can still write its own reply on
//!   the way out and one that cannot.
//! - The full cut is the escalation, for the caller a read-side cut never reached. A peer that
//!   stopped reading parks the caller in write, where no read-side cut lands, and only taking the
//!   send side away frees it. By then the reply is lost either way, so nothing is given up.
//! - Darwin will not take both directions at once on a socket whose read side is already down. Its
//!   shutdown handles the read side first and answers ENOTCONN the moment it sees that side gone,
//!   before it ever reaches the send side, so the escalation lands as a no-op and the peer is never
//!   sent a FIN. Linux and the BSDs act on each direction on its own. The escalation therefore asks
//!   for the send side alone whenever both-at-once was refused, which is the same FIN.
//! - Windows never completes a receive already parked in the kernel on a receive-only disconnect
//!   (documented winsock SD_RECEIVE behavior: it only disallows later receives), so the cut there
//!   is windows_io's partial-disconnect ioctl plus a cancel of every request pending on the handle.
//!   windows_io.readOnce reports both completions as end-of-stream. A std reader cannot (zig 0.16
//!   and 0.17 both treat a cancelled receive as unreachable), so a read that must survive a cut on
//!   Windows goes through windows_io: directly on a bare descriptor, or through socket_cut_reader
//!   where the caller needs a std.Io.Reader. The escalation cancels a parked send the same way, and
//!   std's socket writer calls that unreachable too, so the send side has socket_cut_writer.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("windows_io.zig");
const socket_poll = @import("socket_poll.zig");

const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;

// --------------------------------------------------------- //

/// Shut down the read side of a connected socket, so a thread parked reading it wakes with
/// end-of-stream while the socket's send side stays usable.
///
/// Note:
/// - Best effort: a socket already closed or never connected fails silently, matching every other
///   shutdown/close helper in the tree.
///
/// Param:
/// handle - std.posix.socket_t (the socket, from stream.socket.handle)
///
/// Return:
/// - void
pub fn shutdownRead(handle: std.posix.socket_t) void {
    if (comptime is_windows) {
        win_io.shutdownRead(handle);
        return;
    }

    if (comptime is_linux) {
        _ = std.os.linux.shutdown(handle, std.os.linux.SHUT.RD);
        return;
    }

    _ = std.posix.system.shutdown(handle, std.posix.SHUT.RD);
}

/// Shut down both directions of a connected socket, so a thread parked on it wakes whether it is
/// reading or writing.
///
/// Note:
/// - The escalation after shutdownRead, not a replacement for it. This takes the send side away, so
///   the caller can no longer answer, and it is only right once the reply is already lost.
/// - Best effort, the same as shutdownRead: a socket already closed or never connected fails
///   silently.
/// - Darwin refuses both directions at once once the read side is already down, so the escalation
///   asks for the send side on its own when that happens. See the module note.
///
/// Param:
/// handle - std.posix.socket_t (the socket, from stream.socket.handle)
///
/// Return:
/// - void
pub fn shutdownBoth(handle: std.posix.socket_t) void {
    if (comptime is_windows) {
        win_io.shutdownBoth(handle);
        return;
    }

    if (comptime is_linux) {
        _ = std.os.linux.shutdown(handle, std.os.linux.SHUT.RDWR);
        return;
    }

    const both = std.posix.system.shutdown(handle, std.posix.SHUT.RDWR);
    if (std.posix.errno(both) == .SUCCESS) return;

    _ = std.posix.system.shutdown(handle, std.posix.SHUT.WR);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: socket_cut shutdownRead wakes a parked read and leaves the write side open" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18985);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    const Parked = struct {
        var woke_at_eof: bool = false;

        // The client never sends anything, so this read has nowhere to wake from except the cut.
        // On Windows it parks in windows_io.readOnce, the engines' read path there and the only
        // one that reports a cancelled receive as end-of-stream (a std reader treats it as
        // unreachable on zig 0.16 and 0.17).
        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            var buf: [1]u8 = undefined;
            if (comptime is_windows) {
                const n = win_io.readOnce(stream.socket.handle, &buf) catch return;
                woke_at_eof = (n == 0);
                return;
            }

            var reader = stream.reader(parked_io, &buf);
            reader.interface.readSliceAll(&buf) catch |err| {
                woke_at_eof = (err == error.EndOfStream);
                return;
            };
        }
    };

    const parked = try std.Thread.spawn(.{}, Parked.run, .{ accepted, io });

    // Give the thread time to actually park in its read before the cut lands.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    shutdownRead(accepted.socket.handle);
    parked.join();

    try std.testing.expect(Parked.woke_at_eof);

    // The write side of the cut socket must still carry a reply.
    var write_buf: [16]u8 = undefined;
    var writer = accepted.writer(io, &write_buf);
    try writer.interface.writeAll("still-writable");
    try writer.interface.flush();

    var read_buf: [32]u8 = undefined;
    var client_reader = client.reader(io, &read_buf);
    var got: [14]u8 = undefined;
    try client_reader.interface.readSliceAll(&got);
    try std.testing.expectEqualStrings("still-writable", &got);
}

test "zix utils: socket_cut shutdownRead on an already-cut socket is a no-op" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18986);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    shutdownRead(accepted.socket.handle);
    shutdownRead(accepted.socket.handle);

    // On Windows a receive issued after the cut fails as PIPE_DISCONNECTED, which only
    // windows_io.readOnce reports as end-of-stream.
    var read_buf: [1]u8 = undefined;
    if (comptime is_windows) {
        const n = try win_io.readOnce(accepted.socket.handle, &read_buf);
        try std.testing.expect(n == 0);
        return;
    }

    var reader = accepted.reader(io, &read_buf);
    try std.testing.expectError(error.EndOfStream, reader.interface.readSliceAll(&read_buf));
}

test "zix utils: socket_cut shutdownBoth wakes a writer parked on a peer that stopped reading" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18987);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    // The client connects and then never reads a byte, which is what fills both socket buffers and
    // parks the sender. No read-side cut reaches a thread parked there.
    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    const Parked = struct {
        var finished: std.atomic.Value(bool) = .init(false);

        // Far more than any platform buffers, so the writer is parked long before the last chunk.
        const TOTAL_BYTES: usize = 64 * 1024 * 1024;

        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            defer finished.store(true, .release);

            var chunk: [64 * 1024]u8 = @splat('x');
            var sent: usize = 0;

            if (comptime is_windows) {
                while (sent < TOTAL_BYTES) : (sent += chunk.len) {
                    win_io.writeAll(stream.socket.handle, &chunk) catch return;
                }

                return;
            }

            var write_buf: [4096]u8 = undefined;
            var writer = stream.writer(parked_io, &write_buf);
            while (sent < TOTAL_BYTES) : (sent += chunk.len) {
                writer.interface.writeAll(&chunk) catch return;
                writer.interface.flush() catch return;
            }
        }
    };

    Parked.finished.store(false, .release);
    const parked = try std.Thread.spawn(.{}, Parked.run, .{ accepted, io });

    // Give the writer time to fill the buffers and park in its send.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
    try std.testing.expect(!Parked.finished.load(.acquire));

    shutdownBoth(accepted.socket.handle);
    parked.join();

    try std.testing.expect(Parked.finished.load(.acquire));
}

test "zix utils: socket_cut the escalation still reaches the send side after a read-side cut" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18984);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    // The order every sweep uses: the read side on one tick, both sides on the next. Darwin answers
    // the second call ENOTCONN because the read side is already gone, and stops there, so without
    // the send-only fallback no FIN ever leaves this socket.
    shutdownRead(accepted.socket.handle);
    shutdownBoth(accepted.socket.handle);

    // Waiting on the wire is the point: the peer has to be told, a local state change is not enough.
    // The budget keeps a missing FIN a failure rather than a hang.
    try std.testing.expect(socket_poll.readableWithin(client.socket.handle, 5_000));

    var read_buf: [1]u8 = undefined;
    var client_reader = client.reader(io, &read_buf);
    try std.testing.expectError(error.EndOfStream, client_reader.interface.readSliceAll(&read_buf));
}

test "zix utils: socket_cut a read-side cut leaves a parked writer parked" {
    if (comptime !is_linux) {
        // The escalation exists because of what a read-side cut does not reach, and that was
        // measured on linux. Windows cancels every pending request with its cut, so a parked send
        // wakes there and this check would be asserting the opposite. Nothing is bound.
        std.log.info("the read-side cut against a parked writer was measured on linux, test skipped", .{});

        return;
    }

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18988);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    const Parked = struct {
        var finished: std.atomic.Value(bool) = .init(false);

        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            defer finished.store(true, .release);

            var chunk: [64 * 1024]u8 = @splat('x');
            var write_buf: [4096]u8 = undefined;
            var writer = stream.writer(parked_io, &write_buf);

            var sent: usize = 0;
            while (sent < 64 * 1024 * 1024) : (sent += chunk.len) {
                writer.interface.writeAll(&chunk) catch return;
                writer.interface.flush() catch return;
            }
        }
    };

    Parked.finished.store(false, .release);
    const parked = try std.Thread.spawn(.{}, Parked.run, .{ accepted, io });

    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
    shutdownRead(accepted.socket.handle);

    // Still stuck: the read side is gone and the send side is untouched, so the sweep has to come
    // back and take the send side away too.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
    try std.testing.expect(!Parked.finished.load(.acquire));

    shutdownBoth(accepted.socket.handle);
    parked.join();

    try std.testing.expect(Parked.finished.load(.acquire));
}
