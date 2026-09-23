//! Portable socket readiness gate: wait until a socket can be read (or written) within a deadline.
//!
//! What:
//!   One helper, one concern. Every zix path that needs a *bounded* socket wait goes through here
//!   rather than each engine carrying its own branch.
//!
//! Note:
//! - This exists because std.Io cannot do it on every target. A timed receive
//!   (std.Io.net.Socket.receiveTimeout) races the receive against a timer, which needs the Io to
//!   run the two concurrently, and std.Io.Threaded's Windows backend answers
//!   error.ConcurrencyUnavailable for a net_receive submitted that way (its own source marks it a
//!   TODO pending overlapped I/O). Waiting for readiness first and then doing a plain blocking
//!   receive needs no concurrency at all, so it behaves the same on every target zix builds for.
//! - Windows has no poll() over ntdll, so readiness there comes from the AFD poll ioctl in
//!   windows_io. Everywhere else it is std.posix.poll.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("windows_io.zig");

const is_windows = builtin.os.tag == .windows;

// --------------------------------------------------------- //

/// Readable event bit. std.posix.POLL is not defined on Windows, so the AFD equivalent stands in.
pub const READABLE: i16 = if (is_windows) win_io.POLLIN else std.posix.POLL.IN;

/// Writable event bit, the counterpart of READABLE.
pub const WRITABLE: i16 = if (is_windows) win_io.POLLOUT else std.posix.POLL.OUT;

/// Wait until a socket is ready for `events`, or the timeout elapses.
///
/// Note:
/// - Pair it with a plain blocking receive / send: readiness is what makes that call return
///   promptly, and no part of the pair needs Io concurrency. See the module note for why a timed
///   std.Io receive is not usable here.
/// - A peer hangup counts as readable on both backends, so the following receive is what reports
///   the close, exactly as it would with poll alone.
///
/// Param:
/// handle - std.posix.socket_t (the socket, from socket.handle)
/// events - i16 (READABLE or WRITABLE)
/// timeout_ms - u32 (0 checks once and returns immediately)
///
/// Return:
/// - true when the socket became ready in time
/// - false when the timeout elapsed first
/// - error.BrokenPipe when the Windows poll device or request fails
pub fn waitReady(handle: std.posix.socket_t, events: i16, timeout_ms: u32) !bool {
    if (comptime is_windows) return win_io.pollReady(handle, events, timeout_ms);

    var pending = [1]std.posix.pollfd{.{ .fd = handle, .events = events, .revents = 0 }};
    const ms: i32 = @intCast(@min(timeout_ms, @as(u32, std.math.maxInt(i32))));

    return try std.posix.poll(&pending, ms) > 0;
}

/// Whether the socket has something to read inside the budget, for a caller that treats "no" as its
/// own timeout error.
///
/// Note:
/// - A budget of 0 is the caller asking for no bound at all, so this reports ready without waiting
///   and the read below blocks exactly as it did before any bound existed. That keeps an
///   unconfigured client on its original behaviour.
/// - A failed readiness check counts as not ready: the caller turns that into its timeout rather
///   than parking on a socket it could not ask about.
/// - Never place this in front of a buffered reader without first asking the reader what it already
///   holds. Bytes in userspace leave the socket quiet, so the gate would wait out its whole budget
///   on data that already arrived. Raw-descriptor callers have no such buffer and are safe.
///
/// Param:
/// handle - std.posix.socket_t (the socket, from socket.handle)
/// budget_ms - u32 (0 skips the wait entirely)
///
/// Return:
/// - true when the socket is readable, or when no bound was configured
/// - false when the budget elapsed first
pub fn readableWithin(handle: std.posix.socket_t, budget_ms: u32) bool {
    if (budget_ms == 0) return true;

    return waitReady(handle, READABLE, budget_ms) catch false;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: socket_poll readableWithin skips the wait when the budget is zero" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9756);
    const idle = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer idle.close(io);

    // Nothing is ever sent here, so a real check reports not ready. A zero budget has to report
    // ready regardless, which is what leaves an unconfigured caller on its original blocking read.
    try std.testing.expect(!readableWithin(idle.handle, 50));
    try std.testing.expect(readableWithin(idle.handle, 0));
}

test "zix utils: socket_poll waitReady reports a datagram already queued on the socket" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const recv_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9754);
    const receiver = try recv_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer receiver.close(io);

    const sender_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
    const sender = try sender_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    try sender.send(io, &recv_addr, "ready");

    // The datagram is already in the socket buffer, so readiness has to be reported inside the
    // budget and the plain receive that follows has to return it without blocking.
    try std.testing.expect(try waitReady(receiver.handle, READABLE, 3000));

    var buf: [16]u8 = undefined;
    const msg = try receiver.receive(io, &buf);
    try std.testing.expectEqualStrings("ready", msg.data);
}

test "zix utils: socket_poll waitReady reports not ready when nothing arrives in the budget" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9755);
    const idle = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer idle.close(io);

    // Nobody sends here, so the wait has to end on its own budget rather than block forever.
    try std.testing.expect(!try waitReady(idle.handle, READABLE, 50));
}
