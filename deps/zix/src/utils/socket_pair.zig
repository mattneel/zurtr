//! A connected pair of stream descriptors, on every supported platform.
//!
//! What:
//!   Tests that drive a serve loop need two ends of one connection without standing up a
//!   listener. POSIX has socketpair for exactly this. Windows has no such call, so the pair is
//!   emulated with a loopback connection, which behaves the same from the caller's side.
//!
//! Note:
//! - Both descriptors are blocking stream sockets. Close each one with utils.fd_io.close.
//! - The Windows path binds an ephemeral loopback port, so it needs no fixed port and cannot
//!   collide with a running example.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const fd_io = @import("fd_io.zig");

const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;

pub const Error = error{ZixSocketPairFailed};

// --------------------------------------------------------- //

/// Open two connected stream descriptors.
///
/// Note:
/// - Anything written to one end is readable from the other, in both directions.
///
/// Param:
/// io - std.Io (only used by the Windows loopback path, ignored elsewhere)
/// fds - *[2]posix.fd_t (filled with the two connected ends)
///
/// Return:
/// - void on success
/// - error.ZixSocketPairFailed when the pair could not be established
pub fn open(io: std.Io, fds: *[2]posix.fd_t) Error!void {
    if (comptime is_windows) return openLoopback(io, fds);

    return openPosix(fds);
}

/// The socketpair syscall, direct on Linux and through libc on the other POSIX targets.
///
/// Note:
/// - The two branches check their own return convention separately. Linux packs a negative errno
///   into the returned usize, libc returns -1 and sets errno. A libc -1 widened to usize is
///   maxInt(usize), which never compares equal to -1, so one shared check would report every
///   libc failure as success and leave the caller holding two undefined descriptors.
fn openPosix(fds: *[2]posix.fd_t) Error!void {
    if (comptime is_windows) return error.ZixSocketPairFailed;

    if (comptime is_linux) {
        const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, fds);
        if (posix.errno(rc) != .SUCCESS) return error.ZixSocketPairFailed;

        return;
    }

    const rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, fds);
    if (posix.errno(rc) != .SUCCESS) return error.ZixSocketPairFailed;
}

/// Loopback stand-in used where socketpair does not exist: listen on an ephemeral port,
/// connect to it, accept, then drop the listener so only the two connected ends remain.
fn openLoopback(io: std.Io, fds: *[2]posix.fd_t) Error!void {
    const addr = std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0) catch return error.ZixSocketPairFailed;

    var listener = addr.listen(io, .{ .mode = .stream, .reuse_address = true }) catch return error.ZixSocketPairFailed;
    defer listener.deinit(io);

    const bound = listener.socket.address;

    const client = bound.connect(io, .{ .mode = .stream }) catch return error.ZixSocketPairFailed;
    errdefer fd_io.close(client.socket.handle);

    const server = listener.accept(io) catch return error.ZixSocketPairFailed;

    fds[0] = client.socket.handle;
    fds[1] = server.socket.handle;
}

/// A connected pair that owns whatever it needs to exist, for callers with no io of their own.
///
/// What:
///   POSIX makes a pair with one syscall and needs no io at all. Windows has to stand up a
///   loopback connection, which does need one. This carries an io only on the platform that
///   requires it, so a caller can ask for two descriptors and nothing else.
///
/// Usage:
/// ```zig
/// var pair = try socket_pair.Pair.open(std.testing.allocator);
/// defer pair.deinit();
///
/// try fd_io.writeAll(pair.fds[0], "ping");
/// ```
pub const Pair = struct {
    fds: [2]posix.fd_t,
    backing: if (is_windows) std.Io.Threaded else void,

    /// Open the pair, standing up an io backend only where the platform needs one.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (unused off Windows)
    ///
    /// Return:
    /// - Pair with both ends open
    /// - error.ZixSocketPairFailed when the pair could not be established
    pub fn open(allocator: std.mem.Allocator) Error!Pair {
        if (comptime !is_windows) {
            var fds: [2]posix.fd_t = undefined;
            try openPosix(&fds);

            return .{ .fds = fds, .backing = {} };
        }

        var backing: std.Io.Threaded = .init(allocator, .{});
        errdefer backing.deinit();

        var fds: [2]posix.fd_t = undefined;
        try openLoopback(backing.io(), &fds);

        return .{ .fds = fds, .backing = backing };
    }

    /// Close both ends and release the io backend.
    pub fn deinit(self: *Pair) void {
        fd_io.close(self.fds[0]);
        fd_io.close(self.fds[1]);

        if (comptime is_windows) self.backing.deinit();
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: socket_pair Pair opens and closes without an io of its own" {
    var pair = try Pair.open(std.testing.allocator);
    defer pair.deinit();

    try fd_io.writeAll(pair.fds[0], "self-contained");

    var got: [14]u8 = undefined;
    try fd_io.readAll(pair.fds[1], &got);

    try std.testing.expectEqualStrings("self-contained", &got);
}

test "zix utils: socket_pair open gives two ends that carry bytes both ways" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair: [2]posix.fd_t = undefined;
    try open(io, &pair);
    defer fd_io.close(pair[0]);
    defer fd_io.close(pair[1]);

    try fd_io.writeAll(pair[0], "ping");

    var forward: [4]u8 = undefined;
    try fd_io.readAll(pair[1], &forward);
    try std.testing.expectEqualStrings("ping", &forward);

    // the reverse direction must work too, a half-duplex pair would break a serve loop test
    try fd_io.writeAll(pair[1], "pong");

    var backward: [4]u8 = undefined;
    try fd_io.readAll(pair[0], &backward);
    try std.testing.expectEqualStrings("pong", &backward);
}

test "zix utils: socket_pair open hands back two distinct descriptors" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair: [2]posix.fd_t = undefined;
    try open(io, &pair);
    defer fd_io.close(pair[0]);
    defer fd_io.close(pair[1]);

    try std.testing.expect(pair[0] != pair[1]);
}
