//! Blocking read / write / close / readiness on a raw accepted descriptor.
//!
//! What:
//!   The thread-per-connection paths (https, the h2 terminator) hold a bare fd rather than a
//!   std.Io.net.Stream, and drive TLS records straight over it. This module is the one place
//!   that turns those operations into syscalls, so every caller gets the same platform coverage.
//!
//! Note:
//! - Three backends, selected at comptime: Windows through the ntdll shim, Linux through the
//!   direct syscall fast path, and every other POSIX target (macOS, FreeBSD, NetBSD, OpenBSD)
//!   through the libc layer. The Linux branch is kept separate on purpose and must not be
//!   merged into the POSIX one.
//! - Callers that own a std.Io.net.Stream should use the stream reader / writer instead. This
//!   module exists for the paths that only ever receive a descriptor.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const win_io = @import("windows_io.zig");

/// Windows keeps its own shim, Linux its direct syscalls, everything else goes through libc.
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;

pub const ReadError = error{ ReadFailed, ZixConnectionClosed };
pub const WriteError = error{WriteFailed};

/// Outcome of one raw syscall, before a caller turns it into its own error.
const SyscallError = error{ SyscallFailed, Interrupted };

// --------------------------------------------------------- //

/// One read syscall, normalized to a byte count.
///
/// Note:
/// - The two branches must each check their own return convention. Linux packs a negative errno
///   into the returned usize, libc returns -1 and sets errno. A libc -1 widened to usize is
///   maxInt(usize), which can never compare equal to -1, so a shared check would read every libc
///   failure as success and hand back a bogus count.
///
/// Param:
/// fd - posix.fd_t (an accepted, blocking descriptor)
/// buf - []u8 (destination, filled up to its length)
///
/// Return:
/// - the byte count, where 0 means the peer hung up
/// - error.Interrupted when the syscall was interrupted and should be retried
/// - error.SyscallFailed on any other read error
fn readSyscall(fd: posix.fd_t, buf: []u8) SyscallError!usize {
    if (comptime is_linux) {
        const rc = std.os.linux.read(fd, buf.ptr, buf.len);

        return switch (posix.errno(rc)) {
            .SUCCESS => rc,
            .INTR => error.Interrupted,
            else => error.SyscallFailed,
        };
    }

    const rc = posix.system.read(fd, buf.ptr, buf.len);

    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .INTR => error.Interrupted,
        else => error.SyscallFailed,
    };
}

/// One write syscall, normalized to a byte count. Same two-convention split as readSyscall.
///
/// Param:
/// fd - posix.fd_t (an accepted, blocking descriptor)
/// bytes - []const u8 (source, written up to its length)
///
/// Return:
/// - the byte count accepted by the kernel
/// - error.Interrupted when the syscall was interrupted and should be retried
/// - error.SyscallFailed on any other write error
fn writeSyscall(fd: posix.fd_t, bytes: []const u8) SyscallError!usize {
    if (comptime is_linux) {
        const rc = std.os.linux.write(fd, bytes.ptr, bytes.len);

        return switch (posix.errno(rc)) {
            .SUCCESS => rc,
            .INTR => error.Interrupted,
            else => error.SyscallFailed,
        };
    }

    const rc = posix.system.write(fd, bytes.ptr, bytes.len);

    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .INTR => error.Interrupted,
        else => error.SyscallFailed,
    };
}

// --------------------------------------------------------- //

/// Read exactly buf.len bytes, retrying a short read until the buffer is full.
///
/// Note:
/// - An interrupted syscall retries rather than failing, so a signal during a handshake does
///   not drop the connection.
///
/// Param:
/// fd - posix.fd_t (an accepted, blocking descriptor)
/// buf - []u8 (filled completely on success)
///
/// Return:
/// - void when the whole buffer was filled
/// - error.ZixConnectionClosed when the peer hung up mid-read
/// - error.ReadFailed on any other read error
pub fn readAll(fd: posix.fd_t, buf: []u8) ReadError!void {
    var filled: usize = 0;

    while (filled < buf.len) {
        const chunk = buf[filled..];

        if (comptime is_windows) {
            const got = win_io.readOnce(fd, chunk) catch return error.ReadFailed;
            if (got == 0) return error.ZixConnectionClosed;

            filled += got;
            continue;
        }

        const got = readSyscall(fd, chunk) catch |err| switch (err) {
            error.Interrupted => continue,
            error.SyscallFailed => return error.ReadFailed,
        };
        if (got == 0) return error.ZixConnectionClosed;

        filled += got;
    }
}

/// Read once, returning however many bytes arrived.
///
/// Note:
/// - Unlike readAll this reports a short read rather than looping, which is what a frame or
///   record loop wants: it needs to inspect what arrived before asking for more.
///
/// Param:
/// fd - posix.fd_t (an accepted, blocking descriptor)
/// buf - []u8 (filled up to its length)
///
/// Return:
/// - the byte count, where 0 means the peer hung up
/// - error.ReadFailed on a read error
pub fn readOnce(fd: posix.fd_t, buf: []u8) error{ReadFailed}!usize {
    if (comptime is_windows) return win_io.readOnce(fd, buf) catch error.ReadFailed;

    while (true) {
        return readSyscall(fd, buf) catch |err| switch (err) {
            error.Interrupted => continue,
            error.SyscallFailed => error.ReadFailed,
        };
    }
}

/// Write every byte, retrying a short write until the slice is drained.
///
/// Param:
/// fd - posix.fd_t (an accepted, blocking descriptor)
/// bytes - []const u8 (written in full on success)
///
/// Return:
/// - void when every byte was accepted
/// - error.WriteFailed on a write error or a peer that went away
pub fn writeAll(fd: posix.fd_t, bytes: []const u8) WriteError!void {
    if (comptime is_windows) return win_io.writeAll(fd, bytes) catch error.WriteFailed;

    var written: usize = 0;

    while (written < bytes.len) {
        const chunk = bytes[written..];

        const accepted = writeSyscall(fd, chunk) catch |err| switch (err) {
            error.Interrupted => continue,
            error.SyscallFailed => return error.WriteFailed,
        };

        // a kernel that accepts nothing would spin this loop forever, so treat it as a dead peer
        if (accepted == 0) return error.WriteFailed;

        written += accepted;
    }
}

/// Close an accepted descriptor. A close error is not actionable, so it is dropped.
///
/// Param:
/// fd - posix.fd_t
///
/// Return:
/// - void
pub fn close(fd: posix.fd_t) void {
    if (comptime is_windows) {
        win_io.close(fd);
        return;
    }

    if (comptime is_linux) {
        _ = std.os.linux.close(fd);
        return;
    }

    _ = posix.system.close(fd);
}

/// Block until fd is readable or the timeout elapses.
///
/// Note:
/// - The Windows read path blocks inside the ntdll shim, so there is no readiness wait to
///   perform there and the call reports readable straight away.
///
/// Param:
/// fd - posix.fd_t
/// timeout_ms - i32 (negative waits forever)
///
/// Return:
/// - true when the descriptor became readable
/// - false on timeout or a poll error
pub fn waitReadable(fd: posix.fd_t, timeout_ms: i32) bool {
    if (comptime is_windows) return true;

    var pending = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};

    // std.posix.poll retries an interrupted wait itself, so there is no INTR loop to run here.
    const ready = posix.poll(&pending, timeout_ms) catch return false;

    return ready > 0 and (pending[0].revents & posix.POLL.IN) != 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: fd_io writeAll then readAll moves a whole buffer across a connected pair" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    defer close(pair[0]);
    defer close(pair[1]);

    const payload = "fd_io round trip";
    try writeAll(pair[0], payload);

    var received: [payload.len]u8 = undefined;
    try readAll(pair[1], &received);

    try std.testing.expectEqualStrings(payload, &received);
}

test "zix utils: fd_io readAll reports ConnectionClosed when the peer hangs up early" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    defer close(pair[1]);

    try writeAll(pair[0], "half");
    close(pair[0]);

    // asking for more than the peer ever sent must surface the hangup, not a short read
    var received: [16]u8 = undefined;
    try std.testing.expectError(error.ZixConnectionClosed, readAll(pair[1], &received));
}

test "zix utils: fd_io waitReadable sees pending bytes and times out on a quiet descriptor" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    defer close(pair[0]);
    defer close(pair[1]);

    // quiet peer: the wait must expire rather than report readable
    try std.testing.expect(!waitReadable(pair[1], 10));

    try writeAll(pair[0], "x");

    try std.testing.expect(waitReadable(pair[1], 1000));
}

test "zix utils: fd_io readAll on a closed descriptor errors instead of reporting a filled buffer" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    close(pair[0]);
    close(pair[1]);

    // a failed read must never look like a completed one: reporting success here would hand the
    // caller a buffer it believes is filled, which is what a shared errno check used to do
    var received: [8]u8 = undefined;
    try std.testing.expectError(error.ReadFailed, readAll(pair[1], &received));
}

test "zix utils: fd_io readOnce on a closed descriptor errors instead of reporting a byte count" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    close(pair[0]);
    close(pair[1]);

    var received: [8]u8 = undefined;
    try std.testing.expectError(error.ReadFailed, readOnce(pair[1], &received));
}

test "zix utils: fd_io writeAll on a closed descriptor errors instead of reporting a drained slice" {
    if (comptime is_windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try testSocketPair(&pair);
    close(pair[0]);
    close(pair[1]);

    try std.testing.expectError(error.WriteFailed, writeAll(pair[1], "never leaves"));
}

/// A connected descriptor pair for the tests above, on every POSIX target.
///
/// Note:
/// - Each branch checks its own return convention, for the reason readSyscall spells out. A pair
///   that failed to open must surface as an error here, never as two undefined descriptors.
/// - The guard below is what keeps the body off Windows: a comptime true early return makes the
///   rest of the function dead, so the POSIX calls are never analyzed there. It names a real error
///   rather than a skip, because a skip would leave the caller holding two descriptors that were
///   never opened. Every caller guards Windows first, so the error is unreachable at runtime.
fn testSocketPair(fds: *[2]posix.fd_t) !void {
    if (comptime is_windows) return error.ZixSocketPairNeedsPosix;

    if (comptime is_linux) {
        const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, fds);
        if (posix.errno(rc) != .SUCCESS) return error.ZixSocketPairFailed;

        return;
    }

    const rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, fds);
    if (posix.errno(rc) != .SUCCESS) return error.ZixSocketPairFailed;
}
