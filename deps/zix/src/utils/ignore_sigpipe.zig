//! zix ignore sigpipe: process-wide SIGPIPE suppression for stream servers.
//!
//! Note:
//! - A write to a peer whose read side already closed raises SIGPIPE by
//!   default, which terminates the whole process regardless of which
//!   connection triggered it. Every socket write already maps a failed
//!   write to error.BrokenPipe, so ignoring the signal just lets that
//!   existing error path run instead of the process dying.
//! - sigaction() with the same disposition twice is a no-op, so every
//!   engine's run() calls this unconditionally, no lazy guard needed.
//! - Windows has no SIGPIPE: this is a no-op there.

const std = @import("std");
const builtin = @import("builtin");

pub fn ignoreSigpipe() void {
    if (comptime builtin.target.os.tag == .windows) return;

    std.posix.sigaction(std.posix.SIG.PIPE, &.{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);
}

// --------------------------------------------------------- //

test "zix utils: ignoreSigpipe, write to a closed pipe returns BrokenPipe instead of terminating" {
    if (comptime builtin.target.os.tag == .windows) {
        std.log.info("SIGPIPE has no Windows equivalent, test skipped", .{});
        return;
    }

    ignoreSigpipe();

    const fds = try std.Io.Threaded.pipe2(.{});
    _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    const data: []const u8 = "x";
    const rc = std.posix.system.write(fds[1], data.ptr, data.len);

    try std.testing.expectEqual(std.posix.E.PIPE, std.posix.errno(rc));
}
