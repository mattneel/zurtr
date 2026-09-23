//! zix http2 context: the per-stream env for the ergonomic req, res, ctx handler shape.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");

/// Backing size of the per-request stack arena on Context.allocator. Stack-based
/// (std.heap.FixedBufferAllocator), no heap call, matches core.zig's stack-only Stream buffers.
pub const CTX_ARENA_BYTES: usize = 4096;

pub const Context = struct {
    /// Connection fd, the raw escape hatch.
    fd: std.posix.fd_t,
    /// HTTP/2 stream id.
    sid: u31,
    /// Absolute deadline in nanoseconds (wall clock). Null = no deadline.
    /// Set at dispatch from the server-wide handler_timeout_ms. Handler may read and overwrite.
    deadline_ns: ?u64 = null,
    /// Io backend for the connection. Carried for symmetry with the other engines' Context.
    io: std.Io,
    /// Per-request scratch allocator, backed by a stack buffer (no heap call).
    allocator: std.mem.Allocator,
    /// Static file directory set by the server from config.public_dir. Empty disables the router's
    /// static fallback, so an unmatched route goes straight to 404.
    public_dir: []const u8 = "",
    /// Peer's SETTINGS_MAX_FRAME_SIZE, the cap on every DATA frame the static fallback emits.
    max_frame_size: u32 = 16384,

    /// Return a copy with the deadline set to now + ms.
    pub fn withTimeout(self: Context, ms: u64) Context {
        var ctx = self;
        ctx.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;

        return ctx;
    }

    /// Set the deadline to now + ms in place.
    pub fn setTimeout(self: *Context, ms: u64) void {
        self.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;
    }

    /// Return a copy with an explicit absolute deadline (wall-clock nanoseconds).
    pub fn withDeadline(self: Context, deadline_ns: u64) Context {
        var ctx = self;
        ctx.deadline_ns = deadline_ns;

        return ctx;
    }

    /// Whether the deadline has passed. False when no deadline is set.
    pub fn isExpired(self: *const Context) bool {
        return self.timedOut();
    }

    /// Whether the deadline has passed. False when no deadline is set. The
    /// handler must check this explicitly, it does not interrupt anything.
    pub fn timedOut(self: *const Context) bool {
        const deadline = self.deadline_ns orelse return false;

        return wallClockNs() >= deadline;
    }
};

/// Return the current wall-clock time in nanoseconds (Unix epoch basis). Mirrors zix.Fix's
/// wallClockNs (same raw clock_gettime, no std.Io.Clock: Http2's core is syscall-direct already).
pub fn wallClockNs() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.wallClockNs();

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix http2: Context.withTimeout, withDeadline, and timedOut" {
    const base = Context{ .fd = TEST_FD, .sid = 1, .io = undefined, .allocator = std.testing.allocator };

    try std.testing.expect(!base.isExpired());
    try std.testing.expect(!base.timedOut());

    const future = base.withTimeout(60_000);
    try std.testing.expect(future.deadline_ns != null);
    try std.testing.expect(!future.timedOut());

    const past = base.withDeadline(1);
    try std.testing.expect(past.timedOut());
    try std.testing.expect(past.isExpired());
}

test "zix http2: Context.setTimeout mutates the deadline in place" {
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = undefined, .allocator = std.testing.allocator };

    try std.testing.expect(ctx.deadline_ns == null);

    ctx.setTimeout(60_000);

    try std.testing.expect(ctx.deadline_ns != null);
    try std.testing.expect(!ctx.timedOut());
}
