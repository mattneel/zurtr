//! zix http1 context: the per-request handle for the ergonomic req, res, ctx
//! handler shape. A cheap value struct, built per request, never heap-held.
//!
//! Two lanes construct it:
//! - Async lane: io is a yielding backend (the engine scheduler), so a driver
//!   round trip parks the fiber instead of blocking the worker. deadline lives
//!   in the struct, not a threadlocal, because many fibers share one scheduler
//!   thread and a threadlocal deadline would be clobbered across a yield.
//! - Sync path: io is the worker io, used only if the handler makes a driver
//!   call inline.

const std = @import("std");
const Logger = @import("../../logger/logger.zig").Logger;

pub const Context = struct {
    /// The io the request runs on. Async lane: a yielding backend (parks on a
    /// driver round trip). Sync path: the worker io.
    io: std.Io,
    /// Per-request allocator. Async lane: the fiber arena. Sync path: a worker
    /// scratch arena.
    allocator: std.mem.Allocator,
    /// Connection fd, the raw escape hatch. Response wraps it in the normal case.
    fd: std.posix.fd_t,
    /// Optional logger from config.logger. Null when the server has none.
    logger: ?*Logger = null,
    /// Optional handler deadline (config.handler_timeout_ms). Null = no deadline.
    /// Held per Context, not threadlocal: concurrent fibers on one scheduler
    /// thread each carry their own.
    deadline: ?std.Io.Clock.Timestamp = null,

    /// Build a context over an io, allocator, and fd.
    ///
    /// Param:
    /// io - std.Io (async lane: a yielding backend, sync path: the worker io)
    /// allocator - std.mem.Allocator (per-request scratch)
    /// fd - std.posix.fd_t (the connection)
    ///
    /// Return:
    /// - Context
    pub fn init(io: std.Io, allocator: std.mem.Allocator, fd: std.posix.fd_t) Context {
        return .{ .io = io, .allocator = allocator, .fd = fd };
    }

    /// Return a copy with the deadline set to now + ms.
    pub fn withTimeout(self: Context, ms: u64) Context {
        var ctx = self;
        ctx.deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            std.Io.Clock.Duration{ .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .real },
        );

        return ctx;
    }

    /// Return a copy with an explicit deadline timestamp.
    pub fn withDeadline(self: Context, ts: std.Io.Clock.Timestamp) Context {
        var ctx = self;
        ctx.deadline = ts;

        return ctx;
    }

    /// Set the deadline to now + ms in place.
    pub fn setTimeout(self: *Context, ms: u64) void {
        self.deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            std.Io.Clock.Duration{ .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .real },
        );
    }

    /// Whether the deadline has passed. False when no deadline is set.
    pub fn isExpired(self: Context) bool {
        return self.timedOut();
    }

    /// Whether the deadline has passed. False when no deadline is set. The
    /// handler must check this explicitly, it does not interrupt anything.
    pub fn timedOut(self: Context) bool {
        const deadline = self.deadline orelse return false;

        return std.Io.Clock.Timestamp.now(self.io, .real).compare(.gte, deadline);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: Context.timedOut null deadline always false" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const ctx = Context{ .io = undefined, .allocator = std.testing.allocator, .fd = -1 };
    try std.testing.expect(!ctx.timedOut());
}

test "zix http1: Context.isExpired null deadline always false" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const ctx = Context{ .io = undefined, .allocator = std.testing.allocator, .fd = -1 };
    try std.testing.expect(!ctx.isExpired());
}

test "zix http1: Context.withDeadline sets the exact timestamp on a copy" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const ctx = Context.init(threaded.io(), std.testing.allocator, -1);
    const past = std.Io.Clock.Timestamp.now(threaded.io(), .real);
    const dated = ctx.withDeadline(past);

    try std.testing.expect(ctx.deadline == null);
    try std.testing.expect(dated.deadline != null);
    try std.testing.expect(dated.timedOut());
}

test "zix http1: Context.init sets io, allocator, fd with no deadline" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const ctx = Context.init(threaded.io(), std.testing.allocator, 7);
    try std.testing.expectEqual(@as(std.posix.fd_t, 7), ctx.fd);
    try std.testing.expect(ctx.deadline == null);
    try std.testing.expect(!ctx.isExpired());
}
