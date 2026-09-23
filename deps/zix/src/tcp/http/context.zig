//! zix http context

const std = @import("std");
const Logger = @import("../../logger/logger.zig").Logger;

pub const Context = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    /// Logger injected by the server from HttpServerConfig.logger.
    /// Null when the server was started without a logger.
    logger: ?*Logger = null,
    /// Raw TCP stream, available for WebSocket upgrade handlers.
    /// Normal HTTP handlers should not use this directly.
    stream: std.Io.net.Stream = undefined,
    /// Optional handler deadline set by the server from config.handler_timeout_ms.
    /// Null when handler_timeout_ms == 0 (disabled).
    /// Use setTimeout() to set in place, withTimeout() to get a modified copy.
    /// Check isExpired() or timedOut() between expensive steps.
    deadline: ?std.Io.Clock.Timestamp = null,
    /// Static file directory set by the server from config.public_dir. Empty
    /// disables the router's static-file fallback (Router.dispatch reads this).
    public_dir: []const u8 = "",

    /// Return a copy of ctx with deadline set to now + ms.
    pub fn withTimeout(self: Context, ms: u64) Context {
        var c = self;
        c.deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            std.Io.Clock.Duration{ .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .real },
        );
        return c;
    }

    /// Return a copy of ctx with an explicit deadline timestamp.
    pub fn withDeadline(self: Context, ts: std.Io.Clock.Timestamp) Context {
        var c = self;
        c.deadline = ts;
        return c;
    }

    /// Set the deadline to now + ms milliseconds in place.
    /// Call from the handler to extend or override the deadline at runtime.
    pub fn setTimeout(self: *Context, ms: u64) void {
        self.deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            std.Io.Clock.Duration{ .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .real },
        );
    }

    /// Return true when the deadline has passed. False when deadline is null.
    /// Does not cancel or interrupt anything, handler must check explicitly.
    pub fn isExpired(self: Context) bool {
        return self.timedOut();
    }

    /// Return true when the deadline has passed. False when deadline is null.
    /// Does not cancel or interrupt anything. Handlers must check this explicitly.
    pub fn timedOut(self: Context) bool {
        const d = self.deadline orelse return false;
        return std.Io.Clock.Timestamp.now(self.io, .real).compare(.gte, d);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: Context.timedOut null deadline always false" {
    const ctx = Context{ .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(!ctx.timedOut());
}

test "zix http: Context.isExpired null deadline always false" {
    const ctx = Context{ .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(!ctx.isExpired());
}
