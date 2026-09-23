//! Background flush thread that owns every logger write syscall.

const std = @import("std");
const portable_sleep = @import("../utils/portable_sleep.zig");

// --------------------------------------------------------- //

/// How long the thread naps while a burst may still be in progress.
///
/// Note:
/// - This bounds how long a producer can be stuck when it fills both buffers: it is waiting for
///   this thread to come back and write the one it handed over. A long nap here was measured at
///   roughly 0.9 ms per stall with eight producers, which cost more than the batching saved.
pub const BUSY_NAP_NS: u64 = 20 * std.time.ns_per_us;

/// How long the thread naps once a burst is well and truly over.
///
/// Note:
/// - It is also the worst case for how long `stop` takes to join, so it stays short enough that
///   building and tearing down a logger in a test costs nothing noticeable.
pub const IDLE_NAP_NS: u64 = 2 * std.time.ns_per_ms;

/// How long buffered records may sit before they are written even though the buffer is not full.
/// This is the batching window for a logger that only trickles.
pub const LINGER_NS: u64 = 2 * std.time.ns_per_ms;

/// Quiet passes before the nap lengthens. Short enough that a burst keeps the thread responsive,
/// long enough that a genuinely idle logger stops waking 50,000 times a second.
const PASSES_BEFORE_BACKOFF: u32 = 64;

/// The thread that drains a logger's buffers.
///
/// Note:
/// - The context is type erased on purpose. A generic parameter here would make the logger's own
///   struct definition depend on a generic instantiated over itself.
pub const Flusher = struct {
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    context: ?*anyopaque = null,
    pump: ?*const fn (*anyopaque, bool) bool = null,

    const Self = @This();

    // --------------------------------------------------------- //

    /// Spawn the thread. Calling this twice without a `stop` in between is a caller error.
    ///
    /// Param:
    /// context - *anyopaque (passed back to pump on every pass, must outlive the thread)
    /// pump - *const fn (*anyopaque, bool) bool (one drain pass, the bool asks for urgent work
    ///   only, the result says whether anything was written)
    ///
    /// Return:
    /// - void
    /// - error.OutOfMemory or a spawn error when the thread cannot start
    pub fn start(self: *Self, context: *anyopaque, pump: *const fn (*anyopaque, bool) bool) !void {
        self.context = context;
        self.pump = pump;
        self.stopping.store(false, .release);

        self.thread = try std.Thread.spawn(.{}, loop, .{self});
    }

    /// Stop the thread and wait for it. Safe to call when it never started.
    ///
    /// Note:
    /// - The thread runs one last pass after it sees the stop, so records buffered during the
    ///   final nap still reach the descriptor.
    pub fn stop(self: *Self) void {
        const thread = self.thread orelse return;

        self.stopping.store(true, .release);
        thread.join();

        self.thread = null;
        self.context = null;
        self.pump = null;
    }

    pub fn running(self: *const Self) bool {
        return self.thread != null;
    }

    fn loop(self: *Self) void {
        const context = self.context.?;
        const pump = self.pump.?;

        var quiet_passes: u32 = 0;
        var since_linger_ns: u64 = 0;

        while (!self.stopping.load(.acquire)) {
            // Keeping up with a busy producer comes first, and never naps: a nap taken while a
            // buffer is already handed over is exactly what would stall that producer.
            if (pump(context, true)) {
                quiet_passes = 0;
                since_linger_ns = 0;

                continue;
            }

            // Nothing urgent. Nap briefly while a burst could still be running, and only stretch
            // the nap once the logger has been quiet for a while.
            quiet_passes +|= 1;
            const nap = if (quiet_passes > PASSES_BEFORE_BACKOFF) IDLE_NAP_NS else BUSY_NAP_NS;
            portable_sleep.sleepNs(nap);
            since_linger_ns += nap;

            // A trickle of records would otherwise sit in a half-empty buffer indefinitely. The
            // linger window is what puts them on the descriptor, and bounds the syscall rate for
            // a logger that never fills a buffer.
            if (since_linger_ns >= LINGER_NS) {
                since_linger_ns = 0;
                _ = pump(context, false);
            }
        }

        _ = pump(context, false);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const Counter = struct {
    passes: std.atomic.Value(u32) = .init(0),

    fn pump(context: *anyopaque, urgent_only: bool) bool {
        const self: *Counter = @ptrCast(@alignCast(context));
        _ = urgent_only;
        _ = self.passes.fetchAdd(1, .acq_rel);

        return false;
    }
};

test "zix logger flush: stop on a flusher that never started does nothing" {
    var flusher = Flusher{};

    try std.testing.expect(!flusher.running());
    flusher.stop();
    try std.testing.expect(!flusher.running());
}

test "zix logger flush: the thread runs passes until it is stopped" {
    var counter = Counter{};
    var flusher = Flusher{};

    try flusher.start(&counter, Counter.pump);
    try std.testing.expect(flusher.running());

    // Long enough for several ticks, short enough not to slow the suite.
    portable_sleep.sleepNs(20 * std.time.ns_per_ms);

    flusher.stop();

    const passes = counter.passes.load(.acquire);
    std.log.info(".FLUSH: the thread completed {d} passes before stopping", .{passes});

    try std.testing.expect(passes >= 2);
    try std.testing.expect(!flusher.running());
}

test "zix logger flush: stop runs one final pass so nothing buffered is lost" {
    var counter = Counter{};
    var flusher = Flusher{};

    try flusher.start(&counter, Counter.pump);

    // Stop straight away: even with no time to tick, the final pass has to happen.
    flusher.stop();

    try std.testing.expect(counter.passes.load(.acquire) >= 1);
}

test "zix logger flush: a flusher can be restarted after a stop" {
    var counter = Counter{};
    var flusher = Flusher{};

    try flusher.start(&counter, Counter.pump);
    flusher.stop();
    const after_first = counter.passes.load(.acquire);

    try flusher.start(&counter, Counter.pump);
    flusher.stop();

    try std.testing.expect(counter.passes.load(.acquire) > after_first);
}
