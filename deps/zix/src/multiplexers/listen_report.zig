//! zix listen report: the startup barrier a shared-nothing worker group binds behind

const std = @import("std");
const builtin = @import("builtin");

/// An error value carried across threads as a plain integer, because an atomic cannot hold an
/// error union. Zero is the "nothing failed yet" slot, which is never a real error code.
///
/// Note:
/// - The width is written out rather than derived from anyerror: 0.17 removed both std.meta.Int
///   and @Type, so no spelling of "the integer anyerror fits in" compiles on 0.16 and 0.17 alike.
///   The guard below fails the build if a compiler ever widens anyerror past it.
const ErrorCode = u16;

comptime {
    if (@bitSizeOf(anyerror) > @bitSizeOf(ErrorCode)) @compileError("anyerror outgrew ErrorCode, widen it");
}

/// What every worker in one SO_REUSEPORT group reports before it starts serving.
///
/// Note:
/// - The problem this exists for: each worker binds its own listener inside its own thread, so a
///   bind failure used to end that thread and nothing else. The parent joined, saw nothing, and
///   returned success while the server was not listening.
/// - Every worker reports exactly once, on both paths, and then waits for the whole group. So the
///   group either serves on every worker or fails on all of them, and the parent gets the cause.
/// - The wait is unbounded on purpose. The only work between spawning a worker and its report is
///   the resolve and the bind, both of which either return or fail, so there is nothing here that
///   can leave the group waiting on a worker that never answers.
///
/// Usage:
/// ```zig
/// var report = listen_report.Report.init(worker_count);
///
/// // in each worker, once
/// var srv = addr.listen(io, .{}) catch |err| {
///     report.failed(io, err);
///     return;
/// };
/// report.bound(io);
/// if (report.awaitGroup(io) != null) return;
///
/// // in the parent, after spawning
/// if (report.awaitGroup(io)) |err| {
///     for (threads) |thread| thread.join();
///     return err;
/// }
/// ```
pub const Report = struct {
    /// Workers that have not reported yet. Reaching zero releases everyone waiting.
    pending: std.atomic.Value(u32),
    /// The first failure any worker reported, zero while there is none.
    first_failure: std.atomic.Value(ErrorCode) = .init(0),
    /// How many workers failed, so the parent can say whether the group failed whole or in part.
    failure_count: std.atomic.Value(u32) = .init(0),

    const Self = @This();

    /// Arm a report for a group of the given size.
    ///
    /// Param:
    /// worker_count - usize (how many workers will report, at least 1)
    ///
    /// Return:
    /// - Report, to be shared by pointer with every worker
    pub fn init(worker_count: usize) Self {
        return .{ .pending = .init(@intCast(@max(1, worker_count))) };
    }

    /// Report that this worker's listener is up.
    ///
    /// Param:
    /// io - std.Io (parks and wakes through the backend off Linux)
    pub fn bound(self: *Self, io: std.Io) void {
        self.settle(io);
    }

    /// Report that this worker could not bind, and why.
    ///
    /// Note:
    /// - The first cause wins. Every worker in the group binds the same address, so they fail for
    ///   the same reason, and the first one is the honest one to report.
    ///
    /// Param:
    /// io - std.Io
    /// err - anyerror (whatever resolve or listen raised)
    pub fn failed(self: *Self, io: std.Io, err: anyerror) void {
        _ = self.first_failure.cmpxchgStrong(0, @intFromError(err), .acq_rel, .acquire);
        _ = self.failure_count.fetchAdd(1, .acq_rel);

        self.settle(io);
    }

    /// Block until every worker has reported.
    ///
    /// Note:
    /// - Safe to call from a worker and from the parent, and safe to call more than once.
    ///
    /// Param:
    /// io - std.Io
    ///
    /// Return:
    /// - null when every worker bound
    /// - the first failure otherwise
    pub fn awaitGroup(self: *Self, io: std.Io) ?anyerror {
        while (true) {
            const left = self.pending.load(.acquire);
            if (left == 0) break;

            futexWait(io, &self.pending, left);
        }

        return self.failure();
    }

    /// The first reported failure, without waiting for the group.
    ///
    /// Return:
    /// - null when nothing has failed
    /// - the first failure otherwise
    pub fn failure(self: *Self) ?anyerror {
        const code = self.first_failure.load(.acquire);
        if (code == 0) return null;

        return @errorFromInt(code);
    }

    /// Report on behalf of workers that were never spawned, so the group is not left waiting.
    ///
    /// Param:
    /// io - std.Io
    /// count - usize (workers the spawn loop did not reach)
    /// err - anyerror (why the spawn stopped)
    pub fn abandon(self: *Self, io: std.Io, count: usize, err: anyerror) void {
        _ = self.first_failure.cmpxchgStrong(0, @intFromError(err), .acq_rel, .acquire);
        _ = self.failure_count.fetchAdd(@intCast(count), .acq_rel);

        for (0..count) |_| self.settle(io);
    }

    /// How many workers failed. Meaningful once awaitGroup has returned.
    ///
    /// Return:
    /// - usize
    pub fn failures(self: *Self) usize {
        return self.failure_count.load(.acquire);
    }

    /// One worker's claim on this report, which reports exactly once however the worker leaves.
    ///
    /// Param:
    /// io - std.Io
    /// on_early_exit - anyerror (reported when the worker returns without saying either way, which
    ///   is every `catch return` between the bind and the serve loop)
    ///
    /// Return:
    /// - Slot, to be closed with defer
    pub fn slot(self: *Self, io: std.Io, on_early_exit: anyerror) Slot {
        return .{ .report = self, .io = io, .on_early_exit = on_early_exit };
    }

    /// Count this worker's report and release the group when it was the last one.
    fn settle(self: *Self, io: std.Io) void {
        if (self.pending.fetchSub(1, .acq_rel) == 1) futexWake(io, &self.pending);
    }
};

/// One worker's claim on a Report.
///
/// Note:
/// - The worker's setup has many exits and only one of them is the serve loop. Without this, a
///   `catch return` on any of the others leaves the group waiting on a worker that is already
///   gone. Closing the slot covers every exit that did not report for itself.
pub const Slot = struct {
    report: *Report,
    io: std.Io,
    on_early_exit: anyerror,
    done: bool = false,

    /// Report that this worker's listeners are up.
    pub fn ok(self: *Slot) void {
        if (self.done) return;

        self.done = true;
        self.report.bound(self.io);
    }

    /// Report that this worker could not come up, and why.
    pub fn fail(self: *Slot, err: anyerror) void {
        if (self.done) return;

        self.done = true;
        self.report.failed(self.io, err);
    }

    /// Report the early-exit cause when the worker left without saying either way.
    pub fn close(self: *Slot) void {
        self.fail(self.on_early_exit);
    }
};

/// Park the calling thread while the word still reads expected. Linux keeps the raw futex fast
/// path, other targets park through the io backend, the same split the driver pools use.
fn futexWait(io: std.Io, word: *std.atomic.Value(u32), expected: u32) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.futex_4arg(&word.raw, .{ .cmd = .WAIT, .private = true }, expected, null);

        return;
    }

    io.futexWaitUncancelable(u32, &word.raw, expected);
}

/// Wake every thread parked on the word. Same branch split as futexWait.
fn futexWake(io: std.Io, word: *std.atomic.Value(u32)) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.futex_3arg(&word.raw, .{ .cmd = .WAKE, .private = true }, std.math.maxInt(i32));

        return;
    }

    io.futexWake(u32, &word.raw, std.math.maxInt(u32));
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix multiplexers: listen report, a single worker that binds releases the group" {
    var report = Report.init(1);

    report.bound(std.testing.io);

    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
    try std.testing.expectEqual(@as(?anyerror, null), report.failure());
}

test "zix multiplexers: listen report, a failure is carried out of the group" {
    var report = Report.init(1);

    report.failed(std.testing.io, error.ZixTestBindRefused);

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestBindRefused), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, the first cause wins" {
    var report = Report.init(2);

    report.failed(std.testing.io, error.ZixTestBindRefused);
    report.failed(std.testing.io, error.ZixTestBindDenied);

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestBindRefused), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, one worker failing fails the whole group" {
    var report = Report.init(3);

    report.bound(std.testing.io);
    report.failed(std.testing.io, error.ZixTestBindRefused);
    report.bound(std.testing.io);

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestBindRefused), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, awaitGroup is answerable more than once" {
    var report = Report.init(1);

    report.bound(std.testing.io);

    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, a zero worker count still arms one slot" {
    var report = Report.init(0);

    report.bound(std.testing.io);

    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, abandon releases workers that never spawned" {
    var report = Report.init(4);

    report.bound(std.testing.io);
    report.abandon(std.testing.io, 3, error.ZixTestSpawnRefused);

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestSpawnRefused), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, a worker parks until the last one reports" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var report = Report.init(2);

    const Waiter = struct {
        fn run(shared: *Report, backend: std.Io, seen: *?anyerror) void {
            seen.* = shared.awaitGroup(backend);
        }
    };

    var seen: ?anyerror = error.ZixTestNotSetYet;
    var waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &report, io, &seen });

    report.bound(io);
    report.failed(io, error.ZixTestBindRefused);
    waiter.join();

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestBindRefused), seen);
}

test "zix multiplexers: listen report, a slot that says ok reports success once" {
    var report = Report.init(1);

    {
        var slot = report.slot(std.testing.io, error.ZixTestSetupFailed);
        defer slot.close();

        slot.ok();
    }

    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, a slot closed without a word reports the early-exit cause" {
    var report = Report.init(1);

    {
        var slot = report.slot(std.testing.io, error.ZixTestSetupFailed);
        defer slot.close();
    }

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestSetupFailed), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, a slot reports its own cause ahead of the early-exit one" {
    var report = Report.init(1);

    {
        var slot = report.slot(std.testing.io, error.ZixTestSetupFailed);
        defer slot.close();

        slot.fail(error.ZixTestBindRefused);
    }

    try std.testing.expectEqual(@as(?anyerror, error.ZixTestBindRefused), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, a slot never reports twice" {
    var report = Report.init(2);

    var first = report.slot(std.testing.io, error.ZixTestSetupFailed);
    first.ok();
    first.ok();
    first.close();

    // Still one report outstanding, so the group has not been released by the repeats.
    try std.testing.expectEqual(@as(u32, 1), report.pending.load(.acquire));

    var second = report.slot(std.testing.io, error.ZixTestSetupFailed);
    second.ok();

    try std.testing.expectEqual(@as(?anyerror, null), report.awaitGroup(std.testing.io));
}

test "zix multiplexers: listen report, the failure count separates a whole group from a part of one" {
    var whole = Report.init(2);
    whole.failed(std.testing.io, error.ZixTestBindRefused);
    whole.failed(std.testing.io, error.ZixTestBindRefused);
    _ = whole.awaitGroup(std.testing.io);

    try std.testing.expectEqual(@as(usize, 2), whole.failures());

    var partial = Report.init(3);
    partial.bound(std.testing.io);
    partial.failed(std.testing.io, error.ZixTestBindRefused);
    partial.bound(std.testing.io);
    _ = partial.awaitGroup(std.testing.io);

    try std.testing.expectEqual(@as(usize, 1), partial.failures());
}

test "zix multiplexers: listen report, a group that all bound counts no failures" {
    var report = Report.init(2);

    report.bound(std.testing.io);
    report.bound(std.testing.io);
    _ = report.awaitGroup(std.testing.io);

    try std.testing.expectEqual(@as(usize, 0), report.failures());
}
