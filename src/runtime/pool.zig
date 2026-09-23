//! Bounded worker pool with completion delivery.
//!
//! Execution path for work that must not run on the reactor thread: blocking
//! database operations for live sessions, agent steps, and job bodies when a
//! role runs in-process. Work items run on pool threads; results are pushed to
//! a bounded completion queue that the consumer drains — in the `.ASYNC` lane
//! that consumer is the connection's fiber, which a completion resumes
//! (`docs/architecture/decisions.md` D2). There is no transport wake fd: the
//! `.EPOLL` / `.URING` loops cannot be woken from another thread yet.
//! See `docs/architecture/contracts.md` §1.
//!
//! Contract:
//! - `submit` never blocks the caller beyond a bounded queue push; when
//!   every worker's queue is full it returns `error.QueueFull` (the caller
//!   decides: shed, park, or retry) — the pool never grows without bound.
//! - A completion is delivered exactly once: either drained by the reactor or
//!   freed by `drain`/`deinit`.
//! - `run` is called on a pool thread with no reactor state; it must not touch
//!   session state or transport structures. It returns an owned payload that
//!   the completion carries back.
//!
//! # Intake: per-worker queues, with stealing
//!
//! Each worker owns a lock-free MPMC ring (`runtime/mpmc.zig`). `submit` pushes to a ring that has room
//! — round-robin first, then a bounded scan — and a worker with an empty ring takes from another worker's.
//! That is work stealing, and it is what keeps one busy worker from holding a queue while its neighbours
//! idle: a submit never waits on whoever happens to be running.
//!
//! Two deliberate choices:
//!
//! - **Parking is signalled, with a timeout as a guard.** A submit signals after it pushes, and an idle
//!   worker waits on that signal — the timeout exists only because the push is lock-free and therefore
//!   outside the mutex, so a wakeup can in principle be missed between "ring looks empty" and "start
//!   waiting". The timeout makes that a few milliseconds of latency instead of a lost wakeup. It is not
//!   the mechanism; the signal is.
//! - **The completion queue is still one mutex.** Its consumer is the reactor, single-threaded, and its
//!   producers are already the pool's own threads: there is no stealing to do there, and the interesting
//!   contention is on the intake, where producers are arbitrary threads. Replacing it would be churn,
//!   not progress.

const std = @import("std");
const Io = std.Io;
const mpmc = @import("mpmc.zig");

pub const Completion = struct {
    /// Opaque token identifying the originating request/session/step. The
    /// consumer interprets it; the pool never dereferences it.
    token: u64,
    /// Result payload allocated by the worker with the pool's allocator.
    /// Ownership transfers to the consumer of the completion.
    payload: []u8,
    /// Error name captured from the work function ("" when the work
    /// returned the payload successfully).
    err: []const u8 = "",
    /// Monotonic sequence for ordering diagnostics.
    seq: u64 = 0,
};

pub const WorkFn = *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, token: u64) WorkResult;

pub const WorkResult = struct {
    payload: []u8 = &.{},
    err: []const u8 = "",
};

/// How long an idle worker sleeps before re-checking every ring. Only a guard against a missed wakeup:
/// submissions signal, and that is what normally returns a worker to work.
const idle_wait_ms: u32 = 5;

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: Io,
    work_ctx: *anyopaque,
    work_fn: WorkFn,

    threads: []std.Thread,
    /// One intake ring per worker: the worker pops its own, and steals from the others when it is empty.
    rings: []mpmc.Queue(Item),
    /// Round-robin cursor for `submit`, so submissions spread instead of piling on one worker.
    next_ring: std.atomic.Value(usize) = .init(0),
    mutex: Io.Mutex = .init,
    /// Signalled after a push; idle workers wait on it (see the module doc's note on the timeout guard).
    work_ready: Io.Condition = .init,
    /// Signaled when a completion is appended; used by blocking drains.
    completion_ready: Io.Condition = .init,
    /// Completions ready for the reactor to drain. One mutex is deliberate: one consumer, and its
    /// producers are the pool's own threads.
    completions: std.ArrayList(Completion) = .empty,
    per_ring_capacity: usize,
    shutting_down: bool = false,
    next_seq: u64 = 1,
    /// Set by the owner; called (outside the pool mutex) after a completion
    /// is enqueued so the reactor can be woken. Must be cheap and
    /// thread-safe (typically `io.wake`).
    wake_fn: ?*const fn (wake_ctx: *anyopaque) void = null,
    wake_ctx: ?*anyopaque = null,
    /// Diagnostics.
    completed_count: u64 = 0,
    dropped_count: u64 = 0,

    const Item = struct { token: u64, seq: u64 };

    pub const Error = std.Thread.SpawnError || mpmc.Queue(Item).Error || error{ QueueFull, Shutdown };

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        thread_count: usize,
        pending_capacity: usize,
        work_ctx: *anyopaque,
        work_fn: WorkFn,
    ) Error!*Pool {
        std.debug.assert(thread_count > 0);
        std.debug.assert(pending_capacity > 0);
        const self = try allocator.create(Pool);
        errdefer allocator.destroy(self);
        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        // The bound is the caller's `pending_capacity` in total, split evenly and rounded up to a power
        // of two because the ring is indexed by a mask.
        const per_ring = std.math.ceilPowerOfTwo(usize, @max(2, pending_capacity / thread_count)) catch
            return error.OutOfMemory;
        const rings = try allocator.alloc(mpmc.Queue(Item), thread_count);
        errdefer allocator.free(rings);
        var initialised: usize = 0;
        errdefer for (rings[0..initialised]) |*ring| ring.deinit();
        for (rings) |*ring| {
            ring.* = try mpmc.Queue(Item).init(allocator, per_ring);
            initialised += 1;
        }

        self.* = .{
            .allocator = allocator,
            .io = io,
            .work_ctx = work_ctx,
            .work_fn = work_fn,
            .threads = threads,
            .rings = rings,
            .per_ring_capacity = per_ring,
        };
        var spawned: usize = 0;
        errdefer {
            // Tear down whatever started before failing.
            self.mutex.lockUncancelable(self.io);
            self.shutting_down = true;
            self.work_ready.broadcast(self.io);
            self.mutex.unlock(self.io);
            for (threads[0..spawned]) |t| t.join();
        }
        for (threads, 0..) |*t, index| {
            t.* = try std.Thread.spawn(.{}, workerMain, .{ self, index });
            spawned += 1;
        }
        return self;
    }

    pub fn deinit(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        self.shutting_down = true;
        self.work_ready.broadcast(self.io);
        self.mutex.unlock(self.io);
        for (self.threads) |t| t.join();
        for (self.rings) |*ring| ring.deinit();
        self.allocator.free(self.rings);
        for (self.completions.items) |c| self.freeCompletion(c);
        self.completions.deinit(self.allocator);
        const allocator = self.allocator;
        allocator.free(self.threads);
        allocator.destroy(self);
    }

    pub fn setWake(self: *Pool, ctx: *anyopaque, f: *const fn (*anyopaque) void) void {
        self.wake_ctx = ctx;
        self.wake_fn = f;
    }

    /// Queue work. Returns `error.QueueFull` when every worker's ring is full.
    pub fn submit(self: *Pool, token: u64) Error!void {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.shutting_down) return error.Shutdown;
        }

        const item = Item{ .token = token, .seq = self.next_seq };
        const count = self.rings.len;
        const start = self.next_ring.fetchAdd(1, .monotonic) % count;

        // Round-robin first, then a bounded scan: a full ring is momentary, and the point of having one
        // per worker is that another usually has room.
        var offset: usize = 0;
        while (offset < count) : (offset += 1) {
            const index = (start + offset) % count;
            if (self.rings[index].push(item)) {
                self.next_seq += 1;
                // Outside the mutex the push already happened; the signal is what actually wakes someone.
                self.mutex.lockUncancelable(self.io);
                self.work_ready.signal(self.io);
                self.mutex.unlock(self.io);

                return;
            }
        }

        return error.QueueFull;
    }

    /// Move up to `out.len` completions out of the queue. Returns the count.
    /// The caller owns each returned completion's payload and must free it
    /// with `freePayload`.
    pub fn drain(self: *Pool, out: []Completion) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const n = @min(out.len, self.completions.items.len);
        @memcpy(out[0..n], self.completions.items[0..n]);
        const rest = self.completions.items.len - n;
        std.mem.copyForwards(Completion, self.completions.items[0..rest], self.completions.items[n..]);
        self.completions.items.len = rest;
        return n;
    }

    pub fn freePayload(self: *Pool, payload: []u8) void {
        if (payload.len == 0) return;
        self.allocator.free(payload);
    }

    /// Wait up to `timeout_ms` for at least one completion, then drain up to
    /// `out.len` of them. Returns the count (0 on timeout). Used by role loops
    /// and tests; the reactor uses the non-blocking `drain`.
    pub fn drainBlocking(self: *Pool, out: []Completion, timeout_ms: u32) usize {
        const timeout: Io.Timeout = .{ .duration = .{
            .raw = Io.Duration.fromMilliseconds(timeout_ms),
            .clock = .awake,
        } };
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.completions.items.len == 0) {
            self.completion_ready.waitTimeout(self.io, &self.mutex, timeout) catch {};
        }
        const n = @min(out.len, self.completions.items.len);
        @memcpy(out[0..n], self.completions.items[0..n]);
        const rest = self.completions.items.len - n;
        std.mem.copyForwards(Completion, self.completions.items[0..rest], self.completions.items[n..]);
        self.completions.items.len = rest;
        return n;
    }

    /// How much work is queued across every worker. Each ring reports its own count, so this is a
    /// snapshot: a submission in flight can be counted either way, which is fine for diagnostics and
    /// bounds and is exactly what it is for.
    pub fn pendingCount(self: *Pool) usize {
        var total: usize = 0;
        for (self.rings) |*ring| total += ring.len();

        return total;
    }

    pub fn completionCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.completions.items.len;
    }

    fn freeCompletion(self: *Pool, c: Completion) void {
        if (c.payload.len > 0) self.allocator.free(c.payload);
    }

    fn workerMain(self: *Pool, index: usize) void {
        while (true) {
            if (self.popWork(index)) |item| {
                const result = self.work_fn(self.work_ctx, self.allocator, item.token);

                self.mutex.lockUncancelable(self.io);
                if (self.shutting_down) {
                    // Owner is gone: free the payload rather than leaking it.
                    if (result.payload.len > 0) self.allocator.free(result.payload);
                    self.mutex.unlock(self.io);
                    return;
                }
                self.completions.append(self.allocator, .{
                    .token = item.token,
                    .payload = result.payload,
                    .err = result.err,
                    .seq = item.seq,
                }) catch {
                    if (result.payload.len > 0) self.allocator.free(result.payload);
                    self.dropped_count += 1;
                    self.mutex.unlock(self.io);
                    continue;
                };
                self.completed_count += 1;
                self.completion_ready.signal(self.io);
                self.mutex.unlock(self.io);

                if (self.wake_fn) |f| f(self.wake_ctx.?);

                continue;
            }

            // Nothing anywhere: wait for a submit's signal. The timeout is the guard described in the
            // module doc, not the mechanism.
            self.mutex.lockUncancelable(self.io);
            if (self.shutting_down) {
                self.mutex.unlock(self.io);
                return;
            }
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromMilliseconds(idle_wait_ms),
                .clock = .awake,
            } };
            self.work_ready.waitTimeout(self.io, &self.mutex, timeout) catch {};
            self.mutex.unlock(self.io);
        }
    }

    /// Own ring first, then the others: that order is what makes stealing cheap for the common case and
    /// correct for the busy one.
    fn popWork(self: *Pool, index: usize) ?Item {
        if (self.rings[index].pop()) |item| return item;

        var offset: usize = 1;
        while (offset < self.rings.len) : (offset += 1) {
            const other = (index + offset) % self.rings.len;
            if (self.rings[other].pop()) |item| return item;
        }

        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const TestCtx = struct {
    /// Echo the token back as an 8-byte payload.
    fn work(ctx: *anyopaque, alloc: std.mem.Allocator, token: u64) WorkResult {
        _ = ctx;
        const buf = alloc.alloc(u8, 8) catch return .{ .err = "OutOfMemory" };
        std.mem.writeInt(u64, buf[0..8], token, .little);
        return .{ .payload = buf };
    }
};

fn testIo() std.Io.Threaded {
    return .init(testing.allocator, .{});
}

/// Blocking wait for one completion (bounded by the pool's own timeout).
fn waitForCompletion(pool: *Pool, out: *Completion) bool {
    return pool.drainBlocking(out[0..1], 10_000) == 1;
}

test "pool runs work and delivers an owned completion" {
    var threaded = testIo();
    defer threaded.deinit();

    var ctx: u8 = 0;
    const pool = try Pool.init(testing.allocator, threaded.io(), 2, 8, &ctx, TestCtx.work);
    defer pool.deinit();

    try pool.submit(42);
    var c: Completion = undefined;
    try testing.expect(waitForCompletion(pool, &c));
    defer pool.freePayload(c.payload);
    try testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, c.payload[0..8], .little));
    try testing.expectEqualStrings("", c.err);
}

test "pool preserves order for a single worker" {
    var threaded = testIo();
    defer threaded.deinit();

    var ctx: u8 = 0;
    const pool = try Pool.init(testing.allocator, threaded.io(), 1, 16, &ctx, TestCtx.work);
    defer pool.deinit();

    for (1..6) |i| try pool.submit(i);
    var seen: [5]u64 = undefined;
    for (&seen) |*slot| {
        var c: Completion = undefined;
        try testing.expect(waitForCompletion(pool, &c));
        slot.* = std.mem.readInt(u64, c.payload[0..8], .little);
        pool.freePayload(c.payload);
    }
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4, 5 }, &seen);
}

test "pool enforces the pending bound" {
    var threaded = testIo();
    defer threaded.deinit();

    var ctx: u8 = 0;
    const pool = try Pool.init(testing.allocator, threaded.io(), 1, 2, &ctx, TestCtx.work);
    defer pool.deinit();

    var full_hits: usize = 0;
    for (0..64) |i| {
        pool.submit(i) catch |err| {
            try testing.expectEqual(Pool.Error.QueueFull, err);
            full_hits += 1;
        };
    }
    try testing.expect(full_hits > 0);

    // Drain everything that completes so deinit has nothing left to free, and count what came back:
    // the bound test's real claim is that the pool ran exactly what it accepted, no more and no less.
    var buf: [64]Completion = undefined;
    var drained: usize = 0;
    var guard: usize = 0;
    while (guard < 1_000) : (guard += 1) {
        const n = pool.drainBlocking(&buf, 50);
        for (buf[0..n]) |c| pool.freePayload(c.payload);
        drained += n;
        // Quiet means nothing accepted is still queued and nothing completed is undrained.
        if (drained == 64 - full_hits and pool.pendingCount() == 0 and pool.completionCount() == 0) break;
    }
    try testing.expectEqual(@as(usize, 64 - full_hits), drained);
    try testing.expectEqual(@as(usize, 0), pool.pendingCount());
    try testing.expectEqual(@as(usize, 0), pool.completionCount());
}

test "deinit frees undrained completions" {
    var threaded = testIo();
    defer threaded.deinit();

    var ctx: u8 = 0;
    const pool = try Pool.init(testing.allocator, threaded.io(), 1, 8, &ctx, TestCtx.work);
    try pool.submit(7);
    // Wait for a completion to exist without draining it.
    if (pool.completionCount() == 0) _ = pool.drainBlocking(&[_]Completion{}, 10_000);
    try testing.expect(pool.completionCount() > 0);
    pool.deinit(); // testing.allocator fails the test on any leak
}

/// Work that records which thread ran it, so the test can tell "the pool ran it" from "more than one
/// worker shared it" — which is the whole claim of a stealing pool.
const ThreadRecorder = struct {
    const shared_count = 8;

    const Recorder = struct {
        seen: [shared_count]std.atomic.Value(u64) = @splat(.init(0)),
        slots: std.atomic.Value(usize) = .init(0),

        /// One slot per distinct thread, up to `shared_count`; extra threads are ignored, which is fine
        /// because the assertion is "more than one", not "exactly N".
        fn record(self: *Recorder) void {
            const id: u64 = @intCast(std.Thread.getCurrentId());
            const count = self.slots.load(.acquire);
            for (self.seen[0..@min(count, shared_count)]) |slot| {
                if (slot.load(.acquire) == id) return;
            }
            if (count >= shared_count) return;
            if (self.slots.cmpxchgWeak(count, count + 1, .acq_rel, .acquire)) |_| return;
            self.seen[count].store(id, .release);
        }

        fn distinct(self: *Recorder) usize {
            var n: usize = 0;
            for (self.seen) |slot| {
                if (slot.load(.acquire) != 0) n += 1;
            }

            return n;
        }
    };

    fn work(raw: *anyopaque, alloc: std.mem.Allocator, token: u64) WorkResult {
        // The pool is handed a `*Recorder` as its work context, so that is what comes back out.
        const recorder: *Recorder = @ptrCast(@alignCast(raw));
        // Long enough that a single worker cannot drain the queue by itself before the others look.
        std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
        recorder.record();

        return TestCtx.work(undefined, alloc, token);
    }
};

test "work is shared across workers, not serialized on one" {
    var threaded = testIo();
    defer threaded.deinit();

    var recorder = ThreadRecorder.Recorder{};
    const pool = try Pool.init(testing.allocator, threaded.io(), 4, 64, &recorder, ThreadRecorder.work);
    defer pool.deinit();

    // Four slow items on four workers: if each worker could only drain its own ring, one submitter's
    // items would sit behind one worker's 20ms each while the others idled.
    for (0..8) |i| try pool.submit(@intCast(i));

    var buf: [16]Completion = undefined;
    var drained: usize = 0;
    var guard: usize = 0;
    while (drained < 8 and guard < 500) : (guard += 1) {
        const n = pool.drainBlocking(&buf, 100);
        for (buf[0..n]) |c| pool.freePayload(c.payload);
        drained += n;
    }

    try testing.expectEqual(@as(usize, 8), drained);
    try testing.expect(recorder.distinct() > 1);
}
