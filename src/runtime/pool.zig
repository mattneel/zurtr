//! Bounded worker pool with completion delivery.
//!
//! Execution path for work that must not run on the reactor thread: blocking
//! database operations for live sessions, agent steps, and job bodies when a
//! role runs in-process. Work items run on pool threads; results are pushed to
//! a bounded completion queue that the reactor drains (waking it via the
//! transport's wake fd). See `docs/architecture/contracts.md` §1.
//!
//! Contract:
//! - `submit` never blocks the caller beyond a bounded queue push; when the
//!   queue is full it returns `error.QueueFull` (the caller decides: shed,
//!   park, or retry) — the pool never grows without bound.
//! - A completion is delivered exactly once: either drained by the reactor or
//!   freed by `drain`/`deinit`.
//! - `run` is called on a pool thread with no reactor state; it must not touch
//!   session state or transport structures. It returns an owned payload that
//!   the completion carries back.
//!
//! The pool is intentionally small and boring: fixed thread count, one mutex,
//! one condition variable, no work stealing, no priorities.

const std = @import("std");
const Io = std.Io;

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

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: Io,
    work_ctx: *anyopaque,
    work_fn: WorkFn,

    threads: []std.Thread,
    mutex: Io.Mutex = .init,
    work_ready: Io.Condition = .init,
    /// Signaled when a completion is appended; used by blocking drains.
    completion_ready: Io.Condition = .init,
    /// Completions ready for the reactor to drain.
    completions: std.ArrayList(Completion) = .empty,
    /// Bounded queue of pending work.
    pending: std.ArrayList(Item) = .empty,
    pending_capacity: usize,
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

    pub const Error = std.Thread.SpawnError || error{ QueueFull, Shutdown };

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
        self.* = .{
            .allocator = allocator,
            .io = io,
            .work_ctx = work_ctx,
            .work_fn = work_fn,
            .threads = threads,
            .pending_capacity = pending_capacity,
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
        for (threads) |*t| {
            t.* = try std.Thread.spawn(.{}, workerMain, .{self});
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
        for (self.completions.items) |c| self.freeCompletion(c);
        self.completions.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        const allocator = self.allocator;
        allocator.free(self.threads);
        allocator.destroy(self);
    }

    pub fn setWake(self: *Pool, ctx: *anyopaque, f: *const fn (*anyopaque) void) void {
        self.wake_ctx = ctx;
        self.wake_fn = f;
    }

    /// Queue work. Returns `error.QueueFull` when the bounded queue is full.
    pub fn submit(self: *Pool, token: u64) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.shutting_down) return error.Shutdown;
        if (self.pending.items.len >= self.pending_capacity) return error.QueueFull;
        try self.pending.append(self.allocator, .{ .token = token, .seq = self.next_seq });
        self.next_seq += 1;
        self.work_ready.signal(self.io);
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

    pub fn pendingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pending.items.len;
    }

    pub fn completionCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.completions.items.len;
    }

    fn freeCompletion(self: *Pool, c: Completion) void {
        if (c.payload.len > 0) self.allocator.free(c.payload);
    }

    fn workerMain(self: *Pool) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (self.pending.items.len == 0 and !self.shutting_down) {
                self.work_ready.waitUncancelable(self.io, &self.mutex);
            }
            if (self.pending.items.len == 0 and self.shutting_down) {
                self.mutex.unlock(self.io);
                return;
            }
            const item = self.pending.orderedRemove(0);
            self.mutex.unlock(self.io);

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
        }
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

    // Drain everything that completes so deinit has nothing left to free.
    var buf: [64]Completion = undefined;
    var guard: usize = 0;
    while ((pool.pendingCount() > 0 or pool.completionCount() > 0) and guard < 1_000) : (guard += 1) {
        const n = pool.drainBlocking(&buf, 50);
        for (buf[0..n]) |c| pool.freePayload(c.payload);
    }
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
