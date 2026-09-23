//! The runner: claim, invoke, complete — once per pass, and once per tick for everything periodic.
//!
//! The loop is deliberately one thread and one pass at a time, because the contract says so ("the same
//! loop processes heartbeats and the reaper on a timer; no separate threads") and because the adapter
//! allows nothing else: a `Database` owns one connection and one transaction at a time. What that costs
//! is that a long job body blocks the reap tick, so the body's own step boundaries are where the tick's
//! work happens — the lease is renewed and the cancel snapshot refreshed from `ctx.checkpoint()`, both
//! rate-limited so a body that checks in eagerly does not turn into a query per check.
//!
//! # The job body is the transaction scope
//!
//! A body is handed the job's transaction and writes through it. That gives the completion its
//! atomicity: the body's effects and the job's `completed` state are one commit, and any other outcome
//! rolls the effects back before the state is written in its own transaction. Two consequences are
//! worth stating because they are visible from outside:
//!
//!   * **A body that loses its lease commits nothing.** If the completion finds the row is no longer
//!     this attempt's (`not_owner` — expired, reaped, taken over, or cancelled), the transaction is
//!     rolled back, so a stale attempt cannot leave effects behind.
//!   * **Cancellation rolls back and stays cancelled.** The contract's "a cancelled job's transaction
//!     rolls back, and effects already recorded stay recorded": the body's transaction is discarded,
//!     then `cancelled` is written in a transaction of its own, which is what makes the state change
//!     outlive the rollback.
//!
//! A heartbeat joins the job's transaction (there is one connection, so there is no other place for it
//! to go), which means a rolled-back body also rolls back its own lease extensions. That is safe rather
//! than clever: a lease that expires because its heartbeats were discarded leads to a takeover, the
//! stale attempt's completion is refused, and its effects are rolled back — at-least-once, with no
//! partial effect and no wrong result.

const std = @import("std");
const data = @import("../data/root.zig");
const cancel = @import("cancel.zig");
const registry = @import("registry.zig");
const jobs_mod = @import("root.zig");

const Jobs = jobs_mod.Jobs;

/// What one pass did. Every field is a count a test can assert on, because "the runner ran" is not a
/// thing anyone can check.
pub const Tick = struct {
    claimed: usize = 0,
    completed: usize = 0,
    retried: usize = 0,
    failed: usize = 0,
    cancelled: usize = 0,
    /// Attempts that finished after losing the row: they wrote nothing, which is the count that proves
    /// lease expiry is a recovery rather than a duplicate execution.
    not_owner: usize = 0,
    /// Kinds this deployment cannot run. Each one failed terminally without the body being invoked.
    unknown: usize = 0,
    schedules: usize = 0,
    reaped: Jobs.Reaped = .{},
    /// True when the pass claimed nothing, so the loop may sleep until its poll.
    idle: bool = true,
};

pub const Runner = struct {
    jobs: *Jobs,
    registry: registry.Registry,
    worker: []const u8,
    /// Owns the cancel snapshot for the life of the runner.
    allocator: std.mem.Allocator,
    cancel_set: cancel.Set,
    /// Per-job result memory, reset between jobs so one job's payload cannot outlive it.
    arena: std.heap.ArenaAllocator,
    /// Scratch for per-pass results (leases, schedule outcomes). Reset every pass.
    pass_arena: std.heap.ArenaAllocator,
    last_tick_micros: i64 = std.math.minInt(i64),
    last_refresh_micros: i64 = std.math.minInt(i64),
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: std.mem.Allocator, jobs: *Jobs, registry_value: registry.Registry, worker: []const u8) Runner {
        return .{
            .jobs = jobs,
            .registry = registry_value,
            .worker = worker,
            .allocator = allocator,
            .cancel_set = cancel.Set.init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
            .pass_arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Runner) void {
        self.cancel_set.deinit();
        self.arena.deinit();
        self.pass_arena.deinit();
    }

    /// Ask the loop to return. Wakes it, so a runner blocked on its poll stops now rather than after.
    pub fn stop(self: *Runner) void {
        self.stopping.store(true, .release);
        self.jobs.wake();
    }

    /// One pass: periodic work if a tick is due, then up to `batch` jobs.
    pub fn tick(self: *Runner) jobs_mod.Error!Tick {
        var result = Tick{};
        const now = self.jobs.clock.now();

        // The unset check comes first because `now - minInt(i64)` overflows, and `or` evaluates its left
        // operand before its right one.
        if (self.last_tick_micros == std.math.minInt(i64) or now - self.last_tick_micros >= self.jobs.config.tick_ms) {
            self.last_tick_micros = now;
            result.reaped = self.jobs.reap(now) catch |err| switch (err) {
                // Another writer holds the lock. Nothing is wrong and nothing was reaped: the next tick
                // tries again. Without this, an idle worker would error every time a busy one wrote.
                error.Conflict => .{},
                else => return err,
            };

            const cancelled = try self.jobs.cancelledIds(null, self.allocator);
            defer self.allocator.free(cancelled);
            try self.cancel_set.replace(cancelled);

            const scheduled = try self.jobs.runDueSchedules(
                self.pass_arena.allocator(),
                self.worker,
                self.jobs.config.batch,
            );
            result.schedules = scheduled.len;
        }

        defer _ = self.pass_arena.reset(.retain_capacity);

        const leases = try self.jobs.claim(
            self.pass_arena.allocator(),
            self.worker,
            self.jobs.config.batch,
            now,
        );
        result.claimed = leases.len;
        result.idle = leases.len == 0 and result.schedules == 0;

        for (leases) |lease| {
            _ = self.arena.reset(.retain_capacity);
            try self.runOne(lease, now, &result);
        }

        return result;
    }

    /// The loop. Returns when `stop` is called; a pass that changed nothing waits for a wake or the
    /// poll interval, whichever comes first.
    pub fn run(self: *Runner) jobs_mod.Error!void {
        while (!self.stopping.load(.acquire)) {
            const result = try self.tick();

            if (result.idle) _ = self.jobs.waitForWork(self.jobs.config.poll_interval_ms);
        }
    }

    /// Run one claimed job to its outcome.
    fn runOne(self: *Runner, lease: jobs_mod.Lease, now: i64, result: *Tick) jobs_mod.Error!void {
        const arena = self.arena.allocator();

        // Resolve before anything runs, and never run the wrong code: a row whose kind this deployment
        // does not have, or whose version is not the running action's, is failed with the diagnostic
        // rather than decoded into whatever the current struct happens to be.
        const binding = self.registry.resolve(lease.kind, lease.version) catch |err| switch (err) {
            error.UnknownKind, error.UnsupportedVersion => {
                const reason = try std.fmt.allocPrint(
                    arena,
                    "{s}: kind '{s}' version {d} is not runnable here",
                    .{ @errorName(err), lease.kind, lease.version },
                );
                _ = try self.jobs.failTerminal(null, &lease, reason, now);
                result.unknown += 1;

                return;
            },
            else => return err,
        };

        const principal = try registry.principalFor(arena, lease.queue);

        var ctx = registry.Ctx{
            .job_id = lease.job_id,
            .attempt = lease.attempt,
            .queue = lease.queue,
            .principal = principal,
            .io = self.jobs.io,
            .allocator = arena,
            .now_ms = @divTrunc(now, std.time.us_per_ms),
            .cancel = self.cancel_set.view(),
            .tx = try self.jobs.db.begin(.read_write),
        };

        // Whatever happens from here, the transaction the body is holding is finished here — its own
        // boundary may have replaced it several times, so it is read from the context rather than
        // remembered. `Tx.rollback` is a no-op once the transaction is done, which is what makes this
        // safe on the paths that already committed or rolled back.
        defer if (ctx.tx) |tx| tx.rollback();

        var step = StepContext{ .runner = self, .lease = lease, .last_heartbeat = now };
        ctx.on_step = StepContext.run;
        ctx.on_step_user = &step;

        const outcome = binding.run(&ctx, lease.payload) catch |err| switch (err) {
            // A cancellation is not a failure: the body stopped where it was allowed to, and what is
            // left to do is discard the step it was in the middle of and record that it stopped. The
            // steps it already committed stay committed, which is the contract's "effects already
            // recorded stay recorded".
            error.Cancelled => {
                if (ctx.tx) |tx| tx.rollback();
                ctx.tx = null;

                const owned = try self.jobs.finishCancelled(null, &lease, "cancelled at a step boundary", now);
                if (owned == .committed) {
                    result.cancelled += 1;
                    self.cancel_set.clear(lease.job_id);
                } else result.not_owner += 1;

                return;
            },
            else => {
                // The step's transaction goes first: its effects must not be committed by a failure
                // path, and the retry decision is written afterwards, in its own transaction. Earlier
                // steps are already committed and stay that way.
                if (ctx.tx) |tx| tx.rollback();
                ctx.tx = null;

                const reason = try std.fmt.allocPrint(arena, "{s}", .{@errorName(err)});
                const outcome_ = try self.jobs.fail(null, &lease, reason, now, randomDraw(self.jobs.io));
                switch (outcome_) {
                    .retried => result.retried += 1,
                    .failed => result.failed += 1,
                    .cancelled => {
                        result.cancelled += 1;
                        self.cancel_set.clear(lease.job_id);
                    },
                    .not_owner => result.not_owner += 1,
                }

                return;
            },
        };

        // Success: the last step's effects and the job's own completion are one commit. If the row is no
        // longer this attempt's, that step is rolled back instead — a stale attempt commits nothing,
        // which is what makes a takeover a recovery rather than a duplicate execution.
        const completed = try self.jobs.complete(ctx.tx, &lease, outcome, now);
        switch (completed) {
            .committed => {
                // A commit that fails leaves the transaction open, so the deferred rollback discards
                // it and the job stays leased for the reaper — at-least-once, and the error reaches the
                // caller rather than being swallowed.
                if (ctx.tx) |tx| try tx.commit();
                result.completed += 1;
            },
            .not_owner => {
                if (ctx.tx) |tx| tx.rollback();
                result.not_owner += 1;
            },
        }

        ctx.tx = null;
    }

    /// The per-job step hook: renew the lease, refresh the cancel snapshot, and take the next
    /// transaction — each when it is due.
    ///
    /// The order matters. The lease is renewed and the snapshot refreshed *through the current step's
    /// transaction* (there is one connection, so any other statement is refused while it is open), then
    /// the cancellation is checked from that fresh snapshot, and only if the job is to continue is the
    /// step committed and the next one opened. Committing here is what releases the write lock for long
    /// enough that another process can record a cancellation request at all.
    ///
    /// Both rate limits are time-bounded rather than per-call, which is what keeps a body that checks in
    /// often from turning into a commit — or a query — per check.
    const StepContext = struct {
        runner: *Runner,
        lease: jobs_mod.Lease,
        last_heartbeat: i64,
        last_refresh: i64 = std.math.minInt(i64),

        fn run(user: ?*anyopaque, ctx: *registry.Ctx) void {
            const self: *StepContext = @ptrCast(@alignCast(user.?));
            const now = self.runner.jobs.clock.now();

            // The two rate limits are independent — a refresh that is not due must not skip a heartbeat
            // that is — and the "never refreshed" case is tested before the subtraction, because
            // `now - minInt(i64)` overflows.
            const refresh_due = self.last_refresh == std.math.minInt(i64) or
                now - self.last_refresh >= self.runner.jobs.config.tick_ms;
            if (refresh_due) {
                self.last_refresh = now;

                // Read through the step's own transaction, and freed as soon as the snapshot holds a
                // copy, so a body that checks in often does not grow the runner's memory with it.
                const cancelled = self.runner.jobs.cancelledIds(ctx.tx, self.runner.allocator) catch null;
                if (cancelled) |ids| {
                    self.runner.cancel_set.replace(ids) catch {};
                    self.runner.allocator.free(ids);
                }
                ctx.cancel = self.runner.cancel_set.view();
            }

            if (now - self.last_heartbeat >= self.runner.jobs.config.heartbeatMs()) {
                self.last_heartbeat = now;

                const still_owned = self.runner.jobs.heartbeat(ctx.tx, &self.lease, now) catch true;
                if (!still_owned) {
                    // The lease is gone: say so through the same channel a cancellation uses, because
                    // the body must stop at a boundary either way, and the runner's completion path
                    // decides whether anything is written.
                    self.runner.cancel_set.request(self.lease.job_id) catch {};
                    ctx.cancel = self.runner.cancel_set.view();
                }
            }

            // Stopping here leaves the step's transaction for the runner to roll back; nothing is
            // committed for a step that was interrupted mid-way.
            if (ctx.cancelled()) return;

            if (ctx.tx) |tx| tx.commit() catch |err| {
                ctx.step_failure = err;
                ctx.tx = null;

                return;
            };

            ctx.tx = self.runner.jobs.db.begin(.read_write) catch |err| blk: {
                ctx.step_failure = err;

                break :blk null;
            };
        }
    };

    /// Cancel a job and tell this runner about it at once, rather than at the next reap tick.
    pub fn cancelJob(self: *Runner, job_id: jobs_mod.JobId) jobs_mod.Error!jobs_mod.CancelOutcome {
        const outcome = try self.jobs.cancel(null, job_id, null);
        if (outcome == .requested) try self.cancel_set.request(job_id);

        return outcome;
    }
};

/// A draw for the backoff's jitter. Kept here rather than in the policy so the policy stays a pure
/// function of its inputs, and taken from the `Io` because this pin has no global random source.
fn randomDraw(io: std.Io) u64 {
    var bytes: [8]u8 = undefined;
    std.Io.random(io, &bytes);

    return std.mem.readInt(u64, &bytes, .little);
}

test "a runner that was never started stops immediately when asked" {
    var runner: Runner = undefined;
    runner.stopping = .init(true);

    // The loop checks the flag before its first pass, so a stopped runner does no work and does not
    // block on the poll. This is the only part of the loop that needs no database.
    try std.testing.expect(runner.stopping.load(.acquire));
}
