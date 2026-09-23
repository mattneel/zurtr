//! `zurtr.runtime.task` — structured tasks: a task does not outlive the scope that spawned it.
//!
//! A `Scope` owns the tasks spawned in it. `Scope.end` cancels and waits for every child before it
//! returns, and that is the whole contract: "the function returned" means "everything it started is
//! finished", without anyone remembering to join anything. See `docs/architecture/contracts.md` §1.
//!
//! # The tree
//!
//! Scopes nest implicitly in the task, rather than being something the caller wires up: a spawned task
//! carries its own scope (`Task.scope`), which is where its children go, and that scope is reaped —
//! cancel, then wait — when the body returns. What comes out is a tree:
//!
//!     caller's scope ── task A ── A's scope ── task A1 ── A1's scope ── …
//!
//! Two consequences worth stating plainly:
//!
//!   * A body that returns while its children are still running has them cancelled. Returning from a
//!     scope cancels and waits, and a body returning *is* returning from its scope.
//!   * A task's failure is reported to the scope that spawned it — never swallowed, never left in a
//!     log line nobody reads.
//!
//! # Cancellation
//!
//! Cooperative, and one direction only: down the tree. `Scope.cancel` sets a flag, descendants see it
//! through their parent chain (so a cancel at the root reaches a grandchild with no child list to walk),
//! and a task observes it at a yield point:
//!
//!     fn body(task: *zurtr.runtime.task.Task, args: Args) !void {
//!         while (true) {
//!             try task.checkCancel();  // error.Cancelled when this scope or an ancestor is cancelled
//!             do_one_unit(args);
//!         }
//!     }
//!
//! The flag is one atomic read at the yield point and one atomic store to cancel: safe to set from any
//! thread, including from another task — which is exactly how `.cancel_scope` and `.fail_scope` work.
//!
//! A task that never checks is a bug its caller owns. Nothing here preempts native code, and that is a
//! decision, not a gap: see "Scripts" below for the one place a *scripted* task is interrupted.
//!
//! # Failure
//!
//! A task's error goes to its scope, and the scope's `FailurePolicy` decides what it means: `.ignore`
//! (record it, keep going), `.cancel_scope` (record it, cancel the scope's other tasks), `.fail_scope`
//! (record it, cancel, and make `Scope.wait` return `error.Failed`). Recording happens under every
//! policy — "ignore" decides a failure is not an emergency, never that it did not happen, and
//! `Scope.failureCount` is how you find out it did.
//!
//! `error.Cancelled` is not a failure when the task was really cancelled: that is the answer
//! cancellation asks for, and counting it as failure would make every clean shutdown look broken. A
//! task that returns `error.Cancelled` without being cancelled *is* a failure: it invented one.
//!
//! Failures travel outward by the same mechanism they travel everywhere else: a task whose own subtree
//! failed re-reports that failure (with `Failure.from_children` set, and the child's error, not a
//! synthetic code) to its scope. A failure under `.fail_scope` anywhere in a tree therefore reaches the
//! root's `wait`, and `Failure` names the task it happened in.
//!
//! # Execution
//!
//! Tasks run on real threads. `Executor` is one lock-free intake ring per worker, the same rule as
//! `runtime/pool.zig` (pop your own ring, then steal), and the same parked wait with a timeout as a
//! lost-wakeup guard. Beyond that it does one thing the pool has no reason to: a thread waiting for a
//! scope to drain *helps* — it steals queued tasks and runs them while it waits. On a bounded executor
//! whose workers can all end up waiting for their own children at once, which a nested tree makes the
//! normal case rather than a corner, a waiter that only slept would deadlock the tree it is waiting
//! for. The wait is work, so the waiter does it.
//!
//! # Lifetime discipline
//!
//! What Zig can enforce here at compile time is the shape of a task body: a plain function pointer
//! (`fn (*Task, Args) void` or `!void`), so nothing captures the spawning frame by accident. The rest
//! is enforced at runtime, cheaply:
//!
//!   * Task records for a whole tree come from one arena owned by the root scope. Nothing is freed per
//!     task, and nothing can be freed while a task in that tree is alive: the root's `deinit` frees it,
//!     and the root's `end` has already reaped everything below it.
//!   * `Scope.end` asserts the pending count is zero before it closes, and a spawn into a closed scope
//!     is `error.ScopeClosed` — including into the scope of a task that has already returned.
//!   * `Task.checkCancel` asserts, in debug builds, that the task is still running: a task executing
//!     after its scope returned is precisely the violation this layer exists to prevent, and its yield
//!     point is the cheapest place to catch it.
//!
//! Handles stay readable until the *root* scope is destroyed, because their records live in that
//! arena: after `Scope.wait`, `Task.result` and `Task.scope().firstFailure()` are how a caller does the
//! post-mortem.
//!
//! # ZScript
//!
//! A long-running scripted task is not preempted by the engine either, and does not need to be: QuickJS
//! already polls an interrupt callback every N reductions, so `zurtr.zscript` gets *the same flag* at a
//! different yield point. Install the callback once per runtime with the task as its userdata, and the
//! handler body is `Task.scriptInterrupt` — the single place a zscript task is interrupted, next to
//! `Task.checkCancel` for native code, and deliberately not a second cancellation mechanism:
//!
//!     const Interrupt = struct {
//!         task: *task.Task,
//!
//!         fn handler(self: ?*@This(), _: *quickjs.Runtime) bool {
//!             return self.?.task.scriptInterrupt();
//!         }
//!     };
//!     runtime.setInterruptHandler(Interrupt, &interrupt, Interrupt.handler);
//!
//! (In `zurtr.zscript` that is `quickjs.Runtime.setInterruptHandler`.) The host that evaluates a zscript
//! body inside a task installs this before the call, and turns the engine's interrupt into
//! `error.Cancelled` for the task — preemption for scripts, cooperation for native, one flag under
//! both.

const std = @import("std");
const Io = std.Io;
const mpmc = @import("mpmc.zig");

/// How long a waiter sleeps before it re-checks, when it found no work to help with. Only a guard
/// against a missed wakeup: completions signal under the scope's mutex, and that is the mechanism —
/// this just bounds the damage if a wakeup is ever lost.
const wait_guard_ms: u32 = 5;

/// How many failures a scope keeps details for. The count keeps rising past it: a failure list is a
/// diagnostic, not a ledger.
pub const max_failures = 8;

/// Spawn errors. `QueueFull` and `Shutdown` come from the executor (see `Executor`); `ScopeClosed`
/// comes from the scope — nothing may be spawned into a scope that has returned.
pub const Error = error{ QueueFull, ScopeClosed, Shutdown, OutOfMemory };

/// Waiting on a scope fails when a task failed under `.fail_scope`. Cancellation is deliberately not in
/// here: a cancelled task's `error.Cancelled` is the answer cancellation asks for, and
/// `Scope.isCancelled` is how a caller asks whether it happened.
pub const WaitError = error{Failed};

/// What a task's failure means to the scope that owns it. Fixed when the scope is opened, and inherited
/// by a task's own scope, so a policy chosen at the root governs the whole tree.
pub const FailurePolicy = enum {
    /// Record the failure and keep going; the scope's other tasks are unaffected. The failure is still
    /// on the scope (`failureCount`, `failure`), because "not an emergency" is not "did not happen".
    ignore,
    /// Record the failure and cancel the scope's other tasks. `Scope.wait` does not raise: the caller
    /// asked for cancellation, not for failure.
    cancel_scope,
    /// Record the failure, cancel the scope's other tasks, and fail the scope: `Scope.wait` returns
    /// `error.Failed`. The default, because silence is the one thing this layer must not do by default.
    fail_scope,
};

/// One task's failure, as its scope recorded it.
pub const Failure = struct {
    /// The task that failed, and the name its scope gave it.
    task_id: u64,
    name: []const u8,
    /// What the task returned. With `from_children`, this is the error its subtree failed with — the
    /// precise cause, not a synthetic "child failed" code.
    err: anyerror,
    /// True when the task's body returned successfully and the failure came from its children.
    from_children: bool = false,
};

/// Scope options.
pub const Options = struct {
    policy: FailurePolicy = .fail_scope,
    /// What the scope is called in diagnostics ("" is fine).
    name: []const u8 = "",
};

/// The threads tasks run on, and the intake a scope submits them to.
///
/// One workflow is worth naming: `Scope.spawn` submits, a worker takes the task and never gives it
/// back, and `Scope.wait`/`end` waits on a count rather than on a completion queue — so nothing here
/// needs a result path, or a completion queue's mutex. The count and the condition that carries it
/// belong to the scope, which is the thing that has to know.
pub const Executor = struct {
    allocator: std.mem.Allocator,
    io: Io,
    threads: []std.Thread,
    /// One intake ring per worker: a worker pops its own, then steals from the others.
    rings: []mpmc.Queue(*Task),
    /// Round-robin cursor for `submit`, so submissions spread instead of piling onto one worker.
    next_ring: std.atomic.Value(usize) = .init(0),
    /// Rotating start for an unspecific pop (a helper, or a worker stealing).
    steal_cursor: std.atomic.Value(usize) = .init(0),
    /// Task identities, for diagnostics and failure attribution.
    next_task_id: std.atomic.Value(u64) = .init(1),
    mutex: Io.Mutex = .init,
    /// Signalled after a push; parked workers wait on it.
    work_ready: Io.Condition = .init,
    shutting_down: std.atomic.Value(bool) = .init(false),
    /// Diagnostics.
    started_count: std.atomic.Value(u64) = .init(0),
    abandoned_count: std.atomic.Value(u64) = .init(0),

    pub const InitError = std.Thread.SpawnError || mpmc.Queue(*Task).Error || Error;

    /// `pending_capacity` bounds queued tasks across every worker, split evenly per ring. Bounded on
    /// purpose, like the pool: the caller decides whether to shed or wait, and the framework never grows
    /// a queue without bound.
    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        thread_count: usize,
        pending_capacity: usize,
    ) InitError!*Executor {
        std.debug.assert(thread_count > 0);
        std.debug.assert(pending_capacity > 0);
        const self = try allocator.create(Executor);
        errdefer allocator.destroy(self);

        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        // Rounded up to a power of two because each ring is indexed by a mask.
        const per_ring = std.math.ceilPowerOfTwo(usize, @max(2, pending_capacity / thread_count)) catch
            return error.OutOfMemory;
        const rings = try allocator.alloc(mpmc.Queue(*Task), thread_count);
        errdefer allocator.free(rings);
        var initialised: usize = 0;
        errdefer for (rings[0..initialised]) |*ring| ring.deinit();
        for (rings) |*ring| {
            ring.* = try mpmc.Queue(*Task).init(allocator, per_ring);
            initialised += 1;
        }

        self.* = .{
            .allocator = allocator,
            .io = io,
            .threads = threads,
            .rings = rings,
        };

        var spawned: usize = 0;
        errdefer {
            self.shutting_down.store(true, .release);
            self.mutex.lockUncancelable(self.io);
            self.work_ready.broadcast(self.io);
            self.mutex.unlock(self.io);
            for (threads[0..spawned]) |t| t.join();
        }
        for (threads, 0..) |*t, index| {
            t.* = try std.Thread.spawn(.{}, Executor.workerMain, .{ self, index });
            spawned += 1;
        }

        return self;
    }

    /// Stop the workers, then fail whatever is still queued.
    ///
    /// A queued task will never run, so it is *failed* with `error.ExecutorShutdown` rather than dropped
    /// on the floor: its scope's pending count moves and no scope waits forever for a worker that no
    /// longer exists. Tasks already running are not interrupted here — cancel your scopes before you
    /// tear the executor down, which is what `Scope.end` is for — and no thread may be blocked in a
    /// scope wait while this runs.
    pub fn deinit(self: *Executor) void {
        self.shutting_down.store(true, .release);
        self.mutex.lockUncancelable(self.io);
        self.work_ready.broadcast(self.io);
        self.mutex.unlock(self.io);
        for (self.threads) |t| t.join();

        while (self.tryPopAny()) |task| self.abandonTask(task);
        std.debug.assert(self.pendingCount() == 0);

        for (self.rings) |*ring| ring.deinit();
        self.allocator.free(self.rings);
        self.allocator.free(self.threads);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Tasks queued across every ring. A snapshot, for diagnostics and bounds.
    pub fn pendingCount(self: *const Executor) usize {
        var total: usize = 0;
        for (self.rings) |*ring| total += ring.len();

        return total;
    }

    /// Tasks that have started running. Diagnostics: `started + queued > finished` is a leak.
    pub fn startedCount(self: *const Executor) usize {
        return @intCast(self.started_count.load(.monotonic));
    }

    /// Tasks that were failed because the executor shut down before they ran.
    pub fn abandonedCount(self: *const Executor) usize {
        return @intCast(self.abandoned_count.load(.monotonic));
    }

    fn nextId(self: *Executor) u64 {
        return self.next_task_id.fetchAdd(1, .monotonic);
    }

    /// Queue a task. `error.QueueFull` when every ring is full and `error.Shutdown` when the executor
    /// is going away — both are the caller's (i.e. `Scope.spawn`'s) to roll back, and both are.
    fn submit(self: *Executor, task: *Task) Error!void {
        if (self.shutting_down.load(.acquire)) return error.Shutdown;

        const count = self.rings.len;
        const start = self.next_ring.fetchAdd(1, .monotonic) % count;

        // Round-robin first, then a bounded scan: a full ring is momentary, and the point of one ring
        // per worker is that another usually has room.
        var offset: usize = 0;
        while (offset < count) : (offset += 1) {
            const index = (start + offset) % count;
            if (self.rings[index].push(task)) {
                // The push is lock-free and therefore outside the mutex; the signal under it is what
                // actually wakes a parked worker.
                self.mutex.lockUncancelable(self.io);
                self.work_ready.signal(self.io);
                self.mutex.unlock(self.io);

                return;
            }
        }

        return error.QueueFull;
    }

    /// Take the oldest task from any ring, starting from a rotating cursor. Used by helpers (see
    /// `Scope.reap`) and by the shutdown drain.
    fn tryPopAny(self: *Executor) ?*Task {
        const count = self.rings.len;
        const start = self.steal_cursor.fetchAdd(1, .monotonic) % count;
        var offset: usize = 0;
        while (offset < count) : (offset += 1) {
            if (self.rings[(start + offset) % count].pop()) |task| return task;
        }

        return null;
    }

    /// Own ring first, then the others: that order makes stealing cheap for the common case and correct
    /// for the busy one.
    fn popWork(self: *Executor, index: usize) ?*Task {
        if (self.rings[index].pop()) |task| return task;

        var offset: usize = 1;
        while (offset < self.rings.len) : (offset += 1) {
            if (self.rings[(index + offset) % self.rings.len].pop()) |task| return task;
        }

        return null;
    }

    /// Run a task here and now. The task's own completion is what reports it; there is nothing to
    /// return, which is why a scope can wait on a count instead of on a queue.
    fn runTask(self: *Executor, task: *Task) void {
        std.debug.assert(task.state.load(.monotonic) == .queued);
        task.state.store(.running, .release);
        _ = self.started_count.fetchAdd(1, .monotonic);
        task.run_fn(task);
    }

    /// A task the executor will never run: fail it, and close the scope it would have owned so nothing
    /// can attach itself to a task that never happened.
    fn abandonTask(self: *Executor, task: *Task) void {
        if (task.state.swap(.done, .acq_rel) == .done) return;

        task.outcome = error.ExecutorShutdown;
        task.owner.complete(task);
        task.inner.cancel();
        task.inner.closed.store(true, .release);
        _ = self.abandoned_count.fetchAdd(1, .monotonic);
    }

    fn workerMain(self: *Executor, index: usize) void {
        while (true) {
            if (self.popWork(index)) |task| {
                // Once shutdown has begun no *new* work starts here; this check and `deinit`'s drain are
                // the two places a queued task is failed instead of run.
                if (self.shutting_down.load(.acquire)) {
                    self.abandonTask(task);

                    continue;
                }
                self.runTask(task);

                continue;
            }

            // Nothing anywhere: wait for a submit's signal. The timeout is the guard described in the
            // module doc, not the mechanism.
            self.mutex.lockUncancelable(self.io);
            if (self.shutting_down.load(.acquire)) {
                self.mutex.unlock(self.io);
                return;
            }
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromMilliseconds(wait_guard_ms),
                .clock = .awake,
            } };
            self.work_ready.waitTimeout(self.io, &self.mutex, timeout) catch {};
            self.mutex.unlock(self.io);
        }
    }
};

/// A scope: the thing that owns tasks, cancels them, and outlives all of them.
pub const Scope = struct {
    executor: *Executor,
    io: Io,
    /// Where this scope's task records come from: the tree's arena (see `Root`).
    records: std.mem.Allocator,
    /// The scope this one belongs to. Cancellation reads up this chain; nothing is pushed down it.
    parent: ?*Scope,
    /// Set on a root scope only: the allocator that owns this struct and the tree's arena.
    root: ?Root = null,
    policy: FailurePolicy,
    name: []const u8 = "",
    /// The cancellation flag. `cancel` stores here; descendants read their way up to it.
    cancelled: std.atomic.Value(bool) = .init(false),
    /// Children that have not finished.
    pending: std.atomic.Value(usize) = .init(0),
    /// Mutex and signal for threads waiting on `pending`.
    mutex: Io.Mutex = .init,
    idle: Io.Condition = .init,
    /// Set once the scope has returned (`end`): nothing more may be spawned into it.
    closed: std.atomic.Value(bool) = .init(false),
    /// Set when a task failed under `.fail_scope` — what `wait` raises.
    failed: std.atomic.Value(bool) = .init(false),
    /// Guarded by `mutex`: diagnostics.
    spawned: usize = 0,
    cancelled_children: usize = 0,
    failures_seen: usize = 0,
    failure_count: usize = 0,
    failures: [max_failures]?Failure = @splat(null),

    /// The root scope's own storage: the arena records live in, and the allocator that owns this struct.
    pub const Root = struct {
        allocator: std.mem.Allocator,
        /// One arena per tree, bump-allocated and freed once. Its `Allocator` is thread-safe (given a
        /// thread-safe child), which matters because tasks spawn children from pool threads.
        arena: std.heap.ArenaAllocator,
    };

    pub const InitError = std.mem.Allocator.Error;

    /// Open a root scope. A nested scope is not created by the caller: it is `Task.scope` of the task
    /// that wants children, and it inherits this scope's policy.
    pub fn init(allocator: std.mem.Allocator, executor: *Executor, options: Options) InitError!*Scope {
        const self = try allocator.create(Scope);
        errdefer allocator.destroy(self);

        self.* = .{
            .executor = executor,
            .io = executor.io,
            .records = undefined,
            .parent = null,
            .root = .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) },
            .policy = options.policy,
            .name = options.name,
        };
        self.records = self.root.?.arena.allocator();

        return self;
    }

    /// Tear a root scope down: return from it (`end`), then free every task record in the tree.
    ///
    /// Task handles from this tree are invalid afterwards — their records, including `Task.result`,
    /// lived in that arena. A nested scope has no `deinit` of its own: it is returned from by `end` when
    /// the task that owns it finishes.
    pub fn deinit(self: *Scope) void {
        const root = self.root orelse return self.end();
        self.end();
        root.arena.deinit();
        const allocator = root.allocator;
        allocator.destroy(self);
    }

    /// Ask this scope's tasks to stop. Safe from any thread, including from inside a task — which is how
    /// a failure policy reaches its siblings — and idempotent.
    ///
    /// Cooperative: nothing is interrupted here. The flag is set; the tasks that check for it stop.
    pub fn cancel(self: *Scope) void {
        self.cancelled.store(true, .release);
    }

    /// True when this scope or any ancestor has been cancelled. The read is one atomic load per level,
    /// which is why a cancel needs no child list to walk.
    pub fn isCancelled(self: *const Scope) bool {
        var scope: ?*const Scope = self;
        while (scope) |s| : (scope = s.parent) {
            if (s.cancelled.load(.acquire)) return true;
        }

        return false;
    }

    /// Return from this scope: cancel every task in it, wait for them to finish, and refuse further
    /// spawns. Idempotent.
    ///
    /// Never raises. Cancellation is this function's own act and a child's failure is recorded on the
    /// scope — `wait` is the raising form, for callers that want the failure.
    pub fn end(self: *Scope) void {
        if (self.closed.load(.acquire)) return;
        self.cancel();
        self.reap();

        // Under the mutex, so a concurrent spawn either got in before this point and was counted by the
        // reap above, or sees `closed`. Both can never happen.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.debug.assert(self.pending.load(.acquire) == 0);
        self.closed.store(true, .release);
    }

    /// Wait for every task in this scope to finish, without cancelling anyone first and without closing
    /// the scope: spawning more and waiting again is a batch, not a mistake. `end` is what returns from
    /// a scope.
    ///
    /// Returns `error.Failed` when a task failed under `.fail_scope`; the failure itself, with the task
    /// that caused it, is on `failure`/`failureCount`. Not a yield point — a cancelled task still reaps
    /// its children before it returns, so check `Task.checkCancel` to act on cancellation.
    pub fn wait(self: *Scope) WaitError!void {
        self.reap();
        if (self.failed.load(.acquire)) return error.Failed;
    }

    /// Children that have not finished.
    pub fn pendingCount(self: *const Scope) usize {
        return self.pending.load(.acquire);
    }

    /// True once the scope has returned; nothing more may be spawned into it.
    pub fn isClosed(self: *const Scope) bool {
        return self.closed.load(.acquire);
    }

    /// Tasks spawned in this scope, including the ones that have finished.
    pub fn spawnedCount(self: *Scope) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        return self.spawned;
    }

    /// Tasks that returned `error.Cancelled` because they were cancelled. Not failures.
    pub fn cancelledCount(self: *Scope) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        return self.cancelled_children;
    }

    /// How many failures this scope observed, under every policy. Past `max_failures` the count keeps
    /// rising and `failure` has nothing more to say.
    pub fn failureCount(self: *Scope) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        return self.failures_seen;
    }

    /// The `index`-th recorded failure, oldest first.
    pub fn failure(self: *Scope, index: usize) ?Failure {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (index >= self.failure_count) return null;

        return self.failures[index];
    }

    /// The first failure recorded in this scope: the cause a caller usually wants.
    pub fn firstFailure(self: *Scope) ?Failure {
        return self.failure(0);
    }

    /// Spawn a task into this scope and return its handle. The body is a plain Zig function:
    ///
    ///   * `fn (*Task) void` or `fn (*Task) E!void` — spawn it with `{}` as the arguments,
    ///   * `fn (*Task, Args) void` or `fn (*Task, Args) E!void`.
    pub fn spawn(self: *Scope, comptime func: anytype, args: anytype) Error!*Task {
        return self.spawnNamed("", func, args);
    }

    /// `spawn`, with a name for diagnostics and failure attribution. The name is not copied: pass
    /// static storage.
    pub fn spawnNamed(self: *Scope, name: []const u8, comptime func: anytype, args: anytype) Error!*Task {
        if (self.closed.load(.acquire)) return error.ScopeClosed;

        const Record = TaskRecord(func, @TypeOf(args));
        // One bump allocation from the tree's arena: the record *is* the per-task allocation, and there
        // is no second one.
        const record = self.records.create(Record) catch return error.OutOfMemory;
        record.* = .{
            .task = .{
                .id = self.executor.nextId(),
                .name = name,
                .owner = self,
                .inner = self.innerScope(name),
                .run_fn = Record.run,
            },
            .args = args,
        };
        const task = &record.task;

        // Counted before the push, and under the mutex: the task can finish before `spawn` returns, and
        // the count has to already be there for that to read as "still pending" rather than "done".
        self.mutex.lockUncancelable(self.io);
        if (self.closed.load(.acquire)) {
            self.mutex.unlock(self.io);

            return error.ScopeClosed;
        }
        _ = self.pending.fetchAdd(1, .acq_rel);
        self.spawned += 1;
        self.mutex.unlock(self.io);

        self.executor.submit(task) catch |err| {
            // Never queued, so nothing will ever report it: undo the count here.
            self.mutex.lockUncancelable(self.io);
            _ = self.pending.fetchSub(1, .acq_rel);
            self.spawned -= 1;
            self.mutex.unlock(self.io);

            return err;
        };

        return task;
    }

    /// The scope a task's children go into: same executor and records, parented to the scope that
    /// spawned the task, and inheriting its failure policy.
    fn innerScope(self: *Scope, name: []const u8) Scope {
        return .{
            .executor = self.executor,
            .io = self.io,
            .records = self.records,
            .parent = self,
            .policy = self.policy,
            .name = name,
        };
    }

    /// Wait until every child has finished, helping with queued work while waiting.
    fn reap(self: *Scope) void {
        while (self.pending.load(.acquire) != 0) {
            // Help before blocking: on a bounded executor every worker can end up waiting for its own
            // children at once, and then a waiter that only slept would be waiting for a tree that
            // cannot make progress without it.
            if (self.executor.tryPopAny()) |task| {
                self.executor.runTask(task);

                continue;
            }

            self.mutex.lockUncancelable(self.io);
            if (self.pending.load(.acquire) != 0) {
                const timeout: Io.Timeout = .{ .duration = .{
                    .raw = Io.Duration.fromMilliseconds(wait_guard_ms),
                    .clock = .awake,
                } };
                self.idle.waitTimeout(self.io, &self.mutex, timeout) catch {};
            }
            self.mutex.unlock(self.io);
        }
    }

    /// A task has finished: report its outcome, and apply the policy if it failed.
    ///
    /// Called by the thread that ran the task, never with this scope's mutex held.
    fn complete(self: *Scope, task: *Task) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        _ = self.pending.fetchSub(1, .acq_rel);

        if (task.outcome) |err| {
            if (err == error.Cancelled and task.was_cancelled) {
                // The answer cancellation asks for, not a failure: counting it would make every clean
                // shutdown look broken.
                self.cancelled_children += 1;
            } else {
                self.recordLocked(.{
                    .task_id = task.id,
                    .name = task.name,
                    .err = err,
                    .from_children = task.from_children,
                });
            }
        }

        self.idle.broadcast(self.io);
    }

    /// Record a failure and apply the policy. The record happens under every policy: a policy decides
    /// what a failure *means*, never whether it happened.
    fn recordLocked(self: *Scope, record: Failure) void {
        self.failures_seen += 1;
        if (self.failure_count < max_failures) {
            self.failures[self.failure_count] = record;
            self.failure_count += 1;
        }

        switch (self.policy) {
            .ignore => {},
            .cancel_scope => self.cancel(),
            .fail_scope => {
                // Before the cancel, so a `wait` that returns because of the cancellation already sees
                // the failure.
                self.failed.store(true, .release);
                self.cancel();
            },
        }
    }
};

/// A task: what `spawn` hands back, what the body's yield points read, and where a finished task's
/// result is read from.
pub const Task = struct {
    /// Unique within the executor that spawned it.
    id: u64,
    /// What the spawning scope called this task ("" when unnamed). Not copied: static storage.
    name: []const u8,
    /// The scope that owns this task — the one `Task.result` reports to. The scope this task's *children*
    /// go into is `Task.scope`, which is this task's own.
    owner: *Scope,
    /// The scope this task owns, reaped when its body returns.
    inner: Scope,
    /// The generated entry point: uniform to the executor, typed at the spawn site.
    run_fn: *const fn (*Task) void,
    state: std.atomic.Value(State) = .init(.queued),
    /// What the body returned; null when it succeeded. With `from_children`, it is the error the task's
    /// subtree failed with. Readable after the task has finished, until the root scope is destroyed.
    outcome: ?anyerror = null,
    /// True when `outcome` is a child's failure this task adopted rather than its body's own error.
    from_children: bool = false,
    /// Whether this task was cancelled at the moment its body returned. Captured before the reap, which
    /// cancels the task's own scope and would otherwise answer "yes" for every task.
    was_cancelled: bool = false,

    pub const State = enum(u8) { queued, running, done };

    /// The yield point. Returns `error.Cancelled` when this task's scope, or any ancestor, has been
    /// cancelled — the one check a long-running native body has to make.
    ///
    /// A body that never calls this is a bug its caller owns: nothing here preempts native code.
    pub fn checkCancel(self: *const Task) error{Cancelled}!void {
        // Debug builds only: the state assertion says a task is running, which is what makes "a task
        // cannot outlive its scope" checkable rather than merely intended.
        std.debug.assert(self.state.load(.monotonic) == .running);
        if (self.isCancelled()) return error.Cancelled;
    }

    /// True when this task's scope, or any ancestor, has been cancelled.
    pub fn isCancelled(self: *const Task) bool {
        return self.owner.isCancelled();
    }

    /// The zscript yield point: `true` means "interrupt the running script".
    ///
    /// This is deliberately the *same* flag as `checkCancel` — not a second cancellation mechanism —
    /// read at the yield point a zscript task has instead of a check between units of native work.
    /// Install it as QuickJS's interrupt handler (see the module doc), and a cancelled scope stops a
    /// script at its next reduction count rather than at the end of whatever it is doing.
    pub fn scriptInterrupt(self: *const Task) bool {
        return self.isCancelled();
    }

    /// The scope this task's children go into.
    pub fn scope(self: *Task) *Scope {
        return &self.inner;
    }

    /// What the body returned, or null when it succeeded. Valid until the root scope is destroyed.
    pub fn result(self: *const Task) ?anyerror {
        return self.outcome;
    }

    /// Spawn into this task's own scope: the child is reaped when this task returns, whether it is
    /// still running at that point or not.
    pub fn spawn(self: *Task, comptime func: anytype, args: anytype) Error!*Task {
        return self.inner.spawn(func, args);
    }

    /// `spawn`, with a name for diagnostics.
    pub fn spawnNamed(self: *Task, name: []const u8, comptime func: anytype, args: anytype) Error!*Task {
        return self.inner.spawnNamed(name, func, args);
    }

    /// A body has returned. Cancel and reap this task's children *before* reporting completion outward,
    /// so "the scope returned" implies the whole subtree is gone — and adopt a child's failure if the
    /// body itself succeeded, so a failure in the subtree is never lost on the way up.
    fn finish(self: *Task, outcome: ?anyerror) void {
        self.was_cancelled = self.inner.isCancelled();
        self.outcome = outcome;

        self.inner.end();

        if (self.inner.failed.load(.acquire)) {
            // The body's answer (success, or its own error) is subsumed by the more precise cause: a
            // descendant failed under `.fail_scope`, and that is what this task reports.
            if (self.inner.firstFailure()) |child| {
                self.outcome = child.err;
                self.from_children = true;
            }
        }

        self.state.store(.done, .release);
        self.owner.complete(self);
    }
};

/// The per-task record and its generated entry point.
///
/// One arena allocation holds the handle the caller keeps and the arguments themselves. The entry point
/// is generated per spawn site, which is what lets a body be an ordinary function — any error set, one
/// parameter or two — with no vtable and no type-erased closure, and lets a body's error reach the scope
/// as a value rather than as text.
fn TaskRecord(comptime func: anytype, comptime A: type) type {
    const info = bodyInfo(func);

    return struct {
        task: Task,
        args: A,

        fn run(task: *Task) void {
            const self: *@This() = @alignCast(@fieldParentPtr("task", task));
            task.finish(call(self));
        }

        fn call(self: *@This()) ?anyerror {
            const params = info.param_types;
            switch (@typeInfo(info.return_type.?)) {
                .error_union => {
                    if (params.len == 1) {
                        func(&self.task) catch |err| return err;
                    } else {
                        func(&self.task, self.args) catch |err| return err;
                    }
                },
                .void => {
                    // A body with no error union cannot fail; nothing to catch.
                    if (params.len == 1) {
                        func(&self.task);
                    } else {
                        func(&self.task, self.args);
                    }
                },
                else => unreachable,
            }

            return null;
        }
    };
}

/// A task body's comptime contract, checked where it is written rather than where it fails: a plain
/// function, `(*Task)` or `(*Task, Args)`, returning `void` or `E!void`.
fn bodyInfo(comptime func: anytype) std.builtin.Type.Fn {
    const info = switch (@typeInfo(@TypeOf(func))) {
        .@"fn" => |f| f,
        else => @compileError("a task body must be a function: `fn (*Task) void` or `fn (*Task, Args) !void`"),
    };
    comptime {
        if (info.param_types.len < 1 or info.param_types.len > 2) {
            @compileError("a task body takes `(*Task)` or `(*Task, Args)`");
        }
        if (info.param_types[0] != *Task) {
            @compileError("a task body's first parameter is `*Task`");
        }
        const returns = info.return_type orelse @compileError("a task body's return type must be known");
        const ok = switch (@typeInfo(returns)) {
            .void => true,
            .error_union => |eu| @typeInfo(eu.payload) == .void,
            else => false,
        };
        if (!ok) @compileError("a task body returns `void` or `E!void`");
    }

    return info;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Everything a test body touches. All of it atomic: the bodies run on executor threads, and the test
/// thread reads the result.
const Obs = struct {
    /// Bodies that ran to their last line.
    completed: std.atomic.Value(usize) = .init(0),
    /// Bodies that observed cancellation and returned `error.Cancelled`.
    cancelled: std.atomic.Value(usize) = .init(0),
    /// Bodies that started (their first instruction).
    started: std.atomic.Value(usize) = .init(0),
    /// Units of work finished by bodies that keep working until cancelled.
    work: std.atomic.Value(usize) = .init(0),
    /// Bodies that waited for a peer and gave up: a serialized executor, caught in the act.
    unmet: std.atomic.Value(usize) = .init(0),
    /// One slot per distinct thread, for "tasks run on real threads".
    thread_ids: [8]std.atomic.Value(u64) = @splat(.init(0)),
    thread_count: std.atomic.Value(usize) = .init(0),

    fn noteThread(self: *Obs) void {
        const id: u64 = @intCast(std.Thread.getCurrentId());
        const count = self.thread_count.load(.acquire);
        for (self.thread_ids[0..@min(count, self.thread_ids.len)]) |slot| {
            if (slot.load(.acquire) == id) return;
        }
        if (count >= self.thread_ids.len) return;
        if (self.thread_count.cmpxchgWeak(count, count + 1, .acq_rel, .acquire)) |_| return;
        self.thread_ids[count].store(id, .release);
    }

    fn distinctThreads(self: *const Obs) usize {
        var n: usize = 0;
        for (self.thread_ids) |slot| {
            if (slot.load(.acquire) != 0) n += 1;
        }

        return n;
    }

    fn taken(counter: *const std.atomic.Value(usize)) usize {
        return counter.load(.acquire);
    }
};

/// Units of work a body does before it finishes on its own. Long enough that a cancellation arriving
/// "immediately" is early by three orders of magnitude.
const work_units = 60;

/// Sleeps, then records that it ran. Slow on purpose: a scope that returned before its children finished
/// would be caught by the count rather than by luck.
fn bodySleepThenComplete(task: *Task, obs: *Obs) !void {
    Io.sleep(testing.io, Io.Duration.fromMilliseconds(20), .awake) catch {};
    try task.checkCancel();
    obs.noteThread();
    _ = obs.completed.fetchAdd(1, .acq_rel);
}

/// Waits for a second body to start. Only two threads running at once can pass; a serialized executor
/// would leave this waiting out its budget and record `unmet`.
fn bodyRendezvous(task: *Task, obs: *Obs) !void {
    _ = task;
    _ = obs.started.fetchAdd(1, .acq_rel);

    var waited: usize = 0;
    while (obs.started.load(.acquire) < 2 and waited < 2_000) : (waited += 1) {
        Io.sleep(testing.io, Io.Duration.fromMilliseconds(1), .awake) catch {};
    }

    if (obs.started.load(.acquire) < 2) {
        _ = obs.unmet.fetchAdd(1, .acq_rel);

        return;
    }

    obs.noteThread();
    _ = obs.completed.fetchAdd(1, .acq_rel);
}

/// Works, one unit at a time, checking for cancellation between units — the shape every long-running
/// task has to have.
fn bodyWorkUntilCancelled(task: *Task, obs: *Obs) !void {
    _ = obs.started.fetchAdd(1, .acq_rel);

    var unit: usize = 0;
    while (unit < work_units) : (unit += 1) {
        task.checkCancel() catch {
            _ = obs.cancelled.fetchAdd(1, .acq_rel);

            return error.Cancelled;
        };
        Io.sleep(testing.io, Io.Duration.fromMilliseconds(1), .awake) catch {};
        _ = obs.work.fetchAdd(1, .acq_rel);
    }

    _ = obs.completed.fetchAdd(1, .acq_rel);
}

/// A zscript task's shape: no check between units of native work, but the engine's interrupt callback
/// polled every reduction — and `Task.scriptInterrupt` is that callback's body, reading the same flag.
fn bodyScriptLoop(task: *Task, obs: *Obs) !void {
    var reduction: usize = 0;
    while (reduction < work_units) : (reduction += 1) {
        if (task.scriptInterrupt()) {
            _ = obs.cancelled.fetchAdd(1, .acq_rel);

            return error.Cancelled;
        }
        Io.sleep(testing.io, Io.Duration.fromMilliseconds(1), .awake) catch {};
        _ = obs.work.fetchAdd(1, .acq_rel);
    }

    _ = obs.completed.fetchAdd(1, .acq_rel);
}

/// Fails on its first instruction. What the scope's policy then does is the point of the policy tests.
fn bodyFails(task: *Task, obs: *Obs) !void {
    _ = task;
    _ = obs;

    return error.Boom;
}

/// Returns `error.Cancelled` without anyone having asked: a task that invents a cancellation.
fn bodyInventsCancellation(task: *Task, obs: *Obs) !void {
    _ = task;
    _ = obs;

    return error.Cancelled;
}

/// Spawns a failing child and returns without waiting: the runtime reaps this task's own scope, so the
/// child's failure has to come back as *this* task's outcome.
fn bodySpawnsFailingChild(task: *Task, obs: *Obs) !void {
    _ = try task.spawnNamed("deeper", bodyFails, obs);
}

/// Spawns two grandchildren that work until cancelled, waits for them, then checks its own flag.
fn bodyWaitsForChildren(task: *Task, obs: *Obs) !void {
    _ = try task.spawn(bodyWorkUntilCancelled, obs);
    _ = try task.spawn(bodyWorkUntilCancelled, obs);
    try task.scope().wait();
    try task.checkCancel();
}

/// Stress: leaf work, counted per outcome so the test can assert there is no third one.
const Stress = struct {
    groups_completed: std.atomic.Value(usize) = .init(0),
    groups_cancelled: std.atomic.Value(usize) = .init(0),
    leaves_completed: std.atomic.Value(usize) = .init(0),
    leaves_cancelled: std.atomic.Value(usize) = .init(0),
    leaf_spawns: std.atomic.Value(usize) = .init(0),
};

const groups = 32;
const children_per_group = 4;
const stress_units = 4;

fn bodyStressLeaf(task: *Task, stress: *Stress) !void {
    var unit: usize = 0;
    while (unit < stress_units) : (unit += 1) {
        task.checkCancel() catch {
            _ = stress.leaves_cancelled.fetchAdd(1, .acq_rel);

            return error.Cancelled;
        };
        // A real allocation through the test allocator, from many threads at once: that is what makes
        // "no leaks" a claim this test can fail on rather than a comment.
        const scratch = try testing.allocator.alloc(u8, 64);
        defer testing.allocator.free(scratch);
        scratch[0] = @intCast(unit);
        _ = stress.leaves_completed.load(.monotonic);
        std.atomic.spinLoopHint();
    }

    _ = stress.leaves_completed.fetchAdd(1, .acq_rel);
}

fn bodyStressGroup(task: *Task, stress: *Stress) !void {
    var spawned: usize = 0;
    while (spawned < children_per_group) : (spawned += 1) {
        _ = try task.spawn(bodyStressLeaf, stress);
        _ = stress.leaf_spawns.fetchAdd(1, .acq_rel);
    }

    // Waits for its own leaves. With four workers and thirty-two groups that keeps most workers inside
    // this wait, which only makes progress because a waiting thread helps: the deadlock test as much as
    // the leak test.
    try task.scope().wait();

    task.checkCancel() catch {
        _ = stress.groups_cancelled.fetchAdd(1, .acq_rel);

        return error.Cancelled;
    };
    _ = stress.groups_completed.fetchAdd(1, .acq_rel);
}

fn expectFailureName(failure: Failure, expected: []const u8) !void {
    try testing.expectEqualStrings(expected, @errorName(failure.err));
}

test "a scope waits for every child before it returns" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 16);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .policy = .ignore, .name = "parent" });
    defer scope.deinit();

    var obs = Obs{};
    var handles: [4]*Task = undefined;
    for (&handles, 0..) |*handle, index| {
        handle.* = try scope.spawnNamed(if (index == 0) "first" else "", bodySleepThenComplete, &obs);
    }

    try scope.wait();

    // Every child reached its last line before `wait` returned: a wait that returned early would leave
    // some of them at zero.
    try testing.expectEqual(@as(usize, 4), Obs.taken(&obs.completed));
    try testing.expectEqual(@as(usize, 0), scope.pendingCount());
    try testing.expectEqual(@as(usize, 4), scope.spawnedCount());
    try testing.expectEqual(@as(usize, 0), scope.failureCount());
    for (handles) |handle| try testing.expectEqual(@as(?anyerror, null), handle.result());
}

test "tasks run on real threads, and two of them can meet" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{});
    defer scope.deinit();

    var obs = Obs{};
    _ = try scope.spawn(bodyRendezvous, &obs);
    _ = try scope.spawn(bodyRendezvous, &obs);

    try scope.wait();

    // The rendezvous can only complete with two tasks running at once, and the distinct thread count
    // says it was two threads rather than one task twice.
    try testing.expectEqual(@as(usize, 0), Obs.taken(&obs.unmet));
    try testing.expectEqual(@as(usize, 2), Obs.taken(&obs.completed));
    try testing.expectEqual(@as(usize, 2), obs.distinctThreads());
}

test "returning from a scope cancels its children and waits for them to stop" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .name = "leaving" });
    defer scope.deinit();

    var obs = Obs{};
    const handle = try scope.spawnNamed("worker", bodyWorkUntilCancelled, &obs);

    // Let it actually start, so this is a running task being cancelled and not a queued one.
    var attempts: usize = 0;
    while (obs.started.load(.acquire) == 0 and attempts < 2_000) : (attempts += 1) {
        Io.sleep(testing.io, Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.started));

    scope.end();

    // The body's own work would have taken `work_units` milliseconds; `end` returned long before that,
    // and only after the child had observed the cancellation and returned.
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.cancelled));
    try testing.expectEqual(@as(usize, 0), Obs.taken(&obs.completed));
    try testing.expect(Obs.taken(&obs.work) < work_units);
    try testing.expectEqual(@as(usize, 0), scope.pendingCount());
    try testing.expectEqual(@as(usize, 1), scope.cancelledCount());
    try testing.expectEqual(@as(usize, 0), scope.failureCount());
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.started));
    try testing.expectEqual(@as(?anyerror, error.Cancelled), handle.result());
}

test "the zscript seam reads the same cancellation flag a native check does" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .name = "scripted" });
    defer scope.deinit();

    var obs = Obs{};
    const handle = try scope.spawnNamed("zscript", bodyScriptLoop, &obs);

    // Nothing cancelled: the answer a QuickJS interrupt handler would give is "keep going".
    try testing.expect(!handle.scriptInterrupt());

    // Cancelled from another thread, with no cooperation from the script: a zscript task stops at its
    // next reduction check, and the interruption is a cancellation rather than a failure.
    scope.cancel();
    scope.end();

    try testing.expect(handle.scriptInterrupt());
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.cancelled));
    try testing.expectEqual(@as(usize, 0), Obs.taken(&obs.completed));
    try testing.expect(Obs.taken(&obs.work) < work_units);
    try testing.expectEqual(@as(usize, 1), scope.cancelledCount());
    try testing.expectEqual(@as(usize, 0), scope.failureCount());
    try testing.expectEqual(@as(?anyerror, error.Cancelled), handle.result());
}

test "cancellation is not failure, and a task that invents a cancellation fails" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();

    // A task that returns `error.Cancelled` with nothing cancelled made it up, and a made-up
    // cancellation is a failure like any other.
    {
        const scope = try Scope.init(testing.allocator, executor, .{ .name = "invented" });
        defer scope.deinit();

        var obs = Obs{};
        const handle = try scope.spawnNamed("invented", bodyInventsCancellation, &obs);

        try testing.expectError(error.Failed, scope.wait());
        try testing.expectEqual(@as(usize, 1), scope.failureCount());
        try testing.expectEqual(@as(usize, 0), scope.cancelledCount());
        const failure = scope.firstFailure().?;
        try testing.expectEqual(handle.id, failure.task_id);
        try testing.expectEqualStrings("invented", failure.name);
        try expectFailureName(failure, "Cancelled");
        try testing.expect(!failure.from_children);
    }

    // The same body in a cancelled scope is the answer cancellation asked for: counted, not recorded.
    {
        const scope = try Scope.init(testing.allocator, executor, .{ .name = "cancelled" });
        defer scope.deinit();

        var obs = Obs{};
        const handle = try scope.spawn(bodyInventsCancellation, &obs);
        scope.cancel();
        scope.end();

        try testing.expectEqual(@as(usize, 1), scope.cancelledCount());
        try testing.expectEqual(@as(usize, 0), scope.failureCount());
        try testing.expectEqual(@as(?anyerror, error.Cancelled), handle.result());
    }
}

test "policy ignore: the failure is recorded and the siblings keep working" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .policy = .ignore, .name = "tolerant" });
    defer scope.deinit();

    var obs = Obs{};
    const failed = try scope.spawnNamed("boom", bodyFails, &obs);
    _ = try scope.spawnNamed("sibling", bodyWorkUntilCancelled, &obs);

    try scope.wait();

    // The sibling ran to its last unit: nothing cancelled it. The failure happened, and the scope says
    // so — that is what "ignore" is not allowed to swallow.
    try testing.expectEqual(@as(usize, work_units), Obs.taken(&obs.work));
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.completed));
    try testing.expectEqual(@as(usize, 0), Obs.taken(&obs.cancelled));
    try testing.expect(!scope.isCancelled());
    try testing.expectEqual(@as(usize, 1), scope.failureCount());
    const failure = scope.firstFailure().?;
    try testing.expectEqual(failed.id, failure.task_id);
    try testing.expectEqualStrings("boom", failure.name);
    try expectFailureName(failure, "Boom");
    try testing.expect(!failure.from_children);
}

test "policy cancel_scope: siblings stop, and the scope does not fail" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .policy = .cancel_scope, .name = "stoppable" });
    defer scope.deinit();

    var obs = Obs{};
    _ = try scope.spawnNamed("boom", bodyFails, &obs);
    _ = try scope.spawnNamed("sibling", bodyWorkUntilCancelled, &obs);

    try scope.wait();

    // The sibling stopped at a check, not at the end of its work, and the scope reports a cancellation
    // rather than a failure — the caller asked for cancellation, so that is the answer.
    try testing.expect(Obs.taken(&obs.work) < work_units);
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.cancelled));
    try testing.expectEqual(@as(usize, 0), Obs.taken(&obs.completed));
    try testing.expect(scope.isCancelled());
    try testing.expectEqual(@as(usize, 0), scope.pendingCount());
    try testing.expectEqual(@as(usize, 1), scope.failureCount());
    try expectFailureName(scope.firstFailure().?, "Boom");
}

test "policy fail_scope: siblings stop, and wait raises the failure" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .policy = .fail_scope, .name = "strict" });
    defer scope.deinit();

    var obs = Obs{};
    const failed = try scope.spawnNamed("boom", bodyFails, &obs);
    _ = try scope.spawnNamed("sibling", bodyWorkUntilCancelled, &obs);

    try testing.expectError(error.Failed, scope.wait());

    try testing.expect(Obs.taken(&obs.work) < work_units);
    try testing.expectEqual(@as(usize, 1), Obs.taken(&obs.cancelled));
    try testing.expect(scope.isCancelled());
    try testing.expectEqual(@as(usize, 1), scope.failureCount());
    const failure = scope.firstFailure().?;
    try testing.expectEqual(failed.id, failure.task_id);
    try testing.expectEqualStrings("boom", failure.name);
    try expectFailureName(failure, "Boom");
    try testing.expect(!failure.from_children);
}

test "nested scopes: cancellation reaches inward, failure is observed outward" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 16);
    defer executor.deinit();

    // Inward: a cancel at the root stops grandchildren nobody holds a handle to.
    {
        const scope = try Scope.init(testing.allocator, executor, .{ .name = "root" });
        defer scope.deinit();

        var obs = Obs{};
        const handle = try scope.spawnNamed("outer", bodyWaitsForChildren, &obs);

        var attempts: usize = 0;
        while (obs.started.load(.acquire) < 2 and attempts < 2_000) : (attempts += 1) {
            Io.sleep(testing.io, Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        try testing.expectEqual(@as(usize, 2), Obs.taken(&obs.started));

        scope.cancel();
        scope.end();

        try testing.expectEqual(@as(usize, 2), Obs.taken(&obs.cancelled));
        try testing.expectEqual(@as(usize, 0), scope.pendingCount());
        try testing.expectEqual(@as(usize, 1), scope.cancelledCount());
        try testing.expectEqual(@as(usize, 2), handle.scope().cancelledCount());
        try testing.expectEqual(@as(usize, 0), handle.scope().pendingCount());
        try testing.expectEqual(@as(?anyerror, error.Cancelled), handle.result());
        try testing.expectEqual(@as(usize, 0), scope.failureCount());
        try testing.expectEqual(@as(usize, 0), handle.scope().failureCount());
    }

    // Outward: a task that returns successfully while its child failed under `.fail_scope` reports the
    // child's failure to its own scope, cause and all.
    {
        const scope = try Scope.init(testing.allocator, executor, .{ .name = "root" });
        defer scope.deinit();

        var obs = Obs{};
        const handle = try scope.spawnNamed("outer", bodySpawnsFailingChild, &obs);

        try testing.expectError(error.Failed, scope.wait());

        try testing.expectEqual(@as(usize, 0), scope.pendingCount());
        try testing.expectEqual(@as(usize, 1), scope.failureCount());
        const failure = scope.firstFailure().?;
        try testing.expectEqual(handle.id, failure.task_id);
        try testing.expectEqualStrings("outer", failure.name);
        try expectFailureName(failure, "Boom");
        try testing.expect(failure.from_children);
        // ...and the task that owns the failing child recorded it one level down, under the child's name.
        try testing.expectEqual(@as(usize, 1), handle.scope().failureCount());
        try testing.expectEqualStrings("deeper", handle.scope().firstFailure().?.name);
        try testing.expectEqual(@as(?anyerror, error.Boom), handle.result());
    }
}

test "a scope that has returned refuses new tasks" {
    const executor = try Executor.init(testing.allocator, testing.io, 2, 8);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{});
    defer scope.deinit();

    var obs = Obs{};
    const handle = try scope.spawn(bodySleepThenComplete, &obs);
    scope.end();

    try testing.expectError(error.ScopeClosed, scope.spawn(bodySleepThenComplete, &obs));
    try testing.expectError(error.ScopeClosed, scope.spawnNamed("late", bodySleepThenComplete, &obs));
    // A finished task's own scope has returned too, so nothing can attach itself to a task that is
    // already gone.
    try testing.expect(handle.scope().isClosed());
    try testing.expectError(error.ScopeClosed, handle.scope().spawn(bodySleepThenComplete, &obs));
    try testing.expectError(error.ScopeClosed, handle.spawn(bodySleepThenComplete, &obs));
}

test "an executor torn down with work still queued fails that work instead of leaving a scope waiting" {
    const executor = try Executor.init(testing.allocator, testing.io, 1, 64);
    const scope = try Scope.init(testing.allocator, executor, .{ .name = "abandoned" });
    defer scope.deinit();

    var obs = Obs{};
    for (0..16) |_| _ = try scope.spawn(bodySleepThenComplete, &obs);

    // One worker, sixteen tasks of 20ms each: tearing the executor down now leaves most of them queued,
    // and a queued task that is never run must not leave its scope waiting forever.
    executor.deinit();

    try testing.expectEqual(@as(usize, 0), scope.pendingCount());
    try testing.expect(executor.abandonedCount() > 0);
    try testing.expect(scope.failureCount() > 0);
    // Every task either ran to the end or was failed: there is no third outcome, and nothing was
    // silently dropped.
    try testing.expectEqual(
        @as(usize, 16),
        Obs.taken(&obs.completed) + scope.failureCount(),
    );
    try testing.expectError(error.Failed, scope.wait());
    try expectFailureName(scope.firstFailure().?, "ExecutorShutdown");
}

test "stress: many spawns across nested scopes, cancelled, with leaks failing the test" {
    const executor = try Executor.init(testing.allocator, testing.io, 4, 256);
    defer executor.deinit();
    const scope = try Scope.init(testing.allocator, executor, .{ .name = "stress" });
    defer scope.deinit();

    var stress = Stress{};
    var group_handles: [groups]*Task = undefined;
    for (&group_handles) |*handle| handle.* = try scope.spawn(bodyStressGroup, &stress);

    // Cancel while the tree is still filling in: leaves that have not started are cancelled before they
    // run, and leaves in the middle of a unit stop at the next check.
    //
    // `end` here is also the check on `Scope.reap`'s help: thirty-two groups sitting in `wait` on four
    // worker threads finish only because a waiting thread steals and runs queued tasks. Take that away
    // and this test stops making progress, which in a test binary shows up as a stall rather than as a
    // failed assertion — the one failure mode in this file that is unfriendly rather than obvious.
    scope.cancel();
    scope.end();

    try testing.expectEqual(@as(usize, 0), scope.pendingCount());
    try testing.expectEqual(@as(usize, groups), scope.spawnedCount());
    try testing.expectEqual(@as(usize, groups * children_per_group), Obs.taken(&stress.leaf_spawns));
    try testing.expectEqual(@as(usize, 0), executor.pendingCount());
    // Every task in the tree started, and none was failed for arriving after the executor was done.
    try testing.expectEqual(groups + groups * children_per_group, executor.startedCount());
    try testing.expectEqual(@as(usize, 0), executor.abandonedCount());

    // Every leaf either finished its units or observed the cancellation: no third outcome, and no leaf
    // lost between the two scopes that own them.
    try testing.expectEqual(
        @as(usize, groups * children_per_group),
        Obs.taken(&stress.leaves_completed) + Obs.taken(&stress.leaves_cancelled),
    );
    try testing.expect(Obs.taken(&stress.leaves_cancelled) > 0);
    try testing.expectEqual(
        @as(usize, groups),
        Obs.taken(&stress.groups_completed) + Obs.taken(&stress.groups_cancelled),
    );

    // Cancellation is not failure, at any depth, and every nested scope is empty.
    try testing.expectEqual(@as(usize, 0), scope.failureCount());
    for (group_handles) |handle| {
        try testing.expectEqual(@as(usize, children_per_group), handle.scope().spawnedCount());
        try testing.expectEqual(@as(usize, 0), handle.scope().pendingCount());
        try testing.expectEqual(@as(usize, 0), handle.scope().failureCount());
    }
}
