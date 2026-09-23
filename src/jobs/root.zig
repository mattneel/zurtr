//! `zurtr.jobs` — durable queues, schedules, retries, concurrency, cancellation.
//!
//! The contract is `docs/modules/jobs.md` and it is normative: at-least-once delivery, idempotency by
//! the caller's key, leases rather than locks, retries with bounded attempts, and cancellation as a
//! state transition a running job observes at a step boundary. What this file decides is how that
//! model is *stored*, and the dialect it is stored in is `schema.zig`'s subject — the built adapter is
//! Turso, so the PostgreSQL primitives the contract is written in (`SKIP LOCKED`, `LISTEN`/`NOTIFY`,
//! `bigserial`, `timestamptz`) are replaced rather than emulated:
//!
//!   * **A claim is a select-then-update inside one write transaction**, which is the shape the
//!     contract names. `rows_affected` is the only thing that says the claim was won: the `UPDATE`'s
//!     `WHERE` is the whole guard — `available`, due, in a queue this worker serves, under that queue's
//!     limit. `SKIP LOCKED` exists to stop two claimers interleaving between the select and the update,
//!     and this engine excludes that differently: one writer per database, with every read-write
//!     transaction opened `BEGIN IMMEDIATE`.
//!   * **`attempt` is the ownership token.** Every claim bumps it, and every write only an owner may
//!     make is guarded on `state = 'leased' AND attempt = ?`, in the same statement as the write it
//!     guards. A worker whose lease expired and was taken over therefore affects zero rows and is told
//!     so (`not_owner`) rather than overwriting the attempt that took over — which is why no separate
//!     token column is needed.
//!   * **Wakeups are polls.** Nothing wakes another process on this adapter, so the runner polls at
//!     `poll_interval_ms` — the contract's own fallback — and a same-process enqueue can raise an
//!     in-process condition so an embedded role or a test picks work up immediately. Only `enqueue`
//!     with no transaction wakes by itself: with a caller's `tx`, the commit is the caller's, so the
//!     caller calls `wake()` after it if it wants the same treatment.
//!
//! # Ownership
//!
//! Every slice an operation returns belongs to the **arena the caller passes** and stays valid until
//! the caller releases it. `Jobs` holds no result memory: a lease about to be used across several
//! calls (claim, run, complete) is owned by the runner's per-job arena, and a caller that wants one
//! answer can pass a scratch arena and reset it afterwards.

const std = @import("std");
const data = @import("../data/root.zig");
const cancel = @import("cancel.zig");
const registry = @import("registry.zig");
const retry = @import("retry.zig");
const schema = @import("schema.zig");

pub const State = enum {
    available,
    leased,
    completed,
    failed,
    cancelled,

    pub fn text(self: State) []const u8 {
        return switch (self) {
            .available => "available",
            .leased => "leased",
            .completed => "completed",
            .failed => "failed",
            .cancelled => "cancelled",
        };
    }

    pub fn parse(value: []const u8) data.Error!State {
        inline for (@typeInfo(State).@"enum".field_names) |name| {
            if (std.mem.eql(u8, value, name)) return @field(State, name);
        }

        // A state the schema does not know is a row written by something that is not this module, or a
        // vocabulary that grew without this switch. Either way it is not something to guess about.
        std.log.debug("jobs: unknown job state '{s}'", .{value});

        return error.Internal;
    }
};

pub const JobId = i64;
pub const ScheduleId = i64;

/// A queue this worker serves, and how many of its jobs may be leased at once. A negative limit is
/// the contract's `-1`: unlimited.
pub const QueueLimit = struct {
    name: []const u8,
    limit: i32 = -1,

    pub fn unlimited(self: QueueLimit) bool {
        return self.limit < 0;
    }
};

pub const default_queue = "default";

/// What a caller asks for when it wants work done.
pub const EnqueueSpec = struct {
    /// The action id, checked against the registry before the job runs.
    kind: []const u8,
    /// The action version at insert. A row whose version is not the running action's fails the job
    /// with a diagnostic; it is never decoded as if it were current.
    version: i32 = 1,
    /// The action's `Input`, already serialized. Opaque here: the codec belongs to the application.
    payload: []const u8 = &.{},
    queue: []const u8 = default_queue,
    /// Higher first, then oldest first, then lowest id — the contract's claim order.
    priority: i32 = 0,
    /// When the job becomes available. `null` is "now".
    run_at: ?i64 = null,
    /// How many attempts the row is allowed, counting the first.
    max_attempts: u32 = 5,
    /// The caller's idempotency key. Two enqueues with the same key, queue and kind return the same
    /// job; a different queue or kind is a different job, because the key's uniqueness is scoped to it.
    idempotency_key: ?[]const u8 = null,
};

/// What an enqueue did. `inserted` false means the key already had a job, and this call returned it.
pub const EnqueueOutcome = struct {
    id: JobId,
    inserted: bool,
};

pub const ScheduleSpec = struct {
    kind: []const u8,
    version: i32 = 1,
    payload: []const u8 = &.{},
    queue: []const u8 = default_queue,
    priority: i32 = 0,
    max_attempts: u32 = 5,
    every_seconds: i64,
    /// When the first tick is due. `null` is "now", so the first tick fires on the next pass.
    first_run_at: ?i64 = null,
    enabled: bool = true,
};

/// A row, as read.
pub const Job = struct {
    id: JobId,
    queue: []const u8,
    kind: []const u8,
    version: i32,
    payload: []const u8,
    idempotency_key: ?[]const u8,
    state: State,
    priority: i32,
    attempt: u32,
    max_attempts: u32,
    run_at: i64,
    lease_until: ?i64,
    leased_by: ?[]const u8,
    cancel_requested: bool,
    result: ?[]const u8,
    last_error: ?[]const u8,
    inserted_at: i64,
    updated_at: i64,
};

/// A claimed job: the identity of the row, plus the token that says this attempt owns it.
///
/// The scalars are copied, so a `Lease` is usable as an argument after the arena that produced it is
/// gone. The four slices (`queue`, `kind`, `payload`, `leased_by`) belong to that arena and are read
/// while the job body runs.
pub const Lease = struct {
    job_id: JobId,
    attempt: u32,
    max_attempts: u32,
    queue: []const u8,
    kind: []const u8,
    version: i32,
    payload: []const u8,
    leased_by: []const u8,
    lease_until: i64,
};

/// What a job write did. `not_owner` is what a worker gets when its lease expired and another attempt
/// took over: it must write nothing at all, which is why it is a value and not an error.
pub const Owned = enum { committed, not_owner };

/// The result of asking a job to stop.
pub const CancelOutcome = enum {
    /// The job was `available`: it is terminal now and will never be claimed.
    cancelled,
    /// The job is `leased`: the request is recorded, and the running attempt observes it at its next
    /// step boundary. If that attempt never checks in, the lease expiry path finishes the job.
    requested,
    /// The job is already `completed`, `failed` or `cancelled`.
    already_terminal,
    /// No such job.
    not_found,
};

/// What a failure did to the row.
pub const FailOutcome = enum {
    /// Attempts remain: the row is `available` again, later.
    retried,
    /// No attempts remain: terminal, with the reason kept.
    failed,
    /// The row had a cancellation request outstanding, so it stops here rather than retrying.
    cancelled,
    /// Another attempt owns the row now; nothing was written.
    not_owner,
};

pub const Config = struct {
    /// The queues this worker serves, with their concurrency limits (`-1` = unlimited).
    queues: []const QueueLimit = &.{.{ .name = default_queue }},
    /// How long a claim is valid. A worker that dies leaves a row whose lease expires.
    lease_ms: i64 = 30_000,
    /// How often the runner reaps expired leases, refreshes the cancel snapshot and runs due
    /// schedules.
    tick_ms: i64 = 1_000,
    /// How long the runner waits before claiming again when nothing woke it. The contract's fallback
    /// poll, and on this adapter the only cross-process wakeup there is.
    poll_interval_ms: i64 = 1_000,
    /// How many jobs one pass claims. Bounded so a large backlog cannot starve the reaper.
    batch: usize = 8,
    /// Completed rows are deleted once they are this old. Failed rows are kept until cleared.
    retention_ms: i64 = 7 * 24 * 60 * 60 * 1_000,
    retry: retry.Policy = .{},

    /// A third of the lease, per the contract: a heartbeat is not worth doing more often, and doing it
    /// less often is how a healthy job loses its lease to the reaper.
    pub fn heartbeatMs(self: Config) i64 {
        return @max(1, @divTrunc(self.lease_ms, 3));
    }
};

/// The wall clock, in microseconds. Injectable, so the arithmetic that depends on time — lease
/// expiry, backoff scheduling, retention — is provable without waiting for it.
///
/// The real clock carries its `Io` by value: a pointer to a local `io` parameter would dangle the
/// moment the function that built it returned.
pub const Clock = struct {
    io: ?std.Io = null,
    user: ?*anyopaque = null,
    now_fn: ?*const fn (?*anyopaque) i64 = null,

    pub fn now(self: Clock) i64 {
        if (self.now_fn) |now_fn| return now_fn(self.user);

        return micros(std.Io.Clock.Timestamp.now(self.io.?, .real));
    }

    pub fn real(io: std.Io) Clock {
        return .{ .io = io };
    }

    /// A clock a test moves by hand. `state` must outlive every use of the returned clock.
    pub fn fixed(state: *i64) Clock {
        const Fixed = struct {
            fn now(user: ?*anyopaque) i64 {
                const value: *i64 = @ptrCast(@alignCast(user.?));

                return value.*;
            }
        };

        return .{ .user = @ptrCast(state), .now_fn = Fixed.now };
    }
};

/// Microseconds since the epoch from an `Io` timestamp. Only ordering matters: a lease is compared
/// against the expiry it wrote, and every node sharing a database shares the clock's direction.
pub fn micros(stamp: std.Io.Clock.Timestamp) i64 {
    return @intCast(@divTrunc(stamp.raw.toNanoseconds(), std.time.ns_per_us));
}

pub const Error = data.Error || registry.Error || error{
    /// A spec cannot describe a job (no kind, no queue, no attempts, a non-positive period), or the
    /// configured queue list is too long to build a claim statement from.
    InvalidSpec,
    NotFound,
    /// This layer's own bookkeeping could not allocate — a lease list, a statement buffer's owner, a
    /// decoded row. Reported as itself rather than as `Unavailable`, which is the taxonomy's word for
    /// the *dependency* being down: an allocator that refused is not a database that is gone.
    OutOfMemory,
};

const job_columns =
    "id, queue, kind, version, payload, idempotency_key, state, priority, attempt, max_attempts, " ++
    "run_at, lease_until, leased_by, cancel_requested, result, last_error, " ++
    "inserted_at, updated_at";

/// What a reaped lease leaves in `last_error`. A named constant because a test asserts it and an
/// operator greps for it.
pub const lease_expired_reason = "lease expired";

/// How much room the generated claim statement gets. Each served queue adds one clause of well under a
/// hundred bytes, so this covers far more queues than an application declares; exceeding it is
/// refused (`error.InvalidSpec`) rather than truncated.
pub const claim_sql_capacity = 4 * 1024;

pub const Jobs = struct {
    db: *data.Database,
    io: std.Io,
    config: Config,
    clock: Clock,
    /// Raised when this process enqueues, so a runner in the same process claims without waiting for
    /// its poll. A hint, not a handoff: missing it costs one poll interval and nothing else.
    wake_mutex: std.Io.Mutex = .init,
    wake_condition: std.Io.Condition = .init,

    pub fn init(db: *data.Database, io: std.Io, config: Config) Jobs {
        return .{ .db = db, .io = io, .config = config, .clock = Clock.real(io) };
    }

    /// Apply this module's schema. Idempotent; safe on every start and in every test.
    pub fn migrate(self: *Jobs) Error!void {
        return schema.apply(self.db);
    }

    /// Replace the clock. Tests use this to move time without waiting for it.
    pub fn useClock(self: *Jobs, clock: Clock) void {
        self.clock = clock;
    }

    /// A scratch allocator for work that should not land in a caller's arena. Reset on every call.
    fn scratch(self: *Jobs) std.mem.Allocator {
        _ = self;

        // The module needs one allocator for scratch strings (the idempotency key a schedule renders,
        // the payload lookups a decode duplicates). `page_allocator` is the honest choice for the few
        // small allocations per pass: they are short-lived, and a per-`Jobs` arena would make `Jobs`
        // uncopyable and its memory unaccounted for.
        return std.heap.page_allocator;
    }

    // ---------------------------------------------------------------- //
    // Enqueue

    /// Write a job. With a `tx`, the row commits with the caller's domain write — the slice's atomicity
    /// contract; without one it gets its own short transaction and wakes this process's runner.
    pub fn enqueue(self: *Jobs, tx: ?*data.Tx, spec: EnqueueSpec) Error!EnqueueOutcome {
        const now = self.clock.now();

        if (tx) |handle| {
            try validateEnqueue(spec);

            return self.enqueueIn(handle, spec, now);
        }

        try validateEnqueue(spec);

        var own = try self.db.begin(.read_write);
        defer own.rollback();

        const outcome = try self.enqueueIn(own, spec, now);
        try own.commit();

        // After the commit, never inside it: a waiter woken by a row it cannot see yet would claim
        // nothing and go back to sleep for a poll interval.
        self.wake();

        return outcome;
    }

    fn enqueueIn(self: *Jobs, tx: *data.Tx, spec: EnqueueSpec, now: i64) Error!EnqueueOutcome {
        const run_at = spec.run_at orelse now;

        // `INSERT OR IGNORE` defers to the partial unique index: a duplicate key inserts nothing and
        // says so through `rows_affected`. That is what makes the call idempotent rather than a
        // read-then-write two callers can both win. Every `NOT NULL` column is bound here, so the
        // "ignore" can only ever mean the key was taken.
        const inserted = try self.db.exec(
            tx,
            "INSERT OR IGNORE INTO zurtr_jobs " ++
                "(queue, kind, version, payload, idempotency_key, state, priority, attempt, max_attempts, " ++
                "run_at, inserted_at, updated_at) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, 'available', ?6, 0, ?7, ?8, ?9, ?9)",
            &.{
                .{ .text = spec.queue },
                .{ .text = spec.kind },
                .{ .integer = spec.version },
                .{ .bytes = spec.payload },
                if (spec.idempotency_key) |key| .{ .text = key } else .null,
                .{ .integer = spec.priority },
                .{ .integer = @intCast(spec.max_attempts) },
                .{ .integer = run_at },
                .{ .integer = now },
            },
        );

        if (inserted.rows_affected == 0) {
            // The key was taken. Return the job that holds it: the caller asked for "at most one such
            // job", so that job is the answer rather than an error.
            const key = spec.idempotency_key orelse return error.Internal;
            const existing = try self.queryInt(
                tx,
                "SELECT id FROM zurtr_jobs WHERE queue = ?1 AND kind = ?2 AND idempotency_key = ?3",
                &.{ .{ .text = spec.queue }, .{ .text = spec.kind }, .{ .text = key } },
            ) orelse return error.Internal;

            return .{ .id = existing, .inserted = false };
        }

        // `last_insert_rowid()` is this connection's most recent insert, and `BEGIN IMMEDIATE` holds
        // the write lock from the moment the transaction opened, so between the insert above and this
        // read no other writer can have moved it. That is why the id needs no sequence table.
        const id = (try self.queryInt(tx, "SELECT last_insert_rowid()", &.{})).?;

        return .{ .id = id, .inserted = true };
    }

    // ---------------------------------------------------------------- //
    // Claim, heartbeat, completion

    /// Lease up to `limit` ready jobs, in the contract's order.
    ///
    /// The shape is the contract's select-then-update: pick the candidate, then take it with an `UPDATE`
    /// whose `WHERE` is the whole guard — `available`, due, in a queue this worker serves, under that
    /// queue's limit — and let `rows_affected` decide who won. The write transaction is what makes that
    /// safe, and it is the same sentence the contract uses: SQLite admits one writer per database and the
    /// adapter opens every read-write transaction with `BEGIN IMMEDIATE`, so nothing interleaves between
    /// the two statements and a lost race is only possible when a *different connection* got there first
    /// — which the transaction has already excluded.
    ///
    /// No token column is needed for ownership: `attempt`, which every claim bumps, is what every
    /// owner-only write is guarded on. A worker that lost its lease holds an `attempt` the row no longer
    /// has, and its writes affect zero rows.
    ///
    /// A lease taken here counts towards its queue's limit for every other claimer, because the limit is
    /// evaluated against `state = 'leased'` in the same transaction that takes the lease.
    pub fn claim(
        self: *Jobs,
        allocator: std.mem.Allocator,
        worker: []const u8,
        limit: usize,
        now_micros: ?i64,
    ) Error![]Lease {
        if (self.config.queues.len == 0 or limit == 0) return &.{};

        const now = now_micros orelse self.clock.now();
        const lease_until = now + self.config.lease_ms;

        var select_buffer: [claim_sql_capacity]u8 = undefined;
        const select_sql = try self.claimSelectSql(&select_buffer);

        var tx = self.db.begin(.read_write) catch |err| switch (err) {
            // A serialized-writer engine answers a second writer with Busy, which the adapter maps to
            // `Conflict`. For a claim that means "someone else is writing; look again next pass", not a
            // failure: a queue that errored whenever another worker was mid-write would be useless. The
            // adapter sets no busy timeout, so there is nothing to wait for — this is the wait.
            error.Conflict => return &.{},
            else => return err,
        };
        defer tx.rollback();

        var leases: std.ArrayList(Lease) = .empty;
        errdefer leases.deinit(allocator);

        var index: usize = 0;
        while (index < limit) : (index += 1) {
            const candidate = (try self.candidateLease(allocator, tx, select_sql, now)) orelse break;

            if (try self.takeCandidate(tx, worker, candidate.id, candidate.attempt, now, lease_until)) {
                try leases.append(allocator, .{
                    .job_id = candidate.id,
                    .attempt = candidate.attempt + 1,
                    .max_attempts = candidate.max_attempts,
                    .queue = candidate.queue,
                    .kind = candidate.kind,
                    .version = candidate.version,
                    .payload = candidate.payload,
                    .leased_by = worker,
                    .lease_until = lease_until,
                });
            }
        }

        try tx.commit();

        return leases.toOwnedSlice(allocator);
    }

    /// The candidate: the row a claim would take, read with the same predicate the take is guarded by.
    const Candidate = struct {
        id: JobId,
        attempt: u32,
        max_attempts: u32,
        queue: []const u8,
        kind: []const u8,
        version: i32,
        payload: []const u8,
    };

    fn candidateLease(
        self: *Jobs,
        allocator: std.mem.Allocator,
        tx: *data.Tx,
        select_sql: []const u8,
        now: i64,
    ) Error!?Candidate {
        const Select = struct {
            allocator: std.mem.Allocator,
            candidate: ?Candidate = null,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (self_.candidate != null) return;

                self_.candidate = .{
                    .id = columnInt("id", columns, 0) catch |err| return err,
                    .attempt = columnU32("attempt", columns, 1) catch |err| return err,
                    .max_attempts = columnU32("max_attempts", columns, 2) catch |err| return err,
                    .queue = duplicateText(self_.allocator, "queue", columns, 3) catch |err| return err,
                    .kind = duplicateText(self_.allocator, "kind", columns, 4) catch |err| return err,
                    .version = columnI32("version", columns, 5) catch |err| return err,
                    .payload = duplicateBytes(self_.allocator, "payload", columns, 6) catch |err| return err,
                };
            }
        };

        var params: std.ArrayList(data.Value) = .empty;
        defer params.deinit(allocator);

        try params.append(allocator, .{ .integer = now });
        for (self.config.queues) |queue| {
            try params.append(allocator, .{ .text = queue.name });
            if (!queue.unlimited()) try params.append(allocator, .{ .integer = queue.limit });
        }

        var select = Select{ .allocator = allocator };
        try self.db.query(tx, select_sql, params.items, select.sink());

        return select.candidate;
    }

    /// Take the candidate. The guard is repeated here even though the candidate was selected with it,
    /// because this statement — not the select — is what decides: a row that stopped being available
    /// between the two (impossible under the write lock, and cheap to be sure of) affects zero rows.
    fn takeCandidate(
        self: *Jobs,
        tx: *data.Tx,
        worker: []const u8,
        job_id: JobId,
        attempt: u32,
        now: i64,
        lease_until: i64,
    ) Error!bool {
        const result = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'leased', leased_by = ?1, lease_until = ?2, " ++
                "attempt = attempt + 1, updated_at = ?3 " ++
                "WHERE id = ?4 AND state = 'available' AND attempt = ?5 AND run_at <= ?3",
            &.{
                .{ .text = worker },
                .{ .integer = lease_until },
                .{ .integer = now },
                .{ .integer = job_id },
                .{ .integer = @intCast(attempt) },
            },
        );

        return result.rows_affected == 1;
    }

    /// Build the candidate statement for this worker's queues. Generated rather than fixed because the
    /// per-queue limits are runtime configuration and each queue's limit has to be tested against that
    /// queue's own count; every value still crosses as a parameter, and the number of queues is bounded
    /// by `claim_sql_capacity`.
    fn claimSelectSql(self: *Jobs, buffer: []u8) Error![]const u8 {
        var writer = std.Io.Writer.fixed(buffer);

        writer.writeAll(
            "SELECT id, attempt, max_attempts, queue, kind, version, payload FROM zurtr_jobs " ++
                "WHERE state = 'available' AND run_at <= ?1 AND (",
        ) catch return error.InvalidSpec;

        for (self.config.queues, 0..) |queue, index| {
            if (index != 0) writer.writeAll(" OR ") catch return error.InvalidSpec;

            if (queue.unlimited()) {
                writer.print("queue = ?{d}", .{2 + index * 2}) catch return error.InvalidSpec;
            } else {
                // The count is the contract's rule, evaluated where the lease is taken: this queue cannot
                // exceed its limit, because the row that would exceed it cannot be selected.
                writer.print(
                    "(queue = ?{d} AND (SELECT count(*) FROM zurtr_jobs AS leased_rows " ++
                        "WHERE leased_rows.state = 'leased' AND leased_rows.queue = ?{d}) < ?{d})",
                    .{ 2 + index * 2, 2 + index * 2, 3 + index * 2 },
                ) catch return error.InvalidSpec;
            }
        }

        writer.writeAll(") ORDER BY priority DESC, run_at ASC, id ASC LIMIT 1") catch return error.InvalidSpec;

        return writer.buffered();
    }

    /// Extend a lease. False means this attempt no longer owns the row — expired, reaped, cancelled or
    /// taken over — which is the signal to stop rather than keep working.
    ///
    /// `tx` is the running job's transaction when there is one: there is a single connection, so a
    /// heartbeat issued while a body's transaction is open belongs to that transaction whether it is
    /// passed or not. Passing it says so out loud.
    pub fn heartbeat(self: *Jobs, tx: ?*data.Tx, lease: *const Lease, now_micros: ?i64) Error!bool {
        const now = now_micros orelse self.clock.now();

        const result = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET lease_until = ?1, updated_at = ?2 " ++
                "WHERE id = ?3 AND state = 'leased' AND attempt = ?4",
            &.{
                .{ .integer = now + self.config.lease_ms },
                .{ .integer = now },
                .{ .integer = lease.job_id },
                .{ .integer = @intCast(lease.attempt) },
            },
        );

        return result.rows_affected == 1;
    }

    /// The job succeeded. Pass the running job's transaction so the body's effects and this state change
    /// commit together, or `null` for a completion that is a transaction of its own.
    ///
    /// Only the owning attempt can complete: the guard is the same `attempt` every owner-only write
    /// uses, in the same statement as the write it guards, so a worker whose lease
    /// expired cannot overwrite the attempt that took over — and the caller that sees `not_owner` rolls
    /// its body's effects back rather than committing them.
    pub fn complete(self: *Jobs, tx: ?*data.Tx, lease: *const Lease, result_text: []const u8, now_micros: ?i64) Error!Owned {
        const now = now_micros orelse self.clock.now();

        const result = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'completed', result = ?1, lease_until = NULL, " ++
                "last_error = NULL, updated_at = ?2 " ++
                "WHERE id = ?3 AND state = 'leased' AND attempt = ?4",
            &.{
                .{ .text = result_text },
                .{ .integer = now },
                .{ .integer = lease.job_id },
                .{ .integer = @intCast(lease.attempt) },
            },
        );

        return if (result.rows_affected == 1) .committed else .not_owner;
    }

    /// The job failed. The routing is the contract's: attempts remaining means back off and become
    /// available again; no attempts remaining means terminal, with the reason kept.
    ///
    /// A row that asked for cancellation does not retry — "stop" is the request, and re-running is the
    /// opposite of it. Both decisions are made inside the guarded statements rather than by reading the
    /// row first, so a cancellation recorded between a read and a write cannot be missed.
    pub fn fail(
        self: *Jobs,
        tx: ?*data.Tx,
        lease: *const Lease,
        reason: []const u8,
        now_micros: ?i64,
        jitter_draw: u64,
    ) Error!FailOutcome {
        const now = now_micros orelse self.clock.now();

        if (self.config.retry.retries(lease.attempt, lease.max_attempts)) {
            const delay_ms = self.config.retry.delayMs(lease.attempt, jitter_draw);
            const run_at = now + delay_ms * std.time.us_per_ms;

            const retried = try self.db.exec(
                tx,
                "UPDATE zurtr_jobs SET state = 'available', run_at = ?1, last_error = ?2, " ++
                    "lease_until = NULL, leased_by = NULL, updated_at = ?3 " ++
                    "WHERE id = ?4 AND state = 'leased' AND attempt = ?5 AND cancel_requested = 0",
                &.{
                    .{ .integer = run_at },
                    .{ .text = reason },
                    .{ .integer = now },
                    .{ .integer = lease.job_id },
                    .{ .integer = @intCast(lease.attempt) },
                },
            );
            if (retried.rows_affected == 1) return .retried;
        } else {
            const failed = try self.db.exec(
                tx,
                "UPDATE zurtr_jobs SET state = 'failed', last_error = ?1, lease_until = NULL, " ++
                    "updated_at = ?2 " ++
                    "WHERE id = ?3 AND state = 'leased' AND attempt = ?4 AND cancel_requested = 0",
                &.{
                    .{ .text = reason },
                    .{ .integer = now },
                    .{ .integer = lease.job_id },
                    .{ .integer = @intCast(lease.attempt) },
                },
            );
            if (failed.rows_affected == 1) return .failed;
        }

        // Neither branch wrote, so one of two things is true: the row asked for cancellation and must
        // stop as cancelled, or this attempt is no longer the owner and must not write at all.
        const cancelled = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'cancelled', last_error = ?1, lease_until = NULL, " ++
                "updated_at = ?2 " ++
                "WHERE id = ?3 AND state = 'leased' AND attempt = ?4 AND cancel_requested = 1",
            &.{
                .{ .text = reason },
                .{ .integer = now },
                .{ .integer = lease.job_id },
                .{ .integer = @intCast(lease.attempt) },
            },
        );
        if (cancelled.rows_affected == 1) return .cancelled;

        return .not_owner;
    }

    /// Stop a job that is already running, from inside its own body: the cancellation was observed at a
    /// step boundary and the body's transaction has rolled back. Only the owning attempt can do this, so
    /// a reaped-and-reclaimed job is not cancelled by the attempt that lost it.
    pub fn finishCancelled(self: *Jobs, tx: ?*data.Tx, lease: *const Lease, reason: []const u8, now_micros: ?i64) Error!Owned {
        const now = now_micros orelse self.clock.now();

        const result = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'cancelled', last_error = ?1, lease_until = NULL, " ++
                "updated_at = ?2 " ++
                "WHERE id = ?3 AND state = 'leased' AND attempt = ?4",
            &.{
                .{ .text = reason },
                .{ .integer = now },
                .{ .integer = lease.job_id },
                .{ .integer = @intCast(lease.attempt) },
            },
        );

        return if (result.rows_affected == 1) .committed else .not_owner;
    }

    /// Fail a job without consulting the retry policy: the kind is not runnable here, or its version is
    /// not the running action's. Retrying cannot help — the next attempt would resolve to the same
    /// nothing — so the contract's "fails the job terminally with a diagnostic" is this, and it is the
    /// only path that bypasses `fail`'s attempt counting on purpose.
    pub fn failTerminal(self: *Jobs, tx: ?*data.Tx, lease: *const Lease, reason: []const u8, now_micros: ?i64) Error!Owned {
        const now = now_micros orelse self.clock.now();

        const result = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'failed', last_error = ?1, lease_until = NULL, " ++
                "updated_at = ?2 " ++
                "WHERE id = ?3 AND state = 'leased' AND attempt = ?4",
            &.{
                .{ .text = reason },
                .{ .integer = now },
                .{ .integer = lease.job_id },
                .{ .integer = @intCast(lease.attempt) },
            },
        );

        return if (result.rows_affected == 1) .committed else .not_owner;
    }

    // ---------------------------------------------------------------- //
    // Cancellation

    /// Ask a job to stop. An `available` job becomes terminal here; a `leased` job records the request,
    /// which the running attempt observes at its next step boundary (see `cancel.zig`).
    ///
    /// The caller raises the in-process cancel set itself (`cancel.Set.request`) if its own runner
    /// should see the request without waiting for the next reap tick; a runner in another process finds
    /// out from the database on its own tick.
    pub fn cancel(self: *Jobs, tx: ?*data.Tx, job_id: JobId, now_micros: ?i64) Error!CancelOutcome {
        const now = now_micros orelse self.clock.now();

        const direct = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET state = 'cancelled', cancel_requested = 1, updated_at = ?1 " ++
                "WHERE id = ?2 AND state = 'available'",
            &.{ .{ .integer = now }, .{ .integer = job_id } },
        );
        if (direct.rows_affected == 1) return .cancelled;

        // Either it was not available, or it was claimed between the two statements. Recording the
        // request is guarded on `leased` so a job claimed a moment ago is still cancelled, and a job
        // that finished first is not resurrected.
        const recorded = try self.db.exec(
            tx,
            "UPDATE zurtr_jobs SET cancel_requested = 1, updated_at = ?1 " ++
                "WHERE id = ?2 AND state = 'leased'",
            &.{ .{ .integer = now }, .{ .integer = job_id } },
        );
        if (recorded.rows_affected == 1) return .requested;

        const state = (try self.jobState(tx, job_id)) orelse return .not_found;

        return switch (state) {
            .available, .leased => .requested,
            else => .already_terminal,
        };
    }

    /// The ids of jobs that asked for cancellation and are still leased: one query per reap tick, which
    /// is what keeps `ctx.cancelled()` off the database.
    ///
    /// `tx` is the transaction to read through. A runner refreshing from inside a job passes the job's
    /// own transaction — there is one connection, so an untransacted read while one is open is refused
    /// by the adapter (`error.InvalidState`) rather than queued behind it.
    pub fn cancelledIds(self: *Jobs, tx: ?*data.Tx, allocator: std.mem.Allocator) Error![]i64 {
        const Collect = struct {
            allocator: std.mem.Allocator,
            ids: std.ArrayList(i64) = .empty,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                const id = columnInt("id", columns, 0) catch |err| return err;

                self_.ids.append(self_.allocator, id) catch return error.Unavailable;
            }
        };

        var collect = Collect{ .allocator = allocator };
        try self.db.query(
            tx,
            "SELECT id FROM zurtr_jobs WHERE state = 'leased' AND cancel_requested = 1",
            &.{},
            collect.sink(),
        );

        return collect.ids.toOwnedSlice(allocator);
    }

    // ---------------------------------------------------------------- //
    // The reaper

    pub const Reaped = struct {
        /// Expired leases returned to `available`: they will be claimed again (at-least-once).
        released: u64 = 0,
        /// Expired leases that had asked for cancellation, or had no attempts left: terminal.
        terminated: u64 = 0,
        /// Completed rows deleted by retention.
        deleted: u64 = 0,
    };

    /// The reaper: expired leases, then retention. Run by the same loop as the claim, on a timer.
    ///
    /// Two decisions the contract leaves open, resolved here because they are visible in the row
    /// afterwards:
    ///
    ///   * **An expired lease with attempts left goes back to `available`**, with `lease expired` kept
    ///     as the reason. `attempt` was already bumped by the claim that expired, so a crash loop is
    ///     still a rising number rather than silence.
    ///   * **An expired lease with no attempts left fails**, and an expired lease that had asked for
    ///     cancellation is cancelled. The contract's sentence returns expired rows to `available`; a
    ///     job whose attempts are exhausted could then only be claimed in order to fail again, which
    ///     makes bounded attempts bounded in name only, and re-running cancelled work is the opposite
    ///     of the request that stopped it.
    pub fn reap(self: *Jobs, now_micros: ?i64) Error!Reaped {
        const now = now_micros orelse self.clock.now();
        var reaped = Reaped{};

        const released = try self.db.exec(
            null,
            "UPDATE zurtr_jobs SET state = 'available', lease_until = NULL, " ++
                "leased_by = NULL, last_error = ?1, updated_at = ?2 " ++
                "WHERE state = 'leased' AND lease_until IS NOT NULL AND lease_until <= ?2 " ++
                "AND cancel_requested = 0 AND attempt < max_attempts",
            &.{ .{ .text = lease_expired_reason }, .{ .integer = now } },
        );
        reaped.released = released.rows_affected;

        const cancelled = try self.db.exec(
            null,
            "UPDATE zurtr_jobs SET state = 'cancelled', lease_until = NULL, " ++
                "leased_by = NULL, last_error = ?1, updated_at = ?2 " ++
                "WHERE state = 'leased' AND lease_until IS NOT NULL AND lease_until <= ?2 " ++
                "AND cancel_requested = 1",
            &.{ .{ .text = lease_expired_reason }, .{ .integer = now } },
        );
        reaped.terminated += cancelled.rows_affected;

        const exhausted = try self.db.exec(
            null,
            "UPDATE zurtr_jobs SET state = 'failed', lease_until = NULL, " ++
                "leased_by = NULL, last_error = ?1, updated_at = ?2 " ++
                "WHERE state = 'leased' AND lease_until IS NOT NULL AND lease_until <= ?2 " ++
                "AND cancel_requested = 0 AND attempt >= max_attempts",
            &.{ .{ .text = lease_expired_reason }, .{ .integer = now } },
        );
        reaped.terminated += exhausted.rows_affected;

        const deleted = try self.db.exec(
            null,
            "DELETE FROM zurtr_jobs WHERE state = 'completed' AND updated_at <= ?1",
            &.{.{ .integer = now - self.config.retention_ms }},
        );
        reaped.deleted = deleted.rows_affected;

        return reaped;
    }

    /// Delete every failed row. The contract keeps them "until manually cleared", and this is that.
    pub fn clearFailed(self: *Jobs) Error!u64 {
        const result = try self.db.exec(null, "DELETE FROM zurtr_jobs WHERE state = 'failed'", &.{});

        return result.rows_affected;
    }

    // ---------------------------------------------------------------- //
    // Schedules

    /// Create a recurring job. A tick's idempotency key is derived from the schedule id and the tick
    /// time, so a crash between enqueueing a tick and advancing the schedule cannot double-fire it.
    pub fn scheduleEvery(self: *Jobs, tx: ?*data.Tx, spec: ScheduleSpec) Error!ScheduleId {
        const now = self.clock.now();
        const next = spec.first_run_at orelse now;
        try validateSchedule(spec);

        if (tx) |handle| return self.scheduleIn(handle, spec, next, now);

        var own = try self.db.begin(.read_write);
        defer own.rollback();

        const id = try self.scheduleIn(own, spec, next, now);
        try own.commit();

        return id;
    }

    fn scheduleIn(self: *Jobs, tx: *data.Tx, spec: ScheduleSpec, next: i64, now: i64) Error!ScheduleId {
        _ = try self.db.exec(
            tx,
            "INSERT INTO zurtr_schedules " ++
                "(kind, version, payload, queue, priority, max_attempts, every_seconds, next_run_at, enabled, " ++
                "inserted_at, updated_at) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            &.{
                .{ .text = spec.kind },
                .{ .integer = spec.version },
                .{ .bytes = spec.payload },
                .{ .text = spec.queue },
                .{ .integer = spec.priority },
                .{ .integer = @intCast(spec.max_attempts) },
                .{ .integer = spec.every_seconds },
                .{ .integer = next },
                .{ .integer = if (spec.enabled) 1 else 0 },
                .{ .integer = now },
            },
        );

        return (try self.queryInt(tx, "SELECT last_insert_rowid()", &.{})).?;
    }

    /// One pass over due schedules, oldest tick first.
    ///
    /// A tick is claimed like a job is — a guarded `UPDATE` whose `rows_affected` decides who won — and
    /// the enqueue and the advance commit in the same transaction as that claim, so a crash cannot
    /// leave a tick enqueued and un-advanced. The deterministic key is the second line of defence: if a
    /// tick is ever processed twice, the second enqueue returns the first job rather than making
    /// another.
    pub fn runDueSchedules(
        self: *Jobs,
        allocator: std.mem.Allocator,
        runner: []const u8,
        limit: usize,
    ) Error![]EnqueueOutcome {
        const now = self.clock.now();

        var outcomes: std.ArrayList(EnqueueOutcome) = .empty;
        errdefer outcomes.deinit(allocator);

        var index: usize = 0;
        while (index < limit) : (index += 1) {
            var tx = self.db.begin(.read_write) catch |err| switch (err) {
                // Another writer holds the lock: this pass is over, and the ticks it already committed
                // stand. The caller gets the outcomes it did produce.
                error.Conflict => break,
                else => return err,
            };
            defer tx.rollback();

            const due = try self.dueSchedule(allocator, tx, now) orelse break;

            const claimed = try self.db.exec(
                tx,
                "UPDATE zurtr_schedules SET lease_until = ?1, claimed_by = ?2, updated_at = ?3 " ++
                    "WHERE id = ?4 AND enabled = 1 AND next_run_at = ?5 " ++
                    "AND (lease_until IS NULL OR lease_until <= ?3)",
                &.{
                    .{ .integer = now + self.config.lease_ms },
                    .{ .text = runner },
                    .{ .integer = now },
                    .{ .integer = due.id },
                    .{ .integer = due.next_run_at },
                },
            );
            if (claimed.rows_affected == 0) {
                // Another runner took this tick between the read and the claim. Nothing is wrong: stop,
                // because the next pass sees whatever is left.
                tx.rollback();
                break;
            }

            const key = std.fmt.allocPrint(allocator, "schedule/{d}/{d}", .{ due.id, due.next_run_at }) catch
                return error.Unavailable;

            const outcome = try self.enqueueIn(tx, .{
                .kind = due.kind,
                .version = due.version,
                .payload = due.payload,
                .queue = due.queue,
                .priority = due.priority,
                .max_attempts = due.max_attempts,
                .run_at = due.next_run_at,
                .idempotency_key = key,
            }, now);

            // The next tick is the first boundary *after* now: ticks that elapsed while this schedule
            // was not being run are skipped rather than replayed. That is the cron rule, and the
            // alternative — catching up — turns a ten-minute outage of a one-minute schedule into ten
            // jobs waiting to run, which is a stampede wearing a durability argument. An application
            // that must not skip a period has one-shot `enqueue` with `run_at` for exactly that, and
            // `last_run_at` tells it how far behind it fell.
            const period = due.every_seconds * std.time.us_per_s;
            var next_run_at = due.next_run_at + period;
            if (next_run_at <= now) {
                const behind = now - next_run_at;
                next_run_at += (@divTrunc(behind, period) + 1) * period;
            }

            const advanced = try self.db.exec(
                tx,
                "UPDATE zurtr_schedules SET last_run_at = next_run_at, next_run_at = ?1, " ++
                    "lease_until = NULL, claimed_by = NULL, updated_at = ?2 " ++
                    "WHERE id = ?3 AND next_run_at = ?4",
                &.{
                    .{ .integer = next_run_at },
                    .{ .integer = now },
                    .{ .integer = due.id },
                    .{ .integer = due.next_run_at },
                },
            );
            if (advanced.rows_affected == 0) {
                // The claim above proved this row was still on this tick, in this transaction, so a
                // failed advance means the row moved under a write lock — which cannot happen.
                std.log.err("jobs: schedule {d} did not advance off tick {d}", .{ due.id, due.next_run_at });

                return error.Internal;
            }

            try tx.commit();
            try outcomes.append(allocator, outcome);
        }

        if (outcomes.items.len != 0) self.wake();

        return outcomes.toOwnedSlice(allocator);
    }

    const DueSchedule = struct {
        id: ScheduleId,
        kind: []const u8,
        version: i32,
        payload: []const u8,
        queue: []const u8,
        priority: i32,
        max_attempts: u32,
        every_seconds: i64,
        next_run_at: i64,
    };

    fn dueSchedule(self: *Jobs, allocator: std.mem.Allocator, tx: *data.Tx, now: i64) Error!?DueSchedule {
        const Select = struct {
            allocator: std.mem.Allocator,
            found: ?DueSchedule = null,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (self_.found != null) return;

                self_.found = .{
                    .id = columnInt("id", columns, 0) catch |err| return err,
                    .kind = duplicateText(self_.allocator, "kind", columns, 1) catch |err| return err,
                    .version = columnI32("version", columns, 2) catch |err| return err,
                    .payload = duplicateBytes(self_.allocator, "payload", columns, 3) catch |err| return err,
                    .queue = duplicateText(self_.allocator, "queue", columns, 4) catch |err| return err,
                    .priority = columnI32("priority", columns, 5) catch |err| return err,
                    .max_attempts = columnU32("max_attempts", columns, 6) catch |err| return err,
                    .every_seconds = columnInt("every_seconds", columns, 7) catch |err| return err,
                    .next_run_at = columnInt("next_run_at", columns, 8) catch |err| return err,
                };
            }
        };

        var select = Select{ .allocator = allocator };
        try self.db.query(
            tx,
            "SELECT id, kind, version, payload, queue, priority, max_attempts, every_seconds, next_run_at FROM zurtr_schedules " ++
                "WHERE enabled = 1 AND next_run_at <= ?1 AND (lease_until IS NULL OR lease_until <= ?1) " ++
                "ORDER BY next_run_at ASC, id ASC LIMIT 1",
            &.{.{ .integer = now }},
            select.sink(),
        );

        return select.found;
    }

    /// Turn a schedule off (or back on) without deleting its history.
    pub fn setScheduleEnabled(self: *Jobs, id: ScheduleId, enabled: bool) Error!bool {
        const result = try self.db.exec(
            null,
            "UPDATE zurtr_schedules SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            &.{
                .{ .integer = if (enabled) 1 else 0 },
                .{ .integer = self.clock.now() },
                .{ .integer = id },
            },
        );

        return result.rows_affected == 1;
    }

    // ---------------------------------------------------------------- //
    // Reading

    /// One job, or null. The slices belong to `allocator`.
    pub fn get(self: *Jobs, allocator: std.mem.Allocator, job_id: JobId) Error!?Job {
        const Select = struct {
            allocator: std.mem.Allocator,
            job: ?Job = null,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (self_.job != null) return;

                self_.job = decodeJob(self_.allocator, columns) catch |err| return err;
            }
        };

        var select = Select{ .allocator = allocator };
        try self.db.query(
            null,
            "SELECT " ++ job_columns ++ " FROM zurtr_jobs WHERE id = ?1",
            &.{.{ .integer = job_id }},
            select.sink(),
        );

        return select.job;
    }

    /// How many rows are in one state, for one queue or for all of them.
    pub fn count(self: *Jobs, state: State, queue: ?[]const u8) Error!i64 {
        const value = if (queue) |name|
            try self.queryInt(
                null,
                "SELECT count(*) FROM zurtr_jobs WHERE state = ?1 AND queue = ?2",
                &.{ .{ .text = state.text() }, .{ .text = name } },
            )
        else
            try self.queryInt(
                null,
                "SELECT count(*) FROM zurtr_jobs WHERE state = ?1",
                &.{.{ .text = state.text() }},
            );

        return value orelse error.Internal;
    }

    /// Every `(kind, version)` the table holds, for the startup sweep.
    pub fn storedKinds(self: *Jobs, allocator: std.mem.Allocator) Error![]registry.StoredKind {
        const Collect = struct {
            allocator: std.mem.Allocator,
            kinds: std.ArrayList(registry.StoredKind) = .empty,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));

                self_.kinds.append(self_.allocator, .{
                    .kind = duplicateText(self_.allocator, "kind", columns, 0) catch |err| return err,
                    .version = columnI32("version", columns, 1) catch |err| return err,
                }) catch return error.Unavailable;
            }
        };

        var collect = Collect{ .allocator = allocator };
        try self.db.query(
            null,
            "SELECT DISTINCT kind, version FROM zurtr_jobs",
            &.{},
            collect.sink(),
        );

        return collect.kinds.toOwnedSlice(allocator);
    }

    /// The startup check the contract asks for: every kind in the table must be runnable by this
    /// deployment, so an unknown one is a failed boot rather than a job that fails at 3am. Also validates
    /// the registry itself, because a duplicate binding is the same class of problem.
    pub fn checkRegistry(self: *Jobs, allocator: std.mem.Allocator, registry_value: registry.Registry) Error!void {
        try registry_value.validate();

        const stored = try self.storedKinds(allocator);
        defer {
            // The sweep's rows are this call's own reading of the table, not a result it hands back, so
            // it releases them itself rather than leaving them to a caller that asked a yes/no question.
            for (stored) |entry| allocator.free(entry.kind);
            allocator.free(stored);
        }

        try registry_value.checkStored(stored);
    }

    // ---------------------------------------------------------------- //
    // The in-process wakeup

    /// Tell a runner in this process that there may be work. Harmless if there is none, and a no-op for a
    /// runner in another process — that one has the poll.
    pub fn wake(self: *Jobs) void {
        self.wake_mutex.lockUncancelable(self.io);
        defer self.wake_mutex.unlock(self.io);

        self.wake_condition.broadcast(self.io);
    }

    /// Wait for a wake or for `timeout_ms` to pass, whichever comes first. True when something
    /// signalled. A cancelled or timed-out wait reports false: a runner that stops should stop, and a
    /// runner with nothing to do should poll.
    pub fn waitForWork(self: *Jobs, timeout_ms: i64) bool {
        self.wake_mutex.lockUncancelable(self.io);
        defer self.wake_mutex.unlock(self.io);

        // `waitTimeout` unlocks the mutex itself and re-locks it before returning, which is why the
        // lock above is not released by hand here.
        const timeout: std.Io.Timeout = if (timeout_ms <= 0)
            .none
        else
            .{ .duration = .{ .raw = std.Io.Duration.fromMilliseconds(timeout_ms), .clock = .real } };

        self.wake_condition.waitTimeout(self.io, &self.wake_mutex, timeout) catch return false;

        return true;
    }

    // ---------------------------------------------------------------- //
    // Internals

    fn queryInt(self: *Jobs, tx: ?*data.Tx, sql: []const u8, params: []const data.Value) Error!?i64 {
        const Select = struct {
            value: ?i64 = null,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (self_.value != null) return;

                self_.value = columnInt("value", columns, 0) catch |err| return err;
            }
        };

        var select = Select{};
        try self.db.query(tx, sql, params, select.sink());

        return select.value;
    }

    fn jobState(self: *Jobs, tx: ?*data.Tx, job_id: JobId) Error!?State {
        const Select = struct {
            state: ?State = null,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (columns.len == 0) return error.Internal;

                self_.state = switch (columns[0]) {
                    .text => |value| State.parse(value) catch return error.Internal,
                    else => return error.Internal,
                };
            }
        };

        var select = Select{};
        try self.db.query(
            tx,
            "SELECT state FROM zurtr_jobs WHERE id = ?1",
            &.{.{ .integer = job_id }},
            select.sink(),
        );

        return select.state;
    }
};

fn validateEnqueue(spec: EnqueueSpec) Error!void {
    if (spec.kind.len == 0) return error.InvalidSpec;
    if (spec.queue.len == 0) return error.InvalidSpec;
    if (spec.max_attempts == 0) return error.InvalidSpec;
    if (spec.idempotency_key) |key| if (key.len == 0) return error.InvalidSpec;
}

fn validateSchedule(spec: ScheduleSpec) Error!void {
    if (spec.kind.len == 0) return error.InvalidSpec;
    if (spec.queue.len == 0) return error.InvalidSpec;
    if (spec.max_attempts == 0) return error.InvalidSpec;
    if (spec.every_seconds <= 0) return error.InvalidSpec;
}

// -------------------------------------------------------------------- //
// Row decoding

fn decodeJob(allocator: std.mem.Allocator, columns: []const data.Value) data.Error!Job {
    return .{
        .id = try columnInt("id", columns, 0),
        .queue = try duplicateText(allocator, "queue", columns, 1),
        .kind = try duplicateText(allocator, "kind", columns, 2),
        .version = try columnI32("version", columns, 3),
        .payload = try duplicateBytes(allocator, "payload", columns, 4),
        .idempotency_key = try duplicateOptionalText(allocator, "idempotency_key", columns, 5),
        .state = try State.parse(try columnText("state", columns, 6)),
        .priority = try columnI32("priority", columns, 7),
        .attempt = try columnU32("attempt", columns, 8),
        .max_attempts = try columnU32("max_attempts", columns, 9),
        .run_at = try columnInt("run_at", columns, 10),
        .lease_until = try columnOptionalInt("lease_until", columns, 11),
        .leased_by = try duplicateOptionalText(allocator, "leased_by", columns, 12),
        .cancel_requested = (try columnInt("cancel_requested", columns, 13)) != 0,
        .result = try duplicateOptionalText(allocator, "result", columns, 14),
        .last_error = try duplicateOptionalText(allocator, "last_error", columns, 15),
        .inserted_at = try columnInt("inserted_at", columns, 16),
        .updated_at = try columnInt("updated_at", columns, 17),
    };
}

/// A column the schema says is an integer. Any other tag means this layer and the schema disagree,
/// which is a bug in this file rather than a condition the caller can act on.
fn columnInt(name: []const u8, columns: []const data.Value, index: usize) data.Error!i64 {
    if (index >= columns.len) return error.Internal;

    return switch (columns[index]) {
        .integer => |value| value,
        else => {
            std.log.debug("jobs: column {s} is not an integer", .{name});

            return error.Internal;
        },
    };
}

fn columnI32(name: []const u8, columns: []const data.Value, index: usize) data.Error!i32 {
    return std.math.cast(i32, try columnInt(name, columns, index)) orelse error.Internal;
}

fn columnU32(name: []const u8, columns: []const data.Value, index: usize) data.Error!u32 {
    return std.math.cast(u32, try columnInt(name, columns, index)) orelse error.Internal;
}

fn columnOptionalInt(name: []const u8, columns: []const data.Value, index: usize) data.Error!?i64 {
    if (index >= columns.len) return error.Internal;

    return switch (columns[index]) {
        .null => null,
        .integer => |value| value,
        else => {
            std.log.debug("jobs: column {s} is not an integer", .{name});

            return error.Internal;
        },
    };
}

fn columnText(name: []const u8, columns: []const data.Value, index: usize) data.Error![]const u8 {
    if (index >= columns.len) return error.Internal;

    return switch (columns[index]) {
        .text => |value| value,
        else => {
            std.log.debug("jobs: column {s} is not text", .{name});

            return error.Internal;
        },
    };
}

fn duplicateText(allocator: std.mem.Allocator, name: []const u8, columns: []const data.Value, index: usize) data.Error![]const u8 {
    return allocator.dupe(u8, try columnText(name, columns, index)) catch error.Unavailable;
}

fn duplicateOptionalText(
    allocator: std.mem.Allocator,
    name: []const u8,
    columns: []const data.Value,
    index: usize,
) data.Error!?[]const u8 {
    if (index >= columns.len) return error.Internal;

    return switch (columns[index]) {
        .null => null,
        .text => |value| allocator.dupe(u8, value) catch error.Unavailable,
        else => {
            std.log.debug("jobs: column {s} is not text", .{name});

            return error.Internal;
        },
    };
}

fn duplicateBytes(allocator: std.mem.Allocator, name: []const u8, columns: []const data.Value, index: usize) data.Error![]const u8 {
    if (index >= columns.len) return error.Internal;

    return switch (columns[index]) {
        .bytes => |value| allocator.dupe(u8, value) catch error.Unavailable,
        // An empty payload is a zero-length blob; an engine that hands one back as empty text is
        // handing back the same bytes. Anything else is a mismatch.
        .text => |value| allocator.dupe(u8, value) catch error.Unavailable,
        else => {
            std.log.debug("jobs: column {s} is not bytes", .{name});

            return error.Internal;
        },
    };
}

// -------------------------------------------------------------------- //
// The module surface

pub const policy = retry;
pub const cancellation = cancel;
pub const action_registry = registry;
pub const storage = schema;
pub const Runner = @import("runner.zig").Runner;
pub const Tick = @import("runner.zig").Tick;

test {
    _ = policy;
    _ = cancellation;
    _ = action_registry;
    _ = storage;
    _ = @import("runner.zig");

    // The database-backed acceptance lives in `tests.zig` and is compiled only when the adapter is
    // built: a build without `-Dturso` has no binding, and the adapter's import of it is a compile
    // error rather than a runtime one — which is exactly what `turso_not_built.zig` says.
    if (comptime @import("build_options").turso) _ = @import("tests.zig");
}

test "a state round-trips through its text, and an unknown one is refused" {
    inline for (@typeInfo(State).@"enum".field_names) |name| {
        const state: State = @field(State, name);
        try std.testing.expectEqual(state, try State.parse(state.text()));
    }

    try std.testing.expectError(error.Internal, State.parse("queued"));
    try std.testing.expectError(error.Internal, State.parse(""));
}

test "a configured lease heartbeats at a third of its length, and never at zero" {
    try std.testing.expectEqual(@as(i64, 10_000), (Config{ .lease_ms = 30_000 }).heartbeatMs());
    try std.testing.expectEqual(@as(i64, 1), (Config{ .lease_ms = 2 }).heartbeatMs());
    try std.testing.expectEqual(@as(i64, 1), (Config{ .lease_ms = 0 }).heartbeatMs());
}

test "a queue limit says whether it is the contract's -1" {
    try std.testing.expect((QueueLimit{ .name = "default", .limit = -1 }).unlimited());
    try std.testing.expect((QueueLimit{ .name = "default", .limit = -7 }).unlimited());
    try std.testing.expect(!(QueueLimit{ .name = "default", .limit = 0 }).unlimited());
    try std.testing.expect(!(QueueLimit{ .name = "default", .limit = 4 }).unlimited());
}

test "a spec that cannot describe a job is refused before any statement runs" {
    try std.testing.expectError(error.InvalidSpec, validateEnqueue(.{ .kind = "" }));
    try std.testing.expectError(error.InvalidSpec, validateEnqueue(.{ .kind = "a", .queue = "" }));
    try std.testing.expectError(error.InvalidSpec, validateEnqueue(.{ .kind = "a", .max_attempts = 0 }));
    try std.testing.expectError(error.InvalidSpec, validateEnqueue(.{ .kind = "a", .idempotency_key = "" }));
    try validateEnqueue(.{ .kind = "a", .idempotency_key = null });

    try std.testing.expectError(error.InvalidSpec, validateSchedule(.{ .kind = "a", .every_seconds = 0 }));
    try std.testing.expectError(error.InvalidSpec, validateSchedule(.{ .kind = "a", .every_seconds = -1 }));
    try std.testing.expectError(error.InvalidSpec, validateSchedule(.{ .kind = "a", .every_seconds = 1, .queue = "" }));
    try validateSchedule(.{ .kind = "a", .every_seconds = 60 });
}

test "the claim statement carries one clause per queue, and a limit only where there is one" {
    var jobs: Jobs = undefined;
    jobs.config = .{ .queues = &.{
        .{ .name = "mail", .limit = 2 },
        .{ .name = "media" },
        .{ .name = "reports", .limit = -1 },
    } };

    var buffer: [claim_sql_capacity]u8 = undefined;
    const sql = try jobs.claimSelectSql(&buffer);

    // One clause per queue, each testing its own queue's name. Parameter 1 is the due bound.
    try std.testing.expect(std.mem.indexOf(u8, sql, "queue = ?2") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "queue = ?4") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "queue = ?6") != null);

    // A bounded queue counts the leases it already has; an unlimited one does not, which is what keeps
    // the `-1` case from paying for a count it will ignore. `mail` and `reports` are both bounded here,
    // `media` is not, and only the two bounded ones carry a count.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, sql, "count(*)"));
    try std.testing.expect(std.mem.indexOf(u8, sql, "< ?3") != null);

    // The candidate is what the select decides; the guard that actually takes the row is the update's,
    // which the claim issues separately — see `takeCandidate`.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, sql, "state = 'available'"));
    try std.testing.expect(std.mem.indexOf(u8, sql, "ORDER BY priority DESC, run_at ASC, id ASC LIMIT 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "attempt = attempt + 1") == null);
}
