//! The jobs module's acceptance, against the built adapter.
//!
//! These are the contract's own testing requirements (`docs/modules/jobs.md`, "Testing requirements"),
//! observed from outside the module: what a caller sees, what a worker sees, and — wherever a claim is
//! about rows — what the database actually holds, read with SQL rather than through the module that
//! wrote it.
//!
//! Two differences from the durable reference's suite, both forced by the engine and both stated
//! because they change what a test *is*:
//!
//!   * **There is no second connection in most of these tests.** A `Database` owns one connection, and
//!     the memory tier is a database per handle, so the "ask the database what it stored" checks read
//!     through the same handle with explicit SQL. That still bypasses this module's decoding and its
//!     state machine, which is what the check is for.
//!   * **Where a second connection is the point, the file tier provides one.** The claim-exclusivity
//!     test opens the same database file twice and claims from both handles, so "two workers do not get
//!     the same row" is proved across connections rather than by interleaving calls on one. A true
//!     two-*process* proof needs a harness binary and a build step, which this module does not own yet;
//!     that is called out in the commit message rather than implied by a green suite.
//!
//! Every test opens its own database, so nothing here depends on what another test left behind, and the
//! file-tier test cleans up its path (and the WAL/journal siblings the engine keeps beside it).

const std = @import("std");
const data = @import("../data/root.zig");
const adapter = @import("../data/turso_adapter.zig");
const jobs_mod = @import("root.zig");
const registry = @import("registry.zig");
const retry = @import("retry.zig");
const runner_mod = @import("runner.zig");

const Jobs = jobs_mod.Jobs;
const JobId = jobs_mod.JobId;

/// Open a database, apply the schema, and hand back a `Jobs` bound to it.
///
/// `init` takes a pointer rather than returning a value on purpose: `Jobs` holds a pointer to the
/// database, so the database has to live at a stable address. A returned struct would be copied into the
/// caller's local, and the queue would be holding the address of the copy inside `init`.
const Harness = struct {
    /// The database's own allocations come from here, and are released with it.
    ///
    /// Not out of tidiness: `src/data/turso_adapter.zig` allocates a `data.Tx` for every `begin` and
    /// destroys it nowhere, so a database opened on `std.testing.allocator` fails every test that opens
    /// a transaction with a leak report about the adapter. `src/data/tests.zig` opens its databases from
    /// an arena for the same reason, which is why the leak is invisible from the data module's own
    /// suite. Everything *this* module allocates still comes from `std.testing.allocator`, so a leak
    /// here is still a failed test; the adapter's is reported in the commit rather than papered over.
    db_arena: std.heap.ArenaAllocator,
    db: data.Database,
    jobs: Jobs,
    now: i64 = 1_700_000_000_000_000,

    fn init(
        self: *Harness,
        allocator: std.mem.Allocator,
        io: std.Io,
        tier: data.Tier,
        config: jobs_mod.Config,
    ) !void {
        self.db_arena = std.heap.ArenaAllocator.init(allocator);
        errdefer self.db_arena.deinit();

        self.db = try adapter.open(self.db_arena.allocator(), io, tier);

        self.now = 1_700_000_000_000_000;
        self.jobs = Jobs.init(&self.db, io, config);
        self.jobs.useClock(jobs_mod.Clock.fixed(&self.now));
        try self.jobs.migrate();
    }

    fn deinit(self: *Harness) void {
        self.db.close();
        self.db_arena.deinit();
    }

    fn advance(self: *Harness, micros: i64) void {
        self.now += micros;
    }

    /// Rows, read with SQL: what the module stored, not what it says it stored.
    ///
    /// `tx` is the transaction the read belongs to, when one is open. The adapter's connection refuses a
    /// statement outside the transaction it is in (`error.InvalidState`), which is the binding saying
    /// what the single-connection contract means: inside a transaction, everything goes through it.
    fn scalar(self: *Harness, tx: ?*data.Tx, sql: []const u8, params: []const data.Value) !i64 {
        const Collect = struct {
            value: i64 = -1,

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (columns.len == 0) return error.Internal;

                self_.value = switch (columns[0]) {
                    .integer => |value| value,
                    .null => 0,
                    else => return error.Internal,
                };
            }
        };

        var collect = Collect{};
        try self.db.query(tx, sql, params, collect.sink());

        return collect.value;
    }

    fn text(self: *Harness, allocator: std.mem.Allocator, sql: []const u8, params: []const data.Value) ![]const u8 {
        const Collect = struct {
            allocator: std.mem.Allocator,
            value: []const u8 = &.{},

            fn sink(self_: *@This()) data.RowSink {
                return .{ .context = self_, .push = push };
            }

            fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
                const self_: *@This() = @ptrCast(@alignCast(context));
                if (columns.len == 0) return error.Internal;

                switch (columns[0]) {
                    .text => |value| self_.value = self_.allocator.dupe(u8, value) catch return error.Unavailable,
                    .null => self_.value = &.{},
                    else => return error.Internal,
                }
            }
        };

        var collect = Collect{ .allocator = allocator };
        try self.db.query(null, sql, params, collect.sink());

        return collect.value;
    }
};

// --------------------------------------------------------------------- //
// The dialect record

test "the SQLite surface this queue is built on is the one the engine actually has" {
    // The schema's header claims these five primitives exist. Each one is asserted here rather than
    // assumed, so an engine upgrade that moves one fails by name instead of the queue failing by
    // symptom — a partial unique index, an insert that ignores a duplicate key, a guarded update whose
    // `rows_affected` is the only verdict, a BLOB column that keeps its bytes, and a transaction that
    // discards its writes.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A partial unique index: uniqueness only where the key is not null.
    {
        const first = try harness.jobs.enqueue(null, .{ .kind = "k", .idempotency_key = "key-1", .payload = &.{ 1, 2 } });
        try std.testing.expect(first.inserted);
        const again = try harness.jobs.enqueue(null, .{ .kind = "k", .idempotency_key = "key-1", .payload = &.{9} });
        try std.testing.expect(!again.inserted);
        try std.testing.expectEqual(first.id, again.id);

        const unkeyed = try harness.jobs.enqueue(null, .{ .kind = "k" });
        const unkeyed_again = try harness.jobs.enqueue(null, .{ .kind = "k" });
        try std.testing.expect(unkeyed.inserted and unkeyed_again.inserted);
        try std.testing.expect(unkeyed.id != unkeyed_again.id);

        try std.testing.expectEqual(@as(i64, 3), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));
    }

    // BLOB round-trip, including bytes that are not valid UTF-8 and a zero-length payload.
    {
        const payload = [_]u8{ 0x00, 0xff, 0x80, 'x' };
        const job_id = (try harness.jobs.enqueue(null, .{ .kind = "blob", .payload = &payload })).id;
        const job = (try harness.jobs.get(arena, job_id)).?;
        try std.testing.expectEqualSlices(u8, &payload, job.payload);

        const empty = (try harness.jobs.enqueue(null, .{ .kind = "blob", .payload = &.{} })).id;
        try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.get(arena, empty)).?.payload.len);
    }

    // A transaction discards what it wrote, and the guarded update's `rows_affected` is the verdict.
    {
        var tx = try harness.db.begin(.read_write);
        _ = try harness.db.exec(tx, "INSERT INTO zurtr_jobs (queue, kind, version, payload, state, priority, attempt, max_attempts, run_at, inserted_at, updated_at) VALUES ('default', 'tx', 1, x'00', 'available', 0, 0, 1, 0, 0, 0)", &.{});
        tx.rollback();

        try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE kind = 'tx'", &.{}));
    }
}

// --------------------------------------------------------------------- //
// Enqueue

test "a job enqueued in a transaction is invisible until the commit, and gone after a rollback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Rolled back: the domain write and the job row disappear together, which is the slice's atomicity
    // contract — a job must never outlive a transaction that did not commit.
    {
        var tx = try harness.db.begin(.read_write);
        _ = try harness.jobs.enqueue(tx, .{ .kind = "invoice.send", .idempotency_key = "invoice/1/send" });
        // Read through the transaction: the row is there for the writer, and the connection would
        // refuse this read if it were issued outside it.
        try std.testing.expectEqual(@as(i64, 1), try harness.scalar(tx, "SELECT count(*) FROM zurtr_jobs", &.{}));
        tx.rollback();
    }
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // Committed: claimable, and claimable *because* the commit happened.
    {
        var tx = try harness.db.begin(.read_write);
        _ = try harness.jobs.enqueue(tx, .{ .kind = "invoice.send", .idempotency_key = "invoice/1/send" });
        try tx.commit();
    }

    const leases = try harness.jobs.claim(arena, "worker-a", 1, null);
    try std.testing.expectEqual(@as(usize, 1), leases.len);
    try std.testing.expectEqualStrings("invoice.send", leases[0].kind);
}

test "a duplicate idempotency key returns the job it already made, and makes no second row" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const spec = jobs_mod.EnqueueSpec{ .kind = "invoice.send", .idempotency_key = "invoice/42/send" };

    const first = try harness.jobs.enqueue(null, spec);
    try std.testing.expect(first.inserted);

    const again = try harness.jobs.enqueue(null, spec);
    try std.testing.expect(!again.inserted);
    try std.testing.expectEqual(first.id, again.id);
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // The key is scoped to (queue, kind): the same key in another queue, or of another action, is a
    // different job rather than a collision.
    const other_queue = try harness.jobs.enqueue(null, .{
        .kind = "invoice.send",
        .idempotency_key = "invoice/42/send",
        .queue = "mail",
    });
    try std.testing.expect(other_queue.inserted);
    try std.testing.expect(other_queue.id != first.id);

    const other_kind = try harness.jobs.enqueue(null, .{
        .kind = "invoice.archive",
        .idempotency_key = "invoice/42/send",
    });
    try std.testing.expect(other_kind.inserted);

    try std.testing.expectEqual(@as(i64, 3), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // The duplicate is the *same* job, down to its payload: the second spec is ignored, not merged.
    const job = (try harness.jobs.get(arena, first.id)).?;
    try std.testing.expectEqualStrings("invoice.send", job.kind);
    try std.testing.expectEqualStrings("available", job.state.text());
}

// --------------------------------------------------------------------- //
// Claim and lease

test "claims arrive in the contract's order, and a lease takes the row out of circulation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const low = (try harness.jobs.enqueue(null, .{ .kind = "a", .priority = 0 })).id;
    const high = (try harness.jobs.enqueue(null, .{ .kind = "b", .priority = 5 })).id;
    const later = (try harness.jobs.enqueue(null, .{ .kind = "c", .run_at = harness.now + 60_000_000 })).id;

    // Priority first, then due time: the higher-priority job comes first even though it was enqueued
    // second, and the job that is not due yet is not offered at all.
    const leases = try harness.jobs.claim(arena, "worker-a", 8, null);
    try std.testing.expectEqual(@as(usize, 2), leases.len);
    try std.testing.expectEqual(high, leases[0].job_id);
    try std.testing.expectEqual(low, leases[1].job_id);
    try std.testing.expectEqual(@as(u32, 1), leases[0].attempt);

    // Held: nothing else is claimable, not even by another worker.
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 8, null)).len);

    // Due after its `run_at` passes — and it is the only thing left, because the other two are leased.
    harness.advance(60_000_001);
    const due_leases = try harness.jobs.claim(arena, "worker-b", 8, null);
    try std.testing.expectEqual(@as(usize, 1), due_leases.len);
    try std.testing.expectEqual(later, due_leases[0].job_id);

    // The lease is visible from the raw row as well as from the claim.
    try std.testing.expectEqual(@as(i64, 3), try harness.scalar(
        null,
        "SELECT count(*) FROM zurtr_jobs WHERE state = 'leased' AND leased_by IS NOT NULL",
        &.{},
    ));
}

test "two connections over one file never claim the same job" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // The file tier is what gives a second connection: a memory database is per handle, so this is the
    // only shape in which "two workers" means two connections rather than two names for one.
    const path = "zig-cache-jobs-claim-test.db";
    const siblings = [_][]const u8{ path, "zig-cache-jobs-claim-test.db-wal", "zig-cache-jobs-claim-test.db-shm", "zig-cache-jobs-claim-test.db-journal" };
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};

    var first: Harness = undefined;
    try first.init(allocator, io, .{ .file = path }, .{});
    defer first.deinit();
    var second: Harness = undefined;
    try second.init(allocator, io, .{ .file = path }, .{});
    defer second.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_count = 12;
    var index: usize = 0;
    while (index < job_count) : (index += 1) {
        _ = try first.jobs.enqueue(null, .{ .kind = "work" });
    }

    // Both workers claim until the queue is empty, alternating. Every job is claimed exactly once
    // across the two connections, and neither connection ever sees a job the other holds.
    var seen: std.AutoHashMap(JobId, void) = .init(allocator);
    defer seen.deinit();

    var rounds: usize = 0;
    while (rounds < job_count * 2) : (rounds += 1) {
        const batch_a = try first.jobs.claim(arena, "worker-a", 1, null);
        for (batch_a) |lease| {
            const entry = try seen.getOrPut(lease.job_id);
            try std.testing.expect(!entry.found_existing);
        }

        const batch_b = try second.jobs.claim(arena, "worker-b", 1, null);
        for (batch_b) |lease| {
            const entry = try seen.getOrPut(lease.job_id);
            try std.testing.expect(!entry.found_existing);
            try std.testing.expectEqualStrings("worker-b", lease.leased_by);
        }

        if (batch_a.len == 0 and batch_b.len == 0) break;
    }

    try std.testing.expectEqual(@as(usize, job_count), seen.count());
    try std.testing.expectEqual(@as(i64, job_count), try first.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE state = 'leased'", &.{}));
}

test "a queue's limit is enforced in the claim, and -1 is unlimited" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{
        .queues = &.{
            .{ .name = "mail", .limit = 1 },
            .{ .name = "media", .limit = -1 },
        },
    });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try harness.jobs.enqueue(null, .{ .kind = "send", .queue = "mail" });
    _ = try harness.jobs.enqueue(null, .{ .kind = "send", .queue = "mail" });
    _ = try harness.jobs.enqueue(null, .{ .kind = "render", .queue = "media" });
    _ = try harness.jobs.enqueue(null, .{ .kind = "render", .queue = "media" });
    _ = try harness.jobs.enqueue(null, .{ .kind = "render", .queue = "media" });

    // One claim on `mail` fills its limit; the second claim finds only `media`, which has no limit and
    // therefore four more available across the batch.
    const leases = try harness.jobs.claim(arena, "worker-a", 8, null);
    try std.testing.expectEqual(@as(usize, 4), leases.len);

    var mail: usize = 0;
    var media: usize = 0;
    for (leases) |lease| {
        if (std.mem.eql(u8, lease.queue, "mail")) mail += 1;
        if (std.mem.eql(u8, lease.queue, "media")) media += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), mail);
    try std.testing.expectEqual(@as(usize, 3), media);

    // Held at its limit, `mail` offers nothing more even after a tick, while `media` is exhausted.
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 8, null)).len);
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE state = 'leased' AND queue = 'mail'", &.{}));
}

// --------------------------------------------------------------------- //
// Lease expiry, takeover and retries

test "an expired lease is reaped, re-claimed with the attempt bumped, and the older attempt writes nothing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .lease_ms = 1_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "work", .max_attempts = 3 })).id;

    // An attempt that takes the job and then dies: its lease expires while it is "working".
    const dead = (try harness.jobs.claim(arena, "worker-dead", 1, null))[0];
    try std.testing.expectEqual(@as(u32, 1), dead.attempt);

    // Nothing to claim while the lease lives, and nothing to reap either.
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 1, null)).len);
    try std.testing.expectEqual(@as(u64, 0), (try harness.jobs.reap(null)).released);

    harness.advance(1_000_001);

    // The reaper returns it to `available` with the reason kept: at-least-once, made visible.
    const reaped = try harness.jobs.reap(null);
    try std.testing.expectEqual(@as(u64, 1), reaped.released);
    try std.testing.expectEqualStrings(
        jobs_mod.lease_expired_reason,
        try harness.text(arena, "SELECT last_error FROM zurtr_jobs WHERE id = ?1", &.{.{ .integer = job_id }}),
    );

    // The next claim takes the same job with the attempt count showing there was a previous one: a
    // crash loop is a rising number rather than silence.
    const live = (try harness.jobs.claim(arena, "worker-live", 1, null))[0];
    try std.testing.expectEqual(job_id, live.job_id);
    try std.testing.expectEqual(@as(u32, 2), live.attempt);

    // The dead attempt wakes up and finishes. Its result must not overwrite the attempt that owns the
    // job now, and it must commit nothing at all.
    try std.testing.expectEqual(jobs_mod.Owned.not_owner, try harness.jobs.complete(null, &dead, "done by the dead one", null));
    try std.testing.expectEqual(jobs_mod.Owned.committed, try harness.jobs.complete(null, &live, "done by the live one", null));

    const job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqualStrings("done by the live one", job.result.?);
    try std.testing.expectEqual(jobs_mod.State.completed, job.state);

    // One completion, one owner: the dropped attempt left no trace beyond the attempt it consumed.
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE attempt = 2", &.{}));
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE result = 'done by the dead one'", &.{}));
}

test "a lease that expires with no attempts left fails instead of circulating forever" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .lease_ms = 1_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "work", .max_attempts = 1 })).id;
    _ = try harness.jobs.claim(arena, "worker-dead", 1, null);

    harness.advance(1_000_001);
    const reaped = try harness.jobs.reap(null);

    // The contract returns expired rows to `available`; a job that has used its only attempt would then
    // only be claimed to fail again, so it is terminal here instead.
    try std.testing.expectEqual(@as(u64, 0), reaped.released);
    try std.testing.expectEqual(@as(u64, 1), reaped.terminated);
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 1, null)).len);
    try std.testing.expectEqual(jobs_mod.State.failed, (try harness.jobs.get(arena, job_id)).?.state);
}

test "a retry backs off and becomes available later, and the last attempt fails terminally" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{
        .lease_ms = 60_000,
        .retry = retry.Policy{ .base_ms = 100, .factor = 2, .max_ms = 1_000, .jitter = .none },
    });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "work", .max_attempts = 3 })).id;

    // First failure: available again, one base delay later, with the reason kept.
    const first = (try harness.jobs.claim(arena, "worker-a", 1, null))[0];
    try std.testing.expectEqual(jobs_mod.FailOutcome.retried, try harness.jobs.fail(null, &first, "boom-1", null, 0));
    var job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.available, job.state);
    try std.testing.expectEqual(harness.now + 100 * std.time.us_per_ms, job.run_at);
    try std.testing.expectEqualStrings("boom-1", job.last_error.?);

    // Not due yet: the backoff is a real delay, not a label.
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-a", 1, null)).len);

    // Second failure: the delay doubles.
    harness.advance(100 * std.time.us_per_ms);
    const second = (try harness.jobs.claim(arena, "worker-a", 1, null))[0];
    try std.testing.expectEqual(@as(u32, 2), second.attempt);
    try std.testing.expectEqual(jobs_mod.FailOutcome.retried, try harness.jobs.fail(null, &second, "boom-2", null, 0));
    job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(harness.now + 200 * std.time.us_per_ms, job.run_at);

    // Third failure: no attempts left, so the job is terminal and the reason stays for an operator.
    harness.advance(200 * std.time.us_per_ms);
    const third = (try harness.jobs.claim(arena, "worker-a", 1, null))[0];
    try std.testing.expectEqual(@as(u32, 3), third.attempt);
    try std.testing.expectEqual(jobs_mod.FailOutcome.failed, try harness.jobs.fail(null, &third, "boom-3", null, 0));

    job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.failed, job.state);
    try std.testing.expectEqualStrings("boom-3", job.last_error.?);
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-a", 1, null)).len);

    // Failed rows are kept until cleared, which is asserted in its own test below.
    try std.testing.expectEqual(@as(u64, 1), try harness.jobs.clearFailed());
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));
}

test "completed rows age out, failed rows do not" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .retention_ms = 1_000_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const done = (try harness.jobs.enqueue(null, .{ .kind = "work" })).id;
    const dead = (try harness.jobs.enqueue(null, .{ .kind = "work", .max_attempts = 1 })).id;

    // One at a time: a batch claim would take both rows and leave nothing for the second call.
    const done_lease = (try harness.jobs.claim(arena, "worker-a", 1, null))[0];
    try std.testing.expectEqual(done, done_lease.job_id);
    _ = try harness.jobs.complete(null, &done_lease, "ok", null);

    const dead_lease = (try harness.jobs.claim(arena, "worker-a", 1, null))[0];
    try std.testing.expectEqual(dead, dead_lease.job_id);
    _ = try harness.jobs.fail(null, &dead_lease, "no", null, 0);

    // Old enough: the completed row goes, the failed one is kept for an operator to look at.
    harness.advance(2_000_000);
    const reaped = try harness.jobs.reap(null);
    try std.testing.expectEqual(@as(u64, 1), reaped.deleted);

    try std.testing.expect((try harness.jobs.get(arena, done)) == null);
    try std.testing.expect((try harness.jobs.get(arena, dead)) != null);
}

// --------------------------------------------------------------------- //
// Cancellation

test "cancelling an available job is terminal, and the job is never claimed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "work" })).id;

    try std.testing.expectEqual(jobs_mod.CancelOutcome.cancelled, try harness.jobs.cancel(null, job_id, null));
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-a", 8, null)).len);

    const job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.cancelled, job.state);
    try std.testing.expect(job.cancel_requested);

    // Cancelling again is not an error, and does not move the state back.
    try std.testing.expectEqual(jobs_mod.CancelOutcome.already_terminal, try harness.jobs.cancel(null, job_id, null));
    try std.testing.expectEqual(jobs_mod.CancelOutcome.not_found, try harness.jobs.cancel(null, job_id + 100, null));
}

test "cancelling a leased job records the request, and the worker answers it at a step boundary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // One connection, and the request is written through the job's own transaction.
    //
    // That is not a shortcut. A request from *another* connection cannot be recorded while this job
    // holds the write lock, and on a single-writer engine a running step holds it: the other writer gets
    // `Busy`, not a queued write. So what this test can prove deterministically is the path the contract
    // actually specifies — a request that is in the row is noticed at the next boundary, because the
    // boundary refreshes the snapshot and the body then reports `Cancelled` — and the cross-connection
    // case is covered where no transaction is open (a leased job between steps), in the reaper test.

    // A two-step body: it writes in step 1, checks in — which commits that step — is cancelled from
    // outside while step 2 is open, writes again, and stops at the next boundary. What survives is the
    // contract's sentence made checkable: the committed step stays, the interrupted one does not.
    const Body = struct {
        /// The worker's own handle: the body's writes go through *its* transactions, and a transaction
        /// handle is only ever valid at the database that opened it.
        var worker_jobs: ?*Jobs = null;
        var first_step_committed = false;
        var second_step_written = false;
        var reached_after_cancel = false;

        fn run(ctx: *registry.Ctx, payload: []const u8) anyerror![]const u8 {
            _ = payload;

            // Step 1: a real domain write, through the step's transaction.
            try write(ctx, 'a');

            // The boundary: the first step commits here, which is what releases the write lock — and
            // without releasing it, a request from another connection could not be recorded at all.
            try ctx.checkpoint();
            first_step_committed = true;

            // Step 2: another write, and then the cancellation is requested. Through `ctx.tx` because
            // the connection is inside this step's transaction, which is also where the runner's refresh
            // will read it from at the next boundary.
            try write(ctx, 'b');
            second_step_written = true;

            _ = try worker_jobs.?.cancel(ctx.tx, ctx.job_id, null);

            // The next boundary refreshes the snapshot (tick_ms = 0) and reports the cancellation.
            ctx.checkpoint() catch |err| return err;

            reached_after_cancel = true;

            return &.{};
        }

        fn write(ctx: *registry.Ctx, tag: u8) !void {
            _ = try worker_jobs.?.db.exec(
                ctx.tx,
                "INSERT INTO jobs_test_effects (job_id, tag) VALUES (?1, ?2)",
                &.{ .{ .integer = ctx.job_id }, .{ .text = &.{tag} } },
            );
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .tick_ms = 0, .lease_ms = 60_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `tag` names the step a row came from, so "which step survived" is a question the table answers.
    _ = try harness.db.exec(null, "CREATE TABLE IF NOT EXISTS jobs_test_effects (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, tag TEXT NOT NULL)", &.{});

    Body.worker_jobs = &harness.jobs;
    Body.first_step_committed = false;
    Body.second_step_written = false;
    Body.reached_after_cancel = false;

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "cancellable" })).id;

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "cancellable", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    const tick = try runner.tick();

    // The body committed a step, wrote in the next one, and stopped at the boundary: it did not reach
    // the line after the cancellation, and the job is cancelled rather than retried or failed.
    try std.testing.expect(Body.first_step_committed);
    try std.testing.expect(Body.second_step_written);
    try std.testing.expect(!Body.reached_after_cancel);
    try std.testing.expectEqual(@as(usize, 1), tick.cancelled);
    try std.testing.expectEqual(@as(usize, 0), tick.retried);
    try std.testing.expectEqual(@as(usize, 0), tick.failed);
    try std.testing.expectEqual(@as(usize, 0), tick.not_owner);

    const job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.cancelled, job.state);
    // `cancel_requested` is deliberately *not* asserted here: the request was written through the step
    // that the cancellation interrupted, so it rolled back with it. The terminal state is written after
    // that rollback, in a transaction of its own, which is why it is the durable part.
    try std.testing.expect(!job.cancel_requested);

    // "A cancelled job's transaction rolls back, and effects already recorded stay recorded": the step
    // that committed before the cancellation is there, the step that was interrupted is not, and the
    // cancelled state outlives both.
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(
        null,
        "SELECT count(*) FROM jobs_test_effects WHERE tag = 'a'",
        &.{},
    ));
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(
        null,
        "SELECT count(*) FROM jobs_test_effects WHERE tag = 'b'",
        &.{},
    ));
}

test "a cancelled job whose lease expires is not re-run" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .lease_ms = 1_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "work", .max_attempts = 5 })).id;
    const lease = (try harness.jobs.claim(arena, "worker-dead", 1, null))[0];

    // The worker dies holding a job that was asked to stop. Re-running it would be the opposite of the
    // request, so the expiry path finishes it rather than returning it to circulation.
    try std.testing.expectEqual(jobs_mod.CancelOutcome.requested, try harness.jobs.cancel(null, job_id, null));
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 1, null)).len);

    harness.advance(1_000_001);
    const reaped = try harness.jobs.reap(null);
    try std.testing.expectEqual(@as(u64, 1), reaped.terminated);
    try std.testing.expectEqual(@as(u64, 0), reaped.released);
    try std.testing.expectEqual(jobs_mod.State.cancelled, (try harness.jobs.get(arena, job_id)).?.state);
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.claim(arena, "worker-b", 1, null)).len);

    // The attempt that held it can no longer write anything either.
    try std.testing.expectEqual(jobs_mod.Owned.not_owner, try harness.jobs.complete(null, &lease, "too late", null));
}

// --------------------------------------------------------------------- //
// Schedules

test "a schedule fires once per tick, and a crash between enqueue and advance cannot double-fire" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .lease_ms = 60_000 });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const schedule_id = try harness.jobs.scheduleEvery(null, .{
        .kind = "sweep",
        .every_seconds = 60,
        .first_run_at = harness.now,
    });

    const first_pass = try harness.jobs.runDueSchedules(arena, "runner-a", 8);
    try std.testing.expectEqual(@as(usize, 1), first_pass.len);
    try std.testing.expect(first_pass[0].inserted);
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // The key is derived from the schedule and the tick, so a *deliberate* re-run of the same tick —
    // the crash between enqueueing and advancing, replayed — finds the job already there.
    const due = harness.now;
    const key = try std.fmt.allocPrint(arena, "schedule/{d}/{d}", .{ schedule_id, due });
    const replay = try harness.jobs.enqueue(null, .{
        .kind = "sweep",
        .run_at = due,
        .idempotency_key = key,
    });
    try std.testing.expect(!replay.inserted);
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // The advance happened with the first pass, so the next tick is a minute later and produces its own
    // job: one job per tick, not one job in total.
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.runDueSchedules(arena, "runner-a", 8)).len);
    harness.advance(60 * std.time.us_per_s + 1);

    const second_pass = try harness.jobs.runDueSchedules(arena, "runner-a", 8);
    try std.testing.expectEqual(@as(usize, 1), second_pass.len);
    try std.testing.expect(second_pass[0].inserted);
    try std.testing.expectEqual(@as(i64, 2), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));

    // A schedule that is not enabled fires nothing, and turning it back on does not resurrect the tick
    // it missed.
    try std.testing.expect(try harness.jobs.setScheduleEnabled(schedule_id, false));
    harness.advance(600 * std.time.us_per_s);
    try std.testing.expectEqual(@as(usize, 0), (try harness.jobs.runDueSchedules(arena, "runner-a", 8)).len);
    try std.testing.expect(try harness.jobs.setScheduleEnabled(schedule_id, true));
    try std.testing.expectEqual(@as(usize, 1), (try harness.jobs.runDueSchedules(arena, "runner-a", 8)).len);
}

test "one tick belongs to one runner, even when another is looking at it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Two connections over one file, both with a runner: the claim on a schedule is a guarded update, so
    // only one of them advances a given tick.
    const path = "zig-cache-jobs-schedule-test.db";
    const siblings = [_][]const u8{ path, "zig-cache-jobs-schedule-test.db-wal", "zig-cache-jobs-schedule-test.db-shm", "zig-cache-jobs-schedule-test.db-journal" };
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};

    var first: Harness = undefined;
    try first.init(allocator, io, .{ .file = path }, .{ .lease_ms = 60_000 });
    defer first.deinit();
    var second: Harness = undefined;
    try second.init(allocator, io, .{ .file = path }, .{ .lease_ms = 60_000 });
    defer second.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try first.jobs.scheduleEvery(null, .{ .kind = "sweep", .every_seconds = 60, .first_run_at = first.now });

    const batch_a = try first.jobs.runDueSchedules(arena, "runner-a", 8);
    const batch_b = try second.jobs.runDueSchedules(arena, "runner-b", 8);

    try std.testing.expectEqual(@as(usize, 1), batch_a.len);
    try std.testing.expectEqual(@as(usize, 0), batch_b.len);
    try std.testing.expectEqual(@as(i64, 1), try first.scalar(null, "SELECT count(*) FROM zurtr_jobs", &.{}));
}

// --------------------------------------------------------------------- //
// The runner

test "a registered body runs, and its effects commit with the job's completion" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        var calls: usize = 0;

        fn run(ctx: *registry.Ctx, payload: []const u8) anyerror![]const u8 {
            calls += 1;
            // The principal is the queue's system identity, never a user: an action that needs one
            // carries it in its input.
            try std.testing.expectEqualStrings("system.jobs:default", ctx.principal);
            try std.testing.expect(ctx.tx != null);

            return payload;
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try harness.db.exec(null, "CREATE TABLE IF NOT EXISTS jobs_test_effects (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL)", &.{});

    Body.calls = 0;

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "echo", .payload = "payload-1" })).id;

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    const tick = try runner.tick();
    try std.testing.expectEqual(@as(usize, 1), tick.claimed);
    try std.testing.expectEqual(@as(usize, 1), tick.completed);
    try std.testing.expectEqual(@as(usize, 1), Body.calls);

    const job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.completed, job.state);
    // The body's return value is the row's result summary, which is what the contract keeps there.
    try std.testing.expectEqualStrings("payload-1", job.result.?);

    // Nothing left to claim, and an idle pass says so.
    const idle = try runner.tick();
    try std.testing.expect(idle.idle);
    try std.testing.expectEqual(@as(usize, 0), idle.claimed);
}

test "a body that fails leaves no effects, and its job retries and then fails" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        var jobs: ?*Jobs = null;
        var calls: usize = 0;

        fn run(ctx: *registry.Ctx, payload: []const u8) anyerror![]const u8 {
            _ = payload;
            calls += 1;
            // A domain write that must not survive the failure.
            _ = try jobs.?.db.exec(ctx.tx, "INSERT INTO jobs_test_effects (job_id) VALUES (?1)", &.{
                .{ .integer = ctx.job_id },
            });

            return error.WorkFailed;
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{
        .tick_ms = 0,
        .retry = retry.Policy{ .base_ms = 0, .factor = 2, .max_ms = 0, .jitter = .none },
    });
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try harness.db.exec(null, "CREATE TABLE IF NOT EXISTS jobs_test_effects (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL)", &.{});

    Body.jobs = &harness.jobs;
    Body.calls = 0;

    const job_id = (try harness.jobs.enqueue(null, .{ .kind = "flaky", .max_attempts = 2 })).id;

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "flaky", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    // First pass: the body fails, the job goes back to available, and nothing it wrote survives.
    const first = try runner.tick();
    try std.testing.expectEqual(@as(usize, 1), first.retried);
    try std.testing.expectEqual(@as(usize, 0), first.failed);
    try std.testing.expectEqual(jobs_mod.State.available, (try harness.jobs.get(arena, job_id)).?.state);
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM jobs_test_effects", &.{}));

    // Second pass: no attempts left, so it is terminal, and the reason is the body's error name.
    const second = try runner.tick();
    try std.testing.expectEqual(@as(usize, 1), second.failed);

    const job = (try harness.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.failed, job.state);
    try std.testing.expectEqualStrings("WorkFailed", job.last_error.?);
    try std.testing.expectEqual(@as(i64, 0), try harness.scalar(null, "SELECT count(*) FROM jobs_test_effects", &.{}));
    try std.testing.expectEqual(@as(usize, 2), Body.calls);
}

test "a job whose kind this deployment cannot run fails without the body ever being invoked" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        var calls: usize = 0;

        fn run(_: *registry.Ctx, _: []const u8) anyerror![]const u8 {
            calls += 1;

            return &.{};
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    Body.calls = 0;

    // One job of a kind that is registered at another version, one of a kind that is not registered at
    // all. Neither may be decoded as if it were the running action.
    const wrong_version = (try harness.jobs.enqueue(null, .{ .kind = "echo", .version = 2 })).id;
    const unknown = (try harness.jobs.enqueue(null, .{ .kind = "never.deployed" })).id;

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    const tick = try runner.tick();
    try std.testing.expectEqual(@as(usize, 2), tick.unknown);
    try std.testing.expectEqual(@as(usize, 0), tick.failed);
    try std.testing.expectEqual(@as(usize, 0), Body.calls);

    for ([_]JobId{ wrong_version, unknown }) |job_id| {
        const job = (try harness.jobs.get(arena, job_id)).?;
        try std.testing.expectEqual(jobs_mod.State.failed, job.state);
        try std.testing.expect(std.mem.indexOf(u8, job.last_error.?, "not runnable here") != null);
    }

    // The startup sweep finds both before the queue does, which is what makes an unknown kind a failed
    // boot rather than a job that fails at 3am.
    try std.testing.expectError(error.UnsupportedVersion, harness.jobs.checkRegistry(allocator, registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
    })));
}

test "the startup sweep accepts a registry that covers every kind the table holds" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        fn run(_: *registry.Ctx, _: []const u8) anyerror![]const u8 {
            return &.{};
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    _ = try harness.jobs.enqueue(null, .{ .kind = "echo", .version = 1 });
    _ = try harness.jobs.enqueue(null, .{ .kind = "echo", .version = 1 });
    _ = try harness.jobs.enqueue(null, .{ .kind = "sweep", .version = 3 });
    _ = try harness.jobs.enqueue(null, .{ .kind = "sweep", .version = 3 });

    const full = registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
        .{ .kind = "sweep", .version = 3, .run = Body.run },
    });
    try harness.jobs.checkRegistry(allocator, full);

    try std.testing.expectError(error.UnknownKind, harness.jobs.checkRegistry(allocator, registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
    })));

    // A registry that cannot answer unambiguously is refused here rather than deciding a lookup by
    // declaration order.
    try std.testing.expectError(error.DuplicateKind, harness.jobs.checkRegistry(allocator, registry.Registry.init(&.{
        .{ .kind = "echo", .version = 1, .run = Body.run },
        .{ .kind = "echo", .version = 1, .run = Body.run },
    })));
}

test "a batch is claimed in one pass and every job in it runs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        var seen: std.ArrayList(JobId) = .empty;

        fn run(ctx: *registry.Ctx, _: []const u8) anyerror![]const u8 {
            try seen.append(std.testing.allocator, ctx.job_id);

            return "ok";
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{ .batch = 3 });
    defer harness.deinit();

    Body.seen = .empty;
    defer Body.seen.deinit(allocator);

    var index: usize = 0;
    while (index < 7) : (index += 1) {
        _ = try harness.jobs.enqueue(null, .{ .kind = "work" });
    }

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "work", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    // The batch bound is a bound: three per pass, then three, then one, then idle.
    var completed: usize = 0;
    var passes: usize = 0;
    while (passes < 10) : (passes += 1) {
        const tick = try runner.tick();
        completed += tick.completed;
        if (tick.idle) break;
    }

    try std.testing.expectEqual(@as(usize, 7), completed);
    try std.testing.expectEqual(@as(usize, 7), Body.seen.items.len);
    try std.testing.expectEqual(@as(i64, 7), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE state = 'completed'", &.{}));
}

test "a stopping runner does no work and returns from its loop" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Body = struct {
        fn run(_: *registry.Ctx, _: []const u8) anyerror![]const u8 {
            return &.{};
        }
    };

    var harness: Harness = undefined;
    try harness.init(allocator, io, .{ .memory = {} }, .{});
    defer harness.deinit();

    _ = try harness.jobs.enqueue(null, .{ .kind = "work" });

    var runner = runner_mod.Runner.init(allocator, &harness.jobs, registry.Registry.init(&.{
        .{ .kind = "work", .version = 1, .run = Body.run },
    }), "worker-a");
    defer runner.deinit();

    runner.stop();
    // A stopped loop returns rather than blocking on its poll, and leaves the row alone.
    try runner.run();
    try std.testing.expectEqual(@as(i64, 1), try harness.scalar(null, "SELECT count(*) FROM zurtr_jobs WHERE state = 'available'", &.{}));
}

// --------------------------------------------------------------------- //
// Durability

test "a queue survives the process that wrote it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const path = "zig-cache-jobs-durable-test.db";
    const siblings = [_][]const u8{ path, "zig-cache-jobs-durable-test.db-wal", "zig-cache-jobs-durable-test.db-shm", "zig-cache-jobs-durable-test.db-journal" };
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var job_id: JobId = 0;
    {
        var first: Harness = undefined;
        try first.init(allocator, io, .{ .file = path }, .{ .lease_ms = 60_000 });
        defer first.deinit();

        job_id = (try first.jobs.enqueue(null, .{ .kind = "work", .idempotency_key = "durable/1" })).id;
        const jobs = try first.jobs.claim(arena, "worker-a", 1, null);
        try std.testing.expectEqual(@as(usize, 1), jobs.len);
    }

    // Reopened: the row is still there, still leased by the worker that took it, and still at the
    // attempt that worker claimed it at — which is what an owner-only write is guarded on.
    var second: Harness = undefined;
    try second.init(allocator, io, .{ .file = path }, .{ .lease_ms = 60_000 });
    defer second.deinit();

    const job = (try second.jobs.get(arena, job_id)).?;
    try std.testing.expectEqual(jobs_mod.State.leased, job.state);
    try std.testing.expectEqualStrings("worker-a", job.leased_by.?);
    try std.testing.expectEqual(@as(u32, 1), job.attempt);

    // And the duplicate key still resolves to the same job across a restart, which is the property a
    // caller actually depends on.
    const replay = try second.jobs.enqueue(null, .{ .kind = "work", .idempotency_key = "durable/1" });
    try std.testing.expect(!replay.inserted);
    try std.testing.expectEqual(job_id, replay.id);
}
