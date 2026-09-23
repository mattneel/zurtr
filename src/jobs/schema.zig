//! The queue's storage, in the dialect the built adapter actually speaks.
//!
//! # Which SQL surface this is written against
//!
//! The module contract (`docs/modules/jobs.md`) states its model in PostgreSQL — `bigserial`,
//! `timestamptz`, `bytea`, `FOR UPDATE SKIP LOCKED`, `LISTEN`/`NOTIFY`. None of that exists in the
//! adapter that is built (`src/data/turso_adapter.zig`, SQLite-compatible), and PostgreSQL is a
//! *declared* module with no implementation. So the model is kept and the dialect is replaced:
//!
//! | Contract (PostgreSQL) | Here (SQLite via Turso) |
//! | :- | :- |
//! | `bigserial primary key` | `INTEGER PRIMARY KEY AUTOINCREMENT` |
//! | `timestamptz` | integer **microseconds** since the epoch, the adapter's `timestamp_micros` mapping, which crosses the boundary as `INTEGER` |
//! | `bytea` | `BLOB`, written and read as the adapter's `bytes` value |
//! | `state='leased' ... FOR UPDATE SKIP LOCKED` | a select-then-update inside one write transaction: the candidate is read with the claim's predicate, then taken by an `UPDATE` whose `WHERE` is the whole guard (`state='available'`, `run_at` due, queue limits) and whose `rows_affected` is the verdict. One writer per database, with `BEGIN IMMEDIATE` on every read-write transaction, is what removes the race `SKIP LOCKED` wins |
//! | `LISTEN`/`NOTIFY` wakeup | polling at `poll_interval_ms`, which the contract already specifies as the fallback, plus an in-process signal so a same-process enqueue is picked up at once. Nothing wakes a *different* process; a runner in its own role process learns about new work on its next poll |
//! | `pg_notify` inside the transaction | nothing. The durable path for announcing a state change is the outbox (`docs/modules/live.md`), which is the `live` module's, not the queue's |
//!
//! The same set of differences is asserted against the real engine rather than assumed: `tests.zig`
//! opens a database and exercises each primitive named above — the partial unique index, the
//! `INSERT OR IGNORE` that makes a duplicate key return the existing row, the guarded `UPDATE` whose
//! `rows_affected` is the only thing that says a claim was won, BLOB round-tripping, and a
//! write transaction that rolls back. When a Turso upgrade moves one of those, that test fails by
//! name instead of the queue failing by symptom.
//!
//! # Applying the schema
//!
//! Every statement is `IF NOT EXISTS`, so applying it is idempotent and startup is the only migration
//! step this module needs — the same shape the adapter uses for `zurtr_write_lease` and the durable
//! reference uses for its slice. The statements are also exported as `statements` so an application
//! that owns its migrations can fold them into its own ordered list once `data` grows the migration
//! runner its contract describes (there is no migration API in `src/data/root.zig` yet).

const std = @import("std");
const data = @import("../data/root.zig");

pub const jobs_table = "zurtr_jobs";
pub const schedules_table = "zurtr_schedules";

/// What `zurtr_jobs.state` may hold. Kept as text on purpose: the contract writes the state names out
/// and a row that a human is looking at should say `available` rather than `0`.
pub const states = [_][]const u8{ "available", "leased", "completed", "failed", "cancelled" };

pub const statements = [_][]const u8{
    // The queue. `attempt` counts claims, not failures: the claim bumps it so a worker that dies
    // mid-job still consumed an attempt and a crash loop is visible as a number.
    \\CREATE TABLE IF NOT EXISTS zurtr_jobs (
    \\  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  queue              TEXT    NOT NULL DEFAULT 'default',
    \\  kind               TEXT    NOT NULL,
    \\  version            INTEGER NOT NULL,
    \\  payload            BLOB    NOT NULL,
    \\  idempotency_key    TEXT,
    \\  state              TEXT    NOT NULL,
    \\  priority           INTEGER NOT NULL DEFAULT 0,
    \\  attempt            INTEGER NOT NULL DEFAULT 0,
    \\  max_attempts       INTEGER NOT NULL,
    \\  run_at      INTEGER NOT NULL,
    \\  lease_until INTEGER,
    \\  leased_by          TEXT,
    \\  cancel_requested   INTEGER NOT NULL DEFAULT 0,
    \\  result             TEXT,
    \\  last_error         TEXT,
    \\  inserted_at INTEGER NOT NULL,
    \\  updated_at  INTEGER NOT NULL
    \\)
    ,
    // "At most one job per (queue, kind, key)": the caller's idempotency contract, enforced by the
    // database rather than by a read-then-write that two processes can both pass.
    \\CREATE UNIQUE INDEX IF NOT EXISTS zurtr_jobs_idempotency
    \\  ON zurtr_jobs (queue, kind, idempotency_key) WHERE idempotency_key IS NOT NULL
    ,
    // The claim's own scan: ready rows, in the order the contract specifies.
    \\CREATE INDEX IF NOT EXISTS zurtr_jobs_ready
    \\  ON zurtr_jobs (queue, priority DESC, run_at) WHERE state = 'available'
    ,
    // The reaper's scan, and the per-queue concurrency count.
    \\CREATE INDEX IF NOT EXISTS zurtr_jobs_leased
    \\  ON zurtr_jobs (state, lease_until)
    ,
    \\CREATE INDEX IF NOT EXISTS zurtr_jobs_queue_state
    \\  ON zurtr_jobs (queue, state)
    ,
    // The cancel snapshot refresh, which finds only rows that asked for it.
    \\CREATE INDEX IF NOT EXISTS zurtr_jobs_cancel_requested
    \\  ON zurtr_jobs (state) WHERE cancel_requested = 1
    ,
    // The startup sweep: which kinds and versions the table actually holds.
    \\CREATE INDEX IF NOT EXISTS zurtr_jobs_kind
    \\  ON zurtr_jobs (kind, version)
    ,
    // Recurring schedules. `lease_until`/`claimed_by` are this module's addition to the
    // contract's column list: the deterministic idempotency key already makes a double-fire harmless
    // to the queue, but two runner processes advancing one schedule's `next_run` at the same time
    // would skip a tick, so a tick is claimed like a job is.
    \\CREATE TABLE IF NOT EXISTS zurtr_schedules (
    \\  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  kind               TEXT    NOT NULL,
    \\  version            INTEGER NOT NULL,
    \\  payload            BLOB    NOT NULL,
    \\  queue              TEXT    NOT NULL DEFAULT 'default',
    \\  priority           INTEGER NOT NULL DEFAULT 0,
    \\  max_attempts       INTEGER NOT NULL,
    \\  every_seconds      INTEGER NOT NULL,
    \\  next_run_at    INTEGER NOT NULL,
    \\  last_run_at    INTEGER,
    \\  enabled            INTEGER NOT NULL DEFAULT 1,
    \\  lease_until INTEGER,
    \\  claimed_by         TEXT,
    \\  inserted_at INTEGER NOT NULL,
    \\  updated_at  INTEGER NOT NULL
    \\)
    ,
    \\CREATE INDEX IF NOT EXISTS zurtr_schedules_due
    \\  ON zurtr_schedules (next_run_at) WHERE enabled = 1
    ,
};

/// Apply every statement. Idempotent, so it is safe on every start and in every test.
pub fn apply(db: *data.Database) data.Error!void {
    for (statements) |statement| {
        _ = try db.exec(null, statement, &.{});
    }
}

/// Drop everything this module owns, so a test or a demo run starts from a known state. Not part of
/// `apply`: nothing in a running deployment should be able to call this by accident.
pub fn truncate(db: *data.Database) data.Error!void {
    _ = try db.exec(null, "DELETE FROM zurtr_jobs", &.{});
    _ = try db.exec(null, "DELETE FROM zurtr_schedules", &.{});
}

test "the state vocabulary is the contract's, in the order it writes it" {
    try std.testing.expectEqualSlices(u8, "available", states[0]);
    try std.testing.expectEqualSlices(u8, "cancelled", states[4]);
}
