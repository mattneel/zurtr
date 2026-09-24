# Module contract: Jobs (`zurtr.jobs`)

Scope: durable queues, schedules, retries, concurrency, cancellation. Delivery
is at-least-once; idempotency is the caller's contract (`contracts.md` §5).

Status: **implemented** (`src/jobs/`: `root.zig`, `runner.zig`, `registry.zig`,
`retry.zig`, `cancel.zig`, `schema.zig`). The inventory of record is
`src/root.zig`'s `modules` table, which `zurtr modules` prints; this document is
the contract the module is held to, and the sections below are its design.

## What the adapter forces

The model is stored in the dialect of the adapter that exists: Turso, which is
SQLite-compatible (`src/data/turso_adapter.zig`), opened at one of four tiers
with a single writer per database (`docs/modules/data.md`). PostgreSQL remains a
declared adapter, unbuilt (`decisions.md` D5), so the PostgreSQL primitives this
contract was first written in are *replaced* rather than emulated. That table is
the header of `src/jobs/schema.zig`, and `src/jobs/tests.zig` asserts each entry
against the real engine by name rather than assuming it.

Three of the substitutions are load-bearing, and each is a decision a reader
should be able to find in the code:

- **A claim is a select-then-update inside one write transaction**
  (`Jobs.claim` → `candidateLease` → `takeCandidate`). `SKIP LOCKED` exists to
  stop two claimers interleaving between a select and an update; this engine
  excludes that differently — one writer per database, with every read-write
  transaction opened `BEGIN IMMEDIATE` — so the two statements cannot interleave
  and `rows_affected` from the `UPDATE` is the only thing that says the claim was
  won.
- **`attempt` is the ownership token**, so there is no token column. Every claim
  bumps it, and every write only an owner may make is guarded on
  `state = 'leased' AND attempt = ?` *in the same statement as the write it
  guards* (`heartbeat`, `complete`, `fail`, `finishCancelled`, `failTerminal`). A
  worker whose lease expired and was taken over therefore affects zero rows and
  is told so — `Owned.not_owner` / `FailOutcome.not_owner`, a value and not an
  error — rather than overwriting the attempt that took over.
- **`Conflict` means "someone else is writing", not "the operation failed".**
  The adapter sets no busy timeout, so a second writer gets `Conflict` from
  `begin`; for a claim, a reap or a schedule pass that is "look again next pass",
  and `claim` answers `&.{}`, `Runner.tick` treats it as an empty reap, and
  `runDueSchedules` ends its pass with the ticks it already committed. A queue
  that errored whenever another worker was mid-write would be useless.

## Durable model (Turso / SQLite)

`src/jobs/schema.zig`'s `statements` is the source of truth (exported as
`zurtr.jobs.storage`); the shape:

```sql
create table zurtr_jobs (
  id               integer primary key autoincrement,
  queue            text    not null default 'default',
  kind             text    not null,          -- action id
  version          integer not null,          -- action version at insert
  payload          blob    not null,          -- serialized Input; opaque here
  idempotency_key  text,
  state            text    not null,          -- available|leased|completed|failed|cancelled
  priority         integer not null default 0,
  attempt          integer not null default 0,
  max_attempts     integer not null,
  run_at           integer not null,          -- microseconds since the epoch, UTC
  lease_until      integer,                   -- microseconds; null while not leased
  leased_by        text,
  cancel_requested integer not null default 0,
  result           text,                      -- summary only; large results go to app tables
  last_error       text,
  inserted_at      integer not null,
  updated_at       integer not null
);
create unique index zurtr_jobs_idempotency
  on zurtr_jobs (queue, kind, idempotency_key) where idempotency_key is not null;
create index zurtr_jobs_ready
  on zurtr_jobs (queue, priority desc, run_at) where state = 'available';
```

Four more indexes exist because the queries do: `zurtr_jobs_leased`
(`state, lease_until` — the reaper), `zurtr_jobs_queue_state` (the per-queue
concurrency count), `zurtr_jobs_cancel_requested` (`state`, partial on
`cancel_requested = 1` — the cancel snapshot), and `zurtr_jobs_kind`
(`kind, version` — the startup sweep). The schedules table carries its own
`zurtr_schedules_due` (`next_run_at`, partial on `enabled = 1`).

Instants are integer microseconds since the epoch, UTC — the same encoding the
data contract's `Value.timestamp_micros` carries, because SQLite has no date
type. Every timestamp is written by this module, not by a database function.
`state` is text on purpose: a row a human is looking at should say `available`
rather than `0`. Any other value in the column is refused by `State.parse` as
`error.Internal` — a state this vocabulary does not know is not something to
guess about.

`payload` is the action's `Input`, already serialized: this module never encodes
or decodes it, because the codec is the application's (see "Action binding").
`version` is checked against the running action — an unsupported version fails
the job terminally with a diagnostic, never runs the wrong code.

Schedules live beside it in `zurtr_schedules` (kind, version, payload, queue,
priority, max_attempts, `every_seconds`, `next_run_at`, `last_run_at`, `enabled`,
and `lease_until`/`claimed_by`, which are this module's addition to the
contract's column list — see "Schedules").

## Enqueue

```zig
pub fn enqueue(self: *Jobs, tx: ?*data.Tx, spec: EnqueueSpec) Error!EnqueueOutcome;

// EnqueueSpec = .{ .kind = "invoice.send", .version = 1,
//                  .payload = <the action's Input, already serialized>,
//                  .queue = "default", .priority = 0, .run_at = null,
//                  .max_attempts = 5, .idempotency_key = "invoice/42/send" }
// EnqueueOutcome = .{ .id = <JobId>, .inserted = <bool> }
```

- With a `tx`, the row is written through the same transaction as the domain
  write (the slice's atomicity contract). Without one, it is written in its own
  short transaction and this process's runner is woken *after* the commit — a
  waiter woken by a row it cannot see yet would claim nothing and go back to
  sleep for a poll interval. With a caller's `tx` there is no wake: the commit is
  the caller's, so the caller calls `wake()` itself if it wants the same
  treatment.
- Duplicate `idempotency_key` is not an error: the row is inserted with
  `INSERT OR IGNORE` against the partial unique index, and when that affects no
  rows `enqueue` returns the job that already holds the key with
  `inserted = false`. Two concurrent enqueues resolve in the store, not in the
  runner. The key's uniqueness is scoped to `(queue, kind)`: the same key on a
  different queue or kind is a different job.
- `run_at = null` means "now"; `max_attempts` counts the first attempt and must
  be at least 1. A spec that cannot describe a job (empty kind, empty queue, zero
  attempts, an empty key, a non-positive period) is `error.InvalidSpec` before
  any statement runs.
- There is no notification to issue: the row becomes claimable when the
  transaction commits, and the poller finds it (`decisions.md` D5). What must
  reach a live session is published through the outbox in the same transaction,
  never through the queue.

## Claim / lease / retry

- **Claim.** `Jobs.claim` reads one candidate with the claim's own predicate
  (`claimSelectSql`) and takes it with an `UPDATE` whose `WHERE` repeats the
  whole guard — available, due, in a queue this worker serves, under that
  queue's limit, and `attempt` unchanged — and whose `rows_affected` decides the
  winner (`takeCandidate`). The guard is repeated even though the candidate was
  selected with it, because the `UPDATE`, not the select, is what decides. A
  claim that finds nothing is a cheap indexed lookup against
  `zurtr_jobs_ready`; `batch` bounds how many one pass takes (default 8), so a
  large backlog cannot starve the reaper.
- **`-1` is unlimited.** A queue's concurrency limit is enforced in the select,
  inside the same transaction that takes the lease: a bounded queue's clause
  counts `state = 'leased'` rows for that queue with a subquery and refuses to
  select past the limit. `QueueLimit.unlimited()` is `limit < 0`, so the
  contract's `-1` and any other negative number mean the same thing and an
  unlimited queue pays for no count. `Config.queues` is the list this worker
  serves; the statement is generated per configuration and refused with
  `error.InvalidSpec` (never truncated) if the queue list outgrows
  `claim_sql_capacity`.
- **Heartbeat** extends `lease_until` to `now + lease_ms` every `lease/3`
  (`Config.heartbeatMs`, floored at 1 ms) while a job runs; the guard is the
  attempt, so `false` means this attempt no longer owns the row — stop, rather
  than keep working. The runner issues it from the job's own step boundary
  (`Runner.StepContext`), rate-limited by time.
- **Reaper.** `Jobs.reap` runs in the same loop, on `tick_ms`:
  an expired lease with attempts left goes back to `available` with
  `lease expired` kept as `last_error`; an expired lease that had asked for
  cancellation is `cancelled`; an expired lease with no attempts left is
  `failed`. The contract's sentence returns expired rows to `available`; a job
  whose attempts are exhausted could then only be claimed in order to fail
  again, which would make bounded attempts bounded in name only, and re-running
  cancelled work is the opposite of the request that stopped it. `attempt` was
  already bumped by the claim that expired, so a crash loop is still a rising
  number.
- **Retry** is `retry.Policy`, a pure function of `(attempt, max_attempts,
  draw)`: `retries` is `attempt < max_attempts`, and the delay is the exponential
  ceiling (`base_ms` 1 s, factor 2, capped by `max_ms` 300 s) with full jitter —
  a uniform draw in `[0, ceiling]`, drawn by the runner and passed in, so the
  policy stays testable and a fleet that failed together does not retry
  together. Attempts remaining means `available` at `now + delay`; no attempts
  remaining means `failed` with `last_error` retained. The routing is decided
  inside the guarded statements rather than by reading the row first, so a
  cancellation recorded between a read and a write cannot be missed.
- **A row that asked for cancellation does not retry** — "stop" is the request,
  and re-running is its opposite. `fail` therefore has three outcomes beyond
  `not_owner`: retried, failed, cancelled.
- **Retention.** `completed` rows are deleted by the reaper once
  `updated_at <= now - retention_ms` (default 7 days); `failed` rows are kept
  until an operator clears them — `Jobs.clearFailed` is that, and nothing else
  deletes them.

## Waiting and latency

- The runner polls for due work every `poll_interval_ms` (default 1 s) and
  claims inside a write transaction. There is no `LISTEN` to be woken by: the
  storage has no notification channel (`decisions.md` D4/D5).
- The in-process path is a condition variable: `enqueue` with no transaction and
  a completed schedule pass call `wake()`, and `Runner.run` waits in
  `waitForWork` for a wake or `poll_interval_ms`, whichever comes first. It is a
  hint, not a handoff — missing it costs one poll — and it is a no-op for a
  runner in another process, which has only the poll.
- Latency is therefore bounded by `poll_interval_ms`, and a deployment that wants
  less configures it down; the durable path for a *user-visible* result is the
  outbox, which the application writes when the job completes.
- The same loop processes heartbeats and the reaper: `Runner.tick` does the
  periodic work when `tick_ms` is due, then claims up to `batch` jobs. There are
  no separate threads, and the adapter allows none — a `Database` owns one
  connection and one transaction at a time, which is why a long job body defers
  the tick's work to the body's own step boundaries.

## Schedules

```zig
pub fn scheduleEvery(self: *Jobs, tx: ?*data.Tx, spec: ScheduleSpec) Error!ScheduleId;
pub fn setScheduleEnabled(self: *Jobs, id: ScheduleId, enabled: bool) Error!bool;

// ScheduleSpec = .{ .kind = ..., .version = 1, .payload = ..., .queue = "default",
//                   .priority = 0, .max_attempts = 5, .every_seconds = 60,
//                   .first_run_at = null, .enabled = true }
```

- A schedule claims its tick like a job claims a row: `runDueSchedules` reads the
  due row, takes it with a guarded `UPDATE` on `(id, next_run_at, lease_until)`,
  and enqueues the tick and advances `next_run_at` **in that same transaction**,
  so a crash between the two cannot double-fire. The deterministic idempotency
  key `schedule/<id>/<next_run_at>` is the second line of defence: a tick
  processed twice returns the first job rather than making another.
- Ticks that elapsed while the schedule was not being run are **skipped**, not
  replayed: the next tick is the first boundary after `now`. Catching up would
  turn a ten-minute outage of a one-minute schedule into ten jobs waiting to run
  — a stampede wearing a durability argument. An application that must not skip a
  period has one-shot `enqueue` with `run_at`, and `last_run_at` tells it how far
  behind it fell.
- One-shot delayed work is just `enqueue` with `run_at`.

## Cancellation

- `Jobs.cancel(tx, job_id, now)` answers with a `CancelOutcome`:
  `cancelled` (the job was `available` and is terminal now — nothing is running,
  so there is nothing to interrupt), `requested` (the job is `leased`; the
  request is recorded and the running attempt observes it at its next step
  boundary), `already_terminal`, or `not_found`.
- The request is the row's `cancel_requested`, and the running job learns about
  it from a per-worker snapshot rather than from a query per check:
  `Jobs.cancelledIds` selects the ids that asked and are still leased once per
  reap tick, `cancel.Set` holds them sorted and deduplicated, and
  `Ctx.cancelled()` is a binary search over that snapshot (`cancel.View.has`).
  A job body observes it at `Ctx.checkpoint()`, which is also where the lease is
  renewed and the step commits — the cooperative contract in full: a body that
  never checks in cannot be cancelled, cannot keep a lease, and gets no
  durability for the work it has done.
- A cancelled job's step transaction rolls back and the `cancelled` state is
  written in a transaction of its own, which is what makes the state change
  outlive the rollback. Steps already committed stay committed
  (`Runner.runOne`, `error.Cancelled`).

## Action binding (`registry.zig`)

Jobs are a surface for domain actions: `kind` is the action id, `payload` its
`Input`, and the runner invokes the registered binding with a `registry.Ctx`
whose `principal` is `system.jobs:<queue>` (an action that needs a real one
carries it in its `Input` explicitly, so the authority a job runs with is visible
in the row rather than implied by the queue it came from) and whose `tx` is the
**current step's** transaction, not the job's — the runner replaces it at every
boundary.

- The application owns the codec. `Binding.run` is
  `fn (ctx: *Ctx, payload: []const u8) anyerror![]const u8` and whatever it
  returns is stored in `result`, which the contract keeps as a summary on
  purpose. This module never decodes `Input`.
- `Registry.resolve` tells the two failures apart: a kind this process has never
  heard of is `UnknownKind`, a kind it knows at another version is
  `UnsupportedVersion`. The runner fails such a row terminally
  (`failTerminal`) without ever invoking a body.
- `Jobs.checkRegistry` is the startup sweep the contract asks for:
  `Registry.validate` rejects a duplicate `(kind, version)` binding — a lookup
  that depends on declaration order is a deployment bug — and every `(kind,
  version)` the table already holds must resolve, so an unknown kind is a failed
  boot rather than a job that fails at 3am.

## Role process

**Not implemented.** `src/main.zig` ships two commands — `modules` and `new` —
and says so: `run --role=web|jobs|agents`, `migrate` and `test` arrive with the
modules they drive. What exists today is `Runner`, which runs the loop in
whatever process builds it; separating the web role from the jobs role is a
deployment step nothing in the tree performs yet.

## Testing requirements

`src/jobs/root.zig`'s test block compiles `tests.zig` only when the adapter is
built (`if (comptime @import("build_options").turso) _ = @import("tests.zig");`),
and that gate is the point: **a database-backed test must not run without a
database, and must not be compiled with no binding to link.** Everything else in
the module is a unit test — `JobState`, lease arithmetic, the generated claim
statement, retry timing, the cancel snapshot, registry lookup — and none of it
opens a database. Measured on this tree, `zig build test-zurtr` is 83 tests
without `-Dturso` (82 pass, 1 skip in `src/runtime/task.zig`); `-Dturso=true`
adds exactly `tests.zig`'s 22, and no test outside that file touches the adapter.

The requirements are discharged by name:

- Enqueue-in-transaction: rollback of the domain tx leaves no job row, commit
  makes it claimable — "a job enqueued in a transaction is invisible until the
  commit, and gone after a rollback".
- The SQLite surface is real, not assumed — "the SQLite surface this queue is
  built on is the one the engine actually has".
- Claim exclusivity: two connections over one file never claim the same job
  ("two connections over one file never claim the same job"), and claim order is
  the contract's ("claims arrive in the contract's order, and a lease takes the
  row out of circulation").
- Queue limits: "a queue's limit is enforced in the claim, and -1 is unlimited".
- Lease expiry: "an expired lease is reaped, re-claimed with the attempt bumped,
  and the older attempt writes nothing" (at-least-once proven, not asserted) and
  "a lease that expires with no attempts left fails instead of circulating
  forever".
- Retry/backoff: "a retry backs off and becomes available later, and the last
  attempt fails terminally"; "completed rows age out, failed rows do not".
- Idempotency: "a duplicate idempotency key returns the job it already made, and
  makes no second row".
- Cancellation: "cancelling an available job is terminal, and the job is never
  claimed"; "cancelling a leased job records the request, and the worker answers
  it at a step boundary"; "a cancelled job whose lease expires is not re-run".
- Schedule: "a schedule fires once per tick, and a crash between enqueue and
  advance cannot double-fire"; "one tick belongs to one runner, even when another
  is looking at it".
- Runner and registry: "a batch is claimed in one pass and every job in it runs";
  "a registered body runs, and its effects commit with the job's completion"; "a
  body that fails leaves no effects, and its job retries and then fails"; "a job
  whose kind this deployment cannot run fails without the body ever being
  invoked"; "the startup sweep accepts a registry that covers every kind the
  table holds"; "a stopping runner does no work and returns from its loop"; "a
  queue survives the process that wrote it".
