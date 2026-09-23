# Module contract: Jobs (`zurtr.jobs`)

Scope: durable queues, schedules, retries, concurrency, cancellation. Delivery
is at-least-once; idempotency is the caller's contract (`contracts.md` §5).

Status: **declared** — no implementation in this tree (`src/root.zig`'s module
table). The model below is written in the dialect of the adapter that exists:
Turso, which is SQLite-compatible (`src/data/turso_adapter.zig`), with four
tiers and a single writer per database (`docs/modules/data.md`). PostgreSQL
remains a declared adapter, unbuilt (`decisions.md` D5).

## Durable model (Turso / SQLite)

```sql
create table zurtr_jobs (
  id              integer primary key autoincrement,
  queue           text    not null default 'default',
  kind            text    not null,          -- action id
  version         integer not null,          -- action version at insert
  payload         blob    not null,          -- serialized Input
  idempotency_key text,
  state           text    not null,          -- available|leased|completed|failed|cancelled
  priority        integer not null default 0,
  attempt         integer not null default 0,
  max_attempts    integer not null,
  run_at          integer not null,          -- microseconds since the epoch, UTC
  lease_until     integer,                   -- microseconds; null while not leased
  leased_by       text,
  result          text,                      -- summary only; large results go to app tables
  last_error      text,
  inserted_at     integer not null,
  updated_at      integer not null
);
create unique index zurtr_jobs_idempotency
  on zurtr_jobs (queue, kind, idempotency_key) where idempotency_key is not null;
create index zurtr_jobs_ready
  on zurtr_jobs (queue, priority desc, run_at) where state = 'available';
```

Instants are integer microseconds since the epoch, UTC — the same encoding the
data contract's `Param.timestamp_micros` uses, because SQLite has no date type.
Every timestamp above is written by the runner, not by a database function.

`payload` is the action's `Input` serialized with the framework's binary/JSON
codec; `version` is checked against the running action — an unsupported
version fails the job terminally with a diagnostic, never runs the wrong code.

## Enqueue

```zig
pub fn enqueue(jobs: *Jobs, tx: ?*data.Tx, spec: EnqueueSpec) !JobId;
// EnqueueSpec = .{ .action = Invoice.Send, .input = .{...}, .queue = "default",
//                  .run_at = ..., .max_attempts = 5, .idempotency_key = "invoice/42/send",
//                  .priority = 0 }
```

- With a `tx`, the row is written through the same transaction as the domain
  write (the slice's atomicity contract). Without one, it is written in its own
  short transaction.
- Duplicate `idempotency_key` is not an error: `enqueue` returns the existing
  job id (the caller asked for "at most one such job"). The unique index is the
  dedup mechanism, so two concurrent enqueues resolve in the store, not in the
  runner.
- There is no notification to issue: the row becomes claimable when the
  transaction commits, and the poller finds it (`decisions.md` D5). What must
  reach a live session is published through the outbox in the same transaction,
  never through the queue.

## Claim / lease / retry

- Claim (one statement, inside a write transaction):
  `update zurtr_jobs set state='leased', leased_by=$worker, attempt=attempt+1,
   lease_until=$now+$lease, updated_at=$now where id in (select id from zurtr_jobs
   where state='available' and run_at<=$now and queue=$queue order by priority
   desc, run_at asc limit $n)`.
  The transaction is what makes the select-then-update safe: SQLite admits one
  writer per database, so no two claims interleave inside it. Across nodes that
  property comes from the distributed tier's write lease
  (`docs/modules/data.md`), not from the claim statement.
- Concurrency: per-queue limits enforced in the claim predicate by counting
  `state='leased' and queue=$q` inside the same transaction. `-1` = unlimited.
- Heartbeat extends `lease_until` every `lease/3` while a job runs; a reaper
  (same worker role) returns expired `leased` rows to `available` (they will be
  claimed again — at-least-once).
- Retry decision on failure: `attempt < max_attempts` → `available` with
  `run_at = $now + backoff(attempt)` (exponential with jitter, capped by
  `max_backoff`); else `failed` with `last_error` retained.
- `completed` jobs are retained for `retention` (default 7 days) then deleted
  by the reaper; `failed` are retained until manually cleared.

## Waiting and latency

- The runner polls for due work every `poll_interval` (default 1s, dev 100ms)
  and claims inside a write transaction; a claim that finds nothing is a cheap
  indexed lookup against `zurtr_jobs_ready`. There is no `LISTEN` to be woken
  by: the storage has no notification channel (`decisions.md` D4/D5).
- Latency is therefore bounded by `poll_interval`, and a deployment that wants
  less configures it down; the durable path for a *user-visible* result is the
  outbox, which the runner writes when the job completes.
- The same loop processes heartbeats and the reaper on a timer; no separate
  threads.

## Schedules

```zig
pub fn scheduleEvery(jobs: *Jobs, tx: ?*data.Tx, spec: ScheduleSpec) !ScheduleId;
// ScheduleSpec = .{ .action = ..., .input = ..., .every_seconds = 60, .queue = "default" }
```

- Recurring schedules are rows in `zurtr_schedules` (action, payload, queue,
  `next_run_at`, `last_run_at`, `enabled`). The runner claims due schedules with
  the same claim discipline (one statement inside a write transaction) and
  enqueues the job with a deterministic idempotency key
  `schedule/<id>/<next_run_at>` so a crash between enqueue and
  `next_run_at` update cannot double-fire.
- One-shot delayed work is just `enqueue` with `run_at`.

## Cancellation

- `cancel(job_id)` sets `cancelled` when the job is `available`; when `leased`,
  the state change is recorded and the running job observes it cooperatively:
  `ctx.cancelled()` checks a per-worker cancel set refreshed by the reaper tick
  (a poll, not a notification — `decisions.md` D5), not a query per check.
- A cancelled job's transaction rolls back (the job body is the transaction
  scope); effects already recorded stay recorded.

## Action binding

Jobs are a surface for domain actions: `kind` is the action id, `payload` its
`Input`, and the runner invokes it with a `Ctx` whose `tx` is the job's
transaction and whose `principal` is `system.jobs:<queue>` (actions that need a
user principal must carry it in their `Input` as an explicit field).
Serialization of `Input`: the app's codec registry, generated at comptime from
the actions declared in the app's job registry — unknown kinds fail loudly at
startup, not at run time.

## Role process

`zurtr run --role=jobs` runs the runner loop in its own process (supervised by
the master), so job load and crashes are isolated from the web role. The web
role never executes jobs; it only enqueues.

## Testing requirements

- Enqueue-in-transaction: rollback of the domain tx leaves no job row;
  commit makes it claimable (integration test against the built adapter —
  `zig build test-data -Dturso=true` is the pattern, `docs/modules/data.md`).
- Claim exclusivity: two workers claiming concurrently never get the same row
  (N workers × M jobs test, all jobs executed exactly once per claim); with one
  writer per database the claim is serialized by the store, and the distributed
  tier's write lease is what extends that across nodes.
- Lease expiry: a killed worker's lease is reaped and the job re-runs
  (at-least-once proven, not asserted).
- Retry/backoff: attempts increment, backoff grows, terminal failure retains
  `last_error`.
- Idempotency: duplicate key returns the existing id and no second row.
- Cancellation: available job → `cancelled`, never claimed; leased job observes
  cancellation at the next cooperative check and rolls back.
- Schedule: a crash between enqueue and `next_run_at` advance does not produce
  two jobs for one tick.
