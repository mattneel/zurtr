# Module contract: Jobs (`zurtr.jobs`)

Scope: durable queues, schedules, retries, concurrency, cancellation. Delivery
is at-least-once; idempotency is the caller's contract (`contracts.md` §5).

## Durable model (PostgreSQL)

```sql
create table zurtr_jobs (
  id              bigserial primary key,
  queue           text        not null default 'default',
  kind            text        not null,          -- action id
  version         int         not null,          -- action version at insert
  payload         bytea       not null,          -- serialized Input
  idempotency_key text,
  state           text        not null,          -- available|leased|completed|failed|cancelled
  priority        int         not null default 0,
  attempt         int         not null default 0,
  max_attempts    int         not null,
  run_at          timestamptz not null default now(),
  lease_until     timestamptz,
  leased_by       text,
  result          text,                          -- summary only; large results go to app tables
  last_error      text,
  inserted_at     timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create unique index zurtr_jobs_idempotency
  on zurtr_jobs (queue, kind, idempotency_key) where idempotency_key is not null;
create index zurtr_jobs_ready
  on zurtr_jobs (queue, priority desc, run_at) where state = 'available';
```

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
  job id (the caller asked for "at most one such job").
- After commit, a `NOTIFY zurtr_jobs` is issued (inside the transaction via
  `pg_notify`, so notification is transactional).

## Claim / lease / retry

- Claim (one statement, `FOR UPDATE SKIP LOCKED`):
  `update zurtr_jobs set state='leased', leased_by=$worker, attempt=attempt+1,
   lease_until=now()+lease, updated_at=now() where id in (select id ... where
   state='available' and run_at<=now() and queue=any($queues) order by priority
   desc, run_at asc limit $n for update skip locked) returning *`.
- Concurrency: per-queue limits enforced in the claim predicate by counting
  `state='leased' and queue=$q` (advisory-lock free; the count is taken in the
  same statement). `-1` = unlimited.
- Heartbeat extends `lease_until` every `lease/3` while a job runs; a reaper
  (same worker role) returns expired `leased` rows to `available` (they will be
  claimed again — at-least-once).
- Retry decision on failure: `attempt < max_attempts` → `available` with
  `run_at = now() + backoff(attempt)` (exponential with jitter, capped by
  `max_backoff`); else `failed` with `last_error` retained.
- `completed` jobs are retained for `retention` (default 7 days) then deleted
  by the reaper; `failed` are retained until manually cleared.

## Waiting and latency

- The runner blocks on `LISTEN zurtr_jobs`; the notification wakes the loop,
  which claims. Fallback poll every `poll_interval` (default 1s, dev 100ms) in
  case a notification is missed.
- The same loop processes heartbeats and the reaper on a timer; no separate
  threads.

## Schedules

```zig
pub fn scheduleEvery(jobs: *Jobs, tx: ?*data.Tx, spec: ScheduleSpec) !ScheduleId;
// ScheduleSpec = .{ .action = ..., .input = ..., .every_seconds = 60, .queue = "default" }
```

- Recurring schedules are rows in `zurtr_schedules` (action, payload, queue,
  `next_run_at`, `last_run_at`, `enabled`). The runner claims due schedules with
  the same `SKIP LOCKED` discipline and enqueues the job with a deterministic
  idempotency key `schedule/<id>/<next_run_at>` so a crash between enqueue and
  `next_run_at` update cannot double-fire.
- One-shot delayed work is just `enqueue` with `run_at`.

## Cancellation

- `cancel(job_id)` sets `cancelled` when the job is `available`; when `leased`,
  the state change is recorded and the running job observes it cooperatively:
  `ctx.cancelled()` checks a per-worker cancel set refreshed by the reaper
  tick (and by `NOTIFY zurtr_jobs_cancel`), not a query per check.
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
  commit makes it claimable (integration test with local PostgreSQL).
- Claim exclusivity: two workers claiming concurrently never get the same row
  (N workers × M jobs test, all jobs executed exactly once per claim).
- Lease expiry: a killed worker's lease is reaped and the job re-runs
  (at-least-once proven, not asserted).
- Retry/backoff: attempts increment, backoff grows, terminal failure retains
  `last_error`.
- Idempotency: duplicate key returns the existing id and no second row.
- Cancellation: available job → `cancelled`, never claimed; leased job observes
  cancellation at the next cooperative check and rolls back.
- Schedule: a crash between enqueue and `next_run_at` advance does not produce
  two jobs for one tick.
