# Module contract: Agents (`zurtr.agents`)

Scope: stateful workflows with durable execution — typed signals, decisions,
effects, checkpoints. Agents reuse `jobs` (execution) and `domain` (actions as
tools); they add durable state and replay with recorded effects.

Status: **declared** — read the status from `src/root.zig`'s `modules` table, which is
the inventory of record (`zurtr modules` prints it); this document is the contract the
module is held to, and the sections below are its design.

The tables below are in the same dialect as `jobs.md`'s — Turso /
SQLite, integer microseconds, single writer per database (`decisions.md` D5/D6).

## Model

An agent is a declaration:

```zig
pub fn Agent(comptime Spec: type) type;
// Spec shape:
//   pub const name = "invoice.reconciler";
//   pub const version = 1;
//   pub const State = struct { ... };           // plain data, serializable
//   pub const Signal = union(enum) { ... };     // typed, decodable, durable
//   pub const Decision = union(enum) {          // what the agent decided to do
//       call:  struct { action: ..., input: ... },
//       ask:   struct { question: [...]const u8 },
//       done:  struct { summary: []const u8 },
//   };
//   pub fn decide(ctx: *Ctx, state: *State, signal: Signal) Decision;
//   pub fn apply(ctx: *Ctx, state: *State, result: EffectResult) void;
```

Loop: `signal → decide → effect → apply → (checkpoint)`. There is no implicit
timer loop; scheduling is `jobs`.

## Durable execution

Tables:

```sql
create table zurtr_agent_runs (
  id            integer primary key autoincrement,
  agent         text    not null,
  version       integer not null,
  state         blob    not null,
  status        text    not null,      -- running|waiting|completed|failed|cancelled
  step          integer not null default 0,
  lease_until   integer,               -- microseconds since the epoch, UTC
  leased_by     text,
  created_at    integer not null,
  updated_at    integer not null
);
create table zurtr_agent_steps (
  run_id        integer not null references zurtr_agent_runs(id),
  step          integer not null,
  signal        blob    not null,      -- serialized Signal
  decision      blob    not null,      -- serialized Decision
  effect_status text    not null,      -- pending|succeeded|failed
  effect_result blob,                  -- recorded result, replayed on recovery
  inserted_at   integer not null,
  primary key (run_id, step)
);
create table zurtr_agent_signals (
  id       integer primary key autoincrement,
  run_id   integer not null,
  payload  blob    not null,
  state    text    not null default 'pending', -- pending|delivered
  inserted_at integer not null
);
```

- One step per (run, step index), written with the effect's result before the
  step is considered complete. **Recorded results are the replay mechanism**:
  recovery re-reads `zurtr_agent_steps`; steps with `effect_status=succeeded`
  are applied from `effect_result` without re-issuing the effect
  (`contracts.md` §5).
- The run row is the lease/lock: a worker claims a run with the claim discipline
  `jobs` now implements — the candidate is read, then taken by an `UPDATE` whose
  `WHERE` is the whole guard, with `rows_affected` as the verdict, all inside one
  write transaction (`src/jobs/root.zig`) — so two workers never decide
  concurrently for one run. The queue is the agent's own (`zurtr_agents`), so
  agent work never competes with job work for a claim; what it inherits is the
  discipline, including its ownership rule: a worker whose lease expired is
  refused rather than allowed to overwrite the attempt that took it over.
- `apply` must be deterministic given `(state, effect_result)`; it must not
  perform I/O. All I/O happens in effects (actions, or explicit `effect`
  declarations executed by the runner with recorded results).
- Signals are durable: `sendSignal(run_id, signal)` inserts into
  `zurtr_agent_signals`, and the runner delivers pending signals in id order.
  A `waiting` run wakes on the next poll tick — the storage has no notification
  channel (`decisions.md` D4/D5), so nothing wakes a *different* process, while a
  same-process enqueue is picked up at once because the queue raises an in-process
  condition after the commit (`src/jobs/schema.zig`, `src/jobs/root.zig`). What a
  signal gets instead of a wake-up is therefore a row that cannot be lost, and the
  same two delivery paths jobs already has.
- Versioned transitions: a run records `version`; the runner executes the
  workflow code for that version. New versions apply to new runs;
  migrating a live run is an explicit recorded operation, never implicit.
- Cancellation and failure follow the jobs contract, as that module now implements it: a lease cannot
  be revoked from outside, so cancellation is a state transition plus a per-worker snapshot — a
  request on a leased row is recorded (`cancel_requested`) and the running attempt learns about it
  from a set refreshed once per reap tick, which is why a check is a binary search and not a query
  (`src/jobs/cancel.zig`). `failed` retains the last error and the step it occurred at.

## Effect execution and idempotency

- Effects are actions (`Decision.call`) or declared external effects. Before
  issuing, the runner records the intent (`effect_status=pending`); after,
  it records `succeeded` + result in the same transaction that advances the
  step. Crash between issue and record ⇒ replay sees `pending`, and the effect
  must be idempotent — the key it is idempotent *by* is the caller's, which is
  the shape `jobs` implements: the key travels beside the payload
  (`EnqueueSpec.idempotency_key`) and a partial unique index turns a duplicate
  into the existing row rather than a second one (`src/jobs/root.zig`,
  `src/jobs/schema.zig`). An agent effect's key is derived from `(run_id, step)`
  and passed the same way — into the action's `Input`, so the action's own write
  is what deduplicates, never a read-back of the effect's side effects.
- Effects are never retried blindly on `unavailable` beyond the job-level retry
  policy; the step is retried by the agent queue with its own backoff.

## Where the decision, the model and the script layer attach

The model above deliberately says nothing about *how* a `Decision` is reached. Three things fill that in,
and none of them changes the loop:

- **Decisions from a model.** The stack's sibling `ai.zig` package — an AI SDK implementation, not a
  file in this repository — produces exactly the shapes this contract already names: its
  `generateText`, `streamText`, multi-step tool loops and `ToolLoopAgent` land on a tool call that is
  `Decision.call`, a clarifying turn that is `Decision.ask`, and a final answer that is
  `Decision.done`. The
  agent's tools *are* `domain` actions, so authorization, validation and transaction rules are the same
  ones an HTTP request goes through — the domain's `Surface` enum already carries `agent` beside
  `http`, `live` and `job` (`src/domain/action.zig`), so an agent's invocation is recorded without a
  second vocabulary. Provider choice, credentials and prompt assembly belong to the application; this
  module records what was decided, not how.
- **Decisions from a script.** `zurtr.zscript` may define `decide`/`apply` instead of Zig. What makes that
  workable is the same thing that makes the sibling `jzs` package's agent addons workable: the durable
  surface is exposed as host functions — `emit`, `checkpoint`, `sleep`, `cancelRequested` — and the run's
  state is readable and writable through `state.get/set/del/list`. A script cannot reach the database, the
  network or the clock on its own; it reaches the host, and the host does the durable thing.
- **State is outside the JavaScript heap.** The run's state lives in this module's tables through
  `zurtr.data`, so a script reload changes the rules the *next* decision is made under and never erases a
  run. That is the whole reason the layering is: script for behavior, this module for durability.

### Revision pinning extends to scripts

`version` above pins the workflow code a run executes. When `decide` or `apply` is script-defined, the run
records **the script revision as well** — `{agent version, script revision}` is the unit that is pinned,
and a run started under revision N finishes under N even when the host has loaded N+1
(`contracts.md` §7). A retry, a recovery and a replayed step all execute the recorded revision, so a
reload can never silently change what an in-flight run means.

## Tooling and inspection

- `zurtr inspect agents` (dev only) lists runs, states, pending signals, and
  step history; `zurtr agents retry <run_id>` re-arms a failed run at its last
  step with the recorded results intact.
- The same agent declaration is usable as a job (`Decision.call` on a single
  action) — the lightweight path must not require the full durable workflow. The
  binding already exists in the shape `jobs` needs: `(kind, version)` → `run`,
  with a startup `validate` that refuses an ambiguous registry
  (`src/jobs/registry.zig`), so an agent's single-action case is a registry entry
  rather than a second execution path.

## Testing requirements

- Determinism: replaying steps with recorded results produces the same state as
  the original run (property test over a scripted sequence, no I/O).
- Crash recovery: kill the runner between effect issue and step recording; on
  recovery the effect is not re-issued when recorded, and is re-issued (with
  the same idempotency key) when `pending`.
- Signal ordering: signals delivered in id order; a `waiting` run wakes and
  advances exactly one step per signal.
- Lease exclusivity: concurrent workers never decide for the same run twice.
- Version pinning: a run created at version N completes on version N even when
  the code is deployed with version N+1.
- Script pinning: a run whose decisions come from a script revision completes on that revision after the
  host loads a newer one, and every decision it makes after the reload is the recorded revision's.
