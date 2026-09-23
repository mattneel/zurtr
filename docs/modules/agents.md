# Module contract: Agents (`zurtr.agents`)

Scope: stateful workflows with durable execution — typed signals, decisions,
effects, checkpoints. Agents reuse `jobs` (execution) and `domain` (actions as
tools); they add durable state and replay with recorded effects.

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
  id            bigserial primary key,
  agent         text not null,
  version       int  not null,
  state         bytea not null,
  status        text not null,      -- running|waiting|completed|failed|cancelled
  step          int  not null default 0,
  lease_until   timestamptz,
  leased_by     text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create table zurtr_agent_steps (
  run_id        bigint not null references zurtr_agent_runs(id),
  step          int    not null,
  signal        bytea  not null,    -- serialized Signal
  decision      bytea  not null,    -- serialized Decision
  effect_status text   not null,    -- pending|succeeded|failed
  effect_result bytea,              -- recorded result, replayed on recovery
  inserted_at   timestamptz not null default now(),
  primary key (run_id, step)
);
create table zurtr_agent_signals (
  id       bigserial primary key,
  run_id   bigint not null,
  payload  bytea  not null,
  state    text   not null default 'pending', -- pending|delivered
  inserted_at timestamptz not null default now()
);
```

- One step per (run, step index), written with the effect's result before the
  step is considered complete. **Recorded results are the replay mechanism**:
  recovery re-reads `zurtr_agent_steps`; steps with `effect_status=succeeded`
  are applied from `effect_result` without re-issuing the effect
  (`contracts.md` §5).
- The run row is the lease/lock: a worker claims a run with the same
  `FOR UPDATE SKIP LOCKED` discipline as jobs (separate queue,
  `zurtr_agents`), so two workers never decide concurrently for one run.
- `apply` must be deterministic given `(state, effect_result)`; it must not
  perform I/O. All I/O happens in effects (actions, or explicit `effect`
  declarations executed by the runner with recorded results).
- Signals are durable: `sendSignal(run_id, signal)` inserts into
  `zurtr_agent_signals` (and `NOTIFY`), and the runner delivers pending signals
  in id order. `waiting` runs wake on signal arrival.
- Versioned transitions: a run records `version`; the runner executes the
  workflow code for that version. New versions apply to new runs;
  migrating a live run is an explicit recorded operation, never implicit.
- Cancellation and failure follow the jobs contract: cooperative checks at
  step boundaries; `failed` retains the last error and the step it occurred at.

## Effect execution and idempotency

- Effects are actions (`Decision.call`) or declared external effects. Before
  issuing, the runner records the intent (`effect_status=pending`); after,
  it records `succeeded` + result in the same transaction that advances the
  step. Crash between issue and record ⇒ replay sees `pending`, and the effect
  must be idempotent (its action carries an idempotency key derived from
  `(run_id, step)`) — this is why `domain` actions used as effects must accept
  an explicit idempotency key in their `Input`.
- Effects are never retried blindly on `unavailable` beyond the job-level retry
  policy; the step is retried by the agent queue with its own backoff.

## Tooling and inspection

- `zurtr inspect agents` (dev only) lists runs, states, pending signals, and
  step history; `zurtr agents retry <run_id>` re-arms a failed run at its last
  step with the recorded results intact.
- The same agent declaration is usable as a job (`Decision.call` on a single
  action) — the lightweight path must not require the full durable workflow.

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
