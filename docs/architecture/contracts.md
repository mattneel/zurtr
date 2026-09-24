# zurtr — shared contracts

Normative. Types named here are contracts, not final declarations; the
semantics are what implementations must satisfy. Zig type names use the
`zurtr.<module>` namespace (e.g. `zurtr.data.Tx`).

Status: §1's execution rules and §5's durability rules are the design this tree
is held to, and parts of both are now code: §1.6 is `zurtr.runtime.task`
(`src/runtime/task.zig`), and the queue rules in §5 — leases, bounded retries
with backoff, cancellation as a state transition — are `zurtr.jobs`
(`src/jobs/`). `overview.md` §Execution model records how the async lane maps
onto zix, and `docs/architecture/decisions.md` records the rulings (D1 retires
the park class, D2 confines deferral to `.ASYNC`). §3's adapter position is
stated against the tree.

## 1. Execution

Two classes, defined in `overview.md` §Execution model (the parked class the
third name referred to is retired — `decisions.md` D1). Rules:

1. **Handler context is borrowed.** `RequestView` slices, headers, params and
   the request arena are valid only for the duration of the handler call (or
   the resumed continuation, for an operation in flight on the async lane).
   Nothing derived from them may be stored in session state, job payloads, or
   agent state.
2. **Async lane rules.** A driver round trip parks the connection's fiber, not
   the worker (`deps/zix/src/tcp/http1/context.zig`). The request buffer stays
   valid across the yield. One in-flight operation per fiber; a connection with
   an operation in flight processes no further reads for it, and resume produces
   the response.
3. **Deferred rules.** A deferred completion carries a handle
   (`worker_id, conn_index, conn_generation, request_id`) and **owns** its
   response data: the producer allocates it and transfers ownership, the
   consumer validates the handle before writing and frees what it consumed. A
   dropped handle is counted and ignored; it is never an error path that can
   crash the worker. The runtime's carrier is the substrate rather than the
   handle: `runtime.Completion` (`src/runtime/pool.zig`) is an opaque request
   token plus an owned payload, and the fields above are what a session-level
   consumer derives from that token — none exists yet, because there is no
   session type (`docs/modules/live.md`). Deferral is confined to the `.ASYNC`
   lane until the transport can wake the loop models (`decisions.md` D2).
4. **Ordering.** Per connection, responses are written in completion order;
   the framework never reorders a connection's writes. Per session, event
   processing is serialized by the session owner; asynchronous operations
   complete into the owner's queue and are processed in arrival order.
5. **No blocking.** Loop-thread code must not perform blocking syscalls, mutex
   waits, or unbounded computation. Anything that can wait runs in the async
   lane or moves to a worker role. Submitting work to the runtime's pool
   follows the same rule from the caller's side: the pool's intake is bounded
   per worker, `submit` never waits on whoever is running, and a full intake is
   `error.QueueFull` returned to the caller — shed, retry, or move the work —
   rather than a loop thread stalled behind a queue (`src/runtime/pool.zig`).
6. **Scopes own their tasks.** `zurtr.runtime.task`: a `Scope` owns the tasks
   spawned in it, and `end` cancels and waits for every child before it returns;
   a task's own scope is reaped the same way when its body returns, so nothing
   outlives the scope that spawned it. Parentage is explicit at spawn
   (`Task.inner`, never ambient), so a task running inside another task's frame
   still spawns into its own scope. Cancellation is one flag read up the parent
   chain and observed cooperatively (`Task.checkCancel` for native code,
   `Task.scriptInterrupt` for zscript's interrupt callback) — nothing preempts
   native code — and a failure goes to the scope's `FailurePolicy`, never
   swallowed. A thread waiting for a scope helps by running queued work, which
   may be work that is not its own: a body must not hold a lock across a scope
   wait, and `runtime/task.zig`'s waiter-and-lock test reproduces that cost.

## 2. Ownership and lifetimes

| Data | Owner | Lifetime | May be stored in session/job/agent state? |
| --- | --- | --- | --- |
| Request view slices | zix connection | handler call | No |
| Request arena | request | until response queued | No |
| Event arena | live dispatch | until patches queued for the event | No |
| Decoded event payload | event arena | event | Only after explicit copy into session storage |
| Session state | session | session (explicit replace/reclaim) | Yes (by definition) |
| Outbound live messages | session message queue | until acked/sent | No |
| Queued job payloads | jobs store | until terminal state | Yes (serialized bytes) |
| DB rows | data layer | row/iterator scope or caller-owned copy | Only as owned copies |
| Snapshots | producer | serialized bytes only | Yes — serialization is the transfer format |

Rules:

- **No borrowed pointers across boundaries.** A value crossing a boundary
  (handler→session, session→job, agent→effect) is either owned by the receiver
  or serialized.
- **Session storage supports replacement and reclamation** during the session;
  replacing state is a first-class operation (`replaceState`) with explicit
  old-state destruction, not a leak.
- **Queued messages own their payloads.** Queues are bounded (count + bytes);
  the overflow policy is coalesce → full re-render → terminate session with
  resync, in that order.
- **Persistent state cannot borrow transport buffers.** No exceptions.

## 3. Persistence

- `zurtr.data.Database`: `query`, `exec`, `begin`, `close`. Adapter
  implementations share this interface. Turso is the only built adapter, opened
  at one of four tiers (`docs/modules/data.md`); PostgreSQL is declared over
  zix's `postgrez` driver and is not built. Database calls from a handler run in
  the async lane, where the fiber parks on the driver's `std.Io` round trip
  (`decisions.md` D1); there is no reactor-parking client and none is being
  built.
- `zurtr.data.Tx`: scoped, not thread-safe, not storable. Acquired
  lexically (or by a surface that establishes one for an action). Nested
  scopes use savepoints. A tx that is neither committed nor rolled back at
  scope exit is rolled back with a recorded diagnostic — silently committing is
  forbidden.
- **Job insertion shares the domain transaction.** `jobs.enqueue(tx, ...)`
  writes the job row through the same `Tx`; the job is invisible to workers
  until commit. This is the atomicity contract the slice verifies.
- **Read authorization is part of query execution**, not a post-filter:
  resource queries carry a policy that is compiled into the SQL predicate
  (declarative policies) or applied as a row-level filter before pagination and
  aggregation. Post-filtering a limited page is a contract violation.
- **One writer per database.** The built adapter opens every read-write
  transaction `BEGIN IMMEDIATE` (`connection.begin(.immediate, …)`,
  `src/data/turso_adapter.zig`), so a read-modify-write pair inside one
  transaction is atomic without a row lock, which is what the queue's
  select-then-update claim rests on (`src/jobs/schema.zig`). Across nodes that
  property comes from the `.distributed` tier's write lease (`data.Lease`,
  `src/data/root.zig`), not from the statement.
- Migrations are ordered, versioned, and applied by `zurtr migrate`; each
  migration runs in a transaction; dev mode applies them on start. Both halves
  are unbuilt: `src/main.zig` has `modules` and `new`, and `src/data/root.zig`
  has no migration entry point yet (`docs/modules/data.md`, `src/jobs/schema.zig`).
- Explicit SQL is always available and never rewritten. Resource descriptors
  are an additive query construction layer.

## 4. Authorization

- Every externally-triggered operation (HTTP request, live event, job, agent
  signal) carries an explicit **principal**; anonymous is a principal, not an
  absent one.
- **Connection authentication ≠ per-event authorization.** A live connection
  is authenticated once; every event is authorized against its action's policy
  at handling time. A principal change (logout, token expiry, role change)
  applies to subsequent events on the same connection.
- Policies live with the action/resource: `authorize(principal, input)`
  returns allow/deny, evaluated before execution; read policies are pushed into
  queries per §3.
- Denied operations are reported distinctly from validation failures and never
  leak resource existence beyond what the policy allows.

## 5. Errors and durability

- Error taxonomy: `operation` (surface decides), `validation` (pre-execution),
  `authz` (deny), `conflict` (optimistic/unique violation), `unavailable`
  (dependency down), `internal` (bug; logged with context). A domain action's
  result refines these rather than collapsing them: `denied` and `not_found`
  are separate variants — a denied caller gets `denied` before its payload is
  even decoded, so the two never leak into each other — and `timeout` is
  reported apart from `unavailable` (`src/domain/action.zig`).
- **Jobs are at-least-once.** Workers lease, heartbeat, and may re-deliver after
  lease expiry. Actions used as jobs must be idempotent or carry an
  `idempotency_key` (derived by the caller, unique in the store). Transactional
  writes + unique constraints are the dedup mechanism; there is no
  exactly-once promise. Three consequences the queue is held to, all of them
  implemented in `src/jobs/`:
  - **Claim order and queue limits are part of the predicate.** Highest priority
    first, then earliest due time, then lowest id; a bounded queue counts its
    live leases inside the same transaction that takes the row, and `-1` is
    unlimited (`QueueLimit`, `src/jobs/root.zig`). A limit is not something a
    worker enforces after the fact — a claim that would exceed it takes nothing.
  - **A lost lease cannot overwrite its successor.** Every claim bumps the row's
    `attempt`, and every write only an owner may make is guarded on
    `state = 'leased' AND attempt = ?` in the same statement as the write, so a
    worker whose lease expired affects zero rows and is told `not_owner` rather
    than clobbering the attempt that took over (`src/jobs/root.zig`, `Owned`).
    At-least-once means a job may run twice; it does not mean a run whose lease
    is gone may write.
  - **Wake-up is a poll, and a tick fires at most once.** There is no
    notification channel in the built adapter, so a runner polls at
    `poll_interval_ms` and only a same-process enqueue can raise an in-process
    signal — which is why an `enqueue` inside a caller's `Tx` becomes claimable
    at the caller's commit and not before (`src/jobs/root.zig`). A recurring
    schedule's job carries a key derived from the schedule id and the tick time,
    so a crash between enqueue and advancing the schedule cannot double-fire,
    and ticks that elapsed while no runner was up are skipped rather than
    replayed — catching up turns an outage into a stampede (`src/jobs/root.zig`).
- **External effects require recorded results.** An effect that leaves the
  process (HTTP call, email, payment) records its completion result in durable
  storage before the enclosing step commits; recovery replays decisions from
  recorded results instead of re-issuing effects blindly.
- Retries: bounded attempts with backoff per job kind; terminal failures are
  retained with their last error; cancellation is a state transition, observed
  cooperatively at step boundaries.

## 6. Live protocol

- Server is the single writer for a session; all messages carry a monotonically
  increasing `rev` (server revision). Client events carry client-generated
  event ids; the server acknowledges processed ids.
- Reconnect: client resends unacknowledged events with the last known `rev`.
  Server either (a) processes them against the live session, or (b) issues a
  full resync (`resync` + rendered HTML + fresh `rev`) when the session is
  gone or the revision gap exceeds the retained patch window. Resync is always
  correct; incremental replay is an optimization.
- Patches target stable component identity (explicit keys for list items);
  identity is never derived from position alone.
- Focus, selection, and uncommitted form values survive patches: the client
  bridge restores focus/selection by element identity after applying a patch,
  and the server never rewrites an actively edited input unless the action
  that produced the patch changed that input's value.
- Client-controlled DOM regions are explicit in the render tree (`owned`
  markers); the server does not patch inside them.
- Backpressure: bounded outbound queue per session; coalescing before
  re-render, re-render before disconnect (see §2).
- Event payload validation and authorization happen server-side per event
  (§4); the client is untrusted.

## 7. Versioning

- Actions have a stable id and a version. Job payloads record both; a job whose
  action version is unsupported fails terminally with a diagnostic rather than
  running the wrong code.
- Live session state carries a state version; a snapshot whose version does not
  match the running code is discarded (resync), never partially migrated.
- Agent durable workflows version their transitions; in-flight workflows
  complete on the transition set they started with, and new versions apply to
  new workflows or explicit, recorded migrations.
