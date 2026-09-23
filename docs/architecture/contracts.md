# zurtr — shared contracts

Normative. Types named here are contracts, not final declarations; the
semantics are what implementations must satisfy. Zig type names use the
`zurtr.<module>` namespace (e.g. `zurtr.data.Tx`).

Status: nothing in §1's parked and deferred classes is implemented in this tree
(`overview.md` §Execution model records why: the park sentinel these rules were
written against was swerver's, and zix has no counterpart). §3's adapter
position and §2's transport row are stated against the tree; the rest of the
document is the design the implemented modules (`data`, `live`, `runtime`) and
the declared ones are held to.

## 1. Execution

Three classes, defined in `overview.md` §Execution model. Rules:

1. **Handler context is borrowed.** `RequestView` slices, headers, params and
   the request arena are valid only for the duration of the handler call (or
   the resumed continuation for parked requests). Nothing derived from them may
   be stored in session state, job payloads, or agent state.
2. **Park rules.** One park per request. Park stash is plain data
   (`assertPlainData`-checked at comptime), fixed capacity, copied in and out.
   A parked connection accepts no further requests and no reads are processed
   for it.
3. **Deferred handle rules.** A deferred handle owns its response data; the
   producer allocates it and transfers ownership. Handles are validated
   (worker, connection index, generation, request id) at completion. A dropped
   handle is counted and ignored; it is never an error path that can crash the
   worker.
4. **Ordering.** Per connection, responses are written in completion order;
   the framework never reorders a connection's writes. Per session, event
   processing is serialized by the session owner; asynchronous operations
   complete into the owner's queue and are processed in arrival order.
5. **No blocking.** Reactor-thread code must not perform blocking syscalls,
   mutex waits, or unbounded computation. Anything that can wait is parked,
   deferred, or moved to a worker role.

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
  zix's `postgrez` driver and is not built. The parked execution mode §1
  describes is therefore unbuilt for the data layer: it relied on an
  event-loop-integrated client that parks on the reactor, and zix's `postgrez`
  does not park that way.
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
- Migrations are ordered, versioned, and applied by `zurtr migrate`; each
  migration runs in a transaction; dev mode applies them on start.
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
  (dependency down), `internal` (bug; logged with context).
- **Jobs are at-least-once.** Workers lease, heartbeat, and may re-deliver after
  lease expiry. Actions used as jobs must be idempotent or carry an
  `idempotency_key` (derived by the caller, unique in the store). Transactional
  writes + unique constraints are the dedup mechanism; there is no
  exactly-once promise.
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
