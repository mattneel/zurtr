# zurtr — architecture overview

Status: initial design, 2026-09-22. This document is normative for module
boundaries and execution semantics; per-module contracts live in
`contracts.md` and `modules/`.

## What zurtr is

A native application framework in Zig on top of the vendored swerver transport
(`deps/swerver`, pinned; see `deps/swerver/UPSTREAM.md`). It provides stateful
server-rendered interfaces (Live UI), typed domain actions (Domain), durable
background work (Jobs), agent workflows (Agents), persistence (Data), the
application assembly layer (Application), and a development loop (Development).
Applications are ordinary Zig and deploy as one static executable.

## Modules and dependency direction

| Module | Responsibility | May import |
| --- | --- | --- |
| `runtime` (shared core) | Ownership helpers, arenas, ids, clock, error taxonomy, message types | swerver |
| `data` | Queries, transactions, migrations, adapters | runtime, swerver |
| `domain` | Resources, typed actions, validation, authorization, relationships | data, runtime |
| `live` | Session state, events, components, render/patch, DOM protocol | runtime, swerver |
| `jobs` | Durable queues, schedules, retries, concurrency, cancellation | data, domain (action refs), runtime |
| `agents` | Signals, decisions, effects, checkpoints, durable execution | data, domain, jobs, runtime |
| `app` | Config, routes, middleware, auth, lifecycle, telemetry; wires the rest | all of the above |
| `dev` | Incremental builds, reload, diagnostics, tests, inspection | build system; not linked into release apps |

Dependency rule: arrows point downward only. `live` core never imports `domain`;
the *glue* that binds live events to domain actions lives in `app` (a small
`actions` bridge), so Live UI remains usable without Domain and Domain without
Live UI.

### Seam principle (build latency)

Modules communicate through **narrow registration tables**, not one global
generic type parameterized by the whole application:

- one route table (`app`), one action registry keyed by stable id (`domain`),
  one job-kind registry (`jobs`), one component registry (`live`).
- Tables are per-subsystem and comptime-generated from declarations local to
  their module, so an ordinary edit in one application file invalidates that
  table and its consumers, not the whole world.
- Shared runtime implementations sit behind typed interfaces (vtable-free:
  comptime dispatch on a concrete type chosen once at the edge of the module).

## Execution model

Transport (swerver): one event loop per worker process, N workers via
`SO_REUSEPORT`, synchronous zero-copy handlers; request slices point into the
receive buffer and the response body must be produced before the handler
returns. swerver already has a **park/resume** mechanism (used by its Postgres
client): a handler returns a park sentinel, the connection parks, and the loop
resumes it when the operation completes.

zurtr uses three execution classes:

1. **Synchronous** — routing, session lookup in memory, validation, render,
   patch generation, fast DB ops via the parked path below. Runs on the reactor
   thread. No heap allocation beyond the request arena and response buffers.
2. **Parked (operation in flight)** — the handler hands off one in-flight
   operation to an event-loop-integrated driver (Postgres I/O, timers) and
   returns the park sentinel. The request buffer stays valid; the handoff state
   is plain data (no pointers/slices) in a fixed stash, enforced at comptime.
   One park per request. Resume runs on the reactor thread and produces the
   response.
3. **Deferred (application-completed)** — work that outlives the reactor's own
   drivers (a job completing, an agent step, a pub/sub broadcast) retains an
   explicit **connection handle**: `{worker_id, conn_index, conn_generation,
   request_id}` plus **owned** response data. Completion is enqueued on the
   worker's completion queue and signaled via a registered wake fd; the loop
   drains the queue and, validating the connection generation, writes the
   response or drops it. A stale handle (connection closed/reused) is a
   no-op + counter increment, never a use-after-free.

Everything that can be synchronous should be; parks are for single in-flight
awaitables; deferred handles are for external completions and session fanout.

### Sessions and worker affinity

Live sessions are worker-local: one owner for mutable session state, no shared
mutable state across workers. Consequences, stated plainly:

- Session state is not migrated between workers. A reconnect may land on a
  different worker (kernel `SO_REUSEPORT` dispatch). The session then either
  (a) resumes from a serializable session snapshot if one is available to that
  worker, or (b) is re-initialized and the client receives a full
  resynchronization.
- Deployments that need session continuity across workers use a sticky load
  balancer or a shared external session store; the framework guarantees
  correctness of resynchronization, not cross-worker state migration.
- Sessions never hold pointers into transport buffers or transient arenas
  (see `contracts.md`).

## Failure model

| Class | Behavior |
| --- | --- |
| Recoverable error | Ends the operation; the surface decides (HTTP status, job retry, live event error message). May reset the session (`session_reset`) without affecting other sessions. |
| Session corruption / invariant violation | Session is terminated and marked for resync; the worker keeps serving. |
| Panic, OOM, memory corruption | Worker process aborts. The master respawns it (`swerver.Master` model). In-flight sessions on that worker are lost and resync on reconnect. |
| Isolation needed by the app | Run roles as separate supervised processes from the same executable (`zurtr run --role=web|jobs|agents`), so a crash in one role does not take the others down. |

No BEAM-style per-entity preemptive isolation: stateful entities are not
individually supervised. Per-entity isolation requires a process boundary and
is therefore a deployment choice (role processes, or one process per shard).

## Build and development model

- Every module is a separate Zig module with explicit imports; an application
  compiles only the modules it uses (unreferenced modules are never analyzed).
- Feature flags map to swerver build options (TLS/HTTP2/HTTP3/proxy/io_uring/
  compression), all off by default: base build is HTTP/1.1-only with no
  external dependencies.
- Dev loop (`dev` module): incremental compilation (`-fincremental --watch`),
  process replacement, browser reconnect with session snapshot transfer when
  compatible. Target: handler and component edits reach the browser in <1s,
  measured by a harness, on this workstation.
- Release: static executable; release pins the exact Zig revision and the
  swerver revision; `zurtr build --report` emits cold/warm build times, peak
  RSS, executable size, and the enabled protocol/module inventory.
- Applications never require Node/npm: the DOM bridge ships as a bundled
  prebuilt asset; optional shared client logic compiles from Zig to WASM.

## The slice (first integration milestone)

One application exercising the whole architecture:

1. HTTP request renders initial HTML for a live page; the browser opens a live
   connection; a session is created.
2. A form submits; the event is validated and correlated to a typed domain
   action with an explicit principal.
3. The action runs in one PostgreSQL transaction that (a) writes the domain
   row and (b) inserts a durable job row, in the same commit.
4. The job executes, its result is published on a pub/sub topic owned by the
   live runtime, and the affected UI region is patched.
5. Editing a handler or component in the dev loop reaches the browser within
   the latency target.

Each numbered item is an acceptance check in the slice's end-to-end script.

## Deferred / explicitly out of scope

- Pure-Zig TLS (the documented TLS path requires OpenSSL; a pure-Zig stack
  needs separate engineering and security validation).
- Non-PostgreSQL adapters: the adapter interface is designed, only PostgreSQL
  is implemented.
- Connection migration of live sessions across workers (see above).
- HTTP/2 (RFC 8441) WebSockets: HTTP/1.1 upgrade first.
