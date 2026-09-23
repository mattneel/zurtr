# zurtr — architecture overview

Status: initial design, 2026-09-22; the transport and module inventory were
revised 2026-09-23 for the swap from the vendored swerver to the vendored zix
(`deps/zix`). This document is normative for module boundaries and execution
semantics; per-module contracts live in `contracts.md` and `modules/`.

## What zurtr is

A native application framework in Zig on top of the vendored zix transport
(`deps/zix`, pinned; see `deps/zix/UPSTREAM.md`) — HTTP/1.1 and HTTP/3 on one
origin, WebTransport, and zix's own in-tree drivers (`postgrez`, `rediz`,
`prometheuz`). It provides stateful server-rendered interfaces (Live UI), typed
domain actions (Domain), durable background work (Jobs), agent workflows
(Agents), persistence (Data), the application assembly layer (Application), and
a development loop (Development). Applications are ordinary Zig and deploy as
one static executable.

## Modules and dependency direction

| Module | Responsibility | May import | Status |
| --- | --- | --- | --- |
| `runtime` (shared core) | Worker pool with work stealing and completion delivery, a bounded lock-free MPMC queue, a structured-task layer | zix | implemented: `src/runtime/` |
| `data` | Queries, transactions, migrations, adapters | runtime, zix | implemented: the contract plus the Turso adapter at four tiers (`docs/modules/data.md`) |
| `domain` | Resources, typed actions, validation, authorization, relationships | data, runtime | declared; `src/domain/{action,policy,validation}.zig` is in the tree but is not exported by `src/root.zig` |
| `live` | Session state, events, components, render/patch, DOM protocol | runtime, zix | implemented: `src/live/{protocol,pubsub,tree,patch}.zig` |
| `jobs` | Durable queues, schedules, retries, concurrency, cancellation | data, domain (action refs), runtime | declared |
| `agents` | Signals, decisions, effects, checkpoints, durable execution | data, domain, jobs, runtime | declared |
| `app` | Config, routes, middleware, auth, lifecycle, telemetry; wires the rest | all of the above | declared |
| `dev` | Incremental builds, reload, diagnostics, tests, inspection | build system; not linked into release apps | declared |

The status column mirrors the `modules` table in `src/root.zig`, which is the
tree's own inventory (`zurtr modules` prints it). *Declared* means this tree has
the contract and no implementation; a module moves to *implemented* when its
first real surface lands.

Optional layers: `script` (QuickJS-ng, `docs/modules/script.md`) and `zeex`
(JSX lowered to Zig at build time by a script the build runs, `src/zeex/`) sit
beside the modules rather than in the dependency order — nothing below them
depends on them, and everything above them can. `script` is behavior a host can
replace without a native rebuild, and the authority a script can reach is exactly
the host functions the host registered; `zeex` is a build-time lowering that
leaves nothing of itself in the running program. Both are behind build options
(`-Dscript`, which `zeex` needs): the base build contains neither.

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

Transport (zix): three dispatch models, chosen in the server config
(`deps/zix/src/tcp/http1/config.zig`). `.EPOLL` and `.URING` run N
shared-nothing worker loops, each with its own `SO_REUSEPORT` listener
(`deps/zix/src/tcp/http1/dispatch/{epoll,uring}.zig`); `.ASYNC` runs the request
on a fiber over a thread pool (`dispatch/async.zig`). Handlers are synchronous
and zero-copy in the loop models: request slices point into the receive buffer
and the response body must be produced before the handler returns. In `.ASYNC`
the request's `std.Io` is a yielding backend, so a driver round trip parks the
connection's fiber instead of blocking the worker
(`deps/zix/src/tcp/http1/context.zig`). zix has no park sentinel: the
park/resume mechanism this section was written against belonged to swerver,
which is no longer vendored.

zurtr uses three execution classes. **None of them is implemented in this tree
yet** — the three classes below are the design, and `runtime`'s pool, queue and
task layer (`src/runtime/`) is the only execution machinery that exists.

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
   worker's completion queue and signaled to the loop (via a registered wake fd
   in the original design; zix offers no such hook, see
   `docs/architecture/zix-deferred.md`); the loop drains the queue and,
   validating the connection generation, writes the response or drops it. A
   stale handle (connection closed/reused) is a no-op + counter increment, never
   a use-after-free.

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
| Panic, OOM, memory corruption | The process aborts: zix's workers are threads in one process (`workers` in the server config), and nothing in this tree supervises one. In-flight sessions on that worker are lost and resync on reconnect. |
| Isolation needed by the app | Run roles as separate supervised processes from the same executable (`zurtr run --role=web|jobs|agents`), so a crash in one role does not take the others down. |

No BEAM-style per-entity preemptive isolation: stateful entities are not
individually supervised. Per-entity isolation requires a process boundary and
is therefore a deployment choice (role processes, or one process per shard).

## Build and development model

- Every module is a separate Zig module with explicit imports; an application
  compiles only the modules it uses (unreferenced modules are never analyzed).
- Build options are the framework's own and all default off: `-Dturso` /
  `-Dturso-sync` (the data adapter and its sync SDK Kit) and `-Dscript` (the
  QuickJS layer and the `zeex` compiler that runs on it). zix has no build-time
  feature flags — its protocols, drivers and dispatch models are in-tree source,
  selected in configuration at run time — so the base build is the transport
  plus the framework and needs no external dependency beyond libc.
- Dev loop (`dev` module): incremental compilation (`-fincremental --watch`),
  process replacement, browser reconnect with session snapshot transfer when
  compatible. Target: handler and component edits reach the browser in <1s,
  measured by a harness, on this workstation.
- Release: static executable; release pins the exact Zig revision
  (`minimum_zig_version` in `build.zig.zon`) and the zix revision
  (`deps/zix`); `zurtr build --report` emits cold/warm build times, peak
  RSS, executable size, and the enabled protocol/module inventory.
- Applications never require Node/npm: the DOM bridge ships as a bundled
  prebuilt asset; optional shared client logic compiles from Zig to WASM.

## The slice (first integration milestone)

One application exercising the whole architecture. **Not built yet:**
`apps/slice/` holds the specification (`apps/slice/SPEC.md`); the application,
its migrations and the end-to-end script it names do not exist in this tree.

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
Storage: the slice is specified against PostgreSQL (`apps/slice/SPEC.md` —
`bigserial`, `timestamptz`, `bytea`), while the tree's only built adapter is
Turso, which is SQLite-compatible; the two do not agree yet.

## Deferred / explicitly out of scope

- Pure-Zig TLS as zurtr's own work: zix carries a Zig TLS implementation
  (`deps/zix/src/tls/`, wired into its HTTP/1.1 server as `tls_serve`/`tls_mux`),
  so no OpenSSL is required for HTTPS. zurtr's own TLS surface (config,
  certificates, deployment) is unbuilt.
- Parked and deferred execution (classes 2 and 3 above): designed, not
  implemented. zix has no park sentinel to park against, and its HTTP/1.1
  dispatch exposes no way for another thread to wake the loop
  (`dispatch/epoll.zig` publishes only `runEpoll`); what zurtr uses instead is
  an open call.
- Adapters: Turso is the only built adapter, at four tiers. The PostgreSQL
  adapter is declared over zix's `postgrez` and is not built
  (`docs/modules/data.md`).
- Connection migration of live sessions across workers (see above).
- HTTP/2 (RFC 8441) WebSockets: HTTP/1.1 upgrade first (zix's own server
  serves WebSocket over HTTP/1.1; RFC 8441 appears only in zixer's edge bridge,
  `deps/zix/src/zixer/http2_ws_bridge.zig`).
