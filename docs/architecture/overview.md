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
| `domain` | Resources, typed actions, validation, authorization, relationships | data, runtime | implemented: `src/domain/` (action, policy, validation); the inventory in `src/root.zig` is being updated to match (`decisions.md` D7) |
| `live` | Session state, events, components, render/patch, DOM protocol | runtime, zix | implemented: `src/live/{protocol,pubsub,tree,patch}.zig` |
| `jobs` | Durable queues, schedules, retries, concurrency, cancellation | data, domain (action refs), runtime | declared |
| `agents` | Signals, decisions, effects, checkpoints, durable execution | data, domain, jobs, runtime | declared |
| `app` | Config, routes, middleware, auth, lifecycle, telemetry; wires the rest | all of the above | declared |
| `dev` | Incremental builds, reload, diagnostics, tests, inspection | build system; not linked into release apps | declared |

The status column follows the `modules` table in `src/root.zig`, which is the
tree's own inventory (`zurtr modules` prints it), and differs from it in exactly
one place: `domain` has code in the tree while that table still says declared,
and the table is the side being corrected (`decisions.md` D7). *Declared* means
this tree has the contract and no implementation; a module moves to
*implemented* when its first real surface lands.

Optional layers: `script` (QuickJS-ng, `docs/modules/zscript.md`) and `zeex`
(JSX lowered to Zig at build time by a script the build runs, `src/zeex/`) sit
beside the modules rather than in the dependency order — nothing below them
depends on them, and everything above them can. `script` is behavior a host can
replace without a native rebuild, and the authority a script can reach is exactly
the host functions the host registered; `zeex` is a build-time lowering that
leaves nothing of itself in the running program. Both are behind build options
(`-Dzscript`, which `zeex` needs): the base build contains neither.

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
(`deps/zix/src/tcp/http1/context.zig`). zix has no park sentinel, and none is
being built: see `decisions.md` D1.

zurtr uses **two execution classes** (`docs/architecture/decisions.md` D1). The
third — a park sentinel that handed one operation to an event-loop-integrated
driver and resumed the connection from the loop — died with swerver and is not
being rebuilt: the async lane provides the same property.

1. **Synchronous** — routing, session lookup in memory, validation, render,
   patch generation. Runs on the loop thread, or on the connection's fiber in
   the async lane. No heap allocation beyond the request arena and response
   buffers.
2. **Async (operation in flight)** — the operation runs on the connection's
   fiber in the `.ASYNC` lane: the request's `std.Io` yields on a driver round
   trip, so the fiber parks and the worker keeps serving. The request buffer
   stays valid across the yield, and the response is produced when the fiber
   resumes. One in-flight operation per fiber; a connection with an operation in
   flight processes no further reads for it.

**Deferred completions.** A result that originates outside the connection's own
fiber — a job completing, an agent step, a pub/sub broadcast — is delivered
inside the `.ASYNC` lane, where the parked fiber already has a resume point. The
handle rules in `contracts.md` §1.3 still apply: `{worker_id, conn_index,
conn_generation, request_id}` plus **owned** response data, validated at
completion, and a stale handle (connection closed or reused) is a drop plus a
counter increment, never a use-after-free. What does not exist is a way to wake
the `.EPOLL` / `.URING` loops from another thread, so deferral is confined to
`.ASYNC` for now; a transport-level wake source is the open item
(`decisions.md` D2).

Everything that can be synchronous should be; deferred delivery is for
completions a fiber cannot produce itself.

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

- Every module is a separate Zig module with explicit imports, so an application
  compiles only the modules it uses (unreferenced modules are never analyzed).
  This is the packaging **target**, not today's shape: `build.zig` currently
  declares one `zurtr` module rooted at `src/root.zig`, with the vendored
  dependencies as the only separate modules (`decisions.md` D9).
- Build options are the framework's own and all default off: `-Dturso` /
  `-Dturso-sync` (the data adapter and its sync SDK Kit) and `-Dzscript` (the
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
3. The action runs in one database transaction that (a) writes the domain
   row and (b) inserts a durable job row, in the same commit.
4. The job executes, its result is published on a pub/sub topic owned by the
   live runtime, and the affected UI region is patched.
5. Editing a handler or component in the dev loop reaches the browser within
   the latency target.

Each numbered item is an acceptance check in the slice's end-to-end script.
Storage: the slice is specified in the Turso/SQLite dialect, the only adapter
the tree builds (`apps/slice/SPEC.md`, `decisions.md` D5/D6).

## Deferred / explicitly out of scope

- Pure-Zig TLS as zurtr's own work: zix carries a Zig TLS implementation
  (`deps/zix/src/tls/`, wired into its HTTP/1.1 server as `tls_serve`/`tls_mux`),
  so no OpenSSL is required for HTTPS. zurtr's own TLS surface (config,
  certificates, deployment) is unbuilt.
- Parked execution: retired, not deferred — the async lane is the mechanism
  (`decisions.md` D1). Deferred completions are confined to `.ASYNC` until the
  transport can wake the loop models; that wake source is the open item (D2).
- Adapters: Turso is the only built adapter, at four tiers. The PostgreSQL
  adapter is declared over zix's `postgrez` and is not built
  (`docs/modules/data.md`).
- Connection migration of live sessions across workers (see above).
- HTTP/2 (RFC 8441) WebSockets: HTTP/1.1 upgrade first (zix's own server
  serves WebSocket over HTTP/1.1; RFC 8441 appears only in zixer's edge bridge,
  `deps/zix/src/zixer/http2_ws_bridge.zig`). WebSocket is the documented
  fallback for the live channel; WebTransport is the channel (`decisions.md`
  D3).
