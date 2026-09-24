# zurtr — architecture overview

Status: initial design, 2026-09-22; revised 2026-09-23 for the swap from the
vendored swerver to the vendored zix (`deps/zix`), and for the rest of that day:
`jobs` moved from declared to implemented (`src/jobs/`, `9ac4db6`), the project
generator and its template engine landed (`zurtr new`, `src/main.zig`,
`src/scaffold.zig`, `src/templ.zig`), and `live.tree` was exported from the
framework root (`dae8366`) — without it, every file ZEEX emits names a namespace
that does not exist and cannot compile. This document is normative for module
boundaries and execution semantics; per-module contracts live in `contracts.md`
and `modules/`.

## What zurtr is

A native application framework in Zig on top of the vendored zix transport
(`deps/zix`, pinned; see `deps/zix/UPSTREAM.md`) — HTTP/1.1 and HTTP/3 on one
origin, WebTransport, and zix's own in-tree drivers (`postgrez`, `rediz`,
`prometheuz`). It provides stateful server-rendered interfaces (Live UI), typed
domain actions (Domain), durable background work (Jobs), agent workflows
(Agents), persistence (Data), the application assembly layer (Application), and
a development loop (Development). Applications are ordinary Zig and deploy as
one static executable.

The transport is vendored but not frozen, and that distinction is load-bearing:
`deps/zix` is *editable source* that zurtr patches in place, and
`deps/zix/UPSTREAM.md` is the record — upstream (`prothegee/zix`, fork branch
`mattneel/zix#feat/webtransport`), the pinned revision `5df894c34a35`, the set of
paths the vendored copy contains, and a modification ledger with one line per
change. The vendored set is `build.zig`, `build.zig.zon`, the
`zix*-build*.zig` / `zixer-build*.zig` helpers and `src/`; zix's own `docs/`,
`examples/`, `tests/`, `templates/`, `containers/`, `scripts/`, `localbench/`,
`rnd/` and `README*.md` are not in this tree. So a citation into zix's
documentation or examples has to name the upstream repository rather than a path
here — the fix `decisions.md` D3 needed — and a Zig 0.17 port of a vendored file
is a ledger entry rather than a version bump.

## The toolchain

`build.zig` builds the framework module and the `zurtr` executable
(`src/main.zig`), which is the framework's own entry point — plus the artifacts
the build options ask for: the distributed tier's harness (`zurtr-data-node`,
`src/data/node.zig`, with `-Dturso`) and the live editor (`zeex-live`,
`tools/zeex_live.zig`, with `-Dzscript`). Two commands exist today, and the file
says so rather than pretending otherwise: `modules`, which prints the inventory
it was built with, and `new`, which generates an application. `run --role=…`,
`migrate`, `test` and `build --report` arrive with the modules they drive
(`src/main.zig`).

- **`zurtr modules`** prints `src/root.zig`'s `modules` table — the inventory the
  status column below is read from.
- **`zurtr new <name>`** (`src/scaffold.zig`) generates a project the way the
  toolchain does: `zig init` in the target directory, `zig fetch --save <this
  checkout>` for the dependency, then the framework's templates laid over zig's
  example, with the example's library half (its own `src/root.zig`) deleted and
  optional installer hooks run. The ordering is the toolchain's for two reasons
  that were both blockers: `build.zig.zon` carries a `.fingerprint` validated
  against a CRC of the project name, which no scaffolder can hardcode, and the
  dependency entry is a format only `zig fetch --save` writes correctly.
  Verified end to end at `cf22a13`: `zurtr new hello`, `zig build`,
  `zig build run` opens a file-tier database, registers a live channel, listens
  on 127.0.0.1:8080 and answers `GET /` with 200.

The templates are `src/scaffold/templates/app/*.tpl`, embedded with `@embedFile`
so one missing from the tree is a compile error rather than a runtime surprise,
and the language they are written in is `src/templ.zig`: `{{name}}`
substitution, `{{#if}}`/`{{#unless}}` with nesting, and a name nothing binds is
an error instead of an empty string — a generator that answers a typo with `""`
writes code that looks finished and fails in its user's first build, so the
diagnostic carries the line, the tag and the source line with a caret under it
(`templ.Diagnostic.write`). Conditional entries (`--no-data`, `--no-live`,
`--zscript`) select files rather than rewriting them. Flags are parsed with the
vendored zig-clap (`deps/zig-clap`) for the reason a hand-rolled parser is
wrong: a missing value silently becoming an empty string, `--flag=value` and
`--flag value` disagreeing.

## Modules and dependency direction

| Module | Responsibility | May import | Status |
| --- | --- | --- | --- |
| `runtime` (shared core) | Worker pool with work stealing and completion delivery, a bounded lock-free MPMC queue, a structured-task layer | zix | implemented: `src/runtime/{pool,mpmc,task}.zig` |
| `data` | Queries, transactions, migrations, adapters | runtime, zix | implemented: the contract plus the Turso adapter at four tiers; the migration API the contract names is not in `src/data/root.zig` yet (`docs/modules/data.md`) |
| `domain` | Resources, typed actions, validation, authorization, relationships | data, runtime | implemented: `src/domain/{action,policy,validation}.zig` |
| `live` | Session state, events, components, render/patch, DOM protocol | runtime, zix | implemented: `src/live/{protocol,pubsub,tree,patch}.zig`; the session lifecycle is contract only (`docs/modules/live.md`) |
| `jobs` | Durable queues, schedules, retries, concurrency, cancellation | data, domain (action refs), runtime | implemented: `src/jobs/{root,runner,registry,cancel,retry,schema}.zig` (`docs/modules/jobs.md`) |
| `agents` | Signals, decisions, effects, checkpoints, durable execution | data, domain, jobs, runtime | declared |
| `app` | Config, routes, middleware, auth, lifecycle, telemetry; wires the rest | all of the above | declared |
| `dev` | Incremental builds, reload, diagnostics, tests, inspection | build system; not linked into release apps | declared |

The status column follows the `modules` table in `src/root.zig`, which is the
tree's own inventory (`zurtr modules` prints it), and it agrees with that table
in every row today: `runtime`, `data`, `domain`, `live` and `jobs` are
`.implemented`, `agents`, `app` and `dev` are `.declared` (`decisions.md` D7
closed the one row that disagreed). *Declared* means this tree has the contract
and no implementation; a module moves to *implemented* when its first real
surface lands — `jobs` did at `9ac4db6`.

**May import is a permission; the import graph in the tree is smaller.** The
only edge from one module in this table to another is `jobs` → `data`
(`@import("../data/root.zig")` in `src/jobs/root.zig`, which is where `Tx` and
the adapter's value types come from; `src/jobs/tests.zig` reaches
`../data/turso_adapter.zig` the same way). `runtime`, `data`, `domain` and
`live` import `std` and their own files and nothing else — not the module below
them, and not `zix`. Stated because the permission column reads like a
description: a module that has not earned a dependency has not paid for one, and
the arrow rule is review-enforced until the build enforces it.

Optional layers: `zscript` (QuickJS-ng, `docs/modules/zscript.md`) and `zeex`
(JSX lowered to Zig at build time by a script that runs inside that engine,
`src/zeex/`, `docs/modules/zeex.md`) sit beside the modules rather than in the
dependency order — nothing below them depends on them, and everything above them
can. `zscript` is behavior a host can replace without a native rebuild, and the
authority a script can reach is exactly the host functions the host registered;
`zeex` is a build-time lowering that leaves nothing of itself in the running
program — the generated file needs the framework and nothing else, and putting
that file where a build can import it is the caller's step today, not a framework
build step. Both are behind build options (`-Dzscript`, which `zeex` needs): the
base build contains neither.

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
counter increment, never a use-after-free. What the tree carries today is the
substrate for that, not the handle itself: `runtime.Completion`
(`src/runtime/pool.zig`) is a request token the pool keeps opaque
(`Completion.token`) plus a payload whose ownership transfers to the consumer,
and deriving `{connection, generation}` from the token is a session-level
consumer's job — there is no such consumer yet, because there is no session type
(`docs/modules/live.md`). What does not exist is a way to wake the `.EPOLL` /
`.URING` loops from another thread, so deferral is confined to `.ASYNC` for now;
a transport-level wake source is the open item (`decisions.md` D2).

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
| Recoverable error | Ends the operation; the surface decides (HTTP status, job retry, live event error message). May reset the session without affecting others — the client gets a full `resync` (`contracts.md` §6), which is the protocol's only reset frame. |
| Session corruption / invariant violation | Session is terminated and marked for resync; the worker keeps serving. |
| Panic, OOM, memory corruption | The process aborts: zix's workers are threads in one process (`workers` in the server config), and nothing in this tree supervises one. In-flight sessions on that worker are lost and resync on reconnect. |
| Isolation needed by the app | Run roles as separate supervised processes from the same executable, so a crash in one role does not take the others down. The shape this takes is `zurtr run --role=web\|jobs\|agents`, which no build serves yet — `src/main.zig` has `modules` and `new` — so today the split is a deployment decision, not a framework command. |

No BEAM-style per-entity preemptive isolation: stateful entities are not
individually supervised. Per-entity isolation requires a process boundary and
is therefore a deployment choice (role processes, or one process per shard).

## Build and development model

- Every module is a separate Zig module with explicit imports, so an application
  compiles only the modules it uses (unreferenced modules are never analyzed).
  This is the packaging **target**, not today's shape: `build.zig` wires four
  modules into the build — `zurtr` (rooted at `src/root.zig`), `zix`
  (`deps/zix/src/lib.zig`), and two framework-side modules that exist for
  reachability rather than packaging: `zscript` (`src/zscript/root.zig`) and
  `zigeval` (`tools/zigeval_listen.zig`) — with the vendored dependencies (zix,
  turso, quickjs-ng) and the CLI's parser (`deps/zig-clap`) arriving as modules
  too (`decisions.md` D9). `zscript` and `zigeval` cannot be relative imports
  from where they are used: a relative import cannot cross a module boundary,
  and ZEEX's compiler and the live editor both reach up from below the root.
- Tests are per-module steps rather than one binary, so a failure names the
  module it is in: `test-zurtr` (the framework root), `test-zix` (the vendored
  transport), `test-cli` (the generator — whose tests name `templ` explicitly,
  because an imported file's tests are only analysed when something names it),
  `test-data` / `test-data-nodes` (with `-Dturso`), `test-zscript`, `test-zeex`
  and `test-zeex-live` (with `-Dzscript`), and a `test` aggregate that runs
  whatever the build enabled. A test that needs a binding is compiled only when
  there is one — `src/jobs/root.zig` pulls in its database-backed tests behind
  `if (comptime @import("build_options").turso)`, so the same tree tests the
  queue's logic without the adapter and its storage with it.
- Build options are the framework's own and all default off: `-Dturso` /
  `-Dturso-sync` (the data adapter and its sync SDK Kit) and `-Dzscript` (the
  QuickJS layer and the `zeex` compiler that runs on it). zix has no build-time
  feature flags — its protocols, drivers and dispatch models are in-tree source,
  selected in configuration at run time — so the base build is the transport
  plus the framework and needs no external dependency beyond libc; the vendored
  zig-clap is Zig source and adds none.
- Dev loop (`dev` module is declared; two of its pieces exist): incremental
  compilation (`-fincremental --watch`), process replacement, browser reconnect
  with session snapshot transfer when compatible. Target: handler and component
  edits reach the browser in <1s, measured by a harness, on this workstation.
  What is built today is the template half:
  - `tools/zeex_live.zig` lowers a template on every save, detects a change by
    content rather than by metadata (the compiler's own incremental mode taught
    that lesson — size/mtime/inode comparisons serve stale results), and reports
    a rejected template with the transform's own line number.
  - `tools/zigeval_listen.zig` evaluates Zig expressions in a long-lived
    incremental compiler and takes a module graph, so the evaluated file can
    import `zurtr`. A preview still cannot *evaluate* the render path:
    `@intFromPtr` is not comptime-evaluable and the tree's arena writes a node
    header through a freshly allocated pointer. So a preview runs the code
    (`zig run`) instead of evaluating it — 0.20 s warm, 0.72 s after a change,
    against 1.8 ms to lower a template, which is a preview-on-save budget rather
    than a per-keystroke one.
- Release: static executable; release pins the exact Zig revision
  (`minimum_zig_version` in `build.zig.zon`) and the zix revision
  (`deps/zix`); `zurtr build --report` — which arrives with the modules it
  reports on, `src/main.zig` — will emit cold/warm build times, peak RSS,
  executable size, and the enabled protocol/module inventory.
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
- HTTP/2 (RFC 8441) WebSockets: HTTP/1.1 upgrade first. zix's own HTTP/1.1
  server serves WebSocket (`deps/zix/src/tcp/http1/websocket.zig`); the HTTP/2
  form of that upgrade exists only in zixer's edge bridge
  (`deps/zix/src/zixer/http2_ws_bridge.zig`), and the vendored HTTP/3 tree cites
  RFC 8441 as the extended-CONNECT reference `:protocol` follows
  (`deps/zix/src/udp/http3/h3.zig`), not as a WebSocket path. WebSocket is the
  documented fallback for the live channel and is what the generator emits — the
  generated app's live route upgrades through `zix.Http1.WebSocket.serve`
  (`src/scaffold/templates/app/src/main.zig.tpl`) — while a WebTransport-capable
  endpoint is still unbuilt and WebTransport remains the channel
  (`decisions.md` D3).
