# zurtr

A native application framework in Zig, built on the vendored [zix](https://github.com/mattneel/zix)
transport. Live UI, typed domain actions, durable background work, agent workflows, and
persistence — applications are ordinary Zig and deploy as one static executable.

Status: initial design. **Five of the eight modules have implementations; three have contracts and
no code yet**, and two optional layers sit beside the modules. The module table in `src/root.zig`
is the tree's own inventory — `zurtr modules` prints it — and this file follows it rather than
aspirations.

## What it is

zurtr provides stateful server-rendered interfaces (**Live UI**), typed domain actions
(**Domain**), durable background work (**Jobs**), agent workflows (**Agents**), persistence
(**Data**), the application assembly layer (**Application**), and a development loop
(**Development**) — on top of zix's HTTP/1.1 and HTTP/3 on one origin, WebTransport, and its
in-tree drivers (`postgrez`, `rediz`, `prometheuz`).

## Modules

| Module | Responsibility | Status |
| --- | --- | --- |
| `runtime` | Worker pool with work stealing and completion delivery, a bounded lock-free MPMC queue, a structured-task layer | implemented |
| `data` | Queries, transactions, migrations, adapters | implemented: contract + Turso adapter at four tiers (memory, file, sync, distributed) |
| `domain` | Resources, typed actions, validation, authorization, relationships | implemented |
| `live` | Session state, events, components, render/patch, DOM protocol | implemented |
| `jobs` | Durable queues, schedules, retries, concurrency, cancellation | implemented |
| `agents` | Signals, decisions, effects, checkpoints, durable execution | declared |
| `app` | Config, routes, middleware, auth, lifecycle, telemetry; wires the rest | declared |
| `dev` | Incremental builds, reload, diagnostics, tests, inspection | declared |

*Declared* means the tree has the contract and no implementation. Dependency arrows point downward
only: `live` core never imports `domain`, and the glue that binds live events to domain actions
lives in `app`, so Live UI is usable without Domain and Domain without Live UI.

## Optional layers

Both are behind build options; the base build contains neither.

- **ZScript** (`-Dzscript`) — the QuickJS-ng seam at `src/zscript/`. Behavior the host can replace
  without a native rebuild, where the authority a script reaches is exactly the host functions the
  host registered. See `docs/modules/zscript.md`.
- **ZEEX** (`-Dzscript`) — JSX lowered to Zig at build time by a script the build runs, at
  `src/zeex/`. Leaves nothing of itself in the running program, and generates `props: anytype` so a
  name the caller's struct lacks is a compile error at the call site rather than a blank spot on a
  page. See `docs/modules/zeex.md`, and `tools/zeex_live.zig` for the editor half.

## Build and test

Zig 0.16.x or 0.17.x.

```sh
zig build                                        # the framework and the `zurtr` executable
zig build test-zurtr -Dzscript=true              # zurtr's own tests, engine included
zig build test-zurtr -Dturso=true                # adds the jobs/adapter-backed tests (95 at time of writing)
zig build test -Dturso=true                      # everything: zurtr, zix, data, nodes, zscript, zeex
zig build test-zix                               # the vendored transport's suite (2749 tests)
zig build test-zeex -Dzscript=true               # lowers a template and parses the generated Zig
zig build test-zscript                           # the script layer against the engine
```

Without `-Dturso`, the adapter-backed tests are not compiled at all — unit tests never require a
database. Without `-Dzscript`, neither optional layer is in the build and `zurtr.zeex` is an empty
struct.

The live editor's compiler half is a tool, installed by the build:

```sh
zig build install -Dzscript=true
./zig-out/bin/zeex-live path/to/template.jsx          # lower on every save
./zig-out/bin/zeex-live --once path/to/template.jsx   # one pass, non-zero exit on a rejection
```

## Documentation

- `docs/architecture/overview.md` — module boundaries and execution semantics, normative
- `docs/architecture/contracts.md` — the rules modules hold each other to
- `docs/architecture/decisions.md` — why the shape is the shape
- `docs/modules/` — one contract per module and per optional layer

## The transport

zurtr does not implement HTTP. It vendors zix at `deps/zix` and pins it; `deps/zix/UPSTREAM.md`
records where it came from. The TLS crash fixed on 2026-09-23 exists in both trees.

## Funding

See `.github/FUNDING.yml`.
