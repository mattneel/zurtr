# zurtr

A native application framework in Zig, built on the vendored [zix](https://github.com/mattneel/zix)
transport. Live UI, typed domain actions, durable background work, agent workflows, and
persistence — applications are ordinary Zig and deploy as one static executable.

**Documentation: https://mattneel.github.io/zurtr/** — the `docs/` tree as a book, with search.

Status: initial design. **Five of the eight modules have implementations; three have contracts and
no code yet**, and two optional layers sit beside the modules. The module table in `src/root.zig`
is the tree's own inventory — `zurtr modules` prints it — and this file follows it rather than
aspirations.

## Generate an application

```sh
zig build install -Dzscript=true     # installs `zurtr` and `zeex-live` into zig-out/bin
./zig-out/bin/zurtr new blog
cd blog && zig build run
```

That produces a working application: it opens a file-tier database, registers a live channel, and
serves a page. `zurtr new` does it the way the toolchain does rather than writing a project from
scratch — `zig init`, then `zig fetch --save` for the dependency, then this framework's template
over the example:

- **`build.zig.zon` is zig's**, because its `.fingerprint` is validated as a packed `u64` carrying
  a CRC of the project name, and a zon accepts only an integer literal. No scaffolder can hardcode
  it, and `zig init` writes a correct one.
- **The dependency is `zig fetch --save`'s**, which knows the format — including the rule that a
  path dependency must be relative to the project, which an absolute path fails outright.

The flags are the scaffold's shape, not decoration:

| | |
|---|---|
| `--name`, `--dir` | what to call it and where to put it |
| `--no-data`, `--no-live` | leave out the persistence wiring or the live route |
| `--zscript` | include the script seam (costs a C toolchain and a slow first build) |
| `--no-hooks`, `--install` | skip the installer steps, or include the one that compiles |

Templates are rendered by `src/templ.zig` — substitution, `{{#if}}`/`{{#unless}}` with nesting, and
unknown names as errors rather than empty strings. Installer hooks run in the new project
afterwards: `git init` by default, the first build only with `--install`, because an application's
first build compiles this framework, the vendored transport and — when asked for — a JavaScript
engine.

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
  host registered.
- **ZEEX** (`-Dzscript`) — JSX lowered to Zig at build time by a script the build runs. Leaves
  nothing of itself in the running program, and generates `props: anytype` so a name the caller's
  struct lacks is a compile error at the call site rather than a blank spot on a page.

## Tools

- **`zeex-live`** — the live editor's compiler half. Lowers a template on every save and prints the
  Zig it produced or the line it rejected, detecting changes by content hash rather than file
  metadata, because metadata is how a same-size edit inside one timestamp tick serves the previous
  answer. `zig build install -Dzscript=true` puts it in `zig-out/bin`.
- **`tools/zigeval_listen.zig`** — a build-time evaluator: one long-lived
  `zig build-obj -fincremental --listen=-` process, an expression per evaluation, and the
  compiler's own printed value back. It evaluates `std`-only expressions, and comptime evaluation
  cannot run the render path at all — `@intFromPtr` is not comptime-evaluable, and the render tree
  is arena-built. A preview therefore runs the code rather than evaluating it.

## Build and test

Zig 0.16.x or 0.17.x.

```sh
zig build                                              # framework, `zurtr` executable, `zeex-live`
zig build test                                         # zurtr, zix, and whichever modules are in the build
zig build test-zurtr -Dzscript=true                    # 88 tests, 1 skipped (a deliberate reproduction)
zig build test -Dturso=true                            # everything: 2867 tests, 2 skipped
zig build test-cli                                     # the generator's plan and the template engine
zig build test-zix                                     # the vendored transport
```

**The optional steps do not exist without their flags.** `zig build --list-steps` shows four steps
in a base build and nine with `-Dzscript=true -Dturso=true`: `test-data`, `test-data-nodes`,
`test-zscript`, `test-zeex` and `test-zeex-live` are created only when the thing they test is
compiled in. Without `-Dturso` the adapter-backed tests are not compiled at all — unit tests never
require a database — and without `-Dzscript`, `zurtr.zeex` is an empty struct.

## Documentation

- https://mattneel.github.io/zurtr/ — the book, built from `docs/` by `book.toml` and deployed by
  `.github/workflows/docs.yml`
- `docs/architecture/overview.md` — module boundaries and execution semantics, normative
- `docs/architecture/contracts.md` — the rules modules hold each other to
- `docs/architecture/decisions.md` — why the shape is the shape
- `docs/modules/` — one contract per module and per optional layer
- `mdbook serve` — the book locally, live-reloading

## The transport

zurtr does not implement HTTP. It vendors zix at `deps/zix` and pins it; `deps/zix/UPSTREAM.md`
records where it came from. The vendored copy carries a fix that both trees needed: the handshake
was handed a slice of a temporary, which panicked in Debug and would have read a plausible wrong
length in Release.

## Funding

See `.github/FUNDING.yml`.
