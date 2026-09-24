# Module contract: Development (`zurtr.dev`)

Scope: the development loop, diagnostics, tests, and measurement. This module
is never linked into release applications.

Status: **declared** — read the status from `src/root.zig`'s `modules` table, which is
the inventory of record (`zurtr modules` prints it); this document is the contract the
module is held to, and the sections below are its design.

Three things in the tree today are this module's first real surface, and the sections that
describe them come before the design below: the executable's own commands (`src/main.zig`),
the project generator and the template engine it drives (`src/scaffold.zig`,
`src/templ.zig`), and two tools under `tools/` — the live editor's compiler half and the
build-time evaluator.

## Commands

The design:

```
zurtr dev                  # incremental watch + serve + reconnect
zurtr build [--report]     # release build; --report emits measurements
zurtr test [module...]     # module-scoped test runs
zurtr migrate [--status]   # apply/show migrations
zurtr inspect [sessions|jobs|agents|routes]
zurtr run --role=web|jobs|agents|all
```

What exists (`src/main.zig`, driven by the vendored zig-clap at `deps/zig-clap` — a
hand-rolled parser would be wrong in the ways hand-rolled parsers are wrong, a missing value
silently becoming an empty string among them):

```
zurtr modules              # the inventory this executable was built with
zurtr help                 # the same table clap renders for --help
zurtr new [--name <str>] [--dir <str>] [--force] [--no-data] [--no-live]
          [--zscript] [--no-hooks] [--install]
```

The flags say what they do to the scaffold: `--no-data` leaves out the persistence wiring,
`--no-live` the live route, `--zscript` adds the script seam (which costs a C toolchain and
a first build measured in minutes), `--no-hooks` skips the installer steps, and `--install`
includes the hooks that compile or fetch. The spellings are `--no-` rather than `--with-`
deliberately: the default scaffold is the one worth having, and a generator whose defaults
are wrong is a generator nobody reads the flags of.

## The project generator (`zurtr new`)

The recipe is not "write a whole project from scratch"; it is the toolchain's own work and then this
framework over the example (`src/scaffold.zig`): `zig init` in the target directory, `zig fetch
--save <this checkout>` for the dependency, the framework's templates laid over zig's example
(`build.zig`, `src/main.zig`, `.gitignore`, `README.md`), `src/root.zig` deleted because the library
half of the example is not an application, then the installer hooks.

Two things fall out of letting the toolchain do its own work, and both were blockers found by reading
the compiler rather than by trying harder: `build.zig.zon` is zig's, including the `.fingerprint` it
validates against a CRC of the project name — a value no scaffolder can hardcode, because the field
takes only an integer literal and the value depends on the name — and the dependency entry is written
by the tool that knows the format, including the relative-path restriction the zon enforces.

The manifest is **data, not a procedure**: `entries` and `hooks` say which files a scaffold contains,
under which condition (`.always`, `.data`, `.live`, `.zscript`), and which steps run afterwards.
`planned`/`installers` are pure functions over that plan, so composition is testable without a
filesystem, and `--no-live` does not remove a file from the manifest — it stops the entries whose
condition is `.live` from being written. The templates themselves are `@embedFile`d, so a missing
`.tpl` is a compile error rather than a run-time surprise, and `build.zig.zon` is deliberately absent
from the manifest: zig writes it, and templating it here would be a second source of truth.

Two things the executable carries from its own build, because neither can be discovered at run time
(`build.zig`, `src/main.zig`): **where this checkout is**, since the generated project lives somewhere
else on disk and the zon wants a path relative to *it*, and **which compiler to drive**, because a
`zig` on PATH may be a launcher shim that cannot resolve a version in an empty directory — a failure
that would read as the generator's. `cli_options.zurtr_source_path` is checked for absoluteness at
file scope in `src/main.zig`, and that placement is load-bearing: `zig build` builds that executable
and never runs its tests, so the same guard inside a `test` block would compile and never fire, which
is what the first version of it did.

`--install` gates the hooks that compile or fetch: a project's first build compiles this framework,
the vendored transport and — when asked for — a JavaScript engine, so a generator that appears to
hang is worse than one that prints the command to run next. Verified end to end at `cf22a13`:
`zurtr new hello`, `zig build`, `zig build run` opens the file-tier database and answers `GET /` with
200 — the route that answers it is in `src/scaffold/templates/app/src/main.zig.tpl`.

## The template engine (`src/templ.zig`)

The templates are nearly source, so the language is deliberately small: `{{name}}` substitutes a
value, `{{#if flag}}`/`{{#unless flag}}` include or drop a block, blocks nest, and everything else is
text.

What the engine does with a mistake is the point of it. A generator that answers `{{typo}}` with an
empty string writes `pub const app_name = "";` into a project that otherwise looks finished, and its
user finds out inside generated code at the first build, with nothing pointing back at the template.
So a name nothing binds is an error, a flag written as a substitution is an error, a value written as
a condition is an error, and each is reported with the line, the tag, and the source line with a caret
under the column (`templ.Diagnostic.write`). `bindings` is the single declaration of the name space:
`Params.lookup` resolves against it and an unknown-name message lists it, so a name added there cannot
be missing from the message about a typo in another.

Two properties the scanner keeps, and both are the kind a later simplification would quietly break: a
**substituted value is never scanned again** (a project named `{{weird}}` generates code that says
`{{weird}}`; no part of a value can open a block, end a tag early, or become a name), and **text is
copied rather than escaped** (a template with no placeholders yields its source byte for byte).
Rendering is one pass into one allocating writer — no string per substitution, no intermediate output
— and blocks nest to `max_depth = 32`, past which the template is refused rather than recursed into.

## The live editor's compiler half (`tools/zeex_live.zig`)

```
zig build zeex-live -Dzscript=true -- path/to/template.jsx          # lower on every save
zig build zeex-live -Dzscript=true -- --once path/to/template.jsx   # one pass, exit code on a rejection
```

It reads the template, lowers it with `zurtr.zeex.compile_template`, and reports either the Zig it
produced or the line the transform refused. `--once` is the scriptable mode — a template it cannot
read is an exit code, not a loop — and in the watch loop a rejection is normal (you are mid-keystroke),
so it is reported and the loop continues. Three things it learned the hard way, each stated at the top
of the file:

- **Changes are detected by content hash, not by metadata.** Size/mtime/inode comparisons serve stale
  results — the compiler's own incremental mode is where that was learned — and an editor doing the
  same would show the previous render of the line that was just fixed.
- **The engine's first call is expensive, so it happens at startup.** One small template is lowered
  before the first file is read and its cost is reported, so the first keystroke never pays it; the
  first lowering is about ten times a steady one, and a steady lowering is ~1.8 ms.
- **Every report is flushed as it is produced.** A watch loop never returns, so a deferred flush would
  never run — and the first time this was started, the tool printed nothing at all in the mode it
  exists for.

## The build-time evaluator (`tools/zigeval_listen.zig`)

Not a build step and not a test root: a standalone tool, `std` only, that drives one long-lived
`zig build-obj -fno-emit-bin -fincremental --listen=-` compiler and evaluates expressions at comptime.
It is declared as a module (`zigeval`, `build.zig`) because its one consumer imports it rather than
reaching across a directory, and `zig run tools/zigeval_listen.zig` is its self-test plus timings —
which exits non-zero on any failure. The compiler behaviours it depends on are listed in its header and
each is exercised by that self-test, so a rebase that changes the framing, the error-bundle message, or
incremental change detection fails loudly instead of silently.

Three of those behaviours explain the rest of its shape. Every eval rewrites the scratch file through a
temp file and a rename, because incremental change detection is metadata only (size, mtime in ns,
inode) and a same-size rewrite inside one mtime tick would be served the previous result; every eval
logs a nonce first, and a result carrying any other nonce is rejected as stale; and the evaluator
passes `-j1`, because the compiler sizes its worker pool from the CPU affinity mask while one
expression is one unit of work (unpinned, ten same-size evals: 102 ms with the default pool, 26 ms with
`-j1`).

### What it can and cannot evaluate

The evaluator's real limits are known rather than suspected:

- **It evaluates `std`-only expressions.** The scratch file is a standalone `build-obj`, so a prelude
  cannot import `zurtr` — unless the caller supplies a module graph, which `Options.root_deps` and
  `Options.modules` allow (`--dep zurtr -Mzurtr=<absolute src/root.zig>`, absolute because the
  evaluator's work directory is not the build root). Two fields rather than one argument list because
  of the compiler's own grammar: `--dep` attaches to the *next* module and the first `-M` is the main
  module, so the root's imports have to be declared before the root and every other module after it.
- **Comptime evaluation cannot run the render path at all, module graph or no module graph.**
  `@intFromPtr` is not comptime-evaluable, which is every allocator in the standard library
  (`FixedBufferAllocator.alloc` aligns through it), and the render tree's arena loses even with a
  comptime-safe child allocator, because it writes a node header through a freshly allocated pointer.
  The compiler reports both; no module graph fixes either, because the value would have to come from
  *running* the code rather than evaluating it.

So a preview runs the code: `zig run` with the same module graph, measured at 0.20 s warm and 0.72 s
after a source change (cold 0.73 s), against the 1.8 ms this tool spends lowering a template. That is a
preview-on-save budget, not a per-keystroke one, and choosing between it and a compile-errors-only
preview is a decision rather than a wiring detail.

## Development loop

- `zurtr dev` runs the build with `-fincremental --watch` (Zig master's
  incremental pipeline; the new ELF linker is enabled where it applies because
  it is the fast incremental path on x86_64 Linux) and, on each successful
  build, replaces the running process and lets the browser reconnect.
- **Edit-to-browser**: handler/component source edits are compiled
  incrementally and the affected application code is re-linked into a restarted
  process. The browser reattaches automatically: the client keeps its socket
  and, on `resync`, replaces the DOM from the server. Where the session state
  is serializable and the state version matches, the dev server transfers a
  **session snapshot** (serialized bytes, per `contracts.md` §2) to the new
  process and resumes the session instead of resetting it.
- **Latency harness**: `zurtr dev --measure` instruments the loop: it records
  `t_edit` (file mtime change), `t_build` (watch build completion), `t_serve`
  (new process accepting), and `t_paint` (client patch applied; measured by a
  dev-only client beacon over the live socket). It reports per-phase and
  total edit-to-DOM times for a scripted edit (a handler change and a component
  change) and fails with non-zero status if the total exceeds the configured
  target (default 1000 ms). The harness writes `measurements/dev-latency.json`.
- Native module reload (dlopen-based hot swap) is explicitly not part of v1;
  it requires an ABI and state-migration rules that are not yet designed. The
  incremental process-replacement path is the supported fast loop.

## Build report

`zurtr build --release --report` prints and writes `measurements/build-report.json`:

- cold build wall time (empty cache), warm build wall time (one no-op edit),
- peak RSS of the build, executable size (stripped, release),
- enabled zix protocols/features (dispatch model, TLS, HTTP/3, WebTransport) and
  the framework build options, with the list of compiled zurtr modules,
- external runtime dependencies (a database when the data module is built; no
  OpenSSL — zix carries a Zig TLS implementation) — explicitly separated from
  the executable's own dependency set.

The report is generated by measuring real commands on this workstation
(declared hardware), not estimated.

## Diagnostics

- Dev-only HTTP endpoints and a CLI overlay: session tree (live sessions,
  their state version, queue depth), job queue state (per state + oldest
  ready), agent runs, route table, and migration status.
- Compile errors surface in the dev console and as an overlay in the browser
  (the client keeps the last good DOM and shows the error panel).
- Panics in the dev process keep the terminal scrollback and print the
  request/session context; the process restarts on the next successful build.

## Tests

- `zurtr test` maps to module-scoped Zig test steps; only the modules named are
  compiled, so a one-module edit rebuilds one test binary. The steps in this tree
  (`build.zig`): `test-zurtr`, `test-zix` and `test-cli` unconditionally, `test-data`
  and `test-data-nodes` with `-Dturso=true`, and `test-zscript`, `test-zeex` and
  `test-zeex-live` with `-Dzscript=true`. `zig build test` is the aggregate of all of
  them except `test-cli`, which is reachable only by name; `zeex-live` is a step of its
  own too, because it installs a tool rather than running tests.
- Integration tests that need a database run only for builds that have an
  adapter; there is no `ZURTR_DB_URL` in this tree, and the data module's tier
  tests are the ones that touch storage (`docs/modules/data.md`).
- The end-to-end slice suite (`apps/slice`) is run by
  `zurtr test --e2e`: it boots the demo app on an ephemeral port with a
  temporary database, drives the browser-facing protocol over the live channel
  (WebTransport, the documented WebSocket fallback — `decisions.md` D3), and
  asserts each acceptance check from `overview.md` §The slice. Neither the suite
  nor the application exists yet (`apps/slice/SPEC.md`).

### Test roots, and when a module needs its own step

A Zig import cannot cross a module's path, so a file that imports a sibling
module cannot be the root of its own test step. Which fix applies is decided by
what the dependency *means*, not by which one compiles:

| Situation | Fix | Because |
| :- | :- | :- |
| the dependency is conditional (`src/jobs/tests.zig` imports `../data/root.zig`) | gate it through the parent module: `if (comptime @import("build_options").turso) _ = @import("tests.zig");` in the module's root | the gate carries meaning: a database-backed test must not run without a database, and must not be compiled with no binding to link |
| the dependency is an accident (`src/zeex/compile.zig` reaching `../zscript/root.zig`) | promote it to a named module, as `zix`, `quickjs` and `turso` already are | there is nothing to gate on, so the fix removes an accident rather than encoding a decision |
| the file is outside the framework module (`src/scaffold.zig`, `src/templ.zig`, `tools/zeex_live.zig`) | give it a test root of its own: `test-cli`, `test-zeex-live` | the framework module is rooted at `src/root.zig`, so neither generator file is part of it and nothing under `tools/` can reach `src/` by a relative path |
| the file needs `std` and nothing else (`tools/zigeval_listen.zig`) | no step at all: `zig run tools/zigeval_listen.zig` is its self-test | there is no module graph to break and nothing in the framework imports it, so a step would exist only to run it |

The consequences are the point of the rule. `jobs` needs no `test-jobs` step:
`zurtr.jobs` reached through the root, with its tests behind the gate, *is* the
design, and a second step would be a second path to the same tests. `zeex` did
need `test-zeex` (`build.zig`), and could only have it once `zscript` was a named
module rather than a relative path.

The generator's two files are the same rule from the other direction: `src/scaffold.zig` and
`src/templ.zig` are not part of the framework module, so their tests cannot ride in `test-zurtr` —
`test-cli` is the step that reaches them, and it was written before the renderer it names, because a
test nobody runs is a comment. `tools/zeex_live.zig` is outside for a second reason as well: a `tools/`
root cannot reach `src/` by a relative path, so it imports `zurtr` and `zigeval` as **named modules**
and gets `test-zeex-live`. The evaluator needs neither, because it is `std`-only and standalone: its
self-test is `zig run tools/zigeval_listen.zig`, and a build step would exist only to run tests nothing
else depends on.

One inclusion rule follows from all of this, and is easy to be wrong about: a file's tests are in a
test binary only if that binary's root reaches the file. `src/root.zig`'s test block names
`runtime.pool`, `runtime.mpmc` and `runtime.task` for exactly that reason — `test-zurtr` runs their
tests because the root references them, not because they are under `src/`. And a step is not a
reference: the template engine's suite sat inside `test-cli` without running until
`src/scaffold.zig`'s test block named it, which is why that reference is written down in
`scaffold.zig` with the reason attached rather than left as an import.

## Testing requirements (meta)

- The dev loop must be measured by the harness in CI-equivalent form on this
  machine before the latency claim is made; the claim is never asserted without
  the JSON artifact.
- **A count is not evidence of provenance.** `git diff --stat` reporting `+34`
  where a change was expected says how many lines moved, not which ones or why —
  the same shape as reading a test count as proof that a test ran or that the
  right file changed. Read the lines before attributing the number.
- `zurtr dev` must not modify source files, and must leave the repository clean
  (no generated files outside `zig-out/`, `.zig-cache/`, and `measurements/`).
