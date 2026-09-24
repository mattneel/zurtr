# zurtr — repository guidelines

## Look at the sibling projects first

**Before designing anything, look in `~/src` for the project that already does it.** The user owns
years of work there and a standing instruction: *if you ever have a question, defer to how it is
done in those projects.*

This section is first because that rule was stated and then ignored. `zdl` had been sitting in
`~/src` for eight months — with migrations, schema evolution, Ecto-style changesets and generators
for C, Python and TypeScript — while several of those things were being designed from scratch in
conversation. Check first; the answer is usually already built and better.

- **`~/src/paydaemon`** — Phoenix 1.8.14 / LiveView 1.2 on an Ash kernel. The reference for
  *application-level* conventions: how a live app is laid out, what belongs in a hook versus a
  server event, how assets are built and served.
- **`~/src/zdl`** — Zero Data Layer. Serialization, schema evolution, migrations, changesets,
  zero-copy queries, mutable containers with generation-fenced views, and generators for C, Python
  and TypeScript. Zero dependencies.
- **`~/src/zault`** — post-quantum encrypted storage and secure P2P messaging: **ML-KEM-768**,
  **ML-DSA-65**, ChaCha20-Poly1305, zero-knowledge key handling, a CLI, a C header, a PWA at
  `zault.chat`, and its own book. If a question is about cryptography, secrets, identity, signing or
  key agreement, read it before writing anything — `std.crypto` ships `ml_dsa`, `ml_kem` and
  `hybrid_kem`, and this project has already decided how to use them.
- **`~/src/zix`** — the transport, vendored here at `deps/zix`.
- Everything this tree depends on is **vendored at `deps/` with an `UPSTREAM.md`**. Nothing is
  fetched, so `zig build` works offline and a dependency cannot change under a user.
- **Smoke-testing a model call:** three routes, cheapest first. Prefer the early ones for anything
  repetitive, and treat the last as a last resort.
  1. **Codex CLI** for OpenAI coding models and **Claude Code** for Anthropic models — Max
     subscriptions, so no metered cost. `~/src/quire` wraps the Codex app-server if a reference for
     driving it is useful.
  2. **DeepSeek direct** (`deepseek-v4-flash`, `deepseek-v4-pro`) and **OpenRouter** — metered and
     cheap, approved for spend.
  3. **OpenAI and Anthropic APIs directly** — enterprise pricing. Only in tiny doses, on the small
     models (the Luna class and the latest Haiku).
  `~/.omp/agent/models.yml` is the authority on model ids, base URLs and per-model quirks, and it is
  worth reading before describing any provider: it already carries the exact compat flags each needs —
  reasoning-effort mapping, `max_tokens` versus `max_completion_tokens`, tool-choice support,
  developer-role support. Guessing those from memory wastes calls.
- Keys live in `~/src/rctr/.env` (mode `600`, gitignored) or in the agent config above. **Never copy a
  credential into this tree**, and never print one into a report.

**Almost every layer zurtr integrates already exists as a sibling.** `gh repo list mattneel` is
one call and lists them all; do that before designing anything, and before spawning an agent to go
read sixty directories.

| zurtr's layer | the sibling that already does it |
|---|---|
| transport | **`zix`** — vendored at `deps/zix` |
| data, schema, migrations, codegen | **`zdl`** — Zero Data Layer |
| crypto, secrets, identity, signing | **`zault`** — ML-KEM-768, ML-DSA-65, zero-knowledge |
| the JavaScript sandbox (`zscript`) | **`zig-quickjs-ng`** — Zig build and bindings for quickjs-ng |
| agents, models, tool calling | **`ai.zig`**, **`pi.zig`** ("Pi agent semantics. Zig runtime. One binary."), **`jzs`** ("next generation agent substrate") |
| actors, exactly | **`zacto`** |
| simulation, determinism, forking | **`gkz`** — "a deterministic, fully observable, forkable simulation kernel in Zig", with its own authoring skill |
| WASM translation | **`fizh`** |
| terminal rendering (`zeex` is a TUI) | **`tuizr`**, **`opentui`** |
| the SQL tier | **`turso.zig`** — ownership-safe bindings for Turso's C ABI, which is what the `data` contract is written against |
| build and release automation | **`setup-anyzig`**, `scaffold` |

Known and already read: `zix`, `zdl`, `zault`, `paydaemon`, `gkz`. The rest of the table is from
repository descriptions, not from reading them — check the source before relying on a detail.

**The Elixir side is the same architecture, already shipped.** `entwurfswerk` and `paydaemon` are
both Phoenix applications where durable state goes through Ash actions and events reach the browser
over Phoenix Channels; their conventions are the ones zurtr is converging on.

| zurtr's layer | the Elixir sibling that already ships it |
|---|---|
| `domain` — typed actions, policy, validation | **Ash**, via `paydaemon` and `entwurfswerk`: *"every durable change goes through an Ash action"* |
| `signals` | **Jido** — `entwurfswerk`: *"Jido Signal Bus carries internal events; Phoenix Channels carry them to the browser"* |
| `live` | **Phoenix LiveView** (`paydaemon` for the hook contract and the `JS.*` / server-event split) |
| `zscript` — the JavaScript tier | **`quickjs_ex`** — QuickJS-NG embedded through Zig NIFs, with its ownership rules written down |
| local storage and vector search | **`ex_lancedb`** — embedded LanceDB via Rustler, *"without a sidecar service"* |
| one static executable | **Burrito** and ExTauri, as `entwurfswerk` builds it |
| agent providers and browser actions | **`req_llm`** and **`jido_browser`**, both under the Jido organisation |

**`quickjs_ex` is the honest documentation of the JavaScript tier**, and two of its lines are
corrections to assumptions worth not repeating: *"It is not an OS sandbox; do not treat it as
isolation for adversarial JavaScript without an outer process, container, VM, or similar boundary"*,
and gas accounting *"measure[s] JavaScript execution time, not time parked on a host callback"*. Its
context model — one dedicated OS thread per `JSRuntime`, calls enqueued to that thread, a
`:not_owner` error from any other process, `:context_busy` on re-entry, and retained handles
*poisoned* when the owning process dies — is the semantics `zscript` should implement.

**These are kernels, and the pattern is consistent.** `gkz`, `zacto` and zurtr are the same species:
a pure step function over a value, with determinism as a contract rather than a hope.

- `gkz`: `step : (State, Input) -> State`, where `State` is *"serializable, content-hashable,
  diffable"* — so *"record/replay, time-travel, forks and divergence detection are corollaries, not
  separate features."* Its lineage is named: TigerBeetle, Elm/Redux, rr. Its determinism rules
  (D1–D9) include *no floating point on any sim path* (integers, or `fpz` fixed point), *no clock,
  no syscall, no ambient RNG inside `step`* — randomness is a keyed pure function, not a cursor —
  and *no pointers in hashed state*. Rendering is a one-way view seam that reads snapshots.
- `zacto`: `turn : (State, Envelope) -> (State', Effects) | Error`, effects executed only after the
  turn commits, so a failed turn has neither effects nor state change. `SPEC.md` is 52 numbered
  clauses, each mapped to its conformance test, with provenance in an appendix and the roadmap
  labelled `NOT NORMATIVE`.

Two consequences for writing code here. **The library is the interface** — `gkz` says it directly:
*"an agent that can write and run code does not need a remote-control surface."* And **prove the
contract**: zurtr's `docs/modules/` contracts are prose, where `zacto` maps clause to test and `gkz`
numbers its determinism rules. Match that when a module's behaviour is what matters.

**The toolchain is Zig++, not upstream Zig.** The pinned compiler serves
`0.17.0-dev.2264+230c63650`, which does **not** exist on ziglang.org — searching for it there
returns 404, and the conclusion that the pin is broken is the wrong one. It comes from
`mattneel/zigpp`, a fork that changes `std.lang.Type`; its README states plainly that upstream Zig
binaries can no longer build it. So when a compiler error here looks like an upstream version
change, it may be *this fork's* change instead: read `~/src/zig/zig` before theorising, and do not
assume a fix that works against released Zig will apply.

**Porting a dependency.** Four trees have now gone through it — `zdl`, `zgpu`, `zpool`, and
`deps/quickjs-ng` before them. The mechanical breaks are quick; the two semantic ones are not, and
they fail as *wrong behaviour* rather than compile errors.

| what | 0.17 shape |
|---|---|
| `[_]T{x} ** N` | **parse error** — a whitespace-symmetry rule, so it fires merely by loading the file. Rewrite as `@splat(x)`, which removes the question; add an explicit array type when the result location doesn't provide one. |
| `std.meta.fields(T)` | **hard `@compileError`**. Use `@typeInfo(T).@"struct"` and zip `field_names` / `field_types` / `field_attrs`. |
| `@typeInfo(T).@"enum".fields` | also columnar now — the field is **`field_names`** (with `field_values` and `decl_names` beside it), and `lang.Type.Enum` is documented as kept in sync with the compiler, so read it rather than guessing. Hit in `zglfw`, `zdl` and `zpool`. |
| `std.builtin.Type.StructField` | **gone.** Any signature taking a field descriptor must take something else — a `Column` enum, a name, an index. |
| `@hasDecl` | **only reports *public* declarations now.** Silent: it compiles and fails at runtime, so a test fixture's private hook needs `pub`. This one cost nine failing tests in `zpool`; expect the same in anything that dispatches on declarations. |
| `std.meta.declarations()` | returns *names* (`[]const [:0]const u8`), not field descriptors. |
| `@cImport` | **removed.** A `translate-c` step over the header produces a module to `@import`. |
| `extern enum` | **a compile error:** *"enums do not support packed or extern"*. C enums from a header become `enum(c_int)` with members listed in the header's own order so the implicit values match. |
| `std.meta.intToEnum` | gone → `std.enums.fromInt(...) orelse ...`, which returns an optional, not an error union. |
| `std.meta.Int` | gone → `@Int(.unsigned, bits)`. |
| `Fn.params` | → `param_types`. |
| `field.defaultValue()` | → `attrs.defaultValue(FieldType)`. |
| `std.hash.crc.Crc32` | renamed in the regenerated CRC catalog. |

When porting a vendored dependency, **check the source for these before debugging the errors** — and
after it compiles, run its own test suite, because the `@hasDecl` class will not announce itself.

## Structure

- `src/<module>/` — one directory per module, each with a `root.zig`; `src/root.zig` is the
  inventory and the only place the public surface is assembled. `zurtr modules` prints it.
- `docs/architecture/` — `overview.md` (boundaries and execution semantics, normative),
  `contracts.md` (the rules modules hold each other to), `decisions.md` (why the shape is the
  shape). `docs/modules/` holds one contract per module.
- `docs/` is also an mdBook: `book.toml`, `docs/SUMMARY.md`, deployed by
  `.github/workflows/docs.yml`. `mdbook serve` for a live copy.
- `client/` — the browser half as a TypeScript project (tsdown), built to `assets/zurtr_live.js`.
- `tools/` — `zigeval_listen.zig` (the build-time evaluator), `zeex_live.zig` (the editor's
  compiler half).
- `deps/` — vendored dependencies. `assets/` — what the server serves.

## Commands

```sh
zig build                                  # framework, `zurtr`, `zeex-live`
zig build test                             # zurtr, zix, and whichever modules are compiled in
zig build test-zurtr -Dzscript=true        # 88 tests, 1 skipped (a deliberate reproduction)
zig build test -Dturso=true                # everything: the aggregate
zig build test-cli                         # the generator and the template engine
zig build test-zix                         # the vendored transport alone
mdbook serve                               # the documentation, live-reloading
cd client && bun run build                 # the live client (see the warning in its commit)
```

**The optional steps do not exist without their flags.** `zig build --list-steps` shows four steps
in a base build and nine with `-Dzscript=true -Dturso=true`. Without `-Dturso` the adapter-backed
tests are not compiled at all; without `-Dzscript`, `zurtr.zeex` is an empty struct.

## Conventions learned the hard way

Each of these cost someone an afternoon. They are here so it is not two afternoons.

- **`zig build` never runs tests.** A `comptime` guard inside a `test` block compiles and never
  fires. Put guards at file scope so the build itself fails.
- **An imported file's tests do not run unless something analysed names it.** `src/templ.zig` had
  fourteen tests that had never executed; a `_ = templ;` in the importing file's test block fixed
  it. If you add a module, check the test count moves.
- **A missing build dependency is invisible.** `zig build test` omitted `test-cli` and reported
  "all steps succeeded" either way — the step *count* is the only evidence.
- **Change detection by metadata serves stale results.** The compiler's incremental mode compares
  size, mtime and inode, so a same-size rewrite inside one timestamp tick returns the previous
  answer. Compare content hashes, as `tools/zeex_live.zig` does.
- **A slice of a temporary outlives its storage.** `&.{x}` built inside a function and returned
  panics in Debug and returns a plausible wrong length in Release. If a slice must outlive the call
  that builds it, the `Context`/struct owns it.
- **A NUL sentinel is the contract even when a length is passed.** QuickJS's `JS_Eval` scans for
  `\0` while taking a length, as does the binding above it. Three layers of this stack have been
  caught by it, and every failure looked like a plausible wrong answer rather than an error.
- **`git add <file>` does not clear the index.** Check `git diff --cached --stat` before every
  commit, and stage with explicit paths. This has bitten the team five times, including the person
  who wrote the rule.
- **Test scaffolding hides defects.** An arena frees what the adapter forgot; a test harness that
  compares microseconds to milliseconds passes whatever it is given. Ask what the scaffolding makes
  invisible, and assert the premise (`kill(pid, 0)`, not the row that claims the process is alive).
- **A plausible version string is not a version.** `.minimum_zig_version = "0.17.0"` sends anyzig
  looking for `zig-x86_64-linux-0.17.0.tar.xz`, which 404s — 0.17.0 has not been released. Pin the
  exact dev build: `0.17.0-dev.2264+230c63650`. This has broken the build in `deps/quickjs-ng` and
  then again in `zdl`; when a tree stops building for no clear reason, read its pin before its code.
- **A verification that ran before the last commit is not a verification.** zdl's port measured
  111/111 passing and then landed one more commit changing the toolchain pin — so the green result
  described a state that never existed in history. Run the gate against what you are about to
  commit, not what you had a moment ago.
- **A path dependency cannot escape its package root.** A vendored package's `build.zig.zon` must
  point at something beneath itself (`libs/zpool`), never up and out (`../zpool`). This is why
  `zgpu` carries its patched `zpool` inside `deps/zgpu/` rather than sharing zurtr's `deps/`.
- **Watch it fail once.** A safety test nobody has seen fail is a comment. Sabotage the thing it
  protects and confirm the test notices; the `Tx` leak test names three leaked handles exactly
  because someone did.

## What transfers from Phoenix, and what does not

`~/src/paydaemon` is the reference, but it is Elixir on a BEAM and zurtr is Zig on one thread pool.

**Steal:** the split between *server events* for business effects and `JS.*` for immediate browser
changes; the hook contract — stable element ids, `phx-update="ignore"` for client-owned input,
explicit browser→server events, optional server→browser events; loading/failed/empty transitions
rendered explicitly; and **re-reading authoritative state after a signal rather than trusting the
notification**. Organize UI by surface (`live/console/`), not one directory per domain.

**Do not port:** `use Ash.Domain` and `use MyAppWeb, :live_view` — macro-based helper injection.
Zig gets explicit registries and generated manifests instead, which is what `comptime` is for.
BEAM supervisors, PubSub, GenStage/Broadway demand and Jido process recovery are not free here;
adopt their *contracts* only when the corresponding model exists. And do not cargo-cult installed
extensions nobody uses, or pull a large generated client SDK into a browser bundle that does not
import it.

## Directions already decided

- **The UI layer is branded LiveViewZ** — LiveView names the contract, Z names the family. The
  reference is Phoenix LiveView: server-owned state, a tree as the view, changes arriving as patches,
  events travelling up, `JS.*` for immediate browser changes and server events for business effects,
  and the hook contract (stable ids, `phx-update="ignore"` for client-owned input, explicit
  browser→server events). The patch stream and the hook contract are what "LiveView" means here; the
  renderer is not part of the name.
- **Keep a fidelity ledger, as `pi.zig` does.** It calls itself *"an independent, parity-focused Zig
  implementation"* and carries a `docs/porting-guide.md` with a ledger of what matches upstream, what
  diverges, and why. LiveViewZ wants the same: the divergences are the interesting part, and writing
  them down is what stops "that's not how LiveView does it" becoming relearned knowledge. A second
  client — the Yoga/native one below — is what turns the patch format from an implementation detail
  into a contract, and the ledger is how that claim stays honest.

- **`zdl` is the data layer's future**, not a competitor to the Turso adapter: `zdl` for local
  storage, the wire format and codegen; Turso for the SQL/sync tier. Its Phase 5 (CRDTs, diffs,
  vector clocks) is the sync substrate.
- **The client has three tiers**, and only one of them runs code the application did not write:
  commands and generated functions are plain JS on the fast path; untrusted scripts run in the
  QuickJS engine, which is why it is loaded conditionally. **That engine is not an OS sandbox** —
  `quickjs_ex` says so plainly, and treating it as isolation for adversarial JavaScript needs an
  outer process, container or VM on top of it.
- **Navigation over the live channel** — the patch stream survives a page change, which is what
  Turbo cannot do.
- **Multiple streams at mixed rates** — a topic per lane, datagrams for feeds where losing a tick
  beats being late. `live/pubsub.zig` already has the topic abstraction.
- **`std.crypto` for free**: `ml_dsa`, `ml_kem` and `hybrid_kem` are in the standard library, and
  CRC32 is integrity rather than authenticity. Sign a Merkle root, not every record — ML-DSA-44
  signatures are 2420 bytes.
