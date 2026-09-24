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

- **`zdl` is the data layer's future**, not a competitor to the Turso adapter: `zdl` for local
  storage, the wire format and codegen; Turso for the SQL/sync tier. Its Phase 5 (CRDTs, diffs,
  vector clocks) is the sync substrate.
- **The client has three tiers**, and only one of them is sandboxed: commands and generated
  functions are plain JS on the fast path; **untrusted scripts only** run in the QuickJS wasm
  engine, which is therefore loaded conditionally.
- **Navigation over the live channel** — the patch stream survives a page change, which is what
  Turbo cannot do.
- **Multiple streams at mixed rates** — a topic per lane, datagrams for feeds where losing a tick
  beats being late. `live/pubsub.zig` already has the topic abstraction.
- **`std.crypto` for free**: `ml_dsa`, `ml_kem` and `hybrid_kem` are in the standard library, and
  CRC32 is integrity rather than authenticity. Sign a Merkle root, not every record — ML-DSA-44
  signatures are 2420 bytes.
