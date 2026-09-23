# Vendored turso.zig

- Upstream: https://github.com/tzekid/turso.zig
- Fork (ours): https://github.com/mattneel/turso.zig
- Pinned revision: `def4a791298384ca5d09134eaf08b8fa455311b9` (master, 2026-09-20), plus the Zig 0.17.0-dev.2264 pin bump below
- Vendored: 2026-09-23
- Included paths: `build.zig`, `build.zig.zon`, `include/`, `src/`, `tools/`, `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md`
- Excluded: `.github/`, `docs/`, `examples/`, `bench/`, `tests/`, `flake.*`, `.envrc`, `AGENTS.md`, `SIMPLIFICATION_PLAN.md`

## Policy

This tree is editable source, not a read-only mirror. zurtr patches it in place for:

1. Zig 0.17 master compatibility (upstream pins 0.17.0-dev.2085; zurtr builds 0.17.0-dev.2264).
2. Anything the data adapter needs that the binding does not expose.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `def4a79` (master), unmodified. Its own pure tests and ABI/safe tests pass on 0.17.0-dev.2264 as vendored.|
|2026-09-23|`src/sync.zig`|Re-export the base binding as `pub const base = @import("turso.zig")`. Zig will not put one file in two modules of one compilation, and `turso` and `turso_sync` are two modules over one tree, so a consumer that needs the base types *and* the sync API (zurtr's data adapter does: the database may be opened at any tier) cannot import both. One line, no behavior change; the base surface is unchanged.|
|2026-09-23|`build.zig.zon`|`.minimum_zig_version` 0.17.0-dev.2085+5e36170b5 -> 0.17.0-dev.2264+230c63650, the revision zurtr builds. No source change was needed: `zig build test-pure` (28 test binaries) and `zig build test-abi test-safe` (against the native SDK Kit built from Rust source) both pass on the newer toolchain. The same bump is on the fork, so re-vendoring from the fork carries it.|
