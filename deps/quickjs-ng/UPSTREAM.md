# Vendored zig-quickjs-ng

- Upstream: https://github.com/zig-quickjs-ng/zig-quickjs-ng (fork/ours: https://github.com/mattneel/zig-quickjs-ng)
- Pinned revision: `16eca3e` + the two fixes below (2026-09-23)
- Vendored: 2026-09-23
- Included paths: `build.zig`, `build.zig.zon`, `src/`, `LICENSE`
- Excluded: `examples/`, `flake.*`, `.github/`, `AGENTS.md`, `CLAUDE.md`, `typos.toml`
- Upstream QuickJS-ng C sources are a package dependency of the binding, fetched on demand and never vendored here.

## Policy

This tree is editable source, not a read-only mirror. zurtr patches it in place for:

1. Zig 0.17 master compatibility.
2. Anything the script layer needs that the binding does not expose.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `16eca3e` ("Port bindings to Zig 0.17"), plus: `.minimum_zig_version` was `0.17.0`, a release that does not exist, so anyzig 404s; it is now `0.17.0-dev.2264+230c63650`. Four promise-hook callbacks moved a C `JSValue` into `Value` with `@bitCast`, which 0.17 refuses between extern structs; they now copy through one helper with a comptime size assertion. Both fixes are committed on the fork. Verified: `zig build test` — 165/165 pass on 0.17.0-dev.2264.|
