# Vendored swerver

- Upstream: https://github.com/justinGrosvenor/swerver
- Pinned revision: `af272be5361c6bbf599554f99bee14195223d537` (tag `v0.1.0-alpha.32`, 2026-09-06)
- Vendored: 2026-09-22
- Included paths: `build.zig`, `build.zig.zon`, `LICENSE`, `README.md`, `CHANGELOG.md`, `src/`
- Excluded: `docs/`, `examples/`, `bench/`, `spike/`, `scripts/`, `.github/`, `vendor/wasm3`
  - `vendor/wasm3` is only linked when `enable_wasm=true`; zurtr does not enable WASM edge functions.

## Policy

This tree is editable source, not a read-only mirror. zurtr patches it in place for:

1. Zig master (0.17-dev) compatibility.
2. Native WebSocket server endpoints (upgrade + frames), complementing swerver's
   existing WebSocket *proxy* support (`src/proxy/websocket.zig`).
3. Deferred application responses: a handler may retain an explicit connection
   handle and complete the response later from outside the sync handler return.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

| Date | Files | Change |
| ---- | ----- | ------ |
| 2026-09-22 | (whole tree) | Vendor at `af272be` (upstream alpha.32), unmodified. |
