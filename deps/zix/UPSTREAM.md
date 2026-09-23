# Vendored zix

- Upstream: https://github.com/prothegee/zix (feature branch: https://github.com/mattneel/zix `feat/webtransport`)
- Pinned revision: `5df894c34a356d554b772a4d28682b342bbecc58` (`feat/webtransport`, 2026-09-23)
- Vendored: 2026-09-23
- Included paths: `build.zig`, `build.zig.zon`, the eight `zix*-build*.zig` helpers, `src/`,
  `LICENSE`, `LICENSE-BSD` — the same set zix's own `build.zig.zon` declares in `paths`, so a
  re-vendor is mechanical.
- Excluded: `docs/`, `examples/`, `tests/`, `templates/`, `containers/`, `scripts/`, `localbench/`,
  `rnd/`, `zixer*/`, `README*.md`. The vendored tree is what a build needs, not what the project
  publishes.

## Why this revision

zurtr's transport is zix: HTTP/1.1 and HTTP/3 on one origin, and WebTransport for the live channel.
The pinned revision is the tip of `feat/webtransport`, which carries the WebTransport binding
(`src/udp/http3/webtransport/`), the interop harness, and the HLD/LLD that describe them. It is not
yet merged upstream, which is why the fork is named here alongside the upstream project.

`srv`'s PostgreSQL protocol layer (`deps/swerver/src/db/pg/`) is *not* vendored with it: zix carries
its own drivers under `src/driver/`, including `postgrez`, and that is the one the `data` module
builds on. The previous vendored transport (`deps/swerver`) is removed in the same change.

## Policy

This tree is editable source, not a read-only mirror. zurtr patches it in place for:

1. Zig 0.17 master compatibility (zix supports 0.16 and 0.17 from one tree; zurtr builds 0.17).
2. Anything the framework needs from the transport that zix does not expose yet — each such change
   is an entry in the ledger below and is a candidate to send upstream.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `5df894c` (`feat/webtransport`), unmodified.|
|2026-09-23|(none yet)|Zig 0.17 test run at the pin: 2747/2749 pass; two TLS certificate tests abort in `std.crypto.Certificate.parse` (`index out of bounds: index 0, len 0`) inside `tls/client.zig`'s `verifyCertificateVerify`, which is a std behavior change rather than a zix source error. Not yet fixed: it is a panic on input the code does not control, so it needs a guard in `client.zig` (or a fixture update) with the certificate path re-checked, not a test silenced.|
|2026-09-23|`src/udp/http3/webtransport/session.zig`|Zig 0.17 port: three `[_]u8{x} ** n` repetitions in tests became `@splat` with an explicit array type (`**` repetition is whitespace-checked out in 0.17). `@splat` is valid in 0.16 too, so zix's own 0.16 build is unaffected — verified by building zix at its own pin after the change. The same three edits are in the zix working tree at `feat/webtransport`, so a re-vendor carries them.|
