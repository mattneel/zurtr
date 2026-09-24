# Vendored zpool

- Upstream: https://github.com/zig-gamedev/zpool
- Fork: none — this is upstream at the pinned revision, patched in place.
- Pinned revision: `02d1472cc4c134a86ff31d19fb546cf478f6b988` ("Upgrade to Zig 0.16.x (#5)",
  2026-05-11). The same revision zgpu's `build.zig.zon` pinned by hash before this copy existed:
  `zpool-0.11.0-dev-bG692YNGAQCn-LXPTcrabIVizgnPcxkxYjwKYAnJi6Tp`.
- Vendored: 2026-09-23
- Included paths: `src/`, `build.zig`, `build.zig.zon`, `README.md`, `LICENSE` — exactly the set
  zpool's own `.paths` ships, so a re-vendor is a copy of the same list.
- Excluded: `.git/`, `.github/`, `zig-pkg/`

## Why it lives here instead of being fetched

zgpu's manifest used to declare zpool as a URL+hash dependency. That revision does not parse under
Zig 0.17: `src/handle.zig` writes an array repeat, which 0.17 rejects as a **parse** error, so the
failure fires on merely loading the file — no zgpu build could get past it, and no test filter could
avoid it. A fetched, hash-verified package cannot be patched, and there is nothing newer to point at:
upstream `main` still declares `minimum_zig_version = "0.16.0"`, and there is no fork of zpool to
fetch instead.

So the patch is **load-bearing, not temporary tidiness** — reverting `.zpool` in
`deps/zgpu/build.zig.zon` to the URL+hash form reintroduces a hard build failure. Re-vendoring means
copying the upstream tree here and re-applying the ledger below.

Layout: a path dependency cannot leave its package root, so the copy has to be inside the package
that names it — `deps/zgpu/libs/zpool`, referenced as `.path = "libs/zpool"`. zurtr can reference
`deps/zgpu/libs/zpool` from its own root manifest (generation-counted handles are useful well beyond
zgpu) without anything moving.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `02d1472` as `deps/zgpu/libs/zpool`; `deps/zgpu/build.zig.zon`'s `.zpool` becomes `.path = "libs/zpool"` instead of url+hash.|
|2026-09-23|`build.zig.zon`|`.minimum_zig_version` `"0.16.0"` → `"0.17.0-dev.2264+230c63650"`, matching zurtr's pin.|
|2026-09-23|`src/handle.zig`|`var buffer = [_]u8{0} ** 128;` → `var buffer: [128]u8 = @splat(0);`. Forced by `error: binary operator '*' has whitespace on one side, but not on the other` at `src/handle.zig:268`, which is a parse error and therefore fired for every build that loaded the file, test block or not.|
|2026-09-23|`src/pool.zig`|Columnar `@typeInfo` port: `pub const column_fields = meta.fields(Columns)` → `@typeInfo(Columns).@"struct"` with `column_count = column_fields.field_names.len`. Forced by `error: deprecated in favor of @typeInfo` (`std.meta.fields` is a hard `@compileError`) at `src/pool.zig:97`. `private_fields` likewise, and the two `Storage` loops now zip `field_names`/`field_types`/`field_attrs` instead of copying `.name`/`.type`/`.is_comptime`/`.alignment`/`.default_value_ptr` off field descriptors. Also drops `const StructField = std.builtin.Type.StructField` — `error: union 'lang.Type' has no member named 'StructField'` — so `deinitColumnAt` now takes the column enum and derives the field from `column_fields`.|
|2026-09-23|`src/utils.zig`|`StructOfSlices`: `@typeInfo(Struct).@"struct".fields` → columnar arrays, forced by `error: no field named 'fields' in struct 'lang.Type.Struct'` at `src/utils.zig:52`; the slice pointer alignment now comes from `field_attrs[i].@"align"` (was `field.alignment`).|
|2026-09-23|`src/pool.zig`|`DeinitCounter.deinit` (test fixture) made `pub`. Zig 0.17's `@hasDecl` only reports public declarations, so `Pool` stopped seeing the private `deinit` and 9 tests failed with `expected 1, found 0` / `expected 2, found 0` (`Pool.clear() calls Columns.deinit()`, `Pool.remove() calls ColumnType.deinit()`, `Pool.setColumns() calls ColumnType.deinit()`, …). Public is the correct requirement, not a workaround: `Pool` calls the method from its own file, so a private one would not be callable.|
|2026-09-23|`src/pool.zig`|`zig fmt` normalized `@intFromEnum`/`@enumFromInt` to the new spellings `@backingInt`/`@fromBackingInt` (see `lib/std/lang.zig`, `lib/std/Io.zig`). Cosmetic: both spellings still compile — the formatter just rewrites to the preferred one. Worth knowing because the rename is silent, so a file only changes spelling when it happens to be formatted.|
