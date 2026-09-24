# Vendored zgpu

- Upstream: https://github.com/zig-gamedev/zgpu
- Fork (ours): https://github.com/mattneel/zgpu
- Pinned revision: `e6d8103` ("Update zpool dependency for Zig 0.16.0 (#28)")
- Vendored: 2026-09-23
- Included paths: `build.zig`, `build.zig.zon`, `libs/`, `src/`, `LICENSE`, `README.md` — exactly the
  set zgpu's own `.paths` ships, so a re-vendor is a copy of the same list.
- Excluded: `.git/`, `examples/`, `zig-pkg/`

## Dawn is not vendored, on purpose

`libs/` is Dawn's *headers* (`dawn/include`, `webgpu`, `tint`, 428 KB) plus the vendored `zpool`
copy (`libs/zpool`, ours — see its own `UPSTREAM.md`). The native libraries arrive
as prebuilt archives — one `lazyDependency` per target, pinned by hash in `build.zig.zon`:
`dawn_x86_64_linux_gnu`, `dawn_aarch64_linux_gnu`, `dawn_x86_64_windows_gnu`,
`dawn_x86_64_macos`, `dawn_aarch64_macos`. Fetching a package dependency on demand is this tree's
existing policy, as `deps/quickjs-ng` states for the QuickJS C sources.

For scale, measured rather than assumed: **Dawn from source is 541 MB, 85,589 files and 492,741
lines of C++**, and its `DEPS` pulls roughly **sixty Chromium sub-repositories** — abseil, glslang,
SPIRV-Tools, five separate Vulkan repositories, mesa, SwiftShader, ANGLE, DirectXShaderCompiler,
perfetto, catapult, googletest, and jinja2 — behind two build systems (`BUILD.gn` and
`CMakeLists.txt`). Vendoring zgpu instead is 676 KB, one fetched dependency (`system_sdk`), and a
120 KB local `zpool` copy.

## Policy

Editable source, not a read-only mirror. Patch in place for:

1. Zig 0.17 compatibility. The fork is at 0.16 and zurtr pins `0.17.0-dev.2264+230c63650`, so the
   first build that reaches this dependency is expected to need work — the same pin bump that
   `deps/turso` and `deps/quickjs-ng` needed.
2. Anything a zurtr application needs the bindings to expose.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `e6d8103`.|
|2026-09-23|`build.zig.zon`|`.minimum_zig_version` `"0.15.2"` → `"0.17.0-dev.2264+230c63650"`, zurtr's pin. Anything lower makes anyzig fetch a compiler this tree cannot build with.|
|2026-09-23|`build.zig`|Options reflection: `std.meta.fields(@TypeOf(options))` → columnar `@typeInfo(...).@"struct"` zipped over `field_names`/`field_types`. Forced by `std.meta.fields` being a hard `@compileError` (“deprecated in favor of @typeInfo”) in 0.17.|
|2026-09-23|`src/zgpu.zig`|Five `[_]T{...} ** N` array repeats → `@splat(...)`. Forced by `error: binary operator '*' has whitespace on one side, but not on the other` — a *parse* error in 0.17, so the whole file was unloadable. The result-location makes the type explicit at each site, so no annotation was needed.|
|2026-09-23|`build.zig`|`@cImport` was removed in 0.17, and `src/wgpu.zig`'s ABI-compatibility test used it on `dawn/webgpu.h`. Replaced by an `addTranslateC` step over `libs/dawn/include/dawn/webgpu.h` (plus that include dir) whose module, `dawn_c`, the test imports as `@import("dawn_c")`. The tests module also gained the `zgpu_options` and `zpool` imports it had been missing, without which `src/zgpu.zig` cannot compile as a test root.|
|2026-09-23|`src/wgpu.zig`|ABI test: `@cImport(@cInclude("dawn/webgpu.h"))` → `@import("dawn_c")`, and `decl.name` → `decl_name`: `std.meta.declarations()` now returns `[]const [:0]const u8` (names), not field descriptors. Still compares all 77 hand-written extern structs against the translated header.|
|2026-09-23|`build.zig.zon`, `libs/zpool/`|zpool was a URL+hash dependency whose pinned revision cannot parse under 0.17, so it is vendored at `libs/zpool` and referenced as `.path = "libs/zpool"` (see `libs/zpool/UPSTREAM.md` for the patch list and why reverting is not an option).|
