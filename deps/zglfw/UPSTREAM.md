# Vendored zglfw

- Upstream: https://github.com/zig-gamedev/zglfw
- Fork: none — vendored from upstream directly (unlike `deps/zgpu` and `deps/turso`, which have forks).
- Pinned revision: `f04fdbf` ("CI temp disable macOS")
- Vendored: 2026-09-23
- Included paths: `build.zig`, `build.zig.zon`, `libs/`, `src/`, `README.md`, `LICENSE` — the set
  upstream's own `.paths` ships.
- Excluded: `.git/`, `examples/`, `zig-pkg/`, `zig-out/`, `.zig-cache/`

## What it brings

Windows, via **GLFW 3.4** vendored as source in `libs/glfw` and built to `libglfw.a`. Built with both
`-D_GLFW_X11=1` and `-D_GLFW_WAYLAND=1`, linking `-lX11`, with `system_sdk` as a package dependency
supplying the cross-platform X11/Wayland headers and libraries.

This is the window layer for `deps/zgpu`, which deliberately does not create windows: it takes a
`WindowProvider` vtable of function pointers plus `getX11Window`/`getWaylandSurface` accessors, then
calls `createSurfaceForWindow` → `createSwapChain` and recreates the swapchain on resize. zglfw
supplies the window and implements those accessors.

## Policy

Editable source, not a read-only mirror. Patch in place for:

1. Zig 0.17 compatibility.
2. Anything a zurtr application needs the bindings to expose.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `f04fdbf`. `.minimum_zig_version` set to `0.17.0-dev.2264+230c63650` — the exact dev build, not a release, because `"0.17.0"` does not exist and anyzig 404s on it.|
|2026-09-23|`src/zglfw.zig`|Two enum reflection sites at :553 and :573: `@typeInfo(@This()).@"enum".fields.len` → `.field_names.len`. Zig 0.17 made `lang.Type.Enum` columnar — the field is now `field_names`, alongside `field_values` and `decl_names`. Compiler error was `no field named 'fields' in struct 'lang.Type.Enum'`, the same class of break that `zdl` and `zpool` hit.|

## Verified

`zig build --summary all` — **8/8 steps succeed** on `0.17.0-dev.2264+230c63650`, including the
`zglfw-tests` target, which links `libglfw.a` and the X11/Wayland system libraries.
