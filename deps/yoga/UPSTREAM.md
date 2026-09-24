# Vendored yoga

- Upstream: https://github.com/facebook/yoga
- Fork: none — vendored from upstream directly, like `deps/zglfw` (and unlike `deps/zgpu` and
  `deps/turso`, which have forks).
- Pinned revision: `a8b4817` ("docs: note exception-safe cleanup of JS Yoga trees")
- Vendored: 2026-09-23
- Included paths: `yoga/` — the library, 19 `.cpp` and 60 `.h`, 12,471 lines, 620 KB — plus
  `LICENSE`, and this tree's own `build.zig`, `build.zig.zon`, `UPSTREAM.md` and `smoke/`.
- Not present in this revision: no `website/` (the docs site is `yogalayout.dev` now) and no
  committed `tests/` data, so there was nothing of either to exclude.
- Excluded: the language bindings and their packaging (`java/`, `javascript/`, `lib/` — the JNI,
  JSR-305, nlohmann and soloader headers the Java bindings compile against — `build.gradle`,
  `gradle/`, `gradlew*`, `settings.gradle.kts`, `gradle.properties`, `Package.swift`, `package.json`,
  `yarn.lock`, `enums.py`), the test and tool directories (`tests/`, `benchmark/`, `capture/`,
  `fuzz/`, `gentest/`, `unit_tests*`, `build_fuzz_tests`), repo tooling and docs (`.github/`,
  `.vscode/`, `.clang-format`, `.clang-tidy`, `.editorconfig`, `.prettier*`, `.eslintrc.cjs`,
  `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `LICENSE-examples`, `set-version.py`), and
  `yoga/CMakeLists.txt` — CMake is the build this tree replaces, and leaving the file behind would
  claim a build that is not wired to anything.

## The source set is the CMake one, read rather than guessed

`yoga/CMakeLists.txt` is fifteen lines and says exactly which files the library is:

```cmake
file(GLOB SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/**/*.cpp)
add_library(yogacore STATIC ${SOURCES})
target_include_directories(yogacore PUBLIC $<BUILD_INTERFACE:${YOGA_ROOT}> ...)
```

and the root `CMakeLists.txt` says which of those are public:

```cmake
install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/yoga"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")
```

Two things follow, and both are load-bearing for a consumer:

1. **The translation units are the 19 `.cpp` under `yoga/`, recursively** — 7 at the top level
   (`YGConfig`, `YGEnums`, `YGNode`, `YGNodeLayout`, `YGNodeStyle`, `YGPixelGrid`, `YGValue`), 6
   under `algorithm/`, 1 under `config/`, 2 under `debug/`, 1 under `event/`, 2 under `node/`. They
   are listed by name in `build.zig` because Zig's build system has no glob; a re-vendor re-runs
   those two globs and compares the list.
2. **The include root is the directory that *contains* `yoga/`, not `yoga/` itself** — that is what
   `YOGA_ROOT` is (`${CMAKE_CURRENT_SOURCE_DIR}/..`), and it is why a consumer writes
   `#include <yoga/YGNode.h>`. `Package.swift` agrees independently: `publicHeadersPath: "."`,
   `headerSearchPath(".")`, sources `["yoga"]`. The vendored layout keeps that shape — the headers
   are at `deps/yoga/yoga/*.h` and the search path is `deps/yoga` — so upstream's include spelling
   works here unchanged.

`cmake/project-defaults.cmake` is the other half of the contract: `CMAKE_CXX_STANDARD 20`,
`CMAKE_CXX_VISIBILITY_PRESET hidden`, `CMAKE_POSITION_INDEPENDENT_CODE ON`, `-fno-omit-frame-pointer`,
`-fexceptions`, `-frtti`, `-Wall -Werror`, `-O2` and `-ffunction-sections -fdata-sections` in release
configurations, `-DDEBUG` in debug ones, and `CMAKE_INTERPROCEDURAL_OPTIMIZATION` when
`check_ipo_supported` allows it. `build.zig` names each one it reproduces and each one it drops, and
the two it drops are explained there rather than silently missing.

## What it brings

Layout: the Flexbox engine that turns a tree of styled boxes into `left`/`top`/`width`/`height`. It
is the layer between `deps/zglfw`'s window and `deps/zgpu`'s drawing — a UI tree is laid out once per
change and drawn as rects, and this is the part that decides where the rects go. The C API is the
surface a consumer binds to (`yoga/Yoga.h` and the `YG*.h` headers it re-exports), with the C++
implementation private to the library.

Dependency-free is the point of this choice: no package manager at build time, no generated
configuration headers, no third-party code in the translation units — the only inputs are libc and
libc++.

## Using it

From another build, the whole interface is three lines, and an out-of-tree consumer that does
exactly this was built and run to check it:

```zig
const yoga = b.dependency("yoga", .{ .target = target, .optimize = optimize });
exe.root_module.linkLibrary(yoga.artifact("yoga"));
```

Nothing else: linking the artifact puts `<yoga/…>` on the consumer's include search path (the
headers are installed under that name) and puts `-lc++` on its link line, so
`#include <yoga/YGNode.h>` and `YGNodeCalculateLayout` work without either being named. `zig build`
in this directory installs `libyoga.a` and the headers under `zig-out/` as well, for a consumer
that is not a Zig build.

## Policy

Editable source, not a read-only mirror. Patch in place for:

1. Zig 0.17 compatibility.
2. Anything a zurtr application needs the bindings to expose.
3. Where the C API's behaviour is concerned, upstream wins: the numbers Yoga computes are the
   contract, and a local patch must not change them.

## Modification ledger

Append one line per change; keep it current so re-vendoring is mechanical. The vendored sources are
otherwise **unmodified** — `diff -rq ~/src/yoga/yoga deps/yoga/yoga` reports exactly one line,
`Only in yoga: CMakeLists.txt`, i.e. the deliberate omission.

|Date|Files|Change|
|---|---|---|
|2026-09-23|(whole tree)|Vendor at `a8b4817`: `yoga/` minus `yoga/CMakeLists.txt`, plus `LICENSE`.|
|2026-09-23|`build.zig`, `build.zig.zon`|Added — upstream's only build is CMake. `yoga` (static `libyoga.a`) from the CMake source set, C++20, `-fexceptions`, `-Wall` (upstream's `-Werror` dropped on purpose), `pic`, frame pointers kept, and `-ffunction-sections -fdata-sections` in release — Zig passes the *opposite* of those two by default, and adding them back measures 43 KB off a release smoke executable. Headers installed as `yoga/…` so that linking the artifact is what puts `<yoga/YGNode.h>` on a consumer's include path. `.minimum_zig_version` is the exact dev build `0.17.0-dev.2264+230c63650`; `"0.17.0"` is not a version and 404s.|
|2026-09-23|`build.zig`|`optimize == .Debug` → `.debug`: 0.17 lowercased `std.builtin.Optimize`'s fields, the same break `deps/zgpu`'s ledger records.|
|2026-09-23|`smoke/layout.c`, `smoke/exceptions.cpp`|Added: upstream's tests are GoogleTest and are not vendored, so nothing in this tree would otherwise show the library *running*. One C program prints a layout computed through the C API (and checks the numbers); one C++ program proves a fatal assert arrives as a catchable `std::logic_error` rather than a `std::terminate`. Neither is upstream's; both are wired to `zig build smoke` / `zig build test`.|

## Verified

`zig build test` on `0.17.0-dev.2264+230c63650` — **7/7 steps, both smoke programs succeed**:

```
Yoga C API layout smoke
  root 200x100, row, padding 10 -> content box 180; children grow 1 : 2
  root    left    0.0  top    0.0  width  200.0  height  100.0
  first   left   10.0  top   10.0  width   60.0  height   40.0
  second  left   70.0  top   22.0  width  120.0  height   60.0
OK
Child already has a owner, it must be removed first.
Yoga C API exception smoke
  caught std::logic_error: Child already has a owner, it must be removed first.
OK
```

The 60/120 split is computed by Yoga from the 180-wide content box and the two flex factors — the
program never names those widths. `ReleaseFast` builds and runs the same programs.

The consumer recipe above is not a claim about Zig's API, it is a checked one: a two-file build tree
*outside* this repository, declaring `deps/yoga` as a relative path dependency and setting nothing
on its module but `link_libc`, links `yoga.artifact("yoga")`, includes `<yoga/YGNode.h>` and prints
the same layout. A clean-from-scratch build of just the paths in this package's `.paths` — 86 files
— also builds and runs both smoke programs in Debug and `ReleaseFast`, with no warnings from `-Wall`.
