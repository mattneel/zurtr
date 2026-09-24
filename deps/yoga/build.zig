//! Yoga's build.
//!
//! Yoga is C++ with the C API on top (`yoga/Yoga.h`, and the `YG*.h` headers it re-exports), and
//! upstream's only build is CMake. This is the same source set under Zig's build system: the C++
//! translation units `yoga/CMakeLists.txt` collects, compiled with the standard and the flags
//! `cmake/project-defaults.cmake` asks for, archived as `libyoga.a`, and installed with its public
//! headers as `yoga/…` so that a C consumer writes `#include <yoga/YGNode.h>` exactly as upstream
//! documents.
//!
//! A consumer takes the artifact:
//!
//! ```zig
//! const yoga = b.dependency("yoga", .{ .target = target, .optimize = optimize });
//! exe.root_module.linkLibrary(yoga.artifact("yoga"));
//! ```
//!
//! and needs nothing else to include the C API or to link it. Two things travel with the artifact:
//! the headers marked with `installHeadersDirectory` are added to the include search path of every
//! module that links it — that is what makes `#include <yoga/YGNode.h>` work from a consumer, not
//! from this file — with this directory as the root that `<yoga/…>` resolves against; and the
//! libc++ requirement set on the library's own module propagates, so a consumer's link line gets
//! `-lc++` without asking. (Checked on a consumer outside this tree that sets nothing: `--verbose`
//! shows `-lc++ -lc`, because `libyoga.a` references `operator new`, the containers inside
//! `yoga::Style`, and the unwinder that `assertFatal` throws through.) The smoke programs below
//! still set `link_libcpp` themselves — they declare what they need rather than inherit it.

const std = @import("std");

/// The library's translation units: everything `yoga/CMakeLists.txt` collects with
/// `file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/**/*.cpp)` —
/// 19 files, recursive. Written out rather than globbed (Zig's build system has no glob, and an
/// input set assembled at configure time is an input set a reviewer cannot see); a re-vendor
/// re-runs those two globs and compares.
const sources: []const []const u8 = &.{
    "yoga/YGConfig.cpp",
    "yoga/YGEnums.cpp",
    "yoga/YGNode.cpp",
    "yoga/YGNodeLayout.cpp",
    "yoga/YGNodeStyle.cpp",
    "yoga/YGPixelGrid.cpp",
    "yoga/YGValue.cpp",
    "yoga/algorithm/AbsoluteLayout.cpp",
    "yoga/algorithm/Baseline.cpp",
    "yoga/algorithm/Cache.cpp",
    "yoga/algorithm/CalculateLayout.cpp",
    "yoga/algorithm/FlexLine.cpp",
    "yoga/algorithm/PixelGrid.cpp",
    "yoga/config/Config.cpp",
    "yoga/debug/AssertFatal.cpp",
    "yoga/debug/Log.cpp",
    "yoga/event/event.cpp",
    "yoga/node/LayoutResults.cpp",
    "yoga/node/Node.cpp",
};

/// What `cmake/project-defaults.cmake` compiles with, as flags rather than as module options where
/// Zig has no option for it. The two it *does* have an option for are set on the module below:
/// `-fno-omit-frame-pointer` (CMake adds it in every configuration, "e.g. for crash dumps") is
/// `omit_frame_pointer = false`, and `CMAKE_POSITION_INDEPENDENT_CODE ON` is `pic = true`.
const cxx_flags: []const []const u8 = &.{
    // set(CMAKE_CXX_STANDARD 20). Also what `Package.swift`'s cxxLanguageStandard says, and not
    // negotiable: Yoga uses C++20 (designated initializers in the style structs, `std::span`,
    // `constexpr` containers). Zig's own default for a `.cpp` is older, so this is the one flag the
    // build cannot go without.
    "-std=c++20",
    // -Wall. CMake also passes -Werror; that one is dropped on purpose, because a vendored
    // dependency that fails a consumer's build when a clang bump adds a warning is a dependency
    // that breaks a tree nobody edited. The warnings themselves are still reported.
    "-Wall",
    // -fexceptions. Load-bearing, not decoration: `yoga/debug/AssertFatal.cpp` calls
    // `throw std::logic_error(message)` behind `#if defined(__cpp_exceptions)`, and without
    // exceptions that path degrades to `std::terminate()` — a fatal assert would kill the process
    // instead of reaching the caller that can report it. Clang enables exceptions by default, so
    // this matches what a plain compile already does; it is here so that a future default change
    // (or `-fno-exceptions` arriving from elsewhere in a consumer's flags) cannot quietly turn
    // Yoga's error path into a crash.
    "-fexceptions",
};

/// `cmake/project-defaults.cmake`'s release-only flags. Zig does not merely omit these, it passes
/// their opposites (`-fno-function-sections -fno-data-sections`, visible with `ZIG_VERBOSE_CC=1`),
/// so they have to be added back for the linker to be able to discard anything below the object
/// granularity. Measured rather than assumed: with them the `ReleaseFast` smoke executable is
/// 3,601,920 bytes against 3,645,160 without — CMake's `-Wl,--gc-sections` is Zig's own link
/// behaviour, so the flags are what the dead-stripping needs to have something to strip.
///
/// CMake's `CMAKE_INTERPROCEDURAL_OPTIMIZATION` (LTO, `check_ipo_supported`) is *not* reproduced:
/// this artifact is a static archive, so LTO here would only pay off in a consumer that is itself
/// LTO-ing, and a consumer of a Zig build cannot be. It is an optimization, not a semantic, so the
/// omission changes what the library costs and not what it does.
const release_flags: []const []const u8 = &.{
    "-ffunction-sections",
    "-fdata-sections",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const yoga = addYoga(b, target, optimize);
    b.installArtifact(yoga);

    // --- smoke --------------------------------------------------------------
    // Upstream's own tests are GoogleTest and are not vendored, so nothing here would otherwise
    // prove the library *runs*. These two programs do: `layout.c` calls the C API the way a
    // consumer would and prints the layout Yoga computed, and `exceptions.cpp` checks the flag
    // decision above is real — that a fatal assert arrives at the caller as a C++ exception rather
    // than a terminate. Both link the artifact exactly as an outside consumer does.
    const smoke = b.addExecutable(.{
        .name = "yoga-smoke-layout",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    smoke.root_module.addCSourceFile(.{
        .file = b.path("smoke/layout.c"),
        .flags = &.{ "-std=c11", "-Wall" },
    });
    smoke.root_module.linkLibrary(yoga);
    const run_smoke = b.addRunArtifact(smoke);

    const exceptions = b.addExecutable(.{
        .name = "yoga-smoke-exceptions",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    exceptions.root_module.addCSourceFile(.{
        .file = b.path("smoke/exceptions.cpp"),
        .flags = &.{ "-std=c++20", "-Wall" },
    });
    exceptions.root_module.linkLibrary(yoga);
    const run_exceptions = b.addRunArtifact(exceptions);

    // `zig build smoke` is the one-line proof: it prints a layout through the C API.
    const smoke_step = b.step("smoke", "Print a layout computed through Yoga's C API");
    smoke_step.dependOn(&run_smoke.step);

    const test_step = b.step("test", "Run the smoke programs (this tree vendors no upstream test suite)");
    test_step.dependOn(&run_smoke.step);
    test_step.dependOn(&run_exceptions.step);
}

fn addYoga(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const yoga = b.addLibrary(.{
        .name = "yoga",
        // `add_library(yogacore STATIC ${SOURCES})` — static is what upstream builds, and what an
        // embedded layout engine wants to be: the consumer's final link sees the objects, and there
        // is no `libyoga.so` to version or to find at run time. `YG_EXPORT` is default-visibility
        // annotated, so a dynamic library would also work; nothing here needs one.
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
            .pic = true,
            .omit_frame_pointer = false,
        }),
    });

    var flags: std.ArrayList([]const u8) = .empty;
    flags.appendSlice(b.allocator, cxx_flags) catch @panic("OOM");
    // `$<$<CONFIG:RELEASE>:…>`: release configurations only, which is what `optimize == .debug`
    // separates — everything else up to `.release_small` is a release the linker can strip.
    if (optimize != .debug) flags.appendSlice(b.allocator, release_flags) catch @panic("OOM");
    yoga.root_module.addCSourceFiles(.{ .files = sources, .flags = flags.items });

    // This directory is what `<yoga/…>` resolves against — the headers live in the subdirectory
    // `yoga/`, so the search path is their parent, exactly as `yoga/CMakeLists.txt` sets
    // `$<BUILD_INTERFACE:${YOGA_ROOT}>` (the repository root, one level above `yoga/`).
    yoga.root_module.addIncludePath(b.path("."));

    // `install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/yoga DESTINATION include FILES_MATCHING PATTERN
    // "*.h")`: the headers land at `include/yoga/…`, and `dest_rel_path` is what puts the `yoga/`
    // component into consumers' include path as well as into the install tree.
    yoga.installHeadersDirectory(b.path("yoga"), "yoga", .{});

    // `add_compile_definitions($<$<CONFIG:DEBUG>:DEBUG>)`. Nothing in the vendored sources reads
    // `DEBUG` (grepped: the only hit is `ANDROID_LOG_DEBUG` in `yoga/debug/Log.cpp`), so this is
    // fidelity rather than function — kept so a re-vendor diff against upstream's flag set is empty
    // and so a consumer debugging against these objects sees the same preprocessor state as one
    // debugging against CMake's.
    // `Optimize`'s fields are lowercase as of 0.17 (`.debug`, not `.Debug`) — the same break
    // `deps/zgpu`'s ledger records.
    if (optimize == .debug) yoga.root_module.addCMacro("DEBUG", "1");

    return yoga;
}
