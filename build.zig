//! zurtr's build.
//!
//! One vendored transport: **zix** (`deps/zix`) — HTTP/1.1 and HTTP/3 on one origin, and
//! WebTransport for the live channel. It replaces the previously vendored swerver, including its
//! PostgreSQL protocol layer: zix carries its own drivers, `postgrez` among them, and those are what
//! the `data` module builds on.
//!
//! zix needs three things from a consumer's build, and they are reproduced here exactly as zix's own
//! `build.zig` wires them:
//!
//!   * the `zon_options` module (the user agent and version zix reports),
//!   * Brotli's static dictionary (RFC 7932 Appendix A), generated into the cache by
//!     `brotli_dictionary.gen.zig` and bound to the `@embedFile` import in `brotli.zig`, so no binary
//!     asset is tracked,
//!   * nothing else: the rest of zix is self-contained source.
//!
//! The base build is the transport plus the framework, with no external dependencies beyond libc.

const std = @import("std");

/// zix's manifest, read from the vendored tree so the options module carries zix's own values.
const zix_zon = @import("deps/zix/build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- zix (vendored) -----------------------------------------------------
    const zix = b.addModule("zix", .{
        .root_source_file = b.path("deps/zix/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const zon_options = b.addOptions();
    zon_options.addOption([]const u8, "user_agent", zix_zon.user_agent);
    zon_options.addOption([]const u8, "version", zix_zon.version);
    zix.addOptions("zon_options", zon_options);

    // Compiling the codec depends on this run through the anonymous import, so any target that builds
    // zix regenerates the dictionary first.
    const brotli_dict_gen = b.addExecutable(.{
        .name = "zix_brotli_dictionary_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("deps/zix/src/utils/compression/brotli_dictionary.gen.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const brotli_dict_run = b.addRunArtifact(brotli_dict_gen);
    const brotli_dict = brotli_dict_run.addOutputFileArg("brotli_dictionary.bin");
    zix.addAnonymousImport("brotli_dictionary.bin", .{ .root_source_file = brotli_dict });

    // --- turso (vendored, opt-in) -------------------------------------------
    // The binding compiles Turso's native SDK from Rust source, so the base build must not need it.
    // The module import is always declared (a Zig import name has to resolve even when the branch that
    // uses it is dead), but nothing links the native library until something actually reaches the
    // adapter — and only `-Dturso` builds are meant to.
    const enable_turso = b.option(bool, "turso", "Build the Turso data adapter (compiles the native SDK from Rust source)") orelse false;
    const turso_sync = b.option(bool, "turso-sync", "Include the opt-in Turso sync SDK Kit (implies -Dturso)") orelse false;

    // Asking the package for its module is what asks for its native artifact, so a build that does not
    // build the adapter must not ask: without `-Dturso` the import resolves to a guard file that says
    // so, and cargo is never invoked.
    const turso = if (enable_turso) blk: {
        const turso_dep = b.dependency("turso", .{
            .target = target,
            .optimize = optimize,
            .native = "source",
            .linkage = "static",
            .sync = turso_sync,
        });

        break :blk turso_dep.module("turso");
    } else b.createModule(.{
        .root_source_file = b.path("src/data/turso_not_built.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- zurtr --------------------------------------------------------------
    const zurtr_options = b.addOptions();
    zurtr_options.addOption(bool, "turso", enable_turso);
    zurtr_options.addOption(bool, "turso_sync", turso_sync);

    const zurtr = b.addModule("zurtr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zix", .module = zix },
            .{ .name = "turso", .module = turso },
        },
    });
    zurtr.addOptions("build_options", zurtr_options);

    // --- executable ---------------------------------------------------------
    // Applications deploy as one static executable, and this is the framework's own entry point
    // (assembly and roles hang off it).
    const exe = b.addExecutable(.{
        .name = "zurtr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zurtr", .module = zurtr },
            },
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run zurtr");
    run_step.dependOn(&run_cmd.step);

    // --- tests --------------------------------------------------------------
    const zurtr_tests = b.addTest(.{ .root_module = zurtr });
    const run_zurtr_tests = b.addRunArtifact(zurtr_tests);

    // zix's `lib.zig` reaches every module in the tree through `refAllDecls`, so testing it tests the
    // vendored transport rather than only its root.
    const zix_tests = b.addTest(.{ .root_module = zix });
    const run_zix_tests = b.addRunArtifact(zix_tests);

    const test_zurtr_step = b.step("test-zurtr", "Run zurtr tests");
    test_zurtr_step.dependOn(&run_zurtr_tests.step);

    const test_zix_step = b.step("test-zix", "Run the vendored zix tests");
    test_zix_step.dependOn(&run_zix_tests.step);

    // The data module's tests need a real database, so they are wired only when the adapter is built.
    var data_test_run: ?*std.Build.Step.Run = null;
    if (enable_turso) {
        const data_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/data/tests.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "turso", .module = turso },
                },
            }),
        });
        data_tests.root_module.addOptions("build_options", zurtr_options);
        // The adapter opens a file tier in a place it can clean up, so point the test at the cache.
        const run_data_tests = b.addRunArtifact(data_tests);
        const test_data_step = b.step("test-data", "Run the data module's tests against Turso");
        test_data_step.dependOn(&run_data_tests.step);
        data_test_run = run_data_tests;
    }

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_zurtr_tests.step);
    test_step.dependOn(&run_zix_tests.step);
    if (data_test_run) |run| test_step.dependOn(&run.step);
}
