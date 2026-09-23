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
    // `-Dturso-sync` implies `-Dturso`: there is no adapter to give a remote half to otherwise, and the
    // package only offers the sync module when it was asked to build the adapter at all.
    const turso_sync = enable_turso and (b.option(bool, "turso-sync", "Include the opt-in Turso sync SDK Kit (implies -Dturso)") orelse false);
    // The sync tier's round trip needs a server, so the only test that talks to a remote is told where
    // it is. Passing it through the build (rather than the environment) is what makes the test run
    // reproducible: the value is part of the step's cache key, so a new endpoint really does re-run it.
    const sync_remote = b.option([]const u8, "sync-remote", "Live sync endpoint for the sync tier's round-trip test, e.g. http://127.0.0.1:8080");

    // Asking the package for its module is what asks for its native artifact, so a build that does not
    // build the adapter must not ask: without `-Dturso` the import resolves to a guard file that says
    // so, and cargo is never invoked.
    //
    // The sync module is a second artifact with its own gate: the package only creates `turso_sync` in
    // a build that asked for it, so `-Dturso-sync=false` leaves the name with nothing to resolve and
    // the adapter's `.sync` tier refuses. That is the intended shape, not an omission: the tier is
    // either backed by the SDK Kit or refused, never quietly local-only.
    var turso_sync_module: ?*std.Build.Module = null;

    const turso = if (enable_turso) blk: {
        const turso_dep = b.dependency("turso", .{
            .target = target,
            .optimize = optimize,
            .native = "source",
            .linkage = "static",
            .sync = turso_sync,
        });

        if (turso_sync) turso_sync_module = turso_dep.module("turso_sync");

        break :blk turso_dep.module("turso");
    } else b.createModule(.{
        .root_source_file = b.path("src/data/turso_not_built.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- quickjs (vendored, opt-in) -----------------------------------------
    // The script engine compiles QuickJS-ng's C through Zig and needs the LLVM backend, so the base
    // build must not ask for it. Same pattern as the adapter: the import name always resolves, and what
    // it resolves to depends on whether this build asked for the engine.
    const enable_zscript = b.option(bool, "zscript", "Build ZScript, the QuickJS script layer (vendored zig-quickjs-ng)") orelse false;

    const quickjs = if (enable_zscript) blk: {
        const dep = b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize });

        break :blk dep.module("quickjs");
    } else b.createModule(.{
        .root_source_file = b.path("src/zscript/quickjs_not_built.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ZScript as a named module: it is imported by `root.zig` and by ZEEX's compiler, and a
    // relative import cannot cross a module boundary (ZEEX reaches up to it from `src/zeex/`).
    const zscript = b.addModule("zscript", .{
        .root_source_file = b.path("src/zscript/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quickjs", .module = quickjs }},
    });

    // --- zurtr --------------------------------------------------------------
    const zurtr_options = b.addOptions();
    zurtr_options.addOption(bool, "turso", enable_turso);
    zurtr_options.addOption(bool, "turso_sync", turso_sync);
    zurtr_options.addOption(bool, "zscript", enable_zscript);

    var zurtr_imports: std.ArrayList(std.Build.Module.Import) = .empty;
    zurtr_imports.append(b.allocator, .{ .name = "zix", .module = zix }) catch @panic("OOM");
    zurtr_imports.append(b.allocator, .{ .name = "quickjs", .module = quickjs }) catch @panic("OOM");
    zurtr_imports.append(b.allocator, .{ .name = "zscript", .module = zscript }) catch @panic("OOM");
    if (turso_sync_module) |module| {
        // A sync build has one module for the whole stack: the SDK module is rooted in the same source
        // tree and re-exports the base binding as `base`. Zig will not put one file in two modules of
        // one compilation — and two copies of `Connection` would not be the same type anyway.
        zurtr_imports.append(b.allocator, .{ .name = "turso_sync", .module = module }) catch @panic("OOM");
    } else {
        zurtr_imports.append(b.allocator, .{ .name = "turso", .module = turso }) catch @panic("OOM");
    }

    const zurtr = b.addModule("zurtr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = zurtr_imports.items,
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
    if (enable_zscript) {
        exe.use_llvm = true;
        exe.root_module.linkLibrary(b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));
    }
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
        var data_test_imports: std.ArrayList(std.Build.Module.Import) = .empty;
        if (turso_sync_module) |module| {
            data_test_imports.append(b.allocator, .{ .name = "turso_sync", .module = module }) catch @panic("OOM");
        } else {
            data_test_imports.append(b.allocator, .{ .name = "turso", .module = turso }) catch @panic("OOM");
        }

        const data_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/data/tests.zig"),
                .target = target,
                .optimize = optimize,
                .imports = data_test_imports.items,
            }),
        });
        const data_options = b.addOptions();
        data_options.addOption(bool, "turso_sync", turso_sync);
        data_options.addOption(?[]const u8, "sync_remote", sync_remote);
        data_tests.root_module.addOptions("build_options", data_options);
        // The adapter opens a file tier in a place it can clean up, so point the test at the cache.
        const run_data_tests = b.addRunArtifact(data_tests);
        const test_data_step = b.step("test-data", "Run the data module's tests against Turso");
        test_data_step.dependOn(&run_data_tests.step);
        data_test_run = run_data_tests;
    }

    // The distributed tier's cross-process proof. A single test binary shares one allocator, one
    // thread and one process lifetime, so it can prove the write lease's arithmetic and not its
    // coordination; the harness is a real program, and the test runs it twice as two processes over
    // one database file. It is built only with the adapter, and `test-data-nodes` is the only step
    // that needs it.
    var nodes_test_run: ?*std.Build.Step.Run = null;
    if (enable_turso) {
        const data_node = b.addExecutable(.{
            .name = "zurtr-data-node",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/data/node.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{if (turso_sync_module) |module|
                    .{ .name = "turso_sync", .module = module }
                else
                    .{ .name = "turso", .module = turso }},
            }),
        });
        data_node.root_module.addOptions("build_options", zurtr_options);
        b.installArtifact(data_node);

        const nodes_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/data/nodes_test.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{if (turso_sync_module) |module|
                    .{ .name = "turso_sync", .module = module }
                else
                    .{ .name = "turso", .module = turso }},
            }),
        });
        // The test spawns the harness, so it needs its path — and, through the option, a build edge
        // that guarantees the harness exists first. It also compiles the adapter (through the data
        // module), so its options carry the adapter's own gate as well.
        const nodes_options = b.addOptions();
        nodes_options.addOptionPath("data_node_exe", data_node.getEmittedBin());
        nodes_options.addOption(bool, "turso_sync", turso_sync);
        nodes_tests.root_module.addOptions("build_options", nodes_options);

        const run_nodes_tests = b.addRunArtifact(nodes_tests);
        const test_nodes_step = b.step("test-data-nodes", "Run the distributed tier's two-process proof");
        test_nodes_step.dependOn(&run_nodes_tests.step);
        nodes_test_run = run_nodes_tests;
    }

    var script_test_run: ?*std.Build.Step.Run = null;
    if (enable_zscript) {
        const script_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/zscript/root.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "quickjs", .module = quickjs }},
            }),
        });
        script_tests.root_module.addOptions("build_options", zurtr_options);
        // Zig fails with splitType errors on the QuickJS translation unit without LLVM.
        script_tests.use_llvm = true;
        script_tests.root_module.linkLibrary(b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));

        const run_script_tests = b.addRunArtifact(script_tests);
        const test_script_step = b.step("test-zscript", "Run the script layer's tests against QuickJS");
        test_script_step.dependOn(&run_script_tests.step);
        script_test_run = run_script_tests;
    }

    // ZEEX's compiler is self-contained: it imports the script layer and nothing above it, so it
    // gets its own step rather than riding inside `test-zurtr`, where a failure in it would be
    // indistinguishable from a failure anywhere else in that binary.
    var zeex_test_run: ?*std.Build.Step.Run = null;
    var zeex_live_test_run: ?*std.Build.Step.Run = null;
    if (enable_zscript) {
        const zeex_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/zeex/compile.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "zscript", .module = zscript }},
            }),
        });
        // Zig fails with splitType errors on the QuickJS translation unit without LLVM.
        zeex_tests.use_llvm = true;
        zeex_tests.root_module.linkLibrary(b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));

        const run_zeex_tests = b.addRunArtifact(zeex_tests);
        const test_zeex_step = b.step("test-zeex", "Run the template compiler's tests (lowers JSX and parses the generated Zig)");
        test_zeex_step.dependOn(&run_zeex_tests.step);
        zeex_test_run = run_zeex_tests;
    }

    if (enable_zscript) {
        // zeex-live: the live editor's first half — lower a template on every save and show
        // the Zig it produced, or the line it rejected. Built from the framework module
        // because a `tools/` root cannot reach `src/` by relative path.
        const zeex_live_module = b.createModule(.{
            .root_source_file = b.path("tools/zeex_live.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zurtr", .module = zurtr }},
        });
        const zeex_live = b.addExecutable(.{ .name = "zeex-live", .root_module = zeex_live_module });
        zeex_live.use_llvm = true;
        zeex_live.root_module.linkLibrary(b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));
        b.installArtifact(zeex_live);
        const run_zeex_live = b.addRunArtifact(zeex_live);
        run_zeex_live.addPassthruArgs();
        const zeex_live_step = b.step("zeex-live", "Lower a template on every save (the live editor's compiler half)");
        zeex_live_step.dependOn(&run_zeex_live.step);

        const zeex_live_tests = b.addTest(.{ .root_module = zeex_live_module });
        zeex_live_tests.use_llvm = true;
        zeex_live_tests.root_module.linkLibrary(b.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));
        const run_zeex_live_tests = b.addRunArtifact(zeex_live_tests);
        const test_zeex_live_step = b.step("test-zeex-live", "Run the live editor's tests");
        test_zeex_live_step.dependOn(&run_zeex_live_tests.step);
        zeex_live_test_run = run_zeex_live_tests;
    }

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_zurtr_tests.step);
    test_step.dependOn(&run_zix_tests.step);
    if (data_test_run) |run| test_step.dependOn(&run.step);
    if (nodes_test_run) |run| test_step.dependOn(&run.step);
    if (script_test_run) |run| test_step.dependOn(&run.step);
    if (zeex_test_run) |run| test_step.dependOn(&run.step);
    if (zeex_live_test_run) |run| test_step.dependOn(&run.step);
}
