const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- swerver (vendored) -------------------------------------------------
    // See deps/swerver/UPSTREAM.md. Feature flags mirror upstream's build
    // options; alles opt-in, base build is HTTP/1.1-only with no external
    // dependencies.
    const enable_tls = b.option(bool, "swerver-tls", "swerver: TLS 1.3 (requires OpenSSL)") orelse false;
    const enable_http2 = b.option(bool, "swerver-http2", "swerver: HTTP/2") orelse false;
    const enable_http3 = b.option(bool, "swerver-http3", "swerver: HTTP/3 over QUIC (implies TLS)") orelse false;
    const enable_proxy = b.option(bool, "swerver-proxy", "swerver: reverse proxy") orelse false;
    const enable_io_uring = b.option(bool, "swerver-io-uring", "swerver: io_uring backend (Linux)") orelse false;
    const enable_compression = b.option(bool, "swerver-compression", "swerver: response compression (requires zlib)") orelse false;

    const swerver_options = b.addOptions();
    swerver_options.addOption(bool, "enable_tls", enable_tls);
    swerver_options.addOption(bool, "enable_http2", enable_http2);
    swerver_options.addOption(bool, "enable_http3", enable_http3 and enable_tls);
    swerver_options.addOption(bool, "enable_proxy", enable_proxy);
    swerver_options.addOption(bool, "enable_io_uring", enable_io_uring);
    swerver_options.addOption(bool, "enable_x402_crypto", false);
    swerver_options.addOption(bool, "enable_compression", enable_compression);
    swerver_options.addOption(bool, "enable_wasm", false);

    const swerver_mod = b.addModule("swerver", .{
        .root_source_file = b.path("deps/swerver/src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    swerver_mod.addOptions("build_options", swerver_options);
    if (enable_compression) swerver_mod.linkSystemLibrary("z", .{});
    if (enable_tls or enable_http3) {
        swerver_mod.linkSystemLibrary("ssl", .{});
        swerver_mod.linkSystemLibrary("crypto", .{});
    }

    // --- zurtr --------------------------------------------------------------
    const zurtr_mod = b.addModule("zurtr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "swerver", .module = swerver_mod },
        },
    });

    // --- executable ---------------------------------------------------------
    const exe = b.addExecutable(.{
        .name = "zurtr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zurtr", .module = zurtr_mod },
                .{ .name = "swerver", .module = swerver_mod },
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
    const zurtr_tests = b.addTest(.{ .root_module = zurtr_mod });
    const run_zurtr_tests = b.addRunArtifact(zurtr_tests);

    const swerver_tests = b.addTest(.{ .root_module = swerver_mod });
    const run_swerver_tests = b.addRunArtifact(swerver_tests);

    const test_zurtr_step = b.step("test-zurtr", "Run zurtr tests");
    test_zurtr_step.dependOn(&run_zurtr_tests.step);

    const test_swerver_step = b.step("test-swerver", "Run vendored swerver tests");
    test_swerver_step.dependOn(&run_swerver_tests.step);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_zurtr_tests.step);
    test_step.dependOn(&run_swerver_tests.step);
}
