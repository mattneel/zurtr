const std = @import("std");

/// The demo upstreams under examples/proxies. Each one pairs with the site cfg
/// of the same name under examples/proxies/sites, and the pair is one row of
/// the proxy matrix. The static demo has no upstream, and the two rtc demos
/// reuse an upstream from this table (http1_ws) and one from examples/webrtc.
const demos = [_][]const u8{
    "http1",
    "http1_sse",
    "http1_ws",
    "http2",
    "grpc",
    "http3",
    "udp",
    "mixed",
    "round_robin",
    "tls",
    "bounds",
    "headers",
};

/// Wire the proxy demo upstreams: `zig build zixer-examples` builds them all,
/// `zig build zixer-example-<name>` builds one.
///
/// Note:
/// - Installed binaries carry the zixer- prefix, the target triplet, and the
///   optimize mode (zixer-example-<name>-<arch>-<os>-<optimize>), so they never
///   collide with the zix example binaries and building several targets or
///   several modes in a row never overwrites a prior binary.
/// - A step builds and installs, it never runs: building the matrix must not
///   block on a server that serves forever.
///
/// Param:
/// zix - *std.Build.Module (the engine module every demo links)
///
/// Return:
/// - void
pub fn addSteps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
) void {
    const triple = b.fmt("{s}-{s}", .{ @tagName(target.result.cpu.arch), @tagName(target.result.os.tag) });

    // The optimize mode, lowercased, is the last part of every installed name.
    // No -Doptimize means Debug, so a plain build writes -debug. Spelled out
    // rather than lowercased at runtime so a new mode is a compile error here.
    const mode = switch (optimize) {
        .Debug => "debug",
        .ReleaseSafe => "releasesafe",
        .ReleaseFast => "releasefast",
        .ReleaseSmall => "releasesmall",
    };

    const examples_step = b.step("zixer-examples", "Build every zixer proxy demo upstream");

    inline for (demos) |name| {
        const install = &addDemo(b, target, optimize, zix, triple, mode, name).step;
        examples_step.dependOn(install);

        const single_step = b.step("zixer-example-" ++ name, "Build the zixer " ++ name ++ " proxy demo upstream");
        single_step.dependOn(install);
    }
}

/// Build and install one demo upstream, returning its install step.
pub fn addDemo(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zix: *std.Build.Module,
    triple: []const u8,
    mode: []const u8,
    comptime name: []const u8,
) *std.Build.Step.InstallArtifact {
    const demo_mod = b.createModule(.{
        .root_source_file = b.path("examples/proxies/" ++ name ++ ".zig"),
        .target = target,
        .optimize = optimize,
    });
    demo_mod.addImport("zix", zix);

    const exe = b.addExecutable(.{
        .name = b.fmt("zixer-example-{s}-{s}-{s}", .{ name, triple, mode }),
        .root_module = demo_mod,
    });

    return b.addInstallArtifact(exe, .{});
}
