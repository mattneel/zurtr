const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zgpu = b.dependency("zgpu", .{ .target = target, .optimize = optimize });
    const zglfw = b.dependency("zglfw", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "hello-gpu",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.root_module.addImport("zgpu", zgpu.module("root"));
    exe.root_module.addImport("zglfw", zglfw.module("root"));

    // zdawn is the C-ABI wrapper over Dawn; glfw is GLFW built from the vendored source. Both bring
    // their own system libraries with them, and zgpu's helper adds the platform library search paths
    // for the prebuilt Dawn.
    exe.root_module.linkLibrary(zgpu.artifact("zdawn"));
    exe.root_module.linkLibrary(zglfw.artifact("glfw"));
    // The package's own build.zig, for its platform helpers - the Dependency object only
    // exposes artifacts and modules.
    const zgpu_pkg = @import("zgpu");
    zgpu_pkg.addLibraryPathsTo(exe);

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    b.step("run", "Open a window and draw to it").dependOn(&run.step);
}
