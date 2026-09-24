const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zgpu = b.dependency("zgpu", .{ .target = target, .optimize = optimize });
    const zglfw = b.dependency("zglfw", .{ .target = target, .optimize = optimize });
    const yoga = b.dependency("yoga", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "yoga-boxes",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.root_module.addImport("zgpu", zgpu.module("root"));
    exe.root_module.addImport("zglfw", zglfw.module("root"));

    // zdawn is the C-ABI wrapper over Dawn; glfw is GLFW built from the vendored source; yoga is the
    // layout engine. libyoga.a's C++ needs libc++ and the unwinder, which the library's own module
    // carries into this link line without being asked here.
    exe.root_module.linkLibrary(zgpu.artifact("zdawn"));
    exe.root_module.linkLibrary(zglfw.artifact("glfw"));
    exe.root_module.linkLibrary(yoga.artifact("yoga"));

    // The package's own build.zig, for its platform helpers - the Dependency object only exposes
    // artifacts and modules. It resolves the prebuilt Dawn through *this* build graph, which is why
    // this example's build.zig.zon has to carry the `dawn_*` dependency itself.
    const zgpu_pkg = @import("zgpu");
    zgpu_pkg.addLibraryPathsTo(exe);

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    b.step("run", "Lay out Yoga's tree and draw every box it computed").dependOn(&run.step);
}
