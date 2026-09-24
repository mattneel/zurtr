//! {{name}}'s build.
//!
//! One executable and one dependency. The transport — zix — arrives through `zurtr` rather than as a
//! second dependency: the framework's own build declares its module, wires the options module it
//! reads its user agent and version from, and generates the Brotli dictionary its codec embeds, and a
//! consumer that repeated any of that would be maintaining a copy of it.
//!
//! The options below are the framework's own, passed down rather than re-implemented: the data
//! adapter compiles Turso from Rust source and the script layer compiles QuickJS, so a project that
//! asked for neither must not pay for either — and one that asked for either has to say so here,
//! because the module that reaches those engines is refused, at compile time, by a build without them.

const std = @import("std");

/// The Zig this project is built with: the same floor the framework's manifest sets. A compiler whose
/// dev cycle is moving takes the build system with it, and a mismatch that is not caught here shows
/// up as a page of errors inside the *dependency's* build rather than as one line about the compiler.
const required_zig = "0.17.0-dev.2264+230c63650";

comptime {
    if (@import("builtin").zig_version.order(std.SemanticVersion.parse(required_zig) catch unreachable) == .lt) {
        @compileError("{{name}} needs Zig " ++ required_zig ++ " or newer; this compiler is " ++ @import("builtin").zig_version_string);
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // `zurtr` is a dependency of this package, recorded in build.zig.zon: `zig fetch --save` put the
    // path to the checkout this project was generated from there, so nothing here names a location.
    const zurtr_dep = b.dependency("zurtr", .{
        .target = target,
        .optimize = optimize,
{{#if data}}        // The data module's only adapter is the vendored Turso binding: the file, sync and distributed
        // tiers all open through it, so a project that stores anything asks for it here.
        .turso = true,
{{/if}}{{#if zscript}}        // The script seam's engine. It is C compiled through Zig's LLVM backend, so this also costs a
        // first build measured in minutes.
        .zscript = true,
{{/if}}    });

    const exe = b.addExecutable(.{
        .name = "{{name}}",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zurtr", .module = zurtr_dep.module("zurtr") }},
        }),
    });
{{#if zscript}}
    // The engine is an artifact of the dependency's build, so it is linked from there — the way the
    // framework's own executable links it. A module cannot carry a C library into a consumer.
    exe.use_llvm = true;
    exe.root_module.linkLibrary(zurtr_dep.builder.dependency("quickjs_ng", .{ .target = target, .optimize = optimize }).artifact("quickjs-ng"));
{{/if}}
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run {{name}}");
    run_step.dependOn(&run_cmd.step);
}
