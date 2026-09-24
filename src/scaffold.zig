//! The project generator: `zurtr new`.
//!
//! The recipe is deliberately not "write a whole project from scratch". It is:
//!
//!   1. `zig init` — the toolchain's own scaffold, in the target directory.
//!   2. `zig fetch --save <this checkout>` — the toolchain adding zurtr as a dependency.
//!   3. our template over the example — `build.zig`, `src/main.zig`, `.gitignore`, `README.md`.
//!   4. delete `src/root.zig`, which is the library half of zig's example and not an application.
//!   5. the installer hooks.
//!
//! Two things fall out of letting the toolchain do its own work. `build.zig.zon` is zig's,
//! including the `.fingerprint` field it validates against a CRC of the project name — a value no
//! scaffolder can hardcode, because a zon takes only an integer literal and the value depends on
//! the name. And the dependency is written by the tool that knows the dependency's format,
//! including the relative-path restriction the zon enforces. Both were blockers found by reading
//! the compiler; both are answered by not doing them ourselves.
//!
//! The manifest below is the plan — which files a scaffold contains, under which conditions, and
//! which hooks run afterwards — expressed as data so it can be read in one screen and tested
//! without a filesystem. Conditional entries are what make composition possible without a plugin
//! API: a scaffold carries every variant's files and each declares what it needs, so `--no-live`
//! does not remove a file from the manifest, it stops the entries whose condition is `.live` from
//! being written.

const std = @import("std");
const Io = std.Io;
const templ = @import("templ.zig");

/// What the caller asked for, plus what the executable knows about itself.
pub const Options = struct {
    /// The project name: the directory name, what zig's own scaffold will call it, and the
    /// `{{name}}` the templates use.
    name: []const u8,
    /// Where to write, relative to the current directory or absolute.
    dir: []const u8,
    /// Write into a directory that already exists. Off by default: a generator that merges into an
    /// existing tree has to decide what a conflict means, and this one would rather not.
    force: bool = false,
    /// Include the persistence wiring (`--no-data` turns it off).
    data: bool = true,
    /// Include the live UI route (`--no-live` turns it off).
    live: bool = true,
    /// Include the script seam (`--zscript` turns it on; off by default because it costs a C
    /// toolchain and a first build measured in minutes).
    zscript: bool = false,
    /// Run the installer hooks at all (`--no-hooks` turns them off).
    hooks: bool = true,
    /// Include the hooks that compile or fetch (`--install`). Off by default: an application's
    /// first build compiles this framework, the vendored transport and — when asked for — a
    /// JavaScript engine, so a generator that appears to hang is worse than one that prints the
    /// command to run next.
    install: bool = false,
};

/// Where this checkout is and which compiler to drive. Both are embedded by the build, because
/// neither can be discovered at run time: the generated project lives somewhere else on disk, and
/// the compiler that built this executable is the one whose version the generated manifest has to
/// agree with — a `zig` found on PATH may be a shim that cannot resolve a version in an empty
/// directory, which is a failure this generator would otherwise report as its own.
pub const Toolchain = struct {
    zurtr_path: []const u8,
    zig_exe: []const u8,
};

/// When an entry or a hook applies. The conditions are the flags the CLI exposes, and a test
/// asserts every variant is reachable.
pub const Condition = enum {
    always,
    data,
    live,
    zscript,

    pub fn holds(self: Condition, options: Options) bool {
        return switch (self) {
            .always => true,
            .data => options.data,
            .live => options.live,
            .zscript => options.zscript,
        };
    }
};

/// One generated file. `source` is the template itself, embedded, so the generator carries its
/// templates the way it carries everything else and a missing `.tpl` is a compile error rather
/// than a runtime surprise. `dest` is where the rendered output goes, relative to the project
/// directory.
///
/// `build.zig.zon` is deliberately absent: zig writes it, and `zig fetch --save` patches the
/// dependency into it.
pub const Entry = struct {
    source: []const u8,
    dest: []const u8,
    when: Condition = .always,
};

pub const entries = [_]Entry{
    .{ .source = @embedFile("scaffold/templates/app/build.zig.tpl"), .dest = "build.zig" },
    .{ .source = @embedFile("scaffold/templates/app/gitignore.tpl"), .dest = ".gitignore" },
    .{ .source = @embedFile("scaffold/templates/app/README.md.tpl"), .dest = "README.md" },
    .{ .source = @embedFile("scaffold/templates/app/src/main.zig.tpl"), .dest = "src/main.zig" },
};

/// A step the generator runs in the new project after writing it — the installer half.
pub const Hook = struct {
    /// What to call it in the output. The command itself is not enough: `git init -q` prints
    /// nothing, so a user watching would not know whether anything happened.
    label: []const u8,
    argv: []const []const u8,
    when: Condition = .always,
    /// Hooks that compile or fetch are off unless `--install`.
    needs_install: bool = false,
};

pub const hooks = [_]Hook{
    .{ .label = "git repository", .argv = &.{ "git", "init", "-q" } },
    .{ .label = "first build", .argv = &.{ "zig", "build" }, .needs_install = true },
};

/// The entries this run writes.
pub fn planned(comptime plan: []const Entry, options: Options, out: []Entry) []Entry {
    var count: usize = 0;
    for (plan) |entry| {
        if (entry.when.holds(options)) {
            out[count] = entry;
            count += 1;
        }
    }

    return out[0..count];
}

/// The hooks this run executes.
pub fn installers(comptime plan: []const Hook, options: Options, out: []Hook) []Hook {
    var count: usize = 0;
    if (!options.hooks) return out[0..0];

    for (plan) |hook| {
        if (hook.needs_install and !options.install) continue;
        if (hook.when.holds(options)) {
            out[count] = hook;
            count += 1;
        }
    }

    return out[0..count];
}

// --------------------------------------------------------------- //

/// Generate a project. Every failure is reported to `out` as it happens and returned, so a caller
/// that wants to explain the state it left behind knows which step failed.
pub fn generate(
    gpa: std.mem.Allocator,
    io: Io,
    options: Options,
    toolchain: Toolchain,
    out: *std.Io.Writer,
) !void {
    const target = try Io.Dir.cwd().createDirPathOpen(io, options.dir, .{});
    defer target.close(io);

    // 1. The toolchain's scaffold.
    try run(gpa, io, &.{ toolchain.zig_exe, "init" }, target, out);

    // 2. The dependency, as a path relative to the project. Absolute paths are rejected by the
    //    zon, and the project is not necessarily a child of this checkout, so the relative form is
    //    computed rather than assumed.
    {
        const project_absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, options.dir, gpa);
        defer gpa.free(project_absolute);

        // Both paths are absolute, so the process cwd and the environment are only there for the
        // Windows branch and neither is consulted on this platform.
        const relative = try std.fs.path.relativeAlloc(gpa, ".", null, project_absolute, toolchain.zurtr_path);
        defer gpa.free(relative);

        try run(gpa, io, &.{ toolchain.zig_exe, "fetch", "--save", relative }, target, out);
    }

    // 3. Our template over the example.
    var plan_buffer: [entries.len]Entry = undefined;
    for (planned(&entries, options, &plan_buffer)) |entry| {
        try renderInto(gpa, io, options, entry, target, out);
    }

    // 4. The library half of zig's example. An application is not one, and leaving it means a
    //    second module nothing imports.
    Io.Dir.deleteFile(target, io, "src/root.zig") catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };

    // 5. Hooks.
    var hook_buffer: [hooks.len]Hook = undefined;
    for (installers(&hooks, options, &hook_buffer)) |hook| {
        try out.print("{s}: {s}\n", .{ options.name, hook.label });
        try out.flush();

        // A hook that needs this checkout's path gets it as an argument rather than a template:
        // hooks run in the project, which is not where either path belongs.
        try run(gpa, io, hook.argv, target, out);
    }
}

fn renderInto(
    gpa: std.mem.Allocator,
    io: Io,
    options: Options,
    entry: Entry,
    target: Io.Dir,
    out: *std.Io.Writer,
) !void {
    // The one place the engine's parameter shape is written down. When it changes, this changes,
    // and nothing else in the generator knows the engine has parameters at all.
    var diagnostic: templ.Diagnostic = undefined;
    var params: templ.Params = .{
        .name = options.name,
        .data = options.data,
        .live = options.live,
        .zscript = options.zscript,
    };
    params.diagnostic = &diagnostic;

    const rendered = templ.render(gpa, entry.source, params) catch |err| {
        // The engine fills the diagnostic rather than printing, because it cannot name the file:
        // it renders bytes, and only the manifest knows which file those bytes were for.
        try out.print("{s}: {s}:\n", .{ entry.dest, @errorName(err) });
        try diagnostic.write(out, entry.source);
        try out.flush();

        return err;
    };
    defer gpa.free(rendered);

    if (std.fs.path.dirname(entry.dest)) |parent| {
        try target.createDirPath(io, parent);
    }
    try target.writeFile(io, .{ .sub_path = entry.dest, .data = rendered });
}

/// Run a command in a directory and fail loudly if it does. Its output goes to the caller's
/// terminal rather than through a pipe: `zig init` and `git init` know better how to describe
/// themselves than a generator does, and swallowing that would hide the one thing a user wants
/// when a step they did not expect fails.
fn run(gpa: std.mem.Allocator, io: Io, argv: []const []const u8, cwd: Io.Dir, out: *std.Io.Writer) !void {
    _ = gpa;
    _ = out;

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = cwd },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code == 0) return else return error.StepFailed,
        else => return error.StepFailed,
    }
}

// --------------------------------------------------------------- //

const testing = std.testing;

const base: Options = .{ .name = "hello", .dir = "hello" };

test "a condition selects exactly the entries whose flag is set" {
    // A fixture plan, not the manifest, so the mechanism is exercised today rather than when the
    // manifest happens to grow a conditional entry. Every variant is covered because every variant
    // is reachable from the CLI.
    const fixtures = [_]Entry{
        .{ .source = "a", .dest = "always" },
        .{ .source = "b", .dest = "data", .when = .data },
        .{ .source = "c", .dest = "live", .when = .live },
        .{ .source = "d", .dest = "zscript", .when = .zscript },
    };
    var buffer: [fixtures.len]Entry = undefined;

    const only_always = planned(&fixtures, .{
        .name = "hello",
        .dir = "hello",
        .data = false,
        .live = false,
        .zscript = false,
    }, &buffer);
    try testing.expectEqual(@as(usize, 1), only_always.len);
    try testing.expectEqualStrings("always", only_always[0].dest);

    const all = planned(&fixtures, .{
        .name = "hello",
        .dir = "hello",
        .data = true,
        .live = true,
        .zscript = true,
    }, &buffer);
    try testing.expectEqual(fixtures.len, all.len);

    const no_zscript = planned(&fixtures, .{
        .name = "hello",
        .dir = "hello",
        .data = true,
        .live = true,
        .zscript = false,
    }, &buffer);
    try testing.expectEqual(fixtures.len - 1, no_zscript.len);
    for (no_zscript) |entry| try testing.expect(!std.mem.eql(u8, entry.dest, "zscript"));
}

test "destinations are unique and relative" {
    for (entries, 0..) |entry, i| {
        try testing.expect(!std.mem.startsWith(u8, entry.dest, "/"));
        try testing.expect(!std.mem.startsWith(u8, entry.dest, ".."));
        for (entries[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, entry.dest, other.dest));
        }
    }
}

test "no entry writes the manifest, and none writes the library half of the example" {
    // Both are the toolchain's: zig writes the zon (a fingerprint cannot be hardcoded) and
    // `zig fetch --save` patches the dependency in. `src/root.zig` is deleted rather than
    // overwritten, and templating it here would be a second source of truth.
    for (entries) |entry| {
        try testing.expect(!std.mem.eql(u8, entry.dest, "build.zig.zon"));
        try testing.expect(!std.mem.eql(u8, entry.dest, "src/root.zig"));
    }
}

test "the compile-and-fetch hooks are the ones --install gates" {
    var buffer: [hooks.len]Hook = undefined;

    const without = installers(&hooks, base, &buffer);
    for (without) |hook| try testing.expect(!hook.needs_install);
    try testing.expect(without.len > 0);

    const with_install = installers(&hooks, .{ .name = "hello", .dir = "hello", .install = true }, &buffer);
    try testing.expectEqual(@as(usize, hooks.len), with_install.len);

    const none = installers(&hooks, .{ .name = "hello", .dir = "hello", .hooks = false }, &buffer);
    try testing.expectEqual(@as(usize, 0), none.len);
}
