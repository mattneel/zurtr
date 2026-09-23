//! The project generator: `zurtr new`.
//!
//! Two halves, and the split is the point. This half is the **plan** — which files a scaffold
//! contains, under which conditions, and which installer hooks run afterwards — expressed as data
//! so it can be read in one screen and tested without touching a filesystem. The other half renders
//! that plan through `src/templ.zig` and writes it.
//!
//! Why not a script: a scaffold that produces a project which does not build is worse than no
//! scaffold, because the failure arrives at the user's first command with no obvious cause. So the
//! plan is declarative, every entry is checked by a test that renders it, and `zurtr new` refuses
//! to write over an existing directory rather than merging into it.
//!
//! The conditional entries are what make composition possible without a plugin API: a scaffold
//! carries every variant's files and each declares what it needs. `--no-data` does not remove a
//! file from the manifest, it stops the entries whose `when` is `.data` from being written, and the
//! templates that survive are the same ones — which is why there is one template set rather than
//! three.

const std = @import("std");

/// What the caller asked for. Every conditional in the manifest is answered by this.
pub const Options = struct {
    /// The project name: the directory name by default, and the `{{name}}` the templates use.
    name: []const u8,
    /// Where to write. Defaults to `<name>` in the current directory.
    dir: []const u8,
    /// Write into a directory that already exists. Off by default: a generator that merges into
    /// an existing tree is a generator that has to decide what a conflict means, and this one
    /// would rather not.
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

/// When an entry or a hook applies. One enum rather than a predicate per entry: the conditions are
/// the flags the CLI exposes, and a test asserts every variant is reachable.
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

/// One generated file. `template` names a file under `templates/` without its `.tpl` suffix, and
/// `dest` is where the rendered output goes, relative to the project directory.
pub const Entry = struct {
    template: []const u8,
    dest: []const u8,
    when: Condition = .always,
};

/// The manifest. Adding a file to the scaffold means adding a line here and a `.tpl` beside the
/// others; nothing else in the generator changes.
pub const entries = [_]Entry{
    .{ .template = "app/build.zig", .dest = "build.zig" },
    .{ .template = "app/build.zig.zon", .dest = "build.zig.zon" },
    .{ .template = "app/gitignore", .dest = ".gitignore" },
    .{ .template = "app/README.md", .dest = "README.md" },
    .{ .template = "app/src/main.zig", .dest = "src/main.zig" },
};

/// A step the generator runs in the new project after writing it — the installer half.
pub const Hook = struct {
    /// What to call it in the output. The command itself is not enough: `git init -q` prints
    /// nothing, so a user watching would not know whether anything happened.
    label: []const u8,
    argv: []const []const u8,
    when: Condition = .always,
    /// Hooks that compile or fetch are off unless `--install`. Everything else runs.
    needs_install: bool = false,
};

pub const hooks = [_]Hook{
    .{ .label = "git repository", .argv = &.{ "git", "init", "-q" } },
    .{
        .label = "first build",
        .argv = &.{ "zig", "build" },
        .needs_install = true,
    },
};

/// The value a generated project's `build.zig.zon` needs for `.fingerprint`, as 16 lowercase hex
/// digits without a `0x` prefix — the form the templates interpolate.
///
/// This cannot be hardcoded: Zig validates the field as a packed `struct(u64) { id: u32, checksum:
/// u32 }` with `checksum == Crc32(name)` and an id that is neither 0 nor 0xffffffff, and a zon
/// accepts only an integer literal — no expressions. A wrong or absent fingerprint fails the
/// generated project at `zig build` with "invalid fingerprint: 0x…", which would make the whole
/// generator useless for every name but the one it was written for.
///
/// The id is 1 rather than random. The toolchain generates a random one, and its comment gives the
/// reason uniqueness matters: only among packages in a single dependency graph. Two projects from
/// this command have different names in theirs, so a fixed id is correct here — and a generator
/// whose output changes between runs for the same input is harder to check than one whose output
/// does not.
///
/// Verified against the toolchain rather than argued: in a zon with a dependency graph, `id = 1`
/// builds and `id = 0xffffffff` is rejected with "invalid fingerprint: …; use this value: 0x…",
/// and that suggested value's high half is exactly what `std.hash.Crc32` returns for the name — so
/// this agrees with the compiler's own generator on the half that carries meaning.
pub fn fingerprint(name: []const u8, out: *[16]u8) []const u8 {
    const id: u32 = 1;
    const value: u64 = (@as(u64, std.hash.Crc32.hash(name)) << 32) | id;

    return std.fmt.bufPrint(out, "{x:0>16}", .{value}) catch unreachable;
}

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
    for (plan) |hook| {
        if (!options.hooks) break;
        if (hook.needs_install and !options.install) continue;
        if (hook.when.holds(options)) {
            out[count] = hook;
            count += 1;
        }
    }

    return out[0..count];
}

// --------------------------------------------------------------- //

const testing = std.testing;

const base: Options = .{ .name = "hello", .dir = "hello" };

test "a condition selects exactly the entries whose flag is set" {
    // A fixture plan, not the manifest, so the mechanism is exercised today rather than when the
    // manifest happens to grow a conditional entry. Every variant is covered because every variant
    // is reachable from the CLI.
    const fixtures = [_]Entry{
        .{ .template = "a", .dest = "always" },
        .{ .template = "b", .dest = "data", .when = .data },
        .{ .template = "c", .dest = "live", .when = .live },
        .{ .template = "d", .dest = "zscript", .when = .zscript },
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

test "the fingerprint satisfies the rule the toolchain validates" {
    // The rule, restated from the compiler rather than trusted: the high half is the CRC and the
    // low half is an id outside {0, 0xffffffff}. If a rendered zon is ever rejected, this is the
    // test that should have caught it.
    for ([_][]const u8{ "hello", "", "a-longer-project-name", "Zig", "x" }) |name| {
        var buffer: [16]u8 = undefined;
        const hex = fingerprint(name, &buffer);

        try testing.expectEqual(@as(usize, 16), hex.len);
        const value = try std.fmt.parseInt(u64, hex, 16);

        const id: u32 = @truncate(value);
        const checksum: u32 = @truncate(value >> 32);
        try testing.expect(id != 0);
        try testing.expect(id != 0xffffffff);
        try testing.expectEqual(std.hash.Crc32.hash(name), checksum);
    }

    // Same input, same output: a generator that cannot be checked twice is a generator nobody
    // can compare against a fix.
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings(fingerprint("hello", &a), fingerprint("hello", &b));

    // And different names differ, or the checksum half is not doing its job.
    var c: [16]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, fingerprint("hello", &a), fingerprint("world", &c)));
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
