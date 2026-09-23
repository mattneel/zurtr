//! zixer root dir resolution: --dir, then ZIXER_DIR, then $HOME/.zixer

const std = @import("std");
const builtin = @import("builtin");

pub const Source = enum {
    ARG,
    ENV,
    HOME,
};

/// Resolved root dir plus which source resolved it, so status can say where
/// the dir came from.
pub const RootDir = struct {
    path: []const u8,
    source: Source,
};

/// Resolve the zixer root dir. Fixed order, first hit wins:
/// 1. --dir argument
/// 2. ZIXER_DIR environment variable
/// 3. $HOME/.zixer
///
/// Param:
/// arena - std.mem.Allocator (owns the returned path)
/// dir_arg - ?[]const u8 (value after --dir, null when absent)
/// env_dir - ?[]const u8 (ZIXER_DIR value, null when unset)
/// env_home - ?[]const u8 (HOME value, null when unset)
///
/// Return:
/// - RootDir (path plus the source that resolved it)
/// - error.ZixerNoHomeDir when nothing resolves
pub fn resolve(
    arena: std.mem.Allocator,
    dir_arg: ?[]const u8,
    env_dir: ?[]const u8,
    env_home: ?[]const u8,
) !RootDir {
    if (dir_arg) |dir| return .{ .path = try arena.dupe(u8, dir), .source = .ARG };

    if (env_dir) |dir| {
        if (dir.len != 0) return .{ .path = try arena.dupe(u8, dir), .source = .ENV };
    }

    const home = env_home orelse return error.ZixerNoHomeDir;
    if (home.len == 0) return error.ZixerNoHomeDir;

    return .{ .path = try std.fs.path.join(arena, &.{ home, ".zixer" }), .source = .HOME };
}

/// Resolve from the process environment. Thin wrapper over resolve() that
/// pulls ZIXER_DIR and HOME (USERPROFILE stands in for HOME on Windows).
pub fn resolveFromEnviron(
    arena: std.mem.Allocator,
    dir_arg: ?[]const u8,
    environ_map: *std.process.Environ.Map,
) !RootDir {
    const env_home = if (comptime builtin.os.tag == .windows)
        environ_map.get("USERPROFILE")
    else
        environ_map.get("HOME");

    return resolve(arena, dir_arg, environ_map.get("ZIXER_DIR"), env_home);
}

/// Cfg-style name of a source, for status output.
pub fn sourceName(source: Source) []const u8 {
    return switch (source) {
        .ARG => "--dir",
        .ENV => "ZIXER_DIR",
        .HOME => "HOME",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: root dir, --dir wins over everything" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const root = try resolve(arena.allocator(), "/srv/zixer", "/env/dir", "/home/someone");
    try std.testing.expectEqualStrings("/srv/zixer", root.path);
    try std.testing.expectEqual(Source.ARG, root.source);
}

test "zix zixer: root dir, ZIXER_DIR wins over HOME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const root = try resolve(arena.allocator(), null, "/env/dir", "/home/someone");
    try std.testing.expectEqualStrings("/env/dir", root.path);
    try std.testing.expectEqual(Source.ENV, root.source);
}

test "zix zixer: root dir, HOME fallback appends .zixer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const root = try resolve(arena.allocator(), null, null, "/home/someone");
    const expected = try std.fs.path.join(arena.allocator(), &.{ "/home/someone", ".zixer" });
    try std.testing.expectEqualStrings(expected, root.path);
    try std.testing.expectEqual(Source.HOME, root.source);
}

test "zix zixer: root dir, empty ZIXER_DIR falls through to HOME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const root = try resolve(arena.allocator(), null, "", "/home/someone");
    try std.testing.expectEqual(Source.HOME, root.source);
}

test "zix zixer: root dir, nothing resolves is an error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.ZixerNoHomeDir, resolve(arena.allocator(), null, null, null));
    try std.testing.expectError(error.ZixerNoHomeDir, resolve(arena.allocator(), null, null, ""));
}
