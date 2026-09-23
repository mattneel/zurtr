//! zixer version command: the package version plus the toolchain it was built with

const std = @import("std");
const builtin = @import("builtin");
const zix = @import("zix");

/// What zixer reports as its version. zixer has no version of its own: it
/// ships with the engine, so it reports the engine's package version and can
/// never drift from it.
pub const VERSION: []const u8 = zix.VERSION;

/// The target this binary was built for, i.e. "x86_64-linux". The installed
/// name carries the same triplet.
pub const TRIPLET: []const u8 = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag);

/// Print the version line.
///
/// Note:
/// - One line on purpose: everything a bug report needs, nothing to parse
///   around. The zig version comes from zix.ZIG_SEMVER, the one place the
///   compiler version is read.
///
/// Param:
/// out - *std.Io.Writer (report target, caller flushes)
///
/// Return:
/// - u8 process exit code (always 0)
pub fn run(out: *std.Io.Writer) !u8 {
    try out.print("zixer {s} (zig {d}.{d}.{d}, {s})\n", .{
        VERSION,
        zix.ZIG_SEMVER.MAJOR,
        zix.ZIG_SEMVER.MINOR,
        zix.ZIG_SEMVER.PATCH,
        TRIPLET,
    });

    return 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: cmd version, line carries the package version and toolchain" {
    var report_buf: [256]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);

    const code = try run(&report);
    const line = report.buffered();

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.startsWith(u8, line, "zixer "));
    try std.testing.expect(std.mem.indexOf(u8, line, VERSION) != null);
    try std.testing.expect(std.mem.indexOf(u8, line, TRIPLET) != null);
    try std.testing.expect(std.mem.endsWith(u8, line, ")\n"));

    var zig_buf: [32]u8 = undefined;
    const zig_version = try std.fmt.bufPrint(&zig_buf, "zig {d}.{d}.{d}", .{
        zix.ZIG_SEMVER.MAJOR,
        zix.ZIG_SEMVER.MINOR,
        zix.ZIG_SEMVER.PATCH,
    });
    try std.testing.expect(std.mem.indexOf(u8, line, zig_version) != null);
}

test "zix zixer: cmd version, the version follows the zix package" {
    try std.testing.expectEqualStrings(zix.VERSION, VERSION);
    try std.testing.expect(VERSION.len != 0);

    // A package version is one token: a space here would mean the string came
    // from somewhere other than build.zig.zon.
    try std.testing.expect(std.mem.indexOfScalar(u8, VERSION, ' ') == null);
}

test "zix zixer: cmd version, triplet names this target" {
    try std.testing.expect(std.mem.indexOfScalar(u8, TRIPLET, '-') != null);
    try std.testing.expect(std.mem.startsWith(u8, TRIPLET, @tagName(builtin.cpu.arch)));
    try std.testing.expect(std.mem.endsWith(u8, TRIPLET, @tagName(builtin.os.tag)));
}

test "zix zixer: cmd version, a small buffer reports the write failure" {
    var tiny_buf: [4]u8 = undefined;
    var tiny = std.Io.Writer.fixed(&tiny_buf);

    try std.testing.expectError(error.WriteFailed, run(&tiny));
}
