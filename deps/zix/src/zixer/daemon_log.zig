//! zixer daemon logging: build the daemon's logger from main.cfg, and the one call that writes to it

const std = @import("std");
const zix = @import("zix");

const main_cfg = @import("main_cfg.zig");

const log = std.log.scoped(.zixer);

/// Severity of one daemon line, the zix logger's own enum so a level travels unchanged.
pub const Level = zix.Logger.Level;

/// Base name of the daemon's log files, so a rotated set reads zixer-000000.log.
pub const FILE_NAME = "zixer";

/// Component tag every daemon line carries.
const COMPONENT = "zixer";

/// Build the daemon's logger out of the parsed main.cfg.
///
/// Note:
/// - Both sinks share one dial. log_level sets the file threshold and the console threshold
///   together, because an operator asking for more detail wants it wherever they are reading.
/// - logs_dir is the file sink. An empty one leaves the daemon with console output only, which is
///   what a root with no logs directory gets rather than a refusal to start.
/// - The directory itself is not created here. zixer init makes it and zixer status checks it, so
///   a missing one is already reported before the daemon runs.
///
/// Param:
/// allocator - std.mem.Allocator (owns the logger's write buffer until deinit)
/// cfg - main_cfg.MainCfg (logs_dir and log_level)
///
/// Return:
/// - zix.Logger the caller owns and must deinit
/// - whatever the write-buffer allocation raised
pub fn build(allocator: std.mem.Allocator, cfg: main_cfg.MainCfg) !zix.Logger {
    return zix.Logger.init(allocator, .{
        .console = .ALWAYS,
        .console_min_level = cfg.log_level,
        .save_path = cfg.logs_dir,
        .save_file = FILE_NAME,
        .save_min_level = cfg.log_level,
    });
}

/// Write one daemon line at the given level.
///
/// Note:
/// - The logger is optional because the command paths run before one exists, and a test builds a
///   site without one. Those callers still reach std.log, so a failure is never dropped for the
///   want of a logger.
///
/// Param:
/// logger - ?*zix.Logger (the daemon's, null before it is built)
/// level - Level (.ERROR for a failure the operator must act on)
pub fn logSystem(logger: ?*zix.Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
    if (logger) |lg| {
        lg.system(level, COMPONENT, fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

/// Cfg spelling of a level, null when unknown.
///
/// Param:
/// value - []const u8 (the main.cfg value, lowercase)
///
/// Return:
/// - ?Level
pub fn parseLevel(value: []const u8) ?Level {
    if (std.mem.eql(u8, value, "debug")) return .DEBUG;
    if (std.mem.eql(u8, value, "info")) return .INFO;
    if (std.mem.eql(u8, value, "warn")) return .WARN;
    if (std.mem.eql(u8, value, "error")) return .ERROR;

    return null;
}

/// Lowercase cfg spelling of a level, for status output.
///
/// Param:
/// level - Level
///
/// Return:
/// - []const u8
pub fn levelName(level: Level) []const u8 {
    return switch (level) {
        .DEBUG => "debug",
        .INFO => "info",
        .WARN => "warn",
        .ERROR => "error",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: daemon log, every cfg spelling round trips" {
    try std.testing.expectEqual(Level.DEBUG, parseLevel("debug").?);
    try std.testing.expectEqual(Level.INFO, parseLevel("info").?);
    try std.testing.expectEqual(Level.WARN, parseLevel("warn").?);
    try std.testing.expectEqual(Level.ERROR, parseLevel("error").?);

    try std.testing.expectEqualStrings("debug", levelName(.DEBUG));
    try std.testing.expectEqualStrings("info", levelName(.INFO));
    try std.testing.expectEqualStrings("warn", levelName(.WARN));
    try std.testing.expectEqualStrings("error", levelName(.ERROR));
}

test "zix zixer: daemon log, an unknown or wrongly cased spelling is refused" {
    try std.testing.expectEqual(@as(?Level, null), parseLevel("verbose"));
    try std.testing.expectEqual(@as(?Level, null), parseLevel("ERROR"));
    try std.testing.expectEqual(@as(?Level, null), parseLevel(""));
}

test "zix zixer: daemon log, build carries logs_dir and log_level into both sinks" {
    // A real directory, because build opens the day file straight away and a missing root would
    // report a suspend on stderr rather than exercise the config carry this test is about.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try build(std.testing.allocator, .{ .logs_dir = root, .log_level = .WARN });
    defer logger.deinit();

    try std.testing.expectEqualStrings(root, logger.config.save_path);
    try std.testing.expectEqualStrings(FILE_NAME, logger.config.save_file);
    try std.testing.expectEqual(Level.WARN, logger.config.save_min_level);
    try std.testing.expectEqual(Level.WARN, logger.config.console_min_level);

    // The console sink is on in every build mode. It is the one destination
    // left when logs_dir cannot be written, so a failure is never lost.
    try std.testing.expectEqual(zix.Logger.ConsoleMode.ALWAYS, logger.config.console);
}

test "zix zixer: daemon log, an empty logs_dir leaves the console sink only" {
    var logger = try build(std.testing.allocator, .{});
    defer logger.deinit();

    try std.testing.expectEqual(@as(usize, 0), logger.config.save_path.len);
    try std.testing.expectEqual(Level.INFO, logger.config.console_min_level);
}

test "zix zixer: daemon log, logSystem with no logger does not reach for one" {
    logSystem(null, .DEBUG, "no logger attached", .{});
    logSystem(null, .INFO, "no logger attached", .{});
}

test "zix zixer: daemon log, logSystem files the level it was given" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    // Built by hand rather than through build(), because build() turns the
    // console on and this test would then print its own expected line.
    var logger = try zix.Logger.init(std.testing.allocator, .{
        .console = .OFF,
        .save_path = root,
        .save_file = FILE_NAME,
        .save_min_level = .DEBUG,
    });
    defer logger.deinit();

    logSystem(&logger, .ERROR, "upstream {s} refused the connect", .{"127.0.0.1:9000"});
    logger.flush();

    const line = try readLoggedLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, line, "ERROR") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "upstream 127.0.0.1:9000 refused the connect") != null);
}

/// Read back the one log file written under a temp root.
///
/// Note:
/// - The logger names its file after the current date, so the day directory is found by scanning
///   rather than by rebuilding the date and risking a midnight straddle.
///
/// Return:
/// - the file's bytes, caller owns them
/// - error.ZixerNoLogLine when the logger wrote nothing
fn readLoggedLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
    var days = root.iterate();

    while (try days.next(std.testing.io)) |entry| {
        if (entry.kind != .directory) continue;

        var day = try root.openDir(std.testing.io, entry.name, .{});
        defer day.close(std.testing.io);

        var name_buf: [64]u8 = undefined;
        const file_name = try std.fmt.bufPrint(&name_buf, "{s}-000000.log", .{FILE_NAME});

        const bytes = day.readFileAlloc(std.testing.io, file_name, allocator, .limited(64 * 1024)) catch continue;
        if (bytes.len > 0) return bytes;

        allocator.free(bytes);
    }

    return error.ZixerNoLogLine;
}
