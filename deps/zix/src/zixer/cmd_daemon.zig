//! zixer daemon command: foreground control loop, `daemon stop` shuts it down

const std = @import("std");

const control = @import("control.zig");
const control_client = @import("control_client.zig");
const daemon = @import("daemon.zig");
const daemon_log = @import("daemon_log.zig");
const root_dir = @import("root_dir.zig");

const USAGE =
    \\usage:
    \\    zixer daemon         run the daemon in the foreground
    \\    zixer daemon stop    stop the daemon and every started site
    \\
;

/// Run the daemon in the foreground, or stop a running one.
///
/// Param:
/// io - std.Io
/// allocator - std.mem.Allocator (daemon site registry, long-lived)
/// arena - std.mem.Allocator (owns cfg content and paths, must outlive the daemon)
/// out - *std.Io.Writer (report target, flushed before the loop blocks)
/// root - root_dir.RootDir (resolved root dir)
/// filters - []const []const u8 (empty for foreground, {"stop"} to shut down)
///
/// Return:
/// - u8 process exit code (0 on success, 1 on any refusal)
pub fn run(io: std.Io, allocator: std.mem.Allocator, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir, filters: []const []const u8) !u8 {
    if (filters.len == 1 and std.mem.eql(u8, filters[0], "stop")) return runStop(io, arena, out, root);
    if (filters.len != 0) {
        try out.writeAll(USAGE);
        return 1;
    }

    var control_daemon = daemon.Daemon.init(allocator, io, arena, root) catch |err| switch (err) {
        error.ZixerNotInitialized => {
            try out.print("zixer is not initialized (no main.cfg in {s})\nrun: zixer init\n", .{root.path});
            return 1;
        },
        error.ZixerMainCfgInvalid => {
            try out.writeAll("main.cfg has errors, run: zixer status\n");
            return 1;
        },
        else => return err,
    };
    defer control_daemon.deinit();

    if (!control.fitsSocket(control_daemon.socket_path)) {
        try out.print("control socket path is too long for this platform: {s}\nuse a shorter --dir\n", .{control_daemon.socket_path});
        return 1;
    }
    if (control_client.ping(io, control_daemon.socket_path)) {
        try out.print("daemon is already running on {s}\n", .{control_daemon.socket_path});
        return 1;
    }

    // From here on the daemon's own logger is the only writer, and out is left
    // alone. The two cannot share a destination: out writes to stdout at a
    // position it tracks itself, and a positional write does not move the file
    // offset the logger's console sink appends at, so `zixer daemon > file 2>&1`
    // would have the two overwrite each other from byte zero.
    try out.flush();

    daemon_log.logSystem(&control_daemon.logger, .INFO, "daemon: listening on {s}", .{control_daemon.socket_path});

    control_daemon.run() catch |err| {
        daemon_log.logSystem(&control_daemon.logger, .ERROR, "daemon failed ({s})", .{@errorName(err)});
        return 1;
    };

    return 0;
}

/// Send shutdown to the running daemon and report its reply.
fn runStop(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir) !u8 {
    const socket_path = try control.socketPath(io, arena, root.path);

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = control_client.call(io, socket_path, "shutdown", &reply_buf) catch |err| switch (err) {
        error.ZixerDaemonNotRunning => {
            try out.writeAll("daemon is not running\n");
            return 1;
        },
        error.ZixerUdsNotSupported => {
            try out.writeAll("unix sockets are not supported on this platform\n");
            return 1;
        },
        else => return err,
    };

    try out.print("{s}\n", .{reply.text});

    return if (reply.ok) 0 else 1;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: cmd daemon, unknown sub-argument shows usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, std.testing.allocator, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_daemon_usage", .source = .ARG }, &.{"bogus"});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer daemon stop") != null);
}

test "zix zixer: cmd daemon, stop with an extra argument shows usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, std.testing.allocator, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_daemon_usage", .source = .ARG }, &.{ "stop", "extra" });

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer daemon stop") != null);
}

test "zix zixer: cmd daemon, broken main.cfg refuses with a status hint" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_cmd_daemon_badmain/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_cmd_daemon_badmain") catch {};

    std.Io.Dir.cwd().createDirPath(io, test_root) catch {};
    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{});
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll("no_such_key: 1\n");
    try writer.interface.flush();
    file.close(io);

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, std.testing.allocator, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "main.cfg has errors, run: zixer status") != null);
}

test "zix zixer: cmd daemon, missing root asks for zixer init" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, std.testing.allocator, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_daemon_absent/root", .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer init") != null);
}

test "zix zixer: cmd daemon, stop without a running daemon reports it" {
    if (comptime !std.Io.net.has_unix_sockets) {
        std.log.info("unix sockets are unavailable on this target, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, std.testing.allocator, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_daemon_stop_dead/root", .source = .ARG }, &.{"stop"});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "daemon is not running") != null);
}
