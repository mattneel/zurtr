//! zixer start command: ask the daemon to bind one site, spawning it when needed

const std = @import("std");

const control = @import("control.zig");
const control_client = @import("control_client.zig");
const daemon_spawn = @import("daemon_spawn.zig");
const root_dir = @import("root_dir.zig");

const USAGE =
    \\usage:
    \\    zixer start <site.cfg>
    \\
    \\starts one site inside the daemon, spawning the daemon when it is not
    \\running. The name is a file under sites/, the .cfg suffix is optional.
    \\
;

/// Start one site.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns paths and the request line)
/// out - *std.Io.Writer (report target, caller flushes)
/// root - root_dir.RootDir (resolved root dir)
/// filters - []const []const u8 (exactly one site name)
/// exe_path - []const u8 (argv[0], respawned as the daemon when needed)
///
/// Return:
/// - u8 process exit code (0 when the site started, 1 on any refusal)
pub fn run(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir, filters: []const []const u8, exe_path: []const u8) !u8 {
    if (filters.len != 1) {
        try out.writeAll(USAGE);
        return 1;
    }

    const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });
    std.Io.Dir.cwd().access(io, main_cfg_path, .{}) catch {
        try out.print("zixer is not initialized (no {s})\nrun: zixer init\n", .{main_cfg_path});
        return 1;
    };

    const name = try control.normalizeSiteName(arena, filters[0]);
    const socket_path = try control.socketPath(io, arena, root.path);

    daemon_spawn.ensure(io, exe_path, root.path, socket_path) catch |err| switch (err) {
        error.ZixerDaemonStartTimeout => {
            try out.writeAll("daemon did not answer after spawn, run: zixer daemon to see why\n");
            return 1;
        },
        else => return err,
    };

    const request_line = try std.fmt.allocPrint(arena, "start {s}", .{name});
    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = control_client.call(io, socket_path, request_line, &reply_buf) catch |err| switch (err) {
        error.ZixerDaemonNotRunning => {
            try out.writeAll("daemon went away, run: zixer start again\n");
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

test "zix zixer: cmd start, no name shows usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_start_usage", .source = .ARG }, &.{}, "zixer");

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer start <site.cfg>") != null);
}

test "zix zixer: cmd start, extra names show usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_start_usage", .source = .ARG }, &.{ "a.cfg", "b.cfg" }, "zixer");

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer start <site.cfg>") != null);
}

test "zix zixer: cmd start, missing root asks for zixer init before any spawn" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_start_absent/root", .source = .ARG }, &.{"service_a"}, "zixer");

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer init") != null);
}
