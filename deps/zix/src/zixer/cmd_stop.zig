//! zixer stop command: ask the daemon to unbind one site

const std = @import("std");

const control = @import("control.zig");
const control_client = @import("control_client.zig");
const root_dir = @import("root_dir.zig");

const USAGE =
    \\usage:
    \\    zixer stop <site.cfg>
    \\
    \\stops one started site inside the daemon. The name is a file under
    \\sites/, the .cfg suffix is optional.
    \\
;

/// Stop one site. A dead daemon is reported, never spawned.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns paths and the request line)
/// out - *std.Io.Writer (report target, caller flushes)
/// root - root_dir.RootDir (resolved root dir)
/// filters - []const []const u8 (exactly one site name)
///
/// Return:
/// - u8 process exit code (0 when the site stopped, 1 on any refusal)
pub fn run(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir, filters: []const []const u8) !u8 {
    if (filters.len != 1) {
        try out.writeAll(USAGE);
        return 1;
    }

    const name = try control.normalizeSiteName(arena, filters[0]);
    const socket_path = try control.socketPath(io, arena, root.path);

    const request_line = try std.fmt.allocPrint(arena, "stop {s}", .{name});
    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = control_client.call(io, socket_path, request_line, &reply_buf) catch |err| switch (err) {
        error.ZixerDaemonNotRunning => {
            try out.writeAll("daemon is not running, nothing is started\n");
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

test "zix zixer: cmd stop, no name shows usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_stop_usage", .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer stop <site.cfg>") != null);
}

test "zix zixer: cmd stop, extra names show usage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_stop_usage", .source = .ARG }, &.{ "a.cfg", "b.cfg" });

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer stop <site.cfg>") != null);
}

test "zix zixer: cmd stop, dead daemon is reported not spawned" {
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
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_cmd_stop_dead/root", .source = .ARG }, &.{"service_a"});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "daemon is not running") != null);
}
