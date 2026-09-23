//! zixer list command: one line per loaded site config

const std = @import("std");
const zix = @import("zix");

const cmd_status = @import("cmd_status.zig");
const fault = @import("fault.zig");
const main_cfg = @import("main_cfg.zig");
const root_dir = @import("root_dir.zig");
const site_cfg = @import("site_cfg.zig");

/// Hard ceiling for one config file, a larger file fails instead of allocating.
const MAX_CFG_BYTES: usize = 256 * 1024;

/// List every site config under sites_dir with a one-line verdict.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns file contents and assembled paths)
/// out - *std.Io.Writer (report target, caller flushes)
/// root - root_dir.RootDir (resolved root dir)
///
/// Return:
/// - u8 process exit code (0 when initialized, 1 otherwise)
pub fn run(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir) !u8 {
    const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });
    const content = zix.utils.file.load(io, arena, main_cfg_path, MAX_CFG_BYTES) catch {
        try out.print("zixer is not initialized (no {s})\nrun: zixer init\n", .{main_cfg_path});
        return 1;
    };

    const available_threads = std.Thread.getCpuCount() catch 1;
    var main_faults = fault.FaultList.init(arena);
    const cfg = try main_cfg.parse(arena, content, root.path, available_threads, &main_faults);

    const site_names = try cmd_status.listSiteNames(io, arena, cfg.sites_dir);
    if (site_names.len == 0) {
        try out.print("no site configs in {s}\ncopy the sample there as <name>.cfg to add one\n", .{cfg.sites_dir});
        return 0;
    }

    for (site_names) |name| {
        const site_path = try std.fs.path.join(arena, &.{ cfg.sites_dir, name });
        var site_faults = fault.FaultList.init(arena);

        var site: site_cfg.SiteCfg = .{};
        if (zix.utils.file.load(io, arena, site_path, MAX_CFG_BYTES)) |site_content| {
            site = try site_cfg.parse(arena, site_content, &site_faults);
        } else |err| {
            try site_faults.add(name, "cannot read file ({s})", .{@errorName(err)});
        }

        if (site_faults.slice().len == 0 and site.engine != null and site.port != null) {
            try out.print("{s}: ok, {s}, {s}:{d}\n", .{ name, site_cfg.engineName(site.engine.?), site.ip, site.port.? });
        } else {
            try out.print("{s}: error, run: zixer status {s}\n", .{ name, name });
        }
    }

    return 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const cmd_init = @import("cmd_init.zig");

fn writeSiteFile(io: std.Io, arena: std.mem.Allocator, root: []const u8, name: []const u8, content: []const u8) !void {
    const path = try std.fs.path.join(arena, &.{ root, "sites", name });
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    var write_buf: [1024]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(content);
    try writer.interface.flush();
}

test "zix zixer: cmd list, ok and error sites each get one line" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_list_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_list_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nport: 8080\nupstreams: 127.0.0.1:3000\n");
    try writeSiteFile(io, arena.allocator(), test_root, "service_bad.cfg", "engine: http1\n");

    var report_buf: [4096]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG });

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "service_a.cfg: ok, http1, 0.0.0.0:8080") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "service_bad.cfg: error, run: zixer status service_bad.cfg") != null);
}

test "zix zixer: cmd list, empty sites dir explains how to add one" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_list_empty_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_list_empty_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG });

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "no site configs in") != null);
}

test "zix zixer: cmd list, missing root asks for zixer init" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_list_absent/root", .source = .ARG });

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer init") != null);
}
