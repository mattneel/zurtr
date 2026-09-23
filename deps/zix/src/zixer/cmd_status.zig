//! zixer status command: validate configs and report with fix hints

const std = @import("std");
const zix = @import("zix");

const fault = @import("fault.zig");
const daemon_log = @import("daemon_log.zig");
const main_cfg = @import("main_cfg.zig");
const root_dir = @import("root_dir.zig");
const site_cfg = @import("site_cfg.zig");
const worker_count = @import("worker_count.zig");

/// Hard ceiling for one config file, a larger file fails instead of allocating.
const MAX_CFG_BYTES: usize = 256 * 1024;

/// Validate main.cfg plus every site cfg and report each as its own block.
///
/// Note:
/// - filters narrows the report to the named configs (with or without .cfg).
///   A filter that matches nothing is reported and fails the run.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns file contents and assembled paths)
/// out - *std.Io.Writer (report target, caller flushes)
/// root - root_dir.RootDir (resolved root dir)
/// filters - []const []const u8 (config names to show, empty shows all)
///
/// Return:
/// - u8 process exit code (0 all shown configs pass, 1 otherwise)
pub fn run(
    io: std.Io,
    arena: std.mem.Allocator,
    out: *std.Io.Writer,
    root: root_dir.RootDir,
    filters: []const []const u8,
) !u8 {
    const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });
    const content = zix.utils.file.load(io, arena, main_cfg_path, MAX_CFG_BYTES) catch {
        try out.print(
            \\zixer is not initialized (no {s})
            \\run: zixer init
            \\custom dir: zixer init --dir /foo/bar (then --dir or ZIXER_DIR on every command)
            \\
        , .{main_cfg_path});

        return 1;
    };

    const available_threads = worker_count.available();
    var main_faults = fault.FaultList.init(arena);
    const cfg = try main_cfg.parse(arena, content, root.path, available_threads, &main_faults);
    try checkDirExists(io, &main_faults, "logs_dir", cfg.logs_dir);
    try checkDirExists(io, &main_faults, "sites_dir", cfg.sites_dir);

    const matched = try arena.alloc(bool, filters.len);
    @memset(matched, false);

    var any_error = false;
    if (matches(filters, matched, "main.cfg")) {
        try renderMain(out, main_cfg_path, cfg, main_faults.slice());
        if (main_faults.slice().len != 0) any_error = true;
    }

    const site_names = try listSiteNames(io, arena, cfg.sites_dir);
    for (site_names) |name| {
        if (!matches(filters, matched, name)) continue;

        const site_path = try std.fs.path.join(arena, &.{ cfg.sites_dir, name });
        var site_faults = fault.FaultList.init(arena);

        var site: site_cfg.SiteCfg = .{};
        if (zix.utils.file.load(io, arena, site_path, MAX_CFG_BYTES)) |site_content| {
            site = try site_cfg.parse(arena, site_content, &site_faults);
            try checkSitePaths(io, &site_faults, site);
        } else |err| {
            try site_faults.add(name, "cannot read file ({s})", .{@errorName(err)});
        }

        try renderSite(out, site_path, name, site, site_faults.slice());
        if (site_faults.slice().len != 0) any_error = true;
    }

    for (filters, matched) |filter, filter_matched| {
        if (filter_matched) continue;

        try out.print("no config named {s}\n", .{filter});
        any_error = true;
    }

    return if (any_error) 1 else 0;
}

/// Render the main.cfg block in the status format.
pub fn renderMain(out: *std.Io.Writer, path: []const u8, cfg: main_cfg.MainCfg, faults: []const fault.Fault) !void {
    try out.print("# {s}\nmain.cfg:\n", .{path});
    try out.print("status: {s}\n", .{statusWord(faults)});
    // A bare "workers: 0" tells an operator nothing about what the daemon
    // will actually run, and a platform that cannot share a listen port
    // takes any count down to 1. Print both whenever they differ.
    const resolved_workers = worker_count.resolve(cfg.workers, worker_count.available());
    if (resolved_workers == cfg.workers) {
        try out.print("workers: {d}\n", .{cfg.workers});
    } else {
        try out.print("workers: {d} (resolved to {d})\n", .{ cfg.workers, resolved_workers });
    }
    try out.print("dispatch: {s}\n", .{main_cfg.dispatchName(cfg.dispatch)});
    try out.print("logs_dir: {s}\n", .{cfg.logs_dir});
    try out.print("log_level: {s}\n", .{daemon_log.levelName(cfg.log_level)});
    try out.print("sites_dir: {s}\n", .{cfg.sites_dir});
    try out.print("max_recv_buf: {d}\n", .{cfg.max_recv_buf});
    try out.print("kernel_backlog: {d}\n", .{cfg.kernel_backlog});

    // The queue and its wait mean nothing while the limit is 0, so an
    // untouched daemon prints one honest line instead of three.
    if (cfg.process_limit == 0) {
        try out.writeAll("process_limit: 0 (gate off)\n");
    } else {
        try out.print("process_limit: {d}\n", .{cfg.process_limit});
        try out.print("process_queue_len: {d}\n", .{cfg.process_queue_len});
        try out.print("process_queue_timeout_ms: {d}\n", .{cfg.process_queue_timeout_ms});
    }

    // The limit means nothing while the bound is 0, so an untouched daemon
    // prints one honest line instead of two.
    if (cfg.client_timeout_ms == 0) {
        try out.writeAll("client_timeout_ms: 0 (bound off)\n");
    } else {
        try out.print("client_timeout_ms: {d}\n", .{cfg.client_timeout_ms});
        try out.print("client_conn_limit: {d}\n", .{cfg.client_conn_limit});
    }

    try out.print("upstream_connect_timeout_ms: {d}\n", .{cfg.upstream_connect_timeout_ms});
    try out.print("upstream_idle_ttl_ms: {d}\n", .{cfg.upstream_idle_ttl_ms});

    // The entry count means nothing while the window is 0, so the same one
    // honest line stands in for both keys.
    if (cfg.public_dir_cache_ttl_ms == 0) {
        try out.writeAll("public_dir_cache_ttl_ms: 0 (cache off)\n");
    } else {
        try out.print("public_dir_cache_ttl_ms: {d}\n", .{cfg.public_dir_cache_ttl_ms});
        try out.print("public_dir_cache_max_entries: {d}\n", .{cfg.public_dir_cache_max_entries});
    }

    try renderFaults(out, faults);
    try out.writeAll("\n");
}

/// Render one site cfg block in the status format. Only fields the file set
/// (or that parsed) are shown, the faults explain the rest.
pub fn renderSite(out: *std.Io.Writer, path: []const u8, name: []const u8, cfg: site_cfg.SiteCfg, faults: []const fault.Fault) !void {
    try out.print("# {s}\n{s}:\n", .{ path, name });
    try out.print("status: {s}\n", .{statusWord(faults)});

    if (cfg.engine) |engine| try out.print("engine: {s}\n", .{site_cfg.engineName(engine)});
    try out.print("ip: {s}\n", .{cfg.ip});
    if (cfg.port) |port| try out.print("port: {d}\n", .{port});
    try out.print("tls: {}\n", .{cfg.tls});
    if (cfg.tls_cert) |tls_cert| try out.print("tls_cert: {s}\n", .{tls_cert});
    if (cfg.tls_key) |tls_key| try out.print("tls_key: {s}\n", .{tls_key});
    if (cfg.force_https) try out.print("force_https: {}\n", .{cfg.force_https});
    if (cfg.redirect_host) |redirect_host| try out.print("redirect_host: {s}\n", .{redirect_host});
    if (cfg.acme_webroot) |acme_webroot| try out.print("acme_webroot: {s}\n", .{acme_webroot});
    if (cfg.acme_proxy) |acme_proxy| try out.print("acme_proxy: {s}:{d}\n", .{ acme_proxy.host, acme_proxy.port });

    if (cfg.upstreams.len != 0) {
        try out.writeAll("upstreams: ");
        for (cfg.upstreams, 0..) |upstream, index| {
            if (index != 0) try out.writeAll(", ");
            try out.print("{s}:{d}", .{ upstream.host, upstream.port });
        }
        try out.writeAll("\n");
    }

    if (cfg.public_dir) |public_dir| try out.print("public_dir: {s}\n", .{public_dir});
    if (cfg.public_prefix) |public_prefix| try out.print("public_prefix: {s}\n", .{public_prefix});
    if (cfg.spa_fallback) |spa_fallback| try out.print("spa_fallback: {s}\n", .{spa_fallback});
    if (cfg.kernel_backlog) |kernel_backlog| try out.print("kernel_backlog: {d}\n", .{kernel_backlog});
    if (cfg.max_recv_buf) |max_recv_buf| try out.print("max_recv_buf: {d}\n", .{max_recv_buf});
    if (cfg.client_timeout_ms) |client_timeout_ms| try out.print("client_timeout_ms: {d}\n", .{client_timeout_ms});
    if (cfg.client_conn_limit) |client_conn_limit| try out.print("client_conn_limit: {d}\n", .{client_conn_limit});
    if (cfg.upstream_timeout_ms) |upstream_timeout_ms| try out.print("upstream_timeout_ms: {d}\n", .{upstream_timeout_ms});
    if (cfg.upstream_connect_timeout_ms) |connect_timeout_ms| try out.print("upstream_connect_timeout_ms: {d}\n", .{connect_timeout_ms});
    if (cfg.upstream_idle_ttl_ms) |idle_ttl_ms| try out.print("upstream_idle_ttl_ms: {d}\n", .{idle_ttl_ms});
    if (cfg.process_limit) |process_limit| try out.print("process_limit: {d}\n", .{process_limit});
    if (cfg.process_queue_len) |process_queue_len| try out.print("process_queue_len: {d}\n", .{process_queue_len});
    if (cfg.process_queue_timeout_ms) |process_queue_timeout_ms| try out.print("process_queue_timeout_ms: {d}\n", .{process_queue_timeout_ms});
    if (cfg.public_dir_cache_ttl_ms) |public_dir_cache_ttl_ms| try out.print("public_dir_cache_ttl_ms: {d}\n", .{public_dir_cache_ttl_ms});

    try renderFaults(out, faults);
    try out.writeAll("\n");
}

/// Site cfg names (files ending .cfg) in sites_dir, sorted for a stable report.
///
/// Note:
/// - A sites_dir that cannot be opened yields an empty list: the dir check on
///   main.cfg already reported it.
pub fn listSiteNames(io: std.Io, arena: std.mem.Allocator, sites_dir: []const u8) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;

    var dir = std.Io.Dir.cwd().openDir(io, sites_dir, .{ .iterate = true }) catch return names.items;
    defer dir.close(io);

    var iter = dir.iterate();
    while (iter.next(io) catch null) |entry| {
        if (entry.kind == .directory) continue;
        if (!std.mem.endsWith(u8, entry.name, ".cfg")) continue;

        try names.append(arena, try arena.dupe(u8, entry.name));
    }

    std.sort.insertion([]const u8, names.items, {}, nameLessThan);

    return names.items;
}

fn nameLessThan(context: void, left: []const u8, right: []const u8) bool {
    _ = context;

    return std.mem.lessThan(u8, left, right);
}

/// Whether name passes the filters, marking which filter matched.
/// Empty filters show everything.
fn matches(filters: []const []const u8, matched: []bool, name: []const u8) bool {
    if (filters.len == 0) return true;

    var any = false;
    for (filters, 0..) |filter, index| {
        const hit = std.mem.eql(u8, filter, name) or
            (std.mem.endsWith(u8, name, ".cfg") and std.mem.eql(u8, filter, name[0 .. name.len - 4]));
        if (!hit) continue;

        matched[index] = true;
        any = true;
    }

    return any;
}

fn statusWord(faults: []const fault.Fault) []const u8 {
    return if (faults.len == 0) "ok" else "error";
}

fn renderFaults(out: *std.Io.Writer, faults: []const fault.Fault) !void {
    if (faults.len == 0) return;

    try out.writeAll("errors:\n");
    for (faults) |item| {
        try out.print("    {s}: {s}\n", .{ item.key, item.hint });
    }
}

/// Fault when a configured directory path does not exist.
fn checkDirExists(io: std.Io, faults: *fault.FaultList, key: []const u8, path: []const u8) !void {
    std.Io.Dir.cwd().access(io, path, .{}) catch {
        try faults.add(key, "directory does not exist: {s}", .{path});
    };
}

/// Fault every configured site path that does not exist on this machine.
fn checkSitePaths(io: std.Io, faults: *fault.FaultList, cfg: site_cfg.SiteCfg) !void {
    if (cfg.tls_cert) |tls_cert| try checkPathExists(io, faults, "tls_cert", tls_cert);
    if (cfg.tls_key) |tls_key| try checkPathExists(io, faults, "tls_key", tls_key);
    if (cfg.public_dir) |public_dir| try checkPathExists(io, faults, "public_dir", public_dir);
    if (cfg.acme_webroot) |acme_webroot| try checkPathExists(io, faults, "acme_webroot", acme_webroot);
}

fn checkPathExists(io: std.Io, faults: *fault.FaultList, key: []const u8, path: []const u8) !void {
    std.Io.Dir.cwd().access(io, path, .{}) catch {
        try faults.add(key, "path does not exist: {s}", .{path});
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const cmd_init = @import("cmd_init.zig");

fn writeWholeFile(io: std.Io, path: []const u8, content: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    var write_buf: [1024]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(content);
    try writer.interface.flush();
}

fn writeSiteFile(io: std.Io, arena: std.mem.Allocator, root: []const u8, name: []const u8, content: []const u8) !void {
    const path = try std.fs.path.join(arena, &.{ root, "sites", name });

    try writeWholeFile(io, path, content);
}

test "zix zixer: cmd status, initialized root with a valid site reports ok" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_ok_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_ok_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nport: 8080\nupstreams: 127.0.0.1:3000\n");

    var report_buf: [8192]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "main.cfg:\nstatus: ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "service_a.cfg:\nstatus: ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "upstreams: 127.0.0.1:3000") != null);
}

test "zix zixer: cmd status, missing root asks for zixer init" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = "tmp/zixer_status_absent/root", .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "zixer init") != null);
}

test "zix zixer: cmd status, broken site reports error with hints and exit 1" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_bad_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_bad_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    try writeSiteFile(io, arena.allocator(), test_root, "service_bad.cfg", "engine: warp\nupstreams: 127.0.0.1:3000\n");

    var report_buf: [8192]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "service_bad.cfg:\nstatus: error") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "unknown value 'warp'") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "port: missing") != null);
}

test "zix zixer: cmd status, filter narrows and unknown filter fails" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_filter_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_filter_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nport: 8080\nupstreams: 127.0.0.1:3000\n");

    // Name without the .cfg suffix must match the same file.
    var narrow_buf: [8192]u8 = undefined;
    var narrow = std.Io.Writer.fixed(&narrow_buf);
    const narrow_code = try run(io, arena.allocator(), &narrow, .{ .path = test_root, .source = .ARG }, &.{"service_a"});

    try std.testing.expectEqual(@as(u8, 0), narrow_code);
    try std.testing.expect(std.mem.indexOf(u8, narrow.buffered(), "service_a.cfg:") != null);
    try std.testing.expect(std.mem.indexOf(u8, narrow.buffered(), "main.cfg:") == null);

    var unknown_buf: [8192]u8 = undefined;
    var unknown = std.Io.Writer.fixed(&unknown_buf);
    const unknown_code = try run(io, arena.allocator(), &unknown, .{ .path = test_root, .source = .ARG }, &.{"nope"});

    try std.testing.expectEqual(@as(u8, 1), unknown_code);
    try std.testing.expect(std.mem.indexOf(u8, unknown.buffered(), "no config named nope") != null);
}

test "zix zixer: cmd status, a custom sites_dir is where site configs are read" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_sitesdir_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_sitesdir_test") catch {};

    const elsewhere = try std.fs.path.join(arena.allocator(), &.{ test_root, "elsewhere" });
    const logs = try std.fs.path.join(arena.allocator(), &.{ test_root, "logs" });
    try std.Io.Dir.cwd().createDirPath(io, elsewhere);
    try std.Io.Dir.cwd().createDirPath(io, logs);

    const main_content = try std.fmt.allocPrint(arena.allocator(), "logs_dir: {s}\nsites_dir: {s}\n", .{ logs, elsewhere });
    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    try writeWholeFile(io, main_path, main_content);

    const moved_path = try std.fs.path.join(arena.allocator(), &.{ elsewhere, "moved.cfg" });
    try writeWholeFile(io, moved_path, "engine: http1\nport: 9710\nupstreams: 127.0.0.1:3000\n");

    var report_buf: [8192]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "moved.cfg:\nstatus: ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "elsewhere") != null);
}

test "zix zixer: cmd status, a logs_dir that does not exist faults" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_logsdir_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_logsdir_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    const logs = try std.fs.path.join(arena.allocator(), &.{ test_root, "logs" });
    try std.Io.Dir.cwd().deleteTree(io, logs);

    var report_buf: [8192]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{"main.cfg"});

    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "logs_dir: directory does not exist") != null);
}

test "zix zixer: cmd status, render main block matches the documented shape" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const cfg = main_cfg.MainCfg{ .logs_dir = "/r/logs", .sites_dir = "/r/sites" };
    try renderMain(&out, "/r/main.cfg", cfg, &.{});

    const expected =
        "# /r/main.cfg\n" ++
        "main.cfg:\n" ++
        "status: ok\n" ++
        "workers: 1\n" ++
        "dispatch: async\n" ++
        "logs_dir: /r/logs\n" ++
        "log_level: info\n" ++
        "sites_dir: /r/sites\n" ++
        "max_recv_buf: 8192\n" ++
        "kernel_backlog: 1024\n" ++
        "process_limit: 0 (gate off)\n" ++
        "client_timeout_ms: 0 (bound off)\n" ++
        "upstream_connect_timeout_ms: 5000\n" ++
        "upstream_idle_ttl_ms: 5000\n" ++
        "public_dir_cache_ttl_ms: 0 (cache off)\n" ++
        "\n";
    try std.testing.expectEqualStrings(expected, out.buffered());
}

test "zix zixer: cmd status, an armed client bound prints its limit too" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const cfg = main_cfg.MainCfg{
        .logs_dir = "/r/logs",
        .sites_dir = "/r/sites",
        .client_timeout_ms = 30_000,
        .client_conn_limit = 2048,
    };
    try renderMain(&out, "/r/main.cfg", cfg, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "client_timeout_ms: 30000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "client_conn_limit: 2048\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "bound off") == null);
}

test "zix zixer: cmd status, a site prints only the bound keys it names" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 3000 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .port = 8080,
        .upstreams = &upstreams,
        .client_timeout_ms = 15_000,
        .upstream_idle_ttl_ms = 60_000,
    };
    try renderSite(&out, "/r/sites/a.cfg", "a.cfg", cfg, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "client_timeout_ms: 15000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "upstream_idle_ttl_ms: 60000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "client_conn_limit") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "upstream_connect_timeout_ms") == null);
}

test "zix zixer: cmd status, an armed process gate prints all three values" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const cfg = main_cfg.MainCfg{
        .logs_dir = "/r/logs",
        .sites_dir = "/r/sites",
        .process_limit = 64,
        .process_queue_len = 256,
        .process_queue_timeout_ms = 6000,
    };
    try renderMain(&out, "/r/main.cfg", cfg, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_limit: 64\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_queue_len: 256\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_queue_timeout_ms: 6000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "gate off") == null);
}

test "zix zixer: cmd status, a site prints only the gate keys it names" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 3000 }};
    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 8080, .upstreams = &upstreams, .process_limit = 4 };
    try renderSite(&out, "/r/sites/a.cfg", "a.cfg", cfg, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_limit: 4\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_queue_len") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "process_queue_timeout_ms") == null);
}

test "zix zixer: cmd status, a workers value of zero reports what it resolves to" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const cfg = main_cfg.MainCfg{ .workers = 0, .logs_dir = "/r/logs", .sites_dir = "/r/sites" };
    try renderMain(&out, "/r/main.cfg", cfg, &.{});

    var expected_buf: [64]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "workers: 0 (resolved to {d})\n", .{worker_count.resolve(0, worker_count.available())});
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), expected) != null);
}

test "zix zixer: cmd status, render faults are indented under errors" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const faults = [_]fault.Fault{.{ .key = "workers", .hint = "workers exceed from available threads (8), set to 0 or 1" }};
    try renderMain(&out, "/r/main.cfg", .{ .logs_dir = "/r/logs", .sites_dir = "/r/sites" }, &faults);

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "status: error\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "errors:\n    workers: workers exceed") != null);
}

test "zix zixer: cmd status, a configured upstream read bound is reported back" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_status_timeout_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_status_timeout_test") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    try writeSiteFile(io, arena.allocator(), test_root, "bounded.cfg", "engine: http1\nport: 8081\nupstreams: 127.0.0.1:3000\nupstream_timeout_ms: 2 * 1000\n");
    try writeSiteFile(io, arena.allocator(), test_root, "unbounded.cfg", "engine: http1\nport: 8082\nupstreams: 127.0.0.1:3000\n");

    var report_buf: [8192]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG }, &.{});

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "upstream_timeout_ms: 2000") != null);

    // A site that never set the key prints no line for it, the same as
    // every other optional key.
    const unbounded_at = std.mem.indexOf(u8, report.buffered(), "unbounded.cfg:").?;
    try std.testing.expect(std.mem.indexOf(u8, report.buffered()[unbounded_at..], "upstream_timeout_ms") == null);
}

test "zix zixer: cmd status, the main block reports the static cache off in one line" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    try renderMain(&out, "/r/main.cfg", .{ .logs_dir = "/r/logs", .sites_dir = "/r/sites" }, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "public_dir_cache_ttl_ms: 0 (cache off)\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "public_dir_cache_max_entries") == null);
}

test "zix zixer: cmd status, the main block reports both static cache keys when armed" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const cfg = main_cfg.MainCfg{
        .logs_dir = "/r/logs",
        .sites_dir = "/r/sites",
        .public_dir_cache_ttl_ms = 5000,
        .public_dir_cache_max_entries = 512,
    };

    try renderMain(&out, "/r/main.cfg", cfg, &.{});

    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "public_dir_cache_ttl_ms: 5000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "public_dir_cache_max_entries: 512\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "cache off") == null);
}

test "zix zixer: cmd status, a site block prints the window only when it names one" {
    var out_buf: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);

    const bare = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 8080, .public_dir = "/var/www" };
    try renderSite(&out, "/r/sites/static.cfg", "static.cfg", bare, &.{});
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "public_dir_cache_ttl_ms") == null);

    var set_buf: [1024]u8 = undefined;
    var set_out = std.Io.Writer.fixed(&set_buf);
    const set = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 8080, .public_dir = "/var/www", .public_dir_cache_ttl_ms = 2500 };
    try renderSite(&set_out, "/r/sites/static.cfg", "static.cfg", set, &.{});
    try std.testing.expect(std.mem.indexOf(u8, set_out.buffered(), "public_dir_cache_ttl_ms: 2500\n") != null);
}
