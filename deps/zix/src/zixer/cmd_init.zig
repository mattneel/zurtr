//! zixer init command: scaffold the root dir

const std = @import("std");

const root_dir = @import("root_dir.zig");

/// main.cfg written by init. The two {s} slots take the root path.
const MAIN_CFG_TEMPLATE =
    \\# zixer main configuration
    \\# numeric values accept integer math, i.e. 16 * 1024
    \\
    \\workers: 0                      # accept loops per tcp site, 0 = all available threads
    \\dispatch: async                 # async | epoll | uring
    \\logs_dir: {s}/logs
    \\log_level: info                 # debug | info | warn | error, the log file and the console
    \\sites_dir: {s}/sites
    \\
    \\# per-listener defaults, site files may override
    \\kernel_backlog: 1024
    \\max_recv_buf: 8192              # per-connection stream buffer, one leg
    \\
    \\# overload valve, per site, 0 = off
    \\process_limit: 0                # requests running upstream at once
    \\process_queue_len: 0            # requests that may wait for a slot
    \\process_queue_timeout_ms: 6000  # wait before the edge answers 504
    \\
    \\# client bound, per site, 0 = off
    \\client_timeout_ms: 0            # whole client exchange before the edge cuts it
    \\client_conn_limit: 4096         # connections tracked while the bound is on
    \\
    \\# upstream leg, site files may override
    \\upstream_connect_timeout_ms: 5000   # connect wait before the edge answers 504
    \\upstream_idle_ttl_ms: 5000          # unused backend conn kept for reuse, 0 = none
    \\
;

/// Fully commented site sample. The loader only reads files ending .cfg, so
/// the .sample suffix keeps it inert.
const SAMPLE_SITE_CFG =
    \\# zixer site config sample
    \\# copy it: cp example.cfg.sample my_service.cfg, then zixer status
    \\# one site per file, the file name is the site identity
    \\
    \\# engine: http1                 # http1 | http2 | grpc | http3 | udp
    \\# ip: 0.0.0.0
    \\# port: 8080
    \\
    \\# tls: true
    \\# tls_cert: /etc/letsencrypt/live/example.com/fullchain.pem
    \\# tls_key: /etc/letsencrypt/live/example.com/privkey.pem
    \\# acme_webroot: /var/www/acme
    \\# force_https: true             # port 80 companion, redirects to this site
    \\# redirect_host: example.com     # authority the redirect names, else the client's Host
    \\
    \\# upstreams: 127.0.0.1:3000, 127.0.0.1:3001
    \\
    \\# public_dir: /var/www/app/dist
    \\# public_prefix: /assets
    \\# spa_fallback: index.html
    \\
    \\# max_recv_buf: 16 * 1024
    \\# kernel_backlog: 1024
    \\
    \\# overload valve for this site alone, each one falls back to main.cfg
    \\# process_limit: 64
    \\# process_queue_len: 256
    \\# process_queue_timeout_ms: 6000
    \\
    \\# client bound for this site alone, 0 = off
    \\# client_timeout_ms: 30 * 1000
    \\# client_conn_limit: 4096
    \\
    \\# upstream leg for this site alone, needs upstreams
    \\# upstream_connect_timeout_ms: 5000
    \\# upstream_idle_ttl_ms: 5000
    \\
;

/// Scratch buffer size backing each file writer.
const WRITE_BUF_SIZE: usize = 4096;

/// Create the root dir scaffold: main.cfg, sites/ with a sample, logs/.
///
/// Note:
/// - A root that already has a main.cfg is left untouched.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns every assembled path)
/// out - *std.Io.Writer (report target, caller flushes)
/// root - root_dir.RootDir (resolved root dir)
///
/// Return:
/// - u8 process exit code (0 on success)
pub fn run(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir) !u8 {
    const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });

    if (fileExists(io, main_cfg_path)) {
        try out.print("already initialized: {s}\nnothing changed\n", .{main_cfg_path});
        return 0;
    }

    const sites_path = try std.fs.path.join(arena, &.{ root.path, "sites" });
    const logs_path = try std.fs.path.join(arena, &.{ root.path, "logs" });
    const sample_path = try std.fs.path.join(arena, &.{ sites_path, "example.cfg.sample" });
    const main_cfg_content = try std.fmt.allocPrint(arena, MAIN_CFG_TEMPLATE, .{ root.path, root.path });

    try std.Io.Dir.cwd().createDirPath(io, sites_path);
    try std.Io.Dir.cwd().createDirPath(io, logs_path);
    try writeFile(io, main_cfg_path, main_cfg_content);
    try writeFile(io, sample_path, SAMPLE_SITE_CFG);

    try out.print(
        \\initialized: {s}
        \\created:
        \\    {s}
        \\    {s}
        \\    {s}
        \\next:
        \\    cp {s} {s}/<name>.cfg
        \\    zixer status
        \\
    , .{ root.path, main_cfg_path, sample_path, logs_path, sample_path, sites_path });

    return 0;
}

/// Whether a file exists at path.
fn fileExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;

    return true;
}

/// Write one whole file, creating or truncating it.
fn writeFile(io: std.Io, path: []const u8, content: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    var write_buf: [WRITE_BUF_SIZE]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(content);
    try writer.interface.flush();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const main_cfg = @import("main_cfg.zig");
const fault = @import("fault.zig");

test "zix zixer: cmd init, scaffold is created and main.cfg validates clean" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_init_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_init_test") catch {};

    var report_buf: [2048]u8 = undefined;
    var report = std.Io.Writer.fixed(&report_buf);
    const code = try run(io, arena.allocator(), &report, .{ .path = test_root, .source = .ARG });

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, report.buffered(), "initialized") != null);

    const main_cfg_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const content = try std.Io.Dir.cwd().readFileAlloc(io, main_cfg_path, arena.allocator(), .limited(8192));

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try main_cfg.parse(arena.allocator(), content, test_root, 1, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);

    // The template ships 0, which is every thread the process was given:
    // the comment on the line is what explains it to a first reader.
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
    try std.testing.expectEqual(main_cfg.Dispatch.ASYNC, cfg.dispatch);

    // The overload valve ships off, so a fresh root behaves as it always did.
    try std.testing.expectEqual(@as(usize, 0), cfg.process_limit);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
    try std.testing.expectEqual(@as(u32, 6000), cfg.process_queue_timeout_ms);

    // The client bound ships off for the same reason: a fresh root must not
    // start cutting connections a site has always been allowed to hold. The
    // upstream leg ships with its bounds on, which is what it already ran.
    try std.testing.expectEqual(@as(u32, 0), cfg.client_timeout_ms);
    try std.testing.expectEqual(@as(usize, 4096), cfg.client_conn_limit);
    try std.testing.expectEqual(@as(u32, 5000), cfg.upstream_connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5000), cfg.upstream_idle_ttl_ms);

    const sample_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "sites", "example.cfg.sample" });
    try std.testing.expect(fileExists(io, sample_path));
}

test "zix zixer: cmd init, second run leaves the root untouched" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_reinit_test/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_reinit_test") catch {};

    var first_buf: [2048]u8 = undefined;
    var first_report = std.Io.Writer.fixed(&first_buf);
    _ = try run(io, arena.allocator(), &first_report, .{ .path = test_root, .source = .ARG });

    // Mark the file, then verify the second run does not overwrite it.
    const main_cfg_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    try writeFile(io, main_cfg_path, "workers: 1\n");

    var second_buf: [2048]u8 = undefined;
    var second_report = std.Io.Writer.fixed(&second_buf);
    const code = try run(io, arena.allocator(), &second_report, .{ .path = test_root, .source = .ARG });

    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, second_report.buffered(), "already initialized") != null);

    const content = try std.Io.Dir.cwd().readFileAlloc(io, main_cfg_path, arena.allocator(), .limited(8192));
    try std.testing.expectEqualStrings("workers: 1\n", content);
}
