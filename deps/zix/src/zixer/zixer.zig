//! zixer executable: cli routing over the proxy gateway commands

const std = @import("std");
const builtin = @import("builtin");

const cmd_daemon = @import("cmd_daemon.zig");
const cmd_init = @import("cmd_init.zig");
const cmd_list = @import("cmd_list.zig");
const cmd_restart = @import("cmd_restart.zig");
const cmd_start = @import("cmd_start.zig");
const cmd_status = @import("cmd_status.zig");
const cmd_stop = @import("cmd_stop.zig");
const cmd_version = @import("cmd_version.zig");
const root_dir = @import("root_dir.zig");

/// Std options this executable overrides.
///
/// Note:
/// - signal_stack_size gives every thread its own alternative stack for a
///   signal handler, so a stack overflow can still print a trace. The
///   default is 256 KiB, and std zeroes the whole thread-local area at
///   every thread start, so it is 256 KiB of resident memory per thread.
///   The daemon runs one thread per served connection, which turns it
///   into the largest per-connection cost zixer has, ahead of every
///   buffer put together. Null drops the alternative stack: a connection
///   thread runs a fixed, non-recursive frame chain well under a hundred
///   kilobytes against a 16 MiB stack, so overflow is not the failure
///   this edge is exposed to.
pub const std_options: std.Options = .{
    .signal_stack_size = null,
};

const HELP =
    \\zixer, proxy gateway on the zix engines
    \\
    \\usage:
    \\    zixer [--dir path] <command> [args]
    \\
    \\commands:
    \\    init                create the root dir (main.cfg, sites/, logs/)
    \\    status [name...]    validate main.cfg and site configs, report with fix hints
    \\    list                list site configs
    \\    start <site.cfg>    start one site, spawning the daemon when needed
    \\    stop <site.cfg>     stop one started site
    \\    restart <site.cfg>  re-read one site cfg and rebind it
    \\    daemon              run the daemon in the foreground
    \\    daemon stop         stop the daemon and every started site
    \\    version             show the version, which follows the zix package
    \\    help                show this help
    \\
    \\root dir resolution order:
    \\    1. --dir path
    \\    2. ZIXER_DIR environment variable
    \\    3. $HOME/.zixer
    \\
;

/// Everything pulled out of argv: the command, the --dir value, the rest.
/// exe_path keeps argv[0] so start/restart can respawn this binary as the daemon.
const CliArgs = struct {
    exe_path: []const u8 = "zixer",
    command: ?[]const u8 = null,
    dir_arg: ?[]const u8 = null,
    filters: []const []const u8 = &.{},
};

/// Split argv into command, --dir value, and trailing names.
///
/// Note:
/// - argv[0] is skipped here, hand the iterator over untouched.
/// - --dir is accepted anywhere, so `zixer init --dir /x` and
///   `zixer --dir /x status` both work.
///
/// Param:
/// arena - std.mem.Allocator (owns the filters slice)
/// arg_iter - anytype (pointer to an iterator whose next() yields ?argv slices)
///
/// Return:
/// - CliArgs
/// - error.ZixerMissingDirValue when --dir is the last argument
fn parseArgs(arena: std.mem.Allocator, arg_iter: anytype) !CliArgs {
    var cli = CliArgs{};
    var filters: std.ArrayList([]const u8) = .empty;

    if (arg_iter.next()) |arg0| cli.exe_path = arg0;

    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dir")) {
            cli.dir_arg = arg_iter.next() orelse return error.ZixerMissingDirValue;
        } else if (cli.command == null) {
            cli.command = arg;
        } else {
            try filters.append(arena, arg);
        }
    }

    cli.filters = filters.items;

    return cli;
}

/// Args iterator that also works on Windows: std's Iterator.init is
/// POSIX-only in Zig 0.16, Windows needs the allocating variant.
fn argsIterator(args: std.process.Args) std.process.Args.Iterator {
    if (comptime builtin.os.tag == .windows) {
        return std.process.Args.Iterator.initAllocator(args, std.heap.smp_allocator) catch {
            std.process.exit(2);
        };
    }

    return std.process.Args.Iterator.init(args);
}

/// Bare `zixer`: say where the root dir resolves and whether it is
/// initialized, then show help.
fn reportRootAndHelp(io: std.Io, arena: std.mem.Allocator, out: *std.Io.Writer, root: root_dir.RootDir) !u8 {
    const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });

    const initialized = blk: {
        std.Io.Dir.cwd().access(io, main_cfg_path, .{}) catch break :blk false;
        break :blk true;
    };

    if (initialized) {
        try out.print("initialized: {s} (from {s})\n\n", .{ root.path, root_dir.sourceName(root.source) });
    } else {
        try out.print("not initialized, would use: {s} (from {s})\nrun: zixer init\n\n", .{ root.path, root_dir.sourceName(root.source) });
    }

    try out.writeAll(HELP);

    return 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Slice-backed stand-in for the argv iterator in parseArgs tests.
const FakeArgs = struct {
    items: []const []const u8,
    index: usize = 0,

    fn next(fake: *FakeArgs) ?[]const u8 {
        if (fake.index >= fake.items.len) return null;

        const item = fake.items[fake.index];
        fake.index += 1;

        return item;
    }
};

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    const io = process.io;
    const arena = process.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout_writer.interface;

    var arg_iter = argsIterator(process.minimal.args);
    const cli = parseArgs(arena, &arg_iter) catch {
        try out.writeAll("--dir needs a path\n");
        try out.flush();
        std.process.exit(2);
    };

    const root = root_dir.resolveFromEnviron(arena, cli.dir_arg, process.environ_map) catch {
        try out.writeAll("cannot resolve the root dir: no HOME, use --dir or ZIXER_DIR\n");
        try out.flush();
        std.process.exit(2);
    };

    var code: u8 = 0;
    if (cli.command) |command| {
        if (std.mem.eql(u8, command, "init")) {
            code = try cmd_init.run(io, arena, out, root);
        } else if (std.mem.eql(u8, command, "status")) {
            code = try cmd_status.run(io, arena, out, root, cli.filters);
        } else if (std.mem.eql(u8, command, "list")) {
            code = try cmd_list.run(io, arena, out, root);
        } else if (std.mem.eql(u8, command, "start")) {
            code = try cmd_start.run(io, arena, out, root, cli.filters, cli.exe_path);
        } else if (std.mem.eql(u8, command, "stop")) {
            code = try cmd_stop.run(io, arena, out, root, cli.filters);
        } else if (std.mem.eql(u8, command, "restart")) {
            code = try cmd_restart.run(io, arena, out, root, cli.filters, cli.exe_path);
        } else if (std.mem.eql(u8, command, "daemon")) {
            code = try cmd_daemon.run(io, std.heap.smp_allocator, arena, out, root, cli.filters);
        } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
            code = try cmd_version.run(out);
        } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
            try out.writeAll(HELP);
        } else {
            try out.print("unknown command: {s}\n\n", .{command});
            try out.writeAll(HELP);
            code = 2;
        }
    } else {
        code = try reportRootAndHelp(io, arena, out, root);
    }

    try out.flush();
    if (code != 0) std.process.exit(code);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: std options, the alternative signal stack is off" {
    // Every connection is served on its own thread, and std zeroes the
    // whole thread-local area at thread start, so a 256 KiB alternative
    // signal stack would be 256 KiB of resident memory per connection.
    try std.testing.expectEqual(@as(?u64, null), std_options.signal_stack_size);
}

test "zix zixer: test discovery, every zixer file is referenced" {
    std.testing.refAllDecls(@import("cfg_math.zig"));
    std.testing.refAllDecls(@import("cfg_scanner.zig"));
    std.testing.refAllDecls(@import("header_syntax.zig"));
    std.testing.refAllDecls(@import("cfg_headers.zig"));
    std.testing.refAllDecls(@import("fault.zig"));
    std.testing.refAllDecls(@import("root_dir.zig"));
    std.testing.refAllDecls(@import("main_cfg.zig"));
    std.testing.refAllDecls(@import("site_cfg.zig"));
    std.testing.refAllDecls(@import("cmd_init.zig"));
    std.testing.refAllDecls(@import("cmd_status.zig"));
    std.testing.refAllDecls(@import("cmd_list.zig"));
    std.testing.refAllDecls(@import("control.zig"));
    std.testing.refAllDecls(@import("control_client.zig"));
    std.testing.refAllDecls(@import("port_probe.zig"));
    std.testing.refAllDecls(@import("tcp_nodelay.zig"));
    std.testing.refAllDecls(@import("worker_count.zig"));
    std.testing.refAllDecls(@import("conn_buffer.zig"));
    std.testing.refAllDecls(@import("process_gate.zig"));
    std.testing.refAllDecls(@import("process_wait.zig"));
    std.testing.refAllDecls(@import("bind_options.zig"));
    std.testing.refAllDecls(@import("site_runtime.zig"));
    std.testing.refAllDecls(@import("daemon.zig"));
    std.testing.refAllDecls(@import("daemon_spawn.zig"));
    std.testing.refAllDecls(@import("cmd_daemon.zig"));
    std.testing.refAllDecls(@import("cmd_start.zig"));
    std.testing.refAllDecls(@import("cmd_stop.zig"));
    std.testing.refAllDecls(@import("cmd_restart.zig"));
    std.testing.refAllDecls(@import("cmd_version.zig"));
    std.testing.refAllDecls(@import("https_redirect.zig"));
    std.testing.refAllDecls(@import("request_scheme.zig"));
    std.testing.refAllDecls(@import("upstream_pool.zig"));
    std.testing.refAllDecls(@import("upstream_conn.zig"));
    std.testing.refAllDecls(@import("upstream_status.zig"));
    std.testing.refAllDecls(@import("upstream_deadline.zig"));
    std.testing.refAllDecls(@import("deadline_table.zig"));
    std.testing.refAllDecls(@import("deadline_sweep.zig"));
    std.testing.refAllDecls(@import("client_admit.zig"));
    std.testing.refAllDecls(@import("client_lease.zig"));
    std.testing.refAllDecls(@import("site_sweep.zig"));
    std.testing.refAllDecls(@import("proxy_headers.zig"));
    std.testing.refAllDecls(@import("http1_head.zig"));
    std.testing.refAllDecls(@import("http1_proxy.zig"));
    std.testing.refAllDecls(@import("ws_tunnel.zig"));
    std.testing.refAllDecls(@import("http2_frames.zig"));
    std.testing.refAllDecls(@import("http2_translate.zig"));
    std.testing.refAllDecls(@import("http2_edge.zig"));
    std.testing.refAllDecls(@import("http2_ws_bridge.zig"));
    std.testing.refAllDecls(@import("grpc_relay.zig"));
    std.testing.refAllDecls(@import("grpc_upstream.zig"));
    std.testing.refAllDecls(@import("grpc_edge.zig"));
    std.testing.refAllDecls(@import("static_cached.zig"));
    std.testing.refAllDecls(@import("static_files.zig"));
    std.testing.refAllDecls(@import("tls_edge.zig"));
    std.testing.refAllDecls(@import("acme_challenge.zig"));
    std.testing.refAllDecls(@import("acme_listener.zig"));
    std.testing.refAllDecls(@import("site_worker.zig"));
    std.testing.refAllDecls(@import("site_serve.zig"));
    std.testing.refAllDecls(@import("udp_flow_table.zig"));
    std.testing.refAllDecls(@import("udp_forward.zig"));
    std.testing.refAllDecls(@import("h3_qpack.zig"));
    std.testing.refAllDecls(@import("h3_frames.zig"));
    std.testing.refAllDecls(@import("h3_streams.zig"));
    std.testing.refAllDecls(@import("h3_translate.zig"));
    std.testing.refAllDecls(@import("h3_conn.zig"));
    std.testing.refAllDecls(@import("h3_edge.zig"));
}

test "zix zixer: cli args, command dir flag and filters split out" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var plain = FakeArgs{ .items = &.{ "zixer", "status", "service_a", "service_b" } };
    const plain_cli = try parseArgs(arena.allocator(), &plain);
    try std.testing.expectEqualStrings("status", plain_cli.command.?);
    try std.testing.expectEqual(@as(?[]const u8, null), plain_cli.dir_arg);
    try std.testing.expectEqual(@as(usize, 2), plain_cli.filters.len);
    try std.testing.expectEqualStrings("service_b", plain_cli.filters[1]);

    var dir_first = FakeArgs{ .items = &.{ "zixer", "--dir", "/srv/zixer", "init" } };
    const dir_first_cli = try parseArgs(arena.allocator(), &dir_first);
    try std.testing.expectEqualStrings("init", dir_first_cli.command.?);
    try std.testing.expectEqualStrings("/srv/zixer", dir_first_cli.dir_arg.?);

    var dir_last = FakeArgs{ .items = &.{ "zixer", "init", "--dir", "/srv/zixer" } };
    const dir_last_cli = try parseArgs(arena.allocator(), &dir_last);
    try std.testing.expectEqualStrings("init", dir_last_cli.command.?);
    try std.testing.expectEqualStrings("/srv/zixer", dir_last_cli.dir_arg.?);
}

test "zix zixer: cli args, bare zixer and dangling --dir" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var bare = FakeArgs{ .items = &.{"zixer"} };
    const bare_cli = try parseArgs(arena.allocator(), &bare);
    try std.testing.expectEqual(@as(?[]const u8, null), bare_cli.command);

    var dangling = FakeArgs{ .items = &.{ "zixer", "--dir" } };
    try std.testing.expectError(error.ZixerMissingDirValue, parseArgs(arena.allocator(), &dangling));
}

test "zix zixer: cli help, every command is documented" {
    try std.testing.expect(std.mem.indexOf(u8, HELP, "init") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "status") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "list") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "start <site.cfg>") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "stop <site.cfg>") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "restart <site.cfg>") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "daemon stop") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "version") != null);
    try std.testing.expect(std.mem.indexOf(u8, HELP, "ZIXER_DIR") != null);
}

test "zix zixer: cli args, every version spelling lands as the command" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    for ([_][]const u8{ "version", "--version", "-v" }) |spelling| {
        var args = FakeArgs{ .items = &.{ "zixer", spelling } };
        const cli = try parseArgs(arena.allocator(), &args);

        try std.testing.expectEqualStrings(spelling, cli.command.?);
        try std.testing.expectEqual(@as(usize, 0), cli.filters.len);
    }
}

test "zix zixer: cli args, argv0 lands in exe_path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var args = FakeArgs{ .items = &.{ "/usr/local/bin/zixer-x86_64-linux", "start", "a.cfg" } };
    const cli = try parseArgs(arena.allocator(), &args);

    try std.testing.expectEqualStrings("/usr/local/bin/zixer-x86_64-linux", cli.exe_path);
    try std.testing.expectEqualStrings("start", cli.command.?);
}
