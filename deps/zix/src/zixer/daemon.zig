//! zixer daemon: control socket loop over the started-site registry

const std = @import("std");
const zix = @import("zix");

const control = @import("control.zig");
const daemon_log = @import("daemon_log.zig");
const fault = @import("fault.zig");
const bind_options = @import("bind_options.zig");
const main_cfg = @import("main_cfg.zig");
const root_dir = @import("root_dir.zig");
const site_cfg = @import("site_cfg.zig");
const site_runtime = @import("site_runtime.zig");
const static_cached = @import("static_cached.zig");
const worker_count = @import("worker_count.zig");

/// Hard ceiling for one config file, a larger file fails instead of allocating.
const MAX_CFG_BYTES: usize = 256 * 1024;

/// Consecutive accept failures before the control loop gives up, so a broken
/// socket cannot spin the daemon hot.
const MAX_ACCEPT_FAILURES: usize = 100;

/// The daemon: owns the control socket and every started site.
///
/// Note:
/// - Requests are handled one at a time on purpose. The control plane is not
///   a data path, and serial handling keeps the registry lock-free.
pub const Daemon = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: main_cfg.MainCfg,
    /// Accept loops every started site runs, resolved from cfg.workers once
    /// here rather than per site: the thread count cannot change under a
    /// running daemon, and two sites must not disagree about it.
    workers: usize,
    socket_path: []const u8,
    /// Where every runtime line goes: the log file under logs_dir and the
    /// console, both at cfg.log_level. Owned here because the daemon outlives
    /// every site that writes through it.
    logger: zix.Logger,
    sites: std.ArrayList(site_runtime.SiteRuntime) = .empty,
    stop_requested: bool = false,

    /// Load and validate main.cfg, refuse to build on any fault.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (site registry and names, long-lived)
    /// io - std.Io
    /// arena - std.mem.Allocator (owns main.cfg content and the socket path, must outlive the daemon)
    /// root - root_dir.RootDir (resolved root dir)
    ///
    /// Return:
    /// - Daemon ready for run()
    /// - error.ZixerNotInitialized when main.cfg is missing
    /// - error.ZixerMainCfgInvalid when main.cfg carries faults
    pub fn init(allocator: std.mem.Allocator, io: std.Io, arena: std.mem.Allocator, root: root_dir.RootDir) !Daemon {
        const main_cfg_path = try std.fs.path.join(arena, &.{ root.path, "main.cfg" });
        const content = zix.utils.file.load(io, arena, main_cfg_path, MAX_CFG_BYTES) catch |err| switch (err) {
            error.ZixFileNotFound => return error.ZixerNotInitialized,
            else => return err,
        };

        const available_threads = worker_count.available();
        var faults = fault.FaultList.init(arena);
        const cfg = try main_cfg.parse(arena, content, root.path, available_threads, &faults);
        if (faults.slice().len != 0) return error.ZixerMainCfgInvalid;

        const socket_path = try control.socketPath(io, arena, root.path);

        return .{
            .allocator = allocator,
            .io = io,
            .cfg = cfg,
            .workers = worker_count.resolve(cfg.workers, available_threads),
            .socket_path = socket_path,
            .logger = try daemon_log.build(allocator, cfg),
        };
    }

    /// Unbind whatever is still started and drop the registry.
    ///
    /// Note:
    /// - The logger goes last. Every site writes through it, so it has to
    ///   outlive the unbind that may still report a failure.
    pub fn deinit(self: *Daemon) void {
        self.unbindAll();
        self.sites.deinit(self.allocator);

        self.logger.deinit();
    }

    /// Bind the control socket and serve request lines until shutdown.
    ///
    /// Note:
    /// - The caller has already checked no live daemon answers on the socket,
    ///   so a leftover socket file here is stale and safe to remove.
    ///
    /// Return:
    /// - void after a clean shutdown request
    /// - error.ZixerControlPathTooLong when the root dir cannot host a socket
    /// - error.ZixerControlSocketBroken when accept keeps failing
    pub fn run(self: *Daemon) !void {
        zix.utils.ignore_sigpipe.ignoreSigpipe();

        if (comptime !std.Io.net.has_unix_sockets) return error.ZixerUdsNotSupported;
        if (!control.fitsSocket(self.socket_path)) return error.ZixerControlPathTooLong;

        const io = self.io;

        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};

        const unix_addr = try std.Io.net.UnixAddress.init(self.socket_path);
        var server = try unix_addr.listen(io, .{});
        defer {
            server.deinit(io);
            std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
        }

        var accept_failures: usize = 0;
        while (!self.stop_requested) {
            const stream = server.accept(io) catch {
                accept_failures += 1;
                if (accept_failures >= MAX_ACCEPT_FAILURES) return error.ZixerControlSocketBroken;
                continue;
            };
            accept_failures = 0;

            self.serveConn(stream);
        }

        self.unbindAll();
    }

    /// Handle one request line, the reply lands in reply_buf.
    ///
    /// Note:
    /// - Every outcome is a reply line, the daemon never dies on a request.
    pub fn handleLine(self: *Daemon, line: []const u8, reply_buf: []u8) []const u8 {
        const request = control.parseRequest(line) orelse
            return print(reply_buf, "error: unknown command, use start/stop/restart <site.cfg>, ping, or shutdown", .{});

        return switch (request.verb) {
            .PING => print(reply_buf, "ok: zixer daemon", .{}),
            .SHUTDOWN => self.handleShutdown(reply_buf),
            .START => self.handleStart(request.name, reply_buf),
            .STOP => self.handleStop(request.name, reply_buf),
            .RESTART => self.handleRestart(request.name, reply_buf),
        };
    }

    fn handleStart(self: *Daemon, name: []const u8, reply_buf: []u8) []const u8 {
        if (rejectName(name, reply_buf)) |reply| return reply;
        if (self.findSite(name) != null)
            return print(reply_buf, "error: {s} is already started, use restart to reload it", .{name});

        return self.bindSite(name, reply_buf, "started");
    }

    fn handleStop(self: *Daemon, name: []const u8, reply_buf: []u8) []const u8 {
        if (rejectName(name, reply_buf)) |reply| return reply;

        const index = self.findSite(name) orelse
            return print(reply_buf, "error: {s} is not started", .{name});

        var runtime = self.sites.swapRemove(index);
        runtime.unbind(self.allocator, self.io);

        return print(reply_buf, "ok: {s} stopped", .{name});
    }

    /// Restart re-reads the cfg from disk, that is what a certbot deploy-hook
    /// relies on. A site that was not started is simply started, so the hook
    /// never fails on a site that happened to be down.
    fn handleRestart(self: *Daemon, name: []const u8, reply_buf: []u8) []const u8 {
        if (rejectName(name, reply_buf)) |reply| return reply;

        if (self.findSite(name)) |index| {
            var runtime = self.sites.swapRemove(index);
            runtime.unbind(self.allocator, self.io);

            return self.bindSite(name, reply_buf, "restarted");
        }

        return self.bindSite(name, reply_buf, "started");
    }

    fn handleShutdown(self: *Daemon, reply_buf: []u8) []const u8 {
        self.stop_requested = true;

        return print(reply_buf, "ok: daemon stopped, sites unbound: {d}", .{self.sites.items.len});
    }

    /// Parse, validate, and bind one site, appending it to the registry.
    fn bindSite(self: *Daemon, name: []const u8, reply_buf: []u8, past_verb: []const u8) []const u8 {
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const arena = scratch.allocator();

        const site_path = std.fs.path.join(arena, &.{ self.cfg.sites_dir, name }) catch
            return print(reply_buf, "error: out of memory", .{});
        // One message used to cover missing, unreadable and oversize alike, so an operator with a
        // permission problem was sent to `zixer list` to look for a file that is right there.
        const content = zix.utils.file.load(self.io, arena, site_path, MAX_CFG_BYTES) catch |err| switch (err) {
            error.ZixFileNotFound => return print(reply_buf, "error: no site named {s} in {s}, run: zixer list", .{ name, self.cfg.sites_dir }),
            error.ZixFilePathIsDirectory => return print(reply_buf, "error: {s} is a directory, a site is one cfg file", .{site_path}),
            error.ZixFileTooLarge => return print(reply_buf, "error: {s} is larger than {d} bytes", .{ site_path, MAX_CFG_BYTES }),
            error.OutOfMemory => return print(reply_buf, "error: out of memory", .{}),
            else => return print(reply_buf, "error: cannot read {s}, check its permissions", .{site_path}),
        };

        var faults = fault.FaultList.init(arena);
        const cfg = site_cfg.parse(arena, content, &faults) catch
            return print(reply_buf, "error: out of memory", .{});
        if (faults.slice().len != 0 or cfg.engine == null or cfg.port == null)
            return print(reply_buf, "error: {s} has config errors, run: zixer status {s}", .{ name, name });

        // Tcp sites listen with reuse_address (restart survives TIME_WAIT),
        // so a same-port collision between sites must be caught here, the
        // kernel would happily share the port. A site owns its main port
        // plus, on a TLS acme site, the port 80 companion.
        for (self.sites.items) |*site| {
            if (site.ownsPort(cfg.port.?))
                return print(reply_buf, "error: {s} port {d} is already used by {s}", .{ name, cfg.port.?, site.name });

            if (site_runtime.companionPort(&cfg)) |challenge_port| {
                if (site.ownsPort(challenge_port))
                    return print(reply_buf, "error: {s} challenge port {d} is already used by {s}", .{ name, challenge_port, site.name });
            }
        }

        const options = bind_options.BindOptions{
            .kernel_backlog = resolveBacklog(cfg.kernel_backlog, self.cfg.kernel_backlog),
            .workers = self.workers,
            .max_recv_buf = self.cfg.max_recv_buf,
            .client_timeout_ms = self.cfg.client_timeout_ms,
            .client_conn_limit = self.cfg.client_conn_limit,
            .upstream_connect_timeout_ms = self.cfg.upstream_connect_timeout_ms,
            .upstream_idle_ttl_ms = self.cfg.upstream_idle_ttl_ms,
            .process_limit = self.cfg.process_limit,
            .process_queue_len = self.cfg.process_queue_len,
            .process_queue_timeout_ms = self.cfg.process_queue_timeout_ms,
            .public_dir_cache_ttl_ms = self.cfg.public_dir_cache_ttl_ms,
            .public_dir_cache_max_entries = self.cfg.public_dir_cache_max_entries,
            .logger = &self.logger,
        };
        const runtime = site_runtime.SiteRuntime.bind(self.allocator, self.io, name, cfg, options) catch |err| switch (err) {
            error.AddressInUse => return print(reply_buf, "error: {s} port {d} is already in use", .{ name, cfg.port.? }),
            error.ZixerChallengePortInUse => return print(reply_buf, "error: {s} challenge port {d} is already in use", .{ name, site_runtime.ACME_HTTP_PORT }),
            error.ZixTlsCertFileNotFound => return print(reply_buf, "error: {s} tls_cert does not exist: {s}", .{ name, cfg.tls_cert orelse "" }),
            error.ZixTlsCertPathIsDirectory => return print(reply_buf, "error: {s} tls_cert names a directory: {s}", .{ name, cfg.tls_cert orelse "" }),
            error.ZixTlsCertFileTooLarge => return print(reply_buf, "error: {s} tls_cert is larger than 1 MiB: {s}", .{ name, cfg.tls_cert orelse "" }),
            error.ZixTlsCertFileUnreadable => return print(reply_buf, "error: {s} cannot read tls_cert, check its permissions: {s}", .{ name, cfg.tls_cert orelse "" }),
            error.ZixTlsKeyFileNotFound => return print(reply_buf, "error: {s} tls_key does not exist: {s}", .{ name, cfg.tls_key orelse "" }),
            error.ZixTlsKeyPathIsDirectory => return print(reply_buf, "error: {s} tls_key names a directory: {s}", .{ name, cfg.tls_key orelse "" }),
            error.ZixTlsKeyFileTooLarge => return print(reply_buf, "error: {s} tls_key is larger than 1 MiB: {s}", .{ name, cfg.tls_key orelse "" }),
            error.ZixTlsKeyFileUnreadable => return print(reply_buf, "error: {s} cannot read tls_key, check its permissions: {s}", .{ name, cfg.tls_key orelse "" }),
            else => {
                if (site_runtime.companionPort(&cfg) != null)
                    return print(reply_buf, "error: {s} bind failed ({s}), the acme challenge listener needs port 80", .{ name, @errorName(err) });

                return print(reply_buf, "error: {s} bind failed ({s})", .{ name, @errorName(err) });
            },
        };

        self.sites.append(self.allocator, runtime) catch {
            var orphan = runtime;
            orphan.unbind(self.allocator, self.io);

            return print(reply_buf, "error: out of memory", .{});
        };

        return print(reply_buf, "ok: {s} {s} on {s}:{d}", .{ name, past_verb, cfg.ip, cfg.port.? });
    }

    fn findSite(self: *Daemon, name: []const u8) ?usize {
        for (self.sites.items, 0..) |site, i| {
            if (std.mem.eql(u8, site.name, name)) return i;
        }

        return null;
    }

    fn unbindAll(self: *Daemon) void {
        for (self.sites.items) |*site| site.unbind(self.allocator, self.io);

        self.sites.clearRetainingCapacity();

        // Every site is stopped, so no response can still be holding a cached
        // file. Closing the table here is what returns its descriptors.
        static_cached.shutdown(self.io);
    }

    /// One conn, one exchange: read a line, reply, close.
    fn serveConn(self: *Daemon, stream: std.Io.net.Stream) void {
        const io = self.io;
        defer stream.close(io);

        var read_buf: [control.MAX_LINE]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var line_buf: [control.MAX_LINE]u8 = undefined;
        var len: usize = 0;
        while (len < line_buf.len) {
            const got = reader.interface.readSliceShort(line_buf[len .. len + 1]) catch return;
            if (got == 0) break;
            if (line_buf[len] == '\n') break;
            len += got;
        }

        var reply_buf: [control.MAX_LINE]u8 = undefined;
        const reply = self.handleLine(line_buf[0..len], &reply_buf);

        var write_buf: [control.MAX_LINE]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        writer.interface.writeAll(reply) catch return;
        writer.interface.writeAll("\n") catch return;
        writer.interface.flush() catch return;
    }
};

/// The listen backlog one site binds with: its own kernel_backlog when the
/// site file set one, the main.cfg value otherwise.
fn resolveBacklog(site_backlog: ?u31, main_backlog: u31) u31 {
    return site_backlog orelse main_backlog;
}

/// Reply for a name the daemon must not resolve, null when the name is fine.
fn rejectName(name: []const u8, reply_buf: []u8) ?[]const u8 {
    if (control.siteNameSafe(name)) return null;

    return print(reply_buf, "error: site name must be a bare file name, i.e. service_api_h1.cfg", .{});
}

fn print(buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(buf, fmt, args) catch "error: reply too long";
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const cmd_init = @import("cmd_init.zig");
const control_client = @import("control_client.zig");

fn writeSiteFile(io: std.Io, arena: std.mem.Allocator, root: []const u8, name: []const u8, content: []const u8) !void {
    const path = try std.fs.path.join(arena, &.{ root, "sites", name });
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    var write_buf: [1024]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(content);
    try writer.interface.flush();
}

fn testDaemon(io: std.Io, arena: std.mem.Allocator, root: []const u8) !Daemon {
    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena, &init_report, .{ .path = root, .source = .ARG });

    return Daemon.init(std.testing.allocator, io, arena, .{ .path = root, .source = .ARG });
}

test "zix zixer: daemon init, missing root and broken main.cfg both refuse" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.ZixerNotInitialized,
        Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = "tmp/zixer_daemon_absent/root", .source = .ARG }),
    );

    const test_root = "tmp/zixer_daemon_badmain/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_badmain") catch {};

    var init_buf: [2048]u8 = undefined;
    var init_report = std.Io.Writer.fixed(&init_buf);
    _ = try cmd_init.run(io, arena.allocator(), &init_report, .{ .path = test_root, .source = .ARG });

    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{});
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll("no_such_key: 1\n");
    try writer.interface.flush();
    file.close(io);

    try std.testing.expectError(
        error.ZixerMainCfgInvalid,
        Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = test_root, .source = .ARG }),
    );
}

test "zix zixer: daemon handleLine, ping answers and unknown command explains" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_ping/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_ping") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expectEqualStrings("ok: zixer daemon", daemon.handleLine("ping", &reply_buf));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("reload a.cfg", &reply_buf), "error: unknown command"));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start ../evil.cfg", &reply_buf), "error: site name must be"));
}

test "zix zixer: daemon handleLine, unsafe name is rejected on every site verb" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_unsafe/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_unsafe") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start ../evil.cfg", &reply_buf), "error: site name must be"));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("stop ../evil.cfg", &reply_buf), "error: site name must be"));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("restart ../evil.cfg", &reply_buf), "error: site name must be"));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("stop sub\\site.cfg", &reply_buf), "error: site name must be"));
}

test "zix zixer: daemon handleLine, start stop restart walk the registry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_verbs/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_verbs") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nip: 127.0.0.1\nport: 18864\nupstreams: 127.0.0.1:3000\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expectEqualStrings(
        "ok: service_a.cfg started on 127.0.0.1:18864",
        daemon.handleLine("start service_a.cfg", &reply_buf),
    );
    try std.testing.expectEqual(@as(usize, 1), daemon.sites.items.len);

    try std.testing.expectEqualStrings(
        "error: service_a.cfg is already started, use restart to reload it",
        daemon.handleLine("start service_a.cfg", &reply_buf),
    );

    try std.testing.expectEqualStrings(
        "ok: service_a.cfg restarted on 127.0.0.1:18864",
        daemon.handleLine("restart service_a.cfg", &reply_buf),
    );

    try std.testing.expectEqualStrings("ok: service_a.cfg stopped", daemon.handleLine("stop service_a.cfg", &reply_buf));
    try std.testing.expectEqual(@as(usize, 0), daemon.sites.items.len);

    try std.testing.expectEqualStrings(
        "error: service_a.cfg is not started",
        daemon.handleLine("stop service_a.cfg", &reply_buf),
    );

    try std.testing.expectEqualStrings(
        "ok: service_a.cfg started on 127.0.0.1:18864",
        daemon.handleLine("restart service_a.cfg", &reply_buf),
    );
}

test "zix zixer: daemon handleLine, missing site and broken site refuse to start" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_badsite/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_badsite") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const missing = daemon.handleLine("start absent.cfg", &reply_buf);
    try std.testing.expect(std.mem.startsWith(u8, missing, "error: no site named absent.cfg in "));
    try std.testing.expect(std.mem.endsWith(u8, missing, "run: zixer list"));

    try writeSiteFile(io, arena.allocator(), test_root, "broken.cfg", "engine: http1\n");
    try std.testing.expectEqualStrings(
        "error: broken.cfg has config errors, run: zixer status broken.cfg",
        daemon.handleLine("start broken.cfg", &reply_buf),
    );
}

test "zix zixer: daemon handleLine, two sites on one port collide at start" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_collide/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_collide") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "one.cfg", "engine: http1\nip: 127.0.0.1\nport: 18865\nupstreams: 127.0.0.1:3000\n");
    try writeSiteFile(io, arena.allocator(), test_root, "two.cfg", "engine: http1\nip: 127.0.0.1\nport: 18865\nupstreams: 127.0.0.1:3001\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start one.cfg", &reply_buf), "ok: "));
    try std.testing.expectEqualStrings(
        "error: two.cfg port 18865 is already used by one.cfg",
        daemon.handleLine("start two.cfg", &reply_buf),
    );
}

test "zix zixer: daemon backlog, a site override wins over the main.cfg value" {
    // main.cfg carries the default, a site file may raise or lower it for
    // its own listener. The bound value is visible on the wire as the
    // listen queue length.
    try std.testing.expectEqual(@as(u31, 1024), resolveBacklog(null, 1024));
    try std.testing.expectEqual(@as(u31, 7), resolveBacklog(7, 1024));
    try std.testing.expectEqual(@as(u31, 4096), resolveBacklog(4096, 128));
}

test "zix zixer: daemon backlog, a started site binds with the resolved value" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_backlog/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_backlog") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "inherited.cfg", "engine: http1\nip: 127.0.0.1\nport: 18867\nupstreams: 127.0.0.1:3000\n");
    try writeSiteFile(io, arena.allocator(), test_root, "own.cfg", "engine: http1\nip: 127.0.0.1\nport: 18868\nupstreams: 127.0.0.1:3000\nkernel_backlog: 7\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start inherited.cfg", &reply_buf), "ok: "));
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start own.cfg", &reply_buf), "ok: "));

    // Both bind: a backlog far below the main.cfg default is still a valid
    // listener, it only shortens the pending-connection queue.
    try std.testing.expectEqual(@as(usize, 2), daemon.sites.items.len);
    try std.testing.expectEqual(@as(u31, 1024), daemon.cfg.kernel_backlog);
}

test "zix zixer: daemon workers, the default cfg resolves to every thread" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_workers_default/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_workers_default") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    // zixer init writes workers: 0, and the daemon resolves it once at
    // start so two sites can never disagree about the count.
    try std.testing.expectEqual(@as(usize, 0), daemon.cfg.workers);
    try std.testing.expectEqual(worker_count.resolve(0, worker_count.available()), daemon.workers);
}

test "zix zixer: daemon workers, a site starts with the resolved worker count" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: daemon worker count test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_workers_site/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_workers_site") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    // A named count above what this box has would fault main.cfg, so ask
    // for what the box reports and let 1-core hosts assert the floor.
    const wanted = worker_count.available();
    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{ .truncate = true });
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.print("workers: {d}\n", .{wanted});
    try writer.interface.flush();
    file.close(io);

    var reloaded = try Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = test_root, .source = .ARG });
    defer reloaded.deinit();
    try std.testing.expectEqual(worker_count.resolve(wanted, wanted), reloaded.workers);

    try writeSiteFile(io, arena.allocator(), test_root, "many.cfg", "engine: http1\nip: 127.0.0.1\nport: 18967\nupstreams: 127.0.0.1:18968\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, reloaded.handleLine("start many.cfg", &reply_buf), "ok: "));

    // The count reaches the serving site, not just the daemon field.
    const state = reloaded.sites.items[0].listener.proxy_edge;
    try std.testing.expectEqual(reloaded.workers, state.workers.len);
    try std.testing.expectEqual(reloaded.workers, state.pools.len);
    try std.testing.expectEqual(reloaded.workers, state.idles.len);
}

test "zix zixer: daemon max recv buf, the main.cfg value reaches a started site" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: daemon buffer size test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_recv_buf/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_recv_buf") catch {};

    var seed = try testDaemon(io, arena.allocator(), test_root);
    seed.deinit();

    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{ .truncate = true });
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll("max_recv_buf: 2 * 1024\n");
    try writer.interface.flush();
    file.close(io);

    var daemon = try Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = test_root, .source = .ARG });
    defer daemon.deinit();
    try std.testing.expectEqual(@as(usize, 2048), daemon.cfg.max_recv_buf);

    try writeSiteFile(io, arena.allocator(), test_root, "buffered.cfg", "engine: http1\nip: 127.0.0.1\nport: 18972\nupstreams: 127.0.0.1:18973\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start buffered.cfg", &reply_buf), "ok: "));

    // The site file names no size, so the daemon value is what the edge
    // allocates with.
    const state = daemon.sites.items[0].listener.proxy_edge;
    try std.testing.expectEqual(@as(usize, 2048), state.stream_buf_bytes);
    try std.testing.expectEqual(@as(usize, 2048), state.workers[0].proxy.stream_buf_bytes);
}

test "zix zixer: daemon process gate, the main.cfg values reach a started site" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: daemon process gate test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_process_gate/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_process_gate") catch {};

    var seed = try testDaemon(io, arena.allocator(), test_root);
    seed.deinit();

    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{ .truncate = true });
    var write_buf: [192]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll("process_limit: 6\nprocess_queue_len: 12\nprocess_queue_timeout_ms: 2500\n");
    try writer.interface.flush();
    file.close(io);

    var daemon = try Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = test_root, .source = .ARG });
    defer daemon.deinit();
    try std.testing.expectEqual(@as(usize, 6), daemon.cfg.process_limit);

    try writeSiteFile(io, arena.allocator(), test_root, "gated.cfg", "engine: http1\nip: 127.0.0.1\nport: 18975\nupstreams: 127.0.0.1:18976\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start gated.cfg", &reply_buf), "ok: "));

    // The site file names none of the three, so the daemon values are what
    // the gate runs with, and every worker's proxy points at that one gate.
    const state = daemon.sites.items[0].listener.proxy_edge;
    try std.testing.expectEqual(@as(usize, 6), state.process_gate.settings.limit);
    try std.testing.expectEqual(@as(usize, 12), state.process_gate.settings.queue_len);
    try std.testing.expectEqual(@as(u32, 2500), state.process_gate.settings.timeout_ms);
    try std.testing.expectEqual(@as(usize, 12), state.process_gate.slots.len);
    try std.testing.expectEqual(&state.process_gate, state.workers[0].proxy.process_gate.?);
}

test "zix zixer: daemon process gate, a site override beats the main.cfg value" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: daemon process gate override test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_gate_override/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_gate_override") catch {};

    var seed = try testDaemon(io, arena.allocator(), test_root);
    seed.deinit();

    const main_path = try std.fs.path.join(arena.allocator(), &.{ test_root, "main.cfg" });
    const file = try std.Io.Dir.cwd().createFile(io, main_path, .{ .truncate = true });
    var write_buf: [192]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll("process_limit: 6\nprocess_queue_len: 12\n");
    try writer.interface.flush();
    file.close(io);

    var daemon = try Daemon.init(std.testing.allocator, io, arena.allocator(), .{ .path = test_root, .source = .ARG });
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "own.cfg", "engine: http1\nip: 127.0.0.1\nport: 18977\nupstreams: 127.0.0.1:18978\nprocess_limit: 2\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("start own.cfg", &reply_buf), "ok: "));

    // Only the limit was overridden, so the queue and the wait still come
    // from main.cfg.
    const state = daemon.sites.items[0].listener.proxy_edge;
    try std.testing.expectEqual(@as(usize, 2), state.process_gate.settings.limit);
    try std.testing.expectEqual(@as(usize, 12), state.process_gate.settings.queue_len);
}

test "zix zixer: daemon handleLine, shutdown reports the unbind count and sets the flag" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_shutdown/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_shutdown") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nip: 127.0.0.1\nport: 18866\nupstreams: 127.0.0.1:3000\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    _ = daemon.handleLine("start service_a.cfg", &reply_buf);

    try std.testing.expectEqualStrings("ok: daemon stopped, sites unbound: 1", daemon.handleLine("shutdown", &reply_buf));
    try std.testing.expect(daemon.stop_requested);
}

fn runDaemonThread(daemon: *Daemon) void {
    daemon.run() catch {};
}

test "zix zixer: daemon end to end, socket round trip start ping shutdown" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_e2e/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_e2e") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "service_a.cfg", "engine: http1\nip: 127.0.0.1\nport: 18867\nupstreams: 127.0.0.1:3000\n");

    const daemon_thread = try std.Thread.spawn(.{}, runDaemonThread, .{&daemon});

    // Bounded wait for the control socket to answer, then one exchange per verb.
    var tries: usize = 0;
    while (tries < 100 and !control_client.ping(io, daemon.socket_path)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
    }
    try std.testing.expect(tries < 100);

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const started = try control_client.call(io, daemon.socket_path, "start service_a.cfg", &reply_buf);
    try std.testing.expect(started.ok);
    try std.testing.expectEqualStrings("service_a.cfg started on 127.0.0.1:18867", started.text);

    var stop_buf: [control.MAX_LINE]u8 = undefined;
    const stopped = try control_client.call(io, daemon.socket_path, "shutdown", &stop_buf);
    try std.testing.expect(stopped.ok);

    daemon_thread.join();

    try std.testing.expectEqual(@as(usize, 0), daemon.sites.items.len);
}

test "zix zixer: daemon run, sigpipe is ignored before the accept loop starts" {
    if (comptime @import("builtin").os.tag == .windows) {
        std.log.info("zix zixer: daemon sigpipe test needs POSIX sigaction, skip on windows", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_sigpipe/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_sigpipe") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    const daemon_thread = try std.Thread.spawn(.{}, runDaemonThread, .{&daemon});

    var tries: usize = 0;
    while (tries < 100 and !control_client.ping(io, daemon.socket_path)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
    }
    try std.testing.expect(tries < 100);

    var old_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(std.posix.SIG.PIPE, null, &old_action);
    try std.testing.expectEqual(std.posix.SIG.IGN, old_action.handler.handler);

    var stop_buf: [control.MAX_LINE]u8 = undefined;
    _ = try control_client.call(io, daemon.socket_path, "shutdown", &stop_buf);
    daemon_thread.join();
}

test "zix zixer: daemon handleLine, tls site with a missing cert file refuses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_tlscert/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_tlscert") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "tls_bad.cfg", "engine: http1\nip: 127.0.0.1\nport: 18898\n" ++
        "tls: true\ntls_cert: examples/certs/absent.pem\ntls_key: examples/certs/ecdsa_p256_key.pem\n" ++
        "public_dir: /var/www/pages\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = daemon.handleLine("start tls_bad.cfg", &reply_buf);

    // The cause and the path both, so the operator does not have to guess which file or why.
    try std.testing.expect(std.mem.indexOf(u8, reply, "tls_cert does not exist") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "examples/certs/absent.pem") != null);
}

/// True when this process may bind the privileged http-01 port. Probed
/// with raw syscalls: a failing privileged bind through std prints the
/// unexpected-errno trace in debug builds, the probe keeps unprivileged
/// runs silent.
fn canBindPort80() bool {
    const linux = std.os.linux;

    const fd_raw = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (@as(isize, @bitCast(fd_raw)) < 0) return false;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, 80),
        .addr = std.mem.nativeToBig(u32, 0x7F00_0001),
    };

    return linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)) == 0;
}

test "zix zixer: daemon handleLine, tls acme site starts or names the port 80 need" {
    if (comptime @import("builtin").os.tag == .linux) {
        if (!canBindPort80()) {
            std.log.info("binding the privileged port 80 needs a capability this run lacks, test skipped", .{});
            return;
        }
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const test_root = "tmp/zixer_daemon_tlsacme/root";
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_daemon_tlsacme") catch {};

    var daemon = try testDaemon(io, arena.allocator(), test_root);
    defer daemon.deinit();

    try writeSiteFile(io, arena.allocator(), test_root, "tls_acme.cfg", "engine: http1\nip: 127.0.0.1\nport: 18899\n" ++
        "tls: true\ntls_cert: examples/certs/ecdsa_p256_cert.pem\ntls_key: examples/certs/ecdsa_p256_key.pem\n" ++
        "acme_webroot: /var/www/acme\npublic_dir: /var/www/pages\n");

    var reply_buf: [control.MAX_LINE]u8 = undefined;
    const reply = daemon.handleLine("start tls_acme.cfg", &reply_buf);

    // Three outcomes, all correct: with the privilege and a free port 80 the
    // companion binds and the site starts, without the privilege the bind
    // fails and the reply names the port 80 need, and with a listener outside
    // this daemon on port 80 the probe refuses and the reply names the taken
    // challenge port. Only the port number is common to the two refusals.
    if (std.mem.startsWith(u8, reply, "ok: ")) {
        try std.testing.expect(std.mem.startsWith(u8, daemon.handleLine("stop tls_acme.cfg", &reply_buf), "ok: "));
    } else {
        try std.testing.expect(std.mem.indexOf(u8, reply, "port 80") != null);
    }
}
