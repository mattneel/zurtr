//! zixer site serve state: the workers, pools, and caches one proxy site owns

const std = @import("std");
const zix = @import("zix");

const acme_challenge = @import("acme_challenge.zig");
const bind_options = @import("bind_options.zig");
const cfg_headers = @import("cfg_headers.zig");
const conn_buffer = @import("conn_buffer.zig");
const deadline_table = @import("deadline_table.zig");
const fault = @import("fault.zig");
const http1_proxy = @import("http1_proxy.zig");
const process_gate = @import("process_gate.zig");
const request_scheme = @import("request_scheme.zig");
const site_cfg = @import("site_cfg.zig");
const site_sweep = @import("site_sweep.zig");
const site_worker = @import("site_worker.zig");
const static_cached = @import("static_cached.zig");
const static_files = @import("static_files.zig");
const tls_edge = @import("tls_edge.zig");
const upstream_conn = @import("upstream_conn.zig");
const upstream_deadline = @import("upstream_deadline.zig");
const upstream_pool = @import("upstream_pool.zig");

/// Wake attempts a shutdown makes per worker before it joins anyway, one
/// per millisecond. Generous: the loop stops as soon as every worker has
/// left, so the bound only matters if one is wedged inside a connection.
const WAKE_ROUNDS_PER_WORKER: usize = 200;

/// Everything one serving site owns. Heap-allocated so the accept threads
/// and their connection tasks keep stable pointers while the daemon
/// registry moves.
///
/// Note:
/// - workers holds one accept loop per resolved worker, each with its own
///   listener on the same port. pools and idles are parallel to it, one
///   entry per worker, so a request never crosses a worker's spinlock.
///   Both are empty on a static-only site, which serves public_dir alone.
/// - tls_ctx exists only when the site terminates TLS: built from the cfg
///   cert / key paths at create, so a restart re-reads renewed cert files
///   (the certbot deploy-hook path). Every worker reads the same one.
/// - sweeper runs on a site that has idle caches, a client bound, or both.
///   One thread hands aged upstream connections back even while the site
///   sits quiet, and cuts client connections past their budget. A site with
///   neither never starts it.
/// - client_table is the whole site's, not one per worker: the limit has to
///   mean connections into this site, and workers follows the thread count.
///   Empty (and allocating nothing) unless the site configured a bound.
pub const ServeState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    engine: site_cfg.Engine,
    workers: []site_worker.Worker,
    pools: []upstream_pool.Pool,
    idles: []upstream_conn.IdleCache,
    sweeper: site_sweep.Sweeper = .{},
    /// The site's client bound: how long one exchange may take, and the
    /// slots that track them.
    client_bound: deadline_table.Settings,
    client_table: deadline_table.Table,
    /// How long a connect to an upstream may take, already resolved. Zero
    /// waits on whatever the operating system decides.
    upstream_connect_timeout_ms: u32,
    upstream_timeout_ms: u32,
    /// One leg's stream buffer size, already resolved from the site file
    /// and the main.cfg default. Every connection this site accepts
    /// allocates its buffers at this size.
    stream_buf_bytes: usize,
    /// How many requests this site may run upstream at once, and who waits.
    /// One gate for the whole site, not one per worker: the number has to
    /// mean what the backend absorbs, and workers follows the thread count.
    /// Off (admits everything) unless the config asked for a limit.
    process_gate: process_gate.Gate,
    /// How long a cached public_dir file stays fresh for this site, already
    /// resolved from the site file and the main.cfg default. 0 serves every
    /// static request through the uncached open, which is the default.
    public_dir_cache_ttl_ms: u32,
    public_dir: ?[]const u8,
    public_prefix: ?[]const u8,
    spa_fallback: ?[]const u8,
    tls_ctx: ?zix.Tls.Context,
    /// The site's compiled header sections. Both point into the cfg arena, so
    /// they live as long as the parsed site config does.
    response_headers: cfg_headers.Table,
    request_headers: cfg_headers.Table,
    acme_webroot: ?[]const u8,
    acme_relay: ?site_cfg.Upstream,
    /// The daemon's logger, borrowed. Null is a site built outside a daemon,
    /// and those lines reach std.log instead, see daemon_log.logSystem.
    logger: ?*zix.Logger,
    stop: std.atomic.Value(bool) = .init(false),
    wake_ip: []const u8,
    port: u16,

    /// Build the serve state and start one accept thread per worker.
    ///
    /// Note:
    /// - server is moved in here: the caller hands the bound listener over
    ///   and must not touch it again, it becomes worker 0's. Any further
    ///   worker binds its own listener on the same address, which needs no
    ///   port probe: the site already owns the port at that point.
    /// - Every string taken from cfg is duped, the caller's arena may go.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (state, workers, pools, caches, long-lived)
    /// io - std.Io (must outlive the state)
    /// server - std.Io.net.Server (bound tcp listener, becomes worker 0's)
    /// cfg - *const site_cfg.SiteCfg (validated site config)
    /// port - u16
    /// options - bind_options.BindOptions (the main.cfg values, workers already resolved)
    ///
    /// Return:
    /// - *ServeState with every accept thread running
    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: std.Io.net.Server,
        cfg: *const site_cfg.SiteCfg,
        port: u16,
        options: bind_options.BindOptions,
    ) !*ServeState {
        const worker_total = @max(1, options.workers);
        const kernel_backlog = options.kernel_backlog;

        const state = try allocator.create(ServeState);
        errdefer allocator.destroy(state);

        const idle_ttl_ms = upstream_conn.resolveIdleTtl(cfg.upstream_idle_ttl_ms, options.upstream_idle_ttl_ms);

        var pools: []upstream_pool.Pool = &.{};
        errdefer freePools(allocator, pools);
        var idles: []upstream_conn.IdleCache = &.{};
        errdefer freeIdles(allocator, io, idles);
        if (cfg.upstreams.len > 0) {
            pools = try buildPools(allocator, cfg.upstreams, worker_total);
            idles = try buildIdles(allocator, io, cfg.upstreams.len, worker_total, idle_ttl_ms);
        }

        const wake_ip = try allocator.dupe(u8, cfg.ip);
        errdefer allocator.free(wake_ip);
        const public_dir = try dupeOptional(allocator, cfg.public_dir);
        errdefer freeOptional(allocator, public_dir);
        const public_prefix = try dupeOptional(allocator, cfg.public_prefix);
        errdefer freeOptional(allocator, public_prefix);
        const spa_fallback = try dupeOptional(allocator, cfg.spa_fallback);
        errdefer freeOptional(allocator, spa_fallback);
        const acme_webroot = try dupeOptional(allocator, cfg.acme_webroot);

        // Both tables point into the cfg arena, which does not outlive this
        // state, so the site owns its own copy like every other cfg string.
        const response_headers = try cfg.response_headers.dupe(allocator);
        errdefer response_headers.deinit(allocator);
        const request_headers = try cfg.request_headers.dupe(allocator);
        errdefer request_headers.deinit(allocator);
        errdefer freeOptional(allocator, acme_webroot);
        var acme_relay = cfg.acme_proxy;
        if (cfg.acme_proxy) |relay| acme_relay.?.host = try allocator.dupe(u8, relay.host);
        errdefer if (acme_relay) |relay| allocator.free(relay.host);

        // Validation guarantees cert and key paths exist when tls is on.
        // Loading here (not at validate) keeps restart the cert reload path.
        var tls_ctx: ?zix.Tls.Context = null;
        errdefer if (tls_ctx) |*ctx| ctx.deinit();
        const engine = cfg.engine orelse .HTTP1;
        if (cfg.tls) {
            tls_ctx = try tls_edge.buildContext(allocator, io, cfg.tls_cert.?, cfg.tls_key.?, tls_edge.alpnPrefs(engine));
        }

        const workers_slice = try allocator.alloc(site_worker.Worker, worker_total);
        errdefer allocator.free(workers_slice);

        // Built even when the site has no upstreams: an unarmed gate owns
        // nothing and admits everything, so the edges never branch on it.
        var gate = try process_gate.Gate.init(allocator, process_gate.resolve(
            cfg.process_limit,
            cfg.process_queue_len,
            cfg.process_queue_timeout_ms,
            .{
                .limit = options.process_limit,
                .queue_len = options.process_queue_len,
                .timeout_ms = options.process_queue_timeout_ms,
            },
        ));
        errdefer gate.deinit(allocator);

        // A site with no client bound builds no table and allocates nothing
        // for one, so the edges never pay for a bound the site did not ask
        // for.
        const client_bound = deadline_table.resolve(cfg.client_timeout_ms, cfg.client_conn_limit, .{
            .timeout_ms = options.client_timeout_ms,
            .conn_limit = options.client_conn_limit,
        });
        var client_table = try deadline_table.Table.init(allocator, client_bound.capacity());
        errdefer client_table.deinit(allocator);

        // The table is process-wide and shared by every site, so this only
        // builds one the first time any site asks. A window of 0 builds none.
        const cache_ttl_ms = static_cached.resolveTtl(cfg.public_dir_cache_ttl_ms, options.public_dir_cache_ttl_ms);
        if (public_dir != null) static_cached.install(cache_ttl_ms, options.public_dir_cache_max_entries);

        state.* = .{
            .allocator = allocator,
            .io = io,
            .engine = engine,
            .workers = workers_slice,
            .pools = pools,
            .idles = idles,
            .client_bound = client_bound,
            .client_table = client_table,
            .upstream_connect_timeout_ms = upstream_conn.resolveConnectTimeout(cfg.upstream_connect_timeout_ms, options.upstream_connect_timeout_ms),
            .upstream_timeout_ms = cfg.upstream_timeout_ms orelse upstream_deadline.DEFAULT_MS,
            .stream_buf_bytes = conn_buffer.resolve(cfg.max_recv_buf, options.max_recv_buf),
            .process_gate = gate,
            .public_dir_cache_ttl_ms = if (public_dir == null) 0 else cache_ttl_ms,
            .public_dir = public_dir,
            .public_prefix = public_prefix,
            .spa_fallback = spa_fallback,
            .tls_ctx = tls_ctx,
            .response_headers = response_headers,
            .request_headers = request_headers,
            .acme_webroot = acme_webroot,
            .acme_relay = acme_relay,
            .logger = options.logger,
            .wake_ip = wake_ip,
            .port = port,
        };

        // Worker 0 takes the listener the caller bound. Every other worker
        // binds its own on the same address, which needs no port probe: the
        // site already owns the port, and SO_REUSEPORT is the point here.
        //
        // The error path leaves worker 0's listener alone. Until create
        // returns, that socket is still the caller's to close.
        var bound: usize = 0;
        errdefer for (state.workers[1..@max(1, bound)]) |*worker| worker.closeIdleListener();
        while (bound < worker_total) : (bound += 1) {
            const listener = if (bound == 0) server else try listenShared(io, cfg.ip, port, kernel_backlog);

            state.workers[bound] = .{
                .server = listener,
                .proxy = buildProxy(state, bound),
                .tls_ctx = if (state.tls_ctx) |*ctx| ctx else null,
                .engine = engine,
                .stop = &state.stop,
            };
        }

        // One thread for both sweeps, and none at all for a site with
        // nothing to sweep: a static site with no client bound holds no
        // state that ages.
        if (state.idles.len > 0 or state.client_table.armed()) {
            try state.sweeper.start(io, state.idles, &state.client_table, idle_ttl_ms);
        }
        errdefer state.sweeper.stop();

        try startWorkers(state);

        return state;
    }

    /// Stop every accept thread, close every listener, release everything.
    ///
    /// Note:
    /// - The wake connection is what unblocks an accept call portably:
    ///   closing a socket another thread is blocked on is not reliable
    ///   cross-platform, a loopback connect always is.
    /// - Connections already being served finish on their own tasks.
    pub fn shutdown(state: *ServeState) void {
        const io = state.io;

        state.stop.store(true, .release);
        wakeWorkers(state);

        for (state.workers) |*worker| worker.join();
        for (state.workers) |*worker| worker.cancelConns();
        for (state.workers) |*worker| worker.closeIdleListener();
        state.sweeper.stop();

        state.allocator.free(state.workers);
        state.client_table.deinit(state.allocator);
        state.process_gate.deinit(state.allocator);
        freeIdles(state.allocator, io, state.idles);
        freePools(state.allocator, state.pools);
        if (state.tls_ctx) |*ctx| ctx.deinit();
        state.allocator.free(state.wake_ip);
        freeOptional(state.allocator, state.public_dir);
        freeOptional(state.allocator, state.public_prefix);
        freeOptional(state.allocator, state.spa_fallback);
        freeOptional(state.allocator, state.acme_webroot);
        state.response_headers.deinit(state.allocator);
        state.request_headers.deinit(state.allocator);
        if (state.acme_relay) |relay| state.allocator.free(relay.host);

        const allocator = state.allocator;
        allocator.destroy(state);
    }
};

/// Dupe a string that may be absent.
fn dupeOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    const inner = value orelse return null;

    return try allocator.dupe(u8, inner);
}

fn freeOptional(allocator: std.mem.Allocator, value: ?[]const u8) void {
    if (value) |inner| allocator.free(inner);
}

/// One upstream pool per worker, so the round-robin cursor and its short
/// spinlock are never shared between accept loops.
///
/// Note:
/// - Each copy learns on its own that an upstream is down, so a dead
///   backend costs one failed connect per worker instead of one per site.
///   The cooldown re-admit then works the same way in each copy.
fn buildPools(allocator: std.mem.Allocator, upstreams: []const site_cfg.Upstream, worker_total: usize) ![]upstream_pool.Pool {
    const pools = try allocator.alloc(upstream_pool.Pool, worker_total);
    errdefer allocator.free(pools);

    var built: usize = 0;
    errdefer for (pools[0..built]) |*pool| pool.deinit(allocator);
    while (built < worker_total) : (built += 1) {
        pools[built] = try upstream_pool.Pool.init(allocator, upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    }

    return pools;
}

/// One idle cache per worker, each holding its share of the site's bound and
/// all of them keeping a connection for the same configured age.
fn buildIdles(allocator: std.mem.Allocator, io: std.Io, slot_count: usize, worker_total: usize, idle_ttl_ms: i64) ![]upstream_conn.IdleCache {
    const idles = try allocator.alloc(upstream_conn.IdleCache, worker_total);
    errdefer allocator.free(idles);

    var built: usize = 0;
    errdefer for (idles[0..built]) |*idle| idle.deinit(allocator, io);
    while (built < worker_total) : (built += 1) {
        idles[built] = try upstream_conn.IdleCache.initShare(allocator, slot_count, worker_total, idle_ttl_ms);
    }

    return idles;
}

fn freePools(allocator: std.mem.Allocator, pools: []upstream_pool.Pool) void {
    for (pools) |*pool| pool.deinit(allocator);

    allocator.free(pools);
}

fn freeIdles(allocator: std.mem.Allocator, io: std.Io, idles: []upstream_conn.IdleCache) void {
    for (idles) |*idle| idle.deinit(allocator, io);

    allocator.free(idles);
}

/// Bind one more listener on an address the site already owns.
fn listenShared(io: std.Io, ip: []const u8, port: u16, kernel_backlog: u31) !std.Io.net.Server {
    const addr = std.Io.net.IpAddress.parse(ip, port) catch return error.ZixerSiteCfgIncomplete;

    return addr.listen(io, .{ .reuse_address = true, .kernel_backlog = kernel_backlog });
}

/// The proxy one worker serves with: the site's planes, that worker's
/// upstream leg.
fn buildProxy(state: *ServeState, index: usize) http1_proxy.Proxy {
    const static_site: ?static_files.StaticSite = if (state.public_dir) |dir| .{
        .public_dir = dir,
        .public_prefix = state.public_prefix,
        .spa_fallback = state.spa_fallback,
    } else null;
    const acme: ?acme_challenge.AcmeSite = if (state.acme_webroot != null or state.acme_relay != null)
        .{ .webroot = state.acme_webroot, .relay = state.acme_relay }
    else
        null;

    return .{
        .io = state.io,
        .pool = if (state.pools.len > 0) &state.pools[index] else null,
        .idle = if (state.idles.len > 0) &state.idles[index] else null,
        .static = static_site,
        .acme = acme,
        .tls_cert_der = if (state.tls_ctx) |ctx| ctx.cert_der else null,

        // A terminated TLS edge is the one thing that makes this site https,
        // and the upstream is told that rather than whatever a client claimed.
        .client_scheme = request_scheme.Scheme.ofSite(state.tls_ctx != null),
        .upstream_timeout_ms = state.upstream_timeout_ms,
        .upstream_connect_timeout_ms = state.upstream_connect_timeout_ms,
        .logger = state.logger,
        .allocator = state.allocator,
        .stream_buf_bytes = state.stream_buf_bytes,
        .process_gate = &state.process_gate,
        .client_table = &state.client_table,
        .client_timeout_ms = state.client_bound.timeout_ms,
        .public_dir_cache_ttl_ms = state.public_dir_cache_ttl_ms,
        .response_headers = state.response_headers,
        .request_headers = state.request_headers,
    };
}

/// Spawn every accept thread, worker 0 last.
///
/// Note:
/// - A spawn failure stops whatever already started, so the caller never
///   sees a half-serving site.
/// - Worker 0 serves the listener create was handed, and that socket is
///   the caller's until create returns. Starting it last keeps it
///   unstarted, and so unclosed, on any spawn failure.
fn startWorkers(state: *ServeState) !void {
    var started: usize = 1;
    errdefer {
        state.stop.store(true, .release);
        wakeWorkers(state);
        for (state.workers[1..started]) |*worker| worker.join();
        for (state.workers[1..started]) |*worker| worker.cancelConns();
    }
    while (started < state.workers.len) : (started += 1) {
        try state.workers[started].start();
    }

    try state.workers[0].start();
}

/// Wake accepts until every worker has left its loop.
///
/// Note:
/// - One wake is not one worker: with SO_REUSEPORT the kernel decides which
///   listener takes the connection. A worker closes its listener on the way
///   out, which takes it out of the group, so a retry reaches one that is
///   still blocked.
/// - The round bound only matters when a worker is wedged inside a
///   connection rather than in accept. Joining then blocks either way, the
///   bound just stops the wake loop from spinning on it.
fn wakeWorkers(state: *ServeState) void {
    const rounds = state.workers.len * WAKE_ROUNDS_PER_WORKER;

    for (0..rounds) |_| {
        if (allLeft(state.workers)) return;

        wake(state.io, state.wake_ip, state.port);
        std.Io.sleep(state.io, std.Io.Duration.fromMilliseconds(1), .awake) catch return;
    }
}

fn allLeft(workers: []const site_worker.Worker) bool {
    for (workers) |*worker| {
        if (worker.thread != null and !worker.hasLeft()) return false;
    }

    return true;
}

/// Connect-and-close against the site's own port so a blocked accept returns.
/// A wildcard listen ip is reached through loopback.
fn wake(io: std.Io, ip: []const u8, port: u16) void {
    const target = if (std.mem.eql(u8, ip, "0.0.0.0"))
        "127.0.0.1"
    else if (std.mem.eql(u8, ip, "::"))
        "::1"
    else
        ip;

    // No connect timeout: the std.Io.Threaded backend panics on one (TODO in
    // std), and a loopback connect to an owned port returns immediately.
    const addr = std.Io.net.IpAddress.parse(target, port) catch return;
    const stream = addr.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch return;
    stream.close(io);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const port_probe = @import("port_probe.zig");

test "zix zixer: site serve, create binds a thread and shutdown frees the port" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18982 }};
    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18983, .upstreams = &upstreams };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18983);
    const server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 64 });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18983, .{ .kernel_backlog = 64 });
    state.shutdown();

    // Asked by connect, not by a strict bind. Shutdown's own wake connection
    // leaves this address in TIME_WAIT, which fails a strict bind for a
    // minute for a reason that has nothing to do with the listener. A
    // connect answers the real question: is anything still accepting here.
    try std.testing.expect(!port_probe.isTaken(io, addr));
}

test "zix zixer: site serve, static-only site runs without a pool" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18881,
        .public_dir = "/var/www/static-test",
        .spa_fallback = "index.html",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18881);
    const server = try addr.listen(io, .{ .kernel_backlog = 64, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18881, .{ .kernel_backlog = 64 });
    try std.testing.expect(state.pools.len == 0);
    try std.testing.expect(state.idles.len == 0);
    try std.testing.expectEqualStrings("/var/www/static-test", state.public_dir.?);
    state.shutdown();

    // Asked by connect for the reason the create test spells out above: the
    // shutdown wake connection can leave this address in TIME_WAIT, and a
    // strict bind then fails over a socket that is no longer accepting.
    try std.testing.expect(!port_probe.isTaken(io, addr));
}

test "zix zixer: site serve, wake tolerates a dead port" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    wake(io, "0.0.0.0", 18871);
    wake(io, "not an ip", 18871);
}

test "zix zixer: site serve, tls site create refuses a missing cert file" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18895,
        .tls = true,
        .tls_cert = "examples/certs/absent.pem",
        .tls_key = "examples/certs/ecdsa_p256_key.pem",
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18895);
    var server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    try std.testing.expectError(error.ZixTlsCertFileNotFound, ServeState.create(std.testing.allocator, io, server, &cfg, 18895, .{ .kernel_backlog = 8 }));
    server.deinit(io);
}

test "zix zixer: site serve, tls site terminates and serves the static plane" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(std.testing.io, .{ .sub_path = "index.html", .data = "tls-static" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18894,
        .tls = true,
        .tls_cert = "examples/certs/ecdsa_p256_cert.pem",
        .tls_key = "examples/certs/ecdsa_p256_key.pem",
        .public_dir = root,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18894);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18894, .{ .kernel_backlog = 8 });
    try std.testing.expect(state.tls_ctx != null);

    // manual TLS 1.3 client over the real socket: hello record, read the
    // three-record server flight, finish, then one https request.
    const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    var read_buf: [8 * 1024]u8 = undefined;
    var write_buf: [8 * 1024]u8 = undefined;
    var client_reader = stream.reader(io, &read_buf);
    var client_writer = stream.writer(io, &write_buf);

    var hello_buf: [512]u8 = undefined;
    const started = try zix.Tls.Client.start(.{
        .client_random = @splat(0x11),
        .ephemeral_secret = @splat(0x42),
        .alpn = &.{.HTTP_1_1},
    }, &hello_buf);
    var client_state = started.state;

    var hello_rec: [600]u8 = undefined;
    hello_rec[0] = 22;
    std.mem.writeInt(u16, hello_rec[1..3], 0x0303, .big);
    std.mem.writeInt(u16, hello_rec[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(hello_rec[5 .. 5 + started.client_hello.len], started.client_hello);
    try client_writer.interface.writeAll(hello_rec[0 .. 5 + started.client_hello.len]);
    try client_writer.interface.flush();

    var flight_buf: [8 * 1024]u8 = undefined;
    var flight_len: usize = 0;
    for (0..3) |_| {
        try client_reader.interface.readSliceAll(flight_buf[flight_len..][0..5]);
        const body_len = std.mem.readInt(u16, flight_buf[flight_len + 3 ..][0..2], .big);
        try client_reader.interface.readSliceAll(flight_buf[flight_len + 5 ..][0..body_len]);
        flight_len += 5 + body_len;
    }

    var finish_buf: [256]u8 = undefined;
    const finished = try zix.Tls.Client.finish(&client_state, flight_buf[0..flight_len], &finish_buf);
    var client_conn = finished.connection;
    try client_writer.interface.writeAll(finished.client_finished);
    try client_writer.interface.flush();

    var request_out: [256]u8 = undefined;
    const request_rec = client_conn.writeAppData("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", &request_out);
    try client_writer.interface.writeAll(request_rec);
    try client_writer.interface.flush();

    // collect the sealed response records until the server closes, then
    // decrypt them in order.
    var reply: [2048]u8 = undefined;
    var reply_len: usize = 0;
    var wire: [4096]u8 = undefined;
    collect: while (true) {
        client_reader.interface.readSliceAll(wire[0..5]) catch break :collect;
        const body_len = std.mem.readInt(u16, wire[3..5], .big);
        client_reader.interface.readSliceAll(wire[5..][0..body_len]) catch break :collect;

        var plain: [2048]u8 = undefined;
        const piece = client_conn.readAppData(wire[0 .. 5 + body_len], &plain) catch break :collect;
        @memcpy(reply[reply_len..][0..piece.len], piece);
        reply_len += piece.len;
    }
    stream.close(io);

    const response = reply[0..reply_len];
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, response, "tls-static"));

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, the cfg read bound reaches the state and starts a sweeper" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18954 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18953,
        .upstreams = &upstreams,
        .upstream_timeout_ms = 1234,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18953);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18953, .{ .kernel_backlog = 8 });
    try std.testing.expectEqual(@as(u32, 1234), state.upstream_timeout_ms);
    try std.testing.expect(state.sweeper.thread != null);
    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a site without upstreams takes the default and no sweeper" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18955,
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18955);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18955, .{ .kernel_backlog = 8 });
    try std.testing.expectEqual(upstream_deadline.DEFAULT_MS, state.upstream_timeout_ms);
    try std.testing.expect(state.sweeper.thread == null);
    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

/// One cleartext GET against a running site, the reply head and body.
fn testGet(io: std.Io, port: u16, reply: []u8) ![]const u8 {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var write_buf: [512]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    try writer.interface.flush();

    var read_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    var len: usize = 0;
    while (len < reply.len) {
        const got = reader.interface.readSliceShort(reply[len..]) catch break;
        if (got == 0) break;
        len += got;
    }

    return reply[0..len];
}

test "zix zixer: site serve, a four worker site answers on one shared port" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve worker test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(std.testing.io, .{ .sub_path = "index.html", .data = "four-workers" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18963,
        .public_dir = root,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18963);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18963, .{ .workers = 4, .kernel_backlog = 8 });
    try std.testing.expectEqual(@as(usize, 4), state.workers.len);

    // Four real sockets, not four views of one: the kernel can only spread
    // accepts across listeners that are separately bound.
    for (state.workers, 0..) |*worker, i| {
        for (state.workers[i + 1 ..]) |*other| {
            try std.testing.expect(worker.server.socket.handle != other.server.socket.handle);
        }
    }

    // Four listeners on one port, and every one of them is a live accept
    // loop: a request must be answered whichever the kernel hands it to.
    for (0..12) |_| {
        var reply_buf: [1024]u8 = undefined;
        const reply = try testGet(io, 18963, &reply_buf);

        try std.testing.expect(std.mem.startsWith(u8, reply, "HTTP/1.1 200 OK\r\n"));
        try std.testing.expect(std.mem.endsWith(u8, reply, "four-workers"));
    }

    state.shutdown();

    // Every worker released its listener, so a strict rebind succeeds.
    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, every worker owns its own pool and idle cache" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve per-worker leg test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18965 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18964,
        .upstreams = &upstreams,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18964);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18964, .{ .workers = 3, .kernel_backlog = 8 });
    try std.testing.expectEqual(@as(usize, 3), state.workers.len);
    try std.testing.expectEqual(@as(usize, 3), state.pools.len);
    try std.testing.expectEqual(@as(usize, 3), state.idles.len);

    // No worker shares an upstream leg with another, which is the point of
    // the split: the round-robin cursor and both spinlocks stay local.
    for (state.workers, 0..) |*worker, i| {
        try std.testing.expectEqual(&state.pools[i], worker.proxy.pool.?);
        try std.testing.expectEqual(&state.idles[i], worker.proxy.idle.?);
    }

    // Three workers hold a third of the site bound each, so the backend
    // never loses more of its capacity than a single worker site takes.
    var site_total: usize = 0;
    for (state.idles) |idle| site_total += idle.total_cap;
    try std.testing.expect(site_total <= upstream_conn.TOTAL_IDLE_CAP);

    // One sweep thread covers all three caches.
    try std.testing.expect(state.sweeper.thread != null);
    try std.testing.expectEqual(@as(usize, 3), state.sweeper.caches.len);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a zero worker count still runs one accept loop" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve zero worker test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18966,
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18966);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    // main.cfg resolves 0 before it reaches here, so a 0 arriving at create
    // is a caller mistake. A site with no accept loop would bind the port
    // and answer nothing, which is worse than one loop.
    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18966, .{ .workers = 0, .kernel_backlog = 8 });
    try std.testing.expectEqual(@as(usize, 1), state.workers.len);
    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, the site max recv buf overrides the daemon default" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve buffer size test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18969,
        .public_dir = "/var/www/static-test",
        .max_recv_buf = 4096,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18969);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18969, .{ .workers = 2, .kernel_backlog = 8, .max_recv_buf = 32 * 1024 });

    try std.testing.expectEqual(@as(usize, 4096), state.stream_buf_bytes);
    for (state.workers) |*worker| try std.testing.expectEqual(@as(usize, 4096), worker.proxy.stream_buf_bytes);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a silent site takes the daemon buffer default" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve buffer default test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18970,
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18970);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18970, .{ .kernel_backlog = 8, .max_recv_buf = 16 * 1024 });

    try std.testing.expectEqual(@as(usize, 16 * 1024), state.stream_buf_bytes);
    try std.testing.expectEqual(state.allocator.ptr, state.workers[0].proxy.allocator.ptr);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a site on the smallest buffer still answers" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve small buffer test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const root = "tmp/zixer_small_buf_site";
    try std.Io.Dir.cwd().createDirPath(io, root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    const index = try std.Io.Dir.cwd().createFile(io, root ++ "/index.html", .{});
    var index_buf: [64]u8 = undefined;
    var index_writer = index.writer(io, &index_buf);
    try index_writer.interface.writeAll("small buffer body\n");
    try index_writer.interface.flush();
    index.close(io);

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18971,
        .public_dir = root,
        .max_recv_buf = conn_buffer.MIN_BYTES,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18971);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18971, .{ .kernel_backlog = 8 });
    try std.testing.expectEqual(conn_buffer.MIN_BYTES, state.stream_buf_bytes);

    // A kilobyte per leg is well under the head buffer, so this proves the
    // two are independent: the head still parses, the file still arrives.
    var reply_buf: [1024]u8 = undefined;
    const reply = try testGet(io, 18971, &reply_buf);

    try std.testing.expect(std.mem.indexOf(u8, reply, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "small buffer body") != null);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, the cache window resolves the site over the daemon" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18884,
        .public_dir = "/var/www/static-test",
        .public_dir_cache_ttl_ms = 2500,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18884);
    const server = try addr.listen(io, .{ .kernel_backlog = 64, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18884, .{
        .kernel_backlog = 64,
        .public_dir_cache_ttl_ms = 9000,
        .public_dir_cache_max_entries = 32,
    });
    defer static_cached.shutdown(io);

    // The site wins, and every worker's proxy carries the same resolved value.
    try std.testing.expectEqual(@as(u32, 2500), state.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(@as(u32, 2500), buildProxy(state, 0).public_dir_cache_ttl_ms);
    try std.testing.expect(zix.utils.static_cache.instance() != null);

    state.shutdown();
    try std.testing.expect(!port_probe.isTaken(io, addr));
}

test "zix zixer: site serve, a site with no public dir builds no cache table" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18886 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18885,
        .upstreams = &upstreams,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18885);
    const server = try addr.listen(io, .{ .kernel_backlog = 64, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18885, .{
        .kernel_backlog = 64,
        .public_dir_cache_ttl_ms = 9000,
    });
    defer static_cached.shutdown(io);

    // A proxy-only site has no files to hold, so the daemon window buys it
    // nothing and no descriptors are spent on a table.
    try std.testing.expectEqual(@as(u32, 0), state.public_dir_cache_ttl_ms);
    try std.testing.expect(zix.utils.static_cache.instance() == null);

    state.shutdown();
    try std.testing.expect(!port_probe.isTaken(io, addr));
}

test "zix zixer: site serve, a bounded site sizes its table and reaches every worker" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve client bound test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18926,
        .public_dir = "/var/www/static-test",
        .client_timeout_ms = 20_000,
        .client_conn_limit = 128,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18926);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    // The site names both, so neither daemon default is what runs.
    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18926, .{
        .workers = 2,
        .kernel_backlog = 8,
        .client_timeout_ms = 5_000,
        .client_conn_limit = 4096,
    });

    try std.testing.expectEqual(@as(u32, 20_000), state.client_bound.timeout_ms);
    try std.testing.expectEqual(@as(usize, 128), state.client_table.slots.len);
    try std.testing.expect(state.client_table.armed());

    // One table for the site, and every worker holds the same one: a limit
    // split per worker would mean a different number on every box.
    for (state.workers) |*worker| {
        try std.testing.expectEqual(&state.client_table, worker.proxy.client_table.?);
        try std.testing.expectEqual(@as(u32, 20_000), worker.proxy.client_timeout_ms);
    }

    // A static site has no idle cache, so this thread exists for the client
    // bound alone.
    try std.testing.expectEqual(@as(usize, 0), state.idles.len);
    try std.testing.expect(state.sweeper.thread != null);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a site with no bound allocates no table" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve unbounded site test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18927,
        .public_dir = "/var/www/static-test",
        .client_timeout_ms = 0,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18927);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    // The site turned the bound off for itself while the daemon runs one, so
    // no slot is allocated and no connection can be refused for lack of one.
    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18927, .{
        .kernel_backlog = 8,
        .client_timeout_ms = 30_000,
        .client_conn_limit = 4096,
    });

    try std.testing.expect(!state.client_table.armed());
    try std.testing.expectEqual(@as(usize, 0), state.client_table.slots.len);
    try std.testing.expect(state.sweeper.thread == null);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, the idle age resolves the site over the daemon" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve idle age test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18929 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18928,
        .upstreams = &upstreams,
        .upstream_idle_ttl_ms = 45_000,
        .upstream_connect_timeout_ms = 250,
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18928);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18928, .{
        .workers = 3,
        .kernel_backlog = 8,
        .upstream_idle_ttl_ms = 5_000,
        .upstream_connect_timeout_ms = 9_000,
    });

    // The age is a site value, so every worker's cache holds a connection
    // for the same wait, and the sweep interval follows it.
    for (state.idles) |cache| try std.testing.expectEqual(@as(i64, 45_000), cache.ttl_ms);
    try std.testing.expectEqual(@as(i64, 22_500), state.sweeper.idle_interval_ms);
    try std.testing.expectEqual(@as(u32, 250), state.upstream_connect_timeout_ms);

    for (state.workers) |*worker| try std.testing.expectEqual(@as(u32, 250), worker.proxy.upstream_connect_timeout_ms);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, every worker carries the site's own scheme" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18995 }};

    const cleartext_cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18997,
        .upstreams = &upstreams,
    };
    const cleartext_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18997);
    const cleartext_server = try cleartext_addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    const cleartext = try ServeState.create(std.testing.allocator, io, cleartext_server, &cleartext_cfg, 18997, .{ .workers = 2, .kernel_backlog = 8 });

    for (cleartext.workers) |*worker| try std.testing.expectEqual(request_scheme.Scheme.HTTP, worker.proxy.client_scheme);
    cleartext.shutdown();

    const tls_cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18998,
        .upstreams = &upstreams,
        .tls = true,
        .tls_cert = "examples/certs/ecdsa_p256_cert.pem",
        .tls_key = "examples/certs/ecdsa_p256_key.pem",
    };
    const tls_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18998);
    const tls_server = try tls_addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    const secure = try ServeState.create(std.testing.allocator, io, tls_server, &tls_cfg, 18998, .{ .workers = 2, .kernel_backlog = 8 });

    // The one setting that decides it, reaching every accept loop, so no
    // worker reports a different scheme than its neighbour.
    for (secure.workers) |*worker| try std.testing.expectEqual(request_scheme.Scheme.HTTPS, worker.proxy.client_scheme);
    secure.shutdown();
}

test "zix zixer: site serve, the header tables reach every worker and outlive the cfg arena" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18985);
    const server = try addr.listen(io, .{ .kernel_backlog = 64, .reuse_address = true });

    const state = built: {
        // The cfg arena is released before the state is used, which is what
        // the serving daemon does too.
        var cfg_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer cfg_arena.deinit();

        const content =
            "engine: http1\n" ++
            "ip: 127.0.0.1\n" ++
            "port: 18985\n" ++
            "upstreams: 127.0.0.1:18986\n" ++
            "[response_headers]\n" ++
            "x-frame-options: DENY\n" ++
            "[request_headers]\n" ++
            "x-real-ip: $client_ip\n";

        var faults = fault.FaultList.init(cfg_arena.allocator());
        var cfg = try site_cfg.parse(cfg_arena.allocator(), content, &faults);
        try std.testing.expectEqual(@as(usize, 0), faults.slice().len);

        break :built try ServeState.create(std.testing.allocator, io, server, &cfg, 18985, .{ .kernel_backlog = 64 });
    };

    const proxy = buildProxy(state, 0);
    try std.testing.expect(proxy.response_headers.owns("x-frame-options"));
    try std.testing.expect(proxy.request_headers.owns("x-real-ip"));

    var buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&buf);
    try proxy.response_headers.write(&out, .{});
    try std.testing.expectEqualStrings("x-frame-options: DENY\r\n", out.buffered());

    state.shutdown();
    try std.testing.expect(!port_probe.isTaken(io, addr));
}

test "zix zixer: site serve, the daemon logger reaches every worker's proxy" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve logger handoff test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Writes nowhere, so the handoff is what is under test rather than the output.
    var logger = zix.Logger{ .config = .{}, .allocator = std.testing.allocator };

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18996,
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18996);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18996, .{
        .workers = 2,
        .kernel_backlog = 8,
        .logger = &logger,
    });

    try std.testing.expectEqual(@as(?*zix.Logger, &logger), state.logger);
    for (state.workers) |*worker| try std.testing.expectEqual(@as(?*zix.Logger, &logger), worker.proxy.logger);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}

test "zix zixer: site serve, a site bound with no daemon logger carries none" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site serve logger absence test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18994,
        .public_dir = "/var/www/static-test",
    };

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18994);
    const server = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });

    const state = try ServeState.create(std.testing.allocator, io, server, &cfg, 18994, .{ .kernel_backlog = 8 });

    try std.testing.expectEqual(@as(?*zix.Logger, null), state.logger);
    try std.testing.expectEqual(@as(?*zix.Logger, null), state.workers[0].proxy.logger);

    state.shutdown();

    var rebound = try addr.listen(io, .{ .kernel_backlog = 8, .reuse_address = true });
    rebound.deinit(io);
}
