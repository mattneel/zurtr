//! zixer site background thread: the one tick that drives every periodic sweep a site needs

const std = @import("std");
const zix = @import("zix");

const deadline_sweep = @import("deadline_sweep.zig");
const deadline_table = @import("deadline_table.zig");
const upstream_conn = @import("upstream_conn.zig");

const monotonic_clock = zix.utils.monotonic_clock;

/// One thread per site, running both of the site's sweeps.
///
/// Note:
/// - The client bound is swept every tick, the idle caches every half age. Two intervals, one
///   thread: a sweep is a short walk, so spending a thread on each would buy nothing.
/// - The thread wakes every tick even with nothing to do, which is also what makes stopping a site
///   prompt: the stop flag is read that often.
/// - Expiry on acquire only fires when a request arrives, and a site holding connections it is not
///   using is exactly the case with no requests. That is what the idle sweep covers.
/// - A site with several workers owns one idle cache per worker and one deadline table for the
///   whole site, and this thread covers all of them.
/// - The sweeper must live at a stable address: the thread holds a pointer to it. Every site state
///   that owns one is heap allocated.
pub const Sweeper = struct {
    /// Everything but the flags is filled by start. A default Sweeper is a valid never-started one,
    /// so a site with nothing to sweep can hold the field and still call stop on it.
    io: std.Io = undefined,
    caches: []upstream_conn.IdleCache = &.{},
    table: ?*deadline_table.Table = null,
    /// Gap between two idle sweeps, already derived from the site's configured age.
    idle_interval_ms: i64 = deadline_sweep.TICK_MS,
    stop_flag: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    /// Start the site's sweep thread.
    ///
    /// Note:
    /// - Both targets are optional. An empty caches slice and a null table are legal, the tick then
    ///   only carries the stop flag, and a caller with neither should not start one at all.
    ///
    /// Param:
    /// io - std.Io (must outlive the sweeper)
    /// caches - []upstream_conn.IdleCache (must outlive the sweeper)
    /// table - ?*deadline_table.Table (the site's client bound, null when it runs none)
    /// idle_ttl_ms - i64 (the site's resolved idle age, sets the idle interval)
    ///
    /// Return:
    /// - void, the thread is running
    /// - any std.Thread.spawn error, the sweeper stays unstarted
    pub fn start(
        sweeper: *Sweeper,
        io: std.Io,
        caches: []upstream_conn.IdleCache,
        table: ?*deadline_table.Table,
        idle_ttl_ms: i64,
    ) !void {
        sweeper.* = .{
            .io = io,
            .caches = caches,
            .table = table,
            .idle_interval_ms = idleInterval(idle_ttl_ms),
        };

        sweeper.thread = try std.Thread.spawn(.{}, sweepLoop, .{sweeper});
    }

    /// Stop sweeping and join the thread. Safe on a sweeper that never started.
    pub fn stop(sweeper: *Sweeper) void {
        sweeper.stop_flag.store(true, .release);

        if (sweeper.thread) |thread| thread.join();
        sweeper.thread = null;
    }
};

/// Half the idle age, so a conn is handed back within roughly one and a half times its age of going
/// quiet. Never under one tick: an age of 0 parks nothing, and a sweep faster than the tick is not
/// a thing the thread can do.
pub fn idleInterval(idle_ttl_ms: i64) i64 {
    return @max(deadline_sweep.TICK_MS, @divTrunc(idle_ttl_ms, 2));
}

fn sweepLoop(sweeper: *Sweeper) void {
    var since_idle_ms: i64 = 0;

    while (!sweeper.stop_flag.load(.acquire)) {
        if (!sleepTick(sweeper)) return;

        const now_ms = monotonic_clock.nowMs(sweeper.io);
        if (sweeper.table) |table| _ = deadline_sweep.sweepOnce(table, now_ms);

        since_idle_ms += deadline_sweep.TICK_MS;
        if (since_idle_ms < sweeper.idle_interval_ms) continue;

        since_idle_ms = 0;
        for (sweeper.caches) |*cache| _ = cache.sweepExpired(sweeper.io, now_ms);
    }
}

/// Sleep one tick, false when the site asked to stop.
fn sleepTick(sweeper: *Sweeper) bool {
    std.Io.sleep(sweeper.io, std.Io.Duration.fromMilliseconds(deadline_sweep.TICK_MS), .awake) catch return false;

    return !sweeper.stop_flag.load(.acquire);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: site sweep, the idle interval is half the age and never under a tick" {
    try std.testing.expectEqual(@as(i64, 30_000), idleInterval(60_000));
    try std.testing.expectEqual(@as(i64, deadline_sweep.TICK_MS), idleInterval(0));
    try std.testing.expectEqual(@as(i64, deadline_sweep.TICK_MS), idleInterval(deadline_sweep.TICK_MS));
    try std.testing.expectEqual(@as(i64, 2_500), idleInterval(upstream_conn.DEFAULT_IDLE_TTL_MS));
}

test "zix zixer: site sweep, a quiet site gets its aged conn closed" {
    if (comptime @import("builtin").os.tag != .linux) {
        // non-linux region: the fixture parks a raw socketpair descriptor,
        // which only linux hands out here. Nothing is bound.
        std.log.info("site sweep idle test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[1]);

    var cache = try upstream_conn.IdleCache.init(std.testing.allocator, 1);
    defer cache.deinit(std.testing.allocator, io);

    // Parked with a stamp already past the age bound, so the first sweep
    // takes it. No request is ever made against this site.
    const stale_stamp = monotonic_clock.nowMs(io) - upstream_conn.DEFAULT_IDLE_TTL_MS;
    const parked = upstream_conn.UpstreamConn{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .slot_index = 0,
        .reused = false,
    };
    cache.release(io, parked, stale_stamp);
    try std.testing.expectEqual(@as(usize, 1), cache.totalIdle());

    var sweeper: Sweeper = undefined;
    try sweeper.start(io, (&cache)[0..1], null, upstream_conn.DEFAULT_IDLE_TTL_MS);
    defer sweeper.stop();

    var waited: usize = 0;
    while (cache.totalIdle() > 0 and waited < 60) : (waited += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(100), .awake) catch break;
    }

    try std.testing.expectEqual(@as(usize, 0), cache.totalIdle());

    // The backend end of that connection saw it close.
    var probe: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.read(fds[1], &probe, 1));
}

test "zix zixer: site sweep, stop joins promptly and leaves a fresh conn alone" {
    if (comptime @import("builtin").os.tag != .linux) {
        // non-linux region: the fixture parks a raw socketpair descriptor,
        // which only linux hands out here. Nothing is bound.
        std.log.info("site sweep stop test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[1]);

    var cache = try upstream_conn.IdleCache.init(std.testing.allocator, 1);
    defer cache.deinit(std.testing.allocator, io);

    const parked = upstream_conn.UpstreamConn{
        .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
        .slot_index = 0,
        .reused = false,
    };
    cache.release(io, parked, monotonic_clock.nowMs(io));

    var sweeper: Sweeper = undefined;
    try sweeper.start(io, (&cache)[0..1], null, upstream_conn.DEFAULT_IDLE_TTL_MS);
    sweeper.stop();

    // Stopping inside one interval leaves the fresh conn parked, and a
    // second stop on a joined sweeper is harmless.
    try std.testing.expectEqual(@as(usize, 1), cache.totalIdle());
    sweeper.stop();
}

test "zix zixer: site sweep, one thread sweeps every worker cache of a site" {
    if (comptime @import("builtin").os.tag != .linux) {
        // non-linux region: the fixture parks raw socketpair descriptors,
        // which only linux hands out here. Nothing is bound.
        std.log.info("site sweep multi cache test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var caches: [3]upstream_conn.IdleCache = undefined;
    for (&caches) |*cache| cache.* = try upstream_conn.IdleCache.initShare(std.testing.allocator, 1, caches.len, upstream_conn.DEFAULT_IDLE_TTL_MS);
    defer for (&caches) |*cache| cache.deinit(std.testing.allocator, io);

    // One already-aged conn parked in each worker's cache.
    var pairs: [3][2]std.posix.fd_t = undefined;
    defer for (&pairs) |*fds| {
        _ = std.os.linux.close(fds[1]);
    };

    const stale_stamp = monotonic_clock.nowMs(io) - upstream_conn.DEFAULT_IDLE_TTL_MS;
    for (&pairs, &caches) |*fds, *cache| {
        try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, fds));
        cache.release(io, .{
            .stream = .{ .socket = .{ .handle = fds[0], .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } } },
            .slot_index = 0,
            .reused = false,
        }, stale_stamp);
    }

    var sweeper: Sweeper = undefined;
    try sweeper.start(io, &caches, null, upstream_conn.DEFAULT_IDLE_TTL_MS);
    defer sweeper.stop();

    var waited: usize = 0;
    while (waited < 60) : (waited += 1) {
        if (caches[0].totalIdle() + caches[1].totalIdle() + caches[2].totalIdle() == 0) break;

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(100), .awake) catch break;
    }

    // No cache is left holding a backend connection, not just the first.
    for (&caches) |*cache| try std.testing.expectEqual(@as(usize, 0), cache.totalIdle());

    var probe: [1]u8 = undefined;
    for (&pairs) |*fds| try std.testing.expectEqual(@as(usize, 0), std.os.linux.read(fds[1], &probe, 1));
}

test "zix zixer: site sweep, the same thread cuts a client past its budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18993);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    var table = try deadline_table.Table.init(std.testing.allocator, 4);
    defer table.deinit(std.testing.allocator);

    // A budget that ran out before the sweeper even started, so the first tick has to act. No
    // cache is passed with it: a static-only site has a client bound and no upstream leg at all.
    const ticket = table.claim(accepted.socket.handle, monotonic_clock.nowMs(io) - 1).TAKEN;

    var no_caches: [0]upstream_conn.IdleCache = .{};
    var sweeper: Sweeper = undefined;
    try sweeper.start(io, &no_caches, &table, upstream_conn.DEFAULT_IDLE_TTL_MS);
    defer sweeper.stop();

    // The first tick cuts the read side, which is local and tells the client nothing. The next one
    // takes the send side too, and that is the FIN the client sees. Waiting on the wire is what
    // proves the thread reached the socket rather than only the table.
    try std.testing.expect(zix.utils.socket_poll.readableWithin(client.socket.handle, 5_000));

    var read_buf: [8]u8 = undefined;
    var client_reader = client.reader(io, &read_buf);
    try std.testing.expectError(error.EndOfStream, client_reader.interface.readSliceAll(read_buf[0..1]));

    table.release(ticket);
}
