//! zixer site worker: one accept loop with its own listener and upstream leg

const std = @import("std");
const zix = @import("zix");

const grpc_edge = @import("grpc_edge.zig");
const http1_proxy = @import("http1_proxy.zig");
const http2_edge = @import("http2_edge.zig");
const site_cfg = @import("site_cfg.zig");
const tcp_nodelay = @import("tcp_nodelay.zig");
const tls_edge = @import("tls_edge.zig");

/// Consecutive accept failures before one worker gives up. The other
/// workers of the site keep serving.
pub const MAX_ACCEPT_FAILURES: usize = 100;

/// One accept loop of a serving site.
///
/// Note:
/// - Every worker of a site holds its own listener on the same port, so the
///   kernel spreads accepts instead of one thread taking them all. It also
///   holds its own upstream pool and idle cache, which keeps the two short
///   spinlocks under them uncontended between workers.
/// - stop points at the site's flag: one store stops every worker.
/// - The worker closes its own listener as it leaves. That takes the socket
///   out of the SO_REUSEPORT group, which is what lets the site's shutdown
///   reach the workers that are still blocked in accept.
pub const Worker = struct {
    server: std.Io.net.Server,
    proxy: http1_proxy.Proxy,
    tls_ctx: ?*const zix.Tls.Context,
    engine: site_cfg.Engine,
    stop: *std.atomic.Value(bool),
    /// Live connection tasks. A concurrent group member releases its
    /// resources when the task returns, the site cancels the stragglers
    /// before the pool and strings are freed.
    conns: std.Io.Group = .init,
    thread: ?std.Thread = null,
    left: std.atomic.Value(bool) = .init(false),

    /// Spawn the accept thread.
    ///
    /// Return:
    /// - void, the thread is running
    /// - any std.Thread.spawn error, the worker stays unstarted and still
    ///   owns its listener
    pub fn start(worker: *Worker) !void {
        worker.thread = try std.Thread.spawn(.{}, acceptLoop, .{worker});
    }

    /// Whether the accept loop has returned and closed its listener.
    pub fn hasLeft(worker: *const Worker) bool {
        return worker.left.load(.acquire);
    }

    /// Join the accept thread. Safe on a worker that never started.
    pub fn join(worker: *Worker) void {
        if (worker.thread) |thread| thread.join();
        worker.thread = null;
    }

    /// Cancel whatever connection tasks are still running.
    pub fn cancelConns(worker: *Worker) void {
        worker.conns.cancel(worker.proxy.io);
    }

    /// Close the listener of a worker that never ran. A worker that ran
    /// closed its own on the way out.
    pub fn closeIdleListener(worker: *Worker) void {
        if (worker.hasLeft()) return;

        worker.server.deinit(worker.proxy.io);
    }
};

fn acceptLoop(worker: *Worker) void {
    const io = worker.proxy.io;

    var accept_failures: usize = 0;
    while (!worker.stop.load(.acquire)) {
        const stream = worker.server.accept(io) catch {
            if (worker.stop.load(.acquire)) break;

            accept_failures += 1;
            if (accept_failures >= MAX_ACCEPT_FAILURES) break;
            continue;
        };
        accept_failures = 0;

        if (worker.stop.load(.acquire)) {
            stream.close(io);
            break;
        }

        // Every engine on this listener writes a reply as more than one
        // segment somewhere (h2 frames, grpc trailers, a tls record after a
        // head), so Nagle costs a delayed-ack round trip per request.
        tcp_nodelay.apply(stream);

        const task = ConnTask{ .proxy = worker.proxy, .stream = stream, .tls_ctx = worker.tls_ctx, .engine = worker.engine };
        worker.conns.concurrent(io, serveTask, .{task}) catch serveTask(task);
    }

    // Out of the SO_REUSEPORT group before the flag flips: a shutdown that
    // sees left set must never send another wake connection here.
    worker.server.deinit(io);
    worker.left.store(true, .release);
}

const ConnTask = struct {
    proxy: http1_proxy.Proxy,
    stream: std.Io.net.Stream,
    tls_ctx: ?*const zix.Tls.Context,
    engine: site_cfg.Engine,
};

fn serveTask(task: ConnTask) void {
    if (task.tls_ctx) |ctx| {
        tls_edge.serveConn(&task.proxy, ctx, task.stream, task.engine);
        return;
    }

    // A cleartext http2 site sniffs the preface and falls back to the h1
    // loop for anything else (rfc 9113 3.3 prior knowledge). A grpc site
    // requires the preface outright, prior knowledge is the grpc norm.
    if (task.engine == .HTTP2) {
        http2_edge.serveConn(&task.proxy, task.stream);
        return;
    }
    if (task.engine == .GRPC) {
        grpc_edge.serveConn(&task.proxy, task.stream);
        return;
    }

    http1_proxy.serveConn(&task.proxy, task.stream);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Bind a listener the way a site worker does, for the tests below.
fn testListener(io: std.Io, port: u16) !std.Io.net.Server {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);

    return addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 });
}

/// Connect once and close, the way a site's shutdown wakes an accept.
fn testWake(io: std.Io, port: u16) void {
    const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
    const stream = addr.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch return;
    stream.close(io);
}

test "zix zixer: site worker, an unstarted worker keeps its listener" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site worker listener test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stop = std.atomic.Value(bool).init(false);
    var worker = Worker{
        .server = try testListener(io, 18960),
        .proxy = .{ .io = io },
        .tls_ctx = null,
        .engine = .HTTP1,
        .stop = &stop,
    };

    try std.testing.expect(!worker.hasLeft());
    worker.closeIdleListener();

    // The port is free again, so closeIdleListener really released it.
    var rebound = try testListener(io, 18960);
    rebound.deinit(io);
}

test "zix zixer: site worker, a woken worker closes its listener and flags it" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site worker wake test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stop = std.atomic.Value(bool).init(false);
    var worker = Worker{
        .server = try testListener(io, 18961),
        .proxy = .{ .io = io },
        .tls_ctx = null,
        .engine = .HTTP1,
        .stop = &stop,
    };
    try worker.start();

    stop.store(true, .release);
    testWake(io, 18961);
    worker.join();
    worker.cancelConns();

    try std.testing.expect(worker.hasLeft());

    // left means the loop already closed the listener, so closeIdleListener
    // must leave it alone and the port must be free.
    worker.closeIdleListener();

    var rebound = try testListener(io, 18961);
    rebound.deinit(io);
}

test "zix zixer: site worker, two workers share one port and both accept" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site worker port sharing test needs linux", .{});

        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Two listeners on one port is exactly what a two-worker site binds. A
    // platform without SO_REUSEPORT would refuse the second one here.
    const first = try testListener(io, 18962);
    const second = try testListener(io, 18962);

    var stop = std.atomic.Value(bool).init(false);
    var workers = [_]Worker{
        .{ .server = first, .proxy = .{ .io = io }, .tls_ctx = null, .engine = .HTTP1, .stop = &stop },
        .{ .server = second, .proxy = .{ .io = io }, .tls_ctx = null, .engine = .HTTP1, .stop = &stop },
    };

    for (&workers) |*worker| try worker.start();

    // Both threads must be inside accept before the flag flips. A worker
    // still starting up reads the flag at the top of its loop and leaves
    // on its own, which would hide whether the wake reached it.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};

    stop.store(true, .release);

    // One wake is not one worker: the kernel picks which listener takes the
    // connection. A worker that already left is out of the group, so the
    // retry reaches the one still blocked.
    var rounds: usize = 0;
    while (rounds < 400) : (rounds += 1) {
        if (workers[0].hasLeft() and workers[1].hasLeft()) break;

        testWake(io, 18962);
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
    }

    for (&workers) |*worker| worker.join();
    for (&workers) |*worker| worker.cancelConns();
    for (&workers) |*worker| worker.closeIdleListener();

    try std.testing.expect(workers[0].hasLeft());
    try std.testing.expect(workers[1].hasLeft());

    var rebound = try testListener(io, 18962);
    rebound.deinit(io);
}
