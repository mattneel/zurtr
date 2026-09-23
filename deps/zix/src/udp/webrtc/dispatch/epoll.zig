//! zix WebRTC EPOLL dispatch: one SO_REUSEPORT worker per core, each waiting in epoll_wait for
//! either a datagram or the soonest deadline its peers hold (multicore, Linux).
//!
//! What:
//! - Every worker binds its own socket and owns its own peers, so the hot path takes no lock. The
//!   kernel picks the worker by 4-tuple hash, and a WebRTC peer is identified by exactly that
//!   4-tuple, so all of one peer's datagrams land on the worker holding that peer.
//! - On each readiness wake the socket is drained to EAGAIN, so a datagram never waits a whole
//!   cycle, and the replies for that whole drain go out in one send.
//!
//! Note:
//! - No CBPF CPU steering here, unlike the raw UDP and HTTP/3 engines. Steering picks a worker by
//!   receiving CPU rather than by flow, which could split one peer's datagrams across two workers
//!   that each end up holding half of its handshake. The default 4-tuple hash is what keeps a peer
//!   whole, so this engine does not offer the knob at all.
//! - max_peers is counted per worker: a server with N workers holds up to N * max_peers.
//! - The wait is bounded by the soonest deadline any peer holds, capped by tick_interval_ms. A loop
//!   that parked until the next datagram could not retransmit a DTLS flight into silence.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const common = @import("common.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const core = @import("../core.zig");
const datagram = @import("../../datagram.zig");
const worker = @import("worker.zig");

/// Datagrams one recvmmsg call may bring back. WebRTC datagrams are handshake flights and channel
/// messages rather than a request flood, so this is sized to empty a normal queue in one syscall.
const RECV_BATCH: usize = 32;

/// Cap on one drain-to-EAGAIN pass, so a sustained flood still returns to epoll_wait and lets the
/// deadlines run. EAGAIN normally ends the drain long before this.
const MAX_DRAIN_PER_WAKE: usize = 1024;

/// One EPOLL worker: its socket, its epoll descriptor, and the peers it holds.
const Listener = struct {
    config: WebrtcServerConfig,
    fd: std.posix.socket_t,
    epfd: i32,
    rx: datagram.RecvBatch,
    worker: worker.Worker,

    /// Bind, watch, and allocate everything one worker needs.
    ///
    /// Return:
    /// - Listener
    /// - error.ZixEpollCreateFailed / error.ZixEpollWatchFailed when the kernel refused the descriptor
    /// - whatever the bind or the allocations raised
    fn init(config: WebrtcServerConfig) !Listener {
        const fd = try common.openWorkerSocket(config);
        errdefer datagram.close(fd);

        const created = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (std.posix.errno(created) != .SUCCESS) return error.ZixEpollCreateFailed;

        const epfd: i32 = @intCast(created);
        errdefer _ = linux.close(epfd);

        var watch = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .fd = fd } };
        if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &watch)) != .SUCCESS) return error.ZixEpollWatchFailed;

        var rx = try datagram.RecvBatch.init(config.allocator, RECV_BATCH, config.max_recv_buf);
        errdefer rx.deinit();

        return .{
            .config = config,
            .fd = fd,
            .epfd = epfd,
            .rx = rx,
            .worker = try worker.Worker.initDescriptor(config, fd),
        };
    }

    fn deinit(self: *Listener) void {
        self.worker.deinit();
        self.rx.deinit();
        _ = linux.close(self.epfd);
        datagram.close(self.fd);
    }

    /// One trip round the loop: wait, drain whatever arrived, then answer the deadlines that came
    /// due while waiting.
    ///
    /// Note:
    /// - Separated from the loop so a test can drive single passes against a real socket. The loop
    ///   itself is still this file's own (ADR-043), it just has nothing left in it but the repeat.
    ///
    /// Param:
    /// handler - comptime core.HandlerFn
    ///
    /// Return:
    /// - void
    fn pass(self: *Listener, comptime handler: core.HandlerFn) void {
        // epoll_wait counts its timeout in a signed int, and tick_interval_ms is not bounded by
        // anything that says so, so an absurd configured interval waits a long time rather than
        // trapping on the cast.
        const budget = @min(self.worker.waitMs(common.monotonicMs()), @as(u32, std.math.maxInt(i32)));
        const budget_ms: i32 = @intCast(budget);

        var events: [1]linux.epoll_event = undefined;
        const waited = linux.epoll_wait(self.epfd, &events, 1, budget_ms);

        // EINTR and friends: nothing was read, and the next pass re-arms the wait.
        if (std.posix.errno(waited) != .SUCCESS) return;

        const now_ms = common.monotonicMs();

        if (waited > 0) self.drainReady(handler, now_ms);

        // Deadlines are only worth walking when the wait ran out, or when one of them has actually
        // come due. Under steady traffic neither is true and the walk is skipped.
        if (waited == 0 or self.worker.sweepDue(now_ms)) self.worker.sweep(handler, now_ms);

        self.worker.flush();
    }

    /// Empty the kernel receive queue, giving every datagram to the peer it came from.
    fn drainReady(self: *Listener, comptime handler: core.HandlerFn, now_ms: u64) void {
        var drained: usize = 0;

        while (drained < MAX_DRAIN_PER_WAKE) {
            const count = self.rx.recvNow(self.fd) catch break;

            if (count == 0) break;

            drained += count;

            for (0..count) |i| {
                // A datagram the slot could not hold is one no layer below can parse, and every
                // layer here is authenticated, so guessing at the missing bytes is not an option.
                if (self.rx.hdrs[i].hdr.flags & linux.MSG.TRUNC != 0) {
                    common.logSystem(self.config, .WARN, "dropped a datagram larger than max_recv_buf ({d})", .{self.config.max_recv_buf});

                    continue;
                }

                const received = self.rx.get(i);

                self.worker.serve(handler, datagram.sockaddr6ToIp(received.from), received.data, now_ms);
            }

            self.worker.flush();
        }
    }
};

/// One EPOLL worker for its whole life: pin, bind, then answer peers until the process ends.
///
/// Note:
/// - Pub so the io_uring worker can fall back here on a host with no usable ring, which is a
///   capability fold rather than model mixing.
///
/// Param:
/// handler - comptime core.HandlerFn
/// config - WebrtcServerConfig (already validated by the server)
/// worker_id - usize (its slot in the SO_REUSEPORT group)
///
/// Return:
/// - void, returning only when the worker could not start
pub fn workerLoopEpoll(comptime handler: core.HandlerFn, config: WebrtcServerConfig, worker_id: usize, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    // Every exit between here and the receive loop has to reach the group, or the workers that
    // did bind wait on one that is already gone.
    var slot = report.slot(config.io, error.ZixWebrtcWorkerSetupFailed);
    defer slot.close();

    var listener = Listener.init(config) catch |err| {
        slot.fail(err);

        return;
    };
    defer listener.deinit();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them.
    slot.ok();
    if (report.awaitGroup(config.io) != null) return;

    while (true) listener.pass(handler);
}

/// Run the WebRTC server with one SO_REUSEPORT epoll worker per core.
///
/// Param:
/// handler - comptime core.HandlerFn
/// config - WebrtcServerConfig (already validated by the server)
///
/// Return:
/// - !void, blocking until every worker has gone
/// - error.ZixDispatchModelUnsupported off Linux (ADR-065), where the caller picks .ASYNC
pub fn runEpoll(comptime handler: core.HandlerFn, config: WebrtcServerConfig) !void {
    if (comptime !datagram.is_linux) return error.ZixDispatchModelUnsupported;

    const want = common.effectiveWorkers(config);

    const threads = try config.allocator.alloc(std.Thread, want);
    defer config.allocator.free(threads);

    // What every worker says about its own socket, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(want);

    var spawned: usize = 0;
    for (0..want) |i| {
        threads[i] = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, workerLoopEpoll, .{ handler, config, i, &report }) catch |err| {
            common.logSystem(config, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ i, want, @errorName(err) });
            report.abandon(config.io, want - i, err);

            break;
        };
        spawned += 1;
    }

    if (report.awaitGroup(config.io)) |err| {
        common.logSystem(config, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not start ({s})", .{ config.ip, config.port, report.failures(), want, @errorName(err) });

        for (threads[0..spawned]) |thread| thread.join();

        return error.ZixWebrtcListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a socket that may never have been bound.
    common.logSystem(config, .INFO, "listening on {s}:{d} ({d} workers, SO_REUSEPORT + epoll)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const Tls = @import("../../../tls/Tls.zig");
const dialer = @import("../dialer.zig");
const session = @import("test_session.zig");

/// This model's own ports, so the epoll and io_uring session tests never collide.
const TEST_SERVER_PORT: u16 = 19095;
const TEST_DIALER_PORT: u16 = 19096;

test "zix webrtc: epoll, run is refused off linux and every worker binds on it" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try session.testContext(std.testing.allocator);
    const config = session.testConfig(threaded.io(), std.testing.allocator, &tls, TEST_SERVER_PORT);

    if (comptime builtin.target.os.tag != .linux) {
        try std.testing.expectError(error.ZixDispatchModelUnsupported, runEpoll(session.echoHandler, config));

        return;
    }

    // On Linux the same call would never return, so what is checked here is the piece run() reaches
    // first: a worker that can actually take the socket.
    var listener = Listener.init(config) catch {
        std.log.info("the webrtc listener could not bind its test port, test skipped", .{});
        return;
    };
    defer listener.deinit();

    try std.testing.expectEqual(@as(usize, 0), listener.worker.peers.live);
    try std.testing.expectEqual(config.tick_interval_ms, listener.worker.waitMs(0));
}

test "zix webrtc: epoll, a worker carries one whole session over a real socket" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();

    var tls = try session.testContext(std.testing.allocator);
    const config = session.testConfig(io, std.testing.allocator, &tls, TEST_SERVER_PORT);

    var listener = Listener.init(config) catch {
        std.log.info("the webrtc listener could not bind its test port, test skipped", .{});
        return;
    };
    defer listener.deinit();

    var driver = session.Driver.init(io, TEST_SERVER_PORT, TEST_DIALER_PORT) catch {
        std.log.info("the webrtc test driver could not open its socket, test skipped", .{});
        return;
    };
    defer driver.deinit();

    // Every pass is one epoll_wait plus whatever it brought, so the session is driven a pass at a
    // time with the dialer answering in between.
    var rounds: usize = 0;
    while (rounds < session.MAX_ROUNDS and !driver.done()) : (rounds += 1) {
        try driver.send();

        listener.pass(session.echoHandler);

        try driver.receive();
    }

    try std.testing.expectEqualStrings(session.MESSAGE, driver.echo());
    try std.testing.expectEqual(@as(usize, 1), listener.worker.peers.live);
}

test "zix webrtc: epoll, a pass with nothing to read still returns and drops nobody" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try session.testContext(std.testing.allocator);
    var config = session.testConfig(threaded.io(), std.testing.allocator, &tls, TEST_SERVER_PORT);
    config.tick_interval_ms = 10;

    var listener = Listener.init(config) catch {
        std.log.info("the webrtc listener could not bind its test port, test skipped", .{});
        return;
    };
    defer listener.deinit();

    // Nobody has written to the socket, so this waits out the tick interval and comes back.
    listener.pass(session.echoHandler);

    try std.testing.expectEqual(@as(usize, 0), listener.worker.peers.live);
}
