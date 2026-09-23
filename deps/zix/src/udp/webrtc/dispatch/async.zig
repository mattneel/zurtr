//! zix WebRTC ASYNC dispatch: the portable single-worker loop, on every target zix builds for.
//!
//! What:
//! - One socket, one thread, and one worker. Receive a datagram, give it to the peer it came from,
//!   send back whatever that produced, then look at the deadlines nobody's datagram answered.
//!
//! Note:
//! - The wait is bounded, and that is the whole reason this engine exists. A loop that parks in
//!   receive until the next datagram cannot retransmit a DTLS flight into silence, and a peer that
//!   lost the server's flight would wait forever for one that never comes again.
//! - Readiness first, then a plain receive. A timed std.Io receive races the receive against a
//!   timer, which needs the Io to run both, and the Windows backend answers
//!   error.ConcurrencyUnavailable for a socket receive submitted that way.

const std = @import("std");

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const common = @import("common.zig");
const core = @import("../core.zig");
const socket_poll = @import("../../../utils/socket_poll.zig");
const worker = @import("worker.zig");

/// Run the WebRTC server with a single worker on the calling thread.
///
/// Param:
/// handler - comptime core.HandlerFn
/// config - WebrtcServerConfig (already validated by the server)
///
/// Return:
/// - !void, blocking until the socket cannot be worked with
pub fn runAsync(comptime handler: core.HandlerFn, config: WebrtcServerConfig) !void {
    const io = config.io;

    const socket = try common.bindSocket(config);
    defer socket.close(io);

    var served = try worker.Worker.initSocket(config, socket);
    defer served.deinit();

    const recv_buf = try config.allocator.alloc(u8, config.max_recv_buf);
    defer config.allocator.free(recv_buf);

    const start = std.Io.Clock.Timestamp.now(io, .awake);

    common.logSystem(config, .INFO, "listening on {s}:{d} (single worker)", .{ config.ip, config.port });

    while (true) {
        const before_ms = common.elapsedMs(start, std.Io.Clock.Timestamp.now(io, .awake));
        const budget_ms = served.waitMs(before_ms);

        const ready = socket_poll.waitReady(socket.handle, socket_poll.READABLE, budget_ms) catch |err| {
            common.logSystem(config, .ERROR, "poll error: {s}", .{@errorName(err)});

            continue;
        };

        const now_ms = common.elapsedMs(start, std.Io.Clock.Timestamp.now(io, .awake));

        if (ready) receiveOne(handler, &served, socket, config, recv_buf, now_ms);

        // Deadlines are only worth walking when the wait ran out, or when one of them has actually
        // come due. Under steady traffic neither is true and the walk is skipped.
        if (!ready or served.sweepDue(now_ms)) served.sweep(handler, now_ms);

        served.flush();
    }
}

/// Take one datagram off the socket and give it to the peer it came from.
fn receiveOne(
    comptime handler: core.HandlerFn,
    served: *worker.Worker,
    socket: std.Io.net.Socket,
    config: WebrtcServerConfig,
    recv_buf: []u8,
    now_ms: u64,
) void {
    const message = socket.receive(config.io, recv_buf) catch |err| {
        common.logSystem(config, .ERROR, "receive error: {s}", .{@errorName(err)});

        return;
    };

    // A datagram the buffer could not hold is one no layer below can parse, and every layer here
    // is authenticated, so guessing at the missing bytes is not an option.
    if (message.flags.trunc) {
        common.logSystem(config, .WARN, "dropped a datagram larger than max_recv_buf ({d})", .{config.max_recv_buf});

        return;
    }

    served.serve(handler, message.from, message.data, now_ms);
}
