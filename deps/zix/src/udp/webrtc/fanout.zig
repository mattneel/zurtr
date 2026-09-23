//! zix WebRTC fan-out: how a handler reaches the peers its worker holds besides the one it was
//! called for.
//!
//! What:
//! - One call, and the pointer to whatever answers it. The dispatch worker fills this in when it
//!   builds a handler's context, and the handler never sees what is behind it.
//!
//! Note:
//! - What a fan-out reaches is the peers of ONE worker. That is every peer under `.ASYNC`, which
//!   runs a single worker, and the share the kernel's REUSEPORT hash put on this core under
//!   `.EPOLL` and `.URING`. A room that has to span cores belongs on `.ASYNC`.
//! - Delivery counts rather than fails. A fan-out to a room where one peer has no channel open yet
//!   still reaches everybody else, so the count is what came back and there is no error to handle.
//! - Nothing here knows what a peer or a channel is. Keeping the call this narrow is what lets the
//!   application surface offer a broadcast without reaching into the peer table (core.zig cannot
//!   import it, the table is built out of connections that are built out of core.zig).

const std = @import("std");

const payload = @import("datachannel/payload.zig");

const IpAddress = std.Io.net.IpAddress;

/// Which of the two payload kinds a broadcast travels as (RFC 8831 6.6).
pub const Kind = payload.Kind;

/// What a worker offers a handler: take these bytes to everyone but `from`, and say how many took
/// them.
pub const DeliverFn = *const fn (
    worker: *anyopaque,
    from: IpAddress,
    now_ms: u64,
    kind: Kind,
    bytes: []const u8,
) usize;

/// The one call a handler's broadcast goes through, and the worker it goes to.
///
/// Usage:
/// ```zig
/// const sink: fanout.Sink = .{ .worker = @ptrCast(self), .deliver = deliverBroadcast };
///
/// _ = sink.broadcast(sender_address, now_ms, .STRING, "hello everyone");
/// ```
pub const Sink = struct {
    /// The worker behind the call, passed back to it untouched.
    worker: *anyopaque,
    deliver: DeliverFn,

    /// Take one message to every peer but the one it came from.
    ///
    /// Param:
    /// from - IpAddress (the peer that sent it, which is skipped)
    /// now_ms - u64 (monotonic milliseconds)
    /// kind - Kind
    /// bytes - []const u8 (copied by whatever queues them, so the caller's buffer may be reused)
    ///
    /// Return:
    /// - usize (how many peers took it)
    pub fn broadcast(self: Sink, from: IpAddress, now_ms: u64, kind: Kind, bytes: []const u8) usize {
        return self.deliver(self.worker, from, now_ms, kind, bytes);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_SENDER: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 5000 } };

/// What a worker does with a broadcast, stood in for so this file is testable on its own.
const TestWorker = struct {
    calls: usize = 0,
    last_from: ?IpAddress = null,
    last_kind: Kind = .STRING,
    last_bytes: []const u8 = &.{},
    reach: usize = 0,

    fn deliver(worker: *anyopaque, from: IpAddress, now_ms: u64, kind: Kind, bytes: []const u8) usize {
        _ = now_ms;

        const self: *TestWorker = @ptrCast(@alignCast(worker));

        self.calls += 1;
        self.last_from = from;
        self.last_kind = kind;
        self.last_bytes = bytes;

        return self.reach;
    }

    fn sink(self: *TestWorker) Sink {
        return .{ .worker = @ptrCast(self), .deliver = deliver };
    }
};

test "zix webrtc: fanout sink, a broadcast reaches the worker with everything it was given" {
    var worker: TestWorker = .{ .reach = 3 };

    const took = worker.sink().broadcast(TEST_SENDER, 4242, .BINARY, "payload");

    try std.testing.expectEqual(@as(usize, 3), took);
    try std.testing.expectEqual(@as(usize, 1), worker.calls);
    try std.testing.expect(worker.last_from.?.eql(&TEST_SENDER));
    try std.testing.expectEqual(Kind.BINARY, worker.last_kind);
    try std.testing.expectEqualStrings("payload", worker.last_bytes);
}

test "zix webrtc: fanout sink, a room with nobody else in it answers zero rather than failing" {
    var worker: TestWorker = .{ .reach = 0 };

    try std.testing.expectEqual(@as(usize, 0), worker.sink().broadcast(TEST_SENDER, 0, .STRING, "alone"));
    try std.testing.expectEqual(@as(usize, 1), worker.calls);
}
