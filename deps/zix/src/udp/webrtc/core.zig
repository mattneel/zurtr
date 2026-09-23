//! zix WebRTC application surface: what a handler is handed, and what it can answer with.
//!
//! What:
//! - The three types a handler ever sees: the event that woke it, the message that event may
//!   carry, and the context it replies through. Everything under this file is protocol.
//!
//! Note:
//! - `Context` reaches data channels and nothing else. A handler cannot touch the socket, the DTLS
//!   session, or the peer table, because none of those are reachable from here. That is deliberate:
//!   the layers below are driven by the engine loop in one order, and a handler reaching into the
//!   middle of them would break it.
//! - `broadcast` is the one call that leaves this peer, and it still only reaches channels. The
//!   worker owns the walk, so what a handler holds is one call, not the table (fanout.zig).
//! - A message payload is borrowed and valid for the length of the handler call. Anything worth
//!   keeping is copied.

const std = @import("std");

const datachannel = @import("datachannel/peer.zig");
const fanout = @import("fanout.zig");
const payload = @import("datachannel/payload.zig");

const IpAddress = std.Io.net.IpAddress;

/// Which of the two payload kinds a message travels as (RFC 8831 6.6).
pub const Kind = payload.Kind;

/// What to open a channel with, when the server opens one rather than answering.
pub const OpenRequest = datachannel.OpenRequest;

/// Everything a handler can be told to go wrong.
pub const Error = datachannel.Error;

/// One message that arrived on a data channel.
pub const Message = struct {
    /// The stream identifier the channel sits on, and what a reply is addressed to.
    channel: u16,
    kind: Kind,
    /// Borrowed. Valid for the length of the handler call.
    payload: []const u8,
};

/// Something the application has to know about.
pub const Event = union(enum) {
    /// A channel is usable, carrying its stream identifier.
    CHANNEL_OPEN: u16,
    /// A channel finished closing and its identifier is free again.
    CHANNEL_CLOSED: u16,
    MESSAGE: Message,
};

/// What a handler answers through.
///
/// Note:
/// - Built fresh for every handler call and never outlives it, so nothing here is worth keeping a
///   pointer to.
///
/// Usage:
/// ```zig
/// fn onEvent(event: zix.Webrtc.Event, ctx: *zix.Webrtc.Context) !void {
///     switch (event) {
///         .MESSAGE => |message| try ctx.send(message.channel, message.kind, message.payload),
///         else => {},
///     }
/// }
/// ```
pub const Context = struct {
    /// Borrowed from the connection this event came from.
    channels: *datachannel.Peer,
    /// Where the peer sits, so a handler can tell one from another.
    address: IpAddress,
    /// The engine's clock reading for this call, in monotonic milliseconds.
    now_ms: u64,
    /// How a broadcast reaches the worker's other peers. Null when there is no worker behind this
    /// context, which is a caller driving one connection on its own, and then a broadcast has
    /// nobody to reach and says so.
    fanout: ?fanout.Sink = null,

    /// Send a message on an open channel.
    ///
    /// Note:
    /// - The bytes are copied into the send queue, so the caller's buffer may be reused at once.
    /// - This queues. The packet leaves on the engine's next flush, which is the same loop pass.
    ///
    /// Param:
    /// stream_identifier - u16 (which channel)
    /// kind - Kind
    /// bytes - []const u8 (copied)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSuchChannel, error.ZixChannelClosed when the channel is not usable
    /// - error.ZixNotEstablished, error.ZixNoSpace, error.OutOfMemory
    pub fn send(self: *Context, stream_identifier: u16, kind: Kind, bytes: []const u8) Error!void {
        return self.channels.sendMessage(stream_identifier, kind, bytes, self.now_ms);
    }

    /// Send a message to every peer but this one.
    ///
    /// Note:
    /// - It goes on every open channel each of those peers has, and leaves on the same flush as a
    ///   reply to this peer would.
    /// - The reach is the peers of ONE worker: all of them under `.ASYNC`, and the share this core
    ///   was given under `.EPOLL` and `.URING`, where the kernel puts a peer on a worker by its
    ///   address. A room that has to be whole belongs on `.ASYNC`.
    /// - A peer that cannot take it is skipped rather than raised, so one full send queue never
    ///   costs everybody else the message. The count says how many took it.
    ///
    /// Param:
    /// kind - Kind
    /// bytes - []const u8 (copied)
    ///
    /// Return:
    /// - usize (how many peers took it, zero when this peer is alone)
    pub fn broadcast(self: *Context, kind: Kind, bytes: []const u8) usize {
        const sink = self.fanout orelse return 0;

        return sink.broadcast(self.address, self.now_ms, kind, bytes);
    }

    /// Open a channel from this side.
    ///
    /// Note:
    /// - The identifier comes back at once, and the channel is only usable once the peer answers,
    ///   which arrives as CHANNEL_OPEN.
    ///
    /// Param:
    /// request - OpenRequest
    ///
    /// Return:
    /// - u16 (the stream identifier the channel took)
    /// - error.ZixNoStreamAvailable, error.ZixTooManyChannels, error.ZixNotEstablished
    pub fn openChannel(self: *Context, request: OpenRequest) Error!u16 {
        return self.channels.openChannel(request, self.now_ms);
    }

    /// Start closing a channel.
    ///
    /// Note:
    /// - Takes two stream resets, one each way (RFC 8831 6.7), so the identifier is only free
    ///   again when CHANNEL_CLOSED arrives for it.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSuchChannel
    pub fn close(self: *Context, stream_identifier: u16) Error!void {
        return self.channels.closeChannel(stream_identifier);
    }

    /// How many channels this peer has.
    pub fn channelCount(self: *const Context) usize {
        return self.channels.count();
    }
};

/// The application event handler, baked into the server type at comptime.
pub const HandlerFn = *const fn (event: Event, ctx: *Context) anyerror!void;

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const association = @import("sctp/association.zig");

const TEST_ADDRESS: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9083 } };

/// One association plus the channels over it, which is the least a Context needs behind it.
const TestPeer = struct {
    sctp: association.Association,
    channels: datachannel.Peer,

    fn init(allocator: std.mem.Allocator) !*TestPeer {
        const peer = try allocator.create(TestPeer);

        peer.sctp = try association.Association.init(allocator, .{}, @splat(0x11), .{ .tag = 1, .initial_tsn = 1 });
        peer.channels = datachannel.Peer.init(allocator, &peer.sctp, .{ .role = .DTLS_SERVER });

        return peer;
    }

    fn deinit(self: *TestPeer, allocator: std.mem.Allocator) void {
        self.channels.deinit();
        self.sctp.deinit();
        allocator.destroy(self);
    }
};

test "zix webrtc: core context, a send before the association is up is refused" {
    const peer = try TestPeer.init(std.testing.allocator);
    defer peer.deinit(std.testing.allocator);

    var ctx: Context = .{ .channels = &peer.channels, .address = TEST_ADDRESS, .now_ms = 1000 };

    try std.testing.expectError(error.ZixNoSuchChannel, ctx.send(1, .STRING, "hello"));
    try std.testing.expectError(error.ZixNoSuchChannel, ctx.close(1));
    try std.testing.expectEqual(@as(usize, 0), ctx.channelCount());
}

test "zix webrtc: core context, opening a channel needs an established association" {
    const peer = try TestPeer.init(std.testing.allocator);
    defer peer.deinit(std.testing.allocator);

    var ctx: Context = .{ .channels = &peer.channels, .address = TEST_ADDRESS, .now_ms = 1000 };

    try std.testing.expectError(error.ZixNotEstablished, ctx.openChannel(.{ .label = "chat" }));
}

test "zix webrtc: core context, the address and clock are carried through untouched" {
    const peer = try TestPeer.init(std.testing.allocator);
    defer peer.deinit(std.testing.allocator);

    const ctx: Context = .{ .channels = &peer.channels, .address = TEST_ADDRESS, .now_ms = 4242 };

    try std.testing.expect(ctx.address.eql(&TEST_ADDRESS));
    try std.testing.expectEqual(@as(u64, 4242), ctx.now_ms);
}

test "zix webrtc: core context, a broadcast with no worker behind it reaches nobody" {
    const peer = try TestPeer.init(std.testing.allocator);
    defer peer.deinit(std.testing.allocator);

    // A caller driving one connection by hand has no other peers, so this answers zero rather than
    // needing a worker that is not there.
    var ctx: Context = .{ .channels = &peer.channels, .address = TEST_ADDRESS, .now_ms = 1000 };

    try std.testing.expectEqual(@as(usize, 0), ctx.broadcast(.STRING, "nobody home"));
}

test "zix webrtc: core context, a broadcast hands the worker this peer's address and clock" {
    const peer = try TestPeer.init(std.testing.allocator);
    defer peer.deinit(std.testing.allocator);

    const Reached = struct {
        var from: ?IpAddress = null;
        var at_ms: u64 = 0;
        var kind: Kind = .STRING;
        var bytes: []const u8 = &.{};

        fn deliver(_: *anyopaque, sender: IpAddress, now_ms: u64, sent: Kind, payload_bytes: []const u8) usize {
            from = sender;
            at_ms = now_ms;
            kind = sent;
            bytes = payload_bytes;

            return 2;
        }
    };

    var worker: usize = 0;
    var ctx: Context = .{
        .channels = &peer.channels,
        .address = TEST_ADDRESS,
        .now_ms = 7000,
        .fanout = .{ .worker = @ptrCast(&worker), .deliver = Reached.deliver },
    };

    try std.testing.expectEqual(@as(usize, 2), ctx.broadcast(.BINARY, "to the room"));
    try std.testing.expect(Reached.from.?.eql(&TEST_ADDRESS));
    try std.testing.expectEqual(@as(u64, 7000), Reached.at_ms);
    try std.testing.expectEqual(Kind.BINARY, Reached.kind);
    try std.testing.expectEqualStrings("to the room", Reached.bytes);
}

test "zix webrtc: core event, every variant carries what its name says" {
    const open: Event = .{ .CHANNEL_OPEN = 3 };
    const closed: Event = .{ .CHANNEL_CLOSED = 3 };
    const message: Event = .{ .MESSAGE = .{ .channel = 5, .kind = .BINARY, .payload = "bytes" } };

    try std.testing.expectEqual(@as(u16, 3), open.CHANNEL_OPEN);
    try std.testing.expectEqual(@as(u16, 3), closed.CHANNEL_CLOSED);
    try std.testing.expectEqual(@as(u16, 5), message.MESSAGE.channel);
    try std.testing.expectEqual(Kind.BINARY, message.MESSAGE.kind);
    try std.testing.expectEqualStrings("bytes", message.MESSAGE.payload);
}
