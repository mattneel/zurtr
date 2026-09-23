//! zix WebRTC data channels over one SCTP association (RFC 8831, RFC 8832).
//!
//! What:
//! - The driver: open a channel, carry messages both ways, close a channel, and answer the peer
//!   doing any of the same. Everything below it is codecs and tables, and this is the file that
//!   decides when each one runs.
//! - Driven entirely by the caller, like the association under it. Packets in, packets out, and
//!   a clock the caller owns. Nothing here touches a socket or a timer.
//!
//! Note:
//! - Which identifiers this endpoint may open on comes from the DTLS role, so the role has to be
//!   the one the handshake actually took. Guessing it opens every channel on identifiers the peer
//!   owns, and a correct peer refuses all of them (RFC 8832 6).
//! - A channel this endpoint opened is reported open when the peer's DATA_CHANNEL_ACK arrives. If
//!   the peer's first user message overtakes that acknowledgement, which an unordered channel
//!   allows, the message is delivered and the channel is open from then on, with the message
//!   itself as the notification.
//! - Closing a channel takes two stream resets, one each way (RFC 8831 6.7), so a close is not
//!   finished until the peer has reset its own outgoing stream too. The identifier is only free
//!   for reuse after that, which is why it is released when the close is reported and not when
//!   it is asked for.
//! - A close the peer refuses leaves the channel unusable and its identifier retired, because
//!   reusing an identifier whose sequence numbering was never reset attaches the next channel's
//!   messages to the old one. Asking again is the caller's call, and calling `closeChannel` a
//!   second time is what re-arms it.
//! - Anything malformed closes one channel, never the association. An unreadable
//!   DATA_CHANNEL_OPEN, a payload identifier this endpoint does not carry, and user data on a
//!   stream with no channel are all channel-level faults (RFC 8831 6.6, RFC 8832 6).

const std = @import("std");

const association = @import("../sctp/association.zig");
const channel = @import("channel.zig");
const dcep = @import("dcep.zig");
const payload = @import("payload.zig");
const reassembly = @import("../sctp/reassembly.zig");
const reconfig = @import("../sctp/reconfig.zig");
const registry = @import("registry.zig");
const reset = @import("reset.zig");
const stream_id = @import("stream_id.zig");

/// Largest DATA_CHANNEL_OPEN this endpoint builds, which caps the label and protocol it can send.
pub const MAX_OPEN_BYTES: usize = 512;

/// Setup for the channels on one association.
pub const Config = struct {
    /// Which side of the DTLS handshake this endpoint was, which decides the identifiers it
    /// opens on (RFC 8832 6).
    role: stream_id.Role,
    limits: registry.Limits = .{},
};

/// Everything that can go wrong driving data channels.
pub const Error = error{
    OutOfMemory,
    /// A buffer handed in, or one in here, is too small for what had to go in it.
    ZixNoSpace,
    /// A parameter region that ends mid-parameter.
    ZixTruncated,
    /// A parameter length below the parameter header size.
    ZixBadLength,
    /// The association is not up.
    ZixNotEstablished,
    /// The peer did something the protocol does not allow.
    ZixProtocolViolation,
    /// A message grew past the reassembly limit.
    ZixMessageTooLarge,
    /// SCTP cannot carry a chunk with no payload.
    ZixNoUserData,
    /// No channel on that stream identifier.
    ZixNoSuchChannel,
    /// The channel is closing or already closed.
    ZixChannelClosed,
    /// Every identifier this endpoint owns is taken.
    ZixNoStreamAvailable,
    /// The channel table is at its ceiling.
    ZixTooManyChannels,
    /// A channel already sits on that identifier.
    ZixStreamInUse,
    /// A label or protocol longer than this endpoint accepts.
    ZixFieldTooLong,
    /// The identifier belongs to the other side, or is outside what the association negotiated.
    ZixBadStreamIdentifier,
    /// A retransmission limit and a lifetime were both asked for.
    ZixConflictingReliability,
    /// A channel type outside the six RFC 8832 5.1 defines.
    ZixUnknownChannelType,
    /// A DCEP message type this endpoint does not implement.
    ZixUnknownMessageType,
};

/// What to open a channel with.
pub const OpenRequest = struct {
    options: channel.Options = .{},
    priority: u16 = @intFromEnum(dcep.Priority.NORMAL),
    /// Names the channel for the application, and may be empty.
    label: []const u8 = "",
    /// A subprotocol name, empty when unspecified.
    protocol: []const u8 = "",
};

/// One message that arrived on a channel.
pub const Incoming = struct {
    stream_identifier: u16,
    kind: payload.Kind,
    /// Borrowed. Valid until the next call on this peer.
    payload: []const u8,
};

/// Something the application has to know about.
pub const Event = union(enum) {
    /// A channel is usable, carrying its stream identifier.
    CHANNEL_OPEN: u16,
    /// A channel finished closing and its identifier is free again.
    CHANNEL_CLOSED: u16,
    MESSAGE: Incoming,
};

/// The data channels on one association.
///
/// Usage:
/// ```zig
/// var peer = Peer.init(allocator, &sctp_association, .{ .role = .DTLS_SERVER });
/// defer peer.deinit();
///
/// var out: [1200]u8 = undefined;
/// _ = try peer.handle(datagram, now_ms, &out);
///
/// while (try peer.nextEvent(now_ms)) |event| switch (event) {
///     .MESSAGE => |message| handle(message),
///     else => {},
/// };
///
/// while (try peer.nextOutbound(now_ms, &out)) |packet| try dtls.write(packet);
/// ```
pub const Peer = struct {
    /// Borrowed, and must outlive this peer.
    association: *association.Association,
    channels: registry.Registry,
    resets: reset.Driver,
    /// Whether the reset driver has been given the numbers only the handshake knows.
    started: bool,

    /// Build the channel layer over an association.
    ///
    /// Note:
    /// - The association does not have to be up yet. The numbers a stream reset needs are picked
    ///   up on the first call after the handshake finishes.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, channels free their label as they close)
    /// sctp - *association.Association (borrowed, must outlive this peer)
    /// config - Config
    ///
    /// Return:
    /// - Peer
    pub fn init(allocator: std.mem.Allocator, sctp: *association.Association, config: Config) Peer {
        return .{
            .association = sctp,
            .channels = registry.Registry.init(allocator, config.role, config.limits),
            .resets = reset.Driver.init(0, 0),
            .started = false,
        };
    }

    /// Free every channel still held.
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *Peer) void {
        self.channels.deinit();
    }

    /// How many channels exist, in any state.
    ///
    /// Return:
    /// - usize
    pub fn count(self: Peer) usize {
        return self.channels.count();
    }

    /// The channel on a stream identifier.
    ///
    /// Note:
    /// - The pointer is valid until the next call that opens or closes a channel.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - ?*channel.Channel
    pub fn find(self: *Peer, stream_identifier: u16) ?*channel.Channel {
        return self.channels.find(stream_identifier);
    }

    /// The channel at a position, for walking every channel this peer has.
    ///
    /// Note:
    /// - Positions shift as channels open and close, so this is for one walk and not for holding
    ///   on to. `count()` bounds it, and the pointer lasts until the next open or close.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?*channel.Channel, null past the last one
    pub fn at(self: *Peer, index: usize) ?*channel.Channel {
        return self.channels.at(index);
    }

    /// Open a channel and send the DATA_CHANNEL_OPEN that announces it.
    ///
    /// Note:
    /// - Messages may be sent on the channel at once, without waiting for the acknowledgement
    ///   (RFC 8832 6). They go out ordered until the peer is heard from.
    ///
    /// Param:
    /// request - OpenRequest
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - u16, the stream identifier the channel took
    /// - error.ZixNotEstablished if the association is not up
    /// - error.ZixNoStreamAvailable, error.ZixTooManyChannels, error.ZixFieldTooLong
    /// - error.ZixConflictingReliability if a retransmission limit and a lifetime were both asked for
    /// - error.ZixNoSpace if the label and protocol do not fit MAX_OPEN_BYTES
    /// - error.OutOfMemory
    pub fn openChannel(self: *Peer, request: OpenRequest, now_ms: u64) Error!u16 {
        if (self.association.state != .ESTABLISHED) return error.ZixNotEstablished;

        self.ensureStarted();

        const streams = self.negotiatedStreams();
        const identifier = self.channels.availableIdentifier(streams) orelse return error.ZixNoStreamAvailable;

        const open: dcep.Open = .{
            .channel_type = try channel.channelTypeFor(request.options),
            .priority = request.priority,
            .reliability_parameter = channel.reliabilityParameterFor(request.options),
            .label = request.label,
            .protocol = request.protocol,
        };

        var body: [MAX_OPEN_BYTES]u8 = undefined;
        const message = try dcep.writeOpen(&body, open);

        _ = try self.channels.add(.{
            .stream_identifier = identifier,
            .options = request.options,
            .priority = request.priority,
            .label = request.label,
            .protocol = request.protocol,
            .opener = true,
        }, streams);
        errdefer _ = self.channels.remove(identifier);

        try self.sendControl(identifier, message, now_ms);

        return identifier;
    }

    /// Hand a message to a channel.
    ///
    /// Note:
    /// - An empty message is legal and goes out as the one zero byte RFC 8831 6.6 defines, so a
    ///   caller never has to pad it.
    ///
    /// Param:
    /// stream_identifier - u16
    /// kind - payload.Kind (which of the two empty identifiers an empty message takes)
    /// bytes - []const u8 (copied, so the caller's buffer may be reused)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSuchChannel, error.ZixChannelClosed
    /// - error.ZixNotEstablished, error.ZixNoSpace, error.OutOfMemory
    pub fn sendMessage(
        self: *Peer,
        stream_identifier: u16,
        kind: payload.Kind,
        bytes: []const u8,
        now_ms: u64,
    ) Error!void {
        const found = self.channels.find(stream_identifier) orelse return error.ZixNoSuchChannel;

        if (!found.isSendable()) return error.ZixChannelClosed;

        const identifier = payload.identifierFor(kind, bytes.len);

        try self.association.sendMessage(stream_identifier, payload.payloadFor(bytes), .{
            .payload_protocol = @intFromEnum(identifier),
            .unordered = !found.sendOrdered(),
            .reliability = found.reliability(now_ms),
        }, now_ms);
    }

    /// Start closing a channel.
    ///
    /// Note:
    /// - The reset that carries it goes out on a later `nextOutbound`, and the close is only
    ///   finished once the peer has reset its own stream too. Calling this again on a channel
    ///   whose reset was refused asks for it once more.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSuchChannel
    pub fn closeChannel(self: *Peer, stream_identifier: u16) Error!void {
        const found = self.channels.find(stream_identifier) orelse return error.ZixNoSuchChannel;

        found.requestClose();
    }

    /// Handle one SCTP packet.
    ///
    /// Note:
    /// - Every packet has to come through here rather than through the association directly, or
    ///   a stream reset arrives with nothing to act on it.
    ///
    /// Param:
    /// datagram - []const u8 (payload of one DTLS record)
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8 (at least association.MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - association.Outcome, whose reply borrows `out`
    /// - error.ZixProtocolViolation, error.ZixMessageTooLarge, error.ZixNoSpace, error.OutOfMemory
    pub fn handle(self: *Peer, datagram: []const u8, now_ms: u64, out: []u8) Error!association.Outcome {
        const outcome = try self.association.handle(datagram, now_ms, out);

        self.ensureStarted();

        if (outcome.reconfig) |value| self.onReconfig(value);

        try self.releaseHeldReset();

        return outcome;
    }

    /// The next thing the application has to know about.
    ///
    /// Note:
    /// - Call in a loop until it returns null. A message payload is valid until the next call,
    ///   so anything worth keeping is copied before asking for the next event.
    /// - Acknowledgements for channels the peer opened are queued from here, so a caller that
    ///   never drains events never completes a handshake it was offered.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?Event
    /// - error.ZixProtocolViolation, error.ZixMessageTooLarge, error.ZixNoSpace, error.OutOfMemory
    pub fn nextEvent(self: *Peer, now_ms: u64) Error!?Event {
        // Messages first. A stream reset waits for everything sent before it (RFC 6525 5.2.2),
        // so reporting the close ahead of them would lose the last message on the channel.
        while (try self.association.nextMessage()) |message| {
            if (try self.onMessage(message, now_ms)) |event| return event;
        }

        if (self.channels.takeClosed()) |identifier| return .{ .CHANNEL_CLOSED = identifier };

        return null;
    }

    /// The next packet to send.
    ///
    /// Note:
    /// - Stream resets go before data, because a peer waiting on an answer to a reset is a peer
    ///   that cannot start another one.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8 (the path maximum)
    ///
    /// Return:
    /// - ?[]const u8, a packet to send, borrowing `out`
    /// - error.ZixNoSpace
    pub fn nextOutbound(self: *Peer, now_ms: u64, out: []u8) Error!?[]const u8 {
        self.ensureStarted();

        try self.armPendingResets();

        if (self.resets.nextPending()) |value| return try self.association.sendReconfig(value, out);

        return try self.association.flush(now_ms, out);
    }

    /// Resend the outstanding stream reset, for the timer RFC 6525 5.1.1 asks for.
    ///
    /// Param:
    /// out - []u8 (at least association.MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - ?[]const u8, null when no reset is outstanding
    /// - error.ZixNoSpace, error.ZixNotEstablished, error.ZixProtocolViolation
    pub fn retransmitReset(self: *Peer, out: []u8) Error!?[]const u8 {
        const value = self.resets.retransmit() orelse return null;

        return try self.association.sendReconfig(value, out);
    }

    /// Give the reset driver the numbers only a finished handshake knows.
    fn ensureStarted(self: *Peer) void {
        if (self.started) return;
        if (self.association.state != .ESTABLISHED) return;

        self.resets = reset.Driver.init(self.association.local.initial_tsn, self.association.peerInitialTsn());
        self.started = true;
    }

    /// Streams a channel can sit on, which needs both directions to exist.
    fn negotiatedStreams(self: Peer) u16 {
        return @min(self.association.outbound_streams, self.association.inbound_streams);
    }

    /// One message the association finished reassembling.
    fn onMessage(self: *Peer, message: reassembly.Message, now_ms: u64) Error!?Event {
        if (payload.isControl(message.payload_protocol)) return try self.onControl(message, now_ms);

        const found = self.channels.find(message.stream_identifier) orelse {
            // User data on a stream with no channel behind it (RFC 8832 6). Nothing here can be
            // delivered, and the stream is reset so the identifier can be used again.
            try self.refuseStream(message.stream_identifier);

            return null;
        };

        const incoming = payload.read(message.payload_protocol, message.payload) catch {
            found.requestClose();

            return null;
        };

        found.noteHeardFromPeer();

        return .{ .MESSAGE = .{
            .stream_identifier = message.stream_identifier,
            .kind = incoming.kind,
            .payload = incoming.payload,
        } };
    }

    /// One DCEP message.
    fn onControl(self: *Peer, message: reassembly.Message, now_ms: u64) Error!?Event {
        const kind = dcep.messageType(message.payload) catch return null;

        return switch (kind) {
            .OPEN => try self.onOpen(message, now_ms),
            .ACK => self.onAck(message.stream_identifier),
            // A DCEP message type this endpoint does not know cannot be answered sensibly, and
            // the channel it names is the only thing at stake.
            else => null,
        };
    }

    /// A DATA_CHANNEL_OPEN, which is the peer offering a channel.
    fn onOpen(self: *Peer, message: reassembly.Message, now_ms: u64) Error!?Event {
        const request = dcep.readOpen(message.payload) catch {
            try self.refuseStream(message.stream_identifier);

            return null;
        };

        const options = channel.optionsFor(request.channel_type, request.reliability_parameter) catch {
            try self.refuseStream(message.stream_identifier);

            return null;
        };

        _ = self.channels.add(.{
            .stream_identifier = message.stream_identifier,
            .options = options,
            .priority = request.priority,
            .label = request.label,
            .protocol = request.protocol,
            .opener = false,
        }, self.negotiatedStreams()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Everything else is the peer offering something this endpoint will not take: an
            // identifier it does not own, one already in use, a label past the ceiling, or one
            // channel too many. All of them close the channel and send no acknowledgement
            // (RFC 8832 6).
            else => {
                try self.refuseStream(message.stream_identifier);

                return null;
            },
        };

        var body: [dcep.ACK_LEN]u8 = undefined;
        const ack = try dcep.writeAck(&body);

        self.sendControl(message.stream_identifier, ack, now_ms) catch |err| {
            _ = self.channels.remove(message.stream_identifier);

            return err;
        };

        return .{ .CHANNEL_OPEN = message.stream_identifier };
    }

    /// A DATA_CHANNEL_ACK, which is the peer taking a channel this endpoint offered.
    fn onAck(self: *Peer, stream_identifier: u16) ?Event {
        const found = self.channels.find(stream_identifier) orelse return null;

        // An acknowledgement for a channel already up says nothing new, and reporting it twice
        // would have the application open the same channel twice.
        if (found.state != .CONNECTING) return null;

        found.noteHeardFromPeer();

        return .{ .CHANNEL_OPEN = stream_identifier };
    }

    /// A RE-CONFIG chunk arrived.
    fn onReconfig(self: *Peer, value: []const u8) void {
        // A malformed chunk is dropped rather than answered. There is no sequence number to be
        // sure of in it, so any answer would be a guess at what it asked for.
        const handled = self.resets.handleValue(value, self.association.cumulativeTsn()) catch return;

        if (handled.peer_reset) |request| self.applyPeerReset(request);
        if (handled.completed) |done| self.applyCompletedReset(done);
    }

    /// The peer reset its outgoing streams, so the channels on them are half closed.
    fn applyPeerReset(self: *Peer, request: reconfig.OutgoingReset) void {
        var index: usize = 0;
        while (self.channels.at(index)) |item| : (index += 1) {
            if (!request.covers(item.stream_identifier)) continue;

            item.noteIncomingReset();
        }
    }

    /// The peer answered a reset this endpoint asked for.
    fn applyCompletedReset(self: *Peer, done: reset.Completed) void {
        const found = self.channels.find(done.stream_identifier) orelse return;

        if (!done.isSuccess()) return;

        self.association.resetOutboundStream(done.stream_identifier);
        found.noteOutgoingReset();
    }

    /// A held reset may now be performable.
    fn releaseHeldReset(self: *Peer) Error!void {
        const release = (try self.resets.releaseDeferred(self.association.cumulativeTsn())) orelse return;

        if (release.all) {
            var index: usize = 0;
            while (self.channels.at(index)) |item| : (index += 1) item.noteIncomingReset();

            return;
        }

        for (0..release.count) |index| {
            const found = self.channels.find(release.streams[index]) orelse continue;

            found.noteIncomingReset();
        }
    }

    /// Ask for the reset that closes the next channel waiting on one.
    fn armPendingResets(self: *Peer) Error!void {
        if (!self.association.supportsReconfig()) return;
        if (self.resets.isBusy()) return;

        var index: usize = 0;
        while (self.channels.at(index)) |item| : (index += 1) {
            if (item.state != .CLOSING) continue;
            if (item.reset_requested) continue;
            if (item.outgoing_reset_done) continue;

            // One request at a time (RFC 6525 5.1.1), so the rest wait for a later turn.
            if (try self.resets.requestReset(item.stream_identifier, self.association.lastAssignedTsn())) {
                item.reset_requested = true;
            }

            return;
        }
    }

    /// Close a stream this endpoint will not take what arrived on.
    fn refuseStream(self: *Peer, stream_identifier: u16) Error!void {
        // An offer landing on a stream that already has a channel closes that channel, which is
        // what RFC 8832 6 asks for and what stops the peer's next message being taken as part
        // of it.
        if (self.channels.find(stream_identifier)) |found| {
            found.requestClose();

            return;
        }

        if (!self.association.supportsReconfig()) return;

        // Only if nothing else is outstanding. A refusal that has to wait is dropped rather than
        // queued, and the peer asking again is what brings it back.
        _ = try self.resets.requestReset(stream_identifier, self.association.lastAssignedTsn());
    }

    /// Send a DCEP message, which is always ordered and fully reliable (RFC 8832 6).
    fn sendControl(self: *Peer, stream_identifier: u16, message: []const u8, now_ms: u64) Error!void {
        try self.association.sendMessage(stream_identifier, message, .{
            .payload_protocol = @intFromEnum(payload.Identifier.DCEP),
            .unordered = false,
        }, now_ms);
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const cookie = @import("../sctp/cookie.zig");

const test_secret: [cookie.SECRET_LEN]u8 = @splat(0x22);

const client_identity: association.Identity = .{ .tag = 0x11112222, .initial_tsn = 1_000 };
const server_identity: association.Identity = .{ .tag = 0x33334444, .initial_tsn = 5_000 };

const NOW: u64 = 1_000;

/// Two peers wired to each other in memory, with no DTLS and no socket.
const Fixture = struct {
    client_association: association.Association,
    server_association: association.Association,
    client: Peer,
    server: Peer,

    fn setUp(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.client_association = try association.Association.init(allocator, .{}, test_secret, client_identity);
        self.server_association = try association.Association.init(allocator, .{}, test_secret, server_identity);
        self.client = Peer.init(allocator, &self.client_association, .{ .role = .DTLS_CLIENT });
        self.server = Peer.init(allocator, &self.server_association, .{ .role = .DTLS_SERVER });
    }

    fn tearDown(self: *Fixture) void {
        self.client.deinit();
        self.server.deinit();
        self.client_association.deinit();
        self.server_association.deinit();
    }

    /// Run the SCTP handshake through both peers.
    fn connect(self: *Fixture) !void {
        var client_out: [association.MAX_REPLY_BYTES]u8 = undefined;
        var server_out: [association.MAX_REPLY_BYTES]u8 = undefined;

        const init_packet = try self.client_association.connect(&client_out);
        const init_ack = (try self.server.handle(init_packet, NOW, &server_out)).reply.?;
        const cookie_echo = (try self.client.handle(init_ack, NOW, &client_out)).reply.?;
        const cookie_ack = (try self.server.handle(cookie_echo, NOW, &server_out)).reply.?;

        _ = try self.client.handle(cookie_ack, NOW, &client_out);
    }

    /// Move everything both sides have queued until neither has anything left.
    fn pump(self: *Fixture) !void {
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            const forward = try step(&self.client, &self.server);
            const backward = try step(&self.server, &self.client);

            if (!forward and !backward) return;
        }
    }

    /// Drain one side's events, sending nothing back.
    fn drain(peer: *Peer) !void {
        while (try peer.nextEvent(NOW)) |_| {}
    }

    /// Move one packet from one side to the other, and any immediate answer back.
    fn step(from: *Peer, to: *Peer) !bool {
        var outbound: [2048]u8 = undefined;
        const datagram = (try from.nextOutbound(NOW, &outbound)) orelse return false;

        var answer: [2048]u8 = undefined;
        const outcome = try to.handle(datagram, NOW, &answer);

        if (outcome.reply) |reply| {
            var back: [2048]u8 = undefined;
            _ = try from.handle(reply, NOW, &back);
        }

        return true;
    }
};

/// Open one channel from the client and bring it all the way up on both sides.
fn openOne(fixture: *Fixture, request: OpenRequest) !u16 {
    const identifier = try fixture.client.openChannel(request, NOW);

    try fixture.pump();
    try Fixture.drain(&fixture.server);
    try fixture.pump();
    try Fixture.drain(&fixture.client);

    return identifier;
}

/// Take the next message event off a peer, failing if the next event is something else.
fn expectMessage(peer: *Peer) !Incoming {
    const event = (try peer.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    return switch (event) {
        .MESSAGE => |message| message,
        else => error.TestUnexpectedResult,
    };
}

test "zix datachannel: peer openChannel, the client takes the first even identifier" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try std.testing.expectEqual(@as(u16, 0), try fixture.client.openChannel(.{ .label = "chat" }, NOW));
    try std.testing.expectEqual(@as(u16, 2), try fixture.client.openChannel(.{ .label = "files" }, NOW));
}

test "zix datachannel: peer openChannel, the server takes the first odd identifier" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try std.testing.expectEqual(@as(u16, 1), try fixture.server.openChannel(.{ .label = "chat" }, NOW));
}

test "zix datachannel: peer at, a walk visits every channel and stops at the end" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    _ = try openOne(&fixture, .{ .label = "chat" });
    _ = try openOne(&fixture, .{ .label = "files" });

    // What a fan-out needs: the identifiers of every channel a peer has, without knowing any of
    // them in advance.
    var seen: [2]u16 = undefined;
    var found: usize = 0;

    while (fixture.client.at(found)) |open| : (found += 1) {
        if (found == seen.len) break;

        seen[found] = open.stream_identifier;
    }

    try std.testing.expectEqual(@as(usize, 2), found);
    try std.testing.expectEqual(fixture.client.count(), found);
    try std.testing.expectEqual(@as(u16, 0), seen[0]);
    try std.testing.expectEqual(@as(u16, 2), seen[1]);
    try std.testing.expectEqual(@as(?*channel.Channel, null), fixture.client.at(found));
}

test "zix datachannel: peer openChannel, an association that is not up refuses" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try std.testing.expectError(error.ZixNotEstablished, fixture.client.openChannel(.{}, NOW));
}

test "zix datachannel: peer openChannel, a limit and a lifetime together are refused" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try std.testing.expectError(error.ZixConflictingReliability, fixture.client.openChannel(.{
        .options = .{ .max_retransmits = 2, .max_lifetime_ms = 500 },
    }, NOW));
}

test "zix datachannel: peer openChannel, the offer reaches the peer and both sides report it open" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try fixture.client.openChannel(.{ .label = "chat", .protocol = "zix" }, NOW);
    try fixture.pump();

    const offered = (try fixture.server.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(Event{ .CHANNEL_OPEN = identifier }, offered);

    const accepted = fixture.server.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("chat", accepted.label);
    try std.testing.expectEqualStrings("zix", accepted.protocol);
    try std.testing.expect(!accepted.opener);

    try fixture.pump();

    const acknowledged = (try fixture.client.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(Event{ .CHANNEL_OPEN = identifier }, acknowledged);

    const opened = fixture.client.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(channel.State.OPEN, opened.state);
}

test "zix datachannel: peer openChannel, the properties survive the offer" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{
        .options = .{ .ordered = false, .max_retransmits = 3 },
        .priority = @intFromEnum(dcep.Priority.HIGH),
        .label = "lossy",
    });

    const accepted = fixture.server.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expect(!accepted.options.ordered);
    try std.testing.expectEqual(@as(?u16, 3), accepted.options.max_retransmits);
    try std.testing.expectEqual(@as(u16, 512), accepted.priority);
}

test "zix datachannel: peer sendMessage, a string arrives as the same string" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{ .label = "chat" });

    try fixture.client.sendMessage(identifier, .STRING, "hello", NOW);
    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqual(identifier, message.stream_identifier);
    try std.testing.expectEqual(payload.Kind.STRING, message.kind);
    try std.testing.expectEqualStrings("hello", message.payload);
}

test "zix datachannel: peer sendMessage, binary keeps its kind" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.client.sendMessage(identifier, .BINARY, &.{ 0x00, 0xFF, 0x10 }, NOW);
    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqual(payload.Kind.BINARY, message.kind);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xFF, 0x10 }, message.payload);
}

test "zix datachannel: peer sendMessage, an empty message arrives empty" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.client.sendMessage(identifier, .STRING, "", NOW);
    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqual(payload.Kind.STRING, message.kind);
    try std.testing.expectEqual(@as(usize, 0), message.payload.len);
}

test "zix datachannel: peer sendMessage, a message larger than one packet is rebuilt whole" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    var large: [4_000]u8 = undefined;
    for (&large, 0..) |*byte, index| byte.* = @truncate(index);

    try fixture.client.sendMessage(identifier, .BINARY, &large, NOW);
    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqualSlices(u8, &large, message.payload);
}

test "zix datachannel: peer sendMessage, a message echoes back over the same channel" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{ .label = "echo" });

    try fixture.client.sendMessage(identifier, .STRING, "ping", NOW);
    try fixture.pump();

    const arrived = try expectMessage(&fixture.server);
    try fixture.server.sendMessage(arrived.stream_identifier, arrived.kind, arrived.payload, NOW);
    try fixture.pump();

    const echoed = try expectMessage(&fixture.client);

    try std.testing.expectEqualStrings("ping", echoed.payload);
}

test "zix datachannel: peer sendMessage, an unknown channel is refused" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try std.testing.expectError(error.ZixNoSuchChannel, fixture.client.sendMessage(4, .STRING, "x", NOW));
}

test "zix datachannel: peer sendMessage, a closing channel takes nothing more" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});
    try fixture.client.closeChannel(identifier);

    try std.testing.expectError(
        error.ZixChannelClosed,
        fixture.client.sendMessage(identifier, .STRING, "x", NOW),
    );
}

test "zix datachannel: peer closeChannel, both sides end up closed and free the identifier" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{ .label = "chat" });

    try fixture.client.closeChannel(identifier);
    try fixture.pump();

    const client_event = (try fixture.client.nextEvent(NOW)) orelse return error.TestUnexpectedResult;
    const server_event = (try fixture.server.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(Event{ .CHANNEL_CLOSED = identifier }, client_event);
    try std.testing.expectEqual(Event{ .CHANNEL_CLOSED = identifier }, server_event);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.count());
    try std.testing.expectEqual(@as(usize, 0), fixture.server.count());
}

test "zix datachannel: peer closeChannel, the identifier is reused once the close is reported" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.client.closeChannel(identifier);
    try fixture.pump();
    try Fixture.drain(&fixture.client);

    try std.testing.expectEqual(identifier, try fixture.client.openChannel(.{}, NOW));
}

test "zix datachannel: peer closeChannel, the outgoing sequence numbering goes back to zero" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.client.sendMessage(identifier, .STRING, "one", NOW);
    try fixture.pump();
    try Fixture.drain(&fixture.server);

    try std.testing.expect(fixture.client_association.next_sequence[identifier] > 0);

    try fixture.client.closeChannel(identifier);
    try fixture.pump();

    try std.testing.expectEqual(@as(u16, 0), fixture.client_association.next_sequence[identifier]);
}

test "zix datachannel: peer closeChannel, an unknown channel is refused" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try std.testing.expectError(error.ZixNoSuchChannel, fixture.client.closeChannel(6));
}

test "zix datachannel: peer closeChannel, the peer closing it reaches the same place" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.server.closeChannel(identifier);
    try fixture.pump();

    const client_event = (try fixture.client.nextEvent(NOW)) orelse return error.TestUnexpectedResult;
    const server_event = (try fixture.server.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(Event{ .CHANNEL_CLOSED = identifier }, client_event);
    try std.testing.expectEqual(Event{ .CHANNEL_CLOSED = identifier }, server_event);
    try std.testing.expectEqual(@as(usize, 0), fixture.server.count());
}

test "zix datachannel: peer closeChannel, a message still in flight is delivered before the close" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{ .label = "chat" });

    // The message and the reset are asked for together, and the reset is what goes out first,
    // so the peer has to hold it until the message it is ahead of arrives.
    try fixture.client.sendMessage(identifier, .STRING, "last", NOW);
    try fixture.client.closeChannel(identifier);
    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqualStrings("last", message.payload);

    // The order is the whole point: the close is only reported once nothing is left in front
    // of it.
    const closed = (try fixture.server.nextEvent(NOW)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(Event{ .CHANNEL_CLOSED = identifier }, closed);

    try Fixture.drain(&fixture.client);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.count());
}

test "zix datachannel: peer closeChannel, a reset ahead of its data is held until the data lands" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    try fixture.client.sendMessage(identifier, .STRING, "last", NOW);
    try fixture.client.closeChannel(identifier);

    // The reset goes out before the data it is ahead of, because a RE-CONFIG carries no TSN.
    var wire: [2048]u8 = undefined;
    const reset_packet = (try fixture.client.nextOutbound(NOW, &wire)) orelse return error.TestUnexpectedResult;

    var reply: [2048]u8 = undefined;
    _ = try fixture.server.handle(reset_packet, NOW, &reply);

    const held = fixture.server.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(channel.State.OPEN, held.state);

    try fixture.pump();

    const message = try expectMessage(&fixture.server);

    try std.testing.expectEqualStrings("last", message.payload);
}

test "zix datachannel: peer, a channel the peer opens on the wrong half is refused" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    // Identifier 1 belongs to the server, so an offer from the client on it is not one the
    // server may take (RFC 8832 6).
    var body: [MAX_OPEN_BYTES]u8 = undefined;
    const offer = try dcep.writeOpen(&body, .{
        .channel_type = .RELIABLE,
        .priority = 256,
        .reliability_parameter = 0,
        .label = "wrong",
        .protocol = "",
    });

    try fixture.client_association.sendMessage(1, offer, .{
        .payload_protocol = @intFromEnum(payload.Identifier.DCEP),
    }, NOW);
    try fixture.pump();

    try std.testing.expect((try fixture.server.nextEvent(NOW)) == null);
    try std.testing.expectEqual(@as(usize, 0), fixture.server.count());
}

test "zix datachannel: peer, user data on a stream with no channel is not delivered" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    try fixture.client_association.sendMessage(0, "stray", .{
        .payload_protocol = @intFromEnum(payload.Identifier.STRING),
    }, NOW);
    try fixture.pump();

    try std.testing.expect((try fixture.server.nextEvent(NOW)) == null);
}

test "zix datachannel: peer, a payload identifier this endpoint does not carry closes the channel" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});

    // 52 is the deprecated binary partial identifier, which RFC 8831 6.6 says to close on.
    try fixture.client_association.sendMessage(identifier, "x", .{ .payload_protocol = 52 }, NOW);
    try fixture.pump();

    try std.testing.expect((try fixture.server.nextEvent(NOW)) == null);

    const found = fixture.server.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expect(!found.isSendable());
}

test "zix datachannel: peer, an unreadable offer is not acknowledged" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    // A DATA_CHANNEL_OPEN whose label length runs past the message.
    var body: [dcep.OPEN_FIXED_LEN]u8 = .{
        0x03, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x00,
    };

    try fixture.client_association.sendMessage(0, &body, .{
        .payload_protocol = @intFromEnum(payload.Identifier.DCEP),
    }, NOW);
    try fixture.pump();

    try std.testing.expect((try fixture.server.nextEvent(NOW)) == null);
    try std.testing.expectEqual(@as(usize, 0), fixture.server.count());
}

test "zix datachannel: peer, the same identifier offered twice is refused the second time" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{ .label = "first" });

    var body: [MAX_OPEN_BYTES]u8 = undefined;
    const offer = try dcep.writeOpen(&body, .{
        .channel_type = .RELIABLE,
        .priority = 256,
        .reliability_parameter = 0,
        .label = "second",
        .protocol = "",
    });

    try fixture.client_association.sendMessage(identifier, offer, .{
        .payload_protocol = @intFromEnum(payload.Identifier.DCEP),
    }, NOW);
    try fixture.pump();

    try std.testing.expect((try fixture.server.nextEvent(NOW)) == null);

    const found = fixture.server.find(identifier) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("first", found.label);
}

test "zix datachannel: peer, the channel ceiling is what stops a peer opening without end" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    fixture.server.channels.limits.max_channels = 1;

    try fixture.connect();

    _ = try openOne(&fixture, .{ .label = "first" });
    _ = try fixture.client.openChannel(.{ .label = "second" }, NOW);

    try fixture.pump();
    try Fixture.drain(&fixture.server);

    try std.testing.expectEqual(@as(usize, 1), fixture.server.count());
}

test "zix datachannel: peer retransmitReset, nothing outstanding sends nothing" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    var out: [association.MAX_REPLY_BYTES]u8 = undefined;

    try std.testing.expect((try fixture.client.retransmitReset(&out)) == null);
}

test "zix datachannel: peer retransmitReset, an outstanding reset can be sent again" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const identifier = try openOne(&fixture, .{});
    try fixture.client.closeChannel(identifier);

    var out: [2048]u8 = undefined;
    _ = try fixture.client.nextOutbound(NOW, &out);

    try std.testing.expect((try fixture.client.retransmitReset(&out)) != null);
}

test "zix datachannel: peer, two channels carry their own messages" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const chat = try openOne(&fixture, .{ .label = "chat" });
    const files = try openOne(&fixture, .{ .label = "files" });

    try fixture.client.sendMessage(chat, .STRING, "talk", NOW);
    try fixture.client.sendMessage(files, .BINARY, &.{0xAB}, NOW);
    try fixture.pump();

    // Each payload is read before the next event is asked for, which is as long as it lives.
    const first = try expectMessage(&fixture.server);

    try std.testing.expectEqual(chat, first.stream_identifier);
    try std.testing.expectEqualStrings("talk", first.payload);

    const second = try expectMessage(&fixture.server);

    try std.testing.expectEqual(files, second.stream_identifier);
    try std.testing.expectEqualSlices(u8, &.{0xAB}, second.payload);
}

test "zix datachannel: peer, both sides opening at once do not collide" {
    var fixture: Fixture = undefined;
    try fixture.setUp(std.testing.allocator);
    defer fixture.tearDown();

    try fixture.connect();

    const from_client = try fixture.client.openChannel(.{ .label = "down" }, NOW);
    const from_server = try fixture.server.openChannel(.{ .label = "up" }, NOW);

    try fixture.pump();
    try Fixture.drain(&fixture.client);
    try Fixture.drain(&fixture.server);
    try fixture.pump();

    // The role split is the whole reason these are two channels and not one broken one.
    try std.testing.expectEqual(@as(u16, 0), from_client);
    try std.testing.expectEqual(@as(u16, 1), from_server);
    try std.testing.expectEqual(@as(usize, 2), fixture.client.count());
    try std.testing.expectEqual(@as(usize, 2), fixture.server.count());
}
