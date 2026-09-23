//! zix WebRTC data channel, one channel (RFC 8831 6.4, RFC 8832 6).
//!
//! What:
//! - One bidirectional channel: the properties it was opened with, where it is in its life, and
//!   the translation between how DCEP describes a channel and how SCTP is asked to send.
//!
//! Note:
//! - A channel is a pair of streams sharing one identifier, one each way, and both sides use the
//!   same properties (RFC 8832 4). So one set of options describes both directions.
//! - Until something has been heard back on a channel, everything goes out ordered even when the
//!   channel is unordered (RFC 8832 6). Otherwise a message can overtake the DATA_CHANNEL_OPEN
//!   that explains what the channel is, and arrive on a stream the peer knows nothing about.
//! - A lifetime in DCEP is a duration from when the message was handed over, while the send
//!   queue wants a deadline on the caller's clock. The conversion needs the clock, which is why
//!   `reliability` takes one rather than being a field.
//! - Closing takes both directions. This endpoint resets its outgoing stream and the peer resets
//!   its own, and only when both have happened is the identifier free again (RFC 8831 6.7). The
//!   two flags exist because either side can start it.

const std = @import("std");

const dcep = @import("dcep.zig");
const send_queue = @import("../sctp/send_queue.zig");

/// Where a channel is in its life.
pub const State = enum {
    /// A DATA_CHANNEL_OPEN went out and nothing has come back yet. Messages may already be sent.
    CONNECTING,
    OPEN,
    /// A stream reset is under way, in one direction or both.
    CLOSING,
    /// Both streams have been reset, so the identifier can be used again.
    CLOSED,
};

/// Everything that can go wrong describing a channel.
pub const Error = error{
    OutOfMemory,
    /// A retransmission limit and a lifetime were both asked for. DCEP has no channel type for
    /// that pair (RFC 8832 5.1).
    ZixConflictingReliability,
    /// A channel type outside the six RFC 8832 5.1 defines.
    ZixUnknownChannelType,
};

/// How a channel sends, in the terms an application uses.
pub const Options = struct {
    /// Deliver messages in the order they were sent.
    ordered: bool = true,
    /// Give up on a message after this many retransmissions.
    max_retransmits: ?u16 = null,
    /// Give up on a message this long after it was handed over.
    max_lifetime_ms: ?u32 = null,
};

/// What a channel is built from.
pub const Fields = struct {
    stream_identifier: u16,
    options: Options = .{},
    priority: u16 = @intFromEnum(dcep.Priority.NORMAL),
    /// Copied, so the caller's buffer may be reused.
    label: []const u8 = "",
    /// Copied, so the caller's buffer may be reused.
    protocol: []const u8 = "",
    /// Whether this endpoint sent the DATA_CHANNEL_OPEN.
    opener: bool,
};

/// One data channel.
pub const Channel = struct {
    stream_identifier: u16,
    state: State,
    options: Options,
    priority: u16,
    /// Owned, freed by `deinit`.
    label: []const u8,
    /// Owned, freed by `deinit`.
    protocol: []const u8,
    opener: bool,
    /// Whether anything at all has arrived on the channel, which is what releases unordered
    /// sending (RFC 8832 6).
    peer_heard: bool,
    /// Whether the reset of this endpoint's outgoing stream has finished.
    outgoing_reset_done: bool,
    /// Whether the peer's reset of its outgoing stream has been seen.
    incoming_reset_done: bool,
    /// Whether the reset that closes this channel has already been asked for.
    reset_requested: bool,

    /// Build a channel, copying its label and protocol.
    ///
    /// Note:
    /// - A channel this endpoint opened starts CONNECTING, and one the peer opened is usable at
    ///   once, because the DATA_CHANNEL_OPEN that created it is the whole handshake
    ///   (RFC 8832 6).
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, `deinit` frees the two copies)
    /// fields - Fields
    ///
    /// Return:
    /// - Channel
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, fields: Fields) error{OutOfMemory}!Channel {
        const label = try allocator.dupe(u8, fields.label);
        errdefer allocator.free(label);

        const protocol = try allocator.dupe(u8, fields.protocol);

        return .{
            .stream_identifier = fields.stream_identifier,
            .state = if (fields.opener) .CONNECTING else .OPEN,
            .options = fields.options,
            .priority = fields.priority,
            .label = label,
            .protocol = protocol,
            .opener = fields.opener,
            .peer_heard = !fields.opener,
            .outgoing_reset_done = false,
            .incoming_reset_done = false,
            .reset_requested = false,
        };
    }

    /// Free the label and protocol copies.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (the one `init` was given)
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *Channel, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.protocol);
    }

    /// Something arrived from the peer on this channel.
    ///
    /// Note:
    /// - A DATA_CHANNEL_ACK and an ordinary message both count. Either one proves the peer knows
    ///   the channel exists, which is all the handshake was for (RFC 8832 6).
    ///
    /// Return:
    /// - void
    pub fn noteHeardFromPeer(self: *Channel) void {
        self.peer_heard = true;

        if (self.state == .CONNECTING) self.state = .OPEN;
    }

    /// Whether the next message has to go out ordered.
    ///
    /// Return:
    /// - bool
    pub fn sendOrdered(self: Channel) bool {
        return self.options.ordered or !self.peer_heard;
    }

    /// Whether messages may still be handed over.
    ///
    /// Return:
    /// - bool
    pub fn isSendable(self: Channel) bool {
        return switch (self.state) {
            .CONNECTING, .OPEN => true,
            .CLOSING, .CLOSED => false,
        };
    }

    /// How hard the send queue should try for a message handed over now.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - send_queue.Reliability
    pub fn reliability(self: Channel, now_ms: u64) send_queue.Reliability {
        if (self.options.max_retransmits) |limit| return .{ .max_retransmits = limit };

        // The lifetime is counted from this moment, so the deadline is only knowable here.
        if (self.options.max_lifetime_ms) |lifetime| return .{ .expires_ms = now_ms + lifetime };

        return .{};
    }

    /// Start closing, whoever asked for it.
    ///
    /// Return:
    /// - void
    pub fn beginClosing(self: *Channel) void {
        if (self.state == .CLOSED) return;

        self.state = .CLOSING;
    }

    /// Ask for the close, or ask for it again after one the peer refused.
    ///
    /// Note:
    /// - Re-arming is what lets a refused close be retried. A close already carried out in this
    ///   direction is left alone, because asking twice would reset a stream back to zero that
    ///   the peer is already using again.
    ///
    /// Return:
    /// - void
    pub fn requestClose(self: *Channel) void {
        self.beginClosing();

        if (!self.outgoing_reset_done) self.reset_requested = false;
    }

    /// This endpoint's outgoing stream has been reset.
    ///
    /// Return:
    /// - void
    pub fn noteOutgoingReset(self: *Channel) void {
        self.outgoing_reset_done = true;
        self.beginClosing();
        self.settle();
    }

    /// The peer has reset its outgoing stream, so nothing more will arrive.
    ///
    /// Return:
    /// - void
    pub fn noteIncomingReset(self: *Channel) void {
        self.incoming_reset_done = true;
        self.beginClosing();
        self.settle();
    }

    /// Move to CLOSED once both directions have been reset.
    fn settle(self: *Channel) void {
        if (!self.outgoing_reset_done) return;
        if (!self.incoming_reset_done) return;

        self.state = .CLOSED;
    }
};

/// The DCEP channel type that describes a set of options.
///
/// Param:
/// options - Options
///
/// Return:
/// - dcep.ChannelType
/// - error.ZixConflictingReliability if a retransmission limit and a lifetime were both given
pub fn channelTypeFor(options: Options) Error!dcep.ChannelType {
    if (options.max_retransmits != null and options.max_lifetime_ms != null) {
        return error.ZixConflictingReliability;
    }

    const unordered: u8 = if (options.ordered) 0 else dcep.UNORDERED_FLAG;

    if (options.max_retransmits != null) {
        return @enumFromInt(@intFromEnum(dcep.ChannelType.PARTIAL_RELIABLE_REXMIT) | unordered);
    }

    if (options.max_lifetime_ms != null) {
        return @enumFromInt(@intFromEnum(dcep.ChannelType.PARTIAL_RELIABLE_TIMED) | unordered);
    }

    return @enumFromInt(@intFromEnum(dcep.ChannelType.RELIABLE) | unordered);
}

/// The reliability parameter that goes out with a set of options.
///
/// Note:
/// - Zero on a reliable channel, which is what RFC 8832 5.1 requires a sender to put there.
///
/// Param:
/// options - Options
///
/// Return:
/// - u32
pub fn reliabilityParameterFor(options: Options) u32 {
    if (options.max_retransmits) |limit| return limit;
    if (options.max_lifetime_ms) |lifetime| return lifetime;

    return 0;
}

/// The options a DATA_CHANNEL_OPEN describes.
///
/// Note:
/// - The parameter is read only when the channel type says it means something. On a reliable
///   channel a sender may put anything there and a receiver has to ignore it
///   (RFC 8832 5.1 Table 1).
///
/// Param:
/// channel_type - dcep.ChannelType
/// reliability_parameter - u32
///
/// Return:
/// - Options
/// - error.ZixUnknownChannelType
pub fn optionsFor(channel_type: dcep.ChannelType, reliability_parameter: u32) Error!Options {
    if (!dcep.isKnownChannelType(channel_type)) return error.ZixUnknownChannelType;

    const ordered = !channel_type.isUnordered();

    if (channel_type.limitsRetransmissions()) {
        // The field is four bytes wide and a retransmission count is two, so a peer asking for
        // more retries than that is asking for every retry there is.
        const limit = @min(reliability_parameter, std.math.maxInt(u16));

        return .{ .ordered = ordered, .max_retransmits = @intCast(limit) };
    }

    if (channel_type.limitsLifetime()) {
        return .{ .ordered = ordered, .max_lifetime_ms = reliability_parameter };
    }

    return .{ .ordered = ordered };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix datachannel: channel init, an opened channel starts connecting" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    try std.testing.expectEqual(State.CONNECTING, opened.state);
    try std.testing.expect(!opened.peer_heard);
}

test "zix datachannel: channel init, an accepted channel is open at once" {
    var accepted = try Channel.init(std.testing.allocator, .{ .stream_identifier = 1, .opener = false });
    defer accepted.deinit(std.testing.allocator);

    // The DATA_CHANNEL_OPEN that created it already came from the peer, so there is nothing
    // left to wait for.
    try std.testing.expectEqual(State.OPEN, accepted.state);
    try std.testing.expect(accepted.peer_heard);
}

test "zix datachannel: channel init, the label and protocol are copied" {
    var label: [4]u8 = .{ 'c', 'h', 'a', 't' };

    var opened = try Channel.init(std.testing.allocator, .{
        .stream_identifier = 0,
        .label = &label,
        .protocol = "zix",
        .opener = true,
    });
    defer opened.deinit(std.testing.allocator);

    label[0] = 'x';

    try std.testing.expectEqualStrings("chat", opened.label);
    try std.testing.expectEqualStrings("zix", opened.protocol);
}

test "zix datachannel: channel noteHeardFromPeer, a connecting channel opens" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.noteHeardFromPeer();

    try std.testing.expectEqual(State.OPEN, opened.state);
}

test "zix datachannel: channel noteHeardFromPeer, a closing channel does not reopen" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.beginClosing();
    opened.noteHeardFromPeer();

    try std.testing.expectEqual(State.CLOSING, opened.state);
}

test "zix datachannel: channel sendOrdered, an unordered channel sends ordered until it is heard from" {
    var opened = try Channel.init(std.testing.allocator, .{
        .stream_identifier = 0,
        .options = .{ .ordered = false },
        .opener = true,
    });
    defer opened.deinit(std.testing.allocator);

    try std.testing.expect(opened.sendOrdered());

    opened.noteHeardFromPeer();

    try std.testing.expect(!opened.sendOrdered());
}

test "zix datachannel: channel sendOrdered, an ordered channel always sends ordered" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    try std.testing.expect(opened.sendOrdered());

    opened.noteHeardFromPeer();

    try std.testing.expect(opened.sendOrdered());
}

test "zix datachannel: channel reliability, a reliable channel asks for no limit" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    const limits = opened.reliability(1_000);

    try std.testing.expectEqual(@as(?u16, null), limits.max_retransmits);
    try std.testing.expectEqual(@as(?u64, null), limits.expires_ms);
}

test "zix datachannel: channel reliability, a lifetime becomes a deadline on the caller's clock" {
    var opened = try Channel.init(std.testing.allocator, .{
        .stream_identifier = 0,
        .options = .{ .max_lifetime_ms = 500 },
        .opener = true,
    });
    defer opened.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u64, 1_500), opened.reliability(1_000).expires_ms);
    try std.testing.expectEqual(@as(?u64, 9_500), opened.reliability(9_000).expires_ms);
}

test "zix datachannel: channel reliability, a retransmission limit is passed straight through" {
    var opened = try Channel.init(std.testing.allocator, .{
        .stream_identifier = 0,
        .options = .{ .max_retransmits = 3 },
        .opener = true,
    });
    defer opened.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u16, 3), opened.reliability(1_000).max_retransmits);
}

test "zix datachannel: channel requestClose, asking twice re-arms the request" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.requestClose();
    opened.reset_requested = true;
    opened.requestClose();

    try std.testing.expectEqual(State.CLOSING, opened.state);
    try std.testing.expect(!opened.reset_requested);
}

test "zix datachannel: channel requestClose, a reset already done is not asked for again" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.reset_requested = true;
    opened.noteOutgoingReset();
    opened.requestClose();

    try std.testing.expect(opened.reset_requested);
}

test "zix datachannel: channel closing, one direction alone leaves it closing" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.noteOutgoingReset();

    try std.testing.expectEqual(State.CLOSING, opened.state);
    try std.testing.expect(!opened.isSendable());
}

test "zix datachannel: channel closing, both directions close it" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.noteOutgoingReset();
    opened.noteIncomingReset();

    try std.testing.expectEqual(State.CLOSED, opened.state);
}

test "zix datachannel: channel closing, the peer starting it reaches the same place" {
    var opened = try Channel.init(std.testing.allocator, .{ .stream_identifier = 0, .opener = true });
    defer opened.deinit(std.testing.allocator);

    opened.noteIncomingReset();

    try std.testing.expectEqual(State.CLOSING, opened.state);

    opened.noteOutgoingReset();

    try std.testing.expectEqual(State.CLOSED, opened.state);
}

test "zix datachannel: channel channelTypeFor, the four ordered and unordered pairs" {
    try std.testing.expectEqual(dcep.ChannelType.RELIABLE, try channelTypeFor(.{}));
    try std.testing.expectEqual(
        dcep.ChannelType.RELIABLE_UNORDERED,
        try channelTypeFor(.{ .ordered = false }),
    );
    try std.testing.expectEqual(
        dcep.ChannelType.PARTIAL_RELIABLE_REXMIT,
        try channelTypeFor(.{ .max_retransmits = 2 }),
    );
    try std.testing.expectEqual(
        dcep.ChannelType.PARTIAL_RELIABLE_TIMED_UNORDERED,
        try channelTypeFor(.{ .ordered = false, .max_lifetime_ms = 500 }),
    );
}

test "zix datachannel: channel channelTypeFor, a limit and a lifetime together are refused" {
    try std.testing.expectError(
        error.ZixConflictingReliability,
        channelTypeFor(.{ .max_retransmits = 2, .max_lifetime_ms = 500 }),
    );
}

test "zix datachannel: channel reliabilityParameterFor, a reliable channel sends zero" {
    try std.testing.expectEqual(@as(u32, 0), reliabilityParameterFor(.{}));
    try std.testing.expectEqual(@as(u32, 2), reliabilityParameterFor(.{ .max_retransmits = 2 }));
    try std.testing.expectEqual(@as(u32, 500), reliabilityParameterFor(.{ .max_lifetime_ms = 500 }));
}

test "zix datachannel: channel optionsFor, a reliable type ignores the parameter" {
    const options = try optionsFor(.RELIABLE, 9_999);

    try std.testing.expect(options.ordered);
    try std.testing.expectEqual(@as(?u16, null), options.max_retransmits);
    try std.testing.expectEqual(@as(?u32, null), options.max_lifetime_ms);
}

test "zix datachannel: channel optionsFor, each partial type reads the parameter its own way" {
    const retries = try optionsFor(.PARTIAL_RELIABLE_REXMIT, 4);
    const lifetime = try optionsFor(.PARTIAL_RELIABLE_TIMED_UNORDERED, 750);

    try std.testing.expectEqual(@as(?u16, 4), retries.max_retransmits);
    try std.testing.expectEqual(@as(?u32, null), retries.max_lifetime_ms);
    try std.testing.expectEqual(@as(?u32, 750), lifetime.max_lifetime_ms);
    try std.testing.expect(!lifetime.ordered);
}

test "zix datachannel: channel optionsFor, a retransmission count wider than the counter is clamped" {
    const options = try optionsFor(.PARTIAL_RELIABLE_REXMIT, 100_000);

    try std.testing.expectEqual(@as(?u16, std.math.maxInt(u16)), options.max_retransmits);
}

test "zix datachannel: channel optionsFor, an undefined channel type is refused" {
    try std.testing.expectError(error.ZixUnknownChannelType, optionsFor(@enumFromInt(0x7F), 0));
}

test "zix datachannel: channel options, a round trip through DCEP keeps the properties" {
    const original: Options = .{ .ordered = false, .max_retransmits = 3 };

    const channel_type = try channelTypeFor(original);
    const parameter = reliabilityParameterFor(original);
    const restored = try optionsFor(channel_type, parameter);

    try std.testing.expectEqual(original.ordered, restored.ordered);
    try std.testing.expectEqual(original.max_retransmits, restored.max_retransmits);
    try std.testing.expectEqual(original.max_lifetime_ms, restored.max_lifetime_ms);
}
