//! zix Data Channel Establishment Protocol messages (RFC 8832 5).
//!
//! What:
//! - The two messages that open a data channel in band: DATA_CHANNEL_OPEN, which names every
//!   property the channel will have, and DATA_CHANNEL_ACK, which is one byte saying it is up.
//!
//! Note:
//! - Both messages travel as ordinary user data on the channel's own stream, under the DCEP
//!   payload protocol identifier. That identifier is the only thing separating them from
//!   application messages, so nothing else may be sent under it (RFC 8832 6).
//! - The channel type packs two independent choices into one byte: bit 0x80 is unordered, and
//!   the low bits pick full reliability, a retransmission limit, or a lifetime. Reading it as a
//!   flat list of six values works, and then a seventh value nobody expected is unreadable.
//! - The reliability parameter means nothing on a fully reliable channel and MUST be ignored
//!   there (RFC 8832 5.1 Table 1), so the value that arrives with one is not worth carrying up.
//! - A message is read whole or not at all. Label and protocol lengths that do not add up to the
//!   bytes present are a framing error, which RFC 8832 7 says closes the channel rather than
//!   being repaired by guessing.
//! - Neither field is checked for UTF-8 here. They are carried as bytes, and whatever hands a
//!   label to an application is where that check belongs.

const std = @import("std");

/// Message type, channel type, priority, reliability parameter, and the two length fields.
pub const OPEN_FIXED_LEN: usize = 12;

/// The whole of a DATA_CHANNEL_ACK.
pub const ACK_LEN: usize = 1;

/// Longest label or protocol the length field can describe.
pub const MAX_FIELD_LEN: usize = std.math.maxInt(u16);

/// Set on a channel type that delivers without waiting for earlier messages.
pub const UNORDERED_FLAG: u8 = 0x80;

/// Everything that stops a DCEP message from being read or built.
pub const Error = error{
    /// Fewer bytes than the message needs.
    ZixTruncated,
    /// The label and protocol lengths do not match the bytes that came with them.
    ZixBadLength,
    /// A message type this endpoint does not implement.
    ZixUnknownMessageType,
    /// A channel type outside the six RFC 8832 5.1 defines.
    ZixUnknownChannelType,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// What a DCEP message is (RFC 8832 8.2.1).
pub const MessageType = enum(u8) {
    /// The channel is up, sent by the side that did not open it.
    ACK = 0x02,
    /// Open a channel with these properties.
    OPEN = 0x03,
    _,
};

/// How a channel behaves, as one byte (RFC 8832 8.2.2).
pub const ChannelType = enum(u8) {
    RELIABLE = 0x00,
    /// Retransmit a message at most `reliability_parameter` times.
    PARTIAL_RELIABLE_REXMIT = 0x01,
    /// Give up on a message `reliability_parameter` milliseconds after it was handed over.
    PARTIAL_RELIABLE_TIMED = 0x02,
    RELIABLE_UNORDERED = 0x80,
    PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81,
    PARTIAL_RELIABLE_TIMED_UNORDERED = 0x82,
    _,

    /// Whether messages may be delivered without waiting for earlier ones.
    ///
    /// Return:
    /// - bool
    pub fn isUnordered(self: ChannelType) bool {
        return @intFromEnum(self) & UNORDERED_FLAG != 0;
    }

    /// Whether every message is delivered however long it takes.
    ///
    /// Return:
    /// - bool
    pub fn isReliable(self: ChannelType) bool {
        return @intFromEnum(self) & ~UNORDERED_FLAG == @intFromEnum(ChannelType.RELIABLE);
    }

    /// Whether the reliability parameter counts retransmissions.
    ///
    /// Return:
    /// - bool
    pub fn limitsRetransmissions(self: ChannelType) bool {
        return @intFromEnum(self) & ~UNORDERED_FLAG == @intFromEnum(ChannelType.PARTIAL_RELIABLE_REXMIT);
    }

    /// Whether the reliability parameter is a lifetime in milliseconds.
    ///
    /// Return:
    /// - bool
    pub fn limitsLifetime(self: ChannelType) bool {
        return @intFromEnum(self) & ~UNORDERED_FLAG == @intFromEnum(ChannelType.PARTIAL_RELIABLE_TIMED);
    }
};

/// The four priorities RFC 8831 6.4 says to use.
///
/// Note:
/// - The field is two bytes wide and any value fits, so this is a set of names rather than a
///   closed list. Nothing in zix schedules on it yet.
pub const Priority = enum(u16) {
    BELOW_NORMAL = 128,
    NORMAL = 256,
    HIGH = 512,
    EXTRA_HIGH = 1024,
    _,
};

/// A DATA_CHANNEL_OPEN as it arrived or as it will go out.
pub const Open = struct {
    channel_type: ChannelType,
    priority: u16,
    /// A retransmission count or a lifetime in milliseconds, depending on the channel type, and
    /// meaningless on a reliable channel.
    reliability_parameter: u32,
    /// Borrowed. Names the channel for the application, and may be empty.
    label: []const u8,
    /// Borrowed. A subprotocol name, empty when unspecified.
    protocol: []const u8,
};

/// What kind of message a DCEP payload holds.
///
/// Param:
/// message - []const u8 (one whole DCEP message)
///
/// Return:
/// - MessageType
/// - error.ZixTruncated if the payload is empty
pub fn messageType(message: []const u8) Error!MessageType {
    if (message.len == 0) return error.ZixTruncated;

    return @enumFromInt(message[0]);
}

/// Read a DATA_CHANNEL_OPEN.
///
/// Note:
/// - The channel type is checked here, because a channel opened on a type this endpoint cannot
///   honour would send under the wrong reliability for as long as it lived.
///
/// Param:
/// message - []const u8 (one whole DCEP message, message type byte included)
///
/// Return:
/// - Open borrowing `message`
/// - error.ZixTruncated if the message is shorter than its fixed part
/// - error.ZixBadLength if the two length fields do not account for the rest of it exactly
/// - error.ZixUnknownMessageType if it is not a DATA_CHANNEL_OPEN
/// - error.ZixUnknownChannelType
pub fn readOpen(message: []const u8) Error!Open {
    if (message.len < OPEN_FIXED_LEN) return error.ZixTruncated;
    if ((try messageType(message)) != .OPEN) return error.ZixUnknownMessageType;

    const channel_type: ChannelType = @enumFromInt(message[1]);

    if (!isKnownChannelType(channel_type)) return error.ZixUnknownChannelType;

    const label_len = std.mem.readInt(u16, message[8..10], .big);
    const protocol_len = std.mem.readInt(u16, message[10..12], .big);
    const total = OPEN_FIXED_LEN + @as(usize, label_len) + @as(usize, protocol_len);

    if (message.len != total) return error.ZixBadLength;

    return .{
        .channel_type = channel_type,
        .priority = std.mem.readInt(u16, message[2..4], .big),
        .reliability_parameter = std.mem.readInt(u32, message[4..8], .big),
        .label = message[OPEN_FIXED_LEN..][0..label_len],
        .protocol = message[OPEN_FIXED_LEN + label_len ..][0..protocol_len],
    };
}

/// How many bytes a DATA_CHANNEL_OPEN will take.
///
/// Param:
/// open - Open
///
/// Return:
/// - usize
pub fn openLen(open: Open) usize {
    return OPEN_FIXED_LEN + open.label.len + open.protocol.len;
}

/// Write a DATA_CHANNEL_OPEN.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// open - Open
///
/// Return:
/// - []const u8, the whole message
/// - error.ZixNoSpace if `out` cannot hold it
/// - error.ZixBadLength if the label or the protocol is longer than its length field
/// - error.ZixUnknownChannelType
pub fn writeOpen(out: []u8, open: Open) Error![]const u8 {
    if (open.label.len > MAX_FIELD_LEN) return error.ZixBadLength;
    if (open.protocol.len > MAX_FIELD_LEN) return error.ZixBadLength;
    if (!isKnownChannelType(open.channel_type)) return error.ZixUnknownChannelType;

    const total = openLen(open);

    if (out.len < total) return error.ZixNoSpace;

    out[0] = @intFromEnum(MessageType.OPEN);
    out[1] = @intFromEnum(open.channel_type);
    std.mem.writeInt(u16, out[2..4], open.priority, .big);
    std.mem.writeInt(u32, out[4..8], open.reliability_parameter, .big);
    std.mem.writeInt(u16, out[8..10], @intCast(open.label.len), .big);
    std.mem.writeInt(u16, out[10..12], @intCast(open.protocol.len), .big);
    @memcpy(out[OPEN_FIXED_LEN..][0..open.label.len], open.label);
    @memcpy(out[OPEN_FIXED_LEN + open.label.len ..][0..open.protocol.len], open.protocol);

    return out[0..total];
}

/// Write a DATA_CHANNEL_ACK.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
///
/// Return:
/// - []const u8, the whole message
/// - error.ZixNoSpace
pub fn writeAck(out: []u8) Error![]const u8 {
    if (out.len < ACK_LEN) return error.ZixNoSpace;

    out[0] = @intFromEnum(MessageType.ACK);

    return out[0..ACK_LEN];
}

/// Whether a channel type is one of the six RFC 8832 5.1 defines.
///
/// Param:
/// channel_type - ChannelType
///
/// Return:
/// - bool
pub fn isKnownChannelType(channel_type: ChannelType) bool {
    return switch (channel_type) {
        .RELIABLE,
        .PARTIAL_RELIABLE_REXMIT,
        .PARTIAL_RELIABLE_TIMED,
        .RELIABLE_UNORDERED,
        .PARTIAL_RELIABLE_REXMIT_UNORDERED,
        .PARTIAL_RELIABLE_TIMED_UNORDERED,
        => true,
        else => false,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

/// A DATA_CHANNEL_OPEN for an unordered channel that retransmits twice, label "chat", no
/// protocol. Built by hand from RFC 8832 5.1 rather than by this file's own writer.
const sample_open: [16]u8 = .{
    0x03, 0x81, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x04, 0x00, 0x00,
    'c',  'h',  'a',  't',
};

test "zix datachannel: dcep messageType, the two type numbers match RFC 8832 8.2.1" {
    try std.testing.expectEqual(@as(u8, 0x02), @intFromEnum(MessageType.ACK));
    try std.testing.expectEqual(@as(u8, 0x03), @intFromEnum(MessageType.OPEN));
}

test "zix datachannel: dcep messageType, an empty payload is truncated" {
    try std.testing.expectError(error.ZixTruncated, messageType(""));
}

test "zix datachannel: dcep readOpen, the hand-built sample reads field for field" {
    const open = try readOpen(&sample_open);

    try std.testing.expectEqual(ChannelType.PARTIAL_RELIABLE_REXMIT_UNORDERED, open.channel_type);
    try std.testing.expectEqual(@as(u16, 256), open.priority);
    try std.testing.expectEqual(@as(u32, 2), open.reliability_parameter);
    try std.testing.expectEqualStrings("chat", open.label);
    try std.testing.expectEqualStrings("", open.protocol);
}

test "zix datachannel: dcep readOpen, a label and a protocol both come back" {
    var buf: [64]u8 = undefined;
    const message = try writeOpen(&buf, .{
        .channel_type = .RELIABLE,
        .priority = 256,
        .reliability_parameter = 0,
        .label = "files",
        .protocol = "zix",
    });

    const open = try readOpen(message);

    try std.testing.expectEqualStrings("files", open.label);
    try std.testing.expectEqualStrings("zix", open.protocol);
}

test "zix datachannel: dcep readOpen, a message shorter than the fixed part is truncated" {
    try std.testing.expectError(error.ZixTruncated, readOpen(sample_open[0..11]));
}

test "zix datachannel: dcep readOpen, a label length past the end is a framing error" {
    var message = sample_open;
    std.mem.writeInt(u16, message[8..10], 40, .big);

    try std.testing.expectError(error.ZixBadLength, readOpen(&message));
}

test "zix datachannel: dcep readOpen, trailing bytes are a framing error" {
    var message: [17]u8 = undefined;
    @memcpy(message[0..16], &sample_open);
    message[16] = 0xFF;

    // The lengths account for 16 bytes and 17 arrived, which RFC 8832 7 treats as an error
    // rather than something to read past.
    try std.testing.expectError(error.ZixBadLength, readOpen(&message));
}

test "zix datachannel: dcep readOpen, an ack is not an open" {
    var buf: [ACK_LEN]u8 = undefined;
    const ack = try writeAck(&buf);

    try std.testing.expectError(error.ZixTruncated, readOpen(ack));
}

test "zix datachannel: dcep readOpen, a channel type outside the six is refused" {
    var message = sample_open;
    message[1] = 0x03;

    try std.testing.expectError(error.ZixUnknownChannelType, readOpen(&message));
}

test "zix datachannel: dcep readOpen, a message type that is neither open nor ack is refused" {
    var message = sample_open;
    message[0] = 0x04;

    try std.testing.expectError(error.ZixUnknownMessageType, readOpen(&message));
}

test "zix datachannel: dcep writeOpen, the bytes match the hand-built sample" {
    var buf: [32]u8 = undefined;
    const message = try writeOpen(&buf, .{
        .channel_type = .PARTIAL_RELIABLE_REXMIT_UNORDERED,
        .priority = 256,
        .reliability_parameter = 2,
        .label = "chat",
        .protocol = "",
    });

    try std.testing.expectEqualSlices(u8, &sample_open, message);
}

test "zix datachannel: dcep writeOpen, a buffer one byte short errors" {
    var buf: [15]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeOpen(&buf, .{
        .channel_type = .RELIABLE,
        .priority = 256,
        .reliability_parameter = 0,
        .label = "chat",
        .protocol = "",
    }));
}

test "zix datachannel: dcep writeAck, the whole message is one byte" {
    var buf: [4]u8 = undefined;
    const ack = try writeAck(&buf);

    try std.testing.expectEqual(@as(usize, 1), ack.len);
    try std.testing.expectEqual(MessageType.ACK, try messageType(ack));
}

test "zix datachannel: dcep writeAck, an empty buffer errors" {
    var buf: [0]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeAck(&buf));
}

test "zix datachannel: dcep channel type, the unordered bit is independent of the reliability" {
    try std.testing.expect(!ChannelType.RELIABLE.isUnordered());
    try std.testing.expect(ChannelType.RELIABLE_UNORDERED.isUnordered());
    try std.testing.expect(ChannelType.RELIABLE.isReliable());
    try std.testing.expect(ChannelType.RELIABLE_UNORDERED.isReliable());
}

test "zix datachannel: dcep channel type, each pair names what its parameter counts" {
    try std.testing.expect(ChannelType.PARTIAL_RELIABLE_REXMIT.limitsRetransmissions());
    try std.testing.expect(ChannelType.PARTIAL_RELIABLE_REXMIT_UNORDERED.limitsRetransmissions());
    try std.testing.expect(ChannelType.PARTIAL_RELIABLE_TIMED.limitsLifetime());
    try std.testing.expect(ChannelType.PARTIAL_RELIABLE_TIMED_UNORDERED.limitsLifetime());
    try std.testing.expect(!ChannelType.RELIABLE.limitsRetransmissions());
    try std.testing.expect(!ChannelType.RELIABLE.limitsLifetime());
}

test "zix datachannel: dcep isKnownChannelType, the six defined values pass and others do not" {
    try std.testing.expect(isKnownChannelType(.RELIABLE));
    try std.testing.expect(isKnownChannelType(.PARTIAL_RELIABLE_REXMIT));
    try std.testing.expect(isKnownChannelType(.PARTIAL_RELIABLE_TIMED));
    try std.testing.expect(isKnownChannelType(.RELIABLE_UNORDERED));
    try std.testing.expect(isKnownChannelType(.PARTIAL_RELIABLE_REXMIT_UNORDERED));
    try std.testing.expect(isKnownChannelType(.PARTIAL_RELIABLE_TIMED_UNORDERED));
    try std.testing.expect(!isKnownChannelType(@enumFromInt(0x03)));
    try std.testing.expect(!isKnownChannelType(@enumFromInt(0x7F)));
}

test "zix datachannel: dcep priority, the four named values match RFC 8831 6.4" {
    try std.testing.expectEqual(@as(u16, 128), @intFromEnum(Priority.BELOW_NORMAL));
    try std.testing.expectEqual(@as(u16, 256), @intFromEnum(Priority.NORMAL));
    try std.testing.expectEqual(@as(u16, 512), @intFromEnum(Priority.HIGH));
    try std.testing.expectEqual(@as(u16, 1024), @intFromEnum(Priority.EXTRA_HIGH));
}

test "zix datachannel: dcep openLen, the length matches what was written" {
    const open: Open = .{
        .channel_type = .RELIABLE,
        .priority = 256,
        .reliability_parameter = 0,
        .label = "chat",
        .protocol = "zix",
    };

    var buf: [64]u8 = undefined;
    const message = try writeOpen(&buf, open);

    try std.testing.expectEqual(openLen(open), message.len);
}
