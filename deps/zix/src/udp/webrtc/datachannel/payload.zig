//! zix WebRTC data channel payload identifiers (RFC 8831 6.6 and 8, RFC 8832 8.1).
//!
//! What:
//! - The SCTP payload protocol identifiers a data channel sends under, and the one convention
//!   that goes with them: a message with nothing in it travels as a single zero byte under an
//!   identifier that says it is empty.
//!
//! Note:
//! - SCTP refuses to carry a DATA chunk with no payload (RFC 9260 3.3.1), so an empty string or
//!   an empty buffer cannot be sent as itself. RFC 8831 6.6 sends one zero byte and puts the
//!   emptiness in the identifier instead. A receiver that hands that byte to the application is
//!   delivering a one-byte message the sender never wrote, which is why `read` drops it.
//! - The two partial identifiers, 52 and 54, are deprecated. They carried a fragmentation scheme
//!   that SCTP's own fragmentation replaced. RFC 8831 6.6 says an unsupported identifier closes
//!   the channel, so they are refused here rather than guessed at.
//! - DCEP rides the same stream as user data and is told apart only by this number, so nothing
//!   else may be sent under it (RFC 8832 6).
//! - Nothing here validates UTF-8. The identifier says a string was sent, and checking that the
//!   bytes really are one belongs to whatever hands them to an application.

const std = @import("std");

/// The identifiers a data channel may carry.
pub const Identifier = enum(u32) {
    /// Data Channel Establishment Protocol, never user data (RFC 8832 8.1).
    DCEP = 50,
    /// A non-empty string.
    STRING = 51,
    /// Deprecated, identifier-based fragmentation of binary data.
    BINARY_PARTIAL = 52,
    /// Non-empty binary data.
    BINARY = 53,
    /// Deprecated, identifier-based fragmentation of a string.
    STRING_PARTIAL = 54,
    /// An empty string, carried as one zero byte.
    STRING_EMPTY = 56,
    /// Empty binary data, carried as one zero byte.
    BINARY_EMPTY = 57,
    _,
};

/// What the application handed over, before its length decides the identifier.
pub const Kind = enum {
    STRING,
    BINARY,
};

/// The one byte an empty message travels as.
pub const EMPTY_PAYLOAD: [1]u8 = .{0};

/// The only thing that can go wrong reading an arrived message.
pub const Error = error{
    /// Not an identifier this endpoint carries, so the channel has to close (RFC 8831 6.6).
    UnsupportedIdentifier,
};

/// One user message, as the application sees it.
pub const Message = struct {
    kind: Kind,
    /// Borrowed from the caller. Empty whenever the identifier said the message was empty, no
    /// matter what bytes actually arrived.
    payload: []const u8,
};

/// The identifier a message goes out under.
///
/// Note:
/// - The length decides between the plain identifier and its empty variant, so a caller never
///   picks one directly.
///
/// Param:
/// kind - Kind
/// payload_len - usize (length of the application's own bytes, before the empty convention)
///
/// Return:
/// - Identifier
pub fn identifierFor(kind: Kind, payload_len: usize) Identifier {
    return switch (kind) {
        .STRING => if (payload_len == 0) .STRING_EMPTY else .STRING,
        .BINARY => if (payload_len == 0) .BINARY_EMPTY else .BINARY,
    };
}

/// The bytes to actually put on the wire for a message.
///
/// Param:
/// payload - []const u8 (the application's own bytes)
///
/// Return:
/// - []const u8, the payload itself, or the single zero byte when it was empty
pub fn payloadFor(payload: []const u8) []const u8 {
    if (payload.len == 0) return &EMPTY_PAYLOAD;

    return payload;
}

/// Whether an identifier belongs to DCEP rather than to the application.
///
/// Param:
/// identifier - u32 (the payload protocol identifier a DATA chunk carried)
///
/// Return:
/// - bool
pub fn isControl(identifier: u32) bool {
    return identifier == @intFromEnum(Identifier.DCEP);
}

/// Read a message that arrived.
///
/// Note:
/// - An empty identifier yields an empty payload whatever came with it, so the caller never has
///   to know about the zero byte.
///
/// Param:
/// identifier - u32 (the payload protocol identifier a DATA chunk carried)
/// payload - []const u8 (borrowed, the message as it arrived)
///
/// Return:
/// - Message borrowing `payload`
/// - error.UnsupportedIdentifier for DCEP, for the two deprecated identifiers, and for anything
///   unregistered
pub fn read(identifier: u32, payload: []const u8) Error!Message {
    const known: Identifier = @enumFromInt(identifier);

    // Everything else is DCEP, one of the two deprecated partial identifiers, or a number this
    // endpoint never registered, and all three close the channel.
    return switch (known) {
        .STRING => .{ .kind = .STRING, .payload = payload },
        .BINARY => .{ .kind = .BINARY, .payload = payload },
        .STRING_EMPTY => .{ .kind = .STRING, .payload = "" },
        .BINARY_EMPTY => .{ .kind = .BINARY, .payload = "" },
        else => error.UnsupportedIdentifier,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix datachannel: payload identifiers, the registry numbers match RFC 8831 8" {
    try std.testing.expectEqual(@as(u32, 50), @intFromEnum(Identifier.DCEP));
    try std.testing.expectEqual(@as(u32, 51), @intFromEnum(Identifier.STRING));
    try std.testing.expectEqual(@as(u32, 52), @intFromEnum(Identifier.BINARY_PARTIAL));
    try std.testing.expectEqual(@as(u32, 53), @intFromEnum(Identifier.BINARY));
    try std.testing.expectEqual(@as(u32, 54), @intFromEnum(Identifier.STRING_PARTIAL));
    try std.testing.expectEqual(@as(u32, 56), @intFromEnum(Identifier.STRING_EMPTY));
    try std.testing.expectEqual(@as(u32, 57), @intFromEnum(Identifier.BINARY_EMPTY));
}

test "zix datachannel: payload identifierFor, a non-empty message takes the plain identifier" {
    try std.testing.expectEqual(Identifier.STRING, identifierFor(.STRING, 5));
    try std.testing.expectEqual(Identifier.BINARY, identifierFor(.BINARY, 1));
}

test "zix datachannel: payload identifierFor, an empty message takes the empty identifier" {
    try std.testing.expectEqual(Identifier.STRING_EMPTY, identifierFor(.STRING, 0));
    try std.testing.expectEqual(Identifier.BINARY_EMPTY, identifierFor(.BINARY, 0));
}

test "zix datachannel: payload payloadFor, an empty message goes out as one zero byte" {
    const wire = payloadFor("");

    try std.testing.expectEqual(@as(usize, 1), wire.len);
    try std.testing.expectEqual(@as(u8, 0), wire[0]);
}

test "zix datachannel: payload payloadFor, a non-empty message goes out untouched" {
    const wire = payloadFor("hello");

    try std.testing.expectEqualStrings("hello", wire);
}

test "zix datachannel: payload isControl, only DCEP is control" {
    try std.testing.expect(isControl(50));
    try std.testing.expect(!isControl(51));
    try std.testing.expect(!isControl(53));
    try std.testing.expect(!isControl(0));
}

test "zix datachannel: payload read, a string comes back with its bytes" {
    const message = try read(51, "hello");

    try std.testing.expectEqual(Kind.STRING, message.kind);
    try std.testing.expectEqualStrings("hello", message.payload);
}

test "zix datachannel: payload read, binary comes back with its bytes" {
    const message = try read(53, &.{ 0x01, 0x02 });

    try std.testing.expectEqual(Kind.BINARY, message.kind);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, message.payload);
}

test "zix datachannel: payload read, an empty identifier drops the zero byte" {
    const text = try read(56, &EMPTY_PAYLOAD);
    const bytes = try read(57, &EMPTY_PAYLOAD);

    try std.testing.expectEqual(Kind.STRING, text.kind);
    try std.testing.expectEqual(@as(usize, 0), text.payload.len);
    try std.testing.expectEqual(Kind.BINARY, bytes.kind);
    try std.testing.expectEqual(@as(usize, 0), bytes.payload.len);
}

test "zix datachannel: payload read, an empty identifier ignores whatever arrived with it" {
    // A peer that sends more than the one byte is still saying the message is empty, and
    // handing those bytes on would invent a message the sender did not write.
    const message = try read(56, "not empty");

    try std.testing.expectEqual(@as(usize, 0), message.payload.len);
}

test "zix datachannel: payload read, a deprecated partial identifier is refused" {
    try std.testing.expectError(error.UnsupportedIdentifier, read(52, "x"));
    try std.testing.expectError(error.UnsupportedIdentifier, read(54, "x"));
}

test "zix datachannel: payload read, DCEP is not user data" {
    try std.testing.expectError(error.UnsupportedIdentifier, read(50, "x"));
}

test "zix datachannel: payload read, an unregistered identifier is refused" {
    try std.testing.expectError(error.UnsupportedIdentifier, read(0, "x"));
    try std.testing.expectError(error.UnsupportedIdentifier, read(55, "x"));
    try std.testing.expectError(error.UnsupportedIdentifier, read(4_242, "x"));
}

test "zix datachannel: payload round trip, an empty string survives send and receive" {
    const identifier = identifierFor(.STRING, 0);
    const wire = payloadFor("");

    const message = try read(@intFromEnum(identifier), wire);

    try std.testing.expectEqual(Kind.STRING, message.kind);
    try std.testing.expectEqual(@as(usize, 0), message.payload.len);
}
