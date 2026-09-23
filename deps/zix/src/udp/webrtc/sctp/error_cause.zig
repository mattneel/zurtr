//! zix SCTP error causes (RFC 9260 3.3.10).
//!
//! What:
//! - The reason codes that fill an ERROR chunk or an ABORT chunk, and the small typed values a
//!   few of them carry: which stream was invalid, how stale a cookie was, which chunk type was
//!   not understood.
//! - Reading them back off the wire, so a peer's ABORT can be reported as something better than
//!   "the association went away".
//!
//! Note:
//! - An error cause has the same type-length-value shape as a parameter (RFC 9260 3.3.10 says so
//!   outright), with its own registry of codes. The framing is borrowed from parameter.zig and
//!   the meaning of the numbers lives here.
//! - An ERROR chunk is not fatal by itself. The same cause carried by an ABORT is. Which chunk
//!   it goes in is the association's decision, so nothing here picks one.
//! - Stale Cookie measures staleness in MICROseconds, while cookie.zig works in milliseconds
//!   like every other timer in this tree. The conversion belongs to the caller that has both, so
//!   `writeStaleCookie` takes microseconds and says so.

const std = @import("std");

const parameter = @import("parameter.zig");

/// Cause code and cause length.
pub const HEADER_LEN: usize = parameter.HEADER_LEN;

/// Framing faults, and a buffer too small to write into.
pub const Error = parameter.Error;

/// Cause codes (RFC 9260 3.3.10 Table 11).
///
/// Note:
/// - Non-exhaustive. A peer may send a code from an extension this build does not implement, and
///   an unknown reason is still worth reporting as a number.
pub const Code = enum(u16) {
    /// A DATA chunk arrived on a stream that does not exist.
    INVALID_STREAM_IDENTIFIER = 1,
    MISSING_MANDATORY_PARAMETER = 2,
    /// The cookie in a COOKIE ECHO verified but had expired.
    STALE_COOKIE = 3,
    OUT_OF_RESOURCE = 4,
    UNRESOLVABLE_ADDRESS = 5,
    UNRECOGNIZED_CHUNK_TYPE = 6,
    INVALID_MANDATORY_PARAMETER = 7,
    UNRECOGNIZED_PARAMETERS = 8,
    /// A DATA chunk with a header and no payload.
    NO_USER_DATA = 9,
    COOKIE_RECEIVED_WHILE_SHUTTING_DOWN = 10,
    RESTART_WITH_NEW_ADDRESSES = 11,
    /// The application asked for the abort, and may have attached a reason.
    USER_INITIATED_ABORT = 12,
    /// The peer did something the protocol does not allow.
    PROTOCOL_VIOLATION = 13,
    _,
};

/// One cause, borrowing the bytes it was read from.
pub const Cause = struct {
    code: Code,
    /// Cause-specific information, which several codes leave empty.
    value: []const u8,

    /// How stale a cookie was, in microseconds, for a STALE_COOKIE cause.
    ///
    /// Return:
    /// - ?u32, null if this is another code or the value is the wrong size
    pub fn staleness(self: Cause) ?u32 {
        if (self.code != .STALE_COOKIE) return null;
        if (self.value.len != 4) return null;

        return std.mem.readInt(u32, self.value[0..4], .big);
    }

    /// Which stream was rejected, for an INVALID_STREAM_IDENTIFIER cause.
    ///
    /// Return:
    /// - ?u16, null if this is another code or the value is the wrong size
    pub fn streamIdentifier(self: Cause) ?u16 {
        if (self.code != .INVALID_STREAM_IDENTIFIER) return null;
        if (self.value.len != 4) return null;

        return std.mem.readInt(u16, self.value[0..2], .big);
    }
};

/// Check that every cause in a region is framed correctly.
///
/// Param:
/// region - []const u8 (value of an ERROR or ABORT chunk)
///
/// Return:
/// - void
/// - error.ZixBadLength, error.ZixTruncated
pub fn validate(region: []const u8) Error!void {
    return parameter.validate(region);
}

/// Walks the causes of a validated region.
pub const Iterator = struct {
    inner: parameter.Iterator,

    /// Start walking a region `validate` has accepted.
    ///
    /// Param:
    /// region - []const u8
    ///
    /// Return:
    /// - Iterator
    pub fn begin(region: []const u8) Iterator {
        return .{ .inner = .{ .region = region } };
    }

    /// The next cause, or null at the end of the region.
    ///
    /// Return:
    /// - ?Cause
    pub fn next(self: *Iterator) ?Cause {
        const item = self.inner.next() orelse return null;

        return .{
            .code = @enumFromInt(@intFromEnum(item.kind)),
            .value = item.value,
        };
    }
};

/// First cause of a given code in a validated region.
///
/// Param:
/// region - []const u8
/// code - Code
///
/// Return:
/// - ?Cause
pub fn find(region: []const u8, code: Code) ?Cause {
    var iterator = Iterator.begin(region);

    while (iterator.next()) |item| {
        if (item.code == code) return item;
    }

    return null;
}

/// Write one cause, header then value then padding.
///
/// Note:
/// - Append several by advancing over what each call returns. An ERROR chunk carries one or more
///   causes, an ABORT chunk zero or more.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// code - Code
/// value - []const u8 (cause-specific information, empty for the codes that carry none)
///
/// Return:
/// - []const u8 covering header, value, and padding
/// - error.ZixNoSpace, error.ZixBadLength
pub fn write(out: []u8, code: Code, value: []const u8) Error![]const u8 {
    return parameter.write(out, @enumFromInt(@intFromEnum(code)), value);
}

/// Write a Stale Cookie cause (RFC 9260 3.3.10.3).
///
/// Param:
/// out - []u8
/// staleness_us - u32 (how far past its lifetime the cookie was, in microseconds)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn writeStaleCookie(out: []u8, staleness_us: u32) Error![]const u8 {
    var value: [4]u8 = undefined;
    std.mem.writeInt(u32, &value, staleness_us, .big);

    return write(out, .STALE_COOKIE, &value);
}

/// Write an Invalid Stream Identifier cause (RFC 9260 3.3.10.1).
///
/// Param:
/// out - []u8
/// stream_identifier - u16 (the stream the peer used)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn writeInvalidStreamIdentifier(out: []u8, stream_identifier: u16) Error![]const u8 {
    var value: [4]u8 = undefined;
    std.mem.writeInt(u16, value[0..2], stream_identifier, .big);
    std.mem.writeInt(u16, value[2..4], 0, .big);

    return write(out, .INVALID_STREAM_IDENTIFIER, &value);
}

/// Write a No User Data cause (RFC 9260 3.3.10.9).
///
/// Param:
/// out - []u8
/// tsn - u32 (the TSN of the empty DATA chunk)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn writeNoUserData(out: []u8, tsn: u32) Error![]const u8 {
    var value: [4]u8 = undefined;
    std.mem.writeInt(u32, &value, tsn, .big);

    return write(out, .NO_USER_DATA, &value);
}

/// Write an Unrecognized Chunk Type cause, carrying the chunk as it arrived
/// (RFC 9260 3.3.10.6).
///
/// Param:
/// out - []u8
/// offending - []const u8 (the whole chunk, header included)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeUnrecognizedChunk(out: []u8, offending: []const u8) Error![]const u8 {
    return write(out, .UNRECOGNIZED_CHUNK_TYPE, offending);
}

/// Write a Protocol Violation cause (RFC 9260 3.3.10.13).
///
/// Note:
/// - The text is free-form and goes out to the peer, so keep it about the wire and not about
///   this endpoint's internals.
///
/// Param:
/// out - []u8
/// detail - []const u8 (short description, may be empty)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeProtocolViolation(out: []u8, detail: []const u8) Error![]const u8 {
    return write(out, .PROTOCOL_VIOLATION, detail);
}

/// Write a User-Initiated Abort cause (RFC 9260 3.3.10.12).
///
/// Param:
/// out - []u8
/// reason - []const u8 (what the application gave, may be empty)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeUserInitiatedAbort(out: []u8, reason: []const u8) Error![]const u8 {
    return write(out, .USER_INITIATED_ABORT, reason);
}

/// Write an Out of Resource cause, which carries nothing (RFC 9260 3.3.10.4).
///
/// Param:
/// out - []u8
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn writeOutOfResource(out: []u8) Error![]const u8 {
    return write(out, .OUT_OF_RESOURCE, &.{});
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: error cause write, a stale cookie carries its microseconds" {
    var buf: [16]u8 = undefined;
    const written = try writeStaleCookie(&buf, 250_000);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x03, 0x00, 0x08, 0x00, 0x03, 0xD0, 0x90 }, written);

    try validate(written);
    const cause = find(written, .STALE_COOKIE).?;

    try std.testing.expectEqual(@as(u32, 250_000), cause.staleness().?);
}

test "zix sctp: error cause write, an invalid stream identifier carries the stream" {
    var buf: [16]u8 = undefined;
    const written = try writeInvalidStreamIdentifier(&buf, 7);

    try validate(written);
    const cause = find(written, .INVALID_STREAM_IDENTIFIER).?;

    try std.testing.expectEqual(@as(u16, 7), cause.streamIdentifier().?);

    // The two reserved bytes go out as zero.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, cause.value[2..4]);
}

test "zix sctp: error cause write, no user data carries the offending TSN" {
    var buf: [16]u8 = undefined;
    const written = try writeNoUserData(&buf, 0x01020304);

    try validate(written);
    const cause = find(written, .NO_USER_DATA).?;

    try std.testing.expectEqual(@as(u32, 0x01020304), std.mem.readInt(u32, cause.value[0..4], .big));
}

test "zix sctp: error cause write, out of resource carries nothing" {
    var buf: [8]u8 = undefined;
    const written = try writeOutOfResource(&buf);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x04, 0x00, 0x04 }, written);
    try std.testing.expectEqual(@as(usize, 0), find(written, .OUT_OF_RESOURCE).?.value.len);
}

test "zix sctp: error cause write, an unrecognized chunk is echoed whole" {
    var buf: [32]u8 = undefined;
    const offending: [8]u8 = .{ 99, 0, 0, 8, 1, 2, 3, 4 };
    const written = try writeUnrecognizedChunk(&buf, &offending);

    try validate(written);

    try std.testing.expectEqualSlices(u8, &offending, find(written, .UNRECOGNIZED_CHUNK_TYPE).?.value);
}

test "zix sctp: error cause write, a protocol violation carries its detail padded" {
    var buf: [32]u8 = undefined;
    const written = try writeProtocolViolation(&buf, "bad tag");

    try std.testing.expectEqual(@as(usize, 12), written.len);
    try validate(written);

    try std.testing.expectEqualStrings("bad tag", find(written, .PROTOCOL_VIOLATION).?.value);
}

test "zix sctp: error cause write, a user abort with no reason is a bare header" {
    var buf: [8]u8 = undefined;
    const written = try writeUserInitiatedAbort(&buf, &.{});

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0C, 0x00, 0x04 }, written);
}

test "zix sctp: error cause iterator, several causes come out in order" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try writeOutOfResource(buf[pos..])).len;
    pos += (try writeStaleCookie(buf[pos..], 1_000)).len;
    pos += (try writeProtocolViolation(buf[pos..], "x")).len;

    const region = buf[0..pos];
    try validate(region);

    var iterator = Iterator.begin(region);
    try std.testing.expectEqual(Code.OUT_OF_RESOURCE, iterator.next().?.code);
    try std.testing.expectEqual(@as(u32, 1_000), iterator.next().?.staleness().?);
    try std.testing.expectEqual(Code.PROTOCOL_VIOLATION, iterator.next().?.code);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: error cause read, an unknown code still comes back as a number" {
    var buf: [16]u8 = undefined;
    const written = try write(&buf, @enumFromInt(0x4321), "future");

    try validate(written);

    var iterator = Iterator.begin(written);
    const cause = iterator.next().?;

    try std.testing.expectEqual(@as(u16, 0x4321), @intFromEnum(cause.code));
    try std.testing.expectEqualStrings("future", cause.value);
}

test "zix sctp: error cause read, an accessor on the wrong code returns null" {
    var buf: [16]u8 = undefined;
    const written = try writeOutOfResource(&buf);
    const cause = find(written, .OUT_OF_RESOURCE).?;

    try std.testing.expect(cause.staleness() == null);
    try std.testing.expect(cause.streamIdentifier() == null);
}

test "zix sctp: error cause read, a stale cookie of the wrong size reports nothing" {
    var buf: [16]u8 = undefined;
    const written = try write(&buf, .STALE_COOKIE, &.{ 1, 2 });
    const cause = find(written, .STALE_COOKIE).?;

    try std.testing.expect(cause.staleness() == null);
}

test "zix sctp: error cause write, a buffer too small errors" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeStaleCookie(&buf, 1));
}

test "zix sctp: error cause validate, an empty region is accepted" {
    // An ABORT chunk is allowed to carry no causes at all.
    try validate(&.{});
    try std.testing.expect(find(&.{}, .PROTOCOL_VIOLATION) == null);
}
