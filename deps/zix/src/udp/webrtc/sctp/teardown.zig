//! zix SCTP teardown chunks: SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE, ABORT
//! (RFC 9260 3.3.7, 3.3.8, 3.3.9, 3.3.13).
//!
//! What:
//! - The four chunks that end an association, in one file because they answer one question: how
//!   does this association stop. Three of them do it gracefully, ABORT does it immediately.
//! - The T bit, which SHUTDOWN COMPLETE and ABORT share and nothing else uses.
//!
//! Note:
//! - The graceful close is a three-step handshake. SHUTDOWN says "I have no more data and here
//!   is what I have received", SHUTDOWN ACK answers once the sender's own queue is empty, and
//!   SHUTDOWN COMPLETE closes it. Only SHUTDOWN carries a body.
//! - ABORT is one-way and never answered. RFC 9260 3.3.7 is explicit: an endpoint that receives
//!   an ABORT must not answer with one, or two endpoints that disagree trade aborts forever.
//! - The T bit says the verification tag in the packet was copied from the packet that caused
//!   this one, rather than being the tag the peer expects. It is how an endpoint answers a
//!   packet for an association it has no state for, which it cannot do with the right tag
//!   because it does not know it (RFC 9260 8.4, 8.5.1).
//! - DATA chunks must not be bundled with an ABORT, and control chunks bundled with one must be
//!   placed before it. That is a packet composition rule, enforced where packets are built.

const std = @import("std");

const error_cause = @import("error_cause.zig");

/// Body of a SHUTDOWN chunk: the cumulative TSN ack, and nothing else.
pub const SHUTDOWN_VALUE_LEN: usize = 4;

/// Flag bit saying the verification tag was reflected rather than looked up.
pub const FLAG_T: u8 = 0x01;

/// Everything that stops a teardown chunk from being read or built.
pub const Error = error{
    /// A body shorter than the chunk type requires.
    ZixTruncated,
    /// A cause length below the cause header size.
    ZixBadLength,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// Read the cumulative TSN ack out of a SHUTDOWN chunk.
///
/// Note:
/// - A SHUTDOWN cannot report gaps, so its cumulative TSN ack must never be read as a renege on
///   blocks a previous SACK reported (RFC 9260 3.3.8).
///
/// Param:
/// value - []const u8 (chunk value)
///
/// Return:
/// - u32 cumulative TSN ack
/// - error.ZixTruncated if the body is shorter than 4 bytes
pub fn readShutdown(value: []const u8) Error!u32 {
    if (value.len < SHUTDOWN_VALUE_LEN) return error.ZixTruncated;

    return std.mem.readInt(u32, value[0..4], .big);
}

/// Build the body of a SHUTDOWN chunk.
///
/// Param:
/// out - []u8
/// cumulative_tsn_ack - u32 (highest TSN received with no gap before it)
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixNoSpace
pub fn writeShutdown(out: []u8, cumulative_tsn_ack: u32) Error![]const u8 {
    if (out.len < SHUTDOWN_VALUE_LEN) return error.ZixNoSpace;

    std.mem.writeInt(u32, out[0..4], cumulative_tsn_ack, .big);

    return out[0..SHUTDOWN_VALUE_LEN];
}

/// Chunk flags for a SHUTDOWN COMPLETE or an ABORT.
///
/// Param:
/// reflected - bool (true when the packet's verification tag was copied from the peer's packet)
///
/// Return:
/// - u8
pub fn teardownFlags(reflected: bool) u8 {
    return if (reflected) FLAG_T else 0;
}

/// Whether a SHUTDOWN COMPLETE or ABORT reflected the verification tag.
///
/// Param:
/// flags - u8 (the chunk's flags byte)
///
/// Return:
/// - bool
pub fn isReflected(flags: u8) bool {
    return flags & FLAG_T != 0;
}

/// A parsed ABORT chunk, borrowing the bytes it was read from.
pub const Abort = struct {
    /// Whether the sender reflected the verification tag instead of using the expected one.
    reflected: bool,
    /// The cause region, which may be empty.
    causes: []const u8,

    /// The first cause, for reporting why the peer gave up.
    ///
    /// Return:
    /// - ?error_cause.Cause
    pub fn firstCause(self: Abort) ?error_cause.Cause {
        var iterator = error_cause.Iterator.begin(self.causes);

        return iterator.next();
    }

    /// Whether a given cause is present.
    ///
    /// Param:
    /// code - error_cause.Code
    ///
    /// Return:
    /// - bool
    pub fn hasCause(self: Abort, code: error_cause.Code) bool {
        return error_cause.find(self.causes, code) != null;
    }
};

/// Read an ABORT chunk.
///
/// Note:
/// - An ABORT with broken framing is discarded silently (RFC 9260 3.3.7), so the error here ends
///   in a drop and never in a reply.
///
/// Param:
/// flags - u8 (the chunk's flags byte, which holds the T bit)
/// value - []const u8 (chunk value, zero or more causes)
///
/// Return:
/// - Abort borrowing `value`
/// - error.ZixTruncated, error.ZixBadLength if the cause region is malformed
pub fn readAbort(flags: u8, value: []const u8) Error!Abort {
    try error_cause.validate(value);

    return .{
        .reflected = isReflected(flags),
        .causes = value,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: teardown shutdown, the cumulative TSN round trips" {
    var buf: [8]u8 = undefined;
    const value = try writeShutdown(&buf, 0x0A0B0C0D);

    try std.testing.expectEqual(@as(usize, 4), value.len);
    try std.testing.expectEqual(@as(u32, 0x0A0B0C0D), try readShutdown(value));
}

test "zix sctp: teardown shutdown, a body shorter than the field errors" {
    const short: [3]u8 = .{ 0, 0, 0 };

    try std.testing.expectError(error.ZixTruncated, readShutdown(&short));
}

test "zix sctp: teardown shutdown, a buffer too small errors" {
    var buf: [3]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeShutdown(&buf, 1));
}

test "zix sctp: teardown shutdown, a body longer than the field reads the first four bytes" {
    // Bundling rules never make this happen, but a trailing byte must not turn into an error.
    const padded: [8]u8 = .{ 0, 0, 0, 9, 0xFF, 0xFF, 0xFF, 0xFF };

    try std.testing.expectEqual(@as(u32, 9), try readShutdown(&padded));
}

test "zix sctp: teardown flags, the T bit is set only when the tag was reflected" {
    try std.testing.expectEqual(@as(u8, 0), teardownFlags(false));
    try std.testing.expectEqual(FLAG_T, teardownFlags(true));

    try std.testing.expect(!isReflected(0));
    try std.testing.expect(isReflected(FLAG_T));
}

test "zix sctp: teardown flags, the reserved bits are ignored when reading" {
    // RFC 9260 3.3.7 reserves the other seven bits and says to ignore them on receipt.
    try std.testing.expect(isReflected(0xFF));
    try std.testing.expect(!isReflected(0xFE));
}

test "zix sctp: teardown abort, a bare abort carries no causes" {
    const abort = try readAbort(0, &.{});

    try std.testing.expect(!abort.reflected);
    try std.testing.expect(abort.firstCause() == null);
    try std.testing.expect(!abort.hasCause(.PROTOCOL_VIOLATION));
}

test "zix sctp: teardown abort, the reflected bit and the first cause both come back" {
    var buf: [32]u8 = undefined;
    const causes = try error_cause.writeProtocolViolation(&buf, "bad tag");

    const abort = try readAbort(FLAG_T, causes);

    try std.testing.expect(abort.reflected);
    try std.testing.expectEqual(error_cause.Code.PROTOCOL_VIOLATION, abort.firstCause().?.code);
    try std.testing.expectEqualStrings("bad tag", abort.firstCause().?.value);
}

test "zix sctp: teardown abort, several causes are all searchable" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try error_cause.writeOutOfResource(buf[pos..])).len;
    pos += (try error_cause.writeUserInitiatedAbort(buf[pos..], "closing")).len;

    const abort = try readAbort(0, buf[0..pos]);

    try std.testing.expectEqual(error_cause.Code.OUT_OF_RESOURCE, abort.firstCause().?.code);
    try std.testing.expect(abort.hasCause(.USER_INITIATED_ABORT));
    try std.testing.expect(!abort.hasCause(.STALE_COOKIE));
}

test "zix sctp: teardown abort, a malformed cause region errors" {
    const broken: [4]u8 = .{ 0x00, 0x0C, 0x00, 0x40 };

    try std.testing.expectError(error.ZixTruncated, readAbort(0, &broken));
}

test "zix sctp: teardown abort, a user abort reason survives the round trip" {
    var buf: [32]u8 = undefined;
    const causes = try error_cause.writeUserInitiatedAbort(&buf, "peer went away");

    const abort = try readAbort(0, causes);

    try std.testing.expectEqualStrings("peer went away", abort.firstCause().?.value);
}
