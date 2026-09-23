//! zix SCTP heartbeats, HEARTBEAT and HEARTBEAT ACK (RFC 9260 3.3.5, 3.3.6, 8.3).
//!
//! What:
//! - The keepalive pair. One endpoint sends an opaque blob, the other sends the same blob back
//!   untouched, and the round trip proves the path still works and measures how long it took.
//! - A blob layout that makes the answer useful: a nonce so a late ack cannot be mistaken for a
//!   fresh one, and the send time so the round trip needs no separate bookkeeping.
//!
//! Note:
//! - The chunk value is one Heartbeat Info parameter (type 1), not a bare blob. The parameter
//!   header is part of the wire format even though there is only ever one of them.
//! - The responder must echo the parameter byte for byte and must not interpret it. Nothing here
//!   parses an incoming blob on the responder side, it just copies it back.
//! - Under DTLS an association is single-homed (RFC 8261 6.1), so heartbeats confirm liveness
//!   only. There is no second path to probe and no address to fail over to.
//! - A blob that does not decode as a probe is still a valid heartbeat. Only this endpoint's own
//!   acks carry this layout, and a peer is free to use any bytes it likes.

const std = @import("std");

const parameter = @import("parameter.zig");

/// Nonce and send time.
pub const PROBE_LEN: usize = 16;

/// Chunk value size for a probe: one parameter header plus the probe itself.
pub const PROBE_VALUE_LEN: usize = parameter.HEADER_LEN + PROBE_LEN;

/// Framing faults, and a buffer too small to write into.
pub const Error = error{
    /// The chunk value does not hold a Heartbeat Info parameter.
    ZixMissingInfo,
    /// A parameter runs past the end of the chunk value.
    ZixTruncated,
    /// A parameter length below the parameter header size.
    ZixBadLength,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// What this endpoint puts in the blob it sends.
pub const Probe = struct {
    /// Random per heartbeat, so an ack can be matched to the request that earned it.
    nonce: u64,
    /// When the heartbeat went out, on the caller's monotonic millisecond clock.
    sent_ms: u64,

    /// Round trip time, from this probe coming back.
    ///
    /// Note:
    /// - A clock that went backwards gives 0 rather than an enormous number.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds, when the ack arrived)
    ///
    /// Return:
    /// - u64 milliseconds
    pub fn roundTripMs(self: Probe, now_ms: u64) u64 {
        return now_ms -| self.sent_ms;
    }
};

/// Read the blob out of a HEARTBEAT or HEARTBEAT ACK chunk.
///
/// Param:
/// value - []const u8 (chunk value)
///
/// Return:
/// - []const u8 borrowing `value`, the blob to echo or to decode
/// - error.ZixMissingInfo if there is no Heartbeat Info parameter
/// - error.ZixTruncated, error.ZixBadLength if the parameter region is malformed
pub fn readInfo(value: []const u8) Error![]const u8 {
    try parameter.validate(value);

    const found = parameter.find(value, .HEARTBEAT_INFO) orelse return error.ZixMissingInfo;

    return found.value;
}

/// Build the chunk value carrying a blob.
///
/// Note:
/// - Used for both chunks. A HEARTBEAT ACK is the request's blob written back out, so the
///   responder passes what `readInfo` gave it straight into here.
///
/// Param:
/// out - []u8
/// info - []const u8 (opaque blob)
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeInfo(out: []u8, info: []const u8) Error![]const u8 {
    return parameter.write(out, .HEARTBEAT_INFO, info);
}

/// Build the chunk value for a probe this endpoint will recognise coming back.
///
/// Param:
/// out - []u8 (at least PROBE_VALUE_LEN bytes)
/// probe - Probe
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixNoSpace
pub fn writeProbe(out: []u8, probe: Probe) Error![]const u8 {
    var blob: [PROBE_LEN]u8 = undefined;
    std.mem.writeInt(u64, blob[0..8], probe.nonce, .big);
    std.mem.writeInt(u64, blob[8..16], probe.sent_ms, .big);

    return writeInfo(out, &blob);
}

/// Decode a blob this endpoint sent, out of the ack that carried it back.
///
/// Note:
/// - Null for any blob that is not one of ours, which is not an error. A peer chooses its own
///   layout and this endpoint never sees the inside of it.
///
/// Param:
/// value - []const u8 (chunk value of a HEARTBEAT ACK)
///
/// Return:
/// - ?Probe
pub fn readProbe(value: []const u8) ?Probe {
    const blob = readInfo(value) catch return null;

    if (blob.len != PROBE_LEN) return null;

    return .{
        .nonce = std.mem.readInt(u64, blob[0..8], .big),
        .sent_ms = std.mem.readInt(u64, blob[8..16], .big),
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: heartbeat probe, a probe round trips through a request and an ack" {
    const probe: Probe = .{ .nonce = 0x0123456789ABCDEF, .sent_ms = 4_000 };

    var request_buf: [PROBE_VALUE_LEN]u8 = undefined;
    const request = try writeProbe(&request_buf, probe);

    // The responder copies the blob back without looking inside it.
    var ack_buf: [PROBE_VALUE_LEN]u8 = undefined;
    const ack = try writeInfo(&ack_buf, try readInfo(request));

    try std.testing.expectEqualSlices(u8, request, ack);
    try std.testing.expectEqual(probe, readProbe(ack).?);
}

test "zix sctp: heartbeat probe, the round trip is measured off the ack" {
    const probe: Probe = .{ .nonce = 1, .sent_ms = 4_000 };

    try std.testing.expectEqual(@as(u64, 37), probe.roundTripMs(4_037));
}

test "zix sctp: heartbeat probe, a clock that went backwards gives no round trip" {
    const probe: Probe = .{ .nonce = 1, .sent_ms = 4_000 };

    try std.testing.expectEqual(@as(u64, 0), probe.roundTripMs(3_900));
}

test "zix sctp: heartbeat probe, a different nonce is a different blob" {
    var first_buf: [PROBE_VALUE_LEN]u8 = undefined;
    var second_buf: [PROBE_VALUE_LEN]u8 = undefined;

    const first = try writeProbe(&first_buf, .{ .nonce = 1, .sent_ms = 4_000 });
    const second = try writeProbe(&second_buf, .{ .nonce = 2, .sent_ms = 4_000 });

    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "zix sctp: heartbeat info, an opaque blob from a peer is echoed unchanged" {
    var request_buf: [32]u8 = undefined;
    const request = try writeInfo(&request_buf, "peer chose this");

    try std.testing.expectEqualStrings("peer chose this", try readInfo(request));

    var ack_buf: [32]u8 = undefined;
    const ack = try writeInfo(&ack_buf, try readInfo(request));

    try std.testing.expectEqualSlices(u8, request, ack);
}

test "zix sctp: heartbeat info, a blob that is not a probe decodes to nothing" {
    var buf: [32]u8 = undefined;
    const value = try writeInfo(&buf, "not sixteen");

    try std.testing.expect(readProbe(value) == null);
}

test "zix sctp: heartbeat info, an empty blob is legal" {
    var buf: [8]u8 = undefined;
    const value = try writeInfo(&buf, &.{});

    try std.testing.expectEqual(@as(usize, 0), (try readInfo(value)).len);
    try std.testing.expect(readProbe(value) == null);
}

test "zix sctp: heartbeat info, a chunk value with no info parameter errors" {
    var buf: [8]u8 = undefined;
    const value = try parameter.write(&buf, .STATE_COOKIE, &.{});

    try std.testing.expectError(error.ZixMissingInfo, readInfo(value));
    try std.testing.expect(readProbe(value) == null);
}

test "zix sctp: heartbeat info, an empty chunk value errors" {
    try std.testing.expectError(error.ZixMissingInfo, readInfo(&.{}));
}

test "zix sctp: heartbeat info, a malformed parameter region errors" {
    const broken: [4]u8 = .{ 0x00, 0x01, 0x00, 0x40 };

    try std.testing.expectError(error.ZixTruncated, readInfo(&broken));
}

test "zix sctp: heartbeat info, a buffer too small errors" {
    var buf: [PROBE_VALUE_LEN - 1]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeProbe(&buf, .{ .nonce = 1, .sent_ms = 1 }));
}
