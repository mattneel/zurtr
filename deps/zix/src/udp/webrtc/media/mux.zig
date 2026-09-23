//! zix RTP and RTCP on one port (RFC 5761 4).
//!
//! What:
//! - demux.zig gets a datagram as far as "this is media". This file finishes the job: media on a
//!   WebRTC port is RTP and RTCP together, and which one a packet is comes from its second byte.
//!
//! Note:
//! - The RTCP packet type field sits where RTP keeps the marker bit and the payload type. So the
//!   test is on the second byte with the top bit cleared: 64 through 95 is RTCP, anything else is
//!   RTP. Reading the byte whole instead makes every marked RTP packet look like RTCP.
//! - The same rule forbids RTP payload types 64 through 95 outright while muxing, which is why
//!   `isMuxSafePayloadType` exists. A sender that picks one produces packets no muxed receiver
//!   can route, including its own loopback.
//! - Routing is not validation, the same as in demux.zig. A second byte of 200 says "hand this to
//!   RTCP", not "this is a well-formed sender report".

const std = @import("std");

/// Lowest payload type value that means RTCP (RFC 5761 4).
pub const RTCP_LOW: u8 = 64;

/// Highest payload type value that means RTCP (RFC 5761 4).
pub const RTCP_HIGH: u8 = 95;

/// Bytes needed before the decision can be made at all.
pub const MIN_LEN: usize = 2;

/// Which of the two protocols owns a media datagram.
pub const Kind = enum {
    /// A media packet (RFC 3550 5.1).
    RTP,
    /// A control packet, possibly a compound one (RFC 3550 6).
    RTCP,
};

/// Route a media datagram to RTP or RTCP (RFC 5761 4).
///
/// Note:
/// - Returns null for a datagram with no second byte, which is a real case: a zero-length or
///   one-byte UDP payload is legal on the wire and belongs to neither.
///
/// Param:
/// datagram - []const u8 (read at index 1 only)
///
/// Return:
/// - ?Kind
pub fn classify(datagram: []const u8) ?Kind {
    if (datagram.len < MIN_LEN) return null;

    return if (isRtcpType(@intCast(datagram[1] & 0x7F))) .RTCP else .RTP;
}

/// Whether a payload type value in the range 0 to 127 belongs to RTCP.
///
/// Param:
/// value - u7 (the second byte with the marker bit cleared)
///
/// Return:
/// - bool
pub fn isRtcpType(value: u7) bool {
    return value >= RTCP_LOW and value <= RTCP_HIGH;
}

/// Whether an RTP payload type can be used at all when muxing (RFC 5761 4).
///
/// Note:
/// - Dynamic types belong in 96 to 127, which is where every WebRTC negotiation puts them.
///
/// Param:
/// payload_type - u7
///
/// Return:
/// - bool
pub fn isMuxSafePayloadType(payload_type: u7) bool {
    return !isRtcpType(payload_type);
}

// --------------------------------------------------------------------------------------- //
// test cases

const rtp = @import("rtp.zig");

test "zix media: mux classify, the control packet types route to rtcp" {
    // Sender report, receiver report, SDES, BYE, APP, and the two feedback types.
    const types = [_]u8{ 200, 201, 202, 203, 204, 205, 206 };

    for (types) |packet_type| {
        const datagram = [_]u8{ 0x80, packet_type, 0, 0 };

        try std.testing.expectEqual(Kind.RTCP, classify(&datagram).?);
    }
}

test "zix media: mux classify, a dynamic payload type routes to rtp" {
    for (96..128) |payload_type| {
        const datagram = [_]u8{ 0x80, @intCast(payload_type), 0, 0 };

        try std.testing.expectEqual(Kind.RTP, classify(&datagram).?);
    }
}

test "zix media: mux classify, the marker bit does not turn rtp into rtcp" {
    // Payload type 72 with the marker set is byte 200, which is also the sender report number.
    // Reading the byte whole would call this RTCP.
    const marked = [_]u8{ 0x80, 0x80 | 96, 0, 0 };
    try std.testing.expectEqual(Kind.RTP, classify(&marked).?);

    // And the type that really is 72 stays RTCP whether or not the top bit is set.
    const conflicting = [_]u8{ 0x80, 72, 0, 0 };
    try std.testing.expectEqual(Kind.RTCP, classify(&conflicting).?);
}

test "zix media: mux classify, the range boundaries land on the right side" {
    const cases = [_]struct { value: u8, kind: Kind }{
        .{ .value = 0, .kind = .RTP },
        .{ .value = 63, .kind = .RTP },
        .{ .value = 64, .kind = .RTCP },
        .{ .value = 95, .kind = .RTCP },
        .{ .value = 96, .kind = .RTP },
        .{ .value = 127, .kind = .RTP },
    };

    for (cases) |case| {
        const plain = [_]u8{ 0x80, case.value, 0, 0 };
        const marked = [_]u8{ 0x80, case.value | 0x80, 0, 0 };

        try std.testing.expectEqual(case.kind, classify(&plain).?);
        try std.testing.expectEqual(case.kind, classify(&marked).?);
    }
}

test "zix media: mux classify, a datagram with no second byte belongs to neither" {
    try std.testing.expect(classify(&[_]u8{}) == null);
    try std.testing.expect(classify(&[_]u8{0x80}) == null);
    try std.testing.expect(classify(&[_]u8{ 0x80, 96 }) != null);
}

test "zix media: mux classify, the 128 payload type values split into the sizes the rfc names" {
    var as_rtp: usize = 0;
    var as_rtcp: usize = 0;

    for (0..128) |value| {
        const datagram = [_]u8{ 0x80, @intCast(value), 0, 0 };
        switch (classify(&datagram).?) {
            .RTP => as_rtp += 1,
            .RTCP => as_rtcp += 1,
        }
    }

    try std.testing.expectEqual(@as(usize, 32), as_rtcp);
    try std.testing.expectEqual(@as(usize, 96), as_rtp);
}

test "zix media: mux isMuxSafePayloadType, the blocked range is refused" {
    try std.testing.expect(isMuxSafePayloadType(0));
    try std.testing.expect(isMuxSafePayloadType(63));
    try std.testing.expect(!isMuxSafePayloadType(64));
    try std.testing.expect(!isMuxSafePayloadType(72));
    try std.testing.expect(!isMuxSafePayloadType(95));
    try std.testing.expect(isMuxSafePayloadType(96));
    try std.testing.expect(isMuxSafePayloadType(127));
}

test "zix media: mux classify, a packet rtp.zig wrote routes back to rtp" {
    // The two files have to agree on where the payload type sits, so this reads one through the
    // other rather than trusting a hand-built byte.
    var buf: [16]u8 = undefined;
    const written = try rtp.write(&buf, .{
        .marker = true,
        .payload_type = 111,
        .sequence = 7,
        .timestamp = 0,
        .ssrc = 1,
    }, &.{});

    try std.testing.expectEqual(Kind.RTP, classify(written).?);
    try std.testing.expect(isMuxSafePayloadType((try rtp.read(written)).header.payload_type));
}
