//! zix WebRTC single-port demultiplexing (RFC 7983 7).
//!
//! What:
//! - A WebRTC peer receives STUN, DTLS, and media on ONE UDP port. Which protocol a datagram
//!   belongs to is decided by its first byte alone, and this file is that decision.
//! - `classify` is the whole surface. It is a lookup on one byte, so it sits in front of every
//!   received datagram and must stay cheap.
//!
//! Note:
//! - Routing is not validation. A first byte of 0 says "hand this to STUN", it does not say the
//!   bytes are a well-formed STUN message. Each layer still checks its own framing, which for
//!   STUN means the magic cookie (see stun/message.zig).
//! - ZRTP and TURN_CHANNEL are classified even though zix answers neither. Naming them keeps a
//!   caller from folding them into DROP, so an unexpected peer behaviour shows up as itself
//!   rather than as generic garbage.
//! - The ranges are the RFC 7983 revision, not the original RFC 5764 text. STUN widened from
//!   [0..1] to [0..3] and two ranges were added, so an implementation written against RFC 5764
//!   drops traffic this one accepts.

const std = @import("std");

/// Which protocol owns a datagram, by the RFC 7983 7 first-byte ranges.
pub const Kind = enum {
    /// [0..3], STUN and any later STUN method (RFC 8489).
    STUN,
    /// [16..19], ZRTP (RFC 6189). Not implemented by zix.
    ZRTP,
    /// [20..63], a DTLS record of any content type (RFC 6347).
    DTLS,
    /// [64..79], a TURN channel data message (RFC 8656). Not implemented by zix.
    TURN_CHANNEL,
    /// [128..191], RTP, or RTCP when the two share a port (RFC 3550, RFC 5761).
    RTP,
    /// Outside every known range, or an empty datagram. RFC 7983 7 requires dropping these.
    DROP,
};

/// Route a received datagram to the layer that owns it (RFC 7983 7).
///
/// Note:
/// - An empty datagram is DROP. There is no first byte to route on, and a zero-length UDP
///   payload is legal on the wire, so this is a real case and not a defensive check.
///
/// Param:
/// datagram - []const u8 (one received datagram, read at index 0 only)
///
/// Return:
/// - Kind
pub fn classify(datagram: []const u8) Kind {
    if (datagram.len == 0) return .DROP;

    return switch (datagram[0]) {
        0...3 => .STUN,
        16...19 => .ZRTP,
        20...63 => .DTLS,
        64...79 => .TURN_CHANNEL,
        128...191 => .RTP,
        else => .DROP,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// One datagram whose first byte is `leading`, so a test reads as a packet and not as an index.
fn datagramLedBy(leading: u8) [4]u8 {
    return .{ leading, 0, 0, 0 };
}

test "zix webrtc: demux classify, every range boundary lands on the right side" {
    const cases = [_]struct { leading: u8, kind: Kind }{
        .{ .leading = 0, .kind = .STUN },
        .{ .leading = 3, .kind = .STUN },
        .{ .leading = 4, .kind = .DROP },
        .{ .leading = 15, .kind = .DROP },
        .{ .leading = 16, .kind = .ZRTP },
        .{ .leading = 19, .kind = .ZRTP },
        .{ .leading = 20, .kind = .DTLS },
        .{ .leading = 63, .kind = .DTLS },
        .{ .leading = 64, .kind = .TURN_CHANNEL },
        .{ .leading = 79, .kind = .TURN_CHANNEL },
        .{ .leading = 80, .kind = .DROP },
        .{ .leading = 127, .kind = .DROP },
        .{ .leading = 128, .kind = .RTP },
        .{ .leading = 191, .kind = .RTP },
        .{ .leading = 192, .kind = .DROP },
        .{ .leading = 255, .kind = .DROP },
    };

    for (cases) |case| {
        const datagram = datagramLedBy(case.leading);
        try std.testing.expectEqual(case.kind, classify(&datagram));
    }
}

test "zix webrtc: demux classify, the 256 first bytes split into the sizes the rfc names" {
    var stun: usize = 0;
    var zrtp: usize = 0;
    var dtls: usize = 0;
    var turn: usize = 0;
    var rtp: usize = 0;
    var drop: usize = 0;

    for (0..256) |i| {
        const datagram = datagramLedBy(@intCast(i));
        switch (classify(&datagram)) {
            .STUN => stun += 1,
            .ZRTP => zrtp += 1,
            .DTLS => dtls += 1,
            .TURN_CHANNEL => turn += 1,
            .RTP => rtp += 1,
            .DROP => drop += 1,
        }
    }

    try std.testing.expectEqual(@as(usize, 4), stun);
    try std.testing.expectEqual(@as(usize, 4), zrtp);
    try std.testing.expectEqual(@as(usize, 44), dtls);
    try std.testing.expectEqual(@as(usize, 16), turn);
    try std.testing.expectEqual(@as(usize, 64), rtp);
    try std.testing.expectEqual(@as(usize, 124), drop);
    try std.testing.expectEqual(@as(usize, 256), stun + zrtp + dtls + turn + rtp + drop);
}

test "zix webrtc: demux classify, an empty datagram is dropped" {
    try std.testing.expectEqual(Kind.DROP, classify(&[_]u8{}));
}

test "zix webrtc: demux classify, real packet headers route to their own layer" {
    // A STUN binding request: type 0x0001, length 0, magic cookie, transaction id.
    var binding_request: [20]u8 = @splat(0);
    binding_request[1] = 0x01;
    binding_request[4] = 0x21;
    binding_request[5] = 0x12;
    binding_request[6] = 0xA4;
    binding_request[7] = 0x42;
    try std.testing.expectEqual(Kind.STUN, classify(&binding_request));

    // DTLS 1.2 records, by content type: handshake (22), application data (23), alert (21).
    const dtls_handshake = [_]u8{ 22, 0xfe, 0xfd, 0, 0 };
    const dtls_app_data = [_]u8{ 23, 0xfe, 0xfd, 0, 0 };
    const dtls_alert = [_]u8{ 21, 0xfe, 0xfd, 0, 0 };
    try std.testing.expectEqual(Kind.DTLS, classify(&dtls_handshake));
    try std.testing.expectEqual(Kind.DTLS, classify(&dtls_app_data));
    try std.testing.expectEqual(Kind.DTLS, classify(&dtls_alert));

    // RTP and RTCP both carry version 2 in the top bits of byte 0, so both land in [128..191].
    const rtp_packet = [_]u8{ 0x80, 0x60, 0, 1 };
    const rtcp_sender_report = [_]u8{ 0x80, 200, 0, 6 };
    try std.testing.expectEqual(Kind.RTP, classify(&rtp_packet));
    try std.testing.expectEqual(Kind.RTP, classify(&rtcp_sender_report));
}

test "zix webrtc: demux classify, routing does not imply the payload is valid" {
    // Byte 0 says STUN, but the magic cookie is missing. Demux still routes it, the STUN layer
    // is what rejects it.
    const not_really_stun = [_]u8{ 0x00, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectEqual(Kind.STUN, classify(&not_really_stun));

    // Byte 0 says DTLS, but the rest is nothing of the sort.
    const not_really_dtls = [_]u8{ 22, 0xff, 0xff };
    try std.testing.expectEqual(Kind.DTLS, classify(&not_really_dtls));
}
