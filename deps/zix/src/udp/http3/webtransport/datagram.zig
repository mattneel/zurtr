//! zix WebTransport datagrams: the QUIC DATAGRAM frame (RFC 9221) and the HTTP/3 datagram that
//! carries a WebTransport payload inside it (RFC 9297 2, draft-ietf-webtrans-http3-16 4.5).
//!
//! What:
//! - The DATAGRAM frame codec (RFC 9221 4): type 0x30 with the data running to the end of the packet,
//!   type 0x31 with an explicit length, and the max_datagram_frame_size transport parameter (0x20) that
//!   gates both directions.
//! - The HTTP/3 datagram codec (RFC 9297 2.1): the QUIC DATAGRAM payload starts with the Quarter Stream
//!   ID, and everything after it is the HTTP Datagram Payload. WebTransport puts its payload there
//!   unmodified (4.5), so the session a datagram belongs to is the CONNECT stream id the quarter
//!   stream id came from.
//! - The size arithmetic a sender needs before it queues anything: a DATAGRAM frame cannot be
//!   fragmented, so the app payload must fit the peer's advertised frame limit minus the frame header
//!   and the quarter stream id.
//! - Pure buffer arithmetic, no io, no allocation. Proven against the RFC layouts, the size rules, and
//!   crafted byte streams in the tests below.

const std = @import("std");

const varint = @import("../varint.zig");

/// The QUIC DATAGRAM frame types and the transport parameter that advertises them (RFC 9221 3 / 4).
pub const frame_type = struct {
    /// The DATAGRAM frame with the data running to the end of the packet.
    pub const without_length: u64 = 0x30;
    /// The DATAGRAM frame with an explicit length.
    pub const with_length: u64 = 0x31;
    /// The max_datagram_frame_size transport parameter (RFC 9221 3).
    pub const transport_param: u64 = 0x20;
};

/// The HTTP/3 error code for a datagram that cannot be attributed (RFC 9297 2.1).
pub const h3_datagram_error: u64 = 0x33;

/// The SETTINGS identifier that turns HTTP/3 datagrams on (RFC 9297 2.1.1).
pub const settings_h3_datagram: u64 = 0x33;

/// The largest legal quarter stream id: a QUIC stream id is at most 2^62 - 1, so its quarter is at most
/// 2^60 - 1 (RFC 9297 2.1).
pub const max_quarter_stream_id: u64 = (1 << 60) - 1;

// --------------------------------------------------------------- //
// QUIC DATAGRAM frame (RFC 9221)
// --------------------------------------------------------------- //

/// A parsed DATAGRAM frame.
pub const Frame = struct {
    /// The datagram bytes, borrowing the packet payload.
    data: []const u8,
    /// Bytes of the payload the frame occupied (type, optional length, data).
    consumed: usize,
    /// Whether the frame carried the explicit length field (type 0x31).
    explicit_length: bool,
};

/// Parse a DATAGRAM frame at the start of `buf` (RFC 9221 4). Returns null when the frame is not one
/// this binding reads, or is truncated.
///
/// Note:
/// - The type 0x30 form has no length, so its data runs to the end of the packet: a caller that walks a
///   payload must treat it as the last frame.
pub fn parseFrame(buf: []const u8) ?Frame {
    const type_vi = varint.read(buf) catch return null;

    switch (type_vi.value) {
        frame_type.without_length => return .{
            .data = buf[type_vi.len..],
            .consumed = buf.len,
            .explicit_length = false,
        },
        frame_type.with_length => {
            const length_vi = varint.read(buf[type_vi.len..]) catch return null;
            const header = type_vi.len + length_vi.len;
            const data_len: usize = std.math.cast(usize, length_vi.value) orelse return null;
            if (data_len > buf.len - header) return null;

            return .{
                .data = buf[header..][0..data_len],
                .consumed = header + data_len,
                .explicit_length = true,
            };
        },
        else => return null,
    }
}

/// The frame size a datagram of `data_len` payload bytes needs with the explicit length (type 0x31),
/// which is what the max_datagram_frame_size limit counts (RFC 9221 3).
pub fn encodedSize(data_len: usize) usize {
    return 1 + varint.encodedLen(data_len) + data_len;
}

/// Write a DATAGRAM frame with an explicit length (type 0x31). Returns the bytes written, or null when
/// it does not fit.
///
/// Note:
/// - The explicit form is what a sender uses when the frame shares a packet with other frames. This
///   engine always seals a datagram as the only frame of its packet, so the length is redundant on the
///   wire but keeps the frame self-describing for any receiver.
pub fn writeFrame(out: []u8, data: []const u8) ?usize {
    if (encodedSize(data.len) > out.len) return null;

    var pos: usize = 0;
    out[pos] = @intCast(frame_type.with_length);
    pos += 1;
    pos += varint.write(out[pos..], data.len);
    @memcpy(out[pos..][0..data.len], data);
    pos += data.len;

    return pos;
}

/// Whether a datagram of `data_len` payload bytes may be sent to a peer that advertised
/// `peer_max_frame_size` (RFC 9221 3: the limit counts the whole frame, including its header).
///
/// Note:
/// - A peer that advertised nothing (null) does not support DATAGRAM frames at all, and an endpoint
///   MUST NOT send one to it.
pub fn sendable(peer_max_frame_size: ?u64, data_len: usize) bool {
    const limit = peer_max_frame_size orelse return false;

    return encodedSize(data_len) <= limit;
}

// --------------------------------------------------------------- //
// HTTP/3 datagram (RFC 9297 2.1)
// --------------------------------------------------------------- //

/// The quarter stream id of a CONNECT stream: the stream id divided by four (RFC 9297 2.1). Null when
/// the id is not a client-initiated bidirectional stream id, which is the only id a WebTransport
/// session may be keyed by (4.1 of the binding).
pub fn quarterStreamId(session_id: u64) ?u64 {
    if (session_id % 4 != 0) return null;

    return session_id / 4;
}

/// The session (CONNECT stream) id a quarter stream id refers to. Null when the value is past the
/// largest legal quarter, which is an H3_DATAGRAM_ERROR at the receiver (RFC 9297 2.1).
pub fn sessionIdFromQuarter(quarter: u64) ?u64 {
    if (quarter > max_quarter_stream_id) return null;

    return quarter * 4;
}

/// A parsed HTTP/3 datagram: the session it belongs to, and the payload after the quarter stream id.
pub const Datagram = struct {
    /// The CONNECT stream id this datagram belongs to.
    session_id: u64,
    /// The WebTransport payload (RFC 9297 2.1's HTTP Datagram Payload, unmodified, 4.5).
    payload: []const u8,
};

/// The errors parsing an HTTP/3 datagram raises, both H3_DATAGRAM_ERROR at the connection level.
pub const DatagramError = error{
    /// The payload ended inside the Quarter Stream ID field (RFC 9297 2.1).
    ZixTruncated,
    /// The Quarter Stream ID is past the largest legal value (RFC 9297 2.1).
    ZixDatagramError,
};

/// Parse the payload of a QUIC DATAGRAM frame as an HTTP/3 datagram (RFC 9297 2.1): the quarter stream
/// id, then the payload.
pub fn parseHttp3(buf: []const u8) DatagramError!Datagram {
    const quarter = varint.read(buf) catch return error.ZixTruncated;
    const session_id = sessionIdFromQuarter(quarter.value) orelse return error.ZixDatagramError;

    return .{ .session_id = session_id, .payload = buf[quarter.len..] };
}

/// Write an HTTP/3 datagram: the quarter stream id for `session_id`, then `payload`. Returns the bytes
/// written, or null when `session_id` is not a CONNECT stream id or the datagram does not fit.
pub fn writeHttp3(out: []u8, session_id: u64, payload: []const u8) ?usize {
    const quarter = quarterStreamId(session_id) orelse return null;

    const needed = varint.encodedLen(quarter) + payload.len;
    if (needed > out.len) return null;

    var pos: usize = 0;
    pos += varint.write(out[pos..], quarter);
    @memcpy(out[pos..][0..payload.len], payload);
    pos += payload.len;

    return pos;
}

/// The WebTransport payload bytes that fit one datagram for `session_id`, given the peer's advertised
/// max_datagram_frame_size. Accounts for both layers of framing: the QUIC DATAGRAM frame (its type byte
/// and the length varint) and the HTTP/3 datagram's quarter stream id.
///
/// Note:
/// - Zero means nothing fits, which is what a peer that advertised a frame limit below the framing
///   overhead gets. A DATAGRAM frame cannot be fragmented (RFC 9221 5), so the caller refuses the send
///   instead of splitting the payload.
pub fn maxPayloadBytes(peer_max_frame_size: ?u64, session_id: u64) usize {
    const limit = peer_max_frame_size orelse return 0;
    const quarter = quarterStreamId(session_id) orelse return 0;
    const quarter_len = varint.encodedLen(quarter);

    // The frame's data field is the quarter varint plus the payload, and its own length varint depends
    // on how large that data field is. The four QUIC varint length classes are tried in order, and the
    // one that describes the data field its own arithmetic produces is the answer (RFC 9000 16).
    const length_classes = [_]u64{ 1, 2, 4, 8 };
    for (length_classes) |len_class| {
        if (limit <= 1 + len_class) continue;

        const data = limit - 1 - len_class;
        if (varint.encodedLen(data) != len_class) continue;
        if (data < quarter_len) return 0;

        return @intCast(data - quarter_len);
    }

    return 0;
}

/// Whether a WebTransport payload of `payload_len` bytes fits one datagram for `session_id` within the
/// peer's advertised max_datagram_frame_size.
pub fn payloadFits(peer_max_frame_size: ?u64, session_id: u64, payload_len: usize) bool {
    return payload_len <= maxPayloadBytes(peer_max_frame_size, session_id);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix webtransport: RFC 9221 4 DATAGRAM frame forms" {
    // Type 0x31 with a length: type, length, data.
    const with_len = hexBytes("31056162636465");
    const parsed = parseFrame(&with_len).?;
    try std.testing.expectEqualStrings("abcde", parsed.data);
    try std.testing.expectEqual(@as(usize, 7), parsed.consumed);
    try std.testing.expect(parsed.explicit_length);

    // Type 0x30 has no length, so the data runs to the end of the buffer it was given.
    const no_len = hexBytes("30" ++ "6162636465");
    const running = parseFrame(&no_len).?;
    try std.testing.expectEqualStrings("abcde", running.data);
    try std.testing.expectEqual(no_len.len, running.consumed);
    try std.testing.expect(!running.explicit_length);

    // An empty datagram is legal in both forms.
    try std.testing.expectEqual(@as(usize, 0), parseFrame(&hexBytes("3100")).?.data.len);
    try std.testing.expectEqual(@as(usize, 0), parseFrame(&hexBytes("30")).?.data.len);

    // A length that overruns the buffer, and a truncated header, are both not-a-frame rather than a
    // frame with invented bytes.
    try std.testing.expect(parseFrame(&hexBytes("3105" ++ "6162")) == null);
    try std.testing.expect(parseFrame(&hexBytes("31")) == null);
    try std.testing.expect(parseFrame("") == null);

    // A frame type this module does not model is not a datagram.
    try std.testing.expect(parseFrame(&hexBytes("0800")) == null);
}

test "zix webtransport: the DATAGRAM frame encodes to the size the peer limit counts" {
    var buf: [64]u8 = undefined;
    const written = writeFrame(&buf, "hello").?;

    try std.testing.expectEqual(encodedSize(5), written);
    try std.testing.expectEqual(@as(usize, 7), written);
    try std.testing.expectEqualSlices(u8, &hexBytes("3105" ++ "68656c6c6f"), buf[0..written]);

    // Round trip through the parser.
    const back = parseFrame(buf[0..written]).?;
    try std.testing.expectEqualStrings("hello", back.data);

    // A payload whose length needs a 2-byte varint still fits the size arithmetic, and a frame larger
    // than the destination is refused rather than truncated.
    var big: [300]u8 = @splat(0x77);
    var big_buf: [320]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1 + 2 + 300), encodedSize(300));
    const big_written = writeFrame(&big_buf, &big).?;
    try std.testing.expectEqual(encodedSize(300), big_written);
    try std.testing.expectEqual(@as(usize, 300), parseFrame(big_buf[0..big_written]).?.data.len);
    try std.testing.expect(writeFrame(&buf, &big) == null); // 64-byte destination, a 303-byte frame does not fit
}

test "zix webtransport: RFC 9221 3 the peer limit gates every send" {
    // The limit counts the whole frame, so a 128-byte limit carries 125 payload bytes with the 0x31
    // form (1 type byte, a 2-byte length for anything past 63, then the payload) and not one more.
    try std.testing.expect(sendable(128, 125));
    try std.testing.expect(!sendable(128, 126));

    // A limit below the two header bytes a framed datagram needs carries nothing.
    try std.testing.expect(sendable(2, 0)); // an empty datagram is type + a one-byte length
    try std.testing.expect(!sendable(1, 0));

    // A peer that advertised nothing does not support datagrams at all.
    try std.testing.expect(!sendable(null, 0));
    try std.testing.expect(!sendable(0, 0));

    // The recommended value accepts any datagram that fits a QUIC packet (RFC 9221 3).
    try std.testing.expect(sendable(65535, 1200));
}

test "zix webtransport: RFC 9297 2.1 the quarter stream id carries the session" {
    try std.testing.expectEqual(@as(u64, 0), quarterStreamId(0).?);
    try std.testing.expectEqual(@as(u64, 1), quarterStreamId(4).?);
    try std.testing.expectEqual(@as(u64, 3), quarterStreamId(12).?);

    // Only a client-initiated bidirectional stream id names a WebTransport session (4.1).
    try std.testing.expect(quarterStreamId(1) == null);
    try std.testing.expect(quarterStreamId(2) == null);
    try std.testing.expect(quarterStreamId(3) == null);

    try std.testing.expectEqual(@as(u64, 0), sessionIdFromQuarter(0).?);
    try std.testing.expectEqual(@as(u64, 12), sessionIdFromQuarter(3).?);
    try std.testing.expectEqual(max_quarter_stream_id * 4, sessionIdFromQuarter(max_quarter_stream_id).?);

    // Past the largest legal quarter is H3_DATAGRAM_ERROR at the receiver.
    try std.testing.expect(sessionIdFromQuarter(max_quarter_stream_id + 1) == null);
}

test "zix webtransport: the HTTP/3 datagram round trips through the quarter stream id" {
    var buf: [64]u8 = undefined;

    // Session 4 (quarter 1) with a payload: quarter varint, then the payload unmodified.
    const written = writeHttp3(&buf, 4, "ping").?;
    try std.testing.expectEqualSlices(u8, &hexBytes("01" ++ "70696e67"), buf[0..written]);

    const parsed = try parseHttp3(buf[0..written]);
    try std.testing.expectEqual(@as(u64, 4), parsed.session_id);
    try std.testing.expectEqualStrings("ping", parsed.payload);

    // Session 0 (quarter 0) is the first request stream, and an empty payload is legal.
    const zero = writeHttp3(&buf, 0, "").?;
    const zero_parsed = try parseHttp3(buf[0..zero]);
    try std.testing.expectEqual(@as(u64, 0), zero_parsed.session_id);
    try std.testing.expectEqual(@as(usize, 0), zero_parsed.payload.len);

    // A session id that is not a CONNECT stream id cannot be framed at all.
    try std.testing.expect(writeHttp3(&buf, 7, "x") == null);

    // A payload cut inside the quarter stream id is H3_DATAGRAM_ERROR, and so is an oversized quarter.
    try std.testing.expectError(error.ZixTruncated, parseHttp3(""));
    try std.testing.expectError(error.ZixTruncated, parseHttp3(&hexBytes("c0")));
    // 2^61 as an 8-byte varint is past the largest legal quarter stream id (2^60 - 1).
    try std.testing.expectError(error.ZixDatagramError, parseHttp3(&hexBytes("e0" ++ "00000000000000")));
}

test "zix webtransport: the payload budget subtracts the frame and quarter overhead" {
    // A 1200-byte frame limit over session 0: the frame spends its type byte, a 2-byte length varint
    // for the 1197-byte data field, and a 1-byte quarter varint, leaving 1196 payload bytes.
    try std.testing.expectEqual(@as(usize, 1196), maxPayloadBytes(1200, 0));

    // Session 256 (quarter 64) spends a 2-byte quarter varint, so the budget drops by one.
    try std.testing.expectEqual(@as(usize, 1195), maxPayloadBytes(1200, 256));

    // The recommended 65535 limit carries a full app datagram over the smallest session.
    try std.testing.expectEqual(@as(usize, 65529), maxPayloadBytes(65535, 0));

    // A limit that cannot even hold the framing leaves no payload, and a peer that advertised nothing
    // leaves none either: the caller refuses the send.
    try std.testing.expectEqual(@as(usize, 0), maxPayloadBytes(3, 0));
    try std.testing.expectEqual(@as(usize, 0), maxPayloadBytes(null, 0));

    // What the budget promises is exactly what the peer limit accepts (RFC 9221 3 counts the frame):
    // the largest payload frames into a QUIC DATAGRAM frame the limit holds, and one more byte does not.
    const budget = maxPayloadBytes(1200, 0);
    var payload: [1200]u8 = @splat(0x33);
    var frame_buf: [1300]u8 = undefined;
    const h3_len = writeHttp3(&frame_buf, 0, payload[0..budget]) orelse return error.TestUnexpectedResult;
    try std.testing.expect(sendable(1200, h3_len));
    try std.testing.expect(payloadFits(1200, 0, budget));
    try std.testing.expect(!payloadFits(1200, 0, budget + 1));

    const over_len = writeHttp3(&frame_buf, 0, payload[0 .. budget + 1]).?;
    try std.testing.expect(!sendable(1200, over_len));
}
