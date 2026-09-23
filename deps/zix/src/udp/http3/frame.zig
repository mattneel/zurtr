//! zix HTTP/3 QUIC frame parsing (RFC 9000 12.4 / 12.5 / 19, RFC 9221 4,
//! draft-ietf-quic-reliable-stream-reset-09 4, Layer Q).
//!
//! What:
//! - Reads frames out of a packet payload and enforces the two framing rules an endpoint MUST apply:
//!   an unknown frame type is a FRAME_ENCODING_ERROR (12.4), and a known frame in a packet type that
//!   does not permit it is a PROTOCOL_VIOLATION (12.5, Table 3).
//! - The frame type MUST use its shortest encoding (12.4), so a non-minimal type varint is rejected.
//!   Proven against crafted frames and the Table 3 permission matrix in the tests below.
//! - The two extension frames the WebTransport binding needs: DATAGRAM (RFC 9221 4, types 0x30 / 0x31)
//!   carries application payloads with no retransmission, and RESET_STREAM_AT (reliable stream reset 4,
//!   type 0x24) aborts a stream while still delivering its reliable prefix, which is what keeps the
//!   session id at the head of a WebTransport data stream readable to a peer that is being reset.
//!
//! Note:
//! - parseFrame is live. framePermittedIn (the Table 3 per-space permission matrix) plus Space and
//!   FrameError are implemented and tested but not enforced in the serve path yet (deferred).
//! - Both extension frames belong to the application data space alone, so framePermittedIn rejects them
//!   in Initial and Handshake (RFC 9221 5, reliable stream reset 4). The rules that need connection
//!   state stay with the caller: a DATAGRAM frame larger than the advertised max_datagram_frame_size,
//!   or one received when none was advertised, is a PROTOCOL_VIOLATION (RFC 9221 3), and a
//!   RESET_STREAM_AT that violates flow control is a FLOW_CONTROL_ERROR (reliable stream reset 4).

const std = @import("std");

const varint = @import("varint.zig");

/// The version-1 packet number spaces, named by the packet type that carries them (RFC 9000 12.5).
pub const Space = enum { initial, handshake, zero_rtt, one_rtt };

/// A parsed frame: the RFC 9000 19 subset this engine reads plus the two extension frames the
/// WebTransport binding needs. The rest decode the same way and arrive in later modules (ACK in
/// flow.zig, close frames in close.zig). Connection-id frames are modeled in stream.zig, not yet wired
/// into the serve path (NEW_CONNECTION_ID is skipped for now).
pub const Frame = union(enum) {
    /// A run of PADDING bytes (19.1), coalesced into one length.
    padding: usize,
    /// PING (19.2), no fields.
    ping,
    /// CRYPTO (19.6): an offset and the carried handshake bytes.
    crypto: struct { offset: u64, data: []const u8 },
    /// STREAM (19.8): id, offset, the FIN marker, and the stream bytes.
    stream: struct { id: u64, offset: u64, fin: bool, data: []const u8 },
    /// DATAGRAM (RFC 9221 4, types 0x30 / 0x31): the datagram bytes, borrowing the payload. The 0x31
    /// form carries an explicit length; the 0x30 form has none, so its data runs to the end of the
    /// payload and an empty datagram is a zero-length slice.
    datagram: []const u8,
    /// RESET_STREAM_AT (reliable stream reset 4, type 0x24): a reset that still delivers the stream
    /// prefix up to the reliable size, so the peer can read the session id a WebTransport data stream
    /// puts before the application bytes it is abandoning.
    reset_stream_at: ResetStreamAt,
};

/// The fields of a RESET_STREAM_AT frame (reliable stream reset 4): RESET_STREAM's three fields plus
/// the reliable size, the amount of stream data the sender still guarantees.
pub const ResetStreamAt = struct {
    /// The stream being terminated.
    stream_id: u64,
    /// The application protocol error code saying why (RFC 9000 20.2).
    error_code: u64,
    /// The final size of the stream by the sender, in bytes.
    final_size: u64,
    /// The bytes from the head of the stream the receiver must still deliver to its application. Zero
    /// is legal and makes the frame plain RESET_STREAM semantics.
    reliable_size: u64,
};

/// One parsed frame plus how many bytes it consumed from the payload.
pub const ParsedFrame = struct { frame: Frame, len: usize };

/// The framing errors an endpoint MUST raise (RFC 9000 12.4 / 12.5).
pub const FrameError = error{
    ZixTruncated,
    /// Unknown frame type, or a malformed known frame (e.g. empty NEW_TOKEN): FRAME_ENCODING_ERROR.
    ZixFrameEncodingError,
    /// A frame type encoded on more bytes than necessary: PROTOCOL_VIOLATION (12.4).
    ZixProtocolViolation,
};

/// Parse one frame from the front of a payload (RFC 9000 19). The frame type MUST use its shortest
/// encoding, and an unknown type is a FRAME_ENCODING_ERROR.
///
/// Note:
/// - A DATAGRAM frame without a length (type 0x30) runs to the end of the payload, so `len` is the rest
///   of the buffer and a caller walking a payload MUST treat it as the last frame (RFC 9221 4).
pub fn parseFrame(data: []const u8) FrameError!ParsedFrame {
    const type_vi = varint.read(data) catch return error.ZixTruncated;
    if (type_vi.len != varint.encodedLen(type_vi.value)) return error.ZixProtocolViolation;

    const frame_type = type_vi.value;
    var pos = type_vi.len;

    switch (frame_type) {
        0x00 => {
            // PADDING: coalesce the run of zero bytes.
            var run: usize = 0;
            while (pos + run < data.len and data[pos + run] == 0x00) run += 1;

            return .{ .frame = .{ .padding = run + 1 }, .len = pos + run };
        },
        0x01 => return .{ .frame = .ping, .len = pos },
        0x06 => {
            const offset = try readField(data, &pos);
            const length = try readField(data, &pos);
            if (data.len < pos + length) return error.ZixTruncated;

            const body = data[pos .. pos + length];

            return .{ .frame = .{ .crypto = .{ .offset = offset, .data = body } }, .len = pos + length };
        },
        0x07 => {
            // NEW_TOKEN: the token MUST NOT be empty (19.7).
            const length = try readField(data, &pos);
            if (length == 0) return error.ZixFrameEncodingError;
            if (data.len < pos + length) return error.ZixTruncated;

            return .{ .frame = .ping, .len = pos + length };
        },
        0x08...0x0f => {
            const has_offset = frame_type & 0x04 != 0;
            const has_length = frame_type & 0x02 != 0;
            const fin = frame_type & 0x01 != 0;

            const id = try readField(data, &pos);
            const offset = if (has_offset) try readField(data, &pos) else 0;

            const length = if (has_length) try readField(data, &pos) else data.len - pos;
            if (data.len < pos + length) return error.ZixTruncated;

            const body = data[pos .. pos + length];

            return .{ .frame = .{ .stream = .{ .id = id, .offset = offset, .fin = fin, .data = body } }, .len = pos + length };
        },
        0x24 => {
            // RESET_STREAM_AT (reliable stream reset 4): RESET_STREAM's three fields, then the reliable
            // size. A reliable size past the final size is a FRAME_ENCODING_ERROR, and it is a frame
            // rule rather than connection state, so it is enforced here.
            const stream_id = try readField(data, &pos);
            const error_code = try readField(data, &pos);
            const final_size = try readField(data, &pos);
            const reliable_size = try readField(data, &pos);
            if (reliable_size > final_size) return error.ZixFrameEncodingError;

            return .{ .frame = .{ .reset_stream_at = .{
                .stream_id = stream_id,
                .error_code = error_code,
                .final_size = final_size,
                .reliable_size = reliable_size,
            } }, .len = pos };
        },
        0x30 => {
            // DATAGRAM without a length (RFC 9221 4): the data runs to the end of the payload, so this
            // frame consumes the rest of it. It MUST therefore be the last frame in its packet.
            return .{ .frame = .{ .datagram = data[pos..] }, .len = data.len };
        },
        0x31 => {
            // DATAGRAM with an explicit length (RFC 9221 4), so it may share a packet. A length of zero
            // is a legal empty datagram.
            const length = try readField(data, &pos);
            if (data.len < pos + length) return error.ZixTruncated;

            const body = data[pos .. pos + length];

            return .{ .frame = .{ .datagram = body }, .len = pos + length };
        },
        else => return error.ZixFrameEncodingError,
    }
}

/// Read one variable-length field, advancing the cursor (helper for parseFrame).
fn readField(data: []const u8, pos: *usize) FrameError!u64 {
    const vi = varint.read(data[pos.*..]) catch return error.ZixTruncated;
    pos.* += vi.len;

    return vi.value;
}

/// Whether a known frame type may appear in a given packet number space (RFC 9000 Table 3, "Pkts").
pub fn framePermittedIn(frame_type: u64, space: Space) bool {
    return switch (frame_type) {
        0x00, 0x01 => true, // PADDING, PING: IH01
        0x02, 0x03 => space != .zero_rtt, // ACK: IH_1
        0x06 => space != .zero_rtt, // CRYPTO: IH_1
        0x07 => space == .one_rtt, // NEW_TOKEN: ___1
        0x1b => space == .one_rtt, // PATH_RESPONSE: ___1
        0x1c => true, // CONNECTION_CLOSE 0x1c: ih01
        0x1d => space == .zero_rtt or space == .one_rtt, // CONNECTION_CLOSE 0x1d: __01
        0x1e => space == .one_rtt, // HANDSHAKE_DONE: ___1
        0x24 => space == .zero_rtt or space == .one_rtt, // RESET_STREAM_AT: __01 (reliable stream reset 4)
        0x30, 0x31 => space == .zero_rtt or space == .one_rtt, // DATAGRAM: __01 (RFC 9221 5)
        0x04...0x05, 0x08...0x1a => space == .zero_rtt or space == .one_rtt, // the __01 group
        else => false,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 19 frame parse" {
    const padding = try parseFrame(&hexBytes("000000"));
    try std.testing.expect(padding.frame.padding == 3 and padding.len == 3);

    const ping = try parseFrame(&hexBytes("01"));
    try std.testing.expect(ping.frame == .ping and ping.len == 1);

    const crypto = try parseFrame(&hexBytes("0600040a0b0c0d"));
    try std.testing.expectEqual(@as(u64, 0), crypto.frame.crypto.offset);
    try std.testing.expectEqualSlices(u8, &hexBytes("0a0b0c0d"), crypto.frame.crypto.data);

    const stream_min = try parseFrame(&hexBytes("0804deadbeef"));
    try std.testing.expectEqual(@as(u64, 4), stream_min.frame.stream.id);
    try std.testing.expectEqual(@as(u64, 0), stream_min.frame.stream.offset);
    try std.testing.expect(!stream_min.frame.stream.fin);
    try std.testing.expectEqualSlices(u8, &hexBytes("deadbeef"), stream_min.frame.stream.data);

    const stream_full = try parseFrame(&hexBytes("0f04080241420000"));
    try std.testing.expectEqual(@as(u64, 8), stream_full.frame.stream.offset);
    try std.testing.expect(stream_full.frame.stream.fin);
    try std.testing.expectEqualSlices(u8, &hexBytes("4142"), stream_full.frame.stream.data);
    try std.testing.expectEqual(@as(usize, 6), stream_full.len);
}

test "zix http3: RFC 9000 12.4 frame type rules" {
    try std.testing.expectError(error.ZixFrameEncodingError, parseFrame(&hexBytes("20")));
    try std.testing.expectError(error.ZixProtocolViolation, parseFrame(&hexBytes("4001")));
    try std.testing.expectError(error.ZixFrameEncodingError, parseFrame(&hexBytes("0700")));
}

test "zix http3: RFC 9221 4 datagram frame parse" {
    // The 0x31 form carries a length, so the frame may share a payload with frames after it.
    const with_len = try parseFrame(&hexBytes("31056162636465"));
    try std.testing.expectEqualSlices(u8, &hexBytes("6162636465"), with_len.frame.datagram);
    try std.testing.expectEqual(@as(usize, 7), with_len.len);

    // The 0x30 form has no length, so its data is everything left in the payload.
    const without_len = try parseFrame(&hexBytes("306162636465"));
    try std.testing.expectEqualSlices(u8, &hexBytes("6162636465"), without_len.frame.datagram);
    try std.testing.expectEqual(@as(usize, 6), without_len.len);

    // An empty datagram is legal in both forms, so a zero-length slice is a frame, not a truncation.
    const empty_len = try parseFrame(&hexBytes("3100"));
    try std.testing.expectEqual(@as(usize, 0), empty_len.frame.datagram.len);
    try std.testing.expectEqual(@as(usize, 2), empty_len.len);

    const empty = try parseFrame(&hexBytes("30"));
    try std.testing.expectEqual(@as(usize, 0), empty.frame.datagram.len);
    try std.testing.expectEqual(@as(usize, 1), empty.len);

    // A length past the end of the payload is truncated, never a datagram padded with invented bytes.
    try std.testing.expectError(error.ZixTruncated, parseFrame(&hexBytes("31056162")));
    // A length field cut off before it starts is truncated too.
    try std.testing.expectError(error.ZixTruncated, parseFrame(&hexBytes("31")));
}

test "zix http3: reliable stream reset 4 reset_stream_at frame parse" {
    // Type 0x24, then stream id 4, error code 256 (the two-byte varint 4100), final size 8, reliable
    // size 6.
    const parsed = try parseFrame(&hexBytes("240441000806"));
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.reset_stream_at.stream_id);
    try std.testing.expectEqual(@as(u64, 256), parsed.frame.reset_stream_at.error_code);
    try std.testing.expectEqual(@as(u64, 8), parsed.frame.reset_stream_at.final_size);
    try std.testing.expectEqual(@as(u64, 6), parsed.frame.reset_stream_at.reliable_size);
    try std.testing.expectEqual(@as(usize, 6), parsed.len);

    // A reliable size of zero is the plain RESET_STREAM case; one equal to the final size is legal too.
    const none = try parseFrame(&hexBytes("2404050300"));
    try std.testing.expectEqual(@as(u64, 0), none.frame.reset_stream_at.reliable_size);
    try std.testing.expectEqual(@as(u64, 3), none.frame.reset_stream_at.final_size);

    const whole = try parseFrame(&hexBytes("2404050303"));
    try std.testing.expectEqual(@as(u64, 3), whole.frame.reset_stream_at.reliable_size);

    // A reliable size past the final size is a FRAME_ENCODING_ERROR (reliable stream reset 4).
    try std.testing.expectError(error.ZixFrameEncodingError, parseFrame(&hexBytes("2404050304")));

    // A missing field leaves the frame truncated rather than zero-filled.
    try std.testing.expectError(error.ZixTruncated, parseFrame(&hexBytes("24040500")));
    try std.testing.expectError(error.ZixTruncated, parseFrame(&hexBytes("24")));
}

test "zix http3: RFC 9000 12.5 / Table 3 number-space permission matrix" {
    try std.testing.expect(framePermittedIn(0x00, .initial));
    try std.testing.expect(framePermittedIn(0x01, .initial));

    try std.testing.expect(framePermittedIn(0x02, .initial));
    try std.testing.expect(!framePermittedIn(0x02, .zero_rtt));

    try std.testing.expect(framePermittedIn(0x06, .handshake));
    try std.testing.expect(!framePermittedIn(0x06, .zero_rtt));

    try std.testing.expect(!framePermittedIn(0x08, .initial));
    try std.testing.expect(framePermittedIn(0x08, .one_rtt));

    try std.testing.expect(framePermittedIn(0x07, .one_rtt) and !framePermittedIn(0x07, .initial));
    try std.testing.expect(!framePermittedIn(0x1e, .handshake));
    try std.testing.expect(framePermittedIn(0x1b, .one_rtt) and !framePermittedIn(0x1b, .zero_rtt));
    try std.testing.expect(framePermittedIn(0x1a, .zero_rtt));

    try std.testing.expect(framePermittedIn(0x1c, .initial));
    try std.testing.expect(!framePermittedIn(0x1d, .initial));

    try std.testing.expect(!framePermittedIn(0x10, .initial));
    try std.testing.expect(framePermittedIn(0x10, .one_rtt));
}

test "zix http3: the extension frames are application data only" {
    // DATAGRAM frames MUST be protected with 0-RTT or 1-RTT keys (RFC 9221 5), so neither payload form
    // may appear in an Initial or Handshake packet.
    for ([_]u64{ 0x30, 0x31 }) |datagram_type| {
        try std.testing.expect(framePermittedIn(datagram_type, .zero_rtt));
        try std.testing.expect(framePermittedIn(datagram_type, .one_rtt));
        try std.testing.expect(!framePermittedIn(datagram_type, .initial));
        try std.testing.expect(!framePermittedIn(datagram_type, .handshake));
    }

    // RESET_STREAM_AT MUST only be sent in the application data packet number space (reliable stream
    // reset 4), and it is ack-eliciting, so 0-RTT and 1-RTT accept it.
    try std.testing.expect(framePermittedIn(0x24, .zero_rtt));
    try std.testing.expect(framePermittedIn(0x24, .one_rtt));
    try std.testing.expect(!framePermittedIn(0x24, .initial));
    try std.testing.expect(!framePermittedIn(0x24, .handshake));
}
