//! zix HTTP/3 client transport parameter parsing (RFC 9000 18, RFC 9221 3,
//! draft-ietf-quic-reliable-stream-reset-09 3).
//!
//! What:
//! - What the client will accept, read before the server sends it: the flow control limits the response
//!   path must respect, the largest DATAGRAM frame a WebTransport session may send, and whether the
//!   client understands RESET_STREAM_AT. The client carries them in the quic_transport_parameters TLS
//!   extension (type 0x39) inside its ClientHello; this pulls out the parameters the response and
//!   WebTransport paths need and skips the rest.
//!
//! Note:
//! - A client-initiated bidirectional stream (the request stream) is, from the client's view, locally
//!   initiated. So the limit the server must respect when sending the response on it is the client's
//!   initial_max_stream_data_bidi_local (0x05), plus the connection-wide initial_max_data (0x04).
//! - The parser is deliberately forgiving: a value that breaks its parameter's rules is clamped or
//!   recorded rather than turned into a connection error, because a minimal client is likelier than a
//!   hostile one and the caller can still police (see reset_stream_at for the one parameter the spec
//!   makes fatal to get wrong).

const std = @import("std");

const varint = @import("varint.zig");

/// The quic_transport_parameters TLS extension type (RFC 9001 8.2).
pub const extension_type: u16 = 0x0039;

/// The client transport parameters the response and WebTransport paths need: the flow control limits
/// that gate what the server may send on the streams it replies on, the largest DATAGRAM frame the
/// client accepts, and whether it understands RESET_STREAM_AT. Absent parameters default to 0 (no
/// credit, no datagrams), so the caller treats a client that advertised nothing as having granted
/// nothing.
pub const TransportParams = struct {
    /// Connection-level send limit: total stream data the server may send (param 0x04).
    initial_max_data: u64 = 0,
    /// Per-stream send limit for the request stream the server replies on (param 0x05, the client's
    /// initial_max_stream_data_bidi_local).
    initial_max_stream_data_bidi_local: u64 = 0,
    /// Per-stream send limit for a bidirectional stream the server opens (param 0x06, the client's
    /// initial_max_stream_data_bidi_remote). A WebTransport session's server-initiated streams are
    /// bounded by this until the client raises it with MAX_STREAM_DATA.
    initial_max_stream_data_bidi_remote: u64 = 0,
    /// Per-stream send limit for a unidirectional stream the server opens (param 0x07, the client's
    /// initial_max_stream_data_uni).
    initial_max_stream_data_uni: u64 = 0,
    /// The power-of-two divisor the client used to encode ACK Delay fields (param 0x0a), default 3
    /// (RFC 9000 18.2) when the client sends none. Needed to decode the client's ACK frames for loss
    /// recovery (RFC 9000 19.3).
    ack_delay_exponent: u6 = 3,
    /// The largest UDP payload the client will accept (param 0x03), so the server never sends a datagram
    /// the client must drop (RFC 9000 18.2). Default 65527 when the client sends none (the RFC default),
    /// clamped to at least 1200 (the QUIC minimum). Lets the response path send fewer, larger datagrams
    /// on a path that allows it (a big-MTU loopback), cutting per-packet work on both ends.
    max_udp_payload_size: u64 = 65527,
    /// The largest DATAGRAM frame the client accepts, counting the frame type, the length field, and
    /// the payload (param 0x20, RFC 9221 3). 0 (the default, and what an absent parameter means) says
    /// the client accepts no DATAGRAM frame at all, so the server must not send one and a WebTransport
    /// session has only streams.
    max_datagram_frame_size: u64 = 0,
    /// Whether the client accepts RESET_STREAM_AT frames (param 0x1d,
    /// draft-ietf-quic-reliable-stream-reset-09 3), the frame a draft-16 WebTransport session uses to
    /// reset a data stream while its session id still reaches the peer. The parameter carries an empty
    /// value, and a non-empty one is a TRANSPORT_PARAMETER_ERROR that the caller must police, so a
    /// malformed value still records presence here instead of being silently dropped.
    reset_stream_at: bool = false,
};

/// The RFC 9000 minimum a QUIC endpoint must accept, the floor for max_udp_payload_size.
pub const min_udp_payload_size: u64 = 1200;

/// The RFC 9000 default max_udp_payload_size when a peer advertises none.
pub const default_max_udp_payload_size: u64 = 65527;

/// Parse the body of the quic_transport_parameters extension (RFC 9000 18.1): a sequence of
/// (id, length, value) entries, each varint-framed. Unknown ids are skipped. Integer parameters carry
/// a varint value.
pub fn parse(ext_body: []const u8) TransportParams {
    var params = TransportParams{};
    var pos: usize = 0;
    while (pos < ext_body.len) {
        const id = varint.read(ext_body[pos..]) catch break;
        pos += id.len;

        const length = varint.read(ext_body[pos..]) catch break;
        pos += length.len;

        const value_len: usize = @intCast(length.value);
        if (pos + value_len > ext_body.len) break;

        const value = ext_body[pos .. pos + value_len];
        pos += value_len;

        switch (id.value) {
            // A value below the 1200 minimum is a transport error, but a minimal client is likelier than
            // a hostile one, so clamp up to the floor rather than drop the connection.
            0x03 => if (varintValue(value)) |v| {
                params.max_udp_payload_size = @max(v, min_udp_payload_size);
            },
            0x04 => params.initial_max_data = varintValue(value) orelse params.initial_max_data,
            0x05 => params.initial_max_stream_data_bidi_local = varintValue(value) orelse params.initial_max_stream_data_bidi_local,
            0x06 => params.initial_max_stream_data_bidi_remote = varintValue(value) orelse params.initial_max_stream_data_bidi_remote,
            0x07 => params.initial_max_stream_data_uni = varintValue(value) orelse params.initial_max_stream_data_uni,
            // The valid range is 0-20 (RFC 9000 18.2). A larger value is a transport error, but a
            // minimal client is more likely than a hostile one here, so clamp rather than drop the
            // connection.
            0x0a => if (varintValue(value)) |v| {
                params.ack_delay_exponent = @intCast(@min(v, 20));
            },
            // reliable stream reset 3: an empty value advertises RESET_STREAM_AT support. A non-empty
            // value is the caller's TRANSPORT_PARAMETER_ERROR to raise, so presence is recorded either
            // way rather than the parameter being dropped.
            0x1d => params.reset_stream_at = true,
            // RFC 9221 3: the largest DATAGRAM frame the client accepts. 0 means it accepts none, which
            // is also what an absent parameter means, so the struct default already says it.
            0x20 => params.max_datagram_frame_size = varintValue(value) orelse params.max_datagram_frame_size,
            else => {},
        }
    }

    return params;
}

/// Find and parse the client's quic_transport_parameters extension in a ClientHello handshake message.
/// Returns null when the extension is absent (a minimal test client sends none).
pub fn fromClientHello(client_hello: []const u8) ?TransportParams {
    const ext = findExtension(client_hello, extension_type) orelse return null;

    return parse(ext);
}

/// Read a transport parameter's integer value (a single varint, RFC 9000 18.1).
fn varintValue(value: []const u8) ?u64 {
    const v = varint.read(value) catch return null;

    return v.value;
}

/// Walk a ClientHello (RFC 8446 4.1.2) to its extension list and return the body of `want_type`, or
/// null when the message is malformed or the extension is absent.
fn findExtension(client_hello: []const u8, want_type: u16) ?[]const u8 {
    // Handshake header: msg_type(1, CLIENT_HELLO = 0x01) + length(3).
    if (client_hello.len < 4 or client_hello[0] != 0x01) return null;
    var pos: usize = 4;

    // legacy_version(2) + random(32).
    pos += 2 + 32;
    if (pos >= client_hello.len) return null;

    // legacy_session_id: length(1) + bytes.
    const sid_len = client_hello[pos];
    pos += 1 + sid_len;
    if (pos + 2 > client_hello.len) return null;

    // cipher_suites: length(2) + bytes.
    const cs_len = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2 + cs_len;
    if (pos + 1 > client_hello.len) return null;

    // legacy_compression_methods: length(1) + bytes.
    const cm_len = client_hello[pos];
    pos += 1 + cm_len;
    if (pos + 2 > client_hello.len) return null;

    // extensions: length(2) + entries.
    const ext_total = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total;
    if (ext_end > client_hello.len) return null;

    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        const ext_len = std.mem.readInt(u16, client_hello[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_len > ext_end) return null;

        if (ext_type == want_type) return client_hello[pos .. pos + ext_len];

        pos += ext_len;
    }

    return null;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: parse extracts initial_max_data and initial_max_stream_data_bidi_local" {
    // Three params: 0x04 = 1048576 (varint c0..00100000), 0x05 = 262144 (varint 80040000),
    // 0x08 = 100 (varint 4064, skipped). Each entry is id, length, value.
    const body = hexBytes("04" ++ "04" ++ "80100000" ++ "05" ++ "04" ++ "80040000" ++ "08" ++ "02" ++ "4064");
    const params = parse(&body);

    try std.testing.expectEqual(@as(u64, 1048576), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 262144), params.initial_max_stream_data_bidi_local);
}

test "zix http3: parse defaults absent parameters to zero" {
    // Only initial_max_data present, the per-stream limit defaults to 0.
    const body = hexBytes("04" ++ "04" ++ "80100000");
    const params = parse(&body);

    try std.testing.expectEqual(@as(u64, 1048576), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 0), params.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u6, 3), params.ack_delay_exponent);
    // Absent max_udp_payload_size defaults to the RFC value (accept large), not zero.
    try std.testing.expectEqual(default_max_udp_payload_size, params.max_udp_payload_size);
}

test "zix http3: parse extracts max_udp_payload_size and clamps below the 1200 floor" {
    // 0x03 = 8192 (varint 80002000), so the server may send up to 8 KiB datagrams to this client.
    const body = hexBytes("03" ++ "04" ++ "80002000");
    try std.testing.expectEqual(@as(u64, 8192), parse(&body).max_udp_payload_size);

    // A value under the RFC minimum (0x03 = 512, varint 4200) is clamped up to 1200, never below.
    const tiny = hexBytes("03" ++ "02" ++ "4200");
    try std.testing.expectEqual(min_udp_payload_size, parse(&tiny).max_udp_payload_size);
}

test "zix http3: parse extracts ack_delay_exponent, clamped to the RFC 9000 18.2 valid range" {
    const body = hexBytes("0a" ++ "01" ++ "06");
    try std.testing.expectEqual(@as(u6, 6), parse(&body).ack_delay_exponent);

    const oversized = hexBytes("0a" ++ "02" ++ "4064"); // varint 100, clamped to 20
    try std.testing.expectEqual(@as(u6, 20), parse(&oversized).ack_delay_exponent);

    // 0x0b is max_ack_delay, not ack_delay_exponent (RFC 9000 Table 6), so it must not set the exponent.
    const max_ack_delay = hexBytes("0b" ++ "01" ++ "06");
    try std.testing.expectEqual(@as(u6, 3), parse(&max_ack_delay).ack_delay_exponent);
}

test "zix http3: parse extracts the datagram and reliable reset transport parameters" {
    // 0x20 = 1200 (varint 44b0) and an empty 0x1d, alongside the flow control parameters.
    const body = hexBytes("04" ++ "04" ++ "80100000" ++ "20" ++ "02" ++ "44b0" ++ "1d" ++ "00");
    const params = parse(&body);

    try std.testing.expectEqual(@as(u64, 1048576), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 1200), params.max_datagram_frame_size);
    try std.testing.expect(params.reset_stream_at);
}

test "zix http3: parse defaults the datagram and reliable reset parameters off" {
    // A client with no WebTransport support sends only flow control limits.
    const body = hexBytes("04" ++ "04" ++ "80100000" ++ "05" ++ "04" ++ "80040000");
    const params = parse(&body);

    try std.testing.expectEqual(@as(u64, 0), params.max_datagram_frame_size);
    try std.testing.expect(!params.reset_stream_at);

    // An explicit 0x20 = 0 says the same thing on the wire: no DATAGRAM frames (RFC 9221 3).
    const disabled = hexBytes("20" ++ "01" ++ "00");
    try std.testing.expectEqual(@as(u64, 0), parse(&disabled).max_datagram_frame_size);
}

test "zix http3: a non-empty reset_stream_at value still records the parameter as present" {
    // reliable stream reset 3 makes this a TRANSPORT_PARAMETER_ERROR; the parser records presence and
    // leaves the connection error to the caller, the WebTransport session that needs the extension.
    const body = hexBytes("1d" ++ "01" ++ "01");
    try std.testing.expect(parse(&body).reset_stream_at);
}

// A 32-byte all-zero random, as the 64 hex chars the ClientHello test fixtures embed.
const zero_random = "0000000000000000000000000000000000000000000000000000000000000000";

test "zix http3: fromClientHello returns null without the extension" {
    // A ClientHello with no extensions at all: handshake header + version + random + empty session id
    // + one cipher suite + null compression + empty extension list.
    const client_hello = hexBytes("01" ++ "00002d" ++ "0303" ++ zero_random ++ "00" ++ "0002" ++ "1301" ++ "01" ++ "00" ++ "0000");

    try std.testing.expect(fromClientHello(&client_hello) == null);
}

test "zix http3: fromClientHello finds and parses the transport parameters extension" {
    // Same ClientHello shape, now with one extension: type 0x0039, length 6, body = {0x04, len 4,
    // value 1048576}.
    const ext_body = "04" ++ "04" ++ "80100000";
    const ext = "0039" ++ "0006" ++ ext_body;
    const client_hello = hexBytes("01" ++ "000037" ++ "0303" ++ zero_random ++ "00" ++ "0002" ++ "1301" ++ "01" ++ "00" ++ "000a" ++ ext);

    const params = fromClientHello(&client_hello).?;
    try std.testing.expectEqual(@as(u64, 1048576), params.initial_max_data);
}
