//! zix HTTP/3 server Handshake flight (RFC 9001 4 + RFC 8446 4.3 + RFC 9114 / RFC 9000 18.2).
//!
//! What:
//! - Builds the server's Handshake-level TLS flight (EncryptedExtensions, Certificate,
//!   CertificateVerify, Finished), feeds each message into the handshake transcript, wraps the whole
//!   flight in a CRYPTO frame, and seals it into a Handshake packet with the server Handshake keys.
//! - The EncryptedExtensions is hand-built here (not via src/tls) because QUIC needs two things the
//!   TLS record layer deliberately omits: ALPN "h3" and the quic_transport_parameters extension
//!   (0x39). curl validates original_destination_connection_id and initial_source_connection_id
//!   against what it observed, so those carry the client's first DCID and our SCID byte-exact.
//!
//! Note:
//! - The Certificate / CertificateVerify / Finished message builders are the existing, tested
//!   `src/tls/certificate.zig` (record-free). Only the framing changes: raw handshake bytes go into a
//!   CRYPTO frame instead of a TLS record.

const std = @import("std");

const crypto = @import("crypto.zig");
const protection = @import("protection.zig");
const varint = @import("varint.zig");
const ks = @import("../../tls/key_schedule.zig");
const certificate = @import("../../tls/certificate.zig");
const rsa = @import("../../tls/rsa.zig");

/// Append one integer transport parameter (RFC 9000 18.1): varint id, varint length, varint value.
fn putIntParam(buf: []u8, pos: *usize, id: u64, value: u64) void {
    pos.* += varint.write(buf[pos.*..], id);
    pos.* += varint.write(buf[pos.*..], varint.encodedLen(value));
    pos.* += varint.write(buf[pos.*..], value);
}

/// Append one byte-string transport parameter (RFC 9000 18.1): varint id, varint length, raw bytes.
fn putBytesParam(buf: []u8, pos: *usize, id: u64, value: []const u8) void {
    pos.* += varint.write(buf[pos.*..], id);
    pos.* += varint.write(buf[pos.*..], value.len);
    @memcpy(buf[pos.*..][0..value.len], value);
    pos.* += value.len;
}

/// The one-time connection-wide byte budget advertised in the handshake (initial_max_data, RFC 9000
/// 18.2) and the rolling window replenishMaxData keeps ahead of the client's consumption. One value
/// for both so a replenished grant always extends by exactly what the handshake promised.
pub const initial_max_data: u64 = 1048576;

/// The one-time per-stream byte budget advertised in the handshake (initial_max_stream_data_*, RFC
/// 9000 18.2) and the rolling window a held request stream is extended by. A client uploading past
/// this on one stream blocks until a MAX_STREAM_DATA raises it, so a request larger than this is
/// answerable only because the serve path replenishes it.
pub const initial_max_stream_data: u64 = 262144;

/// The QUIC extensions beyond RFC 9000 an endpoint advertises in its transport parameters. Both are
/// WebTransport prerequisites: the binding carries datagrams over the DATAGRAM frame and resets a data
/// stream with RESET_STREAM_AT so the stream header survives the reset.
///
/// Note:
/// - An endpoint that does not advertise `max_datagram_frame_size` MUST NOT be sent DATAGRAM frames
///   (RFC 9221 3), and one that does not advertise `reset_stream_at` MUST NOT be sent RESET_STREAM_AT
///   (draft-ietf-quic-reliable-stream-reset-09 3), so both are left off when the feature that needs
///   them is disabled: a peer then sees no reason to require them.
pub const TransportExtensions = struct {
    /// The largest DATAGRAM frame this endpoint accepts, type and length included (RFC 9221 3). 0
    /// omits the parameter, which tells the peer this endpoint does not accept DATAGRAM frames.
    pub const max_datagram_frame_size_id: u64 = 0x20;
    /// The empty reset_stream_at parameter (draft-ietf-quic-reliable-stream-reset-09 3).
    pub const reset_stream_at_id: u64 = 0x1d;

    max_datagram_frame_size: u64 = 0,
    reset_stream_at: bool = false,
};

/// Encode the QUIC transport parameters (RFC 9000 18.2). The connection-id params are validated by
/// the peer, so they MUST carry the client's first DCID and our SCID exactly.
fn encodeTransportParams(buf: []u8, original_dcid: []const u8, source_cid: []const u8, max_idle_ms: u64, max_streams: u64, ext: TransportExtensions) usize {
    var pos: usize = 0;

    putBytesParam(buf, &pos, 0x00, original_dcid); // original_destination_connection_id
    putBytesParam(buf, &pos, 0x0f, source_cid); // initial_source_connection_id
    putIntParam(buf, &pos, 0x01, max_idle_ms); // max_idle_timeout
    putIntParam(buf, &pos, 0x04, initial_max_data); // initial_max_data
    putIntParam(buf, &pos, 0x05, initial_max_stream_data); // initial_max_stream_data_bidi_local
    putIntParam(buf, &pos, 0x06, initial_max_stream_data); // initial_max_stream_data_bidi_remote
    putIntParam(buf, &pos, 0x07, initial_max_stream_data); // initial_max_stream_data_uni
    putIntParam(buf, &pos, 0x08, max_streams); // initial_max_streams_bidi
    putIntParam(buf, &pos, 0x09, max_streams); // initial_max_streams_uni

    // The two extension parameters are only sent when the feature behind them is on: an advertised 0
    // (or an absent parameter) is how an endpoint says it will not accept the frames at all.
    if (ext.max_datagram_frame_size != 0) {
        putIntParam(buf, &pos, TransportExtensions.max_datagram_frame_size_id, ext.max_datagram_frame_size);
    }
    if (ext.reset_stream_at) putBytesParam(buf, &pos, TransportExtensions.reset_stream_at_id, "");

    return pos;
}

/// Build the EncryptedExtensions handshake message (RFC 8446 4.3.1) carrying ALPN "h3" and the
/// quic_transport_parameters extension (RFC 9001 8.2). Returns the wire slice.
pub fn buildEncryptedExtensions(buf: []u8, original_dcid: []const u8, source_cid: []const u8, max_idle_ms: u64, max_streams: u64, ext: TransportExtensions) []const u8 {
    var p: usize = 0;
    buf[p] = 0x08; // EncryptedExtensions handshake type
    p += 1;
    const msg_len_at = p;
    p += 3; // u24 length placeholder
    const exts_len_at = p;
    p += 2; // u16 extensions length placeholder
    const exts_start = p;

    // ALPN extension (0x0010): ProtocolNameList of one name, "h3".
    std.mem.writeInt(u16, buf[p..][0..2], 0x0010, .big);
    p += 2;
    const alpn_len_at = p;
    p += 2;
    const alpn_start = p;
    std.mem.writeInt(u16, buf[p..][0..2], 3, .big); // ProtocolNameList length
    p += 2;
    buf[p] = 2; // ProtocolName length
    p += 1;
    @memcpy(buf[p..][0..2], "h3");
    p += 2;
    std.mem.writeInt(u16, buf[alpn_len_at..][0..2], @intCast(p - alpn_start), .big);

    // quic_transport_parameters extension (0x0039).
    std.mem.writeInt(u16, buf[p..][0..2], 0x0039, .big);
    p += 2;
    const tp_len_at = p;
    p += 2;
    const tp_start = p;
    p += encodeTransportParams(buf[p..], original_dcid, source_cid, max_idle_ms, max_streams, ext);
    std.mem.writeInt(u16, buf[tp_len_at..][0..2], @intCast(p - tp_start), .big);

    std.mem.writeInt(u16, buf[exts_len_at..][0..2], @intCast(p - exts_start), .big);

    const msg_len = p - (msg_len_at + 3);
    buf[msg_len_at] = @intCast((msg_len >> 16) & 0xff);
    buf[msg_len_at + 1] = @intCast((msg_len >> 8) & 0xff);
    buf[msg_len_at + 2] = @intCast(msg_len & 0xff);

    return buf[0..p];
}

/// The largest CRYPTO frame payload one Handshake packet carries. A path of twelve hundred bytes is the
/// QUIC minimum every peer must support, and the packet header, the length and the AEAD tag come out of it.
const crypto_chunk: usize = 1100;

/// The most Handshake packets one flight is split across. A chain of a leaf plus three intermediates is
/// about seven kilobytes of DER, so eight packets carry it with room to spare.
pub const max_flight_packets: usize = 8;

/// The buffer one flight needs: every packet at its largest, plus the frame header they each add.
pub const max_flight_bytes: usize = max_flight_packets * (crypto_chunk + 64);

/// A built flight: the sealed packets in order, each one a CRYPTO frame at its own offset. The peer
/// reassembles them into the crypto stream, so the order and the offsets are what make the chain readable.
pub const Flight = struct {
    packets: [max_flight_packets][]const u8 = @splat(&.{}),
    len: usize = 0,
};

/// Build and seal the server Handshake flight into the Handshake packets that carry it (RFC 9001 4).
///
/// The flight is however large the certificate chain makes it. A chain of a leaf plus its intermediates is
/// several kilobytes, which is more than one Handshake packet carries, so it is split across as many packets
/// as it needs: each holds a CRYPTO frame at its own offset, and the peer reassembles them in order. A single
/// certificate is one short packet, so the shape is the same either way.
///
/// Param:
/// out - []u8 (destination for the sealed packets, back to back; max_flight_bytes covers any flight)
/// server_keys - crypto.AesKeys (the server Handshake key / iv / hp)
/// server_traffic - crypto.Secret (the server handshake-traffic secret, for the Finished key)
/// dcid - []const u8 (the client's Source Connection ID, our reply Destination CID)
/// scid - []const u8 (our Source Connection ID)
/// transcript - *ks.Transcript (through ClientHello + ServerHello, continued by this flight)
/// chain - []const []const u8 (the certificates from the TLS context, end-entity first)
/// signing_key - certificate.SigningKey (the certificate's signing key)
/// original_dcid - []const u8 (the client's first Initial DCID, for the transport parameter)
/// source_cid - []const u8 (our SCID, for the transport parameter)
/// max_idle_ms - u64 (idle timeout transport parameter)
/// max_streams - u64 (stream limit transport parameter)
/// ext - TransportExtensions (the DATAGRAM and reliable-reset parameters, empty when the features that
///   need them are off)
///
/// Return:
/// - Flight (the sealed packets), or null on a builder / signing error
pub fn buildHandshakeFlight(
    out: []u8,
    server_keys: crypto.AesKeys,
    server_traffic: crypto.Secret,
    dcid: []const u8,
    scid: []const u8,
    transcript: *ks.Transcript,
    chain: []const []const u8,
    signing_key: certificate.SigningKey,
    original_dcid: []const u8,
    source_cid: []const u8,
    max_idle_ms: u64,
    max_streams: u64,
    ext: TransportExtensions,
) ?Flight {
    var flight: [16384]u8 = undefined;
    var fp: usize = 0;

    var ee_buf: [512]u8 = undefined;
    const ee = buildEncryptedExtensions(&ee_buf, original_dcid, source_cid, max_idle_ms, max_streams, ext);
    @memcpy(flight[fp..][0..ee.len], ee);
    fp += ee.len;
    transcript.update(ee);

    var cert_buf: [16384]u8 = undefined;
    const cert = certificate.buildCertificate(&cert_buf, chain);
    @memcpy(flight[fp..][0..cert.len], cert);
    fp += cert.len;
    transcript.update(cert);

    var cv_buf: [600]u8 = undefined;
    const pss_salt: [rsa.pss_salt_len]u8 = @splat(0); // ignored for ECDSA / Ed25519
    const cert_verify = certificate.buildCertificateVerify(&cv_buf, signing_key, transcript.current(), pss_salt) catch return null;
    @memcpy(flight[fp..][0..cert_verify.len], cert_verify);
    fp += cert_verify.len;
    transcript.update(cert_verify);

    var fin_buf: [128]u8 = undefined;
    const finished = certificate.buildFinished(&fin_buf, certificate.finishedKey(server_traffic), transcript.current());
    @memcpy(flight[fp..][0..finished.len], finished);
    fp += finished.len;
    transcript.update(finished);

    // Wrap the flight in CRYPTO frames, one per packet, each at the offset it belongs at (RFC 9000 19.6).
    var built: Flight = .{};
    var at = out;
    var offset: u64 = 0;
    var packet_number: u32 = 0;

    while (offset < fp) {
        if (built.len == max_flight_packets) return null;

        const take = @min(crypto_chunk, fp - @as(usize, @intCast(offset)));
        var frame_buf: [crypto_chunk + 16]u8 = undefined;
        var cfp: usize = 0;
        frame_buf[cfp] = 0x06;
        cfp += 1;
        cfp += varint.write(frame_buf[cfp..], offset);
        cfp += varint.write(frame_buf[cfp..], take);
        @memcpy(frame_buf[cfp..][0..take], flight[@intCast(offset)..][0..take]);
        cfp += take;

        const sealed = protection.sealHandshake(at, server_keys, dcid, scid, packet_number, frame_buf[0..cfp]) catch return null;
        built.packets[built.len] = sealed;
        built.len += 1;
        at = at[sealed.len..];
        offset += take;
        packet_number += 1;
    }

    return built;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: transport parameters carry the validated connection ids" {
    var buf: [256]u8 = undefined;
    const dcid = hexBytes("8394c8f03e515708");
    const scid = hexBytes("c0ffee00");
    const len = encodeTransportParams(&buf, &dcid, &scid, 30000, 128, .{});
    const params = buf[0..len];

    // original_destination_connection_id (0x00): id, length 8, then the DCID bytes.
    try std.testing.expectEqual(@as(u8, 0x00), params[0]);
    try std.testing.expectEqual(@as(u8, 8), params[1]);
    try std.testing.expectEqualSlices(u8, &dcid, params[2..10]);

    // initial_source_connection_id (0x0f) follows: id, length 4, then the SCID bytes.
    try std.testing.expectEqual(@as(u8, 0x0f), params[10]);
    try std.testing.expectEqual(@as(u8, 4), params[11]);
    try std.testing.expectEqualSlices(u8, &scid, params[12..16]);
}

test "zix http3: the DATAGRAM and reliable-reset parameters are advertised only when asked for" {
    var buf: [256]u8 = undefined;
    const dcid = hexBytes("8394c8f03e515708");
    const scid = hexBytes("c0ffee00");

    // Off: neither parameter appears, so a peer must not send either frame (RFC 9221 3,
    // draft-ietf-quic-reliable-stream-reset-09 3).
    const plain = encodeTransportParams(&buf, &dcid, &scid, 30000, 128, .{});
    try std.testing.expect(std.mem.indexOfScalar(u8, buf[0..plain], 0x20) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, buf[0..plain], 0x1d) == null);

    // On: max_datagram_frame_size (0x20) with its value, then the empty reset_stream_at (0x1d, length 0).
    const ext = encodeTransportParams(&buf, &dcid, &scid, 30000, 128, .{ .max_datagram_frame_size = 1200, .reset_stream_at = true });

    const dgram_at = std.mem.indexOfScalar(u8, buf[0..ext], 0x20).?;
    try std.testing.expectEqual(@as(u8, 0x20), buf[dgram_at]);
    try std.testing.expectEqual(@as(u8, 2), buf[dgram_at + 1]); // a 1200 value needs two varint bytes
    try std.testing.expectEqualSlices(u8, &hexBytes("44b0"), buf[dgram_at + 2 .. dgram_at + 4]);

    const reset_at = std.mem.indexOfScalar(u8, buf[dgram_at + 4 .. ext], 0x1d).? + dgram_at + 4;
    try std.testing.expectEqual(@as(u8, 0x1d), buf[reset_at]);
    try std.testing.expectEqual(@as(u8, 0), buf[reset_at + 1]); // an empty value

    // A zero frame size is the same as omitting the parameter: the peer would otherwise read it as
    // "datagrams supported, but nothing fits".
    const zero = encodeTransportParams(&buf, &dcid, &scid, 30000, 128, .{ .max_datagram_frame_size = 0, .reset_stream_at = true });
    try std.testing.expect(std.mem.indexOfScalar(u8, buf[0..zero], 0x20) == null);
}

test "zix http3: EncryptedExtensions carries ALPN h3 and transport parameters" {
    var buf: [512]u8 = undefined;
    const ee = buildEncryptedExtensions(&buf, &hexBytes("8394c8f03e515708"), &hexBytes("c0ffee00"), 30000, 128, .{});

    // EncryptedExtensions handshake type, and the 24-bit length matches the remaining bytes.
    try std.testing.expectEqual(@as(u8, 0x08), ee[0]);
    const declared = (@as(usize, ee[1]) << 16) | (@as(usize, ee[2]) << 8) | ee[3];
    try std.testing.expectEqual(ee.len - 4, declared);

    // The "h3" ALPN token and the 0x0039 transport-parameters extension id both appear.
    try std.testing.expect(std.mem.indexOf(u8, ee, "h3") != null);
    try std.testing.expect(std.mem.indexOf(u8, ee, &[_]u8{ 0x00, 0x39 }) != null);
}
