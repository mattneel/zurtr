//! zix HTTP/3 QUIC packet protection, the receive (open) path (RFC 9001 5.3 / 5.4).
//!
//! What:
//! - Removes header protection and AEAD-decrypts a received long-header Initial packet, the first
//!   step of the handshake: a server opens the client's Initial with the DCID-derived client keys
//!   (crypto.zig), recovers the packet number, and returns the decrypted frame payload (CRYPTO +
//!   PADDING) for the frame parser.
//! - The packet is bounded by its own Length field, not by the end of the datagram (RFC 9000 17.2): a
//!   client is free to fill the rest of a datagram after its Initial, and real clients do (aioquic pads
//!   its first datagram past the packet). Reading the tag from the end of the datagram instead of the
//!   end of the packet authenticates the wrong bytes and fails on every such client.
//! - The send (seal) primitives live in crypto.zig. This module is the inverse: sample the
//!   ciphertext, compute the header-protection mask, unmask the first byte and packet number, then
//!   open the AEAD with the unprotected header as associated data.
//!
//! Note:
//! - The first received Initial has no prior largest packet number, so the recovered number is the
//!   truncated wire value. Multi-packet recovery uses packet.decodePacketNumber once a largest is
//!   tracked on the connection.

const std = @import("std");

const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// The errors opening a packet can raise.
pub const OpenError = error{
    /// The packet is shorter than the header, sample, and tag require.
    ZixTruncated,
    /// Not a long-header Initial packet.
    ZixNotInitial,
    /// Not a long-header Handshake packet.
    ZixNotHandshake,
    /// Not a short-header (1-RTT) packet.
    ZixNotShort,
    /// The unprotected header did not fit the working buffer (an implausibly long token).
    ZixHeaderTooLong,
    /// AEAD authentication failed: a forged, corrupted, or wrong-key packet.
    ZixDecrypt,
};

/// A decrypted packet: the recovered packet number and the plaintext frame payload (a slice into the
/// caller-provided output buffer).
pub const Opened = struct {
    packet_number: u64,
    payload: []const u8,
};

/// The bounds of a long-header Initial (RFC 9000 17.2): where its packet number starts and where the
/// packet ends. Shares the walk with the coalesced-packet loop (packet.longPacketBounds), so the server
/// and the demux agree on where one packet stops.
fn initialBounds(data: []const u8, hdr: packet.LongHeader) OpenError!packet.PacketBounds {
    if (hdr.packet_type != 0) return error.ZixNotInitial;

    return packet.longPacketBounds(data) orelse error.ZixTruncated;
}

/// Open a long-header Initial packet (RFC 9001 5.3 / 5.4). `keys` are the Initial keys for the
/// sender direction (the client keys when a server opens a client Initial).
///
/// Param:
/// data - []const u8 (the received datagram bytes for one Initial packet)
/// keys - crypto.AesKeys (the Initial key / iv / hp for the sending peer)
/// out - []u8 (destination for the decrypted frame payload, must hold the ciphertext length)
///
/// Return:
/// - Opened (recovered packet number plus the decrypted payload)
/// - OpenError on a malformed or unauthenticated packet
pub fn openInitial(data: []const u8, keys: crypto.AesKeys, out: []u8) OpenError!Opened {
    const hdr = packet.parseLongHeader(data) catch return error.ZixTruncated;
    if (hdr.packet_type != 0) return error.ZixNotInitial;

    const bounds = try initialBounds(data, hdr);

    return openLongHeaderAt(data, keys, out, bounds.pn_offset, bounds.end);
}

/// The bounds of a long-header Handshake packet (RFC 9000 17.2). Unlike an Initial there is no Token
/// Length / Token, which the shared walk handles from the packet type.
fn handshakeBounds(data: []const u8, hdr: packet.LongHeader) OpenError!packet.PacketBounds {
    if (hdr.packet_type != 2) return error.ZixNotHandshake;

    return packet.longPacketBounds(data) orelse error.ZixTruncated;
}

/// Open a long-header Handshake packet (RFC 9001 5.3 / 5.4). `keys` are the Handshake keys for the
/// sending direction (the client handshake keys when a server opens a client Handshake packet).
pub fn openHandshake(data: []const u8, keys: crypto.AesKeys, out: []u8) OpenError!Opened {
    const hdr = packet.parseLongHeader(data) catch return error.ZixTruncated;
    if (hdr.packet_type != 2) return error.ZixNotHandshake;

    const bounds = try handshakeBounds(data, hdr);

    return openLongHeaderAt(data, keys, out, bounds.pn_offset, bounds.end);
}

/// Remove header protection and AEAD-decrypt a long-header packet whose packet number begins at
/// `pn_offset` and whose last byte (the AEAD tag's) is at `packet_end`. Shared by `openInitial` and
/// `openHandshake`.
///
/// Note:
/// - `data` may hold more than this packet: the bytes after `packet_end` belong to whatever the sender
///   put next in the datagram (a coalesced packet, or the padding a client adds to reach the 1200-byte
///   floor outside the packet). They take no part in this packet's AEAD.
fn openLongHeaderAt(data: []const u8, keys: crypto.AesKeys, out: []u8, pn_offset: usize, packet_end: usize) OpenError!Opened {
    // Header-protection sample: 16 bytes starting at pn_offset + 4 (RFC 9001 5.4.2).
    const sample_offset = pn_offset + 4;
    if (data.len < sample_offset + 16) return error.ZixTruncated;

    var sample: [16]u8 = undefined;
    @memcpy(&sample, data[sample_offset .. sample_offset + 16]);
    const mask = crypto.headerMaskAes(keys.hp, sample);

    // Unmask the first byte (long header: low 4 bits) to learn the packet-number length.
    const first = data[0] ^ (mask[0] & 0x0f);
    const pn_len: usize = @as(usize, first & 0x03) + 1;

    const header_len = pn_offset + pn_len;
    if (packet_end < header_len + Aes128Gcm.tag_length) return error.ZixTruncated;
    if (packet_end > data.len) return error.ZixTruncated;

    // Rebuild the unprotected header for the AEAD associated data: the unmasked first byte and the
    // unmasked packet-number bytes, the rest copied verbatim.
    var hdr_buf: [256]u8 = undefined;
    if (header_len > hdr_buf.len) return error.ZixHeaderTooLong;
    @memcpy(hdr_buf[0..header_len], data[0..header_len]);
    hdr_buf[0] = first;

    var truncated_pn: u64 = 0;
    for (0..pn_len) |i| {
        const b = data[pn_offset + i] ^ mask[1 + i];
        hdr_buf[pn_offset + i] = b;
        truncated_pn = (truncated_pn << 8) | b;
    }

    // First Initial: no prior largest, so the recovered number is the truncated value.
    const full_pn = truncated_pn;

    // A long-header packet ends where its Length field says it does, not at the end of the datagram:
    // the bytes after it belong to whatever the sender coalesced or padded after it (RFC 9000 17.2).
    const nonce = crypto.aeadNonce(keys.iv, full_pn);
    const ciphertext = data[header_len .. packet_end - Aes128Gcm.tag_length];
    if (ciphertext.len > out.len) return error.ZixTruncated;

    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    @memcpy(&tag, data[packet_end - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length]);

    Aes128Gcm.decrypt(out[0..ciphertext.len], ciphertext, tag, hdr_buf[0..header_len], nonce, keys.key) catch return error.ZixDecrypt;

    return .{ .packet_number = full_pn, .payload = out[0..ciphertext.len] };
}

/// Open a short-header (1-RTT) packet (RFC 9001 5.3 / 5.4). The Destination Connection ID length is
/// not on the wire, the receiver knows the length it issued. `keys` are the 1-RTT keys for the
/// sending direction (the client 1-RTT keys when a server opens a client request).
///
/// `largest_pn` is the largest 1-RTT packet number successfully decoded on this connection so far, or
/// null when none has been (the first 1-RTT packet). QUIC senders truncate the packet number to the
/// fewest bytes that disambiguate it from the largest the peer has acknowledged (RFC 9000 17.1), so
/// the wire value is NOT the full number once the connection is established: the receiver MUST
/// reconstruct it (RFC 9000 A.3). Skipping that reconstruction works only while the true number still
/// fits in the bytes on the wire (roughly the first 256 packets on a 1-byte-truncated stream), after
/// which the AEAD nonce is built from the wrong number and every packet fails to decrypt, stalling the
/// connection. `largest_pn` feeds packet.decodePacketNumber to recover the full value.
pub fn openShort(data: []const u8, keys: crypto.AesKeys, dcid_len: usize, largest_pn: ?u64, out: []u8) OpenError!Opened {
    if (data.len < 1 + dcid_len) return error.ZixTruncated;
    if (data[0] & 0x80 != 0) return error.ZixNotShort;

    const pn_offset = 1 + dcid_len;
    const sample_offset = pn_offset + 4;
    if (data.len < sample_offset + 16) return error.ZixTruncated;

    var sample: [16]u8 = undefined;
    @memcpy(&sample, data[sample_offset .. sample_offset + 16]);
    const mask = crypto.headerMaskAes(keys.hp, sample);

    // Short header: header protection masks the low 5 bits of the first byte (RFC 9001 5.4.1). A short
    // header carries no Length field, so this packet runs to the end of the datagram: it is always the
    // last packet in one (RFC 9000 12.2).
    const first = data[0] ^ (mask[0] & 0x1f);
    const pn_len: usize = @as(usize, first & 0x03) + 1;

    const header_len = pn_offset + pn_len;
    if (data.len < header_len + Aes128Gcm.tag_length) return error.ZixTruncated;

    var hdr_buf: [64]u8 = undefined;
    if (header_len > hdr_buf.len) return error.ZixHeaderTooLong;
    @memcpy(hdr_buf[0..header_len], data[0..header_len]);
    hdr_buf[0] = first;

    var truncated_pn: u64 = 0;
    for (0..pn_len) |i| {
        const b = data[pn_offset + i] ^ mask[1 + i];
        hdr_buf[pn_offset + i] = b;
        truncated_pn = (truncated_pn << 8) | b;
    }

    // Reconstruct the full packet number from the truncated wire value (RFC 9000 A.3). The first 1-RTT
    // packet has no prior largest, so its number is the wire value as-is.
    const full_pn = if (largest_pn) |lp| packet.decodePacketNumber(lp, truncated_pn, @intCast(pn_len * 8)) else truncated_pn;

    // A short-header packet has no Length field, so its payload runs to the end of the datagram it
    // arrived in (RFC 9000 17.3): the tag is the last 16 bytes of `data`.
    const nonce = crypto.aeadNonce(keys.iv, full_pn);
    const ciphertext = data[header_len .. data.len - Aes128Gcm.tag_length];
    if (ciphertext.len > out.len) return error.ZixTruncated;

    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    @memcpy(&tag, data[data.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length]);

    Aes128Gcm.decrypt(out[0..ciphertext.len], ciphertext, tag, hdr_buf[0..header_len], nonce, keys.key) catch return error.ZixDecrypt;

    return .{ .packet_number = full_pn, .payload = out[0..ciphertext.len] };
}

/// Seal an outgoing long-header Initial packet (RFC 9001 5.3 / 5.4, the send path). Builds the
/// unprotected long header (Initial, version 1, the given DCID / SCID, empty token), AEAD-encrypts
/// `payload` (the frames) with the unprotected header as associated data, then applies header
/// protection. `keys` are the Initial keys for the sending direction (the server keys when a server
/// sends to a client).
///
/// Param:
/// out - []u8 (destination for the whole packet, must be large enough for header + payload + tag)
/// keys - crypto.AesKeys (the Initial key / iv / hp for this sender)
/// dcid - []const u8 (Destination Connection ID, the peer's chosen SCID)
/// scid - []const u8 (our Source Connection ID)
/// packet_number - u32 (this packet's number in the Initial space)
/// payload - []const u8 (the frame bytes: CRYPTO, ACK, PADDING)
///
/// Return:
/// - []const u8 (the protected packet, a slice into `out`)
pub fn sealInitial(out: []u8, keys: crypto.AesKeys, dcid: []const u8, scid: []const u8, packet_number: u32, payload: []const u8) OpenError![]const u8 {
    return sealLongHeader(out, keys, 0xc0, dcid, scid, packet_number, payload, true);
}

/// Seal an outgoing long-header Handshake packet (RFC 9001 5.3 / 5.4). Like `sealInitial` but with
/// the Handshake type (0x02) and no Token field. `keys` are the server Handshake keys.
pub fn sealHandshake(out: []u8, keys: crypto.AesKeys, dcid: []const u8, scid: []const u8, packet_number: u32, payload: []const u8) OpenError![]const u8 {
    return sealLongHeader(out, keys, 0xe0, dcid, scid, packet_number, payload, false);
}

/// Build and protect a long-header packet. `first_base` is the long-header first byte with the type
/// bits already set (0xc0 Initial, 0xe0 Handshake), `with_token` writes the empty Token Length field
/// that only Initial packets carry.
fn sealLongHeader(out: []u8, keys: crypto.AesKeys, first_base: u8, dcid: []const u8, scid: []const u8, packet_number: u32, payload: []const u8, with_token: bool) OpenError![]const u8 {
    const pn_len: usize = if (packet_number <= 0xff) 1 else if (packet_number <= 0xffff) 2 else 4;

    var pos: usize = 0;
    out[pos] = first_base | @as(u8, @intCast(pn_len - 1));
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], 1, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;
    if (with_token) pos += varint.write(out[pos..], 0);
    pos += varint.write(out[pos..], pn_len + payload.len + Aes128Gcm.tag_length);

    const pn_offset = pos;
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, packet_number, .big);
    @memcpy(out[pos..][0..pn_len], pn_bytes[4 - pn_len ..]);
    pos += pn_len;

    const header_len = pos;
    if (header_len + payload.len + Aes128Gcm.tag_length > out.len) return error.ZixTruncated;

    // AEAD-seal the payload with the unprotected header as associated data (RFC 9001 5.3).
    const nonce = crypto.aeadNonce(keys.iv, packet_number);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[header_len .. header_len + payload.len], &tag, payload, out[0..header_len], nonce, keys.key);
    @memcpy(out[header_len + payload.len ..][0..Aes128Gcm.tag_length], &tag);

    const packet_len = header_len + payload.len + Aes128Gcm.tag_length;

    // Header protection: sample 16 bytes at pn_offset + 4, mask, protect the first byte + pn bytes.
    const sample_offset = pn_offset + 4;
    if (packet_len < sample_offset + 16) return error.ZixTruncated;

    var sample: [16]u8 = undefined;
    @memcpy(&sample, out[sample_offset .. sample_offset + 16]);
    const mask = crypto.headerMaskAes(keys.hp, sample);
    out[0] ^= mask[0] & 0x0f;
    for (0..pn_len) |i| out[pn_offset + i] ^= mask[1 + i];

    return out[0..packet_len];
}

/// Seal an outgoing short-header (1-RTT) packet (RFC 9001 5.3 / 5.4). `dcid` is the peer's connection
/// id, placed raw with no length prefix. `keys` are the server 1-RTT keys.
/// Upper bound on the bytes sealShort adds around a 1-RTT payload: the 1-byte short header, up to a
/// 20-byte Destination Connection ID (the RFC 9000 5.1 maximum), up to a 4-byte packet number, and the
/// 16-byte AEAD tag. A caller sealing in place reserves payload.len + this so the sealed packet fits.
pub const short_seal_overhead_max: usize = 1 + 20 + 4 + Aes128Gcm.tag_length;

pub fn sealShort(out: []u8, keys: crypto.AesKeys, dcid: []const u8, packet_number: u32, payload: []const u8) OpenError![]const u8 {
    const pn_len: usize = if (packet_number <= 0xff) 1 else if (packet_number <= 0xffff) 2 else 4;

    var pos: usize = 0;
    // First byte: short form (0x00) | fixed bit (0x40) | spin 0 | key phase 0 | pn length - 1.
    out[pos] = 0x40 | @as(u8, @intCast(pn_len - 1));
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    const pn_offset = pos;
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, packet_number, .big);
    @memcpy(out[pos..][0..pn_len], pn_bytes[4 - pn_len ..]);
    pos += pn_len;

    const header_len = pos;
    if (header_len + payload.len + Aes128Gcm.tag_length > out.len) return error.ZixTruncated;

    const nonce = crypto.aeadNonce(keys.iv, packet_number);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[header_len .. header_len + payload.len], &tag, payload, out[0..header_len], nonce, keys.key);
    @memcpy(out[header_len + payload.len ..][0..Aes128Gcm.tag_length], &tag);

    const packet_len = header_len + payload.len + Aes128Gcm.tag_length;

    const sample_offset = pn_offset + 4;
    if (packet_len < sample_offset + 16) return error.ZixTruncated;

    var sample: [16]u8 = undefined;
    @memcpy(&sample, out[sample_offset .. sample_offset + 16]);
    const mask = crypto.headerMaskAes(keys.hp, sample);
    out[0] ^= mask[0] & 0x1f; // short header: low 5 bits
    for (0..pn_len) |i| out[pn_offset + i] ^= mask[1 + i];

    return out[0..packet_len];
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: open the RFC 9001 A.2 protected client Initial" {
    // Build the byte-exact A.2 protected packet via the seal path, then open it back.
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = crypto.initialSecrets(&dcid);
    const client_keys = crypto.AesKeys.fromSecret(secrets.client);

    const header = hexBytes("c300000001088394c8f03e5157080000449e00000002");
    const pn_offset: usize = 18;
    const pn_length: usize = 4;

    const crypto_frame = hexBytes("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" ++
        "04fe3a47f06a2b69484c000004130113020100" ++ "00c000000010000e00000b6578" ++
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" ++
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" ++
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" ++
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100" ++
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" ++
        "75300901100f088394c8f03e5157080604" ++ "8000ffff");

    var payload: [1162]u8 = undefined;
    @memset(&payload, 0);
    @memcpy(payload[0..crypto_frame.len], &crypto_frame);

    const nonce = crypto.aeadNonce(client_keys.iv, 2);
    var ciphertext: [1162]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &payload, &header, nonce, client_keys.key);

    var sample: [16]u8 = undefined;
    @memcpy(&sample, ciphertext[0..16]);
    const mask = crypto.headerMaskAes(client_keys.hp, sample);

    var protected_packet: [header.len + 1162 + Aes128Gcm.tag_length]u8 = undefined;
    @memcpy(protected_packet[0..header.len], &header);
    protected_packet[0] ^= mask[0] & 0x0f;
    for (0..pn_length) |i| protected_packet[pn_offset + i] ^= mask[1 + i];
    @memcpy(protected_packet[header.len .. header.len + 1162], &ciphertext);
    @memcpy(protected_packet[header.len + 1162 ..], &tag);

    // Open it back with the same client keys.
    var out: [2048]u8 = undefined;
    const opened = try openInitial(&protected_packet, client_keys, &out);

    try std.testing.expectEqual(@as(u64, 2), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &crypto_frame, opened.payload[0..crypto_frame.len]);
}

test "zix http3: sealInitial then openInitial round-trips the payload" {
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = crypto.initialSecrets(&dcid);
    const server_keys = crypto.AesKeys.fromSecret(secrets.server);

    // A server Initial carrying a small CRYPTO frame (a stand-in ServerHello body) plus PADDING to
    // reach the header-protection sample length.
    var payload: [64]u8 = undefined;
    @memset(&payload, 0);
    const frame_bytes = hexBytes("0600200200006c0303") ++ hexBytes("aabbccddeeff");
    @memcpy(payload[0..frame_bytes.len], &frame_bytes);

    var out: [256]u8 = undefined;
    const sealed = try sealInitial(&out, server_keys, &dcid, &hexBytes("c0ffee00"), 0, &payload);

    var recovered: [256]u8 = undefined;
    const opened = try openInitial(sealed, server_keys, &recovered);

    try std.testing.expectEqual(@as(u64, 0), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &payload, opened.payload[0..payload.len]);
}

test "zix http3: sealHandshake then openHandshake round-trips the payload" {
    const secret: crypto.Secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const keys = crypto.AesKeys.fromSecret(secret);

    var payload: [64]u8 = undefined;
    @memset(&payload, 0);
    const frame_bytes = hexBytes("080041020800000e") ++ hexBytes("aabbccdd");
    @memcpy(payload[0..frame_bytes.len], &frame_bytes);

    var out: [256]u8 = undefined;
    const sealed = try sealHandshake(&out, keys, &hexBytes("c0ffee00"), &hexBytes("1234"), 0, &payload);

    var recovered: [256]u8 = undefined;
    const opened = try openHandshake(sealed, keys, &recovered);

    try std.testing.expectEqual(@as(u64, 0), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &payload, opened.payload[0..payload.len]);
}

test "zix http3: sealShort then openShort round-trips the payload" {
    const secret: crypto.Secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const keys = crypto.AesKeys.fromSecret(secret);
    const dcid = hexBytes("c0ffee0011223344");

    var payload: [64]u8 = undefined;
    @memset(&payload, 0);
    const stream_frame = hexBytes("0800") ++ hexBytes("0102030405");
    @memcpy(payload[0..stream_frame.len], &stream_frame);

    var out: [256]u8 = undefined;
    const sealed = try sealShort(&out, keys, &dcid, 0, &payload);

    var recovered: [256]u8 = undefined;
    const opened = try openShort(sealed, keys, dcid.len, null, &recovered);

    try std.testing.expectEqual(@as(u64, 0), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &payload, opened.payload[0..payload.len]);
}

// Seal a short-header packet with the packet number FORCED to one wire byte while the AEAD nonce uses
// the full number, exactly as a QUIC sender truncates once its largest-acked lets it (RFC 9000 17.1).
// sealShort never does this (it sizes the field to the value), so this reproduces the peer behavior
// that broke the receiver past packet 256.
fn sealShortTruncated1(out: []u8, keys: crypto.AesKeys, dcid: []const u8, full_pn: u64, payload: []const u8) []const u8 {
    var pos: usize = 0;
    out[pos] = 0x40; // short form, fixed bit, pn length - 1 = 0 (one byte)
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    const pn_offset = pos;
    out[pos] = @intCast(full_pn & 0xff); // one truncated byte
    pos += 1;

    const header_len = pos;
    const nonce = crypto.aeadNonce(keys.iv, full_pn);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[header_len .. header_len + payload.len], &tag, payload, out[0..header_len], nonce, keys.key);
    @memcpy(out[header_len + payload.len ..][0..Aes128Gcm.tag_length], &tag);

    const packet_len = header_len + payload.len + Aes128Gcm.tag_length;
    var sample: [16]u8 = undefined;
    @memcpy(&sample, out[pn_offset + 4 .. pn_offset + 4 + 16]);
    const mask = crypto.headerMaskAes(keys.hp, sample);
    out[0] ^= mask[0] & 0x1f;
    out[pn_offset] ^= mask[1];

    return out[0..packet_len];
}

test "zix http3: openShort reconstructs a truncated packet number past 256 (the ~256-packet stall)" {
    const secret: crypto.Secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const keys = crypto.AesKeys.fromSecret(secret);
    const dcid = hexBytes("c0ffee0011223344");

    // Full packet number 300: on a 1-byte-truncated stream the wire carries 300 & 0xff = 44. Without
    // reconstruction the receiver builds the nonce from 44 and decryption fails, which is exactly the
    // connection death after ~256 packets.
    var payload: [40]u8 = @splat(0);
    const frame = hexBytes("0800") ++ hexBytes("0102030405");
    @memcpy(payload[0..frame.len], &frame);

    var out: [256]u8 = undefined;
    const sealed = sealShortTruncated1(&out, keys, &dcid, 300, &payload);

    // With the largest-received number (299), openShort recovers 300 and decrypts.
    var recovered: [256]u8 = undefined;
    const opened = try openShort(sealed, keys, dcid.len, 299, &recovered);
    try std.testing.expectEqual(@as(u64, 300), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &payload, opened.payload[0..payload.len]);

    // Without reconstruction (the old behavior, largest_pn = null) the same packet fails to decrypt:
    // proof this test guards the real regression, not a tautology.
    var recovered2: [256]u8 = undefined;
    try std.testing.expectError(error.ZixDecrypt, openShort(sealed, keys, dcid.len, null, &recovered2));
}

test "zix http3: openInitial rejects a tampered packet" {
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = crypto.initialSecrets(&dcid);
    const client_keys = crypto.AesKeys.fromSecret(secrets.client);

    var tampered: [200]u8 = undefined;
    @memset(&tampered, 0);
    tampered[0] = 0xc3;
    std.mem.writeInt(u32, tampered[1..5], 1, .big);
    tampered[5] = 8;
    @memcpy(tampered[6..14], &dcid);
    tampered[14] = 0; // scid len
    tampered[15] = 0; // token len
    _ = varint.write(tampered[16..18], 178); // length: pn(4) + 158 payload + 16 tag
    var out: [256]u8 = undefined;

    // Random ciphertext under the real keys does not authenticate.
    try std.testing.expectError(error.ZixDecrypt, openInitial(&tampered, client_keys, &out));
}
