//! zix HTTP/3 QUIC packet protection (RFC 9001, Layer C).
//!
//! What:
//! - The deterministic crypto bottom of the QUIC stack: Initial secret derivation, per-level
//!   packet-protection keys (AES-128-GCM and ChaCha20-Poly1305), the AEAD nonce and the
//!   header-protection mask, the Retry integrity tag, the key-update secret ratchet, and the AEAD
//!   usage limits.
//! - Every value is proven byte-exact against the RFC 9001 Appendix A worked examples in the tests
//!   below, the same in-file-vector approach the TLS 1.3 key schedule uses against RFC 8448.
//!
//! Note:
//! - Cryptography is std.crypto throughout. HKDF-Expand-Label is the TLS 1.3 form (RFC 8446 7.1).
//! - Connection state (retained old keys, two receive-key sets across a phase flip) lives in
//!   connection.zig, not here. This module is pure functions plus the usage-accounting struct.
//! - The live path is AES-128-GCM only. The Retry tag, key-update ratchet, ChaCha20-Poly1305 mask,
//!   AeadId, and the AEAD usage-limit helpers are implemented and tested but not wired yet
//!   (deferred, RFC-completeness).

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// One SHA-256 block, the width of every schedule secret.
pub const hash_length = Sha256.digest_length;

/// A schedule secret, one SHA-256 block wide.
pub const Secret = [hash_length]u8;

/// The QUIC version 1 Initial salt (RFC 9001 5.2).
pub const initial_salt = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

/// The published version-1 Retry secret (RFC 9001 5.8). The fixed Retry key and nonce derive from it.
pub const retry_secret = [_]u8{ 0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02, 0x81, 0x4c, 0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f, 0xca, 0x8e };

// --------------------------------------------------------------- //

/// HKDF-Expand-Label (RFC 8446 7.1): the "tls13 " prefix, the bare label, and a context.
///
/// Param:
/// out - []u8 (filled in place, its length is the requested output width)
/// secret - Secret (the pseudorandom key)
/// label - []const u8 (the bare label, without the "tls13 " prefix, e.g. "quic key")
/// context - []const u8 (the context bytes, empty for the QUIC key derivations)
///
/// Return:
/// - void
pub fn expandLabel(out: []u8, secret: Secret, label: []const u8, context: []const u8) void {
    const prefix = "tls13 ";

    var info: [2 + 1 + prefix.len + 255 + 1 + hash_length]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(prefix.len + label.len);
    @memcpy(info[3 .. 3 + prefix.len], prefix);
    @memcpy(info[3 + prefix.len .. 3 + prefix.len + label.len], label);

    const context_pos = 3 + prefix.len + label.len;
    info[context_pos] = @intCast(context.len);
    @memcpy(info[context_pos + 1 .. context_pos + 1 + context.len], context);

    HkdfSha256.expand(out, info[0 .. context_pos + 1 + context.len], secret);
}

// --------------------------------------------------------------- //

/// AES-128-GCM packet-protection material for one encryption level (RFC 9001 5.1).
pub const AesKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,

    /// Derive key / iv / hp from a traffic secret via HKDF-Expand-Label (RFC 9001 5.1).
    pub fn fromSecret(secret: Secret) AesKeys {
        var keys: AesKeys = undefined;
        expandLabel(&keys.key, secret, "quic key", "");
        expandLabel(&keys.iv, secret, "quic iv", "");
        expandLabel(&keys.hp, secret, "quic hp", "");

        return keys;
    }
};

/// ChaCha20-Poly1305 packet-protection material for one encryption level (RFC 9001 5.1). Unlike the
/// AES variant the key and hp key are 32 bytes wide.
pub const ChaChaKeys = struct {
    key: [32]u8,
    iv: [12]u8,
    hp: [32]u8,

    /// Derive key / iv / hp from a traffic secret via HKDF-Expand-Label (RFC 9001 5.1).
    pub fn fromSecret(secret: Secret) ChaChaKeys {
        var keys: ChaChaKeys = undefined;
        expandLabel(&keys.key, secret, "quic key", "");
        expandLabel(&keys.iv, secret, "quic iv", "");
        expandLabel(&keys.hp, secret, "quic hp", "");

        return keys;
    }
};

/// The Initial secrets derived from the client's Destination Connection ID (RFC 9001 5.2).
pub const InitialSecrets = struct {
    initial: Secret,
    client: Secret,
    server: Secret,
};

/// Derive the client and server Initial secrets from the client's Destination Connection ID
/// (RFC 9001 5.2): HKDF-Extract under the version-1 salt, then HKDF-Expand-Label "client in" /
/// "server in".
pub fn initialSecrets(dcid: []const u8) InitialSecrets {
    const initial = HkdfSha256.extract(&initial_salt, dcid);

    var client: Secret = undefined;
    var server: Secret = undefined;
    expandLabel(&client, initial, "client in", "");
    expandLabel(&server, initial, "server in", "");

    return .{ .initial = initial, .client = client, .server = server };
}

/// Build the AEAD nonce (RFC 9001 5.3): the 62-bit packet number, left-padded to the IV width,
/// XORed with the IV.
pub fn aeadNonce(iv: [12]u8, packet_number: u64) [12]u8 {
    var nonce = iv;
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, packet_number, .big);

    for (0..8) |i| nonce[12 - 8 + i] ^= pn_bytes[i];

    return nonce;
}

/// Compute the AES header-protection mask (RFC 9001 5.4.1): mask = AES-ECB(hp, sample).
pub fn headerMaskAes(hp: [16]u8, sample: [16]u8) [16]u8 {
    var mask: [16]u8 = undefined;
    Aes128.initEnc(hp).encrypt(&mask, &sample);

    return mask;
}

/// Compute the ChaCha20-based header-protection mask (RFC 9001 5.4.4): the first 4 bytes of the
/// sample are the little-endian block counter, the remaining 12 bytes are the nonce, and the mask is
/// ChaCha20 run over five zero bytes.
pub fn headerMaskChaCha(hp: [32]u8, sample: [16]u8) [5]u8 {
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    const nonce: [12]u8 = sample[4..16].*;

    var mask: [5]u8 = undefined;
    const zeros: [5]u8 = @splat(0);
    ChaCha20IETF.xor(&mask, &zeros, counter, hp, nonce);

    return mask;
}

// --------------------------------------------------------------- //

/// Compute the Retry Integrity Tag (RFC 9001 5.8): AEAD-AES-128-GCM with empty plaintext over the
/// Retry Pseudo-Packet as associated data.
///
/// Param:
/// key - [16]u8 (the fixed version-1 Retry key)
/// nonce - [12]u8 (the fixed version-1 Retry nonce)
/// pseudo_packet - []const u8 (ODCID Length + ODCID + Retry packet without its tag)
///
/// Return:
/// - [16]u8 (the integrity tag)
pub fn retryTag(key: [16]u8, nonce: [12]u8, pseudo_packet: []const u8) [16]u8 {
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    var ciphertext: [0]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &[_]u8{}, pseudo_packet, nonce, key);

    return tag;
}

/// The fixed version-1 Retry key and nonce (RFC 9001 5.8), derived from `retry_secret`.
pub const RetryKeyNonce = struct {
    key: [16]u8,
    nonce: [12]u8,
};

/// Derive the fixed version-1 Retry key and nonce (RFC 9001 5.8).
pub fn retryKeyNonce() RetryKeyNonce {
    var out: RetryKeyNonce = undefined;
    expandLabel(&out.key, retry_secret, "quic key", "");
    expandLabel(&out.nonce, retry_secret, "quic iv", "");

    return out;
}

/// Derive the next-generation traffic secret for a key update (RFC 9001 6.1):
/// secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", 32).
pub fn nextKeyUpdateSecret(secret: Secret) Secret {
    var next: Secret = undefined;
    expandLabel(&next, secret, "quic ku", "");

    return next;
}

// --------------------------------------------------------------- //

/// The AEAD functions QUIC version 1 uses with the TLS 1.3 cipher suites zix offers (RFC 9001 5.3).
pub const AeadId = enum { aes_128_gcm, aes_256_gcm, chacha20_poly1305 };

/// ChaCha20-Poly1305's confidentiality limit exceeds the 2^62 maximum packet number, so RFC 9001
/// 6.6 says it can be disregarded. The sentinel never trips the send-side check.
pub const confidentiality_disregarded: u64 = std.math.maxInt(u64);

/// The confidentiality limit (RFC 9001 6.6): the number of packets that may be encrypted under one
/// key before a key update is mandatory.
pub fn confidentialityLimit(aead: AeadId) u64 {
    return switch (aead) {
        .aes_128_gcm, .aes_256_gcm => 1 << 23,
        .chacha20_poly1305 => confidentiality_disregarded,
    };
}

/// The integrity limit (RFC 9001 6.6): the number of received packets that may fail authentication
/// across a connection before it MUST be closed with AEAD_LIMIT_REACHED.
pub fn integrityLimit(aead: AeadId) u64 {
    return switch (aead) {
        .aes_128_gcm, .aes_256_gcm => 1 << 52,
        .chacha20_poly1305 => 1 << 36,
    };
}

/// What the usage accounting requires of the endpoint after one packet event (RFC 9001 6.6).
pub const Action = enum {
    /// Within both limits, keep using the keys.
    ok,
    /// The confidentiality limit is reached: a key update MUST happen before sending more.
    initiate_key_update,
    /// The integrity limit is reached, or a key update is impossible at the confidentiality limit:
    /// close the connection with AEAD_LIMIT_REACHED.
    close_aead_limit_reached,
};

/// Per-key usage accounting for one key phase (RFC 9001 6.6). Confidentiality counts packets sent,
/// integrity counts received packets that fail authentication.
pub const KeyUsage = struct {
    aead: AeadId,
    encrypted_packets: u64 = 0,
    auth_failures: u64 = 0,
    key_update_possible: bool = true,

    /// Account one packet about to be sent. At the confidentiality limit a key update is mandatory
    /// before sending more, and if one is impossible the connection MUST close.
    pub fn onSend(self: *KeyUsage) Action {
        self.encrypted_packets += 1;

        if (self.encrypted_packets < confidentialityLimit(self.aead)) return .ok;

        return if (self.key_update_possible) .initiate_key_update else .close_aead_limit_reached;
    }

    /// Account one received packet that failed authentication. At the integrity limit the
    /// connection MUST close with AEAD_LIMIT_REACHED.
    pub fn onAuthFailure(self: *KeyUsage) Action {
        self.auth_failures += 1;

        return if (self.auth_failures >= integrityLimit(self.aead)) .close_aead_limit_reached else .ok;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Decode a hex literal (no separators) into a fixed array, for the RFC vectors.
fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9001 A.1 Initial secrets and keys" {
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = initialSecrets(&dcid);

    try std.testing.expectEqualSlices(u8, &hexBytes("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), &secrets.initial);
    try std.testing.expectEqualSlices(u8, &hexBytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), &secrets.client);
    try std.testing.expectEqualSlices(u8, &hexBytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"), &secrets.server);

    const client_keys = AesKeys.fromSecret(secrets.client);
    try std.testing.expectEqualSlices(u8, &hexBytes("1f369613dd76d5467730efcbe3b1a22d"), &client_keys.key);
    try std.testing.expectEqualSlices(u8, &hexBytes("fa044b2f42a3fd3b46fb255c"), &client_keys.iv);
    try std.testing.expectEqualSlices(u8, &hexBytes("9f50449e04a0e810283a1e9933adedd2"), &client_keys.hp);

    const server_keys = AesKeys.fromSecret(secrets.server);
    try std.testing.expectEqualSlices(u8, &hexBytes("cf3a5331653c364c88f0f379b6067e37"), &server_keys.key);
    try std.testing.expectEqualSlices(u8, &hexBytes("0ac1493ca1905853b0bba03e"), &server_keys.iv);
    try std.testing.expectEqualSlices(u8, &hexBytes("c206b8d9b9f0f37644430b490eeaa314"), &server_keys.hp);
}

test "zix http3: RFC 9001 A.2 client Initial packet protection" {
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = initialSecrets(&dcid);
    const client_keys = AesKeys.fromSecret(secrets.client);

    const header = hexBytes("c300000001088394c8f03e5157080000449e00000002");
    const pn_offset: usize = 18;
    const pn_length: usize = 4;
    const packet_number: u64 = 2;

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

    const nonce = aeadNonce(client_keys.iv, packet_number);

    var ciphertext: [1162]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &payload, &header, nonce, client_keys.key);

    const sample_start = pn_offset + 4 - header.len;
    var sample: [16]u8 = undefined;
    @memcpy(&sample, ciphertext[sample_start .. sample_start + 16]);
    try std.testing.expectEqualSlices(u8, &hexBytes("d1b1c98dd7689fb8ec11d242b123dc9b"), &sample);

    const mask = headerMaskAes(client_keys.hp, sample);
    try std.testing.expectEqualSlices(u8, &hexBytes("437b9aec36"), mask[0..5]);

    var protected_header = header;
    protected_header[0] ^= mask[0] & 0x0f;
    for (0..pn_length) |i| protected_header[pn_offset + i] ^= mask[1 + i];

    try std.testing.expectEqualSlices(u8, &hexBytes("c000000001088394c8f03e5157080000449e7b9aec34"), &protected_header);
    try std.testing.expectEqualSlices(u8, &hexBytes("c000000001088394c8f03e5157080000"), protected_header[0..16]);
    try std.testing.expectEqualSlices(u8, &hexBytes("e221af44860018ab0856972e194cd934"), &tag);
}

test "zix http3: RFC 9001 5.8 + A.4 Retry key, nonce, and integrity tag" {
    const kn = retryKeyNonce();
    try std.testing.expectEqualSlices(u8, &hexBytes("be0c690b9f66575a1d766b54e368c84e"), &kn.key);
    try std.testing.expectEqualSlices(u8, &hexBytes("461599d35d632bf2239825bb"), &kn.nonce);

    const odcid = hexBytes("8394c8f03e515708");
    const retry_no_tag = hexBytes("ff000000010008f067a5502a4262b5746f6b656e");

    var pseudo: [1 + odcid.len + retry_no_tag.len]u8 = undefined;
    pseudo[0] = @intCast(odcid.len);
    @memcpy(pseudo[1 .. 1 + odcid.len], &odcid);
    @memcpy(pseudo[1 + odcid.len ..], &retry_no_tag);

    const tag = retryTag(kn.key, kn.nonce, &pseudo);
    try std.testing.expectEqualSlices(u8, &hexBytes("04a265ba2eff4d829058fb3f0f2496ba"), &tag);
}

test "zix http3: RFC 9001 A.5 ChaCha20 keys, key update, and short-header protection" {
    const secret: Secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const keys = ChaChaKeys.fromSecret(secret);
    try std.testing.expectEqualSlices(u8, &hexBytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), &keys.key);
    try std.testing.expectEqualSlices(u8, &hexBytes("e0459b3474bdd0e44a41c144"), &keys.iv);
    try std.testing.expectEqualSlices(u8, &hexBytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), &keys.hp);

    const ku = nextKeyUpdateSecret(secret);
    try std.testing.expectEqualSlices(u8, &hexBytes("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"), &ku);

    const packet_number: u64 = 654360564;
    const pn_length: usize = 3;
    const hdr = hexBytes("4200bff4");
    const plaintext = hexBytes("01");

    const nonce = aeadNonce(keys.iv, packet_number);
    try std.testing.expectEqualSlices(u8, &hexBytes("e0459b3474bdd0e46d417eb0"), &nonce);

    var ciphertext: [1]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, &plaintext, &hdr, nonce, keys.key);

    var sealed: [1 + ChaCha20Poly1305.tag_length]u8 = undefined;
    @memcpy(sealed[0..1], &ciphertext);
    @memcpy(sealed[1..], &tag);
    try std.testing.expectEqualSlices(u8, &hexBytes("655e5cd55c41f69080575d7999c25a5bfb"), &sealed);

    var sample: [16]u8 = undefined;
    @memcpy(&sample, sealed[1 .. 1 + 16]);
    const mask = headerMaskChaCha(keys.hp, sample);
    try std.testing.expectEqualSlices(u8, &hexBytes("aefefe7d03"), &mask);

    var protected_header = hdr;
    protected_header[0] ^= mask[0] & 0x1f;
    for (0..pn_length) |i| protected_header[1 + i] ^= mask[1 + i];

    try std.testing.expectEqualSlices(u8, &hexBytes("4cfe4189"), &protected_header);
}

test "zix http3: RFC 9001 6.6 AEAD usage limits and accounting" {
    try std.testing.expectEqual(@as(u64, 1 << 23), confidentialityLimit(.aes_128_gcm));
    try std.testing.expectEqual(@as(u64, 1 << 23), confidentialityLimit(.aes_256_gcm));
    try std.testing.expectEqual(confidentiality_disregarded, confidentialityLimit(.chacha20_poly1305));

    try std.testing.expectEqual(@as(u64, 1 << 52), integrityLimit(.aes_128_gcm));
    try std.testing.expectEqual(@as(u64, 1 << 52), integrityLimit(.aes_256_gcm));
    try std.testing.expectEqual(@as(u64, 1 << 36), integrityLimit(.chacha20_poly1305));

    var send_usage = KeyUsage{ .aead = .aes_128_gcm, .encrypted_packets = (1 << 23) - 2 };
    try std.testing.expectEqual(Action.ok, send_usage.onSend());
    try std.testing.expectEqual(Action.initiate_key_update, send_usage.onSend());

    var stuck_usage = KeyUsage{ .aead = .aes_128_gcm, .encrypted_packets = (1 << 23) - 1, .key_update_possible = false };
    try std.testing.expectEqual(Action.close_aead_limit_reached, stuck_usage.onSend());

    var chacha_usage = KeyUsage{ .aead = .chacha20_poly1305, .encrypted_packets = 1 << 40 };
    try std.testing.expectEqual(Action.ok, chacha_usage.onSend());

    var recv_usage = KeyUsage{ .aead = .aes_128_gcm, .auth_failures = (1 << 52) - 2 };
    try std.testing.expectEqual(Action.ok, recv_usage.onAuthFailure());
    try std.testing.expectEqual(Action.close_aead_limit_reached, recv_usage.onAuthFailure());
}

test "zix http3: RFC 9001 9.5 constant-time tamper rejection" {
    const key: [16]u8 = @splat(0x2b);
    const nonce: [12]u8 = @splat(0x39);
    const header = "short-header";
    const plaintext = "PING-frame-payload";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, plaintext, header, nonce, key);

    var recovered: [plaintext.len]u8 = undefined;
    try Aes128Gcm.decrypt(&recovered, &ciphertext, tag, header, nonce, key);
    try std.testing.expectEqualSlices(u8, plaintext, &recovered);

    var tampered_tag = tag;
    tampered_tag[0] ^= 0x01;
    try std.testing.expect(std.meta.isError(Aes128Gcm.decrypt(&recovered, &ciphertext, tampered_tag, header, nonce, key)));

    var tampered_ct = ciphertext;
    tampered_ct[0] ^= 0x01;
    try std.testing.expect(std.meta.isError(Aes128Gcm.decrypt(&recovered, &tampered_ct, tag, header, nonce, key)));

    try std.testing.expect(std.meta.isError(Aes128Gcm.decrypt(&recovered, &ciphertext, tag, "Short-header", nonce, key)));

    var tamper_usage = KeyUsage{ .aead = .aes_128_gcm };
    if (std.meta.isError(Aes128Gcm.decrypt(&recovered, &ciphertext, tampered_tag, header, nonce, key))) {
        _ = tamper_usage.onAuthFailure();
    }
    try std.testing.expectEqual(@as(u64, 1), tamper_usage.auth_failures);

    const token_a: [16]u8 = @splat(0xa5);
    var token_b: [16]u8 = @splat(0xa5);
    try std.testing.expect(std.crypto.timing_safe.eql([16]u8, token_a, token_b));

    token_b[15] ^= 0x01;
    try std.testing.expect(!std.crypto.timing_safe.eql([16]u8, token_a, token_b));
}
