//! zix SRTP key derivation (RFC 3711 4.3).
//!
//! What:
//! - Turns the master key and master salt that came out of the DTLS handshake into the six values
//!   SRTP and SRTCP actually use: a cipher key, a salt, and an authentication key for each.
//!
//! Note:
//! - The pseudo-random function is the same AES counter mode the packets use, so this file is a
//!   counter block and a label, and srtp_cipher.zig does the work.
//! - The label byte is exclusive-ored into the master salt at byte 7, not prepended. The salt is
//!   14 bytes and the key identifier is 7 (one label byte plus a six-byte divided index), and
//!   they are aligned by their LOW ends. Getting that offset wrong produces keys that look
//!   perfectly random and match nothing.
//! - DTLS-SRTP fixes the key derivation rate at zero (RFC 5764 4.1.2), so the divided index is
//!   always six zero bytes and derivation happens exactly once per master key. There is no index
//!   parameter here on purpose: taking one would suggest re-derivation that does not happen.
//! - RTP and RTCP get different labels from the same master key, which is what keeps a media
//!   keystream from ever lining up with a control keystream.

const std = @import("std");

const cipher = @import("srtp_cipher.zig");

/// Master key length for the AES-128 profiles.
pub const MASTER_KEY_LEN: usize = 16;

/// Master salt length for the AES-128 profiles.
pub const MASTER_SALT_LEN: usize = 14;

/// Session authentication key length for HMAC-SHA1 (RFC 5764 4.1.2).
pub const AUTH_KEY_LEN: usize = 20;

/// Where the label byte lands in the master salt, from aligning a 7-byte key identifier with a
/// 14-byte salt at their low ends.
pub const LABEL_AT: usize = 7;

/// Which of the six values is being derived (RFC 3711 4.3.1, 4.3.2).
pub const Label = enum(u8) {
    /// SRTP cipher key.
    RTP_ENCRYPTION = 0x00,
    /// SRTP authentication key.
    RTP_AUTHENTICATION = 0x01,
    /// SRTP session salt.
    RTP_SALT = 0x02,
    /// SRTCP cipher key.
    RTCP_ENCRYPTION = 0x03,
    /// SRTCP authentication key.
    RTCP_AUTHENTICATION = 0x04,
    /// SRTCP session salt.
    RTCP_SALT = 0x05,
};

/// The three values one direction of one protocol runs on.
pub const SessionKeys = struct {
    /// Fed to the counter mode cipher.
    cipher_key: [cipher.KEY_LEN]u8,
    /// Seeds every counter block for this stream.
    cipher_salt: [cipher.SALT_LEN]u8,
    /// Fed to HMAC-SHA1.
    auth_key: [AUTH_KEY_LEN]u8,
};

/// Derive one value of any length (RFC 3711 4.3.1).
///
/// Param:
/// out - []u8 (filled completely, its length is what gets derived)
/// master_key - [MASTER_KEY_LEN]u8
/// master_salt - [MASTER_SALT_LEN]u8
/// label - Label
///
/// Return:
/// - void
/// - error.ZixSegmentTooLong for an output past what one counter block may produce
pub fn derive(
    out: []u8,
    master_key: [MASTER_KEY_LEN]u8,
    master_salt: [MASTER_SALT_LEN]u8,
    label: Label,
) cipher.Error!void {
    var block: [cipher.BLOCK_LEN]u8 = @splat(0);
    @memcpy(block[0..MASTER_SALT_LEN], &master_salt);

    // The divided index is zero at a rate of zero, so only the label byte changes anything.
    block[LABEL_AT] ^= @intFromEnum(label);

    try cipher.keystream(out, master_key, block);
}

/// Derive the three values SRTP uses.
///
/// Param:
/// master_key - [MASTER_KEY_LEN]u8
/// master_salt - [MASTER_SALT_LEN]u8
///
/// Return:
/// - SessionKeys
pub fn rtpKeys(master_key: [MASTER_KEY_LEN]u8, master_salt: [MASTER_SALT_LEN]u8) SessionKeys {
    return keysFor(master_key, master_salt, .RTP_ENCRYPTION, .RTP_AUTHENTICATION, .RTP_SALT);
}

/// Derive the three values SRTCP uses.
///
/// Param:
/// master_key - [MASTER_KEY_LEN]u8
/// master_salt - [MASTER_SALT_LEN]u8
///
/// Return:
/// - SessionKeys
pub fn rtcpKeys(master_key: [MASTER_KEY_LEN]u8, master_salt: [MASTER_SALT_LEN]u8) SessionKeys {
    return keysFor(master_key, master_salt, .RTCP_ENCRYPTION, .RTCP_AUTHENTICATION, .RTCP_SALT);
}

/// Derive one label triple. The lengths are all inside what a single counter block produces, so
/// the cipher cannot fail here.
fn keysFor(
    master_key: [MASTER_KEY_LEN]u8,
    master_salt: [MASTER_SALT_LEN]u8,
    encryption: Label,
    authentication: Label,
    salt: Label,
) SessionKeys {
    var keys: SessionKeys = undefined;

    derive(&keys.cipher_key, master_key, master_salt, encryption) catch unreachable;
    derive(&keys.auth_key, master_key, master_salt, authentication) catch unreachable;
    derive(&keys.cipher_salt, master_key, master_salt, salt) catch unreachable;

    return keys;
}

// --------------------------------------------------------------------------------------- //
// test cases

/// The master key from the RFC 3711 B.3 vector.
const VECTOR_MASTER_KEY: [MASTER_KEY_LEN]u8 = .{
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
};

/// The master salt from the same vector.
const VECTOR_MASTER_SALT: [MASTER_SALT_LEN]u8 = .{
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE,
    0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
};

test "zix media: srtp key derive, the cipher key matches the published vector" {
    var derived: [16]u8 = undefined;
    try derive(&derived, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_ENCRYPTION);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE,
        0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87,
    }, &derived);
}

test "zix media: srtp key derive, the cipher salt matches the published vector" {
    var derived: [14]u8 = undefined;
    try derive(&derived, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_SALT);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C,
        0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1,
    }, &derived);
}

test "zix media: srtp key derive, the full 94-byte auth key vector steps the counter" {
    // The vector runs to 94 bytes, which is six AES blocks. Pinning all of it is what proves the
    // block counter advances, and a keystream that never advanced would still pass at 16 bytes.
    var derived: [94]u8 = undefined;
    try derive(&derived, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_AUTHENTICATION);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B,
        0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15,
        0x6D, 0x38, 0xBA, 0xA4, 0x8F, 0x0A, 0x0A, 0xCF,
        0x3C, 0x34, 0xE2, 0x35, 0x9E, 0x6C, 0xDB, 0xCE,
        0xE0, 0x49, 0x64, 0x6C, 0x43, 0xD9, 0x32, 0x7A,
        0xD1, 0x75, 0x57, 0x8E, 0xF7, 0x22, 0x70, 0x98,
        0x63, 0x71, 0xC1, 0x0C, 0x9A, 0x36, 0x9A, 0xC2,
        0xF9, 0x4A, 0x8C, 0x5F, 0xBC, 0xDD, 0xDC, 0x25,
        0x6D, 0x6E, 0x91, 0x9A, 0x48, 0xB6, 0x10, 0xEF,
        0x17, 0xC2, 0x04, 0x1E, 0x47, 0x40, 0x35, 0x76,
        0x6B, 0x68, 0x64, 0x2C, 0x59, 0xBB, 0xFC, 0x2F,
        0x34, 0xDB, 0x60, 0xDB, 0xDF, 0xB2,
    }, &derived);
}

test "zix media: srtp key derive, the label lands at byte seven of the salt" {
    // The vector's own intermediate value: label 0x02 turns salt byte 7 from 0xEB into 0xE9.
    var salted = VECTOR_MASTER_SALT;
    salted[LABEL_AT] ^= @intFromEnum(Label.RTP_SALT);

    try std.testing.expectEqual(@as(u8, 0xE9), salted[LABEL_AT]);
    try std.testing.expectEqual(@as(u8, 0x0E), salted[0]);
    try std.testing.expectEqual(@as(u8, 0xE6), salted[MASTER_SALT_LEN - 1]);
}

test "zix media: srtp key derive, every label gives different material" {
    const labels = [_]Label{
        .RTP_ENCRYPTION,  .RTP_AUTHENTICATION,  .RTP_SALT,
        .RTCP_ENCRYPTION, .RTCP_AUTHENTICATION, .RTCP_SALT,
    };

    var seen: [labels.len][16]u8 = undefined;

    for (labels, 0..) |label, index| {
        try derive(&seen[index], VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, label);
    }

    for (0..labels.len) |first| {
        for (first + 1..labels.len) |second| {
            try std.testing.expect(!std.mem.eql(u8, &seen[first], &seen[second]));
        }
    }
}

test "zix media: srtp key rtpKeys, the bundle is the same three derivations" {
    const keys = rtpKeys(VECTOR_MASTER_KEY, VECTOR_MASTER_SALT);

    var cipher_key: [16]u8 = undefined;
    var cipher_salt: [14]u8 = undefined;
    var auth_key: [AUTH_KEY_LEN]u8 = undefined;

    try derive(&cipher_key, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_ENCRYPTION);
    try derive(&cipher_salt, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_SALT);
    try derive(&auth_key, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTP_AUTHENTICATION);

    try std.testing.expectEqualSlices(u8, &cipher_key, &keys.cipher_key);
    try std.testing.expectEqualSlices(u8, &cipher_salt, &keys.cipher_salt);
    try std.testing.expectEqualSlices(u8, &auth_key, &keys.auth_key);
}

test "zix media: srtp key rtpKeys, the auth key is the first 20 bytes of the long vector" {
    const keys = rtpKeys(VECTOR_MASTER_KEY, VECTOR_MASTER_SALT);

    // RFC 5764 4.1.2 fixes the authentication key at 160 bits, and the RFC 3711 vector runs
    // longer only to show the counter advancing.
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4,
        0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4,
    }, &keys.auth_key);
}

test "zix media: srtp key, rtp and rtcp never share a value" {
    const rtp = rtpKeys(VECTOR_MASTER_KEY, VECTOR_MASTER_SALT);
    const rtcp = rtcpKeys(VECTOR_MASTER_KEY, VECTOR_MASTER_SALT);

    try std.testing.expect(!std.mem.eql(u8, &rtp.cipher_key, &rtcp.cipher_key));
    try std.testing.expect(!std.mem.eql(u8, &rtp.cipher_salt, &rtcp.cipher_salt));
    try std.testing.expect(!std.mem.eql(u8, &rtp.auth_key, &rtcp.auth_key));
}

test "zix media: srtp key, a different master key or salt changes everything" {
    const base = rtpKeys(VECTOR_MASTER_KEY, VECTOR_MASTER_SALT);

    var other_key = VECTOR_MASTER_KEY;
    other_key[0] ^= 0x01;

    var other_salt = VECTOR_MASTER_SALT;
    other_salt[0] ^= 0x01;

    const by_key = rtpKeys(other_key, VECTOR_MASTER_SALT);
    const by_salt = rtpKeys(VECTOR_MASTER_KEY, other_salt);

    try std.testing.expect(!std.mem.eql(u8, &base.cipher_key, &by_key.cipher_key));
    try std.testing.expect(!std.mem.eql(u8, &base.cipher_key, &by_salt.cipher_key));
}

test "zix media: srtp key derive, it is deterministic" {
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;

    try derive(&first, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTCP_ENCRYPTION);
    try derive(&second, VECTOR_MASTER_KEY, VECTOR_MASTER_SALT, .RTCP_ENCRYPTION);

    try std.testing.expectEqualSlices(u8, &first, &second);
}
