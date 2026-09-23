//! zix SRTP protection profile parameters (RFC 5764 4.1.2).
//!
//! What:
//! - What a negotiated profile means in bytes: how long the session cipher key, the salt, the
//!   authentication key, and each authentication tag are.
//!
//! Note:
//! - The profile itself is negotiated in the DTLS handshake, so the enum lives with the handshake
//!   in src/tls. This file is the media side of it: the numbers every packet is measured against.
//! - The trap: SRTP_AES128_CM_HMAC_SHA1_32 does NOT use a 32-bit tag on RTCP. RFC 5764 4.1.2
//!   gives it an 80-bit RTCP tag while RTP keeps 32, so one profile carries two tag lengths.
//!   Reading one number and applying it to both makes every RTCP packet fail authentication, and
//!   only RTCP, which reads as a control-path bug rather than a key one.
//! - The key derivation rate is zero for every profile (RFC 5764 4.1.2), so session keys are
//!   derived exactly once and never re-derived from a packet index.
//! - The NULL profiles are refused. They authenticate but do not encrypt, which is not something
//!   to answer with when the peer also offered a cipher, and dtls_exporter.zig already has no
//!   keys to export for them.

const std = @import("std");

const exporter = @import("../../../tls/dtls_exporter.zig");

/// The key derivation rate every DTLS-SRTP profile uses (RFC 5764 4.1.2).
pub const KEY_DERIVATION_RATE: u32 = 0;

/// Session cipher key length for the AES-128 profiles, 128 bits.
pub const CIPHER_KEY_LEN: usize = 16;

/// Session salt length for the AES-128 profiles, 112 bits.
pub const CIPHER_SALT_LEN: usize = 14;

/// Session authentication key length for HMAC-SHA1, 160 bits.
pub const AUTH_KEY_LEN: usize = 20;

/// The longest authentication tag any answered profile uses, 80 bits.
pub const MAX_TAG_LEN: usize = 10;

/// What stops a profile from being used.
pub const Error = error{
    /// A profile zix does not answer, including the NULL ciphers and anything unregistered.
    ZixUnsupportedProfile,
};

/// The byte lengths one profile fixes.
pub const Parameters = struct {
    /// Session cipher key, the AES-CM key.
    cipher_key_len: usize,
    /// Session salt, which seeds the counter block.
    cipher_salt_len: usize,
    /// Session authentication key fed to HMAC-SHA1.
    auth_key_len: usize,
    /// Tag length on an SRTP packet.
    rtp_tag_len: usize,
    /// Tag length on an SRTCP packet, which is not always the same number.
    rtcp_tag_len: usize,

    /// How many bytes one direction's key derivation produces.
    ///
    /// Return:
    /// - usize
    pub fn sessionMaterialLen(self: Parameters) usize {
        return self.cipher_key_len + self.cipher_salt_len + self.auth_key_len;
    }
};

/// The parameters a profile fixes (RFC 5764 4.1.2).
///
/// Param:
/// profile - exporter.SrtpProfile (what the handshake agreed on)
///
/// Return:
/// - Parameters
/// - error.ZixUnsupportedProfile
pub fn parametersFor(profile: exporter.SrtpProfile) Error!Parameters {
    return switch (profile) {
        .SRTP_AES128_CM_HMAC_SHA1_80 => .{
            .cipher_key_len = CIPHER_KEY_LEN,
            .cipher_salt_len = CIPHER_SALT_LEN,
            .auth_key_len = AUTH_KEY_LEN,
            .rtp_tag_len = 10,
            .rtcp_tag_len = 10,
        },
        .SRTP_AES128_CM_HMAC_SHA1_32 => .{
            .cipher_key_len = CIPHER_KEY_LEN,
            .cipher_salt_len = CIPHER_SALT_LEN,
            .auth_key_len = AUTH_KEY_LEN,
            .rtp_tag_len = 4,
            .rtcp_tag_len = 10,
        },
        else => error.ZixUnsupportedProfile,
    };
}

/// Whether zix answers this profile at all.
///
/// Param:
/// profile - exporter.SrtpProfile
///
/// Return:
/// - bool
pub fn isSupported(profile: exporter.SrtpProfile) bool {
    return parametersFor(profile) != Error.ZixUnsupportedProfile;
}

/// The profiles zix offers, in the order it would rather have them.
///
/// Note:
/// - The 80-bit tag comes first. Four more bytes per packet buys a far harder tag to forge, and
///   the 32-bit profile exists for links where those bytes matter.
///
/// Return:
/// - []const exporter.SrtpProfile
pub fn preferences() []const exporter.SrtpProfile {
    return &.{ .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_AES128_CM_HMAC_SHA1_32 };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix media: profile parametersFor, the 80-bit profile matches the published table" {
    const parameters = try parametersFor(.SRTP_AES128_CM_HMAC_SHA1_80);

    try std.testing.expectEqual(@as(usize, 16), parameters.cipher_key_len);
    try std.testing.expectEqual(@as(usize, 14), parameters.cipher_salt_len);
    try std.testing.expectEqual(@as(usize, 20), parameters.auth_key_len);
    try std.testing.expectEqual(@as(usize, 10), parameters.rtp_tag_len);
    try std.testing.expectEqual(@as(usize, 10), parameters.rtcp_tag_len);
}

test "zix media: profile parametersFor, the 32-bit profile keeps an 80-bit rtcp tag" {
    // The one number in this file that is easy to get wrong, and it only breaks RTCP.
    const parameters = try parametersFor(.SRTP_AES128_CM_HMAC_SHA1_32);

    try std.testing.expectEqual(@as(usize, 4), parameters.rtp_tag_len);
    try std.testing.expectEqual(@as(usize, 10), parameters.rtcp_tag_len);
    try std.testing.expect(parameters.rtp_tag_len != parameters.rtcp_tag_len);
}

test "zix media: profile parametersFor, both aes profiles share every key length" {
    const tag_80 = try parametersFor(.SRTP_AES128_CM_HMAC_SHA1_80);
    const tag_32 = try parametersFor(.SRTP_AES128_CM_HMAC_SHA1_32);

    try std.testing.expectEqual(tag_80.cipher_key_len, tag_32.cipher_key_len);
    try std.testing.expectEqual(tag_80.cipher_salt_len, tag_32.cipher_salt_len);
    try std.testing.expectEqual(tag_80.auth_key_len, tag_32.auth_key_len);
}

test "zix media: profile parametersFor, the null and unknown profiles are refused" {
    try std.testing.expectError(error.ZixUnsupportedProfile, parametersFor(.SRTP_NULL_HMAC_SHA1_80));
    try std.testing.expectError(error.ZixUnsupportedProfile, parametersFor(.SRTP_NULL_HMAC_SHA1_32));
    try std.testing.expectError(error.ZixUnsupportedProfile, parametersFor(@enumFromInt(0xFFFF)));
}

test "zix media: profile isSupported, it agrees with parametersFor" {
    try std.testing.expect(isSupported(.SRTP_AES128_CM_HMAC_SHA1_80));
    try std.testing.expect(isSupported(.SRTP_AES128_CM_HMAC_SHA1_32));
    try std.testing.expect(!isSupported(.SRTP_NULL_HMAC_SHA1_80));
    try std.testing.expect(!isSupported(@enumFromInt(0)));
}

test "zix media: profile sessionMaterialLen, one direction derives 50 bytes" {
    const parameters = try parametersFor(.SRTP_AES128_CM_HMAC_SHA1_80);

    try std.testing.expectEqual(@as(usize, 16 + 14 + 20), parameters.sessionMaterialLen());
}

test "zix media: profile preferences, every entry is one the exporter can key" {
    const master: [48]u8 = @splat(0x11);
    const client_random: [32]u8 = @splat(0x22);
    const server_random: [32]u8 = @splat(0x33);

    for (preferences()) |profile| {
        try std.testing.expect(isSupported(profile));

        _ = try exporter.srtpKeys(profile, master, client_random, server_random);
    }

    try std.testing.expectEqual(@as(usize, 2), preferences().len);
    try std.testing.expectEqual(exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, preferences()[0]);
}

test "zix media: profile, the tag ceiling covers every tag the table names" {
    for (preferences()) |profile| {
        const parameters = try parametersFor(profile);

        try std.testing.expect(parameters.rtp_tag_len <= MAX_TAG_LEN);
        try std.testing.expect(parameters.rtcp_tag_len <= MAX_TAG_LEN);
    }
}
