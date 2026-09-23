//! TLS 1.2 exported keying material (RFC 5705) and the DTLS-SRTP key split (RFC 5764 4.2).
//!
//! What:
//! - Derives key material for a protocol running alongside a DTLS association, from the same
//!   master secret, without ever exposing that secret. DTLS-SRTP is the reason it exists: media
//!   is protected by SRTP keys, not by DTLS records.
//! - Rides the TLS 1.2 PRF already in tls12_prf.zig. Nothing new is invented here, the value is
//!   in getting the seed exactly right.
//!
//! Note:
//! - The seed trap: RFC 5705 defines TWO forms. Without a context the seed is
//!   client_random ++ server_random. With a context, even a zero-length one, a 2-byte length is
//!   appended, so the output is different. DTLS-SRTP uses the NO-CONTEXT form, which is why
//!   `srtpKeys` passes null and not an empty slice. Passing an empty slice compiles, runs, and
//!   silently produces keys a peer cannot match.
//! - The SRTP keys are dormant until media lands. Data channels ride SCTP over DTLS records and
//!   never touch them.

const std = @import("std");

const prf = @import("tls12_prf.zig");

/// Exporter label for DTLS-SRTP (RFC 5764 4.2). The "EXTRACTOR" prefix is historical.
pub const LABEL_DTLS_SRTP: []const u8 = "EXTRACTOR-dtls_srtp";

/// Longest context this file accepts. The PRF builds label ++ seed in a fixed buffer, so the
/// context has to be bounded somewhere. No exporter in use here needs one at all.
pub const MAX_CONTEXT_LEN: usize = 128;

/// client_random ++ server_random, plus room for a length-prefixed context.
const MAX_SEED_LEN: usize = 64 + 2 + MAX_CONTEXT_LEN;

/// SRTP master key length for the AES-128 profiles, 128 bits (RFC 5764 4.1.2).
pub const SRTP_MASTER_KEY_LEN: usize = 16;

/// SRTP master salt length for the AES-128 profiles, 112 bits (RFC 5764 4.1.2).
pub const SRTP_MASTER_SALT_LEN: usize = 14;

pub const Error = error{
    /// The context is longer than MAX_CONTEXT_LEN.
    ZixContextTooLong,
    /// The profile has no cipher key to export.
    ZixUnsupportedProfile,
};

/// SRTP protection profiles negotiated by the use_srtp extension (RFC 5764 4.1.2).
pub const SrtpProfile = enum(u16) {
    SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001,
    SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002,
    SRTP_NULL_HMAC_SHA1_80 = 0x0005,
    SRTP_NULL_HMAC_SHA1_32 = 0x0006,
    _,
};

/// The four values RFC 5764 4.2 splits the exported bytes into, in wire order.
///
/// Note:
/// - Each side encrypts with its own write key and decrypts with the peer's. A server sending
///   media uses server_write_*, and reads the client's stream with client_write_*.
pub const SrtpKeys = struct {
    client_write_key: [SRTP_MASTER_KEY_LEN]u8,
    server_write_key: [SRTP_MASTER_KEY_LEN]u8,
    client_write_salt: [SRTP_MASTER_SALT_LEN]u8,
    server_write_salt: [SRTP_MASTER_SALT_LEN]u8,
};

/// Export keying material for another protocol (RFC 5705 4).
///
/// Note:
/// - context null and context "" are NOT the same. null omits the context entirely, an empty
///   slice appends a 2-byte length of zero. Read the RFC before choosing.
///
/// Param:
/// out - []u8 (filled completely, its length is the amount exported)
/// master_secret - [48]u8 (from the finished handshake)
/// client_random - [32]u8 (from ClientHello)
/// server_random - [32]u8 (from ServerHello)
/// label - []const u8 (registered exporter label, disambiguates one usage from another)
/// context - ?[]const u8 (null for no context, otherwise length-prefixed into the seed)
///
/// Return:
/// - void
/// - error.ZixContextTooLong when the context is over MAX_CONTEXT_LEN
pub fn exportKeyingMaterial(
    out: []u8,
    master_secret: [48]u8,
    client_random: [32]u8,
    server_random: [32]u8,
    label: []const u8,
    context: ?[]const u8,
) Error!void {
    var seed: [MAX_SEED_LEN]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);

    var seed_len: usize = 64;

    if (context) |bytes| {
        if (bytes.len > MAX_CONTEXT_LEN) return error.ZixContextTooLong;

        std.mem.writeInt(u16, seed[seed_len..][0..2], @intCast(bytes.len), .big);
        seed_len += 2;
        @memcpy(seed[seed_len..][0..bytes.len], bytes);
        seed_len += bytes.len;
    }

    prf.prf(out, &master_secret, label, seed[0..seed_len]);
}

/// Derive the SRTP master keys and salts for both directions (RFC 5764 4.2).
///
/// Note:
/// - Exports 2 * (key + salt) bytes in one call and splits them, because the split is positional
///   and doing it anywhere else invites getting the order wrong.
/// - The NULL profiles carry no cipher key, so there is nothing to export for them.
///
/// Param:
/// profile - SrtpProfile (the profile the handshake agreed on)
/// master_secret - [48]u8
/// client_random - [32]u8
/// server_random - [32]u8
///
/// Return:
/// - SrtpKeys
/// - error.ZixUnsupportedProfile for a profile without a cipher key
pub fn srtpKeys(
    profile: SrtpProfile,
    master_secret: [48]u8,
    client_random: [32]u8,
    server_random: [32]u8,
) Error!SrtpKeys {
    switch (profile) {
        .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_AES128_CM_HMAC_SHA1_32 => {},
        else => return error.ZixUnsupportedProfile,
    }

    var material: [2 * (SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN)]u8 = undefined;
    try exportKeyingMaterial(&material, master_secret, client_random, server_random, LABEL_DTLS_SRTP, null);

    const salts_at = 2 * SRTP_MASTER_KEY_LEN;

    return .{
        .client_write_key = material[0..SRTP_MASTER_KEY_LEN].*,
        .server_write_key = material[SRTP_MASTER_KEY_LEN..salts_at].*,
        .client_write_salt = material[salts_at..][0..SRTP_MASTER_SALT_LEN].*,
        .server_write_salt = material[salts_at + SRTP_MASTER_SALT_LEN ..][0..SRTP_MASTER_SALT_LEN].*,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_MASTER: [48]u8 = @splat(0x5A);
const TEST_CLIENT_RANDOM: [32]u8 = @splat(0xAA);
const TEST_SERVER_RANDOM: [32]u8 = @splat(0xBB);

test "zix dtls: exporter, no context seeds with the two randoms and nothing else" {
    var exported: [32]u8 = undefined;
    try exportKeyingMaterial(&exported, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);

    // The same thing computed straight from the PRF over a hand-built seed.
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &TEST_CLIENT_RANDOM);
    @memcpy(seed[32..64], &TEST_SERVER_RANDOM);

    var expected: [32]u8 = undefined;
    prf.prf(&expected, &TEST_MASTER, "label", &seed);

    try std.testing.expectEqualSlices(u8, &expected, &exported);
}

test "zix dtls: exporter, an empty context is not the same as no context" {
    var without: [32]u8 = undefined;
    var with_empty: [32]u8 = undefined;

    try exportKeyingMaterial(&without, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);
    try exportKeyingMaterial(&with_empty, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", "");

    try std.testing.expect(!std.mem.eql(u8, &without, &with_empty));

    // The empty-context form appends a 2-byte length of zero, and nothing more.
    var seed: [66]u8 = undefined;
    @memcpy(seed[0..32], &TEST_CLIENT_RANDOM);
    @memcpy(seed[32..64], &TEST_SERVER_RANDOM);
    seed[64] = 0;
    seed[65] = 0;

    var expected: [32]u8 = undefined;
    prf.prf(&expected, &TEST_MASTER, "label", &seed);

    try std.testing.expectEqualSlices(u8, &expected, &with_empty);
}

test "zix dtls: exporter, label and randoms all separate the output" {
    var base: [32]u8 = undefined;
    var other_label: [32]u8 = undefined;
    var other_client: [32]u8 = undefined;
    var other_server: [32]u8 = undefined;

    const swapped_random: [32]u8 = @splat(0xCC);

    try exportKeyingMaterial(&base, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, LABEL_DTLS_SRTP, null);
    try exportKeyingMaterial(&other_label, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "EXTRACTOR-other", null);
    try exportKeyingMaterial(&other_client, TEST_MASTER, swapped_random, TEST_SERVER_RANDOM, LABEL_DTLS_SRTP, null);
    try exportKeyingMaterial(&other_server, TEST_MASTER, TEST_CLIENT_RANDOM, swapped_random, LABEL_DTLS_SRTP, null);

    try std.testing.expect(!std.mem.eql(u8, &base, &other_label));
    try std.testing.expect(!std.mem.eql(u8, &base, &other_client));
    try std.testing.expect(!std.mem.eql(u8, &base, &other_server));

    // The randoms are ordered, so swapping them is not the same association.
    var forward: [32]u8 = undefined;
    var reversed: [32]u8 = undefined;
    try exportKeyingMaterial(&forward, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);
    try exportKeyingMaterial(&reversed, TEST_MASTER, TEST_SERVER_RANDOM, TEST_CLIENT_RANDOM, "label", null);
    try std.testing.expect(!std.mem.eql(u8, &forward, &reversed));
}

test "zix dtls: exporter, output is deterministic and length independent at the prefix" {
    var short: [16]u8 = undefined;
    var long: [64]u8 = undefined;

    try exportKeyingMaterial(&short, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);
    try exportKeyingMaterial(&long, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);

    // The PRF is a stream, so a shorter export is a prefix of a longer one.
    try std.testing.expectEqualSlices(u8, &short, long[0..16]);

    var again: [16]u8 = undefined;
    try exportKeyingMaterial(&again, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", null);
    try std.testing.expectEqualSlices(u8, &short, &again);
}

test "zix dtls: exporter, a context over the ceiling is refused" {
    var exported: [16]u8 = undefined;
    const too_long: [MAX_CONTEXT_LEN + 1]u8 = @splat(0);

    try std.testing.expectError(
        error.ZixContextTooLong,
        exportKeyingMaterial(&exported, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", &too_long),
    );

    const at_ceiling: [MAX_CONTEXT_LEN]u8 = @splat(0);
    try exportKeyingMaterial(&exported, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, "label", &at_ceiling);
}

test "zix dtls: srtp keys, 60 exported bytes split key key salt salt" {
    const keys = try srtpKeys(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM);

    var material: [60]u8 = undefined;
    try exportKeyingMaterial(&material, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM, LABEL_DTLS_SRTP, null);

    try std.testing.expectEqualSlices(u8, material[0..16], &keys.client_write_key);
    try std.testing.expectEqualSlices(u8, material[16..32], &keys.server_write_key);
    try std.testing.expectEqualSlices(u8, material[32..46], &keys.client_write_salt);
    try std.testing.expectEqualSlices(u8, material[46..60], &keys.server_write_salt);

    // The two directions must never share material.
    try std.testing.expect(!std.mem.eql(u8, &keys.client_write_key, &keys.server_write_key));
    try std.testing.expect(!std.mem.eql(u8, &keys.client_write_salt, &keys.server_write_salt));
}

test "zix dtls: srtp keys, both aes128 profiles derive alike and null profiles are refused" {
    const tag_80 = try srtpKeys(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM);
    const tag_32 = try srtpKeys(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM);

    // The profiles differ only in auth tag length, which is not part of key derivation.
    try std.testing.expectEqualSlices(u8, &tag_80.client_write_key, &tag_32.client_write_key);

    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        srtpKeys(.SRTP_NULL_HMAC_SHA1_80, TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM),
    );
    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        srtpKeys(@enumFromInt(0xFFFF), TEST_MASTER, TEST_CLIENT_RANDOM, TEST_SERVER_RANDOM),
    );
}
