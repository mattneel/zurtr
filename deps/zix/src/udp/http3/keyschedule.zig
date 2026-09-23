//! zix HTTP/3 QUIC handshake key schedule (RFC 8446 7.1 secret tree + RFC 9001 5.1 quic labels).
//!
//! What:
//! - Derives the Handshake-level QUIC packet keys for both directions from the ECDHE shared secret
//!   and the handshake transcript hash through ServerHello. The TLS 1.3 secret tree (early ->
//!   derived -> handshake -> traffic) is the existing `src/tls/key_schedule.zig`, then the QUIC
//!   per-level "quic key" / "quic iv" / "quic hp" derivation reuses `crypto.AesKeys.fromSecret`.
//! - Returns the traffic secrets and the handshake secret too, the inputs the Finished keys and the
//!   later application (1-RTT) key schedule need.

const std = @import("std");

const crypto = @import("crypto.zig");
const ks = @import("../../tls/key_schedule.zig");

/// The Handshake-level keys and the secrets needed to continue the handshake.
pub const HandshakeKeys = struct {
    /// QUIC Handshake keys for sealing server packets (from the server handshake-traffic secret).
    server: crypto.AesKeys,
    /// QUIC Handshake keys for opening client packets (from the client handshake-traffic secret).
    client: crypto.AesKeys,
    /// The handshake secret, the salt for the later master / application key schedule.
    handshake_secret: crypto.Secret,
    /// The server handshake-traffic secret (the Finished key derives from this).
    server_traffic: crypto.Secret,
    /// The client handshake-traffic secret (the client Finished verify derives from this).
    client_traffic: crypto.Secret,
};

/// Derive the Handshake-level keys from the ECDHE shared secret and the transcript hash through
/// ServerHello (RFC 8446 7.1, RFC 9001 5).
///
/// Param:
/// shared - [32]u8 (the ECDHE shared secret)
/// transcript_hash - crypto.Secret (SHA-256 of ClientHello followed by ServerHello)
///
/// Return:
/// - HandshakeKeys
pub fn handshakeKeys(shared: [32]u8, transcript_hash: crypto.Secret) HandshakeKeys {
    const zero = std.mem.zeroes(crypto.Secret);
    const empty_hash = ks.Transcript.init().current();
    const early = ks.HkdfSha256.extract(&zero, &zero);
    const derived = ks.deriveSecret(early, "derived", empty_hash);
    const handshake_secret = ks.HkdfSha256.extract(&derived, &shared);

    const server_traffic = ks.deriveSecret(handshake_secret, "s hs traffic", transcript_hash);
    const client_traffic = ks.deriveSecret(handshake_secret, "c hs traffic", transcript_hash);

    return .{
        .server = crypto.AesKeys.fromSecret(server_traffic),
        .client = crypto.AesKeys.fromSecret(client_traffic),
        .handshake_secret = handshake_secret,
        .server_traffic = server_traffic,
        .client_traffic = client_traffic,
    };
}

/// The 1-RTT application keys for both directions.
pub const AppKeys = struct {
    /// QUIC 1-RTT keys for sealing server packets (from the server application-traffic secret).
    server: crypto.AesKeys,
    /// QUIC 1-RTT keys for opening client packets (from the client application-traffic secret).
    client: crypto.AesKeys,
};

/// Derive the 1-RTT application keys from the handshake secret and the transcript hash through the
/// server Finished (RFC 8446 7.1, RFC 9001 5).
///
/// Param:
/// handshake_secret - crypto.Secret (from handshakeKeys)
/// transcript_through_finished - crypto.Secret (SHA-256 of the transcript through the server Finished)
///
/// Return:
/// - AppKeys
pub fn applicationKeys(handshake_secret: crypto.Secret, transcript_through_finished: crypto.Secret) AppKeys {
    const zero = std.mem.zeroes(crypto.Secret);
    const empty_hash = ks.Transcript.init().current();
    const derived_master = ks.deriveSecret(handshake_secret, "derived", empty_hash);
    const master = ks.HkdfSha256.extract(&derived_master, &zero);

    const server_ap = ks.deriveSecret(master, "s ap traffic", transcript_through_finished);
    const client_ap = ks.deriveSecret(master, "c ap traffic", transcript_through_finished);

    return .{ .server = crypto.AesKeys.fromSecret(server_ap), .client = crypto.AesKeys.fromSecret(client_ap) };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: handshakeKeys is deterministic and direction-split" {
    const shared: [32]u8 = @splat(0x2b);
    const transcript: crypto.Secret = @splat(0x39);

    const a = handshakeKeys(shared, transcript);
    const b = handshakeKeys(shared, transcript);

    // Deterministic for the same inputs.
    try std.testing.expectEqualSlices(u8, &a.server.key, &b.server.key);
    try std.testing.expectEqualSlices(u8, &a.client.iv, &b.client.iv);

    // The two directions derive distinct keys.
    try std.testing.expect(!std.mem.eql(u8, &a.server.key, &a.client.key));
    try std.testing.expect(!std.mem.eql(u8, &a.server_traffic, &a.client_traffic));

    // A different transcript yields different keys.
    const c = handshakeKeys(shared, @splat(0x40));
    try std.testing.expect(!std.mem.eql(u8, &a.server.key, &c.server.key));
}
