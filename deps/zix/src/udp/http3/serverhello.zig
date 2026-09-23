//! zix HTTP/3 ServerHello generation (handshake step 2, the start of the server send path).
//!
//! What:
//! - From a parsed ClientHello, run the server side of ECDHE (X25519), negotiate the cipher and
//!   group, serialize a TLS 1.3 ServerHello (reusing the record-free src/tls builders), wrap it in a
//!   QUIC CRYPTO frame, and seal it into an Initial packet with the server Initial keys.
//! - Returns the packet bytes to send plus the ECDHE shared secret (the input to the later
//!   handshake-traffic-secret derivation).
//!
//! Note:
//! - This slice handles the common X25519 path (curl's default). secp256r1, HelloRetryRequest, and
//!   the encrypted Handshake flight (EE / Cert / CertVerify / Finished) are the following slices.
//! - The TLS message generation is the existing, tested `src/tls` code, only the framing changes:
//!   raw handshake bytes go into a CRYPTO frame instead of a TLS record (RFC 9001 4).

const std = @import("std");

const crypto = @import("crypto.zig");
const protection = @import("protection.zig");
const keyschedule = @import("keyschedule.zig");
const varint = @import("varint.zig");
const handshake = @import("../../tls/handshake.zig");
const ks = @import("../../tls/key_schedule.zig");

const X25519 = std.crypto.dh.X25519;

/// A built server Initial packet plus the handshake state it established.
pub const ServerInitial = struct {
    /// The sealed Initial packet, a slice into the caller-provided output buffer.
    packet: []const u8,
    /// The X25519 shared secret (the ECDHE input to the handshake key schedule).
    shared: [32]u8,
    /// The Handshake-level keys (both directions) derived from the shared secret + CH/SH transcript.
    keys: keyschedule.HandshakeKeys,
    /// The handshake transcript through ClientHello + ServerHello, to continue with the flight.
    transcript: ks.Transcript,
};

/// Build the server's Initial packet carrying a ServerHello in a CRYPTO frame (RFC 9001 4, RFC 8446
/// 4.1.3). Returns null when the client did not offer an X25519 key share or negotiation does not
/// yield a ServerHello (HelloRetryRequest / alert paths are later slices).
///
/// Param:
/// out - []u8 (destination for the whole Initial packet)
/// hello - *const handshake.ClientHello (the parsed client hello)
/// client_hello_bytes - []const u8 (the raw ClientHello bytes, fed into the handshake transcript)
/// server_keys - crypto.AesKeys (the server Initial key / iv / hp)
/// dcid - []const u8 (the client's Source Connection ID, our Destination CID for the reply)
/// scid - []const u8 (our chosen Source Connection ID)
/// server_random - [32]u8 (fresh per connection)
/// ephemeral_secret - [32]u8 (the server's fresh X25519 private scalar)
///
/// Return:
/// - ServerInitial (the packet to send plus the shared secret), or null when not applicable
pub fn buildServerHelloInitial(
    out: []u8,
    hello: *const handshake.ClientHello,
    client_hello_bytes: []const u8,
    server_keys: crypto.AesKeys,
    dcid: []const u8,
    scid: []const u8,
    server_random: [32]u8,
    ephemeral_secret: [32]u8,
) ?ServerInitial {
    const client_share = hello.x25519_share orelse return null;
    if (client_share.len != 32) return null;

    var client_pub: [32]u8 = undefined;
    @memcpy(&client_pub, client_share);

    const server_public = X25519.recoverPublicKey(ephemeral_secret) catch return null;
    const shared = X25519.scalarmult(ephemeral_secret, client_pub) catch return null;

    const params = switch (handshake.negotiate(hello, &server_public, &.{.X25519})) {
        .server_hello => |p| p,
        else => return null,
    };

    var sh_buf: [512]u8 = undefined;
    const server_hello = handshake.serializeServerHello(&sh_buf, &server_random, "", params);

    // Wrap the ServerHello in a CRYPTO frame at offset 0 (RFC 9000 19.6).
    var crypto_frame: [640]u8 = undefined;
    var pos: usize = 0;
    crypto_frame[pos] = 0x06;
    pos += 1;
    pos += varint.write(crypto_frame[pos..], 0);
    pos += varint.write(crypto_frame[pos..], server_hello.len);
    @memcpy(crypto_frame[pos..][0..server_hello.len], server_hello);
    pos += server_hello.len;

    const packet = protection.sealInitial(out, server_keys, dcid, scid, 0, crypto_frame[0..pos]) catch return null;

    // Feed ClientHello + ServerHello into the transcript and derive the Handshake-level keys
    // (RFC 8446 7.1, RFC 9001 5). The transcript continues into the EE / Cert / Finished flight.
    var transcript = ks.Transcript.init();
    transcript.update(client_hello_bytes);
    transcript.update(server_hello);

    const keys = keyschedule.handshakeKeys(shared, transcript.current());

    return .{ .packet = packet, .shared = shared, .keys = keys, .transcript = transcript };
}
