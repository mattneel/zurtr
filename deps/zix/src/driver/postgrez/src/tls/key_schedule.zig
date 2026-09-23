//! TLS 1.3 key schedule (RFC 8446 section 7.1).
//!
//! Note:
//! - HKDF-Expand-Label, Derive-Secret, and a running Transcript-Hash, built on std.crypto
//!   HKDF-SHA256. Pure functions over byte buffers, no I/O.
//! - std.crypto ships HKDF and SHA-256 but no TLS key schedule, so the "tls13 " label encoding
//!   and Derive-Secret are authored here. Verified against the RFC 8448 trace in-file.
//! - This is the layer HTTP/3 (QUIC-TLS, RFC 9001) reuses verbatim, only the record protection
//!   differs.

const std = @import("std");

pub const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

/// Hash output width (SHA-256), the secret and transcript-hash size in bytes.
pub const HASH_LENGTH = Sha256.digest_length;

/// A schedule secret or a transcript hash, one hash block wide.
pub const Secret = [HASH_LENGTH]u8;

// --------------------------------------------------------------- //

/// HKDF-Expand-Label (RFC 8446 7.1): expand `secret` under an info struct of the output length,
/// the label prefixed with "tls13 ", and a context.
///
/// Param:
/// out - []u8 (filled in place, its length is HkdfLabel.length)
/// secret - the pseudorandom key
/// label - the bare label, without the "tls13 " prefix
/// context - the context bytes (a transcript hash, or empty)
///
/// Return:
/// - void
pub fn expandLabel(out: []u8, secret: Secret, label: []const u8, context: []const u8) void {
    const prefix = "tls13 ";

    var info: [2 + 1 + prefix.len + 255 + 1 + HASH_LENGTH]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(prefix.len + label.len);
    @memcpy(info[3 .. 3 + prefix.len], prefix);
    @memcpy(info[3 + prefix.len .. 3 + prefix.len + label.len], label);

    const context_pos = 3 + prefix.len + label.len;
    info[context_pos] = @intCast(context.len);
    @memcpy(info[context_pos + 1 .. context_pos + 1 + context.len], context);

    HkdfSha256.expand(out, info[0 .. context_pos + 1 + context.len], secret);
}

/// Derive-Secret (RFC 8446 7.1): HKDF-Expand-Label keyed by a transcript hash, one block wide.
///
/// Return:
/// - Secret
pub fn deriveSecret(secret: Secret, label: []const u8, transcript_hash: Secret) Secret {
    var out: Secret = undefined;
    expandLabel(&out, secret, label, &transcript_hash);

    return out;
}

// --------------------------------------------------------------- //

/// Running Transcript-Hash over the handshake messages (RFC 8446 4.4.1).
///
/// Usage:
/// ```zig
/// var transcript = Transcript.init();
/// transcript.update(client_hello);
/// transcript.update(server_hello);
/// const th = transcript.current();
/// ```
pub const Transcript = struct {
    hasher: Sha256,

    pub fn init() Transcript {
        return .{ .hasher = Sha256.init(.{}) };
    }

    pub fn update(self: *Transcript, message: []const u8) void {
        self.hasher.update(message);
    }

    /// The transcript hash at the current point, without consuming the running state.
    pub fn current(self: Transcript) Secret {
        var snapshot = self.hasher;

        return snapshot.finalResult();
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "postgrez tls: RFC 8448 key schedule: secret tree + traffic keys" {
    var ecdhe: Secret = undefined;
    _ = try std.fmt.hexToBytes(&ecdhe, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

    var transcript_ch_sh: Secret = undefined;
    _ = try std.fmt.hexToBytes(&transcript_ch_sh, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

    const empty = Transcript.init().current();
    try expectHex(&empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const zero = std.mem.zeroes(Secret);
    const early = HkdfSha256.extract(&zero, &zero);
    try expectHex(&early, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");

    const derived = deriveSecret(early, "derived", empty);
    try expectHex(&derived, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");

    const handshake = HkdfSha256.extract(&derived, &ecdhe);
    try expectHex(&handshake, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");

    const server_hs = deriveSecret(handshake, "s hs traffic", transcript_ch_sh);
    try expectHex(&server_hs, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

    var key: [16]u8 = undefined;
    expandLabel(&key, server_hs, "key", "");
    try expectHex(&key, "3fce516009c21727d0f2e4e86ee403bc");

    var iv: [12]u8 = undefined;
    expandLabel(&iv, server_hs, "iv", "");
    try expectHex(&iv, "5d313eb2671276ee13000b30");

    var finished: Secret = undefined;
    expandLabel(&finished, server_hs, "finished", "");
    try expectHex(&finished, "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");
}

fn expectHex(got: []const u8, comptime hex_str: []const u8) !void {
    var want: [64]u8 = undefined;
    const want_bytes = try std.fmt.hexToBytes(&want, hex_str);

    try std.testing.expectEqualSlices(u8, want_bytes, got);
}
