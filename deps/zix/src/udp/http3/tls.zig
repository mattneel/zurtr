//! zix HTTP/3 TLS-over-QUIC glue (RFC 9001 4, Layer T).
//!
//! What:
//! - The join between the TLS 1.3 handshake and QUIC. In QUIC the handshake does NOT use the TLS
//!   record layer: the messages are carried directly as the payload of CRYPTO frames (19.6),
//!   reassembled by offset into one ordered stream per encryption level, and QUIC packet protection
//!   replaces TLS record protection.
//! - The four encryption levels and their per-level "quic key" derivation, the CRYPTO-stream
//!   reassembly (in-order / gap / overlap), and the three guard rules: TLS 1.3 floor (4.2),
//!   role-split Initial-key discard (4.9.1), and 0-RTT reject (4.6.2, zix default).
//!
//! Note:
//! - The packet keys derive through crypto.zig (the same HKDF-Expand-Label as Layer C). The shipped
//!   server drives the actual TLS 1.3 handshake through src/tls (key_schedule + handshake), only the
//!   record layer differs, which is what this module replaces.
//! - quicKey, clientInitialSecret, tlsVersionAcceptable, InitialKeys, and ZeroRttPolicy are
//!   implemented and tested but not wired into the serve path yet (deferred): keys are derived
//!   directly via crypto / keyschedule, with no TLS-version-floor check or 0-RTT path.

const std = @import("std");

const crypto = @import("crypto.zig");

/// Derive a level's packet-protection key with the "quic key" label (RFC 9001 5.1). The key width
/// follows the negotiated AEAD: 16 bytes for AES-128-GCM, 32 for ChaCha20-Poly1305. The same
/// derivation runs at every level, only the input secret and width change.
pub fn quicKey(out: []u8, secret: crypto.Secret) void {
    crypto.expandLabel(out, secret, "quic key", "");
}

/// Derive the client Initial secret from the Destination Connection ID (RFC 9001 5.2).
pub fn clientInitialSecret(dcid: []const u8) crypto.Secret {
    return crypto.initialSecrets(dcid).client;
}

/// A single CRYPTO stream that reassembles offset-addressed handshake bytes for one encryption level
/// (RFC 9001 4, RFC 9000 19.6). There is no TLS record framing: the bytes inserted are the raw TLS
/// handshake messages, and the contiguous prefix is what TLS may consume.
pub const CryptoStream = struct {
    buf: [4096]u8 = undefined,
    present: [4096]bool = @splat(false),

    /// Insert a CRYPTO frame's data at its offset. Overlapping or duplicate bytes are idempotent
    /// (RFC 9000 2.2: the data at an offset MUST NOT change).
    pub fn insert(self: *CryptoStream, offset: usize, data: []const u8) void {
        @memcpy(self.buf[offset .. offset + data.len], data);
        for (offset..offset + data.len) |i| self.present[i] = true;
    }

    /// The length of the contiguous handshake prefix available from offset 0 (RFC 9001 4): bytes past
    /// a gap are held back until the gap is filled.
    pub fn readableLen(self: CryptoStream) usize {
        var n: usize = 0;
        while (n < self.present.len and self.present[n]) n += 1;

        return n;
    }

    /// The contiguous handshake bytes ready for TLS to consume.
    pub fn readable(self: *const CryptoStream) []const u8 {
        return self.buf[0..self.readableLen()];
    }
};

// --------------------------------------------------------------- //

/// The TLS 1.3 version code as it appears in supported_versions (RFC 8446 4.2.1).
pub const tls_1_3: u16 = 0x0304;

/// Whether the negotiated TLS version is acceptable for QUIC (RFC 9001 4.2): TLS 1.3 or newer. A
/// version below 1.3 MUST terminate the connection.
pub fn tlsVersionAcceptable(negotiated: u16) bool {
    return negotiated >= tls_1_3;
}

/// Which side of the connection an endpoint is (RFC 9001 4.9.1). The Initial-key discard trigger
/// differs by role.
pub const Endpoint = enum { client, server };

/// Tracks whether an endpoint still holds Initial keys (RFC 9001 4.9.1). They are discarded
/// aggressively because Initial packets are not authenticated.
pub const InitialKeys = struct {
    role: Endpoint,
    present: bool = true,

    /// A server discards Initial keys when it first successfully processes a Handshake packet.
    pub fn onHandshakeProcessed(self: *InitialKeys) void {
        if (self.role == .server) self.present = false;
    }

    /// A client discards Initial keys when it first sends a Handshake packet.
    pub fn onHandshakeSent(self: *InitialKeys) void {
        if (self.role == .client) self.present = false;
    }

    /// Whether the endpoint may still send Initial packets (RFC 9001 4.9.1): not after discard.
    pub fn maySendInitial(self: InitialKeys) bool {
        return self.present;
    }
};

/// The server's 0-RTT policy (RFC 9001 4.6.2). Acceptance is signaled by an early_data extension in
/// EncryptedExtensions, and a rejecting server MUST NOT process any 0-RTT packets.
pub const ZeroRttPolicy = struct {
    accepts: bool,

    /// Whether EncryptedExtensions carries the early_data extension (RFC 9001 4.6.2): present only
    /// when 0-RTT is accepted.
    pub fn earlyDataInEncryptedExtensions(self: ZeroRttPolicy) bool {
        return self.accepts;
    }

    /// Whether the server may process a received 0-RTT packet (RFC 9001 4.6.2): never when rejected.
    pub fn mayProcessZeroRtt(self: ZeroRttPolicy) bool {
        return self.accepts;
    }
};

/// zix rejects 0-RTT by default: session resumption is deferred, so there are no early-data keys.
pub const default_zero_rtt = ZeroRttPolicy{ .accepts = false };

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9001 4 CRYPTO-frame handshake reassembly" {
    const client_hello = hexBytes("0100000401020304");

    var in_order = CryptoStream{};
    in_order.insert(0, client_hello[0..4]);
    in_order.insert(4, client_hello[4..8]);
    try std.testing.expectEqualSlices(u8, &client_hello, in_order.readable());

    var out_of_order = CryptoStream{};
    out_of_order.insert(4, client_hello[4..8]);
    try std.testing.expectEqual(@as(usize, 0), out_of_order.readableLen());
    out_of_order.insert(0, client_hello[0..4]);
    try std.testing.expectEqualSlices(u8, &client_hello, out_of_order.readable());

    var overlap = CryptoStream{};
    overlap.insert(0, client_hello[0..6]);
    overlap.insert(2, client_hello[2..8]);
    try std.testing.expectEqualSlices(u8, &client_hello, overlap.readable());

    const ready = in_order.readable();
    try std.testing.expect(ready[0] == 0x01 and ready[0] != 0x16);
}

test "zix http3: RFC 9001 5.1 per-level quic key derivation" {
    const dcid = hexBytes("8394c8f03e515708");
    var initial_key: [16]u8 = undefined;
    quicKey(&initial_key, clientInitialSecret(&dcid));
    try std.testing.expectEqualSlices(u8, &hexBytes("1f369613dd76d5467730efcbe3b1a22d"), &initial_key);

    const app_secret: crypto.Secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    var app_key: [32]u8 = undefined;
    quicKey(&app_key, app_secret);
    try std.testing.expectEqualSlices(u8, &hexBytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), &app_key);

    try std.testing.expect(!std.mem.eql(u8, &initial_key, app_key[0..16]));
}

test "zix http3: RFC 9001 4.2 TLS version floor" {
    try std.testing.expect(tlsVersionAcceptable(0x0304));
    try std.testing.expect(!tlsVersionAcceptable(0x0303));
    try std.testing.expect(!tlsVersionAcceptable(0x0302));
    try std.testing.expect(tlsVersionAcceptable(0x0305));
}

test "zix http3: RFC 9001 4.9.1 Initial-key discard and 4.6.2 0-RTT reject" {
    var server_keys = InitialKeys{ .role = .server };
    try std.testing.expect(server_keys.maySendInitial());
    server_keys.onHandshakeSent();
    try std.testing.expect(server_keys.maySendInitial());
    server_keys.onHandshakeProcessed();
    try std.testing.expect(!server_keys.maySendInitial());

    var client_keys = InitialKeys{ .role = .client };
    client_keys.onHandshakeProcessed();
    try std.testing.expect(client_keys.maySendInitial());
    client_keys.onHandshakeSent();
    try std.testing.expect(!client_keys.maySendInitial());

    const rejecting = ZeroRttPolicy{ .accepts = false };
    try std.testing.expect(!rejecting.earlyDataInEncryptedExtensions() and !rejecting.mayProcessZeroRtt());
    const accepting = ZeroRttPolicy{ .accepts = true };
    try std.testing.expect(accepting.earlyDataInEncryptedExtensions() and accepting.mayProcessZeroRtt());
    try std.testing.expect(!default_zero_rtt.mayProcessZeroRtt());
}
