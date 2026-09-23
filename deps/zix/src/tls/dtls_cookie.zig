//! DTLS stateless cookies for the HelloVerifyRequest exchange (RFC 6347 4.2.1).
//!
//! What:
//! - The countermeasure that makes a DTLS server safe to expose on UDP. Before doing any
//!   expensive work, the server answers a ClientHello with a cookie and waits for the client to
//!   echo it back. A source address that cannot receive packets never gets past this.
//! - Stops two attacks at once: state exhaustion (no per-client state is kept until the cookie
//!   comes back) and amplification (a forged source address never receives the certificate
//!   flight, which is far larger than the ClientHello that would have triggered it).
//!
//! Note:
//! - Nothing is stored per client. The cookie is HMAC(secret, address ++ client parameters), so
//!   verifying it is recomputing it. That is the entire point: state would be the thing under
//!   attack.
//! - The cookie binds the peer IP address, not the port. RFC 6347 4.2.1 says Client-IP, and what
//!   is being proven is that the peer can receive at that address. Leaving the port out means a
//!   NAT rebinding between the two ClientHellos does not cost an extra round trip.
//! - Rotate the secret regularly. A cookie stays valid as long as the secret that signed it
//!   lives, so an attacker who farms cookies from real addresses can reuse them until it turns
//!   over. `rotate` keeps the old secret usable for one more period so a handshake in flight
//!   during the change still completes.
//! - An invalid cookie is treated exactly like no cookie at all (RFC 6347 4.2.1), never as an
//!   error. A client can legitimately hold a cookie signed by a secret that has since rotated
//!   out, and failing it hard would deadlock that handshake.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const IpAddress = std.Io.net.IpAddress;

/// Cookie signing secret width, one SHA-256 block.
pub const SECRET_LEN: usize = 32;

/// Cookie width. HMAC-SHA256 output, used whole.
pub const COOKIE_LEN: usize = HmacSha256.mac_length;

/// Largest cookie DTLS 1.2 allows on the wire (RFC 6347 4.2.1). Earlier versions cap at 32.
pub const MAX_COOKIE_LEN: usize = 255;

pub const Cookie = [COOKIE_LEN]u8;

/// Signs and verifies cookies for one server.
///
/// Note:
/// - Holds two secrets so a rotation does not break handshakes already in flight. Verification
///   tries the current secret first, then the previous one.
pub const Signer = struct {
    current: [SECRET_LEN]u8,
    previous: ?[SECRET_LEN]u8 = null,

    /// Build a signer from a caller-supplied secret.
    ///
    /// Note:
    /// - The secret has to be unpredictable, and sourcing it is the caller's job. This file
    ///   stays free of platform entropy calls so it compiles and tests the same everywhere.
    pub fn init(secret: [SECRET_LEN]u8) Signer {
        return .{ .current = secret };
    }

    /// Take a new secret, keeping the old one valid for one more period.
    ///
    /// Note:
    /// - Call this on a timer, not per handshake. Rotating too fast makes legitimate clients
    ///   fail twice in a row, once for each stale secret.
    pub fn rotate(self: *Signer, secret: [SECRET_LEN]u8) void {
        self.previous = self.current;
        self.current = secret;
    }

    /// Cookie for a peer, under the current secret.
    ///
    /// Param:
    /// peer - std.Io.net.IpAddress (where the ClientHello came from)
    /// client_params - []const u8 (the ClientHello fields the client must repeat verbatim:
    ///                 version, random, session_id, cipher_suites, compression_methods)
    ///
    /// Return:
    /// - Cookie
    pub fn generate(self: *const Signer, peer: IpAddress, client_params: []const u8) Cookie {
        return sign(self.current, peer, client_params);
    }

    /// Whether a cookie is one this server issued for this peer and these parameters.
    ///
    /// Note:
    /// - Compares in constant time. A cookie check that leaks how many bytes matched hands an
    ///   attacker a way to forge one byte at a time.
    /// - false is the answer for a wrong length, a wrong peer, changed parameters, and a secret
    ///   that has aged out. The caller treats all of them as "no cookie".
    ///
    /// Return:
    /// - bool
    pub fn verify(self: *const Signer, peer: IpAddress, client_params: []const u8, cookie: []const u8) bool {
        if (cookie.len != COOKIE_LEN) return false;

        const offered: Cookie = cookie[0..COOKIE_LEN].*;

        if (std.crypto.timing_safe.eql(Cookie, sign(self.current, peer, client_params), offered)) return true;

        if (self.previous) |secret| {
            return std.crypto.timing_safe.eql(Cookie, sign(secret, peer, client_params), offered);
        }

        return false;
    }
};

/// HMAC(secret, address ++ client_params), the construction RFC 6347 4.2.1 recommends.
fn sign(secret: [SECRET_LEN]u8, peer: IpAddress, client_params: []const u8) Cookie {
    var mac = HmacSha256.init(&secret);

    switch (peer) {
        .ip4 => |addr| {
            mac.update(&.{1});
            mac.update(&addr.bytes);
        },
        .ip6 => |addr| {
            mac.update(&.{2});
            mac.update(&addr.bytes);
        },
    }

    mac.update(client_params);

    var cookie: Cookie = undefined;
    mac.final(&cookie);

    return cookie;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_SECRET: [SECRET_LEN]u8 = @splat(0x5A);
const TEST_PARAMS: []const u8 = "client hello parameters";

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 41000 } };

test "zix dtls: cookie, a fresh cookie verifies against the peer that earned it" {
    const signer = Signer.init(TEST_SECRET);
    const cookie = signer.generate(TEST_PEER, TEST_PARAMS);

    try std.testing.expect(signer.verify(TEST_PEER, TEST_PARAMS, &cookie));
    try std.testing.expectEqual(@as(usize, 32), cookie.len);
    try std.testing.expect(cookie.len <= MAX_COOKIE_LEN);
}

test "zix dtls: cookie, generation is stateless and repeatable" {
    const signer = Signer.init(TEST_SECRET);

    const first = signer.generate(TEST_PEER, TEST_PARAMS);
    const second = signer.generate(TEST_PEER, TEST_PARAMS);

    try std.testing.expectEqualSlices(u8, &first, &second);

    // A second signer holding the same secret verifies a cookie it never issued, which is what
    // lets a cookie survive a server that keeps nothing.
    const other = Signer.init(TEST_SECRET);
    try std.testing.expect(other.verify(TEST_PEER, TEST_PARAMS, &first));
}

test "zix dtls: cookie, a different address does not verify" {
    const signer = Signer.init(TEST_SECRET);
    const cookie = signer.generate(TEST_PEER, TEST_PARAMS);

    const other_ip4: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 41000 } };
    try std.testing.expect(!signer.verify(other_ip4, TEST_PARAMS, &cookie));

    const ip6: IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 41000,
    } };
    try std.testing.expect(!signer.verify(ip6, TEST_PARAMS, &cookie));

    // An ipv6 peer gets a cookie of its own, and the family is part of what is signed.
    const ip6_cookie = signer.generate(ip6, TEST_PARAMS);
    try std.testing.expect(signer.verify(ip6, TEST_PARAMS, &ip6_cookie));
    try std.testing.expect(!std.mem.eql(u8, &cookie, &ip6_cookie));
}

test "zix dtls: cookie, the port is deliberately not bound" {
    const signer = Signer.init(TEST_SECRET);
    const cookie = signer.generate(TEST_PEER, TEST_PARAMS);

    // Same address, new source port, as a NAT rebinding between the two ClientHellos produces.
    const rebound: IpAddress = .{ .ip4 = .{ .bytes = TEST_PEER.ip4.bytes, .port = 41001 } };
    try std.testing.expect(signer.verify(rebound, TEST_PARAMS, &cookie));
}

test "zix dtls: cookie, changed client parameters do not verify" {
    const signer = Signer.init(TEST_SECRET);
    const cookie = signer.generate(TEST_PEER, TEST_PARAMS);

    try std.testing.expect(!signer.verify(TEST_PEER, "different parameters", &cookie));
    try std.testing.expect(!signer.verify(TEST_PEER, "", &cookie));
}

test "zix dtls: cookie, a forged or malformed cookie does not verify" {
    const signer = Signer.init(TEST_SECRET);
    var cookie = signer.generate(TEST_PEER, TEST_PARAMS);

    cookie[COOKIE_LEN - 1] ^= 0x01;
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, &cookie));
    cookie[COOKIE_LEN - 1] ^= 0x01;

    cookie[0] ^= 0x80;
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, &cookie));
    cookie[0] ^= 0x80;

    // Length is checked before anything else, so a short or empty cookie cannot slip through.
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, cookie[0 .. COOKIE_LEN - 1]));
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, ""));

    const all_zero: Cookie = @splat(0);
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, &all_zero));
}

test "zix dtls: cookie, another secret issues cookies this server rejects" {
    const signer = Signer.init(TEST_SECRET);
    const other_secret: [SECRET_LEN]u8 = @splat(0xA5);
    const attacker = Signer.init(other_secret);

    const forged = attacker.generate(TEST_PEER, TEST_PARAMS);
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, &forged));
}

test "zix dtls: cookie, a rotation keeps one previous secret usable" {
    var signer = Signer.init(TEST_SECRET);
    const issued_before = signer.generate(TEST_PEER, TEST_PARAMS);

    const second_secret: [SECRET_LEN]u8 = @splat(0xB6);
    signer.rotate(second_secret);

    // A handshake that started before the rotation still completes.
    try std.testing.expect(signer.verify(TEST_PEER, TEST_PARAMS, &issued_before));

    // New cookies are signed with the new secret.
    const issued_after = signer.generate(TEST_PEER, TEST_PARAMS);
    try std.testing.expect(!std.mem.eql(u8, &issued_before, &issued_after));
    try std.testing.expect(signer.verify(TEST_PEER, TEST_PARAMS, &issued_after));

    // One more rotation ages the first secret out for good.
    const third_secret: [SECRET_LEN]u8 = @splat(0xC7);
    signer.rotate(third_secret);
    try std.testing.expect(!signer.verify(TEST_PEER, TEST_PARAMS, &issued_before));
    try std.testing.expect(signer.verify(TEST_PEER, TEST_PARAMS, &issued_after));
}

test "zix dtls: cookie, one flipped secret bit changes the whole cookie" {
    const signer = Signer.init(TEST_SECRET);

    var near_secret: [SECRET_LEN]u8 = TEST_SECRET;
    near_secret[0] ^= 0x01;
    const near = Signer.init(near_secret);

    const cookie = signer.generate(TEST_PEER, TEST_PARAMS);
    const near_cookie = near.generate(TEST_PEER, TEST_PARAMS);

    try std.testing.expect(!std.mem.eql(u8, &cookie, &near_cookie));
    try std.testing.expect(!near.verify(TEST_PEER, TEST_PARAMS, &cookie));
}
