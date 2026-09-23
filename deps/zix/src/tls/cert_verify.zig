//! Layer V: peer certificate verification (the trust step of mTLS).
//!
//! What:
//!   Given a peer's end-entity certificate (DER) and a trust anchor (DER), answer two
//!   separate questions a TLS handshake must ask before it trusts the peer:
//!     1. Does the cert chain to the anchor and sit inside its validity window? (RFC 5280)
//!     2. Does the cert's identity (SAN) match the host we meant to reach? (RFC 6125)
//!   These are split because a path-validation-only caller (no SNI, e.g. a client-auth
//!   server checking a client cert) must not be forced through a hostname check.
//!
//! Note:
//! - Built on std.crypto.Certificate (Parsed.verify + Parsed.verifyHostName). No C FFI.
//! - One-link chain only (end-entity verified directly against one anchor). A self-signed
//!   anchor is its own issuer, so verifyCertChain(ee, ee, ...) validates a self-signed leaf.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const Element = Certificate.der.Element;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Verify the end-entity cert chains to the trust anchor and is time-valid (RFC 5280).
///
/// Note:
/// - Checks issuer-name match, validity window (now_sec), and the issuer's signature.
/// - Does NOT check identity. Pair with verifyCertHostname when a hostname is expected.
///
/// Param:
/// end_entity_der - []const u8 (the peer's leaf certificate, DER-encoded)
/// trust_anchor_der - []const u8 (the CA/anchor to chain against, DER-encoded)
/// now_sec - i64 (current UNIX time in seconds, for the validity window)
///
/// Return:
/// - void on a valid chain
/// - error.CertificateExpired / error.CertificateNotYetValid (outside validity window)
/// - error.CertificateIssuerMismatch (does not chain to the anchor)
/// - propagates std.crypto.Certificate parse/verify errors otherwise
pub fn verifyCertChain(end_entity_der: []const u8, trust_anchor_der: []const u8, now_sec: i64) !void {
    const ee = try (Certificate{ .buffer = end_entity_der, .index = 0 }).parse();
    const anchor = try (Certificate{ .buffer = trust_anchor_der, .index = 0 }).parse();

    try ee.verify(anchor, now_sec);
}

/// Verify the cert's identity (Subject Alternative Name) matches the expected host (RFC 6125).
///
/// Note:
/// - Falls back to the Common Name only when the cert carries no SAN extension.
///
/// Param:
/// end_entity_der - []const u8 (the peer's leaf certificate, DER-encoded)
/// host - []const u8 (the hostname the caller intended to reach)
///
/// Return:
/// - void on a match
/// - error.CertificateHostMismatch (no SAN/CN entry matches host)
pub fn verifyCertHostname(end_entity_der: []const u8, host: []const u8) !void {
    const ee = try (Certificate{ .buffer = end_entity_der, .index = 0 }).parse();

    try ee.verifyHostName(host);
}

/// Verify the cert covers `host` by a DNS SAN (RFC 6125, via std) OR, when host is an IPv4 literal,
/// an iPAddress SAN. std.crypto.Certificate.verifyHostName is DNS-only, so an IP host needs the
/// iPAddress GeneralName checked separately. Used by the https misdirected-request (421) gate.
///
/// Param:
/// end_entity_der - []const u8 (the server's leaf certificate, DER-encoded)
/// host - []const u8 (the request authority host, no port)
///
/// Return:
/// - void when the cert serves host (DNS or IP SAN match)
/// - error.CertificateHostMismatch otherwise
pub fn verifyCertIdentity(end_entity_der: []const u8, host: []const u8) !void {
    const ee = try (Certificate{ .buffer = end_entity_der, .index = 0 }).parse();

    ee.verifyHostName(host) catch {
        if (parseIp4Literal(host)) |ip| {
            const san = ee.slice(ee.subject_alt_name_slice);
            if (sanHasIp4(san, ip)) return;
        }

        return error.CertificateHostMismatch;
    };
}

/// Parse a dotted-quad IPv4 literal (e.g. "127.0.0.1") to its 4 bytes, or null when host is not one.
fn parseIp4Literal(host: []const u8) ?[4]u8 {
    const addr = std.Io.net.IpAddress.parse(host, 0) catch return null;

    return switch (addr) {
        .ip4 => |a| a.bytes,
        else => null,
    };
}

/// Scan a subjectAltName value for an iPAddress GeneralName ([7] = 0x87) holding the IPv4 `ip`.
/// An IPv4 iPAddress entry is encoded as the 6 bytes: 0x87 0x04 followed by the 4 address octets.
fn sanHasIp4(san: []const u8, ip: [4]u8) bool {
    if (san.len < 6) return false;

    var i: usize = 0;
    while (i + 6 <= san.len) : (i += 1) {
        if (san[i] == 0x87 and san[i + 1] == 0x04 and std.mem.eql(u8, san[i + 2 .. i + 6], &ip)) return true;
    }

    return false;
}

/// Extract the peer's ECDSA P-256 public key from its end-entity certificate (DER). The mTLS
/// client CertificateVerify signature is checked against this key (Layer C cross-check).
///
/// Param:
/// end_entity_der - []const u8 (the peer's leaf certificate, DER-encoded)
///
/// Return:
/// - EcdsaP256.PublicKey
/// - error.ZixUnsupportedPeerKey (cert key is not ECDSA on the P-256 / prime256v1 curve)
pub fn peerEcdsaP256PublicKey(end_entity_der: []const u8) !EcdsaP256.PublicKey {
    const ee = try (Certificate{ .buffer = end_entity_der, .index = 0 }).parse();
    switch (ee.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return error.ZixUnsupportedPeerKey,
        else => return error.ZixUnsupportedPeerKey,
    }

    return EcdsaP256.PublicKey.fromSec1(ee.pubKey()) catch error.ZixUnsupportedPeerKey;
}

// --------------------------------------------------------------- //
// multi-cert chain validation (RFC 5280 6.1): verify a [leaf, intermediate, ...] chain to an anchor,
// enforcing the path constraints std.crypto.Certificate.Parsed.verify does not (cA, keyCertSign,
// pathLen, critical-ext). std handles each link's signature + validity + issuer-name.

/// Path constraints pulled from a cert's v3 extensions (std's Parsed does not surface these).
const PathConstraints = struct {
    is_ca: bool = false,
    path_len: ?u32 = null,
    has_key_usage: bool = false,
    key_cert_sign: bool = false,
    unknown_critical: bool = false,
};

/// Walk a certificate's v3 extensions (RFC 5280 4.2) and extract basicConstraints (cA +
/// pathLenConstraint), keyUsage (keyCertSign), and whether any CRITICAL extension carries an OID
/// we do not recognize. Mirrors std's own extension walk (the [3] wrapper reads as tag .bitstring
/// because its context-tag number is 3) using only std's public der + parseExtensionId.
fn pathConstraints(bytes: []const u8) !PathConstraints {
    var out: PathConstraints = .{};

    const certificate = try Element.parse(bytes, 0);
    const tbs = try Element.parse(bytes, certificate.slice.start);
    const version_elem = try Element.parse(bytes, tbs.slice.start);
    const is_v3 = @as(u8, @bitCast(version_elem.identifier)) == 0xa0;
    const serial = if (is_v3) try Element.parse(bytes, version_elem.slice.end) else version_elem;
    const tbs_sig = try Element.parse(bytes, serial.slice.end);
    const issuer = try Element.parse(bytes, tbs_sig.slice.end);
    const validity = try Element.parse(bytes, issuer.slice.end);
    const subject = try Element.parse(bytes, validity.slice.end);
    const spki = try Element.parse(bytes, subject.slice.end);

    if (!is_v3 or spki.slice.end >= tbs.slice.end) return out;

    const outer = try Element.parse(bytes, spki.slice.end);
    if (outer.identifier.tag != .bitstring) return out; // not the [3] EXPLICIT extensions wrapper

    const extensions = try Element.parse(bytes, outer.slice.start);
    var i = extensions.slice.start;
    while (i < extensions.slice.end) {
        const extension = try Element.parse(bytes, i);
        i = extension.slice.end;

        const oid = try Element.parse(bytes, extension.slice.start);
        const crit_elem = try Element.parse(bytes, oid.slice.end);
        const critical = crit_elem.identifier.tag == .boolean and bytes[crit_elem.slice.start] != 0;
        const value = if (crit_elem.identifier.tag != .boolean) crit_elem else try Element.parse(bytes, crit_elem.slice.end);

        const ext_id = Certificate.parseExtensionId(bytes, oid) catch |err| switch (err) {
            error.CertificateHasUnrecognizedObjectId => {
                if (critical) out.unknown_critical = true;

                continue;
            },
            else => |e| return e,
        };

        switch (ext_id) {
            .basic_constraints => {
                // extnValue OCTET STRING wraps SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }.
                const seq = try Element.parse(bytes, value.slice.start);
                if (seq.slice.start >= seq.slice.end) continue;

                const first = try Element.parse(bytes, seq.slice.start);
                if (first.identifier.tag != .boolean) continue;
                out.is_ca = bytes[first.slice.start] != 0;
                if (first.slice.end >= seq.slice.end) continue;

                const pl = try Element.parse(bytes, first.slice.end);
                if (pl.identifier.tag == .integer and (pl.slice.end - pl.slice.start) <= 4) {
                    var v: u32 = 0;
                    for (bytes[pl.slice.start..pl.slice.end]) |b| v = (v << 8) | b;
                    out.path_len = v;
                }
            },
            .key_usage => {
                out.has_key_usage = true;
                // extnValue OCTET STRING wraps BIT STRING { unused_bits, usage... }, keyCertSign = bit 5 (0x04).
                const bs = try Element.parse(bytes, value.slice.start);
                const content = bytes[bs.slice.start..bs.slice.end];
                if (content.len >= 2 and (content[1] & 0x04) != 0) out.key_cert_sign = true;
            },
            else => {},
        }
    }

    return out;
}

/// Verify a certificate chain (RFC 5280 6.1): chain[0] is the end-entity, chain[i] is signed by
/// chain[i+1], and the last cert is signed by trust_anchor_der. Each link's signature, validity
/// window, and issuer-name are checked (std), and on top of that every issuing CA must have
/// basicConstraints cA TRUE, keyCertSign (when keyUsage is present), and a pathLenConstraint the
/// chain does not exceed. Any unrecognized CRITICAL extension on a path cert is rejected.
///
/// Note:
/// - For a single self-signed server, use verifyCertChain (one anchor) instead. This is the
///   intermediate-CA case (the chain the TLS Certificate message carries, leaf first).
///
/// Param:
/// chain_der - []const []const u8 (end-entity first, then intermediates up but NOT the anchor)
/// trust_anchor_der - []const u8 (the trusted root the top of the chain must be signed by)
/// now_sec - i64 (current UNIX time in seconds, for each validity window)
///
/// Return:
/// - void on a valid, constrained chain
/// - error.ZixEmptyChain (chain_der has no certs)
/// - error.ZixIssuerNotCertificateAuthority / error.ZixIssuerKeyUsageForbidsSigning
/// - error.ZixPathLenConstraintExceeded / error.ZixUnrecognizedCriticalExtension
/// - propagates std.crypto.Certificate verify errors (signature / validity / issuer mismatch)
pub fn verifyChain(chain_der: []const []const u8, trust_anchor_der: []const u8, now_sec: i64) !void {
    if (chain_der.len == 0) return error.ZixEmptyChain;

    const anchor = try (Certificate{ .buffer = trust_anchor_der, .index = 0 }).parse();

    var idx: usize = 0;
    while (idx < chain_der.len) : (idx += 1) {
        const subject = try (Certificate{ .buffer = chain_der[idx], .index = 0 }).parse();
        const at_top = idx + 1 >= chain_der.len;
        const issuer_der = if (at_top) trust_anchor_der else chain_der[idx + 1];
        const issuer = if (at_top) anchor else try (Certificate{ .buffer = chain_der[idx + 1], .index = 0 }).parse();

        try subject.verify(issuer, now_sec);

        const issuer_constraints = try pathConstraints(issuer_der);
        if (!issuer_constraints.is_ca) return error.ZixIssuerNotCertificateAuthority;
        if (issuer_constraints.has_key_usage and !issuer_constraints.key_cert_sign) return error.ZixIssuerKeyUsageForbidsSigning;
        if (issuer_constraints.path_len) |pl| {
            // intermediates strictly between this issuer and the end-entity (chain[1..idx]).
            if (idx > pl) return error.ZixPathLenConstraintExceeded;
        }

        const subject_constraints = try pathConstraints(chain_der[idx]);
        if (subject_constraints.unknown_critical) return error.ZixUnrecognizedCriticalExtension;
    }
}

// --------------------------------------------------------------- //
// fixture: self-signed CN=localhost, SAN DNS:localhost + IP:127.0.0.1,
// notBefore Jun 22 2026 / notAfter Jun 19 2036. Shared with client.zig.

const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";

fn fixtureDer(buf: []u8) ![]const u8 {
    return std.fmt.hexToBytes(buf, fixture_cert_hex);
}

test "zix tls: cert verify, self-signed chain inside validity window passes" {
    var buf: [512]u8 = undefined;
    const der = try fixtureDer(&buf);

    const now_sec: i64 = 1_800_000_000; // ~2027-01, inside notBefore (Jun 2026) .. notAfter (Jun 2036)
    try verifyCertChain(der, der, now_sec); // self-signed: anchor is the leaf itself
}

test "zix tls: cert verify, before notBefore is rejected" {
    var buf: [512]u8 = undefined;
    const der = try fixtureDer(&buf);

    const too_early: i64 = 1_700_000_000; // ~2023-11, before notBefore (Jun 2026)
    try std.testing.expectError(error.CertificateNotYetValid, verifyCertChain(der, der, too_early));
}

test "zix tls: cert verify, hostname SAN match and mismatch" {
    var buf: [512]u8 = undefined;
    const der = try fixtureDer(&buf);

    try verifyCertHostname(der, "localhost"); // SAN DNS:localhost
    try std.testing.expectError(error.CertificateHostMismatch, verifyCertHostname(der, "evil.example"));
}

test "zix tls: cert verify, identity matches DNS or IP SAN (for the 421 gate)" {
    var buf: [512]u8 = undefined;
    const der = try fixtureDer(&buf); // SAN DNS:localhost + IP:127.0.0.1

    try verifyCertIdentity(der, "localhost"); // DNS SAN
    try verifyCertIdentity(der, "127.0.0.1"); // iPAddress SAN (std verifyHostName alone would miss this)

    try std.testing.expectError(error.CertificateHostMismatch, verifyCertIdentity(der, "evil.example"));
    try std.testing.expectError(error.CertificateHostMismatch, verifyCertIdentity(der, "10.0.0.1"));
}

test "zix tls: cert verify, peer P-256 public key matches the fixture signing key" {
    var buf: [512]u8 = undefined;
    const der = try fixtureDer(&buf);

    const pub_key = try peerEcdsaP256PublicKey(der);

    // the fixture cert's key is the scalar reused across the tls tests. Its public key must match.
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const expected = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    try std.testing.expectEqualSlices(u8, &expected.public_key.toUncompressedSec1(), &pub_key.toUncompressedSec1());
}

// --------------------------------------------------------------- //
// chain fixture (ECDSA P-256): root (CA, no pathlen) -> intermediate (CA, pathlen:0) -> leaf
// (CN=localhost, SAN DNS:localhost, not a CA). notBefore Jun 23 2026 / notAfter Jun 20 2036.

const chain_root_hex = "308201953082013ba003020102021440f79706c99a7008e5dda0815e4e311f9e702f51300a06082a8648ce3d04030230183116301406035504030c0d7a69782d746573742d726f6f74301e170d3236303632333037333630315a170d3336303632303037333630315a30183116301406035504030c0d7a69782d746573742d726f6f743059301306072a8648ce3d020106082a8648ce3d030107034200044a89ec0c129c506d9b1f92c5b28f9328a7b063556cd64c2d5802db0e64c456fc90219d78b6cfda10027423eb8c1c4a886bfe2bb9b4aa7cba9bd449f117f57c04a3633061301d0603551d0e04160414356f3ac248e3e2a8bb9bd047c5e6219aada7f020301f0603551d23041830168014356f3ac248e3e2a8bb9bd047c5e6219aada7f020300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020348003045022100ea3bdd439b274a5d0ef7993a70f18d913e7840d669d1b44c9eb84149eb7ac08602203804ec5881841d3a734e4e1a05231c595b6f43a1ca3e6f0d0398004f85d0047e";
const chain_int_hex = "3082019f30820146a00302010202140676b25f6c4f12ed9bb873f83a007db84e8f3846300a06082a8648ce3d04030230183116301406035504030c0d7a69782d746573742d726f6f74301e170d3236303632333037333630315a170d3336303632303037333630315a3020311e301c06035504030c157a69782d746573742d696e7465726d6564696174653059301306072a8648ce3d020106082a8648ce3d03010703420004247a6c91f8537ef15cf71670559138fdba0d2a1865b9b809fd1780e227b3a4a8d56c95e7c83311b76c2ab3861b7b1d4d1b535c8f67a5b1e8d32b54b38064c999a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106301d0603551d0e04160414d699cb91497cc7f981bccaf6a632a1eee036d52b301f0603551d23041830168014356f3ac248e3e2a8bb9bd047c5e6219aada7f020300a06082a8648ce3d040302034700304402200a09dc44d9614305084cdc7081d7181a4497d0ee9787d2e5f8196fe7e50c50fd02203e97e6be1d67006729f38c15caf116ec8b0be7cb4a101e1f9ecc71d52b435c71";
const chain_leaf_hex = "308201ad30820152a003020102021472dd9fe9aa428ce22acbb7e6146231e66269a6c0300a06082a8648ce3d0403023020311e301c06035504030c157a69782d746573742d696e7465726d656469617465301e170d3236303632333037333630315a170d3336303632303037333630315a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200047c1d5b1ca87efb392f68fb1c13da2edcc8d7eb0a173eb7ce23174a7009142da963143404d08634fd9a4552594d405fe87bf183c08b973ad1ab0089d43e1949bfa3763074300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030140603551d11040d300b82096c6f63616c686f7374301d0603551d0e0416041460d9685b0a35acfaa9975e62a3d2660234a2ea07301f0603551d23041830168014d699cb91497cc7f981bccaf6a632a1eee036d52b300a06082a8648ce3d0403020349003046022100ee1b1fc48b0e3b3582d0fbcdbc146863263816e1b547f94aba57c25b28cd604d022100c7cdba1f9e63e82ff9cc31e196711368fec9cf3f092b795402f99c28e45f5227";

const chain_now_sec: i64 = 1_800_000_000; // ~2027-01, inside the chain validity window

test "zix tls: cert verify, pathConstraints reads cA / keyCertSign / pathLen per cert" {
    var rb: [512]u8 = undefined;
    var ib: [512]u8 = undefined;
    var lb: [512]u8 = undefined;
    const root = try std.fmt.hexToBytes(&rb, chain_root_hex);
    const intermediate = try std.fmt.hexToBytes(&ib, chain_int_hex);
    const leaf = try std.fmt.hexToBytes(&lb, chain_leaf_hex);

    const rc = try pathConstraints(root);
    try std.testing.expect(rc.is_ca and rc.key_cert_sign);
    try std.testing.expectEqual(@as(?u32, null), rc.path_len); // root has no pathLenConstraint

    const ic = try pathConstraints(intermediate);
    try std.testing.expect(ic.is_ca and ic.key_cert_sign);
    try std.testing.expectEqual(@as(?u32, 0), ic.path_len); // intermediate is pathlen:0

    const lc = try pathConstraints(leaf);
    try std.testing.expect(!lc.is_ca); // the leaf is not a CA
    try std.testing.expect(!lc.key_cert_sign); // digitalSignature only
    try std.testing.expect(!lc.unknown_critical);
}

test "zix tls: cert verify, multi-cert chain leaf<-intermediate<-root validates" {
    var ib: [512]u8 = undefined;
    var lb: [512]u8 = undefined;
    var rb: [512]u8 = undefined;
    const intermediate = try std.fmt.hexToBytes(&ib, chain_int_hex);
    const leaf = try std.fmt.hexToBytes(&lb, chain_leaf_hex);
    const root = try std.fmt.hexToBytes(&rb, chain_root_hex);

    const chain = [_][]const u8{ leaf, intermediate };
    try verifyChain(&chain, root, chain_now_sec);
    try verifyCertHostname(leaf, "localhost"); // the leaf identity still matches
}

test "zix tls: cert verify, multi-cert chain rejects wrong anchor / expiry / empty" {
    var ib: [512]u8 = undefined;
    var lb: [512]u8 = undefined;
    var rb: [512]u8 = undefined;
    const intermediate = try std.fmt.hexToBytes(&ib, chain_int_hex);
    const leaf = try std.fmt.hexToBytes(&lb, chain_leaf_hex);
    const root = try std.fmt.hexToBytes(&rb, chain_root_hex);

    const chain = [_][]const u8{ leaf, intermediate };

    // the leaf is not the intermediate's issuer, so chaining the top to it fails the name/signature link.
    try std.testing.expectError(error.CertificateIssuerMismatch, verifyChain(&chain, leaf, chain_now_sec));

    // far past notAfter (Jun 2036).
    try std.testing.expectError(error.CertificateExpired, verifyChain(&chain, root, 2_200_000_000));

    // an empty chain has no end-entity to anchor.
    try std.testing.expectError(error.ZixEmptyChain, verifyChain(&[_][]const u8{}, root, chain_now_sec));
}
