//! PEM + minimal DER decode for loading the server certificate and ECDSA private key.
//!
//! Note:
//! - `pemToDer` strips the -----BEGIN/END----- armor and base64-decodes the body. The
//!   certificate DER feeds the Certificate message as-is. `ecdsaScalarFromSec1` extracts the
//!   raw 32-byte private scalar from a SEC1 ECPrivateKey (RFC 5915, the form `openssl ecparam
//!   -genkey` emits), and `ed25519SeedFromPkcs8` extracts the 32-byte seed from a PKCS#8
//!   PrivateKeyInfo (RFC 8410, the form `openssl genpkey -algorithm ed25519` emits). Full X.509
//!   parsing is a separate concern.

const std = @import("std");

pub const Error = error{ ZixInvalidPem, ZixInvalidKey, ZixBufferTooSmall };

/// Base64 accumulation buffer: caps the max PEM cert or key document size.
const MAX_PEM_BYTES: usize = 16384;

// --------------------------------------------------------------- //

/// Decode a PEM document body to DER into `out`, returning the DER slice.
pub fn pemToDer(out: []u8, pem: []const u8) ![]const u8 {
    var b64: [MAX_PEM_BYTES]u8 = undefined;
    var n: usize = 0;

    var lines = std.mem.tokenizeScalar(u8, pem, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or std.mem.startsWith(u8, line, "-----")) continue;
        if (n + line.len > b64.len) return error.ZixBufferTooSmall;

        @memcpy(b64[n..][0..line.len], line);
        n += line.len;
    }

    const decoder = std.base64.standard.Decoder;
    const der_len = decoder.calcSizeForSlice(b64[0..n]) catch return error.ZixInvalidPem;
    if (der_len > out.len) return error.ZixBufferTooSmall;
    decoder.decode(out[0..der_len], b64[0..n]) catch return error.ZixInvalidPem;

    return out[0..der_len];
}

/// The most certificates one chain may hold: an end-entity plus the intermediates a public authority
/// needs, bounded the same way the rest of this file is.
pub const max_chain = 4;

/// One decoded certificate chain: the end-entity first, then any intermediates, each DER. The entries
/// point into the caller's buffer, so it must outlive the chain.
pub const Chain = struct {
    ders: [max_chain][]const u8 = @splat(&.{}),
    len: usize = 0,

    /// The entries, in the order the document listed them: the end-entity first.
    pub fn slice(self: *const Chain) []const []const u8 {
        return self.ders[0..self.len];
    }
};

/// Decode every CERTIFICATE block of a PEM document into `out`, in document order.
///
/// Why: a server certificate that a public authority issued is presented with the intermediates that
/// chain it back to that authority. Serving the end-entity alone leaves a client that does not already
/// hold the intermediate unable to build a path, which it reports as a missing issuer. A document with a
/// single block yields a chain of one, so a single-certificate file behaves as it always did.
///
/// Param:
/// out - []u8 (holds every decoded DER, packed end to end)
/// chain - *Chain (filled with the entries, pointing into `out`)
/// pem - []const u8 (the PEM document)
///
/// Return:
/// - error.ZixInvalidPem (no CERTIFICATE block, or a body that is not base64)
/// - error.ZixBufferTooSmall (over max_chain entries, or the DER does not fit `out`)
pub fn chainToDer(out: []u8, chain: *Chain, pem: []const u8) !void {
    var used: usize = 0;
    var b64: [MAX_PEM_BYTES]u8 = undefined;
    var n: usize = 0;
    var in_certificate = false;

    var lines = std.mem.tokenizeScalar(u8, pem, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "-----BEGIN ")) {
            in_certificate = std.mem.indexOf(u8, line, "CERTIFICATE") != null;
            n = 0;

            continue;
        }

        if (std.mem.startsWith(u8, line, "-----END ")) {
            if (!in_certificate) continue;
            if (chain.len == max_chain) return error.ZixBufferTooSmall;

            const decoder = std.base64.standard.Decoder;
            const der_len = decoder.calcSizeForSlice(b64[0..n]) catch return error.ZixInvalidPem;
            if (used + der_len > out.len) return error.ZixBufferTooSmall;
            decoder.decode(out[used..][0..der_len], b64[0..n]) catch return error.ZixInvalidPem;

            chain.ders[chain.len] = out[used..][0..der_len];
            chain.len += 1;
            used += der_len;
            in_certificate = false;

            continue;
        }

        if (!in_certificate) continue;
        if (n + line.len > b64.len) return error.ZixBufferTooSmall;

        @memcpy(b64[n..][0..line.len], line);
        n += line.len;
    }

    if (chain.len == 0) return error.ZixInvalidPem;
}

/// Extract the 32-byte private scalar from a SEC1 ECPrivateKey DER (RFC 5915):
/// SEQUENCE { INTEGER version(1), OCTET STRING privateKey(32), ... }.
pub fn ecdsaScalarFromSec1(der: []const u8) ![32]u8 {
    var r = DerReader{ .buf = der };

    try r.expectTag(0x30); // SEQUENCE
    _ = try r.readLen();
    try r.expectTag(0x02); // INTEGER version
    try r.skip(try r.readLen());
    try r.expectTag(0x04); // OCTET STRING privateKey
    if (try r.readLen() != 32) return error.ZixInvalidKey;

    var out: [32]u8 = undefined;
    @memcpy(&out, try r.read(32));

    return out;
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 PrivateKeyInfo DER (RFC 8410): SEQUENCE {
/// INTEGER version, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING privateKey(32) } }.
/// This is the form `openssl genpkey -algorithm ed25519` emits.
pub fn ed25519SeedFromPkcs8(der: []const u8) ![32]u8 {
    var r = DerReader{ .buf = der };

    try r.expectTag(0x30); // SEQUENCE PrivateKeyInfo
    _ = try r.readLen();
    try r.expectTag(0x02); // INTEGER version
    try r.skip(try r.readLen());
    try r.expectTag(0x30); // SEQUENCE AlgorithmIdentifier
    try r.skip(try r.readLen());
    try r.expectTag(0x04); // OCTET STRING privateKey
    _ = try r.readLen();
    try r.expectTag(0x04); // inner OCTET STRING CurvePrivateKey
    if (try r.readLen() != 32) return error.ZixInvalidKey;

    var out: [32]u8 = undefined;
    @memcpy(&out, try r.read(32));

    return out;
}

const DerReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *DerReader) Error!u8 {
        if (self.pos >= self.buf.len) return error.ZixInvalidKey;

        const b = self.buf[self.pos];
        self.pos += 1;

        return b;
    }

    fn expectTag(self: *DerReader, tag: u8) Error!void {
        if (try self.byte() != tag) return error.ZixInvalidKey;
    }

    fn readLen(self: *DerReader) Error!usize {
        const first = try self.byte();
        if (first < 0x80) return first;

        const count = first & 0x7f;
        if (count == 0 or count > 2) return error.ZixInvalidKey;

        var len: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) len = (len << 8) | (try self.byte());

        return len;
    }

    fn skip(self: *DerReader, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.ZixInvalidKey;
        self.pos += n;
    }

    fn read(self: *DerReader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.ZixInvalidKey;

        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;

        return s;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: pem, a chain decodes every CERTIFICATE block in document order" {
    // The shape a public authority's fullchain file has: the end-entity first, then the intermediate that
    // chains it back to the authority. Before this, every block's body was concatenated into one base64
    // blob, so a chain decoded as garbage and only a single-certificate file survived.
    const document =
        \\-----BEGIN CERTIFICATE-----
        \\MAMBAgM=
        \\-----END CERTIFICATE-----
        \\-----BEGIN CERTIFICATE-----
        \\MAQKCwwN
        \\-----END CERTIFICATE-----
    ;
    const end_entity = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
    const intermediate = [_]u8{ 0x30, 0x04, 0x0a, 0x0b, 0x0c, 0x0d };

    var out: [64]u8 = undefined;
    var chain: Chain = .{};
    try chainToDer(&out, &chain, document);

    try std.testing.expectEqual(@as(usize, 2), chain.len);
    try std.testing.expectEqualSlices(u8, &end_entity, chain.slice()[0]);
    try std.testing.expectEqualSlices(u8, &intermediate, chain.slice()[1]);
}

test "zix tls: pem, one CERTIFICATE block is a chain of one" {
    const document =
        \\-----BEGIN CERTIFICATE-----
        \\MAMBAgM=
        \\-----END CERTIFICATE-----
    ;

    var out: [64]u8 = undefined;
    var chain: Chain = .{};
    try chainToDer(&out, &chain, document);

    try std.testing.expectEqual(@as(usize, 1), chain.len);
    try std.testing.expectEqual(@as(usize, 5), chain.slice()[0].len);
}

test "zix tls: pem, a document with no CERTIFICATE block is not a chain" {
    const document =
        \\-----BEGIN PRIVATE KEY-----
        \\MAMBAgM=
        \\-----END PRIVATE KEY-----
    ;

    var out: [64]u8 = undefined;
    var chain: Chain = .{};
    try std.testing.expectError(error.ZixInvalidPem, chainToDer(&out, &chain, document));
}

test "zix tls: pem, SEC1 ECDSA key -> 32-byte scalar (fixture)" {
    const key_pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHcCAQEEIAt29/HHv24gAp3bVmeV5Y2lumP/vbkUv2mb++0xR9MsoAoGCCqGSM49
        \\AwEHoUQDQgAEwqASGymKyc04kgDnjZTnveHMfNgHR5X6tPkZeZ1A/cIxxakJkKyM
        \\YWauRy8z90/O0Jfy7be4oZdL5mpKsH8lOw==
        \\-----END EC PRIVATE KEY-----
    ;

    var der_buf: [256]u8 = undefined;
    const der = try pemToDer(&der_buf, key_pem);
    const scalar = try ecdsaScalarFromSec1(der);

    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    try std.testing.expectEqualSlices(u8, &expected, &scalar);
}

test "zix tls: pem, PKCS#8 Ed25519 key -> 32-byte seed (fixture)" {
    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIFwpJTm6t3wxIBTGVqlD12tSAhCajuDznWINyTQWWiiM
        \\-----END PRIVATE KEY-----
    ;

    var der_buf: [128]u8 = undefined;
    const der = try pemToDer(&der_buf, key_pem);
    const seed = try ed25519SeedFromPkcs8(der);

    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "5c292539bab77c312014c656a943d76b5202109a8ee0f39d620dc934165a288c");
    try std.testing.expectEqualSlices(u8, &expected, &seed);

    // the seed must reconstruct a valid Ed25519 key pair.
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    _ = kp;
}
