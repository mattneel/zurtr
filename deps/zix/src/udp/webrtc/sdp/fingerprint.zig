//! zix SDP certificate fingerprint (RFC 8122 5, RFC 8842 6).
//!
//! What:
//! - The `a=fingerprint` attribute: a hash function name and the hash of the peer's certificate,
//!   written as colon-separated hex.
//!
//! Note:
//! - This is what makes a self-signed certificate safe to use. Neither side checks a certificate
//!   chain. Instead the signaling channel carries the hash, and the certificate that shows up in
//!   the DTLS handshake has to hash to it (RFC 8842 6). A handshake that completes against a
//!   certificate whose hash was never checked is a handshake with whoever got there first.
//! - The hash function name is compared without case. RFC 8122 5 registers it lower case and
//!   browsers send it that way, while the RFC 8841 and RFC 8842 examples write it upper case, so
//!   both spellings are on the wire already.
//! - The hex digits are read in either case and written upper, which is the case RFC 8122 5
//!   grammar uses.
//! - The digest is copied into a fixed buffer rather than borrowed. A fingerprint outlives the
//!   description it was read from: it is checked against a certificate that arrives later.
//! - Comparison is a plain byte compare. A certificate hash is public, sent in the clear over the
//!   signaling channel, so there is no secret here for a timing difference to leak.

const std = @import("std");

/// The longest digest any listed function produces.
pub const MAX_DIGEST_LEN: usize = 64;

/// The longest attribute value this writes, being the longest name, a space, and the hex form.
pub const MAX_VALUE_LEN: usize = 8 + 1 + MAX_DIGEST_LEN * 3 - 1;

/// What separates the hex pairs.
pub const SEPARATOR: u8 = ':';

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "fingerprint";

/// Everything that stops a fingerprint from being read. Writing only ever runs out of room, so
/// `write` carries that one on its own.
pub const Error = error{
    /// A value without a hash function name and a digest.
    ZixMalformed,
    /// A hash function this endpoint does not implement.
    ZixUnsupportedFunction,
    /// Hex that is not pairs separated by colons, or a length the function does not produce.
    ZixBadDigest,
};

/// The hash functions RFC 8122 5 lists that this endpoint implements.
///
/// Note:
/// - MD5 and MD2 are in the registry and are not here. Both are broken for this use, and a peer
///   offering only those is a peer whose certificate cannot be pinned.
pub const Function = enum {
    SHA_1,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,

    /// The name as it goes out.
    ///
    /// Return:
    /// - []const u8
    pub fn name(self: Function) []const u8 {
        return switch (self) {
            .SHA_1 => "sha-1",
            .SHA_224 => "sha-224",
            .SHA_256 => "sha-256",
            .SHA_384 => "sha-384",
            .SHA_512 => "sha-512",
        };
    }

    /// How many bytes the digest takes.
    ///
    /// Return:
    /// - usize
    pub fn digestLen(self: Function) usize {
        return switch (self) {
            .SHA_1 => 20,
            .SHA_224 => 28,
            .SHA_256 => 32,
            .SHA_384 => 48,
            .SHA_512 => 64,
        };
    }
};

/// One certificate fingerprint, owning its digest.
pub const Fingerprint = struct {
    function: Function,
    digest: [MAX_DIGEST_LEN]u8,
    /// How many of `digest` are filled.
    len: usize,

    /// The digest alone.
    ///
    /// Return:
    /// - []const u8
    pub fn bytes(self: *const Fingerprint) []const u8 {
        return self.digest[0..self.len];
    }

    /// Whether two fingerprints name the same certificate.
    ///
    /// Note:
    /// - Two fingerprints under different hash functions never match here, even for the same
    ///   certificate. Deciding that would mean hashing the certificate again, which is what
    ///   `compute` is for.
    ///
    /// Param:
    /// other - *const Fingerprint
    ///
    /// Return:
    /// - bool
    pub fn matches(self: *const Fingerprint, other: *const Fingerprint) bool {
        if (self.function != other.function) return false;

        return std.mem.eql(u8, self.bytes(), other.bytes());
    }
};

/// Read an `a=fingerprint` attribute value.
///
/// Param:
/// value - []const u8 (everything after `fingerprint:`, such as "sha-256 AB:CD:...")
///
/// Return:
/// - Fingerprint, owning a copy of the digest
/// - error.ZixMalformed if the name or the digest is missing
/// - error.ZixUnsupportedFunction
/// - error.ZixBadDigest if the hex is not pairs, or is the wrong length for the function
pub fn read(value: []const u8) Error!Fingerprint {
    var fields = std.mem.tokenizeScalar(u8, value, ' ');

    const function_name = fields.next() orelse return error.ZixMalformed;
    const hex = fields.next() orelse return error.ZixMalformed;
    const function = try functionFor(function_name);

    var parsed: Fingerprint = .{ .function = function, .digest = @splat(0), .len = 0 };

    var pairs = std.mem.splitScalar(u8, hex, SEPARATOR);
    while (pairs.next()) |pair| {
        if (pair.len != 2) return error.ZixBadDigest;
        if (parsed.len >= MAX_DIGEST_LEN) return error.ZixBadDigest;

        parsed.digest[parsed.len] = ((try hexDigit(pair[0])) << 4) | (try hexDigit(pair[1]));
        parsed.len += 1;
    }

    if (parsed.len != function.digestLen()) return error.ZixBadDigest;

    return parsed;
}

/// Write an `a=fingerprint` attribute value.
///
/// Param:
/// out - []u8 (at least MAX_VALUE_LEN)
/// value - *const Fingerprint
///
/// Return:
/// - []const u8, the value alone, with no attribute name
/// - error.ZixNoSpace
pub fn write(out: []u8, value: *const Fingerprint) error{ZixNoSpace}![]const u8 {
    const alphabet = "0123456789ABCDEF";
    const function_name = value.function.name();
    const total = function_name.len + 1 + value.len * 3 - 1;

    if (value.len == 0) return error.ZixNoSpace;
    if (out.len < total) return error.ZixNoSpace;

    @memcpy(out[0..function_name.len], function_name);
    out[function_name.len] = ' ';

    var at = function_name.len + 1;
    for (value.bytes(), 0..) |byte, index| {
        if (index != 0) {
            out[at] = SEPARATOR;
            at += 1;
        }

        out[at] = alphabet[byte >> 4];
        out[at + 1] = alphabet[byte & 0x0F];
        at += 2;
    }

    return out[0..total];
}

/// Hash a certificate the way RFC 8122 5 asks for.
///
/// Note:
/// - The input is the certificate as DER, which is exactly the bytes a DTLS Certificate message
///   carries. Hashing a PEM-armoured copy gives a different answer and matches nothing.
///
/// Param:
/// certificate_der - []const u8 (one certificate, DER encoded)
/// function - Function
///
/// Return:
/// - Fingerprint
pub fn compute(certificate_der: []const u8, function: Function) Fingerprint {
    var value: Fingerprint = .{ .function = function, .digest = @splat(0), .len = function.digestLen() };

    switch (function) {
        .SHA_1 => std.crypto.hash.Sha1.hash(certificate_der, value.digest[0..20], .{}),
        .SHA_224 => std.crypto.hash.sha2.Sha224.hash(certificate_der, value.digest[0..28], .{}),
        .SHA_256 => std.crypto.hash.sha2.Sha256.hash(certificate_der, value.digest[0..32], .{}),
        .SHA_384 => std.crypto.hash.sha2.Sha384.hash(certificate_der, value.digest[0..48], .{}),
        .SHA_512 => std.crypto.hash.sha2.Sha512.hash(certificate_der, value.digest[0..64], .{}),
    }

    return value;
}

/// The function a name stands for, whatever case it came in.
///
/// Param:
/// text - []const u8
///
/// Return:
/// - Function
/// - error.ZixUnsupportedFunction
pub fn functionFor(text: []const u8) error{ZixUnsupportedFunction}!Function {
    if (std.ascii.eqlIgnoreCase(text, "sha-1")) return .SHA_1;
    if (std.ascii.eqlIgnoreCase(text, "sha-224")) return .SHA_224;
    if (std.ascii.eqlIgnoreCase(text, "sha-256")) return .SHA_256;
    if (std.ascii.eqlIgnoreCase(text, "sha-384")) return .SHA_384;
    if (std.ascii.eqlIgnoreCase(text, "sha-512")) return .SHA_512;

    return error.ZixUnsupportedFunction;
}

/// One hex digit, in either case.
fn hexDigit(character: u8) error{ZixBadDigest}!u8 {
    return switch (character) {
        '0'...'9' => character - '0',
        'a'...'f' => character - 'a' + 10,
        'A'...'F' => character - 'A' + 10,
        else => error.ZixBadDigest,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

const sample_value: []const u8 =
    "sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:" ++
    "DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08";

test "zix sdp: fingerprint read, the JSEP sample reads back byte for byte" {
    const parsed = try read(sample_value);

    try std.testing.expectEqual(Function.SHA_256, parsed.function);
    try std.testing.expectEqual(@as(usize, 32), parsed.len);
    try std.testing.expectEqual(@as(u8, 0x6B), parsed.digest[0]);
    try std.testing.expectEqual(@as(u8, 0x8B), parsed.digest[1]);
    try std.testing.expectEqual(@as(u8, 0x08), parsed.digest[31]);
}

test "zix sdp: fingerprint read, the function name is taken in either case" {
    var upper: [MAX_VALUE_LEN]u8 = undefined;
    @memcpy(upper[0..sample_value.len], sample_value);
    upper[0] = 'S';
    upper[1] = 'H';
    upper[2] = 'A';

    const parsed = try read(upper[0..sample_value.len]);

    // The RFC 8841 and RFC 8842 examples write it upper case and browsers write it lower, so
    // one spelling working and the other not would fail against half of what is out there.
    try std.testing.expectEqual(Function.SHA_256, parsed.function);
}

test "zix sdp: fingerprint read, lower case hex is taken" {
    const parsed = try read("sha-1 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01");

    try std.testing.expectEqual(Function.SHA_1, parsed.function);
    try std.testing.expectEqual(@as(u8, 0xAB), parsed.digest[0]);
    try std.testing.expectEqual(@as(u8, 0x01), parsed.digest[19]);
}

test "zix sdp: fingerprint read, a missing field is refused" {
    try std.testing.expectError(error.ZixMalformed, read("sha-256"));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: fingerprint read, an unlisted function is refused" {
    try std.testing.expectError(error.ZixUnsupportedFunction, read("md5 AB:CD"));
    try std.testing.expectError(error.ZixUnsupportedFunction, read("sha3-256 AB:CD"));
}

test "zix sdp: fingerprint read, a digest of the wrong length for its function is refused" {
    try std.testing.expectError(error.ZixBadDigest, read("sha-256 AB:CD:EF"));
    try std.testing.expectError(error.ZixBadDigest, read("sha-1 " ++ sample_value[8..]));
}

test "zix sdp: fingerprint read, hex that is not pairs is refused" {
    try std.testing.expectError(error.ZixBadDigest, read("sha-1 A:CD:EF"));
    try std.testing.expectError(error.ZixBadDigest, read("sha-1 ABCDEF"));
}

test "zix sdp: fingerprint read, a digit that is not hex is refused" {
    try std.testing.expectError(error.ZixBadDigest, read("sha-1 GG:CD:EF"));
}

test "zix sdp: fingerprint write, the hex goes out upper case" {
    const parsed = try read("sha-1 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01");

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, &parsed);

    try std.testing.expectEqualStrings(
        "sha-1 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
        written,
    );
}

test "zix sdp: fingerprint write, what was written reads back the same" {
    const parsed = try read(sample_value);

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, &parsed);
    const again = try read(written);

    try std.testing.expect(parsed.matches(&again));
    try std.testing.expectEqualStrings(sample_value, written);
}

test "zix sdp: fingerprint write, a short buffer errors" {
    const parsed = try read(sample_value);

    var buf: [16]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, &parsed));
}

test "zix sdp: fingerprint compute, the digest is the one the hash gives" {
    const certificate = "not really a certificate, but a fixed run of bytes";
    const computed = compute(certificate, .SHA_256);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(certificate, &expected, .{});

    try std.testing.expectEqualSlices(u8, &expected, computed.bytes());
    try std.testing.expectEqual(@as(usize, 32), computed.len);
}

test "zix sdp: fingerprint compute, each function fills its own length" {
    const certificate = "fixed";

    try std.testing.expectEqual(@as(usize, 20), compute(certificate, .SHA_1).len);
    try std.testing.expectEqual(@as(usize, 28), compute(certificate, .SHA_224).len);
    try std.testing.expectEqual(@as(usize, 32), compute(certificate, .SHA_256).len);
    try std.testing.expectEqual(@as(usize, 48), compute(certificate, .SHA_384).len);
    try std.testing.expectEqual(@as(usize, 64), compute(certificate, .SHA_512).len);
}

test "zix sdp: fingerprint compute, a written digest reads back as the same one" {
    const computed = compute("a certificate", .SHA_256);

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const parsed = try read(try write(&buf, &computed));

    try std.testing.expect(computed.matches(&parsed));
}

test "zix sdp: fingerprint matches, one different byte is a different certificate" {
    const first = compute("a certificate", .SHA_256);
    const second = compute("a certificatf", .SHA_256);

    try std.testing.expect(!first.matches(&second));
}

test "zix sdp: fingerprint matches, the same bytes under two functions do not match" {
    const under_sha1 = compute("a certificate", .SHA_1);
    const under_sha256 = compute("a certificate", .SHA_256);

    try std.testing.expect(!under_sha1.matches(&under_sha256));
}

test "zix sdp: fingerprint functionFor, the five implemented names resolve" {
    try std.testing.expectEqual(Function.SHA_1, try functionFor("sha-1"));
    try std.testing.expectEqual(Function.SHA_224, try functionFor("SHA-224"));
    try std.testing.expectEqual(Function.SHA_256, try functionFor("sha-256"));
    try std.testing.expectEqual(Function.SHA_384, try functionFor("Sha-384"));
    try std.testing.expectEqual(Function.SHA_512, try functionFor("sha-512"));
}
