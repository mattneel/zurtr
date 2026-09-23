//! An ephemeral self-signed ECDSA P-256 certificate for the in-process TLS server.
//!
//! Note:
//! - Generated per server, never written to disk and never committed. This
//!   mirrors the test container, which also builds its certificate at start.
//! - Only what the driver's TLS client actually reads is emitted: the client
//!   parses the certificate for its public key and verifies CertificateVerify
//!   against it. Chain and hostname trust are out of scope on that side, so no
//!   extensions are emitted here, and the certificate is its own issuer.
//! - Validity is derived from the wall clock rather than hardcoded, so nothing
//!   here quietly rots into an expired fixture if a later change starts
//!   checking dates.

const std = @import("std");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Ceiling for the encoded certificate. A P-256 leaf with a short common name
/// lands near 330 bytes.
pub const MAX_DER = 1024;

/// AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2). Used for
/// both the inner and the outer signature algorithm, which RFC 5280 requires
/// to match.
const ALGO_ECDSA_SHA256 = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/// SubjectPublicKeyInfo algorithm: id-ecPublicKey (1.2.840.10045.2.1) with the
/// named curve prime256v1 (1.2.840.10045.3.1.7).
const ALGO_EC_PUBLIC_KEY_P256 = [_]u8{
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};

/// Object identifier for the commonName attribute (2.5.4.3).
const OID_COMMON_NAME = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
/// Context-specific 0, constructed: the explicit version wrapper.
const TAG_VERSION: u8 = 0xa0;

pub const Error = error{
    /// The certificate did not fit in MAX_DER, or an intermediate did not fit
    /// in its own buffer.
    RedizBufferTooSmall,
};

/// A fixed-capacity DER sink. Elements are built innermost first, then wrapped.
const Der = struct {
    bytes: []u8,
    len: usize = 0,

    fn append(self: *Der, source: []const u8) Error!void {
        if (self.len + source.len > self.bytes.len) return error.RedizBufferTooSmall;

        @memcpy(self.bytes[self.len..][0..source.len], source);
        self.len += source.len;
    }

    fn appendByte(self: *Der, byte: u8) Error!void {
        return self.append(&[_]u8{byte});
    }

    /// One tag-length-value element. Lengths above 127 take the long form,
    /// which is what the TBS wrapper needs.
    fn element(self: *Der, tag: u8, content: []const u8) Error!void {
        try self.appendByte(tag);

        if (content.len < 0x80) {
            try self.appendByte(@intCast(content.len));
        } else if (content.len <= 0xff) {
            try self.append(&[_]u8{ 0x81, @intCast(content.len) });
        } else if (content.len <= 0xffff) {
            try self.append(&[_]u8{ 0x82, @intCast(content.len >> 8), @truncate(content.len) });
        } else {
            return error.RedizBufferTooSmall;
        }

        try self.append(content);
    }

    /// A BIT STRING with no unused trailing bits, which is how both the public
    /// key and the signature are carried.
    fn bitString(self: *Der, content: []const u8) Error!void {
        try self.appendByte(TAG_BIT_STRING);

        const length = content.len + 1;
        if (length < 0x80) {
            try self.appendByte(@intCast(length));
        } else if (length <= 0xff) {
            try self.append(&[_]u8{ 0x81, @intCast(length) });
        } else {
            return error.RedizBufferTooSmall;
        }

        try self.appendByte(0x00);
        try self.append(content);
    }

    fn slice(self: *const Der) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// A generated key pair with its encoded certificate.
pub const SelfSigned = struct {
    key_pair: EcdsaP256.KeyPair,
    der_buf: [MAX_DER]u8,
    der_len: usize,

    const Self = @This();

    /// Generate a key pair and a matching self-signed certificate.
    ///
    /// Param:
    /// io - std.Io (entropy source for the key pair)
    /// common_name - []const u8 (subject and issuer common name)
    ///
    /// Return:
    /// - SelfSigned, copy it by value, it owns no heap memory
    /// - error.RedizBufferTooSmall when common_name pushes the encoding past MAX_DER
    pub fn generate(io: std.Io, common_name: []const u8) !Self {
        const key_pair = EcdsaP256.KeyPair.generate(io);

        var self = Self{ .key_pair = key_pair, .der_buf = undefined, .der_len = 0 };
        try self.encode(io, common_name);

        return self;
    }

    /// The certificate DER, what the Certificate handshake message carries.
    pub fn derBytes(self: *const Self) []const u8 {
        return self.der_buf[0..self.der_len];
    }

    // --------------------------------------------------------- //

    fn encode(self: *Self, io: std.Io, common_name: []const u8) !void {
        var name_buf: [128]u8 = undefined;
        const name = try encodeName(&name_buf, common_name);

        var validity_buf: [40]u8 = undefined;
        const validity = try encodeValidity(&validity_buf, io);

        var spki_buf: [128]u8 = undefined;
        const spki = try encodeSubjectPublicKeyInfo(&spki_buf, self.key_pair.public_key);

        var tbs_buf: [MAX_DER]u8 = undefined;
        const tbs = try encodeTbs(&tbs_buf, name, validity, spki);

        // RFC 5280 4.1.1.3: the signature covers the encoded TBSCertificate.
        const signature = try self.key_pair.sign(tbs, null);
        var signature_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
        const signature_der = signature.toDer(&signature_der_buf);

        var body_buf: [MAX_DER]u8 = undefined;
        var body = Der{ .bytes = &body_buf };
        try body.append(tbs);
        try body.append(&ALGO_ECDSA_SHA256);
        try body.bitString(signature_der);

        var out = Der{ .bytes = &self.der_buf };
        try out.element(TAG_SEQUENCE, body.slice());

        self.der_len = out.len;
    }
};

/// Name ::= SEQUENCE OF RelativeDistinguishedName, carrying just a commonName.
fn encodeName(buf: []u8, common_name: []const u8) Error![]const u8 {
    var attribute_buf: [96]u8 = undefined;
    var attribute = Der{ .bytes = &attribute_buf };
    try attribute.append(&OID_COMMON_NAME);
    try attribute.element(TAG_UTF8_STRING, common_name);

    var pair_buf: [104]u8 = undefined;
    var pair = Der{ .bytes = &pair_buf };
    try pair.element(TAG_SEQUENCE, attribute.slice());

    var rdn_buf: [112]u8 = undefined;
    var rdn = Der{ .bytes = &rdn_buf };
    try rdn.element(TAG_SET, pair.slice());

    var out = Der{ .bytes = buf };
    try out.element(TAG_SEQUENCE, rdn.slice());

    return out.slice();
}

/// Validity ::= SEQUENCE { notBefore, notAfter }, a window around now.
fn encodeValidity(buf: []u8, io: std.Io) Error![]const u8 {
    const now_seconds = wallClockSeconds(io);

    var not_before_buf: [13]u8 = undefined;
    var not_after_buf: [13]u8 = undefined;
    const not_before = utcTime(&not_before_buf, now_seconds -| std.time.s_per_day);
    const not_after = utcTime(&not_after_buf, now_seconds + 365 * std.time.s_per_day);

    var body_buf: [34]u8 = undefined;
    var body = Der{ .bytes = &body_buf };
    try body.element(TAG_UTC_TIME, not_before);
    try body.element(TAG_UTC_TIME, not_after);

    var out = Der{ .bytes = buf };
    try out.element(TAG_SEQUENCE, body.slice());

    return out.slice();
}

fn encodeSubjectPublicKeyInfo(buf: []u8, public_key: EcdsaP256.PublicKey) Error![]const u8 {
    const point = public_key.toUncompressedSec1();

    var body_buf: [112]u8 = undefined;
    var body = Der{ .bytes = &body_buf };
    try body.append(&ALGO_EC_PUBLIC_KEY_P256);
    try body.bitString(&point);

    var out = Der{ .bytes = buf };
    try out.element(TAG_SEQUENCE, body.slice());

    return out.slice();
}

fn encodeTbs(buf: []u8, name: []const u8, validity: []const u8, spki: []const u8) Error![]const u8 {
    var body_buf: [MAX_DER]u8 = undefined;
    var body = Der{ .bytes = &body_buf };

    // version [0] EXPLICIT v3, then a positive one-byte serial
    try body.element(TAG_VERSION, &[_]u8{ TAG_INTEGER, 0x01, 0x02 });
    try body.element(TAG_INTEGER, &[_]u8{0x01});
    try body.append(&ALGO_ECDSA_SHA256);

    // self-signed: issuer and subject are the same name
    try body.append(name);
    try body.append(validity);
    try body.append(name);
    try body.append(spki);

    var out = Der{ .bytes = buf };
    try out.element(TAG_SEQUENCE, body.slice());

    return out.slice();
}

/// UTCTime as `YYMMDDHHMMSSZ`, the 13-byte form the parser demands.
fn utcTime(buf: *[13]u8, unix_seconds: u64) []const u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = unix_seconds };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    _ = std.fmt.bufPrint(buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        @as(u16, year_day.year) % 100,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable;

    return buf;
}

fn wallClockSeconds(io: std.Io) u64 {
    const nanoseconds = std.Io.Timestamp.now(io, .real).nanoseconds;
    if (nanoseconds <= 0) return 0;

    return @intCast(@divTrunc(nanoseconds, std.time.ns_per_s));
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz inproc: certificate parses as x509 and exposes its public key" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const generated = try SelfSigned.generate(threaded.io(), "rediz-inproc");

    const cert = std.crypto.Certificate{ .buffer = generated.derBytes(), .index = 0 };
    const parsed = try cert.parse();

    try testing.expectEqualStrings("rediz-inproc", parsed.commonName());
    try testing.expectEqual(std.crypto.Certificate.Parsed.PubKeyAlgo{
        .X9_62_id_ecPublicKey = .X9_62_prime256v1,
    }, parsed.pub_key_algo);

    // the parsed key is the one that was generated
    const public_key = try EcdsaP256.PublicKey.fromSec1(parsed.pubKey());
    try testing.expectEqualSlices(
        u8,
        &generated.key_pair.public_key.toUncompressedSec1(),
        &public_key.toUncompressedSec1(),
    );
}

test "rediz inproc: certificate signature verifies against its own public key" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const generated = try SelfSigned.generate(threaded.io(), "rediz-inproc");

    // this is the operation the driver performs on CertificateVerify
    const message = "transcript stand-in";
    const signature = try generated.key_pair.sign(message, null);
    try signature.verify(message, generated.key_pair.public_key);
}

test "rediz inproc: certificate reports the signature algorithm as ecdsa sha256" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const generated = try SelfSigned.generate(threaded.io(), "rediz-inproc");

    const cert = std.crypto.Certificate{ .buffer = generated.derBytes(), .index = 0 };
    const parsed = try cert.parse();

    try testing.expectEqual(std.crypto.Certificate.Algorithm.ecdsa_with_SHA256, parsed.signature_algorithm);
}

test "rediz inproc: certificate validity brackets the current time" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const generated = try SelfSigned.generate(io, "rediz-inproc");

    const cert = std.crypto.Certificate{ .buffer = generated.derBytes(), .index = 0 };
    const parsed = try cert.parse();

    const now = wallClockSeconds(io);
    try testing.expect(parsed.validity.not_before < now);
    try testing.expect(parsed.validity.not_after > now);
}

test "rediz inproc: certificate each generation carries a fresh key" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first = try SelfSigned.generate(io, "rediz-inproc");
    const second = try SelfSigned.generate(io, "rediz-inproc");

    try testing.expect(!std.mem.eql(
        u8,
        &first.key_pair.public_key.toUncompressedSec1(),
        &second.key_pair.public_key.toUncompressedSec1(),
    ));
}

test "rediz inproc: certificate utc time formats a known instant" {
    var buf: [13]u8 = undefined;

    // 2024-02-29T12:34:56Z, a leap day so the month walk is exercised
    try testing.expectEqualStrings("240229123456Z", utcTime(&buf, 1_709_210_096));
}
