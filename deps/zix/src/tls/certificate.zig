//! TLS 1.3 Certificate, CertificateVerify, and Finished (RFC 8446 section 4.4).
//!
//! Note:
//! - Server-side message builders plus the CertificateVerify signing content and the Finished
//!   verify_data. zix authenticates with ECDSA P-256, Ed25519, or RSA (rsa_pss_rsae_sha256).
//! - The DER end-entity certificate is supplied by the caller (connection.zig loads it). PEM
//!   parsing + X.509 path validation are separate concerns (Layer V).
//! - Verified against the RFC 8448 trace in-file (Finished verify_data byte-exact).

const std = @import("std");
const wire = @import("wire.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const rsa = @import("rsa.zig");

const Reader = wire.Reader;
const Writer = wire.Writer;
const Secret = key_schedule.Secret;
const hash_length = key_schedule.hash_length;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

/// The server's CertificateVerify signing identity (RFC 8446 4.4.3), matching the certificate's key
/// type. scheme() is the TLS 1.3 SignatureScheme written on the wire, which the client must have
/// offered in signature_algorithms (Layer C selection). An RSA key signs CertificateVerify with
/// rsa_pss_rsae_sha256 (the only RSA scheme TLS 1.3 permits there).
pub const SigningKey = union(enum) {
    ecdsa_p256: EcdsaP256.KeyPair,
    ed25519: Ed25519.KeyPair,
    rsa: rsa.PrivateKey,

    pub fn scheme(self: SigningKey) handshake.SignatureScheme {
        return switch (self) {
            .ecdsa_p256 => .ECDSA_SECP256R1_SHA256,
            .ed25519 => .ED25519,
            .rsa => .RSA_PSS_RSAE_SHA256,
        };
    }
};

/// CertificateVerify context string for a server signature (RFC 8446 4.4.3).
pub const certificate_verify_context = "TLS 1.3, server CertificateVerify";

/// CertificateVerify context string for a client signature (RFC 8446 4.4.3), the mTLS counterpart.
/// Same length as the server context, only the role word differs.
pub const client_certificate_verify_context = "TLS 1.3, client CertificateVerify";

const certificate_verify_content_len = 64 + certificate_verify_context.len + 1 + hash_length;

// --------------------------------------------------------------- //

/// Build the Certificate message (RFC 8446 4.4.2): empty request_context, one entry per certificate in
/// `ders`, empty entry extensions. The entries are presented in the order given, so the end-entity comes
/// first and the intermediates after it. Returns the wire slice.
pub fn buildCertificate(buf: []u8, ders: []const []const u8) []const u8 {
    var w = Writer{ .buf = buf };

    w.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE));
    const header = w.placeU24();

    w.writeU8(0); // empty certificate_request_context

    const list = w.placeU24();
    for (ders) |der| {
        const entry = w.placeU24();
        w.writeBytes(der);
        w.patchU24(entry);
        w.writeU16(0); // empty entry extensions
    }
    w.patchU24(list);

    w.patchU24(header);

    return w.slice();
}

// --------------------------------------------------------------- //

/// Build the CertificateRequest message (RFC 8446 4.3.2): an empty certificate_request_context
/// and a signature_algorithms extension offering ecdsa_secp256r1_sha256 + ed25519. The server
/// emits this to prompt client authentication (mTLS). Returns the wire slice.
pub fn buildCertificateRequest(buf: []u8) []const u8 {
    var w = Writer{ .buf = buf };

    w.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE_REQUEST));
    const header = w.placeU24();

    w.writeU8(0); // empty certificate_request_context (not post-handshake auth)

    const extensions = w.placeU16();
    w.writeU16(@intFromEnum(handshake.ExtensionType.SIGNATURE_ALGORITHMS));
    const ext_body = w.placeU16();
    const scheme_list = w.placeU16();
    w.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    w.writeU16(@intFromEnum(handshake.SignatureScheme.ED25519));
    w.patchU16(scheme_list);
    w.patchU16(ext_body);
    w.patchU16(extensions);

    w.patchU24(header);

    return w.slice();
}

/// Extract the end-entity certificate DER from a Certificate message body (RFC 8446 4.4.2), the
/// bytes after the 4-octet handshake header. Returns the first (end-entity) entry's DER.
pub fn parseEndEntityCertificate(certificate_body: []const u8) !?[]const u8 {
    var r = Reader{ .buf = certificate_body };

    const context_len = try r.readU8();
    _ = try r.readBytes(context_len); // certificate_request_context (empty on the wire)
    const list_len = try r.readU24();
    if (list_len == 0) return null; // client sent an empty certificate_list (declined auth)

    const entry_len = try r.readU24();

    return try r.readBytes(entry_len);
}

// --------------------------------------------------------------- //

/// The CertificateVerify signed content (RFC 8446 4.4.3): a 64-octet 0x20 pad, the context
/// string, a 0x00 separator, then the transcript hash. Returns the slice written into `buf`.
pub fn certificateVerifyContent(buf: []u8, transcript_hash: Secret) []const u8 {
    @memset(buf[0..64], 0x20);
    @memcpy(buf[64 .. 64 + certificate_verify_context.len], certificate_verify_context);
    buf[64 + certificate_verify_context.len] = 0x00;
    @memcpy(buf[64 + certificate_verify_context.len + 1 ..][0..hash_length], &transcript_hash);

    return buf[0..certificate_verify_content_len];
}

/// Sign the CertificateVerify content with the server's key and emit the message (RFC 8446 4.4.3).
/// The wire SignatureScheme is the key's own scheme (ECDSA P-256 -> DER signature, Ed25519 -> raw
/// 64-byte signature, RSA -> rsa_pss_rsae_sha256). The caller selects the key so its scheme is one
/// the client offered.
///
/// Note:
/// - pss_salt is consumed only by the RSA path (EMSA-PSS needs a random salt, RFC 8017 9.1). The
///   serve path sources it from getrandom, the ECDSA / Ed25519 paths ignore it.
///
/// Param:
/// pss_salt - [rsa.pss_salt_len]u8 (the random salt for an RSA PSS signature, ignored otherwise)
pub fn buildCertificateVerify(buf: []u8, signing_key: SigningKey, transcript_hash: Secret, pss_salt: [rsa.pss_salt_len]u8) ![]const u8 {
    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript_hash);

    var w = Writer{ .buf = buf };
    w.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE_VERIFY));
    const header = w.placeU24();
    w.writeU16(@intFromEnum(signing_key.scheme()));
    const sig = w.placeU16();

    switch (signing_key) {
        .ecdsa_p256 => |key_pair| {
            const signature = try key_pair.sign(content, null);
            var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
            w.writeBytes(signature.toDer(&der_buf));
        },
        .ed25519 => |key_pair| {
            const signature = try key_pair.sign(content, null);
            w.writeBytes(&signature.toBytes());
        },
        .rsa => |key| {
            var sig_buf: [rsa.max_modulus_len]u8 = undefined;
            const signature = try key.signPss(content, pss_salt, &sig_buf);
            w.writeBytes(signature);
        },
    }

    w.patchU16(sig);
    w.patchU24(header);

    return w.slice();
}

/// The client CertificateVerify signed content (RFC 8446 4.4.3): identical framing to the server
/// content but with the client context string. Returns the slice written into `buf`.
pub fn clientCertificateVerifyContent(buf: []u8, transcript_hash: Secret) []const u8 {
    @memset(buf[0..64], 0x20);
    @memcpy(buf[64 .. 64 + client_certificate_verify_context.len], client_certificate_verify_context);
    buf[64 + client_certificate_verify_context.len] = 0x00;
    @memcpy(buf[64 + client_certificate_verify_context.len + 1 ..][0..hash_length], &transcript_hash);

    return buf[0..certificate_verify_content_len];
}

/// Verify a client CertificateVerify message body (RFC 8446 4.4.3) against the client cert's
/// public key. The signed content binds the transcript up to (and including) the client
/// Certificate, so `transcript_hash` is that snapshot.
///
/// Param:
/// certificate_verify_body - []const u8 (the message after the 4-octet handshake header)
/// public_key - EcdsaP256.PublicKey (from the client end-entity cert)
/// transcript_hash - Secret (transcript through the client Certificate)
///
/// Return:
/// - void on a valid signature
/// - error.ZixUnsupportedSignatureScheme (scheme is not ecdsa_secp256r1_sha256)
/// - error.SignatureVerificationFailed (signature does not verify)
pub fn verifyClientCertificateVerify(certificate_verify_body: []const u8, public_key: EcdsaP256.PublicKey, transcript_hash: Secret) !void {
    var r = Reader{ .buf = certificate_verify_body };
    const scheme = try r.readU16();
    if (scheme != @intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256)) return error.ZixUnsupportedSignatureScheme;

    const sig_len = try r.readU16();
    const sig_bytes = try r.readBytes(sig_len);

    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = clientCertificateVerifyContent(&content_buf, transcript_hash);

    const signature = EcdsaP256.Signature.fromDer(sig_bytes) catch return error.SignatureVerificationFailed;
    signature.verify(content, public_key) catch return error.SignatureVerificationFailed;
}

// --------------------------------------------------------------- //

/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) (RFC 8446 4.4.4).
pub fn finishedKey(traffic_secret: Secret) Secret {
    var out: Secret = undefined;
    key_schedule.expandLabel(&out, traffic_secret, "finished", "");

    return out;
}

/// Finished verify_data = HMAC(finished_key, Transcript-Hash(...)) (RFC 8446 4.4.4).
pub fn finishedVerifyData(finished_key: Secret, transcript_hash: Secret) Secret {
    var out: Secret = undefined;
    HmacSha256.create(&out, &transcript_hash, &finished_key);

    return out;
}

/// Build the Finished message (RFC 8446 4.4.4) into `buf`, returning the wire slice.
pub fn buildFinished(buf: []u8, finished_key: Secret, transcript_hash: Secret) []const u8 {
    const verify_data = finishedVerifyData(finished_key, transcript_hash);

    var w = Writer{ .buf = buf };
    w.writeU8(@intFromEnum(handshake.HandshakeType.FINISHED));
    const header = w.placeU24();
    w.writeBytes(&verify_data);
    w.patchU24(header);

    return w.slice();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// An all-zero salt, used by the ECDSA / Ed25519 tests where pss_salt is ignored.
const zero_salt = std.mem.zeroes([rsa.pss_salt_len]u8);

/// A deterministic RSA-2048 PKCS#8 key (openssl genpkey), for the RSA CertificateVerify test.
const rsa_fixture_pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDiK/ullhGBT/Mj
    \\s1cQ3b7xqIAtHwMjuTxnUne42qU3cUrEeH2/jWjXjEeBMBqt8TYp1FVpDg+u2DGU
    \\Jada+rtFsPVZkD/07HUGXYfya6hwdwOqwjm+fdI+jIIpM+N1t6Ln+eV75GIu8KEr
    \\uRQVTsR3Rz8uMcIN/apvXP1Tus2Y2ZIhAKX9vk2DvL6+7gCLzK0wJmdQ34aGEw89
    \\MRfQLVmTpFvZSJ2B81dxY+IdgbshiZbbn76pzdH4TvxIOwDpUxW16qY7VXZErMtR
    \\S9jnavMpIB1sTkZLKZyIkowWqeeVWIQG85RreOwiEYywRUYnhI44YBxf0Xmgr1x6
    \\CnJ3atxDAgMBAAECggEACaafz9KF/7MWKG1UJ0OXDL/IbGR44VLbqXsC4c/uod2D
    \\N7v+fah+k0gImxIe6VI0IffOBzQS5j6SawRqTj8Js7EX3xEBMaXPXoyqKuV+JAJo
    \\FSbBiQfca0/alACDUbgayvRGXxGBQQiCkBePLFOWnZJcN0/nPGqZFbRtmN+NO1rk
    \\zTD46uKfBAFMKZLbWrK8plECMfea5h+/ysnfhpZXv5nAXuPY6cvwgDTZvphQdB4l
    \\4mjAtuI6oEYUL4CVga1NE57vC02RxJBwylmxznJyJcRdLl52kSgOMU3xV9isrrZT
    \\88s9Ds5ZxtGqaWUmbF+pHW1wxzTmJhrCXxEGtsrmAQKBgQD5u1KiuTlPnnVgIRfT
    \\thzF5pBp6Ynwbw/Q0SMkF/E7yxkPDdLWMY43WIikRj9IyfDnIRxdGEBkprF7/Sm/
    \\ehGVGRDNNT3eRaZ04jLP/EbksO9hF49ro/FlHSaaVrDSAsW3F8HBp8NQC9Sgpdlf
    \\XwnxZsP35wpISF1hWV5be0yWAQKBgQDn2UYCjGCRFdBNdsqxbgGemPBu60/U0leE
    \\T8xg42jN6tO2j0vesKp83NFcAl71NYh7rl8G+WnFJ3DgrjrFAPbTa6VJdnNnpjV+
    \\3o2CSqSTAReFM2khRIZodCbQ3Ad/6P00RnahpciBemQsQKeyGRMrhrkBZbiPIWch
    \\LgBIniOaQwKBgGcmxsVL+K44Z4cjZDIgoNXlnHUC7+UOGtxH5ln8QbpO87TSIuoy
    \\YeneeeJQ2cb5EraFaK/TWpW4fMsYEOx0QVrylYwNl9Z9snnJDO/35liD9PyHvMfb
    \\WdRILC/H6xVz67Lq7y9MWlJv8I3Cs3y/Rt4dcoitOAQPT/Lr9RuYXFQBAoGBAM0U
    \\QXsrlJeBRhnfQ/eiKMiS28ohVyIXVNZyh4QEY8YRO2g2ZJP8jTGZWY8bgcdArRNJ
    \\8ECJCegctRnow49TBQGKLFBI+Ffsi1FHpsBjKiPmSVnHWezVYlaut07z8aZQ/vfo
    \\hDMEI9Fz43vJTQyaZXyQ1MDJq3DfyQtuV03ko/VlAoGBAJiRuT9T8EQO0gJoaS6g
    \\W/+g7A+JUZnqIrCiL9JAaWzOy4TdKtEgbDQsLH1NfVclcnti5C/6wlCqvPcSQtF/
    \\ZGgEuI4ajyq60Un5tOiB1rbJ5sahSLgpM21Ph6kkC6nxTuKfRPpu1+L92SFZBFrX
    \\sIWllpzoV5pFqYoMGir8MZfp
    \\-----END PRIVATE KEY-----
;

test "zix tls: certificate, a chain is presented end-entity first then intermediates (4.4.2)" {
    const end_entity = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
    const intermediate = [_]u8{ 0x30, 0x02, 0x0a, 0x0b };

    var buf: [64]u8 = undefined;
    const msg = buildCertificate(&buf, &.{ &end_entity, &intermediate });

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 11), try r.readU8());
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u8, 0), try r.readU8());
    const list_len = try r.readU24();

    const first_len = try r.readU24();
    try std.testing.expectEqualSlices(u8, &end_entity, try r.readBytes(first_len));
    try std.testing.expectEqual(@as(u16, 0), try r.readU16());

    const second_len = try r.readU24();
    try std.testing.expectEqualSlices(u8, &intermediate, try r.readBytes(second_len));
    try std.testing.expectEqual(@as(u16, 0), try r.readU16());

    // The list length counts both entries and both empty extension blocks: 3 + 5 + 2 + 3 + 4 + 2.
    try std.testing.expectEqual(@as(usize, 19), list_len);
}

test "zix tls: certificate, Certificate message wraps the DER (4.4.2)" {
    const der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

    var buf: [64]u8 = undefined;
    const msg = buildCertificate(&buf, &.{&der});

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 11), try r.readU8());
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u8, 0), try r.readU8());
    const list_len = try r.readU24();
    try std.testing.expect(list_len > 0);
    const entry_len = try r.readU24();
    try std.testing.expectEqualSlices(u8, &der, try r.readBytes(entry_len));
    try std.testing.expectEqual(@as(u16, 0), try r.readU16());
}

test "zix tls: certificate, CertificateVerify content + ECDSA P-256 sign/verify (4.4.3)" {
    var transcript: Secret = undefined;
    _ = try std.fmt.hexToBytes(&transcript, "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed");

    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript);
    for (content[0..64]) |b| try std.testing.expectEqual(@as(u8, 0x20), b);
    try std.testing.expectEqualStrings(certificate_verify_context, content[64 .. 64 + certificate_verify_context.len]);
    try std.testing.expectEqual(@as(u8, 0), content[64 + certificate_verify_context.len]);

    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    var msg_buf: [256]u8 = undefined;
    const msg = try buildCertificateVerify(&msg_buf, .{ .ecdsa_p256 = key_pair }, transcript, zero_salt);

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 15), try r.readU8());
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u16, 0x0403), try r.readU16());
    const sig_len = try r.readU16();
    const signature = try EcdsaP256.Signature.fromDer(try r.readBytes(sig_len));
    try signature.verify(content, key_pair.public_key);

    var bad = transcript;
    bad[0] ^= 0x01;
    var bad_buf: [certificate_verify_content_len]u8 = undefined;
    const bad_content = certificateVerifyContent(&bad_buf, bad);
    const tamper_rejected = if (signature.verify(bad_content, key_pair.public_key)) false else |_| true;
    try std.testing.expect(tamper_rejected);
}

test "zix tls: certificate, CertificateVerify with an Ed25519 key emits scheme 0x0807 (4.4.3)" {
    var transcript: Secret = undefined;
    _ = try std.fmt.hexToBytes(&transcript, "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed");

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    const signing_key: SigningKey = .{ .ed25519 = key_pair };
    try std.testing.expectEqual(handshake.SignatureScheme.ED25519, signing_key.scheme());

    var msg_buf: [256]u8 = undefined;
    const msg = try buildCertificateVerify(&msg_buf, signing_key, transcript, zero_salt);

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 15), try r.readU8());
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u16, 0x0807), try r.readU16()); // ed25519

    const sig_len = try r.readU16();
    const signature = Ed25519.Signature.fromBytes((try r.readBytes(sig_len))[0..64].*);

    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript);
    try signature.verify(content, key_pair.public_key);
}

test "zix tls: certificate, CertificateVerify with an RSA key emits scheme 0x0804 + PSS verifies (4.4.3)" {
    const pem = @import("pem.zig");
    const StdRsa = std.crypto.Certificate.rsa;
    const std_rsa_verify = @import("std_rsa_verify.zig");

    var transcript: Secret = undefined;
    @memset(&transcript, 0x33);

    var der_buf: [4096]u8 = undefined;
    const der = try pem.pemToDer(&der_buf, rsa_fixture_pkcs8_pem);
    const key = try rsa.PrivateKey.fromDer(der, true);

    const signing_key: SigningKey = .{ .rsa = key };
    try std.testing.expectEqual(handshake.SignatureScheme.RSA_PSS_RSAE_SHA256, signing_key.scheme());

    var salt: [rsa.pss_salt_len]u8 = undefined;
    @memset(&salt, 0x5a);

    var msg_buf: [512]u8 = undefined;
    const msg = try buildCertificateVerify(&msg_buf, signing_key, transcript, salt);

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 15), try r.readU8());
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u16, 0x0804), try r.readU16()); // rsa_pss_rsae_sha256

    const sig_len = try r.readU16();
    const signature = try r.readBytes(sig_len);
    try std.testing.expectEqual(@as(usize, 256), sig_len);

    // the PSS signature must verify over the signed content through std's RSA verify.
    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript);

    var n_bytes: [256]u8 = undefined;
    @memcpy(&n_bytes, key.modulus());
    const e_bytes = [_]u8{ 0x01, 0x00, 0x01 };
    const public_key = try StdRsa.PublicKey.fromBytes(&e_bytes, &n_bytes);
    // Temporary, zig 0.17 only: std's PSS verifier panics, see std_rsa_verify.zig.
    if (!std_rsa_verify.PSS_USABLE) {
        std.log.info("zix tls: certificate, std PSS verify is broken on this zig, cross-check skipped", .{});

        return;
    }

    try std_rsa_verify.verifyPss(256, signature[0..256], content, public_key, std.crypto.hash.sha2.Sha256);
}

test "zix tls: certificate, Finished verify_data byte-exact vs RFC 8448 (4.4.4)" {
    var server_hs_traffic: Secret = undefined;
    _ = try std.fmt.hexToBytes(&server_hs_traffic, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    var transcript: Secret = undefined;
    _ = try std.fmt.hexToBytes(&transcript, "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed");

    const fk = finishedKey(server_hs_traffic);
    var expected_fk: Secret = undefined;
    _ = try std.fmt.hexToBytes(&expected_fk, "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");
    try std.testing.expectEqualSlices(u8, &expected_fk, &fk);

    const verify_data = finishedVerifyData(fk, transcript);
    var expected_vd: Secret = undefined;
    _ = try std.fmt.hexToBytes(&expected_vd, "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
    try std.testing.expectEqualSlices(u8, &expected_vd, &verify_data);

    var bad = transcript;
    bad[0] ^= 0x01;
    try std.testing.expect(!std.mem.eql(u8, &finishedVerifyData(fk, bad), &expected_vd));

    var fin_buf: [64]u8 = undefined;
    const fin = buildFinished(&fin_buf, fk, transcript);
    try std.testing.expectEqual(@as(u8, 20), fin[0]);
    try std.testing.expectEqualSlices(u8, &expected_vd, fin[4..]);
}

test "zix tls: certificate, CertificateRequest carries signature_algorithms (4.3.2)" {
    var buf: [64]u8 = undefined;
    const msg = buildCertificateRequest(&buf);

    var r = Reader{ .buf = msg };
    try std.testing.expectEqual(@as(u8, 13), try r.readU8()); // CERTIFICATE_REQUEST
    _ = try r.readU24();
    try std.testing.expectEqual(@as(u8, 0), try r.readU8()); // empty request context
    _ = try r.readU16(); // extensions length
    try std.testing.expectEqual(@as(u16, 0x000d), try r.readU16()); // signature_algorithms
    _ = try r.readU16(); // extension body length
    const list_len = try r.readU16();
    try std.testing.expectEqual(@as(u16, 4), list_len); // two u16 schemes
    try std.testing.expectEqual(@as(u16, 0x0403), try r.readU16()); // ecdsa_secp256r1_sha256
    try std.testing.expectEqual(@as(u16, 0x0807), try r.readU16()); // ed25519
}

test "zix tls: certificate, parseEndEntityCertificate recovers the DER + empty list is null" {
    const der = [_]u8{ 0x30, 0x05, 0x01, 0x02, 0x03, 0x04 };

    var buf: [64]u8 = undefined;
    const msg = buildCertificate(&buf, &.{&der});

    const recovered = try parseEndEntityCertificate(msg[4..]); // strip the 4-octet handshake header
    try std.testing.expectEqualSlices(u8, &der, recovered.?);

    // an empty certificate_list (context byte 0, list length 0) means the client declined auth.
    const empty_body = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(?[]const u8, null), try parseEndEntityCertificate(&empty_body));
}

test "zix tls: certificate, client CertificateVerify sign + verify + tamper reject (4.4.3)" {
    var transcript: Secret = undefined;
    _ = try std.fmt.hexToBytes(&transcript, "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed");

    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    // the client signs its content, then we verify it through the message-level verifier.
    var content_buf: [certificate_verify_content_len]u8 = undefined;
    const content = clientCertificateVerifyContent(&content_buf, transcript);
    const signature = try key_pair.sign(content, null);

    var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der = signature.toDer(&der_buf);

    var msg_buf: [256]u8 = undefined;
    var w = Writer{ .buf = &msg_buf };
    w.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    const sig = w.placeU16();
    w.writeBytes(der);
    w.patchU16(sig);

    try verifyClientCertificateVerify(w.slice(), key_pair.public_key, transcript);

    var wrong = transcript;
    wrong[0] ^= 0x01;
    try std.testing.expectError(error.SignatureVerificationFailed, verifyClientCertificateVerify(w.slice(), key_pair.public_key, wrong));
}
