//! TLS 1.2 record layer for the AES-128-GCM suites (RFC 5246 6.2 + RFC 5288). Distinct from the 1.3
//! record.zig: the nonce is a 4-byte salt (implicit write_IV) ++ an 8-byte explicit nonce sent on
//! the wire, the AAD is 13 bytes (seq ++ type ++ version ++ plaintext_len), and the record body is
//! explicit_nonce ++ ciphertext ++ tag. zix uses the 64-bit sequence number as the explicit nonce.

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const salt_len: usize = 4;
pub const explicit_nonce_len: usize = 8;
pub const tag_len: usize = Aes128Gcm.tag_length;
const aad_len: usize = 13;
const version_tls_1_2: u16 = 0x0303;

pub const Error = error{ ZixBadRecord, ZixAuthenticationFailed };

/// 13-byte TLS 1.2 AEAD additional data (RFC 5246 6.2.3.3): seq ++ type ++ version ++ length, big-endian.
fn buildAad(seq: u64, content_type: u8, plaintext_len: u16) [aad_len]u8 {
    var aad: [aad_len]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], seq, .big);
    aad[8] = content_type;
    std.mem.writeInt(u16, aad[9..11], version_tls_1_2, .big);
    std.mem.writeInt(u16, aad[11..13], plaintext_len, .big);

    return aad;
}

/// Encrypt one record. The explicit nonce is the sequence number (big-endian). Wire layout:
/// type ++ 0x0303 ++ length ++ [explicit_nonce ++ ciphertext ++ tag], length = 8 + ct + 16.
pub fn protect(out: []u8, plaintext: []const u8, content_type: u8, key: [16]u8, salt: [salt_len]u8, seq: u64) []const u8 {
    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..salt_len], &salt);
    std.mem.writeInt(u64, nonce[salt_len..][0..explicit_nonce_len], seq, .big);

    const aad = buildAad(seq, content_type, @intCast(plaintext.len));
    const body_len = explicit_nonce_len + plaintext.len + tag_len;

    out[0] = content_type;
    std.mem.writeInt(u16, out[1..3], version_tls_1_2, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(body_len), .big);
    @memcpy(out[5 .. 5 + explicit_nonce_len], nonce[salt_len..]);

    const ct = out[5 + explicit_nonce_len .. 5 + explicit_nonce_len + plaintext.len];
    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(ct, &tag, plaintext, &aad, nonce, key);
    @memcpy(out[5 + explicit_nonce_len + plaintext.len ..][0..tag_len], &tag);

    return out[0 .. 5 + body_len];
}

/// Decrypt one record into `out`, verifying the tag. `seq` is the expected receive sequence.
///
/// Return:
/// - the plaintext slice
/// - error.ZixBadRecord if the body is too short, error.ZixAuthenticationFailed if the tag is wrong
pub fn deprotect(out: []u8, record: []const u8, key: [16]u8, salt: [salt_len]u8, seq: u64) Error![]const u8 {
    const content_type = record[0];
    const body = record[5..];
    if (body.len < explicit_nonce_len + tag_len) return error.ZixBadRecord;

    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..salt_len], &salt);
    @memcpy(nonce[salt_len..], body[0..explicit_nonce_len]);

    const ct = body[explicit_nonce_len .. body.len - tag_len];
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, body[body.len - tag_len ..]);

    const aad = buildAad(seq, content_type, @intCast(ct.len));
    Aes128Gcm.decrypt(out[0..ct.len], ct, tag, &aad, nonce, key) catch return error.ZixAuthenticationFailed;

    return out[0..ct.len];
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: tls12 record, AAD byte layout (RFC 5246 6.2.3.3)" {
    const aad = buildAad(0x0102030405060708, 23, 0x0014);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 23, 0x03, 0x03, 0x00, 0x14 }, &aad);
}

test "zix tls: tls12 record, protect -> deprotect round trip + layout" {
    const key: [16]u8 = @splat(0xAB);
    const salt = [salt_len]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const plaintext = "hello tls 1.2 record";

    var rec_buf: [256]u8 = undefined;
    const rec = protect(&rec_buf, plaintext, 23, key, salt, 7);
    try std.testing.expectEqual(@as(u8, 23), rec[0]);
    try std.testing.expectEqual(@as(u64, 7), std.mem.readInt(u64, rec[5..13], .big));

    var plain_buf: [256]u8 = undefined;
    const opened = try deprotect(&plain_buf, rec, key, salt, 7);
    try std.testing.expectEqualSlices(u8, plaintext, opened);
}

test "zix tls: tls12 record, tampered tag fails auth" {
    const key: [16]u8 = @splat(0x11);
    const salt = [salt_len]u8{ 1, 2, 3, 4 };

    var rec_buf: [128]u8 = undefined;
    const rec = protect(&rec_buf, "abc", 23, key, salt, 0);
    rec_buf[rec.len - 1] ^= 0x01;

    var plain_buf: [128]u8 = undefined;
    try std.testing.expectError(error.ZixAuthenticationFailed, deprotect(&plain_buf, rec, key, salt, 0));
}

test "zix tls: tls12 record, AEAD matches NIST AES-128-GCM test case 4" {
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "feffe9928665731c6d6a8f9467308308");
    var nonce: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, "cafebabefacedbaddecaf888");
    var aad: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&aad, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
    var plaintext: [60]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    var expected_ct: [60]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_ct, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
    var expected_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, "5bc94fbc3221a5db94fae95ae7121a47");

    var ct: [60]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, &plaintext, &aad, nonce, key);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
}
