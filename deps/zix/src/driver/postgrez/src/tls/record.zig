//! TLS 1.3 record protection (RFC 8446 section 5).
//!
//! Note:
//! - AEAD protect / deprotect over the TLS 1.3 record framing: outer opaque_type
//!   application_data(23), LEGACY_RECORD_VERSION 0x0303, the per-record nonce (static iv XOR the
//!   sequence number), the inner content type, and zero padding.
//! - AES-128-GCM only (the mandatory-to-implement suite, RFC 8446 9.1). AES-256-GCM and
//!   ChaCha20-Poly1305 are additive later.
//! - Enforces the record-size limit (record_overflow) and maps AEAD open failure to
//!   bad_record_mac (RFC 8446 5.2).
//! - Throughput depends on the BUILD CPU target. std.crypto selects the AES-GCM backend at comptime:
//!   the hardware path needs the `aes` (AES-NI) and `pclmul` (GHASH carry-less multiply) features. A
//!   target without them (`x86_64_v3` does NOT include them, they are separate features) compiles the
//!   software fallback, which is about 40x slower (87 MB/s vs 3742 MB/s on one core). Build with a
//!   target that has them, e.g. `-Dcpu=x86_64_v3+aes+pclmul` or `-Dcpu=native`, for any TLS that
//!   moves real volume (rnd/0.5.x/issue-tls-software-aes.md).

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const KEY_LENGTH = 16;
pub const IV_LENGTH = 12;
pub const TAG_LENGTH = Aes128Gcm.tag_length;

/// TLSPlaintext.length ceiling, 2^14 (RFC 8446 5.1).
pub const MAX_PLAINTEXT = 1 << 14;

/// TLSCiphertext.length ceiling, 2^14 + 256, over which is record_overflow (RFC 8446 5.2).
pub const MAX_CIPHERTEXT = MAX_PLAINTEXT + 256;

/// Read staging for one on-wire TLS record: the record header plus the max
/// TLSCiphertext payload, rounded up so any single record fits in one buffer.
pub const MAX_RECORD_WIRE = 17 * 1024;

const LEGACY_RECORD_VERSION: u16 = 0x0303;

/// Record content type (RFC 8446 5.1). The outer type on the wire for protected records is
/// always application_data(23), the real type travels as the inner content type.
pub const ContentType = enum(u8) {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    _,
};

pub const Error = error{ PostgrezRecordOverflow, PostgrezBadRecordMac, PostgrezDecode };

/// The opened inner of a protected record: the true content type and the data.
pub const Opened = struct {
    inner_type: ContentType,
    data: []const u8,
};

// --------------------------------------------------------------- //

/// Per-record nonce: the static iv XOR the 64-bit sequence number, right-aligned (RFC 8446 5.3).
pub fn nonce(iv: [IV_LENGTH]u8, sequence: u64) [IV_LENGTH]u8 {
    var out = iv;
    var sequence_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_bytes, sequence, .big);

    var i: usize = 0;
    while (i < 8) : (i += 1) out[IV_LENGTH - 8 + i] ^= sequence_bytes[i];

    return out;
}

/// Protect a plaintext into a TLS 1.3 record: AEAD-seal (plaintext || inner content type) under
/// the key, write the header + ciphertext + tag into `out`, and return the full record slice.
///
/// Param:
/// out - []u8 (must hold 5 + plaintext.len + 1 + TAG_LENGTH bytes)
/// plaintext - the application or handshake bytes to protect
/// inner_type - the true content type (travels inside the AEAD)
/// key - the AES-128-GCM key
/// iv - the static iv
/// sequence - the record sequence number for this key
///
/// Return:
/// - []const u8 (the wire record)
pub fn protect(out: []u8, plaintext: []const u8, inner_type: ContentType, key: [KEY_LENGTH]u8, iv: [IV_LENGTH]u8, sequence: u64) []const u8 {
    const inner_length = plaintext.len + 1;
    const record_length = inner_length + TAG_LENGTH;

    out[0] = @intFromEnum(ContentType.APPLICATION_DATA);
    std.mem.writeInt(u16, out[1..3], LEGACY_RECORD_VERSION, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(record_length), .big);

    var inner: [MAX_PLAINTEXT + 1]u8 = undefined;
    @memcpy(inner[0..plaintext.len], plaintext);
    inner[plaintext.len] = @intFromEnum(inner_type);

    var tag: [TAG_LENGTH]u8 = undefined;
    Aes128Gcm.encrypt(out[5 .. 5 + inner_length], &tag, inner[0..inner_length], out[0..5], nonce(iv, sequence), key);
    @memcpy(out[5 + inner_length .. 5 + inner_length + TAG_LENGTH], &tag);

    return out[0 .. 5 + record_length];
}

/// Protect two plaintext slices as one TLS 1.3 record: AEAD-seal (a || b || inner content type). This
/// is the gather form of `protect`: it avoids the caller concatenating `a` and `b` into one buffer
/// first (the send path stages only a small frame-header prefix in `a` and passes the large payload as
/// `b` straight from source). Byte-identical to `protect` on the concatenation.
///
/// Param:
/// out - []u8 (must hold 5 + a.len + b.len + 1 + TAG_LENGTH bytes)
/// a - the first plaintext slice (e.g. a staged frame-header prefix)
/// b - the second plaintext slice (e.g. the source payload)
/// inner_type - the true content type (travels inside the AEAD)
/// key - the AES-128-GCM key
/// iv - the static iv
/// sequence - the record sequence number for this key
///
/// Return:
/// - []const u8 (the wire record)
pub fn protect2(out: []u8, a: []const u8, b: []const u8, inner_type: ContentType, key: [KEY_LENGTH]u8, iv: [IV_LENGTH]u8, sequence: u64) []const u8 {
    const plaintext_len = a.len + b.len;
    const inner_length = plaintext_len + 1;
    const record_length = inner_length + TAG_LENGTH;

    out[0] = @intFromEnum(ContentType.APPLICATION_DATA);
    std.mem.writeInt(u16, out[1..3], LEGACY_RECORD_VERSION, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(record_length), .big);

    var inner: [MAX_PLAINTEXT + 1]u8 = undefined;
    @memcpy(inner[0..a.len], a);
    @memcpy(inner[a.len..][0..b.len], b);
    inner[plaintext_len] = @intFromEnum(inner_type);

    var tag: [TAG_LENGTH]u8 = undefined;
    Aes128Gcm.encrypt(out[5 .. 5 + inner_length], &tag, inner[0..inner_length], out[0..5], nonce(iv, sequence), key);
    @memcpy(out[5 + inner_length .. 5 + inner_length + TAG_LENGTH], &tag);

    return out[0 .. 5 + record_length];
}

/// Deprotect a wire record: AEAD-open into `out`, strip the zero padding and inner content type,
/// and return the true type + data. record_overflow and bad_record_mac per RFC 8446 5.2.
///
/// Return:
/// - Opened
/// - error.PostgrezRecordOverflow if the ciphertext exceeds 2^14 + 256
/// - error.PostgrezBadRecordMac if the AEAD tag does not verify
/// - error.PostgrezDecode if the record is truncated or all-zero (no content type)
pub fn deprotect(out: []u8, record: []const u8, key: [KEY_LENGTH]u8, iv: [IV_LENGTH]u8, sequence: u64) Error!Opened {
    if (record.len < 5 + TAG_LENGTH) return error.PostgrezDecode;

    const header = record[0..5];
    const body = record[5..];
    if (body.len > MAX_CIPHERTEXT) return error.PostgrezRecordOverflow;

    const ciphertext = body[0 .. body.len - TAG_LENGTH];
    var tag: [TAG_LENGTH]u8 = undefined;
    @memcpy(&tag, body[body.len - TAG_LENGTH ..]);

    const plaintext = out[0..ciphertext.len];
    Aes128Gcm.decrypt(plaintext, ciphertext, tag, header, nonce(iv, sequence), key) catch return error.PostgrezBadRecordMac;

    var end = plaintext.len;
    while (end > 0 and plaintext[end - 1] == 0) end -= 1;
    if (end == 0) return error.PostgrezDecode;

    return .{ .inner_type = @enumFromInt(plaintext[end - 1]), .data = plaintext[0 .. end - 1] };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "postgrez tls: record protect/deprotect round trip" {
    var key: [KEY_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [IV_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    const message = "hello over tls 1.3";
    var record_buf: [256]u8 = undefined;
    const record = protect(&record_buf, message, .APPLICATION_DATA, key, iv, 0);
    try std.testing.expectEqual(@as(u8, 23), record[0]);

    var plain_buf: [256]u8 = undefined;
    const opened = try deprotect(&plain_buf, record, key, iv, 0);
    try std.testing.expectEqual(ContentType.APPLICATION_DATA, opened.inner_type);
    try std.testing.expectEqualSlices(u8, message, opened.data);
}

test "postgrez tls: record protect2 gather equals protect on the concatenation and round-trips" {
    var key: [KEY_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [IV_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    // A staged 9-byte frame-header prefix plus a source payload, the shape the send path gathers.
    const prefix = "\x00\x00\x05\x00\x01\x00\x00\x00\x03";
    const payload = "abcde";

    var gathered_buf: [256]u8 = undefined;
    const gathered = protect2(&gathered_buf, prefix, payload, .APPLICATION_DATA, key, iv, 7);

    // Reference: protect on the pre-concatenated plaintext at the same sequence.
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..prefix.len], prefix);
    @memcpy(concat[prefix.len..][0..payload.len], payload);
    var ref_buf: [256]u8 = undefined;
    const ref = protect(&ref_buf, concat[0 .. prefix.len + payload.len], .APPLICATION_DATA, key, iv, 7);

    try std.testing.expectEqualSlices(u8, ref, gathered);

    // And the gathered record deprotects back to prefix || payload.
    var plain_buf: [256]u8 = undefined;
    const opened = try deprotect(&plain_buf, gathered, key, iv, 7);
    try std.testing.expectEqual(ContentType.APPLICATION_DATA, opened.inner_type);
    try std.testing.expectEqualSlices(u8, concat[0 .. prefix.len + payload.len], opened.data);
}

test "postgrez tls: record deprotect failures bad tag, wrong seq, overflow" {
    var key: [KEY_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [IV_LENGTH]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    var record_buf: [256]u8 = undefined;
    const record = protect(&record_buf, "data", .APPLICATION_DATA, key, iv, 0);

    var plain_buf: [256]u8 = undefined;

    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..record.len], record);
    tampered[record.len - 1] ^= 0x01;
    try std.testing.expectError(error.PostgrezBadRecordMac, deprotect(&plain_buf, tampered[0..record.len], key, iv, 0));

    try std.testing.expectError(error.PostgrezBadRecordMac, deprotect(&plain_buf, record, key, iv, 1));

    var oversize: [5 + MAX_CIPHERTEXT + 1]u8 = undefined;
    oversize[0] = 23;
    std.mem.writeInt(u16, oversize[1..3], LEGACY_RECORD_VERSION, .big);
    std.mem.writeInt(u16, oversize[3..5], MAX_CIPHERTEXT + 1, .big);
    try std.testing.expectError(error.PostgrezRecordOverflow, deprotect(&plain_buf, &oversize, key, iv, 0));
}
