//! TLS 1.3 record protection (RFC 8446 section 5).
//!
//! Note:
//! - AEAD protect / deprotect over the TLS 1.3 record framing: outer opaque_type
//!   application_data(23), legacy_record_version 0x0303, the per-record nonce (static iv XOR the
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

pub const key_length = 16;
pub const iv_length = 12;
pub const tag_length = Aes128Gcm.tag_length;

/// TLSPlaintext.length ceiling, 2^14 (RFC 8446 5.1).
pub const max_plaintext = 1 << 14;

/// TLSCiphertext.length ceiling, 2^14 + 256, over which is record_overflow (RFC 8446 5.2).
pub const max_ciphertext = max_plaintext + 256;

/// Read staging for one on-wire TLS record: the record header plus the max
/// TLSCiphertext payload, rounded up so any single record fits in one buffer.
pub const max_record_wire = 17 * 1024;

const legacy_record_version: u16 = 0x0303;

/// Record content type (RFC 8446 5.1). The outer type on the wire for protected records is
/// always application_data(23), the real type travels as the inner content type.
pub const ContentType = enum(u8) {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    _,
};

pub const Error = error{ ZixRecordOverflow, ZixBadRecordMac, ZixDecode };

/// The opened inner of a protected record: the true content type and the data.
pub const Opened = struct {
    inner_type: ContentType,
    data: []const u8,
};

// --------------------------------------------------------------- //

/// Per-record nonce: the static iv XOR the 64-bit sequence number, right-aligned (RFC 8446 5.3).
pub fn nonce(iv: [iv_length]u8, sequence: u64) [iv_length]u8 {
    var out = iv;
    var sequence_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_bytes, sequence, .big);

    var i: usize = 0;
    while (i < 8) : (i += 1) out[iv_length - 8 + i] ^= sequence_bytes[i];

    return out;
}

/// Wire bytes one record costs beyond its plaintext: the 5-byte header, the inner content type,
/// and the AEAD tag.
pub const record_overhead = 5 + 1 + tag_length;

/// Wire bytes needed to seal plaintext_len bytes, counting every record it takes.
///
/// Note:
/// - An empty plaintext is still one record, since the inner content type has to travel.
///
/// Return:
/// - usize (total sealed length, what an output buffer must hold)
pub fn sealedLen(plaintext_len: usize) usize {
    const records = if (plaintext_len == 0) 1 else (plaintext_len + max_plaintext - 1) / max_plaintext;

    return plaintext_len + records * record_overhead;
}

/// Protect a plaintext into a TLS 1.3 record: AEAD-seal (plaintext || inner content type) under
/// the key, write the header + ciphertext + tag into `out`, and return the full record slice.
///
/// Note:
/// - ONE record, so plaintext must be at most max_plaintext. Splitting a longer payload belongs to
///   the caller, which is what tls_session.Session.encrypt does. A payload that does not fit, or an
///   `out` too small to hold the record, returns empty rather than writing anything: the AEAD seal
///   is fed from a fixed record-sized buffer, so an unchecked length here would be a stack overflow
///   rather than a bad record.
///
/// Param:
/// out - []u8 (must hold sealedLen(plaintext.len) bytes)
/// plaintext - the application or handshake bytes to protect, at most max_plaintext
/// inner_type - the true content type (travels inside the AEAD)
/// key - the AES-128-GCM key
/// iv - the static iv
/// sequence - the record sequence number for this key
///
/// Return:
/// - []const u8 (the wire record)
/// - empty when plaintext exceeds max_plaintext or out cannot hold the record
pub fn protect(out: []u8, plaintext: []const u8, inner_type: ContentType, key: [key_length]u8, iv: [iv_length]u8, sequence: u64) []const u8 {
    if (plaintext.len > max_plaintext) return out[0..0];

    const inner_length = plaintext.len + 1;
    const record_length = inner_length + tag_length;
    if (out.len < 5 + record_length) return out[0..0];

    out[0] = @intFromEnum(ContentType.APPLICATION_DATA);
    std.mem.writeInt(u16, out[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(record_length), .big);

    var inner: [max_plaintext + 1]u8 = undefined;
    @memcpy(inner[0..plaintext.len], plaintext);
    inner[plaintext.len] = @intFromEnum(inner_type);

    var tag: [tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[5 .. 5 + inner_length], &tag, inner[0..inner_length], out[0..5], nonce(iv, sequence), key);
    @memcpy(out[5 + inner_length .. 5 + inner_length + tag_length], &tag);

    return out[0 .. 5 + record_length];
}

/// Protect two plaintext slices as one TLS 1.3 record: AEAD-seal (a || b || inner content type). This
/// is the gather form of `protect`: it avoids the caller concatenating `a` and `b` into one buffer
/// first (the send path stages only a small frame-header prefix in `a` and passes the large payload as
/// `b` straight from source). Byte-identical to `protect` on the concatenation.
///
/// Note:
/// - ONE record, exactly like protect, so a.len + b.len must be at most max_plaintext. Callers stage
///   a record-sized buffer and gather the remainder, so the sum is bounded by construction. It is
///   still checked here, because the AEAD seal is fed from a fixed record-sized buffer.
///
/// Param:
/// out - []u8 (must hold sealedLen(a.len + b.len) bytes)
/// a - the first plaintext slice (e.g. a staged frame-header prefix)
/// b - the second plaintext slice (e.g. the source payload)
/// inner_type - the true content type (travels inside the AEAD)
/// key - the AES-128-GCM key
/// iv - the static iv
/// sequence - the record sequence number for this key
///
/// Return:
/// - []const u8 (the wire record)
/// - empty when a.len + b.len exceeds max_plaintext or out cannot hold the record
pub fn protect2(out: []u8, a: []const u8, b: []const u8, inner_type: ContentType, key: [key_length]u8, iv: [iv_length]u8, sequence: u64) []const u8 {
    const plaintext_len = a.len + b.len;
    if (plaintext_len > max_plaintext) return out[0..0];

    const inner_length = plaintext_len + 1;
    const record_length = inner_length + tag_length;
    if (out.len < 5 + record_length) return out[0..0];

    out[0] = @intFromEnum(ContentType.APPLICATION_DATA);
    std.mem.writeInt(u16, out[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(record_length), .big);

    var inner: [max_plaintext + 1]u8 = undefined;
    @memcpy(inner[0..a.len], a);
    @memcpy(inner[a.len..][0..b.len], b);
    inner[plaintext_len] = @intFromEnum(inner_type);

    var tag: [tag_length]u8 = undefined;
    Aes128Gcm.encrypt(out[5 .. 5 + inner_length], &tag, inner[0..inner_length], out[0..5], nonce(iv, sequence), key);
    @memcpy(out[5 + inner_length .. 5 + inner_length + tag_length], &tag);

    return out[0 .. 5 + record_length];
}

/// Deprotect a wire record: AEAD-open into `out`, strip the zero padding and inner content type,
/// and return the true type + data. record_overflow and bad_record_mac per RFC 8446 5.2.
///
/// Return:
/// - Opened
/// - error.ZixRecordOverflow if the ciphertext exceeds 2^14 + 256
/// - error.ZixBadRecordMac if the AEAD tag does not verify
/// - error.ZixDecode if the record is truncated or all-zero (no content type)
pub fn deprotect(out: []u8, record: []const u8, key: [key_length]u8, iv: [iv_length]u8, sequence: u64) Error!Opened {
    if (record.len < 5 + tag_length) return error.ZixDecode;

    const header = record[0..5];
    const body = record[5..];
    if (body.len > max_ciphertext) return error.ZixRecordOverflow;

    const ciphertext = body[0 .. body.len - tag_length];
    var tag: [tag_length]u8 = undefined;
    @memcpy(&tag, body[body.len - tag_length ..]);

    const plaintext = out[0..ciphertext.len];
    Aes128Gcm.decrypt(plaintext, ciphertext, tag, header, nonce(iv, sequence), key) catch return error.ZixBadRecordMac;

    var end = plaintext.len;
    while (end > 0 and plaintext[end - 1] == 0) end -= 1;
    if (end == 0) return error.ZixDecode;

    return .{ .inner_type = @enumFromInt(plaintext[end - 1]), .data = plaintext[0 .. end - 1] };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: record sealedLen counts every record a plaintext takes" {
    // An empty payload is still one record: the inner content type has to travel.
    try std.testing.expectEqual(record_overhead, sealedLen(0));
    try std.testing.expectEqual(1 + record_overhead, sealedLen(1));

    // Exactly one record's worth stays one record, one byte more needs two.
    try std.testing.expectEqual(max_plaintext + record_overhead, sealedLen(max_plaintext));
    try std.testing.expectEqual(max_plaintext + 1 + 2 * record_overhead, sealedLen(max_plaintext + 1));

    // A 64 KiB response is four records, which is what the engines size their staging for.
    try std.testing.expectEqual(65536 + 4 * record_overhead, sealedLen(65536));
}

test "zix tls: record protect refuses a plaintext larger than one record" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    const oversized = try std.testing.allocator.alloc(u8, max_plaintext + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'x');

    const out = try std.testing.allocator.alloc(u8, sealedLen(max_plaintext + 1));
    defer std.testing.allocator.free(out);

    // The seal is fed from a fixed record-sized buffer, so an unchecked length here would smash the
    // stack rather than produce a bad record. Refusing is the only safe answer.
    try std.testing.expectEqual(@as(usize, 0), protect(out, oversized, .APPLICATION_DATA, key, iv, 0).len);

    // One byte under the ceiling is still a real record.
    const at_ceiling = protect(out, oversized[0..max_plaintext], .APPLICATION_DATA, key, iv, 0);
    try std.testing.expectEqual(sealedLen(max_plaintext), at_ceiling.len);
}

test "zix tls: record protect refuses an output buffer too small for the record" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    const message = "needs room for header and tag";

    // One byte short of what the record costs.
    var tight: [sealedLen("needs room for header and tag".len) - 1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), protect(&tight, message, .APPLICATION_DATA, key, iv, 0).len);

    var exact: [sealedLen("needs room for header and tag".len)]u8 = undefined;
    try std.testing.expectEqual(exact.len, protect(&exact, message, .APPLICATION_DATA, key, iv, 0).len);
}

test "zix tls: record protect2 refuses a gather larger than one record" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    const tail = try std.testing.allocator.alloc(u8, max_plaintext);
    defer std.testing.allocator.free(tail);
    @memset(tail, 'y');

    const out = try std.testing.allocator.alloc(u8, sealedLen(max_plaintext + 8));
    defer std.testing.allocator.free(out);

    // The prefix pushes the pair one record over, which the gather form must refuse the same way.
    try std.testing.expectEqual(@as(usize, 0), protect2(out, "prefix", tail, .APPLICATION_DATA, key, iv, 0).len);

    const fits = protect2(out, "prefix", tail[0 .. max_plaintext - "prefix".len], .APPLICATION_DATA, key, iv, 0);
    try std.testing.expectEqual(sealedLen(max_plaintext), fits.len);
}

test "zix tls: record protect/deprotect round trip" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
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

test "zix tls: record protect2 gather equals protect on the concatenation and round-trips" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
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

test "zix tls: record deprotect failures bad tag, wrong seq, overflow" {
    var key: [key_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "3fce516009c21727d0f2e4e86ee403bc");
    var iv: [iv_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "5d313eb2671276ee13000b30");

    var record_buf: [256]u8 = undefined;
    const record = protect(&record_buf, "data", .APPLICATION_DATA, key, iv, 0);

    var plain_buf: [256]u8 = undefined;

    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..record.len], record);
    tampered[record.len - 1] ^= 0x01;
    try std.testing.expectError(error.ZixBadRecordMac, deprotect(&plain_buf, tampered[0..record.len], key, iv, 0));

    try std.testing.expectError(error.ZixBadRecordMac, deprotect(&plain_buf, record, key, iv, 1));

    var oversize: [5 + max_ciphertext + 1]u8 = undefined;
    oversize[0] = 23;
    std.mem.writeInt(u16, oversize[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, oversize[3..5], max_ciphertext + 1, .big);
    try std.testing.expectError(error.ZixRecordOverflow, deprotect(&plain_buf, &oversize, key, iv, 0));
}
