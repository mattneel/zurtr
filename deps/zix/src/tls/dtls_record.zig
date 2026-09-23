//! DTLS 1.2 record layer (RFC 6347 4.1) for the AES-128-GCM suites.
//!
//! What:
//! - The datagram counterpart of tls12_record.zig. Same AEAD, same 13-byte AAD shape, but the
//!   header carries what UDP cannot imply: a 2-byte epoch and a 6-byte sequence number, sent on
//!   the wire because a receiver has no ordered stream to count along with.
//! - Holds the anti-replay window as well (RFC 6347 4.1.2.6). It belongs here because it is
//!   driven entirely by the sequence number this file already reads.
//!
//! Note:
//! - The record header is 13 bytes against TLS 1.2's 5: type, version, epoch, sequence_number,
//!   length. The AAD keeps the TLS 1.2 layout, with epoch and sequence number packed into the
//!   64-bit slot the TLS sequence number occupies (RFC 6347 4.1.2.1).
//! - The wire version counts DOWN as the real version goes up: DTLS 1.2 is 0xFEFD, DTLS 1.0 is
//!   0xFEFF. Both are 1's complements, chosen so DTLS and TLS records cannot be confused.
//! - Sequence numbers restart at 0 for every epoch, so a replay window belongs to one epoch and
//!   the caller keeps one per epoch it accepts traffic on.
//! - An invalid record is discarded, never fatal (RFC 6347 4.1.2.7). Over UDP anyone can forge a
//!   datagram, so tearing down an association on a bad tag hands an attacker a way to kill it.
//! - ContentType comes from record.zig because the numbers are the shared TLS registry, not
//!   anything 1.3 invented. Defining a third copy would be the only alternative.

const std = @import("std");

const record = @import("record.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const ContentType = record.ContentType;

/// DTLS 1.2 on the wire, the 1's complement of 1.2 (RFC 6347 4.1).
pub const VERSION_DTLS_1_2: u16 = 0xFEFD;

/// DTLS 1.0 on the wire. A server sends this version in HelloVerifyRequest regardless of what it
/// will negotiate (RFC 6347 4.2.1), so a receiver must accept it.
pub const VERSION_DTLS_1_0: u16 = 0xFEFF;

/// Bytes before the fragment: type 1, version 2, epoch 2, sequence_number 6, length 2.
pub const HEADER_LEN: usize = 13;

/// Implicit part of the GCM nonce, the write_IV from the key block (RFC 5288).
pub const SALT_LEN: usize = 4;

/// Explicit nonce carried in each record body, ahead of the ciphertext.
pub const EXPLICIT_NONCE_LEN: usize = 8;

pub const TAG_LEN: usize = Aes128Gcm.tag_length;

/// Plaintext ceiling, 2^14 (RFC 6347 4.1, inherited from TLS 1.2).
pub const MAX_PLAINTEXT: usize = 1 << 14;

/// Records this file can protect or open, body included. One record must fit one datagram
/// (RFC 6347 4.1.1), so this is a ceiling and not a target.
pub const MAX_RECORD_WIRE: usize = HEADER_LEN + EXPLICIT_NONCE_LEN + MAX_PLAINTEXT + TAG_LEN;

/// Sliding window width in records. RFC 6347 4.1.2.6 requires at least 32 and prefers 64.
pub const REPLAY_WINDOW_BITS: u48 = 64;

const AAD_LEN: usize = 13;

pub const Error = error{
    /// Fewer bytes than the header, or a length field reaching past the datagram.
    ZixTruncated,
    /// A body too short to hold an explicit nonce and a tag, or a plaintext over the ceiling.
    ZixBadRecord,
    /// The AEAD tag did not verify. Discard the record and keep the association.
    ZixAuthenticationFailed,
};

/// One DTLS record header (RFC 6347 4.1).
pub const Header = struct {
    content_type: ContentType,
    version: u16,
    epoch: u16,
    sequence_number: u48,
    /// Length of the fragment that follows, header excluded.
    length: u16,
};

/// A record opened out of a datagram: its header and its plaintext.
pub const Opened = struct {
    header: Header,
    data: []const u8,
};

/// Read a record header. Does not touch the fragment.
///
/// Param:
/// bytes - []const u8 (start of a record, header first)
///
/// Return:
/// - Header
/// - error.ZixTruncated when fewer than HEADER_LEN bytes are present
pub fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < HEADER_LEN) return error.ZixTruncated;

    return .{
        .content_type = @enumFromInt(bytes[0]),
        .version = std.mem.readInt(u16, bytes[1..3], .big),
        .epoch = std.mem.readInt(u16, bytes[3..5], .big),
        .sequence_number = readSequenceNumber(bytes[5..11]),
        .length = std.mem.readInt(u16, bytes[11..13], .big),
    };
}

/// Write a record header into the first HEADER_LEN bytes of out.
pub fn writeHeader(out: []u8, header: Header) void {
    out[0] = @intFromEnum(header.content_type);
    std.mem.writeInt(u16, out[1..3], header.version, .big);
    std.mem.writeInt(u16, out[3..5], header.epoch, .big);
    writeSequenceNumber(out[5..11], header.sequence_number);
    std.mem.writeInt(u16, out[11..13], header.length, .big);
}

/// Walks the records in one datagram. Multiple records may be packed back to back, a record
/// never spans datagrams, and the first byte is always the start of one (RFC 6347 4.1.1).
///
/// Note:
/// - `next` returns the whole record, header included, ready for `deprotect`. It stops at the
///   first malformed length rather than guessing where the next record starts.
pub const RecordIterator = struct {
    datagram: []const u8,
    pos: usize = 0,

    pub fn next(self: *RecordIterator) Error!?[]const u8 {
        if (self.pos == self.datagram.len) return null;

        const header = try parseHeader(self.datagram[self.pos..]);
        const total = HEADER_LEN + header.length;

        if (self.pos + total > self.datagram.len) return error.ZixTruncated;

        const bytes = self.datagram[self.pos..][0..total];
        self.pos += total;

        return bytes;
    }
};

/// Protect one record (RFC 6347 4.1.2, AEAD as in TLS 1.2).
///
/// Note:
/// - The explicit nonce is the epoch and sequence number of this same record, which is what
///   makes the nonce unique for the life of a key without carrying extra state.
///
/// Param:
/// out - []u8 (destination, needs HEADER_LEN + EXPLICIT_NONCE_LEN + plaintext.len + TAG_LEN)
/// plaintext - []const u8 (the fragment to protect)
/// content_type - ContentType
/// epoch - u16 (current cipher state, incremented on every ChangeCipherSpec)
/// sequence_number - u48 (this record's number inside the epoch)
/// key - [16]u8 (write key for this direction)
/// salt - [4]u8 (implicit write_IV for this direction)
///
/// Return:
/// - []const u8 (the record, borrowing out)
/// - error.ZixBadRecord when the plaintext is over MAX_PLAINTEXT
pub fn protect(
    out: []u8,
    plaintext: []const u8,
    content_type: ContentType,
    epoch: u16,
    sequence_number: u48,
    key: [16]u8,
    salt: [SALT_LEN]u8,
) Error![]const u8 {
    if (plaintext.len > MAX_PLAINTEXT) return error.ZixBadRecord;

    const combined = combinedSequence(epoch, sequence_number);
    const body_len = EXPLICIT_NONCE_LEN + plaintext.len + TAG_LEN;

    writeHeader(out, .{
        .content_type = content_type,
        .version = VERSION_DTLS_1_2,
        .epoch = epoch,
        .sequence_number = sequence_number,
        .length = @intCast(body_len),
    });

    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..SALT_LEN], &salt);
    std.mem.writeInt(u64, nonce[SALT_LEN..][0..EXPLICIT_NONCE_LEN], combined, .big);
    @memcpy(out[HEADER_LEN..][0..EXPLICIT_NONCE_LEN], nonce[SALT_LEN..]);

    const aad = buildAad(combined, content_type, @intCast(plaintext.len));
    const ciphertext = out[HEADER_LEN + EXPLICIT_NONCE_LEN ..][0..plaintext.len];
    var tag: [TAG_LEN]u8 = undefined;

    Aes128Gcm.encrypt(ciphertext, &tag, plaintext, &aad, nonce, key);
    @memcpy(out[HEADER_LEN + EXPLICIT_NONCE_LEN + plaintext.len ..][0..TAG_LEN], &tag);

    return out[0 .. HEADER_LEN + body_len];
}

/// Open one protected record.
///
/// Note:
/// - The epoch and sequence number come from the record itself, not from receiver state. That is
///   the whole reason DTLS carries them, and it is what lets a reordered record still verify.
/// - A failure here is not fatal. Discard the record and keep the association (RFC 6347 4.1.2.7).
///
/// Param:
/// out - []u8 (destination for the plaintext, needs the ciphertext length)
/// bytes - []const u8 (one complete record, header included)
/// key - [16]u8 (read key for this direction)
/// salt - [4]u8 (implicit read_IV for this direction)
///
/// Return:
/// - Opened (header plus plaintext borrowing out)
/// - error.ZixTruncated, error.ZixBadRecord, error.ZixAuthenticationFailed
pub fn deprotect(out: []u8, bytes: []const u8, key: [16]u8, salt: [SALT_LEN]u8) Error!Opened {
    const header = try parseHeader(bytes);

    if (bytes.len < HEADER_LEN + header.length) return error.ZixTruncated;

    const body = bytes[HEADER_LEN..][0..header.length];

    if (body.len < EXPLICIT_NONCE_LEN + TAG_LEN) return error.ZixBadRecord;

    const ciphertext = body[EXPLICIT_NONCE_LEN .. body.len - TAG_LEN];

    if (ciphertext.len > MAX_PLAINTEXT) return error.ZixBadRecord;

    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..SALT_LEN], &salt);
    @memcpy(nonce[SALT_LEN..], body[0..EXPLICIT_NONCE_LEN]);

    var tag: [TAG_LEN]u8 = undefined;
    @memcpy(&tag, body[body.len - TAG_LEN ..]);

    const combined = combinedSequence(header.epoch, header.sequence_number);
    const aad = buildAad(combined, header.content_type, @intCast(ciphertext.len));

    Aes128Gcm.decrypt(out[0..ciphertext.len], ciphertext, tag, &aad, nonce, key) catch
        return error.ZixAuthenticationFailed;

    return .{ .header = header, .data = out[0..ciphertext.len] };
}

/// Write an unprotected record (RFC 6347 4.1). Epoch 0 carries the handshake in the clear until
/// ChangeCipherSpec, so every flight before that goes out through here.
///
/// Param:
/// out - []u8 (destination, needs HEADER_LEN + fragment.len)
/// content_type - ContentType
/// epoch - u16
/// sequence_number - u48
/// fragment - []const u8 (the record body, as is)
///
/// Return:
/// - []const u8 (the record, borrowing out)
/// - error.ZixBadRecord when the fragment is over MAX_PLAINTEXT
pub fn writePlaintext(
    out: []u8,
    content_type: ContentType,
    epoch: u16,
    sequence_number: u48,
    fragment: []const u8,
) Error![]const u8 {
    if (fragment.len > MAX_PLAINTEXT) return error.ZixBadRecord;

    writeHeader(out, .{
        .content_type = content_type,
        .version = VERSION_DTLS_1_2,
        .epoch = epoch,
        .sequence_number = sequence_number,
        .length = @intCast(fragment.len),
    });
    @memcpy(out[HEADER_LEN..][0..fragment.len], fragment);

    return out[0 .. HEADER_LEN + fragment.len];
}

/// The body of an unprotected record, bounds-checked against its own length field.
pub fn plaintextFragment(bytes: []const u8) Error![]const u8 {
    const header = try parseHeader(bytes);

    if (bytes.len < HEADER_LEN + header.length) return error.ZixTruncated;

    return bytes[HEADER_LEN..][0..header.length];
}

/// Sliding replay window for one epoch (RFC 6347 4.1.2.6, the RFC 4303 3.4.3 procedure).
///
/// Note:
/// - Two steps on purpose. `isNew` runs before the AEAD, which is what makes a replay cheap to
///   reject, and `accept` runs only after the tag verifies. Accepting on the strength of a
///   sequence number alone would let a forged datagram poison the window and lock out the real
///   record that follows.
/// - Bit 0 of the mask is `highest` itself, so sequence number 0 is accepted exactly once even
///   though the window starts at zero.
pub const AntiReplay = struct {
    /// Highest sequence number that has verified so far, the right edge of the window.
    highest: u48 = 0,
    /// Bit i marks (highest - i) as already seen.
    window: u64 = 0,

    /// Whether a sequence number is worth the cost of opening the record.
    ///
    /// Return:
    /// - true when it is ahead of the window, or inside it and not yet seen
    /// - false when it duplicates a record or falls off the left edge
    pub fn isNew(self: *const AntiReplay, sequence_number: u48) bool {
        if (sequence_number > self.highest) return true;

        const behind = self.highest - sequence_number;

        if (behind >= REPLAY_WINDOW_BITS) return false;

        return (self.window >> @intCast(behind)) & 1 == 0;
    }

    /// Record a sequence number as seen. Call only after the AEAD tag verifies.
    pub fn accept(self: *AntiReplay, sequence_number: u48) void {
        if (sequence_number > self.highest) {
            const advance = sequence_number - self.highest;
            self.window = if (advance >= REPLAY_WINDOW_BITS) 0 else self.window << @intCast(advance);
            self.window |= 1;
            self.highest = sequence_number;

            return;
        }

        const behind = self.highest - sequence_number;

        if (behind < REPLAY_WINDOW_BITS) self.window |= @as(u64, 1) << @intCast(behind);
    }
};

/// The 64-bit value the AAD and the nonce use: epoch in the top 16 bits, sequence number in the
/// low 48, in wire order (RFC 6347 4.1.2.1).
pub fn combinedSequence(epoch: u16, sequence_number: u48) u64 {
    return (@as(u64, epoch) << 48) | @as(u64, sequence_number);
}

/// 13-byte AEAD additional data: seq ++ type ++ version ++ plaintext length (RFC 5246 6.2.3.3
/// with the DTLS sequence and version).
fn buildAad(combined: u64, content_type: ContentType, plaintext_len: u16) [AAD_LEN]u8 {
    var aad: [AAD_LEN]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], combined, .big);
    aad[8] = @intFromEnum(content_type);
    std.mem.writeInt(u16, aad[9..11], VERSION_DTLS_1_2, .big);
    std.mem.writeInt(u16, aad[11..13], plaintext_len, .big);

    return aad;
}

/// Read the 48-bit sequence number, which has no readInt-sized type on the wire.
fn readSequenceNumber(bytes: *const [6]u8) u48 {
    var value: u48 = 0;
    for (bytes) |byte| value = (value << 8) | byte;

    return value;
}

fn writeSequenceNumber(out: *[6]u8, sequence_number: u48) void {
    for (out, 0..) |*byte, i| byte.* = @truncate(sequence_number >> @intCast(8 * (5 - i)));
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_KEY: [16]u8 = @splat(0xAB);
const TEST_SALT: [SALT_LEN]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF };

test "zix dtls: record header, 13 bytes in wire order" {
    var buf: [HEADER_LEN]u8 = undefined;
    writeHeader(&buf, .{
        .content_type = .HANDSHAKE,
        .version = VERSION_DTLS_1_2,
        .epoch = 1,
        .sequence_number = 0x0102030405,
        .length = 0x0010,
    });

    try std.testing.expectEqualSlices(u8, &[_]u8{
        22, // handshake
        0xFE, 0xFD, // dtls 1.2
        0x00, 0x01, // epoch
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // 48-bit sequence number
        0x00, 0x10, // length
    }, &buf);

    const header = try parseHeader(&buf);
    try std.testing.expectEqual(ContentType.HANDSHAKE, header.content_type);
    try std.testing.expectEqual(@as(u16, VERSION_DTLS_1_2), header.version);
    try std.testing.expectEqual(@as(u16, 1), header.epoch);
    try std.testing.expectEqual(@as(u48, 0x0102030405), header.sequence_number);
    try std.testing.expectEqual(@as(u16, 0x0010), header.length);
}

test "zix dtls: record header, the 48-bit sequence number spans its full range" {
    const cases = [_]u48{ 0, 1, 255, 256, 0xFFFFFF, 0xFFFFFFFFFFFF };

    for (cases) |sequence_number| {
        var buf: [HEADER_LEN]u8 = undefined;
        writeHeader(&buf, .{
            .content_type = .APPLICATION_DATA,
            .version = VERSION_DTLS_1_2,
            .epoch = 0xFFFF,
            .sequence_number = sequence_number,
            .length = 0,
        });

        const header = try parseHeader(&buf);
        try std.testing.expectEqual(sequence_number, header.sequence_number);
        try std.testing.expectEqual(@as(u16, 0xFFFF), header.epoch);
    }

    try std.testing.expectError(error.ZixTruncated, parseHeader(&[_]u8{ 22, 0xFE }));
}

test "zix dtls: record aad, epoch and sequence share the tls sequence slot" {
    const aad = buildAad(combinedSequence(1, 0x020304050607), .APPLICATION_DATA, 0x0014);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x01, // epoch in the top 16 bits
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // sequence number in the low 48
        23, // content type
        0xFE, 0xFD, // dtls 1.2, not 0x0303
        0x00, 0x14, // plaintext length
    }, &aad);

    try std.testing.expectEqual(@as(u64, 0x0001020304050607), combinedSequence(1, 0x020304050607));
    try std.testing.expectEqual(@as(u64, 0), combinedSequence(0, 0));
}

test "zix dtls: record protect, round trip carries the header through" {
    const plaintext = "hello dtls 1.2 record";

    var wire: [128]u8 = undefined;
    const bytes = try protect(&wire, plaintext, .APPLICATION_DATA, 1, 42, TEST_KEY, TEST_SALT);

    try std.testing.expectEqual(HEADER_LEN + EXPLICIT_NONCE_LEN + plaintext.len + TAG_LEN, bytes.len);

    // The explicit nonce on the wire is this record's own epoch and sequence number.
    try std.testing.expectEqual(combinedSequence(1, 42), std.mem.readInt(u64, bytes[HEADER_LEN..][0..8], .big));

    var plain: [128]u8 = undefined;
    const opened = try deprotect(&plain, bytes, TEST_KEY, TEST_SALT);

    try std.testing.expectEqualStrings(plaintext, opened.data);
    try std.testing.expectEqual(ContentType.APPLICATION_DATA, opened.header.content_type);
    try std.testing.expectEqual(@as(u16, 1), opened.header.epoch);
    try std.testing.expectEqual(@as(u48, 42), opened.header.sequence_number);
}

test "zix dtls: record protect, an empty fragment is a legal record" {
    var wire: [64]u8 = undefined;
    const bytes = try protect(&wire, "", .CHANGE_CIPHER_SPEC, 0, 0, TEST_KEY, TEST_SALT);

    var plain: [64]u8 = undefined;
    const opened = try deprotect(&plain, bytes, TEST_KEY, TEST_SALT);

    try std.testing.expectEqual(@as(usize, 0), opened.data.len);
    try std.testing.expectEqual(ContentType.CHANGE_CIPHER_SPEC, opened.header.content_type);
}

test "zix dtls: record deprotect, any tampering fails authentication" {
    var wire: [128]u8 = undefined;
    const bytes = try protect(&wire, "payload", .APPLICATION_DATA, 2, 9, TEST_KEY, TEST_SALT);
    const length = bytes.len;

    var plain: [128]u8 = undefined;

    // The epoch and sequence number are authenticated through the AAD, not just carried.
    const authenticated_offsets = [_]usize{ 0, 3, 5, 10, HEADER_LEN, HEADER_LEN + 9 };
    for (authenticated_offsets) |offset| {
        wire[offset] ^= 0x01;
        try std.testing.expectError(error.ZixAuthenticationFailed, deprotect(&plain, wire[0..length], TEST_KEY, TEST_SALT));
        wire[offset] ^= 0x01;
    }

    // And so is the tag itself.
    wire[length - 1] ^= 0x80;
    try std.testing.expectError(error.ZixAuthenticationFailed, deprotect(&plain, wire[0..length], TEST_KEY, TEST_SALT));
    wire[length - 1] ^= 0x80;

    // Restored, it opens again.
    _ = try deprotect(&plain, wire[0..length], TEST_KEY, TEST_SALT);
}

test "zix dtls: record deprotect, a wrong key or salt fails rather than returning garbage" {
    var wire: [128]u8 = undefined;
    const bytes = try protect(&wire, "payload", .APPLICATION_DATA, 1, 1, TEST_KEY, TEST_SALT);

    var plain: [128]u8 = undefined;
    const other_key: [16]u8 = @splat(0xCD);
    const other_salt: [SALT_LEN]u8 = .{ 1, 2, 3, 4 };

    try std.testing.expectError(error.ZixAuthenticationFailed, deprotect(&plain, bytes, other_key, TEST_SALT));
    try std.testing.expectError(error.ZixAuthenticationFailed, deprotect(&plain, bytes, TEST_KEY, other_salt));
}

test "zix dtls: record deprotect, a short or truncated record is rejected" {
    var plain: [128]u8 = undefined;

    try std.testing.expectError(error.ZixTruncated, deprotect(&plain, &[_]u8{ 23, 0xFE }, TEST_KEY, TEST_SALT));

    // A body shorter than an explicit nonce plus a tag cannot hold a record.
    var stub: [HEADER_LEN + 8]u8 = @splat(0);
    writeHeader(&stub, .{
        .content_type = .APPLICATION_DATA,
        .version = VERSION_DTLS_1_2,
        .epoch = 0,
        .sequence_number = 0,
        .length = 8,
    });
    try std.testing.expectError(error.ZixBadRecord, deprotect(&plain, &stub, TEST_KEY, TEST_SALT));

    // A length field promising more than the datagram holds.
    var wire: [128]u8 = undefined;
    const bytes = try protect(&wire, "payload", .APPLICATION_DATA, 0, 0, TEST_KEY, TEST_SALT);
    try std.testing.expectError(error.ZixTruncated, deprotect(&plain, bytes[0 .. bytes.len - 1], TEST_KEY, TEST_SALT));
}

test "zix dtls: record iterator, several records ride one datagram" {
    var datagram: [512]u8 = undefined;
    var used: usize = 0;

    const fragments = [_][]const u8{ "first", "second", "third" };
    for (fragments, 0..) |fragment, i| {
        const bytes = try protect(datagram[used..], fragment, .HANDSHAKE, 0, @intCast(i), TEST_KEY, TEST_SALT);
        used += bytes.len;
    }

    var iterator: RecordIterator = .{ .datagram = datagram[0..used] };
    var seen: usize = 0;

    while (try iterator.next()) |bytes| {
        var plain: [64]u8 = undefined;
        const opened = try deprotect(&plain, bytes, TEST_KEY, TEST_SALT);

        try std.testing.expectEqualStrings(fragments[seen], opened.data);
        try std.testing.expectEqual(@as(u48, @intCast(seen)), opened.header.sequence_number);

        seen += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), seen);
}

test "zix dtls: record iterator, a length past the end stops the walk" {
    var datagram: [128]u8 = undefined;
    const bytes = try protect(&datagram, "payload", .HANDSHAKE, 0, 0, TEST_KEY, TEST_SALT);

    var iterator: RecordIterator = .{ .datagram = datagram[0 .. bytes.len - 2] };
    try std.testing.expectError(error.ZixTruncated, iterator.next());

    var empty: RecordIterator = .{ .datagram = datagram[0..0] };
    try std.testing.expectEqual(@as(?[]const u8, null), try empty.next());
}

test "zix dtls: record plaintext, epoch 0 carries the handshake in the clear" {
    var wire_buf: [64]u8 = undefined;
    const bytes = try writePlaintext(&wire_buf, .HANDSHAKE, 0, 3, "flight");

    try std.testing.expectEqual(HEADER_LEN + 6, bytes.len);

    const header = try parseHeader(bytes);
    try std.testing.expectEqual(ContentType.HANDSHAKE, header.content_type);
    try std.testing.expectEqual(@as(u16, 0), header.epoch);
    try std.testing.expectEqual(@as(u48, 3), header.sequence_number);
    try std.testing.expectEqualStrings("flight", try plaintextFragment(bytes));

    try std.testing.expectError(error.ZixTruncated, plaintextFragment(bytes[0 .. bytes.len - 1]));

    // A ChangeCipherSpec record is one byte of body, and still epoch 0. Its own buffer, since
    // reusing the one above would leave the slice taken from it pointing at these bytes.
    var ccs_buf: [64]u8 = undefined;
    const ccs = try writePlaintext(&ccs_buf, .CHANGE_CIPHER_SPEC, 0, 4, &[_]u8{1});
    try std.testing.expectEqual(HEADER_LEN + 1, ccs.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, try plaintextFragment(ccs));
}

test "zix dtls: anti-replay, sequence zero is accepted once" {
    var window: AntiReplay = .{};

    try std.testing.expect(window.isNew(0));
    window.accept(0);
    try std.testing.expect(!window.isNew(0));
}

test "zix dtls: anti-replay, in-order, reordered, and duplicate records" {
    var window: AntiReplay = .{};

    for (0..10) |i| {
        const sequence_number: u48 = @intCast(i);
        try std.testing.expect(window.isNew(sequence_number));
        window.accept(sequence_number);
    }

    // Every one of them is now a duplicate.
    for (0..10) |i| {
        try std.testing.expect(!window.isNew(@intCast(i)));
    }

    // A gap ahead is accepted, and the numbers it skipped stay open.
    try std.testing.expect(window.isNew(20));
    window.accept(20);
    try std.testing.expect(window.isNew(15));
    window.accept(15);
    try std.testing.expect(!window.isNew(15));
    try std.testing.expect(window.isNew(16));
}

test "zix dtls: anti-replay, records off the left edge are rejected" {
    var window: AntiReplay = .{};
    window.accept(100);

    try std.testing.expect(window.isNew(100 - REPLAY_WINDOW_BITS + 1));
    try std.testing.expect(!window.isNew(100 - REPLAY_WINDOW_BITS));
    try std.testing.expect(!window.isNew(0));

    // A jump past the whole window clears it, so nothing behind survives.
    window.accept(100 + REPLAY_WINDOW_BITS + 5);
    try std.testing.expect(!window.isNew(100));
    try std.testing.expect(window.isNew(100 + REPLAY_WINDOW_BITS + 4));
}

test "zix dtls: anti-replay, a failed record must not move the window" {
    var window: AntiReplay = .{};
    window.accept(5);

    // isNew alone changes nothing, which is what lets it run before the AEAD.
    try std.testing.expect(window.isNew(6));
    try std.testing.expect(window.isNew(6));
    try std.testing.expectEqual(@as(u48, 5), window.highest);

    // A forged record at a far-ahead number would otherwise clear the window and lock out
    // everything genuine behind it.
    try std.testing.expect(window.isNew(9999));
    try std.testing.expectEqual(@as(u48, 5), window.highest);
    try std.testing.expect(window.isNew(6));
}
