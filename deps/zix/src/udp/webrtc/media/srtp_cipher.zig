//! zix SRTP counter mode cipher (RFC 3711 4.1.1).
//!
//! What:
//! - AES-128 in counter mode, and the counter block SRTP builds for each packet. This is the only
//!   place a keystream is produced, for packets and for key derivation alike.
//!
//! Note:
//! - The counter block is three values exclusive-ored together, each padded to 128 bits:
//!   the session salt shifted left by 16, the SSRC shifted left by 64, and the packet index
//!   shifted left by 16. Laid out in bytes that is the salt across 0 to 14, the SSRC over 4 to 8,
//!   and the 48-bit index over 8 to 14, with the last two bytes left for the block counter.
//! - Reserving those last two bytes caps a keystream segment at 2^16 blocks, which the RFC states
//!   as a MUST NOT rather than a suggestion. Going past it repeats keystream from the next
//!   packet, so it is an error here and not a wrap.
//! - Counter mode is its own inverse: encrypting twice with the same block gives the original
//!   back. `apply` is used for both directions on purpose, and that is also why a counter block
//!   must never repeat under one key.
//! - The block counter is incremented over the whole 128 bits, exactly as RFC 3711 4.1.1 writes
//!   it. Within the 2^16 block ceiling this only ever touches the last two bytes.

const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;

/// AES block size, which is also the counter block size.
pub const BLOCK_LEN: usize = 16;

/// Session cipher key length for the AES-128 profiles.
pub const KEY_LEN: usize = 16;

/// Session salt length for the AES-128 profiles.
pub const SALT_LEN: usize = 14;

/// The most blocks one counter block may produce (RFC 3711 4.1.1).
pub const MAX_BLOCKS: usize = 1 << 16;

/// The most bytes one keystream segment may be.
pub const MAX_SEGMENT_LEN: usize = MAX_BLOCKS * BLOCK_LEN;

/// What stops a keystream from being produced.
pub const Error = error{
    /// More than 2^16 blocks were asked for from one counter block.
    ZixSegmentTooLong,
};

/// Build the counter block for one packet (RFC 3711 4.1.1).
///
/// Note:
/// - SRTP passes the 48-bit ROC and sequence pair as the index. SRTCP passes its own 31-bit
///   index in the same slot, which is why this takes a plain number and not either of them.
///
/// Param:
/// salt - [SALT_LEN]u8 (the session salt, not the master salt)
/// ssrc - u32 (the stream the packet belongs to)
/// index - u48 (the packet index)
///
/// Return:
/// - [BLOCK_LEN]u8
pub fn counterBlock(salt: [SALT_LEN]u8, ssrc: u32, index: u48) [BLOCK_LEN]u8 {
    var block: [BLOCK_LEN]u8 = @splat(0);
    @memcpy(block[0..SALT_LEN], &salt);

    var ssrc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &ssrc_bytes, ssrc, .big);

    for (0..4) |offset| block[4 + offset] ^= ssrc_bytes[offset];

    var index_bytes: [6]u8 = undefined;
    std.mem.writeInt(u48, &index_bytes, index, .big);

    for (0..6) |offset| block[8 + offset] ^= index_bytes[offset];

    return block;
}

/// Fill a buffer with keystream.
///
/// Param:
/// out - []u8 (filled completely)
/// key - [KEY_LEN]u8 (the session cipher key)
/// counter - [BLOCK_LEN]u8 (the starting counter block)
///
/// Return:
/// - void
/// - error.ZixSegmentTooLong
pub fn keystream(out: []u8, key: [KEY_LEN]u8, counter: [BLOCK_LEN]u8) Error!void {
    if (out.len > MAX_SEGMENT_LEN) return error.ZixSegmentTooLong;

    const context = Aes128.initEnc(key);
    var block = counter;
    var at: usize = 0;

    while (at < out.len) : (at += BLOCK_LEN) {
        var produced: [BLOCK_LEN]u8 = undefined;
        context.encrypt(&produced, &block);

        const take = @min(BLOCK_LEN, out.len - at);
        @memcpy(out[at..][0..take], produced[0..take]);

        increment(&block);
    }
}

/// Encrypt or decrypt in place.
///
/// Note:
/// - One function for both directions, because counter mode is symmetric. Calling it twice with
///   the same counter block returns the original bytes, and a test says so.
///
/// Param:
/// data - []u8 (rewritten in place)
/// key - [KEY_LEN]u8
/// counter - [BLOCK_LEN]u8
///
/// Return:
/// - void
/// - error.ZixSegmentTooLong
pub fn apply(data: []u8, key: [KEY_LEN]u8, counter: [BLOCK_LEN]u8) Error!void {
    if (data.len > MAX_SEGMENT_LEN) return error.ZixSegmentTooLong;

    const context = Aes128.initEnc(key);
    var block = counter;
    var at: usize = 0;

    while (at < data.len) : (at += BLOCK_LEN) {
        var produced: [BLOCK_LEN]u8 = undefined;
        context.encrypt(&produced, &block);

        const take = @min(BLOCK_LEN, data.len - at);
        for (0..take) |offset| data[at + offset] ^= produced[offset];

        increment(&block);
    }
}

/// Step a counter block by one, over all 128 bits.
fn increment(block: *[BLOCK_LEN]u8) void {
    var at: usize = BLOCK_LEN;
    while (at > 0) {
        at -= 1;
        block[at] +%= 1;

        if (block[at] != 0) return;
    }
}

// --------------------------------------------------------------------------------------- //
// test cases

/// The session key from the RFC 3711 B.2 vector.
const VECTOR_KEY: [KEY_LEN]u8 = .{
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};

/// The session salt from the same vector, which the counter block is built from.
const VECTOR_SALT: [SALT_LEN]u8 = .{
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
    0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
};

test "zix media: srtp cipher counterBlock, the published vector builds byte for byte" {
    // ROC 0, sequence 0, SSRC 0, so the block is the salt and nothing else.
    const block = counterBlock(VECTOR_SALT, 0, 0);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0x00, 0x00,
    }, &block);
}

test "zix media: srtp cipher keystream, the first blocks match the published vector" {
    var produced: [48]u8 = undefined;
    try keystream(&produced, VECTOR_KEY, counterBlock(VECTOR_SALT, 0, 0));

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xE0, 0x3E, 0xAD, 0x09, 0x35, 0xC9, 0x5E, 0x80,
        0xE1, 0x66, 0xB1, 0x6D, 0xD9, 0x2B, 0x4E, 0xB4,
    }, produced[0..16]);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xD2, 0x35, 0x13, 0x16, 0x2B, 0x02, 0xD0, 0xF7,
        0x2A, 0x43, 0xA2, 0xFE, 0x4A, 0x5F, 0x97, 0xAB,
    }, produced[16..32]);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x41, 0xE9, 0x5B, 0x3B, 0xB0, 0xA2, 0xE8, 0xDD,
        0x47, 0x79, 0x01, 0xE4, 0xFC, 0xA8, 0x94, 0xC0,
    }, produced[32..48]);
}

test "zix media: srtp cipher counterBlock, the ssrc sits over bytes four to eight" {
    const block = counterBlock(@splat(0), 0xAABBCCDD, 0);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, block[4..8]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, block[0..4]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, block[8..16]);
}

test "zix media: srtp cipher counterBlock, the index sits over bytes eight to fourteen" {
    const block = counterBlock(@splat(0), 0, 0x0000_0001_0002);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 }, block[8..14]);

    // The last two bytes belong to the block counter and are never part of the index.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, block[14..16]);
}

test "zix media: srtp cipher counterBlock, the salt is exclusive-ored and not overwritten" {
    const salt: [SALT_LEN]u8 = @splat(0xFF);
    const block = counterBlock(salt, 0x0F0F0F0F, 0);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0xF0, 0xF0, 0xF0 }, block[4..8]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, block[0..4]);
}

test "zix media: srtp cipher counterBlock, every input changes the block" {
    const base = counterBlock(VECTOR_SALT, 1, 1);

    try std.testing.expect(!std.mem.eql(u8, &base, &counterBlock(VECTOR_SALT, 2, 1)));
    try std.testing.expect(!std.mem.eql(u8, &base, &counterBlock(VECTOR_SALT, 1, 2)));
    try std.testing.expect(!std.mem.eql(u8, &base, &counterBlock(@splat(1), 1, 1)));
}

test "zix media: srtp cipher apply, encrypting twice gives the original back" {
    const original = "the payload stays bytes, no codec looks at it";
    var data: [original.len]u8 = original.*;
    const block = counterBlock(VECTOR_SALT, 0xDEADBEEF, 42);

    try apply(&data, VECTOR_KEY, block);
    try std.testing.expect(!std.mem.eql(u8, original, &data));

    try apply(&data, VECTOR_KEY, block);
    try std.testing.expectEqualSlices(u8, original, &data);
}

test "zix media: srtp cipher apply, it is the keystream exclusive-ored in" {
    var data: [40]u8 = @splat(0);
    const block = counterBlock(VECTOR_SALT, 7, 7);

    try apply(&data, VECTOR_KEY, block);

    var expected: [40]u8 = undefined;
    try keystream(&expected, VECTOR_KEY, block);

    // Applying to all zeros is exactly the keystream.
    try std.testing.expectEqualSlices(u8, &expected, &data);
}

test "zix media: srtp cipher apply, a different index gives different ciphertext" {
    var first: [16]u8 = @splat(0x11);
    var second: [16]u8 = @splat(0x11);

    try apply(&first, VECTOR_KEY, counterBlock(VECTOR_SALT, 1, 100));
    try apply(&second, VECTOR_KEY, counterBlock(VECTOR_SALT, 1, 101));

    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "zix media: srtp cipher apply, a partial last block is handled" {
    // 20 bytes is one whole block and four bytes of the next.
    var data: [20]u8 = @splat(0);
    const block = counterBlock(VECTOR_SALT, 0, 0);

    try apply(&data, VECTOR_KEY, block);

    var expected: [32]u8 = undefined;
    try keystream(&expected, VECTOR_KEY, block);

    try std.testing.expectEqualSlices(u8, expected[0..20], &data);
}

test "zix media: srtp cipher apply, an empty buffer does nothing" {
    var data: [0]u8 = undefined;

    try apply(&data, VECTOR_KEY, counterBlock(VECTOR_SALT, 0, 0));
}

test "zix media: srtp cipher increment, it carries across the whole block" {
    var block: [BLOCK_LEN]u8 = @splat(0xFF);
    increment(&block);

    const all_zero: [BLOCK_LEN]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &all_zero, &block);

    var low: [BLOCK_LEN]u8 = @splat(0);
    low[BLOCK_LEN - 1] = 0xFF;
    increment(&low);

    try std.testing.expectEqual(@as(u8, 0x01), low[BLOCK_LEN - 2]);
    try std.testing.expectEqual(@as(u8, 0x00), low[BLOCK_LEN - 1]);
}

test "zix media: srtp cipher, a segment past the block ceiling is refused" {
    // The ceiling is what keeps two packets from sharing keystream, so it errors rather than
    // wrapping the counter back into the next packet's blocks.
    const allocator = std.testing.allocator;
    const too_long = try allocator.alloc(u8, MAX_SEGMENT_LEN + 1);
    defer allocator.free(too_long);

    @memset(too_long, 0);

    try std.testing.expectError(
        error.ZixSegmentTooLong,
        apply(too_long, VECTOR_KEY, counterBlock(VECTOR_SALT, 0, 0)),
    );
    try std.testing.expectError(
        error.ZixSegmentTooLong,
        keystream(too_long, VECTOR_KEY, counterBlock(VECTOR_SALT, 0, 0)),
    );
}
