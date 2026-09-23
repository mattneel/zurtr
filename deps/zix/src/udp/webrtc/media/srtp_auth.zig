//! zix SRTP message authentication (RFC 3711 4.2.1).
//!
//! What:
//! - The truncated HMAC-SHA1 tag that goes on the end of every protected packet, and the check
//!   that it is the right one.
//!
//! Note:
//! - SRTP authenticates the rollover counter even though the counter is never sent. The tag is
//!   computed over the packet followed by four bytes of counter, so a peer that has drifted onto
//!   a different counter fails the check instead of silently decrypting to noise.
//! - SRTCP has no rollover counter. Its index travels in the packet and is inside the
//!   authenticated bytes already, which is why there are two entry points rather than one with a
//!   counter that is sometimes ignored.
//! - The tag is the LEFTMOST bytes of the HMAC output. Taking the rightmost bytes produces a tag
//!   of the correct length that no peer agrees with.
//! - Only 4 and 10 byte tags exist here, from the two profiles zix answers. Any other length is
//!   refused rather than truncated to fit, including on the verify path, where accepting a short
//!   tag would weaken the check to whatever an attacker sent.
//! - Comparison is constant time. A check that returns early on the first wrong byte tells an
//!   attacker how much of a guessed tag was right, which turns forgery into 256 guesses per byte.

const std = @import("std");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

/// Session authentication key length (RFC 5764 4.1.2).
pub const KEY_LEN: usize = 20;

/// The untruncated HMAC-SHA1 output length.
pub const FULL_TAG_LEN: usize = HmacSha1.mac_length;

/// The shorter of the two tag lengths, from SRTP_AES128_CM_HMAC_SHA1_32.
pub const SHORT_TAG_LEN: usize = 4;

/// The longer of the two tag lengths, from SRTP_AES128_CM_HMAC_SHA1_80.
pub const LONG_TAG_LEN: usize = 10;

/// Bytes of rollover counter appended to an SRTP packet before hashing.
pub const ROC_LEN: usize = 4;

/// What stops a tag from being produced.
pub const Error = error{
    /// A tag length neither profile uses.
    ZixBadTagLength,
};

/// What stops a tag from being accepted.
pub const VerifyError = error{
    /// A tag length neither profile uses.
    ZixBadTagLength,
    /// The tag does not match what the key and the bytes produce.
    ZixAuthenticationFailed,
};

/// Tag an SRTP packet (RFC 3711 4.2.1).
///
/// Param:
/// out - []u8 (filled completely, its length is the tag length, 4 or 10)
/// key - [KEY_LEN]u8 (the session authentication key)
/// authenticated - []const u8 (the whole packet, header and encrypted payload, tag excluded)
/// roc - u32 (the rollover counter, hashed but not sent)
///
/// Return:
/// - void
/// - error.ZixBadTagLength
pub fn tagRtp(out: []u8, key: [KEY_LEN]u8, authenticated: []const u8, roc: u32) Error!void {
    return compute(out, key, authenticated, roc);
}

/// Tag an SRTCP packet (RFC 3711 3.4).
///
/// Param:
/// out - []u8 (filled completely, its length is the tag length, 4 or 10)
/// key - [KEY_LEN]u8
/// authenticated - []const u8 (the whole packet, the E flag and index included)
///
/// Return:
/// - void
/// - error.ZixBadTagLength
pub fn tagRtcp(out: []u8, key: [KEY_LEN]u8, authenticated: []const u8) Error!void {
    return compute(out, key, authenticated, null);
}

/// Check the tag on an SRTP packet.
///
/// Param:
/// candidate - []const u8 (the tag as it arrived)
/// key - [KEY_LEN]u8
/// authenticated - []const u8
/// roc - u32
///
/// Return:
/// - void
/// - error.ZixBadTagLength, error.ZixAuthenticationFailed
pub fn verifyRtp(candidate: []const u8, key: [KEY_LEN]u8, authenticated: []const u8, roc: u32) VerifyError!void {
    return check(candidate, key, authenticated, roc);
}

/// Check the tag on an SRTCP packet.
///
/// Param:
/// candidate - []const u8 (the tag as it arrived)
/// key - [KEY_LEN]u8
/// authenticated - []const u8
///
/// Return:
/// - void
/// - error.ZixBadTagLength, error.ZixAuthenticationFailed
pub fn verifyRtcp(candidate: []const u8, key: [KEY_LEN]u8, authenticated: []const u8) VerifyError!void {
    return check(candidate, key, authenticated, null);
}

/// Whether a tag length is one of the two that exist here.
///
/// Param:
/// len - usize
///
/// Return:
/// - bool
pub fn isTagLength(len: usize) bool {
    return len == SHORT_TAG_LEN or len == LONG_TAG_LEN;
}

/// Compute a tag over the bytes and, for SRTP, the rollover counter behind them.
fn compute(out: []u8, key: [KEY_LEN]u8, authenticated: []const u8, roc: ?u32) Error!void {
    if (!isTagLength(out.len)) return error.ZixBadTagLength;

    var mac = HmacSha1.init(&key);
    mac.update(authenticated);

    if (roc) |counter| {
        var counter_bytes: [ROC_LEN]u8 = undefined;
        std.mem.writeInt(u32, &counter_bytes, counter, .big);

        mac.update(&counter_bytes);
    }

    var full: [FULL_TAG_LEN]u8 = undefined;
    mac.final(&full);

    @memcpy(out, full[0..out.len]);
}

/// Recompute and compare in constant time.
fn check(candidate: []const u8, key: [KEY_LEN]u8, authenticated: []const u8, roc: ?u32) VerifyError!void {
    if (!isTagLength(candidate.len)) return error.ZixBadTagLength;

    var expected: [LONG_TAG_LEN]u8 = undefined;
    try compute(expected[0..candidate.len], key, authenticated, roc);

    const same = switch (candidate.len) {
        SHORT_TAG_LEN => std.crypto.timing_safe.eql([SHORT_TAG_LEN]u8, candidate[0..SHORT_TAG_LEN].*, expected[0..SHORT_TAG_LEN].*),
        LONG_TAG_LEN => std.crypto.timing_safe.eql([LONG_TAG_LEN]u8, candidate[0..LONG_TAG_LEN].*, expected[0..LONG_TAG_LEN].*),
        else => false,
    };

    if (!same) return error.ZixAuthenticationFailed;
}

// --------------------------------------------------------------------------------------- //
// test cases

const TEST_KEY: [KEY_LEN]u8 = .{
    0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4,
    0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4,
};

test "zix media: srtp auth, the primitive is hmac-sha1 and truncation takes the left" {
    // RFC 2202 test case 1, which also happens to use a 20-byte key, the same length SRTP does.
    const key: [KEY_LEN]u8 = @splat(0x0B);
    const expected = [_]u8{
        0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B,
        0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00,
    };

    var full: [FULL_TAG_LEN]u8 = undefined;
    HmacSha1.create(&full, "Hi There", &key);

    try std.testing.expectEqualSlices(u8, &expected, &full);

    // The SRTCP tag over the same bytes is the leftmost 10 of that.
    var tag: [LONG_TAG_LEN]u8 = undefined;
    try tagRtcp(&tag, key, "Hi There");

    try std.testing.expectEqualSlices(u8, expected[0..LONG_TAG_LEN], &tag);
}

test "zix media: srtp auth tagRtp, the rollover counter changes the tag" {
    const packet = "an srtp packet, header and ciphertext";

    var first: [LONG_TAG_LEN]u8 = undefined;
    var second: [LONG_TAG_LEN]u8 = undefined;

    try tagRtp(&first, TEST_KEY, packet, 0);
    try tagRtp(&second, TEST_KEY, packet, 1);

    // The counter is never on the wire, so this is the only thing that catches a peer that has
    // drifted onto a different one.
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "zix media: srtp auth, an rtp tag is not an rtcp tag over the same bytes" {
    const packet = "the same bytes both ways";

    var as_rtp: [LONG_TAG_LEN]u8 = undefined;
    var as_rtcp: [LONG_TAG_LEN]u8 = undefined;

    try tagRtp(&as_rtp, TEST_KEY, packet, 0);
    try tagRtcp(&as_rtcp, TEST_KEY, packet);

    // A zero counter still appends four bytes, so the two are not the same message.
    try std.testing.expect(!std.mem.eql(u8, &as_rtp, &as_rtcp));
}

test "zix media: srtp auth, the short tag is a prefix of the long one" {
    const packet = "prefix check";

    var short: [SHORT_TAG_LEN]u8 = undefined;
    var long: [LONG_TAG_LEN]u8 = undefined;

    try tagRtp(&short, TEST_KEY, packet, 7);
    try tagRtp(&long, TEST_KEY, packet, 7);

    try std.testing.expectEqualSlices(u8, &short, long[0..SHORT_TAG_LEN]);
}

test "zix media: srtp auth verifyRtp, a tag this file made is accepted" {
    const packet = "round trip";

    var tag: [LONG_TAG_LEN]u8 = undefined;
    try tagRtp(&tag, TEST_KEY, packet, 99);
    try verifyRtp(&tag, TEST_KEY, packet, 99);

    var short: [SHORT_TAG_LEN]u8 = undefined;
    try tagRtp(&short, TEST_KEY, packet, 99);
    try verifyRtp(&short, TEST_KEY, packet, 99);
}

test "zix media: srtp auth verifyRtp, a changed byte anywhere is refused" {
    const packet = "the payload the tag covers";

    var tag: [LONG_TAG_LEN]u8 = undefined;
    try tagRtp(&tag, TEST_KEY, packet, 5);

    // A different counter.
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tag, TEST_KEY, packet, 6));

    // A different key.
    var other_key = TEST_KEY;
    other_key[0] ^= 0x01;
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tag, other_key, packet, 5));

    // A different packet.
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tag, TEST_KEY, "the payload the tag coverz", 5));

    // A changed tag.
    var tampered = tag;
    tampered[LONG_TAG_LEN - 1] ^= 0x01;
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tampered, TEST_KEY, packet, 5));
}

test "zix media: srtp auth verifyRtcp, it is a different check from the rtp one" {
    const packet = "an srtcp compound with its index";

    var tag: [LONG_TAG_LEN]u8 = undefined;
    try tagRtcp(&tag, TEST_KEY, packet);

    try verifyRtcp(&tag, TEST_KEY, packet);
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tag, TEST_KEY, packet, 0));
}

test "zix media: srtp auth, a tag length neither profile uses is refused" {
    var wrong: [8]u8 = undefined;

    try std.testing.expectError(error.ZixBadTagLength, tagRtp(&wrong, TEST_KEY, "bytes", 0));
    try std.testing.expectError(error.ZixBadTagLength, tagRtcp(&wrong, TEST_KEY, "bytes"));
    try std.testing.expectError(error.ZixBadTagLength, tagRtp(&[_]u8{}, TEST_KEY, "bytes", 0));
}

test "zix media: srtp auth verify, a short tag is refused rather than compared short" {
    const packet = "truncation check";

    var tag: [LONG_TAG_LEN]u8 = undefined;
    try tagRtp(&tag, TEST_KEY, packet, 0);

    // The first four bytes really are the short tag, and offering them where a long one is
    // expected must not pass. Accepting it would let a peer choose its own tag length.
    try std.testing.expectError(error.ZixBadTagLength, verifyRtp(tag[0..3], TEST_KEY, packet, 0));
    try std.testing.expectError(error.ZixBadTagLength, verifyRtp(tag[0..9], TEST_KEY, packet, 0));
}

test "zix media: srtp auth isTagLength, only the two profile lengths are tags" {
    try std.testing.expect(isTagLength(SHORT_TAG_LEN));
    try std.testing.expect(isTagLength(LONG_TAG_LEN));
    try std.testing.expect(!isTagLength(0));
    try std.testing.expect(!isTagLength(8));
    try std.testing.expect(!isTagLength(FULL_TAG_LEN));
}

test "zix media: srtp auth, an empty message still tags" {
    // A header-only RTP packet has no payload, and the tag still covers the header and counter.
    var tag: [LONG_TAG_LEN]u8 = undefined;

    try tagRtp(&tag, TEST_KEY, &.{}, 0);
    try verifyRtp(&tag, TEST_KEY, &.{}, 0);
    try std.testing.expectError(error.ZixAuthenticationFailed, verifyRtp(&tag, TEST_KEY, &.{}, 1));
}
