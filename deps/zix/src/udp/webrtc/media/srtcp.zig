//! zix SRTCP packet protection (RFC 3711 3.4).
//!
//! What:
//! - The control-path sibling of srtp.zig. Same cipher, same authentication, different framing
//!   and a different way of knowing where a packet sits in the stream.
//!
//! Note:
//! - SRTCP carries its index in the packet, all 31 bits of it, so there is no guessing and no
//!   rollover counter. That is the single biggest difference from SRTP and it removes a whole
//!   class of desynchronisation.
//! - The encrypted portion starts at byte 8, after the first packet's common header and sender
//!   identifier. Those eight bytes stay readable so a receiver can find whose packet it is
//!   before it has decrypted anything.
//! - The authenticated portion covers the compound packet AND the flag-and-index word behind it,
//!   after encryption. Tagging before appending the index leaves the index unprotected, and an
//!   attacker who can change it can make a receiver decrypt with the wrong counter block.
//! - The tag length is not always the SRTP one. SRTP_AES128_CM_HMAC_SHA1_32 uses a 4-byte tag on
//!   media and a 10-byte tag here (RFC 5764 4.1.2), which is why this file reads its own number
//!   out of the profile table.
//! - The index must never repeat under one key, so it stops at 2^31 rather than wrapping. Past
//!   that the association has to be re-keyed, which is a decision above this file.

const std = @import("std");

const exporter = @import("../../../tls/dtls_exporter.zig");
const cipher = @import("srtp_cipher.zig");
const packet_index = @import("srtp_index.zig");
const profile = @import("profile.zig");
const rtcp = @import("rtcp.zig");
const srtp_auth = @import("srtp_auth.zig");
const srtp_key = @import("srtp_key.zig");

/// Bytes the flag and index word takes.
pub const INDEX_LEN: usize = 4;

/// Where the encrypted portion starts (RFC 3711 3.4).
pub const ENCRYPTED_FROM: usize = 8;

/// The high bit of the index word, set when the payload is encrypted.
pub const ENCRYPTED_FLAG: u32 = 1 << 31;

/// The last index one key may use.
pub const MAX_INDEX: u32 = (1 << 31) - 1;

/// The most bytes protection adds to a packet.
pub const MAX_OVERHEAD: usize = INDEX_LEN + srtp_auth.LONG_TAG_LEN;

/// What stops a control path from being opened.
pub const InitError = error{
    /// A profile with no keys to run on.
    ZixUnsupportedProfile,
};

/// What stops a packet from being protected.
pub const ProtectError = error{
    /// Too short to hold a common header and a sender identifier.
    ZixTruncated,
    /// No room in the buffer for the index and the tag.
    ZixNoSpace,
    /// A payload past what one counter block may cover.
    ZixSegmentTooLong,
    /// Every index this key may use has been used. The association has to be re-keyed.
    ZixIndexExhausted,
};

/// What stops a packet from being opened.
pub const OpenError = error{
    /// Too short to hold a common header, a sender identifier, an index, and a tag.
    ZixTruncated,
    /// An index already accepted, or too old to tell apart from one.
    ZixReplayed,
    /// The tag does not match, so the packet is not from the peer that holds the key.
    ZixAuthenticationFailed,
    /// A payload past what one counter block may cover.
    ZixSegmentTooLong,
};

/// One direction of the control path.
pub const Session = struct {
    keys: srtp_key.SessionKeys,
    /// Tag length in bytes, which is the RTCP one and not always the RTP one.
    tag_len: usize,
    /// The index the next sent packet will carry.
    send_index: u32,
    replay: packet_index.ReplayList,

    /// Derive the session keys and open a control path.
    ///
    /// Param:
    /// negotiated - exporter.SrtpProfile
    /// master_key - [srtp_key.MASTER_KEY_LEN]u8
    /// master_salt - [srtp_key.MASTER_SALT_LEN]u8
    ///
    /// Return:
    /// - Session
    /// - error.ZixUnsupportedProfile
    pub fn init(
        negotiated: exporter.SrtpProfile,
        master_key: [srtp_key.MASTER_KEY_LEN]u8,
        master_salt: [srtp_key.MASTER_SALT_LEN]u8,
    ) InitError!Session {
        const parameters = profile.parametersFor(negotiated) catch return error.ZixUnsupportedProfile;

        return .{
            .keys = srtp_key.rtcpKeys(master_key, master_salt),
            .tag_len = parameters.rtcp_tag_len,
            .send_index = 0,
            .replay = .{},
        };
    }

    /// How many bytes protection adds.
    ///
    /// Return:
    /// - usize
    pub fn overhead(self: Session) usize {
        return INDEX_LEN + self.tag_len;
    }

    /// Protect a compound packet in place (RFC 3711 3.4).
    ///
    /// Note:
    /// - `buffer` holds the plain compound packet at its start and must have `overhead()` bytes
    ///   spare behind it.
    ///
    /// Param:
    /// buffer - []u8 (working buffer, rewritten in place)
    /// packet_len - usize (how much of it is the plain compound packet)
    ///
    /// Return:
    /// - []const u8, the protected packet
    /// - error.ZixTruncated, error.ZixNoSpace, error.ZixSegmentTooLong, error.ZixIndexExhausted
    pub fn protect(self: *Session, buffer: []u8, packet_len: usize) ProtectError![]const u8 {
        if (packet_len > buffer.len) return error.ZixTruncated;
        if (packet_len < ENCRYPTED_FROM) return error.ZixTruncated;
        if (buffer.len - packet_len < self.overhead()) return error.ZixNoSpace;
        if (self.send_index > MAX_INDEX) return error.ZixIndexExhausted;

        const ssrc = rtcp.senderSsrc(buffer[0..packet_len]) catch return error.ZixTruncated;
        const index = self.send_index;

        const block = cipher.counterBlock(self.keys.cipher_salt, ssrc, index);
        try cipher.apply(buffer[ENCRYPTED_FROM..packet_len], self.keys.cipher_key, block);

        const authenticated_len = packet_len + INDEX_LEN;
        std.mem.writeInt(u32, buffer[packet_len..][0..4], ENCRYPTED_FLAG | index, .big);

        srtp_auth.tagRtcp(
            buffer[authenticated_len..][0..self.tag_len],
            self.keys.auth_key,
            buffer[0..authenticated_len],
        ) catch unreachable;

        self.send_index += 1;

        return buffer[0 .. authenticated_len + self.tag_len];
    }

    /// Open a protected compound packet in place (RFC 3711 3.4).
    ///
    /// Param:
    /// packet - []u8 (one received packet, index and tag included, rewritten in place)
    ///
    /// Return:
    /// - []const u8, the plain compound packet
    /// - error.ZixTruncated, error.ZixReplayed, error.ZixAuthenticationFailed, error.ZixSegmentTooLong
    pub fn unprotect(self: *Session, packet: []u8) OpenError![]const u8 {
        const trailer = INDEX_LEN + self.tag_len;

        if (packet.len < ENCRYPTED_FROM + trailer) return error.ZixTruncated;

        const authenticated_len = packet.len - self.tag_len;
        const body_len = authenticated_len - INDEX_LEN;
        const word = std.mem.readInt(u32, packet[body_len..][0..4], .big);
        const index = word & MAX_INDEX;

        if (!self.replay.isNew(index)) return error.ZixReplayed;

        srtp_auth.verifyRtcp(
            packet[authenticated_len..],
            self.keys.auth_key,
            packet[0..authenticated_len],
        ) catch |failure| return switch (failure) {
            error.ZixAuthenticationFailed => error.ZixAuthenticationFailed,
            error.ZixBadTagLength => unreachable,
        };

        if (word & ENCRYPTED_FLAG != 0) {
            const ssrc = rtcp.senderSsrc(packet[0..body_len]) catch return error.ZixTruncated;
            const block = cipher.counterBlock(self.keys.cipher_salt, ssrc, index);

            try cipher.apply(packet[ENCRYPTED_FROM..body_len], self.keys.cipher_key, block);
        }

        self.replay.accept(index);

        return packet[0..body_len];
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const report = @import("report.zig");

const TEST_MASTER_KEY: [srtp_key.MASTER_KEY_LEN]u8 = .{
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
};

const TEST_MASTER_SALT: [srtp_key.MASTER_SALT_LEN]u8 = .{
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE,
    0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
};

const Pair = struct {
    sender: Session,
    receiver: Session,

    fn open() !Pair {
        return .{
            .sender = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT),
            .receiver = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT),
        };
    }
};

/// A receiver report with one block, which is what a peer sends every few seconds.
fn plainCompound(buffer: []u8) !usize {
    const blocks = [_]report.ReportBlock{.{
        .source = 0x0BADF00D,
        .fraction_lost = 12,
        .packets_lost = 34,
        .highest_sequence = 500,
        .jitter = 7,
        .last_sender_report = 0xAABBCCDD,
        .delay_since_last_sender_report = 65536,
    }};

    return (try report.writeReceiverReport(buffer, 0xDEADBEEF, &blocks)).len;
}

test "zix media: srtcp protect, a compound packet opens back to what went in" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const original: [64]u8 = buffer;

    const protected = try pair.sender.protect(&buffer, packet_len);

    try std.testing.expectEqual(packet_len + INDEX_LEN + 10, protected.len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    const opened = try pair.receiver.unprotect(received[0..protected.len]);

    try std.testing.expectEqualSlices(u8, original[0..packet_len], opened);

    // And it is still a compound packet the walk understands.
    const parsed = try report.readReceiverReport(blk: {
        var walk = try rtcp.begin(opened);
        break :blk walk.next().?;
    });

    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.ssrc);
    try std.testing.expectEqual(@as(u32, 0x0BADF00D), parsed.blocks.at(0).?.source);
}

test "zix media: srtcp protect, the first eight bytes stay readable" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const header: [ENCRYPTED_FROM]u8 = buffer[0..ENCRYPTED_FROM].*;
    const body: [8]u8 = buffer[8..16].*;

    const protected = try pair.sender.protect(&buffer, packet_len);

    // A receiver needs the sender identifier before it can build a counter block, so those eight
    // bytes cannot be encrypted.
    try std.testing.expectEqualSlices(u8, &header, protected[0..ENCRYPTED_FROM]);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try rtcp.senderSsrc(protected));

    // Everything behind them is.
    try std.testing.expect(!std.mem.eql(u8, &body, protected[8..16]));
}

test "zix media: srtcp protect, the index word carries the encrypted flag" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const protected = try pair.sender.protect(&buffer, packet_len);
    const word = std.mem.readInt(u32, protected[packet_len..][0..4], .big);

    try std.testing.expect(word & ENCRYPTED_FLAG != 0);
    try std.testing.expectEqual(@as(u32, 0), word & MAX_INDEX);
}

test "zix media: srtcp protect, the index counts up per packet" {
    var pair = try Pair.open();

    for (0..4) |expected| {
        var buffer: [64]u8 = undefined;
        const packet_len = try plainCompound(&buffer);
        const protected = try pair.sender.protect(&buffer, packet_len);
        const word = std.mem.readInt(u32, protected[packet_len..][0..4], .big);

        try std.testing.expectEqual(@as(u32, @intCast(expected)), word & MAX_INDEX);

        var received: [64]u8 = undefined;
        @memcpy(received[0..protected.len], protected);
        _ = try pair.receiver.unprotect(received[0..protected.len]);
    }

    try std.testing.expectEqual(@as(u32, 4), pair.sender.send_index);
}

test "zix media: srtcp unprotect, a changed index is refused" {
    // The index is inside the tag on purpose. Without that, moving it makes the receiver decrypt
    // with a counter block the sender never used.
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const protected = try pair.sender.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);
    std.mem.writeInt(u32, received[packet_len..][0..4], ENCRYPTED_FLAG | 99, .big);

    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));
}

test "zix media: srtcp unprotect, a tampered body is refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const protected = try pair.sender.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);
    received[ENCRYPTED_FROM] ^= 0x01;

    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));

    // The readable part is authenticated too.
    @memcpy(received[0..protected.len], protected);
    received[5] ^= 0x01;
    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));
}

test "zix media: srtcp unprotect, the same packet twice is refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const protected = try pair.sender.protect(&buffer, packet_len);

    var first: [64]u8 = undefined;
    var second: [64]u8 = undefined;
    @memcpy(first[0..protected.len], protected);
    @memcpy(second[0..protected.len], protected);

    _ = try pair.receiver.unprotect(first[0..protected.len]);

    try std.testing.expectError(error.ZixReplayed, pair.receiver.unprotect(second[0..protected.len]));
}

test "zix media: srtcp unprotect, an unencrypted packet is left alone" {
    // RFC 3550 9.1 lets a compound be split into an encrypted half and a clear one, and the flag
    // is how the receiver is told which it has.
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);
    const original: [64]u8 = buffer;

    std.mem.writeInt(u32, buffer[packet_len..][0..4], 5, .big);

    const authenticated_len = packet_len + INDEX_LEN;
    try srtp_auth.tagRtcp(
        buffer[authenticated_len..][0..10],
        pair.sender.keys.auth_key,
        buffer[0..authenticated_len],
    );

    const opened = try pair.receiver.unprotect(buffer[0 .. authenticated_len + 10]);

    try std.testing.expectEqualSlices(u8, original[0..packet_len], opened);
}

test "zix media: srtcp, two packets never share keystream" {
    var pair = try Pair.open();

    var first: [64]u8 = undefined;
    var second: [64]u8 = undefined;

    const first_len = try plainCompound(&first);
    const second_len = try plainCompound(&second);

    const first_protected = try pair.sender.protect(&first, first_len);
    const second_protected = try pair.sender.protect(&second, second_len);

    try std.testing.expect(!std.mem.eql(
        u8,
        first_protected[ENCRYPTED_FROM..first_len],
        second_protected[ENCRYPTED_FROM..second_len],
    ));
}

test "zix media: srtcp, the short tag profile still tags rtcp with ten bytes" {
    // The trap RFC 5764 4.1.2 sets: one profile, two tag lengths.
    var sender = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT);
    var receiver = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT);

    try std.testing.expectEqual(@as(usize, 10), sender.tag_len);
    try std.testing.expectEqual(@as(usize, INDEX_LEN + 10), sender.overhead());

    var buffer: [64]u8 = undefined;
    const packet_len = try plainCompound(&buffer);
    const protected = try sender.protect(&buffer, packet_len);

    try std.testing.expectEqual(packet_len + INDEX_LEN + 10, protected.len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);
    _ = try receiver.unprotect(received[0..protected.len]);
}

test "zix media: srtcp, the control keys are not the media keys" {
    var control = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT);
    const media = srtp_key.rtpKeys(TEST_MASTER_KEY, TEST_MASTER_SALT);

    try std.testing.expect(!std.mem.eql(u8, &control.keys.cipher_key, &media.cipher_key));
    try std.testing.expect(!std.mem.eql(u8, &control.keys.auth_key, &media.auth_key));
    try std.testing.expect(!std.mem.eql(u8, &control.keys.cipher_salt, &media.cipher_salt));
}

test "zix media: srtcp init, a profile with no keys is refused" {
    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        Session.init(.SRTP_NULL_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT),
    );
}

test "zix media: srtcp protect, the limits are refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainCompound(&buffer);

    // No room for the index and the tag.
    try std.testing.expectError(error.ZixNoSpace, pair.sender.protect(buffer[0 .. packet_len + 5], packet_len));

    // Shorter than a common header and a sender identifier.
    try std.testing.expectError(error.ZixTruncated, pair.sender.protect(&buffer, 7));
    try std.testing.expectError(error.ZixTruncated, pair.sender.protect(&buffer, buffer.len + 1));
}

test "zix media: srtcp protect, an exhausted index is refused rather than reused" {
    var session = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT);
    session.send_index = MAX_INDEX;

    var buffer: [64]u8 = undefined;
    const packet_len = try plainCompound(&buffer);

    // The last legal index still goes out.
    _ = try session.protect(&buffer, packet_len);

    // The next one does not, because reusing an index reuses a counter block.
    var again: [64]u8 = undefined;
    const again_len = try plainCompound(&again);

    try std.testing.expectError(error.ZixIndexExhausted, session.protect(&again, again_len));
}

test "zix media: srtcp unprotect, a packet too short for the trailer is refused" {
    var pair = try Pair.open();
    var packet: [16]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, pair.receiver.unprotect(&packet));
    try std.testing.expectError(error.ZixTruncated, pair.receiver.unprotect(packet[0..4]));
}

test "zix media: srtcp, packets arriving out of order both open" {
    var pair = try Pair.open();

    var packets: [3][64]u8 = undefined;
    var lengths: [3]usize = undefined;

    for (0..3) |index| {
        const packet_len = try plainCompound(&packets[index]);
        const protected = try pair.sender.protect(&packets[index], packet_len);
        lengths[index] = protected.len;
    }

    _ = try pair.receiver.unprotect(packets[2][0..lengths[2]]);
    _ = try pair.receiver.unprotect(packets[0][0..lengths[0]]);
    _ = try pair.receiver.unprotect(packets[1][0..lengths[1]]);

    try std.testing.expectError(error.ZixReplayed, pair.receiver.unprotect(packets[1][0..lengths[1]]));
}
