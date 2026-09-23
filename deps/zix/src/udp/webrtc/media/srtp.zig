//! zix SRTP packet protection (RFC 3711 3.1, 3.3).
//!
//! What:
//! - One direction of one media stream: take a plain RTP packet and protect it, or take a
//!   protected one and give the plain packet back. Everything below is already built, this is the
//!   order the pieces go in.
//!
//! Note:
//! - The RTP header stays in the clear. Only the payload is encrypted, and the tag covers header
//!   and payload together, which is what lets a forwarder read a sequence number without holding
//!   the key of the stream it is reading.
//! - Order matters on the way in: check the replay list, then verify the tag, then decrypt, then
//!   record the index. Decrypting first wastes work on forged packets, and recording first lets a
//!   forged index drag the rollover counter forward and lock out the real stream.
//! - Both directions work in place. A forwarder handles every packet twice, once to open and once
//!   to re-protect, and copying the payload each time is work with nothing to show for it.
//! - There is one of these per direction per stream. Two directions share a master key but derive
//!   different session keys from it, and two streams under one key are separated only by their
//!   SSRC inside the counter block.

const std = @import("std");

const exporter = @import("../../../tls/dtls_exporter.zig");
const cipher = @import("srtp_cipher.zig");
const packet_index = @import("srtp_index.zig");
const profile = @import("profile.zig");
const rtp = @import("rtp.zig");
const srtp_auth = @import("srtp_auth.zig");
const srtp_key = @import("srtp_key.zig");

/// The most bytes protection adds to a packet.
pub const MAX_OVERHEAD: usize = srtp_auth.LONG_TAG_LEN;

/// What stops a stream from being opened.
pub const InitError = error{
    /// A profile with no keys to run on.
    ZixUnsupportedProfile,
};

/// What stops a packet from being protected.
pub const ProtectError = error{
    /// Too short to hold an RTP header.
    ZixTruncated,
    /// An RTP version other than 2.
    ZixUnsupportedVersion,
    /// No room in the buffer for the authentication tag.
    ZixNoSpace,
    /// A payload past what one counter block may cover.
    ZixSegmentTooLong,
};

/// What stops a packet from being opened.
pub const OpenError = error{
    /// Too short to hold an RTP header and a tag.
    ZixTruncated,
    /// An RTP version other than 2.
    ZixUnsupportedVersion,
    /// An index already accepted, or too old to tell apart from one.
    ZixReplayed,
    /// The tag does not match, so the packet is not from the peer that holds the key.
    ZixAuthenticationFailed,
    /// A payload past what one counter block may cover.
    ZixSegmentTooLong,
};

/// One direction of one stream.
pub const Session = struct {
    keys: srtp_key.SessionKeys,
    /// Tag length in bytes, fixed by the profile.
    tag_len: usize,
    /// The receiver-side rollover counter, or the sender-side wrap count.
    index: packet_index.Estimator,
    replay: packet_index.ReplayList,

    /// Derive the session keys and open a stream.
    ///
    /// Param:
    /// negotiated - exporter.SrtpProfile (what the DTLS handshake agreed on)
    /// master_key - [srtp_key.MASTER_KEY_LEN]u8 (one direction's key from the exporter)
    /// master_salt - [srtp_key.MASTER_SALT_LEN]u8 (that direction's salt)
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
            .keys = srtp_key.rtpKeys(master_key, master_salt),
            .tag_len = parameters.rtp_tag_len,
            .index = .{},
            .replay = .{},
        };
    }

    /// How many bytes protection adds.
    ///
    /// Return:
    /// - usize
    pub fn overhead(self: Session) usize {
        return self.tag_len;
    }

    /// Protect a packet in place (RFC 3711 3.3).
    ///
    /// Note:
    /// - `buffer` holds the plain packet at its start and must have `overhead()` bytes spare
    ///   behind it for the tag.
    ///
    /// Param:
    /// buffer - []u8 (working buffer, rewritten in place)
    /// packet_len - usize (how much of it is the plain packet)
    ///
    /// Return:
    /// - []const u8, the protected packet, longer than what went in
    /// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixNoSpace, error.ZixSegmentTooLong
    pub fn protect(self: *Session, buffer: []u8, packet_len: usize) ProtectError![]const u8 {
        if (packet_len > buffer.len) return error.ZixTruncated;
        if (buffer.len - packet_len < self.tag_len) return error.ZixNoSpace;

        const parsed = try rtp.read(buffer[0..packet_len]);
        const index = self.index.forSend(parsed.header.sequence);

        const block = cipher.counterBlock(self.keys.cipher_salt, parsed.header.ssrc, index.value());
        try cipher.apply(buffer[parsed.header_len..packet_len], self.keys.cipher_key, block);

        srtp_auth.tagRtp(
            buffer[packet_len..][0..self.tag_len],
            self.keys.auth_key,
            buffer[0..packet_len],
            index.roc,
        ) catch unreachable;

        return buffer[0 .. packet_len + self.tag_len];
    }

    /// Open a protected packet in place (RFC 3711 3.3).
    ///
    /// Param:
    /// packet - []u8 (one received packet, tag included, rewritten in place)
    ///
    /// Return:
    /// - []const u8, the plain packet, shorter than what came in
    /// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixReplayed, error.ZixAuthenticationFailed,
    ///   error.ZixSegmentTooLong
    pub fn unprotect(self: *Session, packet: []u8) OpenError![]const u8 {
        if (packet.len < rtp.FIXED_HEADER_LEN + self.tag_len) return error.ZixTruncated;

        const body_len = packet.len - self.tag_len;
        const parsed = try rtp.read(packet[0..body_len]);
        const index = self.index.estimate(parsed.header.sequence);

        if (!self.replay.isNew(index.value())) return error.ZixReplayed;

        srtp_auth.verifyRtp(
            packet[body_len..],
            self.keys.auth_key,
            packet[0..body_len],
            index.roc,
        ) catch |failure| return switch (failure) {
            error.ZixAuthenticationFailed => error.ZixAuthenticationFailed,
            error.ZixBadTagLength => unreachable,
        };

        const block = cipher.counterBlock(self.keys.cipher_salt, parsed.header.ssrc, index.value());
        try cipher.apply(packet[parsed.header_len..body_len], self.keys.cipher_key, block);

        self.index.accept(index);
        self.replay.accept(index.value());

        return packet[0..body_len];
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const TEST_MASTER_KEY: [srtp_key.MASTER_KEY_LEN]u8 = .{
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
};

const TEST_MASTER_SALT: [srtp_key.MASTER_SALT_LEN]u8 = .{
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE,
    0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
};

/// A sender and a receiver keyed alike, which is what one direction of a call looks like.
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

/// Build one plain RTP packet into `buffer` and return how long it is.
fn plainPacket(buffer: []u8, sequence: u16, payload: []const u8) !usize {
    const written = try rtp.write(buffer, .{
        .payload_type = 96,
        .sequence = sequence,
        .timestamp = 0x11223344,
        .ssrc = 0xDEADBEEF,
    }, payload);

    return written.len;
}

test "zix media: srtp protect, a packet opens back to what went in" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const payload = "media bytes, no codec involved";
    const packet_len = try plainPacket(&buffer, 1, payload);
    const original: [64]u8 = buffer;

    const protected = try pair.sender.protect(&buffer, packet_len);

    try std.testing.expectEqual(packet_len + 10, protected.len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    const opened = try pair.receiver.unprotect(received[0..protected.len]);

    try std.testing.expectEqualSlices(u8, original[0..packet_len], opened);
    try std.testing.expectEqualSlices(u8, payload, (try rtp.read(opened)).payload);
}

test "zix media: srtp protect, the header stays in the clear and the payload does not" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const payload = "encrypted from here on";
    const packet_len = try plainPacket(&buffer, 7, payload);
    const header: [rtp.FIXED_HEADER_LEN]u8 = buffer[0..rtp.FIXED_HEADER_LEN].*;

    const protected = try pair.sender.protect(&buffer, packet_len);

    // A forwarder reads the sequence number and the SSRC without any key at all.
    try std.testing.expectEqualSlices(u8, &header, protected[0..rtp.FIXED_HEADER_LEN]);
    try std.testing.expectEqual(@as(u16, 7), (try rtp.read(protected)).header.sequence);

    // And the payload is not the bytes that went in.
    try std.testing.expect(!std.mem.eql(u8, payload, protected[rtp.FIXED_HEADER_LEN..packet_len]));
}

test "zix media: srtp unprotect, a tampered payload is refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainPacket(&buffer, 1, "the bytes under the tag");
    const protected = try pair.sender.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);
    received[rtp.FIXED_HEADER_LEN] ^= 0x01;

    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));
}

test "zix media: srtp unprotect, a tampered header is refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainPacket(&buffer, 1, "header is authenticated too");
    const protected = try pair.sender.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    // The header is readable, which does not make it changeable.
    try rtp.setSsrc(received[0..protected.len], 0x0BADF00D);

    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));
}

test "zix media: srtp unprotect, a packet from the wrong key is refused" {
    var pair = try Pair.open();
    var other_salt = TEST_MASTER_SALT;
    other_salt[0] ^= 0x01;

    var stranger = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, other_salt);

    var buffer: [64]u8 = undefined;
    const packet_len = try plainPacket(&buffer, 1, "keyed differently");
    const protected = try stranger.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    try std.testing.expectError(error.ZixAuthenticationFailed, pair.receiver.unprotect(received[0..protected.len]));
}

test "zix media: srtp unprotect, the same packet twice is refused" {
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const packet_len = try plainPacket(&buffer, 1, "replay me");
    const protected = try pair.sender.protect(&buffer, packet_len);

    var first: [64]u8 = undefined;
    var second: [64]u8 = undefined;
    @memcpy(first[0..protected.len], protected);
    @memcpy(second[0..protected.len], protected);

    _ = try pair.receiver.unprotect(first[0..protected.len]);

    try std.testing.expectError(error.ZixReplayed, pair.receiver.unprotect(second[0..protected.len]));
}

test "zix media: srtp unprotect, a forged packet leaves the counter alone" {
    // The ordering this file is built around: a packet that fails the tag must not move the
    // rollover counter, or the genuine stream behind it stops opening.
    var pair = try Pair.open();
    var buffer: [64]u8 = undefined;

    const first_len = try plainPacket(&buffer, 1, "genuine");
    const first = try pair.sender.protect(&buffer, first_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..first.len], first);
    _ = try pair.receiver.unprotect(received[0..first.len]);

    // A forgery claiming a sequence number far ahead, which would wrap the counter if accepted.
    var forged: [64]u8 = undefined;
    const forged_len = try plainPacket(&forged, 40000, "forged");
    @memset(forged[forged_len..][0..10], 0xFF);

    try std.testing.expectError(
        error.ZixAuthenticationFailed,
        pair.receiver.unprotect(forged[0 .. forged_len + 10]),
    );

    // The next genuine packet still opens.
    var next_buffer: [64]u8 = undefined;
    const next_len = try plainPacket(&next_buffer, 2, "still genuine");
    const next = try pair.sender.protect(&next_buffer, next_len);

    @memcpy(received[0..next.len], next);
    const opened = try pair.receiver.unprotect(received[0..next.len]);

    try std.testing.expectEqualStrings("still genuine", (try rtp.read(opened)).payload);
}

test "zix media: srtp, a stream that wraps its sequence number keeps opening" {
    var pair = try Pair.open();

    // The rollover counter is not on the wire, so both sides have to reach the same one on their
    // own. This is the case that proves they do.
    const sequences = [_]u16{ 65533, 65534, 65535, 0, 1, 2 };

    for (sequences) |sequence| {
        var buffer: [64]u8 = undefined;
        const packet_len = try plainPacket(&buffer, sequence, "across the wrap");
        const protected = try pair.sender.protect(&buffer, packet_len);

        var received: [64]u8 = undefined;
        @memcpy(received[0..protected.len], protected);

        const opened = try pair.receiver.unprotect(received[0..protected.len]);
        try std.testing.expectEqualStrings("across the wrap", (try rtp.read(opened)).payload);
    }

    try std.testing.expectEqual(@as(u32, 1), pair.sender.index.roc);
    try std.testing.expectEqual(@as(u32, 1), pair.receiver.index.roc);
}

test "zix media: srtp, two packets never share keystream" {
    var pair = try Pair.open();

    var first: [64]u8 = undefined;
    var second: [64]u8 = undefined;

    const payload = "identical payload bytes";
    const first_len = try plainPacket(&first, 1, payload);
    const second_len = try plainPacket(&second, 2, payload);

    const first_protected = try pair.sender.protect(&first, first_len);
    const second_protected = try pair.sender.protect(&second, second_len);

    // Same payload, different index, so the ciphertext must differ. Two packets that encrypted
    // alike would hand an attacker the exclusive-or of the plaintexts.
    try std.testing.expect(!std.mem.eql(
        u8,
        first_protected[rtp.FIXED_HEADER_LEN..first_len],
        second_protected[rtp.FIXED_HEADER_LEN..second_len],
    ));
}

test "zix media: srtp, the short tag profile writes four bytes and still opens" {
    var sender = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT);
    var receiver = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT);

    try std.testing.expectEqual(@as(usize, 4), sender.overhead());

    var buffer: [64]u8 = undefined;
    const packet_len = try plainPacket(&buffer, 1, "four byte tag");
    const protected = try sender.protect(&buffer, packet_len);

    try std.testing.expectEqual(packet_len + 4, protected.len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    try std.testing.expectEqualStrings("four byte tag", (try rtp.read(try receiver.unprotect(received[0..protected.len]))).payload);
}

test "zix media: srtp, the two profiles cannot open each other's packets" {
    var sender = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT);
    var receiver = try Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_MASTER_KEY, TEST_MASTER_SALT);

    var buffer: [64]u8 = undefined;
    const packet_len = try plainPacket(&buffer, 1, "tag length disagreement");
    const protected = try sender.protect(&buffer, packet_len);

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    // The receiver takes the last four bytes as the tag and the rest as the packet, so nothing
    // lines up. This is what a mismatched negotiation looks like on the wire.
    try std.testing.expectError(
        error.ZixAuthenticationFailed,
        receiver.unprotect(received[0..protected.len]),
    );
}

test "zix media: srtp init, a profile with no keys is refused" {
    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        Session.init(.SRTP_NULL_HMAC_SHA1_80, TEST_MASTER_KEY, TEST_MASTER_SALT),
    );
}

test "zix media: srtp protect, a buffer with no room for the tag is refused" {
    var pair = try Pair.open();
    var buffer: [24]u8 = undefined;

    const packet_len = try plainPacket(&buffer, 1, "twelve bytes");

    try std.testing.expectEqual(@as(usize, 24), packet_len);
    try std.testing.expectError(error.ZixNoSpace, pair.sender.protect(&buffer, packet_len));
    try std.testing.expectError(error.ZixTruncated, pair.sender.protect(&buffer, buffer.len + 1));
}

test "zix media: srtp unprotect, a packet too short to hold a header and a tag is refused" {
    var pair = try Pair.open();
    var packet: [20]u8 = @splat(0);
    packet[0] = 0x80;

    try std.testing.expectError(error.ZixTruncated, pair.receiver.unprotect(&packet));
    try std.testing.expectError(error.ZixTruncated, pair.receiver.unprotect(packet[0..4]));
}

test "zix media: srtp unprotect, a packet that is not rtp is refused" {
    var pair = try Pair.open();
    var packet: [32]u8 = @splat(0);

    // Version 1, which no RTP packet carries.
    packet[0] = 0x40;

    try std.testing.expectError(error.ZixUnsupportedVersion, pair.receiver.unprotect(&packet));
}

test "zix media: srtp, a packet with a csrc list encrypts from the right place" {
    var pair = try Pair.open();

    var buffer: [64]u8 = @splat(0);
    const payload = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // Two contributing sources, so the header runs to 20 bytes and not 12.
    buffer[0] = 0x82;
    buffer[1] = 96;
    std.mem.writeInt(u16, buffer[2..4], 3, .big);
    std.mem.writeInt(u32, buffer[8..12], 0xDEADBEEF, .big);
    std.mem.writeInt(u32, buffer[12..16], 0x01020304, .big);
    std.mem.writeInt(u32, buffer[16..20], 0x05060708, .big);
    @memcpy(buffer[20..24], &payload);

    const csrc: [8]u8 = buffer[12..20].*;
    const protected = try pair.sender.protect(&buffer, 24);

    // The contributing sources are header, so they stay readable.
    try std.testing.expectEqualSlices(u8, &csrc, protected[12..20]);
    try std.testing.expect(!std.mem.eql(u8, &payload, protected[20..24]));

    var received: [64]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    const opened = try pair.receiver.unprotect(received[0..protected.len]);
    try std.testing.expectEqualSlices(u8, &payload, (try rtp.read(opened)).payload);
}

test "zix media: srtp, a header-only packet protects and opens" {
    var pair = try Pair.open();
    var buffer: [32]u8 = undefined;

    const packet_len = try plainPacket(&buffer, 1, &.{});
    const protected = try pair.sender.protect(&buffer, packet_len);

    try std.testing.expectEqual(@as(usize, rtp.FIXED_HEADER_LEN + 10), protected.len);

    var received: [32]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    const opened = try pair.receiver.unprotect(received[0..protected.len]);
    try std.testing.expectEqual(@as(usize, 0), (try rtp.read(opened)).payload.len);
}

test "zix media: srtp unprotect, an out-of-order packet still opens" {
    var pair = try Pair.open();

    var packets: [3][64]u8 = undefined;
    var lengths: [3]usize = undefined;

    for (0..3) |index| {
        const packet_len = try plainPacket(&packets[index], @intCast(10 + index), "reordered");
        const protected = try pair.sender.protect(&packets[index], packet_len);
        lengths[index] = protected.len;
    }

    // Delivered 2, 0, 1, which is ordinary on a lossy path.
    _ = try pair.receiver.unprotect(packets[2][0..lengths[2]]);
    _ = try pair.receiver.unprotect(packets[0][0..lengths[0]]);
    _ = try pair.receiver.unprotect(packets[1][0..lengths[1]]);

    try std.testing.expectEqual(@as(u16, 12), pair.receiver.index.highest_sequence);
}
