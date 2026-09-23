//! zix SRTP forwarding without decoding (RFC 3711 3.1, RFC 3550 5.1).
//!
//! What:
//! - Moving one media packet from the peer that sent it to a peer that wants it. The payload is
//!   opened, rewritten nowhere, and sealed again under the receiving peer's key.
//!
//! Note:
//! - Every peer has its own DTLS association and therefore its own SRTP keys, so a packet CANNOT
//!   be passed along as it arrived. It has to be opened with the sender's key and sealed with the
//!   receiver's. That is the one unavoidable cost of forwarding, and it is why this file exists
//!   rather than a socket write.
//! - The payload is never looked at. zix carries no codecs, so between opening and sealing the
//!   bytes are copied nowhere and read by nothing. What changes is the header: the stream
//!   identifier, and the sequence and timestamp offsets that keep one output stream continuous
//!   across a change of source.
//! - RTCP is NOT forwarded. A report names streams by the identifiers they had before the
//!   rewrite, so relaying one tells the far side about a stream it has never seen. A forwarder
//!   answers the control path itself, which is what report.zig and feedback.zig are for.
//! - A downstream peer asks for a lost packet by the number it saw, which is not the number the
//!   source sent. `sourceSequence` turns one back into the other, and getting that backwards
//!   resends a packet nobody asked for.

const std = @import("std");

const rtp = @import("rtp.zig");
const srtp = @import("srtp.zig");

/// What stops a packet from being forwarded.
pub const Error = error{
    /// Too short to hold an RTP header, or a tag, or both.
    ZixTruncated,
    /// An RTP version other than 2.
    ZixUnsupportedVersion,
    /// No room in the buffer for the outgoing tag.
    ZixNoSpace,
    /// An index already accepted on the way in, or too old to tell apart from one.
    ZixReplayed,
    /// The incoming tag does not match, so the packet is not from the peer that holds the key.
    ZixAuthenticationFailed,
    /// A payload past what one counter block may cover.
    ZixSegmentTooLong,
};

/// How one source's numbering is presented to one destination.
///
/// Note:
/// - The offsets are wrapping, which is what lets one output stream stay continuous across a
///   source that starts wherever RTP happened to start it.
pub const Mapping = struct {
    /// The stream identifier every forwarded packet carries.
    ssrc: u32,
    /// Added to each incoming sequence number.
    sequence_offset: u16 = 0,
    /// Added to each incoming timestamp.
    timestamp_offset: u32 = 0,

    /// The sequence number a forwarded packet carries.
    ///
    /// Param:
    /// source_sequence - u16
    ///
    /// Return:
    /// - u16
    pub fn sequenceFor(self: Mapping, source_sequence: u16) u16 {
        return source_sequence +% self.sequence_offset;
    }

    /// The timestamp a forwarded packet carries.
    ///
    /// Param:
    /// source_timestamp - u32
    ///
    /// Return:
    /// - u32
    pub fn timestampFor(self: Mapping, source_timestamp: u32) u32 {
        return source_timestamp +% self.timestamp_offset;
    }

    /// The source's own sequence number, from one a destination named.
    ///
    /// Note:
    /// - This is the direction a retransmission request travels. A peer NACKs the number it saw,
    ///   and the packet to resend is held under the number the source sent.
    ///
    /// Param:
    /// forwarded_sequence - u16
    ///
    /// Return:
    /// - u16
    pub fn sourceSequence(self: Mapping, forwarded_sequence: u16) u16 {
        return forwarded_sequence -% self.sequence_offset;
    }

    /// The offsets that make `first_forwarded` the number `first_source` comes out as.
    ///
    /// Note:
    /// - What a forwarder computes when it switches which source feeds one output stream: the
    ///   new source picks up exactly where the old one stopped.
    ///
    /// Param:
    /// ssrc - u32 (the identifier the output stream keeps)
    /// first_source - rtp.Header (the first packet of the new source)
    /// next_sequence - u16 (the number the output stream is due to send)
    /// next_timestamp - u32 (the timestamp the output stream is due to send)
    ///
    /// Return:
    /// - Mapping
    pub fn continuing(
        ssrc: u32,
        first_source: rtp.Header,
        next_sequence: u16,
        next_timestamp: u32,
    ) Mapping {
        return .{
            .ssrc = ssrc,
            .sequence_offset = next_sequence -% first_source.sequence,
            .timestamp_offset = next_timestamp -% first_source.timestamp,
        };
    }
};

/// Open a packet from one peer and seal it for another.
///
/// Note:
/// - Works in place. `buffer` holds the protected incoming packet at its start and needs room
///   behind it for the outgoing tag, which is not always the same size as the incoming one.
/// - The incoming packet is opened first, so a forged one is refused before any work is done on
///   behalf of the destination.
/// - One destination. A packet going to a room is opened once with `open` and sealed once per
///   member with `reseal`, because opening it a second time is a replay of an index the source
///   stream has already accepted.
///
/// Param:
/// source - *srtp.Session (the sending peer's stream, opened for reading)
/// destination - *srtp.Session (the receiving peer's stream, opened for writing)
/// mapping - Mapping (how the source's numbering is presented downstream)
/// buffer - []u8 (working buffer, rewritten in place)
/// packet_len - usize (how much of it is the protected incoming packet)
///
/// Return:
/// - []const u8, the packet to send to the destination
/// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixNoSpace, error.ZixReplayed,
///   error.ZixAuthenticationFailed, error.ZixSegmentTooLong
pub fn relay(
    source: *srtp.Session,
    destination: *srtp.Session,
    mapping: Mapping,
    buffer: []u8,
    packet_len: usize,
) Error![]const u8 {
    const opened = try open(source, buffer, packet_len);

    return reseal(destination, mapping, buffer, opened.len);
}

/// Open one packet from the peer that sent it.
///
/// Note:
/// - Works in place, and the plain packet is shorter than what came in.
///
/// Param:
/// source - *srtp.Session (the sending peer's stream, opened for reading)
/// buffer - []u8 (working buffer, rewritten in place)
/// packet_len - usize (how much of it is the protected incoming packet)
///
/// Return:
/// - []const u8, the plain packet, borrowing `buffer`
/// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixReplayed, error.ZixAuthenticationFailed,
///   error.ZixSegmentTooLong
pub fn open(source: *srtp.Session, buffer: []u8, packet_len: usize) Error![]const u8 {
    if (packet_len > buffer.len) return error.ZixTruncated;

    return source.unprotect(buffer[0..packet_len]);
}

/// Renumber an opened packet for one destination and seal it under that destination's key.
///
/// Note:
/// - `buffer` holds the plain packet at its start and needs room behind it for the outgoing tag.
/// - The whole cost of a fan-out is here. What goes to each member of a room is a different
///   ciphertext, because no two members share a key.
///
/// Param:
/// destination - *srtp.Session (the receiving peer's stream, opened for writing)
/// mapping - Mapping (how the source's numbering is presented to this destination)
/// buffer - []u8 (working buffer, rewritten in place)
/// body_len - usize (how much of it is the plain packet)
///
/// Return:
/// - []const u8, the packet to send to the destination
/// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixNoSpace, error.ZixSegmentTooLong
pub fn reseal(
    destination: *srtp.Session,
    mapping: Mapping,
    buffer: []u8,
    body_len: usize,
) Error![]const u8 {
    if (body_len > buffer.len) return error.ZixTruncated;

    const header = (try rtp.read(buffer[0..body_len])).header;

    try rtp.setSsrc(buffer[0..body_len], mapping.ssrc);
    try rtp.setSequence(buffer[0..body_len], mapping.sequenceFor(header.sequence));
    try rtp.setTimestamp(buffer[0..body_len], mapping.timestampFor(header.timestamp));

    return destination.protect(buffer, body_len);
}

/// How large a buffer `relay` needs for a packet of a given size.
///
/// Param:
/// packet_len - usize (the protected incoming packet)
/// destination - srtp.Session
///
/// Return:
/// - usize
pub fn bufferLenFor(packet_len: usize, destination: srtp.Session) usize {
    return packet_len + destination.overhead();
}

// --------------------------------------------------------------------------------------- //
// test cases

const exporter = @import("../../../tls/dtls_exporter.zig");
const srtp_key = @import("srtp_key.zig");

const SENDER_MASTER_KEY: [srtp_key.MASTER_KEY_LEN]u8 = @splat(0x11);
const SENDER_MASTER_SALT: [srtp_key.MASTER_SALT_LEN]u8 = @splat(0x22);
const RECEIVER_MASTER_KEY: [srtp_key.MASTER_KEY_LEN]u8 = @splat(0x33);
const RECEIVER_MASTER_SALT: [srtp_key.MASTER_SALT_LEN]u8 = @splat(0x44);

/// One sender, the forwarder in the middle, and one receiver, each keyed as its own association.
const Relay = struct {
    /// The sending peer, which protects with its own key.
    sender: srtp.Session,
    /// The forwarder's view of the sending peer.
    inbound: srtp.Session,
    /// The forwarder's view of the receiving peer.
    outbound: srtp.Session,
    /// The receiving peer, which opens with its own key.
    receiver: srtp.Session,

    fn open(negotiated: exporter.SrtpProfile) !Relay {
        return .{
            .sender = try srtp.Session.init(negotiated, SENDER_MASTER_KEY, SENDER_MASTER_SALT),
            .inbound = try srtp.Session.init(negotiated, SENDER_MASTER_KEY, SENDER_MASTER_SALT),
            .outbound = try srtp.Session.init(negotiated, RECEIVER_MASTER_KEY, RECEIVER_MASTER_SALT),
            .receiver = try srtp.Session.init(negotiated, RECEIVER_MASTER_KEY, RECEIVER_MASTER_SALT),
        };
    }
};

/// Protect one packet as the sending peer would, into `buffer`.
fn sent(relay_pair: *Relay, buffer: []u8, sequence: u16, timestamp: u32, payload: []const u8) ![]const u8 {
    const written = try rtp.write(buffer, .{
        .payload_type = 96,
        .sequence = sequence,
        .timestamp = timestamp,
        .ssrc = 0x1111_1111,
    }, payload);

    return relay_pair.sender.protect(buffer, written.len);
}

test "zix media: forward relay, a packet crosses two associations unchanged" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const payload = "opaque media bytes";
    const protected = try sent(&pair, &buffer, 100, 9000, payload);
    const forwarded = try relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &buffer,
        protected.len,
    );

    var received: [128]u8 = undefined;
    @memcpy(received[0..forwarded.len], forwarded);

    const opened = try pair.receiver.unprotect(received[0..forwarded.len]);
    const parsed = try rtp.read(opened);

    // The payload came out the far side byte for byte, having been decrypted and re-encrypted
    // under a different key and never read.
    try std.testing.expectEqualStrings(payload, parsed.payload);
    try std.testing.expectEqual(@as(u32, 0x2222_2222), parsed.header.ssrc);
    try std.testing.expectEqual(@as(u16, 100), parsed.header.sequence);
    try std.testing.expectEqual(@as(u32, 9000), parsed.header.timestamp);
}

test "zix media: forward relay, the receiving peer cannot open the sender's own packet" {
    // The reason a forwarder has to re-protect at all: the two peers share no key.
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "not for you");

    var received: [128]u8 = undefined;
    @memcpy(received[0..protected.len], protected);

    try std.testing.expectError(
        error.ZixAuthenticationFailed,
        pair.receiver.unprotect(received[0..protected.len]),
    );
}

test "zix media: forward relay, the ciphertext on the two sides is not the same" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "sixteen bytes ok");
    var inbound_copy: [128]u8 = undefined;
    @memcpy(inbound_copy[0..protected.len], protected);

    const forwarded = try relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &buffer,
        protected.len,
    );

    const payload_at = rtp.FIXED_HEADER_LEN;
    const payload_len = 16;

    try std.testing.expect(!std.mem.eql(
        u8,
        inbound_copy[payload_at..][0..payload_len],
        forwarded[payload_at..][0..payload_len],
    ));
}

test "zix media: forward relay, a forged packet never reaches the destination" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const written = try rtp.write(&buffer, .{
        .payload_type = 96,
        .sequence = 5,
        .timestamp = 0,
        .ssrc = 0x1111_1111,
    }, "forged");

    @memset(buffer[written.len..][0..10], 0xFF);

    try std.testing.expectError(error.ZixAuthenticationFailed, relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &buffer,
        written.len + 10,
    ));

    // Nothing went out, so the destination's own numbering has not moved.
    try std.testing.expectEqual(@as(u32, 0), pair.outbound.index.roc);
    try std.testing.expect(!pair.outbound.index.started);
}

test "zix media: forward relay, a replayed packet is stopped at the inbound side" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;
    var again: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "once");
    @memcpy(again[0..protected.len], protected);
    const packet_len = protected.len;

    _ = try relay(&pair.inbound, &pair.outbound, .{ .ssrc = 0x2222_2222 }, &buffer, packet_len);

    try std.testing.expectError(error.ZixReplayed, relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &again,
        packet_len,
    ));
}

test "zix media: forward mapping, an offset renumbers both ways" {
    const mapping = Mapping{ .ssrc = 7, .sequence_offset = 1000, .timestamp_offset = 90000 };

    try std.testing.expectEqual(@as(u16, 1100), mapping.sequenceFor(100));
    try std.testing.expectEqual(@as(u32, 99000), mapping.timestampFor(9000));

    // And back the way a retransmission request travels.
    try std.testing.expectEqual(@as(u16, 100), mapping.sourceSequence(1100));
    try std.testing.expectEqual(@as(u16, 100), mapping.sourceSequence(mapping.sequenceFor(100)));
}

test "zix media: forward mapping, the offsets wrap with their fields" {
    const mapping = Mapping{ .ssrc = 7, .sequence_offset = 10, .timestamp_offset = 10 };

    try std.testing.expectEqual(@as(u16, 5), mapping.sequenceFor(65531));
    try std.testing.expectEqual(@as(u32, 5), mapping.timestampFor(0xFFFFFFFB));
    try std.testing.expectEqual(@as(u16, 65531), mapping.sourceSequence(5));
}

test "zix media: forward mapping continuing, a new source picks up where the old one stopped" {
    // A layer switch: the output stream has sent up to 500 and is due to send 501, and the new
    // source happens to start its own numbering at 20000.
    const first = rtp.Header{
        .has_padding = false,
        .has_extension = false,
        .csrc_count = 0,
        .marker = false,
        .payload_type = 96,
        .sequence = 20000,
        .timestamp = 777000,
        .ssrc = 0x3333_3333,
    };

    const mapping = Mapping.continuing(0x2222_2222, first, 501, 45000);

    try std.testing.expectEqual(@as(u16, 501), mapping.sequenceFor(20000));
    try std.testing.expectEqual(@as(u32, 45000), mapping.timestampFor(777000));
    try std.testing.expectEqual(@as(u16, 502), mapping.sequenceFor(20001));
}

test "zix media: forward relay, a source switch is invisible downstream" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);

    // The first source runs from 100, and the mapping leaves it alone.
    var buffer: [128]u8 = undefined;
    const first_protected = try sent(&pair, &buffer, 100, 9000, "first source");
    const first_forwarded = try relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &buffer,
        first_protected.len,
    );

    var received: [128]u8 = undefined;
    @memcpy(received[0..first_forwarded.len], first_forwarded);
    const first_out = try rtp.read(try pair.receiver.unprotect(received[0..first_forwarded.len]));

    try std.testing.expectEqual(@as(u16, 100), first_out.header.sequence);

    // A second source starts at 40000, and the mapping makes it look like 101.
    var second_pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    second_pair.outbound = pair.outbound;

    const switched = Mapping.continuing(0x2222_2222, .{
        .has_padding = false,
        .has_extension = false,
        .csrc_count = 0,
        .marker = false,
        .payload_type = 96,
        .sequence = 40000,
        .timestamp = 500000,
        .ssrc = 0x1111_1111,
    }, first_out.header.sequence + 1, first_out.header.timestamp + 3000);

    var second_buffer: [128]u8 = undefined;
    const second_protected = try sent(&second_pair, &second_buffer, 40000, 500000, "second source");
    const second_forwarded = try relay(
        &second_pair.inbound,
        &second_pair.outbound,
        switched,
        &second_buffer,
        second_protected.len,
    );

    @memcpy(received[0..second_forwarded.len], second_forwarded);
    const second_out = try rtp.read(try pair.receiver.unprotect(received[0..second_forwarded.len]));

    // One continuous stream, from the receiver's side: same identifier, next number, clock moved
    // forward rather than jumping.
    try std.testing.expectEqual(@as(u32, 0x2222_2222), second_out.header.ssrc);
    try std.testing.expectEqual(@as(u16, 101), second_out.header.sequence);
    try std.testing.expectEqual(@as(u32, 12000), second_out.header.timestamp);
    try std.testing.expectEqualStrings("second source", second_out.payload);
}

test "zix media: forward relay, a stream of packets keeps its order downstream" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);

    for (0..8) |step| {
        var buffer: [128]u8 = undefined;
        const sequence: u16 = @intCast(200 + step);
        const protected = try sent(&pair, &buffer, sequence, @intCast(1000 * step), "frame");

        const forwarded = try relay(
            &pair.inbound,
            &pair.outbound,
            .{ .ssrc = 0x2222_2222, .sequence_offset = 65333 },
            &buffer,
            protected.len,
        );

        var received: [128]u8 = undefined;
        @memcpy(received[0..forwarded.len], forwarded);

        const parsed = try rtp.read(try pair.receiver.unprotect(received[0..forwarded.len]));
        try std.testing.expectEqual(sequence +% 65333, parsed.header.sequence);
        try std.testing.expectEqualStrings("frame", parsed.payload);
    }

    // The offset puts the first packet at 65533, so the renumbered stream wraps partway through
    // and both ends have to reach the same rollover counter on their own.
    try std.testing.expectEqual(@as(u32, 1), pair.outbound.index.roc);
    try std.testing.expectEqual(@as(u32, 1), pair.receiver.index.roc);
}

test "zix media: forward relay, tag lengths may differ between the two peers" {
    // Nothing says two associations negotiated the same profile, so the outgoing packet is not
    // always the same length as the incoming one.
    var sender = try srtp.Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, SENDER_MASTER_KEY, SENDER_MASTER_SALT);
    var inbound = try srtp.Session.init(.SRTP_AES128_CM_HMAC_SHA1_32, SENDER_MASTER_KEY, SENDER_MASTER_SALT);
    var outbound = try srtp.Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, RECEIVER_MASTER_KEY, RECEIVER_MASTER_SALT);
    var receiver = try srtp.Session.init(.SRTP_AES128_CM_HMAC_SHA1_80, RECEIVER_MASTER_KEY, RECEIVER_MASTER_SALT);

    var buffer: [128]u8 = undefined;
    const written = try rtp.write(&buffer, .{
        .payload_type = 96,
        .sequence = 1,
        .timestamp = 0,
        .ssrc = 0x1111_1111,
    }, "mixed profiles");

    const body_len = written.len;
    const protected = try sender.protect(&buffer, body_len);

    try std.testing.expectEqual(body_len + 4, protected.len);

    const forwarded = try relay(&inbound, &outbound, .{ .ssrc = 0x2222_2222 }, &buffer, protected.len);

    try std.testing.expectEqual(body_len + 10, forwarded.len);

    var received: [128]u8 = undefined;
    @memcpy(received[0..forwarded.len], forwarded);

    try std.testing.expectEqualStrings("mixed profiles", (try rtp.read(try receiver.unprotect(received[0..forwarded.len]))).payload);
}

test "zix media: forward relay, a buffer with no room for the outgoing tag is refused" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "needs room");
    const packet_len = protected.len;

    // Exactly the incoming length, so opening it frees 10 bytes and sealing it wants 10 back.
    // That fits. One byte less does not.
    var tight: [128]u8 = undefined;
    @memcpy(tight[0..packet_len], buffer[0..packet_len]);

    try std.testing.expectError(error.ZixTruncated, relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        tight[0 .. packet_len - 1],
        packet_len,
    ));
}

test "zix media: forward open then reseal, the two halves do what relay does in one call" {
    var split = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var whole = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);

    var split_buf: [128]u8 = undefined;
    var whole_buf: [128]u8 = undefined;

    const split_protected = try sent(&split, &split_buf, 42, 9000, "same both ways");
    const whole_protected = try sent(&whole, &whole_buf, 42, 9000, "same both ways");

    const opened = try open(&split.inbound, &split_buf, split_protected.len);
    const by_halves = try reseal(&split.outbound, .{ .ssrc = 0x2222_2222 }, &split_buf, opened.len);

    const at_once = try relay(
        &whole.inbound,
        &whole.outbound,
        .{ .ssrc = 0x2222_2222 },
        &whole_buf,
        whole_protected.len,
    );

    try std.testing.expectEqualSlices(u8, at_once, by_halves);
}

test "zix media: forward reseal, one packet goes to a room as one ciphertext per member" {
    // The shape a fan-out takes: opened once, because opening it twice is a replay, and sealed
    // once per member, because no two members hold the same key.
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);

    const SECOND_MASTER_KEY: [srtp_key.MASTER_KEY_LEN]u8 = @splat(0x55);
    const SECOND_MASTER_SALT: [srtp_key.MASTER_SALT_LEN]u8 = @splat(0x66);

    var second_outbound = try srtp.Session.init(
        .SRTP_AES128_CM_HMAC_SHA1_80,
        SECOND_MASTER_KEY,
        SECOND_MASTER_SALT,
    );
    var second_receiver = try srtp.Session.init(
        .SRTP_AES128_CM_HMAC_SHA1_80,
        SECOND_MASTER_KEY,
        SECOND_MASTER_SALT,
    );

    var buffer: [128]u8 = undefined;
    const protected = try sent(&pair, &buffer, 100, 9000, "one to the room");

    const opened = try open(&pair.inbound, &buffer, protected.len);
    const body_len = opened.len;

    var plain: [128]u8 = undefined;
    @memcpy(plain[0..body_len], buffer[0..body_len]);

    var first_out: [128]u8 = undefined;
    @memcpy(first_out[0..body_len], plain[0..body_len]);
    const for_first = try reseal(&pair.outbound, .{ .ssrc = 0x2222_2222 }, &first_out, body_len);

    var second_out: [128]u8 = undefined;
    @memcpy(second_out[0..body_len], plain[0..body_len]);
    const for_second = try reseal(&second_outbound, .{ .ssrc = 0x2222_2222 }, &second_out, body_len);

    try std.testing.expect(!std.mem.eql(u8, for_first, for_second));

    // And each member opens its own copy and finds the payload the sender put in.
    var received: [128]u8 = undefined;
    @memcpy(received[0..for_first.len], for_first);
    try std.testing.expectEqualStrings(
        "one to the room",
        (try rtp.read(try pair.receiver.unprotect(received[0..for_first.len]))).payload,
    );

    @memcpy(received[0..for_second.len], for_second);
    try std.testing.expectEqualStrings(
        "one to the room",
        (try rtp.read(try second_receiver.unprotect(received[0..for_second.len]))).payload,
    );
}

test "zix media: forward open, a packet opened twice is refused the second time" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);

    var buffer: [128]u8 = undefined;
    var again: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "once only");
    @memcpy(again[0..protected.len], protected);
    const packet_len = protected.len;

    _ = try open(&pair.inbound, &buffer, packet_len);

    try std.testing.expectError(error.ZixReplayed, open(&pair.inbound, &again, packet_len));
}

test "zix media: forward bufferLenFor, it covers what relay writes" {
    var pair = try Relay.open(.SRTP_AES128_CM_HMAC_SHA1_80);
    var buffer: [128]u8 = undefined;

    const protected = try sent(&pair, &buffer, 1, 0, "sizing");
    const wanted = bufferLenFor(protected.len, pair.outbound);
    const forwarded = try relay(
        &pair.inbound,
        &pair.outbound,
        .{ .ssrc = 0x2222_2222 },
        &buffer,
        protected.len,
    );

    try std.testing.expect(forwarded.len <= wanted);
}
