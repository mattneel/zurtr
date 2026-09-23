//! zix media state of one WebRTC peer (RFC 5764 4.2, RFC 7667 3.7).
//!
//! What:
//! - Everything one peer needs before a media packet can cross it: the keys its DTLS handshake
//!   exported, one SRTP session per stream in each direction, and which source feeds it.
//! - Two calls carry a packet through a forwarder. `open` takes what this peer sent and gives the
//!   plain packet back. `sealFor` takes a plain packet from somebody else and gives back the
//!   datagram this peer can open.
//!
//! Note:
//! - zix always answers the handshake, so the peer is always the DTLS client. That fixes which
//!   half of the exported keys is which: the client write key opens what arrives, the server write
//!   key seals what leaves. Swapping them authenticates nothing and looks exactly like a peer
//!   sending garbage.
//! - A packet is opened ONCE and sealed once per receiver. Opening it a second time is a replay of
//!   an index the source stream has already accepted, so a room is served by one `open` on the
//!   sender and one `sealFor` on each member.
//! - Nothing here reads the payload. Between opening and sealing the bytes are copied and nothing
//!   else, which is what lets a forwarder carry a codec it has never heard of.

const std = @import("std");

const exporter = @import("../../../tls/dtls_exporter.zig");
const forward = @import("forward.zig");
const route = @import("route.zig");
const rtp = @import("rtp.zig");
const srtcp = @import("srtcp.zig");
const stream_set = @import("stream_set.zig");

/// Everything that stops a packet from crossing this peer.
pub const Error = stream_set.Error || route.Error || forward.Error ||
    srtcp.InitError || srtcp.ProtectError || srtcp.OpenError;

/// One opened packet, and the header it arrived with.
///
/// Note:
/// - `header` is the SOURCE's own header, before any renumbering. That is what `sealFor` needs,
///   because each receiver renumbers it differently.
pub const Opened = struct {
    header: rtp.Header,
    /// The plain packet, borrowing the caller's buffer.
    plain: []const u8,
};

/// One peer's media, both ways.
///
/// Usage:
/// ```zig
/// var media = try PeerMedia.init(profile, keys);
/// const opened = try media.open(buffer, packet_len);
///
/// const outgoing = try other_peer.media.sealFor(opened.header, other_buffer, opened.plain.len);
/// ```
pub const PeerMedia = struct {
    negotiated: exporter.SrtpProfile,
    /// Opens what this peer sends, keyed with the client write key.
    inbound: stream_set.StreamSet,
    /// Seals what goes to this peer, keyed with the server write key.
    outbound: stream_set.StreamSet,
    /// Opens the control packets this peer sends.
    control_in: srtcp.Session,
    /// Seals the control packets going to this peer.
    control_out: srtcp.Session,
    /// Which source feeds which of this peer's streams.
    routes: route.Table,

    /// Build one peer's media from what its handshake exported.
    ///
    /// Param:
    /// negotiated - exporter.SrtpProfile (the profile use_srtp agreed on)
    /// keys - exporter.SrtpKeys (the four values RFC 5764 4.2 splits out)
    ///
    /// Return:
    /// - PeerMedia with no stream open yet
    /// - error.ZixUnsupportedProfile
    pub fn init(negotiated: exporter.SrtpProfile, keys: exporter.SrtpKeys) Error!PeerMedia {
        return .{
            .negotiated = negotiated,
            .inbound = try stream_set.StreamSet.init(negotiated, keys.client_write_key, keys.client_write_salt),
            .outbound = try stream_set.StreamSet.init(negotiated, keys.server_write_key, keys.server_write_salt),
            .control_in = try srtcp.Session.init(negotiated, keys.client_write_key, keys.client_write_salt),
            .control_out = try srtcp.Session.init(negotiated, keys.server_write_key, keys.server_write_salt),
            .routes = .{},
        };
    }

    /// Open one media packet this peer sent.
    ///
    /// Note:
    /// - Works in place. The identifier is read from the header, which SRTP leaves in the clear,
    ///   so the right stream is picked before anything is decrypted.
    ///
    /// Param:
    /// buffer - []u8 (holds the protected packet at its start, rewritten in place)
    /// packet_len - usize (how much of it is the packet)
    ///
    /// Return:
    /// - Opened, borrowing `buffer`
    /// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixReplayed, error.ZixAuthenticationFailed,
    ///   error.ZixSegmentTooLong, error.ZixTooManyStreams, error.ZixUnsupportedProfile
    pub fn open(self: *PeerMedia, buffer: []u8, packet_len: usize) Error!Opened {
        if (packet_len > buffer.len) return error.ZixTruncated;

        const header = (try rtp.read(buffer[0..packet_len])).header;
        const stream = try self.inbound.sessionFor(header.ssrc);

        return .{
            .header = header,
            .plain = try forward.open(stream, buffer, packet_len),
        };
    }

    /// Seal one opened packet for this peer, on the route its source feeds.
    ///
    /// Note:
    /// - `buffer` holds the plain packet at its start and needs `overhead()` bytes spare behind it.
    /// - The route is admitted here on a source's first packet, so a receiver needs nothing said
    ///   about a sender before that sender speaks.
    ///
    /// Param:
    /// header - rtp.Header (the source's own header, from `open`)
    /// buffer - []u8 (holds the plain packet at its start, rewritten in place)
    /// body_len - usize (how much of it is the plain packet)
    ///
    /// Return:
    /// - []const u8, the datagram to send to this peer, borrowing `buffer`
    /// - error.ZixTruncated, error.ZixUnsupportedVersion, error.ZixNoSpace, error.ZixSegmentTooLong,
    ///   error.ZixTooManyStreams, error.ZixTooManyRoutes, error.ZixUnsupportedProfile
    pub fn sealFor(self: *PeerMedia, header: rtp.Header, buffer: []u8, body_len: usize) Error![]const u8 {
        const carried = try self.routes.admit(header.ssrc);
        const stream = try self.outbound.sessionFor(carried.mapping.ssrc);

        const packet = try forward.reseal(stream, carried.mapping, buffer, body_len);

        carried.sent(header);

        return packet;
    }

    /// Open one control packet this peer sent.
    ///
    /// Note:
    /// - A forwarder never passes a control packet along. Reports name streams by the numbers they
    ///   had before the rewrite, so relaying one tells the far side about a stream it has never
    ///   seen. What arrives here is read and answered, and that is all.
    ///
    /// Param:
    /// buffer - []u8 (holds the protected compound packet at its start, rewritten in place)
    /// packet_len - usize (how much of it is the packet)
    ///
    /// Return:
    /// - []const u8, the plain compound packet, borrowing `buffer`
    /// - error.ZixTruncated, error.ZixReplayed, error.ZixAuthenticationFailed, error.ZixSegmentTooLong
    pub fn openControl(self: *PeerMedia, buffer: []u8, packet_len: usize) Error![]const u8 {
        if (packet_len > buffer.len) return error.ZixTruncated;

        return self.control_in.unprotect(buffer[0..packet_len]);
    }

    /// Seal one control packet for this peer.
    ///
    /// Param:
    /// buffer - []u8 (holds the plain compound packet at its start, rewritten in place)
    /// body_len - usize (how much of it is the plain packet)
    ///
    /// Return:
    /// - []const u8, the datagram to send to this peer, borrowing `buffer`
    /// - error.ZixTruncated, error.ZixNoSpace, error.ZixSegmentTooLong, error.ZixIndexExhausted
    pub fn sealControl(self: *PeerMedia, buffer: []u8, body_len: usize) Error![]const u8 {
        return self.control_out.protect(buffer, body_len);
    }

    /// How many bytes sealing adds to a packet going to this peer.
    ///
    /// Return:
    /// - usize
    pub fn overhead(self: PeerMedia) usize {
        return self.outbound.overhead();
    }

    /// How many bytes sealing adds to a control packet going to this peer.
    ///
    /// Return:
    /// - usize
    pub fn controlOverhead(self: PeerMedia) usize {
        return self.control_out.overhead();
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const feedback = @import("feedback.zig");
const rtcp = @import("rtcp.zig");

const TEST_KEYS: exporter.SrtpKeys = .{
    .client_write_key = @splat(0x11),
    .server_write_key = @splat(0x22),
    .client_write_salt = @splat(0x33),
    .server_write_salt = @splat(0x44),
};

const OTHER_KEYS: exporter.SrtpKeys = .{
    .client_write_key = @splat(0x55),
    .server_write_key = @splat(0x66),
    .client_write_salt = @splat(0x77),
    .server_write_salt = @splat(0x88),
};

const PROFILE: exporter.SrtpProfile = .SRTP_AES128_CM_HMAC_SHA1_80;

/// The browser half of one peer: it writes with the client key and reads with the server key,
/// which is the mirror of what PeerMedia holds.
const Browser = struct {
    sending: stream_set.StreamSet,
    receiving: stream_set.StreamSet,
    control_sending: srtcp.Session,
    control_receiving: srtcp.Session,

    fn init(keys: exporter.SrtpKeys) !Browser {
        return .{
            .sending = try stream_set.StreamSet.init(PROFILE, keys.client_write_key, keys.client_write_salt),
            .receiving = try stream_set.StreamSet.init(PROFILE, keys.server_write_key, keys.server_write_salt),
            .control_sending = try srtcp.Session.init(PROFILE, keys.client_write_key, keys.client_write_salt),
            .control_receiving = try srtcp.Session.init(PROFILE, keys.server_write_key, keys.server_write_salt),
        };
    }

    /// One protected packet, as this browser would send it.
    fn send(self: *Browser, buffer: []u8, ssrc: u32, sequence: u16, payload: []const u8) ![]const u8 {
        const written = try rtp.write(buffer, .{
            .payload_type = 96,
            .sequence = sequence,
            .timestamp = 90 * @as(u32, sequence),
            .ssrc = ssrc,
        }, payload);

        return (try self.sending.sessionFor(ssrc)).protect(buffer, written.len);
    }

    /// One packet opened, as this browser would receive it.
    fn receive(self: *Browser, buffer: []u8, packet_len: usize) !rtp.Packet {
        const ssrc = (try rtp.read(buffer[0..packet_len])).header.ssrc;

        return rtp.read(try (try self.receiving.sessionFor(ssrc)).unprotect(buffer[0..packet_len]));
    }

    /// One keyframe request, as this browser would send it.
    fn askForKeyframe(self: *Browser, buffer: []u8, own_ssrc: u32, media_ssrc: u32) ![]const u8 {
        const written = try feedback.writePictureLoss(buffer, own_ssrc, media_ssrc);

        return self.control_sending.protect(buffer, written.len);
    }

    /// One control packet opened, as this browser would receive it.
    fn receiveControl(self: *Browser, buffer: []u8, packet_len: usize) ![]const u8 {
        return self.control_receiving.unprotect(buffer[0..packet_len]);
    }
};

test "zix media: peer media init, a profile with no cipher is refused" {
    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        PeerMedia.init(.SRTP_NULL_HMAC_SHA1_32, TEST_KEYS),
    );
}

test "zix media: peer media open, what the peer sent comes back with its own header" {
    var sender = try Browser.init(TEST_KEYS);
    var media = try PeerMedia.init(PROFILE, TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 100, "camera bytes");

    const opened = try media.open(&buffer, protected.len);

    try std.testing.expectEqual(@as(u32, 0x1111_1111), opened.header.ssrc);
    try std.testing.expectEqual(@as(u16, 100), opened.header.sequence);
    try std.testing.expectEqualStrings("camera bytes", (try rtp.read(opened.plain)).payload);
}

test "zix media: peer media open, a packet keyed the other way is refused" {
    // The direction trap: a peer that sealed with the server key is not this peer sending.
    var stranger = try Browser.init(OTHER_KEYS);
    var media = try PeerMedia.init(PROFILE, TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try stranger.send(&buffer, 0x1111_1111, 1, "not from here");

    try std.testing.expectError(error.ZixAuthenticationFailed, media.open(&buffer, protected.len));
}

test "zix media: peer media, one packet crosses a forwarder to a peer keyed differently" {
    var sender = try Browser.init(TEST_KEYS);
    var receiver = try Browser.init(OTHER_KEYS);

    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var receiver_media = try PeerMedia.init(PROFILE, OTHER_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 100, "across the room");
    const opened = try sender_media.open(&buffer, protected.len);

    var outgoing: [256]u8 = undefined;
    @memcpy(outgoing[0..opened.plain.len], opened.plain);

    const sealed = try receiver_media.sealFor(opened.header, &outgoing, opened.plain.len);

    var received: [256]u8 = undefined;
    @memcpy(received[0..sealed.len], sealed);

    const arrived = try receiver.receive(&received, sealed.len);

    // The source's own identifier and numbering, since nothing has been renumbered, and the
    // payload the sender put in.
    try std.testing.expectEqual(@as(u32, 0x1111_1111), arrived.header.ssrc);
    try std.testing.expectEqual(@as(u16, 100), arrived.header.sequence);
    try std.testing.expectEqualStrings("across the room", arrived.payload);
}

test "zix media: peer media sealFor, a room takes one opened packet and gets a ciphertext each" {
    var sender = try Browser.init(TEST_KEYS);
    var first = try Browser.init(OTHER_KEYS);

    const THIRD_KEYS: exporter.SrtpKeys = .{
        .client_write_key = @splat(0x99),
        .server_write_key = @splat(0xAA),
        .client_write_salt = @splat(0xBB),
        .server_write_salt = @splat(0xCC),
    };

    var second = try Browser.init(THIRD_KEYS);

    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var first_media = try PeerMedia.init(PROFILE, OTHER_KEYS);
    var second_media = try PeerMedia.init(PROFILE, THIRD_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 7, "one to everybody");
    const opened = try sender_media.open(&buffer, protected.len);

    var plain: [256]u8 = undefined;
    @memcpy(plain[0..opened.plain.len], opened.plain);
    const body_len = opened.plain.len;

    var first_out: [256]u8 = undefined;
    @memcpy(first_out[0..body_len], plain[0..body_len]);
    const for_first = try first_media.sealFor(opened.header, &first_out, body_len);
    const first_len = for_first.len;

    var second_out: [256]u8 = undefined;
    @memcpy(second_out[0..body_len], plain[0..body_len]);
    const for_second = try second_media.sealFor(opened.header, &second_out, body_len);
    const second_len = for_second.len;

    try std.testing.expect(!std.mem.eql(u8, first_out[0..first_len], second_out[0..second_len]));

    try std.testing.expectEqualStrings("one to everybody", (try first.receive(&first_out, first_len)).payload);
    try std.testing.expectEqualStrings("one to everybody", (try second.receive(&second_out, second_len)).payload);
}

test "zix media: peer media sealFor, a stream of packets keeps its order at the receiver" {
    var sender = try Browser.init(TEST_KEYS);
    var receiver = try Browser.init(OTHER_KEYS);

    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var receiver_media = try PeerMedia.init(PROFILE, OTHER_KEYS);

    for (0..8) |step| {
        const sequence: u16 = @intCast(200 + step);

        var buffer: [256]u8 = undefined;
        const protected = try sender.send(&buffer, 0x1111_1111, sequence, "frame");
        const opened = try sender_media.open(&buffer, protected.len);

        var outgoing: [256]u8 = undefined;
        @memcpy(outgoing[0..opened.plain.len], opened.plain);

        const sealed = try receiver_media.sealFor(opened.header, &outgoing, opened.plain.len);
        const sealed_len = sealed.len;

        const arrived = try receiver.receive(&outgoing, sealed_len);

        try std.testing.expectEqual(sequence, arrived.header.sequence);
        try std.testing.expectEqualStrings("frame", arrived.payload);
    }

    // One route, one stream each way, and the last numbers it sent are the last it was given.
    try std.testing.expectEqual(@as(usize, 1), receiver_media.routes.live);
    try std.testing.expectEqual(@as(u16, 207), receiver_media.routes.find(0x1111_1111).?.last_sequence);
}

test "zix media: peer media sealFor, audio and video keep their own streams at the receiver" {
    var sender = try Browser.init(TEST_KEYS);
    var receiver = try Browser.init(OTHER_KEYS);

    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var receiver_media = try PeerMedia.init(PROFILE, OTHER_KEYS);

    const streams = [_]u32{ 0xAAAA_AAAA, 0xBBBB_BBBB };

    for (streams) |ssrc| {
        var buffer: [256]u8 = undefined;
        const protected = try sender.send(&buffer, ssrc, 100, "two of them");
        const opened = try sender_media.open(&buffer, protected.len);

        var outgoing: [256]u8 = undefined;
        @memcpy(outgoing[0..opened.plain.len], opened.plain);

        const sealed = try receiver_media.sealFor(opened.header, &outgoing, opened.plain.len);
        const sealed_len = sealed.len;

        try std.testing.expectEqual(ssrc, (try receiver.receive(&outgoing, sealed_len)).header.ssrc);
    }

    try std.testing.expectEqual(@as(usize, 2), receiver_media.routes.live);
    try std.testing.expectEqual(@as(usize, 2), receiver_media.outbound.live);
    try std.testing.expectEqual(@as(usize, 2), sender_media.inbound.live);

    // Nothing was ever sealed for the sender, and nothing was ever opened from the receiver.
    try std.testing.expectEqual(@as(usize, 0), sender_media.outbound.live);
    try std.testing.expectEqual(@as(usize, 0), receiver_media.inbound.live);
}

test "zix media: peer media openControl, a keyframe request comes back readable" {
    var receiver = try Browser.init(TEST_KEYS);
    var media = try PeerMedia.init(PROFILE, TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try receiver.askForKeyframe(&buffer, 0x9999_9999, 0x1111_1111);

    const compound = try media.openControl(&buffer, protected.len);
    var walk = try rtcp.begin(compound);
    const packet = walk.next().?;

    try std.testing.expectEqual(feedback.PayloadFormat.PLI, try feedback.payloadFormat(packet));
    try std.testing.expectEqual(@as(u32, 0x1111_1111), (try feedback.read(packet)).media_ssrc);
}

test "zix media: peer media sealControl, a keyframe request reaches the peer that has to answer" {
    // The control path a forwarder really runs: a receiver asks, and the sender is asked in its
    // own right rather than handed the receiver's packet.
    var sender = try Browser.init(TEST_KEYS);
    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const written = try feedback.writePictureLoss(&buffer, 0x0000_0001, 0x1111_1111);
    const sealed = try sender_media.sealControl(&buffer, written.len);
    const sealed_len = sealed.len;

    const compound = try sender.receiveControl(&buffer, sealed_len);
    var walk = try rtcp.begin(compound);
    const packet = walk.next().?;

    try std.testing.expectEqual(feedback.PayloadFormat.PLI, try feedback.payloadFormat(packet));
    try std.testing.expectEqual(@as(u32, 0x1111_1111), (try feedback.read(packet)).media_ssrc);
}

test "zix media: peer media openControl, a control packet keyed the other way is refused" {
    var stranger = try Browser.init(OTHER_KEYS);
    var media = try PeerMedia.init(PROFILE, TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try stranger.askForKeyframe(&buffer, 0x9999_9999, 0x1111_1111);

    try std.testing.expectError(error.ZixAuthenticationFailed, media.openControl(&buffer, protected.len));
}

test "zix media: peer media overhead, it covers what sealFor writes" {
    var sender = try Browser.init(TEST_KEYS);
    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var receiver_media = try PeerMedia.init(PROFILE, OTHER_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 1, "sizing");
    const opened = try sender_media.open(&buffer, protected.len);
    const body_len = opened.plain.len;

    var outgoing: [256]u8 = undefined;
    @memcpy(outgoing[0..body_len], opened.plain);

    const sealed = try receiver_media.sealFor(opened.header, &outgoing, body_len);

    try std.testing.expectEqual(body_len + receiver_media.overhead(), sealed.len);
}

test "zix media: peer media sealFor, a buffer with no room for the tag is refused" {
    var sender = try Browser.init(TEST_KEYS);
    var sender_media = try PeerMedia.init(PROFILE, TEST_KEYS);
    var receiver_media = try PeerMedia.init(PROFILE, OTHER_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 1, "needs room");
    const opened = try sender_media.open(&buffer, protected.len);
    const body_len = opened.plain.len;

    var tight: [256]u8 = undefined;
    @memcpy(tight[0..body_len], opened.plain);

    try std.testing.expectError(
        error.ZixNoSpace,
        receiver_media.sealFor(opened.header, tight[0 .. body_len + receiver_media.overhead() - 1], body_len),
    );
}
