//! zix SRTP streams of one direction of one peer (RFC 3711 3.2.3, RFC 5764 4.2).
//!
//! What:
//! - The SRTP sessions one peer needs for one direction, kept apart by stream identifier and
//!   opened as each identifier is first seen.
//!
//! Note:
//! - One master key covers every stream in a direction, and srtp.Session still has to be one per
//!   stream: the rollover counter and the replay list are per stream. Two identifiers sharing a
//!   session read each other's sequence numbers as gaps and wraps, which rejects real packets and
//!   accepts nothing in their place.
//! - A stream is opened on its first packet rather than declared ahead of it. The SDP need not
//!   name an identifier at all, and a browser is free to change one mid-session, so what is on the
//!   wire is the only thing that can be believed.
//! - Bounded and allocation-free. The ceiling is a peer's whole direction: a camera, a microphone,
//!   and the retransmission streams alongside them.

const std = @import("std");

const exporter = @import("../../../tls/dtls_exporter.zig");
const profile = @import("profile.zig");
const srtp = @import("srtp.zig");
const srtp_key = @import("srtp_key.zig");

/// How many streams one direction of one peer may hold.
pub const MAX_STREAMS: usize = 8;

/// What stops a stream from being opened.
pub const Error = error{
    /// A profile with no keys to run on, including the NULL ciphers.
    ZixUnsupportedProfile,
    /// This direction already holds MAX_STREAMS identifiers.
    ZixTooManyStreams,
};

/// One stream, and the session protecting it.
const Entry = struct {
    ssrc: u32,
    session: srtp.Session,
};

/// Every stream of one direction of one peer.
///
/// Usage:
/// ```zig
/// var inbound = try StreamSet.init(negotiated, keys.client_write_key, keys.client_write_salt);
/// const stream = try inbound.sessionFor(header.ssrc);
///
/// const opened = try stream.unprotect(packet);
/// ```
pub const StreamSet = struct {
    negotiated: exporter.SrtpProfile,
    master_key: [srtp_key.MASTER_KEY_LEN]u8,
    master_salt: [srtp_key.MASTER_SALT_LEN]u8,
    entries: [MAX_STREAMS]Entry,
    /// How many identifiers have been seen.
    live: usize,

    /// Hold the keys one direction protects every stream with.
    ///
    /// Note:
    /// - The profile is checked here so an unusable one is refused once, rather than on whichever
    ///   packet happens to open the first stream.
    ///
    /// Param:
    /// negotiated - exporter.SrtpProfile (what the DTLS handshake agreed on)
    /// master_key - [srtp_key.MASTER_KEY_LEN]u8 (this direction's key from the exporter)
    /// master_salt - [srtp_key.MASTER_SALT_LEN]u8 (this direction's salt)
    ///
    /// Return:
    /// - StreamSet holding no streams yet
    /// - error.ZixUnsupportedProfile
    pub fn init(
        negotiated: exporter.SrtpProfile,
        master_key: [srtp_key.MASTER_KEY_LEN]u8,
        master_salt: [srtp_key.MASTER_SALT_LEN]u8,
    ) Error!StreamSet {
        _ = profile.parametersFor(negotiated) catch return error.ZixUnsupportedProfile;

        return .{
            .negotiated = negotiated,
            .master_key = master_key,
            .master_salt = master_salt,
            .entries = undefined,
            .live = 0,
        };
    }

    /// The session for one stream, opening it the first time that identifier is seen.
    ///
    /// Param:
    /// ssrc - u32 (the stream identifier the packet carries)
    ///
    /// Return:
    /// - *srtp.Session, valid until this set is written over
    /// - error.ZixTooManyStreams, error.ZixUnsupportedProfile
    pub fn sessionFor(self: *StreamSet, ssrc: u32) Error!*srtp.Session {
        if (self.find(ssrc)) |known| return known;

        if (self.live == MAX_STREAMS) return error.ZixTooManyStreams;

        const opened = try srtp.Session.init(self.negotiated, self.master_key, self.master_salt);

        self.entries[self.live] = .{ .ssrc = ssrc, .session = opened };
        self.live += 1;

        return &self.entries[self.live - 1].session;
    }

    /// The session for a stream already open, or null.
    ///
    /// Param:
    /// ssrc - u32
    ///
    /// Return:
    /// - ?*srtp.Session
    pub fn find(self: *StreamSet, ssrc: u32) ?*srtp.Session {
        for (self.entries[0..self.live]) |*entry| {
            if (entry.ssrc == ssrc) return &entry.session;
        }

        return null;
    }

    /// How many bytes protection adds to one packet in this direction.
    ///
    /// Note:
    /// - Fixed by the profile, so it is the same for every stream and answerable before any of
    ///   them is open.
    ///
    /// Return:
    /// - usize
    pub fn overhead(self: StreamSet) usize {
        const parameters = profile.parametersFor(self.negotiated) catch return srtp.MAX_OVERHEAD;

        return parameters.rtp_tag_len;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const rtp = @import("rtp.zig");

const TEST_KEY: [srtp_key.MASTER_KEY_LEN]u8 = @splat(0x11);
const TEST_SALT: [srtp_key.MASTER_SALT_LEN]u8 = @splat(0x22);

/// One plain RTP packet of `ssrc`, protected by `stream`, into `buffer`.
fn protectedPacket(stream: *srtp.Session, buffer: []u8, ssrc: u32, sequence: u16) ![]const u8 {
    const written = try rtp.write(buffer, .{
        .payload_type = 96,
        .sequence = sequence,
        .timestamp = 9000,
        .ssrc = ssrc,
    }, "media bytes");

    return stream.protect(buffer, written.len);
}

test "zix media: stream set init, a profile with no cipher is refused up front" {
    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        StreamSet.init(.SRTP_NULL_HMAC_SHA1_80, TEST_KEY, TEST_SALT),
    );
}

test "zix media: stream set, a new identifier opens a session and the same one comes back" {
    var streams = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);

    try std.testing.expectEqual(@as(usize, 0), streams.live);
    try std.testing.expect(streams.find(0x1111_1111) == null);

    const first = try streams.sessionFor(0x1111_1111);

    try std.testing.expectEqual(@as(usize, 1), streams.live);
    try std.testing.expectEqual(first, try streams.sessionFor(0x1111_1111));
    try std.testing.expectEqual(first, streams.find(0x1111_1111).?);
}

test "zix media: stream set, two identifiers keep their own rollover and replay state" {
    // The reason this file exists. Both streams start at the same sequence number, and neither
    // may read the other's numbering as a replay.
    var sender = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);
    var receiver = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);

    var audio_buf: [128]u8 = undefined;
    var video_buf: [128]u8 = undefined;

    const audio = try protectedPacket(try sender.sessionFor(0xAAAA_AAAA), &audio_buf, 0xAAAA_AAAA, 100);
    const video = try protectedPacket(try sender.sessionFor(0xBBBB_BBBB), &video_buf, 0xBBBB_BBBB, 100);

    var received: [128]u8 = undefined;
    @memcpy(received[0..audio.len], audio);

    const opened_audio = try (try receiver.sessionFor(0xAAAA_AAAA)).unprotect(received[0..audio.len]);
    try std.testing.expectEqualStrings("media bytes", (try rtp.read(opened_audio)).payload);

    @memcpy(received[0..video.len], video);

    const opened_video = try (try receiver.sessionFor(0xBBBB_BBBB)).unprotect(received[0..video.len]);
    try std.testing.expectEqualStrings("media bytes", (try rtp.read(opened_video)).payload);

    try std.testing.expectEqual(@as(usize, 2), receiver.live);
}

test "zix media: stream set, one identifier through one session still refuses a replay" {
    var sender = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);
    var receiver = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);

    var buffer: [128]u8 = undefined;
    const packet = try protectedPacket(try sender.sessionFor(0xAAAA_AAAA), &buffer, 0xAAAA_AAAA, 7);

    var first: [128]u8 = undefined;
    var again: [128]u8 = undefined;
    @memcpy(first[0..packet.len], packet);
    @memcpy(again[0..packet.len], packet);

    _ = try (try receiver.sessionFor(0xAAAA_AAAA)).unprotect(first[0..packet.len]);

    try std.testing.expectError(
        error.ZixReplayed,
        (try receiver.sessionFor(0xAAAA_AAAA)).unprotect(again[0..packet.len]),
    );
}

test "zix media: stream set, a peer past the ceiling is refused rather than given a shared session" {
    var streams = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);

    for (0..MAX_STREAMS) |index| {
        _ = try streams.sessionFor(@intCast(index + 1));
    }

    try std.testing.expectEqual(MAX_STREAMS, streams.live);
    try std.testing.expectError(error.ZixTooManyStreams, streams.sessionFor(0xFFFF_FFFF));

    // A stream already open still answers, so a peer at the ceiling keeps what it had.
    try std.testing.expect(streams.find(1) != null);
}

test "zix media: stream set overhead, the tag length is the profile's and needs no open stream" {
    var long = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_80, TEST_KEY, TEST_SALT);
    var short = try StreamSet.init(.SRTP_AES128_CM_HMAC_SHA1_32, TEST_KEY, TEST_SALT);

    try std.testing.expectEqual(@as(usize, 10), long.overhead());
    try std.testing.expectEqual(@as(usize, 4), short.overhead());
    try std.testing.expectEqual(long.overhead(), (try long.sessionFor(1)).overhead());
    try std.testing.expectEqual(short.overhead(), (try short.sessionFor(1)).overhead());
}
