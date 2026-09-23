//! zix WebRTC media section reader (RFC 8829 5.9, RFC 3264 6.1, RFC 5761 5.1.3).
//!
//! What:
//! - Reads ONE offered audio or video section down to what an answer needs. offer.zig does the
//!   same job for the data channel section, and this is the media half of it.
//!
//! Note:
//! - A section this endpoint will not carry is still read. Every section of an offer has to be
//!   answered, even if the answer is a refusal (RFC 3264 6), so a reader that gives up on an
//!   unsupported section leaves the answer with the wrong number of sections.
//! - RTP and RTCP have to share the port. zix demuxes STUN, DTLS, and media on one socket and has
//!   no second port to offer, so a section without `a=rtcp-mux` is one it cannot carry
//!   (RFC 5761 5.1.3, RFC 8834 4.5). That is recorded rather than treated as an error, so the
//!   answer can refuse the section properly.
//! - The direction is read from the section and then the session level, and defaults to sendrecv.
//!   See direction.zig for why the default is not a guess.
//! - Everything borrows the offer text.

const std = @import("std");

const attribute = @import("attribute.zig");
const direction = @import("direction.zig");
const format = @import("format.zig");
const media = @import("media.zig");
const session = @import("session.zig");

/// The attribute that says RTP and RTCP share one port (RFC 5761 5.1.3).
pub const RTCP_MUX: []const u8 = "rtcp-mux";

/// Everything that stops a media section from being read.
pub const Error = error{
    /// The `m=` line does not frame, or its port does not fit.
    ZixMalformed,
    /// A format field that is not a payload type number.
    ZixBadPayloadType,
    /// More formats than format.MAX_FORMATS.
    ZixTooManyFormats,
};

/// What kind of media a section carries.
pub const Kind = enum {
    AUDIO,
    VIDEO,

    /// The media type this appears under.
    ///
    /// Return:
    /// - []const u8
    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .AUDIO => media.AUDIO_MEDIA,
            .VIDEO => media.VIDEO_MEDIA,
        };
    }
};

/// One offered media section, read down to what an answer needs.
pub const MediaOffer = struct {
    /// The section, borrowed.
    section: session.Section,
    /// The section's `m=` line.
    media_line: media.Media,
    kind: Kind,
    /// The section's identification tag, which an answer echoes back.
    mid: ?[]const u8,
    /// Which way the peer says media flows.
    direction: direction.Direction,
    /// Whether the peer will share one port between RTP and RTCP.
    rtcp_mux: bool,
    /// Whether the peer refused the section itself, by offering port zero.
    rejected: bool,
    /// Every payload type the section lists.
    formats: format.List,

    /// Whether zix can carry this section at all.
    ///
    /// Note:
    /// - Three ways a section is uncarryable: the peer already refused it, it will not share a
    ///   port, or it lists nothing but retransmission streams.
    ///
    /// Return:
    /// - bool
    pub fn isCarryable(self: *const MediaOffer) bool {
        if (self.rejected) return false;
        if (!self.rtcp_mux) return false;

        return self.formats.codecCount() > 0;
    }
};

/// Whether a section is one this file reads.
///
/// Param:
/// section - session.Section
///
/// Return:
/// - bool
pub fn isMediaSection(section: session.Section) bool {
    const media_line = section.mediaLine() catch return false;

    return media_line.isRtpMedia();
}

/// Read one offered audio or video section.
///
/// Param:
/// description - session.Description (for the session level fallback)
/// section - session.Section (an RTP media section, borrowed)
///
/// Return:
/// - MediaOffer borrowing the description
/// - error.ZixMalformed, error.ZixBadPayloadType, error.ZixTooManyFormats
pub fn read(description: session.Description, section: session.Section) Error!MediaOffer {
    const media_line = section.mediaLine() catch return error.ZixMalformed;
    const kind: Kind = if (std.mem.eql(u8, media_line.media, media.VIDEO_MEDIA)) .VIDEO else .AUDIO;

    return .{
        .section = section,
        .media_line = media_line,
        .kind = kind,
        .mid = attribute.findValue(section.text, "mid"),
        .direction = direction.of(section.text, description.session),
        .rtcp_mux = attribute.has(section.text, RTCP_MUX),
        .rejected = media_line.isRejected(),
        .formats = try format.read(section.text, media_line.formats),
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

/// An offer in the shape a browser sends one for a camera and a microphone.
const browser_offer: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0 1\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:0\r\n" ++
    "a=sendrecv\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
    "a=rtcp-fb:111 transport-cc\r\n" ++
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:1\r\n" ++
    "a=sendonly\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtpmap:96 VP8/90000\r\n" ++
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n" ++
    "a=fmtp:97 apt=96\r\n";

fn sectionAt(text: []const u8, index: usize) !struct { session.Description, session.Section } {
    const description = try session.parse(text);
    const section = description.section(index) orelse return error.TestUnexpectedResult;

    return .{ description, section };
}

test "zix sdp: media offer read, an audio section reads down to what an answer needs" {
    const found = try sectionAt(browser_offer, 0);
    const parsed = try read(found[0], found[1]);

    try std.testing.expectEqual(Kind.AUDIO, parsed.kind);
    try std.testing.expectEqualStrings("0", parsed.mid.?);
    try std.testing.expectEqual(direction.Direction.SENDRECV, parsed.direction);
    try std.testing.expect(parsed.rtcp_mux);
    try std.testing.expect(!parsed.rejected);
    try std.testing.expectEqual(@as(usize, 2), parsed.formats.len);
    try std.testing.expect(parsed.isCarryable());
}

test "zix sdp: media offer read, a video section reads its own direction and formats" {
    const found = try sectionAt(browser_offer, 1);
    const parsed = try read(found[0], found[1]);

    try std.testing.expectEqual(Kind.VIDEO, parsed.kind);
    try std.testing.expectEqualStrings("1", parsed.mid.?);
    try std.testing.expectEqual(direction.Direction.SENDONLY, parsed.direction);

    // Three listed, one of them a retransmission stream.
    try std.testing.expectEqual(@as(usize, 2), parsed.formats.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.formats.codecCount());
    try std.testing.expect(parsed.formats.find(97).?.is_retransmission);
}

test "zix sdp: media offer read, feedback support carries per format" {
    const found = try sectionAt(browser_offer, 1);
    const parsed = try read(found[0], found[1]);
    const vp8 = parsed.formats.find(96).?;

    try std.testing.expect(vp8.offers_nack);
    try std.testing.expect(vp8.offers_nack_pli);

    // The audio section offered only transport-cc, which zix does not implement.
    const audio = try sectionAt(browser_offer, 0);
    const opus = (try read(audio[0], audio[1])).formats.find(111).?;

    try std.testing.expect(!opus.offers_nack);
    try std.testing.expect(!opus.offers_nack_pli);
}

test "zix sdp: media offer read, a section without rtcp-mux is not carryable" {
    // zix has one socket. A peer that wants RTCP on a second port is asking for something no
    // layer here can provide, and the answer has to refuse the section rather than pretend.
    const no_mux: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    const found = try sectionAt(no_mux, 0);
    const parsed = try read(found[0], found[1]);

    try std.testing.expect(!parsed.rtcp_mux);
    try std.testing.expect(!parsed.isCarryable());
}

test "zix sdp: media offer read, a section the peer already refused is read anyway" {
    // Reading it is what lets the answer carry a matching refusal in the right position.
    const refused: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    const found = try sectionAt(refused, 0);
    const parsed = try read(found[0], found[1]);

    try std.testing.expect(parsed.rejected);
    try std.testing.expect(!parsed.isCarryable());
    try std.testing.expectEqualStrings("0", parsed.mid.?);
}

test "zix sdp: media offer read, a section of nothing but retransmission is not carryable" {
    const rtx_only: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 97\r\n" ++
        "a=mid:1\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtpmap:97 rtx/90000\r\n";

    const found = try sectionAt(rtx_only, 0);
    const parsed = try read(found[0], found[1]);

    try std.testing.expect(parsed.rtcp_mux);
    try std.testing.expect(!parsed.rejected);
    try std.testing.expect(!parsed.isCarryable());
}

test "zix sdp: media offer read, the session level direction reaches a silent section" {
    const session_level: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=recvonly\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    const found = try sectionAt(session_level, 0);

    try std.testing.expectEqual(direction.Direction.RECVONLY, (try read(found[0], found[1])).direction);
}

test "zix sdp: media offer isMediaSection, only the secure rtp shapes count" {
    const description = try session.parse(browser_offer);

    try std.testing.expect(isMediaSection(description.section(0).?));
    try std.testing.expect(isMediaSection(description.section(1).?));

    const data_channel: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n";

    const other = try session.parse(data_channel);
    try std.testing.expect(!isMediaSection(other.section(0).?));
}

test "zix sdp: media offer isMediaSection, a malformed media line is not one" {
    const broken: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio\r\n";

    const description = try session.parse(broken);
    try std.testing.expect(!isMediaSection(description.section(0).?));
}

test "zix sdp: media offer read, a format list that is not payload types is refused" {
    const wrong: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF opus\r\n" ++
        "a=rtcp-mux\r\n";

    const found = try sectionAt(wrong, 0);

    try std.testing.expectError(error.ZixBadPayloadType, read(found[0], found[1]));
}

test "zix sdp: media offer read, a section with no mid still reads" {
    // RFC 8843 wants one, and an offer without BUNDLE is under no obligation to carry it.
    const no_mid: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    const found = try sectionAt(no_mid, 0);
    const parsed = try read(found[0], found[1]);

    try std.testing.expect(parsed.mid == null);
    try std.testing.expect(parsed.isCarryable());
}

test "zix sdp: media offer read, both sections of a bundled offer read independently" {
    const description = try session.parse(browser_offer);

    try std.testing.expectEqual(@as(usize, 2), description.sectionCount());

    const audio = try read(description, description.section(0).?);
    const video = try read(description, description.section(1).?);

    try std.testing.expectEqual(Kind.AUDIO, audio.kind);
    try std.testing.expectEqual(Kind.VIDEO, video.kind);
    try std.testing.expect(audio.direction != video.direction);
    try std.testing.expectEqualStrings("audio", audio.kind.name());
    try std.testing.expectEqualStrings("video", video.kind.name());
}
