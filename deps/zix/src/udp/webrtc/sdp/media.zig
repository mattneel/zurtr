//! zix SDP media description line (RFC 8866 5.14, RFC 8841 4).
//!
//! What:
//! - The `m=` line: what kind of media a section carries, on which port, over which transport,
//!   and in which formats. Plus the one shape a WebRTC data channel takes.
//!
//! Note:
//! - A port of zero rejects the section (RFC 3264 6). It is the only way to say no to one media
//!   description while accepting the rest, and an answer that copies the port back without
//!   noticing has accepted something it cannot carry.
//! - The transport is compared exactly. "UDP/DTLS/SCTP" and "udp/dtls/sctp" are not the same
//!   token, the registry spells it upper case, and every sender writes it that way.
//! - A data channel section names exactly one format, "webrtc-datachannel" (RFC 8841 4.3). The
//!   format namespace here is not a payload type list, so reading it as one finds numbers that
//!   are not there.
//! - The port and the SCTP port are different numbers. The `m=` line carries the UDP port, and
//!   `a=sctp-port` carries the port inside the association (RFC 8841 5.1). Using one for the
//!   other builds a description that looks right and connects to nothing.

const std = @import("std");

/// The media type a data channel section uses.
pub const DATA_CHANNEL_MEDIA: []const u8 = "application";

/// The transport a data channel runs over.
pub const DATA_CHANNEL_PROTO: []const u8 = "UDP/DTLS/SCTP";

/// The one format value a data channel section names.
pub const DATA_CHANNEL_FORMAT: []const u8 = "webrtc-datachannel";

/// The media type an audio section uses.
pub const AUDIO_MEDIA: []const u8 = "audio";

/// The media type a video section uses.
pub const VIDEO_MEDIA: []const u8 = "video";

/// The transport WebRTC media runs over (RFC 5764 9, RFC 8829 5.1.1).
pub const RTP_PROTO: []const u8 = "UDP/TLS/RTP/SAVPF";

/// The port that says a section is refused (RFC 3264 6).
pub const REJECTED_PORT: u16 = 0;

/// The port an offer uses when it has no candidate to name yet (RFC 8839 4.3.1).
pub const UNSPECIFIED_PORT: u16 = 9;

/// Everything that stops a media line from being read. Writing only ever runs out of room, so
/// `write` carries that one on its own.
pub const Error = error{
    /// Fewer fields than an `m=` line needs.
    ZixMalformed,
    /// A port outside what the field holds.
    ZixBadPort,
};

/// One `m=` line, borrowed from the description it came from.
pub const Media = struct {
    /// "application", "audio", "video", and so on.
    media: []const u8,
    /// The transport port, which is not the SCTP port.
    port: u16,
    /// How many consecutive ports the section covers, from the `port/count` form.
    port_count: ?u16,
    proto: []const u8,
    /// The format list as it stands, space separated.
    formats: []const u8,

    /// Whether the section was refused.
    ///
    /// Return:
    /// - bool
    pub fn isRejected(self: Media) bool {
        return self.port == REJECTED_PORT;
    }

    /// Whether this section describes a WebRTC data channel.
    ///
    /// Return:
    /// - bool
    pub fn isDataChannel(self: Media) bool {
        if (!std.mem.eql(u8, self.media, DATA_CHANNEL_MEDIA)) return false;
        if (!std.mem.eql(u8, self.proto, DATA_CHANNEL_PROTO)) return false;

        return std.mem.eql(u8, self.formats, DATA_CHANNEL_FORMAT);
    }

    /// Whether this section describes WebRTC audio or video.
    ///
    /// Note:
    /// - The transport is checked as well as the media type. An `m=audio` over a plain RTP
    ///   profile is a session with no encryption, which is not one a WebRTC endpoint answers.
    ///
    /// Return:
    /// - bool
    pub fn isRtpMedia(self: Media) bool {
        if (!std.mem.eql(u8, self.proto, RTP_PROTO)) return false;

        return std.mem.eql(u8, self.media, AUDIO_MEDIA) or std.mem.eql(u8, self.media, VIDEO_MEDIA);
    }
};

/// Read an `m=` line value.
///
/// Param:
/// value - []const u8 (everything after `m=`)
///
/// Return:
/// - Media borrowing `value`
/// - error.ZixMalformed if the media, port, transport, or format list is missing
/// - error.ZixBadPort if a port is not a number that fits
pub fn read(value: []const u8) Error!Media {
    var fields = std.mem.tokenizeScalar(u8, value, ' ');

    const media = fields.next() orelse return error.ZixMalformed;
    const port_field = fields.next() orelse return error.ZixMalformed;
    const proto = fields.next() orelse return error.ZixMalformed;
    const formats = fields.rest();

    if (formats.len == 0) return error.ZixMalformed;

    const slash = std.mem.indexOfScalar(u8, port_field, '/') orelse
        return .{
            .media = media,
            .port = try readPort(port_field),
            .port_count = null,
            .proto = proto,
            .formats = formats,
        };

    return .{
        .media = media,
        .port = try readPort(port_field[0..slash]),
        .port_count = try readPort(port_field[slash + 1 ..]),
        .proto = proto,
        .formats = formats,
    };
}

/// How many bytes a media line value will take.
///
/// Param:
/// media - []const u8
/// proto - []const u8
/// formats - []const u8
///
/// Return:
/// - usize, before the port, which is at most five digits
pub fn valueLen(media: []const u8, proto: []const u8, formats: []const u8) usize {
    return media.len + 1 + MAX_PORT_DIGITS + 1 + proto.len + 1 + formats.len;
}

/// Write an `m=` line value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// media - []const u8
/// port - u16
/// proto - []const u8
/// formats - []const u8
///
/// Return:
/// - []const u8, the value alone, with no line type and no terminator
/// - error.ZixNoSpace
pub fn write(out: []u8, media: []const u8, port: u16, proto: []const u8, formats: []const u8) error{ZixNoSpace}![]const u8 {
    var digits: [MAX_PORT_DIGITS]u8 = undefined;
    const port_text = writePort(&digits, port);

    const total = media.len + 1 + port_text.len + 1 + proto.len + 1 + formats.len;

    if (out.len < total) return error.ZixNoSpace;

    var at: usize = 0;
    at += copy(out[at..], media);
    out[at] = ' ';
    at += 1;
    at += copy(out[at..], port_text);
    out[at] = ' ';
    at += 1;
    at += copy(out[at..], proto);
    out[at] = ' ';
    at += 1;
    at += copy(out[at..], formats);

    return out[0..total];
}

/// The most digits a port takes.
pub const MAX_PORT_DIGITS: usize = 5;

/// Read a port field.
fn readPort(text: []const u8) Error!u16 {
    if (text.len == 0) return error.ZixBadPort;

    return std.fmt.parseInt(u16, text, 10) catch error.ZixBadPort;
}

/// Write a port in base ten.
fn writePort(out: *[MAX_PORT_DIGITS]u8, port: u16) []const u8 {
    var digits: [MAX_PORT_DIGITS]u8 = undefined;
    var count: usize = 0;
    var left = port;

    while (true) {
        digits[count] = '0' + @as(u8, @intCast(left % 10));
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return out[0..count];
}

/// Copy into a buffer already known to be long enough.
fn copy(out: []u8, text: []const u8) usize {
    @memcpy(out[0..text.len], text);

    return text.len;
}

// --------------------------------------------------------------------------------------- //
// test cases

const data_channel_line: []const u8 = "application 9 UDP/DTLS/SCTP webrtc-datachannel";

test "zix sdp: media read, a data channel line reads field for field" {
    const parsed = try read(data_channel_line);

    try std.testing.expectEqualStrings("application", parsed.media);
    try std.testing.expectEqual(@as(u16, 9), parsed.port);
    try std.testing.expectEqual(@as(?u16, null), parsed.port_count);
    try std.testing.expectEqualStrings("UDP/DTLS/SCTP", parsed.proto);
    try std.testing.expectEqualStrings("webrtc-datachannel", parsed.formats);
}

test "zix sdp: media read, several formats stay together" {
    const parsed = try read("audio 49170 RTP/AVP 0 8 97");

    try std.testing.expectEqualStrings("0 8 97", parsed.formats);
}

test "zix sdp: media read, the port count form is split off" {
    const parsed = try read("video 49170/2 RTP/AVP 31");

    try std.testing.expectEqual(@as(u16, 49170), parsed.port);
    try std.testing.expectEqual(@as(?u16, 2), parsed.port_count);
}

test "zix sdp: media read, a missing field is refused" {
    try std.testing.expectError(error.ZixMalformed, read("application 9 UDP/DTLS/SCTP"));
    try std.testing.expectError(error.ZixMalformed, read("application 9"));
    try std.testing.expectError(error.ZixMalformed, read("application"));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: media read, a port that is not a number is refused" {
    try std.testing.expectError(error.ZixBadPort, read("application x UDP/DTLS/SCTP webrtc-datachannel"));
}

test "zix sdp: media read, a port past what the field holds is refused" {
    try std.testing.expectError(error.ZixBadPort, read("application 65536 UDP/DTLS/SCTP webrtc-datachannel"));
}

test "zix sdp: media read, an empty port count is refused" {
    try std.testing.expectError(error.ZixBadPort, read("video 49170/ RTP/AVP 31"));
}

test "zix sdp: media isDataChannel, the RFC 8841 shape is accepted" {
    try std.testing.expect((try read(data_channel_line)).isDataChannel());
}

test "zix sdp: media isDataChannel, another media type is not one" {
    try std.testing.expect(!(try read("audio 49170 RTP/AVP 0")).isDataChannel());
}

test "zix sdp: media isDataChannel, another transport is not one" {
    try std.testing.expect(!(try read("application 9 TCP/DTLS/SCTP webrtc-datachannel")).isDataChannel());
}

test "zix sdp: media isDataChannel, the transport compare is exact" {
    // Nothing else spells it in lower case, so accepting that here would take a description no
    // other endpoint reads the same way.
    try std.testing.expect(!(try read("application 9 udp/dtls/sctp webrtc-datachannel")).isDataChannel());
}

test "zix sdp: media isDataChannel, another format is not one" {
    try std.testing.expect(!(try read("application 9 UDP/DTLS/SCTP 5000")).isDataChannel());
}

test "zix sdp: media isRtpMedia, the webrtc audio and video shapes are accepted" {
    try std.testing.expect((try read("audio 9 UDP/TLS/RTP/SAVPF 111 103 0")).isRtpMedia());
    try std.testing.expect((try read("video 9 UDP/TLS/RTP/SAVPF 96 97")).isRtpMedia());
}

test "zix sdp: media isRtpMedia, an unencrypted profile is not one" {
    // RFC 8834 requires the secure profile, so a plain RTP/AVP section is a session this
    // endpoint has no business answering.
    try std.testing.expect(!(try read("audio 49170 RTP/AVP 0 8 97")).isRtpMedia());
    try std.testing.expect(!(try read("audio 9 UDP/TLS/RTP/SAVP 111")).isRtpMedia());
}

test "zix sdp: media isRtpMedia, a data channel is not rtp media and the reverse" {
    const data_channel = try read(data_channel_line);
    const audio = try read("audio 9 UDP/TLS/RTP/SAVPF 111");

    try std.testing.expect(!data_channel.isRtpMedia());
    try std.testing.expect(data_channel.isDataChannel());
    try std.testing.expect(audio.isRtpMedia());
    try std.testing.expect(!audio.isDataChannel());
}

test "zix sdp: media isRejected, a zero port is a refusal" {
    try std.testing.expect((try read("application 0 UDP/DTLS/SCTP webrtc-datachannel")).isRejected());
    try std.testing.expect(!(try read(data_channel_line)).isRejected());
}

test "zix sdp: media isRejected, a refused section keeps its shape" {
    // The shape and the refusal are separate questions, and an answer has to see both.
    const parsed = try read("application 0 UDP/DTLS/SCTP webrtc-datachannel");

    try std.testing.expect(parsed.isDataChannel());
    try std.testing.expect(parsed.isRejected());
}

test "zix sdp: media write, the value is the fields in order" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, DATA_CHANNEL_MEDIA, 9091, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT);

    try std.testing.expectEqualStrings("application 9091 UDP/DTLS/SCTP webrtc-datachannel", written);
}

test "zix sdp: media write, a zero port writes one digit" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, DATA_CHANNEL_MEDIA, 0, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT);

    try std.testing.expectEqualStrings("application 0 UDP/DTLS/SCTP webrtc-datachannel", written);
}

test "zix sdp: media write, a short buffer errors" {
    var buf: [16]u8 = undefined;

    try std.testing.expectError(
        error.ZixNoSpace,
        write(&buf, DATA_CHANNEL_MEDIA, 9091, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT),
    );
}

test "zix sdp: media write, what was written reads back the same" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, DATA_CHANNEL_MEDIA, 65535, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT);
    const parsed = try read(written);

    try std.testing.expectEqual(@as(u16, 65535), parsed.port);
    try std.testing.expect(parsed.isDataChannel());
}

test "zix sdp: media valueLen, the estimate covers what was written" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, DATA_CHANNEL_MEDIA, 9, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT);

    // The estimate assumes the widest port, so it is an upper bound rather than an exact match.
    try std.testing.expect(valueLen(DATA_CHANNEL_MEDIA, DATA_CHANNEL_PROTO, DATA_CHANNEL_FORMAT) >= written.len);
}
