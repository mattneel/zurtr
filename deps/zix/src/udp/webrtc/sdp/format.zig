//! zix SDP media format list (RFC 8866 5.14, RFC 3264 6.1).
//!
//! What:
//! - Gathers what a media section says about each of its payload types: the number, what it
//!   means, its codec settings, and which feedback messages go with it. One entry per number in
//!   the `m=` line's format list.
//!
//! Note:
//! - This file describes, it does not decide. Whether a format ends up in the answer is the
//!   answer builder's call, and every fact it needs to make that call is a field here.
//! - The `rtpmap` and `fmtp` values are kept as the peer wrote them, not just as parsed structs.
//!   An answer echoes them back byte for byte, and re-serialising a parse would quietly normalise
//!   whitespace the peer chose.
//! - A payload type below 96 may have no `a=rtpmap` at all, because RFC 3551 already says what it
//!   means. That is a complete entry, not a broken one.
//! - Retransmission formats are flagged rather than dropped here. `rtx` (RFC 4588) is a transport
//!   mechanism with its own packet history, not a codec, and zix keeps no history. The flag lets
//!   the answer builder leave it out without this file having to know why.

const std = @import("std");

const fmtp = @import("fmtp.zig");
const rtcp_feedback = @import("rtcp_feedback.zig");
const rtpmap = @import("rtpmap.zig");

/// The most payload types one section may list. Browsers offer well under half of this.
pub const MAX_FORMATS: usize = 32;

/// The encoding name for the retransmission payload format (RFC 4588).
pub const RETRANSMISSION_ENCODING: []const u8 = "rtx";

/// What stops a format list from being read.
pub const Error = error{
    /// A format field that is not a payload type number.
    ZixBadPayloadType,
    /// More formats than MAX_FORMATS.
    ZixTooManyFormats,
};

/// One payload type and everything the section says about it.
pub const Format = struct {
    payload_type: u7,
    /// The `a=rtpmap` value as written, absent when the type describes itself (RFC 3551).
    rtpmap_value: ?[]const u8,
    /// The same value parsed, absent for the same reason.
    mapping: ?rtpmap.RtpMap,
    /// The `a=fmtp` value as written, absent when the section carried none.
    fmtp_value: ?[]const u8,
    /// Whether the peer offered a generic retransmission request for this type.
    offers_nack: bool,
    /// Whether the peer offered a keyframe request for this type.
    offers_nack_pli: bool,
    /// Whether this is a retransmission stream rather than a codec.
    is_retransmission: bool,

    /// The encoding name, when the section named one.
    ///
    /// Return:
    /// - ?[]const u8
    pub fn encoding(self: Format) ?[]const u8 {
        const mapping = self.mapping orelse return null;

        return mapping.encoding;
    }
};

/// Every payload type one section lists, in the order the `m=` line put them.
pub const List = struct {
    entries: [MAX_FORMATS]Format,
    len: usize,

    /// The entries as a slice.
    ///
    /// Return:
    /// - []const Format
    pub fn slice(self: *const List) []const Format {
        return self.entries[0..self.len];
    }

    /// One entry by payload type.
    ///
    /// Param:
    /// payload_type - u7
    ///
    /// Return:
    /// - ?Format
    pub fn find(self: *const List, payload_type: u7) ?Format {
        for (self.slice()) |entry| {
            if (entry.payload_type == payload_type) return entry;
        }

        return null;
    }

    /// How many entries are not retransmission streams.
    ///
    /// Return:
    /// - usize
    pub fn codecCount(self: *const List) usize {
        var count: usize = 0;
        for (self.slice()) |entry| {
            if (!entry.is_retransmission) count += 1;
        }

        return count;
    }
};

/// Read the format list of one media section.
///
/// Param:
/// section - []const u8 (the whole section, borrowed, must outlive the result)
/// formats - []const u8 (the `m=` line's format field, space separated)
///
/// Return:
/// - List borrowing `section`
/// - error.ZixBadPayloadType, error.ZixTooManyFormats
pub fn read(section: []const u8, formats: []const u8) Error!List {
    var list: List = .{ .entries = undefined, .len = 0 };
    var fields = std.mem.tokenizeScalar(u8, formats, ' ');

    while (fields.next()) |field| {
        if (list.len == MAX_FORMATS) return error.ZixTooManyFormats;

        const payload_type = std.fmt.parseInt(u7, field, 10) catch return error.ZixBadPayloadType;
        const mapping_value = rtpmap.findValue(section, payload_type);
        const mapping = if (mapping_value) |value| rtpmap.read(value) catch null else null;

        list.entries[list.len] = .{
            .payload_type = payload_type,
            .rtpmap_value = mapping_value,
            .mapping = mapping,
            .fmtp_value = fmtp.findValue(section, payload_type),
            .offers_nack = rtcp_feedback.offers(section, payload_type, "nack", null),
            .offers_nack_pli = rtcp_feedback.offers(section, payload_type, "nack", "pli"),
            .is_retransmission = isRetransmission(mapping),
        };

        list.len += 1;
    }

    return list;
}

/// Whether a mapping names the retransmission payload format (RFC 4588).
fn isRetransmission(mapping: ?rtpmap.RtpMap) bool {
    const named = mapping orelse return false;

    return std.ascii.eqlIgnoreCase(named.encoding, RETRANSMISSION_ENCODING);
}

// --------------------------------------------------------------------------------------- //
// test cases

const video_section: []const u8 =
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\n" ++
    "a=mid:1\r\n" ++
    "a=rtpmap:96 VP8/90000\r\n" ++
    "a=rtcp-fb:96 goog-remb\r\n" ++
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n" ++
    "a=fmtp:97 apt=96\r\n" ++
    "a=rtpmap:98 H264/90000\r\n" ++
    "a=fmtp:98 profile-level-id=42e01f;packetization-mode=1\r\n";

const audio_section: []const u8 =
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n" ++
    "a=mid:0\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n";

test "zix sdp: format read, the list keeps the media line's order" {
    const list = try read(video_section, "96 97 98");

    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqual(@as(u7, 96), list.slice()[0].payload_type);
    try std.testing.expectEqual(@as(u7, 97), list.slice()[1].payload_type);
    try std.testing.expectEqual(@as(u7, 98), list.slice()[2].payload_type);
}

test "zix sdp: format read, each entry picks up its own mapping and settings" {
    const list = try read(video_section, "96 97 98");
    const h264 = list.find(98).?;

    try std.testing.expectEqualStrings("H264", h264.encoding().?);
    try std.testing.expectEqual(@as(u32, 90000), h264.mapping.?.clock_rate);
    try std.testing.expectEqualStrings("98 profile-level-id=42e01f;packetization-mode=1", h264.fmtp_value.?);

    const vp8 = list.find(96).?;
    try std.testing.expectEqualStrings("VP8", vp8.encoding().?);
    try std.testing.expect(vp8.fmtp_value == null);
}

test "zix sdp: format read, the raw values come back as the peer wrote them" {
    // The answer echoes these, so a normalised re-serialisation would be answering something
    // slightly different from what was offered.
    const list = try read(audio_section, "111 0");
    const opus = list.find(111).?;

    try std.testing.expectEqualStrings("111 opus/48000/2", opus.rtpmap_value.?);
    try std.testing.expectEqualStrings("111 minptime=10;useinbandfec=1", opus.fmtp_value.?);
}

test "zix sdp: format read, a static payload type with no mapping is complete" {
    // Payload type 0 is PCMU by definition, so an offer need not describe it.
    const list = try read(audio_section, "111 0");
    const pcmu = list.find(0).?;

    try std.testing.expect(pcmu.rtpmap_value == null);
    try std.testing.expect(pcmu.mapping == null);
    try std.testing.expect(pcmu.encoding() == null);
    try std.testing.expect(!pcmu.is_retransmission);
}

test "zix sdp: format read, feedback support is recorded per payload type" {
    const list = try read(video_section, "96 97 98");

    // 96 was offered nack and nack pli, alongside a goog-remb that zix does not implement.
    const vp8 = list.find(96).?;
    try std.testing.expect(vp8.offers_nack);
    try std.testing.expect(vp8.offers_nack_pli);

    // 98 was offered none of it.
    const h264 = list.find(98).?;
    try std.testing.expect(!h264.offers_nack);
    try std.testing.expect(!h264.offers_nack_pli);
}

test "zix sdp: format read, a retransmission stream is flagged and not dropped" {
    // Flagged here, left out by the answer builder. This file does not decide.
    const list = try read(video_section, "96 97 98");
    const rtx = list.find(97).?;

    try std.testing.expect(rtx.is_retransmission);
    try std.testing.expectEqualStrings("rtx", rtx.encoding().?);
    try std.testing.expectEqualStrings("97 apt=96", rtx.fmtp_value.?);

    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqual(@as(usize, 2), list.codecCount());
}

test "zix sdp: format read, the retransmission name is matched without case" {
    const upper: []const u8 =
        "m=video 9 UDP/TLS/RTP/SAVPF 97\r\n" ++
        "a=rtpmap:97 RTX/90000\r\n";

    try std.testing.expect((try read(upper, "97")).find(97).?.is_retransmission);
}

test "zix sdp: format read, a format field that is not a number is refused" {
    try std.testing.expectError(error.ZixBadPayloadType, read(video_section, "96 x"));
    try std.testing.expectError(error.ZixBadPayloadType, read(video_section, "webrtc-datachannel"));
    try std.testing.expectError(error.ZixBadPayloadType, read(video_section, "200"));
}

test "zix sdp: format read, an empty format field gives an empty list" {
    const list = try read(video_section, "");

    try std.testing.expectEqual(@as(usize, 0), list.len);
    try std.testing.expectEqual(@as(usize, 0), list.slice().len);
    try std.testing.expect(list.find(96) == null);
}

test "zix sdp: format read, more formats than the ceiling is refused" {
    var many: [MAX_FORMATS + 1][3]u8 = undefined;
    var text: [4 * (MAX_FORMATS + 1)]u8 = undefined;
    var at: usize = 0;

    for (0..MAX_FORMATS + 1) |index| {
        const value: u8 = @intCast(index);
        var count: usize = 0;
        var left = value;

        while (true) {
            many[index][count] = '0' + (left % 10);
            count += 1;
            left /= 10;

            if (left == 0) break;
        }

        for (0..count) |digit| {
            text[at] = many[index][count - 1 - digit];
            at += 1;
        }

        text[at] = ' ';
        at += 1;
    }

    try std.testing.expectError(error.ZixTooManyFormats, read(video_section, text[0..at]));
}

test "zix sdp: format read, a repeated number is kept as the media line listed it" {
    // The `m=` line is what the peer sent, and an answer echoing back a list of a different
    // length is not answering the same section.
    const list = try read(video_section, "96 96");

    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqual(@as(u7, 96), list.slice()[1].payload_type);
}

test "zix sdp: format read, a mapping for a number not in the list is left out" {
    const list = try read(video_section, "96");

    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expect(list.find(98) == null);
}

test "zix sdp: format read, a malformed mapping leaves the entry without one" {
    const ragged: []const u8 =
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=rtpmap:96 broken\r\n";

    const list = try read(ragged, "96");
    const entry = list.find(96).?;

    // The number is still offered, so the entry exists. What it means is simply unknown.
    try std.testing.expect(entry.mapping == null);
    try std.testing.expect(entry.rtpmap_value == null);
    try std.testing.expect(!entry.is_retransmission);
}
