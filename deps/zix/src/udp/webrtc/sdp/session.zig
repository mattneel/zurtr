//! zix SDP session description (RFC 8866 5).
//!
//! What:
//! - A whole description cut into the two kinds of region a reader needs: the session level, and
//!   one region per media section.
//!
//! Note:
//! - Nothing is copied. Every region borrows the text handed in, so the description has to
//!   outlive anything read out of it.
//! - The session level ends at the first `m=` line, and each media section runs to the next one.
//!   That split is the whole reason attribute lookups need a region: `a=ice-ufrag` at session
//!   level applies to every section, and the same name inside a section applies to that one
//!   alone (RFC 8839 5.4).
//! - Only the four fields RFC 8866 5 makes mandatory are checked, being the version, the origin,
//!   the session name, and one time description. Everything else is optional, and a description
//!   missing something a particular usage needs is that usage's problem to report.
//! - The version must be 0. There has never been another, and a description claiming one is not
//!   a description this parser understands.

const std = @import("std");

const line = @import("line.zig");
const media = @import("media.zig");

/// The only SDP version there is.
pub const VERSION: []const u8 = "0";

/// Everything that stops a description from being read.
pub const Error = error{
    /// A line without a type character followed by an equals sign.
    ZixMalformed,
    /// A version this parser does not implement.
    ZixUnsupportedVersion,
    /// One of the four fields RFC 8866 5 makes mandatory is missing.
    ZixMissingField,
};

/// One media section, borrowed from the description it came from.
pub const Section = struct {
    /// The `m=` line value, everything after `m=`.
    media_value: []const u8,
    /// The whole section, its `m=` line included, so an attribute search covers it.
    text: []const u8,

    /// Read the `m=` line.
    ///
    /// Return:
    /// - media.Media borrowing this section
    /// - error.ZixMalformed, error.ZixBadPort
    pub fn mediaLine(self: Section) media.Error!media.Media {
        return media.read(self.media_value);
    }
};

/// A validated description, cut into regions.
pub const Description = struct {
    /// The whole text.
    text: []const u8,
    /// Everything before the first `m=` line, being the session level.
    session: []const u8,

    /// How many media sections there are.
    ///
    /// Return:
    /// - usize
    pub fn sectionCount(self: Description) usize {
        return line.count(self.text, .MEDIA);
    }

    /// One media section by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?Section borrowing this description
    pub fn section(self: Description, index: usize) ?Section {
        var seen: usize = 0;
        var iterator = line.Iterator{ .text = self.text };

        while (iterator.next()) |item| {
            if (item.kind != .MEDIA) continue;

            if (seen == index) return .{
                .media_value = item.value,
                .text = self.text[item.offset..self.nextSectionAt(item.offset)],
            };

            seen += 1;
        }

        return null;
    }

    /// The first media section describing a WebRTC data channel.
    ///
    /// Note:
    /// - A bundled session can carry audio, video, and one data channel section, and only the
    ///   last of those is one this endpoint answers.
    ///
    /// Return:
    /// - ?Section
    pub fn dataChannelSection(self: Description) ?Section {
        var index: usize = 0;
        while (self.section(index)) |found| : (index += 1) {
            const parsed = found.mediaLine() catch continue;

            if (parsed.isDataChannel()) return found;
        }

        return null;
    }

    /// Where the section starting at an offset ends, which is the next `m=` line or the end.
    fn nextSectionAt(self: Description, offset: usize) usize {
        var iterator = line.Iterator{ .text = self.text, .pos = offset };

        // The first line the walk returns is the one at `offset`, so it is stepped over.
        _ = iterator.next();

        while (iterator.next()) |item| {
            if (item.kind == .MEDIA) return item.offset;
        }

        return self.text.len;
    }
};

/// Read a whole session description.
///
/// Param:
/// text - []const u8 (borrowed, must outlive everything read out of the result)
///
/// Return:
/// - Description borrowing `text`
/// - error.ZixMalformed if any line is not a type, an equals sign, and a value
/// - error.ZixUnsupportedVersion
/// - error.ZixMissingField
pub fn parse(text: []const u8) Error!Description {
    line.validate(text) catch return error.ZixMalformed;

    const version = line.find(text, .VERSION) orelse return error.ZixMissingField;

    if (!std.mem.eql(u8, version.value, VERSION)) return error.ZixUnsupportedVersion;
    if (line.find(text, .ORIGIN) == null) return error.ZixMissingField;
    if (line.find(text, .SESSION_NAME) == null) return error.ZixMissingField;
    if (line.find(text, .TIME) == null) return error.ZixMissingField;

    const first_media = line.find(text, .MEDIA);
    const session_end = if (first_media) |item| item.offset else text.len;

    return .{ .text = text, .session = text[0..session_end] };
}

// --------------------------------------------------------------------------------------- //
// test cases

const offer: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0\r\n" ++
    "a=ice-ufrag:4ZcD\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:0\r\n" ++
    "a=sctp-port:5000\r\n";

const bundled: []const u8 =
    "v=0\r\n" ++
    "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
    "a=mid:0\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "a=mid:1\r\n" ++
    "a=sctp-port:5000\r\n";

test "zix sdp: session parse, a data channel offer is accepted" {
    const parsed = try parse(offer);

    try std.testing.expectEqual(@as(usize, 1), parsed.sectionCount());
}

test "zix sdp: session parse, the session level stops at the first media line" {
    const parsed = try parse(offer);

    try std.testing.expect(std.mem.endsWith(u8, parsed.session, "a=ice-ufrag:4ZcD\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, parsed.session, "m=") == null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.session, "sctp-port") == null);
}

test "zix sdp: session parse, a description with no media section is all session level" {
    const text = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const parsed = try parse(text);

    try std.testing.expectEqualStrings(text, parsed.session);
    try std.testing.expectEqual(@as(usize, 0), parsed.sectionCount());
    try std.testing.expect(parsed.section(0) == null);
}

test "zix sdp: session parse, a malformed line is refused" {
    try std.testing.expectError(error.ZixMalformed, parse("v=0\r\nbroken\r\n"));
}

test "zix sdp: session parse, a missing mandatory field is refused" {
    try std.testing.expectError(error.ZixMissingField, parse("v=0\r\ns=-\r\nt=0 0\r\n"));
    try std.testing.expectError(error.ZixMissingField, parse("v=0\r\no=- 1 2 IN IP4 1.2.3.4\r\nt=0 0\r\n"));
    try std.testing.expectError(error.ZixMissingField, parse("v=0\r\no=- 1 2 IN IP4 1.2.3.4\r\ns=-\r\n"));
    try std.testing.expectError(error.ZixMissingField, parse("o=- 1 2 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n"));
}

test "zix sdp: session parse, a version other than zero is refused" {
    try std.testing.expectError(
        error.ZixUnsupportedVersion,
        parse("v=1\r\no=- 1 2 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n"),
    );
}

test "zix sdp: session section, the region covers the media line and its attributes" {
    const parsed = try parse(offer);
    const found = parsed.section(0) orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.startsWith(u8, found.text, "m=application"));
    try std.testing.expect(std.mem.indexOf(u8, found.text, "a=sctp-port:5000") != null);
    try std.testing.expect(std.mem.indexOf(u8, found.text, "a=ice-ufrag") == null);
}

test "zix sdp: session section, a section stops at the next media line" {
    const parsed = try parse(bundled);
    const first = parsed.section(0) orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.startsWith(u8, first.text, "m=audio"));
    try std.testing.expect(std.mem.indexOf(u8, first.text, "a=mid:0") != null);
    try std.testing.expect(std.mem.indexOf(u8, first.text, "a=mid:1") == null);
    try std.testing.expect(std.mem.indexOf(u8, first.text, "sctp-port") == null);
}

test "zix sdp: session section, the last section runs to the end" {
    const parsed = try parse(bundled);
    const second = parsed.section(1) orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.startsWith(u8, second.text, "m=application"));
    try std.testing.expect(std.mem.endsWith(u8, second.text, "a=sctp-port:5000\r\n"));
}

test "zix sdp: session section, an index past the end gives null" {
    const parsed = try parse(bundled);

    try std.testing.expectEqual(@as(usize, 2), parsed.sectionCount());
    try std.testing.expect(parsed.section(2) == null);
}

test "zix sdp: session section, the media line reads out of the region" {
    const parsed = try parse(offer);
    const found = parsed.section(0) orelse return error.TestUnexpectedResult;
    const media_line = try found.mediaLine();

    try std.testing.expectEqualStrings("application", media_line.media);
    try std.testing.expectEqual(@as(u16, 9), media_line.port);
}

test "zix sdp: session dataChannelSection, the data channel is picked out of a bundle" {
    const parsed = try parse(bundled);
    const found = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.indexOf(u8, found.text, "a=mid:1") != null);
}

test "zix sdp: session dataChannelSection, a session with no data channel gives null" {
    const audio_only: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n";

    const parsed = try parse(audio_only);

    try std.testing.expect(parsed.dataChannelSection() == null);
}

test "zix sdp: session dataChannelSection, a malformed media line is passed over" {
    const broken: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:1\r\n";

    const parsed = try parse(broken);
    const found = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.indexOf(u8, found.text, "a=mid:1") != null);
}

test "zix sdp: session parse, a description terminated with bare newlines is accepted" {
    const text = "v=0\no=- 1 2 IN IP4 127.0.0.1\ns=-\nt=0 0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\n";
    const parsed = try parse(text);

    try std.testing.expectEqual(@as(usize, 1), parsed.sectionCount());
    try std.testing.expect(parsed.dataChannelSection() != null);
}
