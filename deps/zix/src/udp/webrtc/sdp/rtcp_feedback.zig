//! zix SDP feedback negotiation (RFC 4585 4.2).
//!
//! What:
//! - The `a=rtcp-fb` line, which says what control messages a peer will send and understand for
//!   one payload type. This is where a peer and zix agree that NACKs and keyframe requests are
//!   worth sending at all.
//!
//! Note:
//! - Answer only what is actually implemented. An `a=rtcp-fb` in an answer is a promise to act on
//!   that message, and promising one nothing handles means the peer stops sending the feedback
//!   that would have worked and waits on a reply that never comes. udp/webrtc/media/feedback.zig
//!   is the whole list: generic NACK, and NACK with a picture loss indication.
//! - The payload type may be `*`, which applies the entry to every format in the section. It is
//!   kept as a wildcard rather than expanded, because the format list is the section's business
//!   and this file only reads one line.
//! - An entry with no parameter is not the same as one with a parameter. "nack" alone is the
//!   generic retransmission request, and "nack pli" is a keyframe request. Treating them as one
//!   answers a request for keyframes with a promise to retransmit.

const std = @import("std");

const attribute = @import("attribute.zig");

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "rtcp-fb";

/// The payload type field that means every format in the section.
pub const WILDCARD: []const u8 = "*";

/// The longest value this writes.
pub const MAX_VALUE_LEN: usize = 64;

/// What stops a feedback line from being read.
pub const Error = error{
    /// Not a payload type, a space, and a feedback type.
    ZixMalformed,
    /// A payload type that is neither `*` nor a number that fits.
    ZixBadPayloadType,
};

/// Which payload types an entry covers.
pub const Applies = union(enum) {
    /// Every format in the section.
    ALL,
    /// One format.
    ONE: u7,
};

/// One feedback entry.
pub const Feedback = struct {
    applies: Applies,
    /// "nack", "ack", "ccm", "trr-int", or a registered name.
    kind: []const u8,
    /// "pli", "fir", "rpsi", and so on. Absent for the plain form.
    parameter: ?[]const u8,

    /// Whether this entry covers a payload type.
    ///
    /// Param:
    /// payload_type - u7
    ///
    /// Return:
    /// - bool
    pub fn covers(self: Feedback, payload_type: u7) bool {
        return switch (self.applies) {
            .ALL => true,
            .ONE => |only| only == payload_type,
        };
    }

    /// Whether zix implements the message this entry names.
    ///
    /// Note:
    /// - The list is short on purpose and matches udp/webrtc/media/feedback.zig exactly. Adding a
    ///   name here without the code behind it puts a promise in the answer that is not kept.
    ///
    /// Return:
    /// - bool
    pub fn isSupported(self: Feedback) bool {
        if (!std.mem.eql(u8, self.kind, "nack")) return false;

        const parameter = self.parameter orelse return true;

        return std.mem.eql(u8, parameter, "pli");
    }
};

/// Read an `a=rtcp-fb` value.
///
/// Param:
/// value - []const u8 (everything after `rtcp-fb:`, borrowed)
///
/// Return:
/// - Feedback borrowing `value`
/// - error.ZixMalformed, error.ZixBadPayloadType
pub fn read(value: []const u8) Error!Feedback {
    const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.ZixMalformed;

    if (space == 0) return error.ZixBadPayloadType;

    const rest = value[space + 1 ..];

    if (rest.len == 0) return error.ZixMalformed;

    const applies: Applies = if (std.mem.eql(u8, value[0..space], WILDCARD))
        .ALL
    else
        .{ .ONE = std.fmt.parseInt(u7, value[0..space], 10) catch return error.ZixBadPayloadType };

    const split = std.mem.indexOfScalar(u8, rest, ' ');
    const kind = if (split) |at| rest[0..at] else rest;

    if (kind.len == 0) return error.ZixMalformed;

    var parameter: ?[]const u8 = null;
    if (split) |at| {
        const tail = rest[at + 1 ..];

        if (tail.len == 0) return error.ZixMalformed;

        parameter = tail;
    }

    return .{ .applies = applies, .kind = kind, .parameter = parameter };
}

/// A walk over the feedback entries that cover one payload type.
pub const Entries = struct {
    /// The media section, borrowed.
    section: []const u8,
    payload_type: u7,
    walk: attribute.Iterator,

    /// The next entry covering the payload type, or null at the end.
    ///
    /// Return:
    /// - ?Feedback borrowing the section
    pub fn next(self: *Entries) ?Feedback {
        while (self.walk.next()) |entry| {
            if (!std.mem.eql(u8, entry.name, ATTRIBUTE)) continue;

            const value = entry.value orelse continue;
            const parsed = read(value) catch continue;

            if (parsed.covers(self.payload_type)) return parsed;
        }

        return null;
    }
};

/// Open a walk over one payload type's feedback entries.
///
/// Param:
/// section - []const u8 (a media section, borrowed)
/// payload_type - u7
///
/// Return:
/// - Entries borrowing `section`
pub fn begin(section: []const u8, payload_type: u7) Entries {
    return .{
        .section = section,
        .payload_type = payload_type,
        .walk = attribute.Iterator.begin(section),
    };
}

/// Whether a payload type was offered a feedback message zix implements.
///
/// Param:
/// section - []const u8
/// payload_type - u7
/// kind - []const u8
/// parameter - ?[]const u8
///
/// Return:
/// - bool
pub fn offers(section: []const u8, payload_type: u7, kind: []const u8, parameter: ?[]const u8) bool {
    var walk = begin(section, payload_type);

    while (walk.next()) |entry| {
        if (!std.mem.eql(u8, entry.kind, kind)) continue;

        if (parameter) |wanted| {
            const carried = entry.parameter orelse continue;

            if (std.mem.eql(u8, carried, wanted)) return true;

            continue;
        }

        if (entry.parameter == null) return true;
    }

    return false;
}

/// Write an `a=rtcp-fb` value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// entry - Feedback
///
/// Return:
/// - []const u8, the value alone, with no attribute name and no terminator
/// - error.ZixNoSpace
pub fn write(out: []u8, entry: Feedback) error{ZixNoSpace}![]const u8 {
    var head: [3]u8 = undefined;
    const applies = switch (entry.applies) {
        .ALL => WILDCARD,
        .ONE => |only| writeNumber(&head, only),
    };

    const parameter_len = if (entry.parameter) |text| 1 + text.len else 0;
    const total = applies.len + 1 + entry.kind.len + parameter_len;

    if (out.len < total) return error.ZixNoSpace;

    var at: usize = 0;
    @memcpy(out[at..][0..applies.len], applies);
    at += applies.len;

    out[at] = ' ';
    at += 1;

    @memcpy(out[at..][0..entry.kind.len], entry.kind);
    at += entry.kind.len;

    if (entry.parameter) |text| {
        out[at] = ' ';
        at += 1;

        @memcpy(out[at..][0..text.len], text);
        at += text.len;
    }

    return out[0..total];
}

/// Write a payload type in base ten.
fn writeNumber(out: *[3]u8, value: u7) []const u8 {
    var digits: [3]u8 = undefined;
    var count: usize = 0;
    var left: u8 = value;

    while (true) {
        digits[count] = '0' + (left % 10);
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return out[0..count];
}

// --------------------------------------------------------------------------------------- //
// test cases

const video_section: []const u8 =
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
    "a=rtpmap:96 VP8/90000\r\n" ++
    "a=rtcp-fb:96 goog-remb\r\n" ++
    "a=rtcp-fb:96 transport-cc\r\n" ++
    "a=rtcp-fb:96 ccm fir\r\n" ++
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n";

test "zix sdp: rtcp-fb read, the plain form has no parameter" {
    const parsed = try read("96 nack");

    try std.testing.expectEqual(@as(u7, 96), parsed.applies.ONE);
    try std.testing.expectEqualStrings("nack", parsed.kind);
    try std.testing.expect(parsed.parameter == null);
}

test "zix sdp: rtcp-fb read, a parameter is split from the kind" {
    const parsed = try read("96 nack pli");

    try std.testing.expectEqualStrings("nack", parsed.kind);
    try std.testing.expectEqualStrings("pli", parsed.parameter.?);
}

test "zix sdp: rtcp-fb read, the wildcard applies to every format" {
    const parsed = try read("* nack");

    try std.testing.expectEqual(Applies.ALL, parsed.applies);
    try std.testing.expect(parsed.covers(0));
    try std.testing.expect(parsed.covers(127));
}

test "zix sdp: rtcp-fb read, a numbered entry covers only its own format" {
    const parsed = try read("96 nack");

    try std.testing.expect(parsed.covers(96));
    try std.testing.expect(!parsed.covers(97));
}

test "zix sdp: rtcp-fb read, a malformed value is refused" {
    try std.testing.expectError(error.ZixMalformed, read("96"));
    try std.testing.expectError(error.ZixMalformed, read("96 "));
    try std.testing.expectError(error.ZixMalformed, read("96 nack "));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: rtcp-fb read, a bad payload type is refused" {
    try std.testing.expectError(error.ZixBadPayloadType, read(" nack"));
    try std.testing.expectError(error.ZixBadPayloadType, read("x nack"));
    try std.testing.expectError(error.ZixBadPayloadType, read("200 nack"));
}

test "zix sdp: rtcp-fb isSupported, only what feedback.zig actually sends" {
    try std.testing.expect((try read("96 nack")).isSupported());
    try std.testing.expect((try read("96 nack pli")).isSupported());

    // These are real and common, and zix implements none of them. Answering them would promise
    // bandwidth estimation and keyframe requests that nothing here produces.
    try std.testing.expect(!(try read("96 goog-remb")).isSupported());
    try std.testing.expect(!(try read("96 transport-cc")).isSupported());
    try std.testing.expect(!(try read("96 ccm fir")).isSupported());
    try std.testing.expect(!(try read("96 nack rpsi")).isSupported());
    try std.testing.expect(!(try read("96 ack")).isSupported());
}

test "zix sdp: rtcp-fb begin, a walk gives every entry for one format" {
    var walk = begin(video_section, 96);
    var count: usize = 0;
    var supported: usize = 0;

    while (walk.next()) |entry| {
        count += 1;

        if (entry.isSupported()) supported += 1;
    }

    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expectEqual(@as(usize, 2), supported);
}

test "zix sdp: rtcp-fb begin, a format with no entries walks empty" {
    var walk = begin(video_section, 97);

    try std.testing.expect(walk.next() == null);
}

test "zix sdp: rtcp-fb begin, a wildcard entry reaches every format" {
    const wildcarded: []const u8 =
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
        "a=rtcp-fb:* nack\r\n";

    var first = begin(wildcarded, 96);
    var second = begin(wildcarded, 97);

    try std.testing.expect(first.next() != null);
    try std.testing.expect(second.next() != null);
}

test "zix sdp: rtcp-fb offers, the plain and parameter forms are different questions" {
    try std.testing.expect(offers(video_section, 96, "nack", null));
    try std.testing.expect(offers(video_section, 96, "nack", "pli"));
    try std.testing.expect(!offers(video_section, 96, "nack", "rpsi"));
    try std.testing.expect(!offers(video_section, 97, "nack", null));

    const pli_only: []const u8 = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtcp-fb:96 nack pli\r\n";
    try std.testing.expect(offers(pli_only, 96, "nack", "pli"));
    try std.testing.expect(!offers(pli_only, 96, "nack", null));
}

test "zix sdp: rtcp-fb begin, a malformed line is passed over rather than fatal" {
    const ragged: []const u8 =
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=rtcp-fb:broken\r\n" ++
        "a=rtcp-fb:96 nack\r\n";

    var walk = begin(ragged, 96);

    try std.testing.expectEqualStrings("nack", walk.next().?.kind);
    try std.testing.expect(walk.next() == null);
}

test "zix sdp: rtcp-fb write, what was written reads back the same" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;

    const plain = try write(&buf, .{ .applies = .{ .ONE = 96 }, .kind = "nack", .parameter = null });
    try std.testing.expectEqualStrings("96 nack", plain);

    var other: [MAX_VALUE_LEN]u8 = undefined;
    const with_parameter = try write(&other, .{ .applies = .{ .ONE = 96 }, .kind = "nack", .parameter = "pli" });
    try std.testing.expectEqualStrings("96 nack pli", with_parameter);

    try std.testing.expectEqualStrings("pli", (try read(with_parameter)).parameter.?);
}

test "zix sdp: rtcp-fb write, the wildcard writes as a star" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, .{ .applies = .ALL, .kind = "nack", .parameter = null });

    try std.testing.expectEqualStrings("* nack", written);
    try std.testing.expectEqual(Applies.ALL, (try read(written)).applies);
}

test "zix sdp: rtcp-fb write, a short buffer errors" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(
        error.ZixNoSpace,
        write(&buf, .{ .applies = .{ .ONE = 96 }, .kind = "nack", .parameter = "pli" }),
    );
}

test "zix sdp: rtcp-fb, only the supported entries survive into an answer" {
    // The whole point of the file: five entries offered, two answered, and the three dropped are
    // the ones nothing here would act on.
    var walk = begin(video_section, 96);
    var scratch: [2][MAX_VALUE_LEN]u8 = undefined;
    var written: [2][]const u8 = undefined;
    var count: usize = 0;

    while (walk.next()) |entry| {
        if (!entry.isSupported()) continue;

        written[count] = try write(&scratch[count], entry);
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("96 nack", written[0]);
    try std.testing.expectEqualStrings("96 nack pli", written[1]);
}
