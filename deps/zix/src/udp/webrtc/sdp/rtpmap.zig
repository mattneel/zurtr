//! zix SDP payload type mapping (RFC 8866 6.6).
//!
//! What:
//! - The `a=rtpmap` line, which says what a payload type number means: which encoding, at which
//!   clock rate, with how many channels.
//!
//! Note:
//! - zix carries no codecs, so the encoding name is read and never interpreted. It is carried
//!   from the offer into the answer so the peer sees the number it proposed meaning what it
//!   proposed, and nothing here decides whether "opus" is something zix can play.
//! - A section carries one of these per payload type, so a lookup is by number and not by
//!   attribute name. Taking the first `a=rtpmap` in a section reads whichever codec the peer
//!   happened to list first.
//! - The encoding parameters field is the channel count for audio and is absent for video. It is
//!   kept as text for the same reason the encoding name is: this file is not the one that knows
//!   what a channel is.
//! - Payload types below 96 have static meanings (RFC 3551), so an offer may leave their rtpmap
//!   out. A missing line is not an error, it is a payload type that describes itself.

const std = @import("std");

const attribute = @import("attribute.zig");

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "rtpmap";

/// The first payload type that has no static meaning (RFC 3551 6).
pub const FIRST_DYNAMIC_TYPE: u7 = 96;

/// The longest value this writes, for an encoding name and parameters of sane length.
pub const MAX_VALUE_LEN: usize = 96;

/// What stops a mapping from being read.
pub const Error = error{
    /// Not a payload type, a space, an encoding name, a slash, and a clock rate.
    ZixMalformed,
    /// A payload type that is not a number, or one past 127.
    ZixBadPayloadType,
    /// A clock rate that is not a number.
    ZixBadClockRate,
};

/// What one payload type number means.
pub const RtpMap = struct {
    payload_type: u7,
    /// The encoding name as written, never interpreted here.
    encoding: []const u8,
    clock_rate: u32,
    /// The channel count for audio, absent for video.
    parameters: ?[]const u8,
};

/// Whether a payload type carries its own meaning without an `a=rtpmap` (RFC 3551 6).
///
/// Param:
/// payload_type - u7
///
/// Return:
/// - bool
pub fn isStatic(payload_type: u7) bool {
    return payload_type < FIRST_DYNAMIC_TYPE;
}

/// Read an `a=rtpmap` value.
///
/// Param:
/// value - []const u8 (everything after `rtpmap:`, borrowed)
///
/// Return:
/// - RtpMap borrowing `value`
/// - error.ZixMalformed, error.ZixBadPayloadType, error.ZixBadClockRate
pub fn read(value: []const u8) Error!RtpMap {
    const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.ZixMalformed;
    const payload_type = try readPayloadType(value[0..space]);
    const rest = value[space + 1 ..];

    if (rest.len == 0) return error.ZixMalformed;

    const first_slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.ZixMalformed;
    const encoding = rest[0..first_slash];

    if (encoding.len == 0) return error.ZixMalformed;

    const after = rest[first_slash + 1 ..];
    const second_slash = std.mem.indexOfScalar(u8, after, '/');
    const rate_text = if (second_slash) |at| after[0..at] else after;

    if (rate_text.len == 0) return error.ZixBadClockRate;

    var parameters: ?[]const u8 = null;
    if (second_slash) |at| {
        const tail = after[at + 1 ..];

        if (tail.len == 0) return error.ZixMalformed;

        parameters = tail;
    }

    return .{
        .payload_type = payload_type,
        .encoding = encoding,
        .clock_rate = std.fmt.parseInt(u32, rate_text, 10) catch return error.ZixBadClockRate,
        .parameters = parameters,
    };
}

/// The `a=rtpmap` value for one payload type, out of a section.
///
/// Param:
/// section - []const u8 (a media section, borrowed)
/// payload_type - u7
///
/// Return:
/// - ?[]const u8, the value as written, borrowing `section`
pub fn findValue(section: []const u8, payload_type: u7) ?[]const u8 {
    var walk = attribute.Iterator.begin(section);

    while (walk.next()) |entry| {
        if (!std.mem.eql(u8, entry.name, ATTRIBUTE)) continue;

        const value = entry.value orelse continue;
        const parsed = read(value) catch continue;

        if (parsed.payload_type == payload_type) return value;
    }

    return null;
}

/// The mapping for one payload type, out of a section.
///
/// Param:
/// section - []const u8
/// payload_type - u7
///
/// Return:
/// - ?RtpMap borrowing `section`
pub fn find(section: []const u8, payload_type: u7) ?RtpMap {
    const value = findValue(section, payload_type) orelse return null;

    return read(value) catch null;
}

/// How many bytes a value will take.
///
/// Param:
/// entry - RtpMap
///
/// Return:
/// - usize, an upper bound, since the numbers are written as short as they go
pub fn valueLen(entry: RtpMap) usize {
    const parameters_len = if (entry.parameters) |text| 1 + text.len else 0;

    return 3 + 1 + entry.encoding.len + 1 + 10 + parameters_len;
}

/// Write an `a=rtpmap` value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// entry - RtpMap
///
/// Return:
/// - []const u8, the value alone, with no attribute name and no terminator
/// - error.ZixNoSpace
pub fn write(out: []u8, entry: RtpMap) error{ZixNoSpace}![]const u8 {
    var at: usize = 0;

    at += try writeNumber(out[at..], entry.payload_type);
    at += try writeByte(out[at..], ' ');
    at += try writeText(out[at..], entry.encoding);
    at += try writeByte(out[at..], '/');
    at += try writeNumber(out[at..], entry.clock_rate);

    if (entry.parameters) |text| {
        at += try writeByte(out[at..], '/');
        at += try writeText(out[at..], text);
    }

    return out[0..at];
}

/// Read a payload type field.
fn readPayloadType(text: []const u8) Error!u7 {
    if (text.len == 0) return error.ZixBadPayloadType;

    return std.fmt.parseInt(u7, text, 10) catch error.ZixBadPayloadType;
}

/// Append one byte.
fn writeByte(out: []u8, value: u8) error{ZixNoSpace}!usize {
    if (out.len < 1) return error.ZixNoSpace;

    out[0] = value;

    return 1;
}

/// Append text.
fn writeText(out: []u8, text: []const u8) error{ZixNoSpace}!usize {
    if (out.len < text.len) return error.ZixNoSpace;

    @memcpy(out[0..text.len], text);

    return text.len;
}

/// Append a number in base ten.
fn writeNumber(out: []u8, value: u32) error{ZixNoSpace}!usize {
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var left = value;

    while (true) {
        digits[count] = '0' + @as(u8, @intCast(left % 10));
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    if (out.len < count) return error.ZixNoSpace;

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return count;
}

// --------------------------------------------------------------------------------------- //
// test cases

const audio_section: []const u8 =
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 0\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=rtpmap:103 ISAC/16000\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n";

test "zix sdp: rtpmap read, an audio mapping reads field for field" {
    const parsed = try read("111 opus/48000/2");

    try std.testing.expectEqual(@as(u7, 111), parsed.payload_type);
    try std.testing.expectEqualStrings("opus", parsed.encoding);
    try std.testing.expectEqual(@as(u32, 48000), parsed.clock_rate);
    try std.testing.expectEqualStrings("2", parsed.parameters.?);
}

test "zix sdp: rtpmap read, a video mapping has no parameters" {
    const parsed = try read("96 VP8/90000");

    try std.testing.expectEqual(@as(u7, 96), parsed.payload_type);
    try std.testing.expectEqualStrings("VP8", parsed.encoding);
    try std.testing.expectEqual(@as(u32, 90000), parsed.clock_rate);
    try std.testing.expect(parsed.parameters == null);
}

test "zix sdp: rtpmap read, the encoding name is not interpreted" {
    // Anything the peer wants to call it comes back as itself. zix has no codec table to check
    // it against, and inventing one would refuse encodings it forwards perfectly well.
    const parsed = try read("100 something-nobody-has-heard-of/8000");

    try std.testing.expectEqualStrings("something-nobody-has-heard-of", parsed.encoding);
}

test "zix sdp: rtpmap read, a malformed value is refused" {
    try std.testing.expectError(error.ZixMalformed, read("111"));
    try std.testing.expectError(error.ZixMalformed, read("111 "));
    try std.testing.expectError(error.ZixMalformed, read("111 opus"));
    try std.testing.expectError(error.ZixMalformed, read("111 /48000"));
    try std.testing.expectError(error.ZixMalformed, read("111 opus/48000/"));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: rtpmap read, a bad payload type is refused" {
    try std.testing.expectError(error.ZixBadPayloadType, read("x opus/48000"));
    try std.testing.expectError(error.ZixBadPayloadType, read(" opus/48000"));

    // 128 does not fit the 7-bit field.
    try std.testing.expectError(error.ZixBadPayloadType, read("128 opus/48000"));
    try std.testing.expectEqual(@as(u7, 127), (try read("127 opus/48000")).payload_type);
}

test "zix sdp: rtpmap read, a bad clock rate is refused" {
    try std.testing.expectError(error.ZixBadClockRate, read("111 opus/"));
    try std.testing.expectError(error.ZixBadClockRate, read("111 opus/x"));
}

test "zix sdp: rtpmap find, a section is searched by number and not by order" {
    // The failure this guards against: taking the first a=rtpmap gives opus whichever number
    // was actually asked for.
    const second = find(audio_section, 103).?;

    try std.testing.expectEqualStrings("ISAC", second.encoding);
    try std.testing.expectEqual(@as(u32, 16000), second.clock_rate);

    const first = find(audio_section, 111).?;
    try std.testing.expectEqualStrings("opus", first.encoding);
}

test "zix sdp: rtpmap find, a payload type with no mapping gives null" {
    // Payload type 0 is in the format list and has no rtpmap, because it describes itself.
    try std.testing.expect(find(audio_section, 0) == null);
    try std.testing.expect(findValue(audio_section, 0) == null);
    try std.testing.expect(find(audio_section, 99) == null);
}

test "zix sdp: rtpmap find, a malformed line is passed over rather than fatal" {
    const ragged: []const u8 =
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=rtpmap:broken\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    try std.testing.expectEqualStrings("opus", find(ragged, 111).?.encoding);
}

test "zix sdp: rtpmap findValue, the value comes back as the peer wrote it" {
    try std.testing.expectEqualStrings("111 opus/48000/2", findValue(audio_section, 111).?);
}

test "zix sdp: rtpmap isStatic, the dynamic range starts at 96" {
    try std.testing.expect(isStatic(0));
    try std.testing.expect(isStatic(95));
    try std.testing.expect(!isStatic(96));
    try std.testing.expect(!isStatic(127));
}

test "zix sdp: rtpmap write, what was written reads back the same" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, .{
        .payload_type = 111,
        .encoding = "opus",
        .clock_rate = 48000,
        .parameters = "2",
    });

    try std.testing.expectEqualStrings("111 opus/48000/2", written);

    const parsed = try read(written);
    try std.testing.expectEqual(@as(u7, 111), parsed.payload_type);
    try std.testing.expectEqualStrings("2", parsed.parameters.?);
}

test "zix sdp: rtpmap write, a mapping with no parameters writes two fields" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, .{
        .payload_type = 96,
        .encoding = "VP8",
        .clock_rate = 90000,
        .parameters = null,
    });

    try std.testing.expectEqualStrings("96 VP8/90000", written);
}

test "zix sdp: rtpmap write, a short buffer errors" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .{
        .payload_type = 111,
        .encoding = "opus",
        .clock_rate = 48000,
        .parameters = "2",
    }));
}

test "zix sdp: rtpmap valueLen, the estimate covers what was written" {
    const entry = RtpMap{
        .payload_type = 111,
        .encoding = "opus",
        .clock_rate = 48000,
        .parameters = "2",
    };

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, entry);

    try std.testing.expect(valueLen(entry) >= written.len);
}

test "zix sdp: rtpmap, an offered mapping survives a round trip unchanged" {
    // What the answer builder does: read what the peer proposed and hand the same meaning back.
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const offered = findValue(audio_section, 111).?;
    const written = try write(&buf, try read(offered));

    try std.testing.expectEqualStrings(offered, written);
}
