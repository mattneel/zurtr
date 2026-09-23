//! zix SDP format parameters (RFC 8866 6.15).
//!
//! What:
//! - The `a=fmtp` line, which carries codec settings for one payload type.
//!
//! Note:
//! - The parameters are opaque here, and deliberately so. They are a codec's own language
//!   ("minptime=10;useinbandfec=1" means something to an Opus encoder and nothing to a
//!   forwarder), and zix has no encoder to hand them to.
//! - Opaque does not mean droppable. An answer that omits the parameters the offer carried tells
//!   the peer to fall back to defaults, which changes how it encodes. They are carried across
//!   unchanged for exactly that reason.
//! - This is the one attribute in the media set whose value legitimately contains semicolons.
//!   Nothing here splits on them.

const std = @import("std");

const attribute = @import("attribute.zig");

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "fmtp";

/// What stops a parameter line from being read.
pub const Error = error{
    /// Not a payload type, a space, and at least one parameter byte.
    ZixMalformed,
    /// A payload type that is not a number, or one past 127.
    ZixBadPayloadType,
};

/// One payload type's settings.
pub const Fmtp = struct {
    payload_type: u7,
    /// Everything after the space, as the peer wrote it.
    parameters: []const u8,
};

/// Read an `a=fmtp` value.
///
/// Param:
/// value - []const u8 (everything after `fmtp:`, borrowed)
///
/// Return:
/// - Fmtp borrowing `value`
/// - error.ZixMalformed, error.ZixBadPayloadType
pub fn read(value: []const u8) Error!Fmtp {
    const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.ZixMalformed;

    if (space == 0) return error.ZixBadPayloadType;

    const parameters = value[space + 1 ..];

    if (parameters.len == 0) return error.ZixMalformed;

    return .{
        .payload_type = std.fmt.parseInt(u7, value[0..space], 10) catch return error.ZixBadPayloadType,
        .parameters = parameters,
    };
}

/// The `a=fmtp` value for one payload type, out of a section.
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

/// The settings for one payload type, out of a section.
///
/// Param:
/// section - []const u8
/// payload_type - u7
///
/// Return:
/// - ?Fmtp borrowing `section`
pub fn find(section: []const u8, payload_type: u7) ?Fmtp {
    const value = findValue(section, payload_type) orelse return null;

    return read(value) catch null;
}

/// How many bytes a value will take.
///
/// Param:
/// entry - Fmtp
///
/// Return:
/// - usize
pub fn valueLen(entry: Fmtp) usize {
    return 3 + 1 + entry.parameters.len;
}

/// Write an `a=fmtp` value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// entry - Fmtp
///
/// Return:
/// - []const u8, the value alone, with no attribute name and no terminator
/// - error.ZixNoSpace
pub fn write(out: []u8, entry: Fmtp) error{ZixNoSpace}![]const u8 {
    var digits: [3]u8 = undefined;
    var count: usize = 0;
    var left: u8 = entry.payload_type;

    while (true) {
        digits[count] = '0' + (left % 10);
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    const total = count + 1 + entry.parameters.len;

    if (out.len < total) return error.ZixNoSpace;

    for (0..count) |index| out[index] = digits[count - 1 - index];

    out[count] = ' ';
    @memcpy(out[count + 1 ..][0..entry.parameters.len], entry.parameters);

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

const audio_section: []const u8 =
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 103\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
    "a=rtpmap:103 ISAC/16000\r\n";

test "zix sdp: fmtp read, a parameter line reads into two fields" {
    const parsed = try read("111 minptime=10;useinbandfec=1");

    try std.testing.expectEqual(@as(u7, 111), parsed.payload_type);
    try std.testing.expectEqualStrings("minptime=10;useinbandfec=1", parsed.parameters);
}

test "zix sdp: fmtp read, the parameters keep their semicolons and spaces" {
    // A codec's own language. Splitting it here would be inventing structure that the next
    // codec does not have.
    const parsed = try read("96 profile-level-id=42e01f;packetization-mode=1");

    try std.testing.expectEqualStrings("profile-level-id=42e01f;packetization-mode=1", parsed.parameters);

    const spaced = try read("97 apt=96; x=1");
    try std.testing.expectEqualStrings("apt=96; x=1", spaced.parameters);
}

test "zix sdp: fmtp read, a malformed value is refused" {
    try std.testing.expectError(error.ZixMalformed, read("111"));
    try std.testing.expectError(error.ZixMalformed, read("111 "));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: fmtp read, a bad payload type is refused" {
    try std.testing.expectError(error.ZixBadPayloadType, read(" minptime=10"));
    try std.testing.expectError(error.ZixBadPayloadType, read("x minptime=10"));
    try std.testing.expectError(error.ZixBadPayloadType, read("128 minptime=10"));
}

test "zix sdp: fmtp find, a section is searched by payload type" {
    try std.testing.expectEqualStrings("minptime=10;useinbandfec=1", find(audio_section, 111).?.parameters);
    try std.testing.expect(find(audio_section, 103) == null);
    try std.testing.expect(findValue(audio_section, 103) == null);
}

test "zix sdp: fmtp find, a malformed line is passed over rather than fatal" {
    const ragged: []const u8 =
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=fmtp:broken\r\n" ++
        "a=fmtp:111 minptime=10\r\n";

    try std.testing.expectEqualStrings("minptime=10", find(ragged, 111).?.parameters);
}

test "zix sdp: fmtp write, what was written reads back the same" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, .{ .payload_type = 111, .parameters = "minptime=10;useinbandfec=1" });

    try std.testing.expectEqualStrings("111 minptime=10;useinbandfec=1", written);
    try std.testing.expectEqual(@as(u7, 111), (try read(written)).payload_type);
}

test "zix sdp: fmtp write, a one-digit payload type writes one digit" {
    var buf: [32]u8 = undefined;
    const written = try write(&buf, .{ .payload_type = 0, .parameters = "x=1" });

    try std.testing.expectEqualStrings("0 x=1", written);
}

test "zix sdp: fmtp write, a short buffer errors" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .{ .payload_type = 111, .parameters = "minptime=10" }));
}

test "zix sdp: fmtp valueLen, the estimate covers what was written" {
    const entry = Fmtp{ .payload_type = 111, .parameters = "minptime=10" };

    var buf: [64]u8 = undefined;
    const written = try write(&buf, entry);

    try std.testing.expect(valueLen(entry) >= written.len);
}

test "zix sdp: fmtp, offered parameters survive a round trip unchanged" {
    // Dropping them would silently tell the peer to fall back to its defaults.
    var buf: [64]u8 = undefined;
    const offered = findValue(audio_section, 111).?;
    const written = try write(&buf, try read(offered));

    try std.testing.expectEqualStrings(offered, written);
}
