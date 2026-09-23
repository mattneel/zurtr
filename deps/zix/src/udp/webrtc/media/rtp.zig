//! zix RTP fixed header (RFC 3550 5.1, 5.3.1).
//!
//! What:
//! - Reading an RTP packet far enough to forward it: where the header ends, which stream it
//!   belongs to, and where it sits in that stream. Nothing below the payload is looked at.
//!
//! Note:
//! - zix carries no codecs, so the payload is bytes and stays bytes. The only reason to parse at
//!   all is that SRTP encrypts from the end of the header onward, so the header length has to be
//!   exact, CSRC list and header extension included.
//! - The extension is read as a profile number and a length, per RFC 3550 5.3.1. The one-byte and
//!   two-byte element forms of RFC 8285 are NOT parsed here, and the raw bytes are handed over so
//!   a later layer can do it without this one guessing.
//! - Padding is reported but not stripped. The pad count sits in the LAST byte of the payload,
//!   which SRTP has encrypted, so a receiver can only read it after unprotecting the packet.
//! - A forwarder rewrites the SSRC and the sequence number of packets it relays, so both have an
//!   in-place setter. Rewriting through a parsed copy and re-serialising would move the payload
//!   for no reason.

const std = @import("std");

/// The only RTP version there is (RFC 3550 5.1).
pub const VERSION: u2 = 2;

/// The fixed header, before any CSRC or extension.
pub const FIXED_HEADER_LEN: usize = 12;

/// Bytes one contributing source identifier takes.
pub const CSRC_LEN: usize = 4;

/// The most contributing sources the 4-bit count can name.
pub const MAX_CSRC_COUNT: usize = 15;

/// Profile and length, ahead of the extension body (RFC 3550 5.3.1).
pub const EXTENSION_HEADER_LEN: usize = 4;

/// The longest header a packet can carry: fixed, 15 CSRCs, and a full extension.
pub const MAX_HEADER_LEN: usize = FIXED_HEADER_LEN + MAX_CSRC_COUNT * CSRC_LEN + EXTENSION_HEADER_LEN + 0xFFFF * 4;

/// Where the SSRC sits, for an in-place rewrite.
const SSRC_AT: usize = 8;

/// Where the sequence number sits, for an in-place rewrite.
const SEQUENCE_AT: usize = 2;

/// Where the timestamp sits, for an in-place rewrite.
const TIMESTAMP_AT: usize = 4;

/// What stops a packet from being read.
pub const Error = error{
    /// Fewer bytes than the header fields say the packet has.
    ZixTruncated,
    /// A version other than 2.
    ZixUnsupportedVersion,
};

/// What stops padding from being stripped.
pub const PaddingError = error{
    /// The pad count is zero, or claims more bytes than the payload holds.
    ZixBadPadding,
};

/// The header fields a forwarder reads.
pub const Header = struct {
    /// Set when the payload ends with a pad count.
    has_padding: bool,
    /// Set when a header extension follows the CSRC list.
    has_extension: bool,
    /// How many contributing sources the header names.
    csrc_count: u4,
    /// Profile-defined, commonly the end of a talkspurt or a frame boundary.
    marker: bool,
    /// Which format the payload is in. Never interpreted here.
    payload_type: u7,
    sequence: u16,
    timestamp: u32,
    /// Which stream the packet belongs to.
    ssrc: u32,
};

/// One parsed packet, borrowed from the datagram it came in.
pub const Packet = struct {
    header: Header,
    /// Bytes from the start through the CSRC list and any header extension.
    header_len: usize,
    /// The contributing source list, four bytes per entry, empty when there is none.
    csrc: []const u8,
    /// The header extension body, without its profile and length, null when there is none.
    extension: ?[]const u8,
    /// The profile number an extension carries, null when there is none.
    extension_profile: ?u16,
    /// Everything after the header, padding included. This is what SRTP encrypts.
    payload: []const u8,

    /// The payload with any padding removed (RFC 3550 5.1).
    ///
    /// Note:
    /// - Only meaningful on a packet that is already in the clear. On a protected packet the last
    ///   byte is ciphertext, so the count read out of it is a random number.
    ///
    /// Return:
    /// - []const u8
    /// - error.ZixBadPadding for a zero count or one longer than the payload
    pub fn unpadded(self: Packet) PaddingError![]const u8 {
        if (!self.header.has_padding) return self.payload;
        if (self.payload.len == 0) return error.ZixBadPadding;

        const count = self.payload[self.payload.len - 1];

        if (count == 0 or count > self.payload.len) return error.ZixBadPadding;

        return self.payload[0 .. self.payload.len - count];
    }

    /// One contributing source by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?u32
    pub fn contributingSource(self: Packet, index: usize) ?u32 {
        if (index >= self.header.csrc_count) return null;

        return std.mem.readInt(u32, self.csrc[index * CSRC_LEN ..][0..4], .big);
    }
};

/// The fields `write` needs, for a packet with no CSRC list and no extension.
pub const Fields = struct {
    marker: bool = false,
    payload_type: u7,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
};

/// Read a packet header (RFC 3550 5.1).
///
/// Param:
/// packet - []const u8 (borrowed, must outlive the result)
///
/// Return:
/// - Packet borrowing `packet`
/// - error.ZixTruncated, error.ZixUnsupportedVersion
pub fn read(packet: []const u8) Error!Packet {
    if (packet.len < FIXED_HEADER_LEN) return error.ZixTruncated;

    const version: u2 = @intCast(packet[0] >> 6);

    if (version != VERSION) return error.ZixUnsupportedVersion;

    const csrc_count: u4 = @intCast(packet[0] & 0x0F);
    const csrc_at = FIXED_HEADER_LEN;
    const csrc_len = @as(usize, csrc_count) * CSRC_LEN;

    if (packet.len < csrc_at + csrc_len) return error.ZixTruncated;

    const header: Header = .{
        .has_padding = packet[0] & 0x20 != 0,
        .has_extension = packet[0] & 0x10 != 0,
        .csrc_count = csrc_count,
        .marker = packet[1] & 0x80 != 0,
        .payload_type = @intCast(packet[1] & 0x7F),
        .sequence = std.mem.readInt(u16, packet[2..4], .big),
        .timestamp = std.mem.readInt(u32, packet[4..8], .big),
        .ssrc = std.mem.readInt(u32, packet[8..12], .big),
    };

    var header_len = csrc_at + csrc_len;
    var extension: ?[]const u8 = null;
    var extension_profile: ?u16 = null;

    if (header.has_extension) {
        if (packet.len < header_len + EXTENSION_HEADER_LEN) return error.ZixTruncated;

        const words = std.mem.readInt(u16, packet[header_len + 2 ..][0..2], .big);
        const body_at = header_len + EXTENSION_HEADER_LEN;
        const body_len = @as(usize, words) * 4;

        if (packet.len < body_at + body_len) return error.ZixTruncated;

        extension_profile = std.mem.readInt(u16, packet[header_len..][0..2], .big);
        extension = packet[body_at..][0..body_len];
        header_len = body_at + body_len;
    }

    return .{
        .header = header,
        .header_len = header_len,
        .csrc = packet[csrc_at..][0..csrc_len],
        .extension = extension,
        .extension_profile = extension_profile,
        .payload = packet[header_len..],
    };
}

/// Where the header ends, without reading the rest.
///
/// Note:
/// - This is the number SRTP needs: everything from here to the end of the packet is encrypted.
///
/// Param:
/// packet - []const u8
///
/// Return:
/// - usize
/// - error.ZixTruncated, error.ZixUnsupportedVersion
pub fn headerLen(packet: []const u8) Error!usize {
    return (try read(packet)).header_len;
}

/// Build a packet with a fixed header and nothing else.
///
/// Note:
/// - No CSRC list and no extension. zix originates RTP only in tests and in a forwarder's own
///   probes, and both want the plain shape.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// fields - Fields
/// payload - []const u8 (copied in whole, padding is the caller's to add)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn write(out: []u8, fields: Fields, payload: []const u8) error{ZixNoSpace}![]const u8 {
    const total = FIXED_HEADER_LEN + payload.len;

    if (out.len < total) return error.ZixNoSpace;

    out[0] = @as(u8, VERSION) << 6;
    out[1] = (@as(u8, @intFromBool(fields.marker)) << 7) | @as(u8, fields.payload_type);

    std.mem.writeInt(u16, out[2..4], fields.sequence, .big);
    std.mem.writeInt(u32, out[4..8], fields.timestamp, .big);
    std.mem.writeInt(u32, out[8..12], fields.ssrc, .big);
    @memcpy(out[FIXED_HEADER_LEN..total], payload);

    return out[0..total];
}

/// Rewrite the SSRC of a packet in place.
///
/// Param:
/// packet - []u8 (a whole packet, header included)
/// ssrc - u32
///
/// Return:
/// - void
/// - error.ZixTruncated
pub fn setSsrc(packet: []u8, ssrc: u32) Error!void {
    if (packet.len < FIXED_HEADER_LEN) return error.ZixTruncated;

    std.mem.writeInt(u32, packet[SSRC_AT..][0..4], ssrc, .big);
}

/// Rewrite the sequence number of a packet in place.
///
/// Param:
/// packet - []u8 (a whole packet, header included)
/// sequence - u16
///
/// Return:
/// - void
/// - error.ZixTruncated
pub fn setSequence(packet: []u8, sequence: u16) Error!void {
    if (packet.len < FIXED_HEADER_LEN) return error.ZixTruncated;

    std.mem.writeInt(u16, packet[SEQUENCE_AT..][0..2], sequence, .big);
}

/// Rewrite the timestamp of a packet in place.
///
/// Note:
/// - A forwarder that switches which source it relays has to shift timestamps as well as
///   sequence numbers, or the receiver sees the clock jump backwards.
///
/// Param:
/// packet - []u8 (a whole packet, header included)
/// timestamp - u32
///
/// Return:
/// - void
/// - error.ZixTruncated
pub fn setTimestamp(packet: []u8, timestamp: u32) Error!void {
    if (packet.len < FIXED_HEADER_LEN) return error.ZixTruncated;

    std.mem.writeInt(u32, packet[TIMESTAMP_AT..][0..4], timestamp, .big);
}

// --------------------------------------------------------------------------------------- //
// test cases

/// A 12-byte header packet: marker clear, payload type 96, sequence 1, timestamp 0x11223344.
const sample: [16]u8 = .{
    0x80, 0x60, 0x00, 0x01,
    0x11, 0x22, 0x33, 0x44,
    0xDE, 0xAD, 0xBE, 0xEF,
    0xAA, 0xBB, 0xCC, 0xDD,
};

test "zix media: rtp read, the fixed header reads field for field" {
    const parsed = try read(&sample);

    try std.testing.expect(!parsed.header.has_padding);
    try std.testing.expect(!parsed.header.has_extension);
    try std.testing.expectEqual(@as(u4, 0), parsed.header.csrc_count);
    try std.testing.expect(!parsed.header.marker);
    try std.testing.expectEqual(@as(u7, 96), parsed.header.payload_type);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.sequence);
    try std.testing.expectEqual(@as(u32, 0x11223344), parsed.header.timestamp);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.header.ssrc);
    try std.testing.expectEqual(@as(usize, 12), parsed.header_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, parsed.payload);
}

test "zix media: rtp read, the marker bit is not part of the payload type" {
    // Payload type 96 with the marker set is byte 0xE0, and reading the whole byte gives 224.
    var marked = sample;
    marked[1] = 0x80 | 96;

    const parsed = try read(&marked);

    try std.testing.expect(parsed.header.marker);
    try std.testing.expectEqual(@as(u7, 96), parsed.header.payload_type);
}

test "zix media: rtp read, a version other than two is refused" {
    var wrong = sample;
    wrong[0] = 0x40;

    try std.testing.expectError(error.ZixUnsupportedVersion, read(&wrong));
}

test "zix media: rtp read, a packet shorter than the fixed header is refused" {
    try std.testing.expectError(error.ZixTruncated, read(sample[0..11]));
    try std.testing.expectError(error.ZixTruncated, read(&[_]u8{}));
}

test "zix media: rtp read, a header with no payload is legal" {
    const parsed = try read(sample[0..12]);

    try std.testing.expectEqual(@as(usize, 0), parsed.payload.len);
}

test "zix media: rtp read, the csrc list is counted into the header length" {
    var packet: [24]u8 = @splat(0);
    @memcpy(packet[0..12], sample[0..12]);
    packet[0] = 0x82;

    std.mem.writeInt(u32, packet[12..16], 0x01020304, .big);
    std.mem.writeInt(u32, packet[16..20], 0x05060708, .big);

    const parsed = try read(&packet);

    try std.testing.expectEqual(@as(u4, 2), parsed.header.csrc_count);
    try std.testing.expectEqual(@as(usize, 20), parsed.header_len);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.contributingSource(0).?);
    try std.testing.expectEqual(@as(u32, 0x05060708), parsed.contributingSource(1).?);
    try std.testing.expect(parsed.contributingSource(2) == null);
    try std.testing.expectEqual(@as(usize, 4), parsed.payload.len);
}

test "zix media: rtp read, a csrc list running past the packet is refused" {
    var packet: [16]u8 = sample;
    packet[0] = 0x8F;

    try std.testing.expectError(error.ZixTruncated, read(&packet));
}

test "zix media: rtp read, an extension is measured in 32-bit words" {
    var packet: [24]u8 = @splat(0);
    @memcpy(packet[0..12], sample[0..12]);
    packet[0] = 0x90;

    // Profile 0xBEDE, two words of body.
    std.mem.writeInt(u16, packet[12..14], 0xBEDE, .big);
    std.mem.writeInt(u16, packet[14..16], 2, .big);
    packet[16] = 0x11;
    packet[23] = 0x99;

    const parsed = try read(&packet);

    try std.testing.expect(parsed.header.has_extension);
    try std.testing.expectEqual(@as(u16, 0xBEDE), parsed.extension_profile.?);
    try std.testing.expectEqual(@as(usize, 8), parsed.extension.?.len);
    try std.testing.expectEqual(@as(u8, 0x11), parsed.extension.?[0]);
    try std.testing.expectEqual(@as(usize, 24), parsed.header_len);
    try std.testing.expectEqual(@as(usize, 0), parsed.payload.len);
}

test "zix media: rtp read, an extension running past the packet is refused" {
    var packet: [16]u8 = sample;
    packet[0] = 0x90;

    std.mem.writeInt(u16, packet[12..14], 0xBEDE, .big);
    std.mem.writeInt(u16, packet[14..16], 4, .big);

    try std.testing.expectError(error.ZixTruncated, read(&packet));

    // The extension header itself can also be cut short.
    try std.testing.expectError(error.ZixTruncated, read(packet[0..14]));
}

test "zix media: rtp read, a csrc list and an extension both count" {
    var packet: [24]u8 = @splat(0);
    @memcpy(packet[0..12], sample[0..12]);
    packet[0] = 0x91;

    std.mem.writeInt(u32, packet[12..16], 0x0A0B0C0D, .big);
    std.mem.writeInt(u16, packet[16..18], 0xBEDE, .big);
    std.mem.writeInt(u16, packet[18..20], 1, .big);

    const parsed = try read(&packet);

    try std.testing.expectEqual(@as(u32, 0x0A0B0C0D), parsed.contributingSource(0).?);
    try std.testing.expectEqual(@as(usize, 24), parsed.header_len);
}

test "zix media: rtp unpadded, the count sits in the last byte and is part of the padding" {
    var packet: [16]u8 = sample;
    packet[0] = 0xA0;
    packet[15] = 3;

    const parsed = try read(&packet);

    try std.testing.expect(parsed.header.has_padding);
    try std.testing.expectEqual(@as(usize, 4), parsed.payload.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xAA}, try parsed.unpadded());
}

test "zix media: rtp unpadded, a bad count is refused" {
    var packet: [16]u8 = sample;
    packet[0] = 0xA0;

    // Zero is never a legal count, the byte itself is part of the padding.
    packet[15] = 0;
    try std.testing.expectError(error.ZixBadPadding, (try read(&packet)).unpadded());

    // Longer than the payload.
    packet[15] = 5;
    try std.testing.expectError(error.ZixBadPadding, (try read(&packet)).unpadded());

    // Padding claimed with no payload at all.
    var empty: [12]u8 = sample[0..12].*;
    empty[0] = 0xA0;
    try std.testing.expectError(error.ZixBadPadding, (try read(&empty)).unpadded());
}

test "zix media: rtp unpadded, a packet without the flag is handed back whole" {
    const parsed = try read(&sample);

    try std.testing.expectEqualSlices(u8, parsed.payload, try parsed.unpadded());
}

test "zix media: rtp unpadded, the whole payload can be padding" {
    var packet: [16]u8 = sample;
    packet[0] = 0xA0;
    packet[15] = 4;

    try std.testing.expectEqual(@as(usize, 0), (try (try read(&packet)).unpadded()).len);
}

test "zix media: rtp write, what was written reads back the same" {
    var buf: [32]u8 = undefined;
    const payload = [_]u8{ 1, 2, 3, 4, 5 };

    const written = try write(&buf, .{
        .marker = true,
        .payload_type = 111,
        .sequence = 0xFFFF,
        .timestamp = 0x89ABCDEF,
        .ssrc = 0x12345678,
    }, &payload);

    const parsed = try read(written);

    try std.testing.expectEqual(@as(usize, 17), written.len);
    try std.testing.expect(parsed.header.marker);
    try std.testing.expectEqual(@as(u7, 111), parsed.header.payload_type);
    try std.testing.expectEqual(@as(u16, 0xFFFF), parsed.header.sequence);
    try std.testing.expectEqual(@as(u32, 0x89ABCDEF), parsed.header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x12345678), parsed.header.ssrc);
    try std.testing.expectEqualSlices(u8, &payload, parsed.payload);
}

test "zix media: rtp write, the first two bytes are built bit by bit" {
    var buf: [12]u8 = undefined;
    const written = try write(&buf, .{ .payload_type = 0, .sequence = 0, .timestamp = 0, .ssrc = 0 }, &.{});

    try std.testing.expectEqual(@as(u8, 0x80), written[0]);
    try std.testing.expectEqual(@as(u8, 0x00), written[1]);
}

test "zix media: rtp write, a short buffer errors" {
    var buf: [11]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .{
        .payload_type = 96,
        .sequence = 1,
        .timestamp = 0,
        .ssrc = 0,
    }, &.{}));
}

test "zix media: rtp headerLen, it agrees with a full read" {
    var packet: [24]u8 = @splat(0);
    @memcpy(packet[0..12], sample[0..12]);
    packet[0] = 0x91;

    std.mem.writeInt(u16, packet[16..18], 0xBEDE, .big);
    std.mem.writeInt(u16, packet[18..20], 1, .big);

    try std.testing.expectEqual((try read(&packet)).header_len, try headerLen(&packet));
    try std.testing.expectEqual(@as(usize, 12), try headerLen(&sample));
}

test "zix media: rtp setSsrc, a forwarder rewrites the stream in place" {
    var packet: [16]u8 = sample;
    try setSsrc(&packet, 0x0BADF00D);

    const parsed = try read(&packet);

    try std.testing.expectEqual(@as(u32, 0x0BADF00D), parsed.header.ssrc);

    // Nothing else moved.
    try std.testing.expectEqual(@as(u16, 1), parsed.header.sequence);
    try std.testing.expectEqualSlices(u8, sample[12..16], parsed.payload);
}

test "zix media: rtp setSequence, a forwarder renumbers in place" {
    var packet: [16]u8 = sample;
    try setSequence(&packet, 0xBEEF);

    const parsed = try read(&packet);

    try std.testing.expectEqual(@as(u16, 0xBEEF), parsed.header.sequence);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.header.ssrc);
}

test "zix media: rtp setTimestamp, a forwarder shifts the clock in place" {
    var packet: [16]u8 = sample;
    try setTimestamp(&packet, 0x99887766);

    const parsed = try read(&packet);

    try std.testing.expectEqual(@as(u32, 0x99887766), parsed.header.timestamp);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.sequence);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.header.ssrc);
}

test "zix media: rtp setSsrc, a packet too short to hold one is refused" {
    var packet: [11]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, setSsrc(&packet, 1));
    try std.testing.expectError(error.ZixTruncated, setSequence(&packet, 1));
    try std.testing.expectError(error.ZixTruncated, setTimestamp(&packet, 1));
}
