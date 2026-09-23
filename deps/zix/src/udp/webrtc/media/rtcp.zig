//! zix RTCP compound packet framing (RFC 3550 6.1).
//!
//! What:
//! - The common header every RTCP packet starts with, and the walk that cuts a compound packet
//!   into the packets it holds. What is inside each one is report.zig and feedback.zig.
//!
//! Note:
//! - The length field counts 32-bit WORDS MINUS ONE, so a header-only packet carries a length of
//!   zero and occupies 4 bytes. Reading it as a byte count walks straight off the end.
//! - One datagram can hold several RTCP packets back to back, and a receiver must handle all of
//!   them (RFC 3550 6.1). Stopping after the first drops the reports that follow a sender report.
//! - RFC 3550 6.1 requires a compound packet to start with a sender or receiver report. That is
//!   checked on request rather than during the walk, because RFC 5506 reduced-size RTCP sends a
//!   lone feedback packet and WebRTC endpoints do use it.
//! - Padding belongs to the LAST packet of a compound and is counted in that packet's own length,
//!   so the walk needs no special case for it.

const std = @import("std");

/// The only RTCP version there is (RFC 3550 6).
pub const VERSION: u2 = 2;

/// Version, count, type, and length.
pub const HEADER_LEN: usize = 4;

/// Bytes needed before the sender identifier can be read.
pub const SENDER_SSRC_LEN: usize = 8;

/// What kind of control packet this is (RFC 3550 12.1, RFC 4585 6.1, RFC 3611 2).
pub const PacketType = enum(u8) {
    /// Sender report, from a source that is also sending media.
    SR = 200,
    /// Receiver report, from a source that is only listening.
    RR = 201,
    /// Source description, which carries the CNAME.
    SDES = 202,
    /// A source leaving the session.
    BYE = 203,
    /// Application defined.
    APP = 204,
    /// Transport layer feedback (RFC 4585 6.2).
    RTPFB = 205,
    /// Payload specific feedback (RFC 4585 6.3).
    PSFB = 206,
    /// Extended report (RFC 3611).
    XR = 207,
    _,
};

/// What stops a compound packet from being read.
pub const Error = error{
    /// A packet claims more bytes than the datagram holds, or the walk does not land on the end.
    ZixTruncated,
    /// A version other than 2.
    ZixUnsupportedVersion,
};

/// What stops a compound packet from being a valid one to send.
pub const CompoundError = error{
    /// The first packet is neither a sender report nor a receiver report (RFC 3550 6.1).
    ZixNotAReport,
};

/// One packet inside a compound, borrowed from the datagram it came in.
pub const Packet = struct {
    /// Set when this packet ends with padding.
    has_padding: bool,
    /// The 5-bit field after the version, which counts report blocks, sources, or names a
    /// feedback format depending on the packet type.
    count: u5,
    packet_type: PacketType,
    /// The whole packet, its common header included.
    bytes: []const u8,
    /// Everything after the common header.
    body: []const u8,
};

/// A walk over the packets in one compound datagram.
pub const Iterator = struct {
    /// The whole datagram.
    bytes: []const u8,
    /// Where the next packet starts.
    pos: usize = 0,

    /// The next packet, or null at the end.
    ///
    /// Note:
    /// - Infallible, because `validate` has already bounds-checked every packet. Building one of
    ///   these by hand over unvalidated bytes is what `begin` exists to prevent.
    ///
    /// Return:
    /// - ?Packet borrowing the datagram
    pub fn next(self: *Iterator) ?Packet {
        if (self.pos + HEADER_LEN > self.bytes.len) return null;

        const at = self.pos;
        const total = packetLen(self.bytes[at..]);

        if (at + total > self.bytes.len) return null;

        self.pos = at + total;

        return .{
            .has_padding = self.bytes[at] & 0x20 != 0,
            .count = @intCast(self.bytes[at] & 0x1F),
            .packet_type = @enumFromInt(self.bytes[at + 1]),
            .bytes = self.bytes[at..][0..total],
            .body = self.bytes[at + HEADER_LEN ..][0 .. total - HEADER_LEN],
        };
    }
};

/// Check a compound datagram and open a walk over it.
///
/// Param:
/// compound - []const u8 (borrowed, must outlive the iterator)
///
/// Return:
/// - Iterator borrowing `compound`
/// - error.ZixTruncated, error.ZixUnsupportedVersion
pub fn begin(compound: []const u8) Error!Iterator {
    try validate(compound);

    return .{ .bytes = compound };
}

/// Bounds-check every packet in a compound datagram.
///
/// Note:
/// - The walk has to land exactly on the end. Trailing bytes are a framing error and not
///   something to pass over, the same rule the STUN and SCTP readers already keep.
///
/// Param:
/// compound - []const u8
///
/// Return:
/// - void
/// - error.ZixTruncated, error.ZixUnsupportedVersion
pub fn validate(compound: []const u8) Error!void {
    if (compound.len < HEADER_LEN) return error.ZixTruncated;

    var at: usize = 0;
    while (at < compound.len) {
        if (at + HEADER_LEN > compound.len) return error.ZixTruncated;

        const version: u2 = @intCast(compound[at] >> 6);

        if (version != VERSION) return error.ZixUnsupportedVersion;

        const total = packetLen(compound[at..]);

        if (at + total > compound.len) return error.ZixTruncated;

        at += total;
    }
}

/// How many packets a compound datagram holds.
///
/// Param:
/// compound - []const u8 (already validated)
///
/// Return:
/// - usize
pub fn count(compound: []const u8) usize {
    var seen: usize = 0;
    var walk = Iterator{ .bytes = compound };

    while (walk.next()) |_| seen += 1;

    return seen;
}

/// The identifier of whoever sent the compound packet (RFC 3550 6.4.1).
///
/// Note:
/// - This is the SSRC SRTCP builds its counter block from (RFC 3711 4.1.1), and it always comes
///   from the FIRST packet of the compound whatever the rest carry.
///
/// Param:
/// compound - []const u8
///
/// Return:
/// - u32
/// - error.ZixTruncated when there is no room for one
pub fn senderSsrc(compound: []const u8) Error!u32 {
    if (compound.len < SENDER_SSRC_LEN) return error.ZixTruncated;

    return std.mem.readInt(u32, compound[4..8], .big);
}

/// Whether a compound packet opens the way RFC 3550 6.1 requires.
///
/// Param:
/// compound - []const u8 (already validated)
///
/// Return:
/// - void
/// - error.ZixNotAReport
pub fn requireReportFirst(compound: []const u8) CompoundError!void {
    var walk = Iterator{ .bytes = compound };
    const first = walk.next() orelse return error.ZixNotAReport;

    switch (first.packet_type) {
        .SR, .RR => {},
        else => return error.ZixNotAReport,
    }
}

/// Write a common header.
///
/// Param:
/// out - []u8 (at least HEADER_LEN bytes)
/// packet_type - PacketType
/// item_count - u5 (report blocks, sources, or a feedback format)
/// body_len - usize (bytes after the header, must be a multiple of 4)
///
/// Return:
/// - void
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeHeader(out: []u8, packet_type: PacketType, item_count: u5, body_len: usize) error{ ZixNoSpace, ZixBadLength }!void {
    if (out.len < HEADER_LEN) return error.ZixNoSpace;
    if (body_len % 4 != 0) return error.ZixBadLength;

    const words = (HEADER_LEN + body_len) / 4;

    if (words == 0 or words - 1 > 0xFFFF) return error.ZixBadLength;

    out[0] = (@as(u8, VERSION) << 6) | @as(u8, item_count);
    out[1] = @intFromEnum(packet_type);

    std.mem.writeInt(u16, out[2..4], @intCast(words - 1), .big);
}

/// How many bytes the packet starting here claims, from its length field.
fn packetLen(from: []const u8) usize {
    const words = std.mem.readInt(u16, from[2..4], .big);

    return (@as(usize, words) + 1) * 4;
}

// --------------------------------------------------------------------------------------- //
// test cases

/// A receiver report with no report blocks: 4 header bytes plus the sender identifier.
const empty_report: [8]u8 = .{ 0x80, 201, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };

/// A source description with one chunk, padded out to a whole number of words.
const sdes: [12]u8 = .{ 0x81, 202, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x41, 0x00 };

test "zix media: rtcp validate, a lone receiver report is accepted" {
    try validate(&empty_report);

    try std.testing.expectEqual(@as(usize, 1), count(&empty_report));
}

test "zix media: rtcp validate, the length field counts words minus one" {
    // Length 1 means 2 words, being 8 bytes. Reading it as a byte count would want 1 byte.
    try std.testing.expectEqual(@as(usize, 8), packetLen(&empty_report));

    // A header-only packet carries length 0 and takes 4 bytes.
    const header_only = [_]u8{ 0x80, 201, 0x00, 0x00 };
    try std.testing.expectEqual(@as(usize, 4), packetLen(&header_only));
    try validate(&header_only);
}

test "zix media: rtcp validate, a packet claiming more than the datagram holds is refused" {
    var short = empty_report;
    std.mem.writeInt(u16, short[2..4], 4, .big);

    try std.testing.expectError(error.ZixTruncated, validate(&short));
    try std.testing.expectError(error.ZixTruncated, validate(empty_report[0..3]));
    try std.testing.expectError(error.ZixTruncated, validate(&[_]u8{}));
}

test "zix media: rtcp validate, trailing bytes are a framing error" {
    var buf: [10]u8 = @splat(0);
    @memcpy(buf[0..8], &empty_report);

    try std.testing.expectError(error.ZixTruncated, validate(&buf));
}

test "zix media: rtcp validate, a version other than two is refused" {
    var wrong = empty_report;
    wrong[0] = 0x40;

    try std.testing.expectError(error.ZixUnsupportedVersion, validate(&wrong));
}

test "zix media: rtcp begin, a compound datagram walks packet by packet" {
    var buf: [20]u8 = undefined;
    @memcpy(buf[0..8], &empty_report);
    @memcpy(buf[8..20], &sdes);

    var walk = try begin(&buf);

    const first = walk.next().?;
    try std.testing.expectEqual(PacketType.RR, first.packet_type);
    try std.testing.expectEqual(@as(u5, 0), first.count);
    try std.testing.expectEqual(@as(usize, 8), first.bytes.len);
    try std.testing.expectEqual(@as(usize, 4), first.body.len);

    const second = walk.next().?;
    try std.testing.expectEqual(PacketType.SDES, second.packet_type);
    try std.testing.expectEqual(@as(u5, 1), second.count);
    try std.testing.expectEqual(@as(usize, 12), second.bytes.len);

    try std.testing.expect(walk.next() == null);
    try std.testing.expectEqual(@as(usize, 2), count(&buf));
}

test "zix media: rtcp begin, the second packet is not dropped" {
    // The failure this guards against: a reader that handles only the first packet of a compound
    // never sees the SDES, so it never learns the peer's CNAME.
    var buf: [20]u8 = undefined;
    @memcpy(buf[0..8], &empty_report);
    @memcpy(buf[8..20], &sdes);

    var walk = try begin(&buf);
    _ = walk.next();

    try std.testing.expectEqual(PacketType.SDES, walk.next().?.packet_type);
}

test "zix media: rtcp begin, an unregistered packet type still walks" {
    var unknown = empty_report;
    unknown[1] = 250;

    var walk = try begin(&unknown);
    const first = walk.next().?;

    try std.testing.expectEqual(@as(u8, 250), @intFromEnum(first.packet_type));
}

test "zix media: rtcp senderSsrc, it comes from the first packet" {
    var buf: [20]u8 = undefined;
    @memcpy(buf[0..8], &empty_report);
    @memcpy(buf[8..20], &sdes);
    std.mem.writeInt(u32, buf[12..16], 0x01020304, .big);

    // The SDES names a different source, and the counter block still uses the first one.
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try senderSsrc(&buf));
}

test "zix media: rtcp senderSsrc, a packet too short to hold one is refused" {
    try std.testing.expectError(error.ZixTruncated, senderSsrc(&[_]u8{ 0x80, 201, 0, 0 }));
}

test "zix media: rtcp requireReportFirst, a compound must open with a report" {
    try requireReportFirst(&empty_report);

    try std.testing.expectError(error.ZixNotAReport, requireReportFirst(&sdes));
    try std.testing.expectError(error.ZixNotAReport, requireReportFirst(&[_]u8{}));
}

test "zix media: rtcp requireReportFirst, reduced-size feedback is walked but not required" {
    // RFC 5506 allows a lone feedback packet, so the walk accepts it and only the explicit check
    // says it does not open a compound the old way.
    const feedback = [_]u8{ 0x81, 205, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 };

    try validate(&feedback);
    try std.testing.expectEqual(@as(usize, 1), count(&feedback));
    try std.testing.expectError(error.ZixNotAReport, requireReportFirst(&feedback));
}

test "zix media: rtcp writeHeader, what was written reads back the same" {
    var buf: [8]u8 = @splat(0);
    try writeHeader(&buf, .RR, 0, 4);

    std.mem.writeInt(u32, buf[4..8], 0xDEADBEEF, .big);

    try std.testing.expectEqualSlices(u8, &empty_report, &buf);

    var walk = try begin(&buf);
    const first = walk.next().?;

    try std.testing.expectEqual(PacketType.RR, first.packet_type);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try senderSsrc(&buf));
}

test "zix media: rtcp writeHeader, a body that is not whole words is refused" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixBadLength, writeHeader(&buf, .RR, 0, 3));
    try std.testing.expectError(error.ZixNoSpace, writeHeader(buf[0..3], .RR, 0, 0));
}

test "zix media: rtcp writeHeader, the count field takes all five bits" {
    var buf: [4]u8 = undefined;
    try writeHeader(&buf, .PSFB, 31, 0);

    var walk = try begin(&buf);
    const first = walk.next().?;

    try std.testing.expectEqual(@as(u5, 31), first.count);
    try std.testing.expectEqual(PacketType.PSFB, first.packet_type);
    try std.testing.expect(!first.has_padding);
}

test "zix media: rtcp begin, padding belongs to the last packet and needs no special case" {
    // A receiver report followed by a padded SDES: the pad bytes are inside the SDES length, so
    // the walk lands exactly on the end without knowing anything about padding.
    var buf: [24]u8 = @splat(0);
    @memcpy(buf[0..8], &empty_report);
    @memcpy(buf[8..20], &sdes);

    buf[8] |= 0x20;
    std.mem.writeInt(u16, buf[10..12], 3, .big);
    buf[23] = 4;

    var walk = try begin(&buf);
    _ = walk.next();

    const padded = walk.next().?;

    try std.testing.expect(padded.has_padding);
    try std.testing.expectEqual(@as(usize, 16), padded.bytes.len);
    try std.testing.expect(walk.next() == null);
}
