//! zix RTCP feedback packets (RFC 4585 6).
//!
//! What:
//! - The two feedback packet types a WebRTC endpoint sends constantly: transport layer feedback
//!   (a NACK naming packets that never arrived) and payload specific feedback (a picture loss
//!   indication asking for a fresh keyframe).
//!
//! Note:
//! - Both types share one body: the sender's own identifier, the identifier of the stream being
//!   complained about, and then a format-specific block. The format lives in the count field of
//!   the common header, not in a byte of its own.
//! - A NACK entry names 17 sequence numbers, not one. The packet identifier is the first missing
//!   number and the 16-bit bitmask covers the next 16 after it, LOWEST bit nearest. Reading only
//!   the identifier drops most of what the peer asked for.
//! - Sequence numbers wrap at 65536, so a bitmask can cover a run that crosses the wrap. Every
//!   comparison here is wrapping on purpose, and a run is measured as a distance rather than by
//!   whether one number is larger than another.
//! - zix carries no codecs, so a picture loss indication is forwarded to whoever is sending the
//!   media and never acted on locally. There is nothing here that encodes or drops a frame.

const std = @import("std");

const rtcp = @import("rtcp.zig");

/// Common header, the sender identifier, and the media identifier (RFC 4585 6.1).
pub const HEADER_LEN: usize = rtcp.HEADER_LEN + 8;

/// Bytes one NACK entry takes (RFC 4585 6.2.1).
pub const NACK_ENTRY_LEN: usize = 4;

/// How many sequence numbers past the first one entry's bitmask reaches.
pub const NACK_BITMASK_REACH: u16 = 16;

/// Transport layer feedback formats (RFC 4585 6.2).
pub const TransportFormat = enum(u5) {
    /// Generic negative acknowledgement, naming packets that did not arrive.
    NACK = 1,
    _,
};

/// Payload specific feedback formats (RFC 4585 6.3).
pub const PayloadFormat = enum(u5) {
    /// Picture loss indication, asking the sender for a fresh keyframe.
    PLI = 1,
    /// Slice loss indication.
    SLI = 2,
    /// Reference picture selection indication.
    RPSI = 3,
    /// Application layer feedback, whose body this file does not read.
    AFB = 15,
    _,
};

/// What stops a feedback packet from being read.
pub const Error = error{
    /// Shorter than the two identifiers need, or the block does not divide evenly.
    ZixTruncated,
    /// A packet that is not RTPFB or PSFB.
    ZixWrongType,
};

/// One feedback packet, borrowed from the datagram it came in.
pub const Feedback = struct {
    /// Whoever is complaining.
    sender_ssrc: u32,
    /// The stream being complained about. Zero on a payload format that names no single stream.
    media_ssrc: u32,
    /// The format-specific block, empty for a picture loss indication.
    fci: []const u8,
};

/// One NACK entry: a first missing sequence number and a mask of the 16 that follow.
pub const Nack = struct {
    /// The first sequence number this entry reports missing.
    packet_id: u16,
    /// Bit 0 means packet_id + 1 is missing, bit 15 means packet_id + 16 is.
    bitmask: u16,

    /// Whether this entry reports a sequence number missing.
    ///
    /// Param:
    /// sequence - u16
    ///
    /// Return:
    /// - bool
    pub fn reports(self: Nack, sequence: u16) bool {
        const distance = sequence -% self.packet_id;

        if (distance == 0) return true;
        if (distance > NACK_BITMASK_REACH) return false;

        return self.bitmask & (@as(u16, 1) << @intCast(distance - 1)) != 0;
    }

    /// How many sequence numbers this entry reports missing.
    ///
    /// Return:
    /// - usize
    pub fn count(self: Nack) usize {
        return 1 + @popCount(self.bitmask);
    }

    /// A walk over the sequence numbers this entry reports, in order.
    ///
    /// Return:
    /// - Lost
    pub fn lost(self: Nack) Lost {
        return .{ .entry = self };
    }
};

/// A walk over the sequence numbers one NACK entry names.
pub const Lost = struct {
    entry: Nack,
    /// How far past the packet identifier the walk has gone.
    step: u16 = 0,

    /// The next missing sequence number, or null at the end.
    ///
    /// Return:
    /// - ?u16
    pub fn next(self: *Lost) ?u16 {
        while (self.step <= NACK_BITMASK_REACH) {
            const at = self.step;
            self.step += 1;

            if (at == 0) return self.entry.packet_id;
            if (self.entry.bitmask & (@as(u16, 1) << @intCast(at - 1)) != 0) {
                return self.entry.packet_id +% at;
            }
        }

        return null;
    }
};

/// A walk over the NACK entries in one feedback packet.
pub const Entries = struct {
    /// The feedback control information, four bytes per entry.
    fci: []const u8,
    pos: usize = 0,

    /// The next entry, or null at the end.
    ///
    /// Return:
    /// - ?Nack
    pub fn next(self: *Entries) ?Nack {
        if (self.pos + NACK_ENTRY_LEN > self.fci.len) return null;

        const at = self.pos;
        self.pos += NACK_ENTRY_LEN;

        return .{
            .packet_id = std.mem.readInt(u16, self.fci[at..][0..2], .big),
            .bitmask = std.mem.readInt(u16, self.fci[at + 2 ..][0..2], .big),
        };
    }
};

/// Read a feedback packet body.
///
/// Param:
/// packet - rtcp.Packet (as rtcp.Iterator hands it over)
///
/// Return:
/// - Feedback borrowing the packet
/// - error.ZixWrongType, error.ZixTruncated
pub fn read(packet: rtcp.Packet) Error!Feedback {
    switch (packet.packet_type) {
        .RTPFB, .PSFB => {},
        else => return error.ZixWrongType,
    }

    if (packet.body.len < 8) return error.ZixTruncated;

    return .{
        .sender_ssrc = std.mem.readInt(u32, packet.body[0..4], .big),
        .media_ssrc = std.mem.readInt(u32, packet.body[4..8], .big),
        .fci = packet.body[8..],
    };
}

/// The transport format a packet names, from the count field.
///
/// Param:
/// packet - rtcp.Packet
///
/// Return:
/// - TransportFormat
/// - error.ZixWrongType when the packet is not RTPFB
pub fn transportFormat(packet: rtcp.Packet) Error!TransportFormat {
    if (packet.packet_type != .RTPFB) return error.ZixWrongType;

    return @enumFromInt(packet.count);
}

/// The payload format a packet names, from the count field.
///
/// Param:
/// packet - rtcp.Packet
///
/// Return:
/// - PayloadFormat
/// - error.ZixWrongType when the packet is not PSFB
pub fn payloadFormat(packet: rtcp.Packet) Error!PayloadFormat {
    if (packet.packet_type != .PSFB) return error.ZixWrongType;

    return @enumFromInt(packet.count);
}

/// Open a walk over a NACK packet's entries.
///
/// Param:
/// feedback - Feedback (already read from an RTPFB packet with format NACK)
///
/// Return:
/// - Entries borrowing the packet
/// - error.ZixTruncated when the block does not divide into whole entries
pub fn nackEntries(feedback: Feedback) Error!Entries {
    if (feedback.fci.len % NACK_ENTRY_LEN != 0) return error.ZixTruncated;
    if (feedback.fci.len == 0) return error.ZixTruncated;

    return .{ .fci = feedback.fci };
}

/// Write a picture loss indication (RFC 4585 6.3.1).
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// sender_ssrc - u32 (this endpoint's own identifier)
/// media_ssrc - u32 (the stream a keyframe is wanted for)
///
/// Return:
/// - []const u8 of exactly HEADER_LEN bytes
/// - error.ZixNoSpace
pub fn writePictureLoss(out: []u8, sender_ssrc: u32, media_ssrc: u32) error{ZixNoSpace}![]const u8 {
    return writeFeedback(out, .PSFB, @intFromEnum(PayloadFormat.PLI), sender_ssrc, media_ssrc, 0);
}

/// Write a NACK naming a set of missing sequence numbers (RFC 4585 6.2.1).
///
/// Note:
/// - Entries are packed greedily: each one covers its first number and any of the following 16.
///   A run of 17 consecutive losses is one entry, and 17 losses spread out is 17 entries.
/// - The input must be sorted in the order the numbers were expected. Unsorted input still writes
///   a valid packet, it just wastes entries.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// sender_ssrc - u32
/// media_ssrc - u32
/// missing - []const u16 (at least one, sorted)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace, error.ZixNothingMissing
pub fn writeNack(
    out: []u8,
    sender_ssrc: u32,
    media_ssrc: u32,
    missing: []const u16,
) error{ ZixNoSpace, ZixNothingMissing }![]const u8 {
    if (missing.len == 0) return error.ZixNothingMissing;
    if (out.len < HEADER_LEN) return error.ZixNoSpace;

    var at = HEADER_LEN;
    var index: usize = 0;

    while (index < missing.len) {
        if (at + NACK_ENTRY_LEN > out.len) return error.ZixNoSpace;

        const packet_id = missing[index];
        var bitmask: u16 = 0;

        index += 1;

        while (index < missing.len) : (index += 1) {
            const distance = missing[index] -% packet_id;

            if (distance == 0 or distance > NACK_BITMASK_REACH) break;

            bitmask |= @as(u16, 1) << @intCast(distance - 1);
        }

        std.mem.writeInt(u16, out[at..][0..2], packet_id, .big);
        std.mem.writeInt(u16, out[at + 2 ..][0..2], bitmask, .big);

        at += NACK_ENTRY_LEN;
    }

    _ = try writeFeedback(out, .RTPFB, @intFromEnum(TransportFormat.NACK), sender_ssrc, media_ssrc, at - HEADER_LEN);

    return out[0..at];
}

/// Write a feedback packet header and its two identifiers.
fn writeFeedback(
    out: []u8,
    packet_type: rtcp.PacketType,
    format: u5,
    sender_ssrc: u32,
    media_ssrc: u32,
    fci_len: usize,
) error{ZixNoSpace}![]const u8 {
    const total = HEADER_LEN + fci_len;

    if (out.len < total) return error.ZixNoSpace;

    rtcp.writeHeader(out, packet_type, format, total - rtcp.HEADER_LEN) catch return error.ZixNoSpace;
    std.mem.writeInt(u32, out[rtcp.HEADER_LEN..][0..4], sender_ssrc, .big);
    std.mem.writeInt(u32, out[rtcp.HEADER_LEN + 4 ..][0..4], media_ssrc, .big);

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

fn firstPacket(compound: []const u8) !rtcp.Packet {
    var walk = try rtcp.begin(compound);

    return walk.next() orelse error.TestUnexpectedResult;
}

test "zix media: feedback read, a nack packet reads its two identifiers" {
    var buf: [32]u8 = undefined;
    const written = try writeNack(&buf, 0xDEADBEEF, 0x0BADF00D, &.{100});
    const packet = try firstPacket(written);
    const parsed = try read(packet);

    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0x0BADF00D), parsed.media_ssrc);
    try std.testing.expectEqual(TransportFormat.NACK, try transportFormat(packet));
    try std.testing.expectEqual(@as(usize, 4), parsed.fci.len);
}

test "zix media: feedback read, a packet that is not feedback is refused" {
    const receiver_report = [_]u8{ 0x80, 201, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };

    try std.testing.expectError(error.ZixWrongType, read(try firstPacket(&receiver_report)));
    try std.testing.expectError(error.ZixWrongType, transportFormat(try firstPacket(&receiver_report)));
    try std.testing.expectError(error.ZixWrongType, payloadFormat(try firstPacket(&receiver_report)));
}

test "zix media: feedback read, a body too short for both identifiers is refused" {
    const stub = [_]u8{ 0x81, 205, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };

    try std.testing.expectError(error.ZixTruncated, read(try firstPacket(&stub)));
}

test "zix media: feedback nack, one entry names seventeen sequence numbers" {
    // Packet identifier 100 with every bitmask bit set: 100 through 116.
    const entry = Nack{ .packet_id = 100, .bitmask = 0xFFFF };

    try std.testing.expectEqual(@as(usize, 17), entry.count());
    try std.testing.expect(entry.reports(100));
    try std.testing.expect(entry.reports(116));
    try std.testing.expect(!entry.reports(117));
    try std.testing.expect(!entry.reports(99));
}

test "zix media: feedback nack, the lowest bit is the number right after the identifier" {
    // The easy mistake is reading the mask the other way round, which reports 116 instead of 101.
    const entry = Nack{ .packet_id = 100, .bitmask = 0x0001 };

    try std.testing.expect(entry.reports(101));
    try std.testing.expect(!entry.reports(116));

    const highest = Nack{ .packet_id = 100, .bitmask = 0x8000 };
    try std.testing.expect(highest.reports(116));
    try std.testing.expect(!highest.reports(101));
}

test "zix media: feedback nack, an entry with an empty mask names one number" {
    const entry = Nack{ .packet_id = 7, .bitmask = 0 };

    try std.testing.expectEqual(@as(usize, 1), entry.count());
    try std.testing.expect(entry.reports(7));
    try std.testing.expect(!entry.reports(8));
}

test "zix media: feedback nack, a run crossing the sequence wrap is still one entry" {
    // 65533, 65534, 65535, 0, 1 are consecutive on the wire.
    const entry = Nack{ .packet_id = 65533, .bitmask = 0x000F };

    try std.testing.expect(entry.reports(65533));
    try std.testing.expect(entry.reports(65535));
    try std.testing.expect(entry.reports(0));
    try std.testing.expect(entry.reports(1));
    try std.testing.expect(!entry.reports(2));
}

test "zix media: feedback lost, the walk gives every number the entry names" {
    var walk = (Nack{ .packet_id = 200, .bitmask = 0x0005 }).lost();

    try std.testing.expectEqual(@as(u16, 200), walk.next().?);
    try std.testing.expectEqual(@as(u16, 201), walk.next().?);
    try std.testing.expectEqual(@as(u16, 203), walk.next().?);
    try std.testing.expect(walk.next() == null);
}

test "zix media: feedback lost, the walk wraps with the sequence numbers" {
    var walk = (Nack{ .packet_id = 65535, .bitmask = 0x0003 }).lost();

    try std.testing.expectEqual(@as(u16, 65535), walk.next().?);
    try std.testing.expectEqual(@as(u16, 0), walk.next().?);
    try std.testing.expectEqual(@as(u16, 1), walk.next().?);
    try std.testing.expect(walk.next() == null);
}

test "zix media: feedback writeNack, a consecutive run packs into one entry" {
    var buf: [32]u8 = undefined;
    const missing = [_]u16{ 100, 101, 102, 103 };
    const written = try writeNack(&buf, 1, 2, &missing);

    try std.testing.expectEqual(HEADER_LEN + NACK_ENTRY_LEN, written.len);

    var entries = try nackEntries(try read(try firstPacket(written)));
    const entry = entries.next().?;

    try std.testing.expectEqual(@as(u16, 100), entry.packet_id);
    try std.testing.expectEqual(@as(u16, 0x0007), entry.bitmask);
    try std.testing.expect(entries.next() == null);

    for (missing) |sequence| try std.testing.expect(entry.reports(sequence));
}

test "zix media: feedback writeNack, a gap past the mask reach starts a second entry" {
    var buf: [32]u8 = undefined;
    const written = try writeNack(&buf, 1, 2, &.{ 100, 117 });

    try std.testing.expectEqual(HEADER_LEN + 2 * NACK_ENTRY_LEN, written.len);

    var entries = try nackEntries(try read(try firstPacket(written)));

    try std.testing.expectEqual(@as(u16, 100), entries.next().?.packet_id);
    try std.testing.expectEqual(@as(u16, 117), entries.next().?.packet_id);
    try std.testing.expect(entries.next() == null);
}

test "zix media: feedback writeNack, the last number the mask can reach stays in one entry" {
    var buf: [32]u8 = undefined;
    const written = try writeNack(&buf, 1, 2, &.{ 100, 116 });

    try std.testing.expectEqual(HEADER_LEN + NACK_ENTRY_LEN, written.len);

    var entries = try nackEntries(try read(try firstPacket(written)));
    try std.testing.expectEqual(@as(u16, 0x8000), entries.next().?.bitmask);
}

test "zix media: feedback writeNack, what was written reads back the same numbers" {
    var buf: [64]u8 = undefined;
    const missing = [_]u16{ 10, 11, 40, 41, 42, 300 };
    const written = try writeNack(&buf, 0xAAAA, 0xBBBB, &missing);

    var entries = try nackEntries(try read(try firstPacket(written)));
    var seen: [8]u16 = undefined;
    var count: usize = 0;

    while (entries.next()) |entry| {
        var walk = entry.lost();
        while (walk.next()) |sequence| {
            seen[count] = sequence;
            count += 1;
        }
    }

    try std.testing.expectEqualSlices(u16, &missing, seen[0..count]);
}

test "zix media: feedback writeNack, the limits are refused" {
    var buf: [64]u8 = undefined;

    try std.testing.expectError(error.ZixNothingMissing, writeNack(&buf, 1, 2, &.{}));
    try std.testing.expectError(error.ZixNoSpace, writeNack(buf[0..HEADER_LEN], 1, 2, &.{1}));
    try std.testing.expectError(error.ZixNoSpace, writeNack(buf[0..8], 1, 2, &.{1}));
}

test "zix media: feedback nackEntries, a block that is not whole entries is refused" {
    const ragged = Feedback{ .sender_ssrc = 1, .media_ssrc = 2, .fci = &[_]u8{ 0, 1, 2 } };
    const empty = Feedback{ .sender_ssrc = 1, .media_ssrc = 2, .fci = &.{} };

    try std.testing.expectError(error.ZixTruncated, nackEntries(ragged));
    try std.testing.expectError(error.ZixTruncated, nackEntries(empty));
}

test "zix media: feedback writePictureLoss, it carries no control information" {
    var buf: [16]u8 = undefined;
    const written = try writePictureLoss(&buf, 0xDEADBEEF, 0x0BADF00D);
    const packet = try firstPacket(written);
    const parsed = try read(packet);

    try std.testing.expectEqual(HEADER_LEN, written.len);
    try std.testing.expectEqual(PayloadFormat.PLI, try payloadFormat(packet));
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0x0BADF00D), parsed.media_ssrc);
    try std.testing.expectEqual(@as(usize, 0), parsed.fci.len);
}

test "zix media: feedback writePictureLoss, a short buffer errors" {
    var buf: [HEADER_LEN - 1]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writePictureLoss(&buf, 1, 2));
}

test "zix media: feedback, an unregistered format still reads" {
    var buf: [16]u8 = undefined;
    _ = try writePictureLoss(&buf, 1, 2);

    buf[0] = (buf[0] & 0xE0) | 9;

    const packet = try firstPacket(buf[0..HEADER_LEN]);
    try std.testing.expectEqual(@as(u5, 9), @intFromEnum(try payloadFormat(packet)));
}

test "zix media: feedback, both feedback types sit in one compound datagram" {
    // A browser sends a receiver report, a NACK, and a picture loss indication together, and all
    // three have to come back out of one walk.
    var buf: [64]u8 = @splat(0);
    const report = [_]u8{ 0x80, 201, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };

    @memcpy(buf[0..8], &report);

    var nack_buf: [16]u8 = undefined;
    const nack = try writeNack(&nack_buf, 1, 2, &.{5});
    @memcpy(buf[8 .. 8 + nack.len], nack);

    var pli_buf: [12]u8 = undefined;
    const pli = try writePictureLoss(&pli_buf, 1, 2);
    @memcpy(buf[8 + nack.len ..][0..pli.len], pli);

    var walk = try rtcp.begin(buf[0 .. 8 + nack.len + pli.len]);

    try std.testing.expectEqual(rtcp.PacketType.RR, walk.next().?.packet_type);

    const nack_packet = walk.next().?;
    try std.testing.expectEqual(TransportFormat.NACK, try transportFormat(nack_packet));

    const pli_packet = walk.next().?;
    try std.testing.expectEqual(PayloadFormat.PLI, try payloadFormat(pli_packet));
    try std.testing.expect(walk.next() == null);
}
