//! zix RTCP sender and receiver reports (RFC 3550 6.4).
//!
//! What:
//! - The two packet bodies that carry reception quality: what a sender has sent, and what each
//!   receiver got. rtcp.zig cuts a compound packet into packets, this reads the two that matter.
//!
//! Note:
//! - Cumulative packets lost is SIGNED, 24 bits, two's complement (RFC 3550 6.4.1). A receiver
//!   that got more packets than were expected (duplicates) reports a negative number, and reading
//!   the field unsigned turns a small negative loss into roughly 16 million lost packets.
//! - Fraction lost is a fixed point number with the binary point at the left edge, so the value is
//!   the byte over 256. Reporting it as a percentage without that division is off by 2.56x.
//! - The two report kinds differ only in a 20-byte sender info block. Everything after it is the
//!   same list of report blocks, which is why both share one block reader.
//! - A report block count that does not match the bytes present is a framing error. The count
//!   lives in the common header, so a mismatch means the packet and its header disagree.

const std = @import("std");

const rtcp = @import("rtcp.zig");

/// Sender identifier, ahead of everything else in both report kinds.
pub const SSRC_LEN: usize = 4;

/// Timing and counters a sender reports about itself, after its identifier (RFC 3550 6.4.1).
pub const SENDER_INFO_LEN: usize = 20;

/// One reception report block (RFC 3550 6.4.1).
pub const REPORT_BLOCK_LEN: usize = 24;

/// The most report blocks the 5-bit count can name.
pub const MAX_BLOCKS: usize = 31;

/// What stops a report from being read.
pub const Error = error{
    /// The body is shorter than the header's block count says.
    ZixTruncated,
    /// The packet is not the report kind that was asked for.
    ZixWrongType,
};

/// A 64-bit NTP timestamp, split the way RFC 3550 6.4.1 writes it.
pub const NtpTimestamp = struct {
    seconds: u32,
    fraction: u32,

    /// The middle 32 bits, which is the form a report block echoes back (RFC 3550 6.4.1).
    ///
    /// Note:
    /// - The low 16 bits of the seconds and the high 16 bits of the fraction. Round-trip time is
    ///   measured from this, so taking the wrong half makes every measurement nonsense.
    ///
    /// Return:
    /// - u32
    pub fn middle32(self: NtpTimestamp) u32 {
        return (self.seconds << 16) | (self.fraction >> 16);
    }
};

/// What a sender says about its own stream (RFC 3550 6.4.1).
pub const SenderInfo = struct {
    ntp: NtpTimestamp,
    /// The same instant as the NTP timestamp, in the stream's own clock.
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
};

/// What one receiver says about one source (RFC 3550 6.4.1).
pub const ReportBlock = struct {
    /// Which source is being reported on.
    source: u32,
    /// Loss since the last report, as a fraction over 256.
    fraction_lost: u8,
    /// Expected minus received since the start, which can be negative.
    packets_lost: i32,
    /// Sequence number plus the count of times it has wrapped.
    highest_sequence: u32,
    /// Arrival time variance, in the stream's own clock units.
    jitter: u32,
    /// The middle 32 bits of the last sender report's NTP timestamp, zero if there was none.
    last_sender_report: u32,
    /// Time since that report, in units of 1/65536 seconds.
    delay_since_last_sender_report: u32,

    /// Loss as a fraction of one.
    ///
    /// Return:
    /// - f32
    pub fn lossFraction(self: ReportBlock) f32 {
        return @as(f32, @floatFromInt(self.fraction_lost)) / 256.0;
    }
};

/// The report block list both report kinds end with.
pub const Blocks = struct {
    /// The raw bytes, REPORT_BLOCK_LEN per entry.
    bytes: []const u8,

    /// How many blocks there are.
    ///
    /// Return:
    /// - usize
    pub fn count(self: Blocks) usize {
        return self.bytes.len / REPORT_BLOCK_LEN;
    }

    /// One block by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?ReportBlock
    pub fn at(self: Blocks, index: usize) ?ReportBlock {
        if (index >= self.count()) return null;

        const from = self.bytes[index * REPORT_BLOCK_LEN ..][0..REPORT_BLOCK_LEN];

        return .{
            .source = std.mem.readInt(u32, from[0..4], .big),
            .fraction_lost = from[4],
            .packets_lost = readSigned24(from[5..8]),
            .highest_sequence = std.mem.readInt(u32, from[8..12], .big),
            .jitter = std.mem.readInt(u32, from[12..16], .big),
            .last_sender_report = std.mem.readInt(u32, from[16..20], .big),
            .delay_since_last_sender_report = std.mem.readInt(u32, from[20..24], .big),
        };
    }
};

/// A sender report (RFC 3550 6.4.1).
pub const SenderReport = struct {
    /// Whose stream this describes.
    ssrc: u32,
    info: SenderInfo,
    blocks: Blocks,
};

/// A receiver report (RFC 3550 6.4.2).
pub const ReceiverReport = struct {
    /// Who is doing the reporting.
    ssrc: u32,
    blocks: Blocks,
};

/// Read a sender report body.
///
/// Param:
/// packet - rtcp.Packet (as rtcp.Iterator hands it over)
///
/// Return:
/// - SenderReport borrowing the packet
/// - error.ZixWrongType, error.ZixTruncated
pub fn readSenderReport(packet: rtcp.Packet) Error!SenderReport {
    if (packet.packet_type != .SR) return error.ZixWrongType;

    const fixed = SSRC_LEN + SENDER_INFO_LEN;
    const blocks = try blocksOf(packet, fixed);
    const info = packet.body[SSRC_LEN..fixed];

    return .{
        .ssrc = std.mem.readInt(u32, packet.body[0..4], .big),
        .info = .{
            .ntp = .{
                .seconds = std.mem.readInt(u32, info[0..4], .big),
                .fraction = std.mem.readInt(u32, info[4..8], .big),
            },
            .rtp_timestamp = std.mem.readInt(u32, info[8..12], .big),
            .packet_count = std.mem.readInt(u32, info[12..16], .big),
            .octet_count = std.mem.readInt(u32, info[16..20], .big),
        },
        .blocks = blocks,
    };
}

/// Read a receiver report body.
///
/// Param:
/// packet - rtcp.Packet
///
/// Return:
/// - ReceiverReport borrowing the packet
/// - error.ZixWrongType, error.ZixTruncated
pub fn readReceiverReport(packet: rtcp.Packet) Error!ReceiverReport {
    if (packet.packet_type != .RR) return error.ZixWrongType;

    // Measured before anything is read. A report packet may legally be four bytes of header with
    // no body at all, and reaching for the identifier first walks off the end of it.
    const blocks = try blocksOf(packet, SSRC_LEN);

    return .{
        .ssrc = std.mem.readInt(u32, packet.body[0..4], .big),
        .blocks = blocks,
    };
}

/// How many bytes a receiver report takes, header included.
///
/// Param:
/// block_count - usize
///
/// Return:
/// - usize
pub fn receiverReportLen(block_count: usize) usize {
    return rtcp.HEADER_LEN + SSRC_LEN + block_count * REPORT_BLOCK_LEN;
}

/// Write a receiver report (RFC 3550 6.4.2).
///
/// Note:
/// - This is what a forwarder sends upstream about what it received. There is no sender report
///   writer, because zix originates no media of its own to report on.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// ssrc - u32 (the reporter's own identifier)
/// blocks - []const ReportBlock (at most MAX_BLOCKS)
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace, error.ZixTooManyBlocks
pub fn writeReceiverReport(out: []u8, ssrc: u32, blocks: []const ReportBlock) error{ ZixNoSpace, ZixTooManyBlocks }![]const u8 {
    if (blocks.len > MAX_BLOCKS) return error.ZixTooManyBlocks;

    const total = receiverReportLen(blocks.len);

    if (out.len < total) return error.ZixNoSpace;

    rtcp.writeHeader(out, .RR, @intCast(blocks.len), total - rtcp.HEADER_LEN) catch return error.ZixNoSpace;
    std.mem.writeInt(u32, out[rtcp.HEADER_LEN..][0..4], ssrc, .big);

    var at = rtcp.HEADER_LEN + SSRC_LEN;
    for (blocks) |entry| {
        std.mem.writeInt(u32, out[at..][0..4], entry.source, .big);
        out[at + 4] = entry.fraction_lost;
        writeSigned24(out[at + 5 ..][0..3], entry.packets_lost);
        std.mem.writeInt(u32, out[at + 8 ..][0..4], entry.highest_sequence, .big);
        std.mem.writeInt(u32, out[at + 12 ..][0..4], entry.jitter, .big);
        std.mem.writeInt(u32, out[at + 16 ..][0..4], entry.last_sender_report, .big);
        std.mem.writeInt(u32, out[at + 20 ..][0..4], entry.delay_since_last_sender_report, .big);

        at += REPORT_BLOCK_LEN;
    }

    return out[0..total];
}

/// The report block list of a packet whose fixed part is `fixed` bytes long.
fn blocksOf(packet: rtcp.Packet, fixed: usize) Error!Blocks {
    const wanted = fixed + @as(usize, packet.count) * REPORT_BLOCK_LEN;

    if (packet.body.len < wanted) return error.ZixTruncated;

    return .{ .bytes = packet.body[fixed..wanted] };
}

/// Read a 24-bit two's complement value.
fn readSigned24(from: *const [3]u8) i32 {
    const raw = (@as(u32, from[0]) << 16) | (@as(u32, from[1]) << 8) | @as(u32, from[2]);

    if (raw & 0x800000 != 0) return @as(i32, @bitCast(raw | 0xFF000000));

    return @intCast(raw);
}

/// Write a 24-bit two's complement value, saturating at the ends of the range.
fn writeSigned24(out: *[3]u8, value: i32) void {
    const clamped = std.math.clamp(value, -0x800000, 0x7FFFFF);
    const raw: u32 = @bitCast(clamped);

    out[0] = @intCast((raw >> 16) & 0xFF);
    out[1] = @intCast((raw >> 8) & 0xFF);
    out[2] = @intCast(raw & 0xFF);
}

// --------------------------------------------------------------------------------------- //
// test cases

/// One sender report with a single report block, built field by field.
fn sampleSenderReport(out: *[52]u8) []const u8 {
    out[0] = 0x81;
    out[1] = 200;

    std.mem.writeInt(u16, out[2..4], 12, .big);
    std.mem.writeInt(u32, out[4..8], 0xDEADBEEF, .big);
    std.mem.writeInt(u32, out[8..12], 0x83AA7E80, .big);
    std.mem.writeInt(u32, out[12..16], 0x40000000, .big);
    std.mem.writeInt(u32, out[16..20], 0x00001234, .big);
    std.mem.writeInt(u32, out[20..24], 100, .big);
    std.mem.writeInt(u32, out[24..28], 16000, .big);

    std.mem.writeInt(u32, out[28..32], 0x0BADF00D, .big);
    out[32] = 64;
    out[33] = 0x00;
    out[34] = 0x00;
    out[35] = 0x0A;
    std.mem.writeInt(u32, out[36..40], 0x00010005, .big);
    std.mem.writeInt(u32, out[40..44], 37, .big);
    std.mem.writeInt(u32, out[44..48], 0x7E804000, .big);
    std.mem.writeInt(u32, out[48..52], 0x00002000, .big);

    return out[0..52];
}

fn firstPacket(compound: []const u8) !rtcp.Packet {
    var walk = try rtcp.begin(compound);

    return walk.next() orelse error.TestUnexpectedResult;
}

test "zix media: report readSenderReport, the sender info reads field for field" {
    var buf: [52]u8 = undefined;
    const parsed = try readSenderReport(try firstPacket(sampleSenderReport(&buf)));

    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.ssrc);
    try std.testing.expectEqual(@as(u32, 0x83AA7E80), parsed.info.ntp.seconds);
    try std.testing.expectEqual(@as(u32, 0x40000000), parsed.info.ntp.fraction);
    try std.testing.expectEqual(@as(u32, 0x00001234), parsed.info.rtp_timestamp);
    try std.testing.expectEqual(@as(u32, 100), parsed.info.packet_count);
    try std.testing.expectEqual(@as(u32, 16000), parsed.info.octet_count);
    try std.testing.expectEqual(@as(usize, 1), parsed.blocks.count());
}

test "zix media: report readSenderReport, the report block reads field for field" {
    var buf: [52]u8 = undefined;
    const parsed = try readSenderReport(try firstPacket(sampleSenderReport(&buf)));
    const block = parsed.blocks.at(0).?;

    try std.testing.expectEqual(@as(u32, 0x0BADF00D), block.source);
    try std.testing.expectEqual(@as(u8, 64), block.fraction_lost);
    try std.testing.expectEqual(@as(i32, 10), block.packets_lost);
    try std.testing.expectEqual(@as(u32, 0x00010005), block.highest_sequence);
    try std.testing.expectEqual(@as(u32, 37), block.jitter);
    try std.testing.expect(parsed.blocks.at(1) == null);
}

test "zix media: report, fraction lost is a fraction over 256" {
    var buf: [52]u8 = undefined;
    const parsed = try readSenderReport(try firstPacket(sampleSenderReport(&buf)));

    // 64 out of 256 is a quarter, not 64 percent.
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), parsed.blocks.at(0).?.lossFraction(), 0.0001);
}

test "zix media: report, cumulative packets lost is signed" {
    var buf: [52]u8 = undefined;
    _ = sampleSenderReport(&buf);

    // Minus one, which unsigned would read as 16777215.
    buf[33] = 0xFF;
    buf[34] = 0xFF;
    buf[35] = 0xFF;

    const parsed = try readSenderReport(try firstPacket(&buf));
    try std.testing.expectEqual(@as(i32, -1), parsed.blocks.at(0).?.packets_lost);

    // The most negative value the field holds.
    buf[33] = 0x80;
    buf[34] = 0x00;
    buf[35] = 0x00;
    try std.testing.expectEqual(@as(i32, -8388608), (try readSenderReport(try firstPacket(&buf))).blocks.at(0).?.packets_lost);

    // And the most positive.
    buf[33] = 0x7F;
    buf[34] = 0xFF;
    buf[35] = 0xFF;
    try std.testing.expectEqual(@as(i32, 8388607), (try readSenderReport(try firstPacket(&buf))).blocks.at(0).?.packets_lost);
}

test "zix media: report readSenderReport, a wrong packet type is refused" {
    const receiver_report = [_]u8{ 0x80, 201, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };

    try std.testing.expectError(error.ZixWrongType, readSenderReport(try firstPacket(&receiver_report)));
}

test "zix media: report readSenderReport, a block count the body cannot hold is refused" {
    var buf: [52]u8 = undefined;
    _ = sampleSenderReport(&buf);

    // The header claims two blocks and the packet carries one.
    buf[0] = 0x82;

    try std.testing.expectError(error.ZixTruncated, readSenderReport(try firstPacket(&buf)));
}

test "zix media: report, a report packet with no body at all is refused, not read" {
    // Four bytes of common header and nothing behind it. rtcp.zig accepts that framing, so this
    // reader has to measure before it reaches for the sender identifier.
    const header_only = [_]u8{ 0x80, 201, 0x00, 0x00 };
    const sender_header_only = [_]u8{ 0x80, 200, 0x00, 0x00 };

    try std.testing.expectError(error.ZixTruncated, readReceiverReport(try firstPacket(&header_only)));
    try std.testing.expectError(error.ZixTruncated, readSenderReport(try firstPacket(&sender_header_only)));
}

test "zix media: report readReceiverReport, a report with no blocks is legal" {
    const empty = [_]u8{ 0x80, 201, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };
    const parsed = try readReceiverReport(try firstPacket(&empty));

    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.ssrc);
    try std.testing.expectEqual(@as(usize, 0), parsed.blocks.count());
    try std.testing.expect(parsed.blocks.at(0) == null);
}

test "zix media: report writeReceiverReport, what was written reads back the same" {
    const blocks = [_]ReportBlock{
        .{
            .source = 0x11223344,
            .fraction_lost = 128,
            .packets_lost = -5,
            .highest_sequence = 0x0002000A,
            .jitter = 99,
            .last_sender_report = 0xAABBCCDD,
            .delay_since_last_sender_report = 65536,
        },
        .{
            .source = 0x55667788,
            .fraction_lost = 0,
            .packets_lost = 0,
            .highest_sequence = 1,
            .jitter = 0,
            .last_sender_report = 0,
            .delay_since_last_sender_report = 0,
        },
    };

    var buf: [64]u8 = undefined;
    const written = try writeReceiverReport(&buf, 0x0BADF00D, &blocks);
    const parsed = try readReceiverReport(try firstPacket(written));

    try std.testing.expectEqual(@as(usize, 56), written.len);
    try std.testing.expectEqual(@as(u32, 0x0BADF00D), parsed.ssrc);
    try std.testing.expectEqual(@as(usize, 2), parsed.blocks.count());
    try std.testing.expectEqual(@as(i32, -5), parsed.blocks.at(0).?.packets_lost);
    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), parsed.blocks.at(0).?.last_sender_report);
    try std.testing.expectEqual(@as(u32, 0x55667788), parsed.blocks.at(1).?.source);
}

test "zix media: report writeReceiverReport, an empty report is two words" {
    var buf: [16]u8 = undefined;
    const written = try writeReceiverReport(&buf, 1, &.{});

    try std.testing.expectEqual(@as(usize, 8), written.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 201, 0x00, 0x01, 0, 0, 0, 1 }, written);
}

test "zix media: report writeReceiverReport, the limits are refused" {
    var buf: [1024]u8 = undefined;
    const too_many: [MAX_BLOCKS + 1]ReportBlock = @splat(.{
        .source = 0,
        .fraction_lost = 0,
        .packets_lost = 0,
        .highest_sequence = 0,
        .jitter = 0,
        .last_sender_report = 0,
        .delay_since_last_sender_report = 0,
    });

    try std.testing.expectError(error.ZixTooManyBlocks, writeReceiverReport(&buf, 1, &too_many));
    try std.testing.expectError(error.ZixNoSpace, writeReceiverReport(buf[0..7], 1, &.{}));
}

test "zix media: report writeReceiverReport, a loss count past the field saturates" {
    const blocks = [_]ReportBlock{.{
        .source = 1,
        .fraction_lost = 0,
        .packets_lost = 0x7FFFFFFF,
        .highest_sequence = 0,
        .jitter = 0,
        .last_sender_report = 0,
        .delay_since_last_sender_report = 0,
    }};

    var buf: [64]u8 = undefined;
    const written = try writeReceiverReport(&buf, 1, &blocks);
    const parsed = try readReceiverReport(try firstPacket(written));

    try std.testing.expectEqual(@as(i32, 0x7FFFFF), parsed.blocks.at(0).?.packets_lost);
}

test "zix media: report middle32, it takes the low seconds and the high fraction" {
    const stamp = NtpTimestamp{ .seconds = 0x83AA7E80, .fraction = 0x12345678 };

    try std.testing.expectEqual(@as(u32, 0x7E801234), stamp.middle32());
}

test "zix media: report, a sender report inside a compound reads out of the walk" {
    // The reports a peer sends arrive behind a sender report in one datagram, so the reader has
    // to work on a packet the iterator produced and not on a lone buffer.
    var buf: [64]u8 = undefined;
    var report_buf: [52]u8 = undefined;
    const report = sampleSenderReport(&report_buf);

    @memcpy(buf[0..52], report);
    @memcpy(buf[52..64], &[_]u8{ 0x81, 202, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x41, 0x00 });

    var walk = try rtcp.begin(buf[0..64]);
    const parsed = try readSenderReport(walk.next().?);

    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.ssrc);
    try std.testing.expectEqual(rtcp.PacketType.SDES, walk.next().?.packet_type);
}
