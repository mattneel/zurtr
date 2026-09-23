//! zix HTTP/3 QUIC packet headers and packet numbers (RFC 9000 17, Layer Q).
//!
//! What:
//! - The truncated packet-number encode length and decode (17.1), and the long / short header parse
//!   (17.2 / 17.3) that splits a datagram into its fields. Everything above (frames, streams) reads
//!   through these.
//! - Validates the version-1 invariants: Fixed Bit MUST be 1 (else discard) and a long header
//!   connection ID length MUST NOT exceed 20 (else drop). Proven against RFC 9000 Appendix A.2 / A.3
//!   plus crafted headers in the tests below.
//!
//! Note:
//! - parseLongHeader and decodePacketNumber are live. packetNumberLength, ShortHeader, and
//!   parseShortHeader are implemented and tested but unused: the send path uses a simpler inline
//!   packet-number-length rule and protection.zig parses the short header inline. Kept as the
//!   full-RFC reference (deferred).

const std = @import("std");

const varint = @import("varint.zig");

/// Select the packet-number encoding length in bytes (RFC 9000 17.1, Appendix A.2): the sender MUST
/// use a size able to represent more than twice the range of unacknowledged packet numbers.
pub fn packetNumberLength(full_pn: u64, largest_acked: ?u64) usize {
    const num_unacked = if (largest_acked) |acked| full_pn - acked else full_pn + 1;

    var bytes: usize = 1;
    while (bytes < 4) : (bytes += 1) {
        const range = @as(u128, 1) << @intCast(8 * bytes);
        if (range > 2 * @as(u128, num_unacked)) break;
    }

    return bytes;
}

/// Recover the full packet number from the truncated wire value (RFC 9000 17.1, Appendix A.3):
/// pick the candidate closest to the next expected packet number.
///
/// Note:
/// - The RFC pseudocode uses arbitrary-precision integers, so `expected_pn - pn_hwin` may go negative
///   (any time the expected number is below half a window, e.g. the first ~128 packets on a 1-byte
///   stream). The window comparisons are therefore done in signed i128, not u64: doing them in u64
///   underflows and wrongly shifts small packet numbers up by a whole window (turning packet 1 into
///   257), which would corrupt the AEAD nonce for every early packet.
pub fn decodePacketNumber(largest_pn: u64, truncated_pn: u64, pn_nbits: u6) u64 {
    const expected_pn = largest_pn + 1;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;

    const candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    const candidate: i128 = candidate_pn;
    const expected: i128 = expected_pn;
    const window: i128 = pn_win;
    const half_window: i128 = pn_hwin;
    if (candidate <= expected - half_window and candidate < (@as(i128, 1) << 62) - window) {
        return @intCast(candidate + window);
    }
    if (candidate > expected + half_window and candidate >= window) {
        return @intCast(candidate - window);
    }

    return candidate_pn;
}

// --------------------------------------------------------------- //

/// The errors a version-1 header parse can raise (RFC 9000 17.2 / 17.3 invariants).
pub const ParseError = error{
    ZixTruncated,
    /// Header Form bit says this is not the expected header shape.
    ZixWrongHeaderForm,
    /// Fixed Bit is 0: not a valid version-1 packet, MUST be discarded.
    ZixFixedBitZero,
    /// A connection ID length exceeds the 20-byte version-1 maximum, MUST drop the packet.
    ZixConnectionIdTooLong,
};

/// A version-1 long header packet split into its fields (RFC 9000 17.2).
pub const LongHeader = struct {
    packet_type: u2,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    rest: []const u8,
};

/// Parse a version-1 long header (RFC 9000 17.2). Validates Header Form, Fixed Bit, and the 20-byte
/// connection ID ceiling.
pub fn parseLongHeader(data: []const u8) ParseError!LongHeader {
    if (data.len < 6) return error.ZixTruncated;

    const first = data[0];
    if (first & 0x80 == 0) return error.ZixWrongHeaderForm;
    if (first & 0x40 == 0) return error.ZixFixedBitZero;

    const version = std.mem.readInt(u32, data[1..5], .big);

    var pos: usize = 5;
    const dcid_len = data[pos];
    if (dcid_len > 20) return error.ZixConnectionIdTooLong;
    pos += 1;
    if (data.len < pos + dcid_len) return error.ZixTruncated;
    const dcid = data[pos .. pos + dcid_len];
    pos += dcid_len;

    if (data.len < pos + 1) return error.ZixTruncated;
    const scid_len = data[pos];
    if (scid_len > 20) return error.ZixConnectionIdTooLong;
    pos += 1;
    if (data.len < pos + scid_len) return error.ZixTruncated;
    const scid = data[pos .. pos + scid_len];
    pos += scid_len;

    return .{
        .packet_type = @intCast((first & 0x30) >> 4),
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .rest = data[pos..],
    };
}

/// Where one long-header packet sits inside the datagram that carried it: the byte index of its packet
/// number and the byte index one past its AEAD tag. A long header carries a Length field covering the
/// packet number, the payload, and the tag (RFC 9000 17.2), which is what makes a datagram holding
/// several packets (RFC 9000 12.2) walkable.
pub const PacketBounds = struct { pn_offset: usize, end: usize };

/// The bounds of the long-header packet at the start of `data`, or null when the header, the Token
/// Length, or the Length field is malformed or runs past the buffer.
pub fn longPacketBounds(data: []const u8) ?PacketBounds {
    const hdr = parseLongHeader(data) catch return null;

    var pos = data.len - hdr.rest.len;

    // An Initial carries a Token Length and a Token before its Length field; the other long-header types
    // do not (RFC 9000 17.2).
    if (hdr.packet_type == 0) {
        const token = varint.read(data[pos..]) catch return null;
        pos += token.len + @as(usize, @intCast(token.value));
        if (pos > data.len) return null;
    }

    const length = varint.read(data[pos..]) catch return null;
    const span: usize = std.math.cast(usize, length.value) orelse return null;
    const pn_offset = pos + length.len;
    if (pn_offset + span > data.len) return null;

    return .{ .pn_offset = pn_offset, .end = pn_offset + span };
}

/// A version-1 short header (1-RTT) packet split into its fields (RFC 9000 17.3). The Destination
/// Connection ID length is not on the wire, the receiver knows the length it issued.
pub const ShortHeader = struct {
    spin_bit: bool,
    key_phase: bool,
    pn_length: usize,
    dcid: []const u8,
    rest: []const u8,
};

/// Parse a version-1 short header (RFC 9000 17.3) given the locally issued connection ID length.
/// Validates Header Form and Fixed Bit.
pub fn parseShortHeader(data: []const u8, dcid_len: usize) ParseError!ShortHeader {
    if (data.len < 1 + dcid_len) return error.ZixTruncated;

    const first = data[0];
    if (first & 0x80 != 0) return error.ZixWrongHeaderForm;
    if (first & 0x40 == 0) return error.ZixFixedBitZero;

    return .{
        .spin_bit = first & 0x20 != 0,
        .key_phase = first & 0x04 != 0,
        .pn_length = @as(usize, first & 0x03) + 1,
        .dcid = data[1 .. 1 + dcid_len],
        .rest = data[1 + dcid_len ..],
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 A.2 / A.3 packet number encode length and decode" {
    try std.testing.expectEqual(@as(usize, 2), packetNumberLength(0xac5c02, 0xabe8b3));
    try std.testing.expectEqual(@as(usize, 3), packetNumberLength(0xace8fe, 0xabe8b3));

    try std.testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 16));

    // Small packet numbers: expected_pn is below half a window, so the window math must not underflow.
    // These are the early-connection cases that a u64 subtraction turned into off-by-a-window (packet 1
    // decoded as 257), corrupting the nonce for the first packets of every connection.
    try std.testing.expectEqual(@as(u64, 1), decodePacketNumber(0, 1, 8));
    try std.testing.expectEqual(@as(u64, 2), decodePacketNumber(1, 2, 8));
    try std.testing.expectEqual(@as(u64, 0), decodePacketNumber(0, 0, 8));
    // Crossing the 1-byte boundary: largest 255, wire byte 0x00 means packet 256, not 0.
    try std.testing.expectEqual(@as(u64, 256), decodePacketNumber(255, 0x00, 8));
    // And a step further: largest 300, wire byte 0x2d (=45) resolves to 301, the in-window candidate.
    try std.testing.expectEqual(@as(u64, 301), decodePacketNumber(300, 0x2d, 8));
}

test "zix http3: RFC 9000 17.2 long header parse and invariants" {
    const long = hexBytes("c300000001088394c8f03e515708041122334400");
    const header = try parseLongHeader(&long);
    try std.testing.expectEqual(@as(u2, 0), header.packet_type);
    try std.testing.expectEqual(@as(u32, 1), header.version);
    try std.testing.expectEqualSlices(u8, &hexBytes("8394c8f03e515708"), header.dcid);
    try std.testing.expectEqualSlices(u8, &hexBytes("11223344"), header.scid);
    try std.testing.expectEqualSlices(u8, &hexBytes("00"), header.rest);

    try std.testing.expectError(error.ZixFixedBitZero, parseLongHeader(&hexBytes("830000000100")));
    try std.testing.expectError(error.ZixConnectionIdTooLong, parseLongHeader(&hexBytes("c30000000115")));
}

test "zix http3: RFC 9000 17.3 short header parse and invariants" {
    const short = hexBytes("43cafebabe11223344aabbcc");
    const sh = try parseShortHeader(&short, 8);
    try std.testing.expect(!sh.spin_bit);
    try std.testing.expect(!sh.key_phase);
    try std.testing.expectEqual(@as(usize, 4), sh.pn_length);
    try std.testing.expectEqualSlices(u8, &hexBytes("cafebabe11223344"), sh.dcid);
    try std.testing.expectEqualSlices(u8, &hexBytes("aabbcc"), sh.rest);

    try std.testing.expectError(error.ZixFixedBitZero, parseShortHeader(&hexBytes("03cafebabe11223344"), 8));
}
