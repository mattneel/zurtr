//! zix HTTP/3 QUIC flow control, ACK, and path validation (RFC 9000 4 / 19.3 / 19.17, Layer Q).
//!
//! What:
//! - The three control mechanisms that keep a connection live and bounded: flow control (the
//!   receiver-advertised byte limits, per stream and per connection), acknowledgement (the ACK frame
//!   and its relative range encoding), and path validation (the PATH_CHALLENGE / PATH_RESPONSE echo).
//! - ACK range arithmetic (19.3.1): smallest = largest - range, next largest = previous smallest -
//!   gap - 2, a negative result is FRAME_ENCODING_ERROR. Proven against crafted frames in the tests.

const std = @import("std");

const varint = @import("varint.zig");

/// A receiver-advertised byte limit, per stream or per connection (RFC 9000 4.1). The sender MUST
/// NOT push data past the limit, and an advertised limit only ever increases.
pub const FlowLimit = struct {
    limit: u64,
    used: u64 = 0,

    /// Account data arriving up to absolute offset `end` (RFC 9000 4.1). Exceeding the limit is a
    /// FLOW_CONTROL_ERROR.
    pub fn consume(self: *FlowLimit, end: u64) error{ZixFlowControlError}!void {
        if (end > self.limit) return error.ZixFlowControlError;
        if (end > self.used) self.used = end;
    }

    /// Apply a MAX_DATA / MAX_STREAM_DATA advertisement (RFC 9000 4.1): a smaller limit has no
    /// effect, the sender MUST ignore any value that does not increase the limit.
    pub fn advertise(self: *FlowLimit, new_limit: u64) void {
        if (new_limit > self.limit) self.limit = new_limit;
    }
};

// --------------------------------------------------------------- //

/// A contiguous acknowledged packet-number range, inclusive (RFC 9000 19.3.1).
pub const Range = struct { smallest: u64, largest: u64 };

/// A parsed ACK frame (RFC 9000 19.3). The acknowledged ranges are resolved from the relative
/// encoding, the delay is decoded with the peer's ack_delay_exponent, and ECN counts are present
/// only for the 0x03 type.
pub const Ack = struct {
    largest: u64,
    delay_us: u64,
    ranges: [16]Range,
    range_len: usize,
    ecn: ?[3]u64,
    /// Bytes of the input `data` this frame occupied, so the caller can advance past it in a payload
    /// that coalesces more frames after the ACK.
    consumed: usize,
};

/// The ACK errors an endpoint MUST raise (RFC 9000 19.3.1).
pub const AckError = error{
    ZixTruncated,
    /// A computed packet number went negative, or too many ranges for the buffer: FRAME_ENCODING_ERROR.
    ZixFrameEncodingError,
};

/// Parse an ACK frame including its type byte (RFC 9000 19.3), resolving the relative range encoding
/// into absolute inclusive ranges. `ack_delay_exponent` is the peer's transport parameter.
pub fn parseAck(data: []const u8, ack_delay_exponent: u6) AckError!Ack {
    var pos: usize = 0;

    const ack_type = try field(data, &pos);
    const largest = try field(data, &pos);
    const delay = try field(data, &pos);
    const range_count = try field(data, &pos);
    const first_ack_range = try field(data, &pos);

    var ack: Ack = .{ .largest = largest, .delay_us = delay << ack_delay_exponent, .ranges = undefined, .range_len = 0, .ecn = null, .consumed = 0 };

    if (first_ack_range > largest) return error.ZixFrameEncodingError;

    var cur_smallest = largest - first_ack_range;
    ack.ranges[0] = .{ .smallest = cur_smallest, .largest = largest };
    ack.range_len = 1;

    for (0..range_count) |_| {
        const gap = try field(data, &pos);
        const range_len = try field(data, &pos);

        if (cur_smallest < gap + 2) return error.ZixFrameEncodingError;

        const next_largest = cur_smallest - gap - 2;
        if (range_len > next_largest) return error.ZixFrameEncodingError;

        const next_smallest = next_largest - range_len;
        if (ack.range_len >= ack.ranges.len) return error.ZixFrameEncodingError;

        ack.ranges[ack.range_len] = .{ .smallest = next_smallest, .largest = next_largest };
        ack.range_len += 1;
        cur_smallest = next_smallest;
    }

    if (ack_type == 0x03) {
        const ect0 = try field(data, &pos);
        const ect1 = try field(data, &pos);
        const ce = try field(data, &pos);
        ack.ecn = .{ ect0, ect1, ce };
    }

    ack.consumed = pos;

    return ack;
}

/// Read one variable-length field, advancing the cursor (helper for parseAck).
fn field(data: []const u8, pos: *usize) AckError!u64 {
    const vi = varint.read(data[pos.*..]) catch return error.ZixTruncated;
    pos.* += vi.len;

    return vi.value;
}

// --------------------------------------------------------------- //

/// Parse a PATH_CHALLENGE (0x1a) or PATH_RESPONSE (0x1b) frame and return its 8-byte data field
/// (RFC 9000 19.17 / 19.18).
pub fn parsePathData(data: []const u8) error{ ZixTruncated, ZixWrongType }![8]u8 {
    if (data.len < 9) return error.ZixTruncated;
    if (data[0] != 0x1a and data[0] != 0x1b) return error.ZixWrongType;

    return data[1..9].*;
}

/// A path is validated when a PATH_RESPONSE echoes the data of a previously sent PATH_CHALLENGE
/// (RFC 9000 8.2.3 / 19.18). A mismatch is grounds for a PROTOCOL_VIOLATION.
pub fn pathValidates(sent_challenge: [8]u8, received_response: [8]u8) bool {
    return std.mem.eql(u8, &sent_challenge, &received_response);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 4.1 stream and connection flow control" {
    var stream_flow = FlowLimit{ .limit = 100 };
    try stream_flow.consume(80);
    try std.testing.expectEqual(@as(u64, 80), stream_flow.used);
    try std.testing.expectError(error.ZixFlowControlError, stream_flow.consume(120));

    stream_flow.advertise(200);
    try stream_flow.consume(150);
    try std.testing.expectEqual(@as(u64, 150), stream_flow.used);

    stream_flow.advertise(50);
    try std.testing.expectEqual(@as(u64, 200), stream_flow.limit);

    var conn_flow = FlowLimit{ .limit = 1000 };
    try conn_flow.consume(1000);
    try std.testing.expectError(error.ZixFlowControlError, conn_flow.consume(1001));
}

test "zix http3: RFC 9000 19.3 ACK frame parse and range arithmetic" {
    const ack_single = try parseAck(&hexBytes("020a000003"), 0);
    try std.testing.expectEqual(@as(u64, 10), ack_single.largest);
    try std.testing.expect(ack_single.range_len == 1 and ack_single.ranges[0].smallest == 7 and ack_single.ranges[0].largest == 10);
    try std.testing.expectEqual(@as(usize, 5), ack_single.consumed);

    const ack_multi = try parseAck(&hexBytes("020a00010203" ++ "01"), 0);
    try std.testing.expectEqual(@as(usize, 2), ack_multi.range_len);
    try std.testing.expect(ack_multi.ranges[0].smallest == 8 and ack_multi.ranges[0].largest == 10);
    try std.testing.expect(ack_multi.ranges[1].smallest == 2 and ack_multi.ranges[1].largest == 3);
    try std.testing.expectEqual(@as(usize, 7), ack_multi.consumed);

    const ack_ecn = try parseAck(&hexBytes("030a000003" ++ "010203"), 0);
    try std.testing.expect(ack_ecn.ecn != null and ack_ecn.ecn.?[0] == 1 and ack_ecn.ecn.?[1] == 2 and ack_ecn.ecn.?[2] == 3);
    try std.testing.expectEqual(@as(usize, 8), ack_ecn.consumed);

    const ack_delay = try parseAck(&hexBytes("020a" ++ "4064" ++ "0000"), 3);
    try std.testing.expectEqual(@as(u64, 800), ack_delay.delay_us);

    try std.testing.expectError(error.ZixFrameEncodingError, parseAck(&hexBytes("0202000005"), 0));
}

test "zix http3: RFC 9000 19.17 / 19.18 path validation" {
    const challenge = try parsePathData(&hexBytes("1a0102030405060708"));
    try std.testing.expect(challenge[0] == 0x01 and challenge[7] == 0x08);

    const response = try parsePathData(&hexBytes("1b0102030405060708"));
    try std.testing.expect(pathValidates(challenge, response));

    const wrong = try parsePathData(&hexBytes("1b01020304050607ff"));
    try std.testing.expect(!pathValidates(challenge, wrong));

    try std.testing.expectError(error.ZixWrongType, parsePathData(&hexBytes("0c0102030405060708")));
}
