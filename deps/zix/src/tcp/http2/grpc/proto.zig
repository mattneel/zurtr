//! Protobuf minimal codec: VARINT (0) and LEN (2) wire types.
//! Sufficient for string, int32, bytes, and nested message fields.

const std = @import("std");

// --------------------------------------------------------- //

pub const WT_VARINT: u3 = 0;
pub const WT_I64: u3 = 1;
pub const WT_LEN: u3 = 2;
pub const WT_I32: u3 = 5;

// --------------------------------------------------------- //

/// Encode value as unsigned varint into buf.
///
/// Return:
/// - usize (bytes written)
pub fn encodeVarint(buf: []u8, value: u64) usize {
    var v = value;
    var pos: usize = 0;
    while (v >= 0x80) {
        buf[pos] = @intCast((v & 0x7F) | 0x80);
        pos += 1;
        v >>= 7;
    }
    buf[pos] = @intCast(v);
    return pos + 1;
}

/// Decode unsigned varint from buf.
///
/// Return:
/// - !struct{ value: u64, consumed: usize }
/// - error.ZixUnexpectedEOF if buf ends before the varint terminates
/// - error.ZixVarintOverflow if the encoded value exceeds 64 bits
pub fn decodeVarint(buf: []const u8) error{ ZixUnexpectedEOF, ZixVarintOverflow }!struct { value: u64, consumed: usize } {
    var val: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < buf.len) {
        const b = buf[i];
        i += 1;
        val |= (@as(u64, b & 0x7F)) << shift;
        if ((b & 0x80) == 0) return .{ .value = val, .consumed = i };
        if (shift > 56) return error.ZixVarintOverflow;
        shift += 7;
    }
    return error.ZixUnexpectedEOF;
}

/// Encode a LEN field (string or bytes).
/// Tag encoding: (field_number << 3) | WT_LEN.
///
/// Return:
/// - usize (bytes written)
pub fn encodeString(field_number: u32, str: []const u8, buf: []u8) usize {
    const tag: u64 = (@as(u64, field_number) << 3) | WT_LEN;
    var pos = encodeVarint(buf, tag);
    pos += encodeVarint(buf[pos..], @as(u64, str.len));
    @memcpy(buf[pos..][0..str.len], str);
    return pos + str.len;
}

/// Encode a VARINT field (int32).
/// Tag encoding: (field_number << 3) | WT_VARINT.
///
/// Return:
/// - usize (bytes written)
pub fn encodeInt32(field_number: u32, val: i32, buf: []u8) usize {
    const tag: u64 = (@as(u64, field_number) << 3) | WT_VARINT;
    var pos = encodeVarint(buf, tag);
    pos += encodeVarint(buf[pos..], @bitCast(@as(i64, val)));
    return pos;
}

/// Encode a double (f64) field. Wire type WT_I64 (8 bytes, little-endian).
/// Tag encoding: (field_number << 3) | WT_I64.
///
/// Return:
/// - usize (bytes written)
pub fn encodeDouble(field_number: u32, val: f64, buf: []u8) usize {
    const tag: u64 = (@as(u64, field_number) << 3) | WT_I64;
    const pos = encodeVarint(buf, tag);
    const bits: u64 = @bitCast(val);
    std.mem.writeInt(u64, buf[pos..][0..8], bits, .little);
    return pos + 8;
}

/// Decode a double (f64) from a WT_I64 payload slice (8 bytes, little-endian).
pub fn decodeDouble(payload: *const [8]u8) f64 {
    const bits = std.mem.readInt(u64, payload, .little);
    return @bitCast(bits);
}

// --------------------------------------------------------- //

pub const ProtoField = struct {
    field_number: u32,
    wire_type: u3,
    payload: []const u8,
    value_u64: u64,
};

/// Sequential reader for a single protobuf message.
pub const MessageReader = struct {
    buf: []const u8,
    pos: usize,

    pub fn init(buf: []const u8) MessageReader {
        return .{ .buf = buf, .pos = 0 };
    }

    /// Read the next field.
    ///
    /// Return:
    /// - !?ProtoField (null at end of message)
    pub fn next(self: *MessageReader) !?ProtoField {
        if (self.pos >= self.buf.len) return null;
        const tag_r = try decodeVarint(self.buf[self.pos..]);
        self.pos += tag_r.consumed;
        const wire_type: u3 = @intCast(tag_r.value & 0x07);
        const field_number: u32 = @intCast(tag_r.value >> 3);

        switch (wire_type) {
            WT_VARINT => {
                const r = try decodeVarint(self.buf[self.pos..]);
                self.pos += r.consumed;
                return .{ .field_number = field_number, .wire_type = wire_type, .payload = &.{}, .value_u64 = r.value };
            },
            WT_I64 => {
                if (self.pos + 8 > self.buf.len) return error.ZixUnexpectedEOF;
                const data = self.buf[self.pos..][0..8];
                self.pos += 8;
                return .{ .field_number = field_number, .wire_type = wire_type, .payload = data, .value_u64 = 0 };
            },
            WT_LEN => {
                const len_r = try decodeVarint(self.buf[self.pos..]);
                self.pos += len_r.consumed;
                const data_len: usize = @intCast(len_r.value);
                if (self.pos + data_len > self.buf.len) return error.ZixUnexpectedEOF;
                const data = self.buf[self.pos..][0..data_len];
                self.pos += data_len;
                return .{ .field_number = field_number, .wire_type = wire_type, .payload = data, .value_u64 = 0 };
            },
            WT_I32 => {
                if (self.pos + 4 > self.buf.len) return error.ZixUnexpectedEOF;
                const data = self.buf[self.pos..][0..4];
                self.pos += 4;
                return .{ .field_number = field_number, .wire_type = wire_type, .payload = data, .value_u64 = 0 };
            },
            else => return error.ZixUnknownWireType,
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: encodeVarint single byte" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 1);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
}

test "zix grpc: encodeVarint two bytes for value 300" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 300);
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "zix grpc: decodeVarint single byte roundtrip" {
    const input: []const u8 = &[_]u8{0x01};
    const r = try decodeVarint(input);
    try std.testing.expectEqual(@as(u64, 1), r.value);
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
}

test "zix grpc: decodeVarint multi byte roundtrip" {
    var buf: [10]u8 = undefined;
    const n = encodeVarint(&buf, 300);
    const r = try decodeVarint(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 300), r.value);
}

test "zix grpc: encodeString and MessageReader roundtrip" {
    var buf: [64]u8 = undefined;
    const n = encodeString(1, "hello", &buf);
    var reader = MessageReader.init(buf[0..n]);
    const field = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 1), field.field_number);
    try std.testing.expectEqual(WT_LEN, field.wire_type);
    try std.testing.expectEqualStrings("hello", field.payload);
    try std.testing.expect((try reader.next()) == null);
}

test "zix grpc: MessageReader empty buf returns null" {
    var reader = MessageReader.init(&.{});
    try std.testing.expect((try reader.next()) == null);
}

test "zix grpc: encodeDouble and decodeDouble roundtrip positive" {
    var buf: [16]u8 = undefined;
    const n = encodeDouble(1, 106.8, &buf);
    var reader = MessageReader.init(buf[0..n]);
    const field = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 1), field.field_number);
    try std.testing.expectEqual(WT_I64, field.wire_type);
    try std.testing.expectEqual(@as(f64, 106.8), decodeDouble(field.payload[0..8]));
    try std.testing.expect((try reader.next()) == null);
}

test "zix grpc: encodeDouble and decodeDouble roundtrip negative" {
    var buf: [16]u8 = undefined;
    const n = encodeDouble(2, -6.2, &buf);
    var reader = MessageReader.init(buf[0..n]);
    const field = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 2), field.field_number);
    try std.testing.expectEqual(@as(f64, -6.2), decodeDouble(field.payload[0..8]));
}
