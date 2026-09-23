//! protobuf.zig: a minimal varint plus length-delimited encoder for the
//! subset of the protobuf wire format the remote_write WriteRequest schema
//! needs (string, embedded message, double, int64 fields). Not a general
//! protobuf library: encoding only, no decoding, no other wire types.

const std = @import("std");

/// A growable byte buffer with protobuf field-writing helpers. Each write*
/// call appends one complete field: tag plus payload.
pub const Builder = struct {
    bytes: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
    }

    pub fn toOwnedSlice(self: *Builder, allocator: std.mem.Allocator) ![]u8 {
        return self.bytes.toOwnedSlice(allocator);
    }

    /// Append a `string`/`bytes` field (wire type 2): tag, varint length,
    /// raw bytes.
    pub fn writeString(self: *Builder, allocator: std.mem.Allocator, field_number: u32, value: []const u8) !void {
        try self.writeTag(allocator, field_number, 2);
        try self.writeVarint(allocator, value.len);
        try self.bytes.appendSlice(allocator, value);
    }

    /// Append an embedded message field (wire type 2): tag, varint length,
    /// the already-serialized message bytes.
    pub fn writeMessage(self: *Builder, allocator: std.mem.Allocator, field_number: u32, message_bytes: []const u8) !void {
        try self.writeTag(allocator, field_number, 2);
        try self.writeVarint(allocator, message_bytes.len);
        try self.bytes.appendSlice(allocator, message_bytes);
    }

    /// Append a `double` field (wire type 1, fixed64 little-endian).
    pub fn writeDouble(self: *Builder, allocator: std.mem.Allocator, field_number: u32, value: f64) !void {
        try self.writeTag(allocator, field_number, 1);

        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, @bitCast(value), .little);
        try self.bytes.appendSlice(allocator, &buf);
    }

    /// Append an `int64` field (wire type 0, plain varint of the raw two's
    /// complement bit pattern - not the zigzag `sint64` encoding).
    pub fn writeInt64(self: *Builder, allocator: std.mem.Allocator, field_number: u32, value: i64) !void {
        try self.writeTag(allocator, field_number, 0);
        try self.writeVarint(allocator, @as(u64, @bitCast(value)));
    }

    fn writeTag(self: *Builder, allocator: std.mem.Allocator, field_number: u32, wire_type: u3) !void {
        const tag: u64 = (@as(u64, field_number) << 3) | wire_type;
        try self.writeVarint(allocator, tag);
    }

    fn writeVarint(self: *Builder, allocator: std.mem.Allocator, raw_value: u64) !void {
        var remaining = raw_value;
        while (true) {
            const byte: u8 = @truncate(remaining & 0x7f);
            remaining >>= 7;
            if (remaining == 0) {
                try self.bytes.append(allocator, byte);
                return;
            }
            try self.bytes.append(allocator, byte | 0x80);
        }
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: protobuf varint matches the spec example (150)" {
    var builder: Builder = .{};
    defer builder.deinit(testing.allocator);

    // int64 field 1 = 150: tag (1<<3|0)=0x08, then varint(150)=[0x96,0x01].
    try builder.writeInt64(testing.allocator, 1, 150);

    const bytes = try builder.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bytes);

    try testing.expectEqualSlices(u8, &.{ 0x08, 0x96, 0x01 }, bytes);
}

test "prometheuz: protobuf string field encodes tag length and bytes" {
    var builder: Builder = .{};
    defer builder.deinit(testing.allocator);

    // string field 1 = "testing": tag (1<<3|2)=0x0A, len=7, then the bytes.
    try builder.writeString(testing.allocator, 1, "testing");

    const bytes = try builder.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bytes);

    try testing.expectEqualSlices(u8, "\x0a\x07testing", bytes);
}

test "prometheuz: protobuf double field is little-endian fixed64" {
    var builder: Builder = .{};
    defer builder.deinit(testing.allocator);

    try builder.writeDouble(testing.allocator, 1, 1.0);

    const bytes = try builder.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bytes);

    // tag (1<<3|1)=0x09, then 1.0 as little-endian fixed64.
    try testing.expectEqual(@as(u8, 0x09), bytes[0]);
    const decoded = std.mem.readInt(u64, bytes[1..9], .little);
    try testing.expectEqual(@as(f64, 1.0), @as(f64, @bitCast(decoded)));
}

test "prometheuz: protobuf embedded message nests raw bytes" {
    var inner: Builder = .{};
    try inner.writeString(testing.allocator, 1, "x");
    const inner_bytes = try inner.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(inner_bytes);

    var outer: Builder = .{};
    defer outer.deinit(testing.allocator);
    try outer.writeMessage(testing.allocator, 1, inner_bytes);

    const bytes = try outer.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bytes);

    // tag (1<<3|2)=0x0A, len=3 (inner_bytes.len), then the inner bytes verbatim.
    try testing.expectEqualSlices(u8, "\x0a\x03\x0a\x01x", bytes);
}

test "prometheuz: protobuf varint over 127 needs a continuation byte" {
    var builder: Builder = .{};
    defer builder.deinit(testing.allocator);

    try builder.writeInt64(testing.allocator, 15, 300);

    const bytes = try builder.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bytes);

    // field 15, wire type 0: tag = (15<<3)|0 = 120 = 0x78 (single byte, fits in 7 bits).
    try testing.expectEqual(@as(u8, 0x78), bytes[0]);
    // 300 = 0b1_0010_1100 -> groups [0101100, 0000010] -> [0xac, 0x02].
    try testing.expectEqualSlices(u8, &.{ 0xac, 0x02 }, bytes[1..]);
}
