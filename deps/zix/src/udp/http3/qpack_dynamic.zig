//! zix HTTP/3 QPACK dynamic table and decoder feedback (RFC 9204 3.2 / 4.4 / 4.5.1 / 6, Layer P).
//!
//! What:
//! - The dynamic table (3.2): a bounded, append-with-eviction store, the size accounting (name +
//!   value + 32 per entry), eviction from the oldest end, and the absolute index that never reuses a
//!   value. On top, the Required Insert Count / Base transform (4.5.1) the field section prefix uses.
//! - The decoder-stream instructions (4.4): Section Acknowledgment, Stream Cancellation, and Insert
//!   Count Increment, plus the QPACK error codes (section 6). Proven against the RFC worked examples.
//!
//! Note:
//! - A server may run with dynamic-table capacity 0 and compress with the static table plus literals
//!   alone. This module is the dynamic half for when capacity is advertised.
//! - Implemented and unit-tested, but not wired into the serve path yet (deferred): the live path
//!   uses only the static table, and there is no non-zero dynamic-capacity config to enable it.

const std = @import("std");

const qpack = @import("qpack.zig");

/// The per-entry overhead in the dynamic table size accounting (RFC 9204 3.2.1).
pub const entry_overhead: usize = 32;

/// The size of a dynamic table entry (RFC 9204 3.2.1): name length + value length + 32, using the
/// unencoded (non-Huffman) lengths.
pub fn entrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + entry_overhead;
}

/// One dynamic table entry.
pub const DynEntry = struct { name: []const u8, value: []const u8 };

/// The errors the QPACK dynamic table raises (RFC 9204 3.2.2).
pub const TableError = error{
    /// Inserting an entry larger than the capacity: QPACK_ENCODER_STREAM_ERROR.
    ZixEncoderStreamError,
};

/// The QPACK dynamic table (RFC 9204 3.2): a bounded store, oldest entries evicted from the end to
/// make room. Entries are kept oldest-first, so the oldest (lowest absolute index) is at the front.
pub const DynamicTable = struct {
    capacity: usize,
    items: [64]DynEntry = undefined,
    count: usize = 0,
    size: usize = 0,
    inserts: u64 = 0,

    /// Insert a new entry, evicting from the oldest end first (RFC 9204 3.2.2). An entry larger than
    /// the capacity is a QPACK_ENCODER_STREAM_ERROR.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) TableError!void {
        const need = entrySize(name, value);
        if (need > self.capacity) return error.ZixEncoderStreamError;

        while (self.size + need > self.capacity) self.evictOldest();

        self.items[self.count] = .{ .name = name, .value = value };
        self.count += 1;
        self.size += need;
        self.inserts += 1;
    }

    /// Evict the oldest entry from the front (RFC 9204 3.2.2).
    pub fn evictOldest(self: *DynamicTable) void {
        const gone = entrySize(self.items[0].name, self.items[0].value);
        for (1..self.count) |i| self.items[i - 1] = self.items[i];

        self.count -= 1;
        self.size -= gone;
    }

    /// Reduce or raise the capacity, evicting from the oldest end until the size fits (RFC 9204
    /// 3.2.2). A capacity of 0 clears the table.
    pub fn setCapacity(self: *DynamicTable, new_capacity: usize) void {
        self.capacity = new_capacity;
        while (self.size > self.capacity) self.evictOldest();
    }

    /// The absolute index of the oldest live entry (RFC 9204 3.2.4): inserts so far minus live count.
    pub fn oldestAbsoluteIndex(self: DynamicTable) u64 {
        return self.inserts - self.count;
    }

    /// MaxEntries for the current capacity (RFC 9204 4.5.1.1): floor(capacity / 32).
    pub fn maxEntries(self: DynamicTable) u64 {
        return self.capacity / entry_overhead;
    }
};

// --------------------------------------------------------------- //

/// The errors Required Insert Count reconstruction raises (RFC 9204 4.5.1.1).
pub const RicError = error{
    /// An EncodedInsertCount no conformant encoder could produce: QPACK_DECOMPRESSION_FAILED.
    ZixDecompressionFailed,
};

/// Transform a Required Insert Count for the wire (RFC 9204 4.5.1.1): 0 stays 0, otherwise it is
/// taken modulo twice MaxEntries and offset by one to bound the prefix length.
pub fn encodeRequiredInsertCount(ric: u64, max_entries: u64) u64 {
    if (ric == 0) return 0;

    return (ric % (2 * max_entries)) + 1;
}

/// Reconstruct the Required Insert Count from the wire value (RFC 9204 4.5.1.1), given the total
/// inserts the decoder has made. An unreconstructable value is a QPACK_DECOMPRESSION_FAILED.
pub fn decodeRequiredInsertCount(encoded: u64, total_inserts: u64, max_entries: u64) RicError!u64 {
    if (encoded == 0) return 0;

    const full_range = 2 * max_entries;
    if (encoded > full_range) return error.ZixDecompressionFailed;

    const max_value = total_inserts + max_entries;
    const max_wrapped = (max_value / full_range) * full_range;
    var ric = max_wrapped + encoded - 1;

    if (ric > max_value) {
        if (ric <= full_range) return error.ZixDecompressionFailed;
        ric -= full_range;
    }
    if (ric == 0) return error.ZixDecompressionFailed;

    return ric;
}

/// Resolve the Base from the Required Insert Count, the Sign bit, and Delta Base (RFC 9204 4.5.1.2).
/// Sign 0 adds Delta Base, Sign 1 subtracts Delta Base and one.
pub fn resolveBase(ric: i64, sign: bool, delta_base: i64) i64 {
    return if (sign) ric - delta_base - 1 else ric + delta_base;
}

// --------------------------------------------------------------- //

/// A decoder-stream instruction (RFC 9204 4.4). The payload is a stream id or an increment.
pub const DecoderInstruction = union(enum) {
    /// Section Acknowledgment (4.4.1): the acknowledged field section's stream id.
    section_ack: u64,
    /// Stream Cancellation (4.4.2): the reset / abandoned stream id.
    stream_cancel: u64,
    /// Insert Count Increment (4.4.3): how much to advance the Known Received Count.
    insert_count_increment: u64,
};

/// The decoder-instruction errors an encoder raises (RFC 9204 4.4.3).
pub const InstructionError = error{
    ZixTruncated,
    /// An Insert Count Increment of zero: QPACK_DECODER_STREAM_ERROR.
    ZixDecoderStreamError,
};

/// Encode a Section Acknowledgment (RFC 9204 4.4.1): '1' then a 7-bit prefix stream id.
pub fn encodeSectionAck(out: []u8, stream_id: u64) usize {
    return qpack.encodePrefixedInt(out, 7, 0x80, stream_id);
}

/// Encode a Stream Cancellation (RFC 9204 4.4.2): '01' then a 6-bit prefix stream id.
pub fn encodeStreamCancel(out: []u8, stream_id: u64) usize {
    return qpack.encodePrefixedInt(out, 6, 0x40, stream_id);
}

/// Encode an Insert Count Increment (RFC 9204 4.4.3): '00' then a 6-bit prefix increment.
pub fn encodeInsertCountIncrement(out: []u8, increment: u64) usize {
    return qpack.encodePrefixedInt(out, 6, 0x00, increment);
}

/// Decode one decoder-stream instruction (RFC 9204 4.4), told apart by the leading bits. An Insert
/// Count Increment of zero is a QPACK_DECODER_STREAM_ERROR.
pub fn decodeDecoderInstruction(data: []const u8) InstructionError!DecoderInstruction {
    if (data.len == 0) return error.ZixTruncated;

    const first = data[0];
    if (first & 0x80 != 0) {
        const int = qpack.decodePrefixedInt(data, 7) catch return error.ZixTruncated;
        return .{ .section_ack = int.value };
    }
    if (first & 0x40 != 0) {
        const int = qpack.decodePrefixedInt(data, 6) catch return error.ZixTruncated;
        return .{ .stream_cancel = int.value };
    }

    const int = qpack.decodePrefixedInt(data, 6) catch return error.ZixTruncated;
    if (int.value == 0) return error.ZixDecoderStreamError;

    return .{ .insert_count_increment = int.value };
}

/// The QPACK error codes in the HTTP/3 Error Codes registry (RFC 9204 section 6).
pub const QpackError = enum(u16) {
    decompression_failed = 0x0200,
    encoder_stream_error = 0x0201,
    decoder_stream_error = 0x0202,
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9204 3.2 dynamic table insert and eviction" {
    try std.testing.expectEqual(@as(usize, 38), entrySize("foo", "bar"));
    try std.testing.expectEqual(@as(usize, 32), entrySize("", ""));

    var table = DynamicTable{ .capacity = 76 };
    try table.insert("foo", "bar");
    try std.testing.expect(table.size == 38 and table.count == 1 and table.oldestAbsoluteIndex() == 0);

    try table.insert("baz", "qux");
    try std.testing.expect(table.size == 76 and table.count == 2);

    try table.insert("abc", "def");
    try std.testing.expect(table.count == 2 and std.mem.eql(u8, table.items[0].name, "baz") and table.oldestAbsoluteIndex() == 1 and table.inserts == 3);

    try std.testing.expectError(error.ZixEncoderStreamError, table.insert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

    table.setCapacity(38);
    try std.testing.expect(table.count == 1 and table.size == 38);
    table.setCapacity(0);
    try std.testing.expect(table.count == 0 and table.size == 0);
}

test "zix http3: RFC 9204 4.5.1 Required Insert Count and Base" {
    var sized = DynamicTable{ .capacity = 100 };
    try std.testing.expectEqual(@as(u64, 3), sized.maxEntries());

    try std.testing.expectEqual(@as(u64, 0), encodeRequiredInsertCount(0, 3));
    try std.testing.expectEqual(@as(u64, 4), encodeRequiredInsertCount(9, 3));

    try std.testing.expectEqual(@as(u64, 9), try decodeRequiredInsertCount(4, 10, 3));
    try std.testing.expectEqual(@as(u64, 0), try decodeRequiredInsertCount(0, 10, 3));
    try std.testing.expectError(error.ZixDecompressionFailed, decodeRequiredInsertCount(7, 10, 3));

    try std.testing.expectEqual(@as(i64, 9), resolveBase(9, false, 0));
    try std.testing.expectEqual(@as(i64, 6), resolveBase(9, true, 2));
}

test "zix http3: RFC 9204 4.4 decoder instructions and section 6 error codes" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &hexBytes("84"), buf[0..encodeSectionAck(&buf, 4)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("ff49"), buf[0..encodeSectionAck(&buf, 200)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("48"), buf[0..encodeStreamCancel(&buf, 8)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("0a"), buf[0..encodeInsertCountIncrement(&buf, 10)]);

    const ack = try decodeDecoderInstruction(&hexBytes("84"));
    try std.testing.expect(ack == .section_ack and ack.section_ack == 4);
    const ack_big = try decodeDecoderInstruction(&hexBytes("ff49"));
    try std.testing.expect(ack_big == .section_ack and ack_big.section_ack == 200);
    const cancel = try decodeDecoderInstruction(&hexBytes("48"));
    try std.testing.expect(cancel == .stream_cancel and cancel.stream_cancel == 8);
    const increment = try decodeDecoderInstruction(&hexBytes("0a"));
    try std.testing.expect(increment == .insert_count_increment and increment.insert_count_increment == 10);
    try std.testing.expectError(error.ZixDecoderStreamError, decodeDecoderInstruction(&hexBytes("00")));

    try std.testing.expectEqual(@as(u16, 0x0200), @intFromEnum(QpackError.decompression_failed));
    try std.testing.expectEqual(@as(u16, 0x0201), @intFromEnum(QpackError.encoder_stream_error));
    try std.testing.expectEqual(@as(u16, 0x0202), @intFromEnum(QpackError.decoder_stream_error));
}
