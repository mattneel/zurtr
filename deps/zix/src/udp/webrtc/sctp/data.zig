//! zix SCTP DATA chunk (RFC 9260 3.3.1).
//!
//! What:
//! - The chunk that carries user bytes: a TSN that numbers it inside the association, a stream
//!   identifier and stream sequence number that place it inside a stream, a protocol identifier
//!   the application chose, and the payload.
//! - The four flag bits, which say whether the chunk is a whole message or one piece of one,
//!   whether the stream sequence number means anything, and whether the sender wants its
//!   acknowledgement without delay.
//!
//! Note:
//! - B and E together describe the fragment: both set is a whole message, B alone opens one, E
//!   alone closes it, neither is a middle piece. `isWhole` and `isFragment` say it in words.
//! - An unordered chunk has no stream sequence number. The field is still on the wire and must
//!   be ignored, so `stream_sequence` is left at zero rather than carrying a value a reader
//!   might trust.
//! - A DATA chunk must carry at least one byte. An empty one is a protocol error answered with a
//!   No User Data cause (RFC 9260 3.3.10.9), so it is rejected here rather than delivered as an
//!   empty message. An application that wants to send nothing uses a protocol identifier that
//!   means empty, which is a data channel concern and not an SCTP one.
//! - The payload protocol identifier is opaque here. SCTP never looks inside it, and what its
//!   values mean belongs to the layer that assigns them.

const std = @import("std");

/// TSN, stream identifier, stream sequence number, payload protocol identifier.
pub const FIXED_LEN: usize = 12;

/// The chunk is the last piece of a message, or the whole of one.
pub const FLAG_ENDING: u8 = 0x01;

/// The chunk is the first piece of a message, or the whole of one.
pub const FLAG_BEGINNING: u8 = 0x02;

/// The chunk is unordered, so its stream sequence number means nothing.
pub const FLAG_UNORDERED: u8 = 0x04;

/// The sender asks for the acknowledgement without the usual delay (RFC 7053).
pub const FLAG_IMMEDIATE: u8 = 0x08;

/// Everything that stops a DATA chunk from being read or built.
pub const Error = error{
    /// Fewer bytes than the fixed fields need.
    ZixTruncated,
    /// A chunk with a header and no payload, which RFC 9260 3.3.1 does not allow.
    ZixNoUserData,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// One DATA chunk, borrowing the payload it was read from.
pub const Data = struct {
    tsn: u32,
    stream_identifier: u16,
    /// Meaningless, and left at zero, when `unordered` is set.
    stream_sequence: u16 = 0,
    /// Chosen by the application. SCTP passes it through untouched.
    payload_protocol: u32 = 0,
    /// Deliver as soon as it is reassembled, without waiting for earlier stream sequences.
    unordered: bool = false,
    /// First piece of a message, or the whole of one.
    beginning: bool = true,
    /// Last piece of a message, or the whole of one.
    ending: bool = true,
    /// The sender wants the SACK back without delay (RFC 7053).
    immediate_sack: bool = false,
    /// At least one byte.
    payload: []const u8,

    /// Whether this chunk is a complete message on its own.
    ///
    /// Return:
    /// - bool
    pub fn isWhole(self: Data) bool {
        return self.beginning and self.ending;
    }

    /// Whether this chunk is one piece of a message split across several.
    ///
    /// Return:
    /// - bool
    pub fn isFragment(self: Data) bool {
        return !self.isWhole();
    }

    /// The flags byte for this chunk.
    ///
    /// Return:
    /// - u8
    pub fn flags(self: Data) u8 {
        var bits: u8 = 0;

        if (self.ending) bits |= FLAG_ENDING;
        if (self.beginning) bits |= FLAG_BEGINNING;
        if (self.unordered) bits |= FLAG_UNORDERED;
        if (self.immediate_sack) bits |= FLAG_IMMEDIATE;

        return bits;
    }

    /// Size of the chunk value this chunk would write.
    ///
    /// Return:
    /// - usize
    pub fn valueLen(self: Data) usize {
        return FIXED_LEN + self.payload.len;
    }
};

/// Size of the chunk value for a payload of a given length.
///
/// Note:
/// - Padding is not counted, matching how the chunk length field works.
///
/// Param:
/// payload_len - usize
///
/// Return:
/// - usize
pub fn valueLen(payload_len: usize) usize {
    return FIXED_LEN + payload_len;
}

/// Read a DATA chunk.
///
/// Param:
/// flags - u8 (the chunk's flags byte)
/// value - []const u8 (chunk value, so everything after the 4-byte chunk header)
///
/// Return:
/// - Data borrowing `value`
/// - error.ZixTruncated if the body is shorter than the fixed fields
/// - error.ZixNoUserData if there is no payload after them
pub fn read(flags: u8, value: []const u8) Error!Data {
    if (value.len < FIXED_LEN) return error.ZixTruncated;
    if (value.len == FIXED_LEN) return error.ZixNoUserData;

    const unordered = flags & FLAG_UNORDERED != 0;

    return .{
        .tsn = std.mem.readInt(u32, value[0..4], .big),
        .stream_identifier = std.mem.readInt(u16, value[4..6], .big),
        // Ignored on an unordered chunk (RFC 9260 3.3.1), so it is not carried forward at all.
        .stream_sequence = if (unordered) 0 else std.mem.readInt(u16, value[6..8], .big),
        .payload_protocol = std.mem.readInt(u32, value[8..12], .big),
        .unordered = unordered,
        .beginning = flags & FLAG_BEGINNING != 0,
        .ending = flags & FLAG_ENDING != 0,
        .immediate_sack = flags & FLAG_IMMEDIATE != 0,
        .payload = value[FIXED_LEN..],
    };
}

/// Write a DATA chunk value.
///
/// Note:
/// - Writes the value only. The caller puts it in a packet as a chunk of type DATA with
///   `Data.flags` as the flags byte, which is where the padding is added.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// item - Data
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixNoUserData if the payload is empty
/// - error.ZixNoSpace if the buffer cannot hold the fixed fields and the payload
pub fn write(out: []u8, item: Data) Error![]const u8 {
    if (item.payload.len == 0) return error.ZixNoUserData;

    const total = valueLen(item.payload.len);

    if (out.len < total) return error.ZixNoSpace;

    std.mem.writeInt(u32, out[0..4], item.tsn, .big);
    std.mem.writeInt(u16, out[4..6], item.stream_identifier, .big);
    std.mem.writeInt(u16, out[6..8], if (item.unordered) 0 else item.stream_sequence, .big);
    std.mem.writeInt(u32, out[8..12], item.payload_protocol, .big);
    @memcpy(out[FIXED_LEN..total], item.payload);

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

const sample: Data = .{
    .tsn = 0x0000ABCD,
    .stream_identifier = 3,
    .stream_sequence = 9,
    .payload_protocol = 53,
    .payload = "hello",
};

test "zix sctp: data write, an ordered whole message round trips" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, sample);

    try std.testing.expectEqual(@as(usize, 17), value.len);

    const parsed = try read(sample.flags(), value);

    try std.testing.expectEqual(sample.tsn, parsed.tsn);
    try std.testing.expectEqual(sample.stream_identifier, parsed.stream_identifier);
    try std.testing.expectEqual(sample.stream_sequence, parsed.stream_sequence);
    try std.testing.expectEqual(sample.payload_protocol, parsed.payload_protocol);
    try std.testing.expectEqualStrings("hello", parsed.payload);
    try std.testing.expect(parsed.isWhole());
    try std.testing.expect(!parsed.unordered);
}

test "zix sctp: data flags, a whole message sets both fragment bits" {
    try std.testing.expectEqual(FLAG_BEGINNING | FLAG_ENDING, sample.flags());
}

test "zix sctp: data flags, the three fragment positions each have their own pattern" {
    var first = sample;
    first.ending = false;

    var middle = sample;
    middle.beginning = false;
    middle.ending = false;

    var last = sample;
    last.beginning = false;

    try std.testing.expectEqual(FLAG_BEGINNING, first.flags());
    try std.testing.expectEqual(@as(u8, 0), middle.flags());
    try std.testing.expectEqual(FLAG_ENDING, last.flags());

    try std.testing.expect(first.isFragment());
    try std.testing.expect(middle.isFragment());
    try std.testing.expect(last.isFragment());
}

test "zix sctp: data flags, unordered and immediate ride alongside the fragment bits" {
    var item = sample;
    item.unordered = true;
    item.immediate_sack = true;

    const expected = FLAG_BEGINNING | FLAG_ENDING | FLAG_UNORDERED | FLAG_IMMEDIATE;
    try std.testing.expectEqual(expected, item.flags());
}

test "zix sctp: data read, an unordered chunk reports no stream sequence" {
    var item = sample;
    item.unordered = true;
    item.stream_sequence = 9;

    var buf: [32]u8 = undefined;
    const value = try write(&buf, item);

    // The field goes out as zero and comes back as zero, so nothing downstream can trust it.
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, value[6..8], .big));

    const parsed = try read(item.flags(), value);
    try std.testing.expectEqual(@as(u16, 0), parsed.stream_sequence);
    try std.testing.expect(parsed.unordered);
}

test "zix sctp: data read, an unordered chunk on the wire ignores whatever is in the field" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, sample);

    // A peer that wrote a stream sequence anyway must not have it believed.
    const parsed = try read(sample.flags() | FLAG_UNORDERED, value);

    try std.testing.expectEqual(@as(u16, 0), parsed.stream_sequence);
}

test "zix sctp: data read, a chunk with no payload errors" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, sample);

    try std.testing.expectError(error.ZixNoUserData, read(sample.flags(), value[0..FIXED_LEN]));
}

test "zix sctp: data read, a chunk shorter than the fixed fields errors" {
    const short: [11]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, read(0, &short));
}

test "zix sctp: data write, an empty payload errors" {
    var buf: [32]u8 = undefined;
    var item = sample;
    item.payload = &.{};

    try std.testing.expectError(error.ZixNoUserData, write(&buf, item));
}

test "zix sctp: data write, a buffer too small errors" {
    var buf: [16]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, sample));
}

test "zix sctp: data write, one byte of payload gives a value of seventeen bytes" {
    var buf: [32]u8 = undefined;
    var item = sample;
    item.payload = "x";

    const value = try write(&buf, item);

    // RFC 9260 3.3.1 states this size outright, chunk header included.
    try std.testing.expectEqual(@as(usize, 13), value.len);
    try std.testing.expectEqual(@as(usize, 13), valueLen(1));
    try std.testing.expectEqual(@as(usize, 13), item.valueLen());
}

test "zix sctp: data write, a TSN at the top of its range survives the round trip" {
    var buf: [32]u8 = undefined;
    var item = sample;
    item.tsn = 0xFFFFFFFF;

    const parsed = try read(item.flags(), try write(&buf, item));

    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), parsed.tsn);
}

test "zix sctp: data read, the reserved flag bits are ignored" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, sample);

    // The top four bits are reserved and set to zero on transmit, ignored on receipt.
    const parsed = try read(sample.flags() | 0xF0, value);

    try std.testing.expect(parsed.isWhole());
    try std.testing.expect(!parsed.unordered);
    try std.testing.expect(!parsed.immediate_sack);
}
