//! zix SCTP chunk framing (RFC 9260 3.2).
//!
//! What:
//! - The 4-byte envelope every SCTP chunk shares: type, flags, and a length that covers the
//!   header plus the value. This file walks a packet's chunk region, hands the chunks out one at
//!   a time, and writes simple ones back.
//! - The type registry, and the rule that says what to do with a type this endpoint does not
//!   know. That rule is encoded in the number itself, not in a table.
//!
//! Note:
//! - What each chunk's value means is decoded elsewhere, one file per chunk family. This file
//!   only knows where a chunk starts and ends.
//! - The length field does NOT count the padding that follows, so a chunk of length 5 occupies 8
//!   bytes. The final chunk of a packet is allowed to arrive without its padding (RFC 9260 3.2),
//!   and a receiver that insists on it rejects packets other implementations happily send.
//! - `validate` checks the whole region before anything is read out of it, which is what lets
//!   `Iterator.next` return without an error union. A packet whose framing is broken is
//!   discarded whole, so there is nothing to report per chunk.

const std = @import("std");

/// Type, flags, and length.
pub const HEADER_LEN: usize = 4;

/// Every chunk starts on a 4-byte boundary (RFC 9260 3.2).
pub const ALIGNMENT: usize = 4;

/// Largest value the length field can hold, so the largest a chunk can be.
pub const MAX_CHUNK_LEN: usize = std.math.maxInt(u16);

/// Framing faults that make the whole packet undecodable.
pub const Error = error{
    /// A chunk claims to run past the end of the region.
    ZixTruncated,
    /// A chunk length below the header size, which cannot be right at any type.
    ZixBadLength,
    /// The region has no room for another chunk header.
    ZixNoSpace,
};

/// Chunk types this build knows (RFC 9260 3.2 Table 1, plus the two extensions in use).
///
/// Note:
/// - Non-exhaustive on purpose. An unknown type still has to be represented, because what
///   happens next is decided from its number, see `unknownAction`.
pub const Type = enum(u8) {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13,
    SHUTDOWN_COMPLETE = 14,
    /// RFC 6525 stream reconfiguration, which is how a data channel closes.
    RE_CONFIG = 130,
    /// RFC 4820 padding, required for path MTU probes under DTLS (RFC 8261 6.2).
    PAD = 132,
    /// RFC 3758 partial reliability.
    FORWARD_TSN = 192,
    _,
};

/// What an endpoint does with a chunk type it does not recognise (RFC 9260 3.2 Table 2).
pub const UnknownAction = enum {
    /// Discard this chunk and every chunk after it in the packet.
    STOP,
    /// Discard the rest of the packet and answer with an Unrecognized Chunk Type error.
    STOP_AND_REPORT,
    /// Ignore this chunk and keep going.
    SKIP,
    /// Ignore this chunk, keep going, and answer with an Unrecognized Chunk Type error.
    SKIP_AND_REPORT,
};

/// One chunk, borrowed from the region it was read out of.
pub const Chunk = struct {
    kind: Type,
    flags: u8,
    /// Everything after the 4-byte header, padding excluded.
    value: []const u8,
    /// Where this chunk's header starts inside the region, for callers that need to re-frame it.
    offset: usize,
};

/// Size a chunk of `len` bytes occupies once padded to the next 4-byte boundary.
///
/// Param:
/// len - usize (chunk length as the length field states it, header included)
///
/// Return:
/// - usize
pub fn paddedLen(len: usize) usize {
    return std.mem.alignForward(usize, len, ALIGNMENT);
}

/// How many zero bytes follow a chunk of `len` bytes.
///
/// Param:
/// len - usize (chunk length as the length field states it, header included)
///
/// Return:
/// - usize, always 0 to 3
pub fn paddingLen(len: usize) usize {
    return paddedLen(len) - len;
}

/// The handling rule carried in the top two bits of the type number.
///
/// Note:
/// - Applies to types this build does not know. A known type is handled by its own code.
///
/// Param:
/// kind - Type
///
/// Return:
/// - UnknownAction
pub fn unknownAction(kind: Type) UnknownAction {
    return switch (@intFromEnum(kind) >> 6) {
        0 => .STOP,
        1 => .STOP_AND_REPORT,
        2 => .SKIP,
        else => .SKIP_AND_REPORT,
    };
}

/// Whether this build decodes the chunk type.
///
/// Param:
/// kind - Type
///
/// Return:
/// - bool
pub fn isKnown(kind: Type) bool {
    return switch (kind) {
        .DATA,
        .INIT,
        .INIT_ACK,
        .SACK,
        .HEARTBEAT,
        .HEARTBEAT_ACK,
        .ABORT,
        .SHUTDOWN,
        .SHUTDOWN_ACK,
        .ERROR,
        .COOKIE_ECHO,
        .COOKIE_ACK,
        .ECNE,
        .CWR,
        .SHUTDOWN_COMPLETE,
        .RE_CONFIG,
        .PAD,
        .FORWARD_TSN,
        => true,
        else => false,
    };
}

/// Check that every chunk in a region is framed correctly.
///
/// Note:
/// - Call this once before iterating. `Iterator` trusts the region afterwards.
/// - The last chunk may end without its padding, which is legal and common.
///
/// Param:
/// region - []const u8 (packet bytes after the common header)
///
/// Return:
/// - void
/// - error.ZixBadLength if a chunk claims a length below the header size
/// - error.ZixTruncated if a chunk runs past the end of the region
pub fn validate(region: []const u8) Error!void {
    var pos: usize = 0;

    while (pos < region.len) {
        if (region.len - pos < HEADER_LEN) return error.ZixTruncated;

        const len = std.mem.readInt(u16, region[pos + 2 ..][0..2], .big);

        if (len < HEADER_LEN) return error.ZixBadLength;
        if (region.len - pos < len) return error.ZixTruncated;

        const advance = paddedLen(len);

        // The final chunk is allowed to arrive without its padding, so a step that would run
        // past the end lands exactly on the end instead.
        pos += if (region.len - pos < advance) region.len - pos else advance;
    }
}

/// Walks the chunks of a validated region.
///
/// Note:
/// - Only construct this over a region `validate` has accepted. It reads lengths without
///   rechecking them.
///
/// Usage:
/// ```zig
/// try chunk.validate(region);
///
/// var iterator = chunk.Iterator{ .region = region };
/// while (iterator.next()) |item| {
///     if (item.kind == .DATA) handle(item.value);
/// }
/// ```
pub const Iterator = struct {
    region: []const u8,
    pos: usize = 0,

    /// The next chunk, or null at the end of the region.
    ///
    /// Return:
    /// - ?Chunk
    pub fn next(self: *Iterator) ?Chunk {
        if (self.region.len - self.pos < HEADER_LEN) return null;

        const start = self.pos;
        const kind: Type = @enumFromInt(self.region[start]);
        const flags = self.region[start + 1];
        const len = std.mem.readInt(u16, self.region[start + 2 ..][0..2], .big);
        const advance = paddedLen(len);

        self.pos += if (self.region.len - start < advance) self.region.len - start else advance;

        return .{
            .kind = kind,
            .flags = flags,
            .value = self.region[start + HEADER_LEN ..][0 .. len - HEADER_LEN],
            .offset = start,
        };
    }
};

/// Write one whole chunk, header then value then padding.
///
/// Note:
/// - The padding is written even on the last chunk of a packet. Sending it is always correct,
///   and only receiving without it has to be tolerated.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// kind - Type
/// flags - u8 (meaning depends on the type, 0 where the type defines none)
/// value - []const u8 (chunk body, padding excluded)
///
/// Return:
/// - []const u8 covering header, value, and padding
/// - error.ZixNoSpace if the buffer cannot hold the padded chunk
/// - error.ZixBadLength if the value is too long for the 16-bit length field
pub fn write(out: []u8, kind: Type, flags: u8, value: []const u8) Error![]const u8 {
    const len = HEADER_LEN + value.len;

    if (len > MAX_CHUNK_LEN) return error.ZixBadLength;

    const total = paddedLen(len);

    if (out.len < total) return error.ZixNoSpace;

    out[0] = @intFromEnum(kind);
    out[1] = flags;
    std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
    @memcpy(out[HEADER_LEN..][0..value.len], value);
    @memset(out[len..total], 0);

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: chunk padding, a length is rounded up to the next 4-byte boundary" {
    try std.testing.expectEqual(@as(usize, 4), paddedLen(4));
    try std.testing.expectEqual(@as(usize, 8), paddedLen(5));
    try std.testing.expectEqual(@as(usize, 8), paddedLen(7));
    try std.testing.expectEqual(@as(usize, 8), paddedLen(8));

    try std.testing.expectEqual(@as(usize, 0), paddingLen(8));
    try std.testing.expectEqual(@as(usize, 3), paddingLen(5));
}

test "zix sctp: chunk registry, the known types decode and an unassigned one does not" {
    try std.testing.expect(isKnown(.DATA));
    try std.testing.expect(isKnown(.INIT));
    try std.testing.expect(isKnown(.RE_CONFIG));
    try std.testing.expect(isKnown(.FORWARD_TSN));
    try std.testing.expect(!isKnown(@enumFromInt(99)));
    try std.testing.expect(!isKnown(@enumFromInt(64)));
}

test "zix sctp: chunk unknown action, the top two bits of the type decide it" {
    try std.testing.expectEqual(UnknownAction.STOP, unknownAction(@enumFromInt(0)));
    try std.testing.expectEqual(UnknownAction.STOP, unknownAction(@enumFromInt(63)));
    try std.testing.expectEqual(UnknownAction.STOP_AND_REPORT, unknownAction(@enumFromInt(64)));
    try std.testing.expectEqual(UnknownAction.STOP_AND_REPORT, unknownAction(@enumFromInt(127)));
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(@enumFromInt(128)));
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(@enumFromInt(191)));
    try std.testing.expectEqual(UnknownAction.SKIP_AND_REPORT, unknownAction(@enumFromInt(192)));
    try std.testing.expectEqual(UnknownAction.SKIP_AND_REPORT, unknownAction(@enumFromInt(255)));
}

test "zix sctp: chunk unknown action, the extensions carry the action their RFC expects" {
    // A peer without stream reset must ignore a RE-CONFIG rather than drop the packet holding it.
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(.RE_CONFIG));
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(.PAD));
    try std.testing.expectEqual(UnknownAction.SKIP_AND_REPORT, unknownAction(.FORWARD_TSN));
}

test "zix sctp: chunk write, a header and value round trip through the iterator" {
    var buf: [16]u8 = undefined;
    const written = try write(&buf, .COOKIE_ACK, 0, &.{});

    try std.testing.expectEqual(@as(usize, 4), written.len);
    try std.testing.expectEqualSlices(u8, &.{ 11, 0, 0, 4 }, written);

    try validate(written);

    var iterator = Iterator{ .region = written };
    const item = iterator.next().?;

    try std.testing.expectEqual(Type.COOKIE_ACK, item.kind);
    try std.testing.expectEqual(@as(usize, 0), item.value.len);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: chunk write, an unaligned value is zero padded and the length excludes it" {
    var buf: [16]u8 = undefined;
    const written = try write(&buf, .COOKIE_ECHO, 0, "abcde");

    try std.testing.expectEqual(@as(usize, 12), written.len);
    try std.testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, written[2..4], .big));
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, written[9..12]);

    var iterator = Iterator{ .region = written };
    const item = iterator.next().?;

    try std.testing.expectEqualStrings("abcde", item.value);
}

test "zix sctp: chunk write, a buffer too small for the padding errors" {
    var buf: [8]u8 = undefined;

    // The value needs 9 bytes and the padding takes it to 12, so 8 is short either way.
    try std.testing.expectError(error.ZixNoSpace, write(&buf, .COOKIE_ECHO, 0, "abcde"));
}

test "zix sctp: chunk iterator, three bundled chunks come out in order with their offsets" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .SACK, 0, &.{ 1, 2, 3, 4 })).len;
    pos += (try write(buf[pos..], .HEARTBEAT, 0, "ab")).len;
    pos += (try write(buf[pos..], .COOKIE_ACK, 0, &.{})).len;

    const region = buf[0..pos];
    try validate(region);

    var iterator = Iterator{ .region = region };
    const first = iterator.next().?;
    const second = iterator.next().?;
    const third = iterator.next().?;

    try std.testing.expectEqual(Type.SACK, first.kind);
    try std.testing.expectEqual(@as(usize, 0), first.offset);
    try std.testing.expectEqual(Type.HEARTBEAT, second.kind);
    try std.testing.expectEqual(@as(usize, 8), second.offset);
    try std.testing.expectEqualStrings("ab", second.value);
    try std.testing.expectEqual(Type.COOKIE_ACK, third.kind);
    try std.testing.expectEqual(@as(usize, 16), third.offset);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: chunk validate, a length below the header size errors" {
    const region: [4]u8 = .{ 0, 0, 0, 3 };

    try std.testing.expectError(error.ZixBadLength, validate(&region));
}

test "zix sctp: chunk validate, a chunk running past the region errors" {
    const region: [4]u8 = .{ 11, 0, 0, 8 };

    try std.testing.expectError(error.ZixTruncated, validate(&region));
}

test "zix sctp: chunk validate, a trailing stub too small for a header errors" {
    var buf: [8]u8 = undefined;
    _ = try write(&buf, .COOKIE_ACK, 0, &.{});
    buf[4] = 11;
    buf[5] = 0;

    try std.testing.expectError(error.ZixTruncated, validate(buf[0..6]));
}

test "zix sctp: chunk validate, the last chunk may arrive without its padding" {
    var buf: [16]u8 = undefined;
    const first = try write(&buf, .COOKIE_ACK, 0, &.{});
    _ = try write(buf[first.len..], .HEARTBEAT, 0, "ab");

    // 4 for the first chunk, then 6 of a 6-byte chunk whose 2 padding bytes were left off.
    const region = buf[0..10];
    try validate(region);

    var iterator = Iterator{ .region = region };
    _ = iterator.next().?;
    const second = iterator.next().?;

    try std.testing.expectEqualStrings("ab", second.value);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: chunk validate, an empty region is accepted" {
    // Whether a packet is allowed to carry no chunks is a packet rule, not a framing one.
    try validate(&.{});

    var iterator = Iterator{ .region = &.{} };
    try std.testing.expect(iterator.next() == null);
}
