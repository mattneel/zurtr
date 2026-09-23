//! zix SCTP packet: common header plus bundled chunks (RFC 9260 3, 3.1).
//!
//! What:
//! - Reading a packet out of a DTLS record: check the length, check the CRC32c, check that every
//!   chunk is framed, then hand back the header fields and a chunk walker.
//! - Writing one: stamp the header, append chunks until the buffer is full, and stamp the
//!   checksum last.
//!
//! Note:
//! - Under DTLS the packet is the whole payload of one record (RFC 8261 3), so there is no
//!   framing question here. One record in, one packet out.
//! - Parsing checks the checksum. RFC 9260 6.8 says a packet that fails is discarded silently,
//!   and doing it inside `parse` means no caller can forget. DTLS has already authenticated the
//!   bytes by this point, so a mismatch means a broken sender rather than an attacker.
//! - The verification tag is not checked here. Which tag is correct depends on the chunks the
//!   packet carries (an INIT carries zero, an ABORT may reflect the peer's), so that rule lives
//!   with the association.
//! - Bundling is the sender's choice, with one restriction: INIT, INIT ACK, and SHUTDOWN
//!   COMPLETE travel alone. `mustTravelAlone` states it, and the association enforces it.

const std = @import("std");

const checksum = @import("checksum.zig");
const chunk = @import("chunk.zig");

/// Source port, destination port, verification tag, checksum.
pub const COMMON_HEADER_LEN: usize = 12;

/// Offset of the verification tag inside the common header.
pub const VERIFICATION_TAG_OFFSET: usize = 4;

/// Everything that stops a packet from being read or built.
pub const Error = error{
    /// Fewer bytes than the common header needs.
    ZixShortHeader,
    /// A chunk runs past the end of the packet.
    ZixTruncated,
    /// A chunk claims a length below the chunk header size.
    ZixBadLength,
    /// The CRC32c in the header does not match the bytes.
    ZixBadChecksum,
    /// A common header with no chunks after it, which RFC 9260 3 does not allow.
    ZixEmpty,
    /// The output buffer cannot hold what was asked for.
    ZixNoSpace,
};

/// A parsed packet, borrowing the bytes it was read from.
pub const Packet = struct {
    source_port: u16,
    destination_port: u16,
    verification_tag: u32,
    /// The whole packet, common header included.
    bytes: []const u8,

    /// The chunk region, everything after the common header.
    ///
    /// Return:
    /// - []const u8
    pub fn region(self: Packet) []const u8 {
        return self.bytes[COMMON_HEADER_LEN..];
    }

    /// Walk the chunks in order.
    ///
    /// Note:
    /// - Infallible, because `parse` already validated the framing.
    ///
    /// Return:
    /// - chunk.Iterator
    pub fn chunks(self: Packet) chunk.Iterator {
        return .{ .region = self.region() };
    }

    /// First chunk of a given type.
    ///
    /// Param:
    /// kind - chunk.Type
    ///
    /// Return:
    /// - ?chunk.Chunk
    pub fn find(self: Packet, kind: chunk.Type) ?chunk.Chunk {
        var iterator = self.chunks();

        while (iterator.next()) |item| {
            if (item.kind == kind) return item;
        }

        return null;
    }

    /// The type of the first chunk, which decides how the packet is handled.
    ///
    /// Note:
    /// - Never null. `parse` rejects a packet with no chunks.
    ///
    /// Return:
    /// - chunk.Type
    pub fn firstChunkType(self: Packet) chunk.Type {
        var iterator = self.chunks();

        return iterator.next().?.kind;
    }
};

/// Whether a chunk type has to be the only chunk in its packet (RFC 9260 3).
///
/// Param:
/// kind - chunk.Type
///
/// Return:
/// - bool
pub fn mustTravelAlone(kind: chunk.Type) bool {
    return switch (kind) {
        .INIT, .INIT_ACK, .SHUTDOWN_COMPLETE => true,
        else => false,
    };
}

/// Read a packet.
///
/// Note:
/// - Checks the length, the checksum, and the framing of every chunk, in that order. Once this
///   returns, walking the chunks cannot fail.
///
/// Param:
/// datagram - []const u8 (payload of one DTLS record)
///
/// Return:
/// - Packet borrowing `datagram`
/// - error.ZixShortHeader, error.ZixBadChecksum, error.ZixEmpty, error.ZixTruncated, error.ZixBadLength
pub fn parse(datagram: []const u8) Error!Packet {
    if (datagram.len < COMMON_HEADER_LEN) return error.ZixShortHeader;
    if (datagram.len == COMMON_HEADER_LEN) return error.ZixEmpty;
    if (!checksum.verify(datagram)) return error.ZixBadChecksum;

    try chunk.validate(datagram[COMMON_HEADER_LEN..]);

    return .{
        .source_port = std.mem.readInt(u16, datagram[0..2], .big),
        .destination_port = std.mem.readInt(u16, datagram[2..4], .big),
        .verification_tag = std.mem.readInt(u32, datagram[4..8], .big),
        .bytes = datagram,
    };
}

/// Builds a packet into a caller buffer.
///
/// Note:
/// - The checksum is written by `finish`, so nothing may be edited after it.
/// - The buffer is the path MTU budget. `remaining` says how much room is left, which is what a
///   sender bundling DATA chunks needs to know.
///
/// Usage:
/// ```zig
/// var buf: [1200]u8 = undefined;
/// var writer = try packet.Writer.init(&buf, 5000, 5000, peer_tag);
/// try writer.addChunk(.COOKIE_ACK, 0, &.{});
///
/// const bytes = writer.finish();
/// ```
pub const Writer = struct {
    buf: []u8,
    len: usize,

    /// Stamp the common header and start an empty packet.
    ///
    /// Param:
    /// buf - []u8 (output buffer, sized to the path MTU)
    /// source_port - u16
    /// destination_port - u16
    /// verification_tag - u32 (the peer's initiate tag, or 0 in a packet carrying an INIT)
    ///
    /// Return:
    /// - Writer
    /// - error.ZixNoSpace if the buffer cannot hold a common header
    pub fn init(buf: []u8, source_port: u16, destination_port: u16, verification_tag: u32) Error!Writer {
        if (buf.len < COMMON_HEADER_LEN) return error.ZixNoSpace;

        std.mem.writeInt(u16, buf[0..2], source_port, .big);
        std.mem.writeInt(u16, buf[2..4], destination_port, .big);
        std.mem.writeInt(u32, buf[4..8], verification_tag, .big);
        @memset(buf[8..COMMON_HEADER_LEN], 0);

        return .{ .buf = buf, .len = COMMON_HEADER_LEN };
    }

    /// Bytes still available for another chunk, padding included.
    ///
    /// Return:
    /// - usize
    pub fn remaining(self: Writer) usize {
        return self.buf.len - self.len;
    }

    /// Whether the packet has no chunks yet.
    ///
    /// Return:
    /// - bool
    pub fn isEmpty(self: Writer) bool {
        return self.len == COMMON_HEADER_LEN;
    }

    /// Append a chunk header and leave its value to the caller.
    ///
    /// Note:
    /// - The returned slice is exactly `value_len` bytes and is not zeroed. The padding after it
    ///   is, so the caller only has to fill what it asked for.
    ///
    /// Param:
    /// kind - chunk.Type
    /// flags - u8
    /// value_len - usize (body size, padding excluded)
    ///
    /// Return:
    /// - []u8 to write the body into
    /// - error.ZixNoSpace if the padded chunk does not fit
    /// - error.ZixBadLength if the body is too long for the 16-bit length field
    pub fn reserveChunk(self: *Writer, kind: chunk.Type, flags: u8, value_len: usize) Error![]u8 {
        const len = chunk.HEADER_LEN + value_len;

        if (len > chunk.MAX_CHUNK_LEN) return error.ZixBadLength;

        const total = chunk.paddedLen(len);

        if (self.remaining() < total) return error.ZixNoSpace;

        const start = self.len;
        self.buf[start] = @intFromEnum(kind);
        self.buf[start + 1] = flags;
        std.mem.writeInt(u16, self.buf[start + 2 ..][0..2], @intCast(len), .big);
        @memset(self.buf[start + len ..][0 .. total - len], 0);

        self.len += total;

        return self.buf[start + chunk.HEADER_LEN ..][0..value_len];
    }

    /// Append a whole chunk.
    ///
    /// Param:
    /// kind - chunk.Type
    /// flags - u8
    /// value - []const u8 (body, padding excluded)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace, error.ZixBadLength
    pub fn addChunk(self: *Writer, kind: chunk.Type, flags: u8, value: []const u8) Error!void {
        const body = try self.reserveChunk(kind, flags, value.len);

        @memcpy(body, value);
    }

    /// Stamp the checksum and hand back the finished packet.
    ///
    /// Note:
    /// - Do not write to the buffer after this. Any change invalidates the checksum.
    ///
    /// Return:
    /// - []const u8, the whole packet
    /// - error.ZixEmpty if no chunk was ever added
    pub fn finish(self: *Writer) Error![]const u8 {
        if (self.isEmpty()) return error.ZixEmpty;

        checksum.insert(self.buf[0..self.len]) catch return error.ZixNoSpace;

        return self.buf[0..self.len];
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: packet writer, a header and one chunk round trip through parse" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5001, 0xDEADBEEF);
    try writer.addChunk(.COOKIE_ACK, 0, &.{});

    const bytes = try writer.finish();
    const parsed = try parse(bytes);

    try std.testing.expectEqual(@as(u16, 5000), parsed.source_port);
    try std.testing.expectEqual(@as(u16, 5001), parsed.destination_port);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.verification_tag);
    try std.testing.expectEqual(chunk.Type.COOKIE_ACK, parsed.firstChunkType());
}

test "zix sctp: packet writer, bundled chunks come back in the order they went in" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);
    try writer.addChunk(.SACK, 0, &.{ 0, 0, 0, 7 });
    try writer.addChunk(.HEARTBEAT_ACK, 0, "hb");

    const parsed = try parse(try writer.finish());

    var iterator = parsed.chunks();
    try std.testing.expectEqual(chunk.Type.SACK, iterator.next().?.kind);
    try std.testing.expectEqualStrings("hb", iterator.next().?.value);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: packet writer, reserveChunk hands back a writable body" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);

    const body = try writer.reserveChunk(.HEARTBEAT, 0, 5);
    @memcpy(body, "hello");

    const parsed = try parse(try writer.finish());

    try std.testing.expectEqualStrings("hello", parsed.find(.HEARTBEAT).?.value);
}

test "zix sctp: packet writer, the padding after a reserved body is zeroed" {
    var buf: [64]u8 = undefined;
    @memset(&buf, 0xFF);

    var writer = try Writer.init(&buf, 5000, 5000, 1);
    const body = try writer.reserveChunk(.HEARTBEAT, 0, 5);
    @memcpy(body, "hello");

    const bytes = try writer.finish();

    // 12 header, 4 chunk header, 5 body, then 3 bytes the caller never touched.
    try std.testing.expectEqual(@as(usize, 24), bytes.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, bytes[21..24]);
}

test "zix sctp: packet writer, remaining tracks the padded cost of each chunk" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);

    try std.testing.expectEqual(@as(usize, 52), writer.remaining());
    try std.testing.expect(writer.isEmpty());

    try writer.addChunk(.HEARTBEAT, 0, "x");

    // 4 header plus 1 byte padded to 8, not 5.
    try std.testing.expectEqual(@as(usize, 44), writer.remaining());
    try std.testing.expect(!writer.isEmpty());
}

test "zix sctp: packet writer, a chunk that does not fit errors and leaves the packet usable" {
    var buf: [24]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);
    try writer.addChunk(.COOKIE_ACK, 0, &.{});

    try std.testing.expectError(error.ZixNoSpace, writer.addChunk(.HEARTBEAT, 0, "0123456789"));

    // The failed append wrote nothing, so what was already there still ships.
    const parsed = try parse(try writer.finish());
    try std.testing.expectEqual(chunk.Type.COOKIE_ACK, parsed.firstChunkType());
}

test "zix sctp: packet writer, a buffer smaller than the common header errors" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, Writer.init(&buf, 5000, 5000, 1));
}

test "zix sctp: packet writer, finishing with no chunks errors" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);

    try std.testing.expectError(error.ZixEmpty, writer.finish());
}

test "zix sctp: packet parse, a flipped byte fails the checksum" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);
    try writer.addChunk(.HEARTBEAT, 0, "abcd");

    const bytes = try writer.finish();

    // 12 common header, 4 chunk header, 4 body, so the last payload byte is index 19.
    buf[19] ^= 0x01;

    try std.testing.expectError(error.ZixBadChecksum, parse(bytes));
}

test "zix sctp: packet parse, a common header with no chunks errors" {
    var buf: [COMMON_HEADER_LEN]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);
    _ = &writer;

    try checksum.insert(&buf);

    try std.testing.expectError(error.ZixEmpty, parse(&buf));
}

test "zix sctp: packet parse, fewer bytes than the common header errors" {
    const short: [11]u8 = @splat(0);

    try std.testing.expectError(error.ZixShortHeader, parse(&short));
}

test "zix sctp: packet parse, a broken chunk length errors after the checksum passes" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 1);
    try writer.addChunk(.HEARTBEAT, 0, "abcd");

    // Claim a longer chunk than the packet holds, then restamp so the CRC still matches.
    std.mem.writeInt(u16, buf[14..16], 40, .big);
    const bytes = buf[0..writer.len];
    try checksum.insert(bytes);

    try std.testing.expectError(error.ZixTruncated, parse(bytes));
}

test "zix sctp: packet bundling, only the three solitary chunk types report it" {
    try std.testing.expect(mustTravelAlone(.INIT));
    try std.testing.expect(mustTravelAlone(.INIT_ACK));
    try std.testing.expect(mustTravelAlone(.SHUTDOWN_COMPLETE));
    try std.testing.expect(!mustTravelAlone(.DATA));
    try std.testing.expect(!mustTravelAlone(.COOKIE_ECHO));
    try std.testing.expect(!mustTravelAlone(.ABORT));
}

test "zix sctp: packet parse, an INIT packet carries a zero verification tag" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, 5000, 5000, 0);
    try writer.addChunk(.INIT, 0, &.{ 0x12, 0x34, 0x56, 0x78 });

    const parsed = try parse(try writer.finish());

    try std.testing.expectEqual(@as(u32, 0), parsed.verification_tag);
    try std.testing.expect(mustTravelAlone(parsed.firstChunkType()));
}
