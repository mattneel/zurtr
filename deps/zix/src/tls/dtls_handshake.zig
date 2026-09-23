//! DTLS 1.2 handshake message framing (RFC 6347 4.2.2 / 4.2.3).
//!
//! What:
//! - The 12-byte handshake header DTLS uses in place of the 4-byte TLS one, and the fragmenting
//!   and reassembly it exists to support. TLS gets ordering and completeness free from the
//!   stream underneath it, DTLS has to carry both itself.
//! - Three additions over TLS: message_seq orders messages across loss and reordering,
//!   fragment_offset and fragment_length let one handshake message span several datagrams.
//!
//! Note:
//! - Fragments may OVERLAP, and handling that is required, not optional (RFC 6347 4.2.3). A
//!   sender that lowers its fragment size after a PMTU change resends the same bytes cut
//!   differently, so a receiver counting bytes instead of tracking which ones arrived would
//!   declare a message complete while holes remain.
//! - `length` is the length of the WHOLE message in every fragment, never the fragment's own.
//!   The fragment's size is fragment_length. Reading the wrong one is the classic defect here.
//! - An unfragmented message is the degenerate case, fragment_offset 0 and fragment_length equal
//!   to length. Most messages are this.
//! - MessageType is defined here rather than shared with handshake.zig, because that file names
//!   what TLS 1.3 can send. DTLS 1.2 sends three messages 1.3 deleted (ServerKeyExchange,
//!   ServerHelloDone, ClientKeyExchange) plus one 1.3 never had (HelloVerifyRequest), and a 1.3
//!   handshake has to reject exactly those.

const std = @import("std");

/// Bytes before the fragment body: type 1, length 3, message_seq 2, fragment_offset 3,
/// fragment_length 3.
pub const HEADER_LEN: usize = 12;

/// Ceiling on any single handshake message, from the 24-bit length field.
pub const MAX_MESSAGE_LEN: usize = (1 << 24) - 1;

pub const Error = error{
    /// Fewer bytes than a header, or a fragment shorter than its own fragment_length.
    ZixTruncated,
    /// A fragment reaching past the end of its message, or a zero-length message claiming bytes.
    ZixBadFragment,
    /// A fragment whose message length disagrees with the fragments already accepted.
    ZixLengthMismatch,
    /// A fragment belonging to a different message than the one being reassembled.
    ZixSequenceMismatch,
    /// A message larger than the reassembler was built to hold.
    ZixMessageTooLarge,
};

/// Handshake message types DTLS 1.2 can carry (RFC 5246 7.4, plus RFC 6347 4.2.1).
pub const MessageType = enum(u8) {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    _,
};

/// One DTLS handshake message header (RFC 6347 4.2.2).
pub const Header = struct {
    msg_type: MessageType,
    /// Length of the whole message, the same in every fragment of it.
    length: u24,
    /// Message counter, shared by every fragment and reused on retransmission.
    message_seq: u16,
    /// Where this fragment starts inside the message.
    fragment_offset: u24,
    /// How many bytes of the message this fragment carries.
    fragment_length: u24,

    /// Whether this header carries the entire message rather than a piece of it.
    pub fn isWholeMessage(self: Header) bool {
        return self.fragment_offset == 0 and self.fragment_length == self.length;
    }
};

/// A header together with the fragment bytes it describes.
pub const Fragment = struct {
    header: Header,
    data: []const u8,
};

/// Read a handshake message header. Does not touch the body.
pub fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < HEADER_LEN) return error.ZixTruncated;

    return .{
        .msg_type = @enumFromInt(bytes[0]),
        .length = std.mem.readInt(u24, bytes[1..4], .big),
        .message_seq = std.mem.readInt(u16, bytes[4..6], .big),
        .fragment_offset = std.mem.readInt(u24, bytes[6..9], .big),
        .fragment_length = std.mem.readInt(u24, bytes[9..12], .big),
    };
}

/// Write a handshake message header into the first HEADER_LEN bytes of out.
pub fn writeHeader(out: []u8, header: Header) void {
    out[0] = @intFromEnum(header.msg_type);
    std.mem.writeInt(u24, out[1..4], header.length, .big);
    std.mem.writeInt(u16, out[4..6], header.message_seq, .big);
    std.mem.writeInt(u24, out[6..9], header.fragment_offset, .big);
    std.mem.writeInt(u24, out[9..12], header.fragment_length, .big);
}

/// Walks the handshake messages packed into one record body. Several may share a record as long
/// as they belong to the same flight (RFC 6347 4.2.3).
pub const FragmentIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *FragmentIterator) Error!?Fragment {
        if (self.pos == self.body.len) return null;

        const header = try parseHeader(self.body[self.pos..]);
        const data_start = self.pos + HEADER_LEN;

        if (data_start + header.fragment_length > self.body.len) return error.ZixTruncated;

        const fragment: Fragment = .{
            .header = header,
            .data = self.body[data_start..][0..header.fragment_length],
        };

        self.pos = data_start + header.fragment_length;

        return fragment;
    }
};

/// Cuts one handshake message into fragments that each fit a size limit (RFC 6347 4.2.3).
///
/// Note:
/// - The limit is on the fragment BODY, so a caller sizing against a PMTU subtracts its record
///   and header overhead before setting it.
/// - A message shorter than the limit comes out as one fragment covering all of it, which is the
///   ordinary case.
///
/// Usage:
/// ```zig
/// var fragmenter: Fragmenter = .{
///     .msg_type = .CERTIFICATE,
///     .message_seq = 2,
///     .body = certificate_bytes,
///     .max_fragment_len = 1000,
/// };
///
/// var buf: [1024]u8 = undefined;
/// while (fragmenter.next(&buf)) |piece| try sendRecord(piece);
/// ```
pub const Fragmenter = struct {
    msg_type: MessageType,
    message_seq: u16,
    body: []const u8,
    max_fragment_len: usize,
    pos: usize = 0,
    emitted: bool = false,

    /// Write the next fragment, header included, into out.
    ///
    /// Return:
    /// - []const u8 (the fragment, borrowing out)
    /// - null when the message is fully emitted, or out cannot hold a header and one byte
    pub fn next(self: *Fragmenter, out: []u8) ?[]const u8 {
        if (self.emitted and self.pos == self.body.len) return null;
        if (out.len <= HEADER_LEN) return null;
        if (self.max_fragment_len == 0) return null;

        const room = @min(out.len - HEADER_LEN, self.max_fragment_len);
        const take = @min(room, self.body.len - self.pos);

        writeHeader(out, .{
            .msg_type = self.msg_type,
            .length = @intCast(self.body.len),
            .message_seq = self.message_seq,
            .fragment_offset = @intCast(self.pos),
            .fragment_length = @intCast(take),
        });
        @memcpy(out[HEADER_LEN..][0..take], self.body[self.pos..][0..take]);

        self.pos += take;
        self.emitted = true;

        return out[0 .. HEADER_LEN + take];
    }
};

/// Buffers the fragments of one handshake message until every byte has arrived.
///
/// Note:
/// - Tracks which BYTES arrived, in a bitmap, rather than counting them. Overlapping fragments
///   are legal, so a byte counter would reach the message length with holes still in it and hand
///   the caller a half-filled message.
/// - Holds one message at a time. A caller driving a flight resets between messages, which is
///   also how it drops a message_seq it has already processed.
///
/// Param:
/// max_message_len - usize (largest message this reassembler can hold, sized by the caller for
///                   the biggest flight it expects, usually the certificate)
pub fn Reassembler(comptime max_message_len: usize) type {
    return struct {
        const Self = @This();

        /// Largest message this reassembler accepts.
        pub const CAPACITY: usize = max_message_len;

        msg_type: MessageType = .HELLO_REQUEST,
        message_seq: u16 = 0,
        length: usize = 0,
        started: bool = false,
        have: usize = 0,
        buf: [max_message_len]u8 = undefined,
        received: [(max_message_len + 7) / 8]u8 = @splat(0),

        /// Take one fragment.
        ///
        /// Note:
        /// - The first fragment fixes the message this reassembler is collecting. Every later
        ///   one must agree on type, sequence, and length.
        ///
        /// Return:
        /// - void
        /// - error.ZixTruncated when the data is shorter than fragment_length says
        /// - error.ZixBadFragment when the fragment reaches past the end of the message
        /// - error.ZixMessageTooLarge when the message does not fit CAPACITY
        /// - error.ZixSequenceMismatch, error.ZixLengthMismatch against the message in progress
        pub fn accept(self: *Self, fragment: Fragment) Error!void {
            const header = fragment.header;

            if (fragment.data.len != header.fragment_length) return error.ZixTruncated;
            if (@as(usize, header.fragment_offset) + header.fragment_length > header.length) return error.ZixBadFragment;

            if (!self.started) {
                if (header.length > CAPACITY) return error.ZixMessageTooLarge;

                self.msg_type = header.msg_type;
                self.message_seq = header.message_seq;
                self.length = header.length;
                self.started = true;
            } else {
                if (header.message_seq != self.message_seq) return error.ZixSequenceMismatch;
                if (header.length != self.length) return error.ZixLengthMismatch;
            }

            @memcpy(self.buf[header.fragment_offset..][0..header.fragment_length], fragment.data);
            self.markReceived(header.fragment_offset, header.fragment_length);
        }

        /// Whether every byte of the message has arrived.
        pub fn isComplete(self: *const Self) bool {
            return self.started and self.have == self.length;
        }

        /// The reassembled message, or null while bytes are still missing.
        pub fn message(self: *const Self) ?[]const u8 {
            if (!self.isComplete()) return null;

            return self.buf[0..self.length];
        }

        /// Drop everything and wait for a new message.
        pub fn reset(self: *Self) void {
            self.started = false;
            self.length = 0;
            self.have = 0;
            self.received = @splat(0);
        }

        /// Mark a byte range as arrived, counting only bytes not already held.
        fn markReceived(self: *Self, offset: u24, len: u24) void {
            for (offset..@as(usize, offset) + len) |index| {
                const mask: u8 = @as(u8, 1) << @intCast(index % 8);

                if (self.received[index / 8] & mask != 0) continue;

                self.received[index / 8] |= mask;
                self.have += 1;
            }
        }
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Wrap a body as a single unfragmented message, the shape most tests start from.
fn wholeMessage(msg_type: MessageType, message_seq: u16, body: []const u8) Fragment {
    return .{
        .header = .{
            .msg_type = msg_type,
            .length = @intCast(body.len),
            .message_seq = message_seq,
            .fragment_offset = 0,
            .fragment_length = @intCast(body.len),
        },
        .data = body,
    };
}

fn fragmentOf(body: []const u8, message_seq: u16, offset: u24, len: u24) Fragment {
    return .{
        .header = .{
            .msg_type = .CERTIFICATE,
            .length = @intCast(body.len),
            .message_seq = message_seq,
            .fragment_offset = offset,
            .fragment_length = len,
        },
        .data = body[offset..][0..len],
    };
}

test "zix dtls: handshake header, 12 bytes in wire order" {
    var buf: [HEADER_LEN]u8 = undefined;
    writeHeader(&buf, .{
        .msg_type = .CLIENT_HELLO,
        .length = 0x0000C8,
        .message_seq = 1,
        .fragment_offset = 0x000064,
        .fragment_length = 0x000032,
    });

    try std.testing.expectEqualSlices(u8, &[_]u8{
        1, // client_hello
        0x00, 0x00, 0xC8, // length 200
        0x00, 0x01, // message_seq
        0x00, 0x00, 0x64, // fragment_offset 100
        0x00, 0x00, 0x32, // fragment_length 50
    }, &buf);

    const header = try parseHeader(&buf);
    try std.testing.expectEqual(MessageType.CLIENT_HELLO, header.msg_type);
    try std.testing.expectEqual(@as(u24, 200), header.length);
    try std.testing.expectEqual(@as(u16, 1), header.message_seq);
    try std.testing.expectEqual(@as(u24, 100), header.fragment_offset);
    try std.testing.expectEqual(@as(u24, 50), header.fragment_length);
    try std.testing.expect(!header.isWholeMessage());

    try std.testing.expectError(error.ZixTruncated, parseHeader(&[_]u8{ 1, 0, 0 }));
}

test "zix dtls: handshake header, an unfragmented message is the degenerate case" {
    var buf: [HEADER_LEN]u8 = undefined;
    writeHeader(&buf, .{
        .msg_type = .SERVER_HELLO_DONE,
        .length = 0,
        .message_seq = 3,
        .fragment_offset = 0,
        .fragment_length = 0,
    });

    const header = try parseHeader(&buf);
    try std.testing.expect(header.isWholeMessage());
    try std.testing.expectEqual(MessageType.SERVER_HELLO_DONE, header.msg_type);

    // hello_verify_request is a DTLS-only type, and it must survive the round trip by name.
    writeHeader(&buf, .{
        .msg_type = .HELLO_VERIFY_REQUEST,
        .length = 35,
        .message_seq = 0,
        .fragment_offset = 0,
        .fragment_length = 35,
    });
    try std.testing.expectEqual(MessageType.HELLO_VERIFY_REQUEST, (try parseHeader(&buf)).msg_type);
    try std.testing.expect((try parseHeader(&buf)).isWholeMessage());
}

test "zix dtls: handshake iterator, several messages share one record" {
    var body: [128]u8 = undefined;
    var used: usize = 0;

    const parts = [_]struct { msg_type: MessageType, payload: []const u8 }{
        .{ .msg_type = .SERVER_HELLO, .payload = "server hello" },
        .{ .msg_type = .CERTIFICATE, .payload = "cert" },
        .{ .msg_type = .SERVER_HELLO_DONE, .payload = "" },
    };

    for (parts, 0..) |part, i| {
        var fragmenter: Fragmenter = .{
            .msg_type = part.msg_type,
            .message_seq = @intCast(i),
            .body = part.payload,
            .max_fragment_len = 64,
        };
        const piece = fragmenter.next(body[used..]).?;
        used += piece.len;
    }

    var iterator: FragmentIterator = .{ .body = body[0..used] };
    var seen: usize = 0;

    while (try iterator.next()) |fragment| {
        try std.testing.expectEqual(parts[seen].msg_type, fragment.header.msg_type);
        try std.testing.expectEqualStrings(parts[seen].payload, fragment.data);
        try std.testing.expectEqual(@as(u16, @intCast(seen)), fragment.header.message_seq);

        seen += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), seen);
}

test "zix dtls: handshake iterator, a fragment past the end of the record is rejected" {
    var body: [HEADER_LEN + 4]u8 = undefined;
    writeHeader(&body, .{
        .msg_type = .CERTIFICATE,
        .length = 100,
        .message_seq = 0,
        .fragment_offset = 0,
        .fragment_length = 100,
    });

    var iterator: FragmentIterator = .{ .body = &body };
    try std.testing.expectError(error.ZixTruncated, iterator.next());

    var empty: FragmentIterator = .{ .body = body[0..0] };
    try std.testing.expectEqual(@as(?Fragment, null), try empty.next());
}

test "zix dtls: handshake fragmenter, a short message comes out whole" {
    var out: [128]u8 = undefined;
    var fragmenter: Fragmenter = .{
        .msg_type = .FINISHED,
        .message_seq = 5,
        .body = "verify_data",
        .max_fragment_len = 1000,
    };

    const piece = fragmenter.next(&out).?;
    const header = try parseHeader(piece);

    try std.testing.expect(header.isWholeMessage());
    try std.testing.expectEqual(@as(u24, 11), header.length);
    try std.testing.expectEqualStrings("verify_data", piece[HEADER_LEN..]);
    try std.testing.expectEqual(@as(?[]const u8, null), fragmenter.next(&out));
}

test "zix dtls: handshake fragmenter, an empty message still emits one fragment" {
    var out: [64]u8 = undefined;
    var fragmenter: Fragmenter = .{
        .msg_type = .SERVER_HELLO_DONE,
        .message_seq = 3,
        .body = "",
        .max_fragment_len = 100,
    };

    const piece = fragmenter.next(&out).?;
    try std.testing.expectEqual(HEADER_LEN, piece.len);
    try std.testing.expectEqual(@as(?[]const u8, null), fragmenter.next(&out));
}

test "zix dtls: handshake reassembly, in-order fragments rebuild the message" {
    var body: [300]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var reassembler: Reassembler(1024) = .{};
    try std.testing.expect(!reassembler.isComplete());

    try reassembler.accept(fragmentOf(&body, 7, 0, 100));
    try std.testing.expect(!reassembler.isComplete());
    try std.testing.expectEqual(@as(?[]const u8, null), reassembler.message());

    try reassembler.accept(fragmentOf(&body, 7, 100, 100));
    try reassembler.accept(fragmentOf(&body, 7, 200, 100));

    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualSlices(u8, &body, reassembler.message().?);
    try std.testing.expectEqual(MessageType.CERTIFICATE, reassembler.msg_type);
    try std.testing.expectEqual(@as(u16, 7), reassembler.message_seq);
}

test "zix dtls: handshake reassembly, out-of-order fragments rebuild the message" {
    var body: [300]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var reassembler: Reassembler(1024) = .{};
    try reassembler.accept(fragmentOf(&body, 1, 200, 100));
    try reassembler.accept(fragmentOf(&body, 1, 0, 100));
    try std.testing.expect(!reassembler.isComplete());

    try reassembler.accept(fragmentOf(&body, 1, 100, 100));

    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualSlices(u8, &body, reassembler.message().?);
}

test "zix dtls: handshake reassembly, overlapping fragments do not fake completeness" {
    var body: [300]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var reassembler: Reassembler(1024) = .{};

    // A sender that shrinks its fragment size resends bytes already delivered. Counting bytes
    // instead of tracking them would call this complete with 100 bytes still missing.
    try reassembler.accept(fragmentOf(&body, 2, 0, 150));
    try reassembler.accept(fragmentOf(&body, 2, 100, 100));
    try std.testing.expect(!reassembler.isComplete());
    try std.testing.expectEqual(@as(usize, 200), reassembler.have);

    try reassembler.accept(fragmentOf(&body, 2, 150, 150));
    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualSlices(u8, &body, reassembler.message().?);
}

test "zix dtls: handshake reassembly, a duplicate fragment is counted once" {
    var body: [100]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast(i);

    var reassembler: Reassembler(256) = .{};
    try reassembler.accept(fragmentOf(&body, 0, 0, 50));
    try reassembler.accept(fragmentOf(&body, 0, 0, 50));
    try reassembler.accept(fragmentOf(&body, 0, 0, 50));

    try std.testing.expectEqual(@as(usize, 50), reassembler.have);
    try std.testing.expect(!reassembler.isComplete());

    try reassembler.accept(fragmentOf(&body, 0, 50, 50));
    try std.testing.expect(reassembler.isComplete());
}

test "zix dtls: handshake reassembly, a malformed or foreign fragment is refused" {
    var body: [100]u8 = undefined;
    var reassembler: Reassembler(256) = .{};

    // fragment_length longer than the data actually handed over.
    var lying = fragmentOf(&body, 0, 0, 50);
    lying.data = body[0..10];
    try std.testing.expectError(error.ZixTruncated, reassembler.accept(lying));

    // A fragment reaching past the end of its own message.
    var overrun = fragmentOf(&body, 0, 60, 40);
    overrun.header.length = 80;
    try std.testing.expectError(error.ZixBadFragment, reassembler.accept(overrun));

    // A message too large for this reassembler.
    var oversized = fragmentOf(&body, 0, 0, 100);
    oversized.header.length = 1000;
    try std.testing.expectError(error.ZixMessageTooLarge, reassembler.accept(oversized));

    // Once a message is in progress, fragments of another one do not belong to it.
    try reassembler.accept(fragmentOf(&body, 4, 0, 50));
    try std.testing.expectError(error.ZixSequenceMismatch, reassembler.accept(fragmentOf(&body, 5, 50, 50)));

    // Internally consistent (50 + 40 fits 90) but disagreeing with the message in progress,
    // which is what separates LengthMismatch from BadFragment.
    var wrong_length = fragmentOf(&body, 4, 50, 40);
    wrong_length.header.length = 90;
    try std.testing.expectError(error.ZixLengthMismatch, reassembler.accept(wrong_length));
}

test "zix dtls: handshake reassembly, reset takes the next message" {
    var body: [100]u8 = undefined;
    var reassembler: Reassembler(256) = .{};

    try reassembler.accept(fragmentOf(&body, 1, 0, 50));
    reassembler.reset();

    try std.testing.expect(!reassembler.isComplete());
    try std.testing.expectEqual(@as(usize, 0), reassembler.have);

    // A different message is accepted cleanly after the reset.
    try reassembler.accept(fragmentOf(&body, 2, 0, 100));
    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqual(@as(u16, 2), reassembler.message_seq);
}

test "zix dtls: handshake round trip, fragmenter output feeds the reassembler" {
    var body: [2000]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast((i * 7) % 251);

    var fragmenter: Fragmenter = .{
        .msg_type = .CERTIFICATE,
        .message_seq = 2,
        .body = &body,
        .max_fragment_len = 300,
    };

    var reassembler: Reassembler(4096) = .{};
    var out: [512]u8 = undefined;
    var pieces: usize = 0;

    while (fragmenter.next(&out)) |piece| {
        var iterator: FragmentIterator = .{ .body = piece };
        const fragment = (try iterator.next()).?;

        try std.testing.expect(fragment.header.fragment_length <= 300);
        try std.testing.expectEqual(@as(u24, 2000), fragment.header.length);

        try reassembler.accept(fragment);
        pieces += 1;
    }

    try std.testing.expectEqual(@as(usize, 7), pieces);
    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualSlices(u8, &body, reassembler.message().?);
}

test "zix dtls: handshake round trip, a retransmit with smaller fragments still completes" {
    var body: [1000]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var reassembler: Reassembler(2048) = .{};
    var out: [512]u8 = undefined;

    // First attempt, large fragments, only the first one arrives.
    var first_try: Fragmenter = .{
        .msg_type = .CERTIFICATE,
        .message_seq = 2,
        .body = &body,
        .max_fragment_len = 400,
    };
    const arrived = first_try.next(&out).?;
    var iterator: FragmentIterator = .{ .body = arrived };
    try reassembler.accept((try iterator.next()).?);

    // The peer times out and resends the whole message cut smaller, so every fragment overlaps
    // what already arrived.
    var retry: Fragmenter = .{
        .msg_type = .CERTIFICATE,
        .message_seq = 2,
        .body = &body,
        .max_fragment_len = 150,
    };

    while (retry.next(&out)) |piece| {
        var walk: FragmentIterator = .{ .body = piece };
        try reassembler.accept((try walk.next()).?);
    }

    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualSlices(u8, &body, reassembler.message().?);
}

test "zix dtls: handshake reassembly, a whole message in one fragment completes at once" {
    const body = "server hello done";

    var reassembler: Reassembler(256) = .{};
    try reassembler.accept(wholeMessage(.SERVER_HELLO, 0, body));

    try std.testing.expect(reassembler.isComplete());
    try std.testing.expectEqualStrings(body, reassembler.message().?);

    // A zero-length message is complete the moment it arrives.
    var empty: Reassembler(64) = .{};
    try empty.accept(wholeMessage(.SERVER_HELLO_DONE, 3, ""));
    try std.testing.expect(empty.isComplete());
    try std.testing.expectEqual(@as(usize, 0), empty.message().?.len);
}
