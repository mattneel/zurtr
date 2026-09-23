//! zix WebTransport capsule protocol (RFC 9297 3, draft-ietf-webtrans-http3-16 5.6 / 6).
//!
//! What:
//! - The capsule framing a WebTransport CONNECT stream carries after its response: a type, a length,
//!   and a value, all variable-length integers (RFC 9297 3.2).
//! - A streaming reader: capsules arrive inside HTTP/3 DATA frames, so one capsule can straddle
//!   datagrams and several can share one. The reader keeps the partial capsule, hands complete ones to
//!   a visitor, and skips capsules it does not know without ever buffering their length (a peer is free
//!   to declare a length this endpoint will never hold).
//! - The encoders and decoders for the capsules this binding defines: WT_CLOSE_SESSION, WT_DRAIN_SESSION,
//!   and the draft-16 flow control capsules WT_MAX_STREAMS, WT_STREAMS_BLOCKED, WT_MAX_DATA, and
//!   WT_DATA_BLOCKED.
//! - Pure buffer arithmetic, no io, no allocation. Proven against the RFC layout and crafted byte
//!   streams in the tests below.

const std = @import("std");

const varint = @import("../varint.zig");
const wt = @import("draft.zig");

/// A capsule as it sits on the wire: a type and its value, the value borrowed from the buffer given to
/// `parse` or from the reader's own accumulation buffer.
pub const Capsule = struct {
    type: u64,
    value: []const u8,
};

/// Parsing a single capsule out of a buffer.
pub const ParseError = error{
    /// The buffer ended inside the capsule, so more bytes are needed to finish it.
    ZixTruncated,
};

/// One capsule out of `buf`, and how many bytes of `buf` it took.
pub const Parsed = struct {
    capsule: Capsule,
    consumed: usize,
};

/// Parse one capsule at the start of `buf` (RFC 9297 3.2).
///
/// Param:
/// buf - []const u8 (the capsule stream, starting at a capsule boundary)
///
/// Return:
/// - Parsed (the capsule and the bytes it consumed)
/// - error.ZixTruncated when `buf` ends inside this capsule, the caller keeps the bytes and retries
///   once more arrive
pub fn parse(buf: []const u8) ParseError!Parsed {
    const type_vi = varint.read(buf) catch return error.ZixTruncated;
    const length_vi = varint.read(buf[type_vi.len..]) catch return error.ZixTruncated;

    const header = type_vi.len + length_vi.len;
    const value_len: usize = std.math.cast(usize, length_vi.value) orelse return error.ZixTruncated;
    if (value_len > buf.len - header) return error.ZixTruncated;

    return .{
        .capsule = .{ .type = type_vi.value, .value = buf[header..][0..value_len] },
        .consumed = header + value_len,
    };
}

/// Write one capsule (RFC 9297 3.2) into `out`. Returns the byte count, or null when it does not fit.
pub fn write(out: []u8, capsule_type: u64, value: []const u8) ?usize {
    const needed = varint.encodedLen(capsule_type) + varint.encodedLen(value.len) + value.len;
    if (needed > out.len) return null;

    var pos: usize = 0;
    pos += varint.write(out[pos..], capsule_type);
    pos += varint.write(out[pos..], value.len);
    @memcpy(out[pos..][0..value.len], value);
    pos += value.len;

    return pos;
}

// --------------------------------------------------------------- //
// WT_CLOSE_SESSION (6)
// --------------------------------------------------------------- //

/// A decoded WT_CLOSE_SESSION capsule (6): the application error code and the application message.
pub const CloseSession = struct {
    /// The application's 32-bit error code. Zero with an empty message is a clean close.
    code: u32,
    /// The UTF-8 application message, empty when the peer sent none.
    message: []const u8,
};

/// The errors WT_CLOSE_SESSION validation raises.
pub const CloseSessionError = error{
    /// The value is shorter than the 4-byte application error code.
    ZixTruncated,
    /// The message is longer than the 1024-byte limit, or is not valid UTF-8: the stream is reset with
    /// H3_MESSAGE_ERROR (6).
    ZixMessageError,
};

/// Decode the value of a WT_CLOSE_SESSION capsule (6). The message must be valid UTF-8 of at most 1024
/// bytes; a receiver that reads otherwise resets the stream with H3_MESSAGE_ERROR.
pub fn parseCloseSession(value: []const u8) CloseSessionError!CloseSession {
    if (value.len < 4) return error.ZixTruncated;

    const message = value[4..];
    if (message.len > wt.max_close_message) return error.ZixMessageError;
    if (!std.unicode.utf8ValidateSlice(message)) return error.ZixMessageError;

    return .{
        .code = std.mem.readInt(u32, value[0..4], .big),
        .message = message,
    };
}

/// Encode a WT_CLOSE_SESSION capsule (6): the application error code, then the message, truncated on a
/// UTF-8 character boundary when the application supplied more than the 1024-byte limit.
///
/// Param:
/// out - []u8 (destination, at least 4 + 1024 + 8 bytes to hold any legal capsule)
/// code - u32 (the application error code, zero for a clean close)
/// message - []const u8 (the application message, truncated when it exceeds the limit)
///
/// Return:
/// - ?usize (the bytes written, null when `out` cannot hold the capsule)
pub fn writeCloseSession(out: []u8, code: u32, message: []const u8) ?usize {
    const kept = clampUtf8(message, wt.max_close_message);

    var value: [4 + wt.max_close_message]u8 = undefined;
    std.mem.writeInt(u32, value[0..4], code, .big);
    @memcpy(value[4..][0..kept.len], kept);

    return write(out, wt.capsule.close_session, value[0 .. 4 + kept.len]);
}

/// Truncate `text` to at most `limit` bytes without splitting a UTF-8 character (6: a sender that
/// truncates an application-supplied message MUST do so at a character boundary).
pub fn clampUtf8(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;

    var end = limit;
    // Walk back over continuation bytes (0b10xxxxxx) to the start of the character they belong to.
    while (end > 0 and text[end] & 0xc0 == 0x80) end -= 1;

    return text[0..end];
}

// --------------------------------------------------------------- //
// WT_DRAIN_SESSION (4.7)
// --------------------------------------------------------------- //

/// Encode a WT_DRAIN_SESSION capsule (4.7), whose value is empty.
pub fn writeDrainSession(out: []u8) ?usize {
    return write(out, wt.capsule.drain_session, "");
}

// --------------------------------------------------------------- //
// Flow control capsules (5.6)
// --------------------------------------------------------------- //

/// Encode a WT_MAX_DATA capsule (5.6.4): the session-wide byte limit.
pub fn writeMaxData(out: []u8, maximum_data: u64) ?usize {
    var value: [8]u8 = undefined;
    const len = varint.write(&value, maximum_data);

    return write(out, wt.capsule.max_data, value[0..len]);
}

/// Encode a WT_MAX_STREAMS capsule (5.6.2) for `kind`: the cumulative number of streams the peer may
/// open.
pub fn writeMaxStreams(out: []u8, kind: wt.StreamKind, maximum_streams: u64) ?usize {
    var value: [8]u8 = undefined;
    const len = varint.write(&value, maximum_streams);
    const capsule_type = switch (kind) {
        .bidi => wt.capsule.max_streams_bidi,
        .uni => wt.capsule.max_streams_uni,
    };

    return write(out, capsule_type, value[0..len]);
}

/// Encode a WT_STREAMS_BLOCKED capsule (5.6.3) for `kind`: a sender is willing to open a stream but the
/// peer's limit stopped it.
pub fn writeStreamsBlocked(out: []u8, kind: wt.StreamKind, maximum_streams: u64) ?usize {
    var value: [8]u8 = undefined;
    const len = varint.write(&value, maximum_streams);
    const capsule_type = switch (kind) {
        .bidi => wt.capsule.streams_blocked_bidi,
        .uni => wt.capsule.streams_blocked_uni,
    };

    return write(out, capsule_type, value[0..len]);
}

/// Encode a WT_DATA_BLOCKED capsule (5.6.5): a sender is willing to send data but the session limit
/// stopped it.
pub fn writeDataBlocked(out: []u8, maximum_data: u64) ?usize {
    var value: [8]u8 = undefined;
    const len = varint.write(&value, maximum_data);

    return write(out, wt.capsule.data_blocked, value[0..len]);
}

/// The errors a flow control capsule value raises.
pub const FlowControlError = error{
    /// The value is not a single well-formed variable-length integer.
    ZixTruncated,
    /// The value is past the largest count a stream id can express (2^60), which is a session flow
    /// control error (5.6.2 / 5.6.3).
    ZixFlowControlError,
};

/// Decode the single variable-length integer a flow control capsule carries (5.6.2 to 5.6.5).
///
/// Note:
/// - A stream count past 2^60 cannot describe any stream id, so it is rejected rather than clamped:
///   the caller closes the session with WT_FLOW_CONTROL_ERROR, as the spec requires.
pub fn parseFlowControl(value: []const u8) FlowControlError!u64 {
    const vi = varint.read(value) catch return error.ZixTruncated;
    // A trailing byte after the integer is not a single integer, so the value is malformed.
    if (vi.len != value.len) return error.ZixTruncated;

    return vi.value;
}

/// Decode a WT_MAX_STREAMS / WT_STREAMS_BLOCKED value, which is additionally capped at 2^60 (5.6.2).
pub fn parseStreamCount(value: []const u8) FlowControlError!u64 {
    const count = try parseFlowControl(value);
    if (count > wt.max_stream_count) return error.ZixFlowControlError;

    return count;
}

// --------------------------------------------------------------- //
// Streaming reader
// --------------------------------------------------------------- //

/// The largest value this reader accumulates for a capsule it understands. A capsule declaring a
/// longer value is skipped byte by byte instead of buffered: the largest capsule this binding defines
/// is WT_CLOSE_SESSION at 4 + 1024 bytes, and a peer must not be able to make an endpoint hold an
/// arbitrary length (RFC 9297 3.2 requires unknown capsules to be ignored, not buffered).
pub const max_known_value: usize = 4 + wt.max_close_message;

/// What one `feed` call did, for the caller's accounting and for the session error it may have to
/// raise (a refused capsule).
pub const Outcome = struct {
    /// Capsules this binding knows, handed to the visitor.
    delivered: u32 = 0,
    /// Capsules skipped because their type is not one this binding reads.
    skipped: u32 = 0,
    /// The visitor refused a capsule, so the caller raises the matching session error.
    refused: bool = false,
};

/// A capsule header (type, length) accumulated before the reader knows whether it will keep the value.
const header_bytes_max: usize = 2 * 8;

/// A streaming capsule reader over the CONNECT stream body. Bytes arrive inside HTTP/3 DATA frames, so
/// a capsule may be split across datagrams; the reader owns the partial capsule and never allocates.
///
/// Note:
/// - The reader parses the header first and only then decides: a capsule this binding knows is
///   accumulated into `value`, and any other capsule is skipped byte by byte. That is what keeps a
///   peer from making an endpoint buffer an arbitrary length, which RFC 9297 3.2 requires of a
///   receiver that must ignore unknown capsules.
pub const Reader = struct {
    /// The capsule's bytes still to be consumed, when a value is being accumulated.
    value: [max_known_value]u8 = undefined,
    /// Bytes of `value` in use.
    value_len: usize = 0,
    /// Bytes of `value` still awaited.
    value_need: usize = 0,
    /// The type of the capsule whose value is being accumulated.
    pending_type: u64 = 0,
    /// The capsule header being accumulated (both varints fit in 16 bytes).
    header: [header_bytes_max]u8 = undefined,
    /// Bytes of `header` in use.
    header_len: usize = 0,
    /// Bytes still to skip of a capsule this reader does not keep.
    discard: u64 = 0,

    /// Forget any partial capsule. Called when the session ends, so a half-read capsule never leaks
    /// into a later capsule stream that reuses the reader.
    pub fn reset(self: *Reader) void {
        self.value_len = 0;
        self.value_need = 0;
        self.header_len = 0;
        self.discard = 0;
    }

    /// Feed bytes from the CONNECT stream body. `visit` is called for every complete capsule this
    /// binding knows, in arrival order, with the value borrowed from the reader's buffer (valid only
    /// for that call). Unknown capsules are skipped.
    ///
    /// Param:
    /// self - *Reader
    /// data - []const u8 (bytes off a DATA frame on the CONNECT stream)
    /// visit - fn (context, Capsule) bool (a false return makes the caller fail the session, which is
    ///   how a flow control violation is raised)
    /// context - anytype (passed through to `visit`)
    ///
    /// Return:
    /// - Outcome (how many capsules were delivered, how many skipped, and whether one was refused)
    pub fn feed(self: *Reader, data: []const u8, comptime visit: anytype, context: anytype) Outcome {
        var outcome = Outcome{};
        var pos: usize = 0;

        while (pos < data.len) {
            // Skipping the value of a capsule this endpoint does not read.
            if (self.discard != 0) {
                const take: usize = @intCast(@min(self.discard, data.len - pos));
                pos += take;
                self.discard -= take;
                continue;
            }

            // Accumulating the value of a capsule this endpoint reads.
            if (self.value_need != 0) {
                const take = @min(self.value_need, data.len - pos);
                @memcpy(self.value[self.value_len..][0..take], data[pos..][0..take]);
                self.value_len += take;
                self.value_need -= take;
                pos += take;

                if (self.value_need != 0) break;
                if (!visit(context, .{ .type = self.pending_type, .value = self.value[0..self.value_len] })) {
                    outcome.refused = true;

                    return outcome;
                }

                outcome.delivered += 1;
                self.value_len = 0;
                continue;
            }

            // Reading a header, one byte at a time so a boundary inside a varint stops the walk
            // instead of consuming bytes that belong to the next capsule.
            self.header[self.header_len] = data[pos];
            self.header_len += 1;
            pos += 1;

            // error.ZixTruncated here means a varint is still arriving: two QUIC varints are at most
            // 16 bytes, so the header buffer always holds one and the loop below always resolves.
            const header = parseHeader(self.header[0..self.header_len]) catch continue;

            self.header_len = 0;

            if (known(header.type) and header.length <= max_known_value) {
                self.pending_type = header.type;

                if (header.length == 0) {
                    // An empty capsule (WT_DRAIN_SESSION) delivers as soon as its header is read.
                    if (!visit(context, .{ .type = header.type, .value = self.value[0..0] })) {
                        outcome.refused = true;

                        return outcome;
                    }

                    outcome.delivered += 1;
                    continue;
                }

                self.value_len = 0;
                self.value_need = @intCast(header.length);
                continue;
            }

            outcome.skipped += 1;
            self.discard = header.length;
        }

        return outcome;
    }
};

/// The type and length of a capsule header (RFC 9297 3.2).
const Header = struct { type: u64, length: u64 };

const HeaderError = error{ZixTruncated};

/// Parse a capsule header out of the bytes accumulated so far. error.ZixTruncated means the header is
/// still arriving, not that it is invalid (the caller feeds one byte at a time).
fn parseHeader(buf: []const u8) HeaderError!Header {
    const type_vi = varint.read(buf) catch return error.ZixTruncated;
    const length_vi = varint.read(buf[type_vi.len..]) catch return error.ZixTruncated;

    return .{ .type = type_vi.value, .length = length_vi.value };
}

/// Whether this binding reads a capsule type. Anything else is skipped (RFC 9297 3.2: an unknown
/// capsule type is ignored).
pub fn known(capsule_type: u64) bool {
    return switch (capsule_type) {
        wt.capsule.close_session,
        wt.capsule.drain_session,
        wt.capsule.max_data,
        wt.capsule.data_blocked,
        wt.capsule.max_streams_bidi,
        wt.capsule.max_streams_uni,
        wt.capsule.streams_blocked_bidi,
        wt.capsule.streams_blocked_uni,
        => true,
        else => false,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Collect the capsules a reader delivers, for tests.
const Collector = struct {
    types: [8]u64 = @splat(0),
    values: [8][]const u8 = @splat(""),
    lengths: [8]usize = @splat(0),
    count: usize = 0,

    fn visit(self: *Collector, capsule: Capsule) bool {
        if (self.count < self.types.len) {
            self.types[self.count] = capsule.type;
            self.values[self.count] = capsule.value;
            self.lengths[self.count] = capsule.value.len;
            self.count += 1;
        }

        return true;
    }

    fn byIndex(self: *const Collector, index: usize) Capsule {
        return .{ .type = self.types[index], .value = self.values[index][0..self.lengths[index]] };
    }
};

test "zix webtransport: RFC 9297 3.2 capsule framing" {
    var buf: [64]u8 = undefined;
    const close_len = writeCloseSession(&buf, 0x01020304, "bye").?;

    const parsed = try parse(buf[0..close_len]);
    try std.testing.expectEqual(wt.capsule.close_session, parsed.capsule.type);
    try std.testing.expectEqual(close_len, parsed.consumed);

    const close = try parseCloseSession(parsed.capsule.value);
    try std.testing.expectEqual(@as(u32, 0x01020304), close.code);
    try std.testing.expectEqualStrings("bye", close.message);

    // An empty value is a legal capsule: WT_DRAIN_SESSION carries nothing.
    var drain_buf: [8]u8 = undefined;
    const drain_len = writeDrainSession(&drain_buf).?;
    const drain = try parse(drain_buf[0..drain_len]);
    try std.testing.expectEqual(wt.capsule.drain_session, drain.capsule.type);
    try std.testing.expectEqual(@as(usize, 0), drain.capsule.value.len);

    // A truncated capsule is not an error, it is a request for more bytes.
    try std.testing.expectError(error.ZixTruncated, parse(drain_buf[0 .. drain_len - 1]));
    try std.testing.expectError(error.ZixTruncated, parse(drain_buf[0..1]));
    try std.testing.expectError(error.ZixTruncated, parse(""));
}

test "zix webtransport: 6 WT_CLOSE_SESSION carries an application code and validates the message" {
    var buf: [1200]u8 = undefined;

    // The clean-close shape: code 0, no message.
    const clean_len = writeCloseSession(&buf, 0, "").?;
    const clean = try parseCloseSession((try parse(buf[0..clean_len])).capsule.value);
    try std.testing.expectEqual(@as(u32, 0), clean.code);
    try std.testing.expectEqualStrings("", clean.message);

    // A short value cannot hold the 4-byte code.
    try std.testing.expectError(error.ZixTruncated, parseCloseSession(""));
    try std.testing.expectError(error.ZixTruncated, parseCloseSession(&[_]u8{ 0, 0, 0 }));

    // Invalid UTF-8 in the message is H3_MESSAGE_ERROR at the receiver.
    try std.testing.expectError(error.ZixMessageError, parseCloseSession(&[_]u8{ 0, 0, 0, 0, 0xff, 0xfe }));

    // A message past the 1024-byte limit is H3_MESSAGE_ERROR too, even though it is valid UTF-8.
    var long: [1200]u8 = @splat(0x61);
    std.mem.writeInt(u32, long[0..4], 1, .big);
    try std.testing.expectError(error.ZixMessageError, parseCloseSession(&long));
}

test "zix webtransport: a truncated close message is cut on a character boundary" {
    // 1023 ASCII bytes plus a 2-byte character that straddles the limit: the sender must drop the
    // whole character rather than emit half of it (6).
    var message: [1026]u8 = @splat('a');
    message[1023] = 0xc3;
    message[1024] = 0xa9; // U+00E9, starts at 1023, so it does not fit in 1024 bytes

    const kept = clampUtf8(&message, wt.max_close_message);
    try std.testing.expectEqual(@as(usize, 1023), kept.len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(kept));

    var buf: [1200]u8 = undefined;
    const len = writeCloseSession(&buf, 7, &message).?;
    const close = try parseCloseSession((try parse(buf[0..len])).capsule.value);
    try std.testing.expectEqual(@as(u32, 7), close.code);
    try std.testing.expectEqual(@as(usize, 1023), close.message.len);
}

test "zix webtransport: the flow control capsules encode and decode one varint" {
    var buf: [32]u8 = undefined;

    // Small values stay one byte, large ones take the QUIC varint length (RFC 9000 16).
    const max_data_len = writeMaxData(&buf, 262144).?;
    const max_data = try parse(buf[0..max_data_len]);
    try std.testing.expectEqual(wt.capsule.max_data, max_data.capsule.type);
    try std.testing.expectEqual(@as(u64, 262144), try parseFlowControl(max_data.capsule.value));

    const bidi_len = writeMaxStreams(&buf, .bidi, 3).?;
    const bidi = try parse(buf[0..bidi_len]);
    try std.testing.expectEqual(wt.capsule.max_streams_bidi, bidi.capsule.type);
    try std.testing.expectEqual(@as(u64, 3), try parseStreamCount(bidi.capsule.value));

    const uni_len = writeMaxStreams(&buf, .uni, 7).?;
    try std.testing.expectEqual(wt.capsule.max_streams_uni, (try parse(buf[0..uni_len])).capsule.type);

    const blocked_len = writeStreamsBlocked(&buf, .bidi, 3).?;
    try std.testing.expectEqual(wt.capsule.streams_blocked_bidi, (try parse(buf[0..blocked_len])).capsule.type);

    const blocked_uni_len = writeStreamsBlocked(&buf, .uni, 3).?;
    try std.testing.expectEqual(wt.capsule.streams_blocked_uni, (try parse(buf[0..blocked_uni_len])).capsule.type);

    const data_blocked_len = writeDataBlocked(&buf, 65536).?;
    const data_blocked = try parse(buf[0..data_blocked_len]);
    try std.testing.expectEqual(wt.capsule.data_blocked, data_blocked.capsule.type);
    try std.testing.expectEqual(@as(u64, 65536), try parseFlowControl(data_blocked.capsule.value));

    // A stream count past 2^60 cannot describe any stream id: WT_FLOW_CONTROL_ERROR (5.6.2).
    var big: [8]u8 = undefined;
    const big_len = varint.write(&big, wt.max_stream_count + 1);
    try std.testing.expectError(error.ZixFlowControlError, parseStreamCount(big[0..big_len]));
    try std.testing.expectEqual(wt.max_stream_count, try parseStreamCount(big[0..varint.write(&big, wt.max_stream_count)]));

    // A value that is not a single integer is malformed, not a flow control error.
    // Two integers in one value is not a single integer, and an empty value carries none.
    try std.testing.expectError(error.ZixTruncated, parseFlowControl(&[_]u8{ 0x01, 0x02 }));
    try std.testing.expectError(error.ZixTruncated, parseFlowControl(""));
}

test "zix webtransport: the reader hands over complete capsules across split datagrams" {
    var buf: [64]u8 = undefined;
    const close_len = writeCloseSession(&buf, 9, "gone").?;
    const drain_len = writeDrainSession(buf[close_len..]).?;
    const stream = buf[0 .. close_len + drain_len];

    // Split the two capsules at every possible boundary: each split must deliver exactly the same two
    // capsules, in order, with no loss and no duplicate.
    var split: usize = 0;
    while (split <= stream.len) : (split += 1) {
        var reader = Reader{};
        var collector = Collector{};

        const first = reader.feed(stream[0..split], Collector.visit, &collector);
        const second = reader.feed(stream[split..], Collector.visit, &collector);

        try std.testing.expectEqual(@as(u32, 2), first.delivered + second.delivered);
        try std.testing.expect(!first.refused and !second.refused);
        try std.testing.expectEqual(@as(usize, 2), collector.count);
        try std.testing.expectEqual(wt.capsule.close_session, collector.byIndex(0).type);
        try std.testing.expectEqual(wt.capsule.drain_session, collector.byIndex(1).type);
        try std.testing.expectEqualStrings("gone", (try parseCloseSession(collector.byIndex(0).value)).message);
    }
}

test "zix webtransport: the reader skips an unknown capsule without buffering it" {
    // An unknown capsule declaring 64 KiB, then a known one. The reader must reach the known capsule
    // without ever holding the 64 KiB, feeding it in 16-byte slices.
    var header: [16]u8 = undefined;
    var hp: usize = 0;
    hp += varint.write(header[hp..], 0x1234);
    hp += varint.write(header[hp..], 65536);

    var reader = Reader{};
    var collector = Collector{};

    const announced = reader.feed(header[0..hp], Collector.visit, &collector);
    try std.testing.expectEqual(@as(u32, 0), announced.delivered);
    try std.testing.expectEqual(@as(u32, 1), announced.skipped);
    try std.testing.expectEqual(@as(usize, 0), collector.count);

    var chunk: [16]u8 = @splat(0xab);
    var fed: u64 = 0;
    while (fed < 65536) : (fed += 16) {
        _ = reader.feed(&chunk, Collector.visit, &collector);
    }
    try std.testing.expectEqual(@as(u64, 0), reader.discard);
    try std.testing.expectEqual(@as(usize, 0), collector.count);

    var buf: [32]u8 = undefined;
    const drain_len = writeDrainSession(&buf).?;
    const after = reader.feed(buf[0..drain_len], Collector.visit, &collector);

    try std.testing.expectEqual(@as(u32, 1), after.delivered);
    try std.testing.expectEqual(@as(usize, 1), collector.count);
    try std.testing.expectEqual(wt.capsule.drain_session, collector.byIndex(0).type);
}

test "zix webtransport: an oversized known capsule is skipped rather than buffered" {
    // WT_CLOSE_SESSION declaring more than the reader holds is not a capsule this endpoint can read,
    // so it is skipped, and the reader stays synchronized on the capsule after it.
    var stream: [1200]u8 = undefined;
    var sp: usize = 0;
    sp += varint.write(stream[sp..], wt.capsule.close_session);
    sp += varint.write(stream[sp..], max_known_value + 1);
    const payload_at = sp;
    @memset(stream[sp..][0 .. max_known_value + 1], 0x7a);
    sp += max_known_value + 1;
    const drain_len = writeDrainSession(stream[sp..]).?;
    sp += drain_len;

    var reader = Reader{};
    var collector = Collector{};
    const outcome = reader.feed(stream[0..sp], Collector.visit, &collector);

    try std.testing.expectEqual(@as(u32, 1), outcome.delivered);
    try std.testing.expectEqual(@as(u32, 1), outcome.skipped);
    try std.testing.expectEqual(@as(usize, 1), collector.count);
    try std.testing.expectEqual(wt.capsule.drain_session, collector.byIndex(0).type);
    try std.testing.expect(stream[payload_at] == 0x7a);
}

test "zix webtransport: a refused capsule stops the reader" {
    const Refuser = struct {
        fn visit(_: *u32, capsule: Capsule) bool {
            // Any capsule can be refused; this models a flow control violation, which the caller turns
            // into a WT_FLOW_CONTROL_ERROR session close.
            _ = capsule;

            return false;
        }
    };

    var buf: [32]u8 = undefined;
    const len = writeMaxData(&buf, 1).?;
    var reader = Reader{};
    var marker: u32 = 0;

    const outcome = reader.feed(buf[0..len], Refuser.visit, &marker);
    try std.testing.expect(outcome.refused);
    try std.testing.expectEqual(@as(u32, 0), outcome.delivered);
}

test "zix webtransport: a huge unknown capsule consumes exactly its declared length" {
    // A capsule of an unknown type declaring 4096 bytes: the reader skips the whole value and the
    // capsule after it is still delivered, because the declared length bounds the skip.
    var stream: [4200]u8 = undefined;
    var sp: usize = 0;
    sp += varint.write(stream[sp..], 0x1f);
    sp += varint.write(stream[sp..], 4096);
    @memset(stream[sp..][0..4096], 0x5a);
    sp += 4096;
    const drain_len = writeDrainSession(stream[sp..]).?;
    sp += drain_len;

    var reader = Reader{};
    var collector = Collector{};
    const outcome = reader.feed(stream[0..sp], Collector.visit, &collector);

    try std.testing.expectEqual(@as(u32, 1), outcome.skipped);
    try std.testing.expectEqual(@as(u32, 1), outcome.delivered);
    try std.testing.expectEqual(wt.capsule.drain_session, collector.byIndex(0).type);
}

test "zix webtransport: a capsule declaring a huge value buffers nothing" {
    // The largest length a varint can carry: the reader must settle into skipping it without allocating
    // or panicking, and must not deliver anything from inside it.
    var header: [16]u8 = undefined;
    var hp: usize = 0;
    hp += varint.write(header[hp..], 0x2f);
    hp += varint.write(header[hp..], (1 << 62) - 1);

    var reader = Reader{};
    var collector = Collector{};
    const announced = reader.feed(header[0..hp], Collector.visit, &collector);

    try std.testing.expectEqual(@as(u32, 1), announced.skipped);
    try std.testing.expectEqual(@as(u64, (1 << 62) - 1), reader.discard);

    // The declared value swallows the capsule that follows it, which is what the peer asked for.
    const drain_len = writeDrainSession(header[0..]).?;
    const after = reader.feed(header[0..drain_len], Collector.visit, &collector);
    try std.testing.expectEqual(@as(u32, 0), after.delivered);
    try std.testing.expectEqual(@as(usize, 0), collector.count);
}
