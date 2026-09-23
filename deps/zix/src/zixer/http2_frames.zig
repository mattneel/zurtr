//! zixer http2 frames: blocking frame reads and writes over stream interfaces

const std = @import("std");
const zix = @import("zix");

const Http2 = zix.Http2;

/// Largest frame payload the edge accepts: the rfc 9113 default
/// SETTINGS_MAX_FRAME_SIZE, which zixer never raises.
pub const MAX_PAYLOAD: usize = Http2.DEFAULT_MAX_FRAME_SIZE;

/// The rfc 8441 setting that advertises extended CONNECT support.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x08;

pub const Error = error{
    ZixerConnectionClosed,
    ZixerFrameTooLarge,
    ZixerBadFrame,
};

/// One frame as read off the wire. payload borrows the caller's buffer and
/// only lives until the next read into it.
pub const Frame = struct {
    head: Http2.FrameHeader,
    payload: []const u8,
};

/// Read one frame (header plus payload) into payload_buf.
pub fn readFrame(src: *std.Io.Reader, payload_buf: []u8) Error!Frame {
    var head_bytes: [Http2.FRAME_HEADER_LEN]u8 = undefined;
    src.readSliceAll(&head_bytes) catch return error.ZixerConnectionClosed;

    const head = Http2.parseFrameHeader(&head_bytes);
    if (head.length > payload_buf.len) return error.ZixerFrameTooLarge;
    src.readSliceAll(payload_buf[0..head.length]) catch return error.ZixerConnectionClosed;

    return .{ .head = head, .payload = payload_buf[0..head.length] };
}

/// Write one frame: header plus payload. The caller flushes.
pub fn writeFrame(dst: *std.Io.Writer, frame_type: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    var head_bytes: [Http2.FRAME_HEADER_LEN]u8 = undefined;
    Http2.encodeFrameHeader(&head_bytes, .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });

    try dst.writeAll(&head_bytes);
    try dst.writeAll(payload);
}

/// Write one header block as HEADERS plus CONTINUATION frames when it
/// exceeds max_frame. END_HEADERS rides the last frame, end_stream the
/// HEADERS frame.
pub fn writeHeaderBlock(dst: *std.Io.Writer, stream_id: u31, block: []const u8, end_stream: bool, max_frame: usize) !void {
    var offset: usize = 0;
    var first = true;
    while (true) {
        const take = @min(block.len - offset, max_frame);
        const last = offset + take == block.len;

        var flags: u8 = 0;
        if (first and end_stream) flags |= Http2.FLAG_END_STREAM;
        if (last) flags |= Http2.FLAG_END_HEADERS;

        const frame_type: u8 = if (first) Http2.FRAME_TYPE_HEADERS else Http2.FRAME_TYPE_CONTINUATION;
        try writeFrame(dst, frame_type, flags, stream_id, block[offset..][0..take]);

        offset += take;
        if (last) return;
        first = false;
    }
}

/// Write a SETTINGS frame from [id, value] pairs.
pub fn writeSettings(dst: *std.Io.Writer, params: []const [2]u32) !void {
    var head_bytes: [Http2.FRAME_HEADER_LEN]u8 = undefined;
    Http2.encodeFrameHeader(&head_bytes, .{
        .length = @intCast(params.len * 6),
        .frame_type = Http2.FRAME_TYPE_SETTINGS,
        .flags = 0,
        .stream_id = 0,
    });
    try dst.writeAll(&head_bytes);

    for (params) |param| {
        var entry: [6]u8 = undefined;
        std.mem.writeInt(u16, entry[0..2], @intCast(param[0]), .big);
        std.mem.writeInt(u32, entry[2..6], param[1], .big);
        try dst.writeAll(&entry);
    }
}

pub fn writeSettingsAck(dst: *std.Io.Writer) !void {
    try writeFrame(dst, Http2.FRAME_TYPE_SETTINGS, Http2.FLAG_ACK, 0, "");
}

pub fn writePingAck(dst: *std.Io.Writer, payload: []const u8) !void {
    try writeFrame(dst, Http2.FRAME_TYPE_PING, Http2.FLAG_ACK, 0, payload);
}

pub fn writeRstStream(dst: *std.Io.Writer, stream_id: u31, error_code: u32) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, error_code, .big);

    try writeFrame(dst, Http2.FRAME_TYPE_RST_STREAM, 0, stream_id, &payload);
}

pub fn writeGoaway(dst: *std.Io.Writer, last_stream: u31, error_code: u32) !void {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], last_stream, .big);
    std.mem.writeInt(u32, payload[4..8], error_code, .big);

    try writeFrame(dst, Http2.FRAME_TYPE_GOAWAY, 0, 0, &payload);
}

/// Write the server preface followed straight by a GOAWAY, for a connection
/// closed before it ever serves a stream.
///
/// Note:
/// - An h2 client reads the connection preface first whatever comes after it
///   (rfc 9113 3.4), so the empty SETTINGS is what makes the GOAWAY land as a
///   refusal instead of as a protocol fault.
/// - The last stream id is 0 because none was ever opened, which tells the
///   client every request it had in flight is safe to send elsewhere.
///
/// Param:
/// dst - *std.Io.Writer (the client leg, the caller flushes)
/// error_code - u32 (why the connection is going away)
///
/// Return:
/// - void
/// - the writer's own errors
pub fn writeImmediateGoaway(dst: *std.Io.Writer, error_code: u32) !void {
    try writeSettings(dst, &.{});
    try writeGoaway(dst, 0, error_code);
}

pub fn writeWindowUpdate(dst: *std.Io.Writer, stream_id: u31, increment: u31) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);

    try writeFrame(dst, Http2.FRAME_TYPE_WINDOW_UPDATE, 0, stream_id, &payload);
}

/// Walk the [id, value] pairs of a SETTINGS payload.
pub const SettingsIterator = struct {
    payload: []const u8,
    pos: usize = 0,

    pub fn init(payload: []const u8) SettingsIterator {
        return .{ .payload = payload };
    }

    pub fn next(iter: *SettingsIterator) ?[2]u32 {
        if (iter.pos + 6 > iter.payload.len) return null;

        const id = std.mem.readInt(u16, iter.payload[iter.pos..][0..2], .big);
        const value = std.mem.readInt(u32, iter.payload[iter.pos + 2 ..][0..4], .big);
        iter.pos += 6;

        return .{ id, value };
    }
};

/// The data bytes of a DATA frame, padding stripped (rfc 9113 6.1).
pub fn dataPayload(frame: *const Frame) Error![]const u8 {
    if ((frame.head.flags & Http2.FLAG_PADDED) == 0) return frame.payload;

    if (frame.payload.len < 1) return error.ZixerBadFrame;
    const pad_len: usize = frame.payload[0];
    if (1 + pad_len > frame.payload.len) return error.ZixerBadFrame;

    return frame.payload[1 .. frame.payload.len - pad_len];
}

/// The header block fragment of a HEADERS frame: padding and the
/// deprecated priority fields stripped (rfc 9113 6.2).
pub fn headersFragment(frame: *const Frame) Error![]const u8 {
    var fragment = frame.payload;
    var pad_len: usize = 0;

    if ((frame.head.flags & Http2.FLAG_PADDED) != 0) {
        if (fragment.len < 1) return error.ZixerBadFrame;
        pad_len = fragment[0];
        fragment = fragment[1..];
    }

    if ((frame.head.flags & Http2.FLAG_PRIORITY) != 0) {
        if (fragment.len < 5) return error.ZixerBadFrame;
        fragment = fragment[5..];
    }

    if (pad_len > fragment.len) return error.ZixerBadFrame;

    return fragment[0 .. fragment.len - pad_len];
}

/// The increment of a WINDOW_UPDATE payload, reserved bit dropped.
pub fn windowIncrement(payload: []const u8) Error!u31 {
    if (payload.len != 4) return error.ZixerBadFrame;

    const raw = std.mem.readInt(u32, payload[0..4], .big);

    return @intCast(raw & 0x7FFF_FFFF);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: http2 frames, write and read roundtrip" {
    var wire_buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeFrame(&out, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, 5, "hello");

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [16]u8 = undefined;
    const frame = try readFrame(&src, &payload_buf);

    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), frame.head.frame_type);
    try testing.expectEqual(@as(u8, Http2.FLAG_END_STREAM), frame.head.flags);
    try testing.expectEqual(@as(u31, 5), frame.head.stream_id);
    try testing.expectEqualStrings("hello", frame.payload);
}

test "zix zixer: http2 frames, oversize length refuses before the payload read" {
    var wire_buf: [32]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    var head_bytes: [Http2.FRAME_HEADER_LEN]u8 = undefined;
    Http2.encodeFrameHeader(&head_bytes, .{ .length = 100, .frame_type = Http2.FRAME_TYPE_DATA, .flags = 0, .stream_id = 1 });
    try out.writeAll(&head_bytes);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [16]u8 = undefined;
    try testing.expectError(error.ZixerFrameTooLarge, readFrame(&src, &payload_buf));
}

test "zix zixer: http2 frames, truncated wire reads as connection closed" {
    var src = std.Io.Reader.fixed("\x00\x00");
    var payload_buf: [16]u8 = undefined;

    try testing.expectError(error.ZixerConnectionClosed, readFrame(&src, &payload_buf));
}

test "zix zixer: http2 frames, settings roundtrip through the iterator" {
    var wire_buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeSettings(&out, &.{
        .{ Http2.SETTINGS_MAX_CONCURRENT_STREAMS, 8 },
        .{ SETTINGS_ENABLE_CONNECT_PROTOCOL, 1 },
    });

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [32]u8 = undefined;
    const frame = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), frame.head.frame_type);

    var iter = SettingsIterator.init(frame.payload);
    const first = iter.next().?;
    try testing.expectEqual(@as(u32, Http2.SETTINGS_MAX_CONCURRENT_STREAMS), first[0]);
    try testing.expectEqual(@as(u32, 8), first[1]);
    const second = iter.next().?;
    try testing.expectEqual(@as(u32, SETTINGS_ENABLE_CONNECT_PROTOCOL), second[0]);
    try testing.expectEqual(@as(u32, 1), second[1]);
    try testing.expectEqual(@as(?[2]u32, null), iter.next());
}

test "zix zixer: http2 frames, data padding strips and refuses overrun" {
    const padded = Frame{
        .head = .{ .length = 8, .frame_type = Http2.FRAME_TYPE_DATA, .flags = Http2.FLAG_PADDED, .stream_id = 1 },
        .payload = "\x02helloXY",
    };
    try testing.expectEqualStrings("hello", try dataPayload(&padded));

    const overrun = Frame{
        .head = .{ .length = 2, .frame_type = Http2.FRAME_TYPE_DATA, .flags = Http2.FLAG_PADDED, .stream_id = 1 },
        .payload = "\x05a",
    };
    try testing.expectError(error.ZixerBadFrame, dataPayload(&overrun));

    const plain = Frame{
        .head = .{ .length = 2, .frame_type = Http2.FRAME_TYPE_DATA, .flags = 0, .stream_id = 1 },
        .payload = "ok",
    };
    try testing.expectEqualStrings("ok", try dataPayload(&plain));
}

test "zix zixer: http2 frames, headers fragment drops padding and priority" {
    const with_priority = Frame{
        .head = .{ .length = 8, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_PRIORITY, .stream_id = 1 },
        .payload = "\x00\x00\x00\x03\x10abc",
    };
    try testing.expectEqualStrings("abc", try headersFragment(&with_priority));

    const with_both = Frame{
        .head = .{ .length = 10, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_PRIORITY | Http2.FLAG_PADDED, .stream_id = 1 },
        .payload = "\x01\x00\x00\x00\x03\x10abcZ",
    };
    try testing.expectEqualStrings("abc", try headersFragment(&with_both));

    const short = Frame{
        .head = .{ .length = 2, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_PRIORITY, .stream_id = 1 },
        .payload = "ab",
    };
    try testing.expectError(error.ZixerBadFrame, headersFragment(&short));
}

test "zix zixer: http2 frames, window update roundtrip drops the reserved bit" {
    var wire_buf: [32]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeWindowUpdate(&out, 3, 65535);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [8]u8 = undefined;
    const frame = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u31, 3), frame.head.stream_id);
    try testing.expectEqual(@as(u31, 65535), try windowIncrement(frame.payload));

    const reserved = [4]u8{ 0x80, 0x00, 0x00, 0x07 };
    try testing.expectEqual(@as(u31, 7), try windowIncrement(&reserved));

    try testing.expectError(error.ZixerBadFrame, windowIncrement("abc"));
}

test "zix zixer: http2 frames, goaway carries last stream and error code" {
    var wire_buf: [32]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeGoaway(&out, 7, Http2.ERR_PROTOCOL_ERROR);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [16]u8 = undefined;
    const frame = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_GOAWAY), frame.head.frame_type);
    try testing.expectEqual(@as(u31, 0), frame.head.stream_id);
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, frame.payload[0..4], .big));
    try testing.expectEqual(Http2.ERR_PROTOCOL_ERROR, std.mem.readInt(u32, frame.payload[4..8], .big));
}

test "zix zixer: http2 frames, an immediate goaway leads with the server preface" {
    var wire_buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeImmediateGoaway(&out, Http2.ERR_ENHANCE_YOUR_CALM);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [32]u8 = undefined;

    // SETTINGS first, and empty: nothing is being advertised on a connection
    // that is about to end.
    const settings = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), settings.head.frame_type);
    try testing.expectEqual(@as(u8, 0), settings.head.flags);
    try testing.expectEqual(@as(usize, 0), settings.payload.len);

    const goaway = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_GOAWAY), goaway.head.frame_type);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, goaway.payload[0..4], .big));
    try testing.expectEqual(Http2.ERR_ENHANCE_YOUR_CALM, std.mem.readInt(u32, goaway.payload[4..8], .big));
}

test "zix zixer: http2 frames, header block splits into continuation frames" {
    var block: [40]u8 = undefined;
    for (&block, 0..) |*byte, index| byte.* = @intCast(index);

    var wire_buf: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeHeaderBlock(&out, 9, &block, true, 16);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [16]u8 = undefined;

    const first = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), first.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_STREAM, first.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqual(@as(u8, 0), first.head.flags & Http2.FLAG_END_HEADERS);

    const middle = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_CONTINUATION), middle.head.frame_type);
    try testing.expectEqual(@as(u8, 0), middle.head.flags & Http2.FLAG_END_HEADERS);

    const last = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_CONTINUATION), last.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_HEADERS, last.head.flags & Http2.FLAG_END_HEADERS);
    try testing.expectEqual(@as(u24, 8), last.head.length);
}

test "zix zixer: http2 frames, small block stays one headers frame" {
    var wire_buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&wire_buf);
    try writeHeaderBlock(&out, 1, "abc", false, MAX_PAYLOAD);

    var src = std.Io.Reader.fixed(out.buffered());
    var payload_buf: [16]u8 = undefined;
    const only = try readFrame(&src, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), only.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_HEADERS, only.head.flags & Http2.FLAG_END_HEADERS);
    try testing.expectEqual(@as(u8, 0), only.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqualStrings("abc", only.payload);
}
