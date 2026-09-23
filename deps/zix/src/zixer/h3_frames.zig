//! zixer h3 frames: the HTTP/3 stream framing layer for the edge (rfc 9114 7)

const std = @import("std");
const zix = @import("zix");

const varint = zix.Http3.varint;
const h3 = zix.Http3.h3;

/// Frame types the edge acts on (rfc 9114 7.2). Anything else is skipped: an
/// unknown type is reserved or grease, never an error.
pub const DATA: u64 = 0x00;
pub const HEADERS: u64 = 0x01;
pub const CANCEL_PUSH: u64 = 0x03;
pub const SETTINGS: u64 = 0x04;
pub const PUSH_PROMISE: u64 = 0x05;
pub const GOAWAY: u64 = 0x07;
pub const MAX_PUSH_ID: u64 = 0x0d;

/// Unidirectional stream types (rfc 9114 6.2, rfc 9204 4.2).
pub const CONTROL_STREAM: u64 = h3.control_stream;
pub const PUSH_STREAM: u64 = h3.push_stream;
pub const QPACK_ENCODER_STREAM: u64 = h3.qpack_encoder_stream;
pub const QPACK_DECODER_STREAM: u64 = h3.qpack_decoder_stream;

/// Setting identifiers the edge reads or writes (rfc 9114 7.2.4.1, rfc 9204 5).
pub const SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Largest frame payload the edge buffers whole. A HEADERS block or a request
/// body frame past this is refused, never truncated.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

pub const Error = error{
    /// A frame payload longer than MAX_FRAME_PAYLOAD.
    ZixerFrameTooLarge,
    /// A varint that does not decode, or a length past what the type allows.
    ZixerMalformed,
    /// The output buffer has no room for the frame.
    ZixerBufferFull,
};

/// One parsed frame, its payload borrowing the caller's stream buffer.
pub const Frame = struct {
    kind: u64,
    payload: []const u8,
    /// Bytes of the stream buffer this frame occupied, header included.
    consumed: usize,
};

/// Read the next complete frame from a request or control stream buffer.
///
/// Note:
/// - Null means the frame header or payload has not fully arrived yet, so the
///   caller keeps the bytes and retries after the next STREAM frame.
///
/// Param:
/// buf - []const u8 (stream bytes from the current frame boundary)
///
/// Return:
/// - Frame when one is complete
/// - null when more stream bytes are needed
/// - Error.ZixerFrameTooLarge past MAX_FRAME_PAYLOAD, Error.ZixerMalformed on a bad varint
pub fn nextFrame(buf: []const u8) Error!?Frame {
    if (buf.len == 0) return null;

    const kind = varint.read(buf) catch return null;
    var pos = kind.len;
    if (pos >= buf.len) return null;

    const length = varint.read(buf[pos..]) catch return null;
    pos += length.len;

    if (length.value > MAX_FRAME_PAYLOAD) return error.ZixerFrameTooLarge;

    const payload_len: usize = @intCast(length.value);
    if (buf.len < pos + payload_len) return null;

    return .{ .kind = kind.value, .payload = buf[pos..][0..payload_len], .consumed = pos + payload_len };
}

/// Whether a frame type is legal on a request stream (rfc 9114 7.2).
pub fn allowedOnRequest(kind: u64) bool {
    return switch (kind) {
        DATA, HEADERS => true,
        PUSH_PROMISE => true,
        SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH => false,
        // Reserved and grease types are ignorable, not illegal.
        else => true,
    };
}

/// Whether a frame type is legal on the control stream (rfc 9114 7.2).
pub fn allowedOnControl(kind: u64) bool {
    return switch (kind) {
        SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH => true,
        DATA, HEADERS, PUSH_PROMISE => false,
        else => true,
    };
}

/// Bytes a frame header occupies for this type and length.
pub fn headerLen(kind: u64, payload_len: u64) usize {
    return varint.encodedLen(kind) + varint.encodedLen(payload_len);
}

/// Write a frame header (type then length). The caller appends the payload.
pub fn writeHeader(out: []u8, kind: u64, payload_len: u64) Error!usize {
    const needed = headerLen(kind, payload_len);
    if (out.len < needed) return error.ZixerBufferFull;

    var pos = varint.write(out, kind);
    pos += varint.write(out[pos..], payload_len);

    return pos;
}

/// Write a whole frame: header then payload.
pub fn writeFrame(out: []u8, kind: u64, payload: []const u8) Error!usize {
    const header = try writeHeader(out, kind, payload.len);
    if (out.len < header + payload.len) return error.ZixerBufferFull;

    @memcpy(out[header..][0..payload.len], payload);

    return header + payload.len;
}

/// The settings the edge exchanges. zixer keeps no QPACK dynamic table, so it
/// advertises zero capacity and zero blocked streams: every field section on
/// the wire is static-only in both directions.
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: u64 = 0,
};

/// Write the server SETTINGS frame body the edge advertises.
pub fn writeSettings(out: []u8, settings: Settings) Error!usize {
    var body: [32]u8 = undefined;
    var body_len: usize = 0;

    body_len += varint.write(body[body_len..], SETTING_QPACK_MAX_TABLE_CAPACITY);
    body_len += varint.write(body[body_len..], settings.qpack_max_table_capacity);
    body_len += varint.write(body[body_len..], SETTING_QPACK_BLOCKED_STREAMS);
    body_len += varint.write(body[body_len..], settings.qpack_blocked_streams);

    if (settings.max_field_section_size != 0) {
        body_len += varint.write(body[body_len..], SETTING_MAX_FIELD_SECTION_SIZE);
        body_len += varint.write(body[body_len..], settings.max_field_section_size);
    }

    return writeFrame(out, SETTINGS, body[0..body_len]);
}

/// Read a SETTINGS payload, keeping the identifiers the edge acts on and
/// walking past every other one (an unknown setting is ignorable, rfc 9114 7.2.4).
pub fn parseSettings(payload: []const u8) Error!Settings {
    var settings = Settings{};
    var pos: usize = 0;

    while (pos < payload.len) {
        const id = varint.read(payload[pos..]) catch return error.ZixerMalformed;
        pos += id.len;
        if (pos >= payload.len) return error.ZixerMalformed;

        const value = varint.read(payload[pos..]) catch return error.ZixerMalformed;
        pos += value.len;

        switch (id.value) {
            SETTING_QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value.value,
            SETTING_QPACK_BLOCKED_STREAMS => settings.qpack_blocked_streams = value.value,
            SETTING_MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = value.value,
            else => {},
        }
    }

    return settings;
}

/// Read the leading stream-type varint of a unidirectional stream (rfc 9114 6.2).
/// Null while the varint has not fully arrived.
pub fn readStreamType(buf: []const u8) ?struct { kind: u64, consumed: usize } {
    const kind = varint.read(buf) catch return null;

    return .{ .kind = kind.value, .consumed = kind.len };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: h3 frames, a complete frame parses and reports what it used" {
    var buf: [64]u8 = undefined;
    const len = try writeFrame(&buf, HEADERS, "block-bytes");

    const frame = (try nextFrame(buf[0..len])).?;
    try testing.expectEqual(HEADERS, frame.kind);
    try testing.expectEqualStrings("block-bytes", frame.payload);
    try testing.expectEqual(len, frame.consumed);
}

test "zix zixer: h3 frames, a partial frame asks for more bytes" {
    var buf: [64]u8 = undefined;
    const len = try writeFrame(&buf, DATA, "hello world");

    try testing.expect(try nextFrame(buf[0..0]) == null);
    try testing.expect(try nextFrame(buf[0..1]) == null);
    try testing.expect(try nextFrame(buf[0 .. len - 1]) == null);
    try testing.expect(try nextFrame(buf[0..len]) != null);
}

test "zix zixer: h3 frames, back to back frames walk by consumed" {
    var buf: [128]u8 = undefined;
    var len = try writeFrame(&buf, HEADERS, "head");
    len += try writeFrame(buf[len..], DATA, "body");

    const first = (try nextFrame(buf[0..len])).?;
    try testing.expectEqual(HEADERS, first.kind);

    const second = (try nextFrame(buf[first.consumed..len])).?;
    try testing.expectEqual(DATA, second.kind);
    try testing.expectEqualStrings("body", second.payload);
    try testing.expectEqual(len, first.consumed + second.consumed);
}

test "zix zixer: h3 frames, a payload past the bound is refused" {
    // Type 0x00 then a 4-byte varint length of 2 MiB.
    var buf: [8]u8 = undefined;
    buf[0] = 0x00;
    const written = zix.Http3.varint.write(buf[1..], 2 * 1024 * 1024);

    try testing.expectError(error.ZixerFrameTooLarge, nextFrame(buf[0 .. 1 + written]));
}

test "zix zixer: h3 frames, settings round trip and unknown ids are ignored" {
    var buf: [64]u8 = undefined;
    const len = try writeSettings(&buf, .{ .max_field_section_size = 16384 });

    const frame = (try nextFrame(buf[0..len])).?;
    try testing.expectEqual(SETTINGS, frame.kind);

    const settings = try parseSettings(frame.payload);
    try testing.expectEqual(@as(u64, 0), settings.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), settings.qpack_blocked_streams);
    try testing.expectEqual(@as(u64, 16384), settings.max_field_section_size);

    // An unknown identifier with its value walks past cleanly.
    const with_grease = [_]u8{ 0x40, 0x2a, 0x01, 0x06, 0x44, 0x00 };
    const parsed = try parseSettings(&with_grease);
    try testing.expectEqual(@as(u64, 1024), parsed.max_field_section_size);
}

test "zix zixer: h3 frames, frame placement rules follow rfc 9114 7.2" {
    try testing.expect(allowedOnRequest(HEADERS));
    try testing.expect(allowedOnRequest(DATA));
    try testing.expect(!allowedOnRequest(SETTINGS));
    try testing.expect(!allowedOnRequest(GOAWAY));

    try testing.expect(allowedOnControl(SETTINGS));
    try testing.expect(allowedOnControl(GOAWAY));
    try testing.expect(!allowedOnControl(DATA));
    try testing.expect(!allowedOnControl(HEADERS));

    // Grease types are ignorable on both.
    try testing.expect(allowedOnRequest(0x21));
    try testing.expect(allowedOnControl(0x21));
}

test "zix zixer: h3 frames, a uni stream leads with its type" {
    var buf: [8]u8 = undefined;
    const len = zix.Http3.varint.write(&buf, QPACK_ENCODER_STREAM);

    const prologue = readStreamType(buf[0..len]).?;
    try testing.expectEqual(QPACK_ENCODER_STREAM, prologue.kind);
    try testing.expectEqual(len, prologue.consumed);
}

test "zix zixer: h3 frames, a header write refuses a buffer with no room" {
    var tiny: [1]u8 = undefined;
    try testing.expectError(error.ZixerBufferFull, writeHeader(&tiny, HEADERS, 4096));
    try testing.expectError(error.ZixerBufferFull, writeFrame(&tiny, DATA, "xy"));
}
