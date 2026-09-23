//! zix HTTP/3 1-RTT response framing (RFC 9114).
//!
//! What:
//! - Builds the QUIC 1-RTT payload for a minimal HTTP/3 response: opens the server control stream
//!   with a SETTINGS frame (required first frame, RFC 9114 6.2.1), and sends a HEADERS frame
//!   (`:status`, QPACK-encoded) plus a DATA frame (the body) on the request stream with FIN.
//! - The response uses only the QPACK static table (no dynamic table), so the field section prefix
//!   is Required Insert Count 0 / Base 0 (two zero bytes).

const std = @import("std");

const varint = @import("varint.zig");
const qpack = @import("qpack.zig");

/// The server-initiated unidirectional control stream id (RFC 9000 2.1: server uni ids are 3, 7, ...).
const server_control_stream: u64 = 3;

/// The content coding a handler selected for its response body. `identity` emits no `content-encoding`
/// field. `gzip` / `br` are the two the QPACK static table carries as single indexed field lines
/// (RFC 9204 Appendix A: 43 `content-encoding: gzip`, 42 `content-encoding: br`), so serving a
/// pre-compressed body costs one extra header byte on the wire.
pub const ContentEncoding = enum { identity, gzip, br };

/// Emit the `content-encoding` field for `enc` as a QPACK indexed static field line, or nothing for
/// identity. Returns the bytes written (0 for identity).
fn contentEncodingFieldLine(out: []u8, enc: ContentEncoding) usize {
    const index: u64 = switch (enc) {
        .identity => return 0,
        .br => 42,
        .gzip => 43,
    };

    return qpack.encodeStaticIndexedFieldLine(out, index);
}

/// Write a STREAM frame (RFC 9000 19.8) at offset 0 with an explicit length. `fin` sets the FIN bit.
///
/// Return:
/// - true when the frame was written
/// - false when it does not fit in `out` from `pos` (nothing is written, `pos` is unchanged)
/// Public so the dispatch loop can pack several response stream frames into one coalesced 1-RTT packet.
pub fn writeStreamFrame(out: []u8, pos: *usize, stream_id: u64, fin: bool, data: []const u8) bool {
    const frame_len = 1 + varint.encodedLen(stream_id) + varint.encodedLen(data.len) + data.len;
    if (pos.* + frame_len > out.len) return false;

    out[pos.*] = 0x0a | @as(u8, if (fin) 0x01 else 0); // STREAM (0x08) | LEN (0x02) | optional FIN
    pos.* += 1;
    pos.* += varint.write(out[pos.*..], stream_id);
    pos.* += varint.write(out[pos.*..], data.len);
    @memcpy(out[pos.*..][0..data.len], data);
    pos.* += data.len;

    return true;
}

/// The static entry whose name is `:status`, borrowed when a status has no entry of its own.
const status_name_index: u64 = 24;

/// The QPACK field line for a `:status` value: one indexed byte for a status the static table carries
/// (RFC 9204 Appendix A entries 24..28), otherwise a literal field line spelling the status out.
///
/// Note:
/// - The literal form is what keeps every other status honest. An unlisted status used to fall back
///   to the index for 200, so a 413 or a 500 reached the client as a success.
fn statusFieldLine(out: []u8, status: u16) usize {
    const index: u64 = switch (status) {
        103 => 24,
        200 => 25,
        304 => 26,
        404 => 27,
        503 => 28,
        else => {
            var digits: [3]u8 = undefined;
            const text = std.fmt.bufPrint(&digits, "{d}", .{clampStatus(status)}) catch unreachable;

            return qpack.encodeStaticLiteralNameRef(out, status_name_index, text);
        },
    };

    return qpack.encodeStaticIndexedFieldLine(out, index);
}

/// Keep a status inside the three digits HTTP defines (RFC 9110 15), so the literal form above always
/// fits the buffer it writes into. A handler that sets something outside the range sends 500.
fn clampStatus(status: u16) u16 {
    return if (status >= 100 and status <= 599) status else 500;
}

/// Build the response content for the request stream: a HEADERS frame carrying `:status`, then a DATA
/// frame carrying the body (RFC 9114 7.2.1 / 7.2.2).
///
/// Return:
/// - usize (the number of bytes written)
/// - null when the content does not fit in `out` (a body too large for one packet, the caller then
///   registers it as a multi-packet send stream)
pub fn buildRequestStreamContent(out: []u8, status: u16, content_encoding: ContentEncoding, body: []const u8) ?usize {
    // HEADERS frame: type 0x01, length, then the field section (RIC 0, Base 0, indexed :status, and an
    // optional indexed content-encoding).
    var fields: [16]u8 = undefined;
    var fp: usize = 0;
    fields[fp] = 0x00; // Required Insert Count 0
    fp += 1;
    fields[fp] = 0x00; // Base 0
    fp += 1;
    fp += statusFieldLine(fields[fp..], status);
    fp += contentEncodingFieldLine(fields[fp..], content_encoding);

    const headers_len = 1 + varint.encodedLen(fp) + fp;
    const data_len = 1 + varint.encodedLen(body.len) + body.len;
    if (headers_len + data_len > out.len) return null;

    var pos: usize = 0;
    out[pos] = 0x01; // HEADERS frame type
    pos += 1;
    pos += varint.write(out[pos..], fp);
    @memcpy(out[pos..][0..fp], fields[0..fp]);
    pos += fp;

    // DATA frame: type 0x00, length, body.
    out[pos] = 0x00; // DATA frame type
    pos += 1;
    pos += varint.write(out[pos..], body.len);
    @memcpy(out[pos..][0..body.len], body);
    pos += body.len;

    return pos;
}

/// Build the HTTP/3 response stream prefix: the HEADERS frame (`:status`) plus the DATA frame header
/// (type + body length) that the body bytes follow. The body itself is not copied here: a large body
/// is streamed straight out of the handler's slice, so only this short prefix is materialized.
///
/// Return:
/// - usize (the prefix length written into `out`)
/// - null when the prefix does not fit in `out`
pub fn buildStreamPrefix(out: []u8, status: u16, content_encoding: ContentEncoding, body_len: usize) ?usize {
    var fields: [16]u8 = undefined;
    var fp: usize = 0;
    fields[fp] = 0x00; // Required Insert Count 0
    fp += 1;
    fields[fp] = 0x00; // Base 0
    fp += 1;
    fp += statusFieldLine(fields[fp..], status);
    fp += contentEncodingFieldLine(fields[fp..], content_encoding);

    const headers_len = 1 + varint.encodedLen(fp) + fp;
    const data_header_len = 1 + varint.encodedLen(body_len);
    if (headers_len + data_header_len > out.len) return null;

    var pos: usize = 0;
    out[pos] = 0x01; // HEADERS frame type
    pos += 1;
    pos += varint.write(out[pos..], fp);
    @memcpy(out[pos..][0..fp], fields[0..fp]);
    pos += fp;

    out[pos] = 0x00; // DATA frame type
    pos += 1;
    pos += varint.write(out[pos..], body_len);

    return pos;
}

/// Build an ACK-only 1-RTT payload acknowledging packets 0..largest (RFC 9000 19.3): one contiguous
/// range. Returns 0 when there is nothing to acknowledge.
pub fn buildAck(out: []u8, ack_largest: ?u64) usize {
    const largest = ack_largest orelse return 0;

    const ack_len = 1 + varint.encodedLen(largest) + 1 + 1 + varint.encodedLen(largest);
    if (ack_len > out.len) return 0;

    var pos: usize = 0;
    out[pos] = 0x02; // ACK frame type
    pos += 1;
    pos += varint.write(out[pos..], largest); // Largest Acknowledged
    pos += varint.write(out[pos..], 0); // ACK Delay
    pos += varint.write(out[pos..], 0); // ACK Range Count
    pos += varint.write(out[pos..], largest); // First ACK Range (largest down to 0)

    return pos;
}

/// Build an ACK frame (RFC 9000 19.3) from a received-packet window: Largest Acknowledged plus the First
/// ACK Range and any (Gap, ACK Range Length) pairs the window's holes imply, so the client detects and
/// retransmits a lost request packet instead of stalling on it. `mask` bit i set means (largest - i) was
/// received, bit 0 is largest (always set). Returns 0 when nothing fits (nothing written).
pub fn buildAckRanges(out: []u8, largest: u64, mask: u64) usize {
    if (mask & 1 == 0 or out.len < 32) return 0;

    var pos: usize = 0;
    out[pos] = 0x02; // ACK frame type
    pos += 1;
    pos += varint.write(out[pos..], largest); // Largest Acknowledged
    pos += varint.write(out[pos..], 0); // ACK Delay

    // Range Count is patched in after the walk. One byte holds it: a 64-bit window has at most 31 ranges.
    const range_count_pos = pos;
    pos += 1;

    // First ACK Range: contiguous received packets immediately below largest.
    var bit: usize = 1;
    var first_range: u64 = 0;
    while (bit < 64 and (mask >> @intCast(bit)) & 1 == 1) : (bit += 1) first_range += 1;
    pos += varint.write(out[pos..], first_range);

    // Additional ranges: a gap of unreceived packets, then a run of received ones.
    var range_count: u64 = 0;
    while (bit < 64) {
        var gap: u64 = 0;
        while (bit < 64 and (mask >> @intCast(bit)) & 1 == 0) : (bit += 1) gap += 1;
        if (bit >= 64) break;

        var run: u64 = 0;
        while (bit < 64 and (mask >> @intCast(bit)) & 1 == 1) : (bit += 1) run += 1;

        if (pos + 16 > out.len) break;
        pos += varint.write(out[pos..], gap - 1); // Gap encodes (unacked - 1)
        pos += varint.write(out[pos..], run - 1); // ACK Range Length encodes (acked - 1)
        range_count += 1;
    }

    out[range_count_pos] = @intCast(range_count);

    return pos;
}

/// Build a MAX_STREAMS frame for bidirectional streams (RFC 9000 19.11, type 0x12): raise the
/// cumulative number of client-initiated bidi (request) streams the peer may open. A connection
/// advertises a one-time allowance in the handshake, so without periodic MAX_STREAMS the client stalls
/// once it is spent. Returns 0 when the frame does not fit in `out` (nothing is written).
pub fn buildMaxStreams(out: []u8, max_streams: u64) usize {
    const frame_len = 1 + varint.encodedLen(max_streams);
    if (frame_len > out.len) return 0;

    out[0] = 0x12; // MAX_STREAMS (bidirectional)
    var pos: usize = 1;
    pos += varint.write(out[pos..], max_streams);

    return pos;
}

/// Build a MAX_DATA frame (RFC 9000 19.9, type 0x10): raise the cumulative connection-wide byte
/// budget the peer may send across all its streams. The handshake advertises a one-time
/// initial_max_data, so without periodic MAX_DATA the client stalls for good once it has sent that
/// many request bytes, however many stream credits it still holds. Returns 0 when the frame does not
/// fit in `out` (nothing is written).
pub fn buildMaxData(out: []u8, max_data: u64) usize {
    const frame_len = 1 + varint.encodedLen(max_data);
    if (frame_len > out.len) return 0;

    out[0] = 0x10; // MAX_DATA
    var pos: usize = 1;
    pos += varint.write(out[pos..], max_data);

    return pos;
}

/// Build a MAX_STREAM_DATA frame (RFC 9000 19.10, type 0x11): raise the cumulative byte budget the
/// peer may send on one stream. The handshake advertises a one-time initial_max_stream_data, so a
/// client uploading more than that on a single request stream blocks for good without this: it waits
/// for credit while the server waits for the rest of the request, and neither moves. Returns 0 when
/// the frame does not fit in `out` (nothing is written).
///
/// Param:
/// out - []u8 (destination)
/// stream_id - u64 (the stream being extended)
/// max_stream_data - u64 (the new cumulative limit, an absolute offset, not an increment)
///
/// Return:
/// - usize (bytes written, 0 when it does not fit)
pub fn buildMaxStreamData(out: []u8, stream_id: u64, max_stream_data: u64) usize {
    const frame_len = 1 + varint.encodedLen(stream_id) + varint.encodedLen(max_stream_data);
    if (frame_len > out.len) return 0;

    out[0] = 0x11; // MAX_STREAM_DATA
    var pos: usize = 1;
    pos += varint.write(out[pos..], stream_id);
    pos += varint.write(out[pos..], max_stream_data);

    return pos;
}

/// Which one-shot and terminal frames a response packet carries around the request-stream content.
///
/// Note:
/// - `handshake_done` and `control` belong on the first 1-RTT response of a connection only. The
///   server control stream (SETTINGS) and HANDSHAKE_DONE are sent once. Later per-stream responses
///   leave both false so they carry just the ACK and the request-stream HEADERS / DATA.
pub const Framing = struct {
    handshake_done: bool = true,
    control: bool = true,
    close: bool = false,
    /// When set, a MAX_STREAMS (bidi) frame raising the client's request-stream credit to this
    /// cumulative value rides this packet (RFC 9000 19.11). Set only when replenishment is due.
    max_streams_bidi: ?u64 = null,
    /// When set, a MAX_DATA frame raising the client's connection-wide byte budget to this
    /// cumulative value rides this packet (RFC 9000 19.9). Set only when replenishment is due.
    max_data: ?u64 = null,
};

/// Build the full 1-RTT payload (QUIC frames) for one HTTP/3 response on `stream_id`.
///
/// Param:
/// out - []u8 (destination for the frame payload, sealed into a 1-RTT packet by the caller)
/// stream_id - u64 (the client bidi stream the request arrived on, the response uses the same id)
/// status - u16 (the HTTP status code)
/// body - []const u8 (the response body)
/// ack_largest - ?u64 (largest client 1-RTT packet number to acknowledge, or null for no ACK)
/// framing - Framing (which one-shot / terminal frames to include)
///
/// Return:
/// - usize (the number of bytes written)
/// - null when the response does not fit in `out` (the v1 single-packet limit, caller falls back)
///
/// Note:
/// - Umbrella builder, exercised by the tests below. The live serve path composes the lower-level
///   builders (buildAck / buildStreamPrefix / writeStreamFrame / buildMaxStreams) directly.
pub fn buildResponse(out: []u8, stream_id: u64, status: u16, body: []const u8, ack_largest: ?u64, framing: Framing) ?usize {
    // ACK the client's 1-RTT packets so it stops retransmitting (RFC 9000 19.3).
    var pos: usize = buildAck(out, ack_largest);

    // HANDSHAKE_DONE (RFC 9001 7.5): confirm the handshake to the client so it finalizes the
    // connection rather than waiting. First response of the connection only.
    if (framing.handshake_done) {
        if (pos + 1 > out.len) return null;
        out[pos] = 0x1e;
        pos += 1;
    }

    // Server control stream: the stream type (0x00) followed by an empty SETTINGS frame (0x04, 0).
    if (framing.control) {
        const control_content = [_]u8{ 0x00, 0x04, 0x00 };
        if (!writeStreamFrame(out, &pos, server_control_stream, false, &control_content)) return null;
    }

    // MAX_STREAMS (RFC 9000 19.11): extend the client's request-stream credit so a long-lived
    // connection does not stall once its one-time handshake allowance is spent. Rides this packet only
    // when replenishment is due.
    if (framing.max_streams_bidi) |max_streams| {
        const written = buildMaxStreams(out[pos..], max_streams);
        if (written == 0) return null;

        pos += written;
    }

    // MAX_DATA (RFC 9000 19.9): extend the client's connection-wide byte budget so a long-lived
    // connection does not stall once the one-time initial_max_data is spent. Rides this packet only
    // when replenishment is due.
    if (framing.max_data) |max_data| {
        const written = buildMaxData(out[pos..], max_data);
        if (written == 0) return null;

        pos += written;
    }

    // The response on the request stream, with FIN. The umbrella builder serves identity: a
    // content-encoded body is composed through buildRequestStreamContent / buildStreamPrefix directly.
    var content: [1024]u8 = undefined;
    const content_len = buildRequestStreamContent(&content, status, .identity, body) orelse return null;
    if (!writeStreamFrame(out, &pos, stream_id, true, content[0..content_len])) return null;

    // Application CONNECTION_CLOSE (RFC 9000 19.19, type 0x1d): H3_NO_ERROR with an empty reason, so
    // the client finalizes the connection after the response instead of waiting.
    if (framing.close) {
        const close_len = 1 + varint.encodedLen(0x0100) + varint.encodedLen(0);
        if (pos + close_len > out.len) return null;

        out[pos] = 0x1d; // CONNECTION_CLOSE (application)
        pos += 1;
        pos += varint.write(out[pos..], 0x0100); // H3_NO_ERROR
        pos += varint.write(out[pos..], 0); // Reason Phrase Length
    }

    return pos;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: response carries control SETTINGS and a HEADERS/DATA reply" {
    var out: [1024]u8 = undefined;
    const len = buildResponse(&out, 0, 200, "hi", null, .{}).?;
    const payload = out[0..len];

    // HANDSHAKE_DONE, then a STREAM frame on the server control stream (id 3) carrying the control
    // type + SETTINGS.
    try std.testing.expectEqual(@as(u8, 0x1e), payload[0]); // HANDSHAKE_DONE
    try std.testing.expectEqual(@as(u8, 0x0a), payload[1]); // STREAM, LEN, no FIN
    try std.testing.expectEqual(@as(u8, 3), payload[2]); // stream id 3
    try std.testing.expectEqual(@as(u8, 3), payload[3]); // content length 3
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x00 }, payload[4..7]);

    // Then a STREAM frame on stream 0 with FIN, containing HEADERS (:status 200 = 0xd9) and DATA.
    try std.testing.expectEqual(@as(u8, 0x0b), payload[7]); // STREAM, LEN, FIN
    try std.testing.expect(std.mem.indexOf(u8, payload, &[_]u8{ 0x01, 0x03, 0x00, 0x00, 0xd9 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "hi") != null);
}

test "zix http3: response with ack and close carries both frames" {
    var out: [1024]u8 = undefined;
    const len = buildResponse(&out, 0, 200, "hi", 3, .{ .close = true }).?;
    const payload = out[0..len];

    // Leads with an ACK frame: type 0x02, largest 3, delay 0, range count 0, first range 3.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x03, 0x00, 0x00, 0x03 }, payload[0..5]);

    // Ends with an application CONNECTION_CLOSE (0x1d) carrying H3_NO_ERROR (0x0100 = varint 4100).
    try std.testing.expect(std.mem.indexOf(u8, payload, &[_]u8{ 0x1d, 0x41, 0x00, 0x00 }) != null);
}

test "zix http3: buildAckRanges reports holes so the client retransmits the lost packet" {
    var out: [64]u8 = undefined;

    // 0..5 all received (largest 5): one contiguous range, no gaps. First ACK Range 5, range count 0.
    const contiguous = buildAckRanges(&out, 5, 0b111111);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x05, 0x00, 0x00, 0x05 }, out[0..contiguous]);

    // Packet 4 missing (largest 5, bit 1 clear): first range 0 (just 5), then one range with gap 0
    // (one unacked, packet 4) and length 3 (packets 3,2,1,0). The gap is what makes the client resend 4.
    const holed = buildAckRanges(&out, 5, 0b111101);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03 }, out[0..holed]);

    // Only the largest in the window: range count 0, first range 0.
    const lone = buildAckRanges(&out, 9, 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x09, 0x00, 0x00, 0x00 }, out[0..lone]);
}

test "zix http3: buildMaxStreams encodes a bidi MAX_STREAMS frame, buildResponse rides it" {
    // The frame is type 0x12 then the cumulative limit as a varint (192 = 0x40c0 two-byte varint).
    var frame: [8]u8 = undefined;
    const len = buildMaxStreams(&frame, 192);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x40, 0xc0 }, frame[0..len]);

    // A small destination that cannot hold the frame reports 0 and writes nothing.
    var tiny: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), buildMaxStreams(&tiny, 192));

    // A response with max_streams_bidi set carries the 0x12 frame, a lean response without it does not.
    var out: [1024]u8 = undefined;
    const with = buildResponse(&out, 4, 200, "hi", null, .{ .handshake_done = false, .control = false, .max_streams_bidi = 192 }).?;
    try std.testing.expect(std.mem.indexOf(u8, out[0..with], &[_]u8{ 0x12, 0x40, 0xc0 }) != null);

    var out2: [1024]u8 = undefined;
    const without = buildResponse(&out2, 4, 200, "hi", null, .{ .handshake_done = false, .control = false }).?;
    try std.testing.expect(std.mem.indexOf(u8, out2[0..without], &[_]u8{0x12}) == null);
}

test "zix http3: buildMaxData encodes a MAX_DATA frame, buildResponse rides it" {
    // The frame is type 0x10 then the cumulative byte limit as a varint (192 = 0x40c0 two-byte varint).
    var frame: [8]u8 = undefined;
    const len = buildMaxData(&frame, 192);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0x40, 0xc0 }, frame[0..len]);

    // A small destination that cannot hold the frame reports 0 and writes nothing.
    var tiny: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), buildMaxData(&tiny, 192));

    // A response with max_data set carries the 0x10 frame, a lean response without it does not.
    var out: [1024]u8 = undefined;
    const with = buildResponse(&out, 4, 200, "hi", null, .{ .handshake_done = false, .control = false, .max_data = 192 }).?;
    try std.testing.expect(std.mem.indexOf(u8, out[0..with], &[_]u8{ 0x10, 0x40, 0xc0 }) != null);

    var out2: [1024]u8 = undefined;
    const without = buildResponse(&out2, 4, 200, "hi", null, .{ .handshake_done = false, .control = false }).?;
    try std.testing.expect(std.mem.indexOf(u8, out2[0..without], &[_]u8{0x10}) == null);
}

test "zix http3: a body larger than the buffer returns null, never overflows" {
    // A body that cannot fit the single-packet buffer must report null, not write past `out`.
    var big: [4096]u8 = undefined;
    @memset(&big, 'x');

    var out: [2048]u8 = undefined;
    try std.testing.expect(buildResponse(&out, 0, 200, &big, null, .{}) == null);

    // The content builder reports the same overflow against its own destination.
    var content: [1024]u8 = undefined;
    try std.testing.expect(buildRequestStreamContent(&content, 200, .identity, &big) == null);

    // A body that just fits is still built.
    var small: [16]u8 = undefined;
    @memset(&small, 'y');
    try std.testing.expect(buildResponse(&out, 0, 200, &small, null, .{}) != null);
}

test "zix http3: lean framing carries only the request stream, no HANDSHAKE_DONE or control" {
    var out: [1024]u8 = undefined;
    const len = buildResponse(&out, 4, 200, "hi", null, .{ .handshake_done = false, .control = false }).?;
    const payload = out[0..len];

    // No HANDSHAKE_DONE (0x1e) and no control stream (id 3) frame: the first byte is the request
    // STREAM frame with FIN (0x0b) on stream 4.
    try std.testing.expectEqual(@as(u8, 0x0b), payload[0]); // STREAM, LEN, FIN
    try std.testing.expectEqual(@as(u8, 4), payload[1]); // stream id 4
    try std.testing.expect(std.mem.indexOf(u8, payload, &[_]u8{0x1e}) == null);
}

test "zix http3: buildStreamPrefix emits HEADERS then a DATA header sized to the body" {
    var out: [32]u8 = undefined;
    const len = buildStreamPrefix(&out, 200, .identity, 200000).?;
    const prefix = out[0..len];

    // HEADERS frame: type 0x01, length 3, RIC 0, Base 0, :status 200 (0xd9).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x03, 0x00, 0x00, 0xd9 }, prefix[0..5]);

    // DATA frame header: type 0x00 then the body length as a varint (200000 = 0x80030d40).
    try std.testing.expectEqual(@as(u8, 0x00), prefix[5]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x03, 0x0d, 0x40 }, prefix[6..10]);
}

test "zix http3: content-encoding rides the HEADERS frame as one indexed field line" {
    // A brotli-coded streamed body: the field section gains one byte (0xea = static index 42,
    // content-encoding: br), so the HEADERS frame length is 4 and :status is followed by 0xea.
    var out: [32]u8 = undefined;
    const br_len = buildStreamPrefix(&out, 200, .br, 200000).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x04, 0x00, 0x00, 0xd9, 0xea }, out[0..6]);
    try std.testing.expect(br_len > 6); // followed by the DATA frame header

    // A gzip-coded single-packet body: the field section carries 0xeb (static index 43,
    // content-encoding: gzip) after :status, then the DATA frame with the body.
    var content: [64]u8 = undefined;
    const clen = buildRequestStreamContent(&content, 200, .gzip, "hi").?;
    const packed_content = content[0..clen];
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x04, 0x00, 0x00, 0xd9, 0xeb }, packed_content[0..6]);
    try std.testing.expect(std.mem.indexOf(u8, packed_content, "hi") != null);

    // identity keeps the lean 3-byte field section (no content-encoding line).
    const id_len = buildStreamPrefix(&out, 200, .identity, 200000).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x03, 0x00, 0x00, 0xd9 }, out[0..5]);
    try std.testing.expect(id_len < br_len); // identity prefix is one byte shorter
}

/// The field section out of a built request-stream response: the bytes after the HEADERS frame type
/// and its length.
fn fieldSection(content: []const u8) []const u8 {
    return content[2 .. 2 + content[1]];
}

test "zix http3: a status with no static entry goes out as itself, never as 200" {
    // The failure this pins: an unlisted status used to fall back to the indexed field line for 200,
    // so a client read a 413 or a 500 as a success and parsed the error text as the answer.
    var content: [64]u8 = undefined;
    const len = buildRequestStreamContent(&content, 413, .identity, "").?;
    const fields = fieldSection(content[0..len]);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, fields[0..2]);

    const literal = try qpack.decodeLiteralNameRef(fields[2..]);
    try std.testing.expect(literal.static);
    try std.testing.expect(!literal.huffman);
    try std.testing.expectEqualStrings(":status", qpack.staticEntry(literal.name_index).?.name);
    try std.testing.expectEqualStrings("413", literal.value);
}

test "zix http3: the statuses the static table carries stay one indexed byte" {
    // The literal form above must not cost the common answers anything: 200 and 404 are still a
    // single byte each, which is what keeps the response prefix lean.
    var content: [64]u8 = undefined;

    const ok_len = buildRequestStreamContent(&content, 200, .identity, "").?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0xd9 }, fieldSection(content[0..ok_len]));

    const missing_len = buildRequestStreamContent(&content, 404, .identity, "").?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0xdb }, fieldSection(content[0..missing_len]));
}

test "zix http3: a status outside the HTTP range is sent as 500 rather than as three wrong digits" {
    var content: [64]u8 = undefined;
    const len = buildRequestStreamContent(&content, 9999, .identity, "").?;

    const literal = try qpack.decodeLiteralNameRef(fieldSection(content[0..len])[2..]);
    try std.testing.expectEqualStrings("500", literal.value);
}

test "zix http3: buildStreamPrefix spells an unlisted status out the same way" {
    // The multi-packet path builds its own field section, so it needs the same fix: a large body
    // answered 413 must not reach the client as a 200 with the body attached.
    var out: [64]u8 = undefined;
    const len = buildStreamPrefix(&out, 413, .identity, 200000).?;

    const literal = try qpack.decodeLiteralNameRef(fieldSection(out[0..len])[2..]);
    try std.testing.expectEqualStrings("413", literal.value);
}

test "zix http3: buildMaxStreamData raises one stream's budget, and refuses to overflow" {
    var out: [16]u8 = undefined;

    // Type 0x11, stream 0, limit 300000 (a 4-byte varint: 0x80 0x04 0x93 0xe0).
    const len = buildMaxStreamData(&out, 0, 300000);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x00, 0x80, 0x04, 0x93, 0xe0 }, out[0..len]);

    var tiny: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), buildMaxStreamData(&tiny, 0, 300000));
}

test "zix http3: writeStreamFrame refuses a frame that would overflow the buffer" {
    var out: [8]u8 = undefined;
    var pos: usize = 0;
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    try std.testing.expect(!writeStreamFrame(&out, &pos, 0, true, &data));
    try std.testing.expectEqual(@as(usize, 0), pos); // nothing written, pos unchanged
}
