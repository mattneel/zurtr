//! zix HTTP/3 request decode: pull the request head out of a decrypted 1-RTT payload.
//!
//! What:
//! - Walks the QUIC frames in the payload, finds the client request stream (a client-initiated bidi
//!   stream), parses its HTTP/3 HEADERS frame, and QPACK-decodes the pseudo-headers and the fields
//!   around them from the static table and literal-with-name-reference representations: :method,
//!   :path, :protocol (the extended CONNECT signal, RFC 9220), accept-encoding and origin
//!   (RFC 9114 / RFC 9204).
//! - Pseudo-headers precede regular fields, so the header decode returns as soon as the fields it
//!   needs are found and never has to understand the rest of the header block.
//! - Keeps the DATA frames that follow HEADERS on the same stream as the request body, plus the two
//!   facts a handler needs to trust it: how many body bytes the stream carried, and whether the
//!   client had finished sending.
//! - Walks the client-initiated unidirectional streams of the payload the same way
//!   (`parseUniPieces`), which is how the WebTransport binding sees the data streams a client opens.

const std = @import("std");

const varint = @import("varint.zig");
const qpack = @import("qpack.zig");
const huffman = @import("huffman.zig");

/// The decoded request head: the request line, plus the fields the layers above serve on and the body
/// when the bytes carried one. Slices point into the payload (or into a Huffman-decode buffer).
pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    path_huffman: bool = false,
    /// The value of the `:protocol` pseudo-header, or empty when the request carried none. The
    /// WebTransport binding needs it to recognise an extended CONNECT (RFC 9220 4): a CONNECT carrying
    /// `:protocol` is a tunnel, and the token is what names the protocol to run inside it. Empty means
    /// not an extended CONNECT, and it stays empty when the client spells the name in a way this
    /// decoder cannot read.
    protocol: []const u8 = "",
    protocol_huffman: bool = false,
    /// The value of the `:authority` pseudo-header (the request target host), or empty when the client
    /// sent none. An extended CONNECT always carries one (RFC 9114 4.3.1), and the binding hands it to
    /// the application as the host the session asked for.
    authority: []const u8 = "",
    authority_huffman: bool = false,
    /// The client's `accept-encoding` value, or empty when absent. Set from the QPACK static entry 31
    /// (`gzip, deflate, br`) for the indexed form, or from the literal value for a custom one. When
    /// `accept_encoding_huffman` is set the value is still Huffman-encoded and the serve path expands it.
    accept_encoding: []const u8 = "",
    accept_encoding_huffman: bool = false,
    /// The RFC 6454 `origin` field value, or empty when the client sent none. The WebTransport binding
    /// reads an absent Origin as "not a browser client" and validates the one a browser sends, so an
    /// empty value is a statement about the client, not a decode failure.
    origin: []const u8 = "",
    origin_huffman: bool = false,
    /// The request body, empty when the request carried none. It points into the bytes it was decoded
    /// from, so nothing is copied and the slice lives exactly as long as the fields above do.
    /// `decodeAssembledRequest` joins every DATA frame into it. The read-only decodes carry only the
    /// first, since they cannot move bytes they do not own.
    body: []const u8 = "",
    /// Every DATA byte this stream carried, HTTP/3 framing excluded. It exceeds `body.len` when the
    /// client split its body over several DATA frames and the decode could not join them: the two
    /// together are what tell a partial body from a whole one.
    body_received: u64 = 0,
    /// Whether `body` is the whole request body. True needs all three: the frame walk reached the end
    /// of the stream data cleanly, every counted DATA byte sits inside `body`, and the STREAM frame
    /// ended the stream (FIN) with nothing before it (offset 0).
    body_complete: bool = false,
};

/// A decoded request paired with the client bidi stream it arrived on, so the response goes back on
/// the same stream (RFC 9114 6.1).
pub const StreamRequest = struct {
    stream_id: u64,
    request: DecodedRequest,
};

/// One client request-stream STREAM frame out of a payload, with what it turned out to hold.
///
/// Note:
/// - `request` is set when the bytes start with a HEADERS frame this decode understands, which makes
///   them the head of a request. It is null for a continuation: the body of a request whose head
///   arrived in an earlier packet, which only means something once the two are joined.
pub const StreamPiece = struct {
    stream_id: u64,
    /// Where these bytes sit in the stream. Non-zero means bytes were sent on it before.
    offset: u64,
    /// Whether the frame ends the stream, so the client has sent everything.
    fin: bool,
    /// The raw stream bytes, as HTTP/3 frames.
    data: []const u8,
    request: ?DecodedRequest,
};

/// One client-initiated unidirectional stream frame out of a decrypted 1-RTT payload.
///
/// Note:
/// - The bytes are handed over as they arrived, stream type varint and all: a client can open a uni
///   stream before this layer knows what it is for (a WebTransport data stream, a control stream), and
///   only the caller's own stream registry can say whether the type is one it accepts.
pub const UniPiece = struct {
    stream_id: u64,
    /// Where these bytes sit in the stream. Non-zero means bytes were sent on it before.
    offset: u64,
    /// Whether the frame ends the stream (the peer sent everything on it).
    fin: bool,
    /// The stream bytes as they arrived (the stream type varint is at their start when offset is 0).
    data: []const u8,
};

/// The most request streams the server decodes from one packet, sized to hold a path-MTU 1-RTT packet
/// densely packed with small requests. The packet is acknowledged whole, so any request left undecoded
/// would be dropped-but-acked and its stream would stall.
pub const max_requests_per_packet = 96;

/// Find and decode the request from a decrypted 1-RTT payload. Returns null if no request HEADERS are
/// present (for example a packet that only carries ACK / control-stream frames).
///
/// Note:
/// - A 1-RTT request packet typically leads with frames this module does not need (ACK, and the
///   client's control / QPACK stream setup). It walks past every frame it does not model, scanning
///   only for the client request stream, so an unmodeled frame is skipped rather than fatal.
pub fn parseRequest(payload: []const u8) ?DecodedRequest {
    var one: [1]StreamRequest = undefined;
    if (parseRequests(payload, &one) == 0) return null;

    return one[0].request;
}

/// Decode every client request stream in a decrypted 1-RTT payload, in arrival order, capturing the
/// stream id of each. A connection multiplexes many requests, each on its own client-initiated bidi
/// stream, and one packet can coalesce several. The scan walks past every non-request frame.
///
/// Param:
/// payload - []const u8 (the decrypted 1-RTT payload)
/// out - []StreamRequest (destination, decoding stops once it is full)
///
/// Return:
/// - usize (the number of request streams decoded into `out`)
pub fn parseRequests(payload: []const u8, out: []StreamRequest) usize {
    var pieces: [max_requests_per_packet]StreamPiece = undefined;
    const limit = @min(out.len, pieces.len);
    const piece_count = parseStreamPieces(payload, pieces[0..limit]);

    var count: usize = 0;
    for (pieces[0..piece_count]) |piece| {
        const decoded = piece.request orelse continue;

        out[count] = .{ .stream_id = piece.stream_id, .request = decoded };
        count += 1;
    }

    return count;
}

/// Walk every client request-stream STREAM frame in a decrypted 1-RTT payload, in arrival order,
/// decoding the ones that carry a request head. The scan walks past every non-STREAM frame.
///
/// Note:
/// - This is what the serve path uses, because a request with a body does not arrive whole: a client
///   commonly sends its HEADERS frame in one packet and its DATA frame in the next, and the second
///   frame decodes to no request at all on its own. Handing back both kinds lets the caller join them.
///
/// Param:
/// payload - []const u8 (the decrypted 1-RTT payload)
/// out - []StreamPiece (destination, the walk stops once it is full)
///
/// Return:
/// - usize (the number of pieces written into `out`)
pub fn parseStreamPieces(payload: []const u8, out: []StreamPiece) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < payload.len and count < out.len) {
        const type_vi = varint.read(payload[pos..]) catch break;

        if (isStreamFrameType(type_vi.value)) {
            const stream = parseStreamFrame(payload[pos..]) orelse break;

            // A client-initiated bidi stream (id mod 4 == 0) carries a request (RFC 9000 2.1).
            if (stream.id & 0x03 == 0) {
                // A head only decodes at the start of the stream. Past that the bytes are a body,
                // which is a continuation whatever they happen to look like.
                const at_start = stream.offset == 0;
                out[count] = .{
                    .stream_id = stream.id,
                    .offset = stream.offset,
                    .fin = stream.fin,
                    .data = stream.data,
                    .request = if (at_start) decodeStreamRequest(stream.data, stream.fin) else null,
                };
                count += 1;
            }

            pos += stream.consumed;
            continue;
        }

        // A frame this module does not need (ACK, MAX_DATA, NEW_CONNECTION_ID, ...). Skip it.
        const skipped = skipFrame(payload[pos..]) orelse break;
        pos += skipped;
    }

    return count;
}

/// Walk every client-initiated unidirectional stream frame in a decrypted 1-RTT payload, in arrival
/// order (RFC 9000 2.1: client unidirectional ids are 2 mod 4). The scan walks past every frame that
/// is not one of them and hands the others over without reading what their bytes say, so a control
/// stream frame, a QPACK stream frame and a WebTransport data stream frame all arrive here as they
/// are and the caller's own stream registry is what decides about their types.
///
/// Param:
/// payload - []const u8 (the decrypted 1-RTT payload)
/// out - []UniPiece (destination, the walk stops once it is full)
///
/// Return:
/// - usize (the number of pieces written into `out`)
pub fn parseUniPieces(payload: []const u8, out: []UniPiece) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < payload.len and count < out.len) {
        const type_vi = varint.read(payload[pos..]) catch break;

        if (isStreamFrameType(type_vi.value)) {
            const stream = parseStreamFrame(payload[pos..]) orelse break;

            // A client-initiated unidirectional stream (id mod 4 == 2) is a stream the client opened
            // (RFC 9000 2.1), which is what carries the streams a WebTransport session runs in.
            if (stream.id & 0x03 == 2) {
                out[count] = .{
                    .stream_id = stream.id,
                    .offset = stream.offset,
                    .fin = stream.fin,
                    .data = stream.data,
                };
                count += 1;
            }

            pos += stream.consumed;
            continue;
        }

        // A frame this module does not need (ACK, DATAGRAM, RESET_STREAM_AT, ...). Skip it.
        const skipped = skipFrame(payload[pos..]) orelse break;
        pos += skipped;
    }

    return count;
}

/// Decode a request out of the bytes of one request stream, from its start.
///
/// Note:
/// - Used for both shapes: the stream bytes of a single packet, and the bytes a caller reassembled
///   across packets. `ended` is what the caller knows about the client being finished (the FIN bit on
///   the last frame), and it is what a whole body ultimately depends on.
///
/// Param:
/// stream_data - []const u8 (request-stream bytes from offset 0, as HTTP/3 frames)
/// ended - bool (whether the client has ended the stream)
///
/// Return:
/// - DecodedRequest
/// - null when the bytes carry no HEADERS frame this decode understands
pub fn decodeStreamRequest(stream_data: []const u8, ended: bool) ?DecodedRequest {
    var decoded = decodeRequestStream(stream_data) orelse return null;
    decoded.body_complete = decoded.body_complete and ended;

    return decoded;
}

/// Decode a request out of a buffer the caller owns, joining its DATA frames into one body.
///
/// Note:
/// - Same decode as `decodeStreamRequest`, with one difference that matters for anything larger than
///   a small upload: a client writes a long body as several DATA frames, and this joins their
///   payloads into a single slice instead of delivering the first and reporting the rest as missing.
/// - The join happens inside `stream_data`, so the caller must own those bytes. The reassembly pool
///   does, its slots are the worker's own. The decrypted packet payload does NOT: the serve path
///   walks it again afterwards for flow-control accounting, so that path uses `decodeStreamRequest`.
/// - Every payload moves backwards by at least the frame header it leaves behind (two bytes), so the
///   move never overwrites a byte the walk has not read yet.
///
/// Param:
/// stream_data - []u8 (request-stream bytes from offset 0, as HTTP/3 frames, owned by the caller)
/// ended - bool (whether the client has ended the stream)
///
/// Return:
/// - DecodedRequest (its `body` slices `stream_data`)
/// - null when the bytes carry no HEADERS frame this decode understands
pub fn decodeAssembledRequest(stream_data: []u8, ended: bool) ?DecodedRequest {
    var decoded: DecodedRequest = undefined;
    var have_headers = false;
    var walk = FrameWalk{ .total = stream_data.len };
    // Where a Huffman-coded field name is expanded. It is scratch: nothing decoded points into it.
    var name_scratch: [max_field_name_len]u8 = undefined;

    // Where the joined body starts, and where the next payload lands behind it.
    var body_start: usize = 0;
    var body_end: usize = 0;

    while (walk.next(stream_data)) |frame| {
        const is_data = frame.kind == 0x00;

        // A frame cut short, because the buffer filled before the client finished. Its bytes are
        // still body bytes when it is a DATA frame, so they are joined and counted like any other:
        // what makes the difference is that `walk.intact` has gone false, so nothing calls it whole.
        if (frame.cut and !(is_data and have_headers)) break;

        switch (frame.kind) {
            0x01 => { // HEADERS
                // A second field section is the trailers, which close the request (RFC 9114 4.1).
                if (have_headers) break;

                decoded = decodeHeaders(stream_data[frame.start..][0..frame.len], &name_scratch) orelse return null;
                have_headers = true;
            },
            0x00 => { // DATA
                // DATA before HEADERS is H3_FRAME_UNEXPECTED, and there is no request to attach it to.
                if (!have_headers) return null;

                if (decoded.body_received == 0) {
                    body_start = frame.start;
                    body_end = frame.start;
                }

                std.mem.copyForwards(u8, stream_data[body_end..][0..frame.len], stream_data[frame.start..][0..frame.len]);
                body_end += frame.len;
                decoded.body_received += frame.len;
            },
            else => {}, // A frame this decode does not model (a grease frame, a reserved type).
        }

        if (frame.cut) break;
    }

    if (!have_headers) return null;

    decoded.body = stream_data[body_start..body_end];
    decoded.body_complete = walk.intact and ended;

    return decoded;
}

/// Sum the STREAM-frame payload bytes in a decrypted 1-RTT payload, across every stream (bidi and
/// uni: connection-level flow control counts them all, RFC 9000 4.1). Feeds replenishMaxData so the
/// server keeps the client's MAX_DATA credit ahead of what it consumes.
pub fn streamBytes(payload: []const u8) u64 {
    var total: u64 = 0;
    var pos: usize = 0;

    while (pos < payload.len) {
        const type_vi = varint.read(payload[pos..]) catch break;

        if (isStreamFrameType(type_vi.value)) {
            const stream = parseStreamFrame(payload[pos..]) orelse break;
            total += stream.data.len;
            pos += stream.consumed;
            continue;
        }

        const skipped = skipFrame(payload[pos..]) orelse break;
        pos += skipped;
    }

    return total;
}

/// Whether a frame type is a STREAM frame (RFC 9000 19.8): 0x08..0x0f, OFF / LEN / FIN in the low bits.
pub fn isStreamFrameType(frame_type: u64) bool {
    return frame_type >= 0x08 and frame_type <= 0x0f;
}

pub const ParsedStream = struct {
    id: u64,
    data: []const u8,
    consumed: usize,
    /// Where `data` starts within the stream (RFC 9000 19.8 OFF bit). Zero means this frame carries the
    /// beginning of the stream, so nothing was sent on it before.
    offset: u64 = 0,
    /// Whether the frame ends the stream (the FIN bit): the peer sends nothing more on it.
    fin: bool = false,
};

/// Parse a STREAM frame, returning the stream id, the stream bytes, and how much of `buf` it used.
pub fn parseStreamFrame(buf: []const u8) ?ParsedStream {
    const frame_type = buf[0];
    var pos: usize = 1;

    const id = varint.read(buf[pos..]) catch return null;
    pos += id.len;

    var offset: u64 = 0;
    if (frame_type & 0x04 != 0) {
        const offset_vi = varint.read(buf[pos..]) catch return null;
        pos += offset_vi.len;
        offset = offset_vi.value;
    }

    const has_len = frame_type & 0x02 != 0;
    const length: usize = if (has_len) blk: {
        const len_vi = varint.read(buf[pos..]) catch return null;
        pos += len_vi.len;
        break :blk @intCast(len_vi.value);
    } else buf.len - pos;

    if (pos + length > buf.len) return null;

    return .{
        .id = id.value,
        .data = buf[pos .. pos + length],
        .consumed = pos + length,
        .offset = offset,
        .fin = frame_type & 0x01 != 0,
    };
}

/// Read `n` consecutive varints from `start`, returning the position after them, or null if any is
/// truncated.
fn skipVarints(buf: []const u8, start: usize, n: usize) ?usize {
    var pos = start;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const v = varint.read(buf[pos..]) catch return null;
        pos += v.len;
    }

    return pos;
}

/// Skip a varint length followed by that many bytes (CRYPTO data, NEW_TOKEN token, close reason).
fn skipLenBlob(buf: []const u8, start: usize) ?usize {
    const len = varint.read(buf[start..]) catch return null;
    const end = start + len.len + @as(usize, @intCast(len.value));

    return if (end <= buf.len) end else null;
}

/// Skip any non-STREAM QUIC frame (RFC 9000 19, plus the frames a WebTransport peer interleaves),
/// returning the bytes it occupied or null on a truncated / unknown frame. The scan needs this to walk
/// past everything a request packet coalesces ahead of the request stream (ACK, NEW_CONNECTION_ID,
/// MAX_STREAMS, and the rest).
///
/// Note:
/// - RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-09 3) aborts one of the peer's data
///   streams, and a QUIC DATAGRAM (RFC 9221 3) carries an HTTP datagram: both sit in the same packet
///   as a request stream, and both are skipped like any other frame this decode does not need.
/// - A DATAGRAM without a length field owns the rest of the packet (RFC 9221 3), so the skip runs to
///   the end of `buf` and nothing after it is read. A peer that puts anything behind such a frame has
///   sent it as that frame's data, which is why the walk ends there rather than looking for a frame.
pub fn skipFrame(buf: []const u8) ?usize {
    const type_vi = varint.read(buf) catch return null;
    const pos = type_vi.len;

    switch (type_vi.value) {
        0x00, 0x01, 0x1e => return pos, // PADDING, PING, HANDSHAKE_DONE
        0x02, 0x03 => { // ACK (0x03 adds ECN counts)
            var p = pos;
            const largest = varint.read(buf[p..]) catch return null;
            p += largest.len;
            const delay = varint.read(buf[p..]) catch return null;
            p += delay.len;
            const range_count = varint.read(buf[p..]) catch return null;
            p += range_count.len;
            const first = varint.read(buf[p..]) catch return null;
            p += first.len;

            var i: u64 = 0;
            while (i < range_count.value) : (i += 1) {
                p = skipVarints(buf, p, 2) orelse return null; // Gap, Range Length
            }
            if (type_vi.value == 0x03) p = skipVarints(buf, p, 3) orelse return null; // ECT0, ECT1, CE

            return p;
        },
        0x04 => return skipVarints(buf, pos, 3), // RESET_STREAM
        0x24 => return skipVarints(buf, pos, 4), // RESET_STREAM_AT: the same three fields, then the reliable size
        0x05, 0x11, 0x15 => return skipVarints(buf, pos, 2), // STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED
        0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19 => return skipVarints(buf, pos, 1), // MAX_DATA, MAX_STREAMS, *_BLOCKED, RETIRE_CONNECTION_ID
        0x06 => return skipLenBlob(buf, skipVarints(buf, pos, 1) orelse return null), // CRYPTO: offset then length + data
        0x07 => return skipLenBlob(buf, pos), // NEW_TOKEN: length + token
        0x18 => { // NEW_CONNECTION_ID: seq, retire, len(1), cid, reset token(16)
            const after = skipVarints(buf, pos, 2) orelse return null;
            if (after >= buf.len) return null;
            const cid_len = buf[after];
            const end = after + 1 + cid_len + 16;

            return if (end <= buf.len) end else null;
        },
        0x1a, 0x1b => return if (pos + 8 <= buf.len) pos + 8 else null, // PATH_CHALLENGE / PATH_RESPONSE
        0x1c, 0x1d => { // CONNECTION_CLOSE: error code, [frame type if 0x1c], reason length + reason
            var p = skipVarints(buf, pos, 1) orelse return null;
            if (type_vi.value == 0x1c) p = skipVarints(buf, p, 1) orelse return null;

            return skipLenBlob(buf, p);
        },
        0x30 => return buf.len, // DATAGRAM: no length, so the rest of the packet is this frame's data
        0x31 => return skipLenBlob(buf, pos), // DATAGRAM: a length, then that many bytes
        else => return null, // STREAM is handled by the caller, an unknown / grease frame stops the scan
    }
}

/// Parse the HTTP/3 frames of a request stream: the first HEADERS frame gives the request line, the
/// DATA frames after it give the body (RFC 9114 4.1).
///
/// Note:
/// - A malformed or truncated frame ends the walk instead of failing the request, once HEADERS is in
///   hand: the request line is real and answerable, the body is simply not whole, which
///   `body_complete` reports. Before HEADERS there is nothing to answer, so it stays a null.
/// - Only the first DATA frame is delivered as `body`, because separate frames are not adjacent in the
///   stream (each carries its own header) and joining them would need a copy. Every frame is still
///   counted into `body_received`, so a split body is detectable rather than silently short.
/// One HTTP/3 frame out of a request stream, given as offsets rather than a slice so a caller holding
/// the bytes as mutable can move payloads around while it reads them.
const Frame = struct {
    /// The HTTP/3 frame type (RFC 9114 7.2): 0x00 DATA, 0x01 HEADERS.
    kind: u64,
    /// Where the frame payload starts in the stream bytes.
    start: usize,
    /// Payload bytes present. For a cut frame this is what arrived, not what the frame declared.
    len: usize,
    /// Whether the frame ran past the bytes that arrived.
    cut: bool = false,
};

/// Walk the HTTP/3 frames of a request stream. Shared by both decodes so they agree on what a frame
/// is, what a cut frame is, and when the walk has stopped trusting the bytes.
const FrameWalk = struct {
    total: usize,
    pos: usize = 0,
    /// False once a frame header failed to read or a frame ran past the bytes that arrived. A request
    /// is never whole after that, whatever the frames before it held.
    intact: bool = true,

    fn next(self: *FrameWalk, stream: []const u8) ?Frame {
        if (self.pos >= self.total) return null;

        const type_vi = varint.read(stream[self.pos..]) catch {
            self.intact = false;

            return null;
        };
        var at = self.pos + type_vi.len;

        const len_vi = varint.read(stream[at..]) catch {
            self.intact = false;

            return null;
        };
        at += len_vi.len;

        const declared: usize = @intCast(len_vi.value);
        if (at + declared > self.total) {
            self.intact = false;
            self.pos = self.total;

            return .{ .kind = type_vi.value, .start = at, .len = self.total - at, .cut = true };
        }

        self.pos = at + declared;

        return .{ .kind = type_vi.value, .start = at, .len = declared };
    }
};

fn decodeRequestStream(stream_data: []const u8) ?DecodedRequest {
    var decoded: DecodedRequest = undefined;
    var have_headers = false;
    var walk = FrameWalk{ .total = stream_data.len };
    // Where a Huffman-coded field name is expanded. It is scratch: nothing decoded points into it.
    var name_scratch: [max_field_name_len]u8 = undefined;

    while (walk.next(stream_data)) |frame| {
        const frame_data = stream_data[frame.start..][0..frame.len];

        // A frame cut short, because the datagram was or because reassembly ran out of room. The
        // bytes of a cut DATA frame are still body bytes, so they are delivered and counted: what
        // makes the difference is that the request is no longer marked whole.
        if (frame.cut) {
            if (frame.kind == 0x00 and have_headers) {
                if (decoded.body.len == 0) decoded.body = frame_data;
                decoded.body_received += frame_data.len;
            }

            break;
        }

        switch (frame.kind) {
            0x01 => { // HEADERS
                // A second field section is the trailers, which close the request (RFC 9114 4.1), so
                // the walk is done and whatever body came before it is whole.
                if (have_headers) break;

                decoded = decodeHeaders(frame_data, &name_scratch) orelse return null;
                have_headers = true;
            },
            0x00 => { // DATA
                // DATA before HEADERS is H3_FRAME_UNEXPECTED, and there is no request to attach it to.
                if (!have_headers) return null;

                if (decoded.body.len == 0) decoded.body = frame_data;
                decoded.body_received += frame_data.len;
            },
            else => {}, // A frame this decode does not model (a grease frame, a reserved type).
        }
    }

    if (!have_headers) return null;

    // What this layer can vouch for: the frames read out whole, and the body it hands over holds every
    // byte it counted. parseRequests adds the stream-level end signal on top.
    decoded.body_complete = walk.intact and decoded.body.len == decoded.body_received;

    return decoded;
}

/// The scratch a Huffman-coded field name is expanded into before it can be compared. Every name this
/// decode models is short (`accept-encoding` is the longest at 15 bytes, `:protocol` 9), so a name
/// longer than this is a field it does not model and there is nothing to gain from a bigger buffer.
/// Size a `decodeHeaders` scratch with it, or any size at all: the decode works either way.
pub const max_field_name_len = 48;

/// The fields a field section can carry that this decode keeps. Each value is stored as it arrived,
/// beside the one thing a caller needs to use it: whether it is still Huffman-encoded.
const DecodedFields = struct {
    method: []const u8 = "",
    path: []const u8 = "",
    path_huffman: bool = false,
    protocol: []const u8 = "",
    protocol_huffman: bool = false,
    authority: []const u8 = "",
    authority_huffman: bool = false,
    accept_encoding: []const u8 = "",
    accept_encoding_huffman: bool = false,
    origin: []const u8 = "",
    origin_huffman: bool = false,

    /// Record what a representation said the field with this name is worth, when this decode models
    /// the name at all. The last representation of a name wins, which is what a repeated field means,
    /// and it wins with its own coding: the flag follows the value that was kept.
    fn take(self: *DecodedFields, name: []const u8, value: []const u8, value_huffman: bool) void {
        if (std.mem.eql(u8, name, ":method")) {
            self.method = value;
        } else if (std.mem.eql(u8, name, ":path")) {
            self.path = value;
            self.path_huffman = value_huffman;
        } else if (std.mem.eql(u8, name, ":protocol")) {
            self.protocol = value;
            self.protocol_huffman = value_huffman;
        } else if (std.mem.eql(u8, name, ":authority")) {
            self.authority = value;
            self.authority_huffman = value_huffman;
        } else if (std.mem.eql(u8, name, "accept-encoding")) {
            self.accept_encoding = value;
            self.accept_encoding_huffman = value_huffman;
        } else if (std.mem.eql(u8, name, "origin")) {
            self.origin = value;
            self.origin_huffman = value_huffman;
        }
    }

    /// Whether every field this decode keeps is in hand, which is when the walk has nothing left to
    /// read for.
    fn complete(self: DecodedFields) bool {
        return self.method.len != 0 and self.path.len != 0 and self.protocol.len != 0 and
            self.authority.len != 0 and self.accept_encoding.len != 0 and self.origin.len != 0;
    }
};

/// QPACK-decode a HEADERS field section: the request line and the fields this layer serves on
/// (RFC 9204 4.5).
///
/// Note:
/// - The walk keeps what it has when it meets a representation it cannot read, because a request line
///   already in hand is answerable: the fields carried after that representation are absent, which is
///   what an absent field means to every caller anyway. A name that does not fit `name_scratch` is not
///   such a representation: it is read, and it simply matches no field this decode models.
///
/// Param:
/// block - []const u8 (the HEADERS frame payload)
/// name_scratch - []u8 (destination for a Huffman-coded field name, not kept past the walk)
///
/// Return:
/// - DecodedRequest
/// - null when the section carries no :method or :path this decode can read
pub fn decodeHeaders(block: []const u8, name_scratch: []u8) ?DecodedRequest {
    var pos: usize = 0;

    // Encoded Field Section Prefix: Required Insert Count (8-bit prefix) + Base (7-bit prefix).
    const ric = qpack.decodePrefixedInt(block[pos..], 8) catch return null;
    pos += ric.len;
    const base = qpack.decodePrefixedInt(block[pos..], 7) catch return null;
    pos += base.len;

    var fields = DecodedFields{};

    while (pos < block.len) {
        const lead = block[pos];

        if (lead & 0x80 != 0) {
            // Indexed Field Line (static or dynamic).
            const idx = qpack.decodeIndexedFieldLine(block[pos..]) catch return null;
            pos += idx.len;

            if (idx.static) {
                if (qpack.staticEntry(idx.index)) |entry| fields.take(entry.name, entry.value, false);
            }
        } else if (lead & 0xc0 == 0x40) {
            // Literal Field Line with Name Reference: the name is a static table entry, the value is
            // spelled out.
            const lit = qpack.decodeLiteralNameRef(block[pos..]) catch return null;
            pos += lit.len;

            if (lit.static) {
                if (qpack.staticEntry(lit.name_index)) |entry| fields.take(entry.name, lit.value, lit.huffman);
            }
        } else if (lead & 0xe0 == 0x20) {
            // Literal Field Line with Literal Name: the client spells the name out, which is the shape
            // a name with no static entry has to arrive in (`:protocol`, RFC 9220 4). A Huffman-coded
            // name is expanded into the scratch, because it has to be readable to be compared.
            const lit = qpack.decodeLiteralLiteralName(block[pos..], name_scratch) catch break;
            pos += lit.len;

            fields.take(lit.name, lit.value, lit.huffman);
        } else {
            // A representation this decoder does not model. The fields it needs come first, so what
            // remains does not matter.
            break;
        }

        // A field section can put the fields this decode keeps in any order, so the scan walks until it
        // has them all, the section ends, or it meets a representation it cannot read.
        if (fields.complete()) break;
    }

    if (fields.method.len == 0 or fields.path.len == 0) return null;

    return .{
        .method = fields.method,
        .path = fields.path,
        .path_huffman = fields.path_huffman,
        .protocol = fields.protocol,
        .protocol_huffman = fields.protocol_huffman,
        .authority = fields.authority,
        .authority_huffman = fields.authority_huffman,
        .accept_encoding = fields.accept_encoding,
        .accept_encoding_huffman = fields.accept_encoding_huffman,
        .origin = fields.origin,
        .origin_huffman = fields.origin_huffman,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

/// The HEADERS frame the body tests reuse: 17 bytes on the wire (frame type 0x01, length 0x0f, then a
/// 15-byte field section) carrying :method POST as indexed static line 20 (0xd4) and :path /baseline2
/// as a literal with name reference (0x51, non-Huffman length 0x0a).
const post_headers_frame = "010f" ++ "0000" ++ "d4" ++ "510a" ++ "2f626173656c696e6532";

/// A DATA frame carrying the two bytes "20" (frame type 0x00, length 0x02), 4 bytes on the wire.
const data_frame_20 = "0002" ++ "3230";

test "zix http3: streamBytes sums stream payloads across streams, skipping non-stream frames" {
    // ACK (skipped, charges nothing), a 17-byte request STREAM on bidi stream 0, then a 3-byte
    // STREAM on client uni stream 2: connection-level flow control counts both (RFC 9000 4.1).
    const payload = hexBytes("0200000000" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532" ++ "0a0203" ++ "000400");
    try std.testing.expectEqual(@as(u64, 20), streamBytes(&payload));

    // A payload with no STREAM frame charges nothing.
    const ack_only = hexBytes("0200000000");
    try std.testing.expectEqual(@as(u64, 0), streamBytes(&ack_only));
}

test "zix http3: parseRequest walks past RESET_STREAM_AT and a length-framed DATAGRAM" {
    // The two frames a WebTransport peer interleaves with a request: RESET_STREAM_AT (0x24: stream 0,
    // application error 0, final size 8, reliable size 4) aborting one of its data streams, and a QUIC
    // DATAGRAM with a length (0x31, RFC 9221) carrying the bytes "AB". Neither is this decode's
    // business, and neither may stop the walk: the request STREAM frame behind them still decodes.
    const payload = hexBytes("2400000804" ++ "31024142" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "GET", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
}

test "zix http3: parseRequest reads a request in front of a DATAGRAM that owns the packet end" {
    // 0x30 carries no length: the rest of the packet is the frame's data (RFC 9221 3), so a peer sends
    // it last and a request already decoded in front of it stays decoded.
    const payload = hexBytes("0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532" ++ "30" ++ "0102");
    try std.testing.expectEqualSlices(u8, "/baseline2", parseRequest(&payload).?.path);

    // The same frame ahead of the request owns those bytes, so they are its data, not a frame: there is
    // no request to decode and the walk must not invent one out of another frame's payload.
    const swallowed = hexBytes("300102" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");
    try std.testing.expect(parseRequest(&swallowed) == null);
}

test "zix http3: skipFrame refuses a truncated RESET_STREAM_AT or DATAGRAM" {
    // Three of RESET_STREAM_AT's four varints: the frame is cut, and guessing its length would move the
    // walk into the middle of whatever follows.
    try std.testing.expect(skipFrame(&hexBytes("24000008")) == null);

    // A DATAGRAM that declares four bytes and carries two.
    try std.testing.expect(skipFrame(&hexBytes("31044142")) == null);

    // A length-less DATAGRAM is one frame byte on its own: an empty frame, and it takes the end of the
    // packet with it.
    try std.testing.expectEqual(@as(usize, 1), skipFrame(&hexBytes("30")).?);

    // The truncated frame stops a request walk where it stands: the STREAM frame behind it is never
    // reached, which is the safe half of the trade (nothing is read out of a frame that was cut short).
    const payload = hexBytes("24000008" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");
    try std.testing.expect(parseRequest(&payload) == null);
}

test "zix http3: parseRequest decodes method and path past a leading ACK" {
    // ACK (0x02, largest 0, skipped) then STREAM frame on stream 0 carrying a HEADERS frame:
    // field section prefix 0000, :method GET as an indexed static line (0xd1), :path /baseline2 as a
    // literal-with-name-reference (0x51 = static name index 1, 0x0a = non-Huffman length 10).
    const payload = hexBytes("0200000000" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "GET", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expect(!decoded.path_huffman);
}

test "zix http3: parseRequest captures accept-encoding from the indexed static entry" {
    // Like the test above but the HEADERS field section adds accept-encoding as an indexed static line
    // (0xdf = static index 31, value "gzip, deflate, br"). Field section is now 16 bytes (0x10), so the
    // HEADERS frame is 0x12 and the STREAM length 0x12. The scan runs past :method / :path to reach it.
    const payload = hexBytes("0200000000" ++ "0a0012" ++ "0110" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532" ++ "df");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "GET", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "gzip, deflate, br", decoded.accept_encoding);
    try std.testing.expect(!decoded.accept_encoding_huffman);
}

test "zix http3: parseRequest leaves accept-encoding empty when the client sends none" {
    // The original request shape (no accept-encoding field): the value stays empty, and the serve path
    // then falls back to an identity response.
    const payload = hexBytes("0200000000" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqual(@as(usize, 0), decoded.accept_encoding.len);
}

test "zix http3: parseRequest decodes an extended CONNECT with :protocol, :authority and origin" {
    // The field section a browser sends for a WebTransport session: :method CONNECT and :scheme https
    // as indexed static lines (0xcf, 0xd7), :path and :authority as literals with the static name,
    // then :protocol and origin each spelled out (0x2..., leading '001' plus the name's 'H' bit), since
    // :protocol has no static entry at all and a client that does not index origin's spells it too.
    // Their names and values are Huffman-coded, which is the shape a browser uses.
    const section = "0000" ++ "cf" ++ "d7" ++ "5103" ++ "2f7774" ++ "500b" ++ "6578616d706c652e636f6d" ++ "2f00" ++ "b95d8749c87a3f" ++ "89" ++ "f058d360ea4567b13f" ++ "2d" ++ "3d8698d57f" ++ "8e" ++ "9d29ad171860be474d7415721e9f";
    // STREAM (0x0b, LEN | FIN) on stream 0, 64 bytes of stream data (0x40 0x40, the two-byte form),
    // carrying the 62-byte field section in a 64-byte HEADERS frame (0x01, length 0x3e).
    const payload = hexBytes("0200000000" ++ "0b00" ++ "4040" ++ "013e" ++ section);

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "CONNECT", decoded.method);
    try std.testing.expectEqualSlices(u8, "/wt", decoded.path);

    // :authority is a plain literal value in the name-reference form.
    try std.testing.expectEqualSlices(u8, "example.com", decoded.authority);
    try std.testing.expect(!decoded.authority_huffman);

    // :protocol is what makes this an extended CONNECT (RFC 9220 4). With the flag set the value is
    // still Huffman-coded, exactly like a path or accept-encoding: the caller expands it, and it is
    // Huffman("webtransport") from the RFC 7541 Appendix B table.
    try std.testing.expectEqualSlices(u8, &hexBytes("f058d360ea4567b13f"), decoded.protocol);
    try std.testing.expect(decoded.protocol_huffman);

    var expanded: [16]u8 = undefined;
    const protocol_len = huffman.decode(&expanded, decoded.protocol).?;
    try std.testing.expectEqualSlices(u8, "webtransport", expanded[0..protocol_len]);

    try std.testing.expectEqualSlices(u8, &hexBytes("9d29ad171860be474d7415721e9f"), decoded.origin);
    try std.testing.expect(decoded.origin_huffman);
}

test "zix http3: parseRequest reads origin from the static table by name reference" {
    // origin is RFC 9204 Appendix A entry 90, so a client that knows the table names it instead of
    // spelling it (0x5f 0x4b: static name index 90 in the saturated 4-bit prefix). The value is a
    // plain literal here, which is what the indexed name does not say anything about.
    const section = "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532" ++ "5f4b" ++ "13" ++ "68747470733a2f2f6578616d706c652e636f6d" ++ "df";
    // STREAM (LEN | FIN) on stream 0, 40 bytes, carrying the 38-byte field section in a 40-byte
    // HEADERS frame.
    const payload = hexBytes("0200000000" ++ "0b00" ++ "28" ++ "0126" ++ section);

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "GET", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "https://example.com", decoded.origin);
    try std.testing.expect(!decoded.origin_huffman);

    // The name reference is read, not a representation that stops the walk: the accept-encoding line
    // behind it (0xdf, static entry 31) still lands.
    try std.testing.expectEqualSlices(u8, "gzip, deflate, br", decoded.accept_encoding);

    // A plain GET carries neither of the other two, and empty is what that means.
    try std.testing.expectEqual(@as(usize, 0), decoded.protocol.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.authority.len);
}

test "zix http3: parseRequest carries on past a field name that does not fit the name scratch" {
    // The middle field line spells a 64-byte name in Huffman (the scratch holds 48), so the name cannot
    // be expanded and the line matches no field this decode keeps. That is not a decode failure: the
    // walk keeps its place with the length the representation declares, and the accept-encoding line
    // behind it is still read.
    const long_name = "2f31" ++ "f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9" ++ "0176";
    const section = "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532" ++ long_name ++ "df";
    // The 76-byte field section needs the two-byte length form in both frames: a 79-byte HEADERS frame
    // (0x01 0x40 0x4c) inside a 79-byte STREAM frame (0x40 0x4f).
    const payload = hexBytes("0200000000" ++ "0b00" ++ "404f" ++ "01404c" ++ section);

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "GET", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "gzip, deflate, br", decoded.accept_encoding);

    // Nothing was mistaken for one of the fields the line might have been.
    try std.testing.expectEqual(@as(usize, 0), decoded.protocol.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.authority.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.origin.len);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: parseRequest returns null when no request stream is present" {
    // A packet with only an ACK frame: nothing to decode.
    try std.testing.expect(parseRequest(&hexBytes("0200000000")) == null);
}

test "zix http3: parseRequests decodes two coalesced requests with their stream ids" {
    // Two STREAM frames in one packet: stream 0 (GET /baseline2) then stream 4 (GET /baseline2),
    // each a HEADERS frame with field section prefix 0000, :method GET (0xd1), :path literal.
    const one = "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532";
    const two = "0a0411" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532";
    const payload = hexBytes("0200000000" ++ one ++ two);

    var reqs: [4]StreamRequest = undefined;
    const count = parseRequests(&payload, &reqs);

    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u64, 0), reqs[0].stream_id);
    try std.testing.expectEqual(@as(u64, 4), reqs[1].stream_id);
    try std.testing.expectEqualSlices(u8, "GET", reqs[1].request.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", reqs[1].request.path);
}

test "zix http3: parseStreamFrame reports the end-of-stream bit and the stream offset" {
    // 0x0b is STREAM | LEN | FIN on stream 0 at offset 0, the shape a client uses for a request that
    // fits one packet.
    const with_fin = hexBytes("0b0002" ++ "3230");
    const ended = parseStreamFrame(&with_fin).?;
    try std.testing.expect(ended.fin);
    try std.testing.expectEqual(@as(u64, 0), ended.offset);
    try std.testing.expectEqualSlices(u8, "20", ended.data);

    // 0x0e is STREAM | OFF | LEN with no FIN: a continuation the client will add to.
    const continuation = hexBytes("0e000802" ++ "3232");
    const more = parseStreamFrame(&continuation).?;
    try std.testing.expect(!more.fin);
    try std.testing.expectEqual(@as(u64, 8), more.offset);
    try std.testing.expectEqualSlices(u8, "22", more.data);
}

test "zix http3: parseRequest delivers the DATA frame body of a POST, request whole" {
    // STREAM | LEN | FIN on stream 0, 21 bytes: the 17-byte HEADERS frame then a 4-byte DATA frame.
    const payload = hexBytes("0200000000" ++ "0b0015" ++ post_headers_frame ++ data_frame_20);

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 2), decoded.body_received);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: parseRequest hands over a body the client has not finished, no FIN" {
    // The same request with 0x0a (STREAM | LEN, no FIN): the bytes are real, but the client may still
    // send more on this stream, so the body must not be reported as whole.
    const payload = hexBytes("0200000000" ++ "0a0015" ++ post_headers_frame ++ data_frame_20);

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 2), decoded.body_received);
    try std.testing.expect(!decoded.body_complete);
}

test "zix http3: parseRequest counts every DATA frame but delivers the first, split body" {
    // Two DATA frames ("20" then "22"), 25 bytes of stream data. They are not adjacent on the wire, so
    // only the first is handed over, and the count is what tells the handler bytes are missing.
    const payload = hexBytes("0200000000" ++ "0b0019" ++ post_headers_frame ++ data_frame_20 ++ "0002" ++ "3232");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 4), decoded.body_received);
    try std.testing.expect(!decoded.body_complete);
}

test "zix http3: parseRequest reports a GET with no body as whole" {
    // HEADERS and nothing else, the stream ended: there is no body and nothing to fall short of.
    const payload = hexBytes("0200000000" ++ "0b0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqual(@as(usize, 0), decoded.body.len);
    try std.testing.expectEqual(@as(u64, 0), decoded.body_received);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: parseStreamPieces reports a frame past the stream start as a continuation" {
    // 0x0f is STREAM | OFF | LEN | FIN at offset 8: bytes were sent on this stream before this frame.
    // Whatever these bytes look like they are a body, not a request head, so nothing is decoded out of
    // them here. The serve path joins them to the head that arrived earlier.
    const payload = hexBytes("0f000815" ++ post_headers_frame ++ data_frame_20);

    var pieces: [2]StreamPiece = undefined;
    try std.testing.expectEqual(@as(usize, 1), parseStreamPieces(&payload, &pieces));
    try std.testing.expectEqual(@as(u64, 8), pieces[0].offset);
    try std.testing.expect(pieces[0].fin);
    try std.testing.expect(pieces[0].request == null);
    try std.testing.expectEqual(@as(usize, 21), pieces[0].data.len);

    // The same bytes are no request on their own, which is what a continuation means.
    try std.testing.expect(parseRequest(&payload) == null);
}

test "zix http3: parseUniPieces reports a client uni stream and not the bidi request beside it" {
    // A client uni stream (id 2) whose bytes open the way a WebTransport data stream does: the stream
    // type varint 0x54, the session id 0, then two application bytes. Then a request on the client bidi
    // stream 0. Only the uni frame is a piece here, and the bidi frame is still the request walk's.
    const payload = hexBytes("0a0204" ++ "54000102" ++ "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");

    var pieces: [4]UniPiece = undefined;
    try std.testing.expectEqual(@as(usize, 1), parseUniPieces(&payload, &pieces));
    try std.testing.expectEqual(@as(u64, 2), pieces[0].stream_id);
    try std.testing.expectEqual(@as(u64, 0), pieces[0].offset);
    try std.testing.expect(!pieces[0].fin);
    try std.testing.expectEqualSlices(u8, &hexBytes("54000102"), pieces[0].data);

    var reqs: [4]StreamRequest = undefined;
    try std.testing.expectEqual(@as(usize, 1), parseRequests(&payload, &reqs));
    try std.testing.expectEqual(@as(u64, 0), reqs[0].stream_id);
}

test "zix http3: parseUniPieces reports the offset and the end of a uni stream opened earlier" {
    // 0x0f is STREAM | OFF | LEN | FIN on client uni stream 6 at offset 4: the type varint and the
    // session id went out in an earlier frame, so these bytes sit inside the stream and end it. The ACK
    // in front is skipped like any other frame, and the offset is what tells the caller the type varint
    // is not in these bytes.
    const payload = hexBytes("0200000000" ++ "0f0604" ++ "02" ++ "4142");

    var pieces: [2]UniPiece = undefined;
    try std.testing.expectEqual(@as(usize, 1), parseUniPieces(&payload, &pieces));
    try std.testing.expectEqual(@as(u64, 6), pieces[0].stream_id);
    try std.testing.expectEqual(@as(u64, 4), pieces[0].offset);
    try std.testing.expect(pieces[0].fin);
    try std.testing.expectEqualSlices(u8, "AB", pieces[0].data);
}

test "zix http3: parseUniPieces does not report server-initiated unidirectional frames" {
    // Server uni ids are 3 mod 4 (RFC 9000 2.1), so these frames belong to the server's own streams.
    // Reporting them would attribute the server's control stream to the client.
    const payload = hexBytes("0a0302" ++ "5455" ++ "0a0702" ++ "5455");

    var pieces: [4]UniPiece = undefined;
    try std.testing.expectEqual(@as(usize, 0), parseUniPieces(&payload, &pieces));
}

test "zix http3: parseUniPieces returns nothing for a payload with no uni stream frame" {
    var pieces: [4]UniPiece = undefined;

    // An ACK-only packet.
    try std.testing.expectEqual(@as(usize, 0), parseUniPieces(&hexBytes("0200000000"), &pieces));

    // A packet carrying a client bidi request stream: that frame is the request walk's to report.
    const request_only = hexBytes("0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532");
    try std.testing.expectEqual(@as(usize, 0), parseUniPieces(&request_only, &pieces));
}

test "zix http3: parseStreamPieces hands back the head and the continuation of one request" {
    // The shape a client puts on the wire for a POST: the HEADERS frame with the stream left open,
    // then the body at the offset the head ended on, ending the stream.
    const head = "0a0011" ++ "010f" ++ "0000" ++ "d4" ++ "510a" ++ "2f626173656c696e6532";
    const body = "0f001104" ++ data_frame_20;
    const payload = hexBytes(head ++ body);

    var pieces: [4]StreamPiece = undefined;
    try std.testing.expectEqual(@as(usize, 2), parseStreamPieces(&payload, &pieces));

    // The head decodes, but nothing about it is servable yet: the client has not finished.
    const decoded = pieces[0].request.?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqual(@as(usize, 0), decoded.body.len);
    try std.testing.expect(!decoded.body_complete);

    // The continuation carries the body bytes and the end of the stream.
    try std.testing.expect(pieces[1].request == null);
    try std.testing.expectEqual(@as(u64, 17), pieces[1].offset);
    try std.testing.expect(pieces[1].fin);
    try std.testing.expectEqualSlices(u8, &hexBytes(data_frame_20), pieces[1].data);
}

test "zix http3: decodeStreamRequest reads a request out of reassembled stream bytes" {
    // What the serve path holds once it has joined the two frames above: the same bytes, contiguous,
    // with the client known to have finished.
    const assembled = hexBytes(post_headers_frame ++ data_frame_20);

    const decoded = decodeStreamRequest(&assembled, true).?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 2), decoded.body_received);
    try std.testing.expect(decoded.body_complete);

    // The same bytes with the client not finished are the same request, minus the promise.
    const open_stream = decodeStreamRequest(&assembled, false).?;
    try std.testing.expectEqualSlices(u8, "20", open_stream.body);
    try std.testing.expect(!open_stream.body_complete);
}

test "zix http3: decodeAssembledRequest joins a body the client wrote as several DATA frames" {
    // Three DATA frames on one stream, which is what a client does with any body larger than its
    // write buffer. Read-only, the first is all a handler could be given and the rest reads as
    // missing. Joined in the buffer the worker owns, it is one body.
    var assembled = hexBytes(post_headers_frame ++ data_frame_20 ++ "0002" ++ "3232" ++ "0003" ++ "343536");

    const decoded = decodeAssembledRequest(&assembled, true).?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "2022456", decoded.body);
    try std.testing.expectEqual(@as(u64, 7), decoded.body_received);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: decodeAssembledRequest leaves the request line intact while it joins the body" {
    // The join moves body bytes backwards over the frame headers it drops, and the method and path
    // sit in front of all of it. Reading them after the move is what proves nothing was overwritten.
    var assembled = hexBytes(post_headers_frame ++ data_frame_20 ++ "0002" ++ "3232");

    const decoded = decodeAssembledRequest(&assembled, true).?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "2022", decoded.body);

    // The body is a slice of the buffer, not a copy out of it.
    try std.testing.expect(@intFromPtr(decoded.body.ptr) >= @intFromPtr(&assembled));
    try std.testing.expect(@intFromPtr(decoded.body.ptr) + decoded.body.len <= @intFromPtr(&assembled) + assembled.len);
}

test "zix http3: decodeAssembledRequest still reports a cut trailing DATA frame as short" {
    // The last frame declares 16 bytes and 2 arrived, which is what the slot filling up looks like.
    // The joined body keeps everything real, and the request is not called whole.
    var assembled = hexBytes(post_headers_frame ++ data_frame_20 ++ "0010" ++ "3232");

    const decoded = decodeAssembledRequest(&assembled, true).?;
    try std.testing.expectEqualSlices(u8, "2022", decoded.body);
    try std.testing.expectEqual(@as(u64, 4), decoded.body_received);
    try std.testing.expect(!decoded.body_complete);
}

test "zix http3: decodeAssembledRequest keeps the body whole across a trailing field section" {
    // Trailers close the request (RFC 9114 4.1), so the joined body before them is everything sent.
    var assembled = hexBytes(post_headers_frame ++ data_frame_20 ++ "0002" ++ "3232" ++ "01020000");

    const decoded = decodeAssembledRequest(&assembled, true).?;
    try std.testing.expectEqualSlices(u8, "2022", decoded.body);
    try std.testing.expectEqual(@as(u64, 4), decoded.body_received);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: decodeAssembledRequest agrees with the read-only decode on a single-frame body" {
    // The common shape must not change just because it took the joining path: same body, same counts.
    var assembled = hexBytes(post_headers_frame ++ data_frame_20);
    const read_only = decodeStreamRequest(&assembled, true).?;
    const joined = decodeAssembledRequest(&assembled, true).?;

    try std.testing.expectEqualSlices(u8, read_only.body, joined.body);
    try std.testing.expectEqual(read_only.body_received, joined.body_received);
    try std.testing.expectEqual(read_only.body_complete, joined.body_complete);
}

test "zix http3: decodeAssembledRequest refuses a stream whose DATA frame precedes its HEADERS" {
    var assembled = hexBytes(data_frame_20 ++ post_headers_frame);

    try std.testing.expect(decodeAssembledRequest(&assembled, true) == null);
}

test "zix http3: parseRequest delivers a cut DATA frame short instead of dropping or trusting it" {
    // 0x09 is STREAM | FIN with no length, so the stream runs to the end of the payload. The DATA frame
    // declares 16 bytes and only 2 are there, which is what a cut-off datagram looks like: the request
    // line is answerable, the two bytes are real body bytes and are handed over, and FIN alone must not
    // call the result whole.
    const payload = hexBytes("0900" ++ post_headers_frame ++ "0010" ++ "3230");

    const decoded = parseRequest(&payload).?;
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 2), decoded.body_received);
    try std.testing.expect(!decoded.body_complete);
}

test "zix http3: parseRequest refuses a stream whose DATA frame precedes its HEADERS" {
    // DATA before HEADERS is H3_FRAME_UNEXPECTED (RFC 9114 4.1). There is no request line to answer
    // with, so the stream decodes to nothing rather than to a request with a stray body.
    const payload = hexBytes("0b0015" ++ data_frame_20 ++ post_headers_frame);

    try std.testing.expect(parseRequest(&payload) == null);
}

test "zix http3: parseRequests gives each coalesced request its own body" {
    // One datagram, two requests: a POST with a body on stream 0 and a bodyless GET on stream 4. The
    // body must land on the stream that carried it and nowhere else.
    const post = "0b0015" ++ post_headers_frame ++ data_frame_20;
    const get = "0b0411" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532";
    const payload = hexBytes(post ++ get);

    var reqs: [4]StreamRequest = undefined;
    const count = parseRequests(&payload, &reqs);

    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualSlices(u8, "20", reqs[0].request.body);
    try std.testing.expect(reqs[0].request.body_complete);

    try std.testing.expectEqual(@as(usize, 0), reqs[1].request.body.len);
    try std.testing.expectEqual(@as(u64, 0), reqs[1].request.body_received);
    try std.testing.expect(reqs[1].request.body_complete);
}
