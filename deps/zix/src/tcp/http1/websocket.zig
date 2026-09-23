//! zix http1 websocket
//! RFC 6455 frame codec and handshake over raw fd I/O (no std.Io stream layer).

const std = @import("std");
const core = @import("core.zig");
const fd_io = @import("../../utils/fd_io.zig");

// --------------------------------------------------------- //

const ws_len_max_7bit = 125;
const ws_len_16bit_marker = 126;
const ws_len_64bit_marker = 127;
const ws_len_max_16bit = std.math.maxInt(u16);
const ws_mask_len: usize = 4;
const ws_len_64bit_field_size: usize = 8;
const ws_max_frame_header: usize = 10;

/// Buffer for the accept-key hash input (client key concatenated with the RFC 6455 GUID).
const WS_ACCEPT_HASH_INPUT_SIZE: usize = 128;

/// Buffer for the 101 Switching Protocols upgrade response.
const WS_UPGRADE_RESPONSE_SIZE: usize = 256;

// --------------------------------------------------------- //

/// RFC 6455 5.2 - WebSocket opcodes.
pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

/// Parsed WebSocket frame.
/// payload is a slice into caller-supplied payload_buf (masked) or into the source buffer (unmasked).
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

/// Return value of parseFrame.
pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

/// Parse one WebSocket frame from buf.
///
/// Note:
/// - Client to server frames are masked, the unmasked payload is written into payload_buf.
/// - null when buf does not yet contain a complete frame.
///
/// Param:
/// buf         - []const u8 (raw bytes from the connection)
/// payload_buf - []u8 (caller-provided buffer for the unmasked payload)
///
/// Return:
/// - ?ParseResult
pub fn parseFrame(buf: []const u8, payload_buf: []u8) ?ParseResult {
    if (buf.len < 2) return null;

    var byte_offset: usize = 0;
    const fin = (buf[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(buf[0] & 0x0F);
    byte_offset += 1;

    const masked = (buf[1] & 0x80) != 0;
    var payload_len: u64 = buf[1] & 0x7F;
    byte_offset += 1;

    if (payload_len == ws_len_16bit_marker) {
        if (buf.len < byte_offset + 2) return null;
        payload_len = (@as(u64, buf[byte_offset]) << 8) | buf[byte_offset + 1];
        byte_offset += 2;
    } else if (payload_len == ws_len_64bit_marker) {
        if (buf.len < byte_offset + ws_len_64bit_field_size) return null;
        payload_len = 0;
        for (0..ws_len_64bit_field_size) |i| payload_len = (payload_len << 8) | buf[byte_offset + i];
        byte_offset += ws_len_64bit_field_size;
    }

    var mask: [ws_mask_len]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (buf.len < byte_offset + ws_mask_len) return null;
        @memcpy(&mask, buf[byte_offset .. byte_offset + ws_mask_len]);
        byte_offset += ws_mask_len;
    }

    const capped_len: usize = @intCast(@min(payload_len, payload_buf.len));
    if (buf.len < byte_offset + capped_len) return null;

    const payload: []const u8 = if (masked) blk: {
        const src = buf[byte_offset..][0..capped_len];
        const dst = payload_buf[0..capped_len];
        const vec_width = 16;
        const vec_mask: @Vector(vec_width, u8) = .{
            mask[0], mask[1], mask[2], mask[3],
            mask[0], mask[1], mask[2], mask[3],
            mask[0], mask[1], mask[2], mask[3],
            mask[0], mask[1], mask[2], mask[3],
        };
        var i: usize = 0;

        while (i + vec_width <= capped_len) : (i += vec_width) {
            const chunk: @Vector(vec_width, u8) = src[i..][0..vec_width].*;
            dst[i..][0..vec_width].* = chunk ^ vec_mask;
        }
        while (i < capped_len) : (i += 1) {
            dst[i] = src[i] ^ mask[i % ws_mask_len];
        }

        break :blk payload_buf[0..capped_len];
    } else buf[byte_offset .. byte_offset + capped_len];

    return .{
        .frame = .{ .fin = fin, .opcode = opcode, .payload = payload },
        .consumed = byte_offset + capped_len,
    };
}

/// Build the header of a server to client WebSocket frame (unmasked per
/// RFC 6455 5.1), without the payload.
///
/// Note:
/// - buf must be at least 10 bytes (the maximum frame header size).
///
/// Param:
/// buf         - []u8 (destination, at least 10 bytes)
/// opcode      - Opcode
/// payload_len - usize (length the payload will be)
///
/// Return:
/// - usize (header bytes written into buf)
pub fn buildHeader(buf: []u8, opcode: Opcode, payload_len: usize) usize {
    var byte_offset: usize = 0;
    buf[byte_offset] = 0x80 | @intFromEnum(opcode);
    byte_offset += 1;

    if (payload_len <= ws_len_max_7bit) {
        buf[byte_offset] = @intCast(payload_len);
        byte_offset += 1;
    } else if (payload_len <= ws_len_max_16bit) {
        buf[byte_offset] = ws_len_16bit_marker;
        buf[byte_offset + 1] = @intCast((payload_len >> 8) & 0xFF);
        buf[byte_offset + 2] = @intCast(payload_len & 0xFF);
        byte_offset += 3;
    } else {
        buf[byte_offset] = ws_len_64bit_marker;
        for (0..ws_len_64bit_field_size) |i| {
            const shift: u6 = @intCast((7 - i) * 8);
            buf[byte_offset + 1 + i] = @intCast((payload_len >> shift) & 0xFF);
        }
        byte_offset += 1 + ws_len_64bit_field_size;
    }

    return byte_offset;
}

/// Build a server to client WebSocket frame (unmasked per RFC 6455 5.1).
///
/// Note:
/// - buf must be at least payload.len + 10 bytes (header plus payload).
///
/// Param:
/// buf     - []u8 (destination, at least payload.len + 10)
/// opcode  - Opcode
/// payload - []const u8
///
/// Return:
/// - usize (bytes written into buf)
pub fn buildFrame(buf: []u8, opcode: Opcode, payload: []const u8) usize {
    const header_len = buildHeader(buf, opcode, payload.len);

    @memcpy(buf[header_len .. header_len + payload.len], payload);
    return header_len + payload.len;
}

/// Compute Sec-WebSocket-Accept from Sec-WebSocket-Key (RFC 6455 4.2.2).
///
/// Param:
/// key - []const u8 (value of the Sec-WebSocket-Key request header)
/// out - *[64]u8 (caller-provided output buffer, result is a sub-slice of it)
///
/// Return:
/// - ![]const u8
pub fn acceptKey(key: []const u8, out: *[64]u8) ![]const u8 {
    // RFC 6455 1.3 - this exact GUID is mandated by the WebSocket spec, do not change it.
    const rfc6455_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var hash_input: [WS_ACCEPT_HASH_INPUT_SIZE]u8 = undefined;
    if (key.len + rfc6455_guid.len > hash_input.len) return error.ZixKeyTooLong;

    @memcpy(hash_input[0..key.len], key);
    @memcpy(hash_input[key.len..][0..rfc6455_guid.len], rfc6455_guid);

    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(hash_input[0 .. key.len + rfc6455_guid.len], &hash, .{});

    const encoded_len = std.base64.standard.Encoder.calcSize(20);
    return std.base64.standard.Encoder.encode(out[0..encoded_len], &hash);
}

/// Perform the HTTP to WebSocket upgrade handshake on a raw fd.
/// Writes the 101 Switching Protocols response directly via core.writeAllFD.
///
/// Param:
/// fd     - std.posix.fd_t
/// accept - []const u8 (value returned by acceptKey)
///
/// Return:
/// - !void
pub fn upgrade(fd: std.posix.fd_t, accept: []const u8) !void {
    var hdr_buf: [WS_UPGRADE_RESPONSE_SIZE]u8 = undefined;
    const response = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    );

    try core.writeAllFD(fd, response);
}

// --------------------------------------------------------- //

/// Per-frame callback for an engine-owned WebSocket. Re-exported from core so
/// the type lives in one place. See core.WsFrameFn.
pub const WsFrameFn = core.WsFrameFn;

/// Largest frame written with one combined header+payload buffer + single
/// write. Above this, header and payload are written separately to avoid a
/// large stack copy. Mirrors the http1 write-path trade-off.
const ws_send_inline_cap: usize = 4096;

/// Coalesces all frames sent while serving one readable event into a single
/// write. The engine installs a sink around each pump pass so a pipelined
/// burst of N echoes flushes in one write() instead of N. Auto-flushes when
/// the staging buffer would overflow, and writes oversize frames straight
/// through, so correctness never depends on the buffer being large enough.
const SendSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,

    fn append(self: *SendSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            core.writeAllFD(self.fd, bytes) catch {
                self.failed = true;
            };
            return;
        }

        if (self.len + bytes.len > self.buf.len) self.flush();

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn flush(self: *SendSink) void {
        if (self.len == 0) return;

        core.writeAllFD(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

/// Active send sink for the current thread, set by beginSend during a pump
/// pass. When present, send stages into it instead of writing immediately.
threadlocal var tl_send_sink: ?*SendSink = null;

/// Build and write one unmasked server frame to fd. When the engine has a send
/// sink active (during a pump pass) the frame is staged for a single batched
/// write, otherwise it is written immediately.
///
/// Note:
/// - Outside a sink, small frames go out as one buffer + one write and large
///   frames write the header then the payload (two writes) to avoid a big copy.
///
/// Param:
/// fd      - std.posix.fd_t
/// opcode  - Opcode
/// payload - []const u8
///
/// Return:
/// - !void (error.BrokenPipe on a dead peer)
pub fn sendFD(fd: std.posix.fd_t, opcode: Opcode, payload: []const u8) !void {
    if (tl_send_sink) |sink| {
        var hdr: [ws_max_frame_header]u8 = undefined;
        const hdr_len = buildHeader(&hdr, opcode, payload.len);

        sink.append(hdr[0..hdr_len]);
        sink.append(payload);

        return if (sink.failed) error.BrokenPipe else {};
    }

    if (payload.len + ws_max_frame_header <= ws_send_inline_cap) {
        var buf: [ws_send_inline_cap]u8 = undefined;
        const len = buildFrame(&buf, opcode, payload);

        return core.writeAllFD(fd, buf[0..len]);
    }

    var hdr: [ws_max_frame_header]u8 = undefined;
    const hdr_len = buildHeader(&hdr, opcode, payload.len);

    try core.writeAllFD(fd, hdr[0..hdr_len]);
    try core.writeAllFD(fd, payload);
}

/// Build one server frame and fan it out to every fd in conns. The frame is
/// serialized once and the same bytes are written to each connection, so a room
/// broadcast costs one serialization no matter how many members it reaches.
///
/// Note:
/// - A failed write (dead peer) is skipped, not propagated. The EPOLL engine
///   reaps the fd on its next event, so a broadcast never blocks on one member.
/// - Not staged through the per-event send sink: a broadcast targets many
///   connections, not the single one being pumped.
/// - The caller owns the conns list (a handler-maintained room), the engine has
///   no room registry of its own.
///
/// Param:
/// conns   - []const std.posix.fd_t (target connection fds)
/// opcode  - Opcode
/// payload - []const u8
///
/// Usage:
/// ```zig
/// // in an on_frame callback, fan a chat message out to the room
/// zix.Http1.WebSocket.broadcast(room.fds(), .text, payload);
/// ```
///
/// Return:
/// - void
pub fn broadcast(conns: []const std.posix.fd_t, opcode: Opcode, payload: []const u8) void {
    if (payload.len + ws_max_frame_header <= ws_send_inline_cap) {
        var buf: [ws_send_inline_cap]u8 = undefined;
        const len = buildFrame(&buf, opcode, payload);
        const frame = buf[0..len];

        for (conns) |fd| core.writeAllFD(fd, frame) catch continue;

        return;
    }

    // Oversize payload: build the header once, then write header + payload per
    // fd so the large payload is never copied into a staging buffer.
    var hdr: [ws_max_frame_header]u8 = undefined;
    const hdr_len = buildHeader(&hdr, opcode, payload.len);
    const header = hdr[0..hdr_len];

    for (conns) |fd| {
        core.writeAllFD(fd, header) catch continue;
        core.writeAllFD(fd, payload) catch continue;
    }
}

/// Complete the handshake, then hand the connection to the engine's event loop.
/// Call this from an http1 handler instead of looping on the fd yourself: after
/// it returns, the EPOLL engine drives the frame loop, invoking on_frame for
/// each text/binary frame (ping is auto-ponged, close is auto-echoed). The
/// worker is never parked on a single connection.
///
/// Note:
/// - Honored under dispatch_model .EPOLL only. Under .ASYNC the handoff
///   is cleared and the connection ends after the handler returns.
///
/// Param:
/// fd       - std.posix.fd_t
/// key      - []const u8 (the Sec-WebSocket-Key request header value)
/// on_frame - WsFrameFn
///
/// Return:
/// - !void (handshake errors from acceptKey/upgrade)
pub fn serve(fd: std.posix.fd_t, key: []const u8, on_frame: WsFrameFn) !void {
    var accept_buf: [64]u8 = undefined;
    const accept = try acceptKey(key, &accept_buf);

    try upgrade(fd, accept);
    core.requestWebSocket(fd, on_frame);
}

/// Complete the handshake over TLS, then hand the connection to the https thread (ADR-055). Call
/// this from an http1 handler served over TLS (`config.tls`, the `.ASYNC`
/// path) instead of `serve`: it detaches the buffered response capture so the `101` and every
/// frame encrypt one TLS record per write (ADR-054 stream sink), then registers the handoff. After
/// the handler returns, the https serve loop drives the inline frame loop over the TLS session,
/// invoking on_frame for each text/binary frame (ping auto-ponged, close auto-echoed).
///
/// Note:
/// - Thread-per-connection only, like SSE over TLS. `fd` is the sentinel (-1) the handler is given
///   over TLS, used only to match the send sink, never a real descriptor.
/// - `broadcast` and rooms are not supported over TLS: each connection has its own TLS session, so
///   a frame must be encrypted per connection. Use `sendFD` (echo / per-connection) over TLS.
///
/// Param:
/// fd       - std.posix.fd_t (the sentinel fd the handler received)
/// key      - []const u8 (the Sec-WebSocket-Key request header value)
/// on_frame - WsFrameFn
///
/// Return:
/// - !void (handshake errors from acceptKey / upgrade)
pub fn serveTls(fd: std.posix.fd_t, key: []const u8, on_frame: WsFrameFn) !void {
    var accept_buf: [64]u8 = undefined;
    const accept = try acceptKey(key, &accept_buf);

    core.beginStream();
    try upgrade(fd, accept);
    core.requestWebSocket(fd, on_frame);
}

/// Outcome of one pump pass over a connection's read buffer.
pub const PumpResult = struct {
    /// Bytes consumed from the front of data (whole frames only).
    consumed: usize,
    /// Whether the connection should close (close frame seen or write failed).
    close: bool,
};

/// Parse and dispatch every complete frame in data, in order. Text and binary
/// frames invoke on_frame. Ping is auto-ponged, close is auto-echoed and ends
/// the connection. A trailing partial frame is left for the next read (its
/// bytes are not counted in consumed).
///
/// Note:
/// - All frames sent during the pass (echoes, pong, close) are coalesced into
///   out_buf and flushed in one write, so a pipelined burst costs one write()
///   rather than one per frame.
///
/// Param:
/// fd          - std.posix.fd_t
/// data        - []const u8 (raw bytes received so far)
/// payload_buf - []u8 (scratch for unmasking, must hold the largest payload)
/// out_buf     - []u8 (staging for the coalesced write)
/// on_frame    - WsFrameFn
///
/// Return:
/// - PumpResult
pub fn pump(fd: std.posix.fd_t, data: []const u8, payload_buf: []u8, out_buf: []u8, on_frame: WsFrameFn) PumpResult {
    var sink = SendSink{ .fd = fd, .buf = out_buf };
    tl_send_sink = &sink;
    defer tl_send_sink = null;

    var offset: usize = 0;
    var close = false;

    while (offset < data.len) {
        const result = parseFrame(data[offset..], payload_buf) orelse break;

        switch (result.frame.opcode) {
            .text, .binary => on_frame(fd, @intFromEnum(result.frame.opcode), result.frame.payload),
            .ping => sendFD(fd, .pong, result.frame.payload) catch {},
            .close => {
                sendFD(fd, .close, &.{}) catch {};
                offset += result.consumed;
                close = true;
                break;
            },
            .pong, .continuation => {},
            else => {},
        }

        offset += result.consumed;
    }

    sink.flush();

    return .{ .consumed = offset, .close = close or sink.failed };
}

/// Outcome of one staged pump pass for the .URING ring path.
pub const RingPumpResult = struct {
    /// Bytes consumed from the front of data (whole frames only).
    consumed: usize,
    /// Whether the connection should close (close frame seen or a write failed).
    close: bool,
    /// Bytes staged into out_buf for the caller to submit as one send.
    staged: usize,
};

/// Like pump, but stages every outbound frame into out_buf and returns the
/// staged length instead of writing to the fd. The .URING engine submits one
/// ring send of out_buf[0..staged] afterwards, so the frame loop issues no
/// blocking write of its own.
///
/// Note:
/// - If the echoes overflow out_buf mid-pass, the overflowing batch is written
///   straight to the fd (a rare correctness fallback, safe under the ring's
///   half-duplex guarantee that no send is in flight during a pump pass), and
///   only the trailing bytes are returned as staged.
///
/// Param:
/// fd - std.posix.fd_t
/// data - []const u8 (raw frame bytes received so far)
/// payload_buf - []u8 (scratch for unmasking, must hold the largest payload)
/// out_buf - []u8 (staging for the coalesced ring send)
/// on_frame - WsFrameFn
///
/// Return:
/// - RingPumpResult
pub fn pumpRing(fd: std.posix.fd_t, data: []const u8, payload_buf: []u8, out_buf: []u8, on_frame: WsFrameFn) RingPumpResult {
    var sink = SendSink{ .fd = fd, .buf = out_buf };
    tl_send_sink = &sink;
    defer tl_send_sink = null;

    var offset: usize = 0;
    var close = false;

    while (offset < data.len) {
        const result = parseFrame(data[offset..], payload_buf) orelse break;

        switch (result.frame.opcode) {
            .text, .binary => on_frame(fd, @intFromEnum(result.frame.opcode), result.frame.payload),
            .ping => sendFD(fd, .pong, result.frame.payload) catch {},
            .close => {
                sendFD(fd, .close, &.{}) catch {};
                offset += result.consumed;
                close = true;
                break;
            },
            .pong, .continuation => {},
            else => {},
        }

        offset += result.consumed;
    }

    return .{ .consumed = offset, .close = close or sink.failed, .staged = sink.len };
}

// --------------------------------------------------------- //
// Blocking frame loop (.ASYNC)

/// Drive an engine-owned WebSocket to completion on the calling thread.
///
/// What:
///   The multiplexed models return to their event loop between frames. The .ASYNC model owns one
///   connection per task, so it stays here until the peer goes away. Framing, ping / pong and
///   close handling all come from pump, the same code the event loops use.
///
/// Note:
/// - Blocking reads, so the task parks between frames rather than spinning.
/// - A frame wider than recv_buf can never complete, so the connection is closed instead of
///   looping on bytes that can make no progress.
/// - broadcast works here as it does on the event loops, since every send goes through the fd.
///
/// Param:
/// fd - std.posix.fd_t (the promoted connection)
/// on_frame - WsFrameFn (invoked per text / binary frame)
/// recv_buf - []u8 (accumulates raw frame bytes, sizes the largest accepted frame)
/// payload_buf - []u8 (scratch for unmasking, must hold the largest payload)
/// out_buf - []u8 (staging for the coalesced write)
///
/// Return:
/// - void once the peer hung up, sent a close frame, or a write failed
pub fn serveBlocking(fd: std.posix.fd_t, on_frame: WsFrameFn, recv_buf: []u8, payload_buf: []u8, out_buf: []u8) void {
    var filled: usize = 0;

    while (true) {
        if (filled >= recv_buf.len) return;

        const got = fd_io.readOnce(fd, recv_buf[filled..]) catch return;
        if (got == 0) return;

        filled += got;

        const result = pump(fd, recv_buf[0..filled], payload_buf, out_buf, on_frame);

        if (result.consumed >= filled) {
            filled = 0;
        } else if (result.consumed > 0) {
            std.mem.copyForwards(u8, recv_buf[0 .. filled - result.consumed], recv_buf[result.consumed..filled]);
            filled -= result.consumed;
        }

        if (result.close) return;
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1 ws: acceptKey RFC 6455 vector" {
    var out: [64]u8 = undefined;
    const accept = try acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "zix http1 ws: buildFrame then parseFrame round trip" {
    const payload = "hello";
    var buf: [128]u8 = undefined;
    const len = buildFrame(&buf, .text, payload);

    try std.testing.expect(len > payload.len);
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]); // fin | text
    try std.testing.expectEqual(@as(u8, 5), buf[1]); // unmasked, len 5

    var payload_buf: [128]u8 = undefined;
    const result = parseFrame(buf[0..len], &payload_buf).?;
    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings(payload, result.frame.payload);
    try std.testing.expectEqual(len, result.consumed);
}

test "zix http1 ws: parseFrame unmasks a client frame" {
    // Masked "Hello" from RFC 6455 5.7
    const raw = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var payload_buf: [128]u8 = undefined;
    const result = parseFrame(&raw, &payload_buf).?;
    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings("Hello", result.frame.payload);
}

test "zix http1 ws: parseFrame SIMD unmask matches scalar for 32-byte payload" {
    // 32 bytes exercises 2 full vector iterations (16 bytes each).
    const mask_bytes = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    var raw: [2 + 4 + 32]u8 = undefined;
    raw[0] = 0x82; // FIN + binary
    raw[1] = 0x80 | 32; // masked, 32-byte payload
    @memcpy(raw[2..6], &mask_bytes);
    for (plain, 0..) |byte, i| raw[6 + i] = byte ^ mask_bytes[i % 4];

    var payload_buf: [64]u8 = undefined;
    const result = parseFrame(&raw, &payload_buf).?;

    try std.testing.expectEqualStrings(plain, result.frame.payload);
    try std.testing.expectEqual(raw.len, result.consumed);
}

test "zix http1 ws: parseFrame SIMD unmask handles tail bytes (17-byte payload)" {
    // 17 bytes = 1 vector iteration + 1 scalar tail byte.
    const mask_bytes = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    const plain = "12345678901234567";
    var raw: [2 + 4 + 17]u8 = undefined;
    raw[0] = 0x82; // FIN + binary
    raw[1] = 0x80 | 17; // masked, 17-byte payload
    @memcpy(raw[2..6], &mask_bytes);
    for (plain, 0..) |byte, i| raw[6 + i] = byte ^ mask_bytes[i % 4];

    var payload_buf: [64]u8 = undefined;
    const result = parseFrame(&raw, &payload_buf).?;

    try std.testing.expectEqualStrings(plain, result.frame.payload);
    try std.testing.expectEqual(raw.len, result.consumed);
}

test "zix http1 ws: buildHeader matches buildFrame prefix" {
    const payload = "hello";
    var frame_buf: [128]u8 = undefined;
    var hdr_buf: [ws_max_frame_header]u8 = undefined;

    const frame_len = buildFrame(&frame_buf, .text, payload);
    const hdr_len = buildHeader(&hdr_buf, .text, payload.len);

    try std.testing.expectEqual(frame_len - payload.len, hdr_len);
    try std.testing.expectEqualSlices(u8, frame_buf[0..hdr_len], hdr_buf[0..hdr_len]);
}

fn testEcho(fd: std.posix.fd_t, opcode: u8, payload: []const u8) void {
    sendFD(fd, @enumFromInt(opcode), payload) catch {};
}

test "zix http1 ws: pump echoes masked client frames over a socketpair" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // Two pipelined masked client text frames: "hi" and "yo".
    const data = [_]u8{
        0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'i' ^ 0x02,
        0x81, 0x82, 0x05, 0x06, 0x07, 0x08, 'y' ^ 0x05, 'o' ^ 0x06,
    };

    var payload_buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    const result = pump(fds[1], &data, &payload_buf, &out_buf, testEcho);

    try std.testing.expectEqual(data.len, result.consumed);
    try std.testing.expect(!result.close);

    // Both echoes arrive coalesced. Read and parse them back as server frames.
    var recv: [128]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &recv);

    var scratch: [128]u8 = undefined;
    const first = parseFrame(recv[0..n], &scratch).?;
    try std.testing.expectEqualStrings("hi", first.frame.payload);

    const second = parseFrame(recv[first.consumed..n], &scratch).?;
    try std.testing.expectEqualStrings("yo", second.frame.payload);
}

test "zix http1 ws: pumpRing stages echoes without writing to the fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Two pipelined masked client text frames: "hi" and "yo".
    const data = [_]u8{
        0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'i' ^ 0x02,
        0x81, 0x82, 0x05, 0x06, 0x07, 0x08, 'y' ^ 0x05, 'o' ^ 0x06,
    };

    var payload_buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    // fd -1 is never written: the echoes fit in out_buf, so they stage only.
    const result = pumpRing(-1, &data, &payload_buf, &out_buf, testEcho);

    try std.testing.expectEqual(data.len, result.consumed);
    try std.testing.expect(!result.close);
    try std.testing.expect(result.staged > 0);

    // The staged bytes are two server frames, parseable in order.
    var scratch: [128]u8 = undefined;
    const first = parseFrame(out_buf[0..result.staged], &scratch).?;
    try std.testing.expectEqualStrings("hi", first.frame.payload);

    const second = parseFrame(out_buf[first.consumed..result.staged], &scratch).?;
    try std.testing.expectEqualStrings("yo", second.frame.payload);
}

test "zix http1 ws: pumpRing overflow fallback on a dead fd reports close" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Masked client text frame "hi": its echo is a 4-byte server frame. An
    // out_buf of 2 cannot stage it, forcing the direct-write fallback, and
    // fd -1 makes that write fail. The pump must report close: a consumer
    // that cannot take its echoes is shed, never buffered further.
    const data = [_]u8{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'i' ^ 0x02 };

    var payload_buf: [64]u8 = undefined;
    var out_buf: [2]u8 = undefined;
    const result = pumpRing(-1, &data, &payload_buf, &out_buf, testEcho);

    try std.testing.expect(result.close);
}

test "zix http1 ws: pumpRing reports close and consumes the close frame" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Masked client close frame (opcode 0x8) with an empty payload.
    const data = [_]u8{ 0x88, 0x80, 0x01, 0x02, 0x03, 0x04 };

    var payload_buf: [64]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    const result = pumpRing(-1, &data, &payload_buf, &out_buf, testEcho);

    try std.testing.expect(result.close);
    try std.testing.expectEqual(data.len, result.consumed);
    // The server close echo is staged (2-byte header, empty payload).
    try std.testing.expect(result.staged >= 2);
}

test "zix http1 ws: broadcast fans one built frame out to every member" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Three members, each the read end of its own socketpair.
    var pairs: [3][2]i32 = undefined;
    for (&pairs) |*p| {
        try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, p));
    }
    defer for (pairs) |p| {
        _ = std.os.linux.close(p[0]);
        _ = std.os.linux.close(p[1]);
    };

    const conns = [_]std.posix.fd_t{ pairs[0][1], pairs[1][1], pairs[2][1] };
    broadcast(&conns, .text, "room-msg");

    // Every member receives the identical, well-formed text frame.
    for (pairs) |p| {
        var recv: [128]u8 = undefined;
        const n = try fd_io.readOnce(p[0], &recv);

        var scratch: [128]u8 = undefined;
        const parsed = parseFrame(recv[0..n], &scratch).?;
        try std.testing.expectEqual(Opcode.text, parsed.frame.opcode);
        try std.testing.expectEqualStrings("room-msg", parsed.frame.payload);
    }
}

test "zix http1 ws: broadcast skips a dead fd and still reaches live members" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var live: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &live));
    defer _ = std.os.linux.close(live[0]);
    defer _ = std.os.linux.close(live[1]);

    // -1 is never a valid fd, so the write to it fails and is skipped.
    const conns = [_]std.posix.fd_t{ -1, live[1] };
    broadcast(&conns, .binary, "payload");

    var recv: [128]u8 = undefined;
    const n = try fd_io.readOnce(live[0], &recv);

    var scratch: [128]u8 = undefined;
    const parsed = parseFrame(recv[0..n], &scratch).?;
    try std.testing.expectEqual(Opcode.binary, parsed.frame.opcode);
    try std.testing.expectEqualStrings("payload", parsed.frame.payload);
}

test "zix http1 ws: broadcast to an empty member list is a no-op" {
    const conns = [_]std.posix.fd_t{};
    broadcast(&conns, .text, "ignored");
}
