//! zix http websocket
//! RFC 6455: frame parsing, handshake, room-based broadcast.

const std = @import("std");
const win_io = @import("../../utils/windows_io.zig");
const response = @import("response.zig");

/// WebSocket handshake response header buffer.
const HANDSHAKE_HEADER_BUF: usize = 256;
/// WebSocket handshake write buffer.
const HANDSHAKE_WRITE_BUF: usize = 256;

// --------------------------------------------------------- //

const ws_len_max_7bit = 125;
const ws_len_16bit_marker = 126;
const ws_len_64bit_marker = 127;
const ws_len_max_16bit = std.math.maxInt(u16);
const ws_mask_len: usize = 4;
const ws_len_64bit_field_size: usize = 8;
const broadcast_payload_max: usize = 4096;
const ws_max_frame_header: usize = 10;

/// Buffer for the accept-key hash input (client key concatenated with the RFC 6455 GUID).
const WS_ACCEPT_HASH_INPUT_SIZE: usize = 128;

// --------------------------------------------------------- //

/// RFC 6455 5.2: WebSocket opcodes.
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
/// - Client->server frames are masked, the unmasked payload is written into payload_buf.
///   payload_buf must be at least as large as the expected payload (max 4 KB recommended).
/// - null if buf does not yet contain a complete frame.
///
/// Param:
/// buf - []const u8 (raw bytes from the TCP connection)
/// payload_buf - []u8 (caller-provided buffer for unmasked payload)
///
/// Return:
/// - ?ParseResult
/// Read some bytes from a WebSocket connection fd, for a handler-owned frame
/// loop. Portable: the ntdll shim on Windows, std.posix.read elsewhere.
///
/// Return:
/// - usize (bytes read, 0 when the peer closed)
/// - read error otherwise
pub fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

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

/// Build the header of a server-to-client WebSocket frame (unmasked per
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

/// Build a server-to-client WebSocket frame (unmasked per RFC 6455 5.1).
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
/// out - *[64]u8    (caller-provided output buffer, result is a sub-slice of it)
///
/// Return:
/// - ![]const u8
pub fn acceptKey(key: []const u8, out: *[64]u8) ![]const u8 {
    // RFC 6455 1.3: this exact GUID is mandated by the WebSocket spec, do not change it.
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

/// Perform the HTTP -> WebSocket upgrade handshake.
/// Writes the 101 Switching Protocols response directly onto the stream,
/// bypassing the zix Response layer.
///
/// Param:
/// stream  - std.Io.net.Stream (ctx.stream from the handler)
/// io      - std.Io
/// accept  - []const u8 (value returned by acceptKey)
///
/// Return:
/// - !void
pub fn upgrade(stream: std.Io.net.Stream, io: std.Io, accept: []const u8) !void {
    var hdr_buf: [HANDSHAKE_HEADER_BUF]u8 = undefined;
    const response_bytes = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    );
    var write_buf: [HANDSHAKE_WRITE_BUF]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll(response_bytes);
    try writer.interface.flush();
}

// --------------------------------------------------------- //
// engine-driven WebSocket over TLS (ADR-055)
// --------------------------------------------------------- //

/// Largest frame written with one combined header + payload buffer, above this the header and
/// payload are written separately to avoid a large stack copy.
const ws_send_inline_cap: usize = 4096;

/// Per-frame callback for the engine-driven WebSocket-over-TLS loop. Matches the http1 shape so a
/// handler reads the same. `fd` is the sentinel (-1) over TLS, used only to match the send sink.
pub const WsFrameFn = *const fn (fd: std.posix.fd_t, opcode: u8, payload: []const u8) void;

const WsPending = struct {
    fd: std.posix.fd_t,
    on_frame: WsFrameFn,
};

/// Set by serveTls during a handler, read by the https serve loop right after the handler returns.
/// Thread-local so each connection thread hands off only its own connection.
threadlocal var tl_ws_pending: ?WsPending = null;

/// Request that this connection be promoted to a WebSocket after the handler returns. serveTls calls
/// this for you. Honored on the thread-per-connection https path only.
pub fn requestWebSocket(fd: std.posix.fd_t, on_frame: WsFrameFn) void {
    tl_ws_pending = .{ .fd = fd, .on_frame = on_frame };
}

/// Take and clear any pending WebSocket promotion for the current thread.
pub fn takeWebSocket() ?WsPending {
    const pending = tl_ws_pending;
    tl_ws_pending = null;

    return pending;
}

/// Coalesces every frame sent during one pump pass into a single write, so a burst flushes once.
/// Over TLS the flush goes through response.writeAllFD, which the stream sink encrypts into one
/// record (ADR-054).
const SendSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,

    fn append(self: *SendSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            response.writeAllFD(self.fd, bytes) catch {
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

        response.writeAllFD(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

threadlocal var tl_send_sink: ?*SendSink = null;

/// Build and write one unmasked server frame. During a pump pass the frame is staged into the send
/// sink for a single batched, encrypted write, otherwise it goes out immediately through
/// response.writeAllFD (the stream sink encrypts it over TLS).
///
/// Param:
/// fd      - std.posix.fd_t (the sentinel fd over TLS)
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

        return response.writeAllFD(fd, buf[0..len]);
    }

    var hdr: [ws_max_frame_header]u8 = undefined;
    const hdr_len = buildHeader(&hdr, opcode, payload.len);

    try response.writeAllFD(fd, hdr[0..hdr_len]);
    try response.writeAllFD(fd, payload);
}

/// Outcome of one pump pass over a connection's read buffer.
pub const PumpResult = struct {
    /// Bytes consumed from the front of data (whole frames only).
    consumed: usize,
    /// Whether the connection should close (close frame seen or write failed).
    close: bool,
};

/// Parse and dispatch every complete frame in data, in order. Text and binary frames invoke
/// on_frame, ping is auto-ponged, close is auto-echoed and ends the connection. A trailing partial
/// frame is left for the next read. All frames sent during the pass are coalesced into out_buf and
/// flushed in one write.
///
/// Param:
/// fd          - std.posix.fd_t
/// data        - []const u8 (raw frame bytes received so far)
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

/// Write the 101 Switching Protocols response through response.writeAllFD (the fd / sink path), the
/// TLS counterpart of `upgrade` which writes onto a std.Io stream.
pub fn upgradeFd(fd: std.posix.fd_t, accept: []const u8) !void {
    var hdr_buf: [HANDSHAKE_HEADER_BUF]u8 = undefined;
    const resp = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    );

    try response.writeAllFD(fd, resp);
}

/// Complete the handshake over TLS, then hand the connection to the https thread (ADR-055). Call
/// this from a handler served over TLS (`config.tls`, the `.ASYNC` path)
/// instead of `upgrade` + a stream loop: it detaches the buffered response capture so the `101` and
/// every frame encrypt one TLS record per write (the ADR-054 stream sink), then registers the
/// handoff. After the handler returns, the https serve loop drives the inline frame loop over the
/// TLS session, invoking on_frame per text / binary frame (ping auto-ponged, close auto-echoed).
///
/// Note:
/// - Thread-per-connection only. `fd` is the sentinel (-1) the handler is given over TLS.
/// - Rooms / broadcast are not served over TLS (each connection has its own session). Use `sendFD`.
///
/// Param:
/// fd       - std.posix.fd_t (the sentinel fd, from ctx.stream.socket.handle over TLS)
/// key      - []const u8 (the Sec-WebSocket-Key request header value)
/// on_frame - WsFrameFn
///
/// Return:
/// - !void (handshake errors from acceptKey / upgradeFd)
pub fn serveTls(fd: std.posix.fd_t, key: []const u8, on_frame: WsFrameFn) !void {
    var accept_buf: [64]u8 = undefined;
    const accept = try acceptKey(key, &accept_buf);

    response.tl_resp_sink = null;
    try upgradeFd(fd, accept);
    requestWebSocket(fd, on_frame);
}

// --------------------------------------------------------- //

/// Heap-allocated per-connection handle.
/// Created by the handler with smp_allocator, destroyed when the WS session ends.
pub const Conn = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
};

const Room = struct {
    conns: std.ArrayList(*Conn),
};

/// Thread-safe registry of named rooms, each holding a list of active connections.
///
/// Lifecycle:
/// - Initialize once in main() before server.run().
/// - Call join() when a WebSocket connection opens.
/// - Call leave() (via defer) when a WebSocket connection closes.
/// - broadcast() sends a text frame to every connection in a room.
pub const RoomMap = struct {
    rooms: std.StringHashMap(Room),
    mu: std.Io.Mutex,
    allocator: std.mem.Allocator,

    /// Initialize the room map
    ///
    /// Param:
    /// allocator - std.mem.Allocator (process-lifetime allocator, e.g. smp_allocator)
    ///
    /// Return:
    /// - RoomMap
    pub fn init(allocator: std.mem.Allocator) RoomMap {
        return .{
            .rooms = std.StringHashMap(Room).init(allocator),
            .mu = .init,
            .allocator = allocator,
        };
    }

    /// Free all room and connection list storage, including owned-copy room keys
    pub fn deinit(self: *RoomMap) void {
        var it = self.rooms.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.conns.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.rooms.deinit();
    }

    /// Add a connection to a room, creating the room if needed
    ///
    /// Note:
    /// - The room key is owned-copied so its lifetime is independent of any connection buffer.
    ///
    /// Param:
    /// room - []const u8
    /// conn - *Conn
    /// io   - std.Io
    pub fn join(self: *RoomMap, room: []const u8, conn: *Conn, io: std.Io) void {
        self.mu.lock(io) catch return;
        defer self.mu.unlock(io);

        const room_entry = self.rooms.getOrPut(room) catch return;
        if (!room_entry.found_existing) {
            // Own-copy the key so it doesn't dangle when the connection's read
            // buffer is freed after the WebSocket session ends.
            const owned = self.allocator.dupe(u8, room) catch {
                _ = self.rooms.remove(room);
                return;
            };
            room_entry.key_ptr.* = owned;
            room_entry.value_ptr.* = .{ .conns = .empty };
        }
        room_entry.value_ptr.conns.append(self.allocator, conn) catch return;
    }

    /// Remove a connection from its room, removes the room if it becomes empty
    ///
    /// Note:
    /// - Safe to call from defer, no-op if the conn is not found.
    /// - When the last connection leaves, the owned-copy room key is freed.
    ///
    /// Param:
    /// room - []const u8
    /// conn - *Conn
    /// io   - std.Io
    pub fn leave(self: *RoomMap, room: []const u8, conn: *Conn, io: std.Io) void {
        self.mu.lock(io) catch return;
        defer self.mu.unlock(io);

        const room_ptr = self.rooms.getPtr(room) orelse return;

        var i: usize = 0;
        while (i < room_ptr.conns.items.len) {
            if (room_ptr.conns.items[i] == conn) {
                _ = room_ptr.conns.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        const count = room_ptr.conns.items.len;

        if (count == 0) {
            if (self.rooms.fetchRemove(room)) |kv| {
                var conns = kv.value.conns;
                conns.deinit(self.allocator);
                self.allocator.free(kv.key);
            }
        }
    }

    /// Broadcast a text message to all connections in a room
    ///
    /// Note:
    /// - Frames are serialized once and sent to every connection.
    /// - Payload is capped at 4 KB, larger messages are silently truncated.
    /// - Failed writes are skipped, dead connections are cleaned up by their own handler's leave().
    ///
    /// Param:
    /// room    - []const u8
    /// message - []const u8
    /// io      - std.Io
    pub fn broadcast(self: *RoomMap, room: []const u8, message: []const u8, io: std.Io) void {
        self.mu.lock(io) catch return;
        defer self.mu.unlock(io);

        const room_ptr = self.rooms.getPtr(room) orelse return;

        const payload = message[0..@min(message.len, broadcast_payload_max)];
        var frame_buf: [broadcast_payload_max + ws_max_frame_header]u8 = undefined;
        const frame_len = buildFrame(&frame_buf, .text, payload);
        const frame_data = frame_buf[0..frame_len];

        // Build once, fan out: the staging buffer is reused across every member
        // rather than re-created per connection.
        var write_buf: [broadcast_payload_max + ws_max_frame_header]u8 = undefined;
        for (room_ptr.conns.items) |conn| {
            var writer = conn.stream.writer(conn.io, &write_buf);
            writer.interface.writeAll(frame_data) catch continue;
            writer.interface.flush() catch continue;
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: websocket readOnceFD reads pipe bytes then reports close" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);

    _ = linux.write(pipe_fds[1], "frame", 5);
    _ = linux.close(pipe_fds[1]);

    var buf: [16]u8 = undefined;
    const n = try readOnceFD(pipe_fds[0], &buf);
    try std.testing.expectEqualStrings("frame", buf[0..n]);

    try std.testing.expectEqual(@as(usize, 0), try readOnceFD(pipe_fds[0], &buf));
}

test "zix http: websocket buildHeader matches buildFrame prefix" {
    const payload = "hello";
    var frame_buf: [128]u8 = undefined;
    var hdr_buf: [ws_max_frame_header]u8 = undefined;

    const frame_len = buildFrame(&frame_buf, .text, payload);
    const hdr_len = buildHeader(&hdr_buf, .text, payload.len);

    try std.testing.expectEqual(frame_len - payload.len, hdr_len);
    try std.testing.expectEqualSlices(u8, frame_buf[0..hdr_len], hdr_buf[0..hdr_len]);
}

test "zix http: websocket acceptKey" {
    var out: [64]u8 = undefined;
    const accept = try acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "zix http: websocket frame" {
    const payload = "hello";
    var buf: [128]u8 = undefined;
    const len = buildFrame(&buf, .text, payload);

    try std.testing.expect(len > payload.len);
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]); // fin | text
    try std.testing.expectEqual(@as(u8, 5), buf[1]); // unmasked, len 5
    try std.testing.expectEqualStrings(payload, buf[2..len]);

    var payload_buf: [128]u8 = undefined;
    const result = parseFrame(buf[0..len], &payload_buf).?;
    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings(payload, result.frame.payload);
    try std.testing.expectEqual(len, result.consumed);
}

test "zix http: websocket masked frame" {
    // Masked "Hello" from RFC 6455 5.7
    const raw = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var payload_buf: [128]u8 = undefined;
    const result = parseFrame(&raw, &payload_buf).?;
    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqual(Opcode.text, result.frame.opcode);
    try std.testing.expectEqualStrings("Hello", result.frame.payload);
}

test "zix http: websocket SIMD unmask matches scalar for 32-byte payload" {
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

test "zix http: websocket SIMD unmask handles tail bytes (17-byte payload)" {
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
