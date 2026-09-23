//! zix http websocket client
//! RFC 6455 client: HTTP upgrade handshake, masked send, unmasked recv.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const socket_poll = @import("../../utils/socket_poll.zig");

/// WebSocket client send chunk buffer.
const WS_SEND_CHUNK: usize = 4096;
/// WebSocket handshake request buffer.
const HANDSHAKE_REQ_BUF: usize = 512;
/// WebSocket handshake response buffer.
const HANDSHAKE_RESP_BUF: usize = 4096;

// --------------------------------------------------------- //

const ws_len_max_7bit = 125;
const ws_len_16bit_marker = 126;
const ws_len_64bit_marker = 127;
const ws_len_max_16bit = std.math.maxInt(u16);
const ws_mask_len: usize = 4;
const ws_len_64bit_field_size: usize = 8;
const ws_max_frame_header: usize = 14;

/// Buffer for the accept-key hash input (client key concatenated with the RFC 6455 GUID).
const WS_ACCEPT_HASH_INPUT_SIZE: usize = 128;

// --------------------------------------------------------- //

/// Fill buf with cryptographically secure random bytes.
fn secureRandom(buf: []u8) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.getrandom(buf.ptr, buf.len, 0);
        return;
    }

    if (comptime builtin.target.os.tag == .windows) {
        win_io.secureRandom(buf) catch {};
        return;
    }

    std.c.arc4random_buf(buf.ptr, buf.len);
}

/// RFC 6455 5.2 WebSocket opcodes.
pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

/// Received WebSocket frame. payload points into the caller-supplied buffer.
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

// --------------------------------------------------------- //

/// Configuration for a WebSocket client.
pub const WsClientConfig = struct {
    /// Event-loop backend. Caller owns and must outlive the client.
    io: std.Io,
    /// TCP connect timeout in milliseconds. 0 = no timeout.
    connect_timeout_ms: u32 = 0,
    /// Time allowed to receive the upgrade response after the handshake request is sent, in
    /// milliseconds. 0 = no timeout. Yields error.ZixResponseTimeout when a server accepts and then
    /// never answers.
    response_timeout_ms: u32 = 0,
    /// Idle bound between frames, in milliseconds. The budget restarts on every frame.
    /// 0 = no timeout. Yields error.ZixReadTimeout when the peer goes quiet.
    ///
    /// Note:
    /// - Defaults to no bound on purpose. A live socket is expected to sit idle between frames, so
    ///   only a caller that knows its peer is chatty (a test, a health probe) should set this.
    read_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //

/// Active WebSocket connection after a successful upgrade handshake.
/// Call deinit() to close.
pub const WsConn = struct {
    const Self = @This();

    fd: std.posix.fd_t,
    /// Idle bound carried over from WsClientConfig, applied per socket read in recvExact.
    /// Defaults to no bound so a hand-built connection reads exactly as it did before the field
    /// existed.
    read_timeout_ms: u32 = 0,

    // --------------------------------------------------------- //

    /// Send a masked client-to-server frame (RFC 6455 5.1 mandates masking).
    ///
    /// Note:
    /// - A fresh 4-byte random mask is generated per call.
    /// - Large payloads are written in 4096-byte chunks to avoid large stack copies.
    ///
    /// Param:
    /// opcode  - Opcode
    /// payload - []const u8
    ///
    /// Return:
    /// - !void
    pub fn send(self: Self, opcode: Opcode, payload: []const u8) !void {
        var mask_key: [ws_mask_len]u8 = undefined;
        secureRandom(&mask_key);

        var header: [ws_max_frame_header]u8 = undefined;
        var header_len: usize = 0;

        header[header_len] = 0x80 | @intFromEnum(opcode);
        header_len += 1;

        if (payload.len <= ws_len_max_7bit) {
            header[header_len] = 0x80 | @as(u8, @intCast(payload.len));
            header_len += 1;
        } else if (payload.len <= ws_len_max_16bit) {
            header[header_len] = 0x80 | ws_len_16bit_marker;
            header[header_len + 1] = @intCast((payload.len >> 8) & 0xFF);
            header[header_len + 2] = @intCast(payload.len & 0xFF);
            header_len += 3;
        } else {
            header[header_len] = 0x80 | ws_len_64bit_marker;
            for (0..ws_len_64bit_field_size) |i| {
                const shift: u6 = @intCast((7 - i) * 8);
                header[header_len + 1 + i] = @intCast((payload.len >> shift) & 0xFF);
            }
            header_len += 1 + ws_len_64bit_field_size;
        }

        @memcpy(header[header_len..][0..ws_mask_len], &mask_key);
        header_len += ws_mask_len;

        try writeAllFD(self.fd, header[0..header_len]);

        var byte_offset: usize = 0;
        var chunk: [WS_SEND_CHUNK]u8 = undefined;

        while (byte_offset < payload.len) {
            const batch_size = @min(payload.len - byte_offset, chunk.len);
            for (0..batch_size) |i| chunk[i] = payload[byte_offset + i] ^ mask_key[(byte_offset + i) % ws_mask_len];
            try writeAllFD(self.fd, chunk[0..batch_size]);
            byte_offset += batch_size;
        }
    }

    /// Receive one server-to-client frame (unmasked per RFC 6455 5.1).
    ///
    /// Note:
    /// - Blocks until a complete frame arrives.
    /// - payload_buf must be large enough for the expected payload.
    /// - null when the connection closes cleanly before the next frame header arrives.
    ///
    /// Param:
    /// payload_buf - []u8 (scratch for the frame payload)
    ///
    /// Return:
    /// - ?Frame
    /// - error.ZixConnectionClosed (EOF mid-frame)
    pub fn recv(self: Self, payload_buf: []u8) !?Frame {
        var header: [2]u8 = undefined;
        if (!try recvExact(self.fd, &header, self.read_timeout_ms)) return null;

        const fin = (header[0] & 0x80) != 0;
        const opcode: Opcode = @enumFromInt(header[0] & 0x0F);
        const masked = (header[1] & 0x80) != 0;
        var payload_len: u64 = header[1] & 0x7F;

        if (payload_len == ws_len_16bit_marker) {
            var ext: [2]u8 = undefined;
            if (!try recvExact(self.fd, &ext, self.read_timeout_ms)) return error.ZixConnectionClosed;
            payload_len = (@as(u64, ext[0]) << 8) | ext[1];
        } else if (payload_len == ws_len_64bit_marker) {
            var ext: [ws_len_64bit_field_size]u8 = undefined;
            if (!try recvExact(self.fd, &ext, self.read_timeout_ms)) return error.ZixConnectionClosed;
            payload_len = 0;
            for (0..ws_len_64bit_field_size) |i| payload_len = (payload_len << 8) | ext[i];
        }

        var mask: [ws_mask_len]u8 = .{ 0, 0, 0, 0 };
        if (masked) {
            if (!try recvExact(self.fd, &mask, self.read_timeout_ms)) return error.ZixConnectionClosed;
        }

        const capped_len: usize = @intCast(@min(payload_len, payload_buf.len));
        if (!try recvExact(self.fd, payload_buf[0..capped_len], self.read_timeout_ms)) return error.ZixConnectionClosed;

        if (masked) {
            for (0..capped_len) |i| payload_buf[i] ^= mask[i % ws_mask_len];
        }

        return Frame{ .fin = fin, .opcode = opcode, .payload = payload_buf[0..capped_len] };
    }

    /// Close the underlying TCP connection.
    pub fn deinit(self: Self) void {
        closeFD(self.fd);
    }
};

// --------------------------------------------------------- //

/// WebSocket client. Performs the RFC 6455 HTTP upgrade handshake and returns a WsConn.
///
/// Usage:
/// ```zig
/// var wsc = zix.Http.WsClient.init(.{ .io = process.io });
/// var conn = try wsc.connect("ws://127.0.0.1:9008/chat");
/// defer conn.deinit();
/// try conn.send(.text, "hello");
/// var buf: [4096]u8 = undefined;
/// if (try conn.recv(&buf)) |frame| {
///     std.debug.print("{s}\n", .{frame.payload});
/// }
/// ```
pub const WsClient = struct {
    const Self = @This();

    config: WsClientConfig,

    // --------------------------------------------------------- //

    /// Initialise the client. No connection is opened until connect() is called.
    pub fn init(config: WsClientConfig) Self {
        return .{ .config = config };
    }

    /// Connect to a WebSocket server and complete the RFC 6455 upgrade handshake.
    ///
    /// Note:
    /// - wss:// (TLS) is not yet supported.
    /// - Caller owns the returned WsConn and must call deinit() on it.
    ///
    /// Param:
    /// url - []const u8 (ws://host:port/path)
    ///
    /// Return:
    /// - WsConn
    /// - error.ZixUrlSchemeUnsupported (the scheme is not ws)
    /// - error.ZixUrlHostMissing (the URL carries no host)
    /// - error.ZixUrlPortInvalid (the port is not a number in range)
    /// - error.ZixTlsNotSupported (wss:// scheme)
    /// - error.ZixHandshakeFailed (server did not send 101 or accept key mismatch)
    pub fn connect(self: Self, url: []const u8) !WsConn {
        const parsed = try parseWsUrl(url);

        const addr = try std.Io.net.IpAddress.resolve(self.config.io, parsed.host, parsed.port);
        const stream = try addr.connect(self.config.io, .{ .mode = .stream, .protocol = .tcp });
        const fd = stream.socket.handle;
        errdefer closeFD(fd);

        var nonce: [16]u8 = undefined;
        secureRandom(&nonce);
        var key_buf: [24]u8 = undefined;
        const key_enc_len = std.base64.standard.Encoder.calcSize(16);
        const ws_key = std.base64.standard.Encoder.encode(key_buf[0..key_enc_len], &nonce);

        var req_buf: [HANDSHAKE_REQ_BUF]u8 = undefined;
        const req = std.fmt.bufPrint(
            &req_buf,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}:{d}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n" ++
                "\r\n",
            .{ parsed.path, parsed.host, parsed.port, ws_key },
        ) catch return error.ZixHandshakeFailed;

        writeAllFD(fd, req) catch return error.ZixHandshakeFailed;

        var resp_buf: [HANDSHAKE_RESP_BUF]u8 = undefined;
        var resp_len: usize = 0;
        var header_end: usize = 0;

        while (resp_len < resp_buf.len) {
            if (!socket_poll.readableWithin(fd, self.config.response_timeout_ms)) return error.ZixResponseTimeout;

            const n = readOnceFD(fd, resp_buf[resp_len..]) catch return error.ZixHandshakeFailed;
            if (n == 0) return error.ZixHandshakeFailed;
            resp_len += n;
            if (std.mem.indexOf(u8, resp_buf[0..resp_len], "\r\n\r\n")) |pos| {
                header_end = pos + 4;
                break;
            }
        }

        if (header_end == 0) return error.ZixHandshakeFailed;
        if (!std.mem.startsWith(u8, resp_buf[0..header_end], "HTTP/1.1 101")) return error.ZixHandshakeFailed;

        var accept_out: [64]u8 = undefined;
        const expected_accept = acceptKey(ws_key, &accept_out) catch return error.ZixHandshakeFailed;
        const server_accept = findHeader(resp_buf[0..header_end], "sec-websocket-accept") orelse return error.ZixHandshakeFailed;

        if (!std.mem.eql(u8, std.mem.trim(u8, server_accept, " \t"), expected_accept)) {
            return error.ZixHandshakeFailed;
        }

        return WsConn{ .fd = fd, .read_timeout_ms = self.config.read_timeout_ms };
    }
};

// --------------------------------------------------------- //

/// Compute Sec-WebSocket-Accept from Sec-WebSocket-Key (RFC 6455 4.2.2).
///
/// Param:
/// key - []const u8 (base64-encoded 16-byte nonce)
/// out - *[64]u8 (caller buffer, result is a sub-slice)
///
/// Return:
/// - ![]const u8
pub fn acceptKey(key: []const u8, out: *[64]u8) ![]const u8 {
    // RFC 6455 1.3: this GUID is mandated by the spec, do not change it.
    const rfc6455_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var hash_input: [WS_ACCEPT_HASH_INPUT_SIZE]u8 = undefined;
    if (key.len + rfc6455_guid.len > hash_input.len) return error.ZixKeyTooLong;

    @memcpy(hash_input[0..key.len], key);
    @memcpy(hash_input[key.len..][0..rfc6455_guid.len], rfc6455_guid);

    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(hash_input[0 .. key.len + rfc6455_guid.len], &hash, .{});

    const enc_len = std.base64.standard.Encoder.calcSize(20);

    return std.base64.standard.Encoder.encode(out[0..enc_len], &hash);
}

// --------------------------------------------------------- //

const WsUrlParsed = struct { host: []const u8, port: u16, path: []const u8 };

fn parseWsUrl(url: []const u8) !WsUrlParsed {
    if (std.mem.startsWith(u8, url, "wss://")) return error.ZixTlsNotSupported;
    if (!std.mem.startsWith(u8, url, "ws://")) return error.ZixUrlSchemeUnsupported;

    const authority_start: usize = "ws://".len;
    const path_start = std.mem.indexOfScalarPos(u8, url, authority_start, '/') orelse url.len;
    const authority = url[authority_start..path_start];
    const path_str: []const u8 = if (path_start < url.len) url[path_start..] else "/";

    if (authority.len == 0) return error.ZixUrlHostMissing;

    const colon_pos = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host: []const u8 = if (colon_pos) |cp| authority[0..cp] else authority;
    const port: u16 = if (colon_pos) |cp|
        (std.fmt.parseInt(u16, authority[cp + 1 ..], 10) catch return error.ZixUrlPortInvalid)
    else
        80;

    if (host.len == 0) return error.ZixUrlHostMissing;

    return WsUrlParsed{ .host = host, .port = port, .path = path_str };
}

/// Close fd: the ntdll shim on Windows, the libc close elsewhere.
fn closeFD(fd: std.posix.fd_t) void {
    if (comptime builtin.os.tag == .windows) {
        win_io.close(fd);
        return;
    }

    _ = std.posix.system.close(fd);
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

fn writeAllFD(fd: std.posix.fd_t, data: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data) catch error.BrokenPipe;

    var written: usize = 0;
    while (written < data.len) {
        const rc = std.posix.system.write(fd, data[written..].ptr, data.len - written);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                written += n;
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

fn recvExact(fd: std.posix.fd_t, buf: []u8, idle_ms: u32) !bool {
    if (buf.len == 0) return true;
    var received: usize = 0;
    while (received < buf.len) {
        if (!socket_poll.readableWithin(fd, idle_ms)) return error.ZixReadTimeout;

        const n = readOnceFD(fd, buf[received..]) catch return error.ZixConnectionClosed;
        if (n == 0) return if (received == 0) false else error.ZixConnectionClosed;
        received += n;
    }
    return true;
}

fn findHeader(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
        if (std.ascii.eqlIgnoreCase(header_name, name)) {
            return std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
        }
    }
    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http ws client: acceptKey RFC 6455 vector" {
    var out: [64]u8 = undefined;
    const accept = try acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "zix http ws client: parseWsUrl basic URL" {
    const parsed = try parseWsUrl("ws://127.0.0.1:9000/chat");
    try std.testing.expectEqualStrings("127.0.0.1", parsed.host);
    try std.testing.expectEqual(@as(u16, 9000), parsed.port);
    try std.testing.expectEqualStrings("/chat", parsed.path);
}

test "zix http ws client: parseWsUrl no path defaults to /" {
    const parsed = try parseWsUrl("ws://127.0.0.1:9000");
    try std.testing.expectEqualStrings("/", parsed.path);
}

test "zix http ws client: parseWsUrl default port 80" {
    const parsed = try parseWsUrl("ws://example.com/chat");
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
}

test "zix http ws client: parseWsUrl wss returns TlsNotSupported" {
    try std.testing.expectError(error.ZixTlsNotSupported, parseWsUrl("wss://example.com/ws"));
}

test "zix http ws client: parseWsUrl names an unsupported scheme as one" {
    try std.testing.expectError(error.ZixUrlSchemeUnsupported, parseWsUrl("http://example.com/"));
}

test "zix http ws client: a server that never answers yields ResponseTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Never accepted on purpose. The handshake request goes out and the upgrade reply never comes.
    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9081);
    var silent = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer silent.deinit(io);

    const client = WsClient.init(.{
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 150,
    });

    try std.testing.expectError(error.ZixResponseTimeout, client.connect("ws://127.0.0.1:9081/ws"));
}

test "zix http ws client: a peer that sends no frame yields ReadTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9082);
    var listener = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer listener.deinit(io);

    // Completes a real upgrade (the client verifies Sec-WebSocket-Accept, so the key has to be
    // echoed through acceptKey) and then sends no frame at all. Held open, because closing would
    // give ConnectionClosed instead of the stall under test.
    const Mute = struct {
        fn serve(listen_srv: *std.Io.net.Server, srv_io: std.Io, release: *std.atomic.Value(bool)) void {
            const stream = listen_srv.accept(srv_io) catch return;
            defer stream.close(srv_io);

            var scratch: [2048]u8 = undefined;
            var reader = stream.reader(srv_io, &scratch);

            var key_buf: [128]u8 = undefined;
            var key_len: usize = 0;
            while (reader.interface.takeDelimiterInclusive('\n') catch null) |line| {
                if (line.len <= 2) break;

                const trimmed = std.mem.trimEnd(u8, line, "\r\n");
                const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
                if (!std.ascii.eqlIgnoreCase(trimmed[0..colon], "sec-websocket-key")) continue;

                const value = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
                key_len = @min(value.len, key_buf.len);
                @memcpy(key_buf[0..key_len], value[0..key_len]);
            }

            var accept_out: [64]u8 = undefined;
            const accept = acceptKey(key_buf[0..key_len], &accept_out) catch return;

            var sink: [512]u8 = undefined;
            var writer = stream.writer(srv_io, &sink);
            writer.interface.print(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
                .{accept},
            ) catch return;
            writer.interface.flush() catch return;

            var rounds: usize = 0;
            while (!release.load(.acquire) and rounds < 5000) : (rounds += 1) {
                std.Io.sleep(srv_io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
            }
        }
    };

    var release: std.atomic.Value(bool) = .init(false);
    const serve_thread = try std.Thread.spawn(.{}, Mute.serve, .{ &listener, io, &release });
    defer serve_thread.join();

    const client = WsClient.init(.{
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 3000,
        .read_timeout_ms = 150,
    });

    var conn = client.connect("ws://127.0.0.1:9082/ws") catch |err| {
        release.store(true, .release);
        return err;
    };
    defer conn.deinit();

    var buf: [1024]u8 = undefined;
    const outcome = conn.recv(&buf);
    release.store(true, .release);

    try std.testing.expectError(error.ZixReadTimeout, outcome);
}
