//! zixer websocket tunnel: the rfc 6455 upgrade across the proxy edge,
//! raw bytes both ways after the 101, pick pinned for the tunnel life

const std = @import("std");

const http1_head = @import("http1_head.zig");
const proxy_headers = @import("proxy_headers.zig");

/// Copy ceiling for one tunnel relay burst.
const TUNNEL_CHUNK: usize = 16 * 1024;

/// Both legs of one established tunnel.
pub const Legs = struct {
    io: std.Io,
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    /// Raw client socket: the down leg shuts its receive side to unblock
    /// the waiting client read when the upstream ends first. Null skips
    /// that (socket-less rigs), the up leg then ends on the client's own
    /// close.
    client_stream: ?std.Io.net.Stream,
    up_stream: std.Io.net.Stream,
    up_r: *std.Io.Reader,
    up_w: *std.Io.Writer,
};

/// True when the request asks for the rfc 6455 upgrade zixer tunnels:
/// GET, Connection names upgrade, Upgrade names websocket, no body.
/// Anything else (other Upgrade offers included) proxies as a plain
/// request, dropping the offer is the legal intermediary answer.
pub fn wantsUpgrade(request: *const http1_head.RequestHead) bool {
    if (!std.ascii.eqlIgnoreCase(request.method, "GET")) return false;
    if (request.framing != .none) return false;
    if (!namesToken(request.connection_value, "upgrade")) return false;

    return namesToken(upgradeValue(request), "websocket");
}

/// Append the hop-carried upgrade pair to a rebuilt upstream head. The
/// generic hop-by-hop strip removed them, the tunnel re-adds the canonical
/// form ahead of the blank line.
pub fn writeUpgradeHeaders(out: *std.Io.Writer) !void {
    try out.writeAll("Connection: Upgrade\r\nUpgrade: websocket\r\n");
}

/// Relay the upstream 101 head to the client: end-to-end headers (the
/// Sec-WebSocket-Accept answer among them) plus Via and the re-added
/// upgrade pair.
pub fn writeSwitchHead(client_w: *std.Io.Writer, response: *const http1_head.ResponseHead) !void {
    try client_w.print("HTTP/1.1 101 {s}\r\n", .{response.reason});
    for (response.headerSlice()) |header| {
        if (proxy_headers.isStripped(header.name)) continue;
        if (proxy_headers.namedInConnection(header.name, response.connection_value)) continue;

        try client_w.print("{s}: {s}\r\n", .{ header.name, header.value });
    }

    try client_w.print("Via: {s}\r\n", .{proxy_headers.VIA});
    try client_w.writeAll("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
}

/// Drive the established tunnel until either side ends.
///
/// Note:
/// - The upstream pick happened at the upgrade exchange and this one
///   connection carries the whole session, that is the pinned pick.
/// - Client end half-closes the upstream send side, so the upstream sees
///   a clean EOF while its remaining bytes still drain to the client.
/// - The caller closes both streams after run returns.
pub fn run(legs: Legs) void {
    const io = legs.io;

    // Without the concurrent down leg the tunnel cannot carry both
    // directions, the caller closes both sides.
    var down_leg = io.concurrent(pumpDown, .{legs}) catch return;

    pumpUp(legs);
    legs.up_stream.shutdown(io, .send) catch {};

    down_leg.await(io);
}

/// Client to upstream leg: relay each burst as it arrives.
fn pumpUp(legs: Legs) void {
    while (true) {
        // A zero return stored into the reader buffer instead of the
        // writer (interface readers may), the next pass drains it.
        const got = legs.client_r.stream(legs.up_w, .limited(TUNNEL_CHUNK)) catch return;
        if (got == 0) continue;

        legs.up_w.flush() catch return;
    }
}

/// Upstream to client leg: relay each burst, then unblock the waiting
/// client read when the upstream ends first.
fn pumpDown(legs: Legs) void {
    defer if (legs.client_stream) |stream| stream.shutdown(legs.io, .recv) catch {};

    while (true) {
        const got = legs.up_r.stream(legs.client_w, .limited(TUNNEL_CHUNK)) catch return;
        if (got == 0) continue;

        legs.client_w.flush() catch return;
    }
}

/// The request's Upgrade header value, empty when absent.
fn upgradeValue(request: *const http1_head.RequestHead) []const u8 {
    for (request.headerSlice()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "upgrade")) return header.value;
    }

    return "";
}

/// True when a comma-separated list value names token (case-insensitive).
fn namesToken(value: []const u8, token: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |candidate| {
        const trimmed = std.mem.trim(u8, candidate, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
    }

    return false;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: ws tunnel, upgrade detection takes only the rfc 6455 shape" {
    const plain = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: aaa\r\n\r\n");
    try testing.expect(wantsUpgrade(&plain));

    const listed = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n");
    try testing.expect(wantsUpgrade(&listed));

    const posted = try http1_head.parseRequest("POST /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    try testing.expect(!wantsUpgrade(&posted));

    const no_connection_token = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n");
    try testing.expect(!wantsUpgrade(&no_connection_token));

    const other_protocol = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
    try testing.expect(!wantsUpgrade(&other_protocol));

    const no_upgrade_header = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\n\r\n");
    try testing.expect(!wantsUpgrade(&no_upgrade_header));

    const with_body = try http1_head.parseRequest("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\n");
    try testing.expect(!wantsUpgrade(&with_body));
}

test "zix zixer: ws tunnel, switch head re-adds the upgrade pair once" {
    const response = try http1_head.parseResponse("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", "GET");

    var head_buf: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&head_buf);
    try writeSwitchHead(&out, &response);
    const head = out.buffered();

    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Via: 1.1 zixer\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "Connection:"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "Upgrade:"));
    try testing.expect(std.mem.indexOf(u8, head, "Connection: Upgrade\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Upgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length") == null);
}

// --------------------------------------------------------- //

fn pairStream(handle: std.posix.fd_t) std.Io.net.Stream {
    return .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40010 } } } };
}

/// Tunnel-side rig for the run tests: streams and interfaces over one
/// client socketpair end and one upstream socketpair end.
const TunnelRig = struct {
    client_stream: std.Io.net.Stream,
    up_stream: std.Io.net.Stream,
    client_read_buf: [1024]u8 = undefined,
    client_write_buf: [1024]u8 = undefined,
    up_read_buf: [1024]u8 = undefined,
    up_write_buf: [1024]u8 = undefined,
    client_reader: std.Io.net.Stream.Reader = undefined,
    client_writer: std.Io.net.Stream.Writer = undefined,
    up_reader: std.Io.net.Stream.Reader = undefined,
    up_writer: std.Io.net.Stream.Writer = undefined,

    fn legs(rig: *TunnelRig, io: std.Io) Legs {
        rig.client_reader = rig.client_stream.reader(io, &rig.client_read_buf);
        rig.client_writer = rig.client_stream.writer(io, &rig.client_write_buf);
        rig.up_reader = rig.up_stream.reader(io, &rig.up_read_buf);
        rig.up_writer = rig.up_stream.writer(io, &rig.up_write_buf);

        return .{
            .io = io,
            .client_r = &rig.client_reader.interface,
            .client_w = &rig.client_writer.interface,
            .client_stream = rig.client_stream,
            .up_stream = rig.up_stream,
            .up_r = &rig.up_reader.interface,
            .up_w = &rig.up_writer.interface,
        };
    }
};

fn writeSide(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var write_buf: [256]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn readExact(io: std.Io, stream: std.Io.net.Stream, buf: []u8) !void {
    var read_buf: [256]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    try reader.interface.readSliceAll(buf);
}

fn expectEof(io: std.Io, stream: std.Io.net.Stream) !void {
    var read_buf: [256]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    var probe: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try reader.interface.readSliceShort(&probe));
}

test "zix zixer: ws tunnel, run relays both legs and half-closes on client end" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_fds: [2]std.posix.fd_t = undefined;
    var up_fds: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &client_fds));
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &up_fds));

    var rig = TunnelRig{ .client_stream = pairStream(client_fds[0]), .up_stream = pairStream(up_fds[0]) };
    const tunnel_thread = try std.Thread.spawn(.{}, run, .{rig.legs(io)});

    const peer_client = pairStream(client_fds[1]);
    const peer_up = pairStream(up_fds[1]);

    try writeSide(io, peer_client, "hello");
    var up_seen: [5]u8 = undefined;
    try readExact(io, peer_up, &up_seen);
    try testing.expectEqualStrings("hello", &up_seen);

    try writeSide(io, peer_up, "world");
    var client_seen: [5]u8 = undefined;
    try readExact(io, peer_client, &client_seen);
    try testing.expectEqualStrings("world", &client_seen);

    // Client end: the upstream sees the half-close as EOF, then its own
    // close lets the tunnel finish.
    peer_client.close(io);
    try expectEof(io, peer_up);
    peer_up.close(io);

    tunnel_thread.join();
    rig.client_stream.close(io);
    rig.up_stream.close(io);
}

test "zix zixer: ws tunnel, upstream end unblocks the waiting client leg" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_fds: [2]std.posix.fd_t = undefined;
    var up_fds: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &client_fds));
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &up_fds));

    var rig = TunnelRig{ .client_stream = pairStream(client_fds[0]), .up_stream = pairStream(up_fds[0]) };
    const tunnel_thread = try std.Thread.spawn(.{}, run, .{rig.legs(io)});

    const peer_client = pairStream(client_fds[1]);
    const peer_up = pairStream(up_fds[1]);

    try writeSide(io, peer_client, "ping");
    var up_seen: [4]u8 = undefined;
    try readExact(io, peer_up, &up_seen);
    try testing.expectEqualStrings("ping", &up_seen);

    // Upstream dies while the client leg sits in a blocked read. The join
    // succeeding IS the assertion: the down leg unblocked the client read.
    peer_up.close(io);
    tunnel_thread.join();

    rig.client_stream.close(io);
    rig.up_stream.close(io);
    peer_client.close(io);
}
