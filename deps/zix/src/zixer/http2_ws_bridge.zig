//! zixer http2 websocket bridge: the rfc 8441 extended CONNECT stream
//! bridged to an h1 websocket upstream, DATA frames to raw bytes both ways

const std = @import("std");
const zix = @import("zix");

const http2_frames = @import("http2_frames.zig");

const Http2 = zix.Http2;

/// Poll gap while the down leg waits for send-window credit. Credit only
/// moves when the client grants it, so the wait is client-paced anyway.
const WINDOW_POLL_MS: i64 = 1;

/// Both legs of one established bridge. The h2 side shares the edge
/// connection, so every client write (frames, grants, acks) serializes
/// through write_lock, and the send windows live in atomics the up leg
/// credits while the down leg spends.
pub const Legs = struct {
    io: std.Io,
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    write_lock: *std.atomic.Value(bool),
    /// Raw client socket: the down leg shuts its receive side to unblock
    /// the waiting frame read when the upstream ends first. Null skips
    /// that (socket-less rigs).
    client_stream: ?std.Io.net.Stream,
    stream_id: u31,
    up_stream: std.Io.net.Stream,
    up_r: *std.Io.Reader,
    up_w: *std.Io.Writer,
    conn_window: *std.atomic.Value(i64),
    stream_window: *std.atomic.Value(i64),
    /// Largest DATA payload the peer accepts (already bounded by the
    /// edge's own staging).
    max_frame: usize,
    /// Set by the up leg when the client side ended, aborts a down leg
    /// stuck waiting for window credit.
    stop: *std.atomic.Value(bool),
};

/// Drive the established bridge until either side ends.
///
/// Note:
/// - The upstream pick happened at the CONNECT exchange, this one
///   connection carries the whole session (pinned pick).
/// - Client END_STREAM or RST half-closes the upstream send side, so
///   remaining upstream bytes still drain to the client.
/// - The caller closes both streams after run returns, the edge
///   connection always closes with the tunnel.
pub fn run(legs: Legs) void {
    const io = legs.io;

    var down_leg = io.concurrent(pumpDown, .{legs}) catch return;

    pumpUp(legs);
    legs.stop.store(true, .release);
    legs.up_stream.shutdown(io, .send) catch {};

    down_leg.await(io);
}

/// Client to upstream leg: unwrap DATA frames for the tunnel stream, hand
/// the flow credit back, and keep the shared connection alive (grants,
/// ping acks, settings acks). New streams during a tunnel are refused,
/// the edge closes when the tunnel ends.
fn pumpUp(legs: Legs) void {
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;

    while (true) {
        const frame = http2_frames.readFrame(legs.client_r, &payload_buf) catch return;

        switch (frame.head.frame_type) {
            Http2.FRAME_TYPE_DATA => {
                if (frame.head.stream_id != legs.stream_id) {
                    grantConn(legs, frame.head.length);
                    continue;
                }

                const data = http2_frames.dataPayload(&frame) catch return;
                if (data.len > 0) {
                    legs.up_w.writeAll(data) catch return;
                    legs.up_w.flush() catch return;
                }

                grantTunnel(legs, frame.head.length);
                if ((frame.head.flags & Http2.FLAG_END_STREAM) != 0) return;
            },
            Http2.FRAME_TYPE_WINDOW_UPDATE => {
                const increment = http2_frames.windowIncrement(frame.payload) catch return;

                if (frame.head.stream_id == 0) {
                    _ = legs.conn_window.fetchAdd(increment, .acq_rel);
                } else if (frame.head.stream_id == legs.stream_id) {
                    _ = legs.stream_window.fetchAdd(increment, .acq_rel);
                }
            },
            Http2.FRAME_TYPE_PING => {
                if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;

                lockClient(legs);
                defer unlockClient(legs);
                http2_frames.writePingAck(legs.client_w, frame.payload) catch return;
                legs.client_w.flush() catch return;
            },
            Http2.FRAME_TYPE_SETTINGS => {
                if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;

                // Acked but not applied: a mid-tunnel initial-window change
                // is not folded into the running stream window, explicit
                // WINDOW_UPDATE grants still move credit normally.
                lockClient(legs);
                defer unlockClient(legs);
                http2_frames.writeSettingsAck(legs.client_w) catch return;
                legs.client_w.flush() catch return;
            },
            Http2.FRAME_TYPE_RST_STREAM => {
                if (frame.head.stream_id == legs.stream_id) return;
            },
            Http2.FRAME_TYPE_HEADERS => {
                // A new stream mid-tunnel: refused, the client retries on
                // a fresh connection. The block stays undecoded, which is
                // safe only because this edge connection ends with the
                // tunnel and never decodes again.
                lockClient(legs);
                defer unlockClient(legs);
                http2_frames.writeRstStream(legs.client_w, frame.head.stream_id, Http2.ERR_REFUSED_STREAM) catch return;
                legs.client_w.flush() catch return;
            },
            else => {},
        }
    }
}

/// Upstream to client leg: wrap raw bytes as DATA frames inside the send
/// windows, END_STREAM on upstream EOF, then unblock the waiting client
/// frame read.
fn pumpDown(legs: Legs) void {
    defer if (legs.client_stream) |stream| stream.shutdown(legs.io, .recv) catch {};

    while (true) {
        // At least one byte, then whatever the reader buffered: a filling
        // read would hold streamed bytes hostage until the buffer topped
        // up (the phase 6 SSE lesson).
        const burst = legs.up_r.peekGreedy(1) catch break;

        var offset: usize = 0;
        while (offset < burst.len) {
            if (legs.stop.load(.acquire)) return;

            const window = @min(legs.conn_window.load(.acquire), legs.stream_window.load(.acquire));
            if (window <= 0) {
                std.Io.sleep(legs.io, std.Io.Duration.fromMilliseconds(WINDOW_POLL_MS), .awake) catch {};
                continue;
            }

            const take = @min(burst.len - offset, @min(@as(usize, @intCast(window)), legs.max_frame));

            {
                lockClient(legs);
                defer unlockClient(legs);
                http2_frames.writeFrame(legs.client_w, Http2.FRAME_TYPE_DATA, 0, legs.stream_id, burst[offset..][0..take]) catch return;
                legs.client_w.flush() catch return;
            }

            _ = legs.conn_window.fetchSub(@intCast(take), .acq_rel);
            _ = legs.stream_window.fetchSub(@intCast(take), .acq_rel);
            offset += take;
        }
        legs.up_r.toss(burst.len);
    }

    if (legs.stop.load(.acquire)) return;

    lockClient(legs);
    defer unlockClient(legs);
    http2_frames.writeFrame(legs.client_w, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, legs.stream_id, "") catch return;
    legs.client_w.flush() catch return;
}

/// Grant consumed connection-level flow credit back to the client.
fn grantConn(legs: Legs, consumed: u32) void {
    if (consumed == 0) return;

    lockClient(legs);
    defer unlockClient(legs);
    http2_frames.writeWindowUpdate(legs.client_w, 0, @intCast(consumed)) catch return;
    legs.client_w.flush() catch return;
}

/// Grant consumed credit on both the connection and the tunnel stream.
fn grantTunnel(legs: Legs, consumed: u32) void {
    if (consumed == 0) return;

    lockClient(legs);
    defer unlockClient(legs);
    http2_frames.writeWindowUpdate(legs.client_w, 0, @intCast(consumed)) catch return;
    http2_frames.writeWindowUpdate(legs.client_w, legs.stream_id, @intCast(consumed)) catch return;
    legs.client_w.flush() catch return;
}

fn lockClient(legs: Legs) void {
    while (legs.write_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockClient(legs: Legs) void {
    legs.write_lock.store(false, .release);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn pairStream(handle: std.posix.fd_t) std.Io.net.Stream {
    return .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40011 } } } };
}

/// Bridge-side rig: streams, interfaces, and the shared state one bridge
/// run needs, over one client socketpair end and one upstream end.
const BridgeRig = struct {
    client_stream: std.Io.net.Stream,
    up_stream: std.Io.net.Stream,
    client_read_buf: [4096]u8 = undefined,
    client_write_buf: [4096]u8 = undefined,
    up_read_buf: [4096]u8 = undefined,
    up_write_buf: [4096]u8 = undefined,
    client_reader: std.Io.net.Stream.Reader = undefined,
    client_writer: std.Io.net.Stream.Writer = undefined,
    up_reader: std.Io.net.Stream.Reader = undefined,
    up_writer: std.Io.net.Stream.Writer = undefined,
    write_lock: std.atomic.Value(bool) = .init(false),
    conn_window: std.atomic.Value(i64) = .init(65535),
    stream_window: std.atomic.Value(i64) = .init(65535),
    stop: std.atomic.Value(bool) = .init(false),

    fn legs(rig: *BridgeRig, io: std.Io, stream_id: u31) Legs {
        rig.client_reader = rig.client_stream.reader(io, &rig.client_read_buf);
        rig.client_writer = rig.client_stream.writer(io, &rig.client_write_buf);
        rig.up_reader = rig.up_stream.reader(io, &rig.up_read_buf);
        rig.up_writer = rig.up_stream.writer(io, &rig.up_write_buf);

        return .{
            .io = io,
            .client_r = &rig.client_reader.interface,
            .client_w = &rig.client_writer.interface,
            .write_lock = &rig.write_lock,
            .client_stream = rig.client_stream,
            .stream_id = stream_id,
            .up_stream = rig.up_stream,
            .up_r = &rig.up_reader.interface,
            .up_w = &rig.up_writer.interface,
            .conn_window = &rig.conn_window,
            .stream_window = &rig.stream_window,
            .max_frame = http2_frames.MAX_PAYLOAD,
            .stop = &rig.stop,
        };
    }
};

fn openPair(fds: *[2]std.posix.fd_t) !void {
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, fds));
}

fn writeClientFrame(io: std.Io, stream: std.Io.net.Stream, frame_type: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    var write_buf: [512]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    try http2_frames.writeFrame(&writer.interface, frame_type, flags, stream_id, payload);
    try writer.interface.flush();
}

fn readClientFrame(reader: *std.Io.Reader, payload_buf: []u8) !http2_frames.Frame {
    return http2_frames.readFrame(reader, payload_buf);
}

test "zix zixer: http2 ws bridge, data frames and raw bytes cross both ways" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_fds: [2]std.posix.fd_t = undefined;
    var up_fds: [2]std.posix.fd_t = undefined;
    try openPair(&client_fds);
    try openPair(&up_fds);

    var rig = BridgeRig{ .client_stream = pairStream(client_fds[0]), .up_stream = pairStream(up_fds[0]) };
    const bridge_thread = try std.Thread.spawn(.{}, run, .{rig.legs(io, 1)});

    const peer_client = pairStream(client_fds[1]);
    const peer_up = pairStream(up_fds[1]);
    var peer_read_buf: [4096]u8 = undefined;
    var peer_reader = peer_client.reader(io, &peer_read_buf);

    // client DATA becomes raw upstream bytes, and the credit comes back.
    try writeClientFrame(io, peer_client, Http2.FRAME_TYPE_DATA, 0, 1, "frame-one");
    var up_seen: [9]u8 = undefined;
    var up_read_buf: [256]u8 = undefined;
    var up_reader = peer_up.reader(io, &up_read_buf);
    try up_reader.interface.readSliceAll(&up_seen);
    try testing.expectEqualStrings("frame-one", &up_seen);

    var payload_buf: [4096]u8 = undefined;
    const conn_grant = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_WINDOW_UPDATE), conn_grant.head.frame_type);
    try testing.expectEqual(@as(u31, 0), conn_grant.head.stream_id);
    const stream_grant = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqual(@as(u31, 1), stream_grant.head.stream_id);
    try testing.expectEqual(@as(u31, 9), try http2_frames.windowIncrement(stream_grant.payload));

    // raw upstream bytes become one DATA frame for the tunnel stream.
    var up_write_buf: [256]u8 = undefined;
    var up_writer = peer_up.writer(io, &up_write_buf);
    try up_writer.interface.writeAll("echo-back");
    try up_writer.interface.flush();

    const down = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), down.head.frame_type);
    try testing.expectEqual(@as(u31, 1), down.head.stream_id);
    try testing.expectEqualStrings("echo-back", down.payload);

    // client END_STREAM half-closes the upstream, its close ends the run.
    try writeClientFrame(io, peer_client, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, 1, "");
    var eof_probe: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try up_reader.interface.readSliceShort(&eof_probe));
    peer_up.close(io);

    bridge_thread.join();
    rig.client_stream.close(io);
    rig.up_stream.close(io);
    peer_client.close(io);
}

test "zix zixer: http2 ws bridge, upstream end sends end stream and unblocks the client leg" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_fds: [2]std.posix.fd_t = undefined;
    var up_fds: [2]std.posix.fd_t = undefined;
    try openPair(&client_fds);
    try openPair(&up_fds);

    var rig = BridgeRig{ .client_stream = pairStream(client_fds[0]), .up_stream = pairStream(up_fds[0]) };
    const bridge_thread = try std.Thread.spawn(.{}, run, .{rig.legs(io, 3)});

    const peer_client = pairStream(client_fds[1]);
    const peer_up = pairStream(up_fds[1]);
    var peer_read_buf: [4096]u8 = undefined;
    var peer_reader = peer_client.reader(io, &peer_read_buf);

    try writeClientFrame(io, peer_client, Http2.FRAME_TYPE_DATA, 0, 3, "ping");
    var up_seen: [4]u8 = undefined;
    var up_read_buf: [256]u8 = undefined;
    var up_reader = peer_up.reader(io, &up_read_buf);
    try up_reader.interface.readSliceAll(&up_seen);
    try testing.expectEqualStrings("ping", &up_seen);

    var payload_buf: [4096]u8 = undefined;
    _ = try readClientFrame(&peer_reader.interface, &payload_buf);
    _ = try readClientFrame(&peer_reader.interface, &payload_buf);

    // Upstream dies first: the client leg gets the END_STREAM frame, and
    // the join succeeding proves the blocked frame read was unblocked.
    peer_up.close(io);
    const ended = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), ended.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_STREAM, ended.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqual(@as(u24, 0), ended.head.length);

    bridge_thread.join();
    rig.client_stream.close(io);
    rig.up_stream.close(io);
    peer_client.close(io);
}

test "zix zixer: http2 ws bridge, down leg waits for window credit" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_fds: [2]std.posix.fd_t = undefined;
    var up_fds: [2]std.posix.fd_t = undefined;
    try openPair(&client_fds);
    try openPair(&up_fds);

    var rig = BridgeRig{
        .client_stream = pairStream(client_fds[0]),
        .up_stream = pairStream(up_fds[0]),
        .stream_window = .init(4),
    };
    const bridge_thread = try std.Thread.spawn(.{}, run, .{rig.legs(io, 5)});

    const peer_client = pairStream(client_fds[1]);
    const peer_up = pairStream(up_fds[1]);
    var peer_read_buf: [4096]u8 = undefined;
    var peer_reader = peer_client.reader(io, &peer_read_buf);

    var up_write_buf: [256]u8 = undefined;
    var up_writer = peer_up.writer(io, &up_write_buf);
    try up_writer.interface.writeAll("0123456789");
    try up_writer.interface.flush();

    // Only the 4 credited bytes arrive, the rest waits for the update.
    var payload_buf: [4096]u8 = undefined;
    const first = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqualStrings("0123", first.payload);

    try writeClientFrame(io, peer_client, Http2.FRAME_TYPE_WINDOW_UPDATE, 0, 5, &.{ 0, 0, 0, 32 });
    const rest = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqualStrings("456789", rest.payload);

    // Upstream close ends the run on its own: END_STREAM arrives, and the
    // down leg unblocks the client frame read.
    peer_up.close(io);
    const ended = try readClientFrame(&peer_reader.interface, &payload_buf);
    try testing.expectEqual(Http2.FLAG_END_STREAM, ended.head.flags & Http2.FLAG_END_STREAM);

    bridge_thread.join();
    rig.client_stream.close(io);
    rig.up_stream.close(io);
    peer_client.close(io);
}
