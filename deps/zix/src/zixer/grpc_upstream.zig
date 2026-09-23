//! zixer grpc upstream leg: one h2 connection to a picked upstream, the
//! handshake, stream id allocation, and locked frame writes

const std = @import("std");
const zix = @import("zix");

const conn_buffer = @import("conn_buffer.zig");
const http2_frames = @import("http2_frames.zig");
const upstream_conn = @import("upstream_conn.zig");

const Http2 = zix.Http2;

/// One h2 connection toward an upstream, multiplexing the client streams
/// routed to it.
///
/// Note:
/// - The struct binds reader and writer interfaces to buffers it owns, so
///   it must stay at one address after openInto (the edge session owns it
///   in a fixed array). The buffers themselves are one allocation, sized
///   by the site, and only a connection that actually opened holds any.
/// - Writes come from the up pump (HEADERS, DATA) and the down pump
///   (grants, acks) concurrently, every write helper serializes through
///   write_lock and flushes.
/// - send_window, initial_window, max_frame, and alive are guarded by the
///   edge session's state lock, not by write_lock.
pub const UpConn = struct {
    stream: std.Io.net.Stream,
    slot_index: u32,
    buffers: conn_buffer.Set = .empty,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    write_lock: std.atomic.Value(bool) = .init(false),
    next_stream_id: u31 = 1,
    send_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    initial_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    max_frame: u32 = Http2.DEFAULT_MAX_FRAME_SIZE,
    alive: bool = true,
};

/// Connect to one upstream and run the client-side h2 preface: the
/// connection preface bytes plus an empty SETTINGS frame. The upstream's
/// own SETTINGS is read and acked by the edge's down pump.
///
/// Param:
/// up_conn - *UpConn (initialized in place, address must be final)
/// allocator - std.mem.Allocator (owns this leg's buffers until close)
/// stream_buf_bytes - usize (one direction's size, resolved by the site)
/// connect_timeout_ms - u32 (how long the handshake may take, 0 waits on the
///   operating system's own limit)
///
/// Return:
/// - void, up_conn is ready for stream traffic
/// - error.OutOfMemory, error.ZixerBadUpstreamAddress, error.ZixConnectTimeout,
///   error.ZixConnectFailed, or any write error
pub fn openInto(up_conn: *UpConn, io: std.Io, allocator: std.mem.Allocator, stream_buf_bytes: usize, host: []const u8, port: u16, slot_index: u32, connect_timeout_ms: u32) !void {
    const buffers = try conn_buffer.Set.init(allocator, stream_buf_bytes, .{ .client = false, .upstream = true });
    errdefer buffers.deinit(allocator);

    const conn = try upstream_conn.connect(io, host, port, slot_index, connect_timeout_ms);
    errdefer conn.stream.close(io);

    up_conn.* = .{ .stream = conn.stream, .slot_index = slot_index, .buffers = buffers };
    up_conn.reader = up_conn.stream.reader(io, up_conn.buffers.upstream_read);
    up_conn.writer = up_conn.stream.writer(io, up_conn.buffers.upstream_write);

    try up_conn.writer.interface.writeAll(Http2.PREFACE);
    try http2_frames.writeSettings(&up_conn.writer.interface, &.{});
    try up_conn.writer.interface.flush();
}

/// Close the socket and release the buffers openInto took.
pub fn close(up_conn: *UpConn, io: std.Io, allocator: std.mem.Allocator) void {
    up_conn.stream.close(io);
    up_conn.buffers.deinit(allocator);
    up_conn.buffers = .empty;
}

/// Next client-side stream id on this connection (odd, increasing). The
/// caller holds the edge session's state lock.
pub fn allocStreamId(up_conn: *UpConn) u31 {
    const id = up_conn.next_stream_id;
    up_conn.next_stream_id += 2;

    return id;
}

/// Write one header block (HEADERS plus CONTINUATION as needed) and flush.
pub fn writeHeaders(up_conn: *UpConn, stream_id: u31, block: []const u8, end_stream: bool, max_frame: usize) !void {
    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeHeaderBlock(&up_conn.writer.interface, stream_id, block, end_stream, max_frame);
    try up_conn.writer.interface.flush();
}

/// Write one DATA frame and flush it, so a streamed grpc message reaches
/// the upstream when the client sends it.
pub fn writeData(up_conn: *UpConn, stream_id: u31, bytes: []const u8, end_stream: bool) !void {
    const flags: u8 = if (end_stream) Http2.FLAG_END_STREAM else 0;

    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeFrame(&up_conn.writer.interface, Http2.FRAME_TYPE_DATA, flags, stream_id, bytes);
    try up_conn.writer.interface.flush();
}

/// Reset one upstream stream.
pub fn writeRst(up_conn: *UpConn, stream_id: u31, code: u32) !void {
    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeRstStream(&up_conn.writer.interface, stream_id, code);
    try up_conn.writer.interface.flush();
}

/// Grant consumed flow credit back on the connection and one stream.
pub fn writeGrant(up_conn: *UpConn, stream_id: u31, consumed: u32) !void {
    if (consumed == 0) return;

    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeWindowUpdate(&up_conn.writer.interface, 0, @intCast(consumed));
    if (stream_id != 0) try http2_frames.writeWindowUpdate(&up_conn.writer.interface, stream_id, @intCast(consumed));
    try up_conn.writer.interface.flush();
}

/// Grant consumed connection-level credit only (an unclaimed frame).
pub fn writeConnGrant(up_conn: *UpConn, consumed: u32) !void {
    if (consumed == 0) return;

    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeWindowUpdate(&up_conn.writer.interface, 0, @intCast(consumed));
    try up_conn.writer.interface.flush();
}

/// Ack an upstream SETTINGS frame.
pub fn writeSettingsAck(up_conn: *UpConn) !void {
    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writeSettingsAck(&up_conn.writer.interface);
    try up_conn.writer.interface.flush();
}

/// Ack an upstream PING frame.
pub fn writePingAck(up_conn: *UpConn, payload: []const u8) !void {
    lockWrite(up_conn);
    defer unlockWrite(up_conn);
    try http2_frames.writePingAck(&up_conn.writer.interface, payload);
    try up_conn.writer.interface.flush();
}

fn lockWrite(up_conn: *UpConn) void {
    while (up_conn.write_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockWrite(up_conn: *UpConn) void {
    up_conn.write_lock.store(false, .release);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: grpc upstream, stream ids allocate odd and increasing" {
    var up_conn = UpConn{ .stream = undefined, .slot_index = 0 };

    try testing.expectEqual(@as(u31, 1), allocStreamId(&up_conn));
    try testing.expectEqual(@as(u31, 3), allocStreamId(&up_conn));
    try testing.expectEqual(@as(u31, 5), allocStreamId(&up_conn));
}

test "zix zixer: grpc upstream, open runs the client preface on the wire" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18840);
    var server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 1 });
    defer server.deinit(io);

    var up_conn = UpConn{ .stream = undefined, .slot_index = 3 };
    try openInto(&up_conn, io, testing.allocator, conn_buffer.DEFAULT_BYTES, "127.0.0.1", 18840, 3, 3_000);
    defer close(&up_conn, io, testing.allocator);

    const accepted = try server.accept(io);
    defer accepted.close(io);

    var read_buf: [512]u8 = undefined;
    var reader = accepted.reader(io, &read_buf);

    var preface: [Http2.PREFACE.len]u8 = undefined;
    try reader.interface.readSliceAll(&preface);
    try testing.expectEqualStrings(Http2.PREFACE, &preface);

    var payload_buf: [64]u8 = undefined;
    const settings = try http2_frames.readFrame(&reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), settings.head.frame_type);
    try testing.expectEqual(@as(u24, 0), settings.head.length);

    try testing.expectEqual(@as(u32, 3), up_conn.slot_index);
    try testing.expect(up_conn.alive);
}
