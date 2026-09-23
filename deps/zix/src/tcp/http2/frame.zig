//! HTTP/2 frame codec: constants, FrameHeader, read/write, control frame senders.

const std = @import("std");
const socket_pair = @import("../../utils/socket_pair.zig");
const fd_io = @import("../../utils/fd_io.zig");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");

// --------------------------------------------------------- //

pub const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame header length in octets (RFC 7540 section 4.1): 3 length + 1 type + 1 flags + 4 stream id.
pub const FRAME_HEADER_LEN: usize = 9;

/// Slack added over the negotiated SETTINGS_MAX_FRAME_SIZE when sizing a read or
/// staging buffer: covers the frame header plus small HPACK and control overhead.
pub const FRAME_PAYLOAD_SLACK: usize = 256;

/// Default initial flow-control window (RFC 7540 6.9.2). Also the per-step
/// connection-level WINDOW_UPDATE increment (grant one default window of credit).
pub const DEFAULT_WINDOW_SIZE: u32 = 65535;

/// HPACK encode scratch for one response HEADERS block.
pub const HPACK_ENCODE_SCRATCH: usize = 512;

/// Body-size cutoff for staging a whole response into one buffer and one write. At or below this
/// the body is copied next to its frame headers (one syscall, one hook append). Above it the body
/// leaves zero-copy as the payload half of a vectored write. Loopback-measured crossover: the
/// staged copy wins below 4 KiB, the vectored send wins past it.
pub const SEND_STAGE_BODY_MAX: usize = 4096;

/// Send stage: HEADERS frame header + HPACK block + DATA frame header + a body up to
/// SEND_STAGE_BODY_MAX.
const SEND_STAGE_SIZE: usize = FRAME_HEADER_LEN + HPACK_ENCODE_SCRATCH + FRAME_HEADER_LEN + SEND_STAGE_BODY_MAX;

pub const FRAME_TYPE_DATA: u8 = 0x00;
pub const FRAME_TYPE_HEADERS: u8 = 0x01;
pub const FRAME_TYPE_PRIORITY: u8 = 0x02;
pub const FRAME_TYPE_RST_STREAM: u8 = 0x03;
pub const FRAME_TYPE_SETTINGS: u8 = 0x04;
pub const FRAME_TYPE_PUSH_PROMISE: u8 = 0x05;
pub const FRAME_TYPE_PING: u8 = 0x06;
pub const FRAME_TYPE_GOAWAY: u8 = 0x07;
pub const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x08;
pub const FRAME_TYPE_CONTINUATION: u8 = 0x09;

pub const FLAG_END_STREAM: u8 = 0x01;
pub const FLAG_END_HEADERS: u8 = 0x04;
pub const FLAG_PADDED: u8 = 0x08;
pub const FLAG_PRIORITY: u8 = 0x20;
pub const FLAG_ACK: u8 = 0x01;

pub const ERR_NO_ERROR: u32 = 0x00;
pub const ERR_PROTOCOL_ERROR: u32 = 0x01;
pub const ERR_INTERNAL_ERROR: u32 = 0x02;
pub const ERR_FLOW_CONTROL_ERROR: u32 = 0x03;
pub const ERR_SETTINGS_TIMEOUT: u32 = 0x04;
pub const ERR_STREAM_CLOSED: u32 = 0x05;
pub const ERR_FRAME_SIZE_ERROR: u32 = 0x06;
pub const ERR_REFUSED_STREAM: u32 = 0x07;
pub const ERR_CANCEL: u32 = 0x08;
pub const ERR_COMPRESSION_ERROR: u32 = 0x09;
pub const ERR_CONNECT_ERROR: u32 = 0x0a;
pub const ERR_ENHANCE_YOUR_CALM: u32 = 0x0b;
pub const ERR_INADEQUATE_SECURITY: u32 = 0x0c;
pub const ERR_HTTP_1_1_REQUIRED: u32 = 0x0d;

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x01;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x02;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x03;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;

pub const DEFAULT_INITIAL_WINDOW: u32 = 65535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;
pub const MAX_HEADERS: usize = 64;
pub const MAX_PAYLOAD: usize = 16384;

// --------------------------------------------------------- //

pub const FrameHeader = struct {
    length: u24,
    frame_type: u8,
    flags: u8,
    stream_id: u31,
};

/// Parse a 9-byte frame header from buf (len >= 9). No I/O. Use with a buffered reader.
pub fn parseFrameHeader(buf: []const u8) FrameHeader {
    const length: u24 = (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2];
    const stream_id: u31 = @intCast(
        ((@as(u32, buf[5]) << 24) | (@as(u32, buf[6]) << 16) | (@as(u32, buf[7]) << 8) | buf[8]) & 0x7FFF_FFFF,
    );
    return .{
        .length = length,
        .frame_type = buf[3],
        .flags = buf[4],
        .stream_id = stream_id,
    };
}

pub fn readFrameHeader(fd: std.posix.fd_t) !FrameHeader {
    var buf: [FRAME_HEADER_LEN]u8 = undefined;
    try recvExact(fd, &buf);
    return parseFrameHeader(&buf);
}

/// Encode a 9-byte frame header into buf. No I/O. Use for staged/coalesced writes.
pub fn encodeFrameHeader(buf: *[FRAME_HEADER_LEN]u8, fh: FrameHeader) void {
    buf[0] = @intCast((fh.length >> 16) & 0xFF);
    buf[1] = @intCast((fh.length >> 8) & 0xFF);
    buf[2] = @intCast(fh.length & 0xFF);
    buf[3] = fh.frame_type;
    buf[4] = fh.flags;
    const sid: u32 = fh.stream_id;
    buf[5] = @intCast((sid >> 24) & 0xFF);
    buf[6] = @intCast((sid >> 16) & 0xFF);
    buf[7] = @intCast((sid >> 8) & 0xFF);
    buf[8] = @intCast(sid & 0xFF);
}

pub fn writeFrameHeaderFD(fd: std.posix.fd_t, fh: FrameHeader) !void {
    var buf: [FRAME_HEADER_LEN]u8 = undefined;
    encodeFrameHeader(&buf, fh);
    try writeAllFD(fd, &buf);
}

// --------------------------------------------------------- //

/// Thread-local output redirect. When set, `writeAllFD` hands the plaintext to the hook instead of
/// writing it to the fd. The h2-over-TLS path uses this to encrypt the engine's frames before they
/// reach the socket, so the resumable mux runs unchanged over a TLS connection (no socketpair, no
/// second thread). Null on the cleartext path, where writes go straight to the fd.
pub threadlocal var write_hook: ?*const fn (ctx: *anyopaque, bytes: []const u8) void = null;
pub threadlocal var write_hook_ctx: ?*anyopaque = null;

/// Whether frames for the stream in flight have already left for the peer.
///
/// Note:
/// - The `Response` builder tracks the same thing in `Response.sent`, but a handler may answer
///   through the fd writers instead, which hold no `Response`. Without this the engine reads such
///   a handler as never having answered and completes it a second time, putting a second HEADERS
///   frame on a stream the peer already saw closed.
/// - Cleared by core.invokeHandler, so an engine frame written before dispatch (SETTINGS, the
///   WINDOW_UPDATE that paced the request body) is never mistaken for the handler answering.
pub threadlocal var tl_responded: bool = false;

/// Record that frames for the stream in flight left for the peer.
///
/// Note:
/// - Called by the fd writers, never by a handler. `Response.send*` reaches them through
///   `sendResponseEncodedFD`, so both answer styles set it.
///
/// Return:
/// - void
pub fn markResponded() void {
    tl_responded = true;
}

/// Whether the stream in flight has been answered through the fd writers.
///
/// Return:
/// - bool
pub fn respondedFD() bool {
    return tl_responded;
}

pub fn writeAllFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    markResponded();

    if (write_hook) |hook| {
        hook(write_hook_ctx.?, data);
        return;
    }

    return writeAllRawFD(fd, data);
}

/// Hook-bypassing blocking write-all. A coalescing sink installed as the write hook flushes its
/// staged bytes through this so the flush does not re-enter the hook (which would recurse). Polls on
/// EAGAIN for a non-blocking socket. Identical to writeAllFD minus the hook check.
pub fn writeAllRawFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data);

    var rem = data;
    while (rem.len > 0) {
        const rc = std.posix.system.write(fd, rem.ptr, rem.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                rem = rem[n..];
            },
            .INTR => continue,
            // Non-blocking EPOLL socket with a full send buffer: poll until
            // writable then retry. Blocking sockets never hit this branch.
            .AGAIN => {
                var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                _ = std.posix.poll(&pfd, -1) catch return error.BrokenPipe;
            },
            else => return error.BrokenPipe,
        }
    }
}

/// Hook-bypassing vectored write-all of a header + payload pair: one syscall carries both on the
/// cleartext posix path. Polls on EAGAIN like writeAllRawFD. Windows writes the pair sequentially.
fn writevAllRawFD(fd: std.posix.fd_t, head: []const u8, payload: []const u8) error{BrokenPipe}!void {
    if (comptime builtin.os.tag == .windows) {
        try win_io.writeAll(fd, head);
        return win_io.writeAll(fd, payload);
    }

    var iovs = [2]std.posix.iovec_const{
        .{ .base = head.ptr, .len = head.len },
        .{ .base = payload.ptr, .len = payload.len },
    };
    var iov_idx: usize = 0;

    while (iov_idx < iovs.len) {
        const rc = std.posix.system.writev(fd, iovs[iov_idx..].ptr, @intCast(iovs.len - iov_idx));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                var accepted: usize = @intCast(rc);
                if (accepted == 0) return error.BrokenPipe;

                while (iov_idx < iovs.len and accepted >= iovs[iov_idx].len) {
                    accepted -= iovs[iov_idx].len;
                    iov_idx += 1;
                }
                if (iov_idx < iovs.len and accepted > 0) {
                    iovs[iov_idx].base += accepted;
                    iovs[iov_idx].len -= accepted;
                }
            },
            .INTR => continue,
            // Non-blocking EPOLL socket with a full send buffer: poll until
            // writable then retry. Blocking sockets never hit this branch.
            .AGAIN => {
                var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                _ = std.posix.poll(&pfd, -1) catch return error.BrokenPipe;
            },
            else => return error.BrokenPipe,
        }
    }
}

/// Write a frame header + payload pair. A hook receives the two slices as two appends (its sink
/// coalesces them itself), the cleartext path sends both in one vectored syscall.
fn writePairFD(fd: std.posix.fd_t, head: []const u8, payload: []const u8) error{BrokenPipe}!void {
    markResponded();

    if (write_hook) |hook| {
        hook(write_hook_ctx.?, head);
        hook(write_hook_ctx.?, payload);
        return;
    }

    return writevAllRawFD(fd, head, payload);
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return fd_io.readOnce(fd, buf);
}

pub fn recvExact(fd: std.posix.fd_t, buf: []u8) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = readOnceFD(fd, buf[filled..]) catch return error.ZixClosed;
        if (n == 0) return error.ZixClosed;
        filled += n;
    }
}

// --------------------------------------------------------- //

pub fn sendSettingsFD(fd: std.posix.fd_t, params: []const [2]u32) !void {
    const payload_len: usize = params.len * 6;
    try writeFrameHeaderFD(fd, .{
        .length = @intCast(payload_len),
        .frame_type = FRAME_TYPE_SETTINGS,
        .flags = 0,
        .stream_id = 0,
    });
    var buf: [6]u8 = undefined;
    for (params) |p| {
        const id: u16 = @intCast(p[0]);
        const val: u32 = p[1];
        buf[0] = @intCast((id >> 8) & 0xFF);
        buf[1] = @intCast(id & 0xFF);
        buf[2] = @intCast((val >> 24) & 0xFF);
        buf[3] = @intCast((val >> 16) & 0xFF);
        buf[4] = @intCast((val >> 8) & 0xFF);
        buf[5] = @intCast(val & 0xFF);
        try writeAllFD(fd, &buf);
    }
}

pub fn sendSettingsAckFD(fd: std.posix.fd_t) !void {
    try writeFrameHeaderFD(fd, .{
        .length = 0,
        .frame_type = FRAME_TYPE_SETTINGS,
        .flags = FLAG_ACK,
        .stream_id = 0,
    });
}

pub fn sendPingAckFD(fd: std.posix.fd_t, payload: [8]u8) !void {
    try writeFrameHeaderFD(fd, .{
        .length = 8,
        .frame_type = FRAME_TYPE_PING,
        .flags = FLAG_ACK,
        .stream_id = 0,
    });
    try writeAllFD(fd, &payload);
}

pub fn sendGoawayFD(fd: std.posix.fd_t, last_stream: u31, error_code: u32) !void {
    try writeFrameHeaderFD(fd, .{
        .length = 8,
        .frame_type = FRAME_TYPE_GOAWAY,
        .flags = 0,
        .stream_id = 0,
    });
    var buf: [8]u8 = undefined;
    const ls: u32 = last_stream;
    buf[0] = @intCast((ls >> 24) & 0xFF);
    buf[1] = @intCast((ls >> 16) & 0xFF);
    buf[2] = @intCast((ls >> 8) & 0xFF);
    buf[3] = @intCast(ls & 0xFF);
    buf[4] = @intCast((error_code >> 24) & 0xFF);
    buf[5] = @intCast((error_code >> 16) & 0xFF);
    buf[6] = @intCast((error_code >> 8) & 0xFF);
    buf[7] = @intCast(error_code & 0xFF);
    try writeAllFD(fd, &buf);
}

pub fn sendRstStreamFD(fd: std.posix.fd_t, stream_id: u31, error_code: u32) !void {
    try writeFrameHeaderFD(fd, .{
        .length = 4,
        .frame_type = FRAME_TYPE_RST_STREAM,
        .flags = 0,
        .stream_id = stream_id,
    });
    var buf: [4]u8 = undefined;
    buf[0] = @intCast((error_code >> 24) & 0xFF);
    buf[1] = @intCast((error_code >> 16) & 0xFF);
    buf[2] = @intCast((error_code >> 8) & 0xFF);
    buf[3] = @intCast(error_code & 0xFF);
    try writeAllFD(fd, &buf);
}

pub fn sendWindowUpdateFD(fd: std.posix.fd_t, stream_id: u31, increment: u31) !void {
    try writeFrameHeaderFD(fd, .{
        .length = 4,
        .frame_type = FRAME_TYPE_WINDOW_UPDATE,
        .flags = 0,
        .stream_id = stream_id,
    });
    var buf: [4]u8 = undefined;
    const inc: u32 = increment;
    buf[0] = @intCast((inc >> 24) & 0xFF);
    buf[1] = @intCast((inc >> 16) & 0xFF);
    buf[2] = @intCast((inc >> 8) & 0xFF);
    buf[3] = @intCast(inc & 0xFF);
    try writeAllFD(fd, &buf);
}

/// Send HEADERS + optional DATA for a complete response. Sets END_STREAM on DATA (or HEADERS when body is empty).
/// Not suitable for multi-step responses (e.g. gRPC trailers). Use writeFrameHeaderFD + writeAllFD directly for those.
pub fn sendResponseFD(
    fd: std.posix.fd_t,
    stream_id: u31,
    status: u16,
    content_type: []const u8,
    body: []const u8,
) !void {
    return sendResponseEncodedFD(fd, stream_id, status, content_type, "", body);
}

/// sendResponseFD plus an optional content-encoding header (for serving a precompressed body). An empty
/// content_encoding omits the header. The body is framed in <= DEFAULT_MAX_FRAME_SIZE DATA chunks.
/// This is the immediate, unmetered send (no flow control). For large bodies that may exceed the
/// peer's window use the multiplexed `mux.sendResponseStreamFD`, which paces by WINDOW_UPDATE.
/// A body at or under SEND_STAGE_BODY_MAX leaves as one staged write, a larger one as one vectored
/// write per DATA chunk (the HEADERS block rides the first chunk).
pub fn sendResponseEncodedFD(
    fd: std.posix.fd_t,
    stream_id: u31,
    status: u16,
    content_type: []const u8,
    content_encoding: []const u8,
    body: []const u8,
) !void {
    const hpack = @import("hpack.zig");
    var stage_buf: [SEND_STAGE_SIZE]u8 = undefined;

    // The [:status, content-type, content-encoding] prefix is served from a per-triple cache, only
    // content-length (which varies) is encoded per call. A bodyless response omits content-length.
    const content_length: ?u64 = if (body.len > 0) body.len else null;
    const hblock_len = hpack.respHeaderBlock(stage_buf[FRAME_HEADER_LEN..][0..HPACK_ENCODE_SCRATCH], status, content_type, content_encoding, content_length);
    const end_stream_flag: u8 = if (body.len == 0) FLAG_END_STREAM | FLAG_END_HEADERS else FLAG_END_HEADERS;
    encodeFrameHeader(stage_buf[0..FRAME_HEADER_LEN], .{
        .length = @intCast(hblock_len),
        .frame_type = FRAME_TYPE_HEADERS,
        .flags = end_stream_flag,
        .stream_id = stream_id,
    });
    var staged: usize = FRAME_HEADER_LEN + hblock_len;

    if (body.len == 0) return writeAllFD(fd, stage_buf[0..staged]);

    if (body.len <= SEND_STAGE_BODY_MAX) {
        encodeFrameHeader(stage_buf[staged..][0..FRAME_HEADER_LEN], .{
            .length = @intCast(body.len),
            .frame_type = FRAME_TYPE_DATA,
            .flags = FLAG_END_STREAM,
            .stream_id = stream_id,
        });
        staged += FRAME_HEADER_LEN;
        @memcpy(stage_buf[staged..][0..body.len], body);
        staged += body.len;

        return writeAllFD(fd, stage_buf[0..staged]);
    }

    // Frame the body in <= DEFAULT_MAX_FRAME_SIZE chunks: a single DATA frame larger than the
    // peer's max frame size (16384 by default) is a FRAME_SIZE_ERROR. The last chunk carries
    // END_STREAM.
    var off: usize = 0;
    var first_chunk = true;
    while (off < body.len) {
        const chunk = @min(body.len - off, DEFAULT_MAX_FRAME_SIZE);
        const last = off + chunk == body.len;
        const data_header = FrameHeader{
            .length = @intCast(chunk),
            .frame_type = FRAME_TYPE_DATA,
            .flags = if (last) FLAG_END_STREAM else 0,
            .stream_id = stream_id,
        };

        if (first_chunk) {
            // the HEADERS block and the first DATA header share the head half of one vectored write
            encodeFrameHeader(stage_buf[staged..][0..FRAME_HEADER_LEN], data_header);
            try writePairFD(fd, stage_buf[0 .. staged + FRAME_HEADER_LEN], body[off..][0..chunk]);
            first_chunk = false;
        } else {
            var chunk_header: [FRAME_HEADER_LEN]u8 = undefined;
            encodeFrameHeader(&chunk_header, data_header);
            try writePairFD(fd, &chunk_header, body[off..][0..chunk]);
        }

        off += chunk;
    }
}

// --------------------------------------------------------- //

/// Read one end of a pair until the peer closes it, and report how many bytes arrived.
///
/// Note:
/// - Meant to run as its own task while the other end is still sending. A send larger than the
///   socket buffer only completes while someone is draining: with no concurrent reader the
///   writer blocks the moment that buffer fills and neither side moves again.
fn drainUntilEof(fd: std.posix.fd_t, buf: []u8) usize {
    var total: usize = 0;
    while (total < buf.len) {
        const got = fd_io.readOnce(fd, buf[total..]) catch break;
        if (got == 0) break;

        total += got;
    }

    return total;
}

// --------------------------------------------------------- //

test "zix http2: writeAllFD delivers data on a blocking fd" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    try writeAllFD(fds[1], "frame");
    fd_io.close(fds[1]);

    var buf: [8]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    try std.testing.expectEqualStrings("frame", buf[0..n]);
}

test "zix http2: sendResponseFD chunks a body past the max frame size, END_STREAM on the last" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    // 40000 bytes is past the socket buffer on macOS, NetBSD and OpenBSD (Linux holds it), so
    // the drain has to be in flight before the send starts. Reading afterwards deadlocks there:
    // sendResponseFD fills the buffer and waits on a reader that has not been reached yet.
    var buf: [64 * 1024]u8 = undefined;
    var drain: std.Io.Future(usize) = io.async(drainUntilEof, .{ fds[0], &buf });

    var body: [40000]u8 = undefined;
    @memset(&body, 'a');
    try sendResponseFD(fds[1], 1, 200, "text/plain", &body);
    fd_io.close(fds[1]);

    const total = drain.await(io);

    var off: usize = 0;
    var data_bytes: usize = 0;
    var last_data_flags: u8 = 0;
    while (off + FRAME_HEADER_LEN <= total) {
        const fh = parseFrameHeader(buf[off..][0..FRAME_HEADER_LEN]);
        off += FRAME_HEADER_LEN;

        if (fh.frame_type == FRAME_TYPE_DATA) {
            try std.testing.expect(fh.length <= DEFAULT_MAX_FRAME_SIZE);
            data_bytes += fh.length;
            last_data_flags = fh.flags;
        }

        off += fh.length;
    }

    try std.testing.expectEqual(@as(usize, 40000), data_bytes);
    try std.testing.expect((last_data_flags & FLAG_END_STREAM) != 0);
}

// Capture write-hook appends so a test can assert how many writes one send produced and what the
// first append carried. Used by the send-staging tests below.
const StageProbe = struct {
    count: usize = 0,
    first_len: usize = 0,
    total: usize = 0,
    buf: [1024]u8 = undefined,
};

fn stageProbeWrite(ctx: *anyopaque, bytes: []const u8) void {
    const probe: *StageProbe = @ptrCast(@alignCast(ctx));
    if (probe.count == 0) {
        const keep = @min(bytes.len, probe.buf.len);
        @memcpy(probe.buf[0..keep], bytes[0..keep]);
        probe.first_len = bytes.len;
    }

    probe.count += 1;
    probe.total += bytes.len;
}

/// Hook tests never reach the socket, so the descriptor only has to exist as a value.
const STAGE_TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix http2: sendResponseEncodedFD stages a small response into one write" {
    var probe = StageProbe{};
    write_hook = stageProbeWrite;
    write_hook_ctx = &probe;
    defer {
        write_hook = null;
        write_hook_ctx = null;
    }

    try sendResponseEncodedFD(STAGE_TEST_FD, 1, 200, "text/plain", "", "pong");

    try std.testing.expectEqual(@as(usize, 1), probe.count);

    const headers_fh = parseFrameHeader(probe.buf[0..FRAME_HEADER_LEN]);
    try std.testing.expectEqual(@as(u8, FRAME_TYPE_HEADERS), headers_fh.frame_type);

    const data_off = FRAME_HEADER_LEN + @as(usize, headers_fh.length);
    const data_fh = parseFrameHeader(probe.buf[data_off..][0..FRAME_HEADER_LEN]);
    try std.testing.expectEqual(@as(u8, FRAME_TYPE_DATA), data_fh.frame_type);
    try std.testing.expect((data_fh.flags & FLAG_END_STREAM) != 0);
    try std.testing.expectEqualStrings("pong", probe.buf[data_off + FRAME_HEADER_LEN ..][0..4]);
    try std.testing.expectEqual(data_off + FRAME_HEADER_LEN + 4, probe.total);
}

test "zix http2: sendResponseEncodedFD bodyless response is one write, END_STREAM on HEADERS" {
    var probe = StageProbe{};
    write_hook = stageProbeWrite;
    write_hook_ctx = &probe;
    defer {
        write_hook = null;
        write_hook_ctx = null;
    }

    try sendResponseEncodedFD(STAGE_TEST_FD, 5, 204, "text/plain", "", "");

    try std.testing.expectEqual(@as(usize, 1), probe.count);

    const headers_fh = parseFrameHeader(probe.buf[0..FRAME_HEADER_LEN]);
    try std.testing.expectEqual(@as(u8, FRAME_TYPE_HEADERS), headers_fh.frame_type);
    try std.testing.expect((headers_fh.flags & FLAG_END_STREAM) != 0);
    try std.testing.expect((headers_fh.flags & FLAG_END_HEADERS) != 0);
    try std.testing.expectEqual(FRAME_HEADER_LEN + @as(usize, headers_fh.length), probe.total);
}

test "zix http2: sendResponseEncodedFD stage cap boundary, at the cap one write, past it a pair" {
    var probe = StageProbe{};
    write_hook = stageProbeWrite;
    write_hook_ctx = &probe;
    defer {
        write_hook = null;
        write_hook_ctx = null;
    }

    const at_cap: [SEND_STAGE_BODY_MAX]u8 = @splat('x');
    try sendResponseEncodedFD(STAGE_TEST_FD, 1, 200, "text/plain", "", &at_cap);
    try std.testing.expectEqual(@as(usize, 1), probe.count);

    probe = .{};
    const past_cap: [SEND_STAGE_BODY_MAX + 1]u8 = @splat('x');
    try sendResponseEncodedFD(STAGE_TEST_FD, 1, 200, "text/plain", "", &past_cap);
    try std.testing.expectEqual(@as(usize, 2), probe.count);

    // the head half carries the HEADERS frame plus the DATA header, the body leaves untouched
    const headers_fh = parseFrameHeader(probe.buf[0..FRAME_HEADER_LEN]);
    try std.testing.expectEqual(FRAME_HEADER_LEN + @as(usize, headers_fh.length) + FRAME_HEADER_LEN, probe.first_len);
    try std.testing.expectEqual(probe.first_len + past_cap.len, probe.total);
}

test "zix http2: sendResponseEncodedFD vectored path delivers a single-frame body on a socket" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    // The drain runs concurrently so a small socket buffer never deadlocks the send (same shape
    // as the chunking test above).
    var buf: [16 * 1024]u8 = undefined;
    var drain: std.Io.Future(usize) = io.async(drainUntilEof, .{ fds[0], &buf });

    var body: [8000]u8 = @splat('b');
    try sendResponseEncodedFD(fds[1], 1, 200, "text/plain", "", &body);
    fd_io.close(fds[1]);

    const total = drain.await(io);

    var off: usize = 0;
    var data_frames: usize = 0;
    var data_bytes: usize = 0;
    var last_data_flags: u8 = 0;
    while (off + FRAME_HEADER_LEN <= total) {
        const fh = parseFrameHeader(buf[off..][0..FRAME_HEADER_LEN]);
        off += FRAME_HEADER_LEN;

        if (fh.frame_type == FRAME_TYPE_DATA) {
            data_frames += 1;
            data_bytes += fh.length;
            last_data_flags = fh.flags;
        }

        off += fh.length;
    }

    try std.testing.expectEqual(@as(usize, 1), data_frames);
    try std.testing.expectEqual(@as(usize, 8000), data_bytes);
    try std.testing.expect((last_data_flags & FLAG_END_STREAM) != 0);
}

test "zix http2: frame constants, FRAME_TYPE_HEADERS is 0x01" {
    try std.testing.expectEqual(@as(u8, 0x01), FRAME_TYPE_HEADERS);
}

test "zix http2: frame constants, FLAG_END_STREAM is 0x01" {
    try std.testing.expectEqual(@as(u8, 0x01), FLAG_END_STREAM);
}

test "zix http2: frame constants, ERR_NO_ERROR is 0" {
    try std.testing.expectEqual(@as(u32, 0), ERR_NO_ERROR);
}

test "zix http2: writeFrameHeaderFD and readFrameHeader roundtrip via pipe" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    const fh = FrameHeader{
        .length = 42,
        .frame_type = FRAME_TYPE_HEADERS,
        .flags = FLAG_END_HEADERS,
        .stream_id = 3,
    };
    try writeFrameHeaderFD(fds[1], fh);
    fd_io.close(fds[1]);

    const got = try readFrameHeader(fds[0]);
    try std.testing.expectEqual(fh.length, got.length);
    try std.testing.expectEqual(fh.frame_type, got.frame_type);
    try std.testing.expectEqual(fh.flags, got.flags);
    try std.testing.expectEqual(fh.stream_id, got.stream_id);
}

test "zix http2: PREFACE starts with PRI" {
    try std.testing.expect(std.mem.startsWith(u8, PREFACE, "PRI"));
    try std.testing.expectEqual(@as(usize, 24), PREFACE.len);
}

test "zix http2: sendSettingsFD empty params writes 9-byte SETTINGS frame via pipe" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    try sendSettingsFD(fds[1], &.{});
    fd_io.close(fds[1]);

    const fh = try readFrameHeader(fds[0]);
    try std.testing.expectEqual(@as(u8, FRAME_TYPE_SETTINGS), fh.frame_type);
    try std.testing.expectEqual(@as(u24, 0), fh.length);
    try std.testing.expectEqual(@as(u31, 0), fh.stream_id);
}
