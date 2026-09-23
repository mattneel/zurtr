//! zix http2 static file serving: the public_dir fallback for unmatched routes.
//!
//! The router calls serve here before writing its 404, reading public_dir from the Context the
//! engine built. One HEADERS frame carries the status, type, encoding, and length, then the body
//! goes out as DATA frames capped at the peer's max frame size, the last one flagged END_STREAM.
//!
//! Two paths behind one entry point, the same shape as zix.Http1 static. With a static cache
//! installed (ADR-064) the file is already open and its .br / .gz siblings already resolved, so a
//! repeat request costs a hash lookup. Without one, the file is opened and read per request, so
//! public_dir behaves the same on every engine whether or not caching is enabled.
//!
//! This engine also asks the cache for a resident body. sendfile cannot carry a DATA frame while the
//! mux is coalescing a batch, and that hook is installed for the whole of one, so the body has to
//! reach user space on every dispatch model here. Cutting the frames from bytes the cache already
//! holds is what keeps that from becoming a page-cache read per frame.
//!
//! Range (RFC 7233) is served: a satisfiable single range answers 206 with Content-Range, a
//! well-formed range past the end answers 416, and anything malformed is ignored and gets the whole
//! file. Multi-range (multipart/byteranges) is not served, and a multi-range request is answered
//! with its first range, which a server is allowed to do.

const std = @import("std");
const fd_io = @import("../../utils/fd_io.zig");
const socket_pair = @import("../../utils/socket_pair.zig");
const builtin = @import("builtin");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const Request = @import("request.zig").Request;
const Context = @import("context.zig").Context;
const content = @import("../http/content.zig");
const file_utils = @import("../../utils/file.zig");
const static_cache = @import("../../utils/static_cache.zig");
const static_send = @import("../../utils/static_send.zig");
const http_range = @import("../../utils/http_range.zig");
const response_cache = @import("../../utils/response_cache.zig");

// --------------------------------------------------------- //

/// Served full-path stack buffer.
const FULL_PATH_BUF: usize = 512;

// --------------------------------------------------------- //

/// One servable file, however it was resolved. The cached and uncached paths differ only in where
/// these values come from, so the framing below is written once.
const Source = struct {
    file: std.Io.File,
    size: u64,
    content_type: []const u8,
    content_encoding: []const u8,
    /// Whole body, resident and stable for as long as the hit is pinned. Set when the cache could
    /// snapshot the file, and then the DATA frames are cut from it instead of read back per frame.
    bytes: ?[]const u8 = null,
};

/// Whether the body may be handed straight to the kernel for this response.
///
/// Note:
/// - A frame write hook means a mux worker is coalescing this batch into one buffer. Writing the
///   socket directly would put the body ahead of the frames still staged there, so the copy path
///   runs instead and the body joins the same batch as every other frame.
fn zeroCopyAllowed(fd: std.posix.fd_t) bool {
    if (comptime builtin.os.tag != .linux) return false;

    return fd >= 0 and frame.write_hook == null;
}

/// Which bytes of a source to send, and under what status. A whole-file 200 and a 206 for a byte
/// range differ only in these values, so the framing below is written once for both.
const Segment = struct {
    offset: u64 = 0,
    length: u64,
    status: u16 = 200,
    /// Rendered `bytes start-end/total`, empty for a 200.
    content_range: []const u8 = "",
};

/// Whole-file 200 for a source.
fn wholeOf(source: Source) Segment {
    return .{ .length = source.size };
}

/// Send one HEADERS frame followed by a segment of the file as DATA frames.
///
/// Note:
/// - The body is chunked at max_frame_size because a DATA frame larger than the peer's advertised
///   limit is a FRAME_SIZE_ERROR. The last chunk carries END_STREAM.
/// - An empty segment still needs a response, so the HEADERS frame itself closes the stream.
/// - A resident body is written straight from its own bytes. The copy path would otherwise read the
///   same range back out of the page cache once per DATA frame, which is pure overhead here since
///   the bytes are already addressable.
/// - Content-Length carries the SEGMENT length, not the file size. On a 206 those differ, and
///   sending the file size there makes the client wait for bytes that never arrive.
fn sendFramed(fd: std.posix.fd_t, io: std.Io, sid: u31, source: Source, segment: Segment, max_frame_size: u32) !void {
    var hdr_buf: [frame.HPACK_ENCODE_SCRATCH]u8 = undefined;
    const content_length: ?u64 = if (segment.length > 0) segment.length else null;
    var header_len = hpack.respHeaderBlock(&hdr_buf, segment.status, source.content_type, source.content_encoding, content_length);

    if (segment.content_range.len > 0) {
        var enc = hpack.HpackEncoder{ .buf = &hdr_buf, .pos = header_len };
        enc.writeHeader("content-range", segment.content_range) catch {};
        enc.writeHeader("accept-ranges", "bytes") catch {};
        header_len = enc.pos;
    }

    const hblock = hdr_buf[0..header_len];
    const header_flags: u8 = if (segment.length == 0) frame.FLAG_END_STREAM | frame.FLAG_END_HEADERS else frame.FLAG_END_HEADERS;

    try frame.writeFrameHeaderFD(fd, .{
        .length = @intCast(hblock.len),
        .frame_type = frame.FRAME_TYPE_HEADERS,
        .flags = header_flags,
        .stream_id = sid,
    });
    try frame.writeAllFD(fd, hblock);

    if (segment.length == 0) return;

    const zero_copy = zeroCopyAllowed(fd);
    const chunk_cap: u64 = @max(1, max_frame_size);
    const end = segment.offset + segment.length;
    var offset: u64 = segment.offset;

    while (offset < end) {
        const chunk = @min(end - offset, chunk_cap);
        const last = offset + chunk == end;

        try frame.writeFrameHeaderFD(fd, .{
            .length = @intCast(chunk),
            .frame_type = frame.FRAME_TYPE_DATA,
            .flags = if (last) frame.FLAG_END_STREAM else 0,
            .stream_id = sid,
        });

        if (source.bytes) |body| {
            try frame.writeAllFD(fd, body[@intCast(offset)..][0..@intCast(chunk)]);
        } else {
            try static_send.sendBody(fd, io, source.file, offset, chunk, zero_copy, frame.writeAllFD);
        }

        offset += chunk;
    }
}

/// Take a cache hit for this request, preferring one whose bytes are resident.
///
/// Note:
/// - A resident hit is only worth asking for when the body cannot leave by sendfile, which on this
///   engine is almost always: the mux coalescing hook is installed for the whole of a batch, so
///   zeroCopyAllowed refuses regardless of TLS. Without it the same range is read back out of the
///   page cache once per DATA frame.
/// - acquireMapped declines a file past SNAPSHOT_MAX_BYTES, so that falls back to the plain hit and
///   keeps the open descriptor rather than dropping the request to the uncached path.
fn acquireHit(cache: *static_cache.StaticCache, req: *Request, ctx: *Context, req_path: []const u8) ?static_cache.Hit {
    const accept_encoding = req.header("accept-encoding");
    const ttl = static_cache.ttlMs();
    const now = response_cache.nowMillis();

    if (!zeroCopyAllowed(ctx.fd)) {
        if (cache.acquireMapped(ctx.io, ctx.public_dir, req_path, accept_encoding, ttl, now)) |resident| return resident;
    }

    return cache.acquire(ctx.io, ctx.public_dir, req_path, accept_encoding, ttl, now);
}

/// Answer a range request that names bytes the file does not have: 416 with the length, headers
/// only, per RFC 7233 section 4.4.
fn sendRangeNotSatisfiable(fd: std.posix.fd_t, sid: u31, total: u64) !void {
    var range_buf: [48]u8 = undefined;
    const content_range = std.fmt.bufPrint(&range_buf, "bytes */{d}", .{total}) catch return;

    var hdr_buf: [frame.HPACK_ENCODE_SCRATCH]u8 = undefined;
    var enc = hpack.HpackEncoder{ .buf = &hdr_buf, .pos = hpack.respHeaderBlock(&hdr_buf, 416, "text/plain", "", 0) };
    enc.writeHeader("content-range", content_range) catch {};

    const hblock = hdr_buf[0..enc.pos];

    try frame.writeFrameHeaderFD(fd, .{
        .length = @intCast(hblock.len),
        .frame_type = frame.FRAME_TYPE_HEADERS,
        .flags = frame.FLAG_END_STREAM | frame.FLAG_END_HEADERS,
        .stream_id = sid,
    });
    try frame.writeAllFD(fd, hblock);
}

/// Decide what to send for a request against a source of known size.
///
/// Note:
/// - A header that does not parse is IGNORED and the whole file is sent (RFC 7233 section 3.1). Only
///   a well-formed range naming bytes past the end is a 416, which is why the parse and the clamp
///   are two steps rather than one.
///
/// Return:
/// - Segment (what to frame, 200 or 206)
/// - null when the range is well-formed but unsatisfiable, so the caller must answer 416
fn segmentFor(req: *Request, source: Source, range_buf: []u8) ?Segment {
    const raw = req.header("range") orelse return wholeOf(source);
    const spec = http_range.parseSpec(raw) orelse return wholeOf(source);
    const range = http_range.resolve(spec, source.size) orelse return null;

    const content_range = std.fmt.bufPrint(range_buf, "bytes {d}-{d}/{d}", .{ range.start, range.end, source.size }) catch return wholeOf(source);

    return .{
        .offset = range.start,
        .length = range.length(),
        .status = 206,
        .content_range = content_range,
    };
}

/// Frame a source as a 200, a 206, or a 416, whichever the request asked for.
fn sendSource(ctx: *Context, source: Source, max_frame_size: u32, req: *Request) void {
    var range_buf: [64]u8 = undefined;

    const segment = segmentFor(req, source, &range_buf) orelse {
        sendRangeNotSatisfiable(ctx.fd, ctx.sid, source.size) catch {};

        return;
    };

    sendFramed(ctx.fd, ctx.io, ctx.sid, source, segment, max_frame_size) catch {};
}

/// Serve the request from the static cache when one is installed and can take it.
///
/// Return:
/// - true when the response was framed from the cache
/// - false when there is no cache, or the cache declined the path (caller falls back)
fn serveCached(req: *Request, ctx: *Context, req_path: []const u8, max_frame_size: u32) bool {
    const cache = static_cache.instance() orelse return false;

    const hit = acquireHit(cache, req, ctx, req_path) orelse return false;
    defer cache.release(hit);

    sendSource(ctx, .{
        .file = hit.file,
        .size = hit.size,
        .content_type = hit.content_type,
        .content_encoding = hit.encoding.contentEncoding() orelse "",
        .bytes = hit.bytes,
    }, max_frame_size, req);

    return true;
}

/// Serve a static file from the public directory.
///
/// Rejects paths containing ".." to prevent directory traversal. Answers 200 with the whole file,
/// 206 for a satisfiable Range, or 416 for a well-formed Range the file cannot satisfy.
///
/// Note:
/// - Once the file resolves the request is answered here, write errors included. A broken peer is
///   not a missing file, so the caller must not follow it with a 404.
///
/// Param:
/// req - *Request (read for Accept-Encoding and Range)
/// ctx - *Context (fd, stream id, io, and the configured public_dir)
/// req_path - []const u8 (request path with the leading slash already stripped)
/// max_frame_size - u32 (peer's advertised SETTINGS_MAX_FRAME_SIZE, caps every DATA frame)
///
/// Return:
/// - true if the file was found and a response was framed
/// - false if the file is not found or the path is invalid (caller sends 404)
pub fn serve(req: *Request, ctx: *Context, req_path: []const u8, max_frame_size: u32) bool {
    if (serveCached(req, ctx, req_path, max_frame_size)) return true;

    if (std.mem.indexOf(u8, req_path, "..") != null) return false;

    var full_path_buf: [FULL_PATH_BUF]u8 = undefined;
    if (ctx.public_dir.len + 1 + req_path.len > full_path_buf.len) return false;

    @memcpy(full_path_buf[0..ctx.public_dir.len], ctx.public_dir);
    full_path_buf[ctx.public_dir.len] = '/';
    @memcpy(full_path_buf[ctx.public_dir.len + 1 ..][0..req_path.len], req_path);
    const full_path = full_path_buf[0 .. ctx.public_dir.len + 1 + req_path.len];

    const file = std.Io.Dir.cwd().openFile(ctx.io, full_path, .{}) catch return false;
    defer file.close(ctx.io);

    const stat = file.stat(ctx.io) catch return false;
    if (stat.kind != .file) return false;

    sendSource(ctx, .{
        .file = file,
        .size = stat.size,
        .content_type = content.fromExtension(file_utils.extension(req_path)),
        .content_encoding = "",
    }, max_frame_size, req);

    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;
/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints. Only handed to paths
/// that decline before any write.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else 1;

/// Read back everything staged on the peer end of a socketpair, then walk it as h2 frames.
const FrameSummary = struct {
    header_count: usize = 0,
    data_bytes: u64 = 0,
    largest_data: u32 = 0,
    last_data_flags: u8 = 0,
    header_block: []const u8 = &.{},
};

fn summarizeFrames(wire: []const u8) FrameSummary {
    var summary: FrameSummary = .{};
    var offset: usize = 0;

    while (offset + frame.FRAME_HEADER_LEN <= wire.len) {
        const fh = frame.parseFrameHeader(wire[offset..][0..frame.FRAME_HEADER_LEN]);
        offset += frame.FRAME_HEADER_LEN;
        if (offset + fh.length > wire.len) break;

        if (fh.frame_type == frame.FRAME_TYPE_HEADERS) {
            summary.header_count += 1;
            summary.header_block = wire[offset..][0..fh.length];
        }
        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            summary.data_bytes += fh.length;
            summary.largest_data = @max(summary.largest_data, fh.length);
            summary.last_data_flags = fh.flags;
        }

        offset += fh.length;
    }

    return summary;
}

/// Collect the body bytes of every DATA frame in order.
fn collectData(wire: []const u8, out: []u8) []const u8 {
    var offset: usize = 0;
    var written: usize = 0;

    while (offset + frame.FRAME_HEADER_LEN <= wire.len) {
        const fh = frame.parseFrameHeader(wire[offset..][0..frame.FRAME_HEADER_LEN]);
        offset += frame.FRAME_HEADER_LEN;
        if (offset + fh.length > wire.len) break;

        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            @memcpy(out[written..][0..fh.length], wire[offset..][0..fh.length]);
            written += fh.length;
        }

        offset += fh.length;
    }

    return out[0..written];
}

fn drain(peer: std.posix.fd_t, buf: []u8) []const u8 {
    var total: usize = 0;

    while (total < buf.len) {
        const got = fd_io.readOnce(peer, buf[total..]) catch break;
        if (got == 0) break;

        total += got;
    }

    return buf[0..total];
}

test "zix http2: static zeroCopyAllowed refuses a coalescing batch and the sentinel fd" {
    if (comptime builtin.os.tag != .linux) {
        // Every other target takes the copy path unconditionally.
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    try testing.expect(zeroCopyAllowed(3));
    try testing.expect(!zeroCopyAllowed(-1));

    // While a mux worker coalesces a batch, the body must join it rather than
    // overtake the frames already staged.
    var sink_ctx: usize = 0;
    frame.write_hook = struct {
        fn noop(_: *anyopaque, _: []const u8) void {}
    }.noop;
    frame.write_hook_ctx = @ptrCast(&sink_ctx);
    defer {
        frame.write_hook = null;
        frame.write_hook_ctx = null;
    }

    try testing.expect(!zeroCopyAllowed(3));
}

test "zix http2: static serve frames a file as HEADERS plus DATA with END_STREAM" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "app.json", .data = "{\"ok\":true}" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        fd_io.close(pair[0]);
        fd_io.close(pair[1]);
    }

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = pair[0], .sid = 3, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };
    var req = Request{ .method = "GET", .path = "/app.json", .query = "", .headers = &.{}, .body = &.{} };

    // No cache installed: this exercises the uncached path.
    try testing.expect(static_cache.instance() == null);
    try testing.expect(serve(&req, &ctx, "app.json", frame.DEFAULT_MAX_FRAME_SIZE));

    fd_io.close(pair[0]);

    var wire_buf: [4096]u8 = undefined;
    const wire = drain(pair[1], &wire_buf);
    const summary = summarizeFrames(wire);

    try testing.expectEqual(@as(usize, 1), summary.header_count);
    try testing.expectEqual(@as(u64, 11), summary.data_bytes);
    try testing.expect((summary.last_data_flags & frame.FLAG_END_STREAM) != 0);

    var body_buf: [64]u8 = undefined;
    try testing.expectEqualStrings("{\"ok\":true}", collectData(wire, &body_buf));
}

test "zix http2: static serve rejects traversal and a missing file" {
    var arena_buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = testing.io, .allocator = fba.allocator(), .public_dir = "./public" };
    var req = Request{ .method = "GET", .path = "/x", .query = "", .headers = &.{}, .body = &.{} };

    try testing.expect(!serve(&req, &ctx, "../etc/passwd", frame.DEFAULT_MAX_FRAME_SIZE));
    try testing.expect(!serve(&req, &ctx, "definitely-absent.txt", frame.DEFAULT_MAX_FRAME_SIZE));

    // A path too long for the join buffer is declined rather than truncated.
    var long_buf: [600]u8 = @splat('a');
    try testing.expect(!serve(&req, &ctx, &long_buf, frame.DEFAULT_MAX_FRAME_SIZE));
}

test "zix http2: static serve chunks a body past the max frame size" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Three chunks at a deliberately small frame cap, so the last one is partial.
    var payload: [700]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    tmp.dir.writeFile(testing.io, .{ .sub_path = "big.bin", .data = &payload }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        fd_io.close(pair[0]);
        fd_io.close(pair[1]);
    }

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = pair[0], .sid = 5, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };
    var req = Request{ .method = "GET", .path = "/big.bin", .query = "", .headers = &.{}, .body = &.{} };

    try testing.expect(serve(&req, &ctx, "big.bin", 256));

    fd_io.close(pair[0]);

    var wire_buf: [4096]u8 = undefined;
    const wire = drain(pair[1], &wire_buf);
    const summary = summarizeFrames(wire);

    try testing.expectEqual(@as(u64, payload.len), summary.data_bytes);
    try testing.expect(summary.largest_data <= 256);
    try testing.expect((summary.last_data_flags & frame.FLAG_END_STREAM) != 0);

    var body_buf: [1024]u8 = undefined;
    try testing.expectEqualStrings(&payload, collectData(wire, &body_buf));
}

test "zix http2: static serve closes the stream on the HEADERS frame for an empty file" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "empty.txt", .data = "" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        fd_io.close(pair[0]);
        fd_io.close(pair[1]);
    }

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = pair[0], .sid = 7, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };
    var req = Request{ .method = "GET", .path = "/empty.txt", .query = "", .headers = &.{}, .body = &.{} };

    try testing.expect(serve(&req, &ctx, "empty.txt", frame.DEFAULT_MAX_FRAME_SIZE));

    fd_io.close(pair[0]);

    var wire_buf: [1024]u8 = undefined;
    const wire = drain(pair[1], &wire_buf);
    const summary = summarizeFrames(wire);

    try testing.expectEqual(@as(usize, 1), summary.header_count);
    try testing.expectEqual(@as(u64, 0), summary.data_bytes);

    // No DATA frame follows, so END_STREAM has to ride on HEADERS.
    const fh = frame.parseFrameHeader(wire[0..frame.FRAME_HEADER_LEN]);
    try testing.expect((fh.flags & frame.FLAG_END_STREAM) != 0);
}

/// Collects everything the frame write hook is handed, so the coalescing path can be inspected
/// without a mux. Mirrors what muxCoalesceWrite does to a batch buffer.
var hook_sink: [8192]u8 = undefined;
var hook_sink_len: usize = 0;

fn hookCollect(_: *anyopaque, bytes: []const u8) void {
    if (hook_sink_len + bytes.len > hook_sink.len) return;

    @memcpy(hook_sink[hook_sink_len..][0..bytes.len], bytes);
    hook_sink_len += bytes.len;
}

/// Decode the HPACK header block of the first HEADERS frame on the wire.
fn decodeHeaders(wire: []const u8, out: []hpack.Header, scratch: []u8) []const hpack.Header {
    const summary = summarizeFrames(wire);
    if (summary.header_block.len == 0) return out[0..0];

    var dec = hpack.HpackDecoder.init();
    const count = dec.decode(summary.header_block, out, scratch) catch return out[0..0];

    return out[0..count];
}

fn headerValue(headers: []const hpack.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }

    return null;
}

/// Serve one request against a fixture directory over a socketpair and hand back the wire bytes.
const Served = struct {
    wire: []const u8,
    ok: bool,
};

fn serveOnce(root: []const u8, req: *Request, req_path: []const u8, max_frame_size: u32, wire_buf: []u8) Served {
    var owned = socket_pair.Pair.open(std.testing.allocator) catch return .{ .wire = &.{}, .ok = false };
    defer owned.deinit();
    const pair = owned.fds;

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = pair[0], .sid = 1, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };

    const ok = serve(req, &ctx, req_path, max_frame_size);
    fd_io.close(pair[0]);

    const wire = drain(pair[1], wire_buf);
    fd_io.close(pair[1]);

    return .{ .wire = wire, .ok = ok };
}

test "zix http2: static serves a byte range as 206 with Content-Range" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "clip.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var headers = [_]hpack.Header{.{ .name = "range", .value = "bytes=2-5" }};
    var req = Request{ .method = "GET", .path = "/clip.bin", .query = "", .headers = &headers, .body = &.{} };

    var wire_buf: [2048]u8 = undefined;
    const served = serveOnce(root, &req, "clip.bin", frame.DEFAULT_MAX_FRAME_SIZE, &wire_buf);
    try testing.expect(served.ok);

    var hdrs: [16]hpack.Header = undefined;
    var scratch: [512]u8 = undefined;
    const decoded = decodeHeaders(served.wire, &hdrs, &scratch);

    try testing.expectEqualStrings("206", headerValue(decoded, ":status").?);
    try testing.expectEqualStrings("bytes 2-5/10", headerValue(decoded, "content-range").?);
    try testing.expectEqualStrings("bytes", headerValue(decoded, "accept-ranges").?);
    // Content-Length is the RANGE length, not the file size.
    try testing.expectEqualStrings("4", headerValue(decoded, "content-length").?);

    var body_buf: [64]u8 = undefined;
    try testing.expectEqualStrings("2345", collectData(served.wire, &body_buf));
}

test "zix http2: static fills an open-ended range to the last byte" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "open.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var headers = [_]hpack.Header{.{ .name = "range", .value = "bytes=7-" }};
    var req = Request{ .method = "GET", .path = "/open.bin", .query = "", .headers = &headers, .body = &.{} };

    var wire_buf: [2048]u8 = undefined;
    const served = serveOnce(root, &req, "open.bin", frame.DEFAULT_MAX_FRAME_SIZE, &wire_buf);
    try testing.expect(served.ok);

    var hdrs: [16]hpack.Header = undefined;
    var scratch: [512]u8 = undefined;
    const decoded = decodeHeaders(served.wire, &hdrs, &scratch);

    try testing.expectEqualStrings("206", headerValue(decoded, ":status").?);
    try testing.expectEqualStrings("bytes 7-9/10", headerValue(decoded, "content-range").?);

    var body_buf: [64]u8 = undefined;
    try testing.expectEqualStrings("789", collectData(served.wire, &body_buf));
}

test "zix http2: static answers 416 for a range past the end of the file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "short.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var headers = [_]hpack.Header{.{ .name = "range", .value = "bytes=50-60" }};
    var req = Request{ .method = "GET", .path = "/short.bin", .query = "", .headers = &headers, .body = &.{} };

    var wire_buf: [2048]u8 = undefined;
    const served = serveOnce(root, &req, "short.bin", frame.DEFAULT_MAX_FRAME_SIZE, &wire_buf);
    try testing.expect(served.ok);

    var hdrs: [16]hpack.Header = undefined;
    var scratch: [512]u8 = undefined;
    const decoded = decodeHeaders(served.wire, &hdrs, &scratch);

    try testing.expectEqualStrings("416", headerValue(decoded, ":status").?);
    try testing.expectEqualStrings("bytes */10", headerValue(decoded, "content-range").?);

    // Headers only, and the stream is closed by them.
    const summary = summarizeFrames(served.wire);
    try testing.expectEqual(@as(u64, 0), summary.data_bytes);

    const fh = frame.parseFrameHeader(served.wire[0..frame.FRAME_HEADER_LEN]);
    try testing.expect((fh.flags & frame.FLAG_END_STREAM) != 0);
}

test "zix http2: static ignores a malformed Range and serves the whole file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "whole.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    // RFC 7233 section 3.1: an unparseable Range is ignored, NOT a 416.
    var headers = [_]hpack.Header{.{ .name = "range", .value = "furlongs=1-2" }};
    var req = Request{ .method = "GET", .path = "/whole.bin", .query = "", .headers = &headers, .body = &.{} };

    var wire_buf: [2048]u8 = undefined;
    const served = serveOnce(root, &req, "whole.bin", frame.DEFAULT_MAX_FRAME_SIZE, &wire_buf);
    try testing.expect(served.ok);

    var hdrs: [16]hpack.Header = undefined;
    var scratch: [512]u8 = undefined;
    const decoded = decodeHeaders(served.wire, &hdrs, &scratch);

    try testing.expectEqualStrings("200", headerValue(decoded, ":status").?);
    try testing.expect(headerValue(decoded, "content-range") == null);

    var body_buf: [64]u8 = undefined;
    try testing.expectEqualStrings("0123456789", collectData(served.wire, &body_buf));
}

test "zix http2: static serves a range from the cache and from resident bytes alike" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "cached.bin", .data = "abcdefghij" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var headers = [_]hpack.Header{.{ .name = "range", .value = "bytes=3-6" }};
    var req = Request{ .method = "GET", .path = "/cached.bin", .query = "", .headers = &headers, .body = &.{} };

    // Twice: the first request inserts, the second is served from the cached entry, and a range
    // taken from a resident body has to be sliced rather than read from byte zero.
    for (0..2) |_| {
        var wire_buf: [2048]u8 = undefined;
        const served = serveOnce(root, &req, "cached.bin", frame.DEFAULT_MAX_FRAME_SIZE, &wire_buf);
        try testing.expect(served.ok);

        var hdrs: [16]hpack.Header = undefined;
        var scratch: [512]u8 = undefined;
        const decoded = decodeHeaders(served.wire, &hdrs, &scratch);

        try testing.expectEqualStrings("206", headerValue(decoded, ":status").?);
        try testing.expectEqualStrings("bytes 3-6/10", headerValue(decoded, "content-range").?);

        var body_buf: [64]u8 = undefined;
        try testing.expectEqualStrings("defg", collectData(served.wire, &body_buf));
    }
}

test "zix http2: static chunks a range at the peer's frame size" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var payload: [900]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    tmp.dir.writeFile(testing.io, .{ .sub_path = "big.bin", .data = &payload }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var headers = [_]hpack.Header{.{ .name = "range", .value = "bytes=100-699" }};
    var req = Request{ .method = "GET", .path = "/big.bin", .query = "", .headers = &headers, .body = &.{} };

    // A small cap, so the 600-byte range has to span several DATA frames.
    var wire_buf: [4096]u8 = undefined;
    const served = serveOnce(root, &req, "big.bin", 128, &wire_buf);
    try testing.expect(served.ok);

    const summary = summarizeFrames(served.wire);
    try testing.expectEqual(@as(u64, 600), summary.data_bytes);
    try testing.expect(summary.largest_data <= 128);
    try testing.expect((summary.last_data_flags & frame.FLAG_END_STREAM) != 0);

    var body_buf: [1024]u8 = undefined;
    try testing.expectEqualSlices(u8, payload[100..700], collectData(served.wire, &body_buf));
}

test "zix http2: static acquireHit takes resident bytes only when zero copy is refused" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "resident.css", .data = "body{margin:0}" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    const cache = static_cache.instance().?;

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };
    var req = Request{ .method = "GET", .path = "/resident.css", .query = "", .headers = &.{}, .body = &.{} };

    // Nothing coalescing and a real descriptor: sendfile can carry it, so the body stays unread.
    const direct = acquireHit(cache, &req, &ctx, "resident.css").?;
    try testing.expect(direct.bytes == null);
    cache.release(direct);

    var sink_ctx: usize = 0;
    frame.write_hook = hookCollect;
    frame.write_hook_ctx = @ptrCast(&sink_ctx);
    defer {
        frame.write_hook = null;
        frame.write_hook_ctx = null;
    }

    const resident = acquireHit(cache, &req, &ctx, "resident.css").?;
    defer cache.release(resident);

    try testing.expect(resident.bytes != null);
    try testing.expectEqualStrings("body{margin:0}", resident.bytes.?);
}

test "zix http2: static frames a resident body without reading the file again" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Longer than the frame cap used below, so the resident path has to walk its own offsets.
    var payload: [900]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    tmp.dir.writeFile(testing.io, .{ .sub_path = "bundle.js", .data = &payload }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = TEST_FD, .sid = 11, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };
    var req = Request{ .method = "GET", .path = "/bundle.js", .query = "", .headers = &.{}, .body = &.{} };

    var sink_ctx: usize = 0;
    hook_sink_len = 0;
    frame.write_hook = hookCollect;
    frame.write_hook_ctx = @ptrCast(&sink_ctx);
    defer {
        frame.write_hook = null;
        frame.write_hook_ctx = null;
    }

    try testing.expect(serve(&req, &ctx, "bundle.js", 256));

    const summary = summarizeFrames(hook_sink[0..hook_sink_len]);
    try testing.expectEqual(@as(usize, 1), summary.header_count);
    try testing.expectEqual(@as(u64, payload.len), summary.data_bytes);
    try testing.expect(summary.largest_data <= 256);
    try testing.expect((summary.last_data_flags & frame.FLAG_END_STREAM) != 0);

    var body_buf: [1024]u8 = undefined;
    try testing.expectEqualStrings(&payload, collectData(hook_sink[0..hook_sink_len], &body_buf));
}

test "zix http2: static serves the brotli sibling from resident bytes while coalescing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "theme.css", .data = "the plain theme" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "theme.css.br", .data = "packed" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = TEST_FD, .sid = 13, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };

    var headers = [_]hpack.Header{.{ .name = "accept-encoding", .value = "br, gzip" }};
    var req = Request{ .method = "GET", .path = "/theme.css", .query = "", .headers = &headers, .body = &.{} };

    var sink_ctx: usize = 0;
    hook_sink_len = 0;
    frame.write_hook = hookCollect;
    frame.write_hook_ctx = @ptrCast(&sink_ctx);
    defer {
        frame.write_hook = null;
        frame.write_hook_ctx = null;
    }

    try testing.expect(serve(&req, &ctx, "theme.css", frame.DEFAULT_MAX_FRAME_SIZE));

    // The sibling is snapshotted separately from identity, so the resident path must not serve the
    // identity bytes to a client that negotiated brotli.
    var body_buf: [128]u8 = undefined;
    try testing.expectEqualStrings("packed", collectData(hook_sink[0..hook_sink_len], &body_buf));
}

test "zix http2: static serve picks the brotli sibling from the cache" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js", .data = "the plain vendor bundle" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js.br", .data = "squeezed" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        fd_io.close(pair[0]);
        fd_io.close(pair[1]);
    }

    var arena_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = pair[0], .sid = 9, .io = testing.io, .allocator = fba.allocator(), .public_dir = root };

    var headers = [_]hpack.Header{.{ .name = "accept-encoding", .value = "br, gzip" }};
    var req = Request{ .method = "GET", .path = "/vendor.js", .query = "", .headers = &headers, .body = &.{} };

    try testing.expect(serve(&req, &ctx, "vendor.js", frame.DEFAULT_MAX_FRAME_SIZE));

    fd_io.close(pair[0]);

    var wire_buf: [2048]u8 = undefined;
    const wire = drain(pair[1], &wire_buf);

    var body_buf: [128]u8 = undefined;
    try testing.expectEqualStrings("squeezed", collectData(wire, &body_buf));
}
