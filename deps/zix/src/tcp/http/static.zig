//! zix http static
//!
//! Two paths behind one entry point. When a static cache is installed (ADR-064) a resolved file is
//! already open and its 200 header already rendered, so a repeat request costs a hash lookup and,
//! in cleartext, a single sendfile. Without one, or when the cache cannot take the request, the
//! original open-stat-copy path runs unchanged. Mirrors zix.Http1 static.
//!
//! Over TLS there is no sendfile to reach for: the handler writes into a capture buffer that is
//! encrypted afterwards, so the body has to pass through user space. There the cache is asked for a
//! resident body instead, which is what keeps an encrypted response from re-reading the same file
//! on every request.

const std = @import("std");
const builtin = @import("builtin");
const content = @import("content.zig");
const file_utils = @import("../../utils/file.zig");
const Request = @import("request.zig").Request;
const response = @import("response.zig");
const writeAllFD = response.writeAllFD;
const static_cache = @import("../../utils/static_cache.zig");
const static_send = @import("../../utils/static_send.zig");
const response_cache = @import("../../utils/response_cache.zig");

// --------------------------------------------------------- //

/// Stack buffer for reading and copying a file in chunks during static serving.
const FILE_BUF_SIZE: usize = 8 * 1024;
/// Served full-path stack buffer.
const FULL_PATH_BUF: usize = 512;
/// Static-serve response header staging buffer.
const HEADER_STAGING_BUF: usize = 2048;

// --------------------------------------------------------- //

const RangeRequest = struct {
    start: u64,
    end: ?u64,
};

fn parseRangeHeader(value: []const u8) ?RangeRequest {
    if (!std.mem.startsWith(u8, value, "bytes=")) return null;
    const spec = value[6..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    const start = std.fmt.parseInt(u64, spec[0..dash], 10) catch return null;
    const end = if (dash + 1 < spec.len) std.fmt.parseInt(u64, spec[dash + 1 ..], 10) catch null else null;
    return .{ .start = start, .end = end };
}

/// Whether the body may be handed straight to the kernel for this response.
///
/// Note:
/// - A negative fd is the TLS capture path's sentinel: the "socket" is a buffer that gets
///   encrypted afterwards, so a direct write would put plaintext on the wire.
/// - A streaming TLS sink means every write has to become a TLS record.
fn zeroCopyAllowed(fd: std.posix.fd_t) bool {
    if (comptime builtin.os.tag != .linux) return false;

    return fd >= 0 and response.tl_tls_stream == null;
}

/// Render the 206 header for a range of a cached file. The prerendered header cannot be replayed
/// here: it is a 200 carrying the whole length.
fn renderRangeHeader(buf: []u8, hit: static_cache.Hit, start: u64, end: u64) ?[]const u8 {
    const length = end - start + 1;

    if (hit.encoding.contentEncoding()) |token| {
        return std.fmt.bufPrint(buf, "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Encoding: {s}\r\nContent-Range: bytes {d}-{d}/{d}\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nConnection: keep-alive\r\n\r\n", .{ hit.content_type, length, token, start, end, hit.size }) catch null;
    }

    return std.fmt.bufPrint(buf, "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Range: bytes {d}-{d}/{d}\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nConnection: keep-alive\r\n\r\n", .{ hit.content_type, length, start, end, hit.size }) catch null;
}

/// Write one header and then its body range from an already-open cached file.
///
/// Note:
/// - The zero-copy body bypasses the coalescing sink, so anything staged there is flushed first,
///   otherwise the body would overtake its own header on the wire.
/// - A resident body is written straight from its own bytes. Over TLS the body has to reach user
///   space anyway, and reading the same range back out of the page cache per 16 KiB chunk is pure
///   overhead when the cache already holds it. A range is just a slice of those bytes.
fn sendFromCache(fd: std.posix.fd_t, io: std.Io, hit: static_cache.Hit, header: []const u8, offset: u64, length: u64) void {
    const zero_copy = zeroCopyAllowed(fd);

    writeAllFD(fd, header) catch return;

    if (zero_copy) response.flushPending(fd);

    if (hit.bytes) |body| {
        writeAllFD(fd, body[@intCast(offset)..][0..@intCast(length)]) catch {};

        return;
    }

    static_send.sendBody(fd, io, hit.file, offset, length, zero_copy, writeAllFD) catch {};
}

/// Take a cache hit for this request, preferring one whose bytes are resident.
///
/// Note:
/// - Only worth asking for when the body cannot leave by sendfile, which over TLS it never can:
///   the handler runs against a capture buffer that is encrypted afterwards.
/// - acquireMapped declines a file past SNAPSHOT_MAX_BYTES, so that falls back to the plain hit and
///   keeps the open descriptor rather than dropping the request to the uncached path.
fn acquireHit(
    cache: *static_cache.StaticCache,
    req: *Request,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) ?static_cache.Hit {
    const accept_encoding = req.header("accept-encoding");
    const ttl = static_cache.ttlMs();
    const now = response_cache.nowMillis();

    if (!zeroCopyAllowed(fd)) {
        if (cache.acquireMapped(io, public_dir, req_path, accept_encoding, ttl, now)) |resident| return resident;
    }

    return cache.acquire(io, public_dir, req_path, accept_encoding, ttl, now);
}

/// Serve the request from the static cache when one is installed and can take it.
///
/// Note:
/// - Once a hit is in hand the request is answered here, write errors included. A broken peer is
///   not a missing file, so the caller must not follow it with a 404.
///
/// Return:
/// - true when the response was served from the cache
/// - false when there is no cache, or the cache declined the path (caller falls back)
fn serveCached(
    req: *Request,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) bool {
    const cache = static_cache.instance() orelse return false;

    const hit = acquireHit(cache, req, fd, req_path, public_dir, io) orelse return false;
    defer cache.release(hit);

    if (req.header("range")) |range_val| {
        if (parseRangeHeader(range_val)) |range| {
            var header_buf: [HEADER_STAGING_BUF]u8 = undefined;

            if (range.start >= hit.size) {
                const unsatisfiable = std.fmt.bufPrint(&header_buf, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{d}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", .{hit.size}) catch return true;
                writeAllFD(fd, unsatisfiable) catch {};

                return true;
            }

            const end = range.end orelse hit.size - 1;
            if (renderRangeHeader(&header_buf, hit, range.start, end)) |header| {
                sendFromCache(fd, io, hit, header, range.start, end - range.start + 1);

                return true;
            }
        }
    }

    sendFromCache(fd, io, hit, hit.header, 0, hit.size);

    return true;
}

/// Serve a static file from the public directory.
/// Rejects paths containing ".." to prevent directory traversal.
/// Supports Range requests (RFC 7233) for partial content (206).
///
/// Note:
/// - The cached path is tried first and owns the request once the file resolves. It is inert
///   unless public_dir_cache_ttl_ms is set, so the default configuration runs the original path.
///
/// Return:
/// - false if the file is not found or the path is invalid (caller sends 404)
pub fn serve(
    req: *Request,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) !bool {
    if (serveCached(req, fd, req_path, public_dir, io)) return true;

    if (std.mem.indexOf(u8, req_path, "..") != null) return false;

    var full_path_buf: [FULL_PATH_BUF]u8 = undefined;
    if (public_dir.len + 1 + req_path.len > full_path_buf.len) return false;
    @memcpy(full_path_buf[0..public_dir.len], public_dir);
    full_path_buf[public_dir.len] = '/';
    @memcpy(full_path_buf[public_dir.len + 1 ..][0..req_path.len], req_path);
    const full_path = full_path_buf[0 .. public_dir.len + 1 + req_path.len];

    const f = std.Io.Dir.cwd().openFile(io, full_path, .{}) catch return false;
    defer f.close(io);

    const stat = f.stat(io) catch return false;
    if (stat.kind != .file) return false;

    const content_type = content.fromExtension(file_utils.extension(req_path));

    var header_buf: [HEADER_STAGING_BUF]u8 = undefined;

    if (req.header("range")) |range_val| {
        if (parseRangeHeader(range_val)) |range| {
            const start = range.start;
            const end = range.end orelse stat.size - 1;
            const length = end - start + 1;

            if (start >= stat.size) {
                const s = std.fmt.bufPrint(&header_buf, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{d}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", .{stat.size}) catch return false;
                writeAllFD(fd, s) catch return false;
                return true;
            }

            const s = std.fmt.bufPrint(&header_buf, "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Range: bytes {d}-{d}/{d}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n", .{ content_type, length, start, end, stat.size }) catch return false;
            writeAllFD(fd, s) catch return false;

            var file_buf: [FILE_BUF_SIZE]u8 = undefined;
            var reader = f.reader(io, &file_buf);
            var skipped: u64 = 0;
            while (skipped < start) {
                const to_skip = @min(start - skipped, file_buf.len);
                const n = reader.interface.readSliceShort(file_buf[0..@intCast(to_skip)]) catch break;
                if (n == 0) break;
                skipped += n;
            }
            var copy_buf: [FILE_BUF_SIZE]u8 = undefined;
            var remaining = length;
            while (remaining > 0) {
                const to_read = @min(remaining, copy_buf.len);
                const n = reader.interface.readSliceShort(copy_buf[0..@intCast(to_read)]) catch break;
                if (n == 0) break;
                writeAllFD(fd, copy_buf[0..n]) catch break;
                remaining -= n;
            }
            return true;
        }
    }

    // Full file response.
    const s = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n", .{ content_type, stat.size }) catch return false;
    writeAllFD(fd, s) catch return false;

    var file_buf: [FILE_BUF_SIZE]u8 = undefined;
    var reader = f.reader(io, &file_buf);
    var copy_buf: [FILE_BUF_SIZE]u8 = undefined;
    var remaining = stat.size;
    while (remaining > 0) {
        const to_read = @min(remaining, copy_buf.len);
        const n = reader.interface.readSliceShort(copy_buf[0..to_read]) catch break;
        if (n == 0) break;
        writeAllFD(fd, copy_buf[0..n]) catch break;
        remaining -= n;
    }
    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: static mimeType" {
    try std.testing.expectEqualStrings("text/html", content.fromExtension("html"));
    try std.testing.expectEqualStrings("text/css", content.fromExtension("css"));
    try std.testing.expectEqualStrings("application/json", content.fromExtension("json"));
    try std.testing.expectEqualStrings("image/png", content.fromExtension("png"));
    try std.testing.expectEqualStrings("application/octet-stream", content.fromExtension("unknown"));
}

test "zix http: static parseRangeHeader" {
    const r1 = parseRangeHeader("bytes=0-499").?;
    try std.testing.expectEqual(@as(u64, 0), r1.start);
    try std.testing.expectEqual(@as(u64, 499), r1.end.?);

    const r2 = parseRangeHeader("bytes=500-").?;
    try std.testing.expectEqual(@as(u64, 500), r2.start);
    try std.testing.expect(r2.end == null);

    try std.testing.expect(parseRangeHeader("none") == null);
    try std.testing.expect(parseRangeHeader("bytes=abc") == null);
}

const testing = std.testing;
/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints. Only handed to paths
/// that decline before any write.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else 1;

const parser = @import("parser.zig");

/// Build a Request over a raw request head, the same shape the dispatch loop hands to a handler.
fn testRequest(raw: []const u8, allocator: std.mem.Allocator) !Request {
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;

    return .{
        .buf = raw,
        .head = head,
        .fd = undefined,
        .buf_filled = raw.len,
        .allocator = allocator,
    };
}

/// Drain everything the peer end of a socketpair holds right now.
fn readPeer(peer: std.posix.fd_t, buf: []u8) []const u8 {
    const rc = std.os.linux.read(peer, buf.ptr, buf.len);
    if (std.posix.errno(rc) != .SUCCESS) return &.{};

    return buf[0..@intCast(rc)];
}

/// Collects everything the TLS stream sink is handed, standing in for an encrypted connection so
/// the resident path can be read back without a handshake.
var tls_sink_buf: [8192]u8 = undefined;
var tls_sink_len: usize = 0;
var tls_sink_ctx: usize = 0;

fn tlsSinkWrite(_: *anyopaque, plaintext: []const u8) bool {
    if (tls_sink_len + plaintext.len > tls_sink_buf.len) return false;

    @memcpy(tls_sink_buf[tls_sink_len..][0..plaintext.len], plaintext);
    tls_sink_len += plaintext.len;

    return true;
}

/// Install a collecting TLS stream sink, which is what makes zeroCopyAllowed refuse sendfile.
fn installTlsSink(sink: *response.TlsStreamSink) void {
    sink.* = .{ .ctx = @ptrCast(&tls_sink_ctx), .writeFn = tlsSinkWrite };
    tls_sink_len = 0;
    response.tl_tls_stream = sink;
}

/// Build a public_dir under the test cache directory and return its path inside buf.
fn fixtureRoot(tmp: *std.testing.TmpDir, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;
}

test "zix http: static acquireHit takes resident bytes only when zero copy is refused" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "app.css", .data = "body{margin:0}" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&tmp, &root_buf);

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    const cache = static_cache.instance().?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = try testRequest("GET /app.css HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    // A real descriptor and no TLS sink: sendfile can carry it, so the body is never read.
    const direct = acquireHit(cache, &req, 3, "app.css", root, testing.io).?;
    try testing.expect(direct.bytes == null);
    cache.release(direct);

    var sink: response.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer response.tl_tls_stream = null;

    const resident = acquireHit(cache, &req, 3, "app.css", root, testing.io).?;
    defer cache.release(resident);

    try testing.expect(resident.bytes != null);
    try testing.expectEqualStrings("body{margin:0}", resident.bytes.?);
}

test "zix http: static serveCached writes a whole body from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>encrypted</h1>" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&tmp, &root_buf);

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = try testRequest("GET /page.html HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    var sink: response.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer response.tl_tls_stream = null;

    try testing.expect(serveCached(&req, TEST_FD, "page.html", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 18\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n<h1>encrypted</h1>"));
}

test "zix http: static serveCached answers a Range from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "clip.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&tmp, &root_buf);

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = try testRequest("GET /clip.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=2-5\r\n\r\n", arena.allocator());

    var sink: response.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer response.tl_tls_stream = null;

    // The resident body is the WHOLE file, so a range has to be sliced out of it rather than read
    // at an offset. Getting that wrong serves the right length from byte zero.
    try testing.expect(serveCached(&req, TEST_FD, "clip.bin", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 206 Partial Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Range: bytes 2-5/10\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n2345"));
}

test "zix http: static serveCached serves a sibling from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js", .data = "the plain vendor bundle" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js.gz", .data = "zipped" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&tmp, &root_buf);

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = try testRequest("GET /vendor.js HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n", arena.allocator());

    var sink: response.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer response.tl_tls_stream = null;

    // Each variant is snapshotted separately, so the gzip body must not come back as identity.
    try testing.expect(serveCached(&req, TEST_FD, "vendor.js", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Encoding: gzip\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nzipped"));
}

test "zix http: static zeroCopyAllowed refuses the TLS capture sentinel fd" {
    if (comptime builtin.os.tag != .linux) {
        // Every other target takes the copy path unconditionally, so there is
        // no zero-copy decision to make there.
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    try testing.expect(zeroCopyAllowed(3));
    try testing.expect(!zeroCopyAllowed(-1));
}

test "zix http: static renderRangeHeader states the range and repeats the encoding" {
    var buf: [HEADER_STAGING_BUF]u8 = undefined;

    const plain = renderRangeHeader(&buf, .{
        .slot = 0,
        .file = undefined,
        .size = 100,
        .header = "",
        .content_type = "text/plain",
        .encoding = .IDENTITY,
    }, 10, 19).?;

    try testing.expect(std.mem.startsWith(u8, plain, "HTTP/1.1 206 Partial Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Range: bytes 10-19/100\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Encoding") == null);

    var gz_buf: [HEADER_STAGING_BUF]u8 = undefined;
    const compressed = renderRangeHeader(&gz_buf, .{
        .slot = 0,
        .file = undefined,
        .size = 40,
        .header = "",
        .content_type = "text/css",
        .encoding = .GZIP,
    }, 0, 9).?;

    try testing.expect(std.mem.indexOf(u8, compressed, "Content-Encoding: gzip\r\n") != null);
}

test "zix http: static serveCached declines when no cache is installed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(static_cache.instance() == null);

    var req = try testRequest("GET /anything.txt HTTP/1.1\r\nHost: localhost\r\n\r\n", arena.allocator());
    try testing.expect(!serveCached(&req, TEST_FD, "anything.txt", "./public", testing.io));
}

test "zix http: static serveCached replays the prerendered 200 and the body" {
    if (comptime builtin.os.tag != .linux) {
        // The wire is captured through a Linux socketpair, and the zero-copy
        // send under test is the Linux sendfile shape.
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "index.html", .data = "<p>http</p>" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }

    var req = try testRequest("GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n", arena.allocator());
    try testing.expect(serveCached(&req, pair[0], "index.html", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/html\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 11\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Vary: Accept-Encoding\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n<p>http</p>"));
}

test "zix http: static serveCached answers a Range and rejects one past the end" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "clip.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }

    var satisfiable = try testRequest("GET /clip.bin HTTP/1.1\r\nRange: bytes=4-6\r\n\r\n", arena.allocator());
    try testing.expect(serveCached(&satisfiable, pair[0], "clip.bin", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const partial = readPeer(pair[1], &wire_buf);
    try testing.expect(std.mem.startsWith(u8, partial, "HTTP/1.1 206 Partial Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, partial, "Content-Range: bytes 4-6/10\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, partial, "\r\n\r\n456"));

    // An open-ended range runs to the last byte.
    var open_ended = try testRequest("GET /clip.bin HTTP/1.1\r\nRange: bytes=7-\r\n\r\n", arena.allocator());
    try testing.expect(serveCached(&open_ended, pair[0], "clip.bin", root, testing.io));

    const tail = readPeer(pair[1], &wire_buf);
    try testing.expect(std.mem.indexOf(u8, tail, "Content-Range: bytes 7-9/10\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, tail, "\r\n\r\n789"));

    // A start past the end is unsatisfiable, matching the uncached path.
    var past_end = try testRequest("GET /clip.bin HTTP/1.1\r\nRange: bytes=99-\r\n\r\n", arena.allocator());
    try testing.expect(serveCached(&past_end, pair[0], "clip.bin", root, testing.io));

    const refused = readPeer(pair[1], &wire_buf);
    try testing.expect(std.mem.startsWith(u8, refused, "HTTP/1.1 416 Range Not Satisfiable\r\n"));
    try testing.expect(std.mem.indexOf(u8, refused, "Content-Range: bytes */10\r\n") != null);
}

test "zix http: static serveCached serves the gzip sibling when the client accepts it" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "site.css", .data = "body { margin: 0 }" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "site.css.gz", .data = "gzipped" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }

    var req = try testRequest("GET /site.css HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", arena.allocator());
    try testing.expect(serveCached(&req, pair[0], "site.css", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.indexOf(u8, wire, "Content-Encoding: gzip\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/css\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\ngzipped"));
}

test "zix http: static serve falls back to the uncached path with no cache installed" {
    if (comptime builtin.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "plain.txt", .data = "uncached body" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    try testing.expect(static_cache.instance() == null);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }

    var req = try testRequest("GET /plain.txt HTTP/1.1\r\nHost: localhost\r\n\r\n", arena.allocator());
    try testing.expect(try serve(&req, pair[0], "plain.txt", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Vary") == null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nuncached body"));
}
