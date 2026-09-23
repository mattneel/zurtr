//! zix http1 static file serving: the public_dir fallback for unmatched routes.
//!
//! The static fallback runs inside the router before any handler, so the router reads the
//! configured public_dir and io from core threadlocals (core.setStatic, installed per worker) and
//! calls serve here. Writes go through core.writeAllFD, so the response-coalescing sink and the TLS
//! buffering path are honored the same as any other Http1 response.
//!
//! Two paths live behind one entry point. When a static cache is installed (ADR-064) a resolved
//! file is already open and its 200 header already rendered, so a repeat request costs a hash
//! lookup and, in cleartext, a single sendfile. Without one, or when the cache cannot take the
//! request, the original open-stat-copy path runs unchanged.
//!
//! Over TLS there is no sendfile to reach for: the handler writes into a capture buffer that is
//! encrypted afterwards, so the body has to pass through user space. There the cache is asked for a
//! resident body instead, which is what keeps an encrypted response from re-reading the same file
//! on every request.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
const content = @import("../http/content.zig");
const file_utils = @import("../../utils/file.zig");
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

/// Whether the body may be handed straight to the kernel for this response.
///
/// Note:
/// - A negative fd is the TLS capture path's sentinel: the "socket" is a buffer that gets
///   encrypted afterwards, so a direct write would put plaintext on the wire.
/// - A streaming TLS sink means every write has to become a TLS record.
fn zeroCopyAllowed(fd: std.posix.fd_t) bool {
    if (comptime builtin.target.os.tag != .linux) return false;

    return fd >= 0 and core.tl_tls_stream == null;
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
///   otherwise the body would overtake its own header under pipelining.
/// - A resident body is written straight from its own bytes. Over TLS the body has to reach user
///   space anyway, and reading the same range back out of the page cache per 16 KiB chunk is pure
///   overhead when the cache already holds it. A range is just a slice of those bytes.
fn sendFromCache(fd: std.posix.fd_t, io: std.Io, hit: static_cache.Hit, header: []const u8, offset: u64, length: u64) void {
    const zero_copy = zeroCopyAllowed(fd);

    core.writeAllFD(fd, header) catch return;

    if (zero_copy) core.flushPending(fd);

    if (hit.bytes) |body| {
        core.writeAllFD(fd, body[@intCast(offset)..][0..@intCast(length)]) catch {};

        return;
    }

    static_send.sendBody(fd, io, hit.file, offset, length, zero_copy, core.writeAllFD) catch {};
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
    head: *const core.ParsedHead,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) ?static_cache.Hit {
    const accept_encoding = core.acceptEncoding(head);
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
    head: *const core.ParsedHead,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) bool {
    const cache = static_cache.instance() orelse return false;

    const hit = acquireHit(cache, head, fd, req_path, public_dir, io) orelse return false;
    defer cache.release(hit);

    if (core.getHeader(head, "range")) |range_val| {
        if (core.parseRange(range_val, hit.size)) |range| {
            var header_buf: [HEADER_STAGING_BUF]u8 = undefined;
            if (renderRangeHeader(&header_buf, hit, range.start, range.end)) |header| {
                sendFromCache(fd, io, hit, header, range.start, range.end - range.start + 1);

                return true;
            }
        }
    }

    sendFromCache(fd, io, hit, hit.header, 0, hit.size);

    return true;
}

/// Serve a static file from the public directory.
///
/// Rejects paths containing ".." to prevent directory traversal. Supports Range requests
/// (RFC 7233) for partial content (206). An unsatisfiable or malformed Range is ignored and
/// the full body is sent with 200, which RFC 7233 permits.
///
/// Note:
/// - The cached path is tried first and owns the request once the file resolves. It is inert
///   unless public_dir_cache_ttl_ms is set, so the default configuration runs the original path.
///
/// Param:
/// head - *const core.ParsedHead (request head, read for the Range and Accept-Encoding headers)
/// fd - std.posix.fd_t (socket the response is written to, via core.writeAllFD)
/// req_path - []const u8 (request path with the leading slash already stripped)
/// public_dir - []const u8 (root directory, joined with req_path)
/// io - std.Io (file open / stat / read)
///
/// Return:
/// - true if the file was found and a response was written
/// - false if the file is not found or the path is invalid (caller sends 404)
pub fn serve(
    head: *const core.ParsedHead,
    fd: std.posix.fd_t,
    req_path: []const u8,
    public_dir: []const u8,
    io: std.Io,
) !bool {
    if (serveCached(head, fd, req_path, public_dir, io)) return true;

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

    if (core.getHeader(head, "range")) |range_val| {
        if (core.parseRange(range_val, stat.size)) |range| {
            const start = range.start;
            const end = range.end;
            const length = end - start + 1;

            const s = std.fmt.bufPrint(&header_buf, "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Range: bytes {d}-{d}/{d}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n", .{ content_type, length, start, end, stat.size }) catch return false;
            core.writeAllFD(fd, s) catch return false;

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
                core.writeAllFD(fd, copy_buf[0..n]) catch break;
                remaining -= n;
            }
            return true;
        }
    }

    const s = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n", .{ content_type, stat.size }) catch return false;
    core.writeAllFD(fd, s) catch return false;

    var file_buf: [FILE_BUF_SIZE]u8 = undefined;
    var reader = f.reader(io, &file_buf);
    var copy_buf: [FILE_BUF_SIZE]u8 = undefined;
    var remaining = stat.size;
    while (remaining > 0) {
        const to_read = @min(remaining, copy_buf.len);
        const n = reader.interface.readSliceShort(copy_buf[0..to_read]) catch break;
        if (n == 0) break;
        core.writeAllFD(fd, copy_buf[0..n]) catch break;
        remaining -= n;
    }
    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;
/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints. Only handed to paths
/// that decline before any write.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else 1;

fn testHead(path: []const u8, raw_headers: []const u8) core.ParsedHead {
    return .{
        .method = "GET",
        .path = path,
        .query = "",
        .raw_headers = raw_headers,
        .version_minor = 1,
        .keep_alive = true,
        .content_length = 0,
        .chunked_request = false,
        .expect_continue = false,
    };
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
fn installTlsSink(sink: *core.TlsStreamSink) void {
    sink.* = .{ .ctx = @ptrCast(&tls_sink_ctx), .writeFn = tlsSinkWrite };
    tls_sink_len = 0;
    core.tl_tls_stream = sink;
}

test "zix http1: static acquireHit takes resident bytes only when zero copy is refused" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "app.css", .data = "body{margin:0}" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    const cache = static_cache.instance().?;
    var head = testHead("/app.css", "");

    // A real descriptor and no TLS sink: sendfile can carry it, so the body is never read.
    const direct = acquireHit(cache, &head, 3, "app.css", root, testing.io).?;
    try testing.expect(direct.bytes == null);
    cache.release(direct);

    var sink: core.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer core.tl_tls_stream = null;

    const resident = acquireHit(cache, &head, 3, "app.css", root, testing.io).?;
    defer cache.release(resident);

    try testing.expect(resident.bytes != null);
    try testing.expectEqualStrings("body{margin:0}", resident.bytes.?);
}

test "zix http1: static serveCached writes a whole body from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>encrypted</h1>" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var sink: core.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer core.tl_tls_stream = null;

    var head = testHead("/page.html", "");
    try testing.expect(serveCached(&head, TEST_FD, "page.html", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 18\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n<h1>encrypted</h1>"));
}

test "zix http1: static serveCached answers a Range from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "clip.bin", .data = "0123456789" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var sink: core.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer core.tl_tls_stream = null;

    // The resident body is the WHOLE file, so a range has to be sliced out of it rather than
    // read at an offset. Getting that wrong serves the file from byte zero.
    var head = testHead("/clip.bin", "Range: bytes=2-5\r\n");
    try testing.expect(serveCached(&head, TEST_FD, "clip.bin", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 206 Partial Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Range: bytes 2-5/10\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 4\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n2345"));
}

test "zix http1: static serveCached serves a sibling from resident bytes over TLS" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js", .data = "the plain vendor bundle" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js.br", .data = "squeezed" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var sink: core.TlsStreamSink = undefined;
    installTlsSink(&sink);
    defer core.tl_tls_stream = null;

    // Each variant is snapshotted separately, so the brotli body must not come back as identity.
    var head = testHead("/vendor.js", "Accept-Encoding: br, gzip\r\n");
    try testing.expect(serveCached(&head, TEST_FD, "vendor.js", root, testing.io));

    const wire = tls_sink_buf[0..tls_sink_len];
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Encoding: br\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nsqueezed"));
}

test "zix http1: static serve rejects directory traversal" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var head = testHead("/../etc/passwd", "");
    const served = try serve(&head, 1, "../etc/passwd", "./public", threaded.io());
    try testing.expect(!served);
}

test "zix http1: static serve returns false for a missing file" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var head = testHead("/does-not-exist.txt", "");
    const served = try serve(&head, 1, "does-not-exist.txt", "./public", threaded.io());
    try testing.expect(!served);
}

test "zix http1: static serve returns false when the path overflows the join buffer" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var long_buf: [600]u8 = undefined;
    @memset(&long_buf, 'a');
    const long_path: []const u8 = &long_buf;

    var head = testHead("/x", "");
    const served = try serve(&head, 1, long_path, "./public", threaded.io());
    try testing.expect(!served);
}

test "zix http1: static serve mime resolves from extension" {
    try testing.expectEqualStrings("text/html", content.fromExtension(file_utils.extension("index.html")));
    try testing.expectEqualStrings("text/css", content.fromExtension(file_utils.extension("style.css")));
    try testing.expectEqualStrings("application/json", content.fromExtension(file_utils.extension("data.json")));
    try testing.expectEqualStrings("application/octet-stream", content.fromExtension(file_utils.extension("blob.unknown")));
}

test "zix http1: static zeroCopyAllowed refuses the TLS capture sentinel fd" {
    if (comptime builtin.target.os.tag != .linux) {
        // Every other target takes the copy path unconditionally, so there is
        // no zero-copy decision to make there.
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    // A real socket in cleartext is the only case that may hand the file to the kernel.
    try testing.expect(zeroCopyAllowed(3));

    // The buffered https path passes -1 as the request fd: its "socket" is a
    // staging buffer that gets encrypted afterwards.
    try testing.expect(!zeroCopyAllowed(-1));
}

test "zix http1: static renderRangeHeader states the range and repeats the encoding" {
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
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Length: 10\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Range: bytes 10-19/100\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Encoding") == null);

    // A range over a compressed representation still has to name its encoding,
    // since the offsets are into the encoded bytes.
    var br_buf: [HEADER_STAGING_BUF]u8 = undefined;
    const compressed = renderRangeHeader(&br_buf, .{
        .slot = 0,
        .file = undefined,
        .size = 40,
        .header = "",
        .content_type = "application/javascript",
        .encoding = .BR,
    }, 0, 9).?;

    try testing.expect(std.mem.indexOf(u8, compressed, "Content-Encoding: br\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, compressed, "Content-Range: bytes 0-9/40\r\n") != null);
}

test "zix http1: static serveCached declines when no cache is installed" {
    // The default configuration installs nothing, so every request falls through
    // to the original open-stat-copy path.
    try testing.expect(static_cache.instance() == null);

    var head = testHead("/anything.txt", "");
    try testing.expect(!serveCached(&head, TEST_FD, "anything.txt", "./public", testing.io));
}

/// Drain everything the peer end of a socketpair holds right now.
fn readPeer(peer: std.posix.fd_t, buf: []u8) []const u8 {
    const rc = std.os.linux.read(peer, buf.ptr, buf.len);
    if (std.posix.errno(rc) != .SUCCESS) return &.{};

    return buf[0..@intCast(rc)];
}

test "zix http1: static serveCached replays the prerendered 200 and the body" {
    if (comptime builtin.target.os.tag != .linux) {
        // The wire is captured through a Linux socketpair, and the zero-copy
        // send under test is the Linux sendfile shape.
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>cached</h1>" }) catch @panic("fixture write failed");

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

    var head = testHead("/page.html", "");
    try testing.expect(serveCached(&head, pair[0], "page.html", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/html\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 15\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Vary: Accept-Encoding\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n<h1>cached</h1>"));
}

test "zix http1: static serveCached answers a Range from the cached file" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

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

    var head = testHead("/clip.bin", "Range: bytes=2-5\r\n");
    try testing.expect(serveCached(&head, pair[0], "clip.bin", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 206 Partial Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Range: bytes 2-5/10\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 4\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\n2345"));
}

test "zix http1: static serveCached serves the brotli sibling when the client accepts it" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "bundle.js", .data = "the plain bundle" }) catch @panic("fixture write failed");
    tmp.dir.writeFile(testing.io, .{ .sub_path = "bundle.js.br", .data = "brotli" }) catch @panic("fixture write failed");

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

    var head = testHead("/bundle.js", "Accept-Encoding: br, gzip\r\n");
    try testing.expect(serveCached(&head, pair[0], "bundle.js", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.indexOf(u8, wire, "Content-Encoding: br\r\n") != null);
    // The type still comes from the identity name, not the .br suffix.
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: application/javascript\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nbrotli"));
}

test "zix http1: static serve falls back to the uncached path for a file the cache declines" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("sendfile zero-copy is the Linux shape, every other target copies, test skipped", .{});
        return;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(testing.io, .{ .sub_path = "plain.txt", .data = "uncached body" }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    // No cache installed at all: serve still works, through the original path.
    try testing.expect(static_cache.instance() == null);

    var pair: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair));
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }

    var head = testHead("/plain.txt", "");
    try testing.expect(try serve(&head, pair[0], "plain.txt", root, testing.io));

    var wire_buf: [512]u8 = undefined;
    const wire = readPeer(pair[1], &wire_buf);

    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    // The uncached path never claims to negotiate, so it emits no Vary.
    try testing.expect(std.mem.indexOf(u8, wire, "Vary") == null);
    try testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nuncached body"));
}
