//! zixer static files: resolve one request path to a file under public_dir

const std = @import("std");

const zix = @import("zix");

const cfg_headers = @import("cfg_headers.zig");

const compression = zix.utils.compression;

/// Longest joined path (public_dir plus the request path) this resolver serves,
/// re-exported so a zixer file names it without reaching across the package. It
/// is the same number the shared static cache stores, which is what keeps a path
/// from resolving here and being refused there.
pub const PUBLIC_PATH_MAX: usize = zix.utils.static_cache.PUBLIC_PATH_MAX;

/// Static serving surface of one site. The strings are owned by the serve
/// state and must outlive every connection.
pub const StaticSite = struct {
    public_dir: []const u8,
    public_prefix: ?[]const u8,
    spa_fallback: ?[]const u8,
};

/// One opened file ready to serve. The caller writes the body and closes file.
pub const Resolved = struct {
    file: std.Io.File,
    size: u64,
    content_type: []const u8,
    encoding: compression.Encoding,
};

/// Precompressed sibling probed on disk, in server preference order,
/// matching the zix static cache.
const Sibling = struct {
    encoding: compression.Encoding,
    suffix: []const u8,
};

const SIBLINGS = [_]Sibling{
    .{ .encoding = .BR, .suffix = ".br" },
    .{ .encoding = .GZIP, .suffix = ".gz" },
};

/// True for the methods a file can answer.
pub fn fileMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD");
}

/// True when this request may be answered from public_dir: file methods
/// only, and inside public_prefix when the site bounds one.
pub fn handles(site: *const StaticSite, method: []const u8, target: []const u8) bool {
    if (!fileMethod(method)) return false;

    const prefix = site.public_prefix orelse return true;

    return underPrefix(requestPath(target), prefix);
}

/// The path part of a request target, query dropped.
pub fn requestPath(target: []const u8) []const u8 {
    const query = std.mem.indexOfScalar(u8, target, '?') orelse return target;

    return target[0..query];
}

/// True when path sits at or under prefix on a segment boundary, so /assets
/// never matches /assetsfoo.
fn underPrefix(path: []const u8, prefix: []const u8) bool {
    if (!std.mem.startsWith(u8, path, prefix)) return false;

    return path.len == prefix.len or path[prefix.len] == '/';
}

/// Open the file for target under public_dir, negotiating the precompressed
/// .br and .gz siblings against the request Accept-Encoding.
///
/// Note:
/// - Identity is the floor: a client that accepts none of the present
///   siblings gets the plain file, matching the zix static cache.
/// - The caller closes the returned file once the response is written.
///
/// Param:
/// io - std.Io
/// public_dir - []const u8 (static root from the site cfg)
/// target - []const u8 (raw request target, query allowed)
/// accept_encoding - ?[]const u8 (raw header value, null when absent)
///
/// Return:
/// - Resolved with the file open
/// - null when the path is unsafe, missing, or not a regular file
pub fn open(io: std.Io, public_dir: []const u8, target: []const u8, accept_encoding: ?[]const u8) ?Resolved {
    var path_buf: [PUBLIC_PATH_MAX]u8 = undefined;
    const path = resolvePath(&path_buf, public_dir, requestPath(target)) orelse return null;

    var supported_buf: [SIBLINGS.len]compression.Encoding = undefined;
    for (SIBLINGS, 0..) |sibling, index| supported_buf[index] = sibling.encoding;
    var supported_len: usize = SIBLINGS.len;

    // Probe the negotiated coding first. A missing sibling drops out of the
    // supported set and the rest renegotiates, so a client accepting both
    // codings still gets gzip when only the .gz sibling exists on disk.
    while (supported_len > 0) {
        const chosen = compression.negotiate(accept_encoding, supported_buf[0..supported_len]) orelse .IDENTITY;
        if (chosen == .IDENTITY) break;

        var sibling_buf: [PUBLIC_PATH_MAX + 8]u8 = undefined;
        const sibling_path = std.fmt.bufPrint(&sibling_buf, "{s}{s}", .{ path, suffixOf(chosen) }) catch break;
        if (openFile(io, sibling_path, path, chosen)) |resolved| return resolved;

        supported_len = removeEncoding(supported_buf[0..supported_len], chosen);
    }

    return openFile(io, path, path, .IDENTITY);
}

/// Write the 200 head for a resolved file. Vary rides on every response so
/// an intermediary never hands a compressed body to a client that did not
/// ask for one.
///
/// Note:
/// - A name the site's cfg sets is left out here, so the configured line
///   replaces this one instead of standing beside it. Two lines of the same
///   name read as one comma-joined value (rfc 9110 5.2), which would make a
///   Content-Type unusable.
///
/// Param:
/// out - *std.Io.Writer (the client leg)
/// resolved - *const Resolved (the file this head describes)
/// edge_close - bool (whether this exchange ends the connection)
/// extra - cfg_headers.Block (the site's [response_headers], empty when none)
///
/// Return:
/// - void
pub fn writeResolvedHead(out: *std.Io.Writer, resolved: *const Resolved, edge_close: bool, extra: cfg_headers.Block) !void {
    try out.writeAll("HTTP/1.1 200 OK\r\n");
    if (!extra.owns("content-type")) try out.print("Content-Type: {s}\r\n", .{resolved.content_type});

    try out.print("Content-Length: {d}\r\n", .{resolved.size});
    if (resolved.encoding.contentEncoding()) |token| {
        if (!extra.owns("content-encoding")) try out.print("Content-Encoding: {s}\r\n", .{token});
    }

    if (!extra.owns("vary")) try out.writeAll("Vary: Accept-Encoding\r\n");
    if (edge_close) try out.writeAll("Connection: close\r\n");

    try extra.write(out);
    try out.writeAll("\r\n");
}

/// Join public_dir and the request path into buf, mapping a trailing slash
/// to index.html and rejecting anything a static server must not touch.
///
/// Note:
/// - ".." is rejected outright rather than normalized, matching the zix
///   static cache.
///
/// Return:
/// - []const u8 (the joined path inside buf)
/// - null when the path is unsafe or does not fit
fn resolvePath(buf: []u8, public_dir: []const u8, path: []const u8) ?[]const u8 {
    if (path.len == 0 or path[0] != '/') return null;
    if (std.mem.indexOf(u8, path, "..") != null) return null;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return null;

    const index_tail: []const u8 = if (path[path.len - 1] == '/') "index.html" else "";
    const total = public_dir.len + path.len + index_tail.len;
    if (total > buf.len) return null;

    @memcpy(buf[0..public_dir.len], public_dir);
    @memcpy(buf[public_dir.len..][0..path.len], path);
    @memcpy(buf[public_dir.len + path.len ..][0..index_tail.len], index_tail);

    return buf[0..total];
}

/// Open one candidate file. The content type always comes from the identity
/// name, so app.js.br still reports application/javascript.
fn openFile(io: std.Io, path: []const u8, type_path: []const u8, encoding: compression.Encoding) ?Resolved {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;

    const stat = file.stat(io) catch {
        file.close(io);
        return null;
    };
    if (stat.kind != .file) {
        file.close(io);
        return null;
    }

    const content_type = zix.Http1.Content.fromExtension(zix.utils.file.extension(type_path));

    return .{ .file = file, .size = stat.size, .content_type = content_type, .encoding = encoding };
}

/// Sibling file suffix of a precompressed coding.
fn suffixOf(encoding: compression.Encoding) []const u8 {
    for (SIBLINGS) |sibling| {
        if (sibling.encoding == encoding) return sibling.suffix;
    }

    return "";
}

/// Drop one coding from the supported set, keeping server preference order.
fn removeEncoding(supported: []compression.Encoding, gone: compression.Encoding) usize {
    var keep: usize = 0;
    for (supported) |encoding| {
        if (encoding == gone) continue;

        supported[keep] = encoding;
        keep += 1;
    }

    return keep;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Write one fixture file, panicking on failure since a fixture that cannot
/// be written is a broken test rather than a tested condition.
fn writeFixture(dir: std.Io.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(testing.io, .{ .sub_path = name, .data = data }) catch @panic("fixture write failed");
}

/// The tmp dir path relative to the test cwd, printed into buf.
fn fixtureRoot(buf: []u8, tmp: *const testing.TmpDir) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;
}

test "zix zixer: static files, request path strips the query" {
    try testing.expectEqualStrings("/app.js", requestPath("/app.js?v=3"));
    try testing.expectEqualStrings("/app.js", requestPath("/app.js"));
    try testing.expectEqualStrings("/", requestPath("/?page=2"));
}

test "zix zixer: static files, handles gates method and prefix" {
    const bare = StaticSite{ .public_dir = "/www", .public_prefix = null, .spa_fallback = null };
    try testing.expect(handles(&bare, "GET", "/anything"));
    try testing.expect(handles(&bare, "HEAD", "/anything"));
    try testing.expect(!handles(&bare, "POST", "/anything"));

    const bounded = StaticSite{ .public_dir = "/www", .public_prefix = "/assets", .spa_fallback = null };
    try testing.expect(handles(&bounded, "GET", "/assets/app.js"));
    try testing.expect(handles(&bounded, "GET", "/assets"));
    try testing.expect(handles(&bounded, "GET", "/assets/app.js?v=1"));
    try testing.expect(!handles(&bounded, "GET", "/assetsfoo/app.js"));
    try testing.expect(!handles(&bounded, "GET", "/api/users"));
    try testing.expect(!handles(&bounded, "POST", "/assets/app.js"));
}

test "zix zixer: static files, resolve rejects unsafe paths" {
    var buf: [PUBLIC_PATH_MAX]u8 = undefined;

    try testing.expectEqualStrings("/www/a.txt", resolvePath(&buf, "/www", "/a.txt").?);

    try testing.expect(resolvePath(&buf, "/www", "") == null);
    try testing.expect(resolvePath(&buf, "/www", "a.txt") == null);
    try testing.expect(resolvePath(&buf, "/www", "/../etc/passwd") == null);
    try testing.expect(resolvePath(&buf, "/www", "/a/../b") == null);
    try testing.expect(resolvePath(&buf, "/www", "/a\x00.txt") == null);

    var long: [PUBLIC_PATH_MAX]u8 = @splat('a');
    long[0] = '/';
    try testing.expect(resolvePath(&buf, "/www", &long) == null);
}

test "zix zixer: static files, trailing slash maps to index.html" {
    var buf: [PUBLIC_PATH_MAX]u8 = undefined;

    try testing.expectEqualStrings("/www/index.html", resolvePath(&buf, "/www", "/").?);
    try testing.expectEqualStrings("/www/docs/index.html", resolvePath(&buf, "/www", "/docs/").?);
}

test "zix zixer: static files, open negotiates precompressed siblings" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "plain-body-bytes");
    writeFixture(tmp.dir, "app.js.br", "br-body");
    writeFixture(tmp.dir, "app.js.gz", "gz-body-x");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    const brotli = open(testing.io, root, "/app.js", "br, gzip").?;
    try testing.expectEqual(compression.Encoding.BR, brotli.encoding);
    try testing.expectEqual(@as(u64, "br-body".len), brotli.size);
    try testing.expectEqualStrings("application/javascript", brotli.content_type);
    brotli.file.close(testing.io);

    const gzip = open(testing.io, root, "/app.js", "gzip").?;
    try testing.expectEqual(compression.Encoding.GZIP, gzip.encoding);
    try testing.expectEqual(@as(u64, "gz-body-x".len), gzip.size);
    gzip.file.close(testing.io);

    const plain = open(testing.io, root, "/app.js", null).?;
    try testing.expectEqual(compression.Encoding.IDENTITY, plain.encoding);
    try testing.expectEqual(@as(u64, "plain-body-bytes".len), plain.size);
    plain.file.close(testing.io);
}

test "zix zixer: static files, missing sibling falls back to the next coding" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "solo.css", "body{}");
    writeFixture(tmp.dir, "solo.css.gz", "gz-css");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    // Brotli wins negotiation but has no sibling on disk, so gzip serves.
    const gzip = open(testing.io, root, "/solo.css", "br, gzip").?;
    try testing.expectEqual(compression.Encoding.GZIP, gzip.encoding);
    try testing.expectEqualStrings("text/css", gzip.content_type);
    gzip.file.close(testing.io);

    // A client accepting only brotli falls all the way to identity.
    writeFixture(tmp.dir, "lone.css", "p{}");
    const identity = open(testing.io, root, "/lone.css", "br").?;
    try testing.expectEqual(compression.Encoding.IDENTITY, identity.encoding);
    identity.file.close(testing.io);
}

test "zix zixer: static files, open refuses a directory and a missing file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.createDirPath(testing.io, "sub") catch @panic("fixture dir failed");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    try testing.expect(open(testing.io, root, "/sub", null) == null);
    try testing.expect(open(testing.io, root, "/absent.txt", null) == null);
}

test "zix zixer: static files, resolved head carries vary and encoding" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "page.html", "<h1>hi</h1>");
    writeFixture(tmp.dir, "page.html.br", "br-page");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    const brotli = open(testing.io, root, "/page.html", "br").?;
    defer brotli.file.close(testing.io);

    var head_buf: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&head_buf);
    try writeResolvedHead(&out, &brotli, false, .{});
    const head = out.buffered();

    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Content-Type: text/html\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length: 7\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Encoding: br\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Vary: Accept-Encoding\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Connection") == null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));

    const plain = open(testing.io, root, "/page.html", null).?;
    defer plain.file.close(testing.io);

    var close_buf: [512]u8 = undefined;
    var close_out = std.Io.Writer.fixed(&close_buf);
    try writeResolvedHead(&close_out, &plain, true, .{});
    const close_head = close_out.buffered();

    try testing.expect(std.mem.indexOf(u8, close_head, "Content-Encoding") == null);
    try testing.expect(std.mem.indexOf(u8, close_head, "Connection: close\r\n") != null);
}
