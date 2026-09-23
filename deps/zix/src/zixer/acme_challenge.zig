//! zixer acme challenge plane: answer /.well-known/acme-challenge requests

const std = @import("std");

const site_cfg = @import("site_cfg.zig");
const static_files = @import("static_files.zig");

/// The http-01 challenge path (rfc 8555 8.3). Everything under it is the
/// CA's validation traffic, answered before any site logic.
pub const PREFIX = "/.well-known/acme-challenge/";

/// Relay copy chunk for the standalone passthrough.
const RELAY_CHUNK: usize = 4 * 1024;

/// How one site answers the challenge path: a certbot webroot on disk, or
/// a passthrough to a standalone certbot listener. Validation guarantees
/// at most one of the two is set.
pub const AcmeSite = struct {
    webroot: ?[]const u8 = null,
    relay: ?site_cfg.Upstream = null,
};

/// Whether the request path (query stripped) sits under the challenge
/// prefix with a token present.
pub fn handles(target: []const u8) bool {
    const path = static_files.requestPath(target);

    return std.mem.startsWith(u8, path, PREFIX) and path.len > PREFIX.len;
}

/// Open the challenge file under the webroot. Identity only: the CA never
/// negotiates content codings, and certbot writes plain token files.
pub fn resolveWebroot(io: std.Io, webroot: []const u8, target: []const u8) ?static_files.Resolved {
    return static_files.open(io, webroot, target, null);
}

/// Standalone passthrough (certbot --standalone --http-01-port): one fresh
/// connection per challenge request, re-originated head, response relayed
/// until the standalone listener closes. The edge connection closes after
/// (the relayed response carries no reusable framing promise).
///
/// Return:
/// - true when a response was relayed
/// - false when the listener was unreachable (the caller answers locally)
pub fn relay(io: std.Io, upstream: site_cfg.Upstream, method: []const u8, target: []const u8, host: []const u8, client_w: *std.Io.Writer) bool {
    const addr = std.Io.net.IpAddress.resolve(io, upstream.host, upstream.port) catch return false;
    const stream = addr.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch return false;
    defer stream.close(io);

    var read_buf: [RELAY_CHUNK]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var up_reader = stream.reader(io, &read_buf);
    var up_writer = stream.writer(io, &write_buf);

    up_writer.interface.print(
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\nVia: 1.1 zixer\r\nConnection: close\r\n\r\n",
        .{ method, target, host },
    ) catch return false;
    up_writer.interface.flush() catch return false;

    var chunk: [RELAY_CHUNK]u8 = undefined;
    var relayed = false;
    while (true) {
        const got = up_reader.interface.readSliceShort(&chunk) catch break;
        if (got == 0) break;

        client_w.writeAll(chunk[0..got]) catch return relayed;
        relayed = true;
    }

    return relayed;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn writeFixture(dir: std.Io.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(testing.io, .{ .sub_path = name, .data = data }) catch @panic("fixture write failed");
}

/// The tmp dir path relative to the test cwd, printed into buf.
fn fixtureRoot(buf: []u8, tmp: *const testing.TmpDir) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;
}

test "zix zixer: acme challenge, handles matches only the challenge path" {
    try testing.expect(handles("/.well-known/acme-challenge/token123"));
    try testing.expect(handles("/.well-known/acme-challenge/token123?probe=1"));

    try testing.expect(!handles("/.well-known/acme-challenge/"));
    try testing.expect(!handles("/.well-known/acme-challengeX/token"));
    try testing.expect(!handles("/index.html"));
    try testing.expect(!handles("/"));
}

test "zix zixer: acme challenge, webroot resolves the token file as identity" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.createDirPath(testing.io, ".well-known/acme-challenge") catch @panic("fixture dir failed");
    writeFixture(tmp.dir, ".well-known/acme-challenge/tok_abc", "tok_abc.thumbprint");

    var root_buf: [128]u8 = undefined;
    const webroot = fixtureRoot(&root_buf, &tmp);

    const resolved = resolveWebroot(testing.io, webroot, "/.well-known/acme-challenge/tok_abc") orelse
        return error.TestUnexpectedResult;
    defer resolved.file.close(testing.io);

    try testing.expectEqual(@as(u64, "tok_abc.thumbprint".len), resolved.size);
    try testing.expect(resolved.encoding == .IDENTITY);

    try testing.expect(resolveWebroot(testing.io, webroot, "/.well-known/acme-challenge/absent") == null);
}

/// Fake standalone certbot listener: answer one request with a fixed body,
/// then close.
fn fakeStandalone(io: std.Io, server: *std.Io.net.Server) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);

    var read_buf: [1024]u8 = undefined;
    var write_buf: [256]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    var head: [1024]u8 = undefined;
    var len: usize = 0;
    while (len < head.len) {
        const got = reader.interface.readSliceShort(head[len .. len + 1]) catch return;
        if (got == 0) return;

        len += got;
        if (len >= 4 and std.mem.eql(u8, head[len - 4 .. len], "\r\n\r\n")) break;
    }

    writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\ntoken") catch return;
    writer.interface.flush() catch return;
}

test "zix zixer: acme challenge, relay passes the standalone response through" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18891);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const server_thread = try std.Thread.spawn(.{}, fakeStandalone, .{ io, &server });
    defer server_thread.join();

    var out_buf: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);
    const upstream = site_cfg.Upstream{ .host = "127.0.0.1", .port = 18891 };

    try testing.expect(relay(io, upstream, "GET", "/.well-known/acme-challenge/tok", "example.test", &out));
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "200 OK") != null);
    try testing.expect(std.mem.endsWith(u8, out.buffered(), "token"));
}

test "zix zixer: acme challenge, relay reports an unreachable listener" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&out_buf);
    const upstream = site_cfg.Upstream{ .host = "127.0.0.1", .port = 18892 };

    try testing.expect(!relay(io, upstream, "GET", "/.well-known/acme-challenge/tok", "example.test", &out));
    try testing.expectEqual(@as(usize, 0), out.buffered().len);
}
