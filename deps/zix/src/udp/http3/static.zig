//! zix http3 static file serving: the public_dir fallback for unmatched routes.
//!
//! The router calls serve here before writing its 404, reading public_dir from the Context the
//! engine built. It sets the response body and lets the engine frame it, so a small file rides the
//! coalesced single-packet path and a large one is registered as a send stream the pump fragments.
//!
//! Note:
//! - This engine differs from the other three in one way that decides the whole design. An HTTP/3
//!   response body OUTLIVES the handler: a body too large for one packet is parked in a send-stream
//!   slot and read again for every packet, and again for every retransmission after a loss, until
//!   the client acknowledges all of it. So the body cannot be handler memory, and it cannot be a
//!   descriptor the way the TCP engines use one.
//! - It therefore comes from the static cache as mapped bytes, and the cache pin is HELD past the
//!   handler. Context.static_slot carries it out to the engine, which releases it when the stream
//!   retires or as soon as a single-packet response has been copied out.
//! - Because the body must come from the cache, static serving here needs public_dir_cache_ttl_ms
//!   above 0. With caching off there is no safe body to serve, so the router falls through to 404.
//! - Range (RFC 7233) is not served: HTTP/3 static lands full-body only in this pass.

const std = @import("std");
const core = @import("core.zig");
const Request = core.Request;
const Response = core.Response;
const Context = core.Context;
const ContentEncoding = core.ContentEncoding;
const static_cache = @import("../../utils/static_cache.zig");
const response_cache = @import("../../utils/response_cache.zig");

// --------------------------------------------------------- //

/// Translate the cache's coding to the one this engine emits as a QPACK indexed field line.
///
/// Note:
/// - Deflate has no sibling file convention on disk and the cache never selects it, so it maps to
///   identity rather than claiming a coding the response path cannot emit.
fn contentEncodingFor(encoding: static_cache.Encoding) ContentEncoding {
    return switch (encoding) {
        .IDENTITY, .DEFLATE => .identity,
        .GZIP => .gzip,
        .BR => .br,
    };
}

/// Serve a static file from the public directory.
///
/// Rejects paths containing ".." to prevent directory traversal. Responds 200 with the whole file.
///
/// Note:
/// - On success the cache pin is still held, recorded on ctx.static_slot. The engine owns releasing
///   it. Nothing else may release it, since the bytes are still being sent.
///
/// Param:
/// req - *const Request (read for Accept-Encoding)
/// res - *Response (body and headers are set here, the engine frames them)
/// ctx - *Context (io, the configured public_dir, and the static_slot handed back out)
/// req_path - []const u8 (request path with the leading slash already stripped)
///
/// Return:
/// - true if the file was found and the response was filled in
/// - false if the file is not found, the path is invalid, or caching is off (caller sends 404)
pub fn serve(req: *const Request, res: *Response, ctx: *Context, req_path: []const u8) bool {
    const cache = static_cache.instance() orelse return false;

    const accept: ?[]const u8 = if (req.accept_encoding.len > 0) req.accept_encoding else null;
    const hit = cache.acquireMapped(ctx.io, ctx.public_dir, req_path, accept, static_cache.ttlMs(), response_cache.nowMillis()) orelse return false;
    const bytes = hit.bytes orelse {
        cache.release(hit);

        return false;
    };

    res.content_type = hit.content_type;
    res.setContentEncoding(contentEncodingFor(hit.encoding));
    res.send(bytes);

    // The pin stays held: these bytes have to survive every packet and every retransmission of this
    // response. The engine releases the slot once the stream is done with them.
    ctx.static_slot = hit.slot;

    return true;
}

/// Release a pin the static path handed out, once the engine is finished sending those bytes.
///
/// Note:
/// - Safe to call with null, so the engine's completion paths do not each need a guard.
/// - Releasing early would let the entry be reclaimed and its mapping torn down while the pump is
///   still reading it, so this belongs only at a point where the response is provably done.
pub fn releasePin(slot: ?u32) void {
    const pinned = slot orelse return;
    const cache = static_cache.instance() orelse return;

    cache.releaseSlot(pinned);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Build the Context the engine hands a handler, over a public_dir under the test cache directory.
fn testContext(public_dir: []const u8) Context {
    return .{
        .stream_id = 0,
        .io = testing.io,
        .allocator = testing.allocator,
        .public_dir = public_dir,
    };
}

fn writeFixture(dir: std.Io.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(testing.io, .{ .sub_path = name, .data = data }) catch @panic("fixture write failed");
}

test "zix http3: static contentEncodingFor maps only what the response path can emit" {
    try testing.expectEqual(ContentEncoding.identity, contentEncodingFor(.IDENTITY));
    try testing.expectEqual(ContentEncoding.gzip, contentEncodingFor(.GZIP));
    try testing.expectEqual(ContentEncoding.br, contentEncodingFor(.BR));

    // No .deflate sibling convention exists, so it must not claim a coding.
    try testing.expectEqual(ContentEncoding.identity, contentEncodingFor(.DEFLATE));
}

test "zix http3: static serve declines when caching is off" {
    // With no cache there is no body that outlives the handler, so this engine must not serve.
    try testing.expect(static_cache.instance() == null);

    var res = Response{};
    var ctx = testContext("./public");
    const req = Request{ .method = "GET", .path = "/anything.txt", .accept_encoding = "" };

    try testing.expect(!serve(&req, &res, &ctx, "anything.txt"));
    try testing.expect(!res.sent);
    try testing.expect(ctx.static_slot == null);
}

test "zix http3: static serve fills the response from mapped bytes and keeps the pin" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "page.html", "<h1>h3 static</h1>");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/page.html", .accept_encoding = "" };

    try testing.expect(serve(&req, &res, &ctx, "page.html"));
    try testing.expect(res.sent);
    try testing.expectEqualStrings("<h1>h3 static</h1>", res.body);
    try testing.expectEqualStrings("text/html", res.content_type);
    try testing.expectEqual(ContentEncoding.identity, res.content_encoding);

    // The pin is still held, which is the whole point: the body has to outlive this call.
    try testing.expect(ctx.static_slot != null);

    releasePin(ctx.static_slot);
}

test "zix http3: static serve body stays readable after the handler frame is gone" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Longer than one packet, so this is the shape that gets parked in a send-stream slot.
    var payload: [8192]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    writeFixture(tmp.dir, "big.bin", &payload);

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var res = Response{};
    var slot: ?u32 = null;

    // The Context lives and dies inside this block, exactly like the engine's per-call one.
    {
        var ctx = testContext(root);
        const req = Request{ .method = "GET", .path = "/big.bin", .accept_encoding = "" };

        try testing.expect(serve(&req, &res, &ctx, "big.bin"));
        slot = ctx.static_slot;
    }

    // Read every byte back after the handler's frame is gone, the way the pump does per packet.
    try testing.expectEqual(@as(usize, payload.len), res.body.len);
    try testing.expectEqualSlices(u8, &payload, res.body);

    releasePin(slot);
}

test "zix http3: static serve picks a precompressed sibling and names its coding" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "the plain bundle");
    writeFixture(tmp.dir, "app.js.br", "squeezed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/app.js", .accept_encoding = "br, gzip" };

    try testing.expect(serve(&req, &res, &ctx, "app.js"));
    try testing.expectEqualStrings("squeezed", res.body);
    try testing.expectEqual(ContentEncoding.br, res.content_encoding);
    // The type comes from the identity name, not the .br suffix.
    try testing.expectEqualStrings("application/javascript", res.content_type);

    releasePin(ctx.static_slot);
}

test "zix http3: static serve rejects traversal and a missing file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/x", .accept_encoding = "" };

    try testing.expect(!serve(&req, &res, &ctx, "../etc/passwd"));
    try testing.expect(!serve(&req, &res, &ctx, "absent.txt"));
    try testing.expect(!res.sent);
    try testing.expect(ctx.static_slot == null);
}

test "zix http3: static serve holds exactly one pin and releasePin returns it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "counted.txt", "pin accounting");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    const cache = static_cache.instance().?;

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/counted.txt", .accept_encoding = "" };

    try testing.expect(serve(&req, &res, &ctx, "counted.txt"));

    const slot = ctx.static_slot.?;
    try testing.expectEqual(@as(u32, 1), cache.pinCount(slot));

    releasePin(ctx.static_slot);
    try testing.expectEqual(@as(u32, 0), cache.pinCount(slot));
}

test "zix http3: static a released pin lets the entry be reclaimed and re-resolved" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "stale.txt", "first");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    const cache = static_cache.instance().?;

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/stale.txt", .accept_encoding = "" };

    try testing.expect(serve(&req, &res, &ctx, "stale.txt"));
    const slot = ctx.static_slot.?;
    releasePin(ctx.static_slot);
    try testing.expectEqual(@as(u32, 0), cache.pinCount(slot));

    // Expiry is driven through the cache directly, since `serve` reads a coarse monotonic clock
    // that cannot resolve a window short enough to cross inside one test.
    writeFixture(tmp.dir, "stale.txt", "second-and-longer");

    // Same clock the insert stamped with, pushed past the window, so the comparison is meaningful.
    const past_window = response_cache.nowMillis() + 10_000;
    const refreshed = cache.acquireMapped(testing.io, root, "stale.txt", null, 1000, past_window).?;
    defer cache.release(refreshed);

    // A leaked pin would have blocked the reclaim, so the new bytes are the proof it came back.
    try testing.expectEqualStrings("second-and-longer", refreshed.bytes.?);
}

test "zix http3: static an in-flight body is immune to the file being rewritten in place" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "inflight.txt", "still sending");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    _ = try static_cache.install(16, 60_000);
    defer static_cache.shutdown(testing.io);

    var res = Response{};
    var ctx = testContext(root);
    const req = Request{ .method = "GET", .path = "/inflight.txt", .accept_encoding = "" };

    try testing.expect(serve(&req, &res, &ctx, "inflight.txt"));
    const held = res.body;

    // Rewritten IN PLACE, the same inode, which is what copying a new build over a served file
    // does. The response is still being sent, so its bytes must not move underneath it. A mapping
    // of the file itself would show the new content here.
    writeFixture(tmp.dir, "inflight.txt", "replaced on disk");

    try testing.expectEqualStrings("still sending", held);

    releasePin(ctx.static_slot);
}

test "zix http3: static releasePin tolerates null and a shut-down cache" {
    // Both are real engine states: a response that was not static, and teardown ordering.
    releasePin(null);

    try testing.expect(static_cache.instance() == null);
    releasePin(0);
}
