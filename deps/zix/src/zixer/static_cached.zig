//! zixer static cached: take a public_dir file from the shared zix static cache
//!
//! zixer does not keep a table of its own. `zix.utils.static_cache` already holds
//! one per process, shared by every worker, so a file costs one descriptor for
//! the daemon rather than one per accept loop. On a `workers: 0` box that is the
//! difference between one descriptor and one per thread for the same file.
//!
//! What this file owns is zixer's whole relationship to that table: installing
//! it, turning a request target into a pinned entry, and handing the pin back.
//! Serving the bytes belongs to each edge, because an http1 body, an http2 DATA
//! frame, and an http3 stream do not leave the process the same way.
//!
//! A miss is never an error. Every lookup that cannot be answered returns null
//! and the caller falls back to `static_files.open`, which is also what produces
//! the 404 for a file that is not there.

const std = @import("std");

const zix = @import("zix");

const static_files = @import("static_files.zig");

const cache = zix.utils.static_cache;

/// Entry count when the daemon names none. One entry holds a file and its two
/// precompressed siblings, so this is files, not descriptors.
pub const DEFAULT_MAX_ENTRIES: u32 = 256;

/// Freshness window when nothing sets one. Zero keeps caching off, which is the
/// default the zix engines carry and the one a fresh main.cfg inherits.
pub const DEFAULT_TTL_MS: u32 = 0;

/// Longest window a cfg may ask for, one hour. Past this a stale entry outlives
/// any plausible deploy, and the file it holds open is one nobody can replace.
pub const MAX_TTL_MS: u32 = 60 * 60 * 1000;

/// Largest entry count a cfg may ask for. The table clamps against the process
/// descriptor budget anyway, so this only stops a typo from asking for millions.
pub const MAX_ENTRIES: u32 = 1 << 20;

/// Name served when a request path ends at a directory.
const INDEX_NAME = "index.html";

/// A pinned entry plus the site it came from. Hand it back with release.
pub const Hit = cache.Hit;

// --------------------------------------------------------- //

/// True when this freshness window is one a cfg may set.
pub fn ttlInRange(ttl_ms: u32) bool {
    return ttl_ms <= MAX_TTL_MS;
}

/// True when this entry count is one a cfg may set.
pub fn maxEntriesInRange(entries: u32) bool {
    return entries >= 1 and entries <= MAX_ENTRIES;
}

/// Freshness window for one site: its own value when it names one, the daemon
/// default otherwise. Mirrors how max_recv_buf resolves.
///
/// Param:
/// site_ttl_ms - ?u32 (site override, null when the file does not name one)
/// daemon_ttl_ms - u32 (main.cfg value)
///
/// Return:
/// - u32 (0 means this site serves every static request uncached)
pub fn resolveTtl(site_ttl_ms: ?u32, daemon_ttl_ms: u32) u32 {
    const chosen = site_ttl_ms orelse daemon_ttl_ms;

    return if (ttlInRange(chosen)) chosen else DEFAULT_TTL_MS;
}

/// Build the shared table if this process has none yet.
///
/// Note:
/// - Safe to call from every site that wants caching. The table is process-wide
///   and the first call fixes its size, which is the intent: two tables would
///   double the descriptor cost for the same files.
/// - A later site asking for a different freshness window reports MISMATCHED and
///   is ignored on purpose. zixer passes each site's own window to every lookup,
///   so the value recorded at install is never read back.
/// - A failure to map leaves no table, and every site then serves uncached.
///
/// Param:
/// ttl_ms - u32 (resolved window of the site asking, 0 installs nothing)
/// max_entries - u32 (daemon-wide entry count, only the first call is honoured)
pub fn install(ttl_ms: u32, max_entries: u32) void {
    if (ttl_ms == 0) return;

    _ = cache.install(max_entries, ttl_ms) catch return;
}

/// Close every cached file and drop the table. Call once the daemon has stopped
/// every site, never while one is still serving.
pub fn shutdown(io: std.Io) void {
    cache.shutdown(io);
}

/// Take a pinned entry for this request, negotiating the precompressed siblings
/// from the table rather than probing the disk.
///
/// Note:
/// - The caller MUST release the returned hit once the response is on the wire,
///   otherwise the entry can never expire.
/// - A null result means serve this request through `static_files.open`. It is
///   the answer for a window of 0, a path the cache will not store, a file that
///   is not readable, and a table with no room left.
///
/// Param:
/// io - std.Io
/// public_dir - []const u8 (static root from the site cfg)
/// target - []const u8 (raw request target, query allowed)
/// accept_encoding - ?[]const u8 (raw header value, null when absent)
/// ttl_ms - u32 (this site's resolved window)
///
/// Return:
/// - Hit (pinned, caller releases)
/// - null when this request is not answerable from the table
pub fn acquire(io: std.Io, public_dir: []const u8, target: []const u8, accept_encoding: ?[]const u8, ttl_ms: u32) ?Hit {
    if (ttl_ms == 0) return null;

    const table = cache.instance() orelse return null;

    var path_buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;
    const req_path = cachePath(&path_buf, target) orelse return null;

    return table.acquire(io, public_dir, req_path, accept_encoding, ttl_ms, zix.utils.response_cache.nowMillis());
}

/// Like acquire, but the entry also carries stable bytes.
///
/// Note:
/// - For an edge whose response outlives the call that built it. zixer's http2
///   edge coalesces its frames, which rules out handing the descriptor to
///   sendfile, and its http3 edge re-reads a body for every retransmission.
/// - Falls back to a plain hit when the file is too large to snapshot, so a big
///   file keeps its open descriptor instead of dropping to the uncached path.
///
/// Return:
/// - Hit with bytes set, or a plain Hit when the file cannot be snapshotted
/// - null on the same terms as acquire
pub fn acquireResident(io: std.Io, public_dir: []const u8, target: []const u8, accept_encoding: ?[]const u8, ttl_ms: u32) ?Hit {
    if (ttl_ms == 0) return null;

    const table = cache.instance() orelse return null;

    var path_buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;
    const req_path = cachePath(&path_buf, target) orelse return null;
    const now = zix.utils.response_cache.nowMillis();

    if (table.acquireMapped(io, public_dir, req_path, accept_encoding, ttl_ms, now)) |resident| return resident;

    return table.acquire(io, public_dir, req_path, accept_encoding, ttl_ms, now);
}

/// Hand a pin back. A hit that is never released holds its entry forever.
pub fn release(hit: Hit) void {
    const table = cache.instance() orelse return;

    table.release(hit);
}

/// Hand back a pin held by slot index, for an edge that outlived the Hit.
pub fn releaseSlot(slot: u32) void {
    const table = cache.instance() orelse return;

    table.releaseSlot(slot);
}

/// Turn a request target into the relative path the table stores.
///
/// The table wants the path with no leading slash and refuses an empty one, and
/// it does not map a directory to its index file. Both are this adapter's job,
/// so a cached lookup and `static_files.open` answer the same request the same
/// way.
///
/// Return:
/// - []const u8 (relative path inside buf)
/// - null when the target is not one a static file can answer
fn cachePath(buf: []u8, target: []const u8) ?[]const u8 {
    const path = static_files.requestPath(target);
    if (path.len == 0 or path[0] != '/') return null;
    if (std.mem.indexOf(u8, path, "..") != null) return null;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return null;

    const relative = path[1..];
    const index_tail: []const u8 = if (relative.len == 0 or relative[relative.len - 1] == '/') INDEX_NAME else "";
    const total = relative.len + index_tail.len;
    if (total == 0 or total > buf.len) return null;

    @memcpy(buf[0..relative.len], relative);
    @memcpy(buf[relative.len..][0..index_tail.len], index_tail);

    return buf[0..total];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Write one fixture file, panicking on failure since a fixture that cannot be
/// written is a broken test rather than a tested condition.
fn writeFixture(dir: std.Io.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(testing.io, .{ .sub_path = name, .data = data }) catch @panic("fixture write failed");
}

/// The tmp dir path relative to the test cwd, printed into buf.
fn fixtureRoot(buf: []u8, tmp: *const testing.TmpDir) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;
}

test "zix zixer: static cached, ttl resolves the site over the daemon" {
    try testing.expectEqual(@as(u32, 5000), resolveTtl(5000, 1000));
    try testing.expectEqual(@as(u32, 1000), resolveTtl(null, 1000));
    try testing.expectEqual(@as(u32, 0), resolveTtl(0, 1000));
    try testing.expectEqual(@as(u32, 0), resolveTtl(null, 0));

    // Out of range falls to off rather than to the daemon value, so a cfg that
    // slipped past validation cannot silently serve stale files for a week.
    try testing.expectEqual(@as(u32, 0), resolveTtl(MAX_TTL_MS + 1, 1000));
}

test "zix zixer: static cached, range checks bound both keys" {
    try testing.expect(ttlInRange(0));
    try testing.expect(ttlInRange(MAX_TTL_MS));
    try testing.expect(!ttlInRange(MAX_TTL_MS + 1));

    try testing.expect(!maxEntriesInRange(0));
    try testing.expect(maxEntriesInRange(1));
    try testing.expect(maxEntriesInRange(MAX_ENTRIES));
    try testing.expect(!maxEntriesInRange(MAX_ENTRIES + 1));
}

test "zix zixer: static cached, cache path strips the slash and maps a directory" {
    var buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;

    try testing.expectEqualStrings("app.js", cachePath(&buf, "/app.js").?);
    try testing.expectEqualStrings("app.js", cachePath(&buf, "/app.js?v=3").?);
    try testing.expectEqualStrings("assets/app.js", cachePath(&buf, "/assets/app.js").?);

    try testing.expectEqualStrings(INDEX_NAME, cachePath(&buf, "/").?);
    try testing.expectEqualStrings("docs/" ++ INDEX_NAME, cachePath(&buf, "/docs/").?);
    try testing.expectEqualStrings(INDEX_NAME, cachePath(&buf, "/?page=2").?);
}

test "zix zixer: static cached, cache path refuses what a static server must not open" {
    var buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;

    try testing.expect(cachePath(&buf, "") == null);
    try testing.expect(cachePath(&buf, "app.js") == null);
    try testing.expect(cachePath(&buf, "/../etc/passwd") == null);
    try testing.expect(cachePath(&buf, "/a/../b") == null);
    try testing.expect(cachePath(&buf, "/a\x00.txt") == null);

    var long: [static_files.PUBLIC_PATH_MAX + 2]u8 = @splat('a');
    long[0] = '/';
    try testing.expect(cachePath(&buf, &long) == null);
}

test "zix zixer: static cached, a window of zero never touches the table" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "console.log(1)\n");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(0, DEFAULT_MAX_ENTRIES);
    defer shutdown(testing.io);

    try testing.expect(cache.instance() == null);
    try testing.expect(acquire(testing.io, root, "/app.js", null, 0) == null);
}

test "zix zixer: static cached, a hit carries the file and its prerendered head" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "console.log('identity')\n");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const hit = acquire(testing.io, root, "/app.js", null, 60_000).?;
    defer release(hit);

    try testing.expectEqual(@as(u64, "console.log('identity')\n".len), hit.size);
    try testing.expectEqualStrings("application/javascript", hit.content_type);
    try testing.expectEqual(cache.Encoding.IDENTITY, hit.encoding);
    try testing.expect(std.mem.startsWith(u8, hit.header, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, hit.header, "Vary: Accept-Encoding\r\n") != null);
}

test "zix zixer: static cached, siblings are negotiated without probing disk" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "plain-body-bytes");
    writeFixture(tmp.dir, "app.js.br", "br-body");
    writeFixture(tmp.dir, "app.js.gz", "gz-body-x");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const brotli = acquire(testing.io, root, "/app.js", "br, gzip", 60_000).?;
    try testing.expectEqual(cache.Encoding.BR, brotli.encoding);
    try testing.expectEqual(@as(u64, "br-body".len), brotli.size);
    release(brotli);

    const gzip = acquire(testing.io, root, "/app.js", "gzip", 60_000).?;
    try testing.expectEqual(cache.Encoding.GZIP, gzip.encoding);
    try testing.expectEqual(@as(u64, "gz-body-x".len), gzip.size);
    release(gzip);

    // The same entry answers all three, so identity is a table read too.
    const plain = acquire(testing.io, root, "/app.js", null, 60_000).?;
    try testing.expectEqual(cache.Encoding.IDENTITY, plain.encoding);
    try testing.expectEqual(@as(u64, "plain-body-bytes".len), plain.size);
    release(plain);
}

test "zix zixer: static cached, a trailing slash reaches index.html" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, INDEX_NAME, "<h1>home</h1>");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const hit = acquire(testing.io, root, "/", null, 60_000).?;
    defer release(hit);

    try testing.expectEqual(@as(u64, "<h1>home</h1>".len), hit.size);
    try testing.expectEqualStrings("text/html", hit.content_type);
}

test "zix zixer: static cached, a missing file leaves the caller its own fallback" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    try testing.expect(acquire(testing.io, root, "/absent.txt", null, 60_000) == null);
}

test "zix zixer: static cached, a resident hit carries stable bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "theme.css", "body{color:#000}");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const hit = acquireResident(testing.io, root, "/theme.css", null, 60_000).?;
    defer release(hit);

    try testing.expectEqualStrings("body{color:#000}", hit.bytes.?);
    try testing.expectEqual(@as(u64, "body{color:#000}".len), hit.size);
}

test "zix zixer: static cached, release returns the entry to reclaimable" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "reset.css", "*{margin:0}");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const hit = acquire(testing.io, root, "/reset.css", null, 60_000).?;
    const table = cache.instance().?;
    try testing.expectEqual(@as(u32, 1), table.pinCount(hit.slot));

    release(hit);
    try testing.expectEqual(@as(u32, 0), table.pinCount(hit.slot));
}

test "zix zixer: static cached, a second install keeps the first table" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "logo.svg", "<svg/>");

    var root_buf: [64]u8 = undefined;
    const root = fixtureRoot(&root_buf, &tmp);

    install(60_000, 16);
    defer shutdown(testing.io);

    const first = cache.instance().?;

    // A second site with its own window must not build a second table, and its
    // own window still applies because it travels with the lookup.
    install(1_000, 64);
    try testing.expectEqual(first, cache.instance().?);

    const hit = acquire(testing.io, root, "/logo.svg", null, 1_000).?;
    defer release(hit);

    try testing.expectEqual(@as(u64, "<svg/>".len), hit.size);
}
