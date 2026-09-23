//! zix response cache: per-worker, per-key precomputed response slab.
//!
//! A handler builds a full response once, stores it under a key derived from
//! the request, and on later matching requests the engine writes the cached
//! bytes directly with no re-serialization. The structure is data oriented
//! (structure of arrays plus one flat payload slab) and lock-free by ownership:
//! one instance per worker, never shared. Shared by the Http1, Http and gRPC
//! engines. See ADR-036.

const std = @import("std");
const builtin = @import("builtin");
const slab_mem = @import("../multiplexers/slab.zig");
const win_io = @import("windows_io.zig");

/// Granularity of a slot's slab region. Values pack at this rounding, so the
/// hot entries of a worker sit within a few pages of each other instead of one
/// full per-slot stride apart.
const REGION_ALIGN: usize = 64;

/// Slab prefix made resident at init, so the hot region's residency (and its
/// page placement) is a startup property instead of first-store faults.
const PRETOUCH_BYTES: usize = 64 * 1024;

/// Per-slot bookkeeping, kept separate from the payload bytes so the hot
/// metadata stays dense and the cold payload lives in the slab.
pub const Meta = struct {
    insert_tick_ms: u64,
    len: u32,
    ttl_ms: u32,
    /// Slab byte offset of this slot's value region.
    off: u32,
    /// Capacity of the region at off. A restore whose bytes fit reuses the
    /// region in place, a larger value draws a fresh region from the cursor.
    cap: u32,
};

/// Geometry for one cache instance.
///
/// Note:
/// - max_entries is rounded down to a power of two in init, so the slot index
///   is a mask rather than a modulo. A value of 0 yields a single slot.
pub const Config = struct {
    max_entries: u32,
    max_value_bytes: u32,
};

/// Per-worker response cache. Not thread-safe by design: one instance per
/// worker, never shared, so no lock is needed.
pub const ResponseCache = struct {
    keys: []u64,
    meta: []Meta,
    slab: []u8,
    /// Per-slot pin counts for the zero-copy replay path: while a slot is
    /// pinned its value region backs an in-flight send, so store and
    /// expiry-reuse leave the slot untouched (the bytes must stay stable).
    pins: []u32,
    /// Bump cursor for value regions: values pack from the slab base in
    /// first-store order (REGION_ALIGN rounded), so the hot entries share a
    /// few pages instead of spreading one value_bytes stride apart.
    cursor: usize,
    value_bytes: usize,
    mask: usize,
    arena: std.heap.ArenaAllocator,
    /// Most recent lookup hit, recorded so the engine can resolve the returned
    /// slice back to its slot for the zero-copy replay pin (see hitSlot).
    last_hit: ?[]const u8 = null,
    last_hit_slot: u32 = 0,

    /// Allocate the keys and meta from one arena and the payload slab from its
    /// own anonymous mapping (kernel-zeroed, demand-paged), so the slab's
    /// placement never depends on allocator history and untouched capacity
    /// costs no physical memory.
    ///
    /// Note:
    /// - max_entries is rounded down to a power of two, so the configured entry
    ///   count is an upper bound and the slab never exceeds
    ///   max_entries * max_value_bytes.
    /// - The first PRETOUCH_BYTES of the slab are made resident up front, so
    ///   the hot region is a startup property instead of ramp-time faults.
    ///
    /// Param:
    /// backing - std.mem.Allocator (owns the arena's backing memory)
    /// config - Config (slot count and per-slot byte cap)
    ///
    /// Return:
    /// - !ResponseCache
    pub fn init(backing: std.mem.Allocator, config: Config) !ResponseCache {
        const entries: usize = std.math.floorPowerOfTwo(u32, @max(1, config.max_entries));
        const value_bytes: usize = @max(1, config.max_value_bytes);

        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        const keys = try allocator.alloc(u64, entries);
        @memset(keys, 0);

        const meta = try allocator.alloc(Meta, entries);
        const pins = try allocator.alloc(u32, entries);
        @memset(pins, 0);

        // THP opted out: under an "always" policy the first store would
        // materialize a whole 2 MiB extent of this compact slab, holding far
        // more resident than the packed values need.
        const slab = try slab_mem.mapZeroedSlots(u8, entries * value_bytes);
        slab_mem.adviseNoHugePages(slab);
        slab_mem.pretouch(slab[0..@min(slab.len, PRETOUCH_BYTES)]);

        return .{
            .keys = keys,
            .meta = meta,
            .pins = pins,
            .slab = slab,
            .cursor = 0,
            .value_bytes = value_bytes,
            .mask = entries - 1,
            .arena = arena,
        };
    }

    /// Unmap the slab and free the keys and meta in one shot.
    pub fn deinit(self: *ResponseCache) void {
        slab_mem.unmapSlots(self.slab);
        self.arena.deinit();
    }

    /// Return the cached bytes for key when present and still fresh.
    /// A miss or an expired entry returns null. now_ms is supplied by the caller
    /// so lookup itself does no clock read on the hot path.
    ///
    /// Note:
    /// - An entry expires exactly at insert_tick_ms + ttl_ms, so a ttl_ms of 0
    ///   is always treated as expired (a per-store way to skip the cache).
    ///
    /// Return:
    /// - ?[]const u8
    pub fn lookup(self: *ResponseCache, key: u64, now_ms: u64) ?[]const u8 {
        var index: usize = @intCast(key & self.mask);
        var probes: usize = 0;
        while (probes <= self.mask) : (probes += 1) {
            const slot_key = self.keys[index];
            if (slot_key == 0) return null;

            if (slot_key == key) {
                const entry = self.meta[index];
                if (now_ms >= entry.insert_tick_ms + entry.ttl_ms) return null;

                const bytes = self.slab[entry.off..][0..entry.len];
                self.last_hit = bytes;
                self.last_hit_slot = @intCast(index);

                return bytes;
            }

            index = (index + 1) & self.mask;
        }

        return null;
    }

    /// Copy bytes into the slot for key, evicting an expired neighbour if the
    /// probe reaches one. Expired slots are reused in place rather than zeroed,
    /// since zeroing would truncate an open-addressing probe chain.
    ///
    /// Note:
    /// - A slot whose existing region already fits the bytes keeps its region
    ///   (steady-state TTL refreshes never move or grow the slab). A first
    ///   store, or a larger value, draws a fresh region from the bump cursor.
    ///   The region a larger value abandons is not reclaimed: the slab bounds
    ///   the total at max_entries * max_value_bytes and a full slab fails the
    ///   store, which callers already treat as uncached.
    ///
    /// Return:
    /// - bool (true when stored, false when bytes exceed the per-slot cap, the
    ///   table is full of live distinct keys, or the slab has no region left)
    pub fn store(self: *ResponseCache, key: u64, bytes: []const u8, ttl_ms: u32, now_ms: u64) bool {
        if (bytes.len > self.value_bytes) return false;

        var index: usize = @intCast(key & self.mask);
        var probes: usize = 0;
        while (probes <= self.mask) : (probes += 1) {
            const slot_key = self.keys[index];
            const expired = slot_key != 0 and now_ms >= self.meta[index].insert_tick_ms + self.meta[index].ttl_ms;

            if (slot_key == 0 or slot_key == key or expired) {
                // A pinned slot backs an in-flight zero-copy send: its bytes
                // must stay stable, so the slot's own key skips this store
                // (the next miss retries) and a reusable neighbour is probed
                // past like an occupied slot.
                if (self.pins[index] != 0) {
                    if (slot_key == key) return false;

                    index = (index + 1) & self.mask;
                    continue;
                }

                var off: usize = self.meta[index].off;
                var cap: usize = if (slot_key == 0) 0 else self.meta[index].cap;
                if (cap < bytes.len) {
                    const need = std.mem.alignForward(usize, bytes.len, REGION_ALIGN);
                    if (self.cursor + need > self.slab.len) return false;

                    off = self.cursor;
                    cap = need;
                    self.cursor += need;
                }

                std.debug.assert(self.pins[index] == 0);
                @memcpy(self.slab[off..][0..bytes.len], bytes);

                self.keys[index] = key;
                self.meta[index] = .{
                    .insert_tick_ms = now_ms,
                    .len = @intCast(bytes.len),
                    .ttl_ms = ttl_ms,
                    .off = @intCast(off),
                    .cap = @intCast(cap),
                };

                return true;
            }

            index = (index + 1) & self.mask;
        }

        return false;
    }

    /// Resolve a slice returned by lookup back to its slot for the zero-copy
    /// replay pin. Only the exact slice of the most recent hit resolves, so a
    /// caller that rewrote or re-sliced the bytes falls back to the copy path.
    ///
    /// Return:
    /// - ?u32 (the slot, or null when bytes is not the last hit's slice)
    pub fn hitSlot(self: *const ResponseCache, bytes: []const u8) ?u32 {
        const hit = self.last_hit orelse return null;
        if (hit.ptr != bytes.ptr or hit.len != bytes.len) return null;

        return self.last_hit_slot;
    }

    /// Pin slot's value region while an in-flight send references it. Balanced
    /// by unpin from the send completion (or the connection teardown).
    pub fn pin(self: *ResponseCache, slot: u32) void {
        self.pins[slot] += 1;
    }

    pub fn unpin(self: *ResponseCache, slot: u32) void {
        std.debug.assert(self.pins[slot] > 0);
        self.pins[slot] -= 1;
    }
};

/// Hash the cache key parts into a non-zero u64 (0 is the empty sentinel). The
/// query is part of the key, so two requests on the same path with different
/// query strings hash to distinct entries.
pub fn hashKey(method: []const u8, path: []const u8, query: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(method);
    hasher.update(path);
    hasher.update(query);

    const digest = hasher.final();
    return if (digest == 0) 1 else digest;
}

/// Like hashKey, but folds the content-encoding token into the key so the compressed and identity
/// representations of one resource occupy distinct cache slots (the per-(key, encoding) cache). A
/// NUL separator keeps the encoding from colliding across the path / query boundary.
pub fn hashKeyEncoded(method: []const u8, path: []const u8, query: []const u8, encoding: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(method);
    hasher.update(path);
    hasher.update(query);
    hasher.update("\x00");
    hasher.update(encoding);

    const digest = hasher.final();
    return if (digest == 0) 1 else digest;
}

/// Coarse monotonic milliseconds for TTL. CLOCK_MONOTONIC_COARSE is served from
/// the vDSO without a syscall, and millisecond resolution is enough for TTL.
pub fn nowMillis() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC_COARSE, &ts);

        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.monotonicUs() / std.time.us_per_ms;

    // CLOCK_MONOTONIC_COARSE is a Linux-only clock ID: plain MONOTONIC is the portable equivalent.
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);

    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: response cache store then lookup returns identical bytes" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    const key = hashKey("GET", "/cache", "");
    const payload = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    try std.testing.expect(cache.store(key, payload, 1000, 100));
    try std.testing.expectEqualStrings(payload, cache.lookup(key, 200).?);
}

test "zix utils: response cache miss on absent key" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    try std.testing.expect(cache.lookup(hashKey("GET", "/absent", ""), 100) == null);
}

test "zix utils: response cache expired entry returns null then refetches" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    const key = hashKey("GET", "/cache", "");
    try std.testing.expect(cache.store(key, "first", 1000, 100));

    // now is past insert(100) + ttl(1000)
    try std.testing.expect(cache.lookup(key, 1100) == null);

    // store overwrites the same slot, fresh again
    try std.testing.expect(cache.store(key, "second", 1000, 1200));
    try std.testing.expectEqualStrings("second", cache.lookup(key, 1300).?);
}

test "zix utils: response cache oversize value bypasses store" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 8 });
    defer cache.deinit();

    try std.testing.expect(!cache.store(hashKey("GET", "/big", ""), "this is longer than eight", 1000, 100));
}

test "zix utils: response cache ttl 0 means never fresh" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    const key = hashKey("GET", "/cache", "");
    try std.testing.expect(cache.store(key, "x", 0, 100));
    try std.testing.expect(cache.lookup(key, 100) == null);
}

test "zix utils: response cache distinct keys coexist via probing" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 64 });
    defer cache.deinit();

    const key_a = hashKey("GET", "/a", "");
    const key_b = hashKey("GET", "/b", "");
    try std.testing.expect(cache.store(key_a, "alpha", 1000, 100));
    try std.testing.expect(cache.store(key_b, "bravo", 1000, 100));

    try std.testing.expectEqualStrings("alpha", cache.lookup(key_a, 200).?);
    try std.testing.expectEqualStrings("bravo", cache.lookup(key_b, 200).?);
}

test "zix utils: response cache max_entries rounded down to power of two" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 100, .max_value_bytes = 32 });
    defer cache.deinit();

    // 100 floors to 64, mask = 63
    try std.testing.expectEqual(@as(usize, 63), cache.mask);
    try std.testing.expectEqual(@as(usize, 64), cache.keys.len);
}

test "zix utils: response cache values pack compactly in first-store order" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer cache.deinit();

    // Two distinct keys land 64 bytes apart in the slab (region rounding), not
    // one 4 KiB stride apart, so the hot values share pages.
    try std.testing.expect(cache.store(hashKey("GET", "/a", ""), "alpha", 1000, 100));
    try std.testing.expect(cache.store(hashKey("GET", "/b", ""), "bravo", 1000, 100));

    const val_a = cache.lookup(hashKey("GET", "/a", ""), 200).?;
    const val_b = cache.lookup(hashKey("GET", "/b", ""), 200).?;
    try std.testing.expectEqual(@intFromPtr(val_a.ptr) + 64, @intFromPtr(val_b.ptr));
}

test "zix utils: response cache a refresh that fits reuses its region in place" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer cache.deinit();

    const key = hashKey("GET", "/stable", "");
    try std.testing.expect(cache.store(key, "first-value", 1000, 100));
    const first = cache.lookup(key, 200).?;

    // Same key, same-or-smaller value: the region (and the cursor) must not
    // move, so steady-state TTL refreshes never grow the slab.
    const cursor_before = cache.cursor;
    try std.testing.expect(cache.store(key, "second", 1000, 300));
    const second = cache.lookup(key, 400).?;

    try std.testing.expectEqual(@intFromPtr(first.ptr), @intFromPtr(second.ptr));
    try std.testing.expectEqual(cursor_before, cache.cursor);
    try std.testing.expectEqualStrings("second", second);
}

test "zix utils: response cache an exhausted slab fails the store gracefully" {
    // Two slots at a 96-byte cap: 192 slab bytes, so regions of 64 + 128 fill it.
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 2, .max_value_bytes = 96 });
    defer cache.deinit();

    const key_a = hashKey("GET", "/a", "");
    const key_b = hashKey("GET", "/b", "");

    const val_a: [40]u8 = @splat('x');
    const val_b: [90]u8 = @splat('z');
    const val_refresh: [90]u8 = @splat('y');

    try std.testing.expect(cache.store(key_a, &val_a, 1000, 100));
    try std.testing.expect(cache.store(key_b, &val_b, 1000, 100));

    // A larger refresh of key_a needs a fresh 128-byte region and the slab has
    // none left: the store fails, the existing entry stays intact and replayable.
    try std.testing.expect(!cache.store(key_a, &val_refresh, 1000, 200));
    try std.testing.expectEqualStrings(&val_a, cache.lookup(key_a, 300).?);
}

test "zix utils: response cache hitSlot resolves only the exact last-hit slice" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    const key = hashKey("GET", "/pin", "");
    try std.testing.expect(cache.store(key, "payload", 1000, 100));

    // Before any hit nothing resolves.
    try std.testing.expect(cache.hitSlot("payload") == null);

    const bytes = cache.lookup(key, 200).?;
    try std.testing.expect(cache.hitSlot(bytes) != null);

    // A re-sliced or foreign slice does not resolve, so the engine falls back
    // to the copy path instead of pinning the wrong slot.
    try std.testing.expect(cache.hitSlot(bytes[1..]) == null);
    try std.testing.expect(cache.hitSlot("payload") == null);
}

test "zix utils: response cache a pinned slot is never overwritten" {
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    const key = hashKey("GET", "/pin", "");
    try std.testing.expect(cache.store(key, "in-flight bytes", 1000, 100));

    const bytes = cache.lookup(key, 200).?;
    const slot = cache.hitSlot(bytes).?;
    cache.pin(slot);

    // Same key, expired or not: the store is refused while the send is in
    // flight, and the bytes stay stable.
    try std.testing.expect(!cache.store(key, "replacement bytes", 1000, 5000));
    try std.testing.expectEqualStrings("in-flight bytes", bytes);

    // Unpin re-enables the slot for the next miss.
    cache.unpin(slot);
    try std.testing.expect(cache.store(key, "replacement", 1000, 5000));
    try std.testing.expectEqualStrings("replacement", cache.lookup(key, 5100).?);
}

test "zix utils: response cache store probes past a pinned expired neighbour" {
    // Two slots: key_a lands in its home slot, expires, and gets pinned by an
    // in-flight send. A different key that probes onto it must skip to the
    // next slot instead of clobbering the pinned bytes.
    var cache = try ResponseCache.init(std.testing.allocator, .{ .max_entries = 2, .max_value_bytes = 64 });
    defer cache.deinit();

    // Craft keys that share the home slot (same low bit).
    const key_a: u64 = 2;
    const key_b: u64 = 4;
    try std.testing.expect(cache.store(key_a, "aaaa", 100, 100));

    const bytes_a = cache.lookup(key_a, 150).?;
    cache.pin(cache.hitSlot(bytes_a).?);

    // key_a is expired at now=500, so its slot is reusable in principle, but
    // the pin forces key_b past it into the free neighbour.
    try std.testing.expect(cache.store(key_b, "bbbb", 1000, 500));
    try std.testing.expectEqualStrings("aaaa", bytes_a);
    try std.testing.expectEqualStrings("bbbb", cache.lookup(key_b, 600).?);
}

test "zix utils: response cache hashKey separates by query" {
    try std.testing.expect(hashKey("GET", "/p", "a=1") != hashKey("GET", "/p", "a=2"));
    try std.testing.expect(hashKey("GET", "/p", "") != hashKey("POST", "/p", ""));
}

test "zix utils: response cache hashKeyEncoded separates by encoding and from identity" {
    const gz = hashKeyEncoded("GET", "/json", "", "gzip");
    const br = hashKeyEncoded("GET", "/json", "", "br");
    const ident = hashKey("GET", "/json", "");

    try std.testing.expect(gz != br);
    try std.testing.expect(gz != ident);
    try std.testing.expect(hashKeyEncoded("GET", "/json", "", "gzip") == gz); // stable
}
