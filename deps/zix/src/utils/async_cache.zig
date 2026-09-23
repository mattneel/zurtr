//! The response cache for the .ASYNC dispatch model, one per io pool thread.
//!
//! What:
//!   The multiplexed models build one cache per worker, because a worker owns its connections
//!   for its whole life. .ASYNC has no worker: io.async hands each connection to whichever pool
//!   thread is free. A cache built per connection would die before it ever hit, and a single
//!   shared cache would need a lock on the response path. So the cache is threadlocal, built on
//!   the first connection a pool thread serves and reused by every later one.
//!
//! Note:
//! - A threadlocal has no destructor, and a ResponseCache owns an arena plus an mmap slab. Every
//!   cache is therefore recorded in a registry when it is built, so the server can reclaim them
//!   all when its accept loop ends. Without that the mappings would live until process exit.
//! - Memory scales with pool threads, not connections, so it is bounded by the io pool size.
//! - The multiplexed .EPOLL and .URING paths do not use any of this. They keep building their
//!   own per-worker cache exactly as before, so their hot path is untouched.

const std = @import("std");

const response_cache = @import("response_cache.zig");

pub const ResponseCache = response_cache.ResponseCache;
pub const Config = response_cache.Config;

// --------------------------------------------------------- //

/// One pool thread's cache, plus the flag that stops a failed build retrying on every connection.
threadlocal var tl_cache: ?ResponseCache = null;
threadlocal var tl_tried: bool = false;

/// Every cache built so far, so reclaim() can free them from another thread.
var registry: Registry = .{};

/// Registry of live per-thread caches. A spinlock rather than a mutex: it is taken once per pool
/// thread at build time and once at shutdown, never on the response path.
const Registry = struct {
    lock: std.atomic.Value(bool) = .init(false),
    items: std.ArrayListUnmanaged(*ResponseCache) = .empty,

    fn acquire(self: *Registry) void {
        while (self.lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn release(self: *Registry) void {
        self.lock.store(false, .release);
    }
};

/// Slot count that honors a memory ceiling, mirroring the per-worker sizing the multiplexed
/// models use so both models land on the same footprint for the same config.
///
/// Param:
/// max_entries - u32 (requested slot count)
/// max_value_bytes - usize (per-slot byte cap)
/// max_total_bytes - usize (0 disables the ceiling)
///
/// Return:
/// - u32, never zero
pub fn effectiveEntries(max_entries: u32, max_value_bytes: usize, max_total_bytes: usize) u32 {
    if (max_total_bytes == 0) return max_entries;

    const value_bytes: usize = @max(1, max_value_bytes);
    const fit = max_total_bytes / value_bytes;
    const capped = @min(@as(usize, max_entries), fit);

    return @intCast(@max(@as(usize, 1), capped));
}

/// This pool thread's cache, building it on first use.
///
/// Note:
/// - A build failure is remembered, so a thread that cannot map its slab falls back to serving
///   uncached rather than retrying the allocation on every connection.
///
/// Param:
/// config - Config (slot count and per-slot byte cap)
///
/// Return:
/// - *ResponseCache for this thread
/// - null when the cache could not be built, meaning serve uncached
pub fn forThisThread(config: Config) ?*ResponseCache {
    if (tl_cache) |*cache| return cache;

    if (tl_tried) return null;

    tl_tried = true;

    tl_cache = ResponseCache.init(std.heap.smp_allocator, config) catch return null;

    registry.acquire();
    defer registry.release();

    registry.items.append(std.heap.smp_allocator, &tl_cache.?) catch {};

    return &tl_cache.?;
}

/// Free every per-thread cache built so far. Call this when the accept loop ends.
///
/// Note:
/// - Safe to call from a thread that never built a cache of its own, and safe to call twice.
///
/// Return:
/// - usize, how many caches were reclaimed
pub fn reclaim() usize {
    registry.acquire();
    defer registry.release();

    const freed = registry.items.items.len;
    for (registry.items.items) |cache| cache.deinit();
    registry.items.clearAndFree(std.heap.smp_allocator);

    return freed;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: async_cache effectiveEntries honors the memory ceiling and never returns zero" {
    // no ceiling leaves the requested count alone
    try std.testing.expectEqual(@as(u32, 1024), effectiveEntries(1024, 16 * 1024, 0));

    // a ceiling that fits fewer slots than requested caps the count
    try std.testing.expectEqual(@as(u32, 16), effectiveEntries(1024, 16 * 1024, 256 * 1024));

    // a ceiling too small for even one slot still yields one, never zero
    try std.testing.expectEqual(@as(u32, 1), effectiveEntries(1024, 16 * 1024, 1));
}

test "zix utils: async_cache forThisThread reuses one cache per thread and reclaim frees them all" {
    const config = Config{ .max_entries = 8, .max_value_bytes = 1024 };

    const first = forThisThread(config) orelse return error.ZixCacheBuildFailed;
    const second = forThisThread(config) orelse return error.ZixCacheBuildFailed;

    // the same thread must get the same cache back, else it would never hit
    try std.testing.expectEqual(first, second);

    try std.testing.expectEqual(@as(usize, 1), reclaim());

    // the threadlocal still points at freed memory, so clear it before any later test runs
    tl_cache = null;
    tl_tried = false;

    // reclaim is idempotent
    try std.testing.expectEqual(@as(usize, 0), reclaim());
}

test "zix utils: async_cache builds one cache per thread, not one per call" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Probe = struct {
        fn touch(seen: *std.atomic.Value(usize)) void {
            const config = Config{ .max_entries = 4, .max_value_bytes = 512 };
            if (forThisThread(config) != null) _ = seen.fetchAdd(1, .acq_rel);
        }
    };

    var seen: std.atomic.Value(usize) = .init(0);

    var futures: [64]std.Io.Future(void) = undefined;
    for (&futures) |*fut| fut.* = io.async(Probe.touch, .{&seen});
    for (&futures) |*fut| fut.await(io);

    // every call got a cache
    try std.testing.expectEqual(@as(usize, 64), seen.load(.acquire));

    // but far fewer were built: one per pool thread, not one per call
    const built = reclaim();
    try std.testing.expect(built >= 1);
    try std.testing.expect(built < 64);

    tl_cache = null;
    tl_tried = false;
}
