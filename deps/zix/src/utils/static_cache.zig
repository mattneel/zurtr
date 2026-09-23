//! zix static cache: resolved public_dir files kept open across requests.
//!
//! One table maps a resolved file path to an already-open file, its size, and a
//! prerendered HTTP/1.x 200 header, so a repeat request costs a hash lookup
//! instead of an open plus a stat. Precompressed .br and .gz siblings are
//! resolved once at insert and stored beside the identity file, so per-request
//! encoding negotiation is a table read rather than two speculative opens.
//!
//! The table is shared by every worker instead of living per worker, so a file
//! costs one descriptor for the process rather than one per worker. Reads are
//! lock-free: an insert publishes the slot key and then the live flag with
//! release ordering, and a reader takes a pin with an acquiring compare-and-swap
//! that only succeeds while the slot is live. Insert and reclaim hold a
//! spinlock.
//!
//! The cache never fails a request. A full table, an unreadable file, or a path
//! the caller must reject all return null, and the caller falls back to its own
//! uncached path. See ADR-064.

const std = @import("std");
const builtin = @import("builtin");
const slab_mem = @import("../multiplexers/slab.zig");
const compression = @import("compression/compression.zig");
const file_utils = @import("file.zig");
const content = @import("../tcp/http/content.zig");

// --------------------------------------------------------- //

pub const Encoding = compression.Encoding;

/// Longest path under public_dir (the root, a separator, then the request path)
/// anything static serving touches. It is one number on purpose: a slot stores a
/// path this long, and every caller that buffers a request target sizes that
/// buffer by it, so a path can never resolve on one side and be refused on the
/// other. A longer path is not cacheable and falls back to the uncached path.
///
/// Note:
/// - Raising it costs bytes per LIVE cache entry only. The slot table is
///   demand-paged, so an untouched slot stays out of resident memory.
pub const PUBLIC_PATH_MAX: usize = 512;

/// Prerendered 200 header cap. The longest shape is the status line plus the
/// longest known content type, a 20-digit length, a content encoding, and the
/// four fixed headers, which lands near 231 bytes.
pub const HEADER_MAX: usize = 256;

/// Variants a slot holds: identity plus the two precompressed siblings.
const VARIANT_COUNT: usize = 3;

/// Largest file the cache will snapshot into memory for an engine that needs stable bytes. Only
/// zix.Http3 asks for those, so this bounds what static serving on that engine can hold: at the
/// default entry count, a public_dir of large media would otherwise pull all of it into memory.
/// A file over this is served by the other engines as usual and skipped by zix.Http3.
pub const SNAPSHOT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Slots examined when an insert finds no room. Bounded so no request pays for a
/// full-table scan, which is what keeps the tail latency flat.
const SWEEP_BUDGET: usize = 8;

/// Entry count used when the descriptor limit cannot be read.
const FD_CEILING_FALLBACK: u32 = 256;

/// Share of the descriptor budget the table may hold, since one variant holds
/// one descriptor and the process still needs descriptors for its sockets.
const FD_BUDGET_DIVISOR: u64 = 4;

/// Smallest clamp result, so a hostile-looking limit still leaves a usable table.
const FD_CEILING_MIN: u32 = 32;

/// Slot is published and readable. Cleared by reclaim, which only succeeds while
/// no pin is outstanding.
const STATE_LIVE: u32 = 1 << 31;

/// Outstanding pins occupy the low bits, so live and pins are one atomic word.
const STATE_PIN_MASK: u32 = STATE_LIVE - 1;

/// Precompressed sibling probed at insert, in server preference order.
const Sibling = struct {
    encoding: Encoding,
    suffix: []const u8,
};

const SIBLINGS = [_]Sibling{
    .{ .encoding = .BR, .suffix = ".br" },
    .{ .encoding = .GZIP, .suffix = ".gz" },
};

// --------------------------------------------------------- //

/// One servable representation of a cached file: the open file, its size, and
/// the header bytes replayed for a 200 response.
const Variant = struct {
    file: std.Io.File,
    size: u64,
    content_type: []const u8,
    hdr_len: u16,
    hdr_buf: [HEADER_MAX]u8,
    present: bool,
    /// Stable bytes for a caller whose response outlives the handler call, filled on demand by
    /// mapBytes and valid only once `mapped` reads true.
    map_ptr: [*]const u8 = undefined,
    map_len: usize = 0,
    /// Published last with release ordering, so a reader that sees it also sees the two fields
    /// above. A variant is mapped at most once and unmapped only at reclaim, when the slot is
    /// already dead and unpinned, so there is no unmap to race against.
    mapped: std.atomic.Value(bool) = .init(false),
};

/// One cached path. Zeroed memory is a valid empty slot: key 0 stops a probe and
/// state 0 means not live, so an untouched slot is never read as an entry.
const Slot = struct {
    key: u64,
    state: std.atomic.Value(u32),
    insert_tick_ms: u64,
    path_len: u16,
    path_buf: [PUBLIC_PATH_MAX]u8,
    variants: [VARIANT_COUNT]Variant,
};

/// A pinned cache hit. The caller sends it and must return it with release, so
/// reclaim cannot close the file underneath an in-flight response.
///
/// Note:
/// - file is open for reading and shared: read it positionally (readPositionalAll)
///   or hand it to sendfile. Never seek it, the offset is shared process-wide.
pub const Hit = struct {
    /// Index of the pinned slot, needed by release.
    slot: u32,
    file: std.Io.File,
    size: u64,
    /// Prerendered "HTTP/1.1 200 OK" header, ready to write as bytes.
    header: []const u8,
    content_type: []const u8,
    encoding: Encoding,
    /// Stable bytes of the chosen variant, non-null only for a hit taken through acquireMapped.
    /// They stay valid until the matching release, which is what lets an engine whose response
    /// outlives the handler (zix.Http3) point its body straight at them.
    bytes: ?[]const u8 = null,
};

// --------------------------------------------------------- //

/// Read the descriptor budget and return how many entries the table may hold.
/// One entry holds up to VARIANT_COUNT descriptors, so an unclamped configured
/// value could exhaust the process budget before the sockets get any.
///
/// Return:
/// - u32 (entry ceiling, never below FD_CEILING_MIN)
fn descriptorCeiling() u32 {
    if (comptime builtin.os.tag == .windows) return FD_CEILING_FALLBACK;

    const limit = std.posix.getrlimit(.NOFILE) catch return FD_CEILING_FALLBACK;

    // rlim_t is signed on the BSDs and unsigned on Linux, so normalize before dividing.
    if (limit.cur <= 0) return FD_CEILING_FALLBACK;

    const budget = @as(u64, @intCast(limit.cur)) / FD_BUDGET_DIVISOR;

    return @intCast(@max(FD_CEILING_MIN, @min(budget, @as(u64, std.math.maxInt(u32)))));
}

/// Hash a resolved path into a non-zero key, since 0 marks a slot that has never
/// been used and stops a probe.
fn hashPath(path: []const u8) u64 {
    const digest = std.hash.Wyhash.hash(0, path);

    return if (digest == 0) 1 else digest;
}

/// Index of the variant array holding this encoding.
///
/// Note:
/// - DEFLATE has no sibling file convention on disk, so it maps to identity. It
///   is never returned by negotiation here, which only offers present variants.
fn variantIndex(encoding: Encoding) usize {
    return switch (encoding) {
        .IDENTITY, .DEFLATE => 0,
        .GZIP => 1,
        .BR => 2,
    };
}

/// Render the 200 header a variant replays.
///
/// Note:
/// - Vary is emitted for every variant, identity included, so an intermediary
///   cannot serve a compressed body to a client that did not ask for one.
/// - Connection is fixed to keep-alive, matching the uncached path.
///
/// Return:
/// - []u8 (the rendered slice inside buf)
/// - null when the header does not fit, which makes the variant uncacheable
fn renderHeader(buf: []u8, content_type: []const u8, size: u64, encoding: Encoding) ?[]u8 {
    if (encoding.contentEncoding()) |token| {
        return std.fmt.bufPrint(
            buf,
            "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Encoding: {s}\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nConnection: keep-alive\r\n\r\n",
            .{ content_type, size, token },
        ) catch null;
    }

    return std.fmt.bufPrint(
        buf,
        "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nConnection: keep-alive\r\n\r\n",
        .{ content_type, size },
    ) catch null;
}

/// Join public_dir and req_path into buf, rejecting anything a static server
/// must not serve.
///
/// Note:
/// - ".." is rejected outright rather than normalized, matching the uncached path.
///
/// Return:
/// - []const u8 (the joined path inside buf)
/// - null when the path is unsafe or does not fit
fn resolvePath(buf: []u8, public_dir: []const u8, req_path: []const u8) ?[]const u8 {
    if (req_path.len == 0) return null;
    if (std.mem.indexOf(u8, req_path, "..") != null) return null;
    if (req_path[0] == '/') return null;
    if (public_dir.len + 1 + req_path.len > buf.len) return null;

    @memcpy(buf[0..public_dir.len], public_dir);
    buf[public_dir.len] = '/';
    @memcpy(buf[public_dir.len + 1 ..][0..req_path.len], req_path);

    return buf[0 .. public_dir.len + 1 + req_path.len];
}

// --------------------------------------------------------- //

/// Table of resolved static files, shared by every worker of a server.
pub const StaticCache = struct {
    slots: []Slot,
    mask: usize,
    lock: std.atomic.Value(bool),

    /// Allocate the slot table as one demand-paged mapping, so an untouched slot
    /// costs no physical memory and the empty state needs no memset.
    ///
    /// Note:
    /// - max_entries is clamped against the descriptor budget and then rounded
    ///   down to a power of two, so the slot index is a mask rather than a modulo.
    ///
    /// Param:
    /// max_entries - u32 (requested slot count, clamped and rounded down)
    ///
    /// Return:
    /// - !StaticCache
    pub fn init(max_entries: u32) !StaticCache {
        const clamped = @min(@max(1, max_entries), descriptorCeiling());
        const entries: usize = std.math.floorPowerOfTwo(u32, clamped);

        // THP opted out for the same reason as the response cache: a contiguous
        // table under an "always" policy would materialize a whole 2 MiB extent
        // on the first insert, holding far more resident than the live entries.
        const slots = try slab_mem.mapZeroedSlots(Slot, entries);
        slab_mem.adviseNoHugePages(std.mem.sliceAsBytes(slots));

        return .{
            .slots = slots,
            .mask = entries - 1,
            .lock = .init(false),
        };
    }

    /// Close every open file and unmap the table.
    ///
    /// Note:
    /// - Call only after every worker has stopped. A pinned slot means a response
    ///   is still in flight, and its file is closed anyway.
    pub fn deinit(self: *StaticCache, io: std.Io) void {
        for (self.slots) |*slot| {
            if (slot.state.load(.acquire) & STATE_LIVE == 0) continue;

            closeVariants(slot, io);
            slot.state.store(0, .release);
        }

        slab_mem.unmapSlots(self.slots);
    }

    /// Look up the request path, inserting it on a miss, and return a pinned hit.
    ///
    /// Note:
    /// - The returned hit MUST be handed to release once the response is written,
    ///   otherwise its slot is never reclaimable.
    /// - A null result is never an error: the caller serves the file through its
    ///   own uncached path, which also produces the 404 for a missing file.
    ///
    /// Param:
    /// io - std.Io (used for open, stat, and close)
    /// public_dir - []const u8 (static root, joined with req_path)
    /// req_path - []const u8 (request path with the leading slash stripped)
    /// accept_encoding - ?[]const u8 (raw Accept-Encoding value, null when absent)
    /// ttl_ms - u32 (freshness window, supplied per call so two servers can differ)
    /// now_ms - u64 (coarse monotonic clock, from response_cache.nowMillis)
    ///
    /// Return:
    /// - Hit (pinned, caller must release)
    /// - null when the path is unsafe, the file is unreadable, or the table is full
    pub fn acquire(
        self: *StaticCache,
        io: std.Io,
        public_dir: []const u8,
        req_path: []const u8,
        accept_encoding: ?[]const u8,
        ttl_ms: u32,
        now_ms: u64,
    ) ?Hit {
        if (ttl_ms == 0) return null;

        var path_buf: [PUBLIC_PATH_MAX]u8 = undefined;
        const path = resolvePath(&path_buf, public_dir, req_path) orelse return null;
        const key = hashPath(path);

        if (self.lookup(io, key, path, ttl_ms, now_ms)) |pinned| {
            return buildHit(&self.slots[pinned], pinned, accept_encoding);
        }

        const inserted = self.insert(io, key, path, ttl_ms, now_ms) orelse return null;

        return buildHit(&self.slots[inserted], inserted, accept_encoding);
    }

    /// Like acquire, but the hit also carries stable bytes for the chosen variant.
    ///
    /// Note:
    /// - For an engine whose response outlives the handler call. zix.Http3 parks a large body in a
    ///   send-stream slot and reads it again for every packet and every retransmission, long after
    ///   the handler returned, so it cannot point at handler memory.
    /// - The bytes stay valid until release, which is why the pin has to be held for the whole
    ///   response there rather than dropped when the handler returns.
    /// - Mapping happens once per variant and is charged to the first request that needs it.
    ///
    /// Return:
    /// - Hit with bytes set (pinned, caller must release)
    /// - null on the same terms as acquire, plus a mapping that could not be made
    pub fn acquireMapped(
        self: *StaticCache,
        io: std.Io,
        public_dir: []const u8,
        req_path: []const u8,
        accept_encoding: ?[]const u8,
        ttl_ms: u32,
        now_ms: u64,
    ) ?Hit {
        var hit = self.acquire(io, public_dir, req_path, accept_encoding, ttl_ms, now_ms) orelse return null;
        const variant = &self.slots[hit.slot].variants[variantIndex(hit.encoding)];

        if (!variant.mapped.load(.acquire)) {
            while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
            defer self.lock.store(false, .release);

            if (!mapBytes(variant, io)) {
                self.release(hit);

                return null;
            }
        }

        hit.bytes = variant.map_ptr[0..variant.map_len];

        return hit;
    }

    /// Drop the pin taken by acquire, making the slot reclaimable again.
    pub fn release(self: *StaticCache, hit: Hit) void {
        self.releaseSlot(hit.slot);
    }

    /// Drop a pin held by slot index, for a caller that outlived the Hit it came from. zix.Http3
    /// stores the index on its send-stream slot and releases when the stream retires.
    pub fn releaseSlot(self: *StaticCache, slot: u32) void {
        _ = self.slots[slot].state.fetchSub(1, .release);
    }

    /// How many responses are currently holding this slot. A slot that never returns to 0 is a
    /// leaked pin: it can still be served, but it can never expire or be reclaimed.
    pub fn pinCount(self: *StaticCache, slot: u32) u32 {
        return self.slots[slot].state.load(.acquire) & STATE_PIN_MASK;
    }

    /// Probe for a live, fresh slot holding path and pin it.
    ///
    /// Note:
    /// - An expired slot is reclaimed here rather than by a timer, so clean-up
    ///   rides on the traffic that made the entry stale in the first place.
    ///
    /// Return:
    /// - u32 (pinned slot index)
    /// - null on a miss, an expired entry, or a slot being reclaimed
    fn lookup(self: *StaticCache, io: std.Io, key: u64, path: []const u8, ttl_ms: u32, now_ms: u64) ?u32 {
        var index: usize = @intCast(key & self.mask);
        var probes: usize = 0;
        while (probes <= self.mask) : (probes += 1) {
            const slot = &self.slots[index];

            const slot_key = @atomicLoad(u64, &slot.key, .acquire);
            if (slot_key == 0) return null;

            if (slot_key == key) {
                if (!pinSlot(slot)) return null;

                // The key matched before the pin, so re-read what the pin now
                // protects: a slot reused for another path between the two must
                // not be served under this key.
                if (@atomicLoad(u64, &slot.key, .acquire) != key or !std.mem.eql(u8, slot.path_buf[0..slot.path_len], path)) {
                    unpinSlot(slot);
                    return null;
                }

                if (now_ms >= slot.insert_tick_ms + ttl_ms) {
                    unpinSlot(slot);
                    self.reclaimExpired(io, index);

                    return null;
                }

                return @intCast(index);
            }

            index = (index + 1) & self.mask;
        }

        return null;
    }

    /// Open path and its siblings, publish them into a slot, and pin it.
    ///
    /// Note:
    /// - A miss is never cached. A flood of unknown paths therefore costs one
    ///   failed open each and leaves the table untouched, rather than evicting
    ///   the entries that are actually being served.
    ///
    /// Return:
    /// - u32 (pinned slot index)
    /// - null when the file is unreadable or the table has no room
    fn insert(self: *StaticCache, io: std.Io, key: u64, path: []const u8, ttl_ms: u32, now_ms: u64) ?u32 {
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        defer self.lock.store(false, .release);

        // Another worker may have published this path while this one waited for
        // the lock, and a live slot is never rewritten in place: a reader could
        // be holding it, so a stale-but-pinned entry sends this request uncached
        // rather than clobbering an in-flight response.
        if (self.probeLive(key, path)) |live| {
            const slot = &self.slots[live];
            if (now_ms < slot.insert_tick_ms + ttl_ms and pinSlot(slot)) return @intCast(live);

            return null;
        }

        const index = self.findFreeSlot(io, key) orelse return null;
        const slot = &self.slots[index];

        if (!buildVariants(slot, io, path)) return null;

        slot.insert_tick_ms = now_ms;
        slot.path_len = @intCast(path.len);
        @memcpy(slot.path_buf[0..path.len], path);

        // Key first, then the live flag: a reader only reaches the fields after
        // an acquiring pin, which pairs with this release store.
        @atomicStore(u64, &slot.key, key, .release);
        slot.state.store(STATE_LIVE | 1, .release);

        return @intCast(index);
    }

    /// Find a slot this insert may write, sweeping expired entries when the probe
    /// finds none. Caller holds the lock.
    ///
    /// Return:
    /// - usize (slot index, either never used or already reclaimed)
    /// - null when the table is full of live entries
    fn findFreeSlot(self: *StaticCache, io: std.Io, key: u64) ?usize {
        if (self.probeFreeSlot(key)) |index| return index;

        self.sweep(io, key);

        return self.probeFreeSlot(key);
    }

    /// Walk the probe chain for a slot this insert may write: never used, or
    /// already reclaimed. A live slot is skipped even when its key matches, since
    /// rewriting it would pull the file out from under a reader. Caller holds the
    /// lock.
    fn probeFreeSlot(self: *StaticCache, key: u64) ?usize {
        var index: usize = @intCast(key & self.mask);
        var probes: usize = 0;
        while (probes <= self.mask) : (probes += 1) {
            const slot = &self.slots[index];
            if (slot.state.load(.acquire) & STATE_LIVE == 0) return index;

            index = (index + 1) & self.mask;
        }

        return null;
    }

    /// Walk the probe chain for the live slot holding this exact path. Caller
    /// holds the lock.
    ///
    /// Return:
    /// - usize (index of the live slot, freshness not checked)
    /// - null when no live slot holds the path
    fn probeLive(self: *StaticCache, key: u64, path: []const u8) ?usize {
        var index: usize = @intCast(key & self.mask);
        var probes: usize = 0;
        while (probes <= self.mask) : (probes += 1) {
            const slot = &self.slots[index];
            const slot_key = @atomicLoad(u64, &slot.key, .acquire);
            if (slot_key == 0) return null;

            const live = slot.state.load(.acquire) & STATE_LIVE != 0;
            if (live and slot_key == key and std.mem.eql(u8, slot.path_buf[0..slot.path_len], path)) return index;

            index = (index + 1) & self.mask;
        }

        return null;
    }

    /// Reclaim up to SWEEP_BUDGET unpinned slots starting at the probe home, so
    /// pressure frees the same entries a timer would have. Caller holds the lock.
    ///
    /// Note:
    /// - Freshness is not consulted here. A full table means every slot is worth
    ///   more as room for the request in hand than as a cached entry, and the
    ///   reclaimed file is re-opened on its next request.
    fn sweep(self: *StaticCache, io: std.Io, key: u64) void {
        var index: usize = @intCast(key & self.mask);
        var swept: usize = 0;
        while (swept < SWEEP_BUDGET and swept <= self.mask) : (swept += 1) {
            const slot = &self.slots[index];
            if (slot.state.cmpxchgStrong(STATE_LIVE, 0, .acq_rel, .acquire) == null) {
                closeVariants(slot, io);
            }

            index = (index + 1) & self.mask;
        }
    }

    /// Close an expired slot's files and mark it reusable.
    ///
    /// Note:
    /// - A pinned slot is left alone: a response is still writing from it, and the
    ///   next expired lookup reclaims it once that response finishes.
    fn reclaimExpired(self: *StaticCache, io: std.Io, index: usize) void {
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        defer self.lock.store(false, .release);

        const slot = &self.slots[index];
        if (slot.state.cmpxchgStrong(STATE_LIVE, 0, .acq_rel, .acquire) != null) return;

        closeVariants(slot, io);
    }
};

// --------------------------------------------------------- //

/// Take a pin, which only succeeds while the slot is live.
///
/// Return:
/// - bool (true when the pin is held and the caller must unpin)
fn pinSlot(slot: *Slot) bool {
    var observed = slot.state.load(.acquire);
    while (observed & STATE_LIVE != 0) {
        // A saturated pin count would wrap into the live flag, so refuse instead.
        if (observed & STATE_PIN_MASK == STATE_PIN_MASK) return false;

        if (slot.state.cmpxchgWeak(observed, observed + 1, .acquire, .acquire)) |seen| {
            observed = seen;
            continue;
        }

        return true;
    }

    return false;
}

fn unpinSlot(slot: *Slot) void {
    _ = slot.state.fetchSub(1, .release);
}

/// Close every open variant of a slot, releasing any bytes mapped from it. Caller holds the lock
/// and has already cleared the live flag, so no reader can be inside the slot.
fn closeVariants(slot: *Slot, io: std.Io) void {
    for (&slot.variants) |*variant| {
        if (variant.mapped.load(.acquire)) {
            unmapBytes(variant.map_ptr[0..variant.map_len]);
            variant.mapped.store(false, .release);
            variant.map_len = 0;
        }

        if (!variant.present) continue;

        variant.file.close(io);
        variant.present = false;
    }
}

/// Give a variant stable, addressable bytes for the whole life of the entry. Caller holds the lock.
///
/// Note:
/// - The bytes are a SNAPSHOT, read once into a demand-paged anonymous mapping, not a mapping of the
///   file itself. A file mapping was measured faster to set up and free of this copy, but it is not
///   safe here: a file rewritten IN PLACE (which is what `cp` over a served file does) changes under
///   a mapping that a response is still reading, so an in-flight body would serve the new bytes, and
///   a file that shrank would fault past its own end. A snapshot cannot be changed underneath a
///   response, which is what an HTTP/3 body needs, since it is re-read for every packet and every
///   retransmission.
/// - Bounded by SNAPSHOT_MAX_BYTES. A larger file is not servable this way and the caller falls
///   through, rather than the cache quietly holding an unbounded amount of memory.
/// - An empty file needs no snapshot: an empty slice is already stable.
///
/// Return:
/// - bool (true when bytes are available to read through map_ptr / map_len)
fn mapBytes(variant: *Variant, io: std.Io) bool {
    if (variant.mapped.load(.acquire)) return true;
    if (!variant.present) return false;

    if (variant.size == 0) {
        variant.map_ptr = "";
        variant.map_len = 0;
        variant.mapped.store(true, .release);

        return true;
    }

    if (variant.size > SNAPSHOT_MAX_BYTES) return false;

    const size: usize = std.math.cast(usize, variant.size) orelse return false;

    const buf = slab_mem.mapZeroedSlots(u8, size) catch return false;
    const read = variant.file.readPositionalAll(io, buf, 0) catch {
        slab_mem.unmapSlots(buf);
        return false;
    };
    if (read != size) {
        slab_mem.unmapSlots(buf);
        return false;
    }

    variant.map_ptr = buf.ptr;
    variant.map_len = buf.len;
    variant.mapped.store(true, .release);

    return true;
}

/// Release bytes handed out by mapBytes.
fn unmapBytes(bytes: []const u8) void {
    if (bytes.len == 0) return;

    slab_mem.unmapSlots(@constCast(bytes));
}

/// Open path plus its precompressed siblings into the slot's variants.
///
/// Note:
/// - The identity variant is mandatory: without it there is nothing to serve and
///   the slot stays unpublished.
/// - A sibling that fails to open is simply absent, so a directory holding only
///   some precompressed files still caches the rest.
///
/// Return:
/// - bool (true when the identity variant opened and the slot may be published)
fn buildVariants(slot: *Slot, io: std.Io, path: []const u8) bool {
    for (&slot.variants) |*variant| variant.present = false;

    if (!openVariant(&slot.variants[variantIndex(.IDENTITY)], io, path, path, .IDENTITY)) return false;

    var sibling_buf: [PUBLIC_PATH_MAX + 8]u8 = undefined;
    for (SIBLINGS) |sibling| {
        const sibling_path = std.fmt.bufPrint(&sibling_buf, "{s}{s}", .{ path, sibling.suffix }) catch continue;
        _ = openVariant(&slot.variants[variantIndex(sibling.encoding)], io, sibling_path, path, sibling.encoding);
    }

    return true;
}

/// Open one variant file and render the header it replays.
///
/// Param:
/// path - []const u8 (file actually opened, sibling suffix included)
/// type_path - []const u8 (path the content type comes from, always the identity name)
///
/// Return:
/// - bool (true when the variant is open and usable)
fn openVariant(variant: *Variant, io: std.Io, path: []const u8, type_path: []const u8, encoding: Encoding) bool {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;

    const stat = file.stat(io) catch {
        file.close(io);
        return false;
    };
    if (stat.kind != .file) {
        file.close(io);
        return false;
    }

    const content_type = content.fromExtension(file_utils.extension(type_path));
    const header = renderHeader(&variant.hdr_buf, content_type, stat.size, encoding) orelse {
        file.close(io);
        return false;
    };

    variant.file = file;
    variant.size = stat.size;
    variant.content_type = content_type;
    variant.hdr_len = @intCast(header.len);
    variant.present = true;

    return true;
}

/// Pick the variant the client accepts and describe it as a hit. The slot is
/// already pinned, so the returned file stays open until release.
///
/// Note:
/// - Identity is the floor. A client that rejects every available coding is
///   served the plain file rather than a 406, matching the uncached path.
fn buildHit(slot: *Slot, index: u32, accept_encoding: ?[]const u8) Hit {
    var supported_buf: [SIBLINGS.len]Encoding = undefined;
    var supported_len: usize = 0;
    for (SIBLINGS) |sibling| {
        if (slot.variants[variantIndex(sibling.encoding)].present) {
            supported_buf[supported_len] = sibling.encoding;
            supported_len += 1;
        }
    }

    const chosen = compression.negotiate(accept_encoding, supported_buf[0..supported_len]) orelse .IDENTITY;
    const wanted = &slot.variants[variantIndex(chosen)];
    const variant = if (wanted.present) wanted else &slot.variants[variantIndex(.IDENTITY)];

    return .{
        .slot = index,
        .file = variant.file,
        .size = variant.size,
        .header = variant.hdr_buf[0..variant.hdr_len],
        .content_type = variant.content_type,
        .encoding = if (variant.present and wanted.present) chosen else .IDENTITY,
    };
}

// --------------------------------------------------------- //

/// The table every zix HTTP engine in this process shares. Installed by the
/// first server that enables static caching.
var g_cache: ?StaticCache = null;

/// Entry count and freshness window the installed table was built with, kept so a
/// later server asking for different values is reported instead of silently
/// inheriting the first server's policy.
var g_max_entries: u32 = 0;
var g_ttl_ms: u32 = 0;
var g_install_lock: std.atomic.Value(bool) = .init(false);

/// What a call to install did, so the caller can report a mismatch through its
/// own logger instead of this module writing to stderr behind its back.
pub const InstallResult = enum {
    /// ttl_ms was 0, so caching stays off and every request is uncached.
    DISABLED,
    /// This call built the shared table.
    INSTALLED,
    /// A table already existed with the same settings.
    ALREADY_INSTALLED,
    /// A table already existed with DIFFERENT settings, and it was kept. The
    /// caller runs with the installed policy, not the one it asked for.
    MISMATCHED,
};

/// Build the shared table, or report what stopped it.
///
/// Note:
/// - The first server to enable static caching in a process fixes the table size
///   and the freshness window for the whole process. A later server asking for
///   different values keeps running under the installed policy and gets
///   MISMATCHED back, since a static cache is a process-level resource and two
///   tables would double the descriptor cost.
/// - A ttl_ms of 0 disables caching, so nothing is installed.
///
/// Param:
/// max_entries - u32 (requested slot count, clamped against the descriptor budget)
/// ttl_ms - u32 (freshness window, 0 disables the cache entirely)
///
/// Return:
/// - InstallResult
/// - If error, the mapping failed and there is no table, so callers fall back to
///   the uncached path
pub fn install(max_entries: u32, ttl_ms: u32) !InstallResult {
    if (ttl_ms == 0) return .DISABLED;

    while (g_install_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer g_install_lock.store(false, .release);

    if (g_cache != null) {
        if (g_max_entries != max_entries or g_ttl_ms != ttl_ms) return .MISMATCHED;

        return .ALREADY_INSTALLED;
    }

    g_cache = try StaticCache.init(max_entries);
    g_max_entries = max_entries;
    g_ttl_ms = ttl_ms;

    return .INSTALLED;
}

/// The shared table, or null when no server enabled static caching.
pub fn instance() ?*StaticCache {
    if (g_cache) |*cache| return cache;

    return null;
}

/// Freshness window the shared table was installed with, 0 when there is none.
pub fn ttlMs() u32 {
    return g_ttl_ms;
}

/// Close every cached file and drop the shared table. Call only after every
/// server in the process has stopped.
pub fn shutdown(io: std.Io) void {
    while (g_install_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer g_install_lock.store(false, .release);

    if (g_cache) |*cache| cache.deinit(io);

    g_cache = null;
    g_max_entries = 0;
    g_ttl_ms = 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Write one file into a test directory, panicking on failure since a fixture
/// that cannot be written is a broken test rather than a tested condition.
fn writeFixture(dir: std.Io.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(testing.io, .{ .sub_path = name, .data = data }) catch @panic("fixture write failed");
}

test "zix static_cache: resolvePath joins and rejects unsafe paths" {
    var buf: [PUBLIC_PATH_MAX]u8 = undefined;

    try testing.expectEqualStrings("public/a.txt", resolvePath(&buf, "public", "a.txt").?);
    try testing.expectEqualStrings("./public/dir/a.txt", resolvePath(&buf, "./public", "dir/a.txt").?);

    try testing.expect(resolvePath(&buf, "public", "") == null);
    try testing.expect(resolvePath(&buf, "public", "../etc/passwd") == null);
    try testing.expect(resolvePath(&buf, "public", "a/../b") == null);
    try testing.expect(resolvePath(&buf, "public", "/absolute") == null);

    var long: [PUBLIC_PATH_MAX]u8 = @splat('a');
    try testing.expect(resolvePath(&buf, "public", &long) == null);
}

test "zix static_cache: hashPath is stable, distinct, and never zero" {
    try testing.expectEqual(hashPath("public/a.txt"), hashPath("public/a.txt"));
    try testing.expect(hashPath("public/a.txt") != hashPath("public/b.txt"));
    try testing.expect(hashPath("") != 0);
}

test "zix static_cache: renderHeader carries Vary and only encodes when compressed" {
    var buf: [HEADER_MAX]u8 = undefined;

    const plain = renderHeader(&buf, "text/html", 12, .IDENTITY).?;
    try testing.expect(std.mem.startsWith(u8, plain, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Length: 12\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "Vary: Accept-Encoding\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "Content-Encoding") == null);
    try testing.expect(std.mem.endsWith(u8, plain, "\r\n\r\n"));

    var br_buf: [HEADER_MAX]u8 = undefined;
    const compressed = renderHeader(&br_buf, "text/css", 7, .BR).?;
    try testing.expect(std.mem.indexOf(u8, compressed, "Content-Encoding: br\r\n") != null);

    // A buffer too small to hold the header makes the variant uncacheable
    // instead of truncating the response head.
    var tiny: [8]u8 = undefined;
    try testing.expect(renderHeader(&tiny, "text/html", 12, .IDENTITY) == null);
}

test "zix static_cache: variantIndex separates the three servable codings" {
    try testing.expectEqual(@as(usize, 0), variantIndex(.IDENTITY));
    try testing.expectEqual(@as(usize, 1), variantIndex(.GZIP));
    try testing.expectEqual(@as(usize, 2), variantIndex(.BR));

    // No .deflate sibling convention exists, so it shares the identity slot.
    try testing.expectEqual(variantIndex(.IDENTITY), variantIndex(.DEFLATE));
}

test "zix static_cache: descriptorCeiling stays within its documented floor" {
    const ceiling = descriptorCeiling();

    try testing.expect(ceiling >= FD_CEILING_MIN);
}

test "zix static_cache: init clamps and rounds the entry count down to a power of two" {
    var cache = try StaticCache.init(100);
    defer cache.deinit(testing.io);

    try testing.expectEqual(@as(usize, 64), cache.slots.len);
    try testing.expectEqual(@as(usize, 63), cache.mask);

    // A zero request still yields one usable slot rather than an empty table.
    var single = try StaticCache.init(0);
    defer single.deinit(testing.io);

    try testing.expectEqual(@as(usize, 1), single.slots.len);
}

test "zix static_cache: acquire serves a hit from the cached file on the second request" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "hello.txt", "hello static");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const first = cache.acquire(testing.io, root, "hello.txt", null, 1000, 100).?;
    try testing.expectEqual(@as(u64, "hello static".len), first.size);
    try testing.expectEqualStrings("text/plain", first.content_type);
    try testing.expectEqual(Encoding.IDENTITY, first.encoding);
    try testing.expect(std.mem.indexOf(u8, first.header, "Content-Length: 12\r\n") != null);
    cache.release(first);

    // Second request reuses the same open file, so the cache resolved it once.
    const second = cache.acquire(testing.io, root, "hello.txt", null, 1000, 200).?;
    try testing.expectEqual(first.file.handle, second.file.handle);

    var read_buf: [32]u8 = undefined;
    const read = try second.file.readPositionalAll(testing.io, read_buf[0..@intCast(second.size)], 0);
    try testing.expectEqualStrings("hello static", read_buf[0..read]);
    cache.release(second);
}

test "zix static_cache: acquire returns null for a missing file and caches nothing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    try testing.expect(cache.acquire(testing.io, root, "absent.txt", null, 1000, 100) == null);

    // A miss must not consume a slot, otherwise a flood of unknown paths would
    // evict the entries actually being served.
    for (cache.slots) |*slot| try testing.expectEqual(@as(u64, 0), slot.key);
}

test "zix static_cache: acquire with ttl 0 never touches the table" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "off.txt", "not cached");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    try testing.expect(cache.acquire(testing.io, root, "off.txt", null, 0, 100) == null);
    for (cache.slots) |*slot| try testing.expectEqual(@as(u64, 0), slot.key);
}

test "zix static_cache: acquire rejects traversal before it ever opens a file" {
    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    try testing.expect(cache.acquire(testing.io, "public", "../etc/passwd", null, 1000, 100) == null);
    try testing.expect(cache.acquire(testing.io, "public", "/etc/passwd", null, 1000, 100) == null);
    try testing.expect(cache.acquire(testing.io, "public", "", null, 1000, 100) == null);
}

test "zix static_cache: precompressed siblings are picked up and negotiated" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "app.js", "plain-body-bytes");
    writeFixture(tmp.dir, "app.js.br", "br-body");
    writeFixture(tmp.dir, "app.js.gz", "gz-body-x");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const brotli = cache.acquire(testing.io, root, "app.js", "br, gzip", 1000, 100).?;
    try testing.expectEqual(Encoding.BR, brotli.encoding);
    try testing.expectEqual(@as(u64, "br-body".len), brotli.size);
    try testing.expect(std.mem.indexOf(u8, brotli.header, "Content-Encoding: br\r\n") != null);
    // The content type comes from the identity name, not the .br suffix.
    try testing.expectEqualStrings("application/javascript", brotli.content_type);
    cache.release(brotli);

    const gzip = cache.acquire(testing.io, root, "app.js", "gzip", 1000, 100).?;
    try testing.expectEqual(Encoding.GZIP, gzip.encoding);
    try testing.expectEqual(@as(u64, "gz-body-x".len), gzip.size);
    cache.release(gzip);

    const plain = cache.acquire(testing.io, root, "app.js", null, 1000, 100).?;
    try testing.expectEqual(Encoding.IDENTITY, plain.encoding);
    try testing.expectEqual(@as(u64, "plain-body-bytes".len), plain.size);
    try testing.expect(std.mem.indexOf(u8, plain.header, "Content-Encoding") == null);
    cache.release(plain);
}

test "zix static_cache: a file with no sibling serves identity to a client that wants brotli" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "solo.css", "body{}");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const hit = cache.acquire(testing.io, root, "solo.css", "br, gzip", 1000, 100).?;
    try testing.expectEqual(Encoding.IDENTITY, hit.encoding);
    try testing.expectEqualStrings("text/css", hit.content_type);
    try testing.expect(std.mem.indexOf(u8, hit.header, "Content-Encoding") == null);
    cache.release(hit);
}

test "zix static_cache: an expired entry is reclaimed in place and re-opened" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "stale.txt", "first");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const first = cache.acquire(testing.io, root, "stale.txt", null, 1000, 100).?;
    try testing.expectEqual(@as(u64, 5), first.size);
    cache.release(first);

    // Content changes on disk, and the entry is past its window: the next
    // request re-opens and re-stats, so the new size is visible.
    writeFixture(tmp.dir, "stale.txt", "second-longer");

    const refreshed = cache.acquire(testing.io, root, "stale.txt", null, 1000, 5000).?;
    try testing.expectEqual(@as(u64, "second-longer".len), refreshed.size);
    try testing.expect(std.mem.indexOf(u8, refreshed.header, "Content-Length: 13\r\n") != null);
    cache.release(refreshed);
}

test "zix static_cache: a pinned slot survives reclaim and its file stays readable" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "pinned.txt", "in flight");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const held = cache.acquire(testing.io, root, "pinned.txt", null, 1000, 100).?;

    // An expired lookup while the send is in flight must not close the file.
    try testing.expect(cache.acquire(testing.io, root, "pinned.txt", null, 1000, 9000) == null);
    try testing.expect(cache.slots[held.slot].state.load(.acquire) & STATE_LIVE != 0);

    var read_buf: [16]u8 = undefined;
    const read = try held.file.readPositionalAll(testing.io, read_buf[0..@intCast(held.size)], 0);
    try testing.expectEqualStrings("in flight", read_buf[0..read]);

    cache.release(held);
}

test "zix static_cache: a full table degrades to null instead of failing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "a.txt", "a");
    writeFixture(tmp.dir, "b.txt", "b");
    writeFixture(tmp.dir, "c.txt", "c");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    // Two slots, and both stay pinned, so nothing can be swept for the third.
    var cache = try StaticCache.init(2);
    defer cache.deinit(testing.io);

    const first = cache.acquire(testing.io, root, "a.txt", null, 1000, 100).?;
    const second = cache.acquire(testing.io, root, "b.txt", null, 1000, 100).?;

    try testing.expect(cache.acquire(testing.io, root, "c.txt", null, 1000, 100) == null);

    // The entries already cached keep working, so a full table costs the new
    // request its cache slot and nothing else.
    cache.release(first);
    cache.release(second);

    const again = cache.acquire(testing.io, root, "a.txt", null, 1000, 200).?;
    try testing.expectEqual(@as(u64, 1), again.size);
    cache.release(again);
}

test "zix static_cache: a full table sweeps unpinned entries to make room" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "a.txt", "a");
    writeFixture(tmp.dir, "b.txt", "bb");
    writeFixture(tmp.dir, "c.txt", "ccc");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(2);
    defer cache.deinit(testing.io);

    cache.release(cache.acquire(testing.io, root, "a.txt", null, 1000, 100).?);
    cache.release(cache.acquire(testing.io, root, "b.txt", null, 1000, 100).?);

    // Nothing is pinned now, so the sweep frees room and the third file caches.
    const third = cache.acquire(testing.io, root, "c.txt", null, 1000, 100).?;
    try testing.expectEqual(@as(u64, 3), third.size);
    cache.release(third);
}

test "zix static_cache: distinct paths coexist and keep their own bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    writeFixture(tmp.dir, "one.html", "<h1>one</h1>");
    writeFixture(tmp.dir, "two.json", "{\"n\":2}");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cache = try StaticCache.init(16);
    defer cache.deinit(testing.io);

    const one = cache.acquire(testing.io, root, "one.html", null, 1000, 100).?;
    const two = cache.acquire(testing.io, root, "two.json", null, 1000, 100).?;

    try testing.expect(one.file.handle != two.file.handle);
    try testing.expectEqualStrings("text/html", one.content_type);
    try testing.expectEqualStrings("application/json", two.content_type);

    cache.release(one);
    cache.release(two);
}

test "zix static_cache: install is process-wide and shutdown clears it" {
    // No table until a server enables caching.
    try testing.expect(instance() == null);
    try testing.expectEqual(@as(u32, 0), ttlMs());

    // A ttl of 0 is the disabled default and installs nothing.
    try testing.expectEqual(InstallResult.DISABLED, try install(64, 0));
    try testing.expect(instance() == null);

    try testing.expectEqual(InstallResult.INSTALLED, try install(64, 2000));
    try testing.expect(instance() != null);
    try testing.expectEqual(@as(u32, 2000), ttlMs());

    // A second server with the same settings just shares the table.
    const first = instance().?;
    try testing.expectEqual(InstallResult.ALREADY_INSTALLED, try install(64, 2000));

    // Different settings are reported rather than silently inherited, and the
    // installed table is kept so the descriptor cost does not double.
    try testing.expectEqual(InstallResult.MISMATCHED, try install(128, 5000));
    try testing.expectEqual(@intFromPtr(first), @intFromPtr(instance().?));
    try testing.expectEqual(@as(u32, 2000), ttlMs());

    shutdown(testing.io);
    try testing.expect(instance() == null);
    try testing.expectEqual(@as(u32, 0), ttlMs());
}
