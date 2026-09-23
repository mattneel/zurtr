//! zix HTTP/3 connection-id demux (the v1 single-worker CID table).
//!
//! What:
//! - A QUIC connection is keyed by its Destination Connection ID, not by a socket. The v1 engine runs
//!   one recv worker that owns this table: every datagram for every connection arrives here, so a
//!   4-tuple change (connection migration) is just a new peer address on an existing CID, with no
//!   cross-core routing needed. Per-core CID sharding is v2 (ADR-049 phase 3).
//!
//! Note:
//! - The table is fixed-capacity (no allocation, returns null on overflow) with an embedded
//!   open-addressing hash index for O(1) find. Every received datagram is demuxed by its Destination
//!   Connection ID, so a linear scan would add a per-packet cost that grows with the connection count.

const std = @import("std");

/// A QUIC connection ID, up to 20 bytes (RFC 9000 17.2).
pub const ConnId = struct {
    bytes: [20]u8 = undefined,
    len: u8 = 0,

    /// Build a ConnId from a byte slice, truncating at the 20-byte version-1 maximum.
    pub fn fromSlice(source: []const u8) ConnId {
        var id = ConnId{ .len = @intCast(@min(source.len, 20)) };
        @memcpy(id.bytes[0..id.len], source[0..id.len]);

        return id;
    }

    /// The connection ID bytes.
    pub fn slice(self: *const ConnId) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Whether two connection IDs are byte-equal.
    pub fn eql(self: *const ConnId, other: *const ConnId) bool {
        return self.len == other.len and std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// A fixed-capacity CID-keyed table of `T`, owned by one recv worker. Returns null on overflow rather
/// than allocating, so the caller can apply an admission policy. find / put are O(1) via an embedded
/// open-addressing index, sized at twice the capacity (load factor 0.5) so probe chains stay short.
/// `remove` frees an entry's slot for reuse (the idle-connection eviction the maintenance sweep needs, so
/// a dead connection does not pin its slot for the worker's life). A removed index bucket becomes a
/// tombstone that find and insert probe past, and insert reuses tombstones, so steady-state churn
/// recycles them instead of growing the index. When the table empties, the index is cleared outright.
pub fn Table(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const index_slots = capacity * 2;

        /// The value slots one table holds, so a worker can walk its live connections (at) for upkeep.
        pub const slot_capacity = capacity;

        /// Index sentinel for a bucket whose entry was removed. A plain empty bucket (0) ends a probe, so
        /// a removed key would sever any probe chain that ran through it: a tombstone is probed PAST
        /// instead. Distinct from any real value index (which is slot + 1, at most capacity).
        const tombstone: u32 = std.math.maxInt(u32);

        values: [capacity]T = undefined,
        /// Which value slots currently hold a live entry, so put reuses a slot freed by remove instead of
        /// only ever appending. `count` is how many are set.
        occupied: [capacity]bool = @splat(false),
        count: usize = 0,
        /// Open-addressing index. keys[bucket] is the connection id, slots[bucket] is its value index + 1
        /// (0 means the bucket is empty, `tombstone` means it was removed). The id is stored per bucket,
        /// not per value, so one value can be reached by more than one id (a connection keyed by both the
        /// client DCID and the server SCID).
        keys: [index_slots]ConnId = undefined,
        slots: [index_slots]u32 = @splat(0),

        fn bucketOf(id: *const ConnId) usize {
            return @intCast(std.hash.Wyhash.hash(0, id.slice()) % index_slots);
        }

        /// Place `id -> slot` at the first empty OR tombstone bucket on its probe chain, recycling a
        /// removed bucket. Callers only ever insert a fresh, unique id (a new connection's DCID, then its
        /// distinct server SCID alias), so reusing a tombstone can never shadow an existing equal key
        /// further down the chain.
        fn insertKey(self: *Self, id: ConnId, slot: usize) void {
            var bucket = bucketOf(&id);
            while (self.slots[bucket] != 0 and self.slots[bucket] != tombstone) bucket = (bucket + 1) % index_slots;

            self.keys[bucket] = id;
            self.slots[bucket] = @intCast(slot + 1);
        }

        /// Find the value owned by `id`, or null. O(1) average via the hash index. A tombstone bucket is
        /// probed past (its key is stale), only a real match returns.
        pub fn find(self: *Self, id: *const ConnId) ?*T {
            var bucket = bucketOf(id);
            var probes: usize = 0;
            while (self.slots[bucket] != 0 and probes < index_slots) : (probes += 1) {
                if (self.slots[bucket] != tombstone and self.keys[bucket].eql(id)) return &self.values[self.slots[bucket] - 1];

                bucket = (bucket + 1) % index_slots;
            }

            return null;
        }

        /// Insert a value under `id`. Returns the stored slot, or null when the table is full.
        pub fn put(self: *Self, id: ConnId, value: T) ?*T {
            if (self.count >= capacity) return null;

            const slot = self.freeSlot() orelse return null;
            self.values[slot] = value;
            self.occupied[slot] = true;
            self.count += 1;
            self.insertKey(id, slot);

            return &self.values[slot];
        }

        /// The first free value slot, or null when every slot is live. Linear from 0: called once per new
        /// connection (far rarer than the per-datagram find), so the scan sits off the hot path.
        fn freeSlot(self: *Self) ?usize {
            for (self.occupied, 0..) |live, slot| {
                if (!live) return slot;
            }

            return null;
        }

        /// The live value in `slot`, or null when the slot is free. A worker walks 0..slot_capacity to run
        /// per-connection upkeep (the maintenance sweep). Removing the current entry mid-walk is safe,
        /// since the walk is by slot index over the fixed values array and remove only flips flags.
        pub fn at(self: *Self, slot: usize) ?*T {
            return if (self.occupied[slot]) &self.values[slot] else null;
        }

        /// Add a second id that resolves to an existing entry (e.g. the server-issued SCID for a
        /// connection already keyed by the client's original DCID), so a 1-RTT packet that addresses the
        /// connection by that SCID resolves in O(1) instead of a linear scan.
        pub fn addAlias(self: *Self, id: ConnId, value: *const T) void {
            const slot = (@intFromPtr(value) - @intFromPtr(&self.values[0])) / @sizeOf(T);
            self.insertKey(id, slot);
        }

        /// Remove the entry reached by `id`, freeing its value slot for reuse and tombstoning every index
        /// bucket that pointed at it (the primary DCID key and any SCID alias), so no id for it resolves
        /// afterward. Returns true when an entry was removed, false when `id` was absent (idempotent). On
        /// emptying the table the whole index is cleared, so tombstones never carry across quiet periods.
        pub fn remove(self: *Self, id: *const ConnId) bool {
            const target = self.find(id) orelse return false;
            const slot: u32 = @intCast((@intFromPtr(target) - @intFromPtr(&self.values[0])) / @sizeOf(T));

            for (&self.slots) |*bucket_slot| {
                if (bucket_slot.* != 0 and bucket_slot.* != tombstone and bucket_slot.* - 1 == slot) bucket_slot.* = tombstone;
            }

            self.occupied[slot] = false;
            self.count -= 1;

            if (self.count == 0) self.slots = @splat(0); // empty table: drop every tombstone

            return true;
        }
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: ConnId build, slice, and equality" {
    const a = ConnId.fromSlice(&[_]u8{ 1, 2, 3, 4 });
    const b = ConnId.fromSlice(&[_]u8{ 1, 2, 3, 4 });
    const c = ConnId.fromSlice(&[_]u8{ 1, 2, 3, 5 });

    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, a.slice());
    try std.testing.expect(a.eql(&b));
    try std.testing.expect(!a.eql(&c));
}

test "zix http3: CID table put and find" {
    var table = Table(u32, 4){};
    const id1 = ConnId.fromSlice(&[_]u8{ 0xaa, 0xbb });
    const id2 = ConnId.fromSlice(&[_]u8{ 0xcc, 0xdd });

    _ = table.put(id1, 100);
    _ = table.put(id2, 200);

    try std.testing.expectEqual(@as(u32, 100), table.find(&id1).?.*);
    try std.testing.expectEqual(@as(u32, 200), table.find(&id2).?.*);

    const missing = ConnId.fromSlice(&[_]u8{0xff});
    try std.testing.expect(table.find(&missing) == null);
}

test "zix http3: CID table hash index finds every entry at capacity, rejects overflow" {
    var table = Table(u32, 64){};

    // Fill the table. Two-byte ids collide into buckets, so this exercises the open-addressing probe.
    for (0..64) |entry| {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(entry), 0x5a });
        try std.testing.expect(table.put(id, @intCast(entry * 7)) != null);
    }

    // Every inserted id resolves to its own value via the index, not a stale or wrong slot.
    for (0..64) |entry| {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(entry), 0x5a });
        try std.testing.expectEqual(@as(u32, @intCast(entry * 7)), table.find(&id).?.*);
    }

    // A full table refuses the next insert, and an absent id still returns null.
    const overflow = ConnId.fromSlice(&[_]u8{ 0xff, 0xff });
    try std.testing.expect(table.put(overflow, 1) == null);
    try std.testing.expect(table.find(&overflow) == null);
}

test "zix http3: CID table addAlias resolves a second id to the same entry" {
    var table = Table(u32, 4){};
    const dcid = ConnId.fromSlice(&[_]u8{ 0x01, 0x02 });
    const scid = ConnId.fromSlice(&[_]u8{ 0x09, 0x08, 0x07 });

    const stored = table.put(dcid, 4242).?;
    table.addAlias(scid, stored);

    // Both the original client DCID and the server-issued SCID resolve to the one stored value.
    try std.testing.expectEqual(@as(u32, 4242), table.find(&dcid).?.*);
    try std.testing.expectEqual(@as(u32, 4242), table.find(&scid).?.*);
    try std.testing.expect(table.find(&dcid) == table.find(&scid));
}

test "zix http3: CID table remove drops an entry and its alias, leaves others, is idempotent" {
    var table = Table(u32, 8){};
    const dcid = ConnId.fromSlice(&[_]u8{ 0x01, 0x02 });
    const scid = ConnId.fromSlice(&[_]u8{ 0x09, 0x08, 0x07 });
    const other = ConnId.fromSlice(&[_]u8{0x55});

    const stored = table.put(dcid, 4242).?;
    table.addAlias(scid, stored);
    _ = table.put(other, 7).?;
    try std.testing.expectEqual(@as(usize, 2), table.count);

    // Remove by the primary id: it and the SCID alias both stop resolving, the unrelated entry survives.
    try std.testing.expect(table.remove(&dcid));
    try std.testing.expect(table.find(&dcid) == null);
    try std.testing.expect(table.find(&scid) == null);
    try std.testing.expectEqual(@as(u32, 7), table.find(&other).?.*);
    try std.testing.expectEqual(@as(usize, 1), table.count);

    // A second remove of the same (now absent) id is a no-op.
    try std.testing.expect(!table.remove(&dcid));
    try std.testing.expectEqual(@as(usize, 1), table.count);
}

test "zix http3: CID table reuses a freed slot on the next put" {
    var table = Table(u32, 2){};
    const a = ConnId.fromSlice(&[_]u8{0x01});
    const b = ConnId.fromSlice(&[_]u8{0x02});
    const c = ConnId.fromSlice(&[_]u8{0x03});

    _ = table.put(a, 1).?;
    _ = table.put(b, 2).?;
    try std.testing.expect(table.put(c, 3) == null); // full at capacity 2

    // Freeing a slot lets the next put reuse it, and the surviving entry is untouched.
    try std.testing.expect(table.remove(&a));
    try std.testing.expect(table.put(c, 3) != null);
    try std.testing.expectEqual(@as(u32, 3), table.find(&c).?.*);
    try std.testing.expectEqual(@as(u32, 2), table.find(&b).?.*);
    try std.testing.expectEqual(@as(usize, 2), table.count);
}

test "zix http3: CID table survives removing entries in a probe chain, clears tombstones when empty" {
    var table = Table(u32, 64){};

    // Fill it: two-byte ids collide into buckets, so this builds real open-addressing probe chains.
    for (0..64) |entry| {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(entry), 0x5a });
        try std.testing.expect(table.put(id, @intCast(entry)) != null);
    }

    // Remove every even entry. If a removed bucket were cleared to empty instead of tombstoned, it would
    // sever any chain running through it, so a surviving odd entry would stop resolving. Assert every
    // survivor still resolves and every removed id does not.
    var entry: usize = 0;
    while (entry < 64) : (entry += 2) {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(entry), 0x5a });
        try std.testing.expect(table.remove(&id));
    }
    for (0..64) |probe| {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(probe), 0x5a });
        if (probe % 2 == 0) {
            try std.testing.expect(table.find(&id) == null);
        } else {
            try std.testing.expectEqual(@as(u32, @intCast(probe)), table.find(&id).?.*);
        }
    }
    try std.testing.expectEqual(@as(usize, 32), table.count);

    // Remove the rest: the table empties, its tombstones are cleared, and a fresh fill works cleanly.
    entry = 1;
    while (entry < 64) : (entry += 2) {
        const id = ConnId.fromSlice(&[_]u8{ @intCast(entry), 0x5a });
        try std.testing.expect(table.remove(&id));
    }
    try std.testing.expectEqual(@as(usize, 0), table.count);

    const fresh = ConnId.fromSlice(&[_]u8{ 0x77, 0x5a });
    try std.testing.expect(table.put(fresh, 999) != null);
    try std.testing.expectEqual(@as(u32, 999), table.find(&fresh).?.*);
}

test "zix http3: CID table at() walks live slots and skips a freed one" {
    const Small = Table(u32, 4);
    var table = Small{};
    const a = ConnId.fromSlice(&[_]u8{0x01});
    const b = ConnId.fromSlice(&[_]u8{0x02});

    _ = table.put(a, 10).?;
    _ = table.put(b, 20).?;
    try std.testing.expect(table.remove(&a));

    // Walking every slot visits only the live entry (b -> 20), the freed slot returns null.
    var seen: u32 = 0;
    var live: usize = 0;
    for (0..Small.slot_capacity) |slot| {
        if (table.at(slot)) |value| {
            seen = value.*;
            live += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), live);
    try std.testing.expectEqual(@as(u32, 20), seen);
}
