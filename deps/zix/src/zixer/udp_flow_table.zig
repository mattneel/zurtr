//! zixer udp flow table: which client owns which forward slot, and which
//! slot to give up when all are taken

const std = @import("std");

/// Most flows one udp site carries at once. A media client is one flow, so
/// this bounds concurrent clients per site.
pub const FLOW_CAP: usize = 64;

/// One client's slot in the forward.
///
/// Note:
/// - Every field is guarded by the forward's state lock. The socket a slot
///   maps to lives with the forward itself, this table never touches one.
pub const Flow = struct {
    /// Slot is claimed. Cleared only once the slot is fully released, so
    /// false always means claimable.
    active: bool = false,
    /// The up pump asked this slot's down pump to exit (eviction).
    closing: bool = false,
    /// The down pump returned, the up pump may close the socket and release.
    done: bool = false,
    client: std.Io.net.IpAddress = undefined,
    upstream_index: u32 = 0,
    last_seen: u64 = 0,
};

/// The per-site flow map: a client addr:port sticks to one slot. Lookups
/// scan the fixed small table, and recency is a plain claim counter, so no
/// clock is involved. The caller holds one lock around every call.
pub const Table = struct {
    flows: [FLOW_CAP]Flow = @splat(.{}),
    seq: u64 = 0,

    /// Slot index of the flow this client owns.
    pub fn findByClient(table: *const Table, client: *const std.Io.net.IpAddress) ?u32 {
        for (&table.flows, 0..) |*flow, index| {
            if (flow.active and flow.client.eql(client)) return @intCast(index);
        }

        return null;
    }

    /// First unclaimed slot.
    pub fn findFree(table: *const Table) ?u32 {
        for (&table.flows, 0..) |*flow, index| {
            if (!flow.active) return @intCast(index);
        }

        return null;
    }

    /// Claim a free slot for a client and stamp it most recent.
    pub fn claim(table: *Table, index: u32, client: std.Io.net.IpAddress, upstream_index: u32) void {
        table.flows[index] = .{
            .active = true,
            .client = client,
            .upstream_index = upstream_index,
            .last_seen = table.nextSeq(),
        };
    }

    /// Stamp a flow most recently used.
    pub fn touch(table: *Table, index: u32) void {
        table.flows[index].last_seen = table.nextSeq();
    }

    /// Release a slot outright, so it can be claimed again.
    pub fn release(table: *Table, index: u32) void {
        table.flows[index] = .{};
    }

    /// The least recently used flow not already asked to close or finished:
    /// the slot to evict when the table is full.
    pub fn lruVictim(table: *const Table) ?u32 {
        var victim: ?u32 = null;
        var oldest: u64 = std.math.maxInt(u64);

        for (&table.flows, 0..) |*flow, index| {
            if (!flow.active or flow.closing or flow.done) continue;
            if (flow.last_seen >= oldest) continue;

            victim = @intCast(index);
            oldest = flow.last_seen;
        }

        return victim;
    }

    /// Live flow count, for tests and status.
    pub fn activeCount(table: *const Table) usize {
        var count: usize = 0;
        for (&table.flows) |*flow| {
            if (flow.active) count += 1;
        }

        return count;
    }

    fn nextSeq(table: *Table) u64 {
        table.seq += 1;

        return table.seq;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A loopback client address that is never bound, ports tell them apart.
fn clientAddress(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

test "zix zixer: udp flow table, claim then find by client sticks per addr and port" {
    var table = Table{};

    const first = clientAddress(41101);
    const second = clientAddress(41102);
    table.claim(0, first, 0);

    try testing.expectEqual(@as(?u32, 0), table.findByClient(&first));
    try testing.expectEqual(@as(?u32, null), table.findByClient(&second));

    // Same ip on another port is another client, so another flow.
    table.claim(1, second, 1);
    try testing.expectEqual(@as(?u32, 1), table.findByClient(&second));
    try testing.expectEqual(@as(u32, 1), table.flows[1].upstream_index);
}

test "zix zixer: udp flow table, find free exhausts at the cap and release reopens" {
    var table = Table{};

    for (0..FLOW_CAP) |slot| {
        const index = table.findFree().?;
        try testing.expectEqual(@as(u32, @intCast(slot)), index);
        table.claim(index, clientAddress(@intCast(41200 + slot)), 0);
    }

    try testing.expectEqual(@as(?u32, null), table.findFree());
    try testing.expectEqual(FLOW_CAP, table.activeCount());

    table.release(7);
    try testing.expectEqual(@as(?u32, 7), table.findFree());
    try testing.expectEqual(FLOW_CAP - 1, table.activeCount());
}

test "zix zixer: udp flow table, touch moves a flow off the victim spot" {
    var table = Table{};

    table.claim(0, clientAddress(41103), 0);
    table.claim(1, clientAddress(41104), 0);
    table.claim(2, clientAddress(41105), 0);

    // Slot 0 is the stalest claim until it is touched.
    try testing.expectEqual(@as(?u32, 0), table.lruVictim());

    table.touch(0);
    try testing.expectEqual(@as(?u32, 1), table.lruVictim());
}

test "zix zixer: udp flow table, victim skips closing and done flows" {
    var table = Table{};

    table.claim(0, clientAddress(41106), 0);
    table.claim(1, clientAddress(41107), 0);
    table.claim(2, clientAddress(41108), 0);

    table.flows[0].closing = true;
    table.flows[1].done = true;

    try testing.expectEqual(@as(?u32, 2), table.lruVictim());

    table.flows[2].closing = true;
    try testing.expectEqual(@as(?u32, null), table.lruVictim());
}

test "zix zixer: udp flow table, release clears every flag for reuse" {
    var table = Table{};

    table.claim(3, clientAddress(41109), 2);
    table.flows[3].closing = true;
    table.flows[3].done = true;

    table.release(3);

    try testing.expect(!table.flows[3].active);
    try testing.expect(!table.flows[3].closing);
    try testing.expect(!table.flows[3].done);
    try testing.expectEqual(@as(u32, 0), table.flows[3].upstream_index);
}
