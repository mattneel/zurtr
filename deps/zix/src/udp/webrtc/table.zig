//! zix WebRTC peer table: which address belongs to which connection.
//!
//! What:
//! - A fixed set of slots, each holding one connection, keyed by the address its peer sits at.
//!   The engine loop asks it three things: whose datagram is this, give me a slot for a new peer,
//!   and let go of the ones that died.
//! - Owns every connection in it. A slot released here is a connection freed here, so the loop
//!   above never carries a pointer it has to remember to free.
//!
//! Note:
//! - Lookup is a walk. The ceiling is `max_peers`, which is tens rather than thousands, and this
//!   is the portable correctness path rather than the throughput one. A table keyed by hash is
//!   worth having when the per-core models arrive and the peer counts with them.
//! - A table with no free slot answers null rather than evicting. Dropping a live session to make
//!   room for an unauthenticated stranger is how one stranger ends everyone else's call.

const std = @import("std");

const connection = @import("connection.zig");

const IpAddress = std.Io.net.IpAddress;

/// One slot, either holding a peer or free.
const Slot = struct {
    address: IpAddress,
    peer: ?*connection.Connection,
};

/// Everything the table can raise.
pub const Error = error{OutOfMemory};

/// The peers one worker holds.
///
/// Usage:
/// ```zig
/// var table = try Table.init(allocator, config.max_peers);
/// defer table.deinit();
///
/// const peer = try table.acquire(address, options, secrets, now_ms) orelse return;
/// _ = try peer.handle(datagram, now_ms);
///
/// table.dropDead();
/// ```
pub const Table = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    /// How many slots are taken.
    live: usize,

    /// Build an empty table.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the slots and every connection in them)
    /// max_peers - usize (how many peers this table holds at once, at least one)
    ///
    /// Return:
    /// - Table
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, max_peers: usize) Error!Table {
        const slots = try allocator.alloc(Slot, @max(max_peers, 1));

        for (slots) |*slot| slot.peer = null;

        return .{ .allocator = allocator, .slots = slots, .live = 0 };
    }

    /// Free every connection still held, then the slots.
    pub fn deinit(self: *Table) void {
        for (self.slots) |*slot| {
            const peer = slot.peer orelse continue;

            peer.deinit();
            self.allocator.destroy(peer);
            slot.peer = null;
        }

        self.allocator.free(self.slots);
        self.live = 0;
    }

    /// The connection for an address, or null when that address has none.
    ///
    /// Param:
    /// address - IpAddress
    ///
    /// Return:
    /// - ?*connection.Connection
    pub fn find(self: *Table, address: IpAddress) ?*connection.Connection {
        for (self.slots) |*slot| {
            const peer = slot.peer orelse continue;

            if (slot.address.eql(&address)) return peer;
        }

        return null;
    }

    /// The connection for an address, building one when it is new.
    ///
    /// Note:
    /// - Answers null when the table is full, which reads to that peer as a check nobody replied
    ///   to. It retransmits, and gets in once a slot frees.
    ///
    /// Param:
    /// address - IpAddress
    /// options - connection.Options
    /// secrets - connection.Secrets (fresh per connection, only read when one is built)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?*connection.Connection
    /// - error.OutOfMemory
    pub fn acquire(
        self: *Table,
        address: IpAddress,
        options: connection.Options,
        secrets: connection.Secrets,
        now_ms: u64,
    ) connection.Error!?*connection.Connection {
        if (self.find(address)) |peer| return peer;

        const slot = self.freeSlot() orelse return null;

        const peer = try self.allocator.create(connection.Connection);
        errdefer self.allocator.destroy(peer);

        peer.* = try connection.Connection.init(self.allocator, address, options, secrets, now_ms);

        slot.address = address;
        slot.peer = peer;
        self.live += 1;

        return peer;
    }

    /// Drop one peer, freeing its connection.
    ///
    /// Param:
    /// address - IpAddress
    ///
    /// Return:
    /// - true when a peer was there and is now gone
    pub fn release(self: *Table, address: IpAddress) bool {
        for (self.slots) |*slot| {
            const peer = slot.peer orelse continue;

            if (!slot.address.eql(&address)) continue;

            peer.deinit();
            self.allocator.destroy(peer);
            slot.peer = null;
            self.live -= 1;

            return true;
        }

        return false;
    }

    /// Drop every connection that has said it is finished.
    ///
    /// Return:
    /// - usize (how many were dropped)
    pub fn dropDead(self: *Table) usize {
        var dropped: usize = 0;

        for (self.slots) |*slot| {
            const peer = slot.peer orelse continue;

            if (!peer.isDead()) continue;

            peer.deinit();
            self.allocator.destroy(peer);
            slot.peer = null;
            self.live -= 1;
            dropped += 1;
        }

        return dropped;
    }

    /// The soonest deadline across every peer, or null when none has one.
    ///
    /// Return:
    /// - ?u64 (monotonic milliseconds)
    pub fn earliestDeadline(self: *Table) ?u64 {
        var soonest: ?u64 = null;

        for (self.slots) |*slot| {
            const peer = slot.peer orelse continue;
            const at_ms = peer.deadline() orelse continue;

            if (soonest == null or at_ms < soonest.?) soonest = at_ms;
        }

        return soonest;
    }

    /// Walk every peer the table holds.
    pub fn iterator(self: *Table) Iterator {
        return .{ .table = self, .index = 0 };
    }

    /// The first free slot, or null when the table is full.
    fn freeSlot(self: *Table) ?*Slot {
        for (self.slots) |*slot| {
            if (slot.peer == null) return slot;
        }

        return null;
    }

    /// Walks the peers a table holds, skipping the free slots.
    pub const Iterator = struct {
        table: *Table,
        index: usize,

        /// The next peer, or null at the end.
        pub fn next(self: *Iterator) ?*connection.Connection {
            while (self.index < self.table.slots.len) {
                const slot = &self.table.slots[self.index];
                self.index += 1;

                if (slot.peer) |peer| return peer;
            }

            return null;
        }
    };
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

fn testAddress(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

fn testOptions() !connection.Options {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return .{
        .ice_ufrag = "zixL",
        .ice_password = "zixlocalpasswordaaaaaa",
        .peer_ice_ufrag = "peer",
        .certificate_der = &TEST_DER,
        .signing_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret)),
    };
}

fn testSecrets() connection.Secrets {
    return .{
        .dtls_cookie = @splat(0x5A),
        .sctp_cookie = @splat(0x6B),
        .server_random = @splat(0x33),
        .server_eph_secret = @splat(0x44),
        .sctp_tag = 0x11223344,
        .sctp_initial_tsn = 1000,
    };
}

test "zix webrtc: table, an empty table finds nothing and holds nobody" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 0), table.live);
    try std.testing.expect(table.find(testAddress(1000)) == null);
    try std.testing.expectEqual(@as(?u64, null), table.earliestDeadline());

    var walk = table.iterator();
    try std.testing.expect(walk.next() == null);
}

test "zix webrtc: table, acquiring the same address twice returns the same connection" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    const first = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    const again = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 500)).?;

    try std.testing.expectEqual(first, again);
    try std.testing.expectEqual(@as(usize, 1), table.live);
}

test "zix webrtc: table, separate addresses get separate connections" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    const first = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    const second = (try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)).?;

    try std.testing.expect(first != second);
    try std.testing.expectEqual(@as(usize, 2), table.live);
    try std.testing.expectEqual(first, table.find(testAddress(1000)).?);
    try std.testing.expectEqual(second, table.find(testAddress(1001)).?);
}

test "zix webrtc: table, a full table answers null rather than evicting" {
    var table = try Table.init(std.testing.allocator, 2);
    defer table.deinit();

    _ = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    _ = (try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)).?;

    try std.testing.expect((try table.acquire(testAddress(1002), try testOptions(), testSecrets(), 0)) == null);

    // The two already in are untouched.
    try std.testing.expectEqual(@as(usize, 2), table.live);
    try std.testing.expect(table.find(testAddress(1000)) != null);
    try std.testing.expect(table.find(testAddress(1001)) != null);
}

test "zix webrtc: table, releasing frees the slot for the next peer" {
    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit();

    _ = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    try std.testing.expect((try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)) == null);

    try std.testing.expect(table.release(testAddress(1000)));
    try std.testing.expectEqual(@as(usize, 0), table.live);
    try std.testing.expect(!table.release(testAddress(1000)));

    try std.testing.expect((try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)) != null);
}

test "zix webrtc: table, dropDead takes only the connections that finished" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    const alive = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    const doomed = (try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)).?;

    // Its idle deadline passes, which is what ends a peer that stopped speaking.
    _ = doomed.tick(30_000);

    try std.testing.expectEqual(@as(usize, 1), table.dropDead());
    try std.testing.expectEqual(@as(usize, 1), table.live);
    try std.testing.expectEqual(alive, table.find(testAddress(1000)).?);
    try std.testing.expect(table.find(testAddress(1001)) == null);
}

test "zix webrtc: table, the earliest deadline is the soonest across every peer" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    _ = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 5_000)).?;
    _ = (try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 1_000)).?;

    // Both are counting down their idle window, so the older peer expires first.
    try std.testing.expectEqual(@as(?u64, 31_000), table.earliestDeadline());
}

test "zix webrtc: table, the iterator walks every peer and skips the gaps" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    _ = (try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)).?;
    _ = (try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)).?;
    _ = (try table.acquire(testAddress(1002), try testOptions(), testSecrets(), 0)).?;
    _ = table.release(testAddress(1001));

    var seen: usize = 0;
    var walk = table.iterator();
    while (walk.next()) |_| seen += 1;

    try std.testing.expectEqual(@as(usize, 2), seen);
}

test "zix webrtc: table, a zero ceiling still holds one peer rather than none" {
    var table = try Table.init(std.testing.allocator, 0);
    defer table.deinit();

    try std.testing.expect((try table.acquire(testAddress(1000), try testOptions(), testSecrets(), 0)) != null);
    try std.testing.expect((try table.acquire(testAddress(1001), try testOptions(), testSecrets(), 0)) == null);
}
