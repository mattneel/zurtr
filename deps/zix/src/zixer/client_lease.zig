//! zixer client leg: what one accepted connection holds while an edge serves it

const std = @import("std");
const zix = @import("zix");

const client_admit = @import("client_admit.zig");
const deadline_table = @import("deadline_table.zig");

const monotonic_clock = zix.utils.monotonic_clock;

/// One connection's lease on the site's client bound: the slot it took, and the
/// budget every exchange over it is measured against.
///
/// Note:
/// - A site with no bound leases nothing. Every call below returns before it
///   reads a clock or touches a table, so an unbounded site pays nothing at all
///   for a bound it never asked for.
/// - The lease belongs to the one thread serving the connection, and only that
///   thread calls these. A sweeper reaches the same slot through the table
///   instead, which is where the two are kept apart.
/// - Every call is safe on a lease that holds nothing, so an edge unwinding
///   through several paths never has to ask which one it is on.
pub const Lease = struct {
    io: std.Io = undefined,
    /// The site's table, null on a site that runs no bound.
    table: ?*deadline_table.Table = null,
    /// How long one exchange over this connection may take.
    budget_ms: u32 = 0,
    /// The slot this connection holds, null when nothing is tracked.
    ticket: ?deadline_table.Ticket = null,

    /// A lease over nothing, for an edge with no table behind it.
    pub const none: Lease = .{};

    /// Take a slot for a connection the edge has just accepted.
    ///
    /// Note:
    /// - Call this before anything else the connection would cost: a refused
    ///   connection should not have bought a buffer, a handshake, or a read.
    /// - The refusal is the caller's to write, in whatever framing its clients
    ///   speak, and the caller closes either way.
    ///
    /// Param:
    /// table - ?*deadline_table.Table (the site's table, null when it runs no bound)
    /// io - std.Io
    /// handle - std.posix.socket_t (the accepted socket, from stream.socket.handle)
    /// budget_ms - u32 (the site's resolved client bound)
    ///
    /// Return:
    /// - Lease, which release owes back even when it holds nothing
    /// - null when every slot is in use, and the connection is owed a refusal
    pub fn open(table: ?*deadline_table.Table, io: std.Io, handle: std.posix.socket_t, budget_ms: u32) ?Lease {
        const site_table = table orelse return none;

        return switch (client_admit.admit(site_table, io, handle, budget_ms)) {
            .UNBOUND => none,
            .TAKEN => |ticket| .{ .io = io, .table = site_table, .budget_ms = budget_ms, .ticket = ticket },
            .FULL => null,
        };
    }

    /// Whether this connection is tracked at all.
    pub fn bounded(lease: *const Lease) bool {
        return lease.ticket != null;
    }

    /// Start the budget again for the exchange about to run.
    ///
    /// Note:
    /// - Every request on a kept-alive connection arms its own, so a client
    ///   that keeps asking is never cut for the age of its connection. What
    ///   the budget bounds is one exchange, not one connection.
    pub fn armRequest(lease: *Lease) void {
        const table = lease.table orelse return;
        const ticket = lease.ticket orelse return;

        _ = table.rearm(ticket, client_admit.deadlineFrom(monotonic_clock.nowMs(lease.io), lease.budget_ms));
    }

    /// Take the deadline off an exchange that turned into a stream, and keep
    /// the slot.
    ///
    /// Note:
    /// - A tunnel or an event stream is meant to sit silent for as long as its
    ///   protocol needs, so a budget over one would cut it working as designed.
    ///   The slot stays taken, so a held stream still counts against the site's
    ///   connection limit.
    /// - armRequest puts the connection back under a budget once the stream
    ///   ends, which is what a kept-alive connection does on its next request.
    pub fn holdStream(lease: *Lease) void {
        const table = lease.table orelse return;
        const ticket = lease.ticket orelse return;

        _ = table.hold(ticket);
    }

    /// Give the slot back. A second call does nothing.
    pub fn release(lease: *Lease) void {
        const table = lease.table orelse return;
        const ticket = lease.ticket orelse return;

        table.release(ticket);
        lease.ticket = null;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A stand-in socket for the tests below. The table stores the handle and never
/// acts on it here, so no real socket has to exist.
fn testHandle(seed: usize) std.posix.socket_t {
    if (comptime @typeInfo(std.posix.socket_t) == .pointer) return @ptrFromInt(seed + 1);

    return @intCast(seed + 1);
}

test "zix zixer: client lease, a site with no bound leases nothing" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var lease = Lease.open(null, io, testHandle(1), 30_000).?;
    try testing.expect(!lease.bounded());

    // None of these may reach for a table that is not there.
    lease.armRequest();
    lease.holdStream();
    lease.release();
    lease.release();

    // A site whose bound is off carries a table, and it tracks nothing either.
    var off = deadline_table.Table.off;
    var off_lease = Lease.open(&off, io, testHandle(2), 30_000).?;
    try testing.expect(!off_lease.bounded());
    off_lease.release();
}

test "zix zixer: client lease, a bounded site takes a slot and gives it back" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 2);
    defer table.deinit(testing.allocator);

    var lease = Lease.open(&table, io, testHandle(1), 30_000).?;
    try testing.expect(lease.bounded());
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    lease.release();
    try testing.expectEqual(@as(usize, 0), table.liveCount());

    // The defer of an edge that already handed the slot back must not put it on
    // the free list a second time.
    lease.release();
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    try testing.expect(!lease.bounded());
}

test "zix zixer: client lease, every slot in use refuses the lease" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    var first = Lease.open(&table, io, testHandle(1), 30_000).?;

    // The flood case: the caller owes this one a refusal, in its own framing.
    try testing.expect(Lease.open(&table, io, testHandle(2), 30_000) == null);

    first.release();
    var second = Lease.open(&table, io, testHandle(2), 30_000).?;
    try testing.expect(second.bounded());
    second.release();
}

test "zix zixer: client lease, an armed request is past due only after its budget" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    var lease = Lease.open(&table, io, testHandle(1), 60_000).?;
    defer lease.release();

    lease.armRequest();
    const armed_at = monotonic_clock.nowMs(io);

    // Well inside the budget, which is where a live exchange sits.
    var inside: u32 = 0;
    try testing.expect(table.borrowExpired(armed_at + 30_000, &inside) == null);

    // Past it, which is what the sweep acts on.
    var outside: u32 = 0;
    const expired = table.borrowExpired(armed_at + 61_000, &outside).?;
    try testing.expectEqual(testHandle(1), expired.handle);
    table.endBorrow(expired.ticket);
}

test "zix zixer: client lease, a held stream survives every sweep and comes back armed" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    var lease = Lease.open(&table, io, testHandle(1), 1).?;
    defer lease.release();

    // A one millisecond budget is long past due by the largest stamp the clock
    // can hold, so only the hold can be what keeps this connection alive.
    lease.holdStream();

    var held: u32 = 0;
    try testing.expect(table.borrowExpired(std.math.maxInt(i64), &held) == null);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // The stream ended, so the next request over this connection is bounded
    // again.
    lease.armRequest();

    var after: u32 = 0;
    const expired = table.borrowExpired(monotonic_clock.nowMs(io) + 1_000, &after).?;
    table.endBorrow(expired.ticket);
}
