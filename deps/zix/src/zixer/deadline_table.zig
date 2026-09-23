//! zixer client leg: the slot table that says which connection is over its budget
//!
//! What:
//! - A fixed array per site, sized once at site start. Nothing allocates per connection, and a
//!   sweep that finds nothing past due writes nothing at all. The table decides which connection
//!   ran out of time, the caller decides what to do about it, so no timeout logic ever has to live
//!   inside a dispatch loop.
//!
//! Note:
//! - Every owner change goes through ARMING, and a sweeper acts on nothing but ARMED. That one rule
//!   keeps an owner and a sweeper off the same slot without either holding a lock across a syscall.
//! - SWEEPING is the guard against a recycled descriptor. Without it a sweeper can pick a
//!   descriptor to act on, lose the processor, and wake to find the owner closed it and the kernel
//!   handed the same number to a different connection. A release waits out a running sweep, so the
//!   descriptor cannot be closed under one.
//! - The generation is the other half. A ticket kept past its release names a slot that has moved
//!   on, so a late change is refused instead of landing on whoever holds the slot now.
//! - Deadlines are absolute stamps from utils.monotonic_clock. A wall-clock stamp would move every
//!   live bound in the process the moment the system time steps.

const std = @import("std");

/// Most connections one site may track at once. The table is allocated once at site start, so this
/// is what bounds that allocation.
pub const MAX_SLOTS: usize = 65_536;

/// Connections a site tracks when it turns the bound on without naming a number. Well past what one
/// box serves at once with a thread per connection, so the ceiling is reached by a flood and not by
/// ordinary traffic.
pub const DEFAULT_CONN_LIMIT: usize = 4096;

/// Longest client bound a site may configure. A connection meant to outlive an hour is a stream, and
/// hold() is what a stream uses instead of a budget.
pub const MAX_TIMEOUT_MS: u32 = 3_600_000;

/// The deadline of a slot that is held rather than timed. Nothing is ever past it.
pub const NEVER_MS: i64 = std.math.maxInt(i64);

/// Empty-list marker for the free list. A real index can never reach it: MAX_SLOTS bounds the array
/// far under this.
const NIL: u32 = std.math.maxInt(u32);

/// The two values one site runs the client bound with, already resolved from the site file and the
/// main.cfg defaults.
///
/// Note:
/// - conn_limit only means anything while timeout_ms is above 0. A site with no bound tracks no
///   connection, so it needs no slot and never refuses one.
pub const Settings = struct {
    /// How long one client exchange may take. 0 is the bound off, which is what a site that never
    /// asked for one gets.
    timeout_ms: u32 = 0,
    /// Connections this site may track at once. The table is this many slots, and a connection
    /// arriving with every slot taken is refused rather than served unbounded.
    conn_limit: usize = DEFAULT_CONN_LIMIT,

    /// Whether the bound does anything at all.
    pub fn armed(settings: Settings) bool {
        return settings.timeout_ms > 0;
    }

    /// Slots the table needs for these settings, 0 when the bound is off.
    pub fn capacity(settings: Settings) usize {
        if (!settings.armed()) return 0;

        return settings.conn_limit;
    }
};

/// Whether a configured client bound is one a site may run.
///
/// Note:
/// - 0 is valid and means off, so only the ceiling is checked here.
pub fn timeoutInRange(timeout_ms: u32) bool {
    return timeout_ms <= MAX_TIMEOUT_MS;
}

/// Whether a configured connection count is one a site may track. Zero is refused: a table with no
/// slot would refuse every connection, and turning the bound off is what client_timeout_ms is for.
pub fn connLimitInRange(conn_limit: usize) bool {
    return conn_limit >= 1 and conn_limit <= MAX_SLOTS;
}

/// The site file's values over the daemon defaults, each null falling back.
///
/// Note:
/// - Every input already passed validation, so none can be out of range. Clamping anyway keeps a
///   caller that skipped validation (a test rig, a future caller) inside what the table can hold.
///
/// Param:
/// site_timeout_ms - ?u32 (the site file value, null when it names none)
/// site_conn_limit - ?usize (same)
/// daemon - Settings (the main.cfg values)
///
/// Return:
/// - Settings with both fields inside their range
pub fn resolve(site_timeout_ms: ?u32, site_conn_limit: ?usize, daemon: Settings) Settings {
    return .{
        .timeout_ms = @min(site_timeout_ms orelse daemon.timeout_ms, MAX_TIMEOUT_MS),
        .conn_limit = std.math.clamp(site_conn_limit orelse daemon.conn_limit, 1, MAX_SLOTS),
    };
}

/// Where one slot stands. A sweeper reads this before anything else and acts on nothing but ARMED,
/// which is what keeps it off a slot an owner is part way through.
const SlotState = enum(u8) {
    /// On the free list. No connection, no deadline.
    FREE,
    /// An owner is changing the slot. A sweeper skips it and finds it again next tick.
    ARMING,
    /// A live connection with a deadline a sweeper may act on.
    ARMED,
    /// A sweeper holds it. An owner waiting to change it spins here.
    SWEEPING,
};

/// One tracked connection: written by its owner under ARMING, read by a sweeper under SWEEPING.
const Slot = struct {
    state: std.atomic.Value(SlotState) = .init(.FREE),
    /// When this connection is over its budget. The sweep walk reads it without any lock, so it is
    /// atomic even though every write to it is already exclusive.
    deadline_ms: std.atomic.Value(i64) = .init(NEVER_MS),
    /// Bumped by every release, so a ticket outlives its slot by nothing.
    generation: std.atomic.Value(u32) = .init(0),
    /// The socket to act on. Never read outside SWEEPING.
    handle: std.posix.socket_t = undefined,
    /// Times this connection has been handed to a sweeper.
    cut_count: u16 = 0,
    /// Free list link.
    next: u32 = NIL,
};

/// One owner's claim on a slot, good until release.
pub const Ticket = struct {
    index: u32,
    generation: u32,
};

/// What claiming a slot gave the caller.
pub const Claim = union(enum) {
    /// The site runs no client bound, so nothing is tracked and nothing is owed.
    UNBOUND,
    /// The slot is the caller's, and release owes it back.
    TAKEN: Ticket,
    /// Every slot is in use. Serving the connection unbounded is wrong in exactly the moment the
    /// bound matters, so the caller refuses it instead.
    FULL,
};

/// A slot a sweeper is holding, and what it needs to act on the connection.
pub const Expired = struct {
    ticket: Ticket,
    handle: std.posix.socket_t,
    /// Times this connection has been handed out, this one included. 1 is the first.
    cut_count: u16,
};

/// Whether a deadline is still ahead of the stamp being swept at.
///
/// Note:
/// - NEVER_MS is checked on its own so a held connection is never cut, not even by a sweep at the
///   largest stamp the clock can hold.
fn isFuture(deadline_ms: i64, now_ms: i64) bool {
    return deadline_ms == NEVER_MS or deadline_ms > now_ms;
}

/// One site's deadline table, shared by every worker on that site.
///
/// Note:
/// - A short spinlock guards the free list only. Claim and release each hold it for a handful of
///   pointer writes, and the sweep walk never takes it at all.
/// - Nothing here ever blocks on the network or allocates. The one wait in the structure is an
///   owner waiting out a sweeper, which covers a single shutdown call.
pub const Table = struct {
    slots: []Slot,
    lock_flag: std.atomic.Value(bool) = .init(false),
    free_head: u32 = NIL,
    live: usize = 0,

    /// A table that tracks nothing and owns nothing, for a site with no client bound. deinit on it
    /// frees an empty slice, which is legal.
    pub const off: Table = .{ .slots = &.{} };

    /// Build one site's table.
    ///
    /// Note:
    /// - A capacity past MAX_SLOTS is clamped rather than refused, so a caller that skipped
    ///   validation still lands inside what the table can hold.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the slots, outlives the site)
    /// capacity - usize (connections tracked at once, 0 is the bound off)
    ///
    /// Return:
    /// - Table, off when capacity is 0
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Table {
        if (capacity == 0) return off;

        const room = @min(capacity, MAX_SLOTS);
        const slots = try allocator.alloc(Slot, room);

        // Threaded back to front so index 0 is handed out first, which keeps a slot dump in the
        // order a reader expects.
        var free_head: u32 = NIL;
        var index = room;
        while (index > 0) {
            index -= 1;
            slots[index] = .{ .next = free_head };
            free_head = @intCast(index);
        }

        return .{ .slots = slots, .free_head = free_head };
    }

    pub fn deinit(table: *Table, allocator: std.mem.Allocator) void {
        allocator.free(table.slots);
    }

    /// Whether the table tracks anything at all.
    pub fn armed(table: *const Table) bool {
        return table.slots.len > 0;
    }

    /// Take a slot for one connection.
    ///
    /// Note:
    /// - deadline_ms is an absolute monotonic_clock.nowMs stamp, not a budget. Passing NEVER_MS
    ///   claims a slot that is held from the start.
    ///
    /// Param:
    /// handle - std.posix.socket_t (the connection's socket, from stream.socket.handle)
    /// deadline_ms - i64 (the stamp this connection is over its budget at)
    ///
    /// Return:
    /// - UNBOUND when the site runs no bound, and nothing is owed
    /// - TAKEN with the ticket release owes back
    /// - FULL when every slot is in use
    pub fn claim(table: *Table, handle: std.posix.socket_t, deadline_ms: i64) Claim {
        if (!table.armed()) return .UNBOUND;

        const index = table.takeFreeIndex() orelse return .FULL;

        const slot = &table.slots[index];
        const generation = slot.generation.load(.monotonic);
        slot.handle = handle;
        slot.cut_count = 0;
        slot.deadline_ms.store(deadline_ms, .monotonic);

        // This store publishes the handle and the deadline: a sweeper reads neither until it has
        // seen ARMED.
        slot.state.store(.ARMED, .release);

        return .{ .TAKEN = .{ .index = index, .generation = generation } };
    }

    /// Move a slot's deadline. Every request on a kept-alive connection arms its own.
    ///
    /// Note:
    /// - Waits out a sweep already running on the slot. That sweep is not undone: the connection is
    ///   already ending, and the owner finds out through its own read.
    ///
    /// Param:
    /// ticket - Ticket (from claim)
    /// deadline_ms - i64 (the new absolute stamp)
    ///
    /// Return:
    /// - true when the deadline moved
    /// - false when the ticket no longer names a live slot
    pub fn rearm(table: *Table, ticket: Ticket, deadline_ms: i64) bool {
        if (!table.takeOwnership(ticket)) return false;

        const slot = &table.slots[ticket.index];
        slot.deadline_ms.store(deadline_ms, .monotonic);
        slot.state.store(.ARMED, .release);

        return true;
    }

    /// Drop a slot's deadline and keep the slot, for an exchange that turned into a stream.
    ///
    /// Note:
    /// - A tunnel or an event stream is meant to sit silent for hours, so a deadline over it would
    ///   cut the protocol working as designed. The slot stays claimed so nothing else takes it, and
    ///   rearm puts the connection back under a budget once the stream ends.
    ///
    /// Param:
    /// ticket - Ticket (from claim)
    ///
    /// Return:
    /// - true when the deadline was dropped
    /// - false when the ticket no longer names a live slot
    pub fn hold(table: *Table, ticket: Ticket) bool {
        return table.rearm(ticket, NEVER_MS);
    }

    /// Give a slot back, and make every copy of its ticket stale.
    ///
    /// Note:
    /// - Waits out a sweep already running on the slot, so the owner cannot close a descriptor a
    ///   sweeper is still acting on.
    ///
    /// Param:
    /// ticket - Ticket (from claim)
    ///
    /// Return:
    /// - void
    /// - A ticket that names no live slot is ignored
    pub fn release(table: *Table, ticket: Ticket) void {
        if (!table.takeOwnership(ticket)) return;

        const slot = &table.slots[ticket.index];
        slot.deadline_ms.store(NEVER_MS, .monotonic);
        slot.cut_count = 0;
        slot.generation.store(ticket.generation +% 1, .release);

        table.giveFreeIndex(ticket.index);
    }

    /// Take the next connection that is past its deadline, and hold its slot until endBorrow.
    ///
    /// Note:
    /// - The walk takes no lock and writes nothing until a slot is past due, so a tick that finds
    ///   nothing costs one atomic read per slot.
    /// - The caller owes endBorrow for every slot handed out, on every path. Until then the owner's
    ///   release spins, which is what makes acting on the descriptor safe.
    ///
    /// Param:
    /// now_ms - i64 (a monotonic_clock.nowMs stamp)
    /// cursor - *u32 (walk position, 0 at the start of each tick)
    ///
    /// Return:
    /// - Expired, and the slot is the caller's until endBorrow
    /// - null when the walk reached the end of the table
    pub fn borrowExpired(table: *Table, now_ms: i64, cursor: *u32) ?Expired {
        while (cursor.* < table.slots.len) {
            const index = cursor.*;
            cursor.* += 1;

            const slot = &table.slots[index];
            if (slot.state.load(.acquire) != .ARMED) continue;
            if (isFuture(slot.deadline_ms.load(.monotonic), now_ms)) continue;

            // Losing this exchange means an owner is changing the slot or another sweeper reached
            // it first, and either way it is not this walk's to act on.
            if (slot.state.cmpxchgStrong(.ARMED, .SWEEPING, .acquire, .monotonic) != null) continue;

            // Read again now the slot is held. An owner can move the deadline between the read
            // above and the exchange, and cutting a connection that was just given a fresh budget
            // is the one mistake this table must not make.
            if (isFuture(slot.deadline_ms.load(.monotonic), now_ms)) {
                slot.state.store(.ARMED, .release);
                continue;
            }

            slot.cut_count +|= 1;

            return .{
                .ticket = .{ .index = index, .generation = slot.generation.load(.monotonic) },
                .handle = slot.handle,
                .cut_count = slot.cut_count,
            };
        }

        return null;
    }

    /// Hand a borrowed slot back to its owner.
    ///
    /// Note:
    /// - A second call for the same borrow does nothing, so a caller unwinding through more than
    ///   one path can call it on each without checking.
    ///
    /// Param:
    /// ticket - Ticket (the one borrowExpired handed out)
    ///
    /// Return:
    /// - void
    pub fn endBorrow(table: *Table, ticket: Ticket) void {
        if (ticket.index >= table.slots.len) return;

        const slot = &table.slots[ticket.index];
        _ = slot.state.cmpxchgStrong(.SWEEPING, .ARMED, .release, .monotonic);
    }

    /// Connections tracked right now. For tests and status output.
    pub fn liveCount(table: *Table) usize {
        table.lock();
        defer table.unlock();

        return table.live;
    }

    /// Move a live slot into the caller's hands, waiting out a sweep already running on it.
    ///
    /// Return:
    /// - true with the slot in ARMING, and the caller owes it a state store
    /// - false when the ticket names no live slot of the caller's
    fn takeOwnership(table: *Table, ticket: Ticket) bool {
        if (ticket.index >= table.slots.len) return false;

        const slot = &table.slots[ticket.index];

        while (true) {
            if (slot.generation.load(.acquire) != ticket.generation) return false;

            if (slot.state.cmpxchgStrong(.ARMED, .ARMING, .acquire, .monotonic)) |observed| {
                if (observed != .SWEEPING) return false;

                std.atomic.spinLoopHint();
                continue;
            }

            // The generation cannot move while the slot is held, so this read is the last word on
            // whether the ticket still names the life it was handed out for. Put the slot back
            // exactly as found when it does not, since it belongs to whoever claimed it since.
            if (slot.generation.load(.monotonic) != ticket.generation) {
                slot.state.store(.ARMED, .release);

                return false;
            }

            return true;
        }
    }

    /// Pop a slot off the free list, already moved into the caller's hands.
    fn takeFreeIndex(table: *Table) ?u32 {
        table.lock();
        defer table.unlock();

        const index = table.free_head;
        if (index == NIL) return null;

        const slot = &table.slots[index];
        table.free_head = slot.next;
        slot.next = NIL;
        slot.state.store(.ARMING, .monotonic);
        table.live += 1;

        return index;
    }

    /// Push a held slot back onto the free list, and mark it free to whoever looks.
    fn giveFreeIndex(table: *Table, index: u32) void {
        table.lock();
        defer table.unlock();

        const slot = &table.slots[index];
        slot.next = table.free_head;
        table.free_head = index;
        table.live -= 1;
        slot.state.store(.FREE, .release);
    }

    fn lock(table: *Table) void {
        while (table.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn unlock(table: *Table) void {
        table.lock_flag.store(false, .release);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// A stand-in socket for the tests. The table stores the handle and hands it back, it never acts on
/// it, so no real socket has to exist for any of this.
fn testHandle(seed: usize) std.posix.socket_t {
    if (comptime @typeInfo(std.posix.socket_t) == .pointer) return @ptrFromInt(seed + 1);

    return @intCast(seed + 1);
}

test "zix zixer: deadline table, the bound is off until a timeout names it" {
    const off = Settings{};
    try std.testing.expect(!off.armed());
    try std.testing.expectEqual(@as(usize, 0), off.capacity());

    // The limit alone tracks nothing: without a budget there is no deadline to sweep for.
    const limit_only = Settings{ .conn_limit = 64 };
    try std.testing.expect(!limit_only.armed());
    try std.testing.expectEqual(@as(usize, 0), limit_only.capacity());

    const bounded = Settings{ .timeout_ms = 30_000, .conn_limit = 64 };
    try std.testing.expect(bounded.armed());
    try std.testing.expectEqual(@as(usize, 64), bounded.capacity());
}

test "zix zixer: deadline table, the configured ranges end where the table does" {
    try std.testing.expect(timeoutInRange(0));
    try std.testing.expect(timeoutInRange(MAX_TIMEOUT_MS));
    try std.testing.expect(!timeoutInRange(MAX_TIMEOUT_MS + 1));

    // 0 slots would refuse every connection, which is not what turning a bound off means.
    try std.testing.expect(!connLimitInRange(0));
    try std.testing.expect(connLimitInRange(1));
    try std.testing.expect(connLimitInRange(MAX_SLOTS));
    try std.testing.expect(!connLimitInRange(MAX_SLOTS + 1));
}

test "zix zixer: deadline table, the site file resolves over the daemon default" {
    const daemon = Settings{ .timeout_ms = 30_000, .conn_limit = 1024 };

    const silent = resolve(null, null, daemon);
    try std.testing.expectEqual(@as(u32, 30_000), silent.timeout_ms);
    try std.testing.expectEqual(@as(usize, 1024), silent.conn_limit);

    const named = resolve(5_000, 64, daemon);
    try std.testing.expectEqual(@as(u32, 5_000), named.timeout_ms);
    try std.testing.expectEqual(@as(usize, 64), named.conn_limit);

    // A site turning the bound off while the daemon leaves it on.
    const site_off = resolve(0, null, daemon);
    try std.testing.expect(!site_off.armed());

    // Out of range only reaches here from a caller that skipped validation, and it lands inside
    // what the table can hold rather than allocating past the ceiling.
    const clamped = resolve(MAX_TIMEOUT_MS + 1, MAX_SLOTS + 1, daemon);
    try std.testing.expectEqual(MAX_TIMEOUT_MS, clamped.timeout_ms);
    try std.testing.expectEqual(MAX_SLOTS, clamped.conn_limit);

    const floored = resolve(1_000, 0, daemon);
    try std.testing.expectEqual(@as(usize, 1), floored.conn_limit);
}

test "zix zixer: deadline table, a table with no capacity tracks nothing" {
    var table = try Table.init(std.testing.allocator, 0);
    defer table.deinit(std.testing.allocator);

    try std.testing.expect(!table.armed());
    try std.testing.expectEqual(@as(usize, 0), table.slots.len);
    try std.testing.expectEqual(Claim.UNBOUND, table.claim(testHandle(0), 1000));

    // Nothing was handed out, so nothing can be given back or swept.
    const stale = Ticket{ .index = 0, .generation = 0 };
    table.release(stale);
    try std.testing.expect(!table.rearm(stale, 2000));
    try std.testing.expect(!table.hold(stale));

    var cursor: u32 = 0;
    try std.testing.expect(table.borrowExpired(9000, &cursor) == null);
}

test "zix zixer: deadline table, a claim takes a slot and a release gives it back" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4), table.slots.len);
    try std.testing.expectEqual(@as(usize, 0), table.liveCount());

    const claimed = table.claim(testHandle(1), 5000);
    try std.testing.expect(claimed == .TAKEN);
    try std.testing.expectEqual(@as(usize, 1), table.liveCount());

    // The connection the sweep hands back is the one that was claimed, socket and all.
    var cursor: u32 = 0;
    const expired = table.borrowExpired(5000, &cursor).?;
    try std.testing.expectEqual(testHandle(1), expired.handle);
    try std.testing.expectEqual(@as(u16, 1), expired.cut_count);
    table.endBorrow(expired.ticket);

    table.release(claimed.TAKEN);
    try std.testing.expectEqual(@as(usize, 0), table.liveCount());
}

test "zix zixer: deadline table, every slot in use refuses the claim" {
    var table = try Table.init(std.testing.allocator, 2);
    defer table.deinit(std.testing.allocator);

    const first = table.claim(testHandle(1), 1000);
    const second = table.claim(testHandle(2), 1000);
    try std.testing.expect(first == .TAKEN);
    try std.testing.expect(second == .TAKEN);

    try std.testing.expectEqual(Claim.FULL, table.claim(testHandle(3), 1000));

    // A slot given back is the one the next claim takes.
    table.release(first.TAKEN);
    try std.testing.expect(table.claim(testHandle(3), 1000) == .TAKEN);
    try std.testing.expectEqual(@as(usize, 2), table.liveCount());
}

test "zix zixer: deadline table, a capacity past the ceiling is clamped" {
    var table = try Table.init(std.testing.allocator, MAX_SLOTS + 512);
    defer table.deinit(std.testing.allocator);

    try std.testing.expectEqual(MAX_SLOTS, table.slots.len);
}

test "zix zixer: deadline table, a released ticket moves nothing" {
    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit(std.testing.allocator);

    const first = table.claim(testHandle(1), 1000).TAKEN;
    table.release(first);

    try std.testing.expect(!table.rearm(first, 9000));
    try std.testing.expect(!table.hold(first));

    // The same slot, a new life: the old ticket names neither.
    const second = table.claim(testHandle(2), 1000).TAKEN;
    try std.testing.expectEqual(first.index, second.index);
    try std.testing.expect(first.generation != second.generation);
    try std.testing.expect(!table.rearm(first, 9000));

    // The stale call above left the new owner's deadline where it was.
    var cursor: u32 = 0;
    const expired = table.borrowExpired(1000, &cursor).?;
    try std.testing.expectEqual(testHandle(2), expired.handle);
    table.endBorrow(expired.ticket);

    // A second release of a ticket already given back must not put the slot on the free list
    // twice, which would hand one connection's slot to two owners.
    table.release(first);
    try std.testing.expectEqual(@as(usize, 1), table.liveCount());
    try std.testing.expectEqual(Claim.FULL, table.claim(testHandle(3), 1000));
}

test "zix zixer: deadline table, the sweep hands out only what is past due" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit(std.testing.allocator);

    const early = table.claim(testHandle(1), 100).TAKEN;
    _ = table.claim(testHandle(2), 900);
    _ = table.claim(testHandle(3), NEVER_MS);

    var cursor: u32 = 0;
    const expired = table.borrowExpired(500, &cursor).?;
    try std.testing.expectEqual(early.index, expired.ticket.index);
    table.endBorrow(expired.ticket);

    // The rest of the walk finds nothing: one is inside its budget, one is held, one was never
    // claimed at all.
    try std.testing.expect(table.borrowExpired(500, &cursor) == null);
}

test "zix zixer: deadline table, the sweep acts on the stamp, not after it" {
    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit(std.testing.allocator);

    _ = table.claim(testHandle(1), 1000);

    var one_before: u32 = 0;
    try std.testing.expect(table.borrowExpired(999, &one_before) == null);

    var on_the_stamp: u32 = 0;
    const expired = table.borrowExpired(1000, &on_the_stamp).?;
    table.endBorrow(expired.ticket);
}

test "zix zixer: deadline table, one tick hands a slot out once" {
    var table = try Table.init(std.testing.allocator, 3);
    defer table.deinit(std.testing.allocator);

    _ = table.claim(testHandle(1), 100);
    _ = table.claim(testHandle(2), 100);
    _ = table.claim(testHandle(3), 100);

    var seen = [_]bool{ false, false, false };
    var cursor: u32 = 0;
    var handed: usize = 0;
    while (table.borrowExpired(500, &cursor)) |expired| {
        try std.testing.expect(!seen[expired.ticket.index]);

        seen[expired.ticket.index] = true;
        handed += 1;
        table.endBorrow(expired.ticket);
    }

    try std.testing.expectEqual(@as(usize, 3), handed);
}

test "zix zixer: deadline table, a rearmed connection is left alone" {
    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit(std.testing.allocator);

    const ticket = table.claim(testHandle(1), 1000).TAKEN;

    // The next request on a kept-alive connection arrived, so the budget starts again from here. A
    // deadline armed once per connection would have cut this one instead.
    try std.testing.expect(table.rearm(ticket, 4000));

    var inside_budget: u32 = 0;
    try std.testing.expect(table.borrowExpired(2000, &inside_budget) == null);

    var past_budget: u32 = 0;
    const expired = table.borrowExpired(4000, &past_budget).?;
    table.endBorrow(expired.ticket);
}

test "zix zixer: deadline table, a held connection survives every sweep and comes back under a budget" {
    var table = try Table.init(std.testing.allocator, 2);
    defer table.deinit(std.testing.allocator);

    const ticket = table.claim(testHandle(1), 1000).TAKEN;
    try std.testing.expect(table.hold(ticket));

    // A tunnel is meant to sit silent for hours, so a hundred ticks a minute apart have to find it
    // every time and act on it none.
    var tick: i64 = 0;
    while (tick < 100) : (tick += 1) {
        var cursor: u32 = 0;
        try std.testing.expect(table.borrowExpired(tick * 60_000, &cursor) == null);
    }

    // The slot stayed claimed the whole time, so nothing else could take it.
    try std.testing.expectEqual(@as(usize, 1), table.liveCount());

    // The stream ended, so the connection goes back under a budget.
    try std.testing.expect(table.rearm(ticket, 6_100_000));

    var cursor: u32 = 0;
    const expired = table.borrowExpired(6_100_000, &cursor).?;
    try std.testing.expectEqual(ticket.index, expired.ticket.index);
    table.endBorrow(expired.ticket);
}

test "zix zixer: deadline table, a slot handed out twice counts both times" {
    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit(std.testing.allocator);

    const ticket = table.claim(testHandle(1), 1000).TAKEN;

    var first_tick: u32 = 0;
    const once = table.borrowExpired(2000, &first_tick).?;
    try std.testing.expectEqual(@as(u16, 1), once.cut_count);
    table.endBorrow(once.ticket);

    // Still past due on the next tick, and the count is what tells a caller to act harder the
    // second time.
    var second_tick: u32 = 0;
    const twice = table.borrowExpired(2000, &second_tick).?;
    try std.testing.expectEqual(@as(u16, 2), twice.cut_count);
    table.endBorrow(twice.ticket);

    // A new connection on the same slot starts from nothing.
    table.release(ticket);
    _ = table.claim(testHandle(2), 1000);

    var third_tick: u32 = 0;
    const fresh = table.borrowExpired(2000, &third_tick).?;
    try std.testing.expectEqual(@as(u16, 1), fresh.cut_count);
    table.endBorrow(fresh.ticket);
}

test "zix zixer: deadline table, a release waits out a sweep already running" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try Table.init(std.testing.allocator, 1);
    defer table.deinit(std.testing.allocator);

    const ticket = table.claim(testHandle(1), 1000).TAKEN;

    var cursor: u32 = 0;
    const expired = table.borrowExpired(1000, &cursor).?;

    var entered: std.atomic.Value(bool) = .init(false);
    var returned: std.atomic.Value(bool) = .init(false);

    const Owner = struct {
        fn run(shared: *Table, owned: Ticket, start: *std.atomic.Value(bool), done: *std.atomic.Value(bool)) void {
            start.store(true, .release);
            shared.release(owned);
            done.store(true, .release);
        }
    };

    const owner = try std.Thread.spawn(.{}, Owner.run, .{ &table, ticket, &entered, &returned });
    while (!entered.load(.acquire)) std.atomic.spinLoopHint();

    // The descriptor has to stay open while the sweeper acts on it, so the release cannot finish
    // here. This is the guard that stops a cut landing on a recycled descriptor.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    try std.testing.expect(!returned.load(.acquire));

    table.endBorrow(expired.ticket);
    owner.join();

    try std.testing.expect(returned.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), table.liveCount());
}

test "zix zixer: deadline table, churn from many threads leaves the table idle" {
    var table = try Table.init(std.testing.allocator, 32);
    defer table.deinit(std.testing.allocator);

    var stop: std.atomic.Value(bool) = .init(false);

    const Owner = struct {
        fn run(shared: *Table, seed: usize, rounds: usize) void {
            for (0..rounds) |round| {
                switch (shared.claim(testHandle(seed), @intCast(round))) {
                    .TAKEN => |ticket| {
                        _ = shared.rearm(ticket, @intCast(round + 1));
                        _ = shared.hold(ticket);
                        _ = shared.rearm(ticket, 0);
                        shared.release(ticket);
                    },
                    .FULL => {},
                    .UNBOUND => unreachable,
                }
            }
        }
    };

    const Sweeper = struct {
        fn run(shared: *Table, halt: *std.atomic.Value(bool)) void {
            while (!halt.load(.acquire)) {
                var cursor: u32 = 0;
                while (shared.borrowExpired(std.math.maxInt(i64), &cursor)) |expired| {
                    shared.endBorrow(expired.ticket);
                }
            }
        }
    };

    var owners: [8]std.Thread = undefined;
    for (&owners, 0..) |*thread, seed| thread.* = try std.Thread.spawn(.{}, Owner.run, .{ &table, seed, @as(usize, 2000) });
    const sweeper = try std.Thread.spawn(.{}, Sweeper.run, .{ &table, &stop });

    for (owners) |thread| thread.join();
    stop.store(true, .release);
    sweeper.join();

    // Every claim was matched by a release, so every slot is back on the free list exactly once and
    // none of them is stuck part way through a change.
    try std.testing.expectEqual(@as(usize, 0), table.liveCount());

    var free_slots: usize = 0;
    var index = table.free_head;
    while (index != NIL) : (free_slots += 1) index = table.slots[index].next;
    try std.testing.expectEqual(table.slots.len, free_slots);

    for (table.slots) |*slot| try std.testing.expectEqual(SlotState.FREE, slot.state.load(.acquire));
}
