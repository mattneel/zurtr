//! Shared connection pool: thread-safe acquire/release with an optional
//! bounded FIFO waiter queue (the process-queue semantic at the pool level).
//!
//! Note:
//! - The pool is safe to share across threads: a spinlock guards the slot
//!   and waiter bookkeeping (uncontended cost is one atomic swap), parked
//!   acquires sleep on a futex until a connection is handed over.
//! - config.process_queue_len is the waiter bound: 0 = off (acquire on a
//!   fully-held pool sheds immediately with error.PostgrezPoolExhausted), N parks
//!   up to N acquires FIFO and hands each released connection directly to
//!   the oldest waiter. Beyond N acquire sheds with error.PostgrezPoolBusy.
//! - Parking blocks the calling OS thread: another thread must release or
//!   discard for a parked acquire to resume.
//! - Slots connect lazily on first acquire and reconnect (with the config
//!   retry knobs) after a discard, so a killed connection heals on the next
//!   acquire. The connect itself runs outside the lock.
//! - acquire/release are explicit: release returns the connection, discard
//!   destroys a broken one and frees its slot for reconnect.

const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");
const conn_mod = @import("conn.zig");

const Conn = conn_mod.Conn;

/// One parked acquire. Lives on the parked caller's stack, linked FIFO.
const Waiter = struct {
    /// Futex word: 0 parked, 1 granted.
    ready: std.atomic.Value(u32) = .init(0),
    /// The connection handed over by release. Null grant = an empty slot
    /// (grant_slot) reserved for this waiter, who connects it itself.
    grant_conn: ?*Conn = null,
    grant_slot: usize = 0,
    next: ?*Waiter = null,
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: lib.Config,
    slots: []?*Conn,
    in_use: []bool,
    lock_flag: std.atomic.Value(bool) = .init(false),
    waiter_head: ?*Waiter = null,
    waiter_tail: ?*Waiter = null,
    waiter_count: usize = 0,

    const Self = @This();

    /// Param:
    /// config - lib.Config (pool_size, process_queue_len, retry_max, retry_delay_ms drive the pool)
    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: lib.Config) !Self {
        if (config.pool_size == 0) return error.PostgrezPoolSizeNotConfigured;

        const slots = try allocator.alloc(?*Conn, config.pool_size);
        errdefer allocator.free(slots);
        @memset(slots, null);

        const in_use = try allocator.alloc(bool, config.pool_size);
        @memset(in_use, false);

        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .slots = slots,
            .in_use = in_use,
        };
    }

    /// Callers must be quiescent: no acquire in flight, no parked waiter.
    pub fn deinit(self: *Self) void {
        for (self.slots) |maybe_conn| {
            if (maybe_conn) |pooled| pooled.deinit();
        }
        self.allocator.free(self.slots);
        self.allocator.free(self.in_use);
    }

    // --------------------------------------------------------- //

    /// Take a connection. An idle one is reused, an empty slot connects
    /// (with retries), a fully-held pool parks the caller FIFO when
    /// config.process_queue_len allows it.
    ///
    /// Return:
    /// - *Conn, give it back with release (or discard when broken)
    /// - error.PostgrezPoolExhausted when every slot is held and parking is off
    /// - error.PostgrezPoolBusy when process_queue_len waiters are already parked
    /// - connect errors after retry_max + 1 attempts
    pub fn acquire(self: *Self) !*Conn {
        self.lock();

        // a parked waiter has FIFO priority: the direct path only runs
        // when nobody is ahead
        if (self.waiter_count == 0) {
            // idle connected slot first
            for (self.slots, self.in_use, 0..) |maybe_conn, used, index| {
                if (!used and maybe_conn != null) {
                    self.in_use[index] = true;
                    self.unlock();

                    return maybe_conn.?;
                }
            }

            // empty slot: reserve it, connect outside the lock
            for (self.slots, self.in_use, 0..) |maybe_conn, used, index| {
                if (!used and maybe_conn == null) {
                    self.in_use[index] = true;
                    self.unlock();

                    return self.connectReserved(index);
                }
            }
        }

        if (self.config.process_queue_len == 0) {
            self.unlock();

            return error.PostgrezPoolExhausted;
        }
        if (self.waiter_count >= self.config.process_queue_len) {
            self.unlock();

            return error.PostgrezPoolBusy;
        }

        var waiter = Waiter{};
        self.enqueueWaiter(&waiter);
        self.unlock();

        while (waiter.ready.load(.acquire) == 0) futexWait(self.io, &waiter.ready);

        if (waiter.grant_conn) |granted| return granted;

        return self.connectReserved(waiter.grant_slot);
    }

    /// Return a healthy connection: handed directly to the oldest parked
    /// waiter when one exists, back to its slot otherwise.
    pub fn release(self: *Self, pooled: *Conn) void {
        self.lock();
        const maybe_waiter = self.dequeueWaiter();
        if (maybe_waiter == null) {
            for (self.slots, 0..) |maybe_conn, index| {
                if (maybe_conn == pooled) {
                    self.in_use[index] = false;

                    break;
                }
            }
        }
        self.unlock();

        // direct handoff: the slot stays held, ownership moves over
        if (maybe_waiter) |waiter| grantConn(self.io, waiter, pooled);
    }

    /// Destroy a broken connection and free its slot. With a parked waiter
    /// the freed slot is reserved for it (the waiter reconnects), otherwise
    /// the next acquire reconnects the slot.
    pub fn discard(self: *Self, pooled: *Conn) void {
        self.lock();
        for (self.slots, 0..) |maybe_conn, index| {
            if (maybe_conn == pooled) {
                self.slots[index] = null;

                const maybe_waiter = self.dequeueWaiter();
                if (maybe_waiter == null) self.in_use[index] = false;
                self.unlock();

                pooled.deinit();
                if (maybe_waiter) |waiter| grantSlot(self.io, waiter, index);

                return;
            }
        }
        self.unlock();
    }

    /// Idle connected slots (diagnostics).
    pub fn idleCount(self: *Self) usize {
        self.lock();
        defer self.unlock();

        var count: usize = 0;
        for (self.slots, self.in_use) |maybe_conn, used| {
            if (!used and maybe_conn != null) count += 1;
        }

        return count;
    }

    /// Acquires parked on the waiter queue (diagnostics).
    pub fn waiterCount(self: *Self) usize {
        self.lock();
        defer self.unlock();

        return self.waiter_count;
    }

    // --------------------------------------------------------- //

    /// Connect a reserved empty slot outside the lock. On failure the
    /// reservation moves to the oldest parked waiter (who retries the
    /// connect) or is freed.
    fn connectReserved(self: *Self, index: usize) !*Conn {
        const connected = self.connectWithRetry() catch |err| {
            self.lock();
            const maybe_waiter = self.dequeueWaiter();
            if (maybe_waiter == null) self.in_use[index] = false;
            self.unlock();

            if (maybe_waiter) |waiter| grantSlot(self.io, waiter, index);

            return err;
        };

        self.lock();
        self.slots[index] = connected;
        self.unlock();

        return connected;
    }

    fn connectWithRetry(self: *Self) !*Conn {
        var attempt: u32 = 0;

        while (true) {
            const result = Conn.connect(self.allocator, self.io, self.config);

            if (result) |connected| {
                return connected;
            } else |err| {
                if (attempt >= self.config.retry_max) return err;
                attempt += 1;

                self.io.sleep(.fromMilliseconds(self.config.retry_delay_ms), .awake) catch return err;
            }
        }
    }

    // --------------------------------------------------------- //

    fn lock(self: *Self) void {
        while (self.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Self) void {
        self.lock_flag.store(false, .release);
    }

    fn enqueueWaiter(self: *Self, waiter: *Waiter) void {
        if (self.waiter_tail) |tail| {
            tail.next = waiter;
        } else {
            self.waiter_head = waiter;
        }
        self.waiter_tail = waiter;
        self.waiter_count += 1;
    }

    fn dequeueWaiter(self: *Self) ?*Waiter {
        const waiter = self.waiter_head orelse return null;

        self.waiter_head = waiter.next;
        if (self.waiter_head == null) self.waiter_tail = null;
        self.waiter_count -= 1;

        return waiter;
    }
};

// --------------------------------------------------------- //

fn grantConn(io: std.Io, waiter: *Waiter, granted: *Conn) void {
    waiter.grant_conn = granted;
    waiter.ready.store(1, .release);
    futexWake(io, &waiter.ready);
}

fn grantSlot(io: std.Io, waiter: *Waiter, index: usize) void {
    waiter.grant_slot = index;
    waiter.ready.store(1, .release);
    futexWake(io, &waiter.ready);
}

/// Park the calling thread while the word is 0. Linux keeps the raw futex
/// fast path, other targets park through the io backend.
fn futexWait(io: std.Io, word: *std.atomic.Value(u32)) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.futex_4arg(&word.raw, .{ .cmd = .WAIT, .private = true }, 0, null);

        return;
    }

    io.futexWaitUncancelable(u32, &word.raw, 0);
}

/// Wake one thread parked on the word. Same branch split as futexWait.
fn futexWake(io: std.Io, word: *std.atomic.Value(u32)) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.futex_3arg(&word.raw, .{ .cmd = .WAKE, .private = true }, 1);

        return;
    }

    io.futexWake(u32, &word.raw, 1);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez: pool init validates pool_size and starts empty" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.PostgrezPoolSizeNotConfigured, Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 0,
    }));

    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 3,
    });
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 3), pool.slots.len);
    try testing.expectEqual(@as(usize, 0), pool.idleCount());
    try testing.expectEqual(@as(usize, 0), pool.waiterCount());
}

test "postgrez: pool acquire retries then reports the connect error" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // port 1 on loopback: nothing listens, every attempt is refused fast
    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .ip = "127.0.0.1",
        .port = 1,
        .pool_size = 1,
        .retry_max = 2,
        .retry_delay_ms = 1,
    });
    defer pool.deinit();

    // windows region: zig std's connect path leaves NTSTATUS
    // CONNECTION_REFUSED (0xc0000236) unmapped, so the refused
    // connect surfaces as error.Unexpected there.
    if (builtin.os.tag == .windows) {
        try testing.expectError(error.Unexpected, pool.acquire());
    } else {
        try testing.expectError(error.ConnectionRefused, pool.acquire());
    }
    try testing.expectEqual(@as(usize, 0), pool.idleCount());
}

test "postgrez: pool bookkeeping cycles a slot through release and discard" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 2,
    });
    defer pool.deinit();

    // hand-plant a connection value to test the bookkeeping paths without a
    // live server (never dereferenced through these calls)
    var fake_conn: Conn = undefined;
    pool.slots[0] = &fake_conn;
    pool.in_use[0] = true;

    try testing.expectEqual(@as(usize, 0), pool.idleCount());

    pool.release(&fake_conn);
    try testing.expectEqual(@as(usize, 1), pool.idleCount());
    try testing.expectEqual(false, pool.in_use[0]);

    const reused = try pool.acquire();
    try testing.expectEqual(@as(*Conn, &fake_conn), reused);
    try testing.expectEqual(true, pool.in_use[0]);

    // clear the planted slot by hand (discard would deinit a real conn)
    pool.slots[0] = null;
    pool.in_use[0] = false;
    try testing.expectEqual(@as(usize, 0), pool.idleCount());
}

test "postgrez: pool fully held sheds when parking is off" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 1,
    });
    defer pool.deinit();

    var fake_conn: Conn = undefined;
    pool.slots[0] = &fake_conn;
    pool.in_use[0] = true;

    try testing.expectError(error.PostgrezPoolExhausted, pool.acquire());

    // clear the planted slot by hand
    pool.slots[0] = null;
    pool.in_use[0] = false;
}

fn parkedAcquire(pool: *Pool, out: *?*Conn) void {
    out.* = pool.acquire() catch null;
}

test "postgrez: pool release hands the connection to the parked waiter" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 1,
        .process_queue_len = 2,
    });
    defer pool.deinit();

    var fake_conn: Conn = undefined;
    pool.slots[0] = &fake_conn;
    pool.in_use[0] = true;

    var granted: ?*Conn = null;
    const parker = try std.Thread.spawn(.{}, parkedAcquire, .{ &pool, &granted });

    // wait until the acquire parked, then hand the connection over
    while (pool.waiterCount() == 0) std.atomic.spinLoopHint();
    pool.release(&fake_conn);
    parker.join();

    try testing.expectEqual(@as(?*Conn, &fake_conn), granted);
    try testing.expectEqual(@as(usize, 0), pool.waiterCount());
    // the slot stayed held through the handoff
    try testing.expectEqual(true, pool.in_use[0]);

    // clear the planted slot by hand
    pool.slots[0] = null;
    pool.in_use[0] = false;
}

test "postgrez: pool sheds PoolBusy beyond the waiter bound" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pool = try Pool.init(testing.allocator, threaded.io(), .{
        .user = "tester",
        .pool_size = 1,
        .process_queue_len = 1,
    });
    defer pool.deinit();

    var fake_conn: Conn = undefined;
    pool.slots[0] = &fake_conn;
    pool.in_use[0] = true;

    var granted: ?*Conn = null;
    const parker = try std.Thread.spawn(.{}, parkedAcquire, .{ &pool, &granted });

    while (pool.waiterCount() == 0) std.atomic.spinLoopHint();

    // the bound is one parked waiter: the next acquire sheds
    try testing.expectError(error.PostgrezPoolBusy, pool.acquire());

    pool.release(&fake_conn);
    parker.join();
    try testing.expectEqual(@as(?*Conn, &fake_conn), granted);

    // clear the planted slot by hand
    pool.slots[0] = null;
    pool.in_use[0] = false;
}
