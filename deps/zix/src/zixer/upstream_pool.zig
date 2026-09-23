//! zixer upstream pool: O(1) round-robin over the upstreams that are up

const std = @import("std");

const site_cfg = @import("site_cfg.zig");

/// How long a marked-down upstream stays out before pick may try it again.
pub const DEFAULT_COOLDOWN_MS: i64 = 3000;

/// Shortest gap between two re-admit sweeps, so the sweep cost never lands on
/// every pick.
const READMIT_GAP_MS: i64 = 200;

/// One configured upstream and its availability state.
pub const Slot = struct {
    host: []const u8,
    port: u16,
    up: bool = true,
    ready_pos: u32 = 0,
    down_at_ms: i64 = 0,
};

/// What pick hands out. host stays valid until Pool.deinit.
pub const Pick = struct {
    index: u32,
    host: []const u8,
    port: u16,
};

/// Round-robin pool over the upstreams of one site.
///
/// Note:
/// - Layout follows the plan: slots holds every upstream, ready holds dense
///   indexes of the ones currently up, so pick never scans. markDown is a
///   swap-remove, markUp an append, both O(1).
/// - A short spinlock guards the arrays: the edge serves connections from
///   concurrent tasks in the thread model. The per-worker no-lock copy
///   arrives with the worker-owned dispatch edge.
/// - Recovery is cooldown re-admit at pick time, gated to at most one sweep
///   per READMIT_GAP_MS. A re-admitted upstream that is still dead is marked
///   down again by the next connect failure.
pub const Pool = struct {
    slots: []Slot,
    ready: []u32,
    ready_len: usize,
    rr_cursor: usize = 0,
    cooldown_ms: i64,
    next_readmit_ms: i64 = 0,
    lock_flag: std.atomic.Value(bool) = .init(false),

    /// Build the pool with every upstream up. Host strings are duped.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns slots, ready, and the host copies)
    /// upstreams - []const site_cfg.Upstream (from the validated site cfg)
    /// cooldown_ms - i64 (down time before re-admit, DEFAULT_COOLDOWN_MS fits)
    ///
    /// Return:
    /// - Pool
    /// - error.ZixerNoUpstreams when the list is empty
    pub fn init(allocator: std.mem.Allocator, upstreams: []const site_cfg.Upstream, cooldown_ms: i64) !Pool {
        if (upstreams.len == 0) return error.ZixerNoUpstreams;

        const slots = try allocator.alloc(Slot, upstreams.len);
        errdefer allocator.free(slots);
        const ready = try allocator.alloc(u32, upstreams.len);
        errdefer allocator.free(ready);

        var built: usize = 0;
        errdefer for (slots[0..built]) |slot| allocator.free(slot.host);
        for (upstreams, 0..) |upstream, i| {
            slots[i] = .{
                .host = try allocator.dupe(u8, upstream.host),
                .port = upstream.port,
                .ready_pos = @intCast(i),
            };
            ready[i] = @intCast(i);
            built += 1;
        }

        return .{ .slots = slots, .ready = ready, .ready_len = slots.len, .cooldown_ms = cooldown_ms };
    }

    pub fn deinit(pool: *Pool, allocator: std.mem.Allocator) void {
        for (pool.slots) |slot| allocator.free(slot.host);
        allocator.free(pool.slots);
        allocator.free(pool.ready);
    }

    /// Next upstream in round-robin order, null when none is up.
    ///
    /// Param:
    /// now_ms - i64 (a monotonic_clock.nowMs stamp, drives cooldown re-admit)
    ///
    /// Return:
    /// - ?Pick
    pub fn pick(pool: *Pool, now_ms: i64) ?Pick {
        pool.acquire();
        defer pool.release();

        if (pool.ready_len < pool.slots.len and (now_ms >= pool.next_readmit_ms or pool.ready_len == 0)) {
            pool.readmitLocked(now_ms);
        }
        if (pool.ready_len == 0) return null;

        const index = pool.ready[pool.rr_cursor % pool.ready_len];
        pool.rr_cursor +%= 1;

        return .{ .index = index, .host = pool.slots[index].host, .port = pool.slots[index].port };
    }

    /// Take an upstream out of rotation after a connect or send failure.
    pub fn markDown(pool: *Pool, index: u32, now_ms: i64) void {
        pool.acquire();
        defer pool.release();

        const slot = &pool.slots[index];
        if (!slot.up) return;

        slot.up = false;
        slot.down_at_ms = now_ms;

        const last = pool.ready[pool.ready_len - 1];
        pool.ready[slot.ready_pos] = last;
        pool.slots[last].ready_pos = slot.ready_pos;
        pool.ready_len -= 1;
    }

    /// Put an upstream back into rotation.
    pub fn markUp(pool: *Pool, index: u32) void {
        pool.acquire();
        defer pool.release();

        pool.markUpLocked(index);
    }

    /// How many upstreams are currently up.
    pub fn upCount(pool: *Pool) usize {
        pool.acquire();
        defer pool.release();

        return pool.ready_len;
    }

    fn readmitLocked(pool: *Pool, now_ms: i64) void {
        for (pool.slots, 0..) |slot, i| {
            if (!slot.up and now_ms - slot.down_at_ms >= pool.cooldown_ms) pool.markUpLocked(@intCast(i));
        }

        pool.next_readmit_ms = now_ms + READMIT_GAP_MS;
    }

    fn markUpLocked(pool: *Pool, index: u32) void {
        const slot = &pool.slots[index];
        if (slot.up) return;

        slot.up = true;
        slot.ready_pos = @intCast(pool.ready_len);
        pool.ready[pool.ready_len] = index;
        pool.ready_len += 1;
    }

    fn acquire(pool: *Pool) void {
        while (pool.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn release(pool: *Pool) void {
        pool.lock_flag.store(false, .release);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const TEST_UPSTREAMS = [_]site_cfg.Upstream{
    .{ .host = "127.0.0.1", .port = 3000 },
    .{ .host = "127.0.0.1", .port = 3001 },
    .{ .host = "127.0.0.1", .port = 3002 },
};

test "zix zixer: upstream pool, empty list refuses and hosts are duped" {
    try std.testing.expectError(error.ZixerNoUpstreams, Pool.init(std.testing.allocator, &.{}, DEFAULT_COOLDOWN_MS));

    var host_buf = [_]u8{ '1', '2', '7', '.', '0', '.', '0', '.', '1' };
    const upstreams = [_]site_cfg.Upstream{.{ .host = &host_buf, .port = 3000 }};

    var pool = try Pool.init(std.testing.allocator, &upstreams, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    host_buf[0] = 'x';
    try std.testing.expectEqualStrings("127.0.0.1", pool.slots[0].host);
}

test "zix zixer: upstream pool, pick cycles round-robin over every slot" {
    var pool = try Pool.init(std.testing.allocator, &TEST_UPSTREAMS, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 3000), pool.pick(0).?.port);
    try std.testing.expectEqual(@as(u16, 3001), pool.pick(0).?.port);
    try std.testing.expectEqual(@as(u16, 3002), pool.pick(0).?.port);
    try std.testing.expectEqual(@as(u16, 3000), pool.pick(0).?.port);
}

test "zix zixer: upstream pool, markDown removes from rotation and markUp restores" {
    var pool = try Pool.init(std.testing.allocator, &TEST_UPSTREAMS, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    pool.markDown(1, 0);
    try std.testing.expectEqual(@as(usize, 2), pool.upCount());

    var seen_down_port = false;
    for (0..6) |_| {
        if (pool.pick(0).?.port == 3001) seen_down_port = true;
    }
    try std.testing.expect(!seen_down_port);

    pool.markUp(1);
    try std.testing.expectEqual(@as(usize, 3), pool.upCount());
}

test "zix zixer: upstream pool, all down picks null until cooldown re-admits" {
    var pool = try Pool.init(std.testing.allocator, &TEST_UPSTREAMS, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    pool.markDown(0, 1000);
    pool.markDown(1, 1000);
    pool.markDown(2, 1000);

    try std.testing.expectEqual(@as(?Pick, null), pool.pick(1000 + DEFAULT_COOLDOWN_MS - 1));

    const revived = pool.pick(1000 + DEFAULT_COOLDOWN_MS);
    try std.testing.expect(revived != null);
    try std.testing.expectEqual(@as(usize, 3), pool.upCount());
}

test "zix zixer: upstream pool, double markDown of one slot stays consistent" {
    var pool = try Pool.init(std.testing.allocator, &TEST_UPSTREAMS, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    pool.markDown(2, 0);
    pool.markDown(2, 0);

    try std.testing.expectEqual(@as(usize, 2), pool.upCount());
    try std.testing.expectEqual(@as(u16, 3000), pool.pick(0).?.port);
    try std.testing.expectEqual(@as(u16, 3001), pool.pick(0).?.port);
    try std.testing.expectEqual(@as(u16, 3000), pool.pick(0).?.port);
}

test "zix zixer: upstream pool, readmit sweep is gated between attempts" {
    var pool = try Pool.init(std.testing.allocator, &TEST_UPSTREAMS, DEFAULT_COOLDOWN_MS);
    defer pool.deinit(std.testing.allocator);

    pool.markDown(0, 0);
    _ = pool.pick(10);

    // The sweep at t=10 set the gate to t=210: a slot whose cooldown expires
    // inside the gap stays out until the gate passes, then comes back.
    pool.slots[0].down_at_ms = -DEFAULT_COOLDOWN_MS;
    _ = pool.pick(50);
    try std.testing.expectEqual(@as(usize, 2), pool.upCount());

    _ = pool.pick(10 + READMIT_GAP_MS);
    try std.testing.expectEqual(@as(usize, 3), pool.upCount());
}
