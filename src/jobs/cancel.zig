//! Cooperative cancellation: what the *running* job is allowed to ask about, and how cheaply.
//!
//! A lease cannot be revoked from outside: the worker holding it is somewhere in the middle of a job
//! body, and the only safe place to stop is a boundary the body itself declares. So cancellation is a
//! state transition plus a per-worker snapshot of the rows that asked for it:
//!
//!   * `cancel` on an `available` job is terminal immediately — nothing is running, so there is
//!     nothing to interrupt.
//!   * `cancel` on a `leased` job records the request (the row's `cancel_requested`), and the worker
//!     learns about it from this set, refreshed once per reap tick. A query per check would put a
//!     database round trip on every step boundary of every job, which is exactly the cost the
//!     contract's "not a query per check" forbids.
//!
//! The set is deliberately dumb: sorted ids, binary search, no allocation per query. It is refreshed
//! under the runner's own loop, so there is no lock here and no concurrent writer to defend against —
//! a single-threaded runner owns it. `View` is what a running job sees and cannot mutate.

const std = @import("std");

/// The cancellations this worker currently knows about. Borrowed by the running job for the duration
/// of one step; the runner refreshes it between steps.
pub const View = struct {
    ids: []const i64 = &.{},

    pub fn has(self: View, job_id: i64) bool {
        var low: usize = 0;
        var high: usize = self.ids.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const value = self.ids[middle];
            if (value == job_id) return true;
            if (value < job_id) low = middle + 1 else high = middle;
        }

        return false;
    }
};

/// The runner's snapshot, and the same-process path that keeps it fresh between reap ticks.
pub const Set = struct {
    allocator: std.mem.Allocator,
    ids: std.ArrayList(i64) = .empty,

    pub fn init(allocator: std.mem.Allocator) Set {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Set) void {
        self.ids.deinit(self.allocator);
    }

    /// Replace the snapshot with what the database currently holds. Sorted and deduplicated here, so
    /// the per-check cost is a binary search and nothing else.
    pub fn replace(self: *Set, ids: []const i64) !void {
        self.ids.clearRetainingCapacity();
        try self.ids.appendSlice(self.allocator, ids);
        std.mem.sort(i64, self.ids.items, {}, std.sort.asc(i64));

        // Collapse duplicates in place: the query is `distinct` already, but a same-process request
        // can land on a row the query also returns, and a duplicate would break nothing except the
        // "one entry per cancelled job" invariant a reader would reasonably assume.
        var write: usize = 0;
        for (self.ids.items) |id| {
            if (write == 0 or self.ids.items[write - 1] != id) {
                self.ids.items[write] = id;
                write += 1;
            }
        }
        self.ids.shrinkRetainingCapacity(write);
    }

    /// Record a cancellation the same process already knows about, so a job that cancels itself — or
    /// one cancelled by another task in this process between ticks — is observed at its next
    /// boundary rather than at the next database refresh.
    pub fn request(self: *Set, job_id: i64) !void {
        if (self.view().has(job_id)) return;

        try self.ids.append(self.allocator, job_id);
        std.mem.sort(i64, self.ids.items, {}, std.sort.asc(i64));
    }

    pub fn view(self: *const Set) View {
        return .{ .ids = self.ids.items };
    }

    /// Drop a job from the snapshot once it is terminal, so the set does not grow with every
    /// cancellation the process ever saw.
    pub fn clear(self: *Set, job_id: i64) void {
        for (self.ids.items, 0..) |id, index| {
            if (id == job_id) {
                _ = self.ids.orderedRemove(index);
                return;
            }
        }
    }
};

test "the view answers from a sorted snapshot" {
    const set_view = View{ .ids = &.{ 3, 7, 11, 42 } };

    try std.testing.expect(set_view.has(3));
    try std.testing.expect(set_view.has(42));
    try std.testing.expect(!set_view.has(1));
    try std.testing.expect(!set_view.has(8));
    try std.testing.expect(!set_view.has(100));
    try std.testing.expect(!(View{}).has(0));
}

test "a refresh sorts, deduplicates and survives repeated use" {
    var set = Set.init(std.testing.allocator);
    defer set.deinit();

    try set.replace(&.{ 9, 2, 9, 5 });
    try std.testing.expectEqualSlices(i64, &.{ 2, 5, 9 }, set.view().ids);

    // A second refresh replaces rather than accumulates: a job that is no longer cancelled must stop
    // being reported, or the set would only ever grow.
    try set.replace(&.{});
    try std.testing.expectEqual(@as(usize, 0), set.view().ids.len);
    try std.testing.expect(!set.view().has(2));

    try set.replace(&.{ 1, 2, 3 });
    try std.testing.expectEqualSlices(i64, &.{ 1, 2, 3 }, set.view().ids);
}

test "a same-process request is observed without a refresh, and clear removes it" {
    var set = Set.init(std.testing.allocator);
    defer set.deinit();

    try set.replace(&.{});
    try set.request(20);
    try set.request(5);
    try set.request(20);
    try std.testing.expectEqualSlices(i64, &.{ 5, 20 }, set.view().ids);

    set.clear(5);
    try std.testing.expectEqualSlices(i64, &.{20}, set.view().ids);
    set.clear(99);
    try std.testing.expectEqualSlices(i64, &.{20}, set.view().ids);
}
