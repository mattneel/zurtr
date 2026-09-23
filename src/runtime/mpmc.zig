//! `zurtr.runtime.mpmc` — a bounded lock-free multi-producer multi-consumer queue.
//!
//! This is the substrate the concurrency story stands on:
//!
//!   * the pool's per-worker queues, where a thief takes work from another worker,
//!   * cross-worker completion delivery, where a job or agent thread hands a result to the worker that
//!     owns the session (the deferred-handle model in `overview.md`),
//!   * and the boundary where the framework's "worker-local, no shared mutable state" rule becomes
//!     explicit, because a queue is exactly as much sharing as two threads are allowed to have.
//!
//! It is Dmitry Vyukov's bounded MPMC queue: a ring of cells, each carrying a sequence number that says
//! whether the slot is free, filled, or being reserved. Producers and consumers reserve by CAS on a
//! position counter and then wait for the slot's sequence to catch up, which is what makes it safe
//! without locks, without hazard pointers and without an ABA problem — a slot's sequence is the
//! generation count that a plain index would lose.
//!
//! # Properties, and the price of each
//!
//! - **Bounded, allocated once.** Capacity is fixed at init (a power of two, so the ring is a mask) and
//!   the allocation happens there. `push` never allocates.
//! - **Non-blocking on both sides.** `push` returns false when full, `pop` returns null when empty. There
//!   is no waiting in here at all: the caller decides whether to spin, park, shed or grow, because only
//!   the caller knows whether a dropped item is a lost job or a stale preview.
//! - **Linearizable per operation**, not a transaction: a push either happened before a pop observed it
//!   or after, and nothing else is promised.
//! - **Value semantics.** `T` is copied through the slot; it is not moved from a heap the queue owns.
//!   Keep it small; the queue is a hand-off, not a mailbox.
//! - **One cache line per slot**, so neighbouring slots do not share a line between a producer and a
//!   consumer. That is memory for speed, and it is the reason a queue of large structs is not much more
//!   expensive than a queue of small ones.

const std = @import("std");

/// Assumed false-sharing granularity. `std.atomic.cache_line` is the platform's answer where it exists.
const cache_line = std.atomic.cache_line;

/// A bounded lock-free MPMC queue of `T`.
pub fn Queue(comptime T: type) type {
    return struct {
        const Self = @This();

        const Cell = struct {
            /// The slot's generation: `pos` when the slot is ready to be written (free for the producer
            /// whose position this is), `pos + 1` when it holds a value, and further ahead while a
            /// reservation is in flight.
            sequence: std.atomic.Value(usize) align(cache_line) = .init(0),
            value: T = undefined,
        };

        allocator: std.mem.Allocator,
        buffer: []Cell,
        mask: usize,
        /// Next position a producer may reserve. Padded away from `dequeue_pos`: producers and consumers
        /// hammer different counters, and putting them on one line would serialize them for no reason.
        enqueue_pos: std.atomic.Value(usize) align(cache_line) = .init(0),
        dequeue_pos: std.atomic.Value(usize) align(cache_line) = .init(0),
        /// Items in the queue. Only for diagnostics and bounds — the algorithm below never reads it — so
        /// it is a plain atomic that callers may see a moment out of date under concurrency.
        count: std.atomic.Value(usize) = .init(0),

        pub const Error = error{
            /// Capacity must be at least 2 and a power of two.
            CapacityNotPowerOfTwo,
            OutOfMemory,
        };

        /// Allocate a ring of `capacity` slots. `capacity` must be a power of two: the ring is indexed
        /// by a mask, and that is what makes the wrap unsigned and cheap instead of a modulo.
        pub fn init(allocator: std.mem.Allocator, slots: usize) Error!Self {
            if (slots < 2 or !std.math.isPowerOfTwo(slots)) return error.CapacityNotPowerOfTwo;

            const buffer = allocator.alloc(Cell, slots) catch return error.OutOfMemory;
            errdefer allocator.free(buffer);

            // Slot i starts ready for position i, which is what makes the first wrap work.
            for (buffer, 0..) |*cell, index| cell.* = .{ .sequence = .init(index) };

            return .{
                .allocator = allocator,
                .buffer = buffer,
                .mask = slots - 1,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
            self.* = undefined;
        }

        pub fn capacity(self: *const Self) usize {
            return self.buffer.len;
        }

        /// Items currently in the queue. A snapshot: under concurrency it can be a moment stale, and it
        /// is deliberately not what `push`/`pop` decide with.
        pub fn len(self: *const Self) usize {
            return self.count.load(.monotonic);
        }

        /// Hand `value` to the queue. Returns false if it is full — not an error, and not a wait.
        pub fn push(self: *Self, value: T) bool {
            var pos = self.enqueue_pos.load(.monotonic);
            // Declared outside the loop: the cell is reserved inside it and written after it.
            var cell: *Cell = undefined;

            while (true) {
                cell = &self.buffer[pos & self.mask];
                const sequence = cell.sequence.load(.acquire);
                const diff = @as(isize, @bitCast(sequence -% pos));

                if (diff == 0) {
                    // The slot is ours to claim, unless someone else claims this position first.
                    if (self.enqueue_pos.cmpxchgWeak(pos, pos + 1, .acq_rel, .acquire)) |observed| {
                        pos = observed;

                        continue;
                    }

                    break;
                }

                // Negative means the consumer has not caught up: the ring is full at this position.
                if (diff < 0) return false;

                // Positive means someone reserved this position after we read it; take their place.
                pos = self.enqueue_pos.load(.monotonic);
            }

            cell.value = value;
            // Release: the value write above must be visible to whoever acquires this slot.
            cell.sequence.store(pos + 1, .release);
            _ = self.count.fetchAdd(1, .monotonic);

            return true;
        }

        /// Take the next value, or null when the queue is empty.
        pub fn pop(self: *Self) ?T {
            var pos = self.dequeue_pos.load(.monotonic);
            var cell: *Cell = undefined;

            while (true) {
                cell = &self.buffer[pos & self.mask];
                const sequence = cell.sequence.load(.acquire);
                const diff = @as(isize, @bitCast(sequence -% (pos + 1)));

                if (diff == 0) {
                    if (self.dequeue_pos.cmpxchgWeak(pos, pos + 1, .acq_rel, .acquire)) |observed| {
                        pos = observed;

                        continue;
                    }

                    break;
                }

                // Negative means the producer has not filled this position yet: nothing to take.
                if (diff < 0) return null;

                pos = self.dequeue_pos.load(.monotonic);
            }

            const value = cell.value;
            // The slot becomes free for the producer a full lap ahead: position plus capacity.
            cell.sequence.store(pos +% self.mask +% 1, .release);
            _ = self.count.fetchSub(1, .monotonic);

            return value;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "a queue of capacity two holds two and refuses the third" {
    var queue = try Queue(u32).init(testing.allocator, 2);
    defer queue.deinit();

    try testing.expect(queue.push(1));
    try testing.expect(queue.push(2));
    try testing.expect(!queue.push(3));

    try testing.expectEqual(@as(?u32, 1), queue.pop());
    try testing.expectEqual(@as(?u32, 2), queue.pop());
    try testing.expectEqual(@as(?u32, null), queue.pop());

    // Emptying made room again, which is the whole point of a bounded ring.
    try testing.expect(queue.push(4));
    try testing.expectEqual(@as(?u32, 4), queue.pop());
}

test "the ring wraps without losing or duplicating a value" {
    var queue = try Queue(u32).init(testing.allocator, 4);
    defer queue.deinit();

    // Three laps around a four-slot ring.
    var expected: u32 = 0;
    while (expected < 12) : (expected += 1) {
        try testing.expect(queue.push(expected));
        try testing.expectEqual(@as(?u32, expected), queue.pop());
    }
}

test "capacity must be a power of two" {
    try testing.expectError(error.CapacityNotPowerOfTwo, Queue(u32).init(testing.allocator, 3));
    try testing.expectError(error.CapacityNotPowerOfTwo, Queue(u32).init(testing.allocator, 1));
}

test "many producers and consumers hand over every value exactly once" {
    const producers = 4;
    const consumers = 8;
    const per_producer = 20_000;

    var queue = try Queue(u64).init(testing.allocator, 256);
    defer queue.deinit();

    var received: std.ArrayList(u64) = .empty;
    defer received.deinit(testing.allocator);
    var received_mutex: std.Io.Mutex = .init;
    var done = std.atomic.Value(u64).init(0);

    const ProducerContext = struct {
        queue: *Queue(u64),
        id: u64,

        fn run(self: @This()) void {
            var index: u64 = 0;
            while (index < per_producer) {
                // Full is expected and is the contract: producers run ahead of a bounded queue, and a
                // false here means retry, not failure.
                if (self.queue.push((self.id << 32) | index)) index += 1;
            }
        }
    };

    const ConsumerContext = struct {
        queue: *Queue(u64),
        received: *std.ArrayList(u64),
        allocator: std.mem.Allocator,
        mutex: *std.Io.Mutex,
        done: *std.atomic.Value(u64),

        fn run(self: @This()) void {
            // Bounded spinning on purpose: if the queue ever lost a value, an unbounded loop would hang
            // the suite instead of failing it. After the budget runs out the consumer stops, the totals
            // below do not match, and the failure points at the queue.
            var empty_polls: usize = 0;
            while (self.done.load(.acquire) < producers * per_producer) {
                if (self.queue.pop()) |value| {
                    empty_polls = 0;
                    _ = self.done.fetchAdd(1, .acq_rel);
                    self.mutex.lockUncancelable(std.testing.io);
                    defer self.mutex.unlock(std.testing.io);
                    self.received.append(self.allocator, value) catch {};
                } else {
                    empty_polls += 1;
                    if (empty_polls > 50_000_000) return;
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var threads: std.ArrayList(std.Thread) = .empty;
    defer threads.deinit(testing.allocator);

    for (0..producers) |id| {
        try threads.append(testing.allocator, try std.Thread.spawn(.{}, ProducerContext.run, .{
            ProducerContext{ .queue = &queue, .id = id },
        }));
    }
    for (0..consumers) |_| {
        try threads.append(testing.allocator, try std.Thread.spawn(.{}, ConsumerContext.run, .{
            ConsumerContext{
                .queue = &queue,
                .received = &received,
                .allocator = testing.allocator,
                .mutex = &received_mutex,
                .done = &done,
            },
        }));
    }
    for (threads.items) |thread| thread.join();

    // Every value exactly once: the count is the arithmetic truth, and sorting shows the contents are
    // the sequence the producers were told to hand over — no duplicates, no losses, both attributable.
    try testing.expectEqual(@as(usize, producers * per_producer), received.items.len);

    std.mem.sort(u64, received.items, {}, std.sort.asc(u64));
    for (received.items, 0..) |value, index| {
        const producer_id = value >> 32;
        const offset = value & 0xffff_ffff;
        // The sorted order is by producer then by index, so each position has exactly one right answer.
        try testing.expectEqual(@as(u64, index / per_producer), producer_id);
        try testing.expectEqual(@as(u64, index % per_producer), offset);
    }
}
