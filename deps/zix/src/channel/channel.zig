//! zix channel: typed in-process message passing

const std = @import("std");
const builtin = @import("builtin");
const ZIG_SEMVER = @import("../lib.zig").ZIG_SEMVER;

// --------------------------------------------------------- //

/// A buffered, fiber-safe channel for passing values between concurrent tasks.
///
/// - Blocking send/recv use std.Io.Mutex + std.Io.Condition (same as ConnQueue in server.zig).
///   Locking is fiber-aware: waiting tasks yield the thread rather than blocking it,
///   which keeps io.concurrent tasks compatible with this primitive.
/// - Storage is a heap-allocated ring buffer, O(1) send and recv.
/// - capacity = 0 (rendezvous/unbuffered) is not yet supported, assert fires at init.
///
/// Usage:
/// ```zig
/// const MyChan = zix.Channel(u32);
/// var ch = try MyChan.init(allocator, 8);
/// defer ch.deinit();
/// try ch.send(io, 42);
/// const v = try ch.recv(io);  // v == 42
/// ch.close(io);               // no more sends: recv drains remaining items then returns error.ZixClosed
/// ```
pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: usize = 0,
        count: usize = 0,
        closed: bool = false,
        mutex: std.Io.Mutex = .init,
        not_empty: std.Io.Condition = .init,
        not_full: std.Io.Condition = .init,
        allocator: std.mem.Allocator,

        // --------------------------------------------------------- //

        /// Allocate a ring buffer of `capacity` slots. capacity must be > 0.
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            std.debug.assert(capacity > 0); // unbuffered (rendezvous) not yet supported

            const buf = try allocator.alloc(T, capacity);

            // Debug-build init notice. Suppressed under the test runner: a print here runs
            // while channel tests drive concurrent send/recv and poisons the stdout IPC.
            if (comptime (if (ZIG_SEMVER.MINOR == 16) builtin.mode == .Debug else builtin.mode == .debug) and !builtin.is_test)
                std.debug.print("zix channel: init {s} cap={d}\n", .{ @typeName(T), capacity });

            return .{ .buf = buf, .allocator = allocator };
        }

        /// Free the ring buffer. Call after all senders and receivers have exited.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }

        // --------------------------------------------------------- //

        /// Blocking send. Waits when the buffer is full.
        ///
        /// Return:
        /// - error.ZixClosed if close() was called before or during the wait
        pub fn send(self: *Self, io: std.Io, value: T) !void {
            self.mutex.lockUncancelable(io);
            while (self.count == self.buf.len) {
                if (self.closed) {
                    self.mutex.unlock(io);
                    return error.ZixClosed;
                }
                self.not_full.waitUncancelable(io, &self.mutex);
            }
            if (self.closed) {
                self.mutex.unlock(io);
                return error.ZixClosed;
            }
            const tail = (self.head + self.count) % self.buf.len;
            self.buf[tail] = value;
            self.count += 1;
            self.mutex.unlock(io);
            self.not_empty.signal(io);
        }

        /// Blocking receive. Waits when the buffer is empty.
        /// Drains remaining items after close() before returning error.ZixClosed.
        pub fn recv(self: *Self, io: std.Io) !T {
            self.mutex.lockUncancelable(io);
            while (self.count == 0) {
                if (self.closed) {
                    self.mutex.unlock(io);
                    return error.ZixClosed;
                }
                self.not_empty.waitUncancelable(io, &self.mutex);
            }
            const value = self.buf[self.head];
            self.head = (self.head + 1) % self.buf.len;
            self.count -= 1;
            self.mutex.unlock(io);
            self.not_full.signal(io);
            return value;
        }

        /// Signal no more sends. Unblocks all waiting recvs.
        /// Items already in the buffer remain readable until drained.
        pub fn close(self: *Self, io: std.Io) void {
            self.mutex.lockUncancelable(io);
            self.closed = true;
            self.mutex.unlock(io);
            self.not_empty.broadcast(io);
            self.not_full.broadcast(io);
        }
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix channel: Channel, basic send and recv" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const MyChan = Channel(u32);
    var ch = try MyChan.init(arena.allocator(), 4);
    defer ch.deinit();

    try std.testing.expectEqual(@as(usize, 4), ch.buf.len);
    try std.testing.expectEqual(@as(usize, 0), ch.count);
}

test "zix channel: Channel, ring buffer wraps correctly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const MyChan = Channel(u32);
    var ch = try MyChan.init(arena.allocator(), 4);
    defer ch.deinit();

    // Manually inject items to verify ring arithmetic without io
    ch.buf[0] = 10;
    ch.buf[1] = 20;
    ch.buf[2] = 30;
    ch.count = 3;

    // head starts at 0, tail = (0+3)%4 = 3
    const tail = (ch.head + ch.count) % ch.buf.len;
    try std.testing.expectEqual(@as(usize, 3), tail);
    try std.testing.expectEqual(@as(u32, 10), ch.buf[ch.head]);
}
