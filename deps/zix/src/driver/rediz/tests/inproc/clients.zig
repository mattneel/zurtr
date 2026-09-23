//! Connected clients of the in-process server: their ids, and the kill that makes
//! a pool suite observe a dropped connection.
//!
//! Note:
//! - A kill shuts the victim socket down rather than closing it. The victim
//!   thread is parked inside a read at that moment, and only a shutdown is
//!   guaranteed to make that read return. A close leaves it parked, and the
//!   descriptor number could be handed to the next accept while the old
//!   thread still believes it owns it.
//! - Ids start at 1 to match a real server, where 0 is never a client id.

const std = @import("std");
const builtin = @import("builtin");

/// One accepted connection, as the registry tracks it.
pub const Client = struct {
    id: i64,
    stream: std.Io.net.Stream,
    /// Set by kill, read by the handler loop so it stops after the read fails.
    killed: std.atomic.Value(bool),
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: std.ArrayList(*Client),
    next_id: i64,
    lock: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .entries = .empty,
            .next_id = 1,
            .lock = .init(false),
        };
    }

    pub fn deinit(self: *Self) void {
        self.acquire();
        defer self.release();

        for (self.entries.items) |client| self.allocator.destroy(client);
        self.entries.deinit(self.allocator);
    }

    fn acquire(self: *Self) void {
        while (self.lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn release(self: *Self) void {
        self.lock.store(false, .release);
    }

    /// Track a freshly accepted connection.
    ///
    /// Return:
    /// - *Client owned by the registry until remove is called
    pub fn add(self: *Self, stream: std.Io.net.Stream) !*Client {
        self.acquire();
        defer self.release();

        const client = try self.allocator.create(Client);
        errdefer self.allocator.destroy(client);

        client.* = .{ .id = self.next_id, .stream = stream, .killed = .init(false) };
        try self.entries.append(self.allocator, client);
        self.next_id += 1;

        return client;
    }

    /// Forget a connection whose handler has finished.
    pub fn remove(self: *Self, client: *Client) void {
        self.acquire();
        defer self.release();

        for (self.entries.items, 0..) |entry, index| {
            if (entry != client) continue;

            _ = self.entries.orderedRemove(index);
            self.allocator.destroy(client);

            return;
        }
    }

    /// CLIENT KILL ID: shut the victim's socket down so its next read fails.
    ///
    /// Return:
    /// - true when a client with that id was connected
    pub fn kill(self: *Self, id: i64) bool {
        self.acquire();
        defer self.release();

        for (self.entries.items) |client| {
            if (client.id != id) continue;

            client.killed.store(true, .release);
            client.stream.shutdown(self.io, .both) catch {};

            return true;
        }

        return false;
    }

    /// Shut every tracked connection down so parked handler reads return.
    /// The server calls this on stop, before joining the handler threads.
    pub fn shutdownAll(self: *Self) void {
        self.acquire();
        defer self.release();

        for (self.entries.items) |entry| {
            entry.killed.store(true, .release);
            entry.stream.shutdown(self.io, .both) catch {};
        }
    }

    /// How many connections are currently tracked.
    pub fn count(self: *Self) usize {
        self.acquire();
        defer self.release();

        return self.entries.items.len;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A registry entry needs a real stream to shut down, so the tests pair two
/// loopback sockets rather than inventing a descriptor.
const Pair = struct {
    threaded: std.Io.Threaded,
    listener: std.Io.net.Server,
    server_side: std.Io.net.Stream,
    client_side: std.Io.net.Stream,

    fn open(self: *Pair) !void {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        errdefer self.threaded.deinit();
        const io = self.threaded.io();

        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
        self.listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        errdefer self.listener.deinit(io);

        const Accepted = struct {
            listener: *std.Io.net.Server,
            io: std.Io,
            stream: std.Io.net.Stream = undefined,
            err: ?anyerror = null,

            fn run(inner: *@This()) void {
                inner.stream = inner.listener.accept(inner.io) catch |accept_err| {
                    inner.err = accept_err;

                    return;
                };
            }
        };

        var accepted = Accepted{ .listener = &self.listener, .io = io };
        const thread = try std.Thread.spawn(.{}, Accepted.run, .{&accepted});

        var connect_addr = self.listener.socket.address;
        self.client_side = try connect_addr.connect(io, .{ .mode = .stream });
        thread.join();
        if (accepted.err) |accept_err| return accept_err;

        self.server_side = accepted.stream;
    }

    fn close(self: *Pair) void {
        const io = self.threaded.io();
        self.client_side.close(io);
        self.server_side.close(io);
        self.listener.deinit(io);
        self.threaded.deinit();
    }
};

test "rediz inproc: clients registry hands out increasing ids" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var registry = Registry.init(testing.allocator, pair.threaded.io());
    defer registry.deinit();

    const first = try registry.add(pair.server_side);
    const second = try registry.add(pair.server_side);

    try testing.expectEqual(@as(i64, 1), first.id);
    try testing.expectEqual(@as(i64, 2), second.id);
    try testing.expectEqual(@as(usize, 2), registry.count());
}

test "rediz inproc: clients registry forgets a removed client" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var registry = Registry.init(testing.allocator, pair.threaded.io());
    defer registry.deinit();

    const client = try registry.add(pair.server_side);
    try testing.expectEqual(@as(usize, 1), registry.count());

    registry.remove(client);

    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "rediz inproc: clients kill reports whether the id was connected" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var registry = Registry.init(testing.allocator, pair.threaded.io());
    defer registry.deinit();

    const client = try registry.add(pair.server_side);

    try testing.expectEqual(false, registry.kill(9999));
    try testing.expectEqual(true, registry.kill(client.id));
    try testing.expect(client.killed.load(.acquire));
}

test "rediz inproc: clients kill ends the victim read" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var registry = Registry.init(testing.allocator, pair.threaded.io());
    defer registry.deinit();

    const client = try registry.add(pair.server_side);
    try testing.expectEqual(true, registry.kill(client.id));

    var read_buf: [16]u8 = undefined;
    var reader = pair.server_side.reader(pair.threaded.io(), &read_buf);

    // What kill promises is that a parked read comes back, and how it comes back is the platform's
    // call. POSIX reports a clean end of stream on a socket shut down under the reader. Windows
    // fails the read instead: its socket layer answers STATUS_PIPE_DISCONNECTED there, a status std
    // has no end-of-stream mapping for, so std prints its own unexpected-status diagnostic and
    // returns error.ReadFailed. That diagnostic in a passing Windows run is expected output, not a
    // failure. The transport in this suite already folds the two errors into one closed connection.
    const outcome = reader.interface.takeByte();

    if (comptime builtin.os.tag == .windows) {
        try testing.expectError(error.ReadFailed, outcome);
    } else {
        try testing.expectError(error.EndOfStream, outcome);
    }
}
