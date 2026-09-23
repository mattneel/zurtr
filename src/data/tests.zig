//! The data module's tests, against Turso.
//!
//! These are the contract's own testing requirements, at the tiers that can be exercised without a
//! remote: parameter and row round-trips, transaction semantics, error mapping, and the write lease
//! that makes the distributed tier meaningful. The file tier is tested for the property that
//! distinguishes it from memory — a reopened database still has the data.

const std = @import("std");
const data = @import("root.zig");
const adapter = @import("turso_adapter.zig");

/// Collects rows so assertions can run outside the sink callback.
const Collector = struct {
    rows: std.ArrayList([]data.Value),
    arena: std.mem.Allocator,

    fn init(arena: std.mem.Allocator) Collector {
        return .{ .rows = .empty, .arena = arena };
    }

    fn sink(self: *Collector) data.RowSink {
        return .{ .context = self, .push = push };
    }

    fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
        const self: *Collector = @ptrCast(@alignCast(context));

        // Copy what we keep: the contract says the columns are borrowed for the call only.
        const copy = self.arena.alloc(data.Value, columns.len) catch return error.Internal;
        for (columns, 0..) |column, index| {
            copy[index] = switch (column) {
                .text => |text| data.Value{ .text = self.arena.dupe(u8, text) catch return error.Internal },
                .bytes => |bytes| data.Value{ .bytes = self.arena.dupe(u8, bytes) catch return error.Internal },
                else => column,
            };
        }

        self.rows.append(self.arena, copy) catch return error.Internal;
    }
};

fn schema(db: *data.Database) !void {
    _ = try db.exec(null,
        \\CREATE TABLE IF NOT EXISTS notes (
        \\  id integer PRIMARY KEY,
        \\  title text NOT NULL UNIQUE,
        \\  weight real,
        \\  payload blob,
        \\  word_count integer
        \\)
    , &.{});
}

fn freshMemory(arena: std.mem.Allocator) !data.Database {
    var db = try adapter.open(arena, std.testing.io, .memory);
    try schema(&db);

    return db;
}

test "a value round-trips through every tag the contract defines" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var db = try freshMemory(arena);
    defer db.close();

    const result = try db.exec(null, "INSERT INTO notes (id, title, weight, payload, word_count) VALUES (?1, ?2, ?3, ?4, ?5)", &.{
        .{ .integer = 7 },
        .{ .text = "a note about türso" },
        .{ .float = 1.5 },
        .{ .bytes = &[_]u8{ 0xde, 0xad, 0xbe, 0xef } },
        data.Value{ .null = {} },
    });
    try std.testing.expectEqual(@as(u64, 1), result.rows_affected);

    var collector = Collector.init(arena);
    try db.query(null, "SELECT id, title, weight, payload, word_count FROM notes", &.{}, collector.sink());

    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);
    const row = collector.rows.items[0];

    try std.testing.expectEqual(@as(i64, 7), row[0].integer);
    try std.testing.expectEqualStrings("a note about türso", row[1].text);
    try std.testing.expectEqual(@as(f64, 1.5), row[2].float);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, row[3].bytes);
    try std.testing.expectEqual(data.Value.null, row[4]);
}

test "a unique violation is a conflict, not a mystery" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var db = try freshMemory(arena);
    defer db.close();

    _ = try db.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "first" }, .{ .integer = 1 },
    });

    const second = db.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 2 }, .{ .text = "first" }, .{ .integer = 1 },
    });

    // The caller's decision to make, per the taxonomy: the row exists, and only the caller knows what
    // that means for it.
    try std.testing.expectError(error.Conflict, second);
}

test "a transaction commits what it wrote and discards what it rolled back" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var db = try freshMemory(arena);
    defer db.close();

    var tx = try db.begin(.read_write);
    _ = try db.exec(tx, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "kept" }, .{ .integer = 1 },
    });
    try tx.commit();

    var rolled = try db.begin(.read_write);
    _ = try db.exec(rolled, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 2 }, .{ .text = "discarded" }, .{ .integer = 1 },
    });
    rolled.rollback();

    var collector = Collector.init(arena);
    try db.query(null, "SELECT title FROM notes ORDER BY id", &.{}, collector.sink());

    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);
    try std.testing.expectEqualStrings("kept", collector.rows.items[0][0].text);
}

test "a transaction reads its own uncommitted writes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var db = try freshMemory(arena);
    defer db.close();

    var tx = try db.begin(.read_write);
    _ = try db.exec(tx, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "uncommitted" }, .{ .integer = 1 },
    });

    var collector = Collector.init(arena);
    try db.query(tx, "SELECT title FROM notes", &.{}, collector.sink());
    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);

    // And it is gone once the scope ends without a commit — the contract's rule that a dropped
    // transaction rolls back rather than committing silently.
    tx.rollback();

    var after = Collector.init(arena);
    try db.query(null, "SELECT title FROM notes", &.{}, after.sink());
    try std.testing.expectEqual(@as(usize, 0), after.rows.items.len);
}

test "the file tier survives closing and reopening" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A fixed path in the working directory: the test owns it, deletes it first so a previous run
    // cannot make this pass, and deletes it again afterwards — including the write-ahead log and
    // shared-memory siblings the engine keeps beside it, which are as much the test's as the file.
    const path = "zig-cache-data-tier-test.db";
    const siblings = [_][]const u8{ path, path ++ "-wal", path ++ "-shm" };
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(std.testing.io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(std.testing.io, file) catch {};

    {
        var db = try adapter.open(arena, std.testing.io, .{ .file = path });
        defer db.close();

        try schema(&db);
        _ = try db.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
            .{ .integer = 1 }, .{ .text = "persisted" }, .{ .integer = 1 },
        });
    }

    // The whole point of the tier: the process that wrote this is gone.
    var db = try adapter.open(arena, std.testing.io, .{ .file = path });
    defer db.close();

    var collector = Collector.init(arena);
    try db.query(null, "SELECT title FROM notes", &.{}, collector.sink());

    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);
    try std.testing.expectEqualStrings("persisted", collector.rows.items[0][0].text);
}

test "only one node holds the write lease, and it expires" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var db = try freshMemory(arena);
    defer db.close();

    const engine = adapter.engine(&db);

    // Two nodes reach for the lease. One gets it.
    const now: i64 = 1_000_000;
    try std.testing.expect(try engine.claimLease(adapter.default_lease, "node-a", now));
    try std.testing.expect(!try engine.claimLease(adapter.default_lease, "node-b", now));

    // The holder renews without contention, because the lease is already its own.
    try std.testing.expect(try engine.claimLease(adapter.default_lease, "node-a", now + 1));

    const held = (try engine.leaseHolder(adapter.default_lease)).?;
    try std.testing.expectEqualStrings("node-a", held.holder[0..held.holder_len]);

    // A node that stops renewing loses it, and the next claimant takes over: this is the whole
    // recovery story for a node that died holding the write lease.
    try std.testing.expect(try engine.claimLease(adapter.default_lease, "node-b", now + 2_000_000));

    const now_held = (try engine.leaseHolder(adapter.default_lease)).?;
    try std.testing.expectEqualStrings("node-b", now_held.holder[0..now_held.holder_len]);

    // And a stale holder cannot release someone else's lease.
    try std.testing.expect(!try engine.releaseLease(adapter.default_lease, "node-a"));
    try std.testing.expect(try engine.releaseLease(adapter.default_lease, "node-b"));
    try std.testing.expect((try engine.leaseHolder(adapter.default_lease)) == null);
}

test "a tier whose remote transport is not wired refuses instead of pretending" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The sync tier's remote half needs a transport that does not exist yet, so the tier is refused
    // whether or not the SDK Kit is built: opening the local file instead would hand a caller that
    // asked for synchronization a database that never synchronizes, which is worse than an error.
    try std.testing.expectError(error.Unavailable, adapter.open(arena, std.testing.io, .{
        .sync = .{ .path = ":memory:", .remote = "https://example.invalid" },
    }));
}

test "a distributed tier writes only while it holds the lease" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const path = "zig-cache-data-distributed-test.db";
    const siblings = [_][]const u8{ path, path ++ "-wal", path ++ "-shm" };
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(std.testing.io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(std.testing.io, file) catch {};

    // Two nodes, one logical database: separate engines over the same file, which is what a follower
    // holds on a machine of its own.
    const base = data.Tier{ .distributed = .{ .path = path, .remote = "https://example.invalid", .node = "node-a" } };
    var leader = try adapter.open(arena, std.testing.io, base);
    defer leader.close();
    try schema(&leader);

    const follower_tier = data.Tier{ .distributed = .{ .path = path, .remote = "https://example.invalid", .node = "node-b", .role = .follower } };
    var follower = try adapter.open(arena, std.testing.io, follower_tier);
    defer follower.close();

    // Reading never needs the lease: one writer, many readers.
    var collector = Collector.init(arena);
    try follower.query(null, "SELECT count(*) AS n FROM notes", &.{}, collector.sink());
    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);

    // The leader writes, and writing takes the lease.
    var leader_tx = try leader.begin(.read_write);
    _ = try leader.exec(leader_tx, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "from the leader" }, .{ .integer = 3 },
    });
    try leader_tx.commit();

    // The follower asks to write while the lease is held: it is told no, rather than corrupting the
    // timeline with a second writer.
    try std.testing.expectError(error.Conflict, follower.begin(.read_write));

    // With the lease released, the follower writes.
    try std.testing.expect(try adapter.engine(&leader).releaseLease("default", "node-a"));

    var follower_tx = try follower.begin(.read_write);
    _ = try follower.exec(follower_tx, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 2 }, .{ .text = "from the follower" }, .{ .integer = 3 },
    });
    try follower_tx.commit();

    var both = Collector.init(arena);
    try leader.query(null, "SELECT title FROM notes ORDER BY id", &.{}, both.sink());
    try std.testing.expectEqual(@as(usize, 2), both.rows.items.len);
    try std.testing.expectEqualStrings("from the follower", both.rows.items[1][0].text);
}
