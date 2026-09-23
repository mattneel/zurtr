//! The data module's tests, against Turso.
//!
//! These are the contract's own testing requirements, at the tiers that can be exercised without a
//! remote: parameter and row round-trips, transaction semantics, error mapping, and the write lease
//! that makes the distributed tier meaningful. The file tier is tested for the property that
//! distinguishes it from memory — a reopened database still has the data.
//!
//! The sync tier's tests come in the two configurations the build can have. With `-Dturso-sync` the
//! tier opens and talks to a remote, so what is tested here without one is that a remote that does not
//! answer is a mapped framework error rather than a panic or a silent success; the round trip that
//! needs a live endpoint runs only when the build was told where one is (`-Dsync-remote=...`), and is
//! skipped otherwise. Without the SDK the tier is refused, which is asserted where a reader would look
//! for it. The cross-process evidence for the distributed tier is `test-data-nodes`, not this file.

const std = @import("std");
const data = @import("root.zig");
const adapter = @import("turso_adapter.zig");
const build_options = @import("build_options");

/// A live sync endpoint, when the build was told about one (`-Dsync-remote=http://host:port`). The
/// round trip needs a server that speaks the sync protocol; everything else about the tier is tested
/// without one.
const sync_remote: ?[]const u8 = build_options.sync_remote;

/// The sync tier's own directory. The sync engine keeps a family of files beside the database
/// (`<path>-info`, `<path>-changes`, `<path>-wal`, …), so a test that has to start clean cleans the
/// directory rather than guessing at the family. The tests also *create* it first: like every other
/// tier, the adapter opens a path, it does not invent the directories on the way to it.
const sync_dir = "zig-cache-data-sync-test";

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

test "a transaction's handle is released by the adapter, not by the allocator it came from" {
    // Deliberately *not* an arena, unlike the rest of this file: a `Tx` the adapter forgets to release
    // is invisible to a test that frees everything at once at the end, and a transaction is the one
    // allocation this layer makes on every write path. `std.testing.allocator` is the only witness that
    // notices — and switching this back to the arena the other tests use would not be a simplification,
    // it would be deleting the test: the arena frees exactly what the adapter did not.
    var db = try adapter.open(std.testing.allocator, std.testing.io, .memory);
    defer db.close();

    try schema(&db);

    var committed = try db.begin(.read_write);
    _ = try db.exec(committed, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "kept" }, .{ .integer = 1 },
    });
    try committed.commit();

    var rolled = try db.begin(.read_write);
    _ = try db.exec(rolled, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 2 }, .{ .text = "discarded" }, .{ .integer = 1 },
    });
    rolled.rollback();

    // A third transaction, so the first two handles have to be gone by now rather than all of them at
    // the end; `close` releases this one.
    var last = try db.begin(.read_write);
    try last.commit();
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

/// The remote the offline sync tests point at: a loopback port with nothing behind it, so the
/// connection is refused rather than being refused by policy (a non-loopback `http://` endpoint would
/// be turned away by the transport before it was dialled, which is a different test).
const dead_remote = "http://127.0.0.1:1";

test "a sync tier needs the SDK Kit: refused without it, opened with it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    defer deleteTree(std.testing.io, sync_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sync_dir);

    const path = sync_dir ++ "/app.db";
    const tier = data.Tier{ .sync = .{ .path = path, .remote = dead_remote } };

    if (comptime !build_options.turso_sync) {
        // Without the SDK there is no remote half to open, and opening the local file instead would
        // hand a caller that asked for synchronization a database that never synchronizes. So the tier
        // is refused — in every build that did not ask for the SDK.
        try std.testing.expectError(error.Unavailable, adapter.open(arena, std.testing.io, tier));

        return;
    }

    // With the SDK the tier is a local file plus a remote, and the local half does not wait for the
    // remote: this opens with a remote that nothing is listening on, and serves SQL at that path. The
    // remote's state arrives on the first pull, which is the next test's subject.
    var db = try adapter.open(arena, std.testing.io, tier);
    defer db.close();

    try schema(&db);
    _ = try db.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "local only, so far" }, .{ .integer = 3 },
    });

    var collector = Collector.init(arena);
    try db.query(null, "SELECT title FROM notes", &.{}, collector.sink());
    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);
    try std.testing.expectEqualStrings("local only, so far", collector.rows.items[0][0].text);

    // The sync surface belongs to the same engine, and this is the file the tier promised.
    try std.testing.expect(adapter.engine(&db) == adapter.engine(&db));
    try std.testing.expect(fileExists(std.testing.io, path));
}

test "an operation against a remote that does not answer is a mapped error" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    defer deleteTree(std.testing.io, sync_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sync_dir);

    const tier = data.Tier{ .sync = .{ .path = sync_dir ++ "/unreachable.db", .remote = dead_remote } };

    if (comptime !build_options.turso_sync) {
        // Same assertion, same reason: with no SDK there is no operation to attempt.
        try std.testing.expectError(error.Unavailable, adapter.open(arena, std.testing.io, tier));

        return;
    }

    var db = try adapter.open(arena, std.testing.io, tier);
    defer db.close();
    try schema(&db);

    const engine = adapter.engine(&db);

    // Nothing is listening on that port, so every operation that has to cross to the remote comes back
    // as `unavailable` — the taxonomy's word for "the dependency is down, retry by policy" — rather
    // than a panic, a silent success, or a database that pretends it synchronized.
    try std.testing.expectError(error.Unavailable, engine.push());
    try std.testing.expectError(error.Unavailable, engine.pull());
    try std.testing.expectError(error.Unavailable, engine.syncPass());

    // The local half is still a database: a failed push does not take the SQL surface with it, and the
    // write that was waiting stays local.
    _ = try db.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = 1 }, .{ .text = "still local" }, .{ .integer = 2 },
    });

    var collector = Collector.init(arena);
    try db.query(null, "SELECT title FROM notes", &.{}, collector.sink());
    try std.testing.expectEqual(@as(usize, 1), collector.rows.items.len);
}

test "a sync tier round-trips through a live endpoint" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Needs a server: run with `-Dsync-remote=http://127.0.0.1:8080` against a local `tursodb
    // --sync-server`, or against the same URL tunnelled to a remote box. Without one there is nothing
    // to round-trip through, and the test says so rather than pretending.
    const remote = sync_remote orelse return error.SkipZigTest;

    defer deleteTree(std.testing.io, sync_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sync_dir);

    // The remote is a database that outlives this test and may already have rows in it from an earlier
    // run, so nothing here may assume an empty one: the rows carry this run's own keys and titles, and
    // the assertions look for those rather than for a shape the last run left behind.
    const stamp = std.Io.Clock.Timestamp.now(std.testing.io, .real).raw.toMicroseconds();
    var first_title_buffer: [64]u8 = undefined;
    var second_title_buffer: [64]u8 = undefined;
    const first_title = try std.fmt.bufPrint(&first_title_buffer, "from the first node {d}", .{stamp});
    const second_title = try std.fmt.bufPrint(&second_title_buffer, "from the second node {d}", .{stamp});

    // --- one node: opens, writes, pushes --------------------------------------------------------
    var one = try adapter.open(arena, std.testing.io, .{ .sync = .{ .path = sync_dir ++ "/one.db", .remote = remote } });
    defer one.close();

    try schema(&one);
    _ = try one.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = stamp }, .{ .text = first_title }, .{ .integer = 4 },
    });

    try adapter.engine(&one).push();

    // The numbers the operation reports are the push's own evidence: it reached a server (a push
    // timestamp) and it sent something (bytes). The revision stays as the engine reports it — it is
    // empty on a database that has nothing to be in step with yet, which is a fact about the engine
    // and not something this test should pin.
    var stats = try adapter.engine(&one).stats();
    defer stats.deinit();
    try std.testing.expect(stats.last_push_unix_time > 0);
    try std.testing.expect(stats.network_sent_bytes > 0);

    // A pull straight after a push is the engine's business to report — the remote may hand back the
    // base revision, or nothing. What the binding does promise together is that a pull that received
    // changes applied them, so that is the assertion.
    const after_push = try adapter.engine(&one).pull();
    if (after_push.changes_received) try std.testing.expect(after_push.changes_applied);

    // --- a second node: a fresh local file, the same remote --------------------------------------
    // This is the tier's whole claim: the database survives its machine because the remote has it. The
    // second node has never seen the first one's file, and its own file is empty until it meets the
    // remote — the engine's deferred bootstrap, which is the pull inside this first pass.
    var two = try adapter.open(arena, std.testing.io, .{ .sync = .{ .path = sync_dir ++ "/two.db", .remote = remote } });
    defer two.close();

    const bootstrapped = try adapter.engine(&two).syncPass();
    try std.testing.expect(bootstrapped.push_completed);

    var remote_rows = Collector.init(arena);
    try two.query(null, "SELECT id, title FROM notes", &.{}, remote_rows.sink());
    try std.testing.expect(titlesContain(remote_rows.rows.items, first_title));

    // And back the other way: the second node writes, and the first sees it after a pull. Two local
    // files, two directions, one remote — which is the tier, end to end.
    _ = try two.exec(null, "INSERT INTO notes (id, title, word_count) VALUES (?1, ?2, ?3)", &.{
        .{ .integer = stamp + 1 }, .{ .text = second_title }, .{ .integer = 5 },
    });

    const pass = try adapter.engine(&two).syncPass();
    try std.testing.expect(pass.push_completed);

    const pulled = try adapter.engine(&one).pull();
    try std.testing.expect(pulled.changes_received);
    try std.testing.expect(pulled.changes_applied);

    var both = Collector.init(arena);
    try one.query(null, "SELECT id, title FROM notes", &.{}, both.sink());
    try std.testing.expect(titlesContain(both.rows.items, first_title));
    try std.testing.expect(titlesContain(both.rows.items, second_title));
}

/// Whether the rows a read returned include a title. The remote is shared and persistent, so the
/// questions these tests ask are about *these* rows, never about the whole table's shape.
fn titlesContain(rows: []const []data.Value, title: []const u8) bool {
    for (rows) |row| {
        if (std.mem.eql(u8, row[1].text, title)) return true;
    }

    return false;
}

fn fileExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;

    return true;
}

/// Remove a test's directory and everything in it. The sync engine's files are derived from the
/// database's path, so a directory per test is the only cleanup that cannot miss one.
fn deleteTree(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, path) catch {};
}

test "a distributed tier writes only while it holds the lease" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const path = "zig-cache-data-distributed-test.db";
    // `-tshm` is the shared WAL coordination file the engine's multiprocess mode adds — this tier
    // asks for that mode, so its sidecars are this test's to clean up too.
    const siblings = [_][]const u8{ path, path ++ "-wal", path ++ "-shm", path ++ "-tshm" };
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
