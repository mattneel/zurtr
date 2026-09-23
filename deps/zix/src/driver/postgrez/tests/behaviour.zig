//! postgrez behaviour suite: the driver against the in-process backend.
//!
//! Note:
//! - No container and no daemon, so this runs on every supported platform.
//!   It is the docker-free twin of the happy-path half of
//!   tests/integration.zig, which keeps the live PostgreSQL 18 coverage for
//!   maintainers.
//! - Each test starts its own backend on a kernel-assigned port, so state is
//!   clean by construction and tests never collide.
//! - The backend runs no SQL. What is proven here is the wire path and the
//!   driver's handling of it: authentication, the extended query cycle, row
//!   decoding, transactions, COPY, notifications, pooling. Whether a query
//!   means what its author intended is the container suite's job.

const std = @import("std");
const postgrez = @import("postgrez");

const inproc = @import("inproc/server.zig");

const testing = std.testing;

const TEST_USER = "tester";
const TEST_DATABASE = "testdb";
const TEST_PASSWORD = "postgrez_test_pw";

/// One in-process backend plus the io it runs on, the three lines every test opens with.
const Harness = struct {
    threaded: std.Io.Threaded,
    arena: std.heap.ArenaAllocator,
    server: *inproc.Server,

    fn start(self: *Harness, options: inproc.Options) !void {
        self.threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer self.threaded.deinit();

        self.arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        errdefer self.arena.deinit();

        self.server = try inproc.Server.start(std.heap.smp_allocator, self.threaded.io(), options);
    }

    fn open(self: *Harness) !void {
        return self.start(.{});
    }

    fn stop(self: *Harness) void {
        self.server.stop();
        self.arena.deinit();
        self.threaded.deinit();
    }

    fn io(self: *Harness) std.Io {
        return self.threaded.io();
    }

    fn allocator(self: *Harness) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn config(self: *Harness) postgrez.Config {
        return .{
            .ip = inproc.IP,
            .port = self.server.port,
            .user = TEST_USER,
            .database = TEST_DATABASE,
        };
    }

    fn connect(self: *Harness) !*postgrez.Conn {
        return postgrez.Conn.connect(self.allocator(), self.io(), self.config());
    }
};

test "postgrez behaviour: a trusted connection reaches ready" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(postgrez.frontend.PROTOCOL_V3_2, conn.protocol_code);
    try testing.expect(conn.server_version_major >= 18);
    try testing.expect(conn.backend_pid != 0);
}

test "postgrez behaviour: cleartext authentication completes" {
    var harness: Harness = undefined;
    try harness.start(.{ .auth_mode = .CLEARTEXT, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.password = TEST_PASSWORD;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('a@b.c')", .{}));
}

test "postgrez behaviour: scram authentication completes both halves" {
    var harness: Harness = undefined;
    try harness.start(.{ .auth_mode = .SCRAM, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.password = TEST_PASSWORD;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(postgrez.scram.Mechanism.SCRAM_SHA_256, conn.sasl_mechanism.?);
    try testing.expect(conn.backend_pid != 0);
}

test "postgrez behaviour: a protocol 3.0 backend is negotiated down to" {
    var harness: Harness = undefined;
    try harness.start(.{ .protocol_code = postgrez.frontend.PROTOCOL_V3_0 });
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(postgrez.frontend.PROTOCOL_V3_0, conn.protocol_code);
}

test "postgrez behaviour: exec reports the rows a command touched" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ($1)", .{"ada@example.com"}));
    try testing.expectEqual(@as(u64, 2), try conn.exec("UPDATE users SET active = true", .{}));
    try testing.expectEqual(@as(u64, 1), try conn.exec("DELETE FROM users WHERE id = $1", .{@as(i32, 1)}));
}

test "postgrez behaviour: query maps rows into a struct" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    const User = struct {
        id: i32,
        email: []const u8,
        active: bool,
    };

    const users = try conn.query(User, "SELECT * FROM users ORDER BY id", .{});

    try testing.expectEqual(@as(usize, 2), users.len);
    try testing.expectEqual(@as(i32, 1), users[0].id);
    try testing.expectEqualStrings("ada@example.com", users[0].email);
    try testing.expectEqual(true, users[0].active);
    try testing.expectEqual(@as(i32, 2), users[1].id);
    try testing.expectEqual(false, users[1].active);
}

test "postgrez behaviour: binary decoding covers every column type" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    const Typed = struct {
        small: i16,
        whole: i32,
        big: i64,
        ratio: f64,
        label: []const u8,
        flag: bool,
        document: []const u8,
    };

    const row = (try conn.queryRow(Typed, "SELECT * FROM typed", .{})).?;

    try testing.expectEqual(@as(i16, -300), row.small);
    try testing.expectEqual(@as(i32, 70000), row.whole);
    try testing.expectEqual(@as(i64, -9_000_000_000), row.big);
    try testing.expectEqual(@as(f64, 9.5), row.ratio);
    try testing.expectEqualStrings("widget", row.label);
    try testing.expectEqual(true, row.flag);
    try testing.expectEqualStrings("{\"kind\":\"tool\"}", row.document);
}

test "postgrez behaviour: queryRow reports present and absent" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    const User = struct {
        id: i32,
        email: []const u8,
        active: bool,
    };

    const present = try conn.queryRow(User, "SELECT * FROM users WHERE id = 1", .{});
    try testing.expect(present != null);

    const absent = try conn.queryRow(User, "SELECT * FROM empty", .{});
    try testing.expectEqual(@as(?User, null), absent);
}

test "postgrez behaviour: a null column maps to an optional field" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    const Note = struct {
        id: i32,
        note: ?[]const u8,
    };

    const notes = try conn.query(Note, "SELECT * FROM nullable", .{});

    try testing.expectEqual(@as(usize, 2), notes.len);
    try testing.expectEqualStrings("present", notes[0].note.?);
    try testing.expectEqual(@as(?[]const u8, null), notes[1].note);
}

test "postgrez behaviour: rows streams a result set one row at a time" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var result = try conn.rows("SELECT * FROM users", .{});
    defer result.deinit();

    var seen: usize = 0;
    while (try result.next()) |row| {
        _ = try row.get(i32, 0);
        seen += 1;
    }

    try testing.expectEqual(@as(usize, 2), seen);
}

test "postgrez behaviour: an explicit transaction commits" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var transaction = try conn.begin();
    try testing.expectEqual(@as(u64, 1), try transaction.exec("INSERT INTO users (email) VALUES ('t@x.y')", .{}));
    try transaction.commit();

    // back to idle once the transaction closed
    try testing.expectEqual(postgrez.backend.TransactionStatus.IDLE, conn.transaction_status);
}

test "postgrez behaviour: an explicit transaction rolls back" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var transaction = try conn.begin();
    _ = try transaction.exec("INSERT INTO users (email) VALUES ('t@x.y')", .{});
    transaction.rollback();

    try testing.expectEqual(postgrez.backend.TransactionStatus.IDLE, conn.transaction_status);
}

fn insertOne(transaction: *postgrez.Transaction) !void {
    _ = try transaction.exec("INSERT INTO users (email) VALUES ('callback@x.y')", .{});
}

test "postgrez behaviour: the callback transaction commits on success" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try conn.transaction(insertOne, .{});

    try testing.expectEqual(postgrez.backend.TransactionStatus.IDLE, conn.transaction_status);
}

test "postgrez behaviour: a prepared statement is reused across executions" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var statement = try conn.prepare("SELECT * FROM users WHERE id = $1");
    defer statement.deinit();

    const User = struct {
        id: i32,
        email: []const u8,
        active: bool,
    };

    const first = try statement.query(User, .{@as(i32, 1)});
    try testing.expectEqual(@as(usize, 2), first.len);

    const second = try statement.query(User, .{@as(i32, 2)});
    try testing.expectEqual(@as(usize, 2), second.len);
}

test "postgrez behaviour: a pipeline batches statements into one round trip" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add("INSERT INTO users (email) VALUES ('one@x.y')", .{});
    try pipe.add("UPDATE users SET active = true", .{});
    try pipe.add("DELETE FROM users WHERE id = 9", .{});

    const results = try pipe.sync();

    try testing.expectEqual(@as(usize, 3), results.len);
    try testing.expectEqual(@as(u64, 1), results[0].affected);
    try testing.expectEqual(@as(u64, 2), results[1].affected);
    try testing.expectEqual(@as(u64, 1), results[2].affected);
}

test "postgrez behaviour: copy in streams rows to the backend" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var copy = try conn.copyIn("COPY ledger FROM STDIN");
    try copy.write("1\tone\n");
    try copy.write("2\ttwo\n");
    const written = try copy.finish();

    try testing.expectEqual(@as(u64, 2), written);
}

test "postgrez behaviour: copy out streams rows from the backend" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var copy = try conn.copyOut("COPY ledger TO STDOUT");

    var chunks: usize = 0;
    var bytes: usize = 0;
    while (try copy.next()) |chunk| {
        chunks += 1;
        bytes += chunk.len;
    }

    try testing.expectEqual(@as(usize, 3), chunks);
    try testing.expect(bytes > 0);
}

test "postgrez behaviour: listen and notify deliver on the same connection" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try conn.listen("zix_channel");
    try conn.notify("zix_channel", "payload-1");

    const notification = (try conn.nextNotification()).?;
    try testing.expectEqualStrings("zix_channel", notification.channel);
    try testing.expectEqualStrings("payload-1", notification.payload);
}

test "postgrez behaviour: unlisten stops the delivery" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try conn.listen("zix_channel");
    try conn.unlisten("zix_channel");

    // nothing was queued, so a following statement still runs cleanly
    try conn.notify("zix_channel", "dropped");
    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('x@y.z')", .{}));
}

test "postgrez behaviour: connect by hostname resolves localhost" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    // a DATABASE_URL commonly names the host, not an IP literal
    var config = harness.config();
    config.ip = "localhost";

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expect(conn.backend_pid != 0);
}

test "postgrez behaviour: a pool serves and returns connections" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 2;

    var pool = try postgrez.Pool.init(harness.allocator(), harness.io(), config);
    defer pool.deinit();

    const first = try pool.acquire();
    try testing.expectEqual(@as(u64, 1), try first.exec("INSERT INTO users (email) VALUES ('p@x.y')", .{}));
    pool.release(first);

    const second = try pool.acquire();
    defer pool.release(second);
    try testing.expect(second.backend_pid != 0);
}

fn parkedPoolAcquire(pool: *postgrez.Pool, out: *?*postgrez.Conn) void {
    out.* = pool.acquire() catch null;
}

test "postgrez behaviour: a pool parks an acquire and hands the connection over" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 1;
    config.process_queue_len = 1;

    var pool = try postgrez.Pool.init(harness.allocator(), harness.io(), config);
    defer pool.deinit();

    const held = try pool.acquire();

    var granted: ?*postgrez.Conn = null;
    const parker = try std.Thread.spawn(.{}, parkedPoolAcquire, .{ &pool, &granted });

    // wait until the acquire parked, then hand the connection over
    while (pool.waiterCount() == 0) std.atomic.spinLoopHint();
    pool.release(held);
    parker.join();

    const handed = granted.?;
    try testing.expectEqual(held, handed);
    pool.release(handed);
}

test "postgrez behaviour: the backend reports this session's process id" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    const Pid = struct {
        pg_backend_pid: i32,
    };

    const row = (try conn.queryRow(Pid, "SELECT pg_backend_pid()", .{})).?;

    try testing.expectEqual(conn.backend_pid, row.pg_backend_pid);
}
