//! postgrez integration suite: needs the live PostgreSQL 18 container
//! (containers/postgresql) on 127.0.0.1:54180. `zig build test-integration`
//! owns the container lifecycle, the first test here polls readiness by
//! connecting with the driver itself.
//!
//! Note:
//! - Tests run in declaration order, the readiness gate is first.
//! - Every test uses its own arena as the connection allocator, so mapped
//!   results need no per-item frees.

const std = @import("std");
const postgrez = @import("postgrez");

const testing = std.testing;

const TEST_IP = "127.0.0.1";
const TEST_PORT: u16 = 54180;
const TEST_DATABASE = "postgrez_test";

const SCRAM_CONFIG = postgrez.Config{
    .ip = TEST_IP,
    .port = TEST_PORT,
    .user = "role_scram",
    .password = "postgrez_scram_pw",
    .database = TEST_DATABASE,
};

const SCRAM_PLUS_CONFIG = postgrez.Config{
    .ip = TEST_IP,
    .port = TEST_PORT,
    .user = "role_scram_plus",
    .password = "postgrez_scram_plus_pw",
    .database = TEST_DATABASE,
    .tls = .REQUIRE,
};

const CLEARTEXT_CONFIG = postgrez.Config{
    .ip = TEST_IP,
    .port = TEST_PORT,
    .user = "role_cleartext",
    .password = "postgrez_cleartext_pw",
    .database = TEST_DATABASE,
};

fn ioSleepMs(io: std.Io, ms: u32) void {
    io.sleep(.fromMilliseconds(ms), .awake) catch {};
}

test "postgrez integration: 00 server becomes ready (driver-polled)" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    // first start pulls + initdb: allow up to 120s
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        const conn = postgrez.Conn.connect(arena.allocator(), io, SCRAM_CONFIG) catch {
            if (attempt >= 240) return error.PostgrezServerNeverBecameReady;
            ioSleepMs(io, 500);

            continue;
        };
        defer conn.deinit();

        // reset the tables so reruns start clean
        _ = try conn.exec("TRUNCATE users, ledger, metrics, logs", .{});

        return;
    }
}

test "postgrez integration: 01 protocol 3.2 negotiated on PG 18" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    try testing.expectEqual(postgrez.frontend.PROTOCOL_V3_2, conn.protocol_code);
    try testing.expect(conn.server_version_major >= 18);
    try testing.expectEqual(postgrez.scram.Mechanism.SCRAM_SHA_256, conn.sasl_mechanism.?);
    try testing.expect(conn.backend_pid != 0);
}

test "postgrez integration: 02 scram plus over TLS binds the channel" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_PLUS_CONFIG);
    defer conn.deinit();

    try testing.expect(conn.tls_session != null);
    try testing.expectEqual(postgrez.scram.Mechanism.SCRAM_SHA_256_PLUS, conn.sasl_mechanism.?);
    try testing.expect(conn.tls_session.?.serverCertDer().len > 0);

    const answer = try conn.queryRow(struct { answer: i64 }, "SELECT 42 AS answer", .{});
    try testing.expectEqual(@as(i64, 42), answer.?.answer);
}

test "postgrez integration: 03 cleartext auth with warning" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), CLEARTEXT_CONFIG);
    defer conn.deinit();

    try testing.expectEqual(@as(?postgrez.scram.Mechanism, null), conn.sasl_mechanism);
}

test "postgrez integration: 04 wrong password surfaces INVALID_PASSWORD" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var bad_config = SCRAM_CONFIG;
    bad_config.password = "wrong";

    try testing.expectError(error.PostgrezServerError, postgrez.Conn.connect(arena.allocator(), threaded.io(), bad_config));
}

const Profile = struct {
    theme: []const u8,
    notifications: bool,
};

const User = struct {
    id: i64,
    name: []const u8,
    age: u16,
    bio: ?[]const u8,
    score: f64,
    active: bool,
    tag: [16]u8,
    balance: f64,
    profile: Profile,
    created_at: i64,
};

test "postgrez integration: 05 exec, typed query, binary-first row mapper" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    const inserted = try conn.exec(
        "INSERT INTO users (name, email, age, bio, score, balance, profile) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        .{ "Alice", "alice@example.com", @as(i16, 30), "hello", @as(f64, 1.5), "12.345", "{\"theme\":\"dark\",\"notifications\":true}" },
    );
    try testing.expectEqual(@as(u64, 1), inserted);

    _ = try conn.exec(
        "INSERT INTO users (name, email, age, profile) VALUES ($1, $2, $3, $4)",
        .{ "Bob", "bob@example.com", @as(i16, 25), "{\"theme\":\"light\",\"notifications\":false}" },
    );

    const users = try conn.query(User,
        \\SELECT id, name, age, bio, score, active, tag, balance, profile, created_at
        \\FROM users ORDER BY id
    , .{});

    try testing.expectEqual(@as(usize, 2), users.len);
    try testing.expectEqualStrings("Alice", users[0].name);
    try testing.expectEqual(@as(u16, 30), users[0].age);
    try testing.expectEqualStrings("hello", users[0].bio.?);
    try testing.expectEqual(@as(f64, 1.5), users[0].score);
    try testing.expectEqual(true, users[0].active);
    try testing.expectEqual(@as(f64, 12.345), users[0].balance);
    try testing.expectEqualStrings("dark", users[0].profile.theme);
    try testing.expectEqual(true, users[0].profile.notifications);
    try testing.expect(users[0].created_at > 0);

    try testing.expectEqualStrings("Bob", users[1].name);
    try testing.expectEqual(@as(?[]const u8, null), users[1].bio);
    try testing.expectEqual(@as(f64, 0), users[1].score);
}

test "postgrez integration: 06 binary decode per OID and text fallback" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    var result = try conn.rows(
        \\SELECT 7::int2, 42::int4, 9000000000::int8, 1.5::float4, -2.25::float8,
        \\       true, 'txt'::text, '\xdeadbeef'::bytea,
        \\       '550e8400-e29b-41d4-a716-446655440000'::uuid,
        \\       12345.678::numeric, '1 day'::interval
    , .{});
    defer result.deinit();

    const row = (try result.next()).?;
    try testing.expectEqual(@as(i16, 7), try row.get(i16, 0));
    try testing.expectEqual(@as(i32, 42), try row.get(i32, 1));
    try testing.expectEqual(@as(i64, 9_000_000_000), try row.get(i64, 2));
    try testing.expectEqual(@as(f32, 1.5), try row.get(f32, 3));
    try testing.expectEqual(@as(f64, -2.25), try row.get(f64, 4));
    try testing.expectEqual(true, try row.get(bool, 5));
    try testing.expectEqualStrings("txt", try row.get([]const u8, 6));
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, try row.get([]const u8, 7));

    const uuid = try row.get([16]u8, 8);
    try testing.expectEqual(@as(u8, 0x55), uuid[0]);

    // numeric and interval have no binary decoder: text fallback
    try testing.expectEqual(@as(f64, 12345.678), try row.get(f64, 9));
    try testing.expectEqualStrings("1 day", try row.get([]const u8, 10));
}

test "postgrez integration: 07 queryRow present and absent" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    const Named = struct { name: []const u8 };

    const found = try conn.queryRow(Named, "SELECT name FROM users WHERE email = $1", .{"alice@example.com"});
    try testing.expectEqualStrings("Alice", found.?.name);

    const missing = try conn.queryRow(Named, "SELECT name FROM users WHERE email = $1", .{"nobody@example.com"});
    try testing.expectEqual(@as(?Named, null), missing);
}

test "postgrez integration: 08 unique violation maps to the SQLSTATE enum" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    try testing.expectError(error.PostgrezServerError, conn.exec(
        "INSERT INTO users (name, email, age) VALUES ($1, $2, $3)",
        .{ "Alice2", "alice@example.com", @as(i16, 31) },
    ));
    try testing.expectEqual(postgrez.SqlState.UNIQUE_VIOLATION, conn.lastServerError().state);
    try testing.expectEqualStrings("23505", &conn.lastServerError().code);

    // the connection stays usable
    const count = try conn.queryRow(struct { count: i64 }, "SELECT count(*)::int8 AS count FROM users", .{});
    try testing.expectEqual(@as(i64, 2), count.?.count);
}

test "postgrez integration: 09 transactions, explicit and callback" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    // explicit: rolled back insert is invisible
    {
        var transaction = try conn.begin();
        _ = try transaction.exec("INSERT INTO ledger (amount) VALUES ($1)", .{@as(i64, 100)});
        transaction.rollback();
    }
    const after_rollback = try conn.queryRow(struct { count: i64 }, "SELECT count(*)::int8 AS count FROM ledger", .{});
    try testing.expectEqual(@as(i64, 0), after_rollback.?.count);

    // explicit: committed insert is visible
    {
        var transaction = try conn.begin();
        defer transaction.rollback();
        _ = try transaction.exec("INSERT INTO ledger (amount) VALUES ($1)", .{@as(i64, 100)});

        try transaction.commit();
    }

    // callback sugar
    const addFifty = struct {
        fn run(transaction: *postgrez.Transaction, amount: i64) !void {
            _ = try transaction.exec("INSERT INTO ledger (amount) VALUES ($1)", .{amount});
        }
    }.run;
    try conn.transaction(addFifty, .{@as(i64, 50)});

    const total = try conn.queryRow(struct { total: i64 }, "SELECT sum(amount)::int8 AS total FROM ledger", .{});
    try testing.expectEqual(@as(i64, 150), total.?.total);
}

test "postgrez integration: 10 prepared statement reuse and text fallback" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    var prepared = try conn.prepare("INSERT INTO logs (msg) VALUES ($1)");
    defer prepared.deinit();

    for (0..3) |index| {
        var msg_buf: [16]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "log-{d}", .{index});
        const affected = try prepared.exec(.{@as([]const u8, msg)});
        try testing.expectEqual(@as(u64, 1), affected);
    }

    // described param is int2 (age), the i64 arg falls back to text
    var by_age = try conn.prepare("SELECT name FROM users WHERE age = $1");
    defer by_age.deinit();

    const named = try by_age.queryRow(struct { name: []const u8 }, .{@as(i64, 30)});
    try testing.expectEqualStrings("Alice", named.?.name);

    const log_count = try conn.queryRow(struct { count: i64 }, "SELECT count(*)::int8 AS count FROM logs", .{});
    try testing.expectEqual(@as(i64, 3), log_count.?.count);
}

test "postgrez integration: 11 pipeline batches in one round trip" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"pipe-a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"pipe-b"});
    try pipe.add("SELECT count(*) FROM logs", .{});

    const results = try pipe.sync();
    try testing.expectEqual(@as(usize, 3), results.len);
    for (results) |result| try testing.expectEqual(postgrez.PipelineStatus.OK, result.status);
    try testing.expectEqual(@as(u64, 1), results[0].affected);
}

test "postgrez integration: 12 copy in and copy out round trip" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    var copy_in = try conn.copyIn("COPY metrics (ts, value) FROM STDIN");
    try copy_in.write("2026-07-14 10:00:00\t42\n");
    try copy_in.write("2026-07-14 10:00:01\t43\n");

    const copied = try copy_in.finish();
    try testing.expectEqual(@as(u64, 2), copied);

    var copy_out = try conn.copyOut("COPY metrics TO STDOUT");
    defer copy_out.deinit();

    var lines: usize = 0;
    var sum: i64 = 0;
    while (try copy_out.next()) |line| {
        lines += 1;

        var field_it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\n"), '\t');
        _ = field_it.next();
        sum += try std.fmt.parseInt(i64, field_it.next().?, 10);
    }

    try testing.expectEqual(@as(usize, 2), lines);
    try testing.expectEqual(@as(i64, 85), sum);
}

test "postgrez integration: 13 listen and notify" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    try conn.listen("jobs");
    try conn.notify("jobs", "job-42");

    const note = (try conn.nextNotification()).?;
    try testing.expectEqualStrings("jobs", note.channel);
    try testing.expectEqualStrings("job-42", note.payload);
    try testing.expectEqual(conn.backend_pid, note.pid);

    try conn.unlisten("jobs");
}

test "postgrez integration: 14 pool heals a killed connection via retry" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var pool_config = SCRAM_CONFIG;
    pool_config.pool_size = 2;
    pool_config.retry_max = 3;
    pool_config.retry_delay_ms = 200;

    var pool = try postgrez.Pool.init(arena.allocator(), io, pool_config);
    defer pool.deinit();

    const first = try pool.acquire();
    const victim_pid = first.backend_pid;
    pool.release(first);

    // reuse: same connection comes back
    const again = try pool.acquire();
    try testing.expectEqual(victim_pid, again.backend_pid);

    // kill it from a second connection
    const killer = try pool.acquire();
    _ = try killer.exec("SELECT pg_terminate_backend($1)", .{victim_pid});
    pool.release(killer);
    ioSleepMs(io, 200);

    // the victim now fails, discard frees the slot, acquire reconnects
    try testing.expectError(error.PostgrezConnectionClosed, again.exec("SELECT 1", .{}));
    pool.discard(again);

    const healed = try pool.acquire();
    defer pool.release(healed);
    try testing.expect(healed.backend_pid != victim_pid);

    const one = try healed.queryRow(struct { one: i64 }, "SELECT 1::int8 AS one", .{});
    try testing.expectEqual(@as(i64, 1), one.?.one);
}

test "postgrez integration: 15 connect by hostname resolves localhost" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    // a DATABASE_URL commonly names the host, not an IP literal
    var config = SCRAM_CONFIG;
    config.ip = "localhost";

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    const one = try conn.queryRow(struct { one: i64 }, "SELECT 1::int8 AS one", .{});
    try testing.expectEqual(@as(i64, 1), one.?.one);
}

test "postgrez integration: 16 statement batch shares one round trip" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try postgrez.Conn.connect(arena.allocator(), threaded.io(), SCRAM_CONFIG);
    defer conn.deinit();

    var insert_log = try conn.prepare("INSERT INTO logs (msg) VALUES ($1)");
    defer insert_log.deinit();
    var count_logs = try conn.prepare("SELECT count(*)::int8 FROM logs WHERE msg LIKE 'batch-%'");
    defer count_logs.deinit();

    // two inserts and the count queued behind one Sync
    try insert_log.sendRows(.{@as([]const u8, "batch-a")});
    try insert_log.sendRows(.{@as([]const u8, "batch-b")});
    try count_logs.sendRows(.{});

    var first = try insert_log.awaitRows();
    first.deinit();
    try testing.expectEqual(@as(u64, 1), first.affected);

    var second = try insert_log.awaitRows();
    second.deinit();
    try testing.expectEqual(@as(u64, 1), second.affected);

    var counted = try count_logs.awaitRows();
    const count_row = (try counted.next()).?;
    try testing.expectEqual(@as(i64, 2), try count_row.get(i64, 0));
    counted.deinit();
}

fn parkedPoolAcquire(pool: *postgrez.Pool, out: *?*postgrez.Conn) void {
    out.* = pool.acquire() catch null;
}

test "postgrez integration: 17 pool parks an acquire and hands the connection over" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var pool_config = SCRAM_CONFIG;
    pool_config.pool_size = 1;
    pool_config.process_queue_len = 1;

    var pool = try postgrez.Pool.init(arena.allocator(), threaded.io(), pool_config);
    defer pool.deinit();

    const held = try pool.acquire();
    const held_pid = held.backend_pid;

    var granted: ?*postgrez.Conn = null;
    const parker = try std.Thread.spawn(.{}, parkedPoolAcquire, .{ &pool, &granted });

    // wait until the acquire parked, then hand the connection over
    while (pool.waiterCount() == 0) std.atomic.spinLoopHint();
    pool.release(held);
    parker.join();

    const handed = granted.?;
    try testing.expectEqual(held_pid, handed.backend_pid);

    const one = try handed.queryRow(struct { one: i64 }, "SELECT 1::int8 AS one", .{});
    try testing.expectEqual(@as(i64, 1), one.?.one);
    pool.release(handed);
}

// --------------------------------------------------------- //

// Executor probe: one echo statement (SELECT $1::int8) prepared per
// connection, so a batch proves each job runs on its own arg and its result
// comes back in order. Static because run_batch is a plain function pointer.
const EchoJob = struct {
    id: i64,
    slot: usize,
};

const ExecutorProbe = struct {
    const Kind = postgrez.Executor(EchoJob, 1);

    var results: [16]i64 = @splat(@as(i64, -1));
    var done: std.atomic.Value(u32) = .init(0);
    var break_after: std.atomic.Value(bool) = .init(false);

    fn reset() void {
        results = @splat(@as(i64, -1));
        done.store(0, .monotonic);
        break_after.store(false, .monotonic);
    }

    fn markDone(count: usize) void {
        _ = done.fetchAdd(@intCast(count), .monotonic);
    }

    fn runBatch(batch: *Kind.Batch, jobs: []const EchoJob) void {
        const echo = batch.statement(0, "SELECT $1::int8") orelse {
            markDone(jobs.len);

            return;
        };

        for (jobs) |job| echo.sendRows(.{job.id}) catch return batch.markBroken();

        for (jobs) |job| {
            var result = echo.awaitRows() catch {
                markDone(1);

                continue;
            };
            defer result.deinit();

            if (result.next() catch null) |row| results[job.slot] = row.get(i64, 0) catch -2;

            markDone(1);
        }

        // deterministic discard path: the caller can force every batch to end
        // broken, so the next batch must reconnect and still work
        if (break_after.load(.monotonic)) batch.markBroken();
    }

    fn waitDone(target: u32) !void {
        var spins: usize = 0;
        while (done.load(.monotonic) < target) : (spins += 1) {
            if (spins > 50_000_000) return error.PostgrezExecutorNeverFinished;
            std.atomic.spinLoopHint();
        }
    }
};

test "postgrez integration: 18 executor pipelines a batch of prepared reads in order" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    ExecutorProbe.reset();

    var executor = try ExecutorProbe.Kind.init(std.heap.smp_allocator, threaded.io(), SCRAM_CONFIG, .{
        .run_batch = ExecutorProbe.runBatch,
        .workers = 2,
        .stats = true,
    });
    defer executor.deinit();

    const count = 8;
    for (0..count) |slot| {
        try testing.expect(executor.submit(.{ .id = @intCast(100 + slot), .slot = slot }));
    }

    try ExecutorProbe.waitDone(count);

    // every job saw its own arg echoed back into its own slot
    for (0..count) |slot| try testing.expectEqual(@as(i64, @intCast(100 + slot)), ExecutorProbe.results[slot]);

    // stats settle just after the consumer signals done (the driver records
    // the batch once run_batch returns), so accumulate drained snapshots.
    // jobs and batches land independently: a jobs-only exit can drain all
    // 8 jobs while the batch count arrives a beat later, so wait for both.
    var seen_jobs: u64 = 0;
    var seen_batches: u64 = 0;
    var spins: usize = 0;
    while (seen_jobs < count or seen_batches < 1) : (spins += 1) {
        if (spins > 50_000_000) return error.PostgrezStatsNeverSettled;

        const stats = executor.snapshot();
        seen_jobs += stats.jobs;
        seen_batches += stats.batches;
        std.atomic.spinLoopHint();
    }

    try testing.expectEqual(@as(u64, count), seen_jobs);
    try testing.expect(seen_batches >= 1);
}

test "postgrez integration: 19 executor runInline runs on the caller thread" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    ExecutorProbe.reset();

    var executor = try ExecutorProbe.Kind.init(std.heap.smp_allocator, threaded.io(), SCRAM_CONFIG, .{
        .run_batch = ExecutorProbe.runBatch,
        .workers = 2,
    });
    defer executor.deinit();

    try testing.expect(executor.runInline(.{ .id = 4242, .slot = 0 }));

    // runInline is synchronous: the result is ready without waiting on a worker
    try testing.expectEqual(@as(i64, 4242), ExecutorProbe.results[0]);
}

test "postgrez integration: 20 executor discards a broken connection and reconnects" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    ExecutorProbe.reset();
    ExecutorProbe.break_after.store(true, .monotonic);

    var executor = try ExecutorProbe.Kind.init(std.heap.smp_allocator, threaded.io(), SCRAM_CONFIG, .{
        .run_batch = ExecutorProbe.runBatch,
        .workers = 1,
    });
    defer executor.deinit();

    // each batch ends broken, so every job forces a discard then a reconnect
    for (0..3) |slot| {
        try testing.expect(executor.submit(.{ .id = @intCast(500 + slot), .slot = slot }));
        try ExecutorProbe.waitDone(@intCast(slot + 1));
    }

    for (0..3) |slot| try testing.expectEqual(@as(i64, @intCast(500 + slot)), ExecutorProbe.results[slot]);
}
