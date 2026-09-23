//! rediz integration suite: needs the live Redis 8 container
//! (containers/redis) on 127.0.0.1:63980 (cleartext) and 63981 (TLS).
//! `zig build test-integration` owns the container lifecycle, the first
//! test here polls readiness by connecting with the driver itself.
//!
//! Note:
//! - Tests run in declaration order, the readiness gate is first.
//! - Every test uses its own arena as the connection allocator, so decoded
//!   replies need no per-item frees.

const std = @import("std");
const rediz = @import("rediz");

const testing = std.testing;

const TEST_IP = "127.0.0.1";
const TEST_PORT: u16 = 63980;
const TEST_TLS_PORT: u16 = 63981;

const DEFAULT_CONFIG = rediz.Config{
    .ip = TEST_IP,
    .port = TEST_PORT,
};

const ACL_CONFIG = rediz.Config{
    .ip = TEST_IP,
    .port = TEST_PORT,
    .user = "role_acl",
    .password = "rediz_acl_pw",
};

const TLS_CONFIG = rediz.Config{
    .ip = TEST_IP,
    .port = TEST_TLS_PORT,
    .tls = .REQUIRE,
};

fn ioSleepMs(io: std.Io, ms: u32) void {
    io.sleep(.fromMilliseconds(ms), .awake) catch {};
}

test "rediz integration: 00 server becomes ready (driver-polled)" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    // first start pulls the image: allow up to 120s
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        const conn = rediz.Conn.connect(arena.allocator(), io, DEFAULT_CONFIG) catch {
            if (attempt >= 240) return error.RedizServerNeverBecameReady;
            ioSleepMs(io, 500);

            continue;
        };
        defer conn.deinit();

        // reset the keyspace so reruns start clean
        try conn.flushDb();

        return;
    }
}

test "rediz integration: 01 resp3 negotiated via hello" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);
    try testing.expect(conn.server_version_major >= 7);
    try conn.ping();
}

test "rediz integration: 02 explicit resp2 path works" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = DEFAULT_CONFIG;
    config.protocol_version = .RESP2;

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP2, conn.protocol_active);
    try conn.ping();
    try testing.expectEqual(true, try conn.set("resp2:key", "value", .{}));
    try testing.expectEqualStrings("value", (try conn.get("resp2:key")).?);
    _ = try conn.del(&.{"resp2:key"});
}

test "rediz integration: 03 acl user authenticates through hello" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), ACL_CONFIG);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);
    try conn.ping();

    // the server sees the acl identity
    const reply = try conn.command(&.{ "ACL", "WHOAMI" });
    try testing.expectEqualStrings("role_acl", reply.bulk);
}

test "rediz integration: 04 acl user authenticates through legacy two-arg auth" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = ACL_CONFIG;
    config.protocol_version = .RESP2;

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP2, conn.protocol_active);
    try conn.ping();
}

test "rediz integration: 05 wrong password surfaces WRONGPASS" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = ACL_CONFIG;
    config.password = "wrong";

    try testing.expectError(error.RedizServerError, rediz.Conn.connect(arena.allocator(), threaded.io(), config));
}

test "rediz integration: 06 tls connect round trips" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), TLS_CONFIG);
    defer conn.deinit();

    try testing.expect(conn.tls_session != null);
    try testing.expect(conn.tls_session.?.serverCertDer().len > 0);
    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);

    try conn.ping();
    try testing.expectEqual(true, try conn.set("tls:key", "over-tls", .{}));
    try testing.expectEqualStrings("over-tls", (try conn.get("tls:key")).?);
    _ = try conn.del(&.{"tls:key"});
}

test "rediz integration: 07 core commands round trip" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    // set with expiry, read back, expiry visible
    try testing.expectEqual(true, try conn.set("core:key", "hello", .{ .ex_s = 30 }));
    try testing.expectEqualStrings("hello", (try conn.get("core:key")).?);
    const ttl_left = try conn.ttl("core:key");
    try testing.expect(ttl_left > 0 and ttl_left <= 30);
    try testing.expectEqualStrings("string", try conn.keyType("core:key"));

    // expiry management
    try testing.expectEqual(true, try conn.persist("core:key"));
    try testing.expectEqual(@as(i64, -1), try conn.ttl("core:key"));
    try testing.expectEqual(true, try conn.pexpire("core:key", 30_000));
    try testing.expect(try conn.pttl("core:key") > 0);

    // counters and string ops
    try testing.expectEqual(@as(i64, 1), try conn.incr("core:counter"));
    try testing.expectEqual(@as(i64, 11), try conn.incrBy("core:counter", 10));
    try testing.expectEqual(@as(i64, 10), try conn.decr("core:counter"));
    try testing.expectEqual(@as(u64, 10), try conn.append("core:str", "0123456789"));
    try testing.expectEqual(@as(u64, 10), try conn.strlen("core:str"));

    // multi-key
    try conn.mset(&.{
        .{ .key = "core:m1", .value = "one" },
        .{ .key = "core:m2", .value = "two" },
    });
    const values = try conn.mget(&.{ "core:m1", "core:missing", "core:m2" });
    try testing.expectEqualStrings("one", values[0].?);
    try testing.expectEqual(@as(?[]const u8, null), values[1]);
    try testing.expectEqualStrings("two", values[2].?);

    // existence and deletion
    try testing.expectEqual(@as(u64, 2), try conn.exists(&.{ "core:m1", "core:m2" }));
    try testing.expectEqual(@as(u64, 2), try conn.del(&.{ "core:m1", "core:m2" }));
    try testing.expectEqual(@as(?[]const u8, null), try conn.get("core:m1"));

    _ = try conn.del(&.{ "core:key", "core:counter", "core:str" });
}

test "rediz integration: 08 set nx and xx conditions" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    _ = try conn.del(&.{"cond:key"});

    try testing.expectEqual(false, try conn.set("cond:key", "first", .{ .xx = true }));
    try testing.expectEqual(true, try conn.set("cond:key", "first", .{ .nx = true }));
    try testing.expectEqual(false, try conn.set("cond:key", "second", .{ .nx = true }));
    try testing.expectEqual(true, try conn.set("cond:key", "second", .{ .xx = true }));
    try testing.expectEqualStrings("second", (try conn.get("cond:key")).?);

    _ = try conn.del(&.{"cond:key"});
}

test "rediz integration: 09 pipeline returns ordered replies, errors as data" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add(&.{ "SET", "pipe:a", "1" });
    try pipe.add(&.{ "INCR", "pipe:a" });
    try pipe.add(&.{ "NOSUCHCOMMAND", "x" });
    try pipe.add(&.{ "GET", "pipe:a" });

    const replies = try pipe.sync();
    try testing.expectEqual(@as(usize, 4), replies.len);
    try testing.expect(replies[0].isOk());
    try testing.expectEqual(@as(i64, 2), replies[1].integer);
    try testing.expect(replies[2].isErr());
    try testing.expectEqualStrings("2", replies[3].bulk);

    _ = try conn.del(&.{"pipe:a"});
}

test "rediz integration: 10 max_pending_replies bounds a pipeline batch" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = DEFAULT_CONFIG;
    config.max_pending_replies = 2;

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add(&.{ "SET", "bound:a", "1" });
    try pipe.add(&.{ "SET", "bound:b", "2" });
    try testing.expectError(error.RedizQueueFull, pipe.add(&.{ "SET", "bound:c", "3" }));

    const replies = try pipe.sync();
    try testing.expectEqual(@as(usize, 2), replies.len);
    try testing.expect(replies[0].isOk());
    try testing.expect(replies[1].isOk());

    _ = try conn.del(&.{ "bound:a", "bound:b" });
}

test "rediz integration: 11 wrongtype surfaces the mapped prefix" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    _ = try conn.command(&.{ "RPUSH", "wrong:list", "item" });

    try testing.expectError(error.RedizServerError, conn.incr("wrong:list"));
    try testing.expectEqual(rediz.Prefix.WRONGTYPE, conn.lastServerError().prefix);

    _ = try conn.del(&.{"wrong:list"});
}

test "rediz integration: 12 pool heals a killed connection" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = DEFAULT_CONFIG;
    config.pool_size = 1;
    config.retry_max = 2;
    config.retry_delay_ms = 50;

    var pool = try rediz.Pool.init(allocator, io, config);
    defer pool.deinit();

    // learn the pooled connection's id, then give it back
    const pooled = try pool.acquire();
    const id_reply = try pooled.command(&.{ "CLIENT", "ID" });
    const pooled_id = id_reply.integer;
    pool.release(pooled);

    // kill it from a separate connection
    const killer = try rediz.Conn.connect(allocator, io, DEFAULT_CONFIG);
    defer killer.deinit();
    var id_buf: [20]u8 = undefined;
    const id_text = try std.fmt.bufPrint(&id_buf, "{d}", .{pooled_id});
    _ = try killer.command(&.{ "CLIENT", "KILL", "ID", id_text });

    // the idle slot hands back the dead connection: discard + reacquire heals
    const dead = try pool.acquire();
    try testing.expectError(error.RedizConnectionClosed, dead.ping());
    pool.discard(dead);

    const healed = try pool.acquire();
    defer pool.release(healed);
    try healed.ping();
}

test "rediz integration: 13 select isolates databases" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = DEFAULT_CONFIG;
    config.database = 1;

    const db1_conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer db1_conn.deinit();
    try db1_conn.flushDb();
    try testing.expectEqual(true, try db1_conn.set("iso:key", "db1", .{}));

    const db0_conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer db0_conn.deinit();
    try testing.expectEqual(@as(?[]const u8, null), try db0_conn.get("iso:key"));

    try db1_conn.select(0);
    try testing.expectEqual(@as(?[]const u8, null), try db1_conn.get("iso:key"));
    try db1_conn.select(1);
    try testing.expectEqualStrings("db1", (try db1_conn.get("iso:key")).?);

    _ = try db1_conn.del(&.{"iso:key"});
}

test "rediz integration: 14 dbsize and flushdb" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = DEFAULT_CONFIG;
    config.database = 2;

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    try conn.flushDb();
    try testing.expectEqual(@as(u64, 0), try conn.dbSize());

    try conn.mset(&.{
        .{ .key = "size:a", .value = "1" },
        .{ .key = "size:b", .value = "2" },
        .{ .key = "size:c", .value = "3" },
    });
    try testing.expectEqual(@as(u64, 3), try conn.dbSize());

    try conn.flushDb();
    try testing.expectEqual(@as(u64, 0), try conn.dbSize());
}

test "rediz integration: 15 typed json values round trip" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    const Rating = struct {
        score: i64,
        count: i64,
    };
    const Item = struct {
        id: i64,
        name: []const u8,
        category: ?[]const u8 = null,
        price: f64 = 0.0,
        rating: Rating,
    };

    try testing.expectEqual(true, try conn.setJson("json:item:1", Item{
        .id = 1,
        .name = "widget",
        .category = "tools",
        .price = 9.5,
        .rating = .{ .score = 40, .count = 8 },
    }, .{ .ex_s = 30 }));

    const loaded = (try conn.getJson(Item, "json:item:1")).?;
    try testing.expectEqual(@as(i64, 1), loaded.id);
    try testing.expectEqualStrings("widget", loaded.name);
    try testing.expectEqualStrings("tools", loaded.category.?);
    try testing.expectEqual(@as(f64, 9.5), loaded.price);
    try testing.expectEqual(@as(i64, 40), loaded.rating.score);
    try testing.expectEqual(@as(i64, 8), loaded.rating.count);

    try testing.expectEqual(@as(?Item, null), try conn.getJson(Item, "json:item:missing"));

    // a non-json value in the key surfaces BadJson, the raw text stays readable
    _ = try conn.set("json:broken", "not-json", .{});
    try testing.expectError(error.BadJson, conn.getJson(Item, "json:broken"));
    try testing.expectEqualStrings("not-json", (try conn.get("json:broken")).?);

    _ = try conn.del(&.{ "json:item:1", "json:broken" });
}

test "rediz integration: 16 raw command reaches untyped surface" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    // hash commands have no typed wrapper yet: the raw path covers them
    _ = try conn.command(&.{ "HSET", "raw:hash", "field1", "a", "field2", "b" });

    const reply = try conn.command(&.{ "HGETALL", "raw:hash" });
    switch (reply) {
        // RESP3 returns a map
        .map => |entries| try testing.expectEqual(@as(usize, 2), entries.len),
        // RESP2 would return a flat array
        .array => |items| try testing.expectEqual(@as(usize, 4), items.len),
        else => return error.RedizProtocolViolation,
    }

    _ = try conn.del(&.{"raw:hash"});
}

test "rediz integration: 17 connect by hostname resolves localhost" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    // a REDIS_URL commonly names the host, not an IP literal
    var config = DEFAULT_CONFIG;
    config.ip = "localhost";

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    try conn.ping();
}

test "rediz integration: 18 deferred set and del are visible to a following get" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), DEFAULT_CONFIG);
    defer conn.deinit();

    // write-behind set: flushed immediately, reply drained by the get
    try conn.setDeferred("deferred:key", "v1", .{ .ex_s = 30 });
    try testing.expectEqual(@as(usize, 1), conn.pendingDeferred());
    try testing.expectEqualStrings("v1", (try conn.get("deferred:key")).?);
    try testing.expectEqual(@as(usize, 0), conn.pendingDeferred());

    // write-behind invalidation
    try conn.delDeferred(&.{"deferred:key"});
    try testing.expectEqual(@as(?[]const u8, null), try conn.get("deferred:key"));
    try testing.expectEqual(@as(u64, 0), conn.deferredErrorCount());
}

test "rediz integration: 19 deferred flood stays at the queue bound" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var config = DEFAULT_CONFIG;
    config.max_pending_replies = 8;

    const conn = try rediz.Conn.connect(arena.allocator(), threaded.io(), config);
    defer conn.deinit();

    var key_buf: [32]u8 = undefined;
    for (0..100) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "deferred:flood:{d}", .{i});
        try conn.setDeferred(key, "x", .{ .ex_s = 5 });
        try testing.expect(conn.pendingDeferred() <= 8);
    }

    try conn.drainDeferred();
    try testing.expectEqual(@as(usize, 0), conn.pendingDeferred());
    try testing.expectEqual(@as(u64, 0), conn.deferredErrorCount());
    try testing.expectEqualStrings("x", (try conn.get("deferred:flood:99")).?);

    for (0..100) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "deferred:flood:{d}", .{i});
        _ = try conn.del(&.{key});
    }
}

fn parkedPoolAcquire(pool: *rediz.Pool, out: *?*rediz.Conn) void {
    out.* = pool.acquire() catch null;
}

test "rediz integration: 20 pool parks an acquire and hands the connection over" {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    var pool_config = DEFAULT_CONFIG;
    pool_config.pool_size = 1;
    pool_config.process_queue_len = 1;

    var pool = try rediz.Pool.init(arena.allocator(), threaded.io(), pool_config);
    defer pool.deinit();

    const held = try pool.acquire();

    var granted: ?*rediz.Conn = null;
    const parker = try std.Thread.spawn(.{}, parkedPoolAcquire, .{ &pool, &granted });

    // wait until the acquire parked, then hand the connection over
    while (pool.waiterCount() == 0) std.atomic.spinLoopHint();
    pool.release(held);
    parker.join();

    const handed = granted.?;
    try testing.expectEqual(held, handed);
    try handed.ping();
    pool.release(handed);
}
