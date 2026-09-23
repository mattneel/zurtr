//! rediz behaviour suite: the driver against the in-process server.
//!
//! Note:
//! - No container and no daemon, so this runs on every supported platform.
//!   It is the docker-free twin of the happy-path half of tests/integration.zig,
//!   which keeps the live PostgreSQL-style coverage against a real Redis 8 for
//!   maintainers.
//! - Each test starts its own server on a kernel-assigned port, so the keyspace
//!   is clean by construction and tests never collide.
//! - What is proven here is the driver, not the server. The server is exercised by
//!   its own tests under tests/inproc/.

const std = @import("std");
const rediz = @import("rediz");

const inproc = @import("inproc/server.zig");

const testing = std.testing;

/// One in-process server plus the io it runs on, the three lines every test opens with.
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

    fn config(self: *Harness) rediz.Config {
        return .{ .ip = inproc.IP, .port = self.server.port };
    }

    fn connect(self: *Harness) !*rediz.Conn {
        return rediz.Conn.connect(self.allocator(), self.io(), self.config());
    }
};

test "rediz behaviour: resp3 is negotiated through hello" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);
    try testing.expect(conn.server_version_major >= 7);
    try conn.ping();
}

test "rediz behaviour: an explicit resp2 connection round trips" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.protocol_version = .RESP2;

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP2, conn.protocol_active);
    try conn.ping();
    try testing.expectEqual(true, try conn.set("resp2:key", "value", .{}));
    try testing.expectEqualStrings("value", (try conn.get("resp2:key")).?);
    try testing.expectEqual(@as(u64, 1), try conn.del(&.{"resp2:key"}));
}

test "rediz behaviour: auto falls back to resp2 when hello is refused" {
    var harness: Harness = undefined;
    try harness.start(.{ .resp3_supported = false });
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP2, conn.protocol_active);
    try conn.ping();
}

test "rediz behaviour: an acl user authenticates through hello" {
    var harness: Harness = undefined;
    try harness.start(.{ .user = "role_acl", .password = "rediz_acl_pw" });
    defer harness.stop();

    var config = harness.config();
    config.user = "role_acl";
    config.password = "rediz_acl_pw";

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);
    try conn.ping();

    const reply = try conn.command(&.{ "ACL", "WHOAMI" });
    try testing.expectEqualStrings("role_acl", reply.bulk);
}

test "rediz behaviour: an acl user authenticates through legacy two-arg auth" {
    var harness: Harness = undefined;
    try harness.start(.{ .user = "role_acl", .password = "rediz_acl_pw" });
    defer harness.stop();

    var config = harness.config();
    config.user = "role_acl";
    config.password = "rediz_acl_pw";
    config.protocol_version = .RESP2;

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(rediz.RespVersion.RESP2, conn.protocol_active);
    try conn.ping();
}

test "rediz behaviour: a tls connection round trips" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expect(conn.tls_session != null);

    // the certificate the driver verified is the one the server presented
    try testing.expectEqualSlices(u8, harness.server.certDer(), conn.tls_session.?.serverCertDer());
    try testing.expectEqual(rediz.RespVersion.RESP3, conn.protocol_active);

    try conn.ping();
    try testing.expectEqual(true, try conn.set("tls:key", "over-tls", .{}));
    try testing.expectEqualStrings("over-tls", (try conn.get("tls:key")).?);
    try testing.expectEqual(@as(u64, 1), try conn.del(&.{"tls:key"}));
}

test "rediz behaviour: a tls connection carries an authenticated handshake" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true, .user = "role_acl", .password = "rediz_acl_pw" });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;
    config.user = "role_acl";
    config.password = "rediz_acl_pw";

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try conn.ping();

    const reply = try conn.command(&.{ "ACL", "WHOAMI" });
    try testing.expectEqualStrings("role_acl", reply.bulk);
}

test "rediz behaviour: a tls pipeline keeps reply order across records" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add(&.{ "SET", "tls:pipe", "1" });
    try pipe.add(&.{ "INCR", "tls:pipe" });
    try pipe.add(&.{ "GET", "tls:pipe" });

    const replies = try pipe.sync();
    try testing.expectEqual(@as(usize, 3), replies.len);
    try testing.expect(replies[0].isOk());
    try testing.expectEqual(@as(i64, 2), replies[1].integer);
    try testing.expectEqualStrings("2", replies[2].bulk);
}

test "rediz behaviour: core string, counter and expiry commands round trip" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
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
}

test "rediz behaviour: set nx and xx conditions gate the write" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(false, try conn.set("cond:key", "first", .{ .xx = true }));
    try testing.expectEqual(true, try conn.set("cond:key", "first", .{ .nx = true }));
    try testing.expectEqual(false, try conn.set("cond:key", "second", .{ .nx = true }));
    try testing.expectEqual(true, try conn.set("cond:key", "second", .{ .xx = true }));
    try testing.expectEqualStrings("second", (try conn.get("cond:key")).?);
}

test "rediz behaviour: a pipeline returns ordered replies with errors as data" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
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
}

test "rediz behaviour: select isolates databases on one connection" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.database = 1;

    const db1_conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer db1_conn.deinit();
    try testing.expectEqual(true, try db1_conn.set("iso:key", "db1", .{}));

    const db0_conn = try harness.connect();
    defer db0_conn.deinit();
    try testing.expectEqual(@as(?[]const u8, null), try db0_conn.get("iso:key"));

    try db1_conn.select(0);
    try testing.expectEqual(@as(?[]const u8, null), try db1_conn.get("iso:key"));
    try db1_conn.select(1);
    try testing.expectEqualStrings("db1", (try db1_conn.get("iso:key")).?);
}

test "rediz behaviour: dbsize follows writes and flushdb clears them" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.database = 2;

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

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

test "rediz behaviour: typed json values round trip" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
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
}

test "rediz behaviour: raw command reaches the untyped surface" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    // hash commands have no typed wrapper, the raw path covers them
    _ = try conn.command(&.{ "HSET", "raw:hash", "field1", "a", "field2", "b" });

    const reply = try conn.command(&.{ "HGETALL", "raw:hash" });
    switch (reply) {
        // RESP3 returns a map
        .map => |entries| try testing.expectEqual(@as(usize, 2), entries.len),
        // RESP2 would return a flat array
        .array => |items| try testing.expectEqual(@as(usize, 4), items.len),
        else => return error.RedizProtocolViolation,
    }
}

test "rediz behaviour: connect by hostname resolves localhost" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    // a REDIS_URL commonly names the host, not an IP literal
    var config = harness.config();
    config.ip = "localhost";

    const conn = try rediz.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try conn.ping();
}

test "rediz behaviour: deferred set and del are visible to a following get" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
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

test "rediz behaviour: a pool serves and returns connections" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 2;

    var pool = try rediz.Pool.init(harness.allocator(), harness.io(), config);
    defer pool.deinit();

    const first = try pool.acquire();
    try first.ping();
    try testing.expectEqual(true, try first.set("pool:key", "value", .{}));
    pool.release(first);

    const second = try pool.acquire();
    defer pool.release(second);
    try testing.expectEqualStrings("value", (try second.get("pool:key")).?);
}

fn parkedPoolAcquire(pool: *rediz.Pool, out: *?*rediz.Conn) void {
    out.* = pool.acquire() catch null;
}

test "rediz behaviour: a pool parks an acquire and hands the connection over" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 1;
    config.process_queue_len = 1;

    var pool = try rediz.Pool.init(harness.allocator(), harness.io(), config);
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
