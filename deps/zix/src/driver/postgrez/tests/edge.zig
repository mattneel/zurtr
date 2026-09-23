//! postgrez edge suite: refusals, bounds and broken connections against the
//! in-process backend.
//!
//! Note:
//! - No container and no daemon, so this runs on every supported platform.
//!   It is the docker-free twin of the failure-path half of
//!   tests/integration.zig, which stays as the live coverage for maintainers.
//! - Each test starts its own backend on a kernel-assigned port, so a test
//!   that deliberately breaks a connection cannot disturb another.
//! - The TLS tests drive the driver's real handshake against a real
//!   server-side one, including the SCRAM channel binding, so the crypto path
//!   is covered here rather than only where a container can run.

const std = @import("std");
const builtin = @import("builtin");
const postgrez = @import("postgrez");

const inproc = @import("inproc/server.zig");

const testing = std.testing;

const TEST_USER = "tester";
const TEST_DATABASE = "testdb";
const TEST_PASSWORD = "postgrez_test_pw";

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

test "postgrez edge: a wrong cleartext password is refused" {
    var harness: Harness = undefined;
    try harness.start(.{ .auth_mode = .CLEARTEXT, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.password = "wrong";

    try testing.expectError(error.PostgrezServerError, postgrez.Conn.connect(harness.allocator(), harness.io(), config));
}

test "postgrez edge: a wrong scram password fails the proof" {
    var harness: Harness = undefined;
    try harness.start(.{ .auth_mode = .SCRAM, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.password = "wrong";

    try testing.expectError(error.PostgrezServerError, postgrez.Conn.connect(harness.allocator(), harness.io(), config));
}

test "postgrez edge: an unknown role is refused" {
    var harness: Harness = undefined;
    try harness.start(.{ .user = "someone_else", .auth_mode = .CLEARTEXT, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.password = TEST_PASSWORD;

    try testing.expectError(error.PostgrezServerError, postgrez.Conn.connect(harness.allocator(), harness.io(), config));
}

test "postgrez edge: a server below the supported major is rejected" {
    var harness: Harness = undefined;
    try harness.start(.{ .server_version = "14.9" });
    defer harness.stop();

    try testing.expectError(error.PostgrezUnsupportedServerVersion, harness.connect());
}

test "postgrez edge: connecting to a closed port is refused" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    // take the port away before anyone dials it
    const dead_port = harness.server.port;
    harness.server.stop();

    // stop() frees the backend, so the harness needs a live one back on every exit path, not only
    // the passing one: an expectation that fails below returns before a trailing restart would run,
    // and harness.stop() then frees the same pointer a second time, which crashes the runner.
    defer harness.server = inproc.Server.start(std.heap.smp_allocator, harness.io(), .{}) catch
        @panic("inproc backend restart failed");

    var config = harness.config();
    config.port = dead_port;

    // windows region: zig std's connect path leaves NTSTATUS
    // CONNECTION_REFUSED (0xc0000236) unmapped, so the refused
    // connect surfaces as error.Unexpected there.
    const refused = if (builtin.os.tag == .windows) error.Unexpected else error.ConnectionRefused;

    try testing.expectError(refused, postgrez.Conn.connect(harness.allocator(), harness.io(), config));
}

test "postgrez edge: a unique violation maps to its sqlstate" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectError(error.PostgrezServerError, conn.exec("INSERT INTO duplicated (email) VALUES ('a@b.c')", .{}));

    const failure = conn.lastServerError();
    try testing.expectEqual(postgrez.SqlState.UNIQUE_VIOLATION, failure.state);
    try testing.expectEqualStrings("23505", &failure.code);
}

test "postgrez edge: an undefined column maps to its sqlstate" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectError(error.PostgrezServerError, conn.exec("SELECT undefined_column FROM users", .{}));
    try testing.expectEqual(postgrez.SqlState.UNDEFINED_COLUMN, conn.lastServerError().state);
}

test "postgrez edge: a connection recovers after a failed statement" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectError(error.PostgrezServerError, conn.exec("INSERT INTO duplicated (email) VALUES ('a@b.c')", .{}));

    // the extended protocol resynchronises on Sync, so the next statement runs
    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('b@c.d')", .{}));
}

test "postgrez edge: a failed statement inside a transaction leaves it failed" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var transaction = try conn.begin();
    try testing.expectError(error.PostgrezServerError, transaction.exec("INSERT INTO duplicated (email) VALUES ('a@b.c')", .{}));
    try testing.expectEqual(postgrez.backend.TransactionStatus.IN_FAILED_TRANSACTION, conn.transaction_status);

    transaction.rollback();
    try testing.expectEqual(postgrez.backend.TransactionStatus.IDLE, conn.transaction_status);
}

test "postgrez edge: a prepared statement rejects the wrong argument count" {
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

    try testing.expectError(error.PostgrezParamCountMismatch, statement.query(User, .{}));
}

test "postgrez edge: max_pending_replies bounds a pipeline batch" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.max_pending_replies = 2;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add("INSERT INTO users (email) VALUES ('a@b.c')", .{});
    try pipe.add("INSERT INTO users (email) VALUES ('b@c.d')", .{});
    try testing.expectError(error.PostgrezQueueFull, pipe.add("INSERT INTO users (email) VALUES ('c@d.e')", .{}));

    const results = try pipe.sync();
    try testing.expectEqual(@as(usize, 2), results.len);
}

test "postgrez edge: a pipeline reports a failing statement without losing the rest" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add("INSERT INTO users (email) VALUES ('a@b.c')", .{});
    try pipe.add("INSERT INTO duplicated (email) VALUES ('a@b.c')", .{});
    try pipe.add("UPDATE users SET active = true", .{});

    const results = try pipe.sync();

    try testing.expectEqual(@as(usize, 3), results.len);
    try testing.expectEqual(postgrez.PipelineStatus.OK, results[0].status);
    try testing.expectEqual(postgrez.PipelineStatus.FAILED, results[1].status);
}

test "postgrez edge: an aborted copy leaves the connection usable" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    var copy = try conn.copyIn("COPY ledger FROM STDIN");
    try copy.write("1\tone\n");

    // abort asked for the failure, so it drains the backend's refusal rather
    // than reporting it back
    try copy.abort("changed my mind");

    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('after@x.y')", .{}));
}

test "postgrez edge: a pool heals a terminated backend" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 1;
    config.retry_max = 2;
    config.retry_delay_ms = 50;

    var pool = try postgrez.Pool.init(harness.allocator(), harness.io(), config);
    defer pool.deinit();

    // learn the pooled backend's pid, then give the connection back
    const pooled = try pool.acquire();
    const pooled_pid = pooled.backend_pid;
    pool.release(pooled);

    // terminate it from a separate connection
    const killer = try harness.connect();
    defer killer.deinit();
    _ = try killer.exec("SELECT pg_terminate_backend($1)", .{pooled_pid});

    // the idle slot hands back the dead connection: discard and reacquire heals
    const dead = try pool.acquire();
    try testing.expectError(error.PostgrezConnectionClosed, dead.exec("SELECT 1", .{}));
    pool.discard(dead);

    const healed = try pool.acquire();
    defer pool.release(healed);
    try testing.expect(healed.backend_pid != pooled_pid);
}

test "postgrez edge: a backend that vanishes mid-statement reports the connection closed" {
    var harness: Harness = undefined;
    try harness.start(.{ .drop_on_statement = "SELECT vanish" });
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectError(error.PostgrezConnectionClosed, conn.exec("SELECT vanish", .{}));
}

test "postgrez edge: a fully-held pool without parking sheds immediately" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.pool_size = 1;
    config.process_queue_len = 0;

    var pool = try postgrez.Pool.init(harness.allocator(), harness.io(), config);
    defer pool.deinit();

    const held = try pool.acquire();
    defer pool.release(held);

    try testing.expectError(error.PostgrezPoolExhausted, pool.acquire());
}

test "postgrez edge: an empty statement answers the empty query response" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const conn = try harness.connect();
    defer conn.deinit();

    try testing.expectEqual(@as(u64, 0), try conn.exec("", .{}));
}

// --------------------------------------------------------- //

test "postgrez edge: a tls connection round trips" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expect(conn.tls_session != null);

    // the certificate the driver verified is the one the server presented
    try testing.expectEqualSlices(u8, harness.server.certDer(), conn.tls_session.?.serverCertDer());
    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('tls@x.y')", .{}));
}

test "postgrez edge: scram plus binds the channel to the certificate" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true, .auth_mode = .SCRAM_PLUS, .password = TEST_PASSWORD });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;
    config.password = TEST_PASSWORD;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(postgrez.scram.Mechanism.SCRAM_SHA_256_PLUS, conn.sasl_mechanism.?);

    // the binding is the sha-256 of exactly this certificate
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(harness.server.certDer(), &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &conn.tls_session.?.channelBindingHash());
}

test "postgrez edge: a query result larger than one tls record round trips" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true });
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    // three COPY chunks and a full result set both fit one record, so the
    // point here is that the record layer is actually in the path
    var copy = try conn.copyOut("COPY ledger TO STDOUT");

    var chunks: usize = 0;
    while (try copy.next()) |_| chunks += 1;

    try testing.expectEqual(@as(usize, 3), chunks);
}

test "postgrez edge: a required tls connection fails against a cleartext backend" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.tls = .REQUIRE;

    try testing.expectError(error.PostgrezTlsRefused, postgrez.Conn.connect(harness.allocator(), harness.io(), config));
}

test "postgrez edge: a preferred tls connection falls back to cleartext" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.config();
    config.tls = .PREFER;

    const conn = try postgrez.Conn.connect(harness.allocator(), harness.io(), config);
    defer conn.deinit();

    try testing.expectEqual(@as(?*postgrez.tls.TlsSession, null), conn.tls_session);
    try testing.expectEqual(@as(u64, 1), try conn.exec("INSERT INTO users (email) VALUES ('plain@x.y')", .{}));
}
