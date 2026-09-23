//! Command dispatch for the in-process server: one argv in, one reply out.
//!
//! Note:
//! - Only the commands the driver's typed surface and its suites reach for are
//!   implemented. Anything else answers the same unknown-command error a real
//!   server sends, which is what the pipeline suite relies on.
//! - Reply shapes follow what the driver actually parses, not what looks
//!   tidiest. EXPIRE and PERSIST answer with an integer rather than a RESP3
//!   boolean, because the driver reads them through its integer path.
//! - Dispatch never touches the socket, it fills a ReplyWriter over a buffer.
//!   The transport sends what accumulated, so dispatch is identical whether
//!   the connection is cleartext or TLS.

const std = @import("std");

const clients = @import("clients.zig");
const keyspace_mod = @import("keyspace.zig");
const options_mod = @import("options.zig");
const wire = @import("wire.zig");

/// Error text a real server sends, reused so suites can assert on the prefix.
pub const WRONGTYPE_MESSAGE = "WRONGTYPE Operation against a key holding the wrong kind of value";
pub const NOT_AN_INTEGER_MESSAGE = "ERR value is not an integer or out of range";
pub const WRONGPASS_MESSAGE = "WRONGPASS invalid username-password pair or user is disabled";
pub const NOAUTH_MESSAGE = "NOAUTH Authentication required";
pub const NOPROTO_MESSAGE = "NOPROTO unsupported protocol version";
pub const MISCONF_MESSAGE = "MISCONF Errors writing to the RDB snapshot, writes are disabled";

/// Per-connection state that survives between commands.
pub const Session = struct {
    client: *clients.Client,
    db_index: usize = 0,
    resp3: bool = false,
    authenticated: bool = false,
    /// Reported by ACL WHOAMI.
    user: []const u8 = "default",
};

/// Everything a command may reach outside its own connection.
pub const Context = struct {
    keyspace: *keyspace_mod.Keyspace,
    registry: *clients.Registry,
    options: options_mod.Options,
};

/// Re-exported so a caller that only speaks to dispatch needs one import.
pub const Options = options_mod.Options;

pub const Error = wire.WriteError || error{OutOfMemory};

/// Run one command and write its reply.
///
/// Param:
/// ctx - Context (shared keyspace, client registry, server options)
/// session - *Session (mutated by HELLO, AUTH and SELECT)
/// argv - []const []const u8 (command name first, never empty)
/// out - *wire.ReplyWriter (reply destination, not flushed here)
/// arena - std.mem.Allocator (scratch for this command only)
///
/// Return:
/// - void, every failure the client should see is written as an error reply
/// - error.WriteFailed when the socket is gone
pub fn dispatch(
    ctx: Context,
    session: *Session,
    argv: []const []const u8,
    out: *wire.ReplyWriter,
    arena: std.mem.Allocator,
) Error!void {
    const name = argv[0];

    // HELLO and AUTH are the way in, so they run before the auth gate.
    if (eq(name, "HELLO")) return hello(ctx, session, argv, out);
    if (eq(name, "AUTH")) return auth(ctx, session, argv, out);

    if (authRequired(ctx.options) and !session.authenticated) return out.err(NOAUTH_MESSAGE);

    if (ctx.options.fail_command) |failing| {
        if (eq(name, failing)) return out.err(MISCONF_MESSAGE);
    }

    if (eq(name, "PING")) return out.simple("PONG");
    if (eq(name, "SELECT")) return select(session, argv, out);
    if (eq(name, "CLIENT")) return client(ctx, session, argv, out);
    if (eq(name, "ACL")) return acl(session, argv, out);

    if (eq(name, "SET")) return set(ctx, session, argv, out);
    if (eq(name, "GET")) return get(ctx, session, argv, out, arena);
    if (eq(name, "DEL")) return keyList(ctx, session, argv, out, .delete);
    if (eq(name, "EXISTS")) return keyList(ctx, session, argv, out, .count);
    if (eq(name, "MSET")) return mset(ctx, session, argv, out);
    if (eq(name, "MGET")) return mget(ctx, session, argv, out, arena);

    if (eq(name, "TTL")) return ttl(ctx, session, argv, out, .seconds);
    if (eq(name, "PTTL")) return ttl(ctx, session, argv, out, .millis);
    if (eq(name, "EXPIRE")) return expire(ctx, session, argv, out, std.time.ms_per_s);
    if (eq(name, "PEXPIRE")) return expire(ctx, session, argv, out, 1);
    if (eq(name, "PERSIST")) return persist(ctx, session, argv, out);
    if (eq(name, "TYPE")) return keyTypeName(ctx, session, argv, out);

    if (eq(name, "INCR")) return incrementBy(ctx, session, argv, out, 1);
    if (eq(name, "DECR")) return incrementBy(ctx, session, argv, out, -1);
    if (eq(name, "INCRBY")) return incrBy(ctx, session, argv, out);
    if (eq(name, "APPEND")) return append(ctx, session, argv, out);
    if (eq(name, "STRLEN")) return strlen(ctx, session, argv, out);

    if (eq(name, "DBSIZE")) return out.integer(@intCast(ctx.keyspace.dbSize(session.db_index)));
    if (eq(name, "FLUSHDB")) {
        ctx.keyspace.flushDb(session.db_index);

        return out.simple("OK");
    }

    if (eq(name, "RPUSH")) return rpush(ctx, session, argv, out);
    if (eq(name, "HSET")) return hset(ctx, session, argv, out, arena);
    if (eq(name, "HGETALL")) return hgetAll(ctx, session, argv, out, arena);

    return unknownCommand(argv, out, arena);
}

// --------------------------------------------------------- //

fn eq(actual: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(actual, expected);
}

fn authRequired(options: options_mod.Options) bool {
    return options.password.len > 0;
}

/// Do the offered credentials match what the server was configured with.
fn credentialsMatch(options: options_mod.Options, user: []const u8, password: []const u8) bool {
    if (!std.mem.eql(u8, options.password, password)) return false;

    // An ACL-less server accepts the implicit `default` user.
    if (options.user.len == 0) return true;

    return std.mem.eql(u8, options.user, user);
}

fn wrongArity(argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    const message = try std.fmt.allocPrint(arena, "ERR wrong number of arguments for '{s}' command", .{argv[0]});

    return out.err(message);
}

fn unknownCommand(argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    const message = try std.fmt.allocPrint(arena, "ERR unknown command '{s}'", .{argv[0]});

    return out.err(message);
}

/// Translate a keyspace failure into the error reply a real server sends.
fn keyspaceError(err: keyspace_mod.Error, out: *wire.ReplyWriter) Error!void {
    return switch (err) {
        error.RedizWrongType => out.err(WRONGTYPE_MESSAGE),
        error.RedizNotAnInteger => out.err(NOT_AN_INTEGER_MESSAGE),
        error.OutOfMemory => error.OutOfMemory,
    };
}

// --------------------------------------------------------- //

/// HELLO [version [AUTH user password] [SETNAME name]].
fn hello(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (!ctx.options.resp3_supported) return out.err(NOPROTO_MESSAGE);

    var wanted_resp3 = session.resp3;
    if (argv.len >= 2) {
        const version = std.fmt.parseInt(u8, argv[1], 10) catch return out.err(NOPROTO_MESSAGE);
        if (version != 2 and version != 3) return out.err(NOPROTO_MESSAGE);

        wanted_resp3 = version == 3;
    }

    var index: usize = 2;
    var offered_user: []const u8 = "default";
    var offered_password: ?[]const u8 = null;
    while (index < argv.len) {
        if (eq(argv[index], "AUTH") and index + 2 < argv.len) {
            offered_user = argv[index + 1];
            offered_password = argv[index + 2];
            index += 3;

            continue;
        }
        if (eq(argv[index], "SETNAME") and index + 1 < argv.len) {
            index += 2;

            continue;
        }

        index += 1;
    }

    if (authRequired(ctx.options)) {
        const password = offered_password orelse return out.err(NOAUTH_MESSAGE);
        if (!credentialsMatch(ctx.options, offered_user, password)) return out.err(WRONGPASS_MESSAGE);

        session.authenticated = true;
        session.user = offered_user;
    }

    // The reply itself must already be in the newly agreed protocol.
    session.resp3 = wanted_resp3;
    out.resp3 = wanted_resp3;

    try out.mapHeader(3);
    try out.bulk("server");
    try out.bulk("redis");
    try out.bulk("version");
    try out.bulk(ctx.options.server_version);
    try out.bulk("proto");
    try out.integer(if (wanted_resp3) 3 else 2);
}

/// AUTH password, or the two-argument AUTH user password.
fn auth(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 2 and argv.len != 3) return out.err("ERR wrong number of arguments for 'auth' command");

    if (!authRequired(ctx.options)) {
        return out.err("ERR Client sent AUTH, but no password is set");
    }

    const offered_user = if (argv.len == 3) argv[1] else "default";
    const offered_password = if (argv.len == 3) argv[2] else argv[1];
    if (!credentialsMatch(ctx.options, offered_user, offered_password)) return out.err(WRONGPASS_MESSAGE);

    session.authenticated = true;
    session.user = offered_user;

    return out.simple("OK");
}

fn select(session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments for 'select' command");

    const index = std.fmt.parseInt(usize, argv[1], 10) catch return out.err("ERR value is not an integer or out of range");
    if (index >= keyspace_mod.DB_COUNT) return out.err("ERR DB index is out of range");

    session.db_index = index;

    return out.simple("OK");
}

/// CLIENT ID and CLIENT KILL ID <id>, the two forms the pool suite uses.
fn client(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len >= 2 and eq(argv[1], "ID")) return out.integer(session.client.id);

    if (argv.len >= 4 and eq(argv[1], "KILL") and eq(argv[2], "ID")) {
        const victim = std.fmt.parseInt(i64, argv[3], 10) catch return out.err("ERR value is not an integer or out of range");

        return out.integer(if (ctx.registry.kill(victim)) 1 else 0);
    }

    return out.err("ERR syntax error");
}

fn acl(session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len >= 2 and eq(argv[1], "WHOAMI")) return out.bulk(session.user);

    return out.err("ERR syntax error");
}

// --------------------------------------------------------- //

fn set(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len < 3) return out.err("ERR wrong number of arguments for 'set' command");

    var opts = keyspace_mod.SetOptions{};
    var index: usize = 3;
    while (index < argv.len) {
        if (eq(argv[index], "NX")) {
            opts.nx = true;
            index += 1;

            continue;
        }
        if (eq(argv[index], "XX")) {
            opts.xx = true;
            index += 1;

            continue;
        }
        if (eq(argv[index], "KEEPTTL")) {
            opts.keep_ttl = true;
            index += 1;

            continue;
        }
        if ((eq(argv[index], "EX") or eq(argv[index], "PX")) and index + 1 < argv.len) {
            const amount = std.fmt.parseInt(u64, argv[index + 1], 10) catch return out.err("ERR value is not an integer or out of range");
            opts.expire_ms = if (eq(argv[index], "EX")) amount * std.time.ms_per_s else amount;
            index += 2;

            continue;
        }

        return out.err("ERR syntax error");
    }

    const written = ctx.keyspace.set(session.db_index, argv[1], argv[2], opts) catch |err| return keyspaceError(err, out);

    // A rejected NX or XX answers null, which is how the driver tells the
    // condition apart from a successful write.
    if (!written) return out.nil();

    return out.simple("OK");
}

fn get(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    if (argv.len != 2) return wrongArity(argv, out, arena);

    const value = ctx.keyspace.get(session.db_index, argv[1], arena) catch |err| return keyspaceError(err, out);

    return if (value) |bytes| out.bulk(bytes) else out.nil();
}

const KeyListMode = enum { delete, count };

fn keyList(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, mode: KeyListMode) Error!void {
    if (argv.len < 2) return out.err("ERR wrong number of arguments");

    const keys = argv[1..];
    const total = switch (mode) {
        .delete => ctx.keyspace.del(session.db_index, keys),
        .count => ctx.keyspace.exists(session.db_index, keys),
    };

    return out.integer(@intCast(total));
}

fn mset(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len < 3 or (argv.len - 1) % 2 != 0) return out.err("ERR wrong number of arguments for 'mset' command");

    var index: usize = 1;
    while (index + 1 < argv.len) : (index += 2) {
        _ = ctx.keyspace.set(session.db_index, argv[index], argv[index + 1], .{}) catch |err| return keyspaceError(err, out);
    }

    return out.simple("OK");
}

fn mget(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    if (argv.len < 2) return out.err("ERR wrong number of arguments for 'mget' command");

    const keys = argv[1..];
    try out.arrayHeader(keys.len);
    for (keys) |key| {
        // A wrong-typed key is a null element here, not a failed command.
        const value = ctx.keyspace.get(session.db_index, key, arena) catch null;
        if (value) |bytes| try out.bulk(bytes) else try out.nil();
    }
}

const TtlUnit = enum { seconds, millis };

fn ttl(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, unit: TtlUnit) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments");

    const remaining_ms = ctx.keyspace.ttlMs(session.db_index, argv[1]);

    // -1 and -2 are sentinels, never scale them into seconds.
    if (remaining_ms < 0 or unit == .millis) return out.integer(remaining_ms);

    return out.integer(@divTrunc(remaining_ms + std.time.ms_per_s - 1, std.time.ms_per_s));
}

fn expire(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, unit_ms: u64) Error!void {
    if (argv.len != 3) return out.err("ERR wrong number of arguments");

    const amount = std.fmt.parseInt(u64, argv[2], 10) catch return out.err("ERR value is not an integer or out of range");
    const applied = ctx.keyspace.expireMs(session.db_index, argv[1], amount * unit_ms);

    return out.integer(if (applied) 1 else 0);
}

fn persist(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments");

    return out.integer(if (ctx.keyspace.persist(session.db_index, argv[1])) 1 else 0);
}

fn keyTypeName(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments");

    return out.simple(ctx.keyspace.typeName(session.db_index, argv[1]));
}

fn incrementBy(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, delta: i64) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments");

    const updated = ctx.keyspace.incrBy(session.db_index, argv[1], delta) catch |err| return keyspaceError(err, out);

    return out.integer(updated);
}

fn incrBy(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 3) return out.err("ERR wrong number of arguments for 'incrby' command");

    const delta = std.fmt.parseInt(i64, argv[2], 10) catch return out.err(NOT_AN_INTEGER_MESSAGE);
    const updated = ctx.keyspace.incrBy(session.db_index, argv[1], delta) catch |err| return keyspaceError(err, out);

    return out.integer(updated);
}

fn append(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 3) return out.err("ERR wrong number of arguments for 'append' command");

    const length = ctx.keyspace.append(session.db_index, argv[1], argv[2]) catch |err| return keyspaceError(err, out);

    return out.integer(@intCast(length));
}

fn strlen(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments");

    const length = ctx.keyspace.strlen(session.db_index, argv[1]) catch |err| return keyspaceError(err, out);

    return out.integer(@intCast(length));
}

fn rpush(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter) Error!void {
    if (argv.len < 3) return out.err("ERR wrong number of arguments for 'rpush' command");

    const length = ctx.keyspace.rpush(session.db_index, argv[1], argv[2..]) catch |err| return keyspaceError(err, out);

    return out.integer(@intCast(length));
}

fn hset(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    if (argv.len < 4 or (argv.len - 2) % 2 != 0) return out.err("ERR wrong number of arguments for 'hset' command");

    const pair_count = (argv.len - 2) / 2;
    const fields = try arena.alloc(keyspace_mod.Field, pair_count);
    for (fields, 0..) |*field, index| {
        field.* = .{ .name = argv[2 + index * 2], .value = argv[3 + index * 2] };
    }

    const added = ctx.keyspace.hset(session.db_index, argv[1], fields) catch |err| return keyspaceError(err, out);

    return out.integer(@intCast(added));
}

fn hgetAll(ctx: Context, session: *Session, argv: []const []const u8, out: *wire.ReplyWriter, arena: std.mem.Allocator) Error!void {
    if (argv.len != 2) return out.err("ERR wrong number of arguments for 'hgetall' command");

    const fields = ctx.keyspace.hgetAll(session.db_index, argv[1], arena) catch |err| return keyspaceError(err, out);

    try out.mapHeader(fields.len);
    for (fields) |field| {
        try out.bulk(field.name);
        try out.bulk(field.value);
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Drives dispatch without a socket: the reply lands in a fixed buffer that
/// the test compares byte for byte.
const Harness = struct {
    threaded: std.Io.Threaded,
    keyspace: keyspace_mod.Keyspace,
    registry: clients.Registry,
    client_record: clients.Client,
    session: Session,
    arena: std.heap.ArenaAllocator,
    buf: [4096]u8,

    fn init(self: *Harness) void {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        const io = self.threaded.io();

        self.keyspace = keyspace_mod.Keyspace.init(testing.allocator, io);
        self.registry = clients.Registry.init(testing.allocator, io);
        self.client_record = .{
            .id = 7,
            .stream = .{ .socket = .{ .handle = undefined, .address = .{ .ip4 = .loopback(0) } } },
            .killed = .init(false),
        };
        self.session = .{ .client = &self.client_record };
        self.arena = std.heap.ArenaAllocator.init(testing.allocator);
    }

    fn deinit(self: *Harness) void {
        self.arena.deinit();
        self.registry.deinit();
        self.keyspace.deinit();
        self.threaded.deinit();
    }

    /// Run one command, return the exact bytes it wrote.
    fn run(self: *Harness, options: Options, argv: []const []const u8) ![]const u8 {
        var writer = std.Io.Writer.fixed(&self.buf);
        var out = wire.ReplyWriter{ .writer = &writer, .resp3 = self.session.resp3 };

        const ctx = Context{
            .keyspace = &self.keyspace,
            .registry = &self.registry,
            .options = options,
        };
        try dispatch(ctx, &self.session, argv, &out, self.arena.allocator());

        return writer.buffered();
    }

    /// Run a command on a server with no ACL configured.
    fn open(self: *Harness, argv: []const []const u8) ![]const u8 {
        return self.run(.{}, argv);
    }
};

test "rediz inproc: command hello negotiates resp3 and reports the version" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const reply = try harness.open(&.{ "HELLO", "3" });

    try testing.expect(harness.session.resp3);
    try testing.expectEqualStrings(
        "%3\r\n" ++
            "$6\r\nserver\r\n$5\r\nredis\r\n" ++
            "$7\r\nversion\r\n$5\r\n8.0.2\r\n" ++
            "$5\r\nproto\r\n:3\r\n",
        reply,
    );
}

test "rediz inproc: command hello is refused when resp3 is unsupported" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const reply = try harness.run(.{ .resp3_supported = false }, &.{ "HELLO", "3" });

    try testing.expect(!harness.session.resp3);
    try testing.expectEqualStrings("-" ++ NOPROTO_MESSAGE ++ "\r\n", reply);
}

test "rediz inproc: command hello carries inline credentials" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const acl_options = Options{ .user = "role_acl", .password = "secret" };
    const reply = try harness.run(acl_options, &.{ "HELLO", "3", "AUTH", "role_acl", "secret", "SETNAME", "app" });

    try testing.expect(harness.session.authenticated);
    try testing.expectEqualStrings("role_acl", harness.session.user);
    try testing.expect(std.mem.startsWith(u8, reply, "%3\r\n"));
}

test "rediz inproc: command hello with a wrong password answers WRONGPASS" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const acl_options = Options{ .user = "role_acl", .password = "secret" };
    const reply = try harness.run(acl_options, &.{ "HELLO", "3", "AUTH", "role_acl", "wrong" });

    try testing.expect(!harness.session.authenticated);
    try testing.expectEqualStrings("-" ++ WRONGPASS_MESSAGE ++ "\r\n", reply);
}

test "rediz inproc: command legacy two-argument auth authenticates" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const acl_options = Options{ .user = "role_acl", .password = "secret" };
    const reply = try harness.run(acl_options, &.{ "AUTH", "role_acl", "secret" });

    try testing.expect(harness.session.authenticated);
    try testing.expectEqualStrings("+OK\r\n", reply);
}

test "rediz inproc: command gate blocks an unauthenticated client" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const acl_options = Options{ .user = "role_acl", .password = "secret" };
    const reply = try harness.run(acl_options, &.{"PING"});

    try testing.expectEqualStrings("-" ++ NOAUTH_MESSAGE ++ "\r\n", reply);
}

test "rediz inproc: command set answers null when a condition rejects the write" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqualStrings("$-1\r\n", try harness.open(&.{ "SET", "k", "v", "XX" }));
    try testing.expectEqualStrings("+OK\r\n", try harness.open(&.{ "SET", "k", "v", "NX" }));
    try testing.expectEqualStrings("$-1\r\n", try harness.open(&.{ "SET", "k", "other", "NX" }));
}

test "rediz inproc: command get returns a bulk value and a null miss" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "SET", "k", "value" });

    try testing.expectEqualStrings("$5\r\nvalue\r\n", try harness.open(&.{ "GET", "k" }));
    try testing.expectEqualStrings("$-1\r\n", try harness.open(&.{ "GET", "absent" }));
}

test "rediz inproc: command ttl rounds up to seconds and keeps its sentinels" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqualStrings(":-2\r\n", try harness.open(&.{ "TTL", "absent" }));

    _ = try harness.open(&.{ "SET", "k", "v" });
    try testing.expectEqualStrings(":-1\r\n", try harness.open(&.{ "TTL", "k" }));

    _ = try harness.open(&.{ "SET", "k", "v", "EX", "30" });
    try testing.expectEqualStrings(":30\r\n", try harness.open(&.{ "TTL", "k" }));
}

test "rediz inproc: command expire and persist answer with an integer" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "SET", "k", "v" });

    try testing.expectEqualStrings(":1\r\n", try harness.open(&.{ "PEXPIRE", "k", "30000" }));
    try testing.expectEqualStrings(":1\r\n", try harness.open(&.{ "PERSIST", "k" }));
    try testing.expectEqualStrings(":0\r\n", try harness.open(&.{ "PERSIST", "k" }));
    try testing.expectEqualStrings(":0\r\n", try harness.open(&.{ "EXPIRE", "absent", "30" }));
}

test "rediz inproc: command wrongtype error carries the mapped prefix" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "RPUSH", "list", "item" });
    const reply = try harness.open(&.{ "INCR", "list" });

    try testing.expectEqualStrings("-" ++ WRONGTYPE_MESSAGE ++ "\r\n", reply);
}

test "rediz inproc: command mget reports a missing element as null" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "MSET", "a", "one", "b", "two" });
    const reply = try harness.open(&.{ "MGET", "a", "missing", "b" });

    try testing.expectEqualStrings("*3\r\n$3\r\none\r\n$-1\r\n$3\r\ntwo\r\n", reply);
}

test "rediz inproc: command select moves the connection to another database" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "SET", "k", "db0" });
    try testing.expectEqualStrings("+OK\r\n", try harness.open(&.{ "SELECT", "1" }));
    try testing.expectEqual(@as(usize, 1), harness.session.db_index);

    try testing.expectEqualStrings("$-1\r\n", try harness.open(&.{ "GET", "k" }));
    try testing.expectEqualStrings("-ERR DB index is out of range\r\n", try harness.open(&.{ "SELECT", "99" }));
}

test "rediz inproc: command client id reports this connection" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqualStrings(":7\r\n", try harness.open(&.{ "CLIENT", "ID" }));
    try testing.expectEqualStrings(":0\r\n", try harness.open(&.{ "CLIENT", "KILL", "ID", "12345" }));
}

test "rediz inproc: command hgetall shapes itself to the negotiated protocol" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.open(&.{ "HSET", "hash", "field1", "a", "field2", "b" });

    const resp2 = try harness.open(&.{ "HGETALL", "hash" });
    try testing.expectEqualStrings("*4\r\n$6\r\nfield1\r\n$1\r\na\r\n$6\r\nfield2\r\n$1\r\nb\r\n", resp2);

    harness.session.resp3 = true;
    const resp3 = try harness.open(&.{ "HGETALL", "hash" });
    try testing.expectEqualStrings("%2\r\n$6\r\nfield1\r\n$1\r\na\r\n$6\r\nfield2\r\n$1\r\nb\r\n", resp3);
}

test "rediz inproc: command unknown name answers the same error a server sends" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const reply = try harness.open(&.{ "NOSUCHCOMMAND", "x" });

    try testing.expectEqualStrings("-ERR unknown command 'NOSUCHCOMMAND'\r\n", reply);
}

test "rediz inproc: command fault injection refuses just the named command" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const refusing = Options{ .fail_command = "SET" };

    try testing.expectEqualStrings("-" ++ MISCONF_MESSAGE ++ "\r\n", try harness.run(refusing, &.{ "SET", "k", "v" }));
    try testing.expectEqualStrings("+PONG\r\n", try harness.run(refusing, &.{"PING"}));
}

test "rediz inproc: command names are matched without regard to case" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqualStrings("+PONG\r\n", try harness.open(&.{"ping"}));
    try testing.expectEqualStrings("+OK\r\n", try harness.open(&.{ "set", "k", "v" }));
    try testing.expectEqualStrings("$1\r\nv\r\n", try harness.open(&.{ "Get", "k" }));
}
