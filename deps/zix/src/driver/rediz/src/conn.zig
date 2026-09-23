//! Connection: TCP (or TLS) transport, the HELLO handshake, and the command
//! surface (typed wrappers over one raw command round trip).
//!
//! Note:
//! - Replies are decoded into a per-command arena: any slice a command
//!   returns is valid until the NEXT command on the same connection.
//! - protocol_version .AUTO sends HELLO 3 and falls back to RESP2 (legacy AUTH) when
//!   the server refuses, .RESP3 makes that refusal an error, .RESP2 skips
//!   HELLO entirely.
//! - RESP3 push replies that arrive interleaved are skipped by the command
//!   path (Pub/Sub surfaces them in phase 2).
//! - setDeferred/delDeferred flush write-behind commands without waiting
//!   for the reply: owed replies are drained before the next reply-reading
//!   command (an error reply is captured and counted, never thrown).

const std = @import("std");
const lib = @import("lib.zig");
const resp = @import("protocol/resp.zig");
const reply_error = @import("reply_error.zig");
const pipeline_mod = @import("pipeline.zig");
const tls_mod = @import("tls.zig");

const READ_BUF_LEN = 16 * 1024;
const WRITE_BUF_LEN = 16 * 1024;

/// One key/value pair for mset().
pub const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

/// SET behavior knobs, all off by default.
pub const SetOptions = struct {
    /// Expire in seconds (0 = none).
    ex_s: u64 = 0,
    /// Expire in milliseconds (0 = none, wins over ex_s when both set).
    px_ms: u64 = 0,
    /// Only set when the key does not exist.
    nx: bool = false,
    /// Only set when the key already exists.
    xx: bool = false,
};

pub const Conn = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: lib.Config,
    stream: std.Io.net.Stream,
    stream_reader: std.Io.net.Stream.Reader,
    stream_writer: std.Io.net.Stream.Writer,
    read_buf: []u8,
    write_buf: []u8,

    /// Outgoing command batch, flushed as one send.
    send_buf: std.ArrayList(u8) = .empty,
    /// Owns every decoded reply, reset at the start of every command.
    reply_arena: std.heap.ArenaAllocator,

    /// TLS session when config.tls is .REQUIRE, null on cleartext.
    tls_session: ?*tls_mod.TlsSession = null,
    /// The protocol the handshake settled on (.AUTO resolves here).
    protocol_active: lib.RespVersion = .RESP2,
    server_version_major: u32 = 0,
    last_server_error: reply_error.ServerError = .{},

    /// Replies owed by deferred commands, drained before the next reply
    /// read. Bounded by config.max_pending_replies (0 = one at a time).
    deferred_pending: usize = 0,
    /// Error replies swallowed by the deferred drain since connect.
    deferred_error_count: u64 = 0,

    const Self = @This();

    // --------------------------------------------------------- //

    /// Connect and run the handshake.
    ///
    /// Return:
    /// - *Conn ready for commands
    /// - error.RedizPortNotConfigured / connect errors
    /// - error.RedizProtocolNotSupported (strict .RESP3 refused by the server)
    /// - error.RedizServerError (auth or select rejected, see lastServerError)
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, config: lib.Config) !*Self {
        if (config.port == 0) return error.RedizPortNotConfigured;

        const stream = try connectTcp(io, config.ip, config.port);

        return fromStream(allocator, io, config, stream);
    }

    /// TCP connect to an IP literal or a hostname. A literal skips the
    /// resolver, anything else goes through the hosts/DNS lookup
    /// (a REDIS_URL commonly carries a hostname, e.g. localhost).
    fn connectTcp(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
        if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
            return addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        } else |_| {
            const host_name = try std.Io.net.HostName.init(host);

            return host_name.connect(io, port, .{ .mode = .stream, .protocol = .tcp });
        }
    }

    /// Run the handshake over an already-connected stream. The Conn owns
    /// the stream from here on, failure included.
    pub fn fromStream(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, stream: std.Io.net.Stream) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const read_buf = try allocator.alloc(u8, READ_BUF_LEN);
        errdefer allocator.free(read_buf);
        const write_buf = try allocator.alloc(u8, WRITE_BUF_LEN);
        errdefer allocator.free(write_buf);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .stream = stream,
            .stream_reader = undefined,
            .stream_writer = undefined,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .reply_arena = std.heap.ArenaAllocator.init(allocator),
        };
        self.stream_reader = self.stream.reader(io, read_buf);
        self.stream_writer = self.stream.writer(io, write_buf);

        errdefer {
            if (self.tls_session) |session| allocator.destroy(session);
            self.send_buf.deinit(allocator);
            self.reply_arena.deinit();
            self.stream.close(io);
        }

        if (config.tls == .REQUIRE) {
            self.tls_session = try tls_mod.handshake(allocator, io, &self.stream_reader.interface, &self.stream_writer.interface);
        }

        try self.runHandshake();

        return self;
    }

    /// Close the stream and free everything (no farewell command, closing
    /// the socket is the protocol-level goodbye).
    pub fn deinit(self: *Self) void {
        const allocator = self.allocator;

        self.stream.close(self.io);

        if (self.tls_session) |session| allocator.destroy(session);
        self.send_buf.deinit(allocator);
        self.reply_arena.deinit();
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
        allocator.destroy(self);
    }

    /// The last error reply the server sent on this connection.
    pub fn lastServerError(self: *const Self) *const reply_error.ServerError {
        return &self.last_server_error;
    }

    // --------------------------------------------------------- //

    /// One raw command round trip: any command as argument slices.
    ///
    /// Return:
    /// - resp.Reply valid until the next command on this connection
    /// - error.RedizServerError with lastServerError filled on an error reply
    pub fn command(self: *Self, args: []const []const u8) !resp.Reply {
        _ = self.reply_arena.reset(.retain_capacity);

        return self.roundTrip(args);
    }

    // --------------------------------------------------------- //

    /// PING, expects PONG.
    pub fn ping(self: *Self) !void {
        const reply = try self.command(&.{"PING"});
        if (reply != .simple or !std.mem.eql(u8, reply.simple, "PONG")) return error.RedizProtocolViolation;
    }

    /// SET with optional expiry and NX/XX condition.
    ///
    /// Return:
    /// - true when the value was written
    /// - false when an NX/XX condition skipped the write
    pub fn set(self: *Self, key: []const u8, value: []const u8, opts: SetOptions) !bool {
        _ = self.reply_arena.reset(.retain_capacity);

        return self.setInner(key, value, opts);
    }

    /// SET a value stored as its JSON text (stringified via std.json), the
    /// write-side twin of getJson.
    ///
    /// Param:
    /// value - anytype (struct, array, or any std.json-stringifiable value)
    ///
    /// Return:
    /// - true when the value was written
    /// - false when an NX/XX condition skipped the write
    pub fn setJson(self: *Self, key: []const u8, value: anytype, opts: SetOptions) !bool {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();
        const body = try std.json.Stringify.valueAlloc(arena, value, .{});

        return self.setInner(key, body, opts);
    }

    /// GET a JSON value parsed into T (std.json under the hood, unknown
    /// fields ignored, a missing field falls back to its default).
    ///
    /// Return:
    /// - T with slices valid until the next command on this connection
    /// - null when the key does not exist
    /// - error.BadJson when the stored text does not parse into T
    pub fn getJson(self: *Self, comptime T: type, key: []const u8) !?T {
        const raw = (try self.get(key)) orelse return null;

        return std.json.parseFromSliceLeaky(T, self.reply_arena.allocator(), raw, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch error.BadJson;
    }

    /// Internal: SET argv build + round trip, arena already reset (set and
    /// setJson keep their arena values alive through here).
    fn setInner(self: *Self, key: []const u8, value: []const u8, opts: SetOptions) !bool {
        const arena = self.reply_arena.allocator();

        var argv_buf: [7][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "SET";
        argc += 1;
        argv_buf[argc] = key;
        argc += 1;
        argv_buf[argc] = value;
        argc += 1;
        if (opts.px_ms > 0) {
            argv_buf[argc] = "PX";
            argc += 1;
            argv_buf[argc] = try std.fmt.allocPrint(arena, "{d}", .{opts.px_ms});
            argc += 1;
        } else if (opts.ex_s > 0) {
            argv_buf[argc] = "EX";
            argc += 1;
            argv_buf[argc] = try std.fmt.allocPrint(arena, "{d}", .{opts.ex_s});
            argc += 1;
        }
        if (opts.nx) {
            argv_buf[argc] = "NX";
            argc += 1;
        } else if (opts.xx) {
            argv_buf[argc] = "XX";
            argc += 1;
        }

        const reply = try self.roundTrip(argv_buf[0..argc]);

        return switch (reply) {
            .simple => reply.isOk(),
            .null => false,
            else => error.RedizProtocolViolation,
        };
    }

    /// SET with the reply deferred (write-behind): the command is flushed
    /// to the server now, the reply is drained automatically before the
    /// next reply-reading command on this connection.
    ///
    /// Note:
    /// - An error reply found at drain time is captured into
    ///   lastServerError and counted, never thrown (best effort write).
    /// - Does not reset the reply arena: slices returned by a previous
    ///   command stay valid across deferred calls.
    /// - config.max_pending_replies bounds the outstanding deferred
    ///   replies (0 = no queueing: each call first drains the previous
    ///   one).
    pub fn setDeferred(self: *Self, key: []const u8, value: []const u8, opts: SetOptions) !void {
        var expiry_buf: [20]u8 = undefined;

        var argv_buf: [7][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "SET";
        argc += 1;
        argv_buf[argc] = key;
        argc += 1;
        argv_buf[argc] = value;
        argc += 1;
        if (opts.px_ms > 0) {
            argv_buf[argc] = "PX";
            argc += 1;
            argv_buf[argc] = std.fmt.bufPrint(&expiry_buf, "{d}", .{opts.px_ms}) catch unreachable;
            argc += 1;
        } else if (opts.ex_s > 0) {
            argv_buf[argc] = "EX";
            argc += 1;
            argv_buf[argc] = std.fmt.bufPrint(&expiry_buf, "{d}", .{opts.ex_s}) catch unreachable;
            argc += 1;
        }
        if (opts.nx) {
            argv_buf[argc] = "NX";
            argc += 1;
        } else if (opts.xx) {
            argv_buf[argc] = "XX";
            argc += 1;
        }

        try self.sendDeferred(argv_buf[0..argc]);
    }

    /// GET one key.
    ///
    /// Return:
    /// - the value (valid until the next command)
    /// - null when the key does not exist
    pub fn get(self: *Self, key: []const u8) !?[]const u8 {
        const reply = try self.command(&.{ "GET", key });

        return switch (reply) {
            .bulk => |value| value,
            .null => null,
            else => error.RedizProtocolViolation,
        };
    }

    /// DEL one or more keys, returns how many existed.
    pub fn del(self: *Self, keys: []const []const u8) !u64 {
        return self.keysCommand("DEL", keys);
    }

    /// DEL with the reply deferred, the existed-count is dropped
    /// (write-behind cache invalidation, see setDeferred for drain rules).
    pub fn delDeferred(self: *Self, keys: []const []const u8) !void {
        const arena = self.reply_arena.allocator();

        const argv = try arena.alloc([]const u8, keys.len + 1);
        argv[0] = "DEL";
        @memcpy(argv[1..], keys);

        try self.sendDeferred(argv);
    }

    /// EXISTS one or more keys, returns how many exist.
    pub fn exists(self: *Self, keys: []const []const u8) !u64 {
        return self.keysCommand("EXISTS", keys);
    }

    /// EXPIRE in seconds, returns false when the key does not exist.
    pub fn expire(self: *Self, key: []const u8, seconds: u64) !bool {
        return self.expireCommand("EXPIRE", key, seconds);
    }

    /// PEXPIRE in milliseconds, returns false when the key does not exist.
    pub fn pexpire(self: *Self, key: []const u8, millis: u64) !bool {
        return self.expireCommand("PEXPIRE", key, millis);
    }

    /// TTL in seconds (-1 = no expiry, -2 = no such key).
    pub fn ttl(self: *Self, key: []const u8) !i64 {
        return self.integerReply(&.{ "TTL", key });
    }

    /// PTTL in milliseconds (-1 = no expiry, -2 = no such key).
    pub fn pttl(self: *Self, key: []const u8) !i64 {
        return self.integerReply(&.{ "PTTL", key });
    }

    /// PERSIST, returns false when the key has no expiry to remove.
    pub fn persist(self: *Self, key: []const u8) !bool {
        return (try self.integerReply(&.{ "PERSIST", key })) == 1;
    }

    /// TYPE of a key ("string", "list", ..., "none" when missing).
    pub fn keyType(self: *Self, key: []const u8) ![]const u8 {
        const reply = try self.command(&.{ "TYPE", key });
        if (reply != .simple) return error.RedizProtocolViolation;

        return reply.simple;
    }

    /// INCR, returns the new value.
    pub fn incr(self: *Self, key: []const u8) !i64 {
        return self.integerReply(&.{ "INCR", key });
    }

    /// DECR, returns the new value.
    pub fn decr(self: *Self, key: []const u8) !i64 {
        return self.integerReply(&.{ "DECR", key });
    }

    /// INCRBY, returns the new value.
    pub fn incrBy(self: *Self, key: []const u8, delta: i64) !i64 {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();
        const delta_text = try std.fmt.allocPrint(arena, "{d}", .{delta});

        const reply = try self.roundTrip(&.{ "INCRBY", key, delta_text });
        if (reply != .integer) return error.RedizProtocolViolation;

        return reply.integer;
    }

    /// APPEND, returns the new length.
    pub fn append(self: *Self, key: []const u8, value: []const u8) !u64 {
        const reply = try self.command(&.{ "APPEND", key, value });
        if (reply != .integer or reply.integer < 0) return error.RedizProtocolViolation;

        return @intCast(reply.integer);
    }

    /// STRLEN (0 when the key does not exist).
    pub fn strlen(self: *Self, key: []const u8) !u64 {
        const reply = try self.command(&.{ "STRLEN", key });
        if (reply != .integer or reply.integer < 0) return error.RedizProtocolViolation;

        return @intCast(reply.integer);
    }

    /// MGET, one entry per key: the value, or null for a missing key. The
    /// slice and values live until the next command.
    pub fn mget(self: *Self, keys: []const []const u8) ![]?[]const u8 {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();

        const argv = try arena.alloc([]const u8, keys.len + 1);
        argv[0] = "MGET";
        @memcpy(argv[1..], keys);

        const reply = try self.roundTrip(argv);
        if (reply != .array or reply.array.len != keys.len) return error.RedizProtocolViolation;

        const values = try arena.alloc(?[]const u8, keys.len);
        for (reply.array, values) |item, *value| {
            value.* = switch (item) {
                .bulk => |bytes| bytes,
                .null => null,
                else => return error.RedizProtocolViolation,
            };
        }

        return values;
    }

    /// MSET, sets every pair atomically.
    pub fn mset(self: *Self, entries: []const KeyValue) !void {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();

        const argv = try arena.alloc([]const u8, entries.len * 2 + 1);
        argv[0] = "MSET";
        for (entries, 0..) |entry, index| {
            argv[1 + index * 2] = entry.key;
            argv[2 + index * 2] = entry.value;
        }

        const reply = try self.roundTrip(argv);
        if (!reply.isOk()) return error.RedizProtocolViolation;
    }

    /// SELECT a database index.
    pub fn select(self: *Self, database: u32) !void {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();
        const database_text = try std.fmt.allocPrint(arena, "{d}", .{database});

        const reply = try self.roundTrip(&.{ "SELECT", database_text });
        if (!reply.isOk()) return error.RedizProtocolViolation;
    }

    /// DBSIZE, key count of the selected database.
    pub fn dbSize(self: *Self) !u64 {
        const reply = try self.command(&.{"DBSIZE"});
        if (reply != .integer or reply.integer < 0) return error.RedizProtocolViolation;

        return @intCast(reply.integer);
    }

    /// FLUSHDB, wipe the selected database (test suites).
    pub fn flushDb(self: *Self) !void {
        const reply = try self.command(&.{"FLUSHDB"});
        if (!reply.isOk()) return error.RedizProtocolViolation;
    }

    /// Open a pipeline on this connection.
    pub fn pipeline(self: *Self) !pipeline_mod.Pipeline {
        return pipeline_mod.Pipeline.begin(self);
    }

    // --------------------------------------------------------- //

    /// Drain every reply owed by deferred commands. Runs automatically
    /// before any reply-reading command, public as an explicit flush point.
    ///
    /// Return:
    /// - void (an error reply is captured and counted, not thrown)
    /// - transport errors are thrown as usual (drop the connection)
    pub fn drainDeferred(self: *Self) !void {
        while (self.deferred_pending > 0) {
            const reply = try self.receiveReply(false);
            if (reply.errLine()) |line| {
                self.last_server_error.capture(line);
                self.deferred_error_count += 1;
            }

            self.deferred_pending -= 1;
        }
    }

    /// Replies still owed by deferred commands on this connection.
    pub fn pendingDeferred(self: *const Self) usize {
        return self.deferred_pending;
    }

    /// Error replies swallowed by the deferred drain since connect.
    pub fn deferredErrorCount(self: *const Self) u64 {
        return self.deferred_error_count;
    }

    /// Internal: flush one deferred command. At the outstanding bound
    /// (config.max_pending_replies, 0 = one at a time) the owed replies
    /// are drained first, so memory and reply backlog stay flat.
    fn sendDeferred(self: *Self, args: []const []const u8) !void {
        if (self.deferred_pending >= @max(self.config.max_pending_replies, 1)) try self.drainDeferred();

        self.send_buf.clearRetainingCapacity();
        try resp.encodeCommand(self.allocator, &self.send_buf, args);
        try self.flushSend();
        self.deferred_pending += 1;
    }

    // --------------------------------------------------------- //

    /// Internal: DEL/EXISTS shape, `verb key...` returning a count.
    fn keysCommand(self: *Self, verb: []const u8, keys: []const []const u8) !u64 {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();

        const argv = try arena.alloc([]const u8, keys.len + 1);
        argv[0] = verb;
        @memcpy(argv[1..], keys);

        const reply = try self.roundTrip(argv);
        if (reply != .integer or reply.integer < 0) return error.RedizProtocolViolation;

        return @intCast(reply.integer);
    }

    /// Internal: EXPIRE/PEXPIRE shape, `verb key amount` returning 1/0.
    fn expireCommand(self: *Self, verb: []const u8, key: []const u8, amount: u64) !bool {
        _ = self.reply_arena.reset(.retain_capacity);
        const arena = self.reply_arena.allocator();
        const amount_text = try std.fmt.allocPrint(arena, "{d}", .{amount});

        const reply = try self.roundTrip(&.{ verb, key, amount_text });

        return (try expectInteger(reply)) == 1;
    }

    /// Internal: one command whose reply must be an integer.
    fn integerReply(self: *Self, args: []const []const u8) !i64 {
        const reply = try self.command(args);

        return expectInteger(reply);
    }

    fn expectInteger(reply: resp.Reply) !i64 {
        if (reply != .integer) return error.RedizProtocolViolation;

        return reply.integer;
    }

    // --------------------------------------------------------- //

    /// Internal: send one command and read its reply. The caller has reset
    /// (or deliberately kept) the reply arena.
    ///
    /// Note:
    /// - Pipeline batches commands itself and drains replies with
    ///   receiveReply, it never goes through here.
    pub fn roundTrip(self: *Self, args: []const []const u8) !resp.Reply {
        self.send_buf.clearRetainingCapacity();
        try resp.encodeCommand(self.allocator, &self.send_buf, args);
        try self.flushSend();

        // Deferred replies precede this command's reply on the wire (their
        // commands were flushed earlier), drain them after the send so
        // everything arrives in one readable burst.
        try self.drainDeferred();

        return self.receiveReply(true);
    }

    /// Internal: read one reply, skipping RESP3 pushes.
    ///
    /// Param:
    /// map_errors - bool (true maps an error reply to error.RedizServerError,
    /// false hands it back as data, the pipeline drain wants that)
    pub fn receiveReply(self: *Self, map_errors: bool) !resp.Reply {
        while (true) {
            const reply = try resp.decode(self.reply_arena.allocator(), &TransportSource{ .conn = self });
            if (reply == .push) continue;

            if (map_errors) {
                if (reply.errLine()) |line| {
                    self.last_server_error.capture(line);

                    return error.RedizServerError;
                }
            }

            return reply;
        }
    }

    /// Internal: send everything batched in send_buf.
    pub fn flushSend(self: *Self) !void {
        const writer = &self.stream_writer.interface;

        if (self.tls_session) |session| {
            session.writeAll(writer, self.send_buf.items) catch return error.RedizConnectionClosed;
        } else {
            writer.writeAll(self.send_buf.items) catch return error.RedizConnectionClosed;
        }
        writer.flush() catch return error.RedizConnectionClosed;
        self.send_buf.clearRetainingCapacity();
    }

    // --------------------------------------------------------- //

    /// Handshake: HELLO / AUTH per config.protocol_version, then SELECT when a
    /// non-zero database index is configured.
    fn runHandshake(self: *Self) !void {
        switch (self.config.protocol_version) {
            .RESP2 => try self.legacyAuth(),
            .AUTO, .RESP3 => try self.helloHandshake(),
        }

        if (self.config.database != 0) {
            _ = self.reply_arena.reset(.retain_capacity);
            const arena = self.reply_arena.allocator();
            const database_text = try std.fmt.allocPrint(arena, "{d}", .{self.config.database});

            self.send_buf.clearRetainingCapacity();
            try resp.encodeCommand(self.allocator, &self.send_buf, &.{ "SELECT", database_text });
            try self.flushSend();
            try self.waitReadableAfterSend();

            const reply = try self.receiveReply(true);
            if (!reply.isOk()) return error.RedizProtocolViolation;
        }
    }

    /// HELLO 3 (credentials and client name inline). A refusal falls back
    /// to RESP2 on .AUTO and fails on strict .RESP3.
    fn helloHandshake(self: *Self) !void {
        _ = self.reply_arena.reset(.retain_capacity);

        var argv_buf: [7][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "HELLO";
        argc += 1;
        argv_buf[argc] = "3";
        argc += 1;
        if (self.config.password.len > 0) {
            argv_buf[argc] = "AUTH";
            argc += 1;
            argv_buf[argc] = if (self.config.user.len > 0) self.config.user else "default";
            argc += 1;
            argv_buf[argc] = self.config.password;
            argc += 1;
        }
        if (self.config.client_name) |name| {
            argv_buf[argc] = "SETNAME";
            argc += 1;
            argv_buf[argc] = name;
            argc += 1;
        }

        self.send_buf.clearRetainingCapacity();
        try resp.encodeCommand(self.allocator, &self.send_buf, argv_buf[0..argc]);
        try self.flushSend();
        try self.waitReadableAfterSend();

        const reply = try self.receiveReply(false);

        if (reply.errLine()) |line| {
            self.last_server_error.capture(line);

            // NOPROTO (or pre-HELLO "unknown command"): the server cannot
            // speak RESP3
            const refused = self.last_server_error.prefix == .NOPROTO or
                self.last_server_error.prefix == .ERR;
            if (!refused) return error.RedizServerError;
            if (self.config.protocol_version == .RESP3) return error.RedizProtocolNotSupported;

            try self.legacyAuth();

            return;
        }

        if (reply != .map) return error.RedizProtocolViolation;
        self.protocol_active = .RESP3;
        self.captureServerVersion(reply.map);
    }

    /// RESP2 path: no HELLO, credentials go through AUTH when configured.
    fn legacyAuth(self: *Self) !void {
        self.protocol_active = .RESP2;
        if (self.config.password.len == 0) return;

        _ = self.reply_arena.reset(.retain_capacity);

        const argv: []const []const u8 = if (self.config.user.len > 0)
            &.{ "AUTH", self.config.user, self.config.password }
        else
            &.{ "AUTH", self.config.password };

        self.send_buf.clearRetainingCapacity();
        try resp.encodeCommand(self.allocator, &self.send_buf, argv);
        try self.flushSend();
        try self.waitReadableAfterSend();

        const reply = try self.receiveReply(true);
        if (!reply.isOk()) return error.RedizProtocolViolation;
    }

    fn captureServerVersion(self: *Self, entries: []resp.MapEntry) void {
        for (entries) |entry| {
            const key = switch (entry.key) {
                .bulk => |bytes| bytes,
                .simple => |bytes| bytes,
                else => continue,
            };
            if (!std.mem.eql(u8, key, "version")) continue;

            const version_text = switch (entry.value) {
                .bulk => |bytes| bytes,
                .simple => |bytes| bytes,
                else => return,
            };
            const major_end = std.mem.indexOfScalar(u8, version_text, '.') orelse version_text.len;
            self.server_version_major = std.fmt.parseInt(u32, version_text[0..major_end], 10) catch 0;

            return;
        }
    }

    // --------------------------------------------------------- //

    /// Internal: read exactly buf.len bytes through the transport.
    fn transportReadAll(self: *Self, buf: []u8) !void {
        if (self.tls_session) |session| {
            session.readAll(&self.stream_reader.interface, buf) catch return error.RedizConnectionClosed;

            return;
        }

        self.stream_reader.interface.readSliceAll(buf) catch return error.RedizConnectionClosed;
    }

    /// Internal: one protocol line into buf, CRLF stripped.
    fn transportReadLine(self: *Self, buf: []u8) ![]const u8 {
        var len: usize = 0;

        while (true) {
            var byte: u8 = undefined;
            if (self.tls_session) |session| {
                var one: [1]u8 = undefined;
                session.readAll(&self.stream_reader.interface, &one) catch return error.RedizConnectionClosed;
                byte = one[0];
            } else {
                byte = self.stream_reader.interface.takeByte() catch return error.RedizConnectionClosed;
            }

            if (byte == '\n') {
                if (len == 0 or buf[len - 1] != '\r') return error.RedizProtocolViolation;

                return buf[0 .. len - 1];
            }

            if (len >= buf.len) return error.RedizProtocolViolation;
            buf[len] = byte;
            len += 1;
        }
    }

    /// Bound the handshake replies by conn_timeout_ms (0 disables).
    fn waitReadableAfterSend(self: *Self) !void {
        // No poll over the ntdll path: conn_timeout_ms degrades to a blocking
        // read on Windows.
        if (comptime @import("builtin").target.os.tag == .windows) return;

        if (self.config.conn_timeout_ms == 0) return;
        if (self.stream_reader.interface.bufferedLen() > 0) return;
        if (self.tls_session) |session| {
            if (session.bufferedLen() > 0) return;
        }

        var poll_fds = [1]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const timeout_ms: i32 = @intCast(@min(self.config.conn_timeout_ms, @as(u32, std.math.maxInt(i32))));

        const ready = std.posix.poll(&poll_fds, timeout_ms) catch return error.RedizConnectionClosed;
        if (ready == 0) return error.RedizConnectTimeout;
    }
};

/// Adapter between the transport and the resp decoder.
const TransportSource = struct {
    conn: *Conn,

    pub fn readLine(self: *const TransportSource, buf: []u8) ![]const u8 {
        return self.conn.transportReadLine(buf);
    }

    pub fn readExact(self: *const TransportSource, buf: []u8) !void {
        return self.conn.transportReadAll(buf);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A scripted mock server: all server bytes are pre-written into one end
/// of a loopback TCP pair, the Conn reads them as the flow advances. Client
/// writes land in the socket buffer unread, which is fine for scripted flows.
const MOCK_SERVER_PORT: u16 = 19200;

const MockServer = struct {
    conn_fd: std.posix.fd_t,
    script_stream: std.Io.net.Stream,

    fn init(io: std.Io, script: []const u8) !MockServer {
        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", MOCK_SERVER_PORT);
        var listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        defer listener.deinit(io);

        const Accepted = struct {
            listener: *std.Io.net.Server,
            io: std.Io,
            stream: std.Io.net.Stream = undefined,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.stream = self.listener.accept(self.io) catch |e| {
                    self.err = e;
                    return;
                };
            }
        };

        var accepted = Accepted{ .listener = &listener, .io = io };
        const t = try std.Thread.spawn(.{}, Accepted.run, .{&accepted});

        const client_stream = try addr.connect(io, .{ .mode = .stream });
        t.join();
        if (accepted.err) |e| return e;

        var write_buf: [4096]u8 = undefined;
        var writer = accepted.stream.writer(io, &write_buf);
        try writer.interface.writeAll(script);
        try writer.interface.flush();

        return .{ .conn_fd = client_stream.socket.handle, .script_stream = accepted.stream };
    }

    fn stream(self: *const MockServer) std.Io.net.Stream {
        return .{ .socket = .{ .handle = self.conn_fd, .address = .{ .ip4 = .loopback(0) } } };
    }
};

/// A live scripted connection. The script side of the loopback pair stays
/// open for the whole test so post-handshake sends do not hit EPIPE.
const Scripted = struct {
    conn: *Conn,
    script_stream: std.Io.net.Stream,

    fn deinit(self: *const Scripted, io: std.Io) void {
        self.conn.deinit();
        self.script_stream.close(io);
    }
};

const HELLO_OK_SCRIPT =
    "%3\r\n" ++
    "$6\r\nserver\r\n$5\r\nredis\r\n" ++
    "$7\r\nversion\r\n$5\r\n8.0.2\r\n" ++
    "$5\r\nproto\r\n:3\r\n";

fn connectScripted(io: std.Io, script: []const u8, config: lib.Config) !Scripted {
    const mock = try MockServer.init(io, script);
    errdefer mock.script_stream.close(io);

    const conn = try Conn.fromStream(testing.allocator, io, config, mock.stream());

    return .{ .conn = conn, .script_stream = mock.script_stream };
}

test "rediz: conn mock hello negotiates resp3 and captures version" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const scripted = try connectScripted(threaded.io(), HELLO_OK_SCRIPT, .{});
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(lib.RespVersion.RESP3, scripted.conn.protocol_active);
    try testing.expectEqual(@as(u32, 8), scripted.conn.server_version_major);
}

test "rediz: conn mock noproto falls back to resp2 on auto" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const scripted = try connectScripted(threaded.io(), "-NOPROTO unsupported protocol version\r\n", .{});
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(lib.RespVersion.RESP2, scripted.conn.protocol_active);
}

test "rediz: conn mock noproto fails a strict resp3 config" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.RedizProtocolNotSupported, connectScripted(
        threaded.io(),
        "-NOPROTO unsupported protocol version\r\n",
        .{ .protocol_version = .RESP3 },
    ));
}

test "rediz: conn mock resp2 fallback runs legacy auth" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // HELLO refused, then AUTH accepted
    const script = "-ERR unknown command 'HELLO'\r\n" ++ "+OK\r\n";
    const scripted = try connectScripted(threaded.io(), script, .{ .password = "secret" });
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(lib.RespVersion.RESP2, scripted.conn.protocol_active);
}

test "rediz: conn mock wrong password surfaces server error" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.RedizServerError, connectScripted(
        threaded.io(),
        "-WRONGPASS invalid username-password pair or user is disabled.\r\n",
        .{ .user = "app", .password = "bad" },
    ));
}

test "rediz: conn mock selects a non-zero database" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++ "+OK\r\n";
    const scripted = try connectScripted(threaded.io(), script, .{ .database = 2 });
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(lib.RespVersion.RESP3, scripted.conn.protocol_active);
}

test "rediz: conn mock command surface round trips" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++
        "+PONG\r\n" ++ // ping
        "+OK\r\n" ++ // set
        "$5\r\nhello\r\n" ++ // get hit
        "$-1\r\n" ++ // get miss
        ":1\r\n" ++ // del
        ":7\r\n" ++ // incr
        ":-2\r\n" ++ // ttl missing key
        "*3\r\n$1\r\na\r\n$-1\r\n$1\r\nc\r\n" ++ // mget
        "+string\r\n"; // type
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.ping();
    try testing.expectEqual(true, try conn.set("key", "hello", .{ .ex_s = 1 }));
    try testing.expectEqualStrings("hello", (try conn.get("key")).?);
    try testing.expectEqual(@as(?[]const u8, null), try conn.get("missing"));
    try testing.expectEqual(@as(u64, 1), try conn.del(&.{"key"}));
    try testing.expectEqual(@as(i64, 7), try conn.incr("counter"));
    try testing.expectEqual(@as(i64, -2), try conn.ttl("missing"));

    const values = try conn.mget(&.{ "one", "two", "three" });
    try testing.expectEqualStrings("a", values[0].?);
    try testing.expectEqual(@as(?[]const u8, null), values[1]);
    try testing.expectEqualStrings("c", values[2].?);

    try testing.expectEqualStrings("string", try conn.keyType("key"));
}

test "rediz: conn mock set with nx miss returns false" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++ "$-1\r\n";
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(false, try scripted.conn.set("key", "value", .{ .nx = true }));
}

test "rediz: conn mock json set and get round trip a struct" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const Profile = struct {
        theme: []const u8,
        notifications: bool,
    };
    const User = struct {
        id: i64,
        name: []const u8,
        bio: ?[]const u8 = null,
        score: f64 = 0.0,
        profile: Profile,
    };

    const stored_json = "{\"id\":7,\"name\":\"Alice\",\"bio\":\"likes zig\",\"profile\":{\"theme\":\"dark\",\"notifications\":true},\"unknown\":1}";
    var stored_len_buf: [16]u8 = undefined;
    const stored_len = try std.fmt.bufPrint(&stored_len_buf, "${d}\r\n", .{stored_json.len});

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.appendSlice(testing.allocator, HELLO_OK_SCRIPT);
    try script.appendSlice(testing.allocator, "+OK\r\n"); // setJson
    try script.appendSlice(testing.allocator, stored_len); // getJson hit
    try script.appendSlice(testing.allocator, stored_json);
    try script.appendSlice(testing.allocator, "\r\n");
    try script.appendSlice(testing.allocator, "$-1\r\n"); // getJson miss
    try script.appendSlice(testing.allocator, "$8\r\nnot-json\r\n"); // getJson bad payload

    const scripted = try connectScripted(threaded.io(), script.items, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectEqual(true, try conn.setJson("json:user", User{
        .id = 7,
        .name = "Alice",
        .bio = "likes zig",
        .profile = .{ .theme = "dark", .notifications = true },
    }, .{ .ex_s = 1 }));

    const loaded = (try conn.getJson(User, "json:user")).?;
    try testing.expectEqual(@as(i64, 7), loaded.id);
    try testing.expectEqualStrings("Alice", loaded.name);
    try testing.expectEqualStrings("likes zig", loaded.bio.?);
    try testing.expectEqual(@as(f64, 0.0), loaded.score); // missing field -> default
    try testing.expectEqual(true, loaded.profile.notifications);
    try testing.expectEqualStrings("dark", loaded.profile.theme);

    try testing.expectEqual(@as(?User, null), try conn.getJson(User, "json:missing"));
    try testing.expectError(error.BadJson, conn.getJson(User, "json:broken"));
}

test "rediz: conn mock error reply maps to ServerError" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++ "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectError(error.RedizServerError, conn.get("a-list"));
    try testing.expectEqual(reply_error.Prefix.WRONGTYPE, conn.lastServerError().prefix);
}

test "rediz: conn mock skips resp3 push before the reply" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++
        ">2\r\n$7\r\nmessage\r\n$4\r\nnews\r\n" ++
        "+PONG\r\n";
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());

    try scripted.conn.ping();
}

test "rediz: conn mock deferred set drains before the next reply read" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // A get after the deferred set only sees "hello" when the drain
    // consumed the deferred +OK first (a simple reply to get would be a
    // protocol violation).
    const script = HELLO_OK_SCRIPT ++
        "+OK\r\n" ++ // deferred set
        "$5\r\nhello\r\n"; // get
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.setDeferred("key", "hello", .{ .ex_s = 1 });
    try testing.expectEqual(@as(usize, 1), conn.pendingDeferred());

    try testing.expectEqualStrings("hello", (try conn.get("key")).?);
    try testing.expectEqual(@as(usize, 0), conn.pendingDeferred());
    try testing.expectEqual(@as(u64, 0), conn.deferredErrorCount());
}

test "rediz: conn mock deferred error reply is captured not thrown" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++
        "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n" ++ // deferred set
        "+PONG\r\n"; // ping
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.setDeferred("a-list", "value", .{});

    try conn.ping();
    try testing.expectEqual(@as(u64, 1), conn.deferredErrorCount());
    try testing.expectEqual(reply_error.Prefix.WRONGTYPE, conn.lastServerError().prefix);
}

test "rediz: conn mock deferred without a queue drains one at a time" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++ "+OK\r\n+OK\r\n"; // two deferred sets
    const scripted = try connectScripted(threaded.io(), script, .{ .max_pending_replies = 0 });
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.setDeferred("one", "1", .{});
    try testing.expectEqual(@as(usize, 1), conn.pendingDeferred());

    // max_pending_replies 0: the second call drains the first reply first.
    try conn.setDeferred("two", "2", .{});
    try testing.expectEqual(@as(usize, 1), conn.pendingDeferred());
}

test "rediz: conn mock deferred queue bound forces a drain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++ ":1\r\n:1\r\n:1\r\n"; // three deferred dels
    const scripted = try connectScripted(threaded.io(), script, .{ .max_pending_replies = 2 });
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.delDeferred(&.{"one"});
    try conn.delDeferred(&.{"two"});
    try testing.expectEqual(@as(usize, 2), conn.pendingDeferred());

    // At the bound: both owed replies drain before the third send.
    try conn.delDeferred(&.{"three"});
    try testing.expectEqual(@as(usize, 1), conn.pendingDeferred());
}

test "rediz: conn mock deferred replies drain ahead of a pipeline sync" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const script = HELLO_OK_SCRIPT ++
        ":1\r\n" ++ // deferred del
        "+OK\r\n:5\r\n"; // pipeline: set, incr
    const scripted = try connectScripted(threaded.io(), script, .{});
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try conn.delDeferred(&.{"stale"});

    var pipe = try conn.pipeline();
    try pipe.add(&.{ "SET", "key", "value" });
    try pipe.add(&.{ "INCR", "counter" });
    const replies = try pipe.sync();

    try testing.expectEqual(@as(usize, 2), replies.len);
    try testing.expect(replies[0].isOk());
    try testing.expectEqual(@as(i64, 5), replies[1].integer);
    try testing.expectEqual(@as(usize, 0), conn.pendingDeferred());
}

test "rediz: conn mock deferred transport error surfaces on drain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const mock = try MockServer.init(threaded.io(), HELLO_OK_SCRIPT);
    const conn = try Conn.fromStream(testing.allocator, threaded.io(), .{}, mock.stream());
    defer conn.deinit();

    try conn.setDeferred("key", "value", .{});

    // The peer goes away with a reply still owed: the next command fails
    // on the transport, the consumer drops the connection.
    mock.script_stream.close(threaded.io());
    try testing.expectError(error.RedizConnectionClosed, conn.get("key"));
}
