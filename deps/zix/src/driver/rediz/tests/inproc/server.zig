//! The in-process server itself: an in-process listener that speaks enough of the
//! protocol for a suite to exercise the driver end to end, with no container.
//!
//! Note:
//! - Binds port 0 and reports the port the kernel picked, so several servers
//!   can run at once and nothing collides with a fixed test port.
//! - One thread per connection. This server serves a handful of connections,
//!   so the clarity is worth more than a multiplexed loop would be.
//! - Stop is deterministic: the flag goes up, every client socket is shut
//!   down so parked reads return, a throwaway self-connect wakes the accept,
//!   then every thread is joined. No sleeping and no spinning.
//!
//! Usage:
//! ```zig
//! const server = try Server.start(allocator, io, .{});
//! defer server.stop();
//!
//! const config = rediz.Config{ .ip = inproc.IP, .port = server.port };
//! ```

const std = @import("std");

const certificate = @import("certificate.zig");
const clients = @import("clients.zig");
const command = @import("command.zig");
const keyspace_mod = @import("keyspace.zig");
const options_mod = @import("options.zig");
const transport_mod = @import("transport.zig");
const wire = @import("wire.zig");

/// Loopback only: the server never wants to be reachable off the machine.
pub const IP = "127.0.0.1";

/// Ceiling for one command's reply. The largest a suite produces is a small
/// MGET array, this leaves generous room above that.
const REPLY_BUF_SIZE = 64 * 1024;

pub const Options = options_mod.Options;

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: options_mod.Options,
    listener: std.Io.net.Server,
    /// The port the kernel assigned, what a suite points its config at.
    port: u16,
    keyspace: keyspace_mod.Keyspace,
    registry: clients.Registry,
    /// Present only when options.tls is set. Generated once per server and
    /// presented to every connection.
    cert: ?certificate.SelfSigned,
    stopping: std.atomic.Value(bool),
    accept_thread: ?std.Thread,
    handlers: std.ArrayList(std.Thread),
    handlers_lock: std.atomic.Value(bool),

    const Self = @This();

    /// Bind, start accepting, and return once the port is known.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the server, its keyspace and its client records)
    /// io - std.Io (must outlive the server)
    /// options - options_mod.Options (credentials demanded, version reported, TLS)
    ///
    /// Return:
    /// - *Server, stop it to release the port and every thread
    pub fn start(allocator: std.mem.Allocator, io: std.Io, options: options_mod.Options) !*Self {
        const addr = try std.Io.net.IpAddress.resolve(io, IP, 0);
        const listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });

        // one certificate per server, so every connection sees the same peer
        const cert = if (options.tls)
            try certificate.SelfSigned.generate(io, options.tls_common_name)
        else
            null;

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .listener = listener,
            .port = listener.socket.address.getPort(),
            .keyspace = keyspace_mod.Keyspace.init(allocator, io),
            .registry = clients.Registry.init(allocator, io),
            .cert = cert,
            .stopping = .init(false),
            .accept_thread = null,
            .handlers = .empty,
            .handlers_lock = .init(false),
        };

        self.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{self});

        return self;
    }

    /// The certificate DER this server presents, empty on a cleartext server.
    /// A suite can compare it against what the driver reports it saw.
    pub fn certDer(self: *const Self) []const u8 {
        // capture by pointer: unwrapping by value would return a slice into a
        // copy that dies with this call
        if (self.cert) |*cert| return cert.derBytes();

        return &.{};
    }

    /// Stop accepting, drop every connection, release everything.
    pub fn stop(self: *Self) void {
        self.stopping.store(true, .release);

        // Parked handler reads only return once their socket is shut down.
        self.registry.shutdownAll();
        self.wakeAccept();

        if (self.accept_thread) |thread| thread.join();

        self.acquireHandlers();
        const pending = self.handlers.toOwnedSlice(self.allocator) catch &.{};
        self.releaseHandlers();

        for (pending) |thread| thread.join();
        self.allocator.free(pending);

        self.listener.deinit(self.io);
        self.registry.deinit();
        self.keyspace.deinit();

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Reset the keyspace between scenarios without restarting the listener.
    pub fn flushAll(self: *Self) void {
        for (0..keyspace_mod.DB_COUNT) |db_index| self.keyspace.flushDb(db_index);
    }

    /// How many connections the server currently holds, so a pool suite can
    /// assert what it opened.
    pub fn connectionCount(self: *Self) usize {
        return self.registry.count();
    }

    // --------------------------------------------------------- //

    /// A throwaway connection so the parked accept returns and sees the flag.
    /// A shutdown on a listening socket is not portable across the BSDs, so
    /// this is the wake-up that works everywhere.
    fn wakeAccept(self: *Self) void {
        var addr = std.Io.net.IpAddress.resolve(self.io, IP, self.port) catch return;
        const stream = addr.connect(self.io, .{ .mode = .stream }) catch return;
        stream.close(self.io);
    }

    fn acquireHandlers(self: *Self) void {
        while (self.handlers_lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn releaseHandlers(self: *Self) void {
        self.handlers_lock.store(false, .release);
    }

    fn acceptLoop(self: *Self) void {
        while (true) {
            const stream = self.listener.accept(self.io) catch return;
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);

                return;
            }

            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, stream }) catch {
                stream.close(self.io);

                continue;
            };

            self.acquireHandlers();
            self.handlers.append(self.allocator, thread) catch thread.detach();
            self.releaseHandlers();
        }
    }

    fn handleConnection(self: *Self, stream: std.Io.net.Stream) void {
        defer stream.close(self.io);

        const client = self.registry.add(stream) catch return;
        defer self.registry.remove(client);

        // The transport holds its own reader and writer buffers, which point
        // back into it, so it must stay put for the life of the connection.
        var transport: transport_mod.Transport = undefined;
        if (self.cert) |*cert| {
            transport.openTls(self.io, stream, cert) catch return;
        } else {
            transport.openPlain(self.io, stream);
        }

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        var reply_buf: [REPLY_BUF_SIZE]u8 = undefined;

        var session = command.Session{ .client = client };
        const ctx = command.Context{
            .keyspace = &self.keyspace,
            .registry = &self.registry,
            .options = self.options,
        };

        while (!self.stopping.load(.acquire) and !client.killed.load(.acquire)) {
            _ = arena.reset(.retain_capacity);

            const argv = wire.readCommand(&transport, arena.allocator()) catch return;

            var reply = std.Io.Writer.fixed(&reply_buf);
            var out = wire.ReplyWriter{ .writer = &reply, .resp3 = session.resp3 };
            command.dispatch(ctx, &session, argv, &out, arena.allocator()) catch return;

            transport.send(reply.buffered()) catch return;
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A bare protocol client, so these tests prove the server without depending
/// on the driver they exist to serve.
const RawClient = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    read_buf: [4096]u8,
    write_buf: [4096]u8,

    fn connect(self: *RawClient, io: std.Io, port: u16) !void {
        var addr = try std.Io.net.IpAddress.resolve(io, IP, port);
        self.io = io;
        self.stream = try addr.connect(io, .{ .mode = .stream });
        self.reader = self.stream.reader(io, &self.read_buf);
        self.writer = self.stream.writer(io, &self.write_buf);
    }

    fn close(self: *RawClient) void {
        self.stream.close(self.io);
    }

    fn send(self: *RawClient, argv: []const []const u8) !void {
        try self.writer.interface.print("*{d}\r\n", .{argv.len});
        for (argv) |arg| {
            try self.writer.interface.print("${d}\r\n", .{arg.len});
            try self.writer.interface.writeAll(arg);
            try self.writer.interface.writeAll("\r\n");
        }
        try self.writer.interface.flush();
    }

    /// One reply line, CRLF stripped. Aggregate replies need one call per line.
    fn line(self: *RawClient, buf: []u8) ![]const u8 {
        const raw = try self.reader.interface.takeDelimiterInclusive('\n');
        if (raw.len < 2) return error.RedizProtocolViolation;

        const body = raw[0 .. raw.len - 2];
        @memcpy(buf[0..body.len], body);

        return buf[0..body.len];
    }

    fn roundTrip(self: *RawClient, argv: []const []const u8, buf: []u8) ![]const u8 {
        try self.send(argv);

        return self.line(buf);
    }
};

const Harness = struct {
    threaded: std.Io.Threaded,
    server: *Server,

    fn start(self: *Harness, options: command.Options) !void {
        self.threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer self.threaded.deinit();

        self.server = try Server.start(std.heap.smp_allocator, self.threaded.io(), options);
    }

    fn stop(self: *Harness) void {
        self.server.stop();
        self.threaded.deinit();
    }
};

test "rediz inproc: server reports the port the kernel assigned" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    try testing.expect(harness.server.port != 0);
}

test "rediz inproc: server round trips a command over a real socket" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var client: RawClient = undefined;
    try client.connect(harness.threaded.io(), harness.server.port);
    defer client.close();

    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("+PONG", try client.roundTrip(&.{"PING"}, &buf));
    try testing.expectEqualStrings("+OK", try client.roundTrip(&.{ "SET", "k", "v" }, &buf));
    try testing.expectEqualStrings("$1", try client.roundTrip(&.{ "GET", "k" }, &buf));
    try testing.expectEqualStrings("v", try client.line(&buf));
}

test "rediz inproc: server keeps per-connection state apart" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    const io = harness.threaded.io();

    var first: RawClient = undefined;
    try first.connect(io, harness.server.port);
    defer first.close();

    var second: RawClient = undefined;
    try second.connect(io, harness.server.port);
    defer second.close();

    var buf: [128]u8 = undefined;

    // the first connection moves to database 1, the second stays on 0
    try testing.expectEqualStrings("+OK", try first.roundTrip(&.{ "SELECT", "1" }, &buf));
    try testing.expectEqualStrings("+OK", try first.roundTrip(&.{ "SET", "scoped", "one" }, &buf));
    try testing.expectEqualStrings("$-1", try second.roundTrip(&.{ "GET", "scoped" }, &buf));
}

test "rediz inproc: server answers a pipeline in order in one flush" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var client: RawClient = undefined;
    try client.connect(harness.threaded.io(), harness.server.port);
    defer client.close();

    try client.send(&.{ "SET", "pipe", "1" });
    try client.send(&.{ "INCR", "pipe" });
    try client.send(&.{ "NOSUCHCOMMAND", "x" });
    try client.send(&.{ "GET", "pipe" });

    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("+OK", try client.line(&buf));
    try testing.expectEqualStrings(":2", try client.line(&buf));
    try testing.expectEqualStrings("-ERR unknown command 'NOSUCHCOMMAND'", try client.line(&buf));
    try testing.expectEqualStrings("$1", try client.line(&buf));
    try testing.expectEqualStrings("2", try client.line(&buf));
}

test "rediz inproc: server tracks and forgets connections" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var client: RawClient = undefined;
    try client.connect(harness.threaded.io(), harness.server.port);

    var buf: [128]u8 = undefined;
    _ = try client.roundTrip(&.{"PING"}, &buf);

    try testing.expectEqual(@as(usize, 1), harness.server.connectionCount());

    client.close();

    // the handler notices the closed peer on its next read
    while (harness.server.connectionCount() != 0) std.atomic.spinLoopHint();
}

test "rediz inproc: server kill drops the victim connection" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    const io = harness.threaded.io();

    var victim: RawClient = undefined;
    try victim.connect(io, harness.server.port);
    defer victim.close();

    var killer: RawClient = undefined;
    try killer.connect(io, harness.server.port);
    defer killer.close();

    var buf: [128]u8 = undefined;
    const id_line = try victim.roundTrip(&.{ "CLIENT", "ID" }, &buf);
    try testing.expect(id_line[0] == ':');

    var id_text_buf: [32]u8 = undefined;
    const id_text = try std.fmt.bufPrint(&id_text_buf, "{s}", .{id_line[1..]});

    var killer_buf: [128]u8 = undefined;
    try testing.expectEqualStrings(":1", try killer.roundTrip(&.{ "CLIENT", "KILL", "ID", id_text }, &killer_buf));

    // The victim's next command has to find a dead connection. Which error names that is the
    // platform's call: Linux hands back a clean EOF, NetBSD resets the socket and std reports the
    // reset as ReadFailed. A completed round trip is the only wrong outcome here.
    if (victim.roundTrip(&.{"PING"}, &buf)) |_| return error.RedizVictimSurvivedKill else |_| {}
}

test "rediz inproc: server demands credentials when configured with them" {
    var harness: Harness = undefined;
    try harness.start(.{ .user = "role_acl", .password = "secret" });
    defer harness.stop();

    var client: RawClient = undefined;
    try client.connect(harness.threaded.io(), harness.server.port);
    defer client.close();

    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("-" ++ command.NOAUTH_MESSAGE, try client.roundTrip(&.{"PING"}, &buf));
    try testing.expectEqualStrings("+OK", try client.roundTrip(&.{ "AUTH", "role_acl", "secret" }, &buf));
    try testing.expectEqualStrings("+PONG", try client.roundTrip(&.{"PING"}, &buf));
}

test "rediz inproc: server serves several servers at once on distinct ports" {
    var first: Harness = undefined;
    try first.start(.{});
    defer first.stop();

    var second: Harness = undefined;
    try second.start(.{});
    defer second.stop();

    try testing.expect(first.server.port != second.server.port);
}
