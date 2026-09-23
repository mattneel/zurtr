//! The in-process backend itself: an in-process listener that speaks enough of the
//! PostgreSQL v3 protocol for a suite to exercise the driver end to end, with
//! no container.
//!
//! Note:
//! - Binds port 0 and reports the port the kernel picked, so several backends
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
//! const config = postgrez.Config{ .ip = inproc.IP, .port = server.port };
//! ```

const std = @import("std");

const certificate = @import("certificate.zig");
const clients = @import("clients.zig");
const options_mod = @import("options.zig");
const session_mod = @import("session.zig");
const startup_mod = @import("startup.zig");
const transport_mod = @import("transport.zig");

/// Loopback only: the server never wants to be reachable off the machine.
pub const IP = "127.0.0.1";

pub const Options = options_mod.Options;
pub const AuthMode = options_mod.AuthMode;

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: options_mod.Options,
    listener: std.Io.net.Server,
    /// The port the kernel assigned, what a suite points its config at.
    port: u16,
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
    /// allocator - std.mem.Allocator (owns the server and its client records)
    /// io - std.Io (must outlive the server)
    /// options - options_mod.Options (auth, TLS, catalog, reported version)
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

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// The certificate DER this backend presents, empty when it serves
    /// cleartext. A suite compares it against what the driver reports it saw.
    pub fn certDer(self: *const Self) []const u8 {
        // capture by pointer: unwrapping by value would return a slice into a
        // copy that dies with this call
        if (self.cert) |*cert| return cert.derBytes();

        return &.{};
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
        transport.open(self.io, stream);

        var handshake_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer handshake_arena.deinit();

        const cert: ?*const certificate.SelfSigned = if (self.cert) |*value| value else null;
        _ = startup_mod.run(&transport, self.options, cert, client, handshake_arena.allocator()) catch return;

        var session = session_mod.Session.init(
            self.allocator,
            self.options,
            client,
            &self.registry,
            &transport,
        ) catch return;
        defer session.deinit();

        session.run();
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const Harness = struct {
    threaded: std.Io.Threaded,
    server: *Server,

    fn start(self: *Harness, options: options_mod.Options) !void {
        self.threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer self.threaded.deinit();

        self.server = try Server.start(std.heap.smp_allocator, self.threaded.io(), options);
    }

    fn stop(self: *Harness) void {
        self.server.stop();
        self.threaded.deinit();
    }
};

test "postgrez inproc: server reports the port the kernel assigned" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    try testing.expect(harness.server.port != 0);
}

test "postgrez inproc: server serves several backends at once on distinct ports" {
    var first: Harness = undefined;
    try first.start(.{});
    defer first.stop();

    var second: Harness = undefined;
    try second.start(.{});
    defer second.stop();

    try testing.expect(first.server.port != second.server.port);
}

test "postgrez inproc: server presents no certificate in cleartext" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    try testing.expectEqual(@as(usize, 0), harness.server.certDer().len);
}

test "postgrez inproc: server generates a certificate when it serves tls" {
    var harness: Harness = undefined;
    try harness.start(.{ .tls = true });
    defer harness.stop();

    try testing.expect(harness.server.certDer().len > 0);

    // it must be a certificate the driver's own parser accepts
    const cert = std.crypto.Certificate{ .buffer = harness.server.certDer(), .index = 0 };
    const parsed = try cert.parse();
    try testing.expectEqualStrings("postgrez-inproc", parsed.commonName());
}

test "postgrez inproc: server starts with no connections" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    try testing.expectEqual(@as(usize, 0), harness.server.connectionCount());
}
