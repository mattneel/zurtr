//! zix udp server

const std = @import("std");
const Config = @import("config.zig");
const UdpServerConfig = Config.UdpServerConfig;
const Logger = @import("../logger/logger.zig").Logger;
const socket_poll = @import("../utils/socket_poll.zig");

const log = std.log.scoped(.zix_udp);

// --------------------------------------------------------- //

/// Emit a server line at the given level. Routes through config.logger when present.
///
/// Note:
/// - Without a logger the line still reaches std.log, so a release build never loses a failure.
///   std.log's own default level does the filtering: .ERROR and .WARN survive a release build,
///   .INFO and .DEBUG do not, and a caller who sets std.options.logFn can route or silence all
///   of them.
///
/// Param:
/// level - Logger.Level (.ERROR for a failure the reader must act on, .INFO for a lifecycle line)
fn logSystem(config: UdpServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "udp", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

// --------------------------------------------------------- //

/// UDP server typed to a user-defined extern struct packet.
///
/// Usage:
/// ```zig
/// const MyServer = zix.Udp.Server(MyPacket);
/// var server = try MyServer.init(config, .{});   // config-only (config.io required)
/// // set config.allow_args = true and pass process args to read --ip / --port:
/// // var server = try MyServer.init(config, process.minimal.args);
/// defer server.deinit();
/// try server.run();
/// ```
pub fn UdpServer(comptime Packet: type) type {
    // RFC 768: max UDP payload = 65,535 - 8 (UDP header) - 20 (min IPv4 header) = 65,507 bytes.
    // Packets larger than this cannot be sent in a single datagram.
    if (@sizeOf(Packet) > 65_507) @compileError("Packet size exceeds maximum UDP payload of 65,507 bytes (RFC 768)");
    return struct {
        const Self = @This();

        // Note: index is a monotonic connection counter, transient identity, not stable across reconnects.
        // Note: client identity structure and validation are the application's responsibility,
        //       the server only assigns an index for internal tracking and log output.
        const ClientRecord = struct {
            from: std.Io.net.IpAddress,
            last_seen: std.Io.Clock.Timestamp,
            index: usize,
        };

        // PERF: peers is heap-allocated per packet, no fixed cap.
        //       Allocated before io.concurrent() dispatch, freed inside processPacket after broadcast.
        // Note: socket is shared across concurrent tasks, UDP send is kernel-atomic per datagram.
        const Task = struct {
            buf: [@sizeOf(Packet)]u8,
            from: std.Io.net.IpAddress,
            socket: std.Io.net.Socket,
            io: std.Io,
            config: UdpServerConfig,
            peers: []std.Io.net.IpAddress,
            logger: ?*Logger,
        };

        config: UdpServerConfig,

        // --------------------------------------------------------- //

        /// Initialize. When `config.allow_args` is set, `--ip` / `--port` from `args` override the
        /// config (a missing arg keeps the config value), otherwise `args` is ignored. The final port
        /// must be non-zero.
        ///
        /// Param:
        /// config - UdpServerConfig
        /// args - std.process.Args (e.g. process.minimal.args), or `.{}` when not reading CLI
        ///
        /// Return:
        /// - error.ZixPortNotConfigured if the resolved port is zero
        pub fn init(config: UdpServerConfig, args: anytype) !Self {
            var cfg = config;
            // The parse only compiles when args is a real std.process.Args. Passing `.{}` (no CLI)
            // skips it at comptime, so the empty case does not need a process.Args value.
            if (comptime @TypeOf(args) == std.process.Args) {
                if (cfg.allow_args) cfg = Config.applyServerArgs(cfg, args);
            }

            if (cfg.port == 0) return error.ZixPortNotConfigured;

            return .{ .config = cfg };
        }

        /// Release resources. Call after run() exits or errors.
        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Bind the socket and start the receive loop. Blocks until an error occurs.
        /// io is taken from config.io (caller-provided, must outlive the server).
        /// Prints "listening on ip:port" after a successful bind.
        pub fn run(self: *Self) !void {
            const io = self.config.io;

            const addr = try std.Io.net.IpAddress.parse(self.config.ip, self.config.port);
            const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
            defer socket.close(io);

            logSystem(self.config, .INFO, "listening on {s}:{d}", .{ self.config.ip, self.config.port });

            // The typed messaging path runs a single async receive loop. The per-core dispatch models
            // are a property of the raw path (zix.Udp.Raw), so a non-ASYNC value folds here with a
            // notice rather than silently doing nothing.
            if (self.config.dispatch_model != .ASYNC) logSystem(self.config, .WARN, "typed UDP uses the ASYNC receive loop, {s} applies only to zix.Udp.Raw", .{@tagName(self.config.dispatch_model)});

            // Note: config.allocator must be a general-purpose allocator, not an ArenaAllocator.
            //       The client list grows and shrinks (swapRemove on disconnect). The broadcast peer
            //       snapshot is allocated and freed per packet. ArenaAllocator.free() is a no-op,
            //       so snapshots would accumulate unboundedly until the server stops.
            var clients = std.array_list.Managed(ClientRecord).init(self.config.allocator);
            defer clients.deinit();

            // poll_timeout_ms is signed in the config: a value at or below zero is a plain
            // non-blocking check, which is what the previous timed receive did with it too.
            const poll_ms: u32 = if (self.config.poll_timeout_ms <= 0)
                0
            else
                @intCast(@min(self.config.poll_timeout_ms, std.math.maxInt(u32)));

            var last_check = std.Io.Clock.Timestamp.now(io, .awake);
            var next_index: usize = 1; // 1-based for readable log output

            while (true) {
                var buf: [@sizeOf(Packet)]u8 = undefined;

                // Wait for readiness, then receive plainly. A timed std.Io receive would race the
                // receive against a timer, which the Windows backend cannot do for a socket (it
                // answers error.ConcurrencyUnavailable). That error is not error.Timeout, so this
                // loop used to log it and spin without ever taking a datagram: the server bound its
                // port and then answered nobody. The wait carries the idle tick either way.
                const ready = socket_poll.waitReady(socket.handle, socket_poll.READABLE, poll_ms) catch |err| {
                    if (self.config.logger) |lg| lg.system(.WARN, "udp", "poll error: {}", .{err});

                    continue;
                };
                if (!ready) {
                    const now = std.Io.Clock.Timestamp.now(io, .awake);
                    checkDisconnections(&clients, now, self.config.conn_timeout_ms, self.config.logger);
                    last_check = now;

                    continue;
                }

                const msg = socket.receive(io, &buf) catch |err| {
                    if (self.config.logger) |lg| lg.system(.WARN, "udp", "receive error: {}", .{err});

                    continue;
                };

                // overflow / size guard, drop datagrams that are not exactly Packet size
                if (msg.flags.trunc or msg.data.len != @sizeOf(Packet)) {
                    if (self.config.error_report) socket.send(io, &msg.from, &[_]u8{0x15}) catch {};
                    if (self.config.logger) |lg| lg.system(.WARN, "udp", "drop: expected {d} bytes, got {d} trunc={}", .{ @sizeOf(Packet), msg.data.len, msg.flags.trunc });
                    continue;
                }

                const now = std.Io.Clock.Timestamp.now(io, .awake);

                // track connected clients, capture sender_index for the task
                var sender_index: usize = 0;
                var known = false;
                for (clients.items) |*r| {
                    if (r.from.eql(&msg.from)) {
                        r.last_seen = now;
                        sender_index = r.index;
                        known = true;
                        break;
                    }
                }
                if (!known) {
                    sender_index = next_index;
                    next_index += 1;
                    clients.append(.{ .from = msg.from, .last_seen = now, .index = sender_index }) catch {};
                    if (self.config.logger) |lg| {
                        var addr_buf: [64]u8 = undefined;
                        lg.system(.INFO, "udp", "client connected: {s} index={d} total={d}", .{ fmtAddr(msg.from, &addr_buf), sender_index, clients.items.len });
                    }
                }

                // rate-limited disconnect check even when packets arrive rapidly
                if (std.Io.Clock.Timestamp.durationTo(last_check, now).raw.toMilliseconds() >= self.config.poll_timeout_ms) {
                    checkDisconnections(&clients, now, self.config.conn_timeout_ms, self.config.logger);
                    last_check = now;
                }

                // Heap-allocate peer snapshot for broadcast, freed inside processPacket after all sends.
                // PERF: allocation only occurs when broadcast is enabled and clients list is non-empty.
                // Note: must use a general-purpose allocator, the free() below is real, not a no-op.
                var peers: []std.Io.net.IpAddress = &.{};
                if (self.config.broadcast and clients.items.len > 0) {
                    if (self.config.allocator.alloc(std.Io.net.IpAddress, clients.items.len)) |p| {
                        for (clients.items, 0..) |r, i| p[i] = r.from;
                        peers = p;
                    } else |_| {}
                }

                const task = Task{
                    .buf = buf,
                    .from = msg.from,
                    .socket = socket,
                    .io = io,
                    .config = self.config,
                    .peers = peers,
                    .logger = self.config.logger,
                };

                _ = io.concurrent(processPacket, .{task}) catch |err| {
                    if (self.config.logger) |lg| lg.system(.WARN, "udp", "concurrent error: {}", .{err});
                    processPacket(task);
                };
            }
        }

        // --------------------------------------------------------- //

        fn processPacket(task: Task) void {
            // Free peer snapshot allocated in run() before io.concurrent() dispatch.
            // Note: this free() is real, config.allocator must not be an ArenaAllocator.
            defer if (task.peers.len > 0) task.config.allocator.free(task.peers);

            var addr_buf: [64]u8 = undefined;
            const peer = fmtAddr(task.from, &addr_buf);
            if (task.logger) |lg| lg.packet(.RECV, peer, @sizeOf(Packet), null);

            if (task.config.auto_ack) {
                task.socket.send(task.io, &task.from, &[_]u8{0x06}) catch |err| {
                    if (task.logger) |lg| lg.system(.WARN, "udp", "ack error: {}", .{err});
                };
            }

            if (task.config.auto_echo) {
                task.socket.send(task.io, &task.from, &task.buf) catch |err| {
                    if (task.logger) |lg| lg.system(.WARN, "udp", "echo error: {}", .{err});
                };
            }

            if (task.config.broadcast) {
                // SECURITY: no sender validation, spoofed IPs can trigger broadcast to all peers
                // PERF: N sequential send() syscalls per broadcast. sendmmsg batching lives in the raw path (zix.Udp.Raw), not this typed broadcast loop.
                for (task.peers) |*peer_addr| {
                    task.socket.send(task.io, peer_addr, &task.buf) catch |err| {
                        if (task.logger) |lg| lg.system(.WARN, "udp", "broadcast error: {}", .{err});
                    };
                }
            }
        }

        fn checkDisconnections(
            clients: *std.array_list.Managed(ClientRecord),
            now: std.Io.Clock.Timestamp,
            timeout_ms: i64,
            logger: ?*Logger,
        ) void {
            var i: usize = 0;
            while (i < clients.items.len) {
                const elapsed = std.Io.Clock.Timestamp.durationTo(clients.items[i].last_seen, now).raw.toMilliseconds();
                if (elapsed >= timeout_ms) {
                    var buf: [64]u8 = undefined;
                    const addr_str = fmtAddr(clients.items[i].from, &buf);
                    const client_index = clients.items[i].index;
                    _ = clients.swapRemove(i);
                    if (logger) |lg| lg.system(.INFO, "udp", "client disconnected: {s} index={d} total={d}", .{ addr_str, client_index, clients.items.len });
                } else {
                    i += 1;
                }
            }
        }

        fn fmtAddr(from: std.Io.net.IpAddress, buf: []u8) []const u8 {
            return switch (from) {
                .ip4 => |addr| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                    addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3], addr.port,
                }) catch "?",
                .ip6 => "ipv6",
            };
        }
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

// RFC 768: port 0 is reserved, binding to it is undefined behavior.
// init() rejects port 0 with error.ZixPortNotConfigured before any socket is opened.
// run() and socket I/O are excluded from unit tests, those require live I/O.

const TestPkt = extern struct { value: u32 };

test "zix udp: UdpServer init, port zero returns PortNotConfigured" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const S = UdpServer(TestPkt);
    try std.testing.expectError(error.ZixPortNotConfigured, S.init(.{ .io = threaded.io(), .allocator = std.testing.allocator, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC }, .{}));
}

test "zix udp: UdpServer init, nonzero port succeeds" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const S = UdpServer(TestPkt);
    var server = try S.init(.{ .io = threaded.io(), .allocator = std.testing.allocator, .ip = "127.0.0.1", .port = 9100, .dispatch_model = .ASYNC }, .{});
    server.deinit();
}

test "zix udp: UdpServer init, config fields are preserved" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const S = UdpServer(TestPkt);
    var server = try S.init(.{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9200,
        .dispatch_model = .ASYNC,
        .broadcast = true,
        .auto_ack = true,
    }, .{});
    defer server.deinit();

    try std.testing.expectEqual(std.testing.allocator.ptr, server.config.allocator.ptr);
    try std.testing.expectEqual(@as(u16, 9200), server.config.port);
    try std.testing.expect(server.config.broadcast);
    try std.testing.expect(server.config.auto_ack);
}
