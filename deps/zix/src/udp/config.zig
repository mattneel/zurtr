//! zix udp config

const std = @import("std");

// --------------------------------------------------------- //

const Logger = @import("../logger/logger.zig").Logger;

/// The dispatch model, shared with the TCP engines (`src/tcp/config.zig`). Reused so the UDP engine
/// names concurrency the same way the rest of the family does.
pub const DispatchModel = @import("../tcp/config.zig").DispatchModel;

// --------------------------------------------------------- //

/// Wire endianness for the typed path's packet conversion. The client applies it on every send and
/// receive. The typed server relays raw bytes without decoding, so it does not apply it. Client and
/// server config must agree for correct decoding.
pub const Endianness = enum(u8) {
    /// Same machine only, unsafe across platforms or languages.
    NATIVE,
    /// Recommended for cross-language clients (Go, C++, Rust) on modern hardware.
    LITTLE,
    /// Network byte order, use when interoperating with legacy or internet protocols.
    BIG,
};

// --------------------------------------------------------- //

pub const UdpServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Backing allocator: typed path client list and broadcast peer snapshots, raw path
    /// (`zix.Udp.Raw`) recv / send batches and the worker array. Must be general-purpose (e.g.
    /// std.heap.smp_allocator): snapshots are freed per packet, so an arena (free is a no-op) leaks.
    allocator: std.mem.Allocator,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero (RFC 768). Can be supplied by `--port` when `allow_args` is set.
    port: u16,
    /// When true, init() applies `--ip` / `--port` CLI overrides from the args it is passed.
    allow_args: bool = false,

    // Datagram-transport knobs (ADR-049), used by the raw-bytes path (`zix.Udp.Raw`). The typed
    // messaging path runs a single async receive loop: it folds a non-ASYNC `dispatch_model` with a
    // notice and does not use the batch / worker knobs.

    /// Concurrency model for the raw path. `.ASYNC` runs a single worker. `.EPOLL` / `.URING` run one
    /// per-core SO_REUSEPORT worker per CPU (ADR-050) and are Linux-only, run() rejects them elsewhere
    /// with error.ZixDispatchModelUnsupported. Required: set explicitly (no default).
    dispatch_model: DispatchModel,
    /// Worker count for the per-core models. 0 means one per available CPU.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the per-core raw workers (.EPOLL / .URING). Thread
    /// stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// SO_BUSY_POLL spin window in microseconds for the raw path's UDP socket (.EPOLL / .URING): the
    /// kernel busy-spins this long before sleeping the worker, trading CPU for lower recvmmsg wake-up
    /// latency. Default 0 leaves it unset. No-op when the kernel lacks SO_BUSY_POLL.
    busy_poll_us: u32 = 0,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): socket index = receiving CPU mod
    /// workers per packet instead of the 4-tuple hash, so a datagram is served on the core that
    /// received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Set SO_REUSEADDR + SO_REUSEPORT so multiple workers can bind the same port and the kernel
    /// load-balances datagrams across them.
    reuse_address: bool = false,
    /// recvmmsg batch size: datagrams received per syscall on the raw path.
    recv_batch: usize = 32,
    /// sendmmsg batch size: replies coalesced per flush on the raw path.
    send_batch: usize = 32,
    /// Maximum datagram size for the raw path, the receive buffer per slot. The typed path uses
    /// `@sizeOf(Packet)` instead. 1500 is the common Ethernet MTU.
    max_recv_buf: usize = 1500,
    /// Enable UDP GSO (UDP_SEGMENT) on the send path: consecutive same-destination replies in a
    /// flush are coalesced into one sendmsg and segmented by the kernel. Default false (plain
    /// sendmmsg). Probed at worker start, left off pre-4.18. Helps multi-packet same-peer bursts.
    gso_enabled: bool = false,

    // Typed messaging path knobs.

    /// Wire endianness. Currently unused server-side (the typed server relays raw bytes without
    /// decoding). Kept for symmetry with the client, which does apply it.
    endianness: Endianness = .LITTLE,
    /// Milliseconds of silence before a client is considered disconnected (idle connection timeout).
    conn_timeout_ms: u32 = 5000,
    /// Receive poll interval in milliseconds, controls disconnect check frequency.
    poll_timeout_ms: i64 = 2000,
    /// Send 0x06 ACK byte back to sender on successful packet receipt.
    auto_ack: bool = false,
    /// Send 0x15 NACK byte back to sender on malformed or oversized packet.
    error_report: bool = false,
    /// Echo the received packet back to the sender as-is.
    auto_echo: bool = false,
    /// Relay the received packet to all connected clients.
    broadcast: bool = false,
    /// Optional logger. When non-null, the server calls logger.system() for lifecycle events
    /// and logger.packet() for each received datagram. Caller owns. Must outlive the server.
    logger: ?*Logger = null,
};

// --------------------------------------------------------- //

pub const UdpClientConfig = struct {
    /// Server address to send packets to.
    ip: []const u8,
    /// Server port. Must be non-zero. Can be supplied by `--server-port` when `allow_args` is set.
    server_port: u16,
    /// Local bind address. Defaults to loopback. Set to "0.0.0.0" to accept responses on all interfaces.
    bind_ip: []const u8 = "127.0.0.1",
    /// Local bind port, server uses this to send responses back.
    bind_port: u16,
    /// When true, init() applies `--bind-ip` / `--bind-port` / `--server-port` CLI overrides.
    allow_args: bool = false,
    /// Wire endianness, must match the server's endianness config.
    endianness: Endianness = .LITTLE,
    /// Receive timeout in milliseconds, applied via poll before the blocking receive. 0 = disabled.
    recv_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //

/// Apply `--ip` / `--port` CLI overrides to a server config (space form, e.g. `--port 9000`). Called
/// by `zix.Udp.Server` / `zix.Udp.Raw` init when `allow_args` is set. A missing arg keeps the config
/// value.
pub fn applyServerArgs(config: UdpServerConfig, args: anytype) UdpServerConfig {
    // std.process.Args.Iterator is POSIX-only in Zig 0.16: CLI overrides are
    // skipped on Windows, the config values stay.
    if (comptime @import("builtin").target.os.tag == .windows) return config;

    var cfg = config;
    var it = std.process.Args.Iterator.init(args);
    _ = it.skip();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ip")) {
            if (it.next()) |val| cfg.ip = val;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (it.next()) |val| cfg.port = std.fmt.parseInt(u16, val, 10) catch cfg.port;
        }
    }

    return cfg;
}

/// Apply `--bind-ip` / `--bind-port` / `--server-port` CLI overrides to a client config (space form).
/// Called by `zix.Udp.Client` init when `allow_args` is set. A missing arg keeps the config value.
pub fn applyClientArgs(config: UdpClientConfig, args: anytype) UdpClientConfig {
    // std.process.Args.Iterator is POSIX-only in Zig 0.16: CLI overrides are
    // skipped on Windows, the config values stay.
    if (comptime @import("builtin").target.os.tag == .windows) return config;

    var cfg = config;
    var it = std.process.Args.Iterator.init(args);
    _ = it.skip();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--bind-ip")) {
            if (it.next()) |val| cfg.bind_ip = val;
        } else if (std.mem.eql(u8, arg, "--bind-port")) {
            if (it.next()) |val| cfg.bind_port = std.fmt.parseInt(u16, val, 10) catch cfg.bind_port;
        } else if (std.mem.eql(u8, arg, "--server-port")) {
            if (it.next()) |val| cfg.server_port = std.fmt.parseInt(u16, val, 10) catch cfg.server_port;
        }
    }

    return cfg;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

// RFC 768: port 0 is reserved and must not be used for binding.
// init() enforces this, port 0 in config yields error.ZixPortNotConfigured.
// These tests verify that defaults are safe and that enum representations are stable.

test "zix udp: UdpServerConfig, default field values" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = UdpServerConfig{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9100,
        .dispatch_model = .ASYNC,
    };
    try std.testing.expectEqual(std.testing.allocator.ptr, cfg.allocator.ptr);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9100), cfg.port);
    try std.testing.expect(!cfg.allow_args);
    try std.testing.expectEqual(Endianness.LITTLE, cfg.endianness);
    try std.testing.expectEqual(@as(u32, 5000), cfg.conn_timeout_ms);
    try std.testing.expectEqual(@as(i64, 2000), cfg.poll_timeout_ms);
    try std.testing.expect(!cfg.auto_ack);
    try std.testing.expect(!cfg.error_report);
    try std.testing.expect(!cfg.auto_echo);
    try std.testing.expect(!cfg.broadcast);
}

test "zix udp: UdpServerConfig, datagram-transport defaults (ADR-049)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = UdpServerConfig{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9100,
        .dispatch_model = .ASYNC,
    };
    try std.testing.expectEqual(DispatchModel.ASYNC, cfg.dispatch_model);
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
    try std.testing.expect(!cfg.reuse_address);
    try std.testing.expectEqual(@as(usize, 32), cfg.recv_batch);
    try std.testing.expectEqual(@as(usize, 32), cfg.send_batch);
    try std.testing.expectEqual(@as(usize, 1500), cfg.max_recv_buf);
    try std.testing.expectEqual(@as(u32, 0), cfg.busy_poll_us);
    try std.testing.expect(!cfg.reuseport_cbpf);
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
}

test "zix udp: UdpClientConfig, default field values" {
    const cfg = UdpClientConfig{ .ip = "127.0.0.1", .server_port = 9100, .bind_port = 9101 };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9100), cfg.server_port);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.bind_ip);
    try std.testing.expectEqual(@as(u16, 9101), cfg.bind_port);
    try std.testing.expect(!cfg.allow_args);
    try std.testing.expectEqual(Endianness.LITTLE, cfg.endianness);
    try std.testing.expectEqual(@as(u32, 0), cfg.recv_timeout_ms);
}

test "zix udp: Endianness enum backing values are stable" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Endianness.NATIVE));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Endianness.LITTLE));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Endianness.BIG));
}
