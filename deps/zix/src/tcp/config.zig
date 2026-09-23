//! zix tcp config

const std = @import("std");
const Logger = @import("../logger/logger.zig").Logger;

// --------------------------------------------------------- //

/// Connection dispatch model. Controls how accepted connections are handed off to handlers.
/// Zero-value (.ASYNC = 0) is the default for zero-init structs.
pub const DispatchModel = enum(u8) {
    /// Single accept thread dispatches each connection via io.async(). workers is ignored.
    /// The only model available on every platform, and the one every non-Linux target uses.
    ASYNC = 0,
    /// Shared-nothing epoll: each worker owns one SO_REUSEPORT listener and one epoll instance, the
    /// kernel load-balances connections with no shared queue. Linux-only, best at very high connection
    /// counts. workers sets the count (0 = cpu_count). All engines native.
    EPOLL = 1,
    /// Shared-nothing io_uring (ADR-037): same thread-per-core topology as .EPOLL but completion-based,
    /// so most syscall transitions are batched away. Linux-only. All engines (plus the WebSocket pump
    /// and the zix.Tcp framed path) run natively and fall back to .EPOLL when io_uring is unavailable.
    URING = 2,
}; // for all Tcp

// --------------------------------------------------------- //

/// TCP stream server configuration.
/// Pass to Tcp.Server.init(). Fields without defaults (io, ip, port) are required.
pub const TcpServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,
    /// Connection dispatch model. Required: the caller must set it explicitly (no default).
    dispatch_model: DispatchModel,
    /// TCP listen backlog: pending connections queued by the kernel before accept().
    kernel_backlog: u31 = 4096,
    /// Shared-nothing worker count for .EPOLL / .URING (0 = cpu_count). Ignored by .ASYNC,
    /// which always runs exactly one accept thread.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the .EPOLL and .URING handler threads.
    /// Thread stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): a new connection goes to listener
    /// index = receiving CPU mod workers instead of the 4-tuple hash, so it is served start-to-finish
    /// on the core that received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Maximum payload bytes per frame. Frames exceeding this close the connection.
    max_recv_buf: usize = 4096,
    /// Per-connection send buffer size in bytes for the .URING framed model. The send half
    /// of the per-connection footprint (max_recv_buf covers recv). No effect under the other
    /// dispatch models.
    uring_send_buf_size: usize = 64 * 1024,
    /// Max concurrent connections one .URING worker tracks (the per-worker fd-indexed slab size).
    /// The slab is demand-paged, so a larger value costs little until used. Connections past it are refused.
    uring_max_conns_per_worker: usize = 1 << 16,
    /// Socket receive timeout per accepted connection in milliseconds (SO_RCVTIMEO). 0 = disabled.
    recv_timeout_ms: u32 = 0,
    /// Socket send timeout per accepted connection in milliseconds (SO_SNDTIMEO). 0 = disabled.
    send_timeout_ms: u32 = 0,
    /// Optional logger. When non-null, the server calls logger.system() for lifecycle events
    /// and logger.conn() after each connection closes. Caller owns. Must outlive the server.
    logger: ?*Logger = null,
};

// --------------------------------------------------------- //

/// TCP stream client configuration.
pub const TcpClientConfig = struct {
    /// Server address.
    ip: []const u8,
    /// Server port. Must be non-zero.
    port: u16,
    /// Maximum payload bytes per frame.
    max_recv_buf: usize = 4096,
    /// Socket receive timeout after connect in milliseconds (SO_RCVTIMEO). 0 = disabled.
    recv_timeout_ms: u32 = 0,
    /// Socket send timeout after connect in milliseconds (SO_SNDTIMEO). 0 = disabled.
    send_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix tcp: TcpServerConfig, default field values" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = TcpServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9300, .dispatch_model = .ASYNC };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9300), cfg.port);
    try std.testing.expectEqual(DispatchModel.ASYNC, cfg.dispatch_model);
    try std.testing.expectEqual(@as(u31, 4096), cfg.kernel_backlog);
    try std.testing.expect(!cfg.reuseport_cbpf);
    try std.testing.expectEqual(@as(usize, 4096), cfg.max_recv_buf);
    try std.testing.expectEqual(@as(usize, 64 * 1024), cfg.uring_send_buf_size);
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(usize, 1 << 16), cfg.uring_max_conns_per_worker);
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
    try std.testing.expectEqual(@as(u32, 0), cfg.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.send_timeout_ms);
}

test "zix tcp: DispatchModel, variant values are gapless and ASYNC is the zero value" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(DispatchModel.ASYNC));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(DispatchModel.EPOLL));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(DispatchModel.URING));
}

test "zix tcp: DispatchModel, only the three maintained models exist" {
    // An exhaustive switch with no else prong: adding a fourth variant breaks this at compile time,
    // which is the point. Written without @typeInfo so it reads the same on every Zig version.
    const label = struct {
        fn of(model: DispatchModel) []const u8 {
            return switch (model) {
                .ASYNC => "ASYNC",
                .EPOLL => "EPOLL",
                .URING => "URING",
            };
        }
    }.of;

    try std.testing.expectEqualStrings("ASYNC", label(.ASYNC));
    try std.testing.expectEqualStrings("EPOLL", label(.EPOLL));
    try std.testing.expectEqualStrings("URING", label(.URING));
}

test "zix tcp: DispatchModel, the dropped POOL and MIXED names resolve to nothing" {
    try std.testing.expect(std.meta.stringToEnum(DispatchModel, "POOL") == null);
    try std.testing.expect(std.meta.stringToEnum(DispatchModel, "MIXED") == null);
    try std.testing.expectEqual(DispatchModel.ASYNC, std.meta.stringToEnum(DispatchModel, "ASYNC").?);
}

test "zix tcp: TcpClientConfig, default field values" {
    const cfg = TcpClientConfig{ .ip = "127.0.0.1", .port = 9300 };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9300), cfg.port);
    try std.testing.expectEqual(@as(usize, 4096), cfg.max_recv_buf);
    try std.testing.expectEqual(@as(u32, 0), cfg.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.send_timeout_ms);
}
