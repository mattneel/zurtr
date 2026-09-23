//! zix fix config

const std = @import("std");
const DispatchModel = @import("../config.zig").DispatchModel;
const Logger = @import("../../logger/logger.zig").Logger;

// --------------------------------------------------------- //

/// Configuration for a FIX 4.x session server instance.
/// Pass to Fix.Server.init(). Fields without defaults (io, ip, port, comp_id) are required.
/// No allocator field, the server uses stack allocation and smp_allocator internally.
pub const FixServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,
    /// Server SenderCompID (tag 49). Caller-provided. Must outlive the server.
    comp_id: []const u8,
    /// Connection dispatch model. Selects between .ASYNC, .EPOLL, and .URING (.EPOLL and .URING are
    /// Linux-only, run() rejects them elsewhere with error.ZixDispatchModelUnsupported).
    /// Required: the caller must set it explicitly (no default).
    dispatch_model: DispatchModel,
    /// TCP listen backlog: pending connections queued by the kernel before accept().
    kernel_backlog: u31 = 1024,
    /// Shared-nothing listener worker count for .EPOLL / .URING (0 = cpu_count). Ignored by
    /// .ASYNC, which always runs exactly one accept thread.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the .EPOLL and .URING handler threads.
    /// Thread stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): a new connection goes to listener
    /// index = receiving CPU mod workers instead of the 4-tuple hash, so it is served start-to-finish
    /// on the core that received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Per-connection send buffer size in bytes for the .URING dispatch model. The send half
    /// of the per-connection footprint. No effect under the other dispatch models.
    uring_send_buf_size: usize = 64 * 1024,
    /// Max concurrent connections one .URING worker tracks (the per-worker fd-indexed slab size).
    /// The slab is demand-paged, so a larger value costs little until used. Connections past it are refused.
    uring_max_conns_per_worker: usize = 1 << 16,
    /// Default HeartBtInt (seconds) echoed in the Logon response when the client omits tag 108.
    default_heartbeat_secs: u32 = 30,
    /// Heartbeat timeout in milliseconds. 0 = disabled. After this interval with no incoming message
    /// the server sends TestRequest (35=1), after another silent interval Logout (35=5) and close.
    /// Takes effect after Logon completes. Before Logon, timeout closes silently.
    heartbeat_timeout_ms: u32 = 0,
    /// Idle connection timeout in milliseconds. 0 = disabled. When non-zero and heartbeat_timeout_ms
    /// is 0: the connection is closed if no message arrives within this interval (no TestRequest).
    conn_timeout_ms: u32 = 0,
    /// Server-wide default handler processing timeout in milliseconds. 0 = disabled.
    /// Applied to each routed message dispatch. Per-route Route.timeout_ms overrides this.
    handler_timeout_ms: u32 = 0,
    /// Optional logger. When non-null, the server calls logger.system() for lifecycle events
    /// and logger.session() for each FIX message processed. Caller owns. Must outlive the server.
    logger: ?*Logger = null,
};

/// Configuration for a FIX 4.x session client instance.
/// Pass to Fix.Client.connect(). All fields are required.
pub const FixClientConfig = struct {
    /// Server address.
    ip: []const u8,
    /// Server port. Must be non-zero.
    port: u16,
    /// This client's SenderCompID (tag 49).
    comp_id: []const u8,
    /// Server TargetCompID (tag 56).
    target_comp_id: []const u8,
    /// Socket receive timeout after connect in milliseconds (SO_RCVTIMEO). 0 = disabled.
    recv_timeout_ms: u32 = 0,
    /// Socket send timeout after connect in milliseconds (SO_SNDTIMEO). 0 = disabled.
    send_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix fix: FixServerConfig required fields" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9500), cfg.port);
    try std.testing.expectEqualStrings("SERVER", cfg.comp_id);
}

test "zix fix: FixServerConfig dispatch_model is required and stored as set" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(DispatchModel.ASYNC, cfg.dispatch_model);
}

test "zix fix: FixServerConfig workers defaults to auto-size (zero)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
}

test "zix fix: FixServerConfig kernel_backlog default" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u31, 1024), cfg.kernel_backlog);
    try std.testing.expect(!cfg.reuseport_cbpf);
}

test "zix fix: FixServerConfig uring_send_buf_size default" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 64 * 1024), cfg.uring_send_buf_size);
}

test "zix fix: FixServerConfig worker stack defaults" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(usize, 1 << 16), cfg.uring_max_conns_per_worker);
    try std.testing.expectEqual(@as(u32, 30), cfg.default_heartbeat_secs);
}

test "zix fix: FixServerConfig heartbeat_timeout_ms defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 0), cfg.heartbeat_timeout_ms);
}

test "zix fix: FixServerConfig conn_timeout_ms defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 0), cfg.conn_timeout_ms);
}

test "zix fix: FixServerConfig handler_timeout_ms defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = FixServerConfig{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 0), cfg.handler_timeout_ms);
}

test "zix fix: FixClientConfig fields" {
    const cfg = FixClientConfig{
        .ip = "127.0.0.1",
        .port = 9500,
        .comp_id = "CLIENT",
        .target_comp_id = "SERVER",
    };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 9500), cfg.port);
    try std.testing.expectEqualStrings("CLIENT", cfg.comp_id);
    try std.testing.expectEqualStrings("SERVER", cfg.target_comp_id);
    try std.testing.expectEqual(@as(u32, 0), cfg.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.send_timeout_ms);
}
