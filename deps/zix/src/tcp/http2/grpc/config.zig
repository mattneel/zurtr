//! gRPC server and client configuration.

const std = @import("std");
const DispatchModel = @import("../../config.zig").DispatchModel;
const Logger = @import("../../../logger/logger.zig").Logger;
const Tls = @import("../../../tls/Tls.zig");

// --------------------------------------------------------- //

/// Configuration for a gRPC h2c server instance.
/// Pass to Grpc.Server.init(). Fields without defaults (io, ip, port) are required.
/// No allocator field, the server uses smp_allocator internally.
pub const GrpcServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,
    /// Connection dispatch model. Selects between .ASYNC, .EPOLL, and .URING (.EPOLL and .URING are
    /// Linux-only, run() rejects them elsewhere with error.ZixDispatchModelUnsupported).
    /// Required: the caller must set it explicitly (no default).
    dispatch_model: DispatchModel,
    /// TCP listen backlog.
    kernel_backlog: u31 = 1024,
    /// Multiplexed worker count for .EPOLL / .URING (0 = cpu_count). Ignored by .ASYNC
    /// (always 1 accept thread).
    workers: usize = 0,
    /// Worker thread stack size in bytes for the .EPOLL, .URING, and TLS handler threads.
    /// Thread stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// SO_BUSY_POLL spin window in microseconds for accepted connections (.EPOLL / .URING): the
    /// kernel busy-spins this long before sleeping the worker, trading CPU for lower wake-up latency.
    /// Default 0 leaves it unset (set e.g. 50 to opt in). No-op when the kernel lacks SO_BUSY_POLL.
    busy_poll_us: u32 = 0,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): a new connection goes to listener
    /// index = receiving CPU mod workers instead of the 4-tuple hash, so it is served start-to-finish
    /// on the core that received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Per-connection receive buffer in bytes (.EPOLL / .URING). Used as a floor: the reader is
    /// sized to the larger of this and one max frame, so a larger value cuts read() and compaction
    /// for big frames.
    max_recv_buf: usize = 64 * 1024,
    /// Initial capacity in bytes of the per-connection TLS pending-write buffer (it grows on demand).
    tls_write_buf_initial_bytes: usize = 16 * 1024,
    /// Maximum concurrent h2 streams per connection.
    max_streams: u32 = 128,
    /// MAX_FRAME_SIZE setting sent to clients (bytes).
    max_frame_size: u32 = 16384,
    /// HPACK scratch buffer size per connection.
    max_header_scratch: usize = 4096,
    /// Maximum body buffer per stream (bytes).
    max_body: usize = 16384,
    /// Global handler timeout cap (milliseconds). 0 = disabled. When non-zero, each stream dispatch
    /// sets GrpcContext.deadline_ns to now + tighter_of(handler_timeout_ms, Route.timeout_ms,
    /// grpc-timeout header). Handlers opt in by checking ctx.isExpired() between expensive steps.
    handler_timeout_ms: u32 = 0,
    /// Enable gzip response compression. When true, the server compresses DATA frames
    /// for clients that advertise grpc-accept-encoding: gzip. Default: false.
    compress: bool = false,
    /// Enable the per-worker unary response cache (ADR-036). Default false. When off, the handler
    /// cache API (ctx.serveCached / ctx.sendCached) degrades to a plain send. Active under every
    /// dispatch model.
    response_cache: bool = false,
    /// Response cache slot count, rounded down to a power of two. Per-worker memory
    /// is cache_max_entries * cache_max_value_bytes, times the worker count.
    cache_max_entries: u32 = 256,
    /// Per-slot response-message cap. A response message larger than this bypasses
    /// the cache. Caching pays off above a few KiB, so keep this lean.
    cache_max_value_bytes: u32 = 16 * 1024,
    /// Default freshness in milliseconds, exposed to handlers via cacheTtl().
    /// Handlers may pass their own TTL per store.
    cache_ttl_ms: u32 = 1000,
    /// Optional ceiling on per-worker cache memory. 0 disables the ceiling. When
    /// set, the effective entry count is reduced so entries * value_bytes fits.
    cache_max_total_bytes: usize = 0,
    /// https - opt-in. When non-null the server serves gRPC over TLS (zix.Tls, ALPN h2) instead of
    /// h2c, a gated per-connection terminator in front of the h2c engine (cleartext models
    /// untouched). alpn should include .H2 (RFC 7540 3.3). Caller owns the Context, must outlive.
    tls: ?*Tls.Context = null,
    /// Companion gRPC-over-TLS bind port for the dual-listener mode. 0 (default) keeps
    /// single-listener behavior (with tls set the server is TLS-only on port). Non-zero (requires
    /// tls) serves cleartext on port AND TLS on tls_port from one worker fleet. Ignored when tls null.
    tls_port: u16 = 0,
    /// Optional logger. When non-null, the server calls logger.system() for lifecycle events
    /// and logger.rpc() for each gRPC stream dispatched. Caller owns. Must outlive the server.
    logger: ?*Logger = null,
};

/// Configuration for a gRPC h2c client connection.
/// Pass to Grpc.Client.connect().
pub const GrpcClientConfig = struct {
    /// Server address.
    ip: []const u8,
    /// Server port. Must be non-zero.
    port: u16,
    /// Socket receive timeout after connect in milliseconds (SO_RCVTIMEO). 0 = disabled.
    recv_timeout_ms: u32 = 0,
    /// Socket send timeout after connect in milliseconds (SO_SNDTIMEO). 0 = disabled.
    send_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: GrpcServerConfig required fields" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 8083), cfg.port);
}

test "zix grpc: GrpcServerConfig dispatch_model is required and stored as set" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(DispatchModel.ASYNC, cfg.dispatch_model);
}

test "zix grpc: GrpcServerConfig workers defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
    try std.testing.expectEqual(@as(u32, 0), cfg.busy_poll_us);
    try std.testing.expect(!cfg.reuseport_cbpf);
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(usize, 64 * 1024), cfg.max_recv_buf);
    try std.testing.expectEqual(@as(usize, 16 * 1024), cfg.tls_write_buf_initial_bytes);
}

test "zix grpc: GrpcServerConfig stream and body defaults" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 128), cfg.max_streams);
    try std.testing.expectEqual(@as(u32, 16384), cfg.max_frame_size);
    try std.testing.expectEqual(@as(usize, 16384), cfg.max_body);
}

test "zix grpc: GrpcServerConfig handler_timeout_ms defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 0), cfg.handler_timeout_ms);
}

test "zix grpc: GrpcServerConfig compress defaults to false" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = GrpcServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8083, .dispatch_model = .ASYNC };
    try std.testing.expect(!cfg.compress);
}

test "zix grpc: GrpcClientConfig fields" {
    const cfg = GrpcClientConfig{ .ip = "127.0.0.1", .port = 8083 };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 8083), cfg.port);
    try std.testing.expectEqual(@as(u32, 0), cfg.recv_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.send_timeout_ms);
}
