//! zix http server config

const std = @import("std");
const HeaderSize = @import("response.zig").HeaderSize;
const RequestHeaderSize = @import("parser.zig").RequestHeaderSize;
const Logger = @import("../../logger/logger.zig").Logger;
const Tls = @import("../../tls/Tls.zig");
pub const DispatchModel = @import("../config.zig").DispatchModel;

// --------------------------------------------------------- //

/// Configuration for an HTTP server instance.
/// Pass to Http.Server.init(). Fields without defaults (ip, port) are required.
pub const HttpServerConfig = struct {
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
    /// TCP listen backlog: maximum pending connections queued by the kernel before accept().
    kernel_backlog: u31 = 1024,
    /// Shared-nothing worker count for .EPOLL / .URING (0 = cpu_count). Ignored by .ASYNC,
    /// which always runs exactly one accept thread.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the .EPOLL and .URING handler threads.
    /// Thread stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// Worker thread stack size in bytes when compression is enabled, a floor under .EPOLL / .URING:
    /// the effective stack is max(worker_stack_size_bytes, this). std.compress.flate builds on the
    /// handler stack frame (about 230 KB), so a compressing handler needs more. No effect when off.
    worker_stack_compress_bytes: usize = 2 * 1024 * 1024,
    /// SO_BUSY_POLL spin window in microseconds for accepted connections (.EPOLL / .URING). The kernel
    /// busy-spins this long before sleeping the worker, trading CPU for lower tail latency. 0 leaves
    /// it unset. No-op when the kernel lacks SO_BUSY_POLL.
    busy_poll_us: u32 = 50,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): a new connection goes to listener
    /// index = receiving CPU mod workers instead of the 4-tuple hash, so it is served start-to-finish
    /// on the core that received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Read buffer size in bytes per request. Requests exceeding this are rejected with 431.
    max_recv_buf: usize = 6 * 1024,
    /// SO_RCVBUF in bytes, applied only while reading a large request body (uploads). Default 0 keeps
    /// the kernel default plus receive autotuning, which already sizes the upload window well. An
    /// explicit value caps the window AND disables autotuning, set it only to FORCE a larger window.
    large_body_rcvbuf: usize = 0,
    /// Max milliseconds Request.body() waits for the next segment of a multi-segment body on the
    /// non-blocking .EPOLL / .URING fd (upload path), bounding a stalled client. Default 30000 covers
    /// a slow upload. The hot GET path returns early (no body) and never waits here.
    body_read_timeout_ms: i32 = 30000,
    /// Largest request body in bytes the engine will take, counted from what actually arrives and
    /// not from the Content-Length header. A declared length past this is refused with 413 before
    /// anything is allocated, and a chunked body is stopped at the byte that crosses it, since
    /// chunked declares no length up front. 0 removes the check on Content-Length and restores the
    /// old behaviour of sizing the allocation from whatever the client claimed. A chunked body keeps
    /// an internal ceiling either way, since there is no declared length to check.
    max_request_body: usize = 8 * 1024 * 1024,
    /// Per-connection send buffer size in bytes for the .URING dispatch model. The send
    /// half of the per-connection footprint (max_recv_buf covers recv). No effect under
    /// the other dispatch models.
    uring_send_buf_size: usize = 16 * 1024,
    /// Minimum warm idle-connection pool size for the .URING dispatch model: a closed connection is
    /// pooled (recv and send buffers intact) so a later accept reuses the allocation. The pool cap
    /// scales with the worker's live concurrency, this is the idle floor. Mirrors zix.Http1.
    uring_idle_pool_floor: usize = 8,
    /// Absolute warm idle-connection pool ceiling for the .URING dispatch model: the effective
    /// cap is clamped between uring_idle_pool_floor and this. Mirrors zix.Http1.
    uring_idle_pool_ceiling: usize = 256,
    /// Process queue capacity (entry count) for the .URING dispatch model: a recv or send that
    /// finds the submission queue full is parked on a per-worker FIFO ring of this length
    /// (references only, fd + generation) and retried next loop pass instead of closing the
    /// connection. 0 (default) = off. Mirrors zix.Http1. No effect under the other models.
    process_queue_len: usize = 0,
    /// Initial arena capacity in bytes per connection. Grows automatically if exceeded.
    max_allocator_size: usize = 1024 * 4,
    /// Maximum request headers accepted per request. Requests exceeding this are rejected with 431.
    /// CUSTOM values above 64 are silently capped at the parser storage limit (64).
    /// See RequestHeaderSize for tier guidance.
    max_request_headers: RequestHeaderSize = .LARGE,
    /// Maximum custom response headers per request (default: .MINIMAL = 16). The backing buffer is
    /// arena-allocated per request to exactly this size. See docs/headers.md and zix.HeaderSize.
    max_response_headers: HeaderSize = .MINIMAL,
    /// Network-level connection guard (Layer D: ConnRegistry eviction). 0 = disabled. Connections
    /// exceeding this lifetime in milliseconds are shut down by the background timer thread.
    /// Should be >= handler_timeout_ms to avoid cutting off an in-flight response.
    conn_timeout_ms: u32 = 0,
    /// Per-handler execution budget in milliseconds (Layer B: ctx.isExpired / ctx.timedOut).
    /// 0 = disabled. When non-zero, ctx.deadline is set before each handler dispatch and handlers
    /// opt in by checking ctx.isExpired() between expensive steps.
    handler_timeout_ms: u32 = 0,
    /// Include the Date header in every response. Default true for RFC 7231 compliance.
    /// Set false to reduce response size by 37 bytes per response. Mirrors zix.Http1.
    send_date_header: bool = true,
    /// Root directory for static file serving. Empty string disables static serving.
    public_dir: []const u8 = "",
    /// Upload subdirectory relative to public_dir. Receives multipart uploads.
    public_dir_upload: []const u8 = "u",
    /// How long a resolved static file stays cached, in milliseconds. Default 0 means never cached:
    /// every request re-opens and re-reads the file, which is the behaviour shipped before ADR-064.
    /// Above 0 the file is kept open and its response header prerendered, so a repeat request costs
    /// a hash lookup, and a file changed on disk is picked up within one window.
    /// Separate from cache_ttl_ms, which belongs to the handler response cache.
    public_dir_cache_ttl_ms: u32 = 0,
    /// Static cache slot count, rounded down to a power of two and clamped against the process
    /// descriptor budget. One slot holds one file plus its .br and .gz siblings, so 256 covers 85
    /// distinct files at three variants each. A full table serves the request uncached, never an error.
    public_dir_cache_max_entries: u32 = 256,
    /// Enable response compression with Accept-Encoding negotiation (gzip, deflate, brotli). Default
    /// false: compression spends CPU and only pays off over a real network, so off keeps the perf
    /// gate untouched. Active under every dispatch model. A handler opts in via resp.sendNegotiated.
    compress: bool = false,
    /// Minimum response body size in bytes before compression is attempted. A body under this floor
    /// is sent uncompressed, since the header and CPU cost outweighs the saving.
    /// Mirrors utils.compression.min_size_default.
    compression_min_size: usize = 256,
    /// Max output size in bytes for one compressed response, across ALL codings (gzip, deflate,
    /// brotli). A response whose compressed form would exceed this is sent uncompressed instead.
    compression_max_out: usize = 256 * 1024,
    /// Enable the per-worker response cache (ADR-036). Default false. When off, the handler cache
    /// API (res.sendFromCache / res.sendCached) degrades to a plain send. Active under every model.
    response_cache: bool = false,
    /// Response cache slot count, rounded down to a power of two. Per-worker
    /// memory is cache_max_entries * cache_max_value_bytes, times the worker count.
    cache_max_entries: u32 = 256,
    /// Per-slot response cap. A response larger than this bypasses the cache.
    /// Caching pays off above a few KiB, so keep this lean.
    cache_max_value_bytes: u32 = 16 * 1024,
    /// Default freshness in milliseconds, exposed to handlers via cacheTtl().
    /// Handlers may pass their own TTL per store.
    cache_ttl_ms: u32 = 1000,
    /// Optional ceiling on per-worker cache memory. 0 disables the ceiling. When
    /// set, the effective entry count is reduced so entries * value_bytes fits.
    cache_max_total_bytes: usize = 0,
    /// https - opt-in. When non-null the server serves HTTP/1.1 over TLS (zix.Tls) on a gated path,
    /// cleartext engine untouched: .EPOLL / .URING terminate in tls_mux (SSE via the stream sink),
    /// the thread model (.ASYNC) in tls_serve (WS over TLS rides that, ADR-055). Caller owns, must outlive.
    tls: ?*Tls.Context = null,
    /// Companion https bind port for the dual-listener mode. 0 (default) keeps single-listener
    /// behavior (with tls set the server is TLS-only on port). Non-zero (requires tls) serves
    /// cleartext on port AND TLS on tls_port from one worker fleet. Ignored when tls is null.
    tls_port: u16 = 0,
    /// Optional logger. When non-null, the server calls logger.access() after each
    /// response and injects a pointer into ctx.logger for handler use.
    /// Caller owns the Logger and must ensure it outlives the server.
    logger: ?*Logger = null,
};

test "zix http: HttpServerConfig uring_send_buf_size default" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = HttpServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 8080, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 16 * 1024), cfg.uring_send_buf_size);
    try std.testing.expectEqual(@as(usize, 8), cfg.uring_idle_pool_floor);
    try std.testing.expectEqual(@as(usize, 256), cfg.uring_idle_pool_ceiling);
    try std.testing.expectEqual(@as(u31, 1024), cfg.kernel_backlog);
    try std.testing.expectEqual(@as(usize, 6 * 1024), cfg.max_recv_buf);
    try std.testing.expect(cfg.send_date_header);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(u32, 50), cfg.busy_poll_us);
    try std.testing.expect(!cfg.reuseport_cbpf);
    try std.testing.expectEqual(@as(i32, 30000), cfg.body_read_timeout_ms);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), cfg.worker_stack_compress_bytes);
}
