//! zix http1 server configuration

const std = @import("std");
const DispatchModel = @import("../config.zig").DispatchModel;
const Logger = @import("../../logger/logger.zig").Logger;
const Tls = @import("../../tls/Tls.zig");
const HeaderSize = @import("response.zig").HeaderSize;

/// HTTP/1 server configuration.
pub const Http1ServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,
    /// Connection dispatch model. Required: the caller must set it explicitly (no default).
    dispatch_model: DispatchModel,
    /// TCP listen backlog.
    kernel_backlog: u31 = 1024,
    /// Shared-nothing worker count for .EPOLL / .URING (0 = cpu_count). Ignored by .ASYNC,
    /// which always runs exactly one accept thread.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the .EPOLL and .URING handler threads.
    /// Thread stacks are demand-paged, so this costs little RSS until the depth is used.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// Worker thread stack size in bytes when compression is enabled, a floor under .EPOLL / .URING:
    /// the effective stack is max(worker_stack_size_bytes, this). The codec state itself lives in
    /// per-worker mapped / heap scratch (never a stack temporary), the floor keeps headroom for the
    /// deeper compression call chains. No effect when off.
    worker_stack_compress_bytes: usize = 2 * 1024 * 1024,
    /// SO_BUSY_POLL spin window in microseconds for accepted connections (.EPOLL / .URING). The kernel
    /// busy-spins this long before sleeping the worker, trading CPU for lower tail latency. 0 leaves
    /// it unset. No-op when the kernel lacks SO_BUSY_POLL.
    busy_poll_us: u32 = 50,
    /// Attach SO_ATTACH_REUSEPORT_CBPF steering (.EPOLL / .URING): a new connection goes to listener
    /// index = receiving CPU mod workers instead of the 4-tuple hash, so it is served start-to-finish
    /// on the core that received it. Opt-in, default false. Silent no-op on a kernel pre-4.5.
    reuseport_cbpf: bool = false,
    /// Max bytes to buffer per request header block and per HTTP connection
    /// in EPOLL mode.
    max_recv_buf: usize = 6 * 1024,
    /// SO_RCVBUF in bytes, applied ONLY on the large-body (upload) path. Default 0 keeps the kernel
    /// default plus receive autotuning, which already sizes the upload window well. An explicit value
    /// caps the window AND disables autotuning, set it only to FORCE a window larger than autotuning.
    large_body_rcvbuf: usize = 0,
    /// Largest request body in bytes the engine will take. A declared Content-Length past this is
    /// refused with 413 and the connection closes, before the body is read or discarded, so a client
    /// cannot make a worker consume an arbitrary number of bytes. A chunked body declares no length
    /// and is bounded by max_recv_buf instead. 0 removes the check.
    max_request_body: usize = 8 * 1024 * 1024,
    /// Per-connection receive buffer for WebSocket connections in bytes. 0 falls back to max_recv_buf.
    /// Set it larger to give WS connections room to accumulate pipelined frames without a compact-and-reread
    /// each fill. Under .EPOLL it sizes the WS recv buffer, under .URING the frame-accumulation buffer (conn.buf).
    ws_recv_buf: usize = 0,
    /// Per-connection send buffer size in bytes for the .URING dispatch model, the send half of the
    /// per-connection footprint (max_recv_buf covers recv). A larger response grows the buffer up to
    /// an internal ceiling and still leaves as one on-ring send. No effect under the other models.
    uring_send_buf_size: usize = 16 * 1024,
    /// Warm idle-connection pool floor for the .URING dispatch model: the minimum number of
    /// closed connections kept warm (buffers resident) per worker when otherwise idle, so a trickle
    /// of new connections skips the allocator. No effect under the other dispatch models.
    uring_idle_pool_floor: usize = 8,
    /// Warm idle-connection pool ceiling for the .URING dispatch model: the absolute per-worker
    /// upper bound, warm cap = clamp(live_count, floor, ceiling). Holds the warm set below a large
    /// live working set, whose resident buffers otherwise double RSS and cost cache / TLB pressure.
    uring_idle_pool_ceiling: usize = 256,
    /// Process queue capacity (entry count) for the .URING dispatch model: a recv or send that
    /// finds the submission queue full is parked on a per-worker FIFO ring of this length
    /// (references only, fd + generation) and retried next loop pass instead of closing the
    /// connection. 0 (default) = off. No effect under the other models.
    process_queue_len: usize = 0,
    /// Cap on custom response headers a handler may add per request (Response.addHeader).
    /// The backing buffer is arena-allocated lazily on the first addHeader call, so requests
    /// that add none pay nothing.
    max_response_headers: HeaderSize = .MINIMAL,
    /// Whole-connection wall-clock budget in milliseconds on the blocking model (.ASYNC):
    /// a timer sweep shuts down any connection older than this.
    /// Should be >= handler_timeout_ms to avoid cutting off an in-flight response.
    /// 0 = disabled. No-op under .EPOLL and .URING (those event loops own connection lifetime).
    conn_timeout_ms: u32 = 0,
    /// Per-handler execution budget in milliseconds. 0 = disabled. When non-zero, a thread-local
    /// deadline is armed before each dispatch: handlers opt in via ctx.timedOut() (or
    /// zix.Http1.isExpired()) between expensive steps and may shorten their own budget via
    /// ctx.setTimeout().
    handler_timeout_ms: u32 = 0,
    /// Include the Date header in every response. Default true for RFC 7231 compliance.
    /// Set false to reduce response size by 37 bytes per response.
    send_date_header: bool = true,
    /// Root directory for static file serving. Empty (default) disables it. A request matching no
    /// route is served as a file before the 404 fallback (every dispatch model and https), ".." is
    /// rejected, Range (RFC 7233) yields 206. Validated at run(): missing dir = error.ZixPublicDirNotFound.
    public_dir: []const u8 = "",
    /// Upload subdirectory relative to public_dir. Declarative companion to public_dir: an upload
    /// handler saves received files here by convention. The engine does not auto-wire uploads,
    /// the handler owns the write. Mirrors zix.Http public_dir_upload.
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
    /// gate untouched. Active under every dispatch model. A handler opts in via res.sendNegotiated or
    /// the raw sendNegotiateCachedFD.
    compress: bool = false,
    /// Minimum response body size in bytes before compression is attempted. A body under this floor
    /// is sent uncompressed, since the header and CPU cost outweighs the saving.
    /// Mirrors utils.compression.min_size_default.
    compression_min_size: usize = 256,
    /// Max output size in bytes for one compressed response, across ALL codings (gzip, deflate,
    /// brotli). A response whose compressed form would exceed this is sent uncompressed instead.
    compression_max_out: usize = 256 * 1024,
    /// Enable the per-worker response cache (ADR-036). Default false. When off, the handler cache
    /// API (res.sendFromCache / res.sendCached and the raw cacheLookup / cacheStore /
    /// sendWithCacheFD) degrades to a no-op. Active under every dispatch model, shared-nothing
    /// either way: one cache per multiplexed worker, one per io pool thread under .ASYNC.
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
    /// otherwise cleartext (the default), leaving the .EPOLL / .URING hot path untouched. The context
    /// carries the cert / key / alpn / policy (Tls.Context.Config). Caller owns, must outlive.
    tls: ?*Tls.Context = null,
    /// Companion https bind port for the dual-listener mode. 0 (default) keeps single-listener
    /// behavior (with tls set the server is TLS-only on port). Non-zero (requires tls) serves
    /// cleartext on port AND https on tls_port from one worker fleet. Ignored when tls is null.
    tls_port: u16 = 0,
    /// Optional logger. When non-null the server routes its lifecycle lines (listening, fallback
    /// notices) through logger.system() instead of std.log, and writes one access record per served
    /// request tagged [http1:access]. A handler that frames its own bytes outside the Response is
    /// not counted in that record's byte total. Caller owns, must outlive.
    logger: ?*Logger = null,
};

test "zix http1: Http1ServerConfig URING knob defaults" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = Http1ServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9200, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 16 * 1024), cfg.uring_send_buf_size);
    try std.testing.expectEqual(@as(usize, 8), cfg.uring_idle_pool_floor);
    try std.testing.expectEqual(@as(usize, 256), cfg.uring_idle_pool_ceiling);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
}

test "zix http1: Http1ServerConfig worker stack defaults" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = Http1ServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9200, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), cfg.worker_stack_compress_bytes);
    try std.testing.expectEqual(@as(u32, 50), cfg.busy_poll_us);
    try std.testing.expect(!cfg.reuseport_cbpf);
}

test "zix http1: Http1ServerConfig static-serve defaults and override" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const cfg = Http1ServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9200, .dispatch_model = .ASYNC };
    try std.testing.expectEqualStrings("", cfg.public_dir);
    try std.testing.expectEqualStrings("u", cfg.public_dir_upload);

    const with_static = Http1ServerConfig{ .io = threaded.io(), .ip = "127.0.0.1", .port = 9200, .dispatch_model = .ASYNC, .public_dir = "./public", .public_dir_upload = "uploads" };
    try std.testing.expectEqualStrings("./public", with_static.public_dir);
    try std.testing.expectEqualStrings("uploads", with_static.public_dir_upload);
}
