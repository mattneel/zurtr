//! HTTP/2 server configuration.

const std = @import("std");
const DispatchModel = @import("../config.zig").DispatchModel;
const Logger = @import("../../logger/logger.zig").Logger;
const Tls = @import("../../tls/Tls.zig");

// --------------------------------------------------------- //

/// Configuration for an HTTP/2 h2c server instance.
/// Pass to Http2.Server.init(). Fields without defaults (io, ip, port) are required.
pub const Http2ServerConfig = struct {
    /// Io backend for the server. Caller-provided. Must outlive the server.
    io: std.Io,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,
    /// Connection dispatch model. .ASYNC is the cleartext blocking model, .EPOLL / .URING the
    /// Linux-only shared-nothing multiplexed loops (one SO_REUSEPORT listener plus epoll or io_uring
    /// per worker, .URING falls back to .EPOLL when io_uring is unavailable). Off Linux, run() rejects
    /// .EPOLL and .URING with error.ZixDispatchModelUnsupported. Required.
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
    /// Per-connection receive buffer in bytes (.EPOLL / .URING mux). Used as a floor: the reader is
    /// sized to the larger of this and one max frame, so a larger value cuts read() and compaction
    /// for big frames.
    max_recv_buf: usize = 32 * 1024,
    /// Initial capacity in bytes of the per-connection TLS pending-write buffer (it grows on demand).
    /// A larger initial avoids early reallocation under big responses on the TLS path.
    tls_write_buf_initial_bytes: usize = 16 * 1024,
    /// Maximum concurrent streams per connection, advertised as SETTINGS_MAX_CONCURRENT_STREAMS. The
    /// .EPOLL / .URING mux borrows each stream's slot from a per-worker pool, so this bounds
    /// concurrency without reserving the full count per connection.
    max_streams: u32 = 128,
    /// MAX_FRAME_SIZE setting sent to clients (bytes).
    max_frame_size: u32 = 16384,
    /// HPACK scratch buffer size per connection.
    max_header_scratch: usize = 4096,
    /// Maximum request body buffered per stream (bytes). A larger request body is truncated to this.
    max_body: usize = 16384,
    /// Enable the per-worker response cache (ADR-036). Default false. When off, the handler cache API
    /// (serveCached / sendCachedFD) degrades to a plain send. Active under every dispatch model.
    response_cache: bool = false,
    /// Response cache slot count, rounded down to a power of two. Per-worker memory is
    /// cache_max_entries * cache_max_value_bytes, times the worker count.
    cache_max_entries: u32 = 256,
    /// Per-slot response cap in bytes. A response larger than this bypasses the cache.
    cache_max_value_bytes: u32 = 16 * 1024,
    /// Default cache freshness in milliseconds, exposed to handlers via cacheTtl().
    cache_ttl_ms: u32 = 1000,
    /// Optional ceiling on per-worker cache memory in bytes. 0 disables the ceiling.
    cache_max_total_bytes: usize = 0,
    /// https - opt-in. When non-null the server serves HTTP/2 over TLS (zix.Tls, ALPN h2), otherwise
    /// h2c (the default), the cleartext dispatch models untouched. alpn should include .H2 (browsers
    /// require it, RFC 7540 3.3). Caller owns the Context (Tls.Context.Config policy), must outlive.
    tls: ?*Tls.Context = null,
    /// Companion h2-over-TLS bind port for the dual-listener mode. 0 (default) keeps single-listener
    /// behavior (with tls set the server is TLS-only on port). Non-zero (requires tls) serves
    /// cleartext on port AND TLS on tls_port from one worker fleet. Ignored when tls is null.
    tls_port: u16 = 0,
    /// Optional logger. When non-null, the server routes its lifecycle lines (listening, fallback
    /// notices) through logger.system() instead of std.log, and writes one access record per served
    /// stream tagged [http2:access]. A handler that frames its own bytes outside the Response is not
    /// counted in that record's byte total. Caller owns, must outlive.
    logger: ?*Logger = null,
    /// Server-wide default handler processing timeout in milliseconds. 0 = disabled.
    /// Seeds Context.deadline_ns at dispatch. The handler may extend or override via setTimeout/withTimeout.
    handler_timeout_ms: u32 = 0,
    /// Root directory for static file serving. Empty (default) disables it. A request matching no
    /// route is served as a file before the 404 fallback, ".." is rejected. Range (RFC 7233) is
    /// served: 206 for a satisfiable range, 416 for a well-formed one past the end, and a malformed
    /// header is ignored so the whole file is sent. A multi-range header answers the first range.
    /// Validated at run(): missing dir = error.ZixPublicDirNotFound.
    public_dir: []const u8 = "",
    /// How long a resolved static file stays cached, in milliseconds. Default 0 means never cached:
    /// every request re-opens and re-reads the file. Above 0 the file is kept open and its .br / .gz
    /// siblings resolved once, so a repeat request costs a hash lookup, and a file changed on disk is
    /// picked up within one window. Separate from cache_ttl_ms, which belongs to the response cache.
    public_dir_cache_ttl_ms: u32 = 0,
    /// Static cache slot count, rounded down to a power of two and clamped against the process
    /// descriptor budget. One slot holds one file plus its .br and .gz siblings, so 256 covers 85
    /// distinct files at three variants each. A full table serves the request uncached, never an error.
    public_dir_cache_max_entries: u32 = 256,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http2: Http2ServerConfig required fields" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqualStrings("127.0.0.1", cfg.ip);
    try std.testing.expectEqual(@as(u16, 8082), cfg.port);
}

test "zix http2: Http2ServerConfig dispatch_model is required and stored as set" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(DispatchModel.ASYNC, cfg.dispatch_model);
}

test "zix http2: Http2ServerConfig workers defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
}

test "zix http2: Http2ServerConfig stream and frame defaults" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 128), cfg.max_streams);
    try std.testing.expectEqual(@as(u32, 16384), cfg.max_frame_size);
    try std.testing.expectEqual(@as(usize, 16384), cfg.max_body);
}

test "zix http2: Http2ServerConfig logger defaults to null" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expect(cfg.logger == null);
}

test "zix http2: Http2ServerConfig handler_timeout_ms defaults to zero" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(u32, 0), cfg.handler_timeout_ms);
}

test "zix http2: Http2ServerConfig worker_stack_size_bytes default" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = Http2ServerConfig{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC };
    try std.testing.expectEqual(@as(usize, 512 * 1024), cfg.worker_stack_size_bytes);
    try std.testing.expectEqual(@as(usize, 32 * 1024), cfg.max_recv_buf);
    try std.testing.expectEqual(@as(usize, 16 * 1024), cfg.tls_write_buf_initial_bytes);
    try std.testing.expectEqual(@as(u32, 0), cfg.busy_poll_us);
    try std.testing.expect(!cfg.reuseport_cbpf);
}
