//! zix HTTP/3 server: the public Server type and the dispatch_model switch. Each
//! dispatch model lives in its own file under dispatch/ (ADR-043).
//!
//! What:
//! - Server.init(handler, config) binds a UDP socket and serves QUIC / HTTP-3 on the zix.Udp
//!   datagram substrate. The dispatch model selects the worker shape per the ADR-050 contract:
//!   `.ASYNC` runs a single-worker recv with internal CID demux. `.EPOLL` / `.URING` run one
//!   SO_REUSEPORT worker per core, the kernel load-balancing connections by 4-tuple.
//!
//! Usage:
//! ```zig
//! fn handler(req: *const zix.Http3.Request, res: *zix.Http3.Response, ctx: *zix.Http3.Context) !void {
//!     res.send("hello over h3");
//! }
//! var server = zix.Http3.Server.init(handler, config); // config.tls must be a TLS 1.3 context
//! try server.run();
//! ```

const std = @import("std");

const Config = @import("config.zig");
const Http3ServerConfig = Config.Http3ServerConfig;
const core = @import("core.zig");
const static_cache = @import("../../utils/static_cache.zig");
const dispatch_support = @import("../../utils/dispatch_support.zig");

const Webtransport = @import("webtransport/Webtransport.zig");
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");

/// The application request handler (re-exported from core).
pub const HandlerFn = core.HandlerFn;
/// A decoded HTTP/3 request (re-exported from core).
pub const Request = core.Request;
/// The response the handler fills (re-exported from core).
pub const Response = core.Response;
/// The per-request env: deadline, io, allocator (re-exported from core).
pub const Context = core.Context;
/// The content coding a handler sets on its response body (re-exported from core).
pub const ContentEncoding = core.ContentEncoding;

// Internal generic implementation: use `Server.init(handler, config)` publicly.
fn Http3ServerImpl(comptime handler: HandlerFn) type {
    return struct {
        const Self = @This();

        config: Http3ServerConfig,

        /// Initialize the HTTP/3 server with the given config. Validation happens in run.
        ///
        /// Return:
        /// - Self
        pub fn init(config: Http3ServerConfig) Self {
            return .{ .config = config };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Bind and serve. Blocks until an error occurs. The dispatch model selects the worker shape.
        ///
        /// Return:
        /// - !void
        /// - error.ZixPortNotConfigured if config.port is 0
        /// - error.ZixTlsRequired if config.tls is null (QUIC has no cleartext mode)
        /// - error.ZixDispatchModelUnsupported if dispatch_model is .EPOLL or .URING off Linux
        /// - error.ZixWebtransportConfig if the WebTransport knobs exceed what the engine can hold
        pub fn run(self: *const Self) !void {
            if (self.config.port == 0) return error.ZixPortNotConfigured;

            // WebTransport is checked before anything is bound, so a config the engine cannot honour
            // fails to start instead of silently running with a smaller feature than it advertises.
            // Webtransport.capacityError(config) names the offending field for a caller that wants to
            // report which knob to lower; the run path only needs the verdict.
            if (self.config.webtransport.enabled) {
                if (Webtransport.capacityError(self.config.webtransport) != null) return error.ZixWebtransportConfig;

                // One decrypted 1-RTT payload has to hold a whole DATAGRAM frame for the receive path to
                // read it, so the advertised frame limit cannot exceed that buffer.
                if (self.config.webtransport.max_datagram_frame_size > common.max_app_payload_buf) return error.ZixWebtransportConfig;
            }

            // Reject an unrunnable model before binding, so a rejected config leaves nothing
            // behind (ADR-065).
            if (!dispatch_support.isSupported(self.config.dispatch_model)) {
                common.logSystem(self.config, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(self.config.dispatch_model)});

                return error.ZixDispatchModelUnsupported;
            }

            if (self.config.tls == null) return error.ZixTlsRequired;

            // Static serving is opt-in: when public_dir is set, fail fast if the directory is absent
            // rather than 404-ing every file request at runtime. Mirrors zix.Http1.Server.run.
            if (self.config.public_dir.len > 0) {
                // One name used to cover missing, not-a-directory and permission-denied alike, so
                // a public_dir the process cannot enter reported as one that is not there.
                const dir = std.Io.Dir.openDir(std.Io.Dir.cwd(), self.config.io, self.config.public_dir, .{}) catch |err| return switch (err) {
                    error.FileNotFound => error.ZixPublicDirNotFound,
                    error.NotDir => error.ZixPublicDirNotADirectory,
                    else => error.ZixPublicDirUnreadable,
                };
                dir.close(self.config.io);

                // Unlike the other engines this is not just an optimization: an HTTP/3 response body
                // outlives its handler, so a static file can only be served out of the cache. With
                // caching off, the router falls through to 404 instead.
                // A failed install used to look exactly like caching being off, so a box out of
                // memory served every static file through the slow path and said nothing.
                const installed = static_cache.install(self.config.public_dir_cache_max_entries, self.config.public_dir_cache_ttl_ms) catch |err| downgrade: {
                    common.logSystem(self.config, .WARN, "the static cache could not be installed ({s}), every static request re-opens its file", .{@errorName(err)});

                    break :downgrade .DISABLED;
                };
                if (installed == .DISABLED) {
                    common.logSystem(self.config, .WARN, "public_dir is set but public_dir_cache_ttl_ms is 0, so static serving stays off", .{});
                }
                if (installed == .MISMATCHED) {
                    common.logSystem(self.config, .WARN, "a static cache is already installed in this process with different settings, keeping it", .{});
                }
            }

            return switch (self.config.dispatch_model) {
                .ASYNC => async_model.runAsync(handler, self.config),
                .EPOLL => epoll_model.runEpoll(handler, self.config),
                .URING => uring_model.runUring(handler, self.config),
            };
        }
    };
}

// --------------------------------------------------------------- //

/// http3 server - initialize with a comptime handler and a runtime config.
///
/// Note:
/// - handler must be comptime: it is baked into the server type, so there is no
///   dynamic registration after init. Pass a Router(routes).dispatch or a bare handler.
/// - QUIC has no cleartext mode: run() requires config.tls (a TLS 1.3 context).
///
/// Usage:
/// ```zig
/// const Routes = zix.Http3.Router(&[_]zix.Http3.Route{
///     .{ .path = "/", .handler = home },
/// });
///
/// var server = zix.Http3.Server.init(Routes.dispatch, .{
///     .io = io,
///     .allocator = allocator,
///     .ip = "0.0.0.0",
///     .port = 8443,
///     .tls = &tls,
///     .dispatch_model = .EPOLL,
/// });
/// defer server.deinit();
///
/// try server.run();
/// ```
pub const Server = struct {
    /// Param:
    /// handler - comptime HandlerFn (baked into the server type)
    /// config - Http3ServerConfig
    ///
    /// Return:
    /// - Http3ServerImpl(handler)
    pub fn init(comptime handler: HandlerFn, config: Http3ServerConfig) Http3ServerImpl(handler) {
        return Http3ServerImpl(handler).init(config);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn noopHandler(_: *const Request, _: *Response, _: *Context) !void {}

test "zix http3: run rejects a WebTransport config the engine cannot hold" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    // The connection tables are sized from these ceilings, so a larger value would promise a client more
    // sessions than the engine can track.
    var too_many_sessions = Server.init(noopHandler, .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9063,
        .dispatch_model = .ASYNC,
        .webtransport = .{ .enabled = true, .max_sessions_per_connection = Webtransport.connection_session_cap + 1 },
    });
    defer too_many_sessions.deinit();

    try std.testing.expectError(error.ZixWebtransportConfig, too_many_sessions.run());

    // A DATAGRAM frame larger than the payload buffer the receive path decodes into could never be read.
    var too_large = Server.init(noopHandler, .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9063,
        .dispatch_model = .ASYNC,
        .webtransport = .{ .enabled = true, .max_datagram_frame_size = common.max_app_payload_buf + 1 },
    });
    defer too_large.deinit();

    try std.testing.expectError(error.ZixWebtransportConfig, too_large.run());
}

test "zix http3: run rejects port zero and missing TLS" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var no_port = Server.init(noopHandler, .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 0,
        .dispatch_model = .ASYNC,
    });
    defer no_port.deinit();

    try std.testing.expectError(error.ZixPortNotConfigured, no_port.run());

    var no_tls = Server.init(noopHandler, .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9063,
        .dispatch_model = .ASYNC,
    });
    defer no_tls.deinit();

    try std.testing.expectError(error.ZixTlsRequired, no_tls.run());
}

comptime {
    _ = common;
}
