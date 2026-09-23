//! rediz: a Redis driver.
//!
//! Note:
//! - Zig std only, standalone package. This file is the public root.
//! - RESP3 via HELLO with in-place RESP2 fallback, compatible with Redis 7
//!   and 8 (no 8-only command or reply dependency).

const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for rediz source.
///
/// Note:
/// - Do not create in other place!
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

// --------------------------------------------------------- //

pub const resp = @import("protocol/resp.zig");
pub const reply_error = @import("reply_error.zig");
pub const url = @import("url.zig");
pub const conn = @import("conn.zig");
pub const pool = @import("pool.zig");
pub const dispatch = @import("dispatch/dispatch.zig");
pub const pipeline = @import("pipeline.zig");
pub const tls = @import("tls.zig");

/// Wire protocol selector.
pub const RespVersion = enum {
    /// HELLO 3, fall back to RESP2 when the server refuses.
    AUTO,
    /// Skip HELLO, speak RESP2 (legacy AUTH when credentials are set).
    RESP2,
    /// HELLO 3, fail the connect when the server refuses.
    RESP3,
};

/// TLS behavior of a connection.
///
/// Note:
/// - A Redis TLS port speaks TLS from the first byte, there is no in-band
///   upgrade to prefer: it is either on or off for a given port.
pub const TlsMode = enum {
    /// Cleartext TCP, the default.
    OFF,
    /// TLS from the first byte, fail the connect on a broken handshake.
    REQUIRE,
};

/// How the driver multiplexes socket I/O across connections.
///
/// Note:
/// - ASYNC: the Pool, blocking connections with one round trip in flight per
///   held connection. The default.
/// - EPOLL: one thread that owns non-blocking connections and pipelines many
///   commands per connection (see dispatch.Transport).
/// - URING: the same single-thread multiplex on io_uring.
/// - EPOLL and URING are cleartext only, so they pair with tls = OFF.
pub const DispatchModel = enum {
    ASYNC,
    EPOLL,
    URING,
};

/// Flat connection config, shared by Conn and Pool (pool_size and the retry
/// knobs only matter for Pool).
pub const Config = struct {
    /// IP literal or hostname (a hostname goes through the hosts/DNS lookup).
    ip: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    /// ACL user, empty = the default user.
    user: []const u8 = "",
    /// Empty = no authentication.
    password: []const u8 = "",
    /// SELECT index after the handshake, 0 = stay on the default.
    database: u32 = 0,
    /// CLIENT name set through HELLO (RESP3 path only), null = none.
    client_name: ?[]const u8 = "rediz",
    /// Bounds the connect + handshake phase in milliseconds, 0 disables.
    conn_timeout_ms: u32 = 10_000,
    protocol_version: RespVersion = .AUTO,
    tls: TlsMode = .OFF,
    /// Transport that multiplexes socket I/O. ASYNC (the Pool) is the
    /// default, EPOLL and URING select the single-thread multiplexed
    /// dispatch.Transport (cleartext only, so keep tls = OFF for them).
    dispatch_model: DispatchModel = .ASYNC,
    /// Bounds replies a connection may owe: commands queued by a Pipeline
    /// (sheds error.RedizQueueFull at the bound, 0 = no bound) and outstanding
    /// deferred commands (drained at the bound, 0 acts as one at a time).
    max_pending_replies: usize = 16,
    /// Pool only: acquires parked on a fully-held pool (FIFO handoff on
    /// release), 0 = off (acquire sheds immediately with
    /// error.RedizPoolExhausted). Beyond the bound acquire sheds with
    /// error.RedizPoolBusy.
    process_queue_len: usize = 0,
    /// Pool only: connections per pool.
    pool_size: usize = 6,
    /// Pool only: connect attempts per acquire beyond the first.
    retry_max: u32 = 3,
    /// Pool only: delay between connect retries.
    retry_delay_ms: u32 = 250,
};

/// Connection surface, re-exported: rediz.Conn.connect(...).
pub const Conn = conn.Conn;
pub const SetOptions = conn.SetOptions;
pub const KeyValue = conn.KeyValue;

/// Shared connection pool, re-exported: rediz.Pool.init(...).
pub const Pool = pool.Pool;

/// Multiplexed dispatch transport, re-exported: rediz.Transport.open(...).
pub const Transport = dispatch.Transport;

/// Batched commands, re-exported: conn.pipeline().
pub const Pipeline = pipeline.Pipeline;

/// Decoded reply surface, re-exported.
pub const Reply = resp.Reply;
pub const MapEntry = resp.MapEntry;

/// Error prefix enum + the captured server error, re-exported.
pub const Prefix = reply_error.Prefix;
pub const ServerError = reply_error.ServerError;

/// REDIS_URL parsing, re-exported: rediz.parseUrl("redis://...").
pub const parseUrl = url.parseUrl;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test {
    _ = resp;
    _ = reply_error;
    _ = url;
    _ = conn;
    _ = pool;
    _ = dispatch;
    _ = pipeline;
    _ = tls;
    _ = @import("tls/wire.zig");
    _ = @import("tls/key_schedule.zig");
    _ = @import("tls/record.zig");
    _ = @import("tls/client.zig");
}
