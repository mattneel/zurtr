//! postgrez: a PostgreSQL database driver.
//!
//! Note:
//! - Zig std only, standalone package. This file is the public root.
//! - Wire protocol 3.2 with in-place 3.0 fallback, minimum server is
//!   PostgreSQL 15.

const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for postgrez source.
///
/// Note:
/// - Do not create in other place!
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

// --------------------------------------------------------- //

pub const frontend = @import("protocol/frontend.zig");
pub const backend = @import("protocol/backend.zig");
pub const startup = @import("protocol/startup.zig");
pub const scram = @import("auth/scram.zig");
pub const cleartext = @import("auth/cleartext.zig");
pub const oid = @import("types/oid.zig");
pub const binary = @import("types/binary.zig");
pub const text = @import("types/text.zig");
pub const row = @import("types/row.zig");
pub const sqlstate = @import("sqlstate.zig");
pub const conn = @import("conn.zig");
pub const pool = @import("pool.zig");
pub const statement = @import("statement.zig");
pub const executor = @import("executor.zig");
pub const dispatch = @import("dispatch/dispatch.zig");
pub const pipeline = @import("pipeline.zig");
pub const copy = @import("copy.zig");
pub const notify = @import("notify.zig");
pub const tls = @import("tls.zig");
pub const url = @import("url.zig");

/// Startup protocol knob, re-exported for config use.
pub const ProtocolVersion = startup.ProtocolVersion;

/// TLS behavior of a connection.
pub const TlsMode = enum {
    /// Cleartext TCP, the default.
    OFF,
    /// Ask for TLS, continue cleartext when the server refuses.
    PREFER,
    /// Ask for TLS, fail the connect when the server refuses.
    REQUIRE,
};

/// How the driver multiplexes socket I/O across connections.
///
/// Note:
/// - ASYNC: the Executor, a thread pool of blocking connections with one
///   round trip in flight per worker. The default.
/// - EPOLL: one thread that owns non-blocking connections and pipelines many
///   requests per connection (see dispatch.Transport).
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
    port: u16 = 5432,
    user: []const u8,
    password: []const u8 = "",
    database: ?[]const u8 = null,
    application_name: ?[]const u8 = "postgrez",
    /// Bounds the connect + startup phase in milliseconds, 0 disables.
    conn_timeout_ms: u32 = 10_000,
    protocol_version: ProtocolVersion = .AUTO,
    tls: TlsMode = .OFF,
    /// Transport that multiplexes socket I/O. ASYNC (the Executor) is the
    /// default, EPOLL and URING select the single-thread multiplexed
    /// dispatch.Transport (cleartext only, so keep tls = OFF for them).
    dispatch_model: DispatchModel = .ASYNC,
    /// Bounds replies a connection may owe: statements queued by a
    /// Pipeline or by Statement.sendRows. At the bound the queuing call
    /// sheds with error.PostgrezQueueFull, 0 = no bound.
    max_pending_replies: usize = 16,
    /// Pool only: acquires parked on a fully-held pool (FIFO handoff on
    /// release), 0 = off (acquire sheds immediately with
    /// error.PostgrezPoolExhausted). Beyond the bound acquire sheds with
    /// error.PostgrezPoolBusy.
    process_queue_len: usize = 0,
    /// Pool only: connections per pool.
    pool_size: usize = 6,
    /// Pool only: connect attempts per acquire beyond the first.
    retry_max: u32 = 3,
    /// Pool only: delay between connect retries.
    retry_delay_ms: u32 = 250,
};

/// Connection surface, re-exported: postgrez.Conn.connect(...).
pub const Conn = conn.Conn;
pub const Transaction = conn.Transaction;
pub const Result = conn.Result;
pub const RowView = conn.Row;
pub const OwnedNotification = conn.OwnedNotification;

/// Shared connection pool, re-exported: postgrez.Pool.init(...).
pub const Pool = pool.Pool;

/// Driver features, re-exported.
pub const Statement = statement.Statement;
pub const Executor = executor.Executor;
pub const Transport = dispatch.Transport;
pub const Pipeline = pipeline.Pipeline;
pub const PipelineResult = pipeline.PipelineResult;
pub const PipelineStatus = pipeline.PipelineStatus;
pub const CopyIn = copy.CopyIn;
pub const CopyOut = copy.CopyOut;

/// Full SQLSTATE enum + the captured server error, re-exported.
pub const SqlState = sqlstate.SqlState;
pub const ServerError = sqlstate.ServerError;

/// Row mapper surface, re-exported: postgrez.parseRow(User, ...).
pub const ColumnInfo = row.ColumnInfo;
pub const ParseRowOptions = row.ParseRowOptions;
pub const parseRow = row.parseRow;

/// DATABASE_URL parsing, re-exported: postgrez.parseUrl("postgres://...").
pub const parseUrl = url.parseUrl;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test {
    _ = frontend;
    _ = backend;
    _ = startup;
    _ = scram;
    _ = cleartext;
    _ = oid;
    _ = binary;
    _ = text;
    _ = row;
    _ = sqlstate;
    _ = conn;
    _ = pool;
    _ = statement;
    _ = executor;
    _ = dispatch;
    _ = pipeline;
    _ = copy;
    _ = notify;
    _ = tls;
    _ = url;
    _ = @import("tls/wire.zig");
    _ = @import("tls/key_schedule.zig");
    _ = @import("tls/record.zig");
    _ = @import("tls/client.zig");
}
