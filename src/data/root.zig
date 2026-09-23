//! `zurtr.data` — queries, transactions, migrations, adapters.
//!
//! The interface is the one `docs/modules/data.md` defines, unchanged: a `Database` is an owner plus a
//! vtable, `Tx` is a scoped handle that must be committed or rolled back, rows arrive through a
//! push-style sink, and errors land in the framework taxonomy. Adapters are chosen by construction, so
//! callers never see which engine is underneath.
//!
//! # Tiers
//!
//! An adapter is opened at a **tier**, and the tier is the whole of its durability and reach:
//!
//!   * `.memory` — the process. Nothing survives exit; one writer, no coordination. Tests and caches.
//!   * `.file` — this machine, this path. Survives exit; one writer at a time, enforced by the engine.
//!   * `.sync` — a local file plus remote synchronization with another database. Survives the machine.
//!   * `.distributed` — several zurtr nodes over one logical database, with a write lease so exactly
//!     one of them writes at a time and the others follow.
//!
//! Tier 1 and 2 are local and complete on their own. Tiers 3 and 4 sit on top of a local file: the
//! database always works locally first, and the remote is what carries changes further. That ordering is
//! the point — a node that cannot reach its remote keeps serving and keeps its own state, which is what
//! makes the deployment model (one static executable, many nodes) survivable.

const std = @import("std");

pub const turso = @import("turso_adapter.zig");

/// A value crossing the database boundary.
///
/// Mirrors the contract's `Param`, with `null` a distinct tag rather than an absence, on the way in and
/// on the way out. Slices in a `Value` handed to an adapter are borrowed for the duration of the call;
/// slices in a `Value` handed to a `RowSink` are borrowed for the duration of that call and the sink
/// copies what it keeps (the contract's rule, and the reason there is no lazy iterator in v1).
pub const Value = union(enum) {
    null,
    boolean: bool,
    integer: i64,
    float: f64,
    text: []const u8,
    bytes: []const u8,
    uuid: [16]u8,
    /// Microseconds since the Unix epoch, UTC.
    timestamp_micros: i64,
};

/// How a transaction may be used.
pub const TxMode = enum {
    /// Reads and writes; the default for anything that mutates.
    read_write,
    /// Reads only. An engine that can enforce it should, and one that cannot still refuses writes at
    /// the layer above.
    read_only,
};

pub const ExecResult = struct {
    rows_affected: u64,
};

/// The framework's error taxonomy, at the layer that can actually tell these apart.
///
/// The surface above decides what to show a caller; an adapter only has to be honest about which class
/// it hit. `syntax` is a bug (the SQL is written by the program, not by a caller), and `internal` is a
/// bug in the adapter or the engine.
pub const Error = error{
    /// The dependency is down or the pool is exhausted. Retryable by policy, not by accident.
    Unavailable,
    /// A unique or foreign-key violation, or a serialization failure. The caller's decision to make.
    Conflict,
    /// The operation exceeded its deadline.
    Timeout,
    /// The statement does not compile. Programmer error.
    Syntax,
    /// The engine refused the operation (constraint, type, closed handle).
    Operation,
    /// A bug: an invariant of this layer does not hold.
    Internal,
};

/// Where a `Database` lives and what that buys.
pub const Tier = union(enum) {
    /// The process's lifetime. One writer, no coordination, nothing survives exit.
    memory,
    /// One machine, one file. Survives exit; the engine serializes writers.
    file: []const u8,
    /// A local file that also synchronizes with a remote database. The remote is what survives the
    /// machine, and what other nodes synchronize against.
    sync: Sync,
    /// Several zurtr nodes over one logical database. Each keeps a local file and follows the remote;
    /// exactly one holds the write lease (see `Lease`).
    distributed: Distributed,

    pub const Sync = struct {
        /// The local file. The database is always usable at this path, remote or not.
        path: []const u8,
        /// The remote endpoint, as the sync transport expects it.
        remote: []const u8,
        /// The token the remote authenticates, when it wants one.
        auth_token: ?[]const u8 = null,
    };

    pub const Distributed = struct {
        path: []const u8,
        remote: []const u8,
        auth_token: ?[]const u8 = null,
        /// What this node intends to be. A `follower` never takes the lease while another node holds it;
        /// a `leader` takes it when it is free.
        role: Role = .follower,
    };

    pub const Role = enum { leader, follower };

    /// One line, for logs and `zurtr modules`-style reports.
    pub fn describe(self: Tier) []const u8 {
        return switch (self) {
            .memory => "memory",
            .file => "file",
            .sync => "sync",
            .distributed => "distributed",
        };
    }
};

/// A row, pushed rather than pulled.
///
/// Implementations copy anything they keep: the columns slice and every borrowed slice inside it are
/// valid only for the call.
pub const RowSink = struct {
    context: *anyopaque,
    push: *const fn (context: *anyopaque, columns: []const Value) Error!void,

    pub fn row(self: RowSink, columns: []const Value) Error!void {
        return self.push(self.context, columns);
    }
};

/// A scoped transaction handle.
///
/// Not thread-safe and not storable, per the contract. It must be committed or rolled back; an adapter
/// that observes a `Tx` dropped without either rolls back and records a diagnostic, because silently
/// committing is forbidden.
pub const Tx = struct {
    context: *anyopaque,
    database: *Database,
    mode: TxMode,
    done: bool = false,

    pub fn commit(self: *Tx) Error!void {
        try self.database.begin_commit(self);
        self.done = true;
    }

    pub fn rollback(self: *Tx) void {
        if (self.done) return;

        self.database.begin_rollback(self) catch {};
        self.done = true;
    }
};

/// An open database. One per role process, per the contract.
pub const Database = struct {
    context: *anyopaque,
    vtable: *const VTable,
    /// The tier this was opened at. Read-only after construction.
    tier: Tier,
    /// Set when a `Tx` was dropped without commit or rollback; the contract requires it be observable
    /// rather than silent.
    uncommitted_transactions: u64 = 0,

    pub const VTable = struct {
        exec: *const fn (context: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Value) Error!ExecResult,
        query: *const fn (context: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Value, sink: RowSink) Error!void,
        begin: *const fn (context: *anyopaque, mode: TxMode) Error!*Tx,
        commit: *const fn (context: *anyopaque, tx: *Tx) Error!void,
        rollback: *const fn (context: *anyopaque, tx: *Tx) Error!void,
        close: *const fn (context: *anyopaque) void,
    };

    pub fn exec(self: *Database, tx: ?*Tx, sql: []const u8, params: []const Value) Error!ExecResult {
        return self.vtable.exec(self.context, tx, sql, params);
    }

    pub fn query(self: *Database, tx: ?*Tx, sql: []const u8, params: []const Value, sink: RowSink) Error!void {
        return self.vtable.query(self.context, tx, sql, params, sink);
    }

    pub fn begin(self: *Database, mode: TxMode) Error!*Tx {
        return self.vtable.begin(self.context, mode);
    }

    /// Called by `Tx.commit`, which owns the `done` flag.
    fn begin_commit(self: *Database, tx: *Tx) Error!void {
        return self.vtable.commit(self.context, tx);
    }

    /// Called by `Tx.rollback`, which owns the `done` flag.
    fn begin_rollback(self: *Database, tx: *Tx) Error!void {
        return self.vtable.rollback(self.context, tx);
    }

    /// Release the engine, and any node-level state the tier holds (a lease, a sync handle).
    pub fn close(self: *Database) void {
        self.vtable.close(self.context);
    }
};

/// The write lease a `.distributed` node holds.
///
/// One row per logical database; a node writes only while it holds the lease. Held through the database
/// itself, so the lease travels the same path as the data it guards — a node that can write data can
/// renew it, and a node that cannot reach the database cannot hold it.
pub const Lease = struct {
    /// How long a held lease is valid for, in milliseconds.
    ttl_ms: i64 = 30_000,
    holder: []const u8,
    until_micros: i64,
};

test "a tier says what it is" {
    try std.testing.expectEqualStrings("memory", (Tier{ .memory = {} }).describe());
    try std.testing.expectEqualStrings("file", (Tier{ .file = "app.db" }).describe());
    try std.testing.expectEqualStrings("sync", (Tier{ .sync = .{ .path = "app.db", .remote = "https://example" } }).describe());
    try std.testing.expectEqualStrings(
        "distributed",
        (Tier{ .distributed = .{ .path = "app.db", .remote = "https://example" } }).describe(),
    );
}
