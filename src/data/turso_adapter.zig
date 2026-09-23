//! The Turso adapter: `zurtr.data` over turso.zig, at any tier.
//!
//! # Shape
//!
//! One `Engine` is one `turso.Database` plus one `turso.Connection`. The contract says one `Database`
//! per role process and that it is not thread-safe; this adapter keeps that literal — no pool, no
//! sharing, no hidden connections.
//!
//! Parameters cross as a runtime slice of `data.Value` and are mapped into turso's own runtime `Value`
//! for the call. Rows come back the same way, through `Row.value(index)`, so a query never has to know
//! its column types at comptime. Row slices are borrowed for the duration of the sink call and the
//! scratch is reused between rows, which is what the contract asks for and what keeps a long result set
//! flat in memory.
//!
//! # Tiers
//!
//! `.memory` and `.file` are complete here. `.sync` and `.distributed` are the same local database with
//! a remote recorded: the remote half needs the sync SDK Kit, which is a separate build of the native
//! library (`-Dsync=true` in turso.zig), so a build without it reports `error.Unavailable` when asked
//! for a tier that needs one rather than pretending the tier is local-only.
//!
//! The lease below is what makes `.distributed` meaningful and it is implemented here for every tier:
//! one row, one holder, renewed through the same connection as the data it guards, so a node that can
//! write data can renew its lease and a node that cannot reach the database cannot hold one.

const std = @import("std");
const turso = @import("turso");
const data = @import("root.zig");

/// The lease table. Created on open, idempotent like every other schema statement.
const lease_schema =
    \\CREATE TABLE IF NOT EXISTS zurtr_write_lease (
    \\  name text PRIMARY KEY,
    \\  holder text NOT NULL,
    \\  until_micros integer NOT NULL
    \\)
;

/// The default lease name: one logical database has one writer.
pub const default_lease = "default";

/// Open a database at `tier`.
///
/// The handle this returns is the whole contract: a v-table plus the opaque engine, closed with
/// `Database.close`. Tier-specific surface (the write lease, and later the sync handle) is reached
/// through `engine(&handle)`.
pub fn open(allocator: std.mem.Allocator, io: std.Io, tier: data.Tier) data.Error!data.Database {
    return Engine.open(allocator, io, tier);
}

/// The engine behind a handle, for the tier-specific surface (the write lease).
pub fn engine(handle: *data.Database) *Engine {
    return @ptrCast(@alignCast(handle.context));
}

pub const Engine = struct {
    allocator: std.mem.Allocator,
    /// The clock the lease compares against, and (for the tiers that have one) the transport the sync
    /// half would use.
    io: std.Io,
    database: turso.Database,
    connection: turso.Connection,
    tier: data.Tier,
    /// This engine's own `data.Database` handle. A `Tx` carries a pointer to it, which is how
    /// `Tx.commit` reaches the vtable without the vtable having to carry the handle back.
    handle: data.Database = undefined,
    /// The transaction in flight, if a `Tx` is live. The contract allows one adapter-owned transaction
    /// at a time (nesting is a surface concern, expressed with savepoints); a second concurrent `begin`
    /// is a programming error, reported as `error.Operation`.
    tx: ?turso.Transaction = null,
    /// Parameter scratch, reused per call.
    values: std.ArrayList(turso.Value) = .empty,
    /// Row scratch, reused per row.
    columns: std.ArrayList(data.Value) = .empty,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, tier: data.Tier) data.Error!data.Database {
        const path = switch (tier) {
            .memory => ":memory:",
            .file => |p| p,
            .sync => |s| s.path,
            .distributed => |d| d.path,
        };

        // The remote half of these tiers is a different build of the native SDK *and* a transport that
        // drives it. The transport is not wired yet, so `.sync` is refused outright rather than opening
        // a local file and quietly never synchronizing — a caller that asked for synchronization must
        // not get a database that pretends to.
        //
        // `.distributed` opens: its local half is real and enforced (the write lease below), and what
        // it still needs for a deployment across machines is the same transport `.sync` is waiting on.
        // `-Dturso-sync` builds the SDK; nothing calls it yet.
        switch (tier) {
            .sync => return error.Unavailable,
            .memory, .file, .distributed => {},
        }

        const instance = allocator.create(Engine) catch return error.Internal;
        errdefer allocator.destroy(instance);

        instance.* = .{
            .allocator = allocator,
            .io = io,
            .database = turso.Database.open(allocator, .{ .path = path }) catch |err| return mapError(err),
            .connection = undefined,
            .tier = tier,
        };
        errdefer instance.database.deinit();

        instance.connection = instance.database.connect(.{}) catch |err| return mapError(err);

        // The lease is part of every tier: it costs one statement on open and makes the distributed
        // story true wherever the database runs.
        _ = instance.connection.exec(lease_schema, &.{}, .{}) catch |err| return mapError(err);

        instance.handle = .{ .context = instance, .vtable = &vtable, .tier = tier };

        return instance.handle;
    }

    const vtable = data.Database.VTable{
        .exec = exec,
        .query = query,
        .begin = begin,
        .commit = commit,
        .rollback = rollback,
        .close = close,
    };

    fn exec(context: *anyopaque, tx: ?*data.Tx, sql: []const u8, params: []const data.Value) data.Error!data.ExecResult {
        const self: *Engine = @ptrCast(@alignCast(context));
        defer self.values.clearRetainingCapacity();

        try self.bindParams(params);

        const affected = if (tx) |handle|
            asTx(handle).exec(sql, self.values.items, .{}) catch |err| return mapError(err)
        else
            self.connection.exec(sql, self.values.items, .{}) catch |err| return mapError(err);

        return .{ .rows_affected = affected };
    }

    fn query(context: *anyopaque, tx: ?*data.Tx, sql: []const u8, params: []const data.Value, sink: data.RowSink) data.Error!void {
        const self: *Engine = @ptrCast(@alignCast(context));
        defer self.values.clearRetainingCapacity();

        try self.bindParams(params);

        var rows = if (tx) |handle|
            asTx(handle).query(sql, self.values.items, .{}) catch |err| return mapError(err)
        else
            self.connection.query(sql, self.values.items, .{}) catch |err| return mapError(err);
        defer rows.deinit();

        while (rows.next() catch |err| return mapError(err)) |row| {
            defer self.columns.clearRetainingCapacity();

            const count = row.columnCount();
            self.columns.ensureTotalCapacity(self.allocator, count) catch return error.Internal;

            for (0..count) |index| {
                const value = row.value(index) catch |err| return mapError(err);
                self.columns.appendAssumeCapacity(toDataValue(value));
            }

            try sink.row(self.columns.items);
        }
    }

    fn begin(context: *anyopaque, mode: data.TxMode) data.Error!*data.Tx {
        const self: *Engine = @ptrCast(@alignCast(context));
        if (self.tx != null) return error.Operation;

        // The distributed tier's rule, enforced where writes actually begin rather than trusted to the
        // caller: a node writes only while it holds the lease, and a follower that asks to write while
        // someone else holds it is told so. Reads never need the lease — one writer, many readers.
        if (mode == .read_write and self.tier == .distributed) {
            const node = self.tier.distributed.node;
            if (!try self.claimLease(self.tier.distributed.lease_name, node, self.nowMicros())) return error.Conflict;
        }

        self.tx = self.connection.begin(.immediate, .{}) catch |err| return mapError(err);

        const tx = self.allocator.create(data.Tx) catch return error.Internal;
        tx.* = .{
            // `exec` and `query` receive the `*Tx` and route through it; the context is the live
            // transaction handle, which is what they actually need.
            .context = if (self.tx) |*handle| @ptrCast(handle) else return error.Internal,
            .database = &self.handle,
            .mode = mode,
        };

        return tx;
    }

    fn commit(context: *anyopaque, tx: *data.Tx) data.Error!void {
        const self: *Engine = @ptrCast(@alignCast(context));
        _ = tx;

        var handle = self.tx orelse return error.Internal;
        handle.commit(null) catch |err| return mapError(err);
        self.tx = null;
    }

    fn rollback(context: *anyopaque, tx: *data.Tx) data.Error!void {
        const self: *Engine = @ptrCast(@alignCast(context));
        _ = tx;

        var handle = self.tx orelse return;
        handle.rollback(null) catch |err| return mapError(err);
        self.tx = null;
    }

    fn close(context: *anyopaque) void {
        const self: *Engine = @ptrCast(@alignCast(context));

        if (self.tx) |*handle| {
            handle.rollback(null) catch {};
            self.tx = null;
        }

        self.values.deinit(self.allocator);
        self.columns.deinit(self.allocator);
        self.connection.deinit();
        self.database.deinit();
        self.allocator.destroy(self);
    }

    /// The wall clock, in microseconds. Only ordering matters here: a lease compares it against the
    /// expiry it wrote, and every node that shares a database shares the same clock's direction.
    fn nowMicros(self: *Engine) i64 {
        const stamp = std.Io.Clock.Timestamp.now(self.io, .real);

        return @intCast(@divTrunc(stamp.raw.toNanoseconds(), std.time.ns_per_us));
    }

    // --------------------------------------------------------- //
    // The write lease

    /// Take or renew the lease for this process. Returns false when another holder has it unexpired.
    ///
    /// Held through the database so the lease and the writes it guards cannot diverge: a node that can
    /// write can renew, and a node that cannot reach its remote cannot pretend to hold the lease.
    pub fn claimLease(self: *Engine, name: []const u8, holder: []const u8, now_micros: i64) data.Error!bool {
        const until = now_micros + 1_000_000;
        const claimed = self.connection.execParams(
            \\INSERT INTO zurtr_write_lease (name, holder, until_micros) VALUES (?1, ?2, ?3)
            \\ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, until_micros = excluded.until_micros
            \\WHERE zurtr_write_lease.holder = excluded.holder OR zurtr_write_lease.until_micros <= ?4
        , .{ name, holder, until, now_micros }, .{}) catch |err| return mapError(err);

        return claimed > 0;
    }

    /// Release the lease, but only if this holder still has it.
    pub fn releaseLease(self: *Engine, name: []const u8, holder: []const u8) data.Error!bool {
        const released = self.connection.execParams(
            "DELETE FROM zurtr_write_lease WHERE name = ?1 AND holder = ?2",
            .{ name, holder },
            .{},
        ) catch |err| return mapError(err);

        return released > 0;
    }

    /// The current holder and its expiry, copied into the caller's buffer.
    pub const Held = struct { holder: [64]u8, holder_len: usize, until_micros: i64 };

    pub fn leaseHolder(self: *Engine, name: []const u8) data.Error!?Held {
        var rows = self.connection.queryParams(
            "SELECT holder, until_micros FROM zurtr_write_lease WHERE name = ?1",
            .{name},
            .{},
        ) catch |err| return mapError(err);
        defer rows.deinit();

        const row = (rows.next() catch |err| return mapError(err)) orelse return null;

        var held = Held{ .holder = undefined, .holder_len = 0, .until_micros = row.get(i64, 1) catch |err| return mapError(err) };
        const holder = row.get([]const u8, 0) catch |err| return mapError(err);
        held.holder_len = @min(holder.len, held.holder.len);
        @memcpy(held.holder[0..held.holder_len], holder[0..held.holder_len]);

        return held;
    }

    // --------------------------------------------------------- //

    fn bindParams(self: *Engine, params: []const data.Value) data.Error!void {
        self.values.ensureTotalCapacity(self.allocator, params.len) catch return error.Internal;

        for (params) |param| {
            const value: turso.Value = switch (param) {
                .null => .null_value,
                .boolean => |b| .{ .integer = @intFromBool(b) },
                .integer => |i| .{ .integer = i },
                .float => |f| .{ .real = f },
                .text => |t| .{ .text = t },
                .bytes => |b| .{ .blob = b },
                .uuid => |u| .{ .blob = &u },
                // SQLite has no date type: an instant is an integer of microseconds, which is exact and
                // sorts correctly, and is what every caller of this API already has.
                .timestamp_micros => |t| .{ .integer = t },
            };

            self.values.appendAssumeCapacity(value);
        }
    }

    fn toDataValue(value: turso.Value) data.Value {
        return switch (value) {
            .null_value => .null,
            .integer => |i| .{ .integer = i },
            .real => |f| .{ .float = f },
            .text => |t| .{ .text = t },
            .blob => |b| .{ .bytes = b },
        };
    }

    fn asTx(tx: *data.Tx) *turso.Transaction {
        return @ptrCast(@alignCast(tx.context));
    }
};

/// Map turso's status into the framework taxonomy.
///
/// The contract's classes are about what a *caller* can do, so the mapping is by consequence rather
/// than by name: a constraint violation is the caller's to resolve (`Conflict`), a busy database is a
/// serialization failure (`Conflict`), a broken or absent dependency is `Unavailable`, and anything
/// that can only be a bug in this adapter or the statement is `Internal`/`Syntax`.
fn mapError(err: anyerror) data.Error {
    return switch (err) {
        error.Constraint, error.Busy, error.BusySnapshot => error.Conflict,
        error.Io, error.NotDatabase, error.Corrupt, error.DatabaseFull, error.OutOfMemory => error.Unavailable,
        error.Interrupt => error.Timeout,
        error.ReadOnly, error.IntegerOverflow => error.Operation,
        error.Misuse, error.InvalidState, error.ParameterCountMismatch, error.ParameterNotFound => error.Internal,
        error.ColumnOutOfBounds, error.TypeMismatch, error.NoRow, error.InvalidUtf8, error.InteriorNul => error.Internal,
        error.UnexpectedStatus, error.Unsupported, error.VersionMismatch, error.AlreadySetup => error.Internal,
        else => error.Internal,
    };
}
