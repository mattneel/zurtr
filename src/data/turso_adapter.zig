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
//! `.memory`, `.file` and `.distributed` are local databases here, and `.sync` is a local database with
//! a remote the sync engine keeps it in step with. The remote half is the sync SDK Kit — a separate
//! build of the native library, asked for with `-Dturso-sync` — so a build without it refuses `.sync`
//! with `error.Unavailable` rather than opening a local file that would never synchronize.
//!
//! The lease below is what makes `.distributed` meaningful and it is implemented here for every tier:
//! one row, one holder, renewed through the same connection as the data it guards, so a node that can
//! write data can renew its lease and a node that cannot reach the database cannot hold one. The tier
//! also asks the engine for its experimental multiprocess WAL coordination, without which a second
//! live process cannot open the file at all — see `features` in `open`.

const std = @import("std");
const data = @import("root.zig");
const build_options = @import("build_options");

/// The binding root, in a build that has no sync SDK: the vendored binding, or the guard file that
/// says the adapter was not asked for.
const base = @import("turso");
/// In a sync build there is one module for the whole stack — the SDK module is rooted in the same
/// source tree and re-exports the base binding as `base`, because Zig will not put one file in two
/// modules of one compilation and two copies would not be the same type. So the base names resolve
/// through it, and `Connection` from here *is* the connection the sync operations hand back.
const turso = if (build_options.turso_sync) sync_sdk.base else base;

/// The sync SDK Kit, in a build that asked for it (`-Dturso-sync`).
///
/// A module import in a branch a build never takes is never resolved, which is what lets a build
/// without the SDK compile this file at all — there is no `turso_sync` module to resolve. Every use of
/// this name is therefore inside `if (comptime build_options.turso_sync)`, and `Synced` below is the
/// empty stand-in that keeps the engine's shape identical in both builds.
const sync_sdk = if (build_options.turso_sync) @import("turso_sync") else struct {};

/// The remote half of a `.sync` engine: the SDK's own database, the transport that drives it, and the
/// credentials the tier was opened with. Empty in a build without the SDK, where no `.sync` engine can
/// exist in the first place.
const Synced = if (build_options.turso_sync) SyncedState else struct {};

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
    /// The clock the lease compares against, and the clock the sync transport is driven with.
    io: std.Io,
    /// The local database, for the tiers that are only local. A `.sync` engine leaves this empty — the
    /// SDK's own database owns the file, `synced` holds it, and `connection` below is one of *its*
    /// connections, so the SQL surface is the same one either way. An empty handle is a null `state`,
    /// which the binding's `deinit` treats as a no-op.
    database: turso.Database = .{ .state = null },
    /// Whether `connection` holds a live handle. Set as the last step of opening one, which is what
    /// lets `deinit` release a half-opened engine without touching uninitialized memory.
    connection_opened: bool = false,
    connection: turso.Connection,
    /// The remote half. Null on every other tier, and on every build without the SDK.
    synced: ?Synced = null,
    tier: data.Tier,
    /// This engine's own `data.Database` handle. A `Tx` carries a pointer to it, which is how
    /// `Tx.commit` reaches the vtable without the vtable having to carry the handle back.
    handle: data.Database = undefined,
    /// The transaction in flight, if a `Tx` is live. The contract allows one adapter-owned transaction
    /// at a time (nesting is a surface concern, expressed with savepoints); a second concurrent `begin`
    /// is a programming error, reported as `error.Operation`.
    tx: ?turso.Transaction = null,
    /// The `Tx` handle handed to the caller for that transaction. The adapter owns it: the contract says
    /// a `Tx` is not storable, which means the last moment it *can* be in use is the next `begin` or the
    /// engine closing — so those are where it is released. A transaction is the one object this layer
    /// creates on every write path, which is why letting the caller's allocator decide was not enough.
    tx_handle: ?*data.Tx = null,
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

        // `.sync` is the one tier whose remote half lives in a different build of the native library.
        // Without it the tier is refused rather than opened as a local file that would never
        // synchronize: a caller that asked for synchronization must not get a database that pretends
        // to. With it, the tier is a local file plus a remote, and `openSynced` below is the whole of
        // that difference.
        if (tier == .sync and !build_options.turso_sync) return error.Unavailable;

        const instance = allocator.create(Engine) catch return error.Internal;
        errdefer allocator.destroy(instance);

        // The engine takes an exclusive `fcntl` lock on every open that is not read-only, so with its
        // defaults a second *live* process cannot open the file at all — which is the one thing the
        // distributed tier promises. Its way out is the experimental multiprocess WAL coordination,
        // which opens the file with `NoLock` and coordinates through a shared WAL mapping instead. It
        // is enabled here and nowhere else: the single-node tiers want the exclusive lock, and the
        // `.tshm`/`.wal` coordination files it adds are only worth having when more than one process
        // is the point. The tier's docs name the feature, and `test-data-nodes` is the evidence.
        const features: turso.FeatureSet = switch (tier) {
            .memory, .file, .sync => .{},
            .distributed => .{ .multiprocess_wal = true },
        };

        instance.* = .{
            .allocator = allocator,
            .io = io,
            .connection = undefined,
            .tier = tier,
        };
        errdefer {
            instance.deinit();
            allocator.destroy(instance);
        }

        switch (tier) {
            .memory, .file, .distributed => instance.openLocal(path, features) catch |err| return err,
            .sync => |sync| {
                if (comptime build_options.turso_sync) {
                    instance.openSynced(sync) catch |err| return err;
                } else {
                    return error.Unavailable;
                }
            },
        }

        // The lease is part of every tier: it costs one statement on open and makes the distributed
        // story true wherever the database runs.
        _ = instance.connection.exec(lease_schema, &.{}, .{}) catch |err| return mapError(err);

        instance.handle = .{ .context = instance, .vtable = &vtable, .tier = tier };

        return instance.handle;
    }

    /// Open the local database: one file, or one process's memory, plus the connection this engine
    /// serves SQL through.
    fn openLocal(self: *Engine, path: []const u8, features: turso.FeatureSet) data.Error!void {
        self.database = turso.Database.open(self.allocator, .{
            .path = path,
            .features = features,
        }) catch |err| return mapError(err);
        errdefer self.database.deinit();

        self.connection = self.database.connect(.{}) catch |err| return mapError(err);
        self.connection_opened = true;
    }

    /// Open the `.sync` tier: the SDK's database for this path and remote, opened (or created) through
    /// the transport, then one connection from it for the SQL surface.
    fn openSynced(self: *Engine, sync: data.Tier.Sync) data.Error!void {
        var synced = SyncedState.open(self.allocator, self.io, sync) catch |err| return mapSyncError(err);
        errdefer synced.deinit();

        self.connection = synced.connect() catch |err| return mapSyncError(err);
        self.connection_opened = true;
        self.synced = synced;
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

        // Whatever the caller did with the previous handle, it is spent: it was lent for one scope.
        self.releaseTxHandle();

        // The distributed tier's rule, enforced where writes actually begin rather than trusted to the
        // caller: a node writes only while it holds the lease, and a follower that asks to write while
        // someone else holds it is told so. Reads never need the lease — one writer, many readers.
        if (mode == .read_write and self.tier == .distributed) {
            const node = self.tier.distributed.node;
            if (!try self.claimLease(self.tier.distributed.lease_name, node, self.nowMicros())) return error.Conflict;
        }

        self.tx = self.connection.begin(.immediate, .{}) catch |err| return mapError(err);
        errdefer {
            // A transaction with no handle to commit it is the engine's state leaking too, not just this
            // allocation.
            if (self.tx) |*live| live.rollback(null) catch {};
            self.tx = null;
        }

        const live = &(self.tx orelse return error.Internal);
        const tx = self.allocator.create(data.Tx) catch return error.Internal;
        errdefer self.allocator.destroy(tx);
        tx.* = .{
            // `exec` and `query` receive the `*Tx` and route through it; the context is the live
            // transaction handle, which is what they actually need.
            .context = @ptrCast(live),
            .database = &self.handle,
            .mode = mode,
        };
        self.tx_handle = tx;

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

        self.deinit();
        self.allocator.destroy(self);
    }

    /// Release everything this engine holds, in the order the owners require: the transaction, then the
    /// connection (the sync database refuses to close while one of its connections is live), then the
    /// database and the remote half. Safe on a half-opened engine, which is why `open` can use it as
    /// its error path.
    fn deinit(self: *Engine) void {
        if (self.tx) |*handle| {
            handle.rollback(null) catch {};
            self.tx = null;
        }

        self.values.deinit(self.allocator);
        self.columns.deinit(self.allocator);

        self.releaseTxHandle();

        if (self.connection_opened) {
            self.connection.deinit();
            self.connection_opened = false;
        }

        self.database.deinit();

        // The remote half exists only in a build that has the SDK, so releasing it is behind the same
        // gate that created it. (`deinit` is reached from `close`, which every build analyzes.)
        if (comptime build_options.turso_sync) {
            if (self.synced) |*synced| {
                synced.deinit();
                self.synced = null;
            }
        }
    }

    /// Release the `Tx` the caller was handed, if it is still outstanding. Safe to call at any point
    /// the caller cannot still be using it: the start of the next transaction, and close.
    fn releaseTxHandle(self: *Engine) void {
        if (self.tx_handle) |tx| {
            self.allocator.destroy(tx);
            self.tx_handle = null;
        }
    }

    // --------------------------------------------------------- //
    // The sync half

    /// Pull remote changes into the local database and apply them.
    ///
    /// One operation, not a loop: the binding leaves scheduling, retry and conflict policy to the
    /// caller, and so does this. `changes_received` and `changes_applied` are both false when the
    /// remote had nothing new.
    pub fn pull(self: *Engine) data.Error!Pull {
        const synced = try self.syncHalf();

        return synced.pull();
    }

    /// Push this node's local changes to the remote.
    pub fn push(self: *Engine) data.Error!void {
        const synced = try self.syncHalf();

        return synced.push();
    }

    /// One full pass: push, then wait for remote changes and apply them if there are any. The two
    /// directions are two operations, not a distributed transaction, which is what the summary says.
    pub fn syncPass(self: *Engine) data.Error!Pass {
        const synced = try self.syncHalf();

        return synced.pass();
    }

    /// The sync engine's own numbers: how much it has pushed, pulled and written, and its revision.
    /// The caller owns the result and frees it with `Stats.deinit`.
    pub fn stats(self: *Engine) data.Error!Stats {
        const synced = try self.syncHalf();

        return synced.stats();
    }

    /// The remote half of this engine, or the reason there is none: `error.Unavailable` in a build
    /// without the SDK, `error.Operation` when the engine was opened at a tier that has no remote.
    fn syncHalf(self: *Engine) data.Error!*Synced {
        if (comptime !build_options.turso_sync) return error.Unavailable;

        return if (self.synced) |*synced| synced else error.Operation;
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

// --------------------------------------------------------- //
// The sync half's own state

/// What a pull did. Declared here rather than re-exported from the binding because this is part of a
/// surface that has to compile in a build with no binding at all.
pub const Pull = struct {
    changes_received: bool,
    changes_applied: bool,
};

/// What a full pass did: the two directions are two operations, and this says so.
pub const Pass = struct {
    push_completed: bool,
    pull: Pull,
};

/// The sync engine's numbers, copied out of the binding's own owner so a caller can keep them without
/// learning the SDK's lifetime rules. `revision` is this adapter's allocation; `deinit` frees it.
pub const Stats = struct {
    cdc_operations: i64,
    main_wal_size: i64,
    revert_wal_size: i64,
    last_pull_unix_time: i64,
    last_push_unix_time: i64,
    network_sent_bytes: i64,
    network_received_bytes: i64,
    revision: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Stats) void {
        self.allocator.free(self.revision);
        self.revision = &.{};
    }
};

/// What the transport needs that the tier does not carry: the SDK's database, the HTTP client its
/// transport borrows, the credentials, and whether plain HTTP is allowed for this remote.
///
/// Only ever reached in a build with the sync SDK, which is what `Synced` above stands in for.
const SyncedState = struct {
    allocator: std.mem.Allocator,
    database: sync_sdk.SyncDatabase,
    client: *std.http.Client,
    /// The transport the operations are driven with: std's HTTP client, the filesystem root the
    /// engine's own file requests resolve against, and whether plain HTTP is allowed for this remote.
    /// A field rather than a value built per call, because the driver takes a mutable pointer to it.
    transport: sync_sdk.StandardTransport,
    /// The `Authorization` header for the remote. The tier's `auth_token` is used verbatim as the
    /// header's value — `Bearer <token>` for services that want one — because this adapter has no way
    /// to know a remote's scheme and must not invent one.
    authorization: ?sync_sdk.TransportHeader = null,

    fn open(allocator: std.mem.Allocator, io: std.Io, tier: data.Tier.Sync) !SyncedState {
        // The engine hands its own file requests — the metadata, the changes log, the WAL — to the
        // transport as paths derived from the database's, and the transport resolves them under the
        // working directory and refuses absolute ones. The engine also opens the database itself
        // through the same relative path, so the two agree only when the tier's path is relative; an
        // absolute one is refused here, saying why, instead of failing later inside the transport.
        if (std.fs.path.isAbsolute(tier.path)) return error.UnsupportedPath;

        const client = try allocator.create(std.http.Client);
        errdefer allocator.destroy(client);
        client.* = .{ .allocator = allocator, .io = io };
        errdefer client.deinit();

        var state: SyncedState = .{
            .allocator = allocator,
            .database = undefined,
            .client = client,
            .transport = .{
                .allocator = allocator,
                .io = io,
                .client = client,
                // Plain HTTP only for a loopback remote, and deliberately: the sync servers this has
                // been run against have no authentication at all, so an http endpoint this adapter
                // would dial is by definition one on this machine.
                .root_dir = std.Io.Dir.cwd(),
                .allow_http = isLoopback(tier.remote),
            },
        };
        if (tier.auth_token) |token| state.authorization = .{ .name = "authorization", .value = token };

        // `bootstrap_if_empty` is deliberately left off. Setting it would make the engine download the
        // remote's state *while opening* a fresh local file, and the price is the tier's first promise:
        // the local file is usable whether or not the remote is, so opening must not need the network.
        // Off, the engine opens the local file and defers the remote's state to the first pull — which
        // is the caller's operation anyway, and reports the remote's absence as `unavailable` when it
        // is driven.
        state.database = try sync_sdk.SyncDatabase.new(allocator, .{ .path = tier.path }, .{
            .remote_url = tier.remote,
            .client_name = client_name,
        }, null);

        return state;
    }

    fn deinit(self: *SyncedState) void {
        self.database.deinit();
        self.client.deinit();
        self.allocator.destroy(self.client);
    }

    /// Open (or create) the synced database, then take the connection the SQL surface uses.
    ///
    /// Both are operations with I/O of their own: `create` is where the local file is prepared for
    /// synchronization and where a remote that is missing, empty or unreachable is found out about.
    fn connect(self: *SyncedState) !turso.Connection {
        var open_operation = try self.database.create(null);
        try sync_sdk.runVoid(self.allocator, &self.database, &open_operation, &self.transport, self.options());

        var connect_operation = try self.database.connect(null);
        return sync_sdk.runConnection(self.allocator, &self.database, &connect_operation, &self.transport, self.options());
    }

    fn pull(self: *SyncedState) data.Error!Pull {
        const summary = sync_sdk.pull(self.allocator, &self.database, &self.transport, self.options()) catch |err| return mapSyncError(err);

        return .{
            .changes_received = summary.changes_received,
            .changes_applied = summary.changes_applied,
        };
    }

    fn push(self: *SyncedState) data.Error!void {
        var operation = self.database.push(null) catch |err| return mapSyncError(err);
        sync_sdk.runVoid(self.allocator, &self.database, &operation, &self.transport, self.options()) catch |err| return mapSyncError(err);
    }

    fn pass(self: *SyncedState) data.Error!Pass {
        const summary = sync_sdk.sync(self.allocator, &self.database, &self.transport, self.options()) catch |err| return mapSyncError(err);

        return .{
            .push_completed = summary.push_completed,
            .pull = .{
                .changes_received = summary.pull.changes_received,
                .changes_applied = summary.pull.changes_applied,
            },
        };
    }

    fn stats(self: *SyncedState) data.Error!Stats {
        var operation = self.database.stats(null) catch |err| return mapSyncError(err);
        var reported = sync_sdk.run(sync_sdk.Stats, self.allocator, &self.database, &operation, &self.transport, self.options()) catch |err| return mapSyncError(err);
        defer reported.deinit();

        return .{
            .cdc_operations = reported.cdc_operations,
            .main_wal_size = reported.main_wal_size,
            .revert_wal_size = reported.revert_wal_size,
            .last_pull_unix_time = reported.last_pull_unix_time,
            .last_push_unix_time = reported.last_push_unix_time,
            .network_sent_bytes = reported.network_sent_bytes,
            .network_received_bytes = reported.network_received_bytes,
            .revision = self.allocator.dupe(u8, reported.revision) catch return error.Internal,
            .allocator = self.allocator,
        };
    }

    fn options(self: *SyncedState) sync_sdk.TransportOptions {
        return .{ .authorization = self.authorization };
    }
};

/// The prefix the sync engine puts on its client id. It only has to be a stable, non-empty string; the
/// engine adds the uniqueness.
const client_name = "zurtr";

/// Whether `remote` names a loopback endpoint, which is the only place plain HTTP is allowed. The
/// binding's own example makes the same call, and it is the difference between a local sync server and
/// an unauthenticated one on the open internet.
fn isLoopback(remote: []const u8) bool {
    const uri = std.Uri.parse(remote) catch return false;
    const host = if (uri.host) |host| switch (host) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    } else return false;

    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;

    const address = std.Io.net.IpAddress.parse(std.mem.trim(u8, host, "[]"), 0) catch return false;
    const v6_loopback: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    return switch (address) {
        .ip4 => |ip| ip.bytes[0] == 127,
        .ip6 => |ip| std.mem.eql(u8, &ip.bytes, &v6_loopback),
    };
}

/// Map the sync path's errors into the framework taxonomy.
///
/// The sync path's failures are mostly one thing to a caller: the remote did not answer, or the
/// transport could not drive it — the engine's own retryable failure, a refused connection, a poisoned
/// I/O item, a token the server rejected. That is `unavailable`, and it is retryable by policy, which
/// is exactly the caller's decision to make. What is *not* unavailable is a coordination failure
/// (`conflict`), a deadline (`timeout`), or something this adapter got wrong, which is a bug here and
/// stays `internal`.
fn mapSyncError(err: anyerror) data.Error {
    return switch (err) {
        error.Busy, error.BusySnapshot, error.Constraint => error.Conflict,
        error.Interrupt => error.Timeout,
        error.Misuse,
        error.InvalidState,
        error.TypeMismatch,
        error.Unsupported,
        error.VersionMismatch,
        error.AlreadySetup,
        error.UnexpectedStatus,
        error.InvalidFilePath,
        error.InvalidHttpHeader,
        error.InvalidHttpStatus,
        error.MissingHttpStatus,
        error.UnsupportedHttpMethod,
        error.UnsupportedHttpBody,
        error.UnsupportedUriScheme,
        => error.Internal,
        // The tier's own path, which only `.sync` constrains: see `SyncedState.open`.
        error.UnsupportedPath => error.Operation,
        else => error.Unavailable,
    };
}

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
