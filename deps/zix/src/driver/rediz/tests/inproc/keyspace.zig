//! In-memory keyspace behind the in-process server: numbered databases, typed
//! values, and per-key expiry.
//!
//! Note:
//! - One instance is shared by every connection handler thread, so every
//!   public method takes the spinlock itself. Nothing here hands out a pointer
//!   into the map: readers copy into a caller arena, which keeps a later
//!   rehash from invalidating a slice a handler is still writing out.
//! - Expiry is driven by the awake clock, so a suite that sets a TTL and reads
//!   it back sees a monotonic value rather than a wall clock that can step.

const std = @import("std");

/// Databases a client may SELECT, matching a stock server's default.
pub const DB_COUNT = 16;

pub const Error = error{
    RedizWrongType,
    RedizNotAnInteger,
    OutOfMemory,
};

/// One field of a hash value.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// The value types the server understands. A real server has more, these are
/// the ones the driver's own surface and its suites reach for.
pub const Value = union(enum) {
    string: []u8,
    list: std.ArrayList([]u8),
    hash: std.ArrayList(Field),

    /// Name as the TYPE command reports it.
    pub fn typeName(self: Value) []const u8 {
        return switch (self) {
            .string => "string",
            .list => "list",
            .hash => "hash",
        };
    }

    fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |bytes| allocator.free(bytes),
            .list => |*items| {
                for (items.items) |item| allocator.free(item);
                items.deinit(allocator);
            },
            .hash => |*fields| {
                for (fields.items) |field| {
                    allocator.free(field.name);
                    allocator.free(field.value);
                }
                fields.deinit(allocator);
            },
        }
    }
};

const Entry = struct {
    value: Value,
    /// Absent means the key never expires.
    expire_at_ns: ?i96,
};

/// Conditions and expiry carried by SET.
pub const SetOptions = struct {
    /// Only set when the key does not exist.
    nx: bool = false,
    /// Only set when the key already exists.
    xx: bool = false,
    /// Expiry in milliseconds, absent leaves the key persistent.
    expire_ms: ?u64 = null,
    /// Carry the existing expiry across the write.
    keep_ttl: bool = false,
};

const Database = std.StringHashMapUnmanaged(Entry);

pub const Keyspace = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    databases: [DB_COUNT]Database,
    lock: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .databases = @splat(.empty),
            .lock = .init(false),
        };
    }

    pub fn deinit(self: *Self) void {
        for (&self.databases) |*database| self.clearLocked(database);
        for (&self.databases) |*database| database.deinit(self.allocator);
    }

    // --------------------------------------------------------- //

    fn acquire(self: *Self) void {
        while (self.lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn release(self: *Self) void {
        self.lock.store(false, .release);
    }

    fn nowNs(self: *Self) i96 {
        return std.Io.Timestamp.now(self.io, .awake).nanoseconds;
    }

    /// Drop the key when its expiry has passed. Callers hold the lock.
    ///
    /// Return:
    /// - ?*Entry, the live entry, or null when missing or just expired
    fn liveEntry(self: *Self, database: *Database, key: []const u8) ?*Entry {
        const entry = database.getPtr(key) orelse return null;

        const deadline = entry.expire_at_ns orelse return entry;
        if (self.nowNs() < deadline) return entry;

        self.removeLocked(database, key);

        return null;
    }

    fn removeLocked(self: *Self, database: *Database, key: []const u8) void {
        const removed = database.fetchRemove(key) orelse return;

        var value = removed.value.value;
        value.deinit(self.allocator);
        self.allocator.free(removed.key);
    }

    fn clearLocked(self: *Self, database: *Database) void {
        var it = database.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.value.deinit(self.allocator);
            self.allocator.free(kv.key_ptr.*);
        }
        database.clearRetainingCapacity();
    }

    /// Install a value under key, replacing whatever was there. Callers hold
    /// the lock and hand over ownership of value.
    fn putLocked(self: *Self, database: *Database, key: []const u8, value: Value, expire_at_ns: ?i96) Error!void {
        if (database.getPtr(key)) |existing| {
            existing.value.deinit(self.allocator);
            existing.* = .{ .value = value, .expire_at_ns = expire_at_ns };

            return;
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        try database.put(self.allocator, owned_key, .{ .value = value, .expire_at_ns = expire_at_ns });
    }

    // --------------------------------------------------------- //

    /// SET with its NX / XX / expiry conditions.
    ///
    /// Return:
    /// - true when the write happened
    /// - false when an NX or XX condition rejected it
    pub fn set(self: *Self, db_index: usize, key: []const u8, value: []const u8, opts: SetOptions) Error!bool {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        const existing = self.liveEntry(database, key);
        if (opts.nx and existing != null) return false;
        if (opts.xx and existing == null) return false;

        const carried = if (opts.keep_ttl and existing != null) existing.?.expire_at_ns else null;
        const expire_at_ns = if (opts.expire_ms) |ms| self.nowNs() + @as(i96, ms) * std.time.ns_per_ms else carried;

        const owned = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned);

        try self.putLocked(database, key, .{ .string = owned }, expire_at_ns);

        return true;
    }

    /// GET, copied into arena so the caller may hold it past the next write.
    ///
    /// Return:
    /// - ?[]const u8, null when the key is missing or expired
    /// - error.RedizWrongType when the key holds a list or a hash
    pub fn get(self: *Self, db_index: usize, key: []const u8, arena: std.mem.Allocator) Error!?[]const u8 {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return null;
        if (entry.value != .string) return error.RedizWrongType;

        return try arena.dupe(u8, entry.value.string);
    }

    /// DEL, returning how many of the named keys existed.
    pub fn del(self: *Self, db_index: usize, keys: []const []const u8) u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        var removed: u64 = 0;
        for (keys) |key| {
            if (self.liveEntry(database, key) == null) continue;

            self.removeLocked(database, key);
            removed += 1;
        }

        return removed;
    }

    /// EXISTS, counting repeats the way a real server does.
    pub fn exists(self: *Self, db_index: usize, keys: []const []const u8) u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        var found: u64 = 0;
        for (keys) |key| {
            if (self.liveEntry(database, key) != null) found += 1;
        }

        return found;
    }

    /// INCRBY and its DECR / INCR wrappers.
    ///
    /// Return:
    /// - i64 value after the delta
    /// - error.RedizNotAnInteger when the stored string is not a number
    /// - error.RedizWrongType when the key holds a list or a hash
    pub fn incrBy(self: *Self, db_index: usize, key: []const u8, delta: i64) Error!i64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        const entry = self.liveEntry(database, key);
        if (entry) |live| {
            if (live.value != .string) return error.RedizWrongType;
        }

        const current: i64 = if (entry) |live|
            std.fmt.parseInt(i64, live.value.string, 10) catch return error.RedizNotAnInteger
        else
            0;
        const updated = current +% delta;

        var text_buf: [24]u8 = undefined;
        const text = std.fmt.bufPrint(&text_buf, "{d}", .{updated}) catch unreachable;

        const owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned);

        const carried = if (entry) |live| live.expire_at_ns else null;
        try self.putLocked(database, key, .{ .string = owned }, carried);

        return updated;
    }

    /// APPEND, returning the resulting length.
    pub fn append(self: *Self, db_index: usize, key: []const u8, suffix: []const u8) Error!u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        const entry = self.liveEntry(database, key);
        if (entry) |live| {
            if (live.value != .string) return error.RedizWrongType;
        }

        const current: []const u8 = if (entry) |live| live.value.string else "";
        const joined = try std.mem.concat(self.allocator, u8, &.{ current, suffix });
        errdefer self.allocator.free(joined);

        const carried = if (entry) |live| live.expire_at_ns else null;
        try self.putLocked(database, key, .{ .string = joined }, carried);

        return joined.len;
    }

    /// STRLEN, 0 for a missing key.
    pub fn strlen(self: *Self, db_index: usize, key: []const u8) Error!u64 {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return 0;
        if (entry.value != .string) return error.RedizWrongType;

        return entry.value.string.len;
    }

    /// TTL in milliseconds.
    ///
    /// Return:
    /// - -2 when the key does not exist
    /// - -1 when the key exists with no expiry
    /// - the remaining milliseconds otherwise
    pub fn ttlMs(self: *Self, db_index: usize, key: []const u8) i64 {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return -2;
        const deadline = entry.expire_at_ns orelse return -1;
        const remaining = @divTrunc(deadline - self.nowNs(), std.time.ns_per_ms);

        return @intCast(@max(0, remaining));
    }

    /// PEXPIRE and the seconds-based EXPIRE.
    ///
    /// Return:
    /// - true when the key existed and the expiry was set
    pub fn expireMs(self: *Self, db_index: usize, key: []const u8, ms: u64) bool {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return false;
        entry.expire_at_ns = self.nowNs() + @as(i96, ms) * std.time.ns_per_ms;

        return true;
    }

    /// PERSIST.
    ///
    /// Return:
    /// - true when an expiry was actually cleared
    pub fn persist(self: *Self, db_index: usize, key: []const u8) bool {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return false;
        if (entry.expire_at_ns == null) return false;

        entry.expire_at_ns = null;

        return true;
    }

    /// TYPE, `none` for a missing key.
    pub fn typeName(self: *Self, db_index: usize, key: []const u8) []const u8 {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return "none";

        return entry.value.typeName();
    }

    /// DBSIZE, counting only keys that have not expired.
    pub fn dbSize(self: *Self, db_index: usize) u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];

        var expired: std.ArrayList([]const u8) = .empty;
        defer expired.deinit(self.allocator);

        const now_ns = self.nowNs();
        var live: u64 = 0;
        var it = database.iterator();
        while (it.next()) |kv| {
            const deadline = kv.value_ptr.expire_at_ns orelse {
                live += 1;

                continue;
            };
            if (now_ns < deadline) {
                live += 1;

                continue;
            }

            expired.append(self.allocator, kv.key_ptr.*) catch continue;
        }

        for (expired.items) |key| self.removeLocked(database, key);

        return live;
    }

    /// FLUSHDB.
    pub fn flushDb(self: *Self, db_index: usize) void {
        self.acquire();
        defer self.release();

        self.clearLocked(&self.databases[db_index]);
    }

    /// RPUSH, creating the list when absent.
    ///
    /// Return:
    /// - u64 list length after the push
    /// - error.RedizWrongType when the key holds a string or a hash
    pub fn rpush(self: *Self, db_index: usize, key: []const u8, values: []const []const u8) Error!u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        if (self.liveEntry(database, key)) |entry| {
            if (entry.value != .list) return error.RedizWrongType;

            for (values) |value| try entry.value.list.append(self.allocator, try self.allocator.dupe(u8, value));

            return entry.value.list.items.len;
        }

        var items: std.ArrayList([]u8) = .empty;
        errdefer {
            for (items.items) |item| self.allocator.free(item);
            items.deinit(self.allocator);
        }
        for (values) |value| try items.append(self.allocator, try self.allocator.dupe(u8, value));

        const length = items.items.len;
        try self.putLocked(database, key, .{ .list = items }, null);

        return length;
    }

    /// HSET, creating the hash when absent.
    ///
    /// Return:
    /// - u64 count of fields that did not exist before
    /// - error.RedizWrongType when the key holds a string or a list
    pub fn hset(self: *Self, db_index: usize, key: []const u8, fields: []const Field) Error!u64 {
        self.acquire();
        defer self.release();

        const database = &self.databases[db_index];
        if (self.liveEntry(database, key) == null) {
            const empty: std.ArrayList(Field) = .empty;
            try self.putLocked(database, key, .{ .hash = empty }, null);
        }

        const entry = database.getPtr(key).?;
        if (entry.value != .hash) return error.RedizWrongType;

        var added: u64 = 0;
        for (fields) |field| {
            if (findField(entry.value.hash.items, field.name)) |slot| {
                const owned = try self.allocator.dupe(u8, field.value);
                self.allocator.free(slot.value);
                slot.value = owned;

                continue;
            }

            const owned_name = try self.allocator.dupe(u8, field.name);
            errdefer self.allocator.free(owned_name);
            const owned_value = try self.allocator.dupe(u8, field.value);
            errdefer self.allocator.free(owned_value);

            try entry.value.hash.append(self.allocator, .{ .name = owned_name, .value = owned_value });
            added += 1;
        }

        return added;
    }

    /// HGETALL, copied into arena in insertion order.
    ///
    /// Return:
    /// - []Field, empty when the key is missing
    /// - error.RedizWrongType when the key holds a string or a list
    pub fn hgetAll(self: *Self, db_index: usize, key: []const u8, arena: std.mem.Allocator) Error![]Field {
        self.acquire();
        defer self.release();

        const entry = self.liveEntry(&self.databases[db_index], key) orelse return &.{};
        if (entry.value != .hash) return error.RedizWrongType;

        const copies = try arena.alloc(Field, entry.value.hash.items.len);
        for (entry.value.hash.items, copies) |field, *copy| {
            copy.* = .{
                .name = try arena.dupe(u8, field.name),
                .value = try arena.dupe(u8, field.value),
            };
        }

        return copies;
    }
};

fn findField(fields: []Field, name: []const u8) ?*Field {
    for (fields) |*field| {
        if (std.mem.eql(u8, field.name, name)) return field;
    }

    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Every test drives a real Keyspace, so the harness is the same three lines.
const Harness = struct {
    threaded: std.Io.Threaded,
    keyspace: Keyspace,

    fn init(self: *Harness) void {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        self.keyspace = Keyspace.init(testing.allocator, self.threaded.io());
    }

    fn deinit(self: *Harness) void {
        self.keyspace.deinit();
        self.threaded.deinit();
    }
};

test "rediz inproc: keyspace set and get round trip a string" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(try harness.keyspace.set(0, "key", "value", .{}));
    try testing.expectEqualStrings("value", (try harness.keyspace.get(0, "key", arena.allocator())).?);
    try testing.expectEqual(@as(?[]const u8, null), try harness.keyspace.get(0, "missing", arena.allocator()));
}

test "rediz inproc: keyspace nx and xx gate the write" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(false, try harness.keyspace.set(0, "cond", "first", .{ .xx = true }));
    try testing.expectEqual(true, try harness.keyspace.set(0, "cond", "first", .{ .nx = true }));
    try testing.expectEqual(false, try harness.keyspace.set(0, "cond", "second", .{ .nx = true }));
    try testing.expectEqual(true, try harness.keyspace.set(0, "cond", "second", .{ .xx = true }));
    try testing.expectEqualStrings("second", (try harness.keyspace.get(0, "cond", arena.allocator())).?);
}

test "rediz inproc: keyspace databases are isolated" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    _ = try harness.keyspace.set(1, "iso", "db1", .{});

    try testing.expectEqual(@as(?[]const u8, null), try harness.keyspace.get(0, "iso", arena.allocator()));
    try testing.expectEqualStrings("db1", (try harness.keyspace.get(1, "iso", arena.allocator())).?);
}

test "rediz inproc: keyspace ttl reports missing, persistent and expiring keys" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqual(@as(i64, -2), harness.keyspace.ttlMs(0, "absent"));

    _ = try harness.keyspace.set(0, "plain", "v", .{});
    try testing.expectEqual(@as(i64, -1), harness.keyspace.ttlMs(0, "plain"));

    _ = try harness.keyspace.set(0, "timed", "v", .{ .expire_ms = 30_000 });
    const remaining = harness.keyspace.ttlMs(0, "timed");
    try testing.expect(remaining > 0 and remaining <= 30_000);

    try testing.expectEqual(true, harness.keyspace.persist(0, "timed"));
    try testing.expectEqual(@as(i64, -1), harness.keyspace.ttlMs(0, "timed"));
    try testing.expectEqual(false, harness.keyspace.persist(0, "timed"));
}

test "rediz inproc: keyspace drops a key whose expiry has passed" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    _ = try harness.keyspace.set(0, "brief", "v", .{ .expire_ms = 1 });
    try testing.expectEqual(@as(u64, 1), harness.keyspace.dbSize(0));

    harness.threaded.io().sleep(.fromMilliseconds(15), .awake) catch {};

    try testing.expectEqual(@as(?[]const u8, null), try harness.keyspace.get(0, "brief", arena.allocator()));
    try testing.expectEqual(@as(u64, 0), harness.keyspace.dbSize(0));
    try testing.expectEqual(@as(i64, -2), harness.keyspace.ttlMs(0, "brief"));
}

test "rediz inproc: keyspace set keeps ttl only when asked" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.keyspace.set(0, "k", "one", .{ .expire_ms = 30_000 });
    _ = try harness.keyspace.set(0, "k", "two", .{ .keep_ttl = true });
    try testing.expect(harness.keyspace.ttlMs(0, "k") > 0);

    _ = try harness.keyspace.set(0, "k", "three", .{});
    try testing.expectEqual(@as(i64, -1), harness.keyspace.ttlMs(0, "k"));
}

test "rediz inproc: keyspace counters start at zero and carry the ttl" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    try testing.expectEqual(@as(i64, 1), try harness.keyspace.incrBy(0, "counter", 1));
    try testing.expectEqual(@as(i64, 11), try harness.keyspace.incrBy(0, "counter", 10));
    try testing.expectEqual(@as(i64, 10), try harness.keyspace.incrBy(0, "counter", -1));

    _ = try harness.keyspace.set(0, "timed", "5", .{ .expire_ms = 30_000 });
    _ = try harness.keyspace.incrBy(0, "timed", 1);
    try testing.expect(harness.keyspace.ttlMs(0, "timed") > 0);
}

test "rediz inproc: keyspace incr on a non-numeric string is not an integer" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.keyspace.set(0, "word", "abc", .{});
    try testing.expectError(error.RedizNotAnInteger, harness.keyspace.incrBy(0, "word", 1));
}

test "rediz inproc: keyspace rejects a string operation on a list" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(@as(u64, 1), try harness.keyspace.rpush(0, "list", &.{"item"}));
    try testing.expectEqualStrings("list", harness.keyspace.typeName(0, "list"));

    try testing.expectError(error.RedizWrongType, harness.keyspace.incrBy(0, "list", 1));
    try testing.expectError(error.RedizWrongType, harness.keyspace.get(0, "list", arena.allocator()));
    try testing.expectError(error.RedizWrongType, harness.keyspace.strlen(0, "list"));
}

test "rediz inproc: keyspace append builds a string in place" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(@as(u64, 3), try harness.keyspace.append(0, "str", "abc"));
    try testing.expectEqual(@as(u64, 6), try harness.keyspace.append(0, "str", "def"));
    try testing.expectEqual(@as(u64, 6), try harness.keyspace.strlen(0, "str"));
    try testing.expectEqualStrings("abcdef", (try harness.keyspace.get(0, "str", arena.allocator())).?);
}

test "rediz inproc: keyspace del and exists count only live keys" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.keyspace.set(0, "a", "1", .{});
    _ = try harness.keyspace.set(0, "b", "2", .{});

    try testing.expectEqual(@as(u64, 2), harness.keyspace.exists(0, &.{ "a", "b", "missing" }));
    try testing.expectEqual(@as(u64, 2), harness.keyspace.del(0, &.{ "a", "b", "missing" }));
    try testing.expectEqual(@as(u64, 0), harness.keyspace.exists(0, &.{ "a", "b" }));
}

test "rediz inproc: keyspace dbsize and flushdb track the selected database" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    _ = try harness.keyspace.set(2, "a", "1", .{});
    _ = try harness.keyspace.set(2, "b", "2", .{});
    _ = try harness.keyspace.set(3, "c", "3", .{});

    try testing.expectEqual(@as(u64, 2), harness.keyspace.dbSize(2));
    try testing.expectEqual(@as(u64, 1), harness.keyspace.dbSize(3));

    harness.keyspace.flushDb(2);

    try testing.expectEqual(@as(u64, 0), harness.keyspace.dbSize(2));
    try testing.expectEqual(@as(u64, 1), harness.keyspace.dbSize(3));
}

test "rediz inproc: keyspace hset overwrites a field without double counting" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(@as(u64, 2), try harness.keyspace.hset(0, "hash", &.{
        .{ .name = "field1", .value = "a" },
        .{ .name = "field2", .value = "b" },
    }));
    try testing.expectEqual(@as(u64, 0), try harness.keyspace.hset(0, "hash", &.{
        .{ .name = "field1", .value = "replaced" },
    }));

    const fields = try harness.keyspace.hgetAll(0, "hash", arena.allocator());
    try testing.expectEqual(@as(usize, 2), fields.len);
    try testing.expectEqualStrings("field1", fields[0].name);
    try testing.expectEqualStrings("replaced", fields[0].value);
    try testing.expectEqualStrings("field2", fields[1].name);
}

test "rediz inproc: keyspace serves concurrent writers without losing counts" {
    var harness: Harness = undefined;
    harness.init();
    defer harness.deinit();

    const Worker = struct {
        fn run(keyspace: *Keyspace) void {
            for (0..200) |_| _ = keyspace.incrBy(0, "shared", 1) catch return;
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{&harness.keyspace});
    for (&threads) |thread| thread.join();

    try testing.expectEqual(@as(i64, 801), try harness.keyspace.incrBy(0, "shared", 1));
}
