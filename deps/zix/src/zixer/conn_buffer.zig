//! zixer connection buffers: the stream buffer block one edge connection holds

const std = @import("std");

/// Smallest buffer a site may configure. A request head that does not fit
/// in one read costs an extra syscall per request, and below a kilobyte
/// almost no head fits.
pub const MIN_BYTES: usize = 1024;

/// Largest buffer a site may configure. The block is allocated per
/// connection, so this is what bounds one connection's buffer cost.
pub const MAX_BYTES: usize = 256 * 1024;

/// What a leg gets when neither main.cfg nor the site file names a size.
pub const DEFAULT_BYTES: usize = 8 * 1024;

/// Which legs a connection needs buffers for.
///
/// Note:
/// - A static-only site answers from public_dir and never opens an
///   upstream connection, so it asks for the client pair alone.
/// - An edge that was handed a reader and writer already (the TLS session,
///   the http2 fallback to the http1 loop) asks for the upstream pair
///   alone, and for neither when its site has no pool.
pub const Legs = struct {
    client: bool,
    upstream: bool,

    /// How many buffers a connection of this shape holds.
    pub fn count(legs: Legs) usize {
        return (if (legs.client) @as(usize, 2) else 0) + (if (legs.upstream) @as(usize, 2) else 0);
    }
};

/// Whether a configured size is one the edges can serve.
pub fn inRange(bytes: usize) bool {
    return bytes >= MIN_BYTES and bytes <= MAX_BYTES;
}

/// The size one leg gets, from the site override and the daemon default.
///
/// Note:
/// - Both inputs already passed validation, so neither can be out of
///   range. Clamping anyway keeps a caller that skipped validation (a
///   test rig, a future caller) inside what the block can hold.
///
/// Param:
/// site - ?usize (the site file value, null when the file does not set one)
/// daemon_default - usize (the main.cfg value)
///
/// Return:
/// - usize between MIN_BYTES and MAX_BYTES
pub fn resolve(site: ?usize, daemon_default: usize) usize {
    const wanted = site orelse daemon_default;

    return std.math.clamp(wanted, MIN_BYTES, MAX_BYTES);
}

/// The buffers one edge connection reads and writes through.
///
/// Note:
/// - One allocation per connection, sliced into the legs. Buffers this
///   size cannot be stack arrays: a stack array is sized at compile time,
///   so a site could not lower it, and an oversized one costs its whole
///   length in resident memory whether or not the bytes are used.
/// - A leg the set was not asked for is an empty slice, not a null. The
///   edge only reaches a leg on the path that asked for it, so an empty
///   one surfaces as a failed read rather than a branch in the hot loop.
pub const Set = struct {
    block: []u8,
    client_read: []u8,
    client_write: []u8,
    upstream_read: []u8,
    upstream_write: []u8,

    /// A set that owns nothing, for a leg that has not opened yet.
    /// deinit on it is a free of an empty slice, which is legal.
    pub const empty: Set = .{
        .block = &.{},
        .client_read = &.{},
        .client_write = &.{},
        .upstream_read = &.{},
        .upstream_write = &.{},
    };

    /// Allocate one connection's buffers.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (the worker's, outlives the connection)
    /// bytes - usize (one leg's size, already resolved)
    /// legs - Legs (which legs the site's shape needs)
    ///
    /// Return:
    /// - Set with every requested leg pointing into one block
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, bytes: usize, legs: Legs) !Set {
        const leg_bytes = std.math.clamp(bytes, MIN_BYTES, MAX_BYTES);
        const block = try allocator.alloc(u8, leg_bytes * legs.count());

        const upstream_at: usize = if (legs.client) leg_bytes * 2 else 0;

        return .{
            .block = block,
            .client_read = if (legs.client) block[0..leg_bytes] else block[0..0],
            .client_write = if (legs.client) block[leg_bytes..][0..leg_bytes] else block[0..0],
            .upstream_read = if (legs.upstream) block[upstream_at..][0..leg_bytes] else block[0..0],
            .upstream_write = if (legs.upstream) block[upstream_at + leg_bytes ..][0..leg_bytes] else block[0..0],
        };
    }

    pub fn deinit(set: Set, allocator: std.mem.Allocator) void {
        allocator.free(set.block);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: conn buffer, a site value overrides the daemon default" {
    try std.testing.expectEqual(@as(usize, 4096), resolve(4096, 8192));
    try std.testing.expectEqual(@as(usize, 8192), resolve(null, 8192));
}

test "zix zixer: conn buffer, resolve clamps an unvalidated value into range" {
    try std.testing.expectEqual(MIN_BYTES, resolve(1, DEFAULT_BYTES));
    try std.testing.expectEqual(MAX_BYTES, resolve(MAX_BYTES * 4, DEFAULT_BYTES));
    try std.testing.expectEqual(MIN_BYTES, resolve(null, 0));
}

test "zix zixer: conn buffer, in range accepts the ends and rejects past them" {
    try std.testing.expect(inRange(MIN_BYTES));
    try std.testing.expect(inRange(MAX_BYTES));
    try std.testing.expect(inRange(DEFAULT_BYTES));
    try std.testing.expect(!inRange(MIN_BYTES - 1));
    try std.testing.expect(!inRange(MAX_BYTES + 1));
    try std.testing.expect(!inRange(0));
}

test "zix zixer: conn buffer, a client set holds two legs and no upstream pair" {
    const set = try Set.init(std.testing.allocator, 2048, .{ .client = true, .upstream = false });
    defer set.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4096), set.block.len);
    try std.testing.expectEqual(@as(usize, 2048), set.client_read.len);
    try std.testing.expectEqual(@as(usize, 2048), set.client_write.len);
    try std.testing.expectEqual(@as(usize, 0), set.upstream_read.len);
    try std.testing.expectEqual(@as(usize, 0), set.upstream_write.len);
}

test "zix zixer: conn buffer, an upstream only set puts its pair at the front" {
    const set = try Set.init(std.testing.allocator, 2048, .{ .client = false, .upstream = true });
    defer set.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4096), set.block.len);
    try std.testing.expectEqual(@as(usize, 0), set.client_read.len);
    try std.testing.expectEqual(@as(usize, 2048), set.upstream_read.len);
    try std.testing.expectEqual(set.block.ptr, set.upstream_read.ptr);
}

test "zix zixer: conn buffer, a set with neither leg allocates nothing" {
    const set = try Set.init(std.testing.allocator, 2048, .{ .client = false, .upstream = false });
    defer set.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), set.block.len);
    try std.testing.expectEqual(@as(usize, 0), set.client_read.len);
    try std.testing.expectEqual(@as(usize, 0), set.upstream_write.len);
}

test "zix zixer: conn buffer, a full set holds four legs that do not overlap" {
    const set = try Set.init(std.testing.allocator, 1024, .{ .client = true, .upstream = true });
    defer set.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4096), set.block.len);

    // Every leg writes its own marker, then all four are read back: an
    // overlap would show up as a marker the other leg overwrote.
    @memset(set.client_read, 'a');
    @memset(set.client_write, 'b');
    @memset(set.upstream_read, 'c');
    @memset(set.upstream_write, 'd');

    try std.testing.expectEqual(@as(u8, 'a'), set.client_read[1023]);
    try std.testing.expectEqual(@as(u8, 'b'), set.client_write[1023]);
    try std.testing.expectEqual(@as(u8, 'c'), set.upstream_read[1023]);
    try std.testing.expectEqual(@as(u8, 'd'), set.upstream_write[1023]);
}

test "zix zixer: conn buffer, an out of range size is clamped before allocating" {
    const small = try Set.init(std.testing.allocator, 1, .{ .client = true, .upstream = false });
    defer small.deinit(std.testing.allocator);

    try std.testing.expectEqual(MIN_BYTES, small.client_read.len);
}

test "zix zixer: conn buffer, leg count follows what was asked for" {
    try std.testing.expectEqual(@as(usize, 0), (Legs{ .client = false, .upstream = false }).count());
    try std.testing.expectEqual(@as(usize, 2), (Legs{ .client = true, .upstream = false }).count());
    try std.testing.expectEqual(@as(usize, 2), (Legs{ .client = false, .upstream = true }).count());
    try std.testing.expectEqual(@as(usize, 4), (Legs{ .client = true, .upstream = true }).count());
}
