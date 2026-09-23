//! zixer client leg: one pass over the deadline table, and how hard it cuts

const std = @import("std");
const zix = @import("zix");

const deadline_table = @import("deadline_table.zig");

const socket_cut = zix.utils.socket_cut;

/// Gap between two passes. Short enough that a bound is enforced close to the stamp it names, and a
/// pass that finds nothing past due costs one atomic read per slot.
pub const TICK_MS: i64 = 100;

/// What one pass did. The counts are for status output, nothing branches on them.
pub const Swept = struct {
    /// Connections whose read side was cut, the first act on each.
    cut: usize = 0,
    /// Connections whose send side was taken away too, after a cut that did not free them.
    dropped: usize = 0,
};

/// Cut every connection the table reports past its deadline.
///
/// Note:
/// - The first pass over a connection cuts the read side alone, which wakes the handler and leaves
///   it able to write the status the client is owed. The next pass takes the send side away as
///   well, for the one shape a read-side cut never reaches: a client that stopped reading parks the
///   handler in write. One tick of grace is what buys the handler its chance to answer.
/// - Nothing here closes a descriptor or gives a slot back. The handler owns both, finds out
///   through its own failed read or write, and unwinds the way it does for any client that
///   vanished. That is what keeps timeout logic out of every dispatch loop.
/// - A connection still claimed several passes later keeps being cut, which costs one syscall a
///   tick and is what a wedged handler needs anyway.
///
/// Param:
/// table - *deadline_table.Table (the site's table)
/// now_ms - i64 (a monotonic_clock.nowMs stamp)
///
/// Return:
/// - Swept, both counts 0 when nothing was past due
pub fn sweepOnce(table: *deadline_table.Table, now_ms: i64) Swept {
    var swept = Swept{};
    var cursor: u32 = 0;

    while (table.borrowExpired(now_ms, &cursor)) |expired| {
        if (expired.cut_count <= 1) {
            socket_cut.shutdownRead(expired.handle);
            swept.cut += 1;
        } else {
            socket_cut.shutdownBoth(expired.handle);
            swept.dropped += 1;
        }

        table.endBorrow(expired.ticket);
    }

    return swept;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A connected loopback pair: what the site accepted, and the client holding the other end.
const TestPair = struct {
    server: std.Io.net.Server,
    client: std.Io.net.Stream,
    accepted: std.Io.net.Stream,

    fn open(io: std.Io, port: u16) !TestPair {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
        errdefer server.deinit(io);

        const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        errdefer client.close(io);
        const accepted = try server.accept(io);

        return .{ .server = server, .client = client, .accepted = accepted };
    }

    fn close(pair: *TestPair, io: std.Io) void {
        pair.accepted.close(io);
        pair.client.close(io);
        pair.server.deinit(io);
    }
};

test "zix zixer: deadline sweep, a pass with nothing past due touches nothing" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18989);
    defer pair.close(io);

    var table = try deadline_table.Table.init(testing.allocator, 4);
    defer table.deinit(testing.allocator);

    const ticket = table.claim(pair.accepted.socket.handle, 5_000).TAKEN;

    const swept = sweepOnce(&table, 1_000);
    try testing.expectEqual(@as(usize, 0), swept.cut);
    try testing.expectEqual(@as(usize, 0), swept.dropped);

    // The connection is untouched in both directions, so a live exchange inside its budget carries
    // on as if no table existed.
    var write_buf: [32]u8 = undefined;
    var writer = pair.accepted.writer(io, &write_buf);
    try writer.interface.writeAll("still-open");
    try writer.interface.flush();

    var read_buf: [32]u8 = undefined;
    var client_reader = pair.client.reader(io, &read_buf);
    var got: [10]u8 = undefined;
    try client_reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("still-open", &got);

    table.release(ticket);
}

test "zix zixer: deadline sweep, the first pass cuts the read side and leaves the answer a way out" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18990);
    defer pair.close(io);

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    const ticket = table.claim(pair.accepted.socket.handle, 1_000).TAKEN;

    const swept = sweepOnce(&table, 1_000);
    try testing.expectEqual(@as(usize, 1), swept.cut);
    try testing.expectEqual(@as(usize, 0), swept.dropped);

    // The handler's next read ends, which is how it learns the exchange is over. On Windows only
    // windows_io.readOnce reports a cancelled receive that way, so the check below stays off that
    // platform and the edges read through utils/socket_cut_reader instead.
    if (comptime @import("builtin").os.tag != .windows) {
        var read_buf: [1]u8 = undefined;
        var reader = pair.accepted.reader(io, &read_buf);
        try testing.expectError(error.EndOfStream, reader.interface.readSliceAll(&read_buf));
    }

    // The status the client is owed still fits through, which is the whole reason the first cut is
    // read-side only.
    var write_buf: [64]u8 = undefined;
    var writer = pair.accepted.writer(io, &write_buf);
    try writer.interface.writeAll("HTTP/1.1 408 Request Timeout\r\n\r\n");
    try writer.interface.flush();

    var reply_buf: [64]u8 = undefined;
    var client_reader = pair.client.reader(io, &reply_buf);
    var head: [15]u8 = undefined;
    try client_reader.interface.readSliceAll(&head);
    try testing.expectEqualStrings("HTTP/1.1 408 R", head[0..14]);

    // The slot came back to its owner, so the handler's own release still lands.
    table.release(ticket);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
}

test "zix zixer: deadline sweep, the next pass takes the send side too" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18991);
    defer pair.close(io);

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    const ticket = table.claim(pair.accepted.socket.handle, 1_000).TAKEN;

    const first = sweepOnce(&table, 2_000);
    try testing.expectEqual(@as(usize, 1), first.cut);
    try testing.expectEqual(@as(usize, 0), first.dropped);

    // Still claimed a tick later: the handler did not unwind, so the grace is over.
    const second = sweepOnce(&table, 2_100);
    try testing.expectEqual(@as(usize, 0), second.cut);
    try testing.expectEqual(@as(usize, 1), second.dropped);

    // Nothing can leave this socket now, which is what frees a handler parked in write.
    var write_buf: [32]u8 = undefined;
    var writer = pair.accepted.writer(io, &write_buf);
    writer.interface.writeAll("late") catch {
        table.release(ticket);

        return;
    };
    try testing.expectError(error.WriteFailed, writer.interface.flush());

    table.release(ticket);
}

test "zix zixer: deadline sweep, a held connection is never cut" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18992);
    defer pair.close(io);

    var table = try deadline_table.Table.init(testing.allocator, 2);
    defer table.deinit(testing.allocator);

    // A tunnel: claimed so nothing else takes the slot, with no deadline to act on.
    const ticket = table.claim(pair.accepted.socket.handle, deadline_table.NEVER_MS).TAKEN;

    var tick: i64 = 0;
    while (tick < 20) : (tick += 1) {
        const swept = sweepOnce(&table, tick * 60_000);
        try testing.expectEqual(@as(usize, 0), swept.cut);
        try testing.expectEqual(@as(usize, 0), swept.dropped);
    }

    // Still a live connection after twenty minutes of sweeps, which is the tunnel working.
    var write_buf: [32]u8 = undefined;
    var writer = pair.accepted.writer(io, &write_buf);
    try writer.interface.writeAll("tunnel-alive");
    try writer.interface.flush();

    var read_buf: [32]u8 = undefined;
    var client_reader = pair.client.reader(io, &read_buf);
    var got: [12]u8 = undefined;
    try client_reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("tunnel-alive", &got);

    table.release(ticket);
}

test "zix zixer: deadline sweep, a table that tracks nothing sweeps nothing" {
    var table = deadline_table.Table.off;

    const swept = sweepOnce(&table, std.math.maxInt(i64));
    try testing.expectEqual(@as(usize, 0), swept.cut);
    try testing.expectEqual(@as(usize, 0), swept.dropped);
}
