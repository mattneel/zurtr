//! zixer client leg: take a slot for one accepted connection, or refuse it

const std = @import("std");
const zix = @import("zix");

const deadline_table = @import("deadline_table.zig");

const monotonic_clock = zix.utils.monotonic_clock;

/// What a refused connection is told, before it has sent a single byte.
const REFUSAL_BODY = "too many connections\n";

/// The whole refusal, head and body. Built once at compile time so the length
/// header can never drift from what follows it.
///
/// Note:
/// - This is the http1 wire form, which is what the cleartext and the TLS h1
///   edges write. An engine with its own framing answers a full table in that
///   framing instead, the decision it carries is the same one.
/// - Connection: close because there is nothing to keep: the connection is
///   being refused, not served.
pub const REFUSAL: []const u8 = std.fmt.comptimePrint(
    "HTTP/1.1 503 Service Unavailable\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Proxy-Status: zixer; error=\"connection_limit_reached\"\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}",
    .{ REFUSAL_BODY.len, REFUSAL_BODY },
);

/// The stamp a budget runs out at, counted from now.
///
/// Note:
/// - A budget of 0 is nothing to time, so it names the held deadline rather
///   than a stamp already in the past. Arming a connection at now + 0 would
///   have the next sweep cut it before it ever sent a request.
/// - Saturating, so a budget near the end of the clock's range lands on the
///   held deadline instead of wrapping into the past.
///
/// Param:
/// now_ms - i64 (a monotonic_clock.nowMs stamp)
/// budget_ms - u32 (how long the connection has from now)
///
/// Return:
/// - i64 absolute stamp for the table
pub fn deadlineFrom(now_ms: i64, budget_ms: u32) i64 {
    if (budget_ms == 0) return deadline_table.NEVER_MS;

    return std.math.add(i64, now_ms, budget_ms) catch deadline_table.NEVER_MS;
}

/// Take a slot for a connection the site has just accepted.
///
/// Note:
/// - A site with no bound answers UNBOUND, so an edge calls this without
///   asking whether its site configured one.
/// - FULL is the flood case, and the caller owes the connection the refusal
///   above. Serving it unbounded instead is the wrong answer in exactly the
///   moment the bound exists for.
///
/// Param:
/// table - *deadline_table.Table (the site's table)
/// io - std.Io
/// handle - std.posix.socket_t (the accepted socket, from stream.socket.handle)
/// budget_ms - u32 (the site's resolved client bound)
///
/// Return:
/// - UNBOUND when the site runs no bound, and nothing is owed
/// - TAKEN with the ticket the connection owes back at close
/// - FULL when every slot is in use
pub fn admit(table: *deadline_table.Table, io: std.Io, handle: std.posix.socket_t, budget_ms: u32) deadline_table.Claim {
    if (!table.armed()) return .UNBOUND;

    return table.claim(handle, deadlineFrom(monotonic_clock.nowMs(io), budget_ms));
}

/// Answer a connection there was no slot for, then leave it to the caller to
/// close.
///
/// Note:
/// - Written off the stack, and every failure is swallowed: the site is at
///   its ceiling, so a refusal that cannot be delivered is not worth a second
///   attempt or an allocation.
///
/// Param:
/// io - std.Io
/// stream - std.Io.net.Stream (the accepted connection)
///
/// Return:
/// - void
pub fn refuse(io: std.Io, stream: std.Io.net.Stream) void {
    var refusal_buf: [REFUSAL.len]u8 = undefined;
    var refusal_writer = stream.writer(io, &refusal_buf);

    refusal_writer.interface.writeAll(REFUSAL) catch return;
    refusal_writer.interface.flush() catch {};
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A stand-in socket for the tests that never touch the wire. The table stores
/// the handle and hands it back, so no real socket has to exist.
fn testHandle(seed: usize) std.posix.socket_t {
    if (comptime @typeInfo(std.posix.socket_t) == .pointer) return @ptrFromInt(seed + 1);

    return @intCast(seed + 1);
}

test "zix zixer: client admit, the refusal says what it is and how long it is" {
    try testing.expect(std.mem.startsWith(u8, REFUSAL, "HTTP/1.1 503 Service Unavailable\r\n"));
    try testing.expect(std.mem.endsWith(u8, REFUSAL, "\r\n\r\n" ++ REFUSAL_BODY));
    try testing.expect(std.mem.indexOf(u8, REFUSAL, "Connection: close\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, REFUSAL, "Proxy-Status: zixer; error=\"connection_limit_reached\"\r\n") != null);

    // The length header has to match the body a client will actually read, or
    // the client waits for bytes that never come.
    var length_buf: [32]u8 = undefined;
    const length_line = try std.fmt.bufPrint(&length_buf, "Content-Length: {d}\r\n", .{REFUSAL_BODY.len});
    try testing.expect(std.mem.indexOf(u8, REFUSAL, length_line) != null);
}

test "zix zixer: client admit, a budget counts from now and zero holds" {
    try testing.expectEqual(@as(i64, 1_500), deadlineFrom(1_000, 500));

    // Nothing to time is not the same as already out of time.
    try testing.expectEqual(deadline_table.NEVER_MS, deadlineFrom(1_000, 0));

    // A budget that would run off the end of the clock holds instead of
    // wrapping into a stamp every sweep treats as past due.
    try testing.expectEqual(deadline_table.NEVER_MS, deadlineFrom(std.math.maxInt(i64) - 1, 1_000));
}

test "zix zixer: client admit, a site with no bound owes nothing" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = deadline_table.Table.off;

    const claim = admit(&table, io, testHandle(1), 30_000);
    try testing.expectEqual(deadline_table.Claim.UNBOUND, claim);
}

test "zix zixer: client admit, a bounded site hands out slots until it runs out" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 2);
    defer table.deinit(testing.allocator);

    const first = admit(&table, io, testHandle(1), 30_000);
    const second = admit(&table, io, testHandle(2), 30_000);
    try testing.expect(first == .TAKEN);
    try testing.expect(second == .TAKEN);

    // The flood case: the third connection is refused rather than served
    // with no bound on it at all.
    try testing.expectEqual(deadline_table.Claim.FULL, admit(&table, io, testHandle(3), 30_000));

    // The budget is a stamp ahead of now, so a sweep at this instant leaves
    // both of them alone.
    var cursor: u32 = 0;
    try testing.expect(table.borrowExpired(monotonic_clock.nowMs(io), &cursor) == null);

    table.release(first.TAKEN);
    try testing.expect(admit(&table, io, testHandle(3), 30_000) == .TAKEN);
}

test "zix zixer: client admit, a refused connection is told so on the wire" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18994);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);

    refuse(io, accepted);
    accepted.close(io);

    var reply_buf: [512]u8 = undefined;
    var reader = client.reader(io, &reply_buf);

    var reply: [REFUSAL.len]u8 = undefined;
    try reader.interface.readSliceAll(&reply);
    try testing.expectEqualStrings(REFUSAL, &reply);
}
