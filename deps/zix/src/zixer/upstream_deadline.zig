//! zixer upstream leg: bound the wait for an upstream to send something

const std = @import("std");
const zix = @import("zix");

/// Budget for one upstream read when the site cfg names none. A backend that
/// has said nothing for this long is stalled, not slow.
pub const DEFAULT_MS: u32 = 30_000;

/// One bounded upstream read: which socket to watch, and for how long.
///
/// Note:
/// - A budget of 0 turns the bound off and every read blocks exactly as it
///   did before any deadline existed. That is the escape hatch for a site
///   whose backend legitimately thinks for minutes.
/// - The gate covers the wait for a response head and the reads of a
///   Content-Length body. A chunked or close-delimited body has no byte
///   count to end on, and a server-sent-event stream is silent between
///   events by design, so those stay unbounded.
pub const Gate = struct {
    stream: std.Io.net.Stream,
    budget_ms: u32,

    /// Whether the next read can be served without waiting past the budget.
    ///
    /// Note:
    /// - The buffered check has to come first. A reader that already holds
    ///   bytes leaves the socket quiet, so polling the descriptor would wait
    ///   out the whole budget on a response that already arrived.
    /// - A poll that fails counts as not ready: the caller answers its own
    ///   timeout rather than parking on a socket it could not ask about.
    ///
    /// Param:
    /// up_r - *std.Io.Reader (the reader that will do the read)
    ///
    /// Return:
    /// - true when the read may proceed
    /// - false when the budget elapsed with the upstream still silent
    pub fn ready(gate: Gate, up_r: *std.Io.Reader) bool {
        if (gate.budget_ms == 0) return true;
        if (up_r.bufferedLen() > 0) return true;

        return zix.utils.socket_poll.readableWithin(gate.stream.socket.handle, gate.budget_ms);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: upstream deadline, a silent upstream is not ready inside the budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18943);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    var read_buf: [256]u8 = undefined;
    var reader = client.reader(io, &read_buf);

    // The peer accepted and then said nothing, which is the stall the gate
    // exists for.
    const gate = Gate{ .stream = client, .budget_ms = 50 };
    try std.testing.expect(!gate.ready(&reader.interface));

    // A zero budget is the bound turned off, so it always reports ready.
    const unbounded = Gate{ .stream = client, .budget_ms = 0 };
    try std.testing.expect(unbounded.ready(&reader.interface));
}

test "zix zixer: upstream deadline, bytes on the socket report ready" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18944);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = accepted.writer(io, &write_buf);
    try writer.interface.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.interface.flush();

    var read_buf: [256]u8 = undefined;
    var reader = client.reader(io, &read_buf);

    const gate = Gate{ .stream = client, .budget_ms = 3000 };
    try std.testing.expect(gate.ready(&reader.interface));
}

test "zix zixer: upstream deadline, bytes already in the reader report ready on a quiet socket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18945);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = accepted.writer(io, &write_buf);
    try writer.interface.writeAll("head-and-body-in-one-write");
    try writer.interface.flush();

    var read_buf: [256]u8 = undefined;
    var reader = client.reader(io, &read_buf);

    // Pull everything into the reader, so the socket itself goes quiet while
    // the answer is already in hand. A gate that only polled would time out
    // here on a healthy exchange.
    var head_buf: [4]u8 = undefined;
    try reader.interface.readSliceAll(&head_buf);
    try std.testing.expect(reader.interface.bufferedLen() > 0);

    const gate = Gate{ .stream = client, .budget_ms = 50 };
    try std.testing.expect(gate.ready(&reader.interface));
}
