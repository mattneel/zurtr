//! Byte movement for one accepted connection, cleartext or TLS.
//!
//! Note:
//! - Every PostgreSQL message is length prefixed, so the framing above only
//!   ever needs `readExact`. There is no line reading here, unlike a
//!   text-protocol server.
//! - TLS arrives as an upgrade rather than from the first byte: the client
//!   sends an SSLRequest in the clear, the backend answers one byte, and only
//!   then does the handshake run. `upgrade` performs that second half.
//! - Holds its own reader and writer buffers, which point back into the
//!   struct, so it must not be moved after open. Handlers keep it on the
//!   stack and pass a pointer.

const std = @import("std");

const certificate = @import("certificate.zig");
const tls_server = @import("tls_server.zig");

const READ_BUF_SIZE = 8 * 1024;
const WRITE_BUF_SIZE = 8 * 1024;

pub const Error = error{
    PostgrezConnectionClosed,
    WriteFailed,
};

pub const Transport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    read_buf: [READ_BUF_SIZE]u8 = undefined,
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    /// Absent until an SSLRequest has been accepted and the handshake run.
    tls: ?tls_server.Session = null,

    const Self = @This();

    /// Take over an accepted stream in cleartext.
    pub fn open(self: *Self, io: std.Io, stream: std.Io.net.Stream) void {
        self.io = io;
        self.stream = stream;
        self.reader = stream.reader(io, &self.read_buf);
        self.writer = stream.writer(io, &self.write_buf);
        self.tls = null;
    }

    /// Run the server side of the TLS handshake, after the one-byte answer to
    /// the SSLRequest has already been sent in the clear.
    ///
    /// Return:
    /// - void once the client Finished has been verified
    /// - the handshake errors from tls_server, all fatal for this connection
    pub fn upgrade(self: *Self, cert: *const certificate.SelfSigned) !void {
        self.tls = try tls_server.handshake(self.io, &self.reader.interface, &self.writer.interface, cert);
    }

    pub fn isEncrypted(self: *const Self) bool {
        return self.tls != null;
    }

    /// Fill buf completely.
    pub fn readExact(self: *Self, buf: []u8) Error!void {
        if (self.tls) |*session| {
            session.readAll(&self.reader.interface, buf) catch return error.PostgrezConnectionClosed;

            return;
        }

        self.reader.interface.readSliceAll(buf) catch return error.PostgrezConnectionClosed;
    }

    /// Write one reply flight and put it on the wire.
    pub fn send(self: *Self, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;

        if (self.tls) |*session| {
            session.writeAll(&self.writer.interface, bytes) catch return error.WriteFailed;
            self.writer.interface.flush() catch return error.WriteFailed;

            return;
        }

        self.writer.interface.writeAll(bytes) catch return error.WriteFailed;
        self.writer.interface.flush() catch return error.WriteFailed;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A connected loopback pair, so the transport is exercised over a real
/// socket rather than a byte slice.
const Pair = struct {
    threaded: std.Io.Threaded,
    listener: std.Io.net.Server,
    server_side: std.Io.net.Stream,
    client_side: std.Io.net.Stream,

    fn open(self: *Pair) !void {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        errdefer self.threaded.deinit();
        const io = self.threaded.io();

        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
        self.listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        errdefer self.listener.deinit(io);

        const Accepted = struct {
            listener: *std.Io.net.Server,
            io: std.Io,
            stream: std.Io.net.Stream = undefined,
            err: ?anyerror = null,

            fn run(inner: *@This()) void {
                inner.stream = inner.listener.accept(inner.io) catch |accept_err| {
                    inner.err = accept_err;

                    return;
                };
            }
        };

        var accepted = Accepted{ .listener = &self.listener, .io = io };
        const thread = try std.Thread.spawn(.{}, Accepted.run, .{&accepted});

        var connect_addr = self.listener.socket.address;
        self.client_side = try connect_addr.connect(io, .{ .mode = .stream });
        thread.join();
        if (accepted.err) |accept_err| return accept_err;

        self.server_side = accepted.stream;
    }

    fn close(self: *Pair) void {
        const io = self.threaded.io();
        self.client_side.close(io);
        self.server_side.close(io);
        self.listener.deinit(io);
        self.threaded.deinit();
    }

    fn clientWrite(self: *Pair, bytes: []const u8) !void {
        var buf: [1024]u8 = undefined;
        var writer = self.client_side.writer(self.threaded.io(), &buf);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }

    fn clientRead(self: *Pair, want: []u8) !void {
        var buf: [1024]u8 = undefined;
        var reader = self.client_side.reader(self.threaded.io(), &buf);
        try reader.interface.readSliceAll(want);
    }
};

test "postgrez inproc: transport reads exactly what was written" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    try pair.clientWrite("Q\x00\x00\x00\x0dSELECT 1\x00");

    var transport: Transport = undefined;
    transport.open(pair.threaded.io(), pair.server_side);

    var header: [5]u8 = undefined;
    try transport.readExact(&header);
    try testing.expectEqual(@as(u8, 'Q'), header[0]);
    try testing.expectEqual(@as(i32, 13), std.mem.readInt(i32, header[1..5], .big));

    var payload: [9]u8 = undefined;
    try transport.readExact(&payload);
    try testing.expectEqualStrings("SELECT 1\x00", &payload);
}

test "postgrez inproc: transport starts out unencrypted" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.open(pair.threaded.io(), pair.server_side);

    try testing.expect(!transport.isEncrypted());
}

test "postgrez inproc: transport send puts the whole flight on the wire" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.open(pair.threaded.io(), pair.server_side);

    try transport.send("Z\x00\x00\x00\x05I");

    var got: [6]u8 = undefined;
    try pair.clientRead(&got);
    try testing.expectEqualStrings("Z\x00\x00\x00\x05I", &got);
}

test "postgrez inproc: transport send of nothing touches the wire not at all" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.open(pair.threaded.io(), pair.server_side);

    try transport.send("");
    try transport.send("done");

    var got: [4]u8 = undefined;
    try pair.clientRead(&got);
    try testing.expectEqualStrings("done", &got);
}

test "postgrez inproc: transport reports a closed peer" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.open(pair.threaded.io(), pair.server_side);

    try pair.client_side.shutdown(pair.threaded.io(), .both);

    var buf: [5]u8 = undefined;
    try testing.expectError(error.PostgrezConnectionClosed, transport.readExact(&buf));
}
