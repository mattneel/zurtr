//! Byte movement for one accepted connection, cleartext or TLS.
//!
//! Note:
//! - Provides the `readLine` / `readExact` pair the RESP framing in wire.zig
//!   expects, plus a `send` that writes a whole reply at once. The framing
//!   above never learns which of the two it is talking through, which is the
//!   same separation the driver keeps on its own side.
//! - Holds its own reader and writer buffers, so it must not be moved after
//!   open: the reader points into the struct. Handlers keep it on the stack
//!   and pass a pointer.
//! - Reading a line one byte at a time is the TLS path's cost of not having a
//!   buffered reader over the decrypted stream. A test server trades that for
//!   not reimplementing buffering, exactly as the driver does.

const std = @import("std");

const certificate = @import("certificate.zig");
const tls_server = @import("tls_server.zig");
const wire = @import("wire.zig");

const READ_BUF_SIZE = 8 * 1024;
const WRITE_BUF_SIZE = 8 * 1024;

pub const Transport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    read_buf: [READ_BUF_SIZE]u8 = undefined,
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    /// Absent on a cleartext connection.
    tls: ?tls_server.Session = null,

    const Self = @This();

    /// Take over an accepted stream in cleartext.
    pub fn openPlain(self: *Self, io: std.Io, stream: std.Io.net.Stream) void {
        self.io = io;
        self.stream = stream;
        self.reader = stream.reader(io, &self.read_buf);
        self.writer = stream.writer(io, &self.write_buf);
        self.tls = null;
    }

    /// Take over an accepted stream and run the server side of the TLS
    /// handshake before any application byte moves.
    ///
    /// Return:
    /// - void once the client Finished has been verified
    /// - the handshake errors from tls_server, all fatal for this connection
    pub fn openTls(
        self: *Self,
        io: std.Io,
        stream: std.Io.net.Stream,
        cert: *const certificate.SelfSigned,
    ) !void {
        self.openPlain(io, stream);
        self.tls = try tls_server.handshake(io, &self.reader.interface, &self.writer.interface, cert);
    }

    /// One CRLF-terminated line, CRLF stripped, copied into buf.
    pub fn readLine(self: *Self, buf: []u8) wire.ReadError![]const u8 {
        if (self.tls != null) return self.readLineTls(buf);

        // takeDelimiterInclusive, not the exclusive form: the exclusive form
        // leaves the delimiter behind and the next read sees an empty line.
        const raw = self.reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream, error.ReadFailed => return error.RedizConnectionClosed,
            error.StreamTooLong => return error.RedizProtocolViolation,
        };
        if (raw.len < 2 or raw[raw.len - 2] != '\r') return error.RedizProtocolViolation;

        const body = raw[0 .. raw.len - 2];
        if (body.len > buf.len) return error.RedizProtocolViolation;
        @memcpy(buf[0..body.len], body);

        return buf[0..body.len];
    }

    fn readLineTls(self: *Self, buf: []u8) wire.ReadError![]const u8 {
        var len: usize = 0;

        while (true) {
            var byte: [1]u8 = undefined;
            self.tls.?.readAll(&self.reader.interface, &byte) catch return error.RedizConnectionClosed;

            if (byte[0] == '\n') {
                if (len == 0 or buf[len - 1] != '\r') return error.RedizProtocolViolation;

                return buf[0 .. len - 1];
            }

            if (len >= buf.len) return error.RedizProtocolViolation;
            buf[len] = byte[0];
            len += 1;
        }
    }

    /// Fill buf completely.
    pub fn readExact(self: *Self, buf: []u8) wire.ReadError!void {
        if (self.tls) |*session| {
            session.readAll(&self.reader.interface, buf) catch return error.RedizConnectionClosed;

            return;
        }

        self.reader.interface.readSliceAll(buf) catch return error.RedizConnectionClosed;
    }

    /// Write one reply and put it on the wire.
    pub fn send(self: *Self, bytes: []const u8) wire.WriteError!void {
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

    /// Write raw bytes from the client end.
    fn clientWrite(self: *Pair, bytes: []const u8) !void {
        var buf: [1024]u8 = undefined;
        var writer = self.client_side.writer(self.threaded.io(), &buf);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }

    /// Read exactly want.len bytes at the client end.
    fn clientRead(self: *Pair, want: []u8) !void {
        var buf: [1024]u8 = undefined;
        var reader = self.client_side.reader(self.threaded.io(), &buf);
        try reader.interface.readSliceAll(want);
    }
};

test "rediz inproc: transport reads a cleartext line without the CRLF" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    try pair.clientWrite("*1\r\n$4\r\nPING\r\n");

    var transport: Transport = undefined;
    transport.openPlain(pair.threaded.io(), pair.server_side);

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("*1", try transport.readLine(&buf));
    try testing.expectEqualStrings("$4", try transport.readLine(&buf));
}

test "rediz inproc: transport readExact takes a bulk body byte for byte" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    try pair.clientWrite("PING\r\n");

    var transport: Transport = undefined;
    transport.openPlain(pair.threaded.io(), pair.server_side);

    var body: [4]u8 = undefined;
    try transport.readExact(&body);
    try testing.expectEqualStrings("PING", &body);

    var crlf: [2]u8 = undefined;
    try transport.readExact(&crlf);
    try testing.expectEqualStrings("\r\n", &crlf);
}

test "rediz inproc: transport rejects a line with no carriage return" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    try pair.clientWrite("bare\n");

    var transport: Transport = undefined;
    transport.openPlain(pair.threaded.io(), pair.server_side);

    var buf: [64]u8 = undefined;
    try testing.expectError(error.RedizProtocolViolation, transport.readLine(&buf));
}

test "rediz inproc: transport reports a closed peer" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.openPlain(pair.threaded.io(), pair.server_side);

    // shut the client end down so the server read cannot block
    try pair.client_side.shutdown(pair.threaded.io(), .both);

    var buf: [64]u8 = undefined;
    try testing.expectError(error.RedizConnectionClosed, transport.readLine(&buf));
}

test "rediz inproc: transport send puts the whole reply on the wire" {
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();

    var transport: Transport = undefined;
    transport.openPlain(pair.threaded.io(), pair.server_side);

    try transport.send("+PONG\r\n");

    var got: [7]u8 = undefined;
    try pair.clientRead(&got);
    try testing.expectEqualStrings("+PONG\r\n", &got);
}
