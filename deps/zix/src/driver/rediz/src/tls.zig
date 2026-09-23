//! TLS transport for a connection: the direct handshake and the
//! record-framed read/write path the connection tunnels through.
//!
//! Note:
//! - A Redis TLS port speaks TLS from the first byte: handshake() runs the
//!   TLS 1.3 client handshake (tls/client.zig) immediately, no upgrade
//!   request precedes it.
//! - The session is heap-allocated: it carries record staging and decrypted
//!   spill buffers (~50 KiB).
//! - No chain or hostname validation: TLS here provides encryption, and
//!   finish() verifies the server holds the certificate key
//!   (CertificateVerify).

const std = @import("std");

/// The TLS layers this file is built from, named so they can be reached as
/// rediz.tls.record and friends. Direction-neutral: wire, key_schedule and
/// record describe the protocol rather than the client role, which is what
/// lets the in-process test server drive the other side of the same handshake.
pub const client = @import("tls/client.zig");
pub const record = @import("tls/record.zig");
pub const wire = @import("tls/wire.zig");
pub const key_schedule = @import("tls/key_schedule.zig");

pub const TlsSession = struct {
    connection: client.ClientConnection,
    server_cert: [client.MAX_SERVER_CERT_DER]u8,
    server_cert_len: usize,

    /// Read staging for one wire record.
    record_buf: [record.MAX_RECORD_WIRE]u8 = undefined,
    /// Decrypted spill: plaintext not yet consumed by readAll.
    plain_buf: [record.MAX_PLAINTEXT + 256]u8 = undefined,
    plain_len: usize = 0,
    plain_pos: usize = 0,
    /// Write staging for one protected record.
    write_buf: [record.MAX_RECORD_WIRE]u8 = undefined,

    /// The server end-entity certificate DER.
    pub fn serverCertDer(self: *const TlsSession) []const u8 {
        return self.server_cert[0..self.server_cert_len];
    }

    /// Decrypted bytes already buffered (readable without touching the wire).
    pub fn bufferedLen(self: *const TlsSession) usize {
        return self.plain_len - self.plain_pos;
    }

    /// Encrypt and send `bytes`, chunked into records. The caller flushes
    /// the stream writer afterwards.
    pub fn writeAll(self: *TlsSession, writer: *std.Io.Writer, bytes: []const u8) !void {
        var pos: usize = 0;
        while (pos < bytes.len) {
            const chunk_len = @min(bytes.len - pos, record.MAX_PLAINTEXT);
            const rec = self.connection.writeAppData(bytes[pos..][0..chunk_len], &self.write_buf);

            try writer.writeAll(rec);
            pos += chunk_len;
        }
    }

    /// Fill `out` with decrypted application data, reading records as
    /// needed. Post-handshake HANDSHAKE records (session tickets) are
    /// skipped, an ALERT ends the stream.
    pub fn readAll(self: *TlsSession, reader: *std.Io.Reader, out: []u8) !void {
        var pos: usize = 0;
        while (pos < out.len) {
            if (self.bufferedLen() == 0) try self.fillPlain(reader);

            const take = @min(out.len - pos, self.bufferedLen());
            @memcpy(out[pos..][0..take], self.plain_buf[self.plain_pos..][0..take]);
            self.plain_pos += take;
            pos += take;
        }
    }

    fn fillPlain(self: *TlsSession, reader: *std.Io.Reader) !void {
        while (true) {
            const rec = try readWireRecord(reader, &self.record_buf);
            if (rec[0] == 21) return error.RedizConnectionClosed; // plaintext alert

            var opened_buf: [record.MAX_PLAINTEXT + 256]u8 = undefined;
            const opened = self.connection.readRecord(rec, &opened_buf) catch return error.RedizConnectionClosed;

            switch (opened.inner_type) {
                .APPLICATION_DATA => {
                    @memcpy(self.plain_buf[0..opened.data.len], opened.data);
                    self.plain_len = opened.data.len;
                    self.plain_pos = 0;

                    return;
                },
                .HANDSHAKE => continue, // NewSessionTicket / KeyUpdate info
                else => return error.RedizConnectionClosed,
            }
        }
    }
};

// --------------------------------------------------------- //

/// TLS 1.3 handshake over an established stream, first bytes included.
///
/// Return:
/// - *TlsSession on a completed handshake (allocator-owned)
/// - error.TlsHandshakeFailed and friends on a broken handshake
pub fn handshake(allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !*TlsSession {
    // handshake phase 1: ClientHello in a plaintext handshake record
    var client_random: [32]u8 = undefined;
    io.random(&client_random);
    var ephemeral_secret: [32]u8 = undefined;
    io.random(&ephemeral_secret);

    var hello_buf: [512]u8 = undefined;
    const started = try client.start(.{ .client_random = client_random, .ephemeral_secret = ephemeral_secret }, &hello_buf);

    var hello_record: [512 + 5]u8 = undefined;
    hello_record[0] = 22;
    std.mem.writeInt(u16, hello_record[1..3], 0x0303, .big);
    std.mem.writeInt(u16, hello_record[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(hello_record[5 .. 5 + started.client_hello.len], started.client_hello);

    writer.writeAll(hello_record[0 .. 5 + started.client_hello.len]) catch return error.RedizConnectionClosed;
    writer.flush() catch return error.RedizConnectionClosed;

    // handshake phase 2: accumulate server records until finish() completes
    var flight_buf: [client.MAX_FLIGHT_PLAIN + 4096]u8 = undefined;
    var flight_len: usize = 0;
    var fin_buf: [256]u8 = undefined;

    const finished = while (true) {
        const rec = readWireRecord(reader, flight_buf[flight_len..]) catch return error.RedizConnectionClosed;
        flight_len += rec.len;

        var state = started.state;
        const result = client.finish(&state, flight_buf[0..flight_len], &fin_buf) catch |err| switch (err) {
            error.RedizNeedMoreRecords => continue,
            else => return err,
        };

        break result;
    };

    writer.writeAll(finished.client_finished) catch return error.RedizConnectionClosed;
    writer.flush() catch return error.RedizConnectionClosed;

    const session = try allocator.create(TlsSession);
    session.* = .{
        .connection = finished.connection,
        .server_cert = finished.server_cert,
        .server_cert_len = finished.server_cert_len,
    };

    return session;
}

/// One TLS record off the wire: 5-byte header, then the framed length.
fn readWireRecord(reader: *std.Io.Reader, buf: []u8) ![]const u8 {
    if (buf.len < 5) return error.RedizRecordTooLarge;

    reader.readSliceAll(buf[0..5]) catch return error.RedizConnectionClosed;
    const body_len = std.mem.readInt(u16, buf[3..5], .big);
    if (body_len > record.MAX_CIPHERTEXT) return error.RedizRecordTooLarge;
    if (5 + @as(usize, body_len) > buf.len) return error.RedizRecordTooLarge;

    reader.readSliceAll(buf[5 .. 5 + body_len]) catch return error.RedizConnectionClosed;

    return buf[0 .. 5 + body_len];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz: tls session read and write tunnel app data" {
    var session = try testing.allocator.create(TlsSession);
    defer testing.allocator.destroy(session);
    session.* = .{
        .connection = .{
            .client_app_key = @splat(0x01),
            .client_app_iv = @splat(0x02),
            .server_app_key = @splat(0x03),
            .server_app_iv = @splat(0x04),
        },
        .server_cert = undefined,
        .server_cert_len = 0,
    };

    // mirror side: reads client records, writes server records
    var mirror = client.ClientConnection{
        .client_app_key = @splat(0x03),
        .client_app_iv = @splat(0x04),
        .server_app_key = @splat(0x01),
        .server_app_iv = @splat(0x02),
    };

    // session write path into a fixed writer
    var wire_buf: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&wire_buf);
    try session.writeAll(&writer, "PING");

    var plain_buf: [256]u8 = undefined;
    const opened = try mirror.readRecord(writer.buffered(), &plain_buf);
    try testing.expectEqualStrings("PING", opened.data);

    // session read path: a ticket record (skipped) then app data
    var ticket_rec_buf: [256]u8 = undefined;
    const ticket_rec = record.protect(&ticket_rec_buf, &.{ 4, 0, 0, 0 }, .HANDSHAKE, mirror.client_app_key, mirror.client_app_iv, 0);
    var data_rec_buf: [256]u8 = undefined;
    const data_rec = record.protect(&data_rec_buf, "+PONG\r\n", .APPLICATION_DATA, mirror.client_app_key, mirror.client_app_iv, 1);

    var stream_bytes: [512]u8 = undefined;
    @memcpy(stream_bytes[0..ticket_rec.len], ticket_rec);
    @memcpy(stream_bytes[ticket_rec.len..][0..data_rec.len], data_rec);

    var reader = std.Io.Reader.fixed(stream_bytes[0 .. ticket_rec.len + data_rec.len]);
    var out: [7]u8 = undefined;
    try session.readAll(&reader, &out);
    try testing.expectEqualStrings("+PONG\r\n", &out);
    try testing.expectEqual(@as(usize, 0), session.bufferedLen());
}

test "rediz: tls serverCertDer views the captured cert" {
    var session = try testing.allocator.create(TlsSession);
    defer testing.allocator.destroy(session);
    session.* = .{
        .connection = undefined,
        .server_cert = undefined,
        .server_cert_len = 4,
    };
    @memcpy(session.server_cert[0..4], "cert");

    try testing.expectEqualStrings("cert", session.serverCertDer());
}
