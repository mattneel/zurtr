//! Shared h2-over-TLS terminator (RFC 8446 + 7540 + 7301 ALPN), engine-agnostic.
//!
//! Note:
//! - Terminates TLS in front of an h2 engine: the handshake runs via zix.Tls (version subject to the
//!   context min_version / max_version) and ALPN must select h2, then a caller-supplied `driver` runs
//!   the decrypted h2 stream. The Http2 and gRPC engines pass an inline-mux driver that drives their
//!   resumable h2 state machine directly over the decrypted records (no socketpair, no second thread),
//!   sealing the engine's frames into TLS records through a thread-local write hook.
//! - The handshake (1.3 and the 1.2 fallback) is engine-agnostic, so the same terminator serves both
//!   zix.Http2 and zix.Grpc without duplicating it.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const fd_io = @import("../../utils/fd_io.zig");
const Tls = @import("../../tls/Tls.zig");
const tls12 = @import("../../tls/tls12_connection.zig");
const record = @import("../../tls/record.zig");

/// Server handshake flight output staging buffer.
const HANDSHAKE_FLIGHT_BUF: usize = 8192;

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const content_type_change_cipher_spec: u8 = 20;
pub const content_type_alert: u8 = 21;
pub const content_type_handshake: u8 = 22;
pub const content_type_application_data: u8 = 23;

/// A plaintext alert arriving mid-handshake (the peer aborted): parse it (RFC 8446 6) and signal a
/// clean teardown so the caller closes the connection rather than misreading it as a record.
fn peerAlert(body: []const u8) anyerror {
    _ = Tls.parseInboundAlert(body) catch {};

    return error.ZixPeerAlert;
}

/// Terminate TLS on fd, then serve the decrypted h2 stream through the caller-supplied engine.
///
/// Param:
/// fd - posix.fd_t (the accepted TLS socket, owned by the caller)
/// ctx - *const Tls.Context (loaded cert / key / alpn / version policy)
/// driver - anytype (its drive(fd, conn, record_buf) owns the connection until close)
///
/// Return:
/// - !void (errors on a rejected handshake or non-h2 ALPN)
///
/// driver runs the decrypted h2 stream after the handshake. The Http2 and gRPC engines pass an
/// inline-mux driver that drives their resumable h2 state machine directly over the records (no
/// socketpair, no second thread).
pub fn serveConnTls(
    fd: posix.fd_t,
    ctx: *const Tls.Context,
    io: std.Io,
    driver: anytype,
) !void {
    var record_buf: [record.max_record_wire]u8 = undefined;

    // ClientHello (a plaintext handshake record carries the message in its body).
    const client_hello_rec = try readRecord(fd, &record_buf);
    if (client_hello_rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;

    var ephemeral_secret: [32]u8 = undefined;
    var server_random: [32]u8 = undefined;
    var pss_salt: [32]u8 = undefined;
    // std.Io carries the platform's CSPRNG, so the handshake secrets need no syscall branch.
    try io.randomSecure(&ephemeral_secret);
    try io.randomSecure(&server_random);
    try io.randomSecure(&pss_salt);

    const hs_opts = ctx.handshakeOptions(ephemeral_secret, server_random, pss_salt);

    // Version policy: when the ceiling is TLS 1.2, never take the 1.3 path. The 1.2 path is
    // ECDSA-signed, so an Ed25519 context cannot serve 1.2.
    if (!ctx.allowsTls13()) {
        const ecdsa_key = switch (ctx.signing_key) {
            .ecdsa_p256 => |kp| kp,
            else => return error.ZixTls12RequiresEcdsa,
        };

        return serveConnTls12(fd, ctx, ecdsa_key, client_hello_rec.body, ephemeral_secret, server_random, driver);
    }

    var handshake_out: [HANDSHAKE_FLIGHT_BUF]u8 = undefined;
    const result = Tls.serverHandshake(hs_opts, client_hello_rec.body, &handshake_out) catch |err| {
        // no 1.3 offer -> the client is TLS 1.2 only. Honor the floor: refuse when min_version is
        // 1.3, else take the h2-over-1.2 path.
        if (err == error.ZixUnsupportedTlsVersion) {
            if (!ctx.allowsTls12()) {
                var ver_alert: [Tls.fatal_record_len]u8 = undefined;
                if (Tls.alertRecordForError(&ver_alert, err)) |rec| writeAllFD(fd, rec) catch {};

                return err;
            }

            const ecdsa_key = switch (ctx.signing_key) {
                .ecdsa_p256 => |kp| kp,
                else => return error.ZixTls12RequiresEcdsa,
            };

            return serveConnTls12(fd, ctx, ecdsa_key, client_hello_rec.body, ephemeral_secret, server_random, driver);
        }

        // any other rejected ClientHello (incl. no_application_protocol): send the fatal alert in
        // the clear (no keys yet), then close.
        var alert_buf: [Tls.fatal_record_len]u8 = undefined;
        if (Tls.alertRecordForError(&alert_buf, err)) |rec| writeAllFD(fd, rec) catch {};

        return err;
    };
    try writeAllFD(fd, result.to_send);
    var conn = result.connection;

    // h2 over TLS requires ALPN to have selected h2 (RFC 7540 3.3). Without it, end the connection
    // rather than guess the application protocol.
    if (result.alpn != .H2) return error.ZixAlpnNotH2;

    // client ChangeCipherSpec (skipped) + Finished. A plaintext alert here means the peer aborted.
    while (true) {
        const rec = try readRecord(fd, &record_buf);
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return peerAlert(rec.body);
        if (rec.content_type != content_type_application_data) return error.ZixUnexpectedRecord;

        try conn.verifyClientFinished(rec.full);
        break;
    }

    driver.drive(fd, &conn, &record_buf);
}

/// h2-over-TLS-1.2 (RFC 7540 over RFC 5246): the two-phase 1.2 handshake (tls12_connection) with
/// ALPN h2, then the caller-supplied driver over the engine. Reached only when the client did not
/// offer 1.3. The 1.2 ephemeral reuses the random bytes (reduced to a P-256 scalar inside the engine).
fn serveConnTls12(
    fd: posix.fd_t,
    ctx: *const Tls.Context,
    key_pair: EcdsaP256.KeyPair,
    client_hello: []const u8,
    ephemeral_secret: [32]u8,
    server_random: [32]u8,
    driver: anytype,
) !void {
    var flight_out: [8192]u8 = undefined;
    const flight = try tls12.serverFlight1(.{
        .certificate_der = ctx.cert_der,
        .signing_key = key_pair,
        .server_eph_secret = ephemeral_secret,
        .server_random = server_random,
        .alpn_prefs = ctx.alpn,
    }, client_hello, &flight_out);
    try writeAllFD(fd, flight.to_send);
    var state = flight.state;

    // h2 over TLS requires ALPN to have selected h2 (RFC 7540 3.3).
    if (state.alpn != .H2) return error.ZixAlpnNotH2;

    var record_buf: [record.max_record_wire]u8 = undefined;

    // ClientKeyExchange (plaintext handshake record), copied out before record_buf is reused.
    const cke_rec = try readRecord(fd, &record_buf);
    if (cke_rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;
    var cke_buf: [256]u8 = undefined;
    if (cke_rec.body.len > cke_buf.len) return error.ZixRecordTooLarge;
    @memcpy(cke_buf[0..cke_rec.body.len], cke_rec.body);
    const client_key_exchange = cke_buf[0..cke_rec.body.len];

    // skip ChangeCipherSpec, then the encrypted client Finished (a handshake record).
    const finished_rec = while (true) {
        const rec = try readRecord(fd, &record_buf);
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return peerAlert(rec.body);
        if (rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;

        break rec;
    };

    var finish_out: [256]u8 = undefined;
    const finish = try tls12.serverFinish(&state, client_key_exchange, finished_rec.full, &finish_out);
    try writeAllFD(fd, finish.to_send);
    var conn = finish.connection;

    driver.drive(fd, &conn, &record_buf);
}

// --------------------------------------------------------------- //

pub const Record = struct {
    content_type: u8,
    full: []const u8,
    body: []const u8,
};

pub fn readRecord(fd: posix.fd_t, buf: []u8) !Record {
    try readAll(fd, buf[0..5]);

    const length = std.mem.readInt(u16, buf[3..5], .big);
    if (5 + length > buf.len) return error.ZixRecordTooLarge;

    try readAll(fd, buf[5 .. 5 + length]);

    return .{ .content_type = buf[0], .full = buf[0 .. 5 + length], .body = buf[5 .. 5 + length] };
}

/// Record traffic runs over the bare accepted descriptor, so it goes through the shared
/// fd helpers rather than a per-platform branch in this file.
const readAll = fd_io.readAll;

pub const writeAllFD = fd_io.writeAll;
