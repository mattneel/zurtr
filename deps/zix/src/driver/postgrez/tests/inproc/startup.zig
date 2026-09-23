//! The connection handshake: the optional TLS upgrade, the startup packet,
//! authentication, and the parameters a backend reports before it is ready.
//!
//! Note:
//! - Split from the query loop because it is a different job with different
//!   state. Once this returns, the connection speaks only the query protocol.
//! - Authentication is real, not waved through. A SCRAM exchange runs both
//!   halves, so a driver that computed the wrong proof is rejected here the
//!   way a real backend would reject it.
//! - The TLS answer to an SSLRequest is a single raw byte, not a framed
//!   message. It is the one place the backend writes something that is not a
//!   message at all.

const std = @import("std");

const backend = @import("backend.zig");
const certificate = @import("certificate.zig");
const clients = @import("clients.zig");
const frontend = @import("frontend.zig");
const message = @import("message.zig");
const options_mod = @import("options.zig");
const scram_server = @import("scram_server.zig");
const transport_mod = @import("transport.zig");

/// SQLSTATE for a rejected password, which the driver maps to INVALID_PASSWORD.
const INVALID_PASSWORD = "28P01";

/// SQLSTATE for a client asking for TLS the backend will not give.
const PROTOCOL_VIOLATION = "08P01";

pub const Error = error{
    PostgrezConnectionClosed,
    PostgrezMalformedMessage,
    PostgrezMessageTooLarge,
    /// The client asked to cancel a query rather than open a session.
    PostgrezCancelRequested,
    /// The client gave up, or gave the wrong password. Either way the
    /// connection is finished.
    PostgrezAuthenticationFailed,
    OutOfMemory,
    PostgrezTruncated,
    WriteFailed,
};

pub const Result = struct {
    user: []const u8,
    database: []const u8,
    /// What the connection settled on after any negotiation.
    protocol_code: i32,
};

/// Drive the handshake to the first ReadyForQuery.
///
/// Param:
/// transport - *transport_mod.Transport (upgraded in place when TLS is agreed)
/// options - options_mod.Options (auth mode, credentials, TLS, version)
/// cert - ?*const certificate.SelfSigned (present when the backend serves TLS)
/// client - *clients.Client (its pid goes into BackendKeyData)
/// arena - std.mem.Allocator (scratch for the handshake only)
///
/// Return:
/// - Result once ReadyForQuery has been sent
/// - error.PostgrezAuthenticationFailed after the rejection has been written
pub fn run(
    transport: *transport_mod.Transport,
    options: options_mod.Options,
    cert: ?*const certificate.SelfSigned,
    client: *clients.Client,
    arena: std.mem.Allocator,
) Error!Result {
    var first = try frontend.readStartup(transport, arena);

    if (first == .ssl_request) {
        try answerSslRequest(transport, options, cert);

        // the real startup packet follows, inside TLS when it was accepted
        first = try frontend.readStartup(transport, arena);
        if (first == .ssl_request) return error.PostgrezMalformedMessage;
    }

    if (first == .cancel_request) return error.PostgrezCancelRequested;

    const hello = first.hello;

    var reply_buf: [4096]u8 = undefined;
    var reply = message.Writer{ .buf = &reply_buf };

    // a client asking for a minor the backend does not have is told the
    // highest it does have, and carries on
    if (hello.protocol_code > options.protocol_code) {
        backend.negotiateProtocolVersion(&reply, options.protocol_code, &.{});
    }

    const settled_code = @min(hello.protocol_code, options.protocol_code);

    try authenticate(transport, options, cert, hello, arena, &reply);

    backend.parameterStatus(&reply, "server_version", options.server_version);
    backend.parameterStatus(&reply, "client_encoding", "UTF8");
    backend.parameterStatus(&reply, "DateStyle", "ISO, MDY");
    backend.parameterStatus(&reply, "integer_datetimes", "on");
    backend.backendKeyData(&reply, client.pid, &[_]u8{ 0xca, 0xfe, 0xba, 0xbe });
    backend.readyForQuery(&reply, .IDLE);

    try transport.send(try reply.finish());

    return .{
        .user = hello.user,
        .database = hello.database,
        .protocol_code = settled_code,
    };
}

// --------------------------------------------------------- //

/// One raw byte: 'S' to continue in TLS, 'N' to stay in the clear.
fn answerSslRequest(
    transport: *transport_mod.Transport,
    options: options_mod.Options,
    cert: ?*const certificate.SelfSigned,
) Error!void {
    if (!options.tls or cert == null) {
        try transport.send("N");

        return;
    }

    try transport.send("S");
    transport.upgrade(cert.?) catch return error.PostgrezConnectionClosed;
}

fn authenticate(
    transport: *transport_mod.Transport,
    options: options_mod.Options,
    cert: ?*const certificate.SelfSigned,
    hello: frontend.Hello,
    arena: std.mem.Allocator,
    reply: *message.Writer,
) Error!void {
    if (options.user.len > 0 and !std.mem.eql(u8, options.user, hello.user)) {
        return reject(transport, reply, "role does not exist");
    }

    switch (options.auth_mode) {
        .TRUST => backend.authenticationOk(reply),
        .CLEARTEXT => try cleartextExchange(transport, options, arena, reply),
        .SCRAM, .SCRAM_PLUS => try scramExchange(transport, options, cert, arena, reply),
    }
}

fn cleartextExchange(
    transport: *transport_mod.Transport,
    options: options_mod.Options,
    arena: std.mem.Allocator,
    reply: *message.Writer,
) Error!void {
    var challenge_buf: [16]u8 = undefined;
    var challenge = message.Writer{ .buf = &challenge_buf };
    backend.authenticationCleartextPassword(&challenge);
    try transport.send(try challenge.finish());

    const msg = try frontend.readMessage(transport, arena);
    if (msg != .password) return error.PostgrezMalformedMessage;

    // the payload is the password with its NUL terminator
    const offered = std.mem.sliceTo(msg.password, 0);
    if (!std.mem.eql(u8, offered, options.password)) {
        return reject(transport, reply, "password authentication failed");
    }

    backend.authenticationOk(reply);
}

fn scramExchange(
    transport: *transport_mod.Transport,
    options: options_mod.Options,
    cert: ?*const certificate.SelfSigned,
    arena: std.mem.Allocator,
    reply: *message.Writer,
) Error!void {
    const plus = options.auth_mode == .SCRAM_PLUS;

    // tls-server-end-point (RFC 5929) is the SHA-256 of the certificate DER
    var cbind: [32]u8 = undefined;
    if (plus) {
        const presented = cert orelse return error.PostgrezMalformedMessage;
        std.crypto.hash.sha2.Sha256.hash(presented.derBytes(), &cbind, .{});
    }

    var scram = scram_server.Server.init(.{
        .mechanism = if (plus) .SCRAM_SHA_256_PLUS else .SCRAM_SHA_256,
        .password = options.password,
        .expected_cbind = if (plus) &cbind else "",
    });

    var offer_buf: [128]u8 = undefined;
    var offer = message.Writer{ .buf = &offer_buf };
    if (plus) {
        backend.authenticationSasl(&offer, &.{ "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256" });
    } else {
        backend.authenticationSasl(&offer, &.{"SCRAM-SHA-256"});
    }
    try transport.send(try offer.finish());

    const initial = try frontend.readMessage(transport, arena);
    if (initial != .password) return error.PostgrezMalformedMessage;

    const client_first = try initialResponseBody(initial.password);
    const server_first = scram.handleClientFirst(client_first) catch {
        return reject(transport, reply, "SASL authentication failed");
    };

    var continue_buf: [512]u8 = undefined;
    var continue_writer = message.Writer{ .buf = &continue_buf };
    backend.authenticationSaslContinue(&continue_writer, server_first);
    try transport.send(try continue_writer.finish());

    const final = try frontend.readMessage(transport, arena);
    if (final != .password) return error.PostgrezMalformedMessage;

    var server_final_buf: [256]u8 = undefined;
    const server_final = scram.handleClientFinal(final.password, &server_final_buf) catch {
        return reject(transport, reply, "password authentication failed");
    };

    backend.authenticationSaslFinal(reply, server_final);
    backend.authenticationOk(reply);
}

/// SASLInitialResponse: the mechanism name, then a length-prefixed body.
fn initialResponseBody(payload: []const u8) Error![]const u8 {
    var reader = message.Reader{ .buf = payload };
    _ = reader.cstring() catch return error.PostgrezMalformedMessage;

    const length = reader.int32() catch return error.PostgrezMalformedMessage;
    if (length < 0) return error.PostgrezMalformedMessage;

    return reader.bytes(@intCast(length)) catch return error.PostgrezMalformedMessage;
}

/// Write the refusal, put it on the wire, and end the connection.
fn reject(transport: *transport_mod.Transport, reply: *message.Writer, text: []const u8) Error!void {
    reply.reset();
    backend.errorResponse(reply, .{
        .severity = "FATAL",
        .code = INVALID_PASSWORD,
        .message = text,
    });
    try transport.send(try reply.finish());

    return error.PostgrezAuthenticationFailed;
}

/// Refuse a TLS request the backend cannot honour, used when a suite wants the
/// driver's .REQUIRE path to fail cleanly.
pub fn refuseTls(transport: *transport_mod.Transport) Error!void {
    var reply_buf: [256]u8 = undefined;
    var reply = message.Writer{ .buf = &reply_buf };
    backend.errorResponse(&reply, .{
        .severity = "FATAL",
        .code = PROTOCOL_VIOLATION,
        .message = "this backend does not support SSL",
    });

    try transport.send(try reply.finish());
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez inproc: startup extracts the sasl initial response body" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    writer.cstring("SCRAM-SHA-256");
    writer.int32(9);
    writer.bytes("n,,n=,r=x");

    const body = try initialResponseBody(try writer.finish());

    try testing.expectEqualStrings("n,,n=,r=x", body);
}

test "postgrez inproc: startup rejects a sasl initial response with no length" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    writer.cstring("SCRAM-SHA-256");

    try testing.expectError(error.PostgrezMalformedMessage, initialResponseBody(try writer.finish()));
}

test "postgrez inproc: startup rejects a sasl body shorter than its length" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    writer.cstring("SCRAM-SHA-256");
    writer.int32(64);
    writer.bytes("short");

    try testing.expectError(error.PostgrezMalformedMessage, initialResponseBody(try writer.finish()));
}
