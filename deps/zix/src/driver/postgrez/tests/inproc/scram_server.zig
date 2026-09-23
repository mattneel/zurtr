//! The server half of SCRAM-SHA-256 (RFC 5802) and its channel-bound variant.
//!
//! Note:
//! - The mirror of src/auth/scram.zig. The client proves it knows the
//!   password, and the server proves the same back, so a stand-in that only
//!   answered "ok" would leave the driver's second half untested.
//! - PLUS binds the channel with tls-server-end-point (RFC 5929): the client
//!   sends the hash of the server certificate inside its final message, and a
//!   mismatch is rejected here rather than waved through.
//! - Fixed buffers throughout, no allocation. A message past a bound is
//!   rejected rather than truncated.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const MAX_CLIENT_FIRST_BARE = 256;
const MAX_SERVER_FIRST = 256;
const MAX_CLIENT_FINAL = 1024;
const MAX_AUTH_MESSAGE = 2048;
const MAX_SALT = 64;

const GS2_NO_BINDING = "n,,";
const GS2_NO_BINDING_UNSUPPORTED = "y,,";
const GS2_END_POINT = "p=tls-server-end-point,,";

pub const Error = error{
    PostgrezBadClientFirst,
    PostgrezBadClientFinal,
    PostgrezNonceMismatch,
    PostgrezChannelBindingMismatch,
    PostgrezProofMismatch,
    PostgrezInputTooLong,
};

pub const Mechanism = enum {
    SCRAM_SHA_256,
    SCRAM_SHA_256_PLUS,

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .SCRAM_SHA_256 => "SCRAM-SHA-256",
            .SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
        };
    }
};

pub const Options = struct {
    mechanism: Mechanism = .SCRAM_SHA_256,
    password: []const u8,
    /// Per-connection in a real server. A fixed value here keeps the exchange
    /// reproducible, and it is not a secret in a test.
    salt: []const u8 = "postgrez-inproc-salt",
    /// A real server uses 4096. Lower keeps the suites quick, and the client
    /// takes whatever it is told.
    iterations: u32 = 4096,
    /// Appended to the client nonce. Must not be empty: the client checks that
    /// the combined nonce actually extends its own.
    server_nonce: []const u8 = "serverservernonce",
    /// For PLUS: the tls-server-end-point hash the client must present.
    expected_cbind: []const u8 = "",
};

pub const Server = struct {
    options: Options,

    client_first_bare_buf: [MAX_CLIENT_FIRST_BARE]u8 = undefined,
    client_first_bare_len: usize = 0,

    server_first_buf: [MAX_SERVER_FIRST]u8 = undefined,
    server_first_len: usize = 0,

    combined_nonce_buf: [MAX_CLIENT_FIRST_BARE]u8 = undefined,
    combined_nonce_len: usize = 0,

    salted_password: [32]u8 = undefined,

    const Self = @This();

    pub fn init(options: Options) Self {
        return .{ .options = options };
    }

    /// Consume the client-first message and produce the server-first message.
    ///
    /// Return:
    /// - the server-first message, valid until the next call
    /// - error.PostgrezBadClientFirst on a malformed or unbound greeting
    pub fn handleClientFirst(self: *Self, client_first: []const u8) Error![]const u8 {
        const bare = try self.stripGs2Header(client_first);
        if (bare.len > self.client_first_bare_buf.len) return error.PostgrezInputTooLong;

        @memcpy(self.client_first_bare_buf[0..bare.len], bare);
        self.client_first_bare_len = bare.len;

        const client_nonce = findAttribute(bare, 'r') orelse return error.PostgrezBadClientFirst;
        if (client_nonce.len == 0) return error.PostgrezBadClientFirst;
        if (client_nonce.len + self.options.server_nonce.len > self.combined_nonce_buf.len) return error.PostgrezInputTooLong;

        @memcpy(self.combined_nonce_buf[0..client_nonce.len], client_nonce);
        @memcpy(self.combined_nonce_buf[client_nonce.len..][0..self.options.server_nonce.len], self.options.server_nonce);
        self.combined_nonce_len = client_nonce.len + self.options.server_nonce.len;

        if (self.options.salt.len > MAX_SALT) return error.PostgrezInputTooLong;
        var salt_b64: [std.base64.standard.Encoder.calcSize(MAX_SALT)]u8 = undefined;
        const salt_encoded = std.base64.standard.Encoder.encode(&salt_b64, self.options.salt);

        var writer = std.Io.Writer.fixed(&self.server_first_buf);
        writer.print("r={s},s={s},i={d}", .{
            self.combinedNonce(),
            salt_encoded,
            self.options.iterations,
        }) catch return error.PostgrezInputTooLong;
        self.server_first_len = writer.buffered().len;

        std.crypto.pwhash.pbkdf2(
            &self.salted_password,
            self.options.password,
            self.options.salt,
            self.options.iterations,
            HmacSha256,
        ) catch return error.PostgrezBadClientFirst;

        return self.serverFirst();
    }

    /// Verify the client-final message and produce the server-final message.
    ///
    /// Return:
    /// - the server-final message `v=<signature>`, valid until the next call
    /// - error.PostgrezProofMismatch when the client did not know the password
    /// - error.PostgrezChannelBindingMismatch when a PLUS binding did not match
    pub fn handleClientFinal(self: *Self, client_final: []const u8, out: []u8) Error![]const u8 {
        if (client_final.len > MAX_CLIENT_FINAL) return error.PostgrezInputTooLong;

        const proof_marker = std.mem.lastIndexOf(u8, client_final, ",p=") orelse return error.PostgrezBadClientFinal;
        const without_proof = client_final[0..proof_marker];
        const proof_b64 = client_final[proof_marker + 3 ..];

        const nonce = findAttribute(without_proof, 'r') orelse return error.PostgrezBadClientFinal;
        if (!std.mem.eql(u8, nonce, self.combinedNonce())) return error.PostgrezNonceMismatch;

        try self.checkChannelBinding(without_proof);

        var auth_message_buf: [MAX_AUTH_MESSAGE]u8 = undefined;
        var auth_writer = std.Io.Writer.fixed(&auth_message_buf);
        auth_writer.print("{s},{s},{s}", .{
            self.clientFirstBare(),
            self.serverFirst(),
            without_proof,
        }) catch return error.PostgrezInputTooLong;
        const auth_message = auth_writer.buffered();

        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &self.salted_password);

        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        var client_signature: [32]u8 = undefined;
        HmacSha256.create(&client_signature, auth_message, &stored_key);

        var proof: [32]u8 = undefined;
        const proof_len = std.base64.standard.Decoder.calcSizeForSlice(proof_b64) catch return error.PostgrezBadClientFinal;
        if (proof_len != proof.len) return error.PostgrezBadClientFinal;
        std.base64.standard.Decoder.decode(&proof, proof_b64) catch return error.PostgrezBadClientFinal;

        // ClientKey = ClientProof XOR ClientSignature, and hashing it must
        // land back on the stored key
        var recovered_key: [32]u8 = undefined;
        for (&recovered_key, proof, client_signature) |*out_byte, proof_byte, signature_byte| {
            out_byte.* = proof_byte ^ signature_byte;
        }

        var recovered_stored: [32]u8 = undefined;
        Sha256.hash(&recovered_key, &recovered_stored, .{});
        if (!std.mem.eql(u8, &recovered_stored, &stored_key)) return error.PostgrezProofMismatch;

        var server_key: [32]u8 = undefined;
        HmacSha256.create(&server_key, "Server Key", &self.salted_password);

        var server_signature: [32]u8 = undefined;
        HmacSha256.create(&server_signature, auth_message, &server_key);

        var signature_b64: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
        const signature_encoded = std.base64.standard.Encoder.encode(&signature_b64, &server_signature);

        var writer = std.Io.Writer.fixed(out);
        writer.print("v={s}", .{signature_encoded}) catch return error.PostgrezInputTooLong;

        return writer.buffered();
    }

    // --------------------------------------------------------- //

    fn clientFirstBare(self: *const Self) []const u8 {
        return self.client_first_bare_buf[0..self.client_first_bare_len];
    }

    fn serverFirst(self: *const Self) []const u8 {
        return self.server_first_buf[0..self.server_first_len];
    }

    fn combinedNonce(self: *const Self) []const u8 {
        return self.combined_nonce_buf[0..self.combined_nonce_len];
    }

    fn gs2Header(self: *const Self) []const u8 {
        return switch (self.options.mechanism) {
            .SCRAM_SHA_256 => GS2_NO_BINDING,
            .SCRAM_SHA_256_PLUS => GS2_END_POINT,
        };
    }

    /// Remove the gs2 header, leaving client-first-bare.
    fn stripGs2Header(self: *const Self, client_first: []const u8) Error![]const u8 {
        if (self.options.mechanism == .SCRAM_SHA_256_PLUS) {
            if (!std.mem.startsWith(u8, client_first, GS2_END_POINT)) return error.PostgrezBadClientFirst;

            return client_first[GS2_END_POINT.len..];
        }

        // a plain exchange accepts both "client does not support binding" and
        // "client supports it but believes the server does not"
        if (std.mem.startsWith(u8, client_first, GS2_NO_BINDING)) return client_first[GS2_NO_BINDING.len..];
        if (std.mem.startsWith(u8, client_first, GS2_NO_BINDING_UNSUPPORTED)) {
            return client_first[GS2_NO_BINDING_UNSUPPORTED.len..];
        }

        return error.PostgrezBadClientFirst;
    }

    /// The c= attribute must decode to the gs2 header plus, for PLUS, the
    /// binding data the server expects.
    fn checkChannelBinding(self: *const Self, without_proof: []const u8) Error!void {
        const encoded = findAttribute(without_proof, 'c') orelse return error.PostgrezBadClientFinal;

        var decoded_buf: [GS2_END_POINT.len + 64]u8 = undefined;
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.PostgrezBadClientFinal;
        if (decoded_len > decoded_buf.len) return error.PostgrezBadClientFinal;
        std.base64.standard.Decoder.decode(decoded_buf[0..decoded_len], encoded) catch return error.PostgrezBadClientFinal;

        const decoded = decoded_buf[0..decoded_len];
        const header = self.gs2Header();
        if (!std.mem.startsWith(u8, decoded, header)) return error.PostgrezChannelBindingMismatch;

        const binding = decoded[header.len..];
        if (self.options.mechanism == .SCRAM_SHA_256) {
            if (binding.len != 0) return error.PostgrezChannelBindingMismatch;

            return;
        }

        if (!std.mem.eql(u8, binding, self.options.expected_cbind)) return error.PostgrezChannelBindingMismatch;
    }
};

/// The value of the first `<code>=` attribute in a comma-separated message.
fn findAttribute(message: []const u8, code: u8) ?[]const u8 {
    var parts = std.mem.splitScalar(u8, message, ',');
    while (parts.next()) |part| {
        if (part.len < 2 or part[0] != code or part[1] != '=') continue;

        return part[2..];
    }

    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const postgrez = @import("postgrez");

const TEST_PASSWORD = "postgrez_scram_pw";
const CLIENT_NONCE = "clientnoncetext_abcdef00";

/// Drive the driver's own SCRAM client against this server, which is the only
/// way to prove the two halves agree.
fn exchange(server: *Server, mechanism: postgrez.scram.Mechanism, cbind: []const u8) !void {
    var client = try postgrez.scram.Scram.init(mechanism, "", TEST_PASSWORD, CLIENT_NONCE, cbind);

    var client_first_buf: [256]u8 = undefined;
    const client_first = try client.clientFirst(&client_first_buf);

    const server_first = try server.handleClientFirst(client_first);
    const client_final = try client.handleServerFirst(server_first);

    var server_final_buf: [256]u8 = undefined;
    const server_final = try server.handleClientFinal(client_final, &server_final_buf);

    try client.handleServerFinal(server_final);
}

test "postgrez inproc: scram completes a plain exchange with the driver client" {
    var server = Server.init(.{ .password = TEST_PASSWORD });

    try exchange(&server, .SCRAM_SHA_256, "");
}

test "postgrez inproc: scram completes a channel-bound exchange" {
    const cbind: [32]u8 = @splat(0xab);
    var server = Server.init(.{
        .mechanism = .SCRAM_SHA_256_PLUS,
        .password = TEST_PASSWORD,
        .expected_cbind = &cbind,
    });

    try exchange(&server, .SCRAM_SHA_256_PLUS, &cbind);
}

test "postgrez inproc: scram rejects a client that knows the wrong password" {
    var server = Server.init(.{ .password = "the-real-password" });

    var client = try postgrez.scram.Scram.init(.SCRAM_SHA_256, "", "a-guess", CLIENT_NONCE, "");

    var client_first_buf: [256]u8 = undefined;
    const client_first = try client.clientFirst(&client_first_buf);
    const server_first = try server.handleClientFirst(client_first);
    const client_final = try client.handleServerFirst(server_first);

    var server_final_buf: [256]u8 = undefined;
    try testing.expectError(error.PostgrezProofMismatch, server.handleClientFinal(client_final, &server_final_buf));
}

test "postgrez inproc: scram rejects a binding the client got wrong" {
    const server_cbind: [32]u8 = @splat(0xab);
    const client_cbind: [32]u8 = @splat(0xcd);

    var server = Server.init(.{
        .mechanism = .SCRAM_SHA_256_PLUS,
        .password = TEST_PASSWORD,
        .expected_cbind = &server_cbind,
    });

    var client = try postgrez.scram.Scram.init(.SCRAM_SHA_256_PLUS, "", TEST_PASSWORD, CLIENT_NONCE, &client_cbind);

    var client_first_buf: [256]u8 = undefined;
    const client_first = try client.clientFirst(&client_first_buf);
    const server_first = try server.handleClientFirst(client_first);
    const client_final = try client.handleServerFirst(server_first);

    var server_final_buf: [256]u8 = undefined;
    try testing.expectError(error.PostgrezChannelBindingMismatch, server.handleClientFinal(client_final, &server_final_buf));
}

test "postgrez inproc: scram server first extends the client nonce" {
    var server = Server.init(.{ .password = TEST_PASSWORD, .server_nonce = "SERVERPART" });

    const server_first = try server.handleClientFirst("n,,n=,r=" ++ CLIENT_NONCE);

    const nonce = findAttribute(server_first, 'r').?;
    try testing.expect(std.mem.startsWith(u8, nonce, CLIENT_NONCE));
    try testing.expectEqualStrings(CLIENT_NONCE ++ "SERVERPART", nonce);
}

test "postgrez inproc: scram server first reports its salt and iteration count" {
    var server = Server.init(.{ .password = TEST_PASSWORD, .salt = "abcd", .iterations = 1024 });

    const server_first = try server.handleClientFirst("n,,n=,r=" ++ CLIENT_NONCE);

    try testing.expectEqualStrings("1024", findAttribute(server_first, 'i').?);

    var salt: [8]u8 = undefined;
    const salt_b64 = findAttribute(server_first, 's').?;
    try std.base64.standard.Decoder.decode(salt[0..4], salt_b64);
    try testing.expectEqualStrings("abcd", salt[0..4]);
}

test "postgrez inproc: scram rejects a greeting with no gs2 header" {
    var server = Server.init(.{ .password = TEST_PASSWORD });

    try testing.expectError(error.PostgrezBadClientFirst, server.handleClientFirst("n=,r=" ++ CLIENT_NONCE));
}

test "postgrez inproc: scram plain accepts the y gs2 header" {
    var server = Server.init(.{ .password = TEST_PASSWORD });

    const server_first = try server.handleClientFirst("y,,n=,r=" ++ CLIENT_NONCE);

    try testing.expect(findAttribute(server_first, 'r') != null);
}

test "postgrez inproc: scram rejects a final message whose nonce drifted" {
    var server = Server.init(.{ .password = TEST_PASSWORD });

    _ = try server.handleClientFirst("n,,n=,r=" ++ CLIENT_NONCE);

    var out: [256]u8 = undefined;
    try testing.expectError(
        error.PostgrezNonceMismatch,
        server.handleClientFinal("c=biws,r=somethingelse,p=AAAA", &out),
    );
}
