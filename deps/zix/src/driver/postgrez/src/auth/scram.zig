//! SCRAM-SHA-256 and SCRAM-SHA-256-PLUS client exchange (RFC 5802, RFC 7677).
//!
//! Note:
//! - Sans-IO: the connection feeds server messages in and sends the returned
//!   client messages. No allocation, everything lives in fixed buffers.
//! - PLUS binds the channel with tls-server-end-point (RFC 5929): the caller
//!   passes the server certificate hash as `cbind_data`, computed by the TLS
//!   layer.
//! - The password is used as-is (no SASLprep normalization). PostgreSQL
//!   stores verifiers the same way for ASCII passwords, which is the
//!   supported range here.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Mechanism = enum {
    SCRAM_SHA_256,
    SCRAM_SHA_256_PLUS,

    /// Wire name of the mechanism as listed in AuthenticationSASL.
    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .SCRAM_SHA_256 => "SCRAM-SHA-256",
            .SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
        };
    }
};

pub const ScramError = error{
    PostgrezBadServerFirst,
    PostgrezBadServerFinal,
    PostgrezServerRejected,
    PostgrezServerSignatureMismatch,
    PostgrezNonceMismatch,
    PostgrezInputTooLong,
};

/// Upper bounds for the fixed buffers. A server-first beyond this is
/// rejected instead of truncated.
const MAX_USERNAME = 128;
const MAX_NONCE_TEXT = 64;
const MAX_SERVER_FIRST = 512;
const MAX_CBIND_DATA = 64;
const MAX_SALT = 128;

const GS2_NO_BINDING = "n,,";
const GS2_END_POINT = "p=tls-server-end-point,,";

// --------------------------------------------------------- //

/// One SCRAM exchange. Create with init, then drive:
///
/// Usage:
/// ```zig
/// var scram = Scram.init(.SCRAM_SHA_256, "", password, nonce_text, "");
/// send(scram.clientFirst());
/// const client_final = try scram.handleServerFirst(server_first);
/// send(client_final);
/// try scram.handleServerFinal(server_final);
/// ```
pub const Scram = struct {
    mechanism: Mechanism,
    password: []const u8,
    cbind_data: []const u8,

    client_first_bare_buf: [4 + MAX_USERNAME + MAX_NONCE_TEXT]u8 = undefined,
    client_first_bare_len: usize = 0,

    server_first_buf: [MAX_SERVER_FIRST]u8 = undefined,
    server_first_len: usize = 0,

    client_final_buf: [1024]u8 = undefined,
    client_final_len: usize = 0,

    client_nonce_len: usize = 0,

    salted_password: [32]u8 = undefined,
    auth_message_buf: [2048]u8 = undefined,
    auth_message_len: usize = 0,

    /// Param:
    /// username - []const u8 (PostgreSQL ignores it, pass empty)
    /// nonce_text - []const u8 (printable random text, the caller generates it)
    /// cbind_data - []const u8 (server certificate hash for PLUS, empty otherwise)
    pub fn init(mechanism: Mechanism, username: []const u8, password: []const u8, nonce_text: []const u8, cbind_data: []const u8) ScramError!Scram {
        if (username.len > MAX_USERNAME) return error.PostgrezInputTooLong;
        if (nonce_text.len == 0 or nonce_text.len > MAX_NONCE_TEXT) return error.PostgrezInputTooLong;
        if (cbind_data.len > MAX_CBIND_DATA) return error.PostgrezInputTooLong;

        var self = Scram{
            .mechanism = mechanism,
            .password = password,
            .cbind_data = cbind_data,
        };

        var writer = std.Io.Writer.fixed(&self.client_first_bare_buf);
        writer.writeAll("n=") catch return error.PostgrezInputTooLong;
        writer.writeAll(username) catch return error.PostgrezInputTooLong;
        writer.writeAll(",r=") catch return error.PostgrezInputTooLong;
        writer.writeAll(nonce_text) catch return error.PostgrezInputTooLong;
        self.client_first_bare_len = writer.buffered().len;
        self.client_nonce_len = nonce_text.len;

        return self;
    }

    fn gs2Header(self: *const Scram) []const u8 {
        return switch (self.mechanism) {
            .SCRAM_SHA_256 => GS2_NO_BINDING,
            .SCRAM_SHA_256_PLUS => GS2_END_POINT,
        };
    }

    fn clientFirstBare(self: *const Scram) []const u8 {
        return self.client_first_bare_buf[0..self.client_first_bare_len];
    }

    /// The client-first message, gs2 header included. Valid until deinit of
    /// this struct, no allocation.
    pub fn clientFirst(self: *Scram, out: []u8) ScramError![]const u8 {
        const gs2 = self.gs2Header();
        const bare = self.clientFirstBare();
        if (gs2.len + bare.len > out.len) return error.PostgrezInputTooLong;

        @memcpy(out[0..gs2.len], gs2);
        @memcpy(out[gs2.len..][0..bare.len], bare);

        return out[0 .. gs2.len + bare.len];
    }

    /// Consume the server-first message and produce the client-final message.
    ///
    /// Return:
    /// - the client-final message, valid until the next call on this struct
    /// - error.PostgrezBadServerFirst on malformed attributes
    /// - error.PostgrezNonceMismatch when the server nonce does not extend ours
    pub fn handleServerFirst(self: *Scram, server_first: []const u8) ScramError![]const u8 {
        if (server_first.len > MAX_SERVER_FIRST) return error.PostgrezInputTooLong;

        @memcpy(self.server_first_buf[0..server_first.len], server_first);
        self.server_first_len = server_first.len;
        const kept = self.server_first_buf[0..self.server_first_len];

        var full_nonce: []const u8 = "";
        var salt_b64: []const u8 = "";
        var iterations: u32 = 0;

        var part_it = std.mem.splitScalar(u8, kept, ',');
        while (part_it.next()) |part| {
            if (attrValue(part, 'r')) |value| {
                full_nonce = value;
            } else if (attrValue(part, 's')) |value| {
                salt_b64 = value;
            } else if (attrValue(part, 'i')) |value| {
                iterations = std.fmt.parseInt(u32, value, 10) catch return error.PostgrezBadServerFirst;
            } else if (attrValue(part, 'm')) |_| {
                return error.PostgrezBadServerFirst;
            }
        }
        if (full_nonce.len == 0 or salt_b64.len == 0 or iterations == 0) return error.PostgrezBadServerFirst;

        const client_nonce = self.clientFirstBare()[self.client_first_bare_len - self.client_nonce_len ..];
        if (full_nonce.len <= client_nonce.len) return error.PostgrezNonceMismatch;
        if (!std.mem.startsWith(u8, full_nonce, client_nonce)) return error.PostgrezNonceMismatch;

        var salt_buf: [MAX_SALT]u8 = undefined;
        const salt_len = std.base64.standard.Decoder.calcSizeForSlice(salt_b64) catch return error.PostgrezBadServerFirst;
        if (salt_len > salt_buf.len) return error.PostgrezBadServerFirst;
        std.base64.standard.Decoder.decode(salt_buf[0..salt_len], salt_b64) catch return error.PostgrezBadServerFirst;

        std.crypto.pwhash.pbkdf2(&self.salted_password, self.password, salt_buf[0..salt_len], iterations, HmacSha256) catch return error.PostgrezBadServerFirst;

        // client-final-without-proof: c=<b64(gs2 + cbind)>,r=<full nonce>
        var final_writer = std.Io.Writer.fixed(&self.client_final_buf);
        var cbind_input: [GS2_END_POINT.len + MAX_CBIND_DATA]u8 = undefined;
        const gs2 = self.gs2Header();
        @memcpy(cbind_input[0..gs2.len], gs2);
        @memcpy(cbind_input[gs2.len..][0..self.cbind_data.len], self.cbind_data);
        var cbind_b64: [std.base64.standard.Encoder.calcSize(cbind_input.len)]u8 = undefined;
        const cbind_encoded = std.base64.standard.Encoder.encode(&cbind_b64, cbind_input[0 .. gs2.len + self.cbind_data.len]);

        final_writer.writeAll("c=") catch return error.PostgrezInputTooLong;
        final_writer.writeAll(cbind_encoded) catch return error.PostgrezInputTooLong;
        final_writer.writeAll(",r=") catch return error.PostgrezInputTooLong;
        final_writer.writeAll(full_nonce) catch return error.PostgrezInputTooLong;

        // AuthMessage = client-first-bare , server-first , client-final-without-proof
        var auth_writer = std.Io.Writer.fixed(&self.auth_message_buf);
        auth_writer.writeAll(self.clientFirstBare()) catch return error.PostgrezInputTooLong;
        auth_writer.writeAll(",") catch return error.PostgrezInputTooLong;
        auth_writer.writeAll(kept) catch return error.PostgrezInputTooLong;
        auth_writer.writeAll(",") catch return error.PostgrezInputTooLong;
        auth_writer.writeAll(final_writer.buffered()) catch return error.PostgrezInputTooLong;
        self.auth_message_len = auth_writer.buffered().len;

        // ClientProof = ClientKey XOR HMAC(SHA256(ClientKey), AuthMessage)
        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &self.salted_password);

        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        var client_signature: [32]u8 = undefined;
        HmacSha256.create(&client_signature, self.authMessage(), &stored_key);

        var proof: [32]u8 = undefined;
        for (&proof, client_key, client_signature) |*out_byte, key_byte, sig_byte| {
            out_byte.* = key_byte ^ sig_byte;
        }

        var proof_b64: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
        const proof_encoded = std.base64.standard.Encoder.encode(&proof_b64, &proof);

        final_writer.writeAll(",p=") catch return error.PostgrezInputTooLong;
        final_writer.writeAll(proof_encoded) catch return error.PostgrezInputTooLong;
        self.client_final_len = final_writer.buffered().len;

        return self.client_final_buf[0..self.client_final_len];
    }

    /// Verify the server-final message (server signature proves the server
    /// also knows the verifier).
    ///
    /// Return:
    /// - void when the signature matches
    /// - error.PostgrezServerRejected on an e= attribute
    /// - error.PostgrezServerSignatureMismatch on a wrong v= value
    pub fn handleServerFinal(self: *Scram, server_final: []const u8) ScramError!void {
        var part_it = std.mem.splitScalar(u8, server_final, ',');
        const first = part_it.next() orelse return error.PostgrezBadServerFinal;

        if (attrValue(first, 'e')) |_| return error.PostgrezServerRejected;
        const verifier_b64 = attrValue(first, 'v') orelse return error.PostgrezBadServerFinal;

        var expected: [32]u8 = undefined;
        const expected_len = std.base64.standard.Decoder.calcSizeForSlice(verifier_b64) catch return error.PostgrezBadServerFinal;
        if (expected_len != expected.len) return error.PostgrezBadServerFinal;
        std.base64.standard.Decoder.decode(&expected, verifier_b64) catch return error.PostgrezBadServerFinal;

        var server_key: [32]u8 = undefined;
        HmacSha256.create(&server_key, "Server Key", &self.salted_password);

        var server_signature: [32]u8 = undefined;
        HmacSha256.create(&server_signature, self.authMessage(), &server_key);

        if (!std.mem.eql(u8, &server_signature, &expected)) return error.PostgrezServerSignatureMismatch;
    }

    fn authMessage(self: *const Scram) []const u8 {
        return self.auth_message_buf[0..self.auth_message_len];
    }
};

fn attrValue(part: []const u8, code: u8) ?[]const u8 {
    if (part.len < 2 or part[0] != code or part[1] != '=') return null;

    return part[2..];
}

/// Encode 18 random bytes (from io.random) into printable nonce text.
pub fn encodeNonce(raw: [18]u8, out: *[24]u8) void {
    _ = std.base64.standard.Encoder.encode(out, &raw);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

// RFC 7677 section 3 example exchange (password "pencil").
const RFC_USER = "user";
const RFC_PASSWORD = "pencil";
const RFC_CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO";
const RFC_SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const RFC_CLIENT_FINAL = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const RFC_SERVER_FINAL = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

test "postgrez auth: scram client-first matches RFC 7677 vector" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    const client_first = try scram.clientFirst(&buf);

    try testing.expectEqualStrings("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", client_first);
}

test "postgrez auth: scram client-final and server verify match RFC 7677 vector" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);

    const client_final = try scram.handleServerFirst(RFC_SERVER_FIRST);
    try testing.expectEqualStrings(RFC_CLIENT_FINAL, client_final);

    try scram.handleServerFinal(RFC_SERVER_FINAL);
}

test "postgrez auth: scram rejects a wrong server signature" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);
    _ = try scram.handleServerFirst(RFC_SERVER_FIRST);

    try testing.expectError(
        error.PostgrezServerSignatureMismatch,
        scram.handleServerFinal("v=aaaaTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
    );
}

test "postgrez auth: scram rejects a server error reply" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);
    _ = try scram.handleServerFirst(RFC_SERVER_FIRST);

    try testing.expectError(error.PostgrezServerRejected, scram.handleServerFinal("e=invalid-proof"));
}

test "postgrez auth: scram rejects a nonce that does not extend ours" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);

    try testing.expectError(
        error.PostgrezNonceMismatch,
        scram.handleServerFirst("r=XXXXNGfwEbeRWgbNEkqOtail,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"),
    );
}

test "postgrez auth: scram rejects malformed server-first" {
    var scram = try Scram.init(.SCRAM_SHA_256, RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE, "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);

    try testing.expectError(error.PostgrezBadServerFirst, scram.handleServerFirst("s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"));
}

test "postgrez auth: scram PLUS binds the channel into gs2 and c=" {
    const cbind: [32]u8 = @splat(0xAB);
    var scram = try Scram.init(.SCRAM_SHA_256_PLUS, "", RFC_PASSWORD, RFC_CLIENT_NONCE, &cbind);

    var buf: [256]u8 = undefined;
    const client_first = try scram.clientFirst(&buf);
    try testing.expectEqualStrings("p=tls-server-end-point,,n=,r=rOprNGfwEbeRWgbNEkqO", client_first);

    const client_final = try scram.handleServerFirst(RFC_SERVER_FIRST);

    var cbind_input: [GS2_END_POINT.len + 32]u8 = undefined;
    @memcpy(cbind_input[0..GS2_END_POINT.len], GS2_END_POINT);
    @memcpy(cbind_input[GS2_END_POINT.len..], &cbind);
    var expected_b64: [std.base64.standard.Encoder.calcSize(cbind_input.len)]u8 = undefined;
    const expected_c = std.base64.standard.Encoder.encode(&expected_b64, &cbind_input);

    var prefix_buf: [128]u8 = undefined;
    const expected_prefix = try std.fmt.bufPrint(&prefix_buf, "c={s},r=", .{expected_c});
    try testing.expect(std.mem.startsWith(u8, client_final, expected_prefix));
}

test "postgrez auth: scram full loop against a local verifier" {
    // A minimal server side built from the same primitives, checking the
    // client proof the way PostgreSQL does (RFC 5802 server steps).
    const password = "s3cret";
    const salt = "0123456789abcdef";
    const iterations: u32 = 4096;

    var scram = try Scram.init(.SCRAM_SHA_256, "", password, "clientnoncetext_", "");

    var buf: [256]u8 = undefined;
    _ = try scram.clientFirst(&buf);

    var salt_b64: [std.base64.standard.Encoder.calcSize(salt.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&salt_b64, salt);

    var server_first_buf: [200]u8 = undefined;
    const server_first = try std.fmt.bufPrint(&server_first_buf, "r=clientnoncetext_SERVER,s={s},i={d}", .{ salt_b64, iterations });

    const client_final = try scram.handleServerFirst(server_first);

    // Server side: recover the proof, derive StoredKey, verify.
    const proof_b64 = client_final[std.mem.lastIndexOf(u8, client_final, ",p=").? + 3 ..];
    var proof: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&proof, proof_b64);

    var salted: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, password, salt, iterations, HmacSha256);

    var client_key: [32]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted);
    var stored_key: [32]u8 = undefined;
    Sha256.hash(&client_key, &stored_key, .{});

    var signature: [32]u8 = undefined;
    HmacSha256.create(&signature, scram.authMessage(), &stored_key);

    var recovered_key: [32]u8 = undefined;
    for (&recovered_key, proof, signature) |*out_byte, proof_byte, sig_byte| {
        out_byte.* = proof_byte ^ sig_byte;
    }

    var recovered_stored: [32]u8 = undefined;
    Sha256.hash(&recovered_key, &recovered_stored, .{});
    try testing.expectEqualSlices(u8, &stored_key, &recovered_stored);

    // And the client accepts the matching server signature.
    var server_key: [32]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted);
    var server_signature: [32]u8 = undefined;
    HmacSha256.create(&server_signature, scram.authMessage(), &server_key);

    var verifier_b64: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
    const verifier = std.base64.standard.Encoder.encode(&verifier_b64, &server_signature);

    var final_buf: [64]u8 = undefined;
    const server_final = try std.fmt.bufPrint(&final_buf, "v={s}", .{verifier});
    try scram.handleServerFinal(server_final);
}

test "postgrez auth: encodeNonce yields printable base64 text" {
    var raw: [18]u8 = undefined;
    for (&raw, 0..) |*byte, index| byte.* = @intCast(index * 13 % 256);

    var nonce: [24]u8 = undefined;
    encodeNonce(raw, &nonce);

    for (nonce) |byte| {
        const printable = (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or byte == '+' or byte == '/' or byte == '=';
        try testing.expect(printable);
    }
}
