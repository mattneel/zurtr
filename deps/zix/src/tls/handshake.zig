//! TLS 1.3 handshake flow + version negotiation (RFC 8446 section 4).
//!
//! Note:
//! - Server side: parse a ClientHello, negotiate version / cipher / group, and serialize the
//!   ServerHello. The crypto (key schedule, record protection) is key_schedule.zig + record.zig.
//! - Wire registries are enums with UPPER_CASE values (matching Content.Type / gRPC Code),
//!   non-exhaustive (`_`) so an unknown value from a peer is still representable.
//! - Verified against the RFC 8448 trace in-file (byte-exact ServerHello).

const std = @import("std");
const wire = @import("wire.zig");
const alert = @import("alert.zig");

const Reader = wire.Reader;
const Writer = wire.Writer;
const Alert = alert.Alert;

/// Max key_share groups parsed from a ClientHello (the offered curves cap).
const MAX_KEY_SHARE_GROUPS: usize = 16;

/// legacy_version on the wire (RFC 8446 4.1.2): 1.2 in the record / hello, 1.3 in supported_versions.
pub const VERSION_TLS_1_2: u16 = 0x0303;
pub const VERSION_TLS_1_3: u16 = 0x0304;

pub const HandshakeType = enum(u8) {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE_REQUEST = 13,
    CERTIFICATE = 11,
    CERTIFICATE_VERIFY = 15,
    FINISHED = 20,
    _,
};

pub const ExtensionType = enum(u16) {
    SERVER_NAME = 0x0000,
    SUPPORTED_GROUPS = 0x000a,
    SIGNATURE_ALGORITHMS = 0x000d,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010,
    RECORD_SIZE_LIMIT = 0x001c,
    SUPPORTED_VERSIONS = 0x002b,
    KEY_SHARE = 0x0033,
    _,
};

pub const CipherSuite = enum(u16) {
    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,
    /// TLS 1.2 ECDHE-ECDSA-AES128-GCM-SHA256 (RFC 5289). Carried in this enum so a single config
    /// cipher list can span 1.2 and 1.3. It is the 1.2 floor suite, not part of the 1.3 negotiate
    /// (server_cipher_prefs), where only the 0x13xx suites apply.
    ECDHE_ECDSA_AES128_GCM_SHA256 = 0xc02b,
    _,
};

pub const NamedGroup = enum(u16) {
    SECP256R1 = 0x0017,
    X25519 = 0x001d,
    _,
};

pub const SignatureScheme = enum(u16) {
    RSA_PKCS1_SHA256 = 0x0401,
    ECDSA_SECP256R1_SHA256 = 0x0403,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    ED25519 = 0x0807,
    _,
};

/// Server crypto preference order, mandatory-to-implement first (RFC 8446 9.1). Only
/// TLS_AES_128_GCM_SHA256 is offered: the key schedule is SHA-256 throughout (Secret = [32]u8),
/// so AES_256_GCM_SHA384 (SHA-384) and CHACHA20_POLY1305_SHA256 (different AEAD) are future work,
/// gated on generalizing the hash / AEAD. Listing only the implemented suite keeps negotiate()
/// from ever selecting one the connection layer cannot honor.
pub const server_cipher_prefs = [_]CipherSuite{.AES_128_GCM_SHA256};
/// secp256r1 and X25519 ECDHE are both implemented (connection.computeKeyExchange), X25519 first.
pub const server_group_prefs = [_]NamedGroup{ .X25519, .SECP256R1 };

// --------------------------------------------------------------- //

/// The parsed ClientHello fields the server needs (RFC 8446 4.1.2).
pub const ClientHello = struct {
    legacy_version: u16,
    random: [32]u8,
    session_id: []const u8,
    cipher_suites: []const u8,
    offers_tls13: bool = false,
    has_signature_algorithms: bool = false,
    has_supported_groups: bool = false,
    supported_groups: []const u8 = &.{},
    /// The raw SignatureSchemeList body (RFC 8446 4.2.3), each entry a u16. The server picks its
    /// CertificateVerify scheme from this via offersSignatureScheme. Empty when not offered.
    signature_schemes: []const u8 = &.{},
    key_share_groups: [MAX_KEY_SHARE_GROUPS]NamedGroup = undefined,
    key_share_count: usize = 0,
    x25519_share: ?[]const u8 = null,
    secp256r1_share: ?[]const u8 = null,
    sni: ?[]const u8 = null,
    /// The raw ProtocolNameList body of the ALPN extension (RFC 7301), null when not offered.
    /// Fed to extensions.negotiateAlpn to select one protocol.
    alpn: ?[]const u8 = null,

    pub fn offersCipher(self: *const ClientHello, suite: CipherSuite) bool {
        var r = Reader{ .buf = self.cipher_suites };
        while (r.remaining() >= 2) {
            if ((r.readU16() catch return false) == @intFromEnum(suite)) return true;
        }

        return false;
    }

    pub fn offersGroup(self: *const ClientHello, group: NamedGroup) bool {
        var r = Reader{ .buf = self.supported_groups };
        while (r.remaining() >= 2) {
            if ((r.readU16() catch return false) == @intFromEnum(group)) return true;
        }

        return false;
    }

    pub fn hasKeyShare(self: *const ClientHello, group: NamedGroup) bool {
        for (self.key_share_groups[0..self.key_share_count]) |g| {
            if (g == group) return true;
        }

        return false;
    }

    /// Whether the client offered the given signature scheme in signature_algorithms (RFC 8446
    /// 4.2.3). The server uses this to confirm it can sign CertificateVerify with its key's scheme.
    pub fn offersSignatureScheme(self: *const ClientHello, scheme: SignatureScheme) bool {
        var r = Reader{ .buf = self.signature_schemes };
        while (r.remaining() >= 2) {
            if ((r.readU16() catch return false) == @intFromEnum(scheme)) return true;
        }

        return false;
    }
};

pub const ParseResult = union(enum) {
    ok: ClientHello,
    alert: Alert,
};

const ParseError = error{ ZixTruncated, ZixIllegalParameter };

/// Parse a ClientHello message into its fields, or the fatal alert it triggers.
pub fn parseClientHello(bytes: []const u8) ParseResult {
    const hello = parseClientHelloInner(bytes) catch |err| return .{ .alert = switch (err) {
        error.ZixIllegalParameter => .ILLEGAL_PARAMETER,
        error.ZixTruncated => .DECODE_ERROR,
    } };

    return .{ .ok = hello };
}

fn parseClientHelloInner(bytes: []const u8) ParseError!ClientHello {
    var r = Reader{ .buf = bytes };

    if (try r.readU8() != @intFromEnum(HandshakeType.CLIENT_HELLO)) return error.ZixIllegalParameter;
    _ = try r.readU24();

    const legacy_version = try r.readU16();
    const random = try r.readBytes(32);
    const session_id_len = try r.readU8();
    const session_id = try r.readBytes(session_id_len);

    const cipher_suites_len = try r.readU16();
    const cipher_suites = try r.readBytes(cipher_suites_len);

    const compression_len = try r.readU8();
    const compression = try r.readBytes(compression_len);
    if (compression_len != 1 or compression[0] != 0) return error.ZixIllegalParameter;

    var hello = ClientHello{
        .legacy_version = legacy_version,
        .random = undefined,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
    };
    @memcpy(&hello.random, random);

    const extensions_len = try r.readU16();
    const extensions = try r.readBytes(extensions_len);
    try parseClientExtensions(&hello, extensions);

    return hello;
}

fn parseClientExtensions(hello: *ClientHello, extensions: []const u8) ParseError!void {
    var r = Reader{ .buf = extensions };
    while (r.remaining() >= 4) {
        const ext_type: ExtensionType = @enumFromInt(try r.readU16());
        const ext_len = try r.readU16();
        const ext_data = try r.readBytes(ext_len);

        switch (ext_type) {
            .SUPPORTED_VERSIONS => {
                var er = Reader{ .buf = ext_data };
                const list_len = try er.readU8();
                const list = try er.readBytes(list_len);
                var lr = Reader{ .buf = list };
                while (lr.remaining() >= 2) {
                    if (try lr.readU16() == VERSION_TLS_1_3) hello.offers_tls13 = true;
                }
            },
            .SUPPORTED_GROUPS => {
                hello.has_supported_groups = true;
                var er = Reader{ .buf = ext_data };
                const list_len = try er.readU16();
                hello.supported_groups = try er.readBytes(list_len);
            },
            .SIGNATURE_ALGORITHMS => {
                hello.has_signature_algorithms = true;
                var er = Reader{ .buf = ext_data };
                const list_len = try er.readU16();
                hello.signature_schemes = try er.readBytes(list_len);
            },
            .APPLICATION_LAYER_PROTOCOL_NEGOTIATION => hello.alpn = ext_data,
            .KEY_SHARE => try parseKeyShare(hello, ext_data),
            .SERVER_NAME => {
                var er = Reader{ .buf = ext_data };
                _ = try er.readU16();
                _ = try er.readU8();
                const name_len = try er.readU16();
                hello.sni = try er.readBytes(name_len);
            },
            else => {},
        }
    }
}

fn parseKeyShare(hello: *ClientHello, ext_data: []const u8) ParseError!void {
    var er = Reader{ .buf = ext_data };
    const shares_len = try er.readU16();
    const shares = try er.readBytes(shares_len);

    var sr = Reader{ .buf = shares };
    while (sr.remaining() >= 4) {
        const group: NamedGroup = @enumFromInt(try sr.readU16());
        const ke_len = try sr.readU16();
        const ke = try sr.readBytes(ke_len);

        if (hello.key_share_count < hello.key_share_groups.len) {
            hello.key_share_groups[hello.key_share_count] = group;
            hello.key_share_count += 1;
        }
        if (group == .X25519) hello.x25519_share = ke;
        if (group == .SECP256R1) hello.secp256r1_share = ke;
    }
}

// --------------------------------------------------------------- //

pub const ServerHelloParams = struct {
    cipher: CipherSuite,
    group: NamedGroup,
    key_exchange: []const u8,
};

/// Negotiation outcome. The lower_case tags follow the internal control-flow enum exception
/// (the same shape as ConnOutcome), not the public UPPER_CASE enum rule.
pub const Outcome = union(enum) {
    server_hello: ServerHelloParams,
    hello_retry_request: NamedGroup,
    legacy_version,
    alert: Alert,
};

/// Negotiate version, cipher, and group from a parsed ClientHello (RFC 8446 4.1.1, 9.1). group_prefs
/// is the configured curve preference order (Tls.Context.curves), so a server that restricts or
/// reorders its curves is honored here rather than always using the built-in default order.
pub fn negotiate(hello: *const ClientHello, key_exchange: []const u8, group_prefs: []const NamedGroup) Outcome {
    if (!hello.offers_tls13) return .legacy_version;

    if (!hello.has_signature_algorithms or !hello.has_supported_groups) return .{ .alert = .MISSING_EXTENSION };

    const cipher = pickCipher(hello) orelse return .{ .alert = .HANDSHAKE_FAILURE };
    const group = pickGroup(hello, group_prefs) orelse return .{ .alert = .HANDSHAKE_FAILURE };

    if (!hello.hasKeyShare(group)) return .{ .hello_retry_request = group };

    return .{ .server_hello = .{ .cipher = cipher, .group = group, .key_exchange = key_exchange } };
}

fn pickCipher(hello: *const ClientHello) ?CipherSuite {
    for (server_cipher_prefs) |suite| {
        if (hello.offersCipher(suite)) return suite;
    }

    return null;
}

/// Pick the first configured curve the client also offered (server-preference order). group_prefs is
/// the server's curve list, already validated to the implemented set (X25519 / secp256r1).
fn pickGroup(hello: *const ClientHello, group_prefs: []const NamedGroup) ?NamedGroup {
    for (group_prefs) |group| {
        if (hello.offersGroup(group)) return group;
    }

    return null;
}

// --------------------------------------------------------------- //

/// Serialize a ServerHello message (RFC 8446 4.1.3) into `buf`, returning the wire slice.
pub fn serializeServerHello(buf: []u8, random: []const u8, session_id: []const u8, params: ServerHelloParams) []const u8 {
    var w = Writer{ .buf = buf };

    w.writeU8(@intFromEnum(HandshakeType.SERVER_HELLO));
    const header = w.placeU24();

    w.writeU16(VERSION_TLS_1_2);
    w.writeBytes(random);
    w.writeU8(@intCast(session_id.len));
    w.writeBytes(session_id);
    w.writeU16(@intFromEnum(params.cipher));
    w.writeU8(0);

    const extensions = w.placeU16();

    w.writeU16(@intFromEnum(ExtensionType.KEY_SHARE));
    const key_share = w.placeU16();
    w.writeU16(@intFromEnum(params.group));
    const key_exchange = w.placeU16();
    w.writeBytes(params.key_exchange);
    w.patchU16(key_exchange);
    w.patchU16(key_share);

    w.writeU16(@intFromEnum(ExtensionType.SUPPORTED_VERSIONS));
    const supported_versions = w.placeU16();
    w.writeU16(VERSION_TLS_1_3);
    w.patchU16(supported_versions);

    w.patchU16(extensions);
    w.patchU24(header);

    return w.slice();
}

/// The fixed HelloRetryRequest sentinel placed in ServerHello.random (RFC 8446 4.1.3): the SHA-256
/// of the string "HelloRetryRequest". A ServerHello carrying this random IS a HelloRetryRequest.
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// Serialize a HelloRetryRequest (RFC 8446 4.1.4): a ServerHello carrying the HRR random sentinel,
/// supported_versions (0x0304), and a key_share extension naming ONLY the group the client must
/// retry with (a KeyShareHelloRetryRequest, no key bytes). Sent when the server picked a group the
/// client supports but did not provide a key_share for.
pub fn serializeHelloRetryRequest(buf: []u8, session_id: []const u8, cipher: CipherSuite, group: NamedGroup) []const u8 {
    var w = Writer{ .buf = buf };

    w.writeU8(@intFromEnum(HandshakeType.SERVER_HELLO));
    const header = w.placeU24();

    w.writeU16(VERSION_TLS_1_2);
    w.writeBytes(&hello_retry_request_random);
    w.writeU8(@intCast(session_id.len));
    w.writeBytes(session_id);
    w.writeU16(@intFromEnum(cipher));
    w.writeU8(0);

    const extensions = w.placeU16();

    w.writeU16(@intFromEnum(ExtensionType.SUPPORTED_VERSIONS));
    const supported_versions = w.placeU16();
    w.writeU16(VERSION_TLS_1_3);
    w.patchU16(supported_versions);

    w.writeU16(@intFromEnum(ExtensionType.KEY_SHARE));
    const key_share = w.placeU16();
    w.writeU16(@intFromEnum(group)); // KeyShareHelloRetryRequest: the selected group only
    w.patchU16(key_share);

    w.patchU16(extensions);
    w.patchU24(header);

    return w.slice();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: handshake, RFC 8448 ClientHello parse + negotiate + ServerHello byte-exact" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    var server_hello: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_hello, "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");

    var server_random: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_random, "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
    var server_public: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_public, "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");

    const parsed = parseClientHello(&client_hello);
    try std.testing.expect(parsed == .ok);
    const hello = parsed.ok;
    try std.testing.expect(hello.offers_tls13);
    try std.testing.expect(hello.has_signature_algorithms and hello.has_supported_groups);
    try std.testing.expect(hello.hasKeyShare(.X25519));
    try std.testing.expectEqualStrings("server", hello.sni orelse "");

    const outcome = negotiate(&hello, &server_public, &server_group_prefs);
    try std.testing.expect(outcome == .server_hello);
    try std.testing.expectEqual(CipherSuite.AES_128_GCM_SHA256, outcome.server_hello.cipher);
    try std.testing.expectEqual(NamedGroup.X25519, outcome.server_hello.group);

    var sh_buf: [256]u8 = undefined;
    const sh = serializeServerHello(&sh_buf, &server_random, hello.session_id, outcome.server_hello);
    try std.testing.expectEqualSlices(u8, &server_hello, sh);
}

test "zix tls: handshake, negotiate honors the configured curve preference order" {
    // The RFC 8448 ClientHello offers x25519 + secp256r1 in supported_groups but sends a key_share
    // only for x25519. Changing the server curve order must change the outcome (the Tls.Context.curves
    // honesty boundary), proving group_prefs is threaded into negotiation rather than hardcoded.
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    const parsed = parseClientHello(&client_hello);
    try std.testing.expect(parsed == .ok);
    const hello = parsed.ok;

    // default order prefers X25519, for which the client sent a key_share -> direct ServerHello.
    const default_pick = negotiate(&hello, &.{}, &server_group_prefs);
    try std.testing.expect(default_pick == .server_hello);
    try std.testing.expectEqual(NamedGroup.X25519, default_pick.server_hello.group);

    // reordering to prefer secp256r1 is honored: the client offered it but sent no key_share, so the
    // server asks for a HelloRetryRequest on that group instead of falling back to x25519.
    const reordered = negotiate(&hello, &.{}, &[_]NamedGroup{ .SECP256R1, .X25519 });
    try std.testing.expect(reordered == .hello_retry_request);
    try std.testing.expectEqual(NamedGroup.SECP256R1, reordered.hello_retry_request);

    // restricting the server to only x25519 still selects it.
    const restricted = negotiate(&hello, &.{}, &[_]NamedGroup{.X25519});
    try std.testing.expect(restricted == .server_hello);
    try std.testing.expectEqual(NamedGroup.X25519, restricted.server_hello.group);
}

test "zix tls: handshake, ClientHello captures the ALPN protocol list" {
    var buf: [256]u8 = undefined;
    var w = Writer{ .buf = &buf };

    w.writeU8(@intFromEnum(HandshakeType.CLIENT_HELLO));
    const header = w.placeU24();
    w.writeU16(VERSION_TLS_1_2);
    const zero_random = std.mem.zeroes([32]u8);
    w.writeBytes(&zero_random); // random
    w.writeU8(0); // empty session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(@intFromEnum(CipherSuite.AES_128_GCM_SHA256));
    w.writeU8(1); // compression length
    w.writeU8(0); // null compression

    const exts = w.placeU16();
    w.writeU16(@intFromEnum(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION));
    const ext = w.placeU16();
    const list = w.placeU16();
    w.writeU8(2);
    w.writeBytes("h2");
    w.writeU8(8);
    w.writeBytes("http/1.1");
    w.patchU16(list);
    w.patchU16(ext);
    w.patchU16(exts);
    w.patchU24(header);

    const parsed = parseClientHello(w.slice());
    try std.testing.expect(parsed == .ok);
    try std.testing.expect(parsed.ok.alpn != null);

    const extensions = @import("extensions.zig");
    const prefs = [_]extensions.Alpn{ .H2, .HTTP_1_1 };
    try std.testing.expectEqual(extensions.Alpn.H2, extensions.negotiateAlpn(parsed.ok.alpn.?, &prefs).?);
}

test "zix tls: handshake, an unknown extension (cookie 0x002c) is parsed past, not rejected" {
    // A server that never emits HelloRetryRequest never asks for a cookie, so a cookie in the
    // initial ClientHello is ignored (RFC 8446 4.2.2). It must not break parsing of the rest.
    var buf: [256]u8 = undefined;
    var w = Writer{ .buf = &buf };

    w.writeU8(@intFromEnum(HandshakeType.CLIENT_HELLO));
    const header = w.placeU24();
    w.writeU16(VERSION_TLS_1_2);
    const zero_random = std.mem.zeroes([32]u8);
    w.writeBytes(&zero_random);
    w.writeU8(0); // empty session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(@intFromEnum(CipherSuite.AES_128_GCM_SHA256));
    w.writeU8(1); // compression length
    w.writeU8(0); // null compression

    const exts = w.placeU16();
    // cookie (0x002c): an opaque cookie<1..2^16-1>, here 3 bytes. Comes BEFORE a known extension.
    w.writeU16(0x002c);
    const cookie_ext = w.placeU16();
    const cookie_body = w.placeU16();
    w.writeBytes(&[_]u8{ 0xAA, 0xBB, 0xCC });
    w.patchU16(cookie_body);
    w.patchU16(cookie_ext);
    // supported_versions advertising TLS 1.3, parsed AFTER the ignored cookie.
    w.writeU16(@intFromEnum(ExtensionType.SUPPORTED_VERSIONS));
    w.writeU16(3);
    w.writeU8(2);
    w.writeU16(VERSION_TLS_1_3);
    w.patchU16(exts);
    w.patchU24(header);

    const parsed = parseClientHello(w.slice());
    try std.testing.expect(parsed == .ok);
    try std.testing.expect(parsed.ok.offers_tls13); // the post-cookie extension was still reached
}

test "zix tls: handshake, serializeHelloRetryRequest carries the HRR random + selected group" {
    var buf: [128]u8 = undefined;
    const hrr = serializeHelloRetryRequest(&buf, &.{}, .AES_128_GCM_SHA256, .X25519);

    // ServerHello message type, then (after type[1] + len[3] + legacy_version[2]) the 32-byte random.
    try std.testing.expectEqual(@intFromEnum(HandshakeType.SERVER_HELLO), hrr[0]);
    try std.testing.expectEqualSlices(u8, &hello_retry_request_random, hrr[6..38]);

    // the key_share extension must name the group the client has to retry with (x25519, 0x001d).
    try std.testing.expect(std.mem.indexOf(u8, hrr, &[_]u8{ 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d }) != null);
}

test "zix tls: handshake, offersSignatureScheme matches the offered list (Layer C)" {
    // a SignatureSchemeList body: ecdsa_secp256r1_sha256 (0x0403) then ed25519 (0x0807).
    const schemes = [_]u8{ 0x04, 0x03, 0x08, 0x07 };
    const hello = ClientHello{
        .legacy_version = VERSION_TLS_1_2,
        .random = std.mem.zeroes([32]u8),
        .session_id = &.{},
        .cipher_suites = &.{},
        .signature_schemes = &schemes,
    };

    try std.testing.expect(hello.offersSignatureScheme(.ECDSA_SECP256R1_SHA256));
    try std.testing.expect(hello.offersSignatureScheme(.ED25519));
    try std.testing.expect(!hello.offersSignatureScheme(@enumFromInt(0x0401))); // rsa_pkcs1_sha256, not offered
    try std.testing.expect(!hello.offersSignatureScheme(@enumFromInt(0x0203))); // ecdsa_sha1, never offered

    // a client that offered no signature_algorithms offers nothing.
    const none = ClientHello{
        .legacy_version = VERSION_TLS_1_2,
        .random = std.mem.zeroes([32]u8),
        .session_id = &.{},
        .cipher_suites = &.{},
    };
    try std.testing.expect(!none.offersSignatureScheme(.ECDSA_SECP256R1_SHA256));
}

test "zix tls: handshake, negatives (compression, no TLS 1.3)" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    // compression method byte (offset 48) flipped to 1 -> illegal_parameter (RFC 8446 4.1.2).
    var bad_compression = client_hello;
    bad_compression[48] = 1;
    const r1 = parseClientHello(&bad_compression);
    try std.testing.expect(r1 == .alert and r1.alert == .ILLEGAL_PARAMETER);

    // supported_versions 0x0304 (offsets 146-147) -> 0x0303 -> no TLS 1.3.
    var no_tls13 = client_hello;
    no_tls13[146] = 0x03;
    no_tls13[147] = 0x03;
    const r2 = parseClientHello(&no_tls13);
    try std.testing.expect(r2 == .ok and !r2.ok.offers_tls13);
    try std.testing.expect(negotiate(&r2.ok, &[_]u8{}, &server_group_prefs) == .legacy_version);
}
