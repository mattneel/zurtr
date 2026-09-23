//! zix server-side TLS context (the loaded cert/key + validated policy, the SSL_CTX analog).
//!
//! Note:
//! - zix.Tls is sans-I/O and has no listener, so this is a CONTEXT, not a server: it holds the
//!   material the HTTP engine reads per connection, built once on the cold path. The HTTP server
//!   config attaches it by pointer (tls: ?*Tls.Context), mirroring the logger (logger: ?*Logger).
//! - Config is plain settings (what the user writes). Context is the live object (what the engine
//!   reads). init loads + validates ONCE, so the per-connection serve path sees a ready Context.
//! - Curves and ciphers are validated allow-lists: an unsupported value is a startup error, never a
//!   silent no-op. The implemented set widens as crypto lands, with no API change.

const std = @import("std");
const handshake = @import("handshake.zig");
const connection = @import("connection.zig");
const certificate = @import("certificate.zig");
const extensions = @import("extensions.zig");
const pem = @import("pem.zig");
const rsa = @import("rsa.zig");

const Alpn = extensions.Alpn;
const NamedGroup = handshake.NamedGroup;
const CipherSuite = handshake.CipherSuite;
const SigningKey = certificate.SigningKey;
const HandshakeOptions = connection.HandshakeOptions;

/// Widest PEM file the context will read. A certificate chain or a private key past this is a
/// configuration mistake, not a large key, so the read stops rather than allocating for it.
const PEM_MAX_BYTES: usize = 1 << 20;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

/// TLS version floor / ceiling for the bind policy. The valid range is TLS_1_2..TLS_1_3 (1.0 / 1.1
/// are deprecated by RFC 8996 and never offered). Values order numerically for min <= max checks.
pub const Version = enum(u8) {
    TLS_1_2 = 0x12,
    TLS_1_3 = 0x13,
};

/// The curves zix actually implements, server-preference order (X25519 first).
pub const default_curves = &[_]NamedGroup{ .X25519, .SECP256R1 };
/// The AEAD suites zix actually implements: AES-128-GCM for 1.3, ECDHE-ECDSA-AES128-GCM for 1.2.
pub const default_ciphers = &[_]CipherSuite{ .AES_128_GCM_SHA256, .ECDHE_ECDSA_AES128_GCM_SHA256 };

/// Server-side TLS configuration (the settings the user fills in). Plain POD, like Logger.Config.
/// Tls.Context.init reads + validates this ONCE on the cold path, then the engine reads the
/// resulting Context per connection. Omitting the optional fields yields the secure default
/// (forward secrecy + AEAD, ECDHE-only).
pub const Config = struct {
    /// PEM path to the end-entity certificate (ECDSA P-256, Ed25519, or RSA). Required.
    cert_path: []const u8,
    /// PEM path to the private key matching cert_path. Required.
    key_path: []const u8,

    /// ALPN protocols offered, in server-preference order. Empty = no ALPN.
    /// Http1: .{ .HTTP_1_1 }. Http2 over TLS: .{ .H2 } (optionally .{ .H2, .HTTP_1_1 }).
    alpn: []const Alpn = &.{},

    /// Version floor / ceiling (RFC 8446 / 5246). Valid range TLS_1_2..TLS_1_3.
    /// 1.0 / 1.1 are never offered (RFC 8996). Default = TLS 1.2 floor, 1.3 preferred.
    min_version: Version = .TLS_1_2,
    max_version: Version = .TLS_1_3,

    /// ECDHE curves in server-preference order. Validated at init: an unsupported value
    /// (P384, MLKEM768) returns error.ZixTlsUnsupportedCurve, never a silent drop.
    curves: []const NamedGroup = default_curves,
    /// AEAD cipher suites in preference order, spanning 1.3 and 1.2. Same validate-or-reject
    /// contract: an unsupported value (AES_256, CHACHA20, any RSA suite) returns
    /// error.ZixTlsUnsupportedCipher.
    ciphers: []const CipherSuite = default_ciphers,

    /// Honor server cipher order over the client's (the server-prefers-order policy).
    /// Note: with the current single-suite-per-version set the selection is identical either way.
    prefer_server_ciphers: bool = true,

    /// HSTS max-age in SECONDS (RFC 6797). 0 = off. Enables the Strict-Transport-Security header,
    /// the recommended hardening for https. Lives here because it only has meaning over TLS.
    hsts_max_age_s: u32 = 0,
};

/// Errors init can raise from the policy (beyond the I/O / parse errors of loading the PEM files).
pub const ConfigError = error{
    ZixTlsNoCurves,
    ZixTlsNoCiphers,
    ZixTlsUnsupportedCurve,
    ZixTlsUnsupportedCipher,
    ZixTlsInvalidVersionRange,
    ZixTlsMissingCipherForVersion,
    ZixTlsMissingCurveForTls12,
    ZixUnsupportedCertificateKey,
};

/// The live context: the loaded certificate + signing key and the validated policy the engine
/// reads per connection. Build with init, release with deinit. Attach by pointer to the HTTP
/// server config (tls: ?*Tls.Context).
pub const Context = struct {
    allocator: std.mem.Allocator,
    /// DER end-entity certificate, owned (freed by deinit).
    cert_der: []u8,
    /// The chain as presented: the end-entity first, then any intermediates. Empty in a Context built by
    /// hand (a test fixture), where the single `cert_der` above stands in for it.
    certificate_chain: []const []const u8 = &.{},
    /// Storage for the chain's DER bytes, owned (freed by deinit).
    chain_pool: []u8 = &.{},
    /// Storage for the chain's entries, owned (freed by deinit).
    chain_entries: [][]const u8 = &.{},
    /// The signing identity matching the certificate's key type (ECDSA P-256, Ed25519, or RSA).
    signing_key: SigningKey,
    alpn: []const Alpn,
    curves: []const NamedGroup,
    ciphers: []const CipherSuite,
    min_version: Version,
    max_version: Version,
    prefer_server_ciphers: bool,
    hsts_max_age_s: u32,

    /// Load the cert + key, detect the key type, and validate the policy. Cold path, called once at
    /// startup. The slices in config (alpn / curves / ciphers) are borrowed, so they must outlive
    /// the Context (a string literal or the zixer parser's arena, both outlive it).
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the duplicated cert DER)
    /// io - std.Io (reads the PEM files)
    /// config - Config (the settings, validated here)
    ///
    /// Return:
    /// - Context
    /// - ConfigError on an unhonorable policy, or the PEM parse errors
    /// - error.ZixTlsCertFileNotFound / error.ZixTlsKeyFileNotFound (no such path)
    /// - error.ZixTlsCertFileUnreadable / error.ZixTlsKeyFileUnreadable (the path exists and the
    ///   read still failed, most often permissions)
    /// - error.ZixTlsCertPathIsDirectory / error.ZixTlsKeyPathIsDirectory (a directory was named)
    /// - error.ZixTlsCertFileTooLarge / error.ZixTlsKeyFileTooLarge (over PEM_MAX_BYTES)
    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Context {
        try validate(config);

        // Four causes, four names. They used to collapse into "not found", so a permission
        // problem and a typo in the path read the same to whoever had to fix it.
        const cert_pem = std.Io.Dir.cwd().readFileAlloc(io, config.cert_path, allocator, .limited(PEM_MAX_BYTES)) catch |err| return switch (err) {
            error.FileNotFound => error.ZixTlsCertFileNotFound,
            error.IsDir => error.ZixTlsCertPathIsDirectory,
            error.StreamTooLong => error.ZixTlsCertFileTooLarge,
            error.OutOfMemory => error.OutOfMemory,
            else => error.ZixTlsCertFileUnreadable,
        };
        defer allocator.free(cert_pem);
        // The document may hold the end-entity plus the intermediates that chain it back to its authority, and
        // a document with one block is a chain of one. Every block is decoded in place: the first entry is the
        // end-entity, which is the one the key belongs to and the one the identity checks read.
        var chain_view: pem.Chain = .{};
        const chain_pool = try allocator.alloc(u8, PEM_MAX_BYTES);
        errdefer allocator.free(chain_pool);
        try pem.chainToDer(chain_pool, &chain_view, cert_pem);

        const cert_der = try allocator.dupe(u8, chain_view.slice()[0]);
        errdefer allocator.free(cert_der);

        const chain_entries = try allocator.dupe([]const u8, chain_view.slice());
        errdefer allocator.free(chain_entries);

        const key_pem = std.Io.Dir.cwd().readFileAlloc(io, config.key_path, allocator, .limited(PEM_MAX_BYTES)) catch |err| return switch (err) {
            error.FileNotFound => error.ZixTlsKeyFileNotFound,
            error.IsDir => error.ZixTlsKeyPathIsDirectory,
            error.StreamTooLong => error.ZixTlsKeyFileTooLarge,
            error.OutOfMemory => error.OutOfMemory,
            else => error.ZixTlsKeyFileUnreadable,
        };
        defer allocator.free(key_pem);
        var key_der_buf: [4096]u8 = undefined; // RSA PKCS#8 DER is far larger than an EC key
        const key_der = try pem.pemToDer(&key_der_buf, key_pem);

        // The signing key matches the certificate's key type: ECDSA P-256 (SEC1), Ed25519 (PKCS#8),
        // or RSA (PKCS#1 or PKCS#8). An RSA key signs CertificateVerify with rsa_pss_rsae_sha256, so
        // it requires TLS 1.3 (the 1.2 ServerKeyExchange path is ECDSA-only).
        const cert_parsed = try (std.crypto.Certificate{ .buffer = cert_der, .index = 0 }).parse();
        const signing_key: SigningKey = switch (cert_parsed.pub_key_algo) {
            .X9_62_id_ecPublicKey => .{ .ecdsa_p256 = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(try pem.ecdsaScalarFromSec1(key_der))) },
            .curveEd25519 => .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(try pem.ed25519SeedFromPkcs8(key_der)) },
            .rsaEncryption => blk: {
                const is_pkcs8 = std.mem.indexOf(u8, key_pem, "BEGIN RSA PRIVATE KEY") == null;
                const key = try rsa.PrivateKey.fromDer(key_der, is_pkcs8);
                if (key.size() < 256) return error.ZixRsaKeyTooSmall; // RSA-2048 minimum

                break :blk .{ .rsa = key };
            },
            else => return error.ZixUnsupportedCertificateKey,
        };

        return .{
            .allocator = allocator,
            .cert_der = cert_der,
            .certificate_chain = chain_entries,
            .chain_pool = chain_pool,
            .chain_entries = chain_entries,
            .signing_key = signing_key,
            .alpn = config.alpn,
            .curves = config.curves,
            .ciphers = config.ciphers,
            .min_version = config.min_version,
            .max_version = config.max_version,
            .prefer_server_ciphers = config.prefer_server_ciphers,
            .hsts_max_age_s = config.hsts_max_age_s,
        };
    }

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.cert_der);
        self.allocator.free(self.chain_pool);
        self.allocator.free(self.chain_entries);
    }

    /// Build the per-connection handshake options from the context plus the freshly generated
    /// ephemeral secret + server random + PSS salt. The serve path supplies the randoms (they differ
    /// per connection), the context supplies the cert / key / alpn / curve policy. The salt is only
    /// consumed by an RSA signing key, the ECDSA / Ed25519 paths ignore it.
    pub fn handshakeOptions(self: *const Context, ephemeral_secret: [32]u8, server_random: [32]u8, pss_salt: [rsa.pss_salt_len]u8) HandshakeOptions {
        return .{
            .certificate_chain = if (self.certificate_chain.len > 0) self.certificate_chain else &.{self.cert_der},
            .signing_key = self.signing_key,
            .ephemeral_secret = ephemeral_secret,
            .server_random = server_random,
            .pss_salt = pss_salt,
            .alpn_prefs = self.alpn,
            .group_prefs = self.curves,
        };
    }

    /// Whether the TLS 1.3 path is offered under this policy (ceiling reaches 1.3).
    pub fn allowsTls13(self: *const Context) bool {
        return self.max_version == .TLS_1_3;
    }

    /// Whether the TLS 1.2 path is offered under this policy (floor is 1.2).
    pub fn allowsTls12(self: *const Context) bool {
        return self.min_version == .TLS_1_2;
    }
};

/// I/O-free policy validation (the honesty boundary). Rejects any curve / cipher the engine cannot
/// honor and any version range it cannot serve, so a configured field is never silently ignored.
pub fn validate(config: Config) ConfigError!void {
    if (config.curves.len == 0) return error.ZixTlsNoCurves;
    if (config.ciphers.len == 0) return error.ZixTlsNoCiphers;

    for (config.curves) |curve| {
        if (!isImplementedCurve(curve)) return error.ZixTlsUnsupportedCurve;
    }
    for (config.ciphers) |cipher| {
        if (!isImplementedCipher(cipher)) return error.ZixTlsUnsupportedCipher;
    }

    if (@intFromEnum(config.min_version) > @intFromEnum(config.max_version)) return error.ZixTlsInvalidVersionRange;

    // Each offered version needs its suite (and 1.2 ECDHE needs secp256r1) present in the lists.
    if (config.max_version == .TLS_1_3 and !contains(CipherSuite, config.ciphers, .AES_128_GCM_SHA256)) {
        return error.ZixTlsMissingCipherForVersion;
    }
    if (config.min_version == .TLS_1_2) {
        if (!contains(CipherSuite, config.ciphers, .ECDHE_ECDSA_AES128_GCM_SHA256)) return error.ZixTlsMissingCipherForVersion;
        if (!contains(NamedGroup, config.curves, .SECP256R1)) return error.ZixTlsMissingCurveForTls12;
    }
}

fn isImplementedCurve(curve: NamedGroup) bool {
    return curve == .X25519 or curve == .SECP256R1;
}

fn isImplementedCipher(cipher: CipherSuite) bool {
    return cipher == .AES_128_GCM_SHA256 or cipher == .ECDHE_ECDSA_AES128_GCM_SHA256;
}

fn contains(comptime T: type, list: []const T, value: T) bool {
    for (list) |item| {
        if (item == value) return true;
    }

    return false;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: context, default config validates" {
    try validate(.{ .cert_path = "c", .key_path = "k" });
}

test "zix tls: context, unsupported curve is rejected" {
    try std.testing.expectError(error.ZixTlsUnsupportedCurve, validate(.{
        .cert_path = "c",
        .key_path = "k",
        .curves = &.{ .X25519, @enumFromInt(0x4588) }, // a curve zix does not implement (e.g. MLKEM768)
    }));
}

test "zix tls: context, unsupported cipher is rejected" {
    try std.testing.expectError(error.ZixTlsUnsupportedCipher, validate(.{
        .cert_path = "c",
        .key_path = "k",
        .ciphers = &.{ .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256, .ECDHE_ECDSA_AES128_GCM_SHA256 },
    }));
}

test "zix tls: context, empty curves / ciphers rejected" {
    try std.testing.expectError(error.ZixTlsNoCurves, validate(.{ .cert_path = "c", .key_path = "k", .curves = &.{} }));
    try std.testing.expectError(error.ZixTlsNoCiphers, validate(.{ .cert_path = "c", .key_path = "k", .ciphers = &.{} }));
}

test "zix tls: context, inverted version range rejected" {
    try std.testing.expectError(error.ZixTlsInvalidVersionRange, validate(.{
        .cert_path = "c",
        .key_path = "k",
        .min_version = .TLS_1_3,
        .max_version = .TLS_1_2,
    }));
}

test "zix tls: context, version requires its suite present" {
    // 1.3-only policy missing the 1.3 suite.
    try std.testing.expectError(error.ZixTlsMissingCipherForVersion, validate(.{
        .cert_path = "c",
        .key_path = "k",
        .min_version = .TLS_1_3,
        .max_version = .TLS_1_3,
        .ciphers = &.{.ECDHE_ECDSA_AES128_GCM_SHA256},
    }));

    // 1.2 floor without secp256r1 (1.2 ECDHE needs it).
    try std.testing.expectError(error.ZixTlsMissingCurveForTls12, validate(.{
        .cert_path = "c",
        .key_path = "k",
        .curves = &.{.X25519},
    }));
}

test "zix tls: context, single-version policies validate" {
    // 1.3 only.
    try validate(.{
        .cert_path = "c",
        .key_path = "k",
        .min_version = .TLS_1_3,
        .max_version = .TLS_1_3,
        .ciphers = &.{.AES_128_GCM_SHA256},
        .curves = &.{.X25519},
    });

    // 1.2 only.
    try validate(.{
        .cert_path = "c",
        .key_path = "k",
        .min_version = .TLS_1_2,
        .max_version = .TLS_1_2,
        .ciphers = &.{.ECDHE_ECDSA_AES128_GCM_SHA256},
        .curves = &.{.SECP256R1},
    });
}

test "zix tls: context, version range gates the serve path" {
    // A Context built directly (no I/O) to test the pure allowsTls12 / allowsTls13 helpers that the
    // serve path uses to force the 1.2 path (ceiling 1.2) or refuse a 1.2 client (floor 1.3).
    const base = Context{
        .allocator = std.testing.allocator,
        .cert_der = &.{},
        .signing_key = undefined,
        .alpn = &.{},
        .curves = default_curves,
        .ciphers = default_ciphers,
        .min_version = .TLS_1_2,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = true,
        .hsts_max_age_s = 0,
    };

    // both versions (default): 1.2 and 1.3 paths both allowed.
    try std.testing.expect(base.allowsTls12());
    try std.testing.expect(base.allowsTls13());

    // floor 1.3: the serve path refuses a 1.2-only client.
    var floor_13 = base;
    floor_13.min_version = .TLS_1_3;
    try std.testing.expect(!floor_13.allowsTls12());
    try std.testing.expect(floor_13.allowsTls13());

    // ceiling 1.2: the serve path never takes the 1.3 path.
    var ceil_12 = base;
    ceil_12.max_version = .TLS_1_2;
    try std.testing.expect(ceil_12.allowsTls12());
    try std.testing.expect(!ceil_12.allowsTls13());
}
