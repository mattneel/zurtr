//! How the in-process backend is configured: what it presents, what it demands, and
//! where it deliberately misbehaves.
//!
//! Note:
//! - Flat, like the driver's own Config. A suite sets only the fields its
//!   scenario needs and leaves the rest at their defaults.
//! - Lives apart from the session and the listener because both read it, and
//!   neither should have to import the other.

const std = @import("std");

const catalog_mod = @import("catalog.zig");

/// How the backend asks the client to prove itself.
pub const AuthMode = enum {
    /// AuthenticationOk straight away.
    TRUST,
    CLEARTEXT,
    SCRAM,
    /// SCRAM-SHA-256-PLUS, which needs TLS for the channel binding.
    SCRAM_PLUS,
};

pub const Options = struct {
    /// Reported through the server_version parameter. The driver parses the
    /// major out of it and refuses anything below 15.
    server_version: []const u8 = "18.0",
    /// Highest protocol the backend admits to. A client asking for more is
    /// answered with NegotiateProtocolVersion.
    protocol_code: i32 = 196610,
    auth_mode: AuthMode = .TRUST,
    /// Expected user, empty accepts whatever the client sent.
    user: []const u8 = "",
    password: []const u8 = "",
    /// Serve TLS on the SSLRequest upgrade. The certificate is generated per
    /// server and never touches disk.
    tls: bool = false,
    /// Common name on the generated certificate.
    tls_common_name: []const u8 = "postgrez-inproc",
    /// What each statement answers.
    catalog: catalog_mod.Catalog = .{},
    /// Fault injection: a statement whose text starts with this always fails
    /// with a connection reset instead of a reply. Models a backend that died
    /// mid-query, which the pool's healing path needs.
    drop_on_statement: ?[]const u8 = null,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez inproc: options default to a trusting cleartext backend" {
    const options = Options{};

    try testing.expectEqual(AuthMode.TRUST, options.auth_mode);
    try testing.expect(!options.tls);
    try testing.expectEqualStrings("18.0", options.server_version);
    try testing.expectEqual(@as(?[]const u8, null), options.drop_on_statement);
}

test "postgrez inproc: options protocol code defaults to 3.2" {
    const options = Options{};

    // 3.2 is 0x00030002, which the driver names PROTOCOL_V3_2
    try testing.expectEqual(@as(i32, 0x0003_0002), options.protocol_code);
}

test "postgrez inproc: options keep their defaults when one field is set" {
    const options = Options{ .auth_mode = .SCRAM, .password = "secret" };

    try testing.expectEqual(AuthMode.SCRAM, options.auth_mode);
    try testing.expectEqualStrings("postgrez-inproc", options.tls_common_name);
    try testing.expectEqual(@as(usize, catalog_mod.DEFAULT_ENTRIES.len), options.catalog.entries.len);
}
