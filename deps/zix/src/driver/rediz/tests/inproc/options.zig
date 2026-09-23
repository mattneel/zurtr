//! How the in-process server is configured: what it presents, what it demands, and
//! where it deliberately misbehaves.
//!
//! Note:
//! - Flat, like the driver's own Config. A suite sets only the fields its
//!   scenario needs and leaves the rest at their defaults.
//! - Lives apart from both command.zig and server.zig because both read it,
//!   and neither should have to import the other.

const std = @import("std");

pub const Options = struct {
    /// Required username, empty means the server has no ACL configured.
    user: []const u8 = "",
    /// Required password, empty means no authentication is demanded.
    password: []const u8 = "",
    /// Reported through HELLO, the driver parses the major out of it.
    server_version: []const u8 = "8.0.2",
    /// When false, HELLO is refused so the driver falls back to RESP2. Models
    /// a server too old to know the command.
    resp3_supported: bool = true,
    /// Fault injection: this command name always answers MISCONF instead of
    /// running. Models a server that has stopped accepting writes, which is
    /// the only way to reach the driver's write-behind error accounting, since
    /// the commands it defers cannot fail on a healthy server.
    fail_command: ?[]const u8 = null,
    /// Serve TLS instead of cleartext. The certificate is generated per
    /// server and never touches disk.
    tls: bool = false,
    /// Common name on the generated certificate.
    tls_common_name: []const u8 = "rediz-inproc",
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz inproc: options default to an open cleartext server" {
    const options = Options{};

    try testing.expectEqualStrings("", options.user);
    try testing.expectEqualStrings("", options.password);
    try testing.expect(options.resp3_supported);
    try testing.expect(!options.tls);
    try testing.expectEqual(@as(?[]const u8, null), options.fail_command);
}

test "rediz inproc: options keep their defaults when one field is set" {
    const options = Options{ .tls = true };

    try testing.expect(options.tls);
    try testing.expectEqualStrings("rediz-inproc", options.tls_common_name);
    try testing.expectEqualStrings("8.0.2", options.server_version);
}
