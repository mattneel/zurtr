//! REDIS_URL parsing: `redis://[user[:password]@]host[:port][/db]` into a
//! Config. `rediss://` selects TLS.
//!
//! Note:
//! - Returned slices borrow the url string: keep it alive as long as the
//!   Config (environment values live for the process).
//! - No percent-decoding: credentials with reserved characters are out of
//!   scope for the URL form, set them on Config directly.

const std = @import("std");
const lib = @import("lib.zig");

/// Parse a Redis URL into a Config (every non-URL knob keeps its default).
///
/// Param:
/// url - []const u8 (must outlive the returned Config)
///
/// Return:
/// - lib.Config on success
/// - error.RedizUnsupportedScheme (not redis:// or rediss://)
/// - error.RedizInvalidUrl on a malformed host, port or db segment
pub fn parseUrl(url: []const u8) !lib.Config {
    var config = lib.Config{};
    var rest = url;

    if (std.mem.startsWith(u8, rest, "rediss://")) {
        config.tls = .REQUIRE;
        rest = rest["rediss://".len..];
    } else if (std.mem.startsWith(u8, rest, "redis://")) {
        rest = rest["redis://".len..];
    } else {
        return error.RedizUnsupportedScheme;
    }

    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at_pos| {
        const userinfo = rest[0..at_pos];
        rest = rest[at_pos + 1 ..];

        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon_pos| {
            config.user = userinfo[0..colon_pos];
            config.password = userinfo[colon_pos + 1 ..];
        } else {
            config.password = userinfo;
        }
    }

    if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
        const db_text = rest[slash_pos + 1 ..];
        rest = rest[0..slash_pos];

        if (db_text.len > 0) {
            config.database = std.fmt.parseInt(u32, db_text, 10) catch return error.RedizInvalidUrl;
        }
    }

    if (std.mem.indexOfScalar(u8, rest, ':')) |colon_pos| {
        config.port = std.fmt.parseInt(u16, rest[colon_pos + 1 ..], 10) catch return error.RedizInvalidUrl;
        rest = rest[0..colon_pos];
    }

    if (rest.len == 0) return error.RedizInvalidUrl;
    config.ip = rest;

    return config;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz: url minimal host only" {
    const config = try parseUrl("redis://localhost");

    try testing.expectEqualStrings("localhost", config.ip);
    try testing.expectEqual(@as(u16, 6379), config.port);
    try testing.expectEqualStrings("", config.user);
    try testing.expectEqualStrings("", config.password);
    try testing.expectEqual(@as(u32, 0), config.database);
    try testing.expectEqual(lib.TlsMode.OFF, config.tls);
}

test "rediz: url full form with credentials port and db" {
    const config = try parseUrl("redis://app:secret@127.0.0.1:6390/2");

    try testing.expectEqualStrings("127.0.0.1", config.ip);
    try testing.expectEqual(@as(u16, 6390), config.port);
    try testing.expectEqualStrings("app", config.user);
    try testing.expectEqualStrings("secret", config.password);
    try testing.expectEqual(@as(u32, 2), config.database);
}

test "rediz: url password only userinfo" {
    const config = try parseUrl("redis://secret@localhost:6379");

    try testing.expectEqualStrings("", config.user);
    try testing.expectEqualStrings("secret", config.password);
}

test "rediz: url rediss scheme requires tls" {
    const config = try parseUrl("rediss://localhost:6390");

    try testing.expectEqual(lib.TlsMode.REQUIRE, config.tls);
    try testing.expectEqual(@as(u16, 6390), config.port);
}

test "rediz: url trailing slash keeps db 0" {
    const config = try parseUrl("redis://localhost:6379/");

    try testing.expectEqual(@as(u32, 0), config.database);
}

test "rediz: url rejects malformed input" {
    try testing.expectError(error.RedizUnsupportedScheme, parseUrl("http://localhost"));
    try testing.expectError(error.RedizUnsupportedScheme, parseUrl("localhost:6379"));
    try testing.expectError(error.RedizInvalidUrl, parseUrl("redis://"));
    try testing.expectError(error.RedizInvalidUrl, parseUrl("redis://localhost:notaport"));
    try testing.expectError(error.RedizInvalidUrl, parseUrl("redis://localhost:6379/notadb"));
}
