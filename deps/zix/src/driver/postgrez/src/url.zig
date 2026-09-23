//! DATABASE_URL parsing: `postgres://user[:password]@host[:port][/database]`
//! into a Config. `postgresql://` is an accepted alias, `?sslmode=` selects
//! TLS (disable, prefer, require).
//!
//! Note:
//! - Returned slices borrow the url string: keep it alive as long as the
//!   Config (environment values live for the process).
//! - No percent-decoding: credentials with reserved characters are out of
//!   scope for the URL form, set them on Config directly.
//! - Query parameters other than sslmode are ignored.

const std = @import("std");
const lib = @import("lib.zig");

/// Parse a PostgreSQL URL into a Config (every non-URL knob keeps its
/// default).
///
/// Param:
/// url - []const u8 (must outlive the returned Config)
///
/// Return:
/// - lib.Config on success
/// - error.PostgrezUnsupportedScheme (not postgres:// or postgresql://)
/// - error.PostgrezInvalidUrl on a malformed or missing user, host, port, or
///   sslmode segment
pub fn parseUrl(url: []const u8) !lib.Config {
    var config = lib.Config{ .user = "" };
    var rest = url;

    if (std.mem.startsWith(u8, rest, "postgresql://")) {
        rest = rest["postgresql://".len..];
    } else if (std.mem.startsWith(u8, rest, "postgres://")) {
        rest = rest["postgres://".len..];
    } else {
        return error.PostgrezUnsupportedScheme;
    }

    if (std.mem.indexOfScalar(u8, rest, '?')) |query_pos| {
        try applyQuery(&config, rest[query_pos + 1 ..]);
        rest = rest[0..query_pos];
    }

    if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
        const database = rest[slash_pos + 1 ..];
        rest = rest[0..slash_pos];

        if (database.len > 0) config.database = database;
    }

    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at_pos| {
        const userinfo = rest[0..at_pos];
        rest = rest[at_pos + 1 ..];

        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon_pos| {
            config.user = userinfo[0..colon_pos];
            config.password = userinfo[colon_pos + 1 ..];
        } else {
            config.user = userinfo;
        }
    }

    if (std.mem.indexOfScalar(u8, rest, ':')) |colon_pos| {
        config.port = std.fmt.parseInt(u16, rest[colon_pos + 1 ..], 10) catch return error.PostgrezInvalidUrl;
        rest = rest[0..colon_pos];
    }

    if (rest.len == 0 or config.user.len == 0) return error.PostgrezInvalidUrl;
    config.ip = rest;

    return config;
}

/// The query segment: only sslmode is honored, everything else is ignored.
fn applyQuery(config: *lib.Config, query: []const u8) !void {
    var param_iter = std.mem.splitScalar(u8, query, '&');

    while (param_iter.next()) |param| {
        const eq_pos = std.mem.indexOfScalar(u8, param, '=') orelse continue;
        if (!std.mem.eql(u8, param[0..eq_pos], "sslmode")) continue;

        const mode = param[eq_pos + 1 ..];
        if (std.mem.eql(u8, mode, "disable")) {
            config.tls = .OFF;
        } else if (std.mem.eql(u8, mode, "prefer")) {
            config.tls = .PREFER;
        } else if (std.mem.eql(u8, mode, "require")) {
            config.tls = .REQUIRE;
        } else {
            return error.PostgrezInvalidUrl;
        }
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez: url minimal user and host" {
    const config = try parseUrl("postgres://app@localhost");

    try testing.expectEqualStrings("localhost", config.ip);
    try testing.expectEqual(@as(u16, 5432), config.port);
    try testing.expectEqualStrings("app", config.user);
    try testing.expectEqualStrings("", config.password);
    try testing.expectEqual(@as(?[]const u8, null), config.database);
    try testing.expectEqual(lib.TlsMode.OFF, config.tls);
}

test "postgrez: url full form with credentials port and database" {
    const config = try parseUrl("postgres://app:secret@127.0.0.1:54180/appdb");

    try testing.expectEqualStrings("127.0.0.1", config.ip);
    try testing.expectEqual(@as(u16, 54180), config.port);
    try testing.expectEqualStrings("app", config.user);
    try testing.expectEqualStrings("secret", config.password);
    try testing.expectEqualStrings("appdb", config.database.?);
}

test "postgrez: url postgresql alias scheme" {
    const config = try parseUrl("postgresql://app@localhost:5433/other");

    try testing.expectEqual(@as(u16, 5433), config.port);
    try testing.expectEqualStrings("other", config.database.?);
}

test "postgrez: url sslmode selects tls" {
    const require = try parseUrl("postgres://app@localhost/db?sslmode=require");
    try testing.expectEqual(lib.TlsMode.REQUIRE, require.tls);

    const prefer = try parseUrl("postgres://app@localhost/db?sslmode=prefer");
    try testing.expectEqual(lib.TlsMode.PREFER, prefer.tls);

    const disable = try parseUrl("postgres://app@localhost/db?sslmode=disable");
    try testing.expectEqual(lib.TlsMode.OFF, disable.tls);

    // unknown query parameters are ignored
    const extra = try parseUrl("postgres://app@localhost/db?application_name=x&sslmode=require");
    try testing.expectEqual(lib.TlsMode.REQUIRE, extra.tls);
}

test "postgrez: url trailing slash keeps database null" {
    const config = try parseUrl("postgres://app@localhost:5432/");

    try testing.expectEqual(@as(?[]const u8, null), config.database);
}

test "postgrez: url rejects malformed input" {
    try testing.expectError(error.PostgrezUnsupportedScheme, parseUrl("mysql://app@localhost"));
    try testing.expectError(error.PostgrezUnsupportedScheme, parseUrl("localhost:5432"));
    try testing.expectError(error.PostgrezInvalidUrl, parseUrl("postgres://"));
    try testing.expectError(error.PostgrezInvalidUrl, parseUrl("postgres://localhost")); // no user
    try testing.expectError(error.PostgrezInvalidUrl, parseUrl("postgres://app@localhost:notaport"));
    try testing.expectError(error.PostgrezInvalidUrl, parseUrl("postgres://app@localhost/db?sslmode=bogus"));
}
