//! Parse a target URL (`http://host[:port][/path]`) into one of the flat
//! Config structs. `https://` is rejected: http_client.zig is cleartext
//! only for now.
//!
//! Note:
//! - Returned slices borrow the url string: keep it alive as long as the
//!   Config.

const std = @import("std");
const config = @import("config.zig");

const Target = struct {
    ip: []const u8,
    port: ?u16,
    path: []const u8,
};

/// Parse `url` into a ScrapeConfig. A missing port defaults to 9100, a
/// missing path defaults to "/metrics".
///
/// Return:
/// - config.ScrapeConfig on success
/// - error.PrometheuzUnsupportedScheme (not http://)
/// - error.PrometheuzInvalidUrl (malformed host or port)
pub fn parseScrapeUrl(url: []const u8) !config.ScrapeConfig {
    const target = try parseTarget(url);

    return .{
        .ip = target.ip,
        .port = target.port orelse 9100,
        .path = if (target.path.len > 0) target.path else "/metrics",
    };
}

/// Parse `url` into a WriteConfig. A missing port defaults to 9090, a
/// missing path defaults to "/api/v1/write".
///
/// Return:
/// - config.WriteConfig on success
/// - error.PrometheuzUnsupportedScheme (not http://)
/// - error.PrometheuzInvalidUrl (malformed host or port)
pub fn parseWriteUrl(url: []const u8) !config.WriteConfig {
    const target = try parseTarget(url);

    return .{
        .ip = target.ip,
        .port = target.port orelse 9090,
        .path = if (target.path.len > 0) target.path else "/api/v1/write",
    };
}

/// Parse `url` into a QueryConfig (host and port only, query() and
/// query_range() carry their own fixed path). A missing port defaults to
/// 9090.
///
/// Return:
/// - config.QueryConfig on success
/// - error.PrometheuzUnsupportedScheme (not http://)
/// - error.PrometheuzInvalidUrl (malformed host or port)
pub fn parseQueryUrl(url: []const u8) !config.QueryConfig {
    const target = try parseTarget(url);

    return .{
        .ip = target.ip,
        .port = target.port orelse 9090,
    };
}

// --------------------------------------------------------- //

fn parseTarget(url: []const u8) !Target {
    if (std.mem.startsWith(u8, url, "https://")) return error.PrometheuzUnsupportedScheme;
    if (!std.mem.startsWith(u8, url, "http://")) return error.PrometheuzUnsupportedScheme;

    var rest = url["http://".len..];
    if (rest.len == 0) return error.PrometheuzInvalidUrl;

    var path: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
        path = rest[slash_pos..];
        rest = rest[0..slash_pos];
    }

    var port: ?u16 = null;
    if (std.mem.indexOfScalar(u8, rest, ':')) |colon_pos| {
        port = std.fmt.parseInt(u16, rest[colon_pos + 1 ..], 10) catch return error.PrometheuzInvalidUrl;
        rest = rest[0..colon_pos];
    }

    if (rest.len == 0) return error.PrometheuzInvalidUrl;

    return .{ .ip = rest, .port = port, .path = path };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: url scrape target with explicit port and path" {
    const scrape = try parseScrapeUrl("http://127.0.0.1:9100/metrics");

    try testing.expectEqualStrings("127.0.0.1", scrape.ip);
    try testing.expectEqual(@as(u16, 9100), scrape.port);
    try testing.expectEqualStrings("/metrics", scrape.path);
}

test "prometheuz: url scrape target defaults port and path" {
    const scrape = try parseScrapeUrl("http://node-exporter.local");

    try testing.expectEqualStrings("node-exporter.local", scrape.ip);
    try testing.expectEqual(@as(u16, 9100), scrape.port);
    try testing.expectEqualStrings("/metrics", scrape.path);
}

test "prometheuz: url write target defaults path" {
    const write = try parseWriteUrl("http://10.0.0.5:9090");

    try testing.expectEqualStrings("10.0.0.5", write.ip);
    try testing.expectEqual(@as(u16, 9090), write.port);
    try testing.expectEqualStrings("/api/v1/write", write.path);
}

test "prometheuz: url query target host and port only" {
    const query = try parseQueryUrl("http://10.0.0.5:9090");

    try testing.expectEqualStrings("10.0.0.5", query.ip);
    try testing.expectEqual(@as(u16, 9090), query.port);
}

test "prometheuz: url rejects https and malformed input" {
    try testing.expectError(error.PrometheuzUnsupportedScheme, parseScrapeUrl("https://127.0.0.1:9100/metrics"));
    try testing.expectError(error.PrometheuzUnsupportedScheme, parseScrapeUrl("node-exporter:9100"));
    try testing.expectError(error.PrometheuzInvalidUrl, parseScrapeUrl("http://"));
    try testing.expectError(error.PrometheuzInvalidUrl, parseScrapeUrl("http://127.0.0.1:notaport"));
}
