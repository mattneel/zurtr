//! prometheuz config: flat, per-surface configuration structs.
//!
//! Note:
//! - Cleartext only for now: http_client.zig has no TLS support yet, so
//!   there is deliberately no `tls` field here until that lands.

const std = @import("std");

/// Scrape target (node-exporter, or any Prometheus text 0.0.4 endpoint).
pub const ScrapeConfig = struct {
    ip: []const u8 = "127.0.0.1",
    port: u16 = 9100,
    path: []const u8 = "/metrics",
    /// Scraper poller interval in milliseconds.
    scrape_interval_ms: u32 = 15_000,
    /// Bounds the TCP connect phase in milliseconds, 0 disables.
    conn_timeout_ms: u32 = 5_000,
    /// Caps the scraped response body in bytes.
    max_response_body: usize = 1024 * 1024 * 4,
};

/// remote_write receiver target.
pub const WriteConfig = struct {
    ip: []const u8 = "127.0.0.1",
    port: u16 = 9090,
    path: []const u8 = "/api/v1/write",
    conn_timeout_ms: u32 = 5_000,
    max_response_body: usize = 1024 * 1024,
};

/// PromQL query API target. query() and query_range() append their own
/// fixed path (/api/v1/query, /api/v1/query_range).
pub const QueryConfig = struct {
    ip: []const u8 = "127.0.0.1",
    port: u16 = 9090,
    conn_timeout_ms: u32 = 5_000,
    max_response_body: usize = 1024 * 1024 * 4,
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: config defaults" {
    const scrape = ScrapeConfig{};
    try testing.expectEqualStrings("127.0.0.1", scrape.ip);
    try testing.expectEqual(@as(u16, 9100), scrape.port);
    try testing.expectEqualStrings("/metrics", scrape.path);
    try testing.expectEqual(@as(u32, 15_000), scrape.scrape_interval_ms);

    const write = WriteConfig{};
    try testing.expectEqual(@as(u16, 9090), write.port);
    try testing.expectEqualStrings("/api/v1/write", write.path);

    const query = QueryConfig{};
    try testing.expectEqual(@as(u16, 9090), query.port);
}
