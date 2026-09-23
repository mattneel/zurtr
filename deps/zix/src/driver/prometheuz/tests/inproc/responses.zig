//! What the in-process endpoint answers per route, and what it recorded.
//!
//! Note:
//! - The driver talks to three different servers in production: an exporter
//!   that serves metrics text, a receiver that accepts remote writes, and a
//!   query API that answers JSON. All three are plain HTTP, so one endpoint
//!   serves all three and a suite points whichever config it needs at it.
//! - Remote writes are recorded rather than interpreted. Decoding the
//!   snappy-framed protobuf back into samples would be reimplementing the
//!   encoder the suite is trying to test, so the body is kept for the suite
//!   to inspect with the driver's own decoder.

const std = @import("std");

/// The metrics body a scrape gets by default: one counter, one gauge with
/// labels, and a histogram, so the parser meets every shape it handles.
pub const DEFAULT_METRICS =
    \\# HELP zix_requests_total Total requests handled.
    \\# TYPE zix_requests_total counter
    \\zix_requests_total{method="get"} 1027
    \\zix_requests_total{method="post"} 3
    \\# HELP zix_temperature_celsius Current temperature.
    \\# TYPE zix_temperature_celsius gauge
    \\zix_temperature_celsius 21.5
    \\# HELP zix_latency_seconds Request latency.
    \\# TYPE zix_latency_seconds histogram
    \\zix_latency_seconds_bucket{le="0.1"} 200
    \\zix_latency_seconds_bucket{le="0.5"} 280
    \\zix_latency_seconds_bucket{le="+Inf"} 300
    \\zix_latency_seconds_sum 47.9
    \\zix_latency_seconds_count 300
    \\
;

/// A PromQL instant query answer with two series.
pub const DEFAULT_QUERY_JSON =
    \\{"status":"success","data":{"resultType":"vector","result":[
    \\{"metric":{"__name__":"zix_requests_total","method":"get"},"value":[1700000000,"1027"]},
    \\{"metric":{"__name__":"zix_requests_total","method":"post"},"value":[1700000000,"3"]}
    \\]}}
;

/// A PromQL range query answer with one series and three points.
pub const DEFAULT_QUERY_RANGE_JSON =
    \\{"status":"success","data":{"resultType":"matrix","result":[
    \\{"metric":{"__name__":"zix_temperature_celsius"},"values":[
    \\[1700000000,"21.5"],[1700000015,"21.7"],[1700000030,"21.4"]]}
    \\]}}
;

/// A PromQL error answer, the shape the API uses for a bad expression.
pub const BAD_QUERY_JSON =
    \\{"status":"error","errorType":"bad_data","error":"invalid parameter \"query\": unexpected end of input"}
;

/// One canned HTTP answer.
pub const Reply = struct {
    status: u16 = 200,
    /// Sent as the Content-Type header, omitted when empty.
    content_type: []const u8 = "text/plain; version=0.0.4",
    body: []const u8 = "",
    /// Answer without a Content-Length, closing the connection to mark the
    /// end. A real exporter behind a proxy can do this.
    close_without_length: bool = false,
};

/// A recorded request, so a suite can assert on what the driver sent.
pub const Recorded = struct {
    method: []const u8,
    path: []const u8,
    /// The full request target including any query string.
    target: []const u8,
    body: []const u8,
    content_encoding: []const u8,
};

/// What each route answers. A suite overrides only the ones it cares about.
pub const Routes = struct {
    /// GET on the scrape path.
    metrics: Reply = .{ .body = DEFAULT_METRICS },
    /// POST on the remote-write path. A receiver answers 204 with no body.
    write: Reply = .{ .status = 204, .content_type = "", .body = "" },
    /// GET or POST on /api/v1/query.
    query: Reply = .{ .content_type = "application/json", .body = DEFAULT_QUERY_JSON },
    /// GET or POST on /api/v1/query_range.
    query_range: Reply = .{ .content_type = "application/json", .body = DEFAULT_QUERY_RANGE_JSON },
    /// Anything else.
    not_found: Reply = .{ .status = 404, .content_type = "text/plain", .body = "not found" },

    /// Path the metrics reply is served on, matching ScrapeConfig.path.
    metrics_path: []const u8 = "/metrics",
    /// Path the write reply is served on, matching WriteConfig.path.
    write_path: []const u8 = "/api/v1/write",

    /// Pick the reply for a request target.
    pub fn pick(self: Routes, target: []const u8) Reply {
        const path = pathOf(target);

        if (std.mem.eql(u8, path, self.metrics_path)) return self.metrics;
        if (std.mem.eql(u8, path, self.write_path)) return self.write;
        if (std.mem.eql(u8, path, "/api/v1/query")) return self.query;
        if (std.mem.eql(u8, path, "/api/v1/query_range")) return self.query_range;

        return self.not_found;
    }
};

/// The path part of a request target, query string dropped.
pub fn pathOf(target: []const u8) []const u8 {
    const question = std.mem.indexOfScalar(u8, target, '?') orelse return target;

    return target[0..question];
}

/// The query string of a request target, empty when there is none.
pub fn queryOf(target: []const u8) []const u8 {
    const question = std.mem.indexOfScalar(u8, target, '?') orelse return "";

    return target[question + 1 ..];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "prometheuz inproc: responses split a target into path and query" {
    try testing.expectEqualStrings("/api/v1/query", pathOf("/api/v1/query?query=up"));
    try testing.expectEqualStrings("query=up", queryOf("/api/v1/query?query=up"));

    try testing.expectEqualStrings("/metrics", pathOf("/metrics"));
    try testing.expectEqualStrings("", queryOf("/metrics"));
}

test "prometheuz inproc: responses route each path to its reply" {
    const routes = Routes{};

    try testing.expectEqualStrings(DEFAULT_METRICS, routes.pick("/metrics").body);
    try testing.expectEqual(@as(u16, 204), routes.pick("/api/v1/write").status);
    try testing.expectEqualStrings(DEFAULT_QUERY_JSON, routes.pick("/api/v1/query?query=up").body);
    try testing.expectEqualStrings(DEFAULT_QUERY_RANGE_JSON, routes.pick("/api/v1/query_range?query=up").body);
    try testing.expectEqual(@as(u16, 404), routes.pick("/nothing/here").status);
}

test "prometheuz inproc: responses honour an overridden scrape path" {
    const routes = Routes{ .metrics_path = "/custom" };

    try testing.expectEqualStrings(DEFAULT_METRICS, routes.pick("/custom").body);
    try testing.expectEqual(@as(u16, 404), routes.pick("/metrics").status);
}

test "prometheuz inproc: responses can be replaced wholesale by a suite" {
    const routes = Routes{ .metrics = .{ .status = 500, .body = "boom" } };

    const reply = routes.pick("/metrics");
    try testing.expectEqual(@as(u16, 500), reply.status);
    try testing.expectEqualStrings("boom", reply.body);
}

test "prometheuz inproc: the default metrics body carries every shape the parser handles" {
    try testing.expect(std.mem.indexOf(u8, DEFAULT_METRICS, "# TYPE zix_requests_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, DEFAULT_METRICS, "# TYPE zix_temperature_celsius gauge") != null);
    try testing.expect(std.mem.indexOf(u8, DEFAULT_METRICS, "# TYPE zix_latency_seconds histogram") != null);
    try testing.expect(std.mem.indexOf(u8, DEFAULT_METRICS, "le=\"+Inf\"") != null);
}
