//! prometheuz edge suite: refusals, bad bodies and unreachable endpoints
//! against the in-process server.
//!
//! Note:
//! - No container and no daemon, so this runs on every supported platform.
//! - A scrape never throws: a failure becomes a snapshot with up = false and
//!   the reason in last_error, so most of the checks here are on that shape
//!   rather than on an error union.
//! - Each test starts its own server on a kernel-assigned port, so a test that
//!   deliberately breaks an endpoint cannot disturb another.

const std = @import("std");
const builtin = @import("builtin");
const prometheuz = @import("prometheuz");

const inproc = @import("inproc/server.zig");

const testing = std.testing;

const Harness = struct {
    threaded: std.Io.Threaded,
    server: *inproc.Server,

    fn start(self: *Harness, routes: inproc.Routes) !void {
        self.threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer self.threaded.deinit();

        self.server = try inproc.Server.start(std.heap.smp_allocator, self.threaded.io(), routes);
    }

    fn open(self: *Harness) !void {
        return self.start(.{});
    }

    fn stop(self: *Harness) void {
        self.server.stop();
        self.threaded.deinit();
    }

    fn io(self: *Harness) std.Io {
        return self.threaded.io();
    }

    fn scrapeConfig(self: *Harness) prometheuz.ScrapeConfig {
        return .{ .ip = inproc.IP, .port = self.server.port };
    }

    fn writeConfig(self: *Harness) prometheuz.WriteConfig {
        return .{ .ip = inproc.IP, .port = self.server.port };
    }

    fn queryConfig(self: *Harness) prometheuz.QueryConfig {
        return .{ .ip = inproc.IP, .port = self.server.port };
    }
};

test "prometheuz edge: a scrape of a closed port reports down, not an error" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const dead_port = harness.server.port;
    harness.server.stop();

    // stop() frees the server, so the harness needs a live one back on every exit path, not only
    // the passing one: an expectation that fails below returns before a trailing restart would run,
    // and harness.stop() then frees the same pointer a second time, which crashes the runner.
    defer harness.server = inproc.Server.start(std.heap.smp_allocator, harness.io(), .{}) catch
        @panic("inproc server restart failed");

    var config = harness.scrapeConfig();
    config.port = dead_port;
    config.conn_timeout_ms = 500;

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), config);
    defer snapshot.release();

    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
    try testing.expectEqual(@as(usize, 0), snapshot.families.len);
}

test "prometheuz edge: a non-200 scrape reports down with a reason" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{ .status = 503, .body = "unavailable" } });
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
}

test "prometheuz edge: a scrape of a missing path reports down" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.scrapeConfig();
    config.path = "/nowhere";

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), config);
    defer snapshot.release();

    try testing.expect(!snapshot.up);
}

test "prometheuz edge: an empty metrics body is up with no families" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{ .body = "" } });
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    try testing.expect(snapshot.up);
    try testing.expectEqual(@as(usize, 0), snapshot.families.len);
}

test "prometheuz edge: a malformed metrics line fails the scrape without throwing" {
    const body =
        \\# TYPE zix_good gauge
        \\zix_good 1
        \\this line is not a metric at all
        \\zix_good_two 2
        \\
    ;

    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{ .body = body } });
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    // the parser rejects the body rather than salvaging the good lines, and
    // the scrape reports that as down instead of propagating an error
    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
}

test "prometheuz edge: a scrape body past the cap reports down" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.scrapeConfig();
    config.max_response_body = 8;

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), config);
    defer snapshot.release();

    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
}

test "prometheuz edge: an answer with no content length still scrapes" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{
        .body = "# TYPE zix_bare gauge\nzix_bare 3\n",
        .close_without_length = true,
    } });
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    try testing.expect(snapshot.up);
    try testing.expect(snapshot.family("zix_bare") != null);
}

test "prometheuz edge: a query error body surfaces QueryFailed" {
    var harness: Harness = undefined;
    try harness.start(.{ .query = .{
        .content_type = "application/json",
        .body = inproc.responses.BAD_QUERY_JSON,
        .status = 400,
    } });
    defer harness.stop();

    try testing.expectError(
        error.PrometheuzQueryFailed,
        prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "up =="),
    );
}

test "prometheuz edge: a query answer that is not json surfaces InvalidResponse" {
    var harness: Harness = undefined;
    try harness.start(.{ .query = .{ .content_type = "application/json", .body = "not json at all" } });
    defer harness.stop();

    try testing.expectError(
        error.PrometheuzInvalidResponse,
        prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "up"),
    );
}

test "prometheuz edge: a query answer with an unexpected shape surfaces InvalidResponse" {
    var harness: Harness = undefined;
    try harness.start(.{ .query = .{
        .content_type = "application/json",
        .body = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\"}}",
    } });
    defer harness.stop();

    try testing.expectError(
        error.PrometheuzInvalidResponse,
        prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "up"),
    );
}

test "prometheuz edge: an empty query result is not an error" {
    var harness: Harness = undefined;
    try harness.start(.{ .query = .{
        .content_type = "application/json",
        .body = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[]}}",
    } });
    defer harness.stop();

    var result = try prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "nothing_matches");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 0), result.vector.len);
}

test "prometheuz edge: a query against a closed port is refused" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const dead_port = harness.server.port;
    harness.server.stop();

    // stop() frees the server, so the harness needs a live one back on every exit path, not only
    // the passing one: an expectation that fails below returns before a trailing restart would run,
    // and harness.stop() then frees the same pointer a second time, which crashes the runner.
    defer harness.server = inproc.Server.start(std.heap.smp_allocator, harness.io(), .{}) catch
        @panic("inproc server restart failed");

    var config = harness.queryConfig();
    config.port = dead_port;
    config.conn_timeout_ms = 500;

    // windows region: zig std's connect path leaves NTSTATUS
    // CONNECTION_REFUSED (0xc0000236) unmapped, so the refused
    // connect surfaces as error.Unexpected there.
    const refused = if (builtin.os.tag == .windows) error.Unexpected else error.ConnectionRefused;

    try testing.expectError(
        refused,
        prometheuz.query(testing.allocator, harness.io(), config, "up"),
    );
}

test "prometheuz edge: a remote write refused by the receiver surfaces the failure" {
    var harness: Harness = undefined;
    try harness.start(.{ .write = .{ .status = 400, .content_type = "text/plain", .body = "bad request" } });
    defer harness.stop();

    const samples = [_]prometheuz.Sample{
        .{ .name = "zix_requests_total", .labels = &.{}, .value = 1, .timestamp_ms = null },
    };

    try testing.expectError(
        error.PrometheuzRemoteWriteRejected,
        prometheuz.remoteWrite(testing.allocator, harness.io(), harness.writeConfig(), &samples),
    );
}

test "prometheuz edge: a remote write to a closed port is refused" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const dead_port = harness.server.port;
    harness.server.stop();

    // stop() frees the server, so the harness needs a live one back on every exit path, not only
    // the passing one: an expectation that fails below returns before a trailing restart would run,
    // and harness.stop() then frees the same pointer a second time, which crashes the runner.
    defer harness.server = inproc.Server.start(std.heap.smp_allocator, harness.io(), .{}) catch
        @panic("inproc server restart failed");

    var config = harness.writeConfig();
    config.port = dead_port;
    config.conn_timeout_ms = 500;

    const samples = [_]prometheuz.Sample{
        .{ .name = "zix_requests_total", .labels = &.{}, .value = 1, .timestamp_ms = null },
    };

    // windows region: zig std's connect path leaves NTSTATUS
    // CONNECTION_REFUSED (0xc0000236) unmapped, so the refused
    // connect surfaces as error.Unexpected there.
    const refused = if (builtin.os.tag == .windows) error.Unexpected else error.ConnectionRefused;

    try testing.expectError(
        refused,
        prometheuz.remoteWrite(testing.allocator, harness.io(), config, &samples),
    );
}

test "prometheuz edge: a scraper keeps polling after a failed scrape" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{ .status = 503, .body = "down" } });
    defer harness.stop();

    var config = harness.scrapeConfig();
    config.scrape_interval_ms = 20;

    const scraper = try prometheuz.Scraper.start(testing.allocator, harness.io(), config);
    defer scraper.deinit();

    // two polls prove the worker survived the first failure
    while (harness.server.requestCount() < 2) std.atomic.spinLoopHint();

    const snapshot = scraper.latest();
    defer snapshot.release();

    try testing.expect(!snapshot.up);
}
