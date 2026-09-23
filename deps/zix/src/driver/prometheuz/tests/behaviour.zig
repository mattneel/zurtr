//! prometheuz behaviour suite: the driver against the in-process endpoint.
//!
//! Note:
//! - No container and no daemon, so this runs on every supported platform.
//!   prometheuz had no integration suite at all before this, only in-file unit
//!   tests and a container-backed example runner, so this is its first
//!   end-to-end coverage that CI can run everywhere.
//! - One endpoint serves all three roles the driver talks to: the exporter it
//!   scrapes, the receiver it writes to, and the query API it reads from.
//! - Each test starts its own server on a kernel-assigned port, so recordings
//!   belong to that test alone.

const std = @import("std");
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

test "prometheuz behaviour: a scrape reports up and parses every family" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    try testing.expect(snapshot.up);
    try testing.expectEqual(@as(?[]const u8, null), snapshot.last_error);
    try testing.expectEqual(@as(usize, 3), snapshot.families.len);

    const counter = snapshot.family("zix_requests_total").?;
    try testing.expectEqual(prometheuz.MetricType.counter, counter.metric_type);
    try testing.expectEqualStrings("Total requests handled.", counter.help);

    const gauge = snapshot.family("zix_temperature_celsius").?;
    try testing.expectEqual(prometheuz.MetricType.gauge, gauge.metric_type);
}

test "prometheuz behaviour: a scrape keeps labels and values together" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    const counter = snapshot.family("zix_requests_total").?;
    try testing.expectEqual(@as(usize, 2), counter.samples.len);

    var get_value: ?f64 = null;
    for (counter.samples) |sample| {
        for (sample.labels) |label| {
            if (!std.mem.eql(u8, label.name, "method")) continue;
            if (!std.mem.eql(u8, label.value, "get")) continue;

            get_value = sample.value;
        }
    }

    try testing.expectEqual(@as(f64, 1027), get_value.?);
}

test "prometheuz behaviour: a scrape flattens every sample for the write path" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), harness.scrapeConfig());
    defer snapshot.release();

    // two counter series, one gauge, three buckets plus sum and count
    try testing.expectEqual(@as(usize, 8), snapshot.samples.len);
}

test "prometheuz behaviour: a scrape asks for the configured path" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics_path = "/custom/metrics" });
    defer harness.stop();

    var config = harness.scrapeConfig();
    config.path = "/custom/metrics";

    const snapshot = try prometheuz.scrapeOnce(testing.allocator, harness.io(), config);
    defer snapshot.release();

    try testing.expect(snapshot.up);
    try testing.expectEqualStrings("/custom/metrics", harness.server.lastRequest().?.path);
    try testing.expectEqualStrings("GET", harness.server.lastRequest().?.method);
}

test "prometheuz behaviour: an instant query returns a vector" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var result = try prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "zix_requests_total");
    defer result.deinit();

    try testing.expectEqual(prometheuz.query_mod.ResultType.vector, result.result_type);
    try testing.expectEqual(@as(usize, 2), result.vector.len);
    try testing.expectEqual(@as(f64, 1027), result.vector[0].value);
    try testing.expectEqual(@as(f64, 1700000000), result.vector[0].timestamp);
}

test "prometheuz behaviour: an instant query sends the expression it was given" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var result = try prometheuz.query(testing.allocator, harness.io(), harness.queryConfig(), "up == 1");
    defer result.deinit();

    const recorded = harness.server.lastRequest().?;
    try testing.expectEqualStrings("/api/v1/query", recorded.path);
    try testing.expect(std.mem.indexOf(u8, recorded.target, "query=") != null);
}

test "prometheuz behaviour: a range query returns a matrix of points" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var result = try prometheuz.queryRange(
        testing.allocator,
        harness.io(),
        harness.queryConfig(),
        "zix_temperature_celsius",
        1700000000,
        1700000030,
        "15s",
    );
    defer result.deinit();

    try testing.expectEqual(prometheuz.query_mod.ResultType.matrix, result.result_type);
    try testing.expectEqual(@as(usize, 1), result.matrix.len);
    try testing.expectEqual(@as(usize, 3), result.matrix[0].values.len);
    try testing.expectEqual(@as(f64, 21.5), result.matrix[0].values[0].value);
}

test "prometheuz behaviour: a range query carries its window and step" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var result = try prometheuz.queryRange(
        testing.allocator,
        harness.io(),
        harness.queryConfig(),
        "up",
        1700000000,
        1700000030,
        "15s",
    );
    defer result.deinit();

    const target = harness.server.lastRequest().?.target;
    try testing.expect(std.mem.indexOf(u8, target, "start=1700000000") != null);
    try testing.expect(std.mem.indexOf(u8, target, "end=1700000030") != null);
    try testing.expect(std.mem.indexOf(u8, target, "step=15s") != null);
}

test "prometheuz behaviour: a remote write posts snappy protobuf" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const samples = [_]prometheuz.Sample{
        .{ .name = "zix_requests_total", .labels = &.{}, .value = 5, .timestamp_ms = null },
        .{ .name = "zix_temperature_celsius", .labels = &.{}, .value = 21.5, .timestamp_ms = null },
    };

    try prometheuz.remoteWrite(testing.allocator, harness.io(), harness.writeConfig(), &samples);

    const recorded = harness.server.lastRequest().?;
    try testing.expectEqualStrings("POST", recorded.method);
    try testing.expectEqualStrings("/api/v1/write", recorded.path);
    try testing.expectEqualStrings("snappy", recorded.content_encoding);
    try testing.expect(recorded.body.len > 0);
}

test "prometheuz behaviour: a remote write body is snappy framed" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    const samples = [_]prometheuz.Sample{
        .{ .name = "zix_requests_total", .labels = &.{}, .value = 5, .timestamp_ms = null },
    };

    try prometheuz.remoteWrite(testing.allocator, harness.io(), harness.writeConfig(), &samples);

    // the driver only encodes, so the check is on the frame it produced: a
    // snappy block starts with the varint length of the decompressed body
    const body = harness.server.lastRequest().?.body;
    try testing.expect(body.len > 1);
    try testing.expect(body[0] != 0);
}

test "prometheuz behaviour: an empty remote write sends nothing at all" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    try prometheuz.remoteWrite(testing.allocator, harness.io(), harness.writeConfig(), &.{});

    try testing.expectEqual(@as(usize, 0), harness.server.requestCount());
}

test "prometheuz behaviour: a registry exposes what a scrape can read back" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var registry = prometheuz.Registry.init(testing.allocator);
    defer registry.deinit();

    const jobs = try registry.counter("zix_jobs_total", "Jobs run.", &.{"queue"});
    jobs.with(&.{"default"}).inc();
    jobs.with(&.{"default"}).add(4);

    const depth = try registry.gauge("zix_queue_depth", "Queued jobs.", &.{});
    depth.with(&.{}).set(7);

    // expose and parse both take an arena: they allocate intermediates they
    // do not individually free
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const exposed = try prometheuz.expose(arena.allocator(), &registry);

    // what the registry produced must parse back through the driver's own parser
    const families = try prometheuz.parse(arena.allocator(), exposed);
    try testing.expectEqual(@as(usize, 2), families.len);
}

test "prometheuz behaviour: a background scraper publishes a snapshot" {
    var harness: Harness = undefined;
    try harness.open();
    defer harness.stop();

    var config = harness.scrapeConfig();
    config.scrape_interval_ms = 20;

    const scraper = try prometheuz.Scraper.start(testing.allocator, harness.io(), config);
    defer scraper.deinit();

    // wait for a poll that actually reached the server rather than guessing at
    // a sleep length
    while (harness.server.requestCount() == 0) std.atomic.spinLoopHint();

    while (true) {
        const snapshot = scraper.latest();
        defer snapshot.release();

        if (!snapshot.up) continue;

        try testing.expect(snapshot.family("zix_requests_total") != null);

        break;
    }
}
