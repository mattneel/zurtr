//! remote_write.zig: push samples to a Prometheus remote_write receiver
//! (POST /api/v1/write, protobuf WriteRequest body, snappy-compressed).
//! Schema: prometheus.WriteRequest{ repeated TimeSeries timeseries = 1 },
//! TimeSeries{ repeated Label labels = 1; repeated Sample samples = 2 },
//! Label{ string name = 1; string value = 2 }, Sample{ double value = 1;
//! int64 timestamp = 2 }. The metric name travels as the conventional
//! `__name__` label, same as real Prometheus.

const std = @import("std");
const builtin = @import("builtin");
const config_mod = @import("config.zig");
const http_client = @import("http_client.zig");
const protobuf = @import("protobuf.zig");
const snappy = @import("snappy.zig");
const sample_mod = @import("sample.zig");

const WriteConfig = config_mod.WriteConfig;
const Sample = sample_mod.Sample;

/// Push `samples` to config's remote_write receiver. Each sample becomes
/// one TimeSeries (its name as the `__name__` label, plus its own labels)
/// carrying one Sample point. A sample with no timestamp is stamped with
/// the current wall-clock time.
///
/// Return:
/// - void on a 2xx response
/// - error.PrometheuzRemoteWriteRejected (non-2xx response)
/// - error.OutOfMemory
pub fn remoteWrite(allocator: std.mem.Allocator, io: std.Io, config: WriteConfig, samples: []const Sample) !void {
    if (samples.len == 0) return;

    const now_ms = std.Io.Clock.real.now(io).toMilliseconds();

    const body = try encodeWriteRequest(allocator, samples, now_ms);
    defer allocator.free(body);

    const compressed = try snappy.encode(allocator, body);
    defer allocator.free(compressed);

    var response = try http_client.post(allocator, io, config.ip, config.port, config.path, .{
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/x-protobuf" },
            .{ .name = "Content-Encoding", .value = "snappy" },
            .{ .name = "X-Prometheus-Remote-Write-Version", .value = "0.1.0" },
        },
        .body = compressed,
        .connect_timeout_ms = config.conn_timeout_ms,
        .max_response_body = config.max_response_body,
    });
    defer response.deinit();

    try checkStatus(response.status());
}

fn checkStatus(status_code: u16) !void {
    if (status_code < 200 or status_code >= 300) return error.PrometheuzRemoteWriteRejected;
}

// --------------------------------------------------------- //

fn encodeWriteRequest(allocator: std.mem.Allocator, samples: []const Sample, now_ms: i64) ![]u8 {
    var request: protobuf.Builder = .{};
    defer request.deinit(allocator);

    for (samples) |current_sample| {
        const series_bytes = try encodeTimeSeries(allocator, current_sample, now_ms);
        defer allocator.free(series_bytes);

        try request.writeMessage(allocator, 1, series_bytes); // WriteRequest.timeseries = 1
    }

    return request.toOwnedSlice(allocator);
}

fn encodeTimeSeries(allocator: std.mem.Allocator, current_sample: Sample, now_ms: i64) ![]u8 {
    var series: protobuf.Builder = .{};
    defer series.deinit(allocator);

    const name_label = try encodeLabel(allocator, "__name__", current_sample.name);
    defer allocator.free(name_label);
    try series.writeMessage(allocator, 1, name_label); // TimeSeries.labels = 1

    for (current_sample.labels) |label| {
        const label_bytes = try encodeLabel(allocator, label.name, label.value);
        defer allocator.free(label_bytes);
        try series.writeMessage(allocator, 1, label_bytes);
    }

    var point: protobuf.Builder = .{};
    defer point.deinit(allocator);
    try point.writeDouble(allocator, 1, current_sample.value);
    try point.writeInt64(allocator, 2, current_sample.timestamp_ms orelse now_ms);
    const point_bytes = try point.toOwnedSlice(allocator);
    defer allocator.free(point_bytes);
    try series.writeMessage(allocator, 2, point_bytes); // TimeSeries.samples = 2

    return series.toOwnedSlice(allocator);
}

fn encodeLabel(allocator: std.mem.Allocator, name: []const u8, value: []const u8) ![]u8 {
    var label: protobuf.Builder = .{};
    defer label.deinit(allocator);
    try label.writeString(allocator, 1, name);
    try label.writeString(allocator, 2, value);

    return label.toOwnedSlice(allocator);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

/// A tiny protobuf reader, test-only: walks tags and length-delimited
/// fields to verify encodeWriteRequest's actual output, not just its
/// intended shape.
const TestReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readVarint(self: *TestReader) u64 {
        var result: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const byte = self.bytes[self.pos];
            self.pos += 1;
            result |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) break;
            shift += 7;
        }

        return result;
    }

    const Tag = struct { field: u32, wire_type: u3 };

    fn readTag(self: *TestReader) Tag {
        const raw = self.readVarint();

        return .{ .field = @intCast(raw >> 3), .wire_type = @intCast(raw & 0x7) };
    }

    fn readLengthDelimited(self: *TestReader) []const u8 {
        const len = self.readVarint();
        const start = self.pos;
        self.pos += len;

        return self.bytes[start..self.pos];
    }

    fn readFixed64(self: *TestReader) u64 {
        const value = std.mem.readInt(u64, self.bytes[self.pos..][0..8], .little);
        self.pos += 8;

        return value;
    }

    fn atEnd(self: *const TestReader) bool {
        return self.pos >= self.bytes.len;
    }
};

test "prometheuz: encodeWriteRequest round-trips a labeled sample" {
    const labels = [_]sample_mod.Label{.{ .name = "reason", .value = "user_create_failed" }};
    const samples = [_]Sample{.{ .name = "app_write_errors_total", .labels = &labels, .value = 3, .timestamp_ms = 1_700_000_000_000 }};

    const body = try encodeWriteRequest(testing.allocator, &samples, 0);
    defer testing.allocator.free(body);

    var top = TestReader{ .bytes = body };
    const outer_tag = top.readTag();
    try testing.expectEqual(@as(u32, 1), outer_tag.field);
    try testing.expectEqual(@as(u3, 2), outer_tag.wire_type);
    const series_bytes = top.readLengthDelimited();
    try testing.expect(top.atEnd()); // exactly one TimeSeries in the request

    var series_reader = TestReader{ .bytes = series_bytes };
    var name_seen = false;
    var reason_seen = false;
    var value_seen: ?f64 = null;
    var timestamp_seen: ?i64 = null;

    while (!series_reader.atEnd()) {
        const field_tag = series_reader.readTag();
        if (field_tag.field == 1) {
            const label_bytes = series_reader.readLengthDelimited();
            var label_reader = TestReader{ .bytes = label_bytes };
            _ = label_reader.readTag();
            const name = label_reader.readLengthDelimited();
            _ = label_reader.readTag();
            const value = label_reader.readLengthDelimited();

            if (std.mem.eql(u8, name, "__name__")) {
                try testing.expectEqualStrings("app_write_errors_total", value);
                name_seen = true;
            } else if (std.mem.eql(u8, name, "reason")) {
                try testing.expectEqualStrings("user_create_failed", value);
                reason_seen = true;
            }
        } else if (field_tag.field == 2) {
            const point_bytes = series_reader.readLengthDelimited();
            var point_reader = TestReader{ .bytes = point_bytes };
            while (!point_reader.atEnd()) {
                const point_tag = point_reader.readTag();
                if (point_tag.field == 1) {
                    value_seen = @bitCast(point_reader.readFixed64());
                } else if (point_tag.field == 2) {
                    timestamp_seen = @intCast(point_reader.readVarint());
                }
            }
        }
    }

    try testing.expect(name_seen);
    try testing.expect(reason_seen);
    try testing.expectEqual(@as(f64, 3), value_seen.?);
    try testing.expectEqual(@as(i64, 1_700_000_000_000), timestamp_seen.?);
}

test "prometheuz: encodeWriteRequest stamps now_ms when a sample has no timestamp" {
    const samples = [_]Sample{.{ .name = "up", .labels = &.{}, .value = 1, .timestamp_ms = null }};

    const body = try encodeWriteRequest(testing.allocator, &samples, 1_650_000_000_000);
    defer testing.allocator.free(body);

    var top = TestReader{ .bytes = body };
    _ = top.readTag();
    const series_bytes = top.readLengthDelimited();

    var series_reader = TestReader{ .bytes = series_bytes };
    var timestamp_seen: ?i64 = null;
    while (!series_reader.atEnd()) {
        const field_tag = series_reader.readTag();
        if (field_tag.field == 2) {
            const point_bytes = series_reader.readLengthDelimited();
            var point_reader = TestReader{ .bytes = point_bytes };
            while (!point_reader.atEnd()) {
                const point_tag = point_reader.readTag();
                if (point_tag.field == 2) {
                    timestamp_seen = @intCast(point_reader.readVarint());
                } else {
                    _ = point_reader.readFixed64();
                }
            }
        } else {
            _ = series_reader.readLengthDelimited();
        }
    }

    try testing.expectEqual(@as(i64, 1_650_000_000_000), timestamp_seen.?);
}

test "prometheuz: remoteWrite is a no-op for an empty sample list" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // No network call happens (would hang/fail against port 1 otherwise).
    try remoteWrite(testing.allocator, threaded.io(), .{ .ip = "127.0.0.1", .port = 1 }, &.{});
}

test "prometheuz: remoteWrite surfaces a connection failure" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const samples = [_]Sample{.{ .name = "up", .labels = &.{}, .value = 1, .timestamp_ms = 0 }};

    // windows region: zig std's connect path leaves NTSTATUS
    // CONNECTION_REFUSED (0xc0000236) unmapped, so the refused
    // connect surfaces as error.Unexpected there.
    const expected = if (builtin.os.tag == .windows) error.Unexpected else error.ConnectionRefused;
    try testing.expectError(
        expected,
        remoteWrite(testing.allocator, threaded.io(), .{ .ip = "127.0.0.1", .port = 1 }, &samples),
    );
}

test "prometheuz: checkStatus accepts 2xx and rejects others" {
    try checkStatus(200);
    try checkStatus(204);
    try testing.expectError(error.PrometheuzRemoteWriteRejected, checkStatus(400));
    try testing.expectError(error.PrometheuzRemoteWriteRejected, checkStatus(500));
}
