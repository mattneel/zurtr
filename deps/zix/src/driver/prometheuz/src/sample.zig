//! Parsed Prometheus text-format types: Sample, Label, MetricFamily,
//! MetricType, plus small allocation-free query helpers for histogram
//! buckets and summary quantiles.

const std = @import("std");

/// The four Prometheus metric kinds, plus untyped (no # TYPE line, or an
/// unrecognized type keyword).
pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,
    untyped,
};

/// One label name/value pair on a sample.
pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// One parsed sample line. `name` carries the histogram/summary suffix
/// (`_bucket`, `_sum`, `_count`) exactly as the wire format does. `le` and
/// `quantile` are ordinary labels, not separate fields.
pub const Sample = struct {
    name: []const u8,
    labels: []const Label,
    value: f64,
    timestamp_ms: ?i64,

    /// First label value with this name. null when absent.
    pub fn label(self: Sample, name: []const u8) ?[]const u8 {
        for (self.labels) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }

        return null;
    }
};

/// A metric family: one HELP/TYPE header plus every sample line that
/// belongs to it. A counter/gauge family has one sample per label set, a
/// histogram/summary family has several: bucket/quantile lines plus _sum
/// and _count.
pub const MetricFamily = struct {
    name: []const u8,
    help: []const u8,
    metric_type: MetricType,
    samples: []const Sample,

    /// The _sum sample of a histogram or summary family. null when absent.
    pub fn sumSample(self: MetricFamily) ?Sample {
        return self.sampleWithSuffix("_sum");
    }

    /// The _count sample of a histogram or summary family. null when absent.
    pub fn countSample(self: MetricFamily) ?Sample {
        return self.sampleWithSuffix("_count");
    }

    /// The histogram bucket sample whose `le` label equals `le`, e.g.
    /// `bucket("0.5")`. null when absent.
    pub fn bucket(self: MetricFamily, le: []const u8) ?Sample {
        for (self.samples) |current_sample| {
            if (!std.mem.endsWith(u8, current_sample.name, "_bucket")) continue;
            if (!std.mem.eql(u8, current_sample.name[0 .. current_sample.name.len - "_bucket".len], self.name)) continue;
            const sample_le = current_sample.label("le") orelse continue;
            if (std.mem.eql(u8, sample_le, le)) return current_sample;
        }

        return null;
    }

    /// The summary quantile sample whose `quantile` label equals `q`, e.g.
    /// `quantile("0.99")`. null when absent.
    pub fn quantile(self: MetricFamily, q: []const u8) ?Sample {
        for (self.samples) |current_sample| {
            if (!std.mem.eql(u8, current_sample.name, self.name)) continue;
            const sample_quantile = current_sample.label("quantile") orelse continue;
            if (std.mem.eql(u8, sample_quantile, q)) return current_sample;
        }

        return null;
    }

    fn sampleWithSuffix(self: MetricFamily, suffix: []const u8) ?Sample {
        for (self.samples) |current_sample| {
            if (!std.mem.endsWith(u8, current_sample.name, suffix)) continue;
            if (std.mem.eql(u8, current_sample.name[0 .. current_sample.name.len - suffix.len], self.name)) return current_sample;
        }

        return null;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: sample label lookup" {
    const labels = [_]Label{
        .{ .name = "method", .value = "post" },
        .{ .name = "code", .value = "200" },
    };
    const value_sample = Sample{ .name = "http_requests_total", .labels = &labels, .value = 1027, .timestamp_ms = null };

    try testing.expectEqualStrings("post", value_sample.label("method").?);
    try testing.expectEqualStrings("200", value_sample.label("code").?);
    try testing.expectEqual(@as(?[]const u8, null), value_sample.label("missing"));
}

test "prometheuz: metric family histogram sum count and bucket" {
    const bucket_low = Sample{
        .name = "http_request_duration_seconds_bucket",
        .labels = &.{.{ .name = "le", .value = "0.1" }},
        .value = 33444,
        .timestamp_ms = null,
    };
    const bucket_high = Sample{
        .name = "http_request_duration_seconds_bucket",
        .labels = &.{.{ .name = "le", .value = "+Inf" }},
        .value = 144320,
        .timestamp_ms = null,
    };
    const sum = Sample{ .name = "http_request_duration_seconds_sum", .labels = &.{}, .value = 53423, .timestamp_ms = null };
    const count = Sample{ .name = "http_request_duration_seconds_count", .labels = &.{}, .value = 144320, .timestamp_ms = null };

    const family = MetricFamily{
        .name = "http_request_duration_seconds",
        .help = "A histogram of the request duration.",
        .metric_type = .histogram,
        .samples = &.{ bucket_low, bucket_high, sum, count },
    };

    try testing.expectEqual(@as(f64, 33444), family.bucket("0.1").?.value);
    try testing.expectEqual(@as(f64, 144320), family.bucket("+Inf").?.value);
    try testing.expectEqual(@as(?Sample, null), family.bucket("0.99"));
    try testing.expectEqual(@as(f64, 53423), family.sumSample().?.value);
    try testing.expectEqual(@as(f64, 144320), family.countSample().?.value);
}

test "prometheuz: metric family summary quantile" {
    const q50 = Sample{
        .name = "rpc_duration_seconds",
        .labels = &.{.{ .name = "quantile", .value = "0.5" }},
        .value = 4773,
        .timestamp_ms = null,
    };
    const sum = Sample{ .name = "rpc_duration_seconds_sum", .labels = &.{}, .value = 1.7560473e7, .timestamp_ms = null };

    const family = MetricFamily{
        .name = "rpc_duration_seconds",
        .help = "A summary of the RPC duration in seconds.",
        .metric_type = .summary,
        .samples = &.{ q50, sum },
    };

    try testing.expectEqual(@as(f64, 4773), family.quantile("0.5").?.value);
    try testing.expectEqual(@as(?Sample, null), family.quantile("0.99"));
    try testing.expectEqual(@as(f64, 1.7560473e7), family.sumSample().?.value);
}
