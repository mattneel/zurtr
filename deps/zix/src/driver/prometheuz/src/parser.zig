//! Prometheus text exposition format 0.0.4 parser: turns a scraped response
//! body into arena-owned MetricFamily/Sample data. Full depth: HELP/TYPE
//! comments, multi-line histogram (_bucket/_sum/_count) and summary
//! (quantile) families, label escaping, +Inf/-Inf/Nan values, optional
//! timestamps.

const std = @import("std");
const sample_mod = @import("sample.zig");

const Sample = sample_mod.Sample;
const Label = sample_mod.Label;
const MetricFamily = sample_mod.MetricFamily;
const MetricType = sample_mod.MetricType;

const FamilyBuilder = struct {
    name: []const u8,
    help: []const u8,
    metric_type: MetricType,
    samples: std.ArrayList(Sample),
};

// --------------------------------------------------------- //

/// Parse `text` (a scraped /metrics body) into arena-owned metric families.
/// Every string in the result is either a sub-slice of an arena-owned copy
/// of `text`, or (for escaped label values and HELP text) freshly allocated
/// in `arena`. `text` itself does not need to outlive the call.
///
/// Return:
/// - []MetricFamily (arena-owned)
/// - error.PrometheuzInvalidSample (malformed labels, value, or timestamp)
pub fn parse(arena: std.mem.Allocator, text: []const u8) ![]MetricFamily {
    const owned_text = try arena.dupe(u8, text);

    var families: std.ArrayList(MetricFamily) = .empty;
    var current: ?FamilyBuilder = null;

    var line_iter = std.mem.splitScalar(u8, owned_text, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "# HELP ")) {
            try flushCurrent(arena, &families, &current);

            const rest = line["# HELP ".len..];
            const name_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
            const name = rest[0..name_end];
            const help_raw = if (name_end < rest.len) rest[name_end + 1 ..] else "";

            current = .{ .name = name, .help = try unescapeText(arena, help_raw, false), .metric_type = .untyped, .samples = .empty };

            continue;
        }

        if (std.mem.startsWith(u8, line, "# TYPE ")) {
            const rest = line["# TYPE ".len..];
            const name_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
            const name = rest[0..name_end];
            const type_str = if (name_end < rest.len) rest[name_end + 1 ..] else "";
            const metric_type = parseMetricType(type_str);

            if (current) |*fam| {
                if (std.mem.eql(u8, fam.name, name)) {
                    fam.metric_type = metric_type;

                    continue;
                }
            }

            try flushCurrent(arena, &families, &current);
            current = .{ .name = name, .help = "", .metric_type = metric_type, .samples = .empty };

            continue;
        }

        if (line[0] == '#') continue; // plain comment line, ignored

        const parsed_sample = try parseSampleLine(arena, line);

        if (current) |*fam| {
            if (matchesFamily(parsed_sample.name, fam.name, fam.metric_type)) {
                try fam.samples.append(arena, parsed_sample);

                continue;
            }

            try flushCurrent(arena, &families, &current);
        }

        current = .{ .name = parsed_sample.name, .help = "", .metric_type = .untyped, .samples = .empty };
        try current.?.samples.append(arena, parsed_sample);
    }

    try flushCurrent(arena, &families, &current);

    return families.toOwnedSlice(arena);
}

// --------------------------------------------------------- //

fn flushCurrent(arena: std.mem.Allocator, families: *std.ArrayList(MetricFamily), current: *?FamilyBuilder) !void {
    var fam = current.* orelse return;

    try families.append(arena, .{
        .name = fam.name,
        .help = fam.help,
        .metric_type = fam.metric_type,
        .samples = try fam.samples.toOwnedSlice(arena),
    });
    current.* = null;
}

/// Whether `sample_name` belongs to `family_name`: an exact match (counter,
/// gauge, untyped, or a summary's quantile line), or, for histogram and
/// summary families, one of the suffixed lines (_bucket, _sum, _count).
fn matchesFamily(sample_name: []const u8, family_name: []const u8, family_type: MetricType) bool {
    if (std.mem.eql(u8, sample_name, family_name)) return true;

    const suffixes: []const []const u8 = switch (family_type) {
        .histogram => &.{ "_bucket", "_sum", "_count" },
        .summary => &.{ "_sum", "_count" },
        else => &.{},
    };

    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, sample_name, suffix) and
            std.mem.eql(u8, sample_name[0 .. sample_name.len - suffix.len], family_name)) return true;
    }

    return false;
}

fn parseMetricType(text: []const u8) MetricType {
    if (std.mem.eql(u8, text, "counter")) return .counter;
    if (std.mem.eql(u8, text, "gauge")) return .gauge;
    if (std.mem.eql(u8, text, "histogram")) return .histogram;
    if (std.mem.eql(u8, text, "summary")) return .summary;

    return .untyped;
}

/// Parse one metric line: `name{label="value",...} value [timestamp]` or
/// `name value [timestamp]`.
fn parseSampleLine(arena: std.mem.Allocator, line: []const u8) !Sample {
    const name_end = std.mem.indexOfAny(u8, line, "{ ") orelse line.len;
    const name = line[0..name_end];
    var pos = name_end;

    var labels: []const Label = &.{};
    if (pos < line.len and line[pos] == '{') {
        const close = try findClosingBrace(line, pos + 1);
        labels = try parseLabels(arena, line[pos + 1 .. close]);
        pos = close + 1;
    }

    while (pos < line.len and line[pos] == ' ') pos += 1;

    const value_end = std.mem.indexOfScalarPos(u8, line, pos, ' ') orelse line.len;
    const value = try parseSampleValue(line[pos..value_end]);
    pos = value_end;

    while (pos < line.len and line[pos] == ' ') pos += 1;

    const timestamp_ms: ?i64 = if (pos < line.len)
        std.fmt.parseInt(i64, line[pos..], 10) catch return error.PrometheuzInvalidSample
    else
        null;

    return .{ .name = name, .labels = labels, .value = value, .timestamp_ms = timestamp_ms };
}

/// Find the `}` that closes the label block starting at `start` (the byte
/// right after `{`), honoring quoted label values so a literal `}` inside a
/// value does not end the block early.
fn findClosingBrace(line: []const u8, start: usize) !usize {
    var pos = start;
    var in_quotes = false;
    var escaped = false;

    while (pos < line.len) : (pos += 1) {
        const byte = line[pos];

        if (in_quotes) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_quotes = false;
            }

            continue;
        }

        if (byte == '"') {
            in_quotes = true;
        } else if (byte == '}') {
            return pos;
        }
    }

    return error.PrometheuzInvalidSample;
}

fn parseSampleValue(text: []const u8) !f64 {
    if (std.mem.eql(u8, text, "+Inf") or std.mem.eql(u8, text, "Inf")) return std.math.inf(f64);
    if (std.mem.eql(u8, text, "-Inf")) return -std.math.inf(f64);
    if (std.mem.eql(u8, text, "Nan") or std.mem.eql(u8, text, "NaN")) return std.math.nan(f64);

    return std.fmt.parseFloat(f64, text) catch error.PrometheuzInvalidSample;
}

fn parseLabels(arena: std.mem.Allocator, text: []const u8) ![]const Label {
    var labels: std.ArrayList(Label) = .empty;
    var pos: usize = 0;

    while (pos < text.len) {
        while (pos < text.len and (text[pos] == ' ' or text[pos] == ',')) pos += 1;
        if (pos >= text.len) break;

        const eq_pos = std.mem.indexOfScalarPos(u8, text, pos, '=') orelse return error.PrometheuzInvalidSample;
        const label_name = std.mem.trim(u8, text[pos..eq_pos], " ");
        pos = eq_pos + 1;

        if (pos >= text.len or text[pos] != '"') return error.PrometheuzInvalidSample;
        pos += 1;

        const value_start = pos;
        var escaped = false;
        while (pos < text.len) : (pos += 1) {
            if (escaped) {
                escaped = false;

                continue;
            }
            if (text[pos] == '\\') {
                escaped = true;

                continue;
            }
            if (text[pos] == '"') break;
        }
        if (pos >= text.len) return error.PrometheuzInvalidSample;

        const label_value = try unescapeText(arena, text[value_start..pos], true);
        pos += 1; // past the closing quote

        try labels.append(arena, .{ .name = label_name, .value = label_value });
    }

    return labels.toOwnedSlice(arena);
}

/// Unescape `\\`, `\n`, and (label values only) `\"`. Returns the input
/// slice unchanged (no allocation) when there is nothing to unescape.
fn unescapeText(arena: std.mem.Allocator, raw: []const u8, allow_quote_escape: bool) ![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '\\') == null) return raw;

    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < raw.len) {
        if (raw[index] == '\\' and index + 1 < raw.len) {
            switch (raw[index + 1]) {
                '\\' => try out.append(arena, '\\'),
                'n' => try out.append(arena, '\n'),
                '"' => if (allow_quote_escape) {
                    try out.append(arena, '"');
                } else {
                    try out.append(arena, raw[index]);
                    try out.append(arena, raw[index + 1]);
                },
                else => {
                    try out.append(arena, raw[index]);
                    try out.append(arena, raw[index + 1]);
                },
            }
            index += 2;

            continue;
        }

        try out.append(arena, raw[index]);
        index += 1;
    }

    return out.toOwnedSlice(arena);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: parser counter with labels" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text =
        "# HELP http_requests_total The total number of HTTP requests.\n" ++
        "# TYPE http_requests_total counter\n" ++
        "http_requests_total{method=\"post\",code=\"200\"} 1027 1395066363000\n" ++
        "http_requests_total{method=\"post\",code=\"400\"}    3 1395066363000\n";

    const families = try parse(arena, text);

    try testing.expectEqual(@as(usize, 1), families.len);
    const family = families[0];
    try testing.expectEqualStrings("http_requests_total", family.name);
    try testing.expectEqualStrings("The total number of HTTP requests.", family.help);
    try testing.expectEqual(MetricType.counter, family.metric_type);
    try testing.expectEqual(@as(usize, 2), family.samples.len);
    try testing.expectEqual(@as(f64, 1027), family.samples[0].value);
    try testing.expectEqualStrings("post", family.samples[0].label("method").?);
    try testing.expectEqual(@as(?i64, 1395066363000), family.samples[0].timestamp_ms);
    try testing.expectEqual(@as(f64, 3), family.samples[1].value);
}

test "prometheuz: parser escaped label values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1.458255915e9\n";

    const families = try parse(arena, text);

    try testing.expectEqual(@as(usize, 1), families.len);
    const sample = families[0].samples[0];
    try testing.expectEqualStrings("C:\\DIR\\FILE.TXT", sample.label("path").?);
    try testing.expectEqualStrings("Cannot find file:\n\"FILE.TXT\"", sample.label("error").?);
    try testing.expectEqual(@as(f64, 1.458255915e9), sample.value);
}

test "prometheuz: parser scalar without labels or timestamp" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const families = try parse(arena, "metric_without_timestamp_and_labels 12.47\n");

    try testing.expectEqual(@as(usize, 1), families.len);
    try testing.expectEqualStrings("metric_without_timestamp_and_labels", families[0].name);
    try testing.expectEqual(MetricType.untyped, families[0].metric_type);
    try testing.expectEqual(@as(f64, 12.47), families[0].samples[0].value);
    try testing.expectEqual(@as(?i64, null), families[0].samples[0].timestamp_ms);
}

test "prometheuz: parser special float values and negative timestamp" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const families = try parse(arena, "something_weird{problem=\"division by zero\"} +Inf -3982045\n");

    const sample = families[0].samples[0];
    try testing.expect(std.math.isPositiveInf(sample.value));
    try testing.expectEqual(@as(?i64, -3982045), sample.timestamp_ms);
}

test "prometheuz: parser multi-line histogram family" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text =
        "# HELP http_request_duration_seconds A histogram of the request duration.\n" ++
        "# TYPE http_request_duration_seconds histogram\n" ++
        "http_request_duration_seconds_bucket{le=\"0.05\"} 24054\n" ++
        "http_request_duration_seconds_bucket{le=\"0.1\"} 33444\n" ++
        "http_request_duration_seconds_bucket{le=\"+Inf\"} 144320\n" ++
        "http_request_duration_seconds_sum 53423\n" ++
        "http_request_duration_seconds_count 144320\n";

    const families = try parse(arena, text);

    try testing.expectEqual(@as(usize, 1), families.len);
    const family = families[0];
    try testing.expectEqual(MetricType.histogram, family.metric_type);
    try testing.expectEqual(@as(usize, 5), family.samples.len);
    try testing.expectEqual(@as(f64, 33444), family.bucket("0.1").?.value);
    try testing.expectEqual(@as(f64, 53423), family.sumSample().?.value);
    try testing.expectEqual(@as(f64, 144320), family.countSample().?.value);
}

test "prometheuz: parser multi-line summary family" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text =
        "# HELP rpc_duration_seconds A summary of the RPC duration in seconds.\n" ++
        "# TYPE rpc_duration_seconds summary\n" ++
        "rpc_duration_seconds{quantile=\"0.01\"} 3102\n" ++
        "rpc_duration_seconds{quantile=\"0.5\"} 4773\n" ++
        "rpc_duration_seconds{quantile=\"0.99\"} 76656\n" ++
        "rpc_duration_seconds_sum 1.7560473e+07\n" ++
        "rpc_duration_seconds_count 2693\n";

    const families = try parse(arena, text);

    try testing.expectEqual(@as(usize, 1), families.len);
    const family = families[0];
    try testing.expectEqual(MetricType.summary, family.metric_type);
    try testing.expectEqual(@as(f64, 4773), family.quantile("0.5").?.value);
    try testing.expectEqual(@as(f64, 2693), family.countSample().?.value);
}

test "prometheuz: parser multiple families, comments, and blank lines" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text =
        "# this is a plain comment, ignored\n" ++
        "\n" ++
        "# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.\n" ++
        "# TYPE node_cpu_seconds_total counter\n" ++
        "node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 1234.5\n" ++
        "\n" ++
        "# HELP node_memory_free_bytes Free memory in bytes.\n" ++
        "# TYPE node_memory_free_bytes gauge\n" ++
        "node_memory_free_bytes 8589934592\n";

    const families = try parse(arena, text);

    try testing.expectEqual(@as(usize, 2), families.len);
    try testing.expectEqualStrings("node_cpu_seconds_total", families[0].name);
    try testing.expectEqual(MetricType.counter, families[0].metric_type);
    try testing.expectEqualStrings("node_memory_free_bytes", families[1].name);
    try testing.expectEqual(MetricType.gauge, families[1].metric_type);
    try testing.expectEqual(@as(f64, 8589934592), families[1].samples[0].value);
}

test "prometheuz: parser rejects an unterminated label block" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectError(error.PrometheuzInvalidSample, parse(arena, "broken_metric{label=\"value\" 5\n"));
}
