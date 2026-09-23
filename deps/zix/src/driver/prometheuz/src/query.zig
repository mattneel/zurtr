//! query.zig: PromQL instant query (GET /api/v1/query) and ranged query
//! (GET /api/v1/query_range) against a real Prometheus, plus JSON response
//! decode into arena-owned vector/matrix results.

const std = @import("std");
const config_mod = @import("config.zig");
const http_client = @import("http_client.zig");
const sample_mod = @import("sample.zig");

const QueryConfig = config_mod.QueryConfig;
const Label = sample_mod.Label;

// --------------------------------------------------------- //

/// One (timestamp, value) point, as PromQL reports it: seconds since epoch,
/// fractional.
pub const Point = struct {
    timestamp: f64,
    value: f64,
};

/// One series in an instant-query vector result.
pub const VectorEntry = struct {
    metric: []const Label,
    timestamp: f64,
    value: f64,
};

/// One series in a ranged-query matrix result.
pub const MatrixEntry = struct {
    metric: []const Label,
    values: []const Point,
};

pub const ResultType = enum { vector, matrix, scalar, string, unknown };

/// A PromQL response. Only `vector` or `matrix` is populated, matching
/// `result_type` (an instant query yields vector, a range query yields
/// matrix).
pub const QueryResult = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    result_type: ResultType,
    vector: []const VectorEntry,
    matrix: []const MatrixEntry,

    pub fn deinit(self: *QueryResult) void {
        const owner = self.allocator;
        self.arena.deinit();
        owner.destroy(self);
    }
};

// --------------------------------------------------------- //

/// Instant PromQL query: GET /api/v1/query?query=<expr>.
///
/// Return:
/// - *QueryResult (caller must result.deinit()), result_type = .vector
/// - error.PrometheuzQueryFailed (non-200 response, or "status":"error" in the body)
/// - error.PrometheuzInvalidResponse (malformed JSON or an unexpected shape)
pub fn query(allocator: std.mem.Allocator, io: std.Io, config: QueryConfig, expr: []const u8) !*QueryResult {
    return runQuery(allocator, io, config, "/api/v1/query", &.{
        .{ .name = "query", .value = expr },
    });
}

/// Ranged PromQL query: GET /api/v1/query_range?query=<expr>&start=<s>&end=<e>&step=<step>.
/// `start_unix_s`/`end_unix_s` are Unix seconds, `step` is a PromQL
/// duration string (e.g. "15s").
///
/// Return:
/// - *QueryResult (caller must result.deinit()), result_type = .matrix
/// - error.PrometheuzQueryFailed (non-200 response, or "status":"error" in the body)
/// - error.PrometheuzInvalidResponse (malformed JSON or an unexpected shape)
pub fn queryRange(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: QueryConfig,
    expr: []const u8,
    start_unix_s: i64,
    end_unix_s: i64,
    step: []const u8,
) !*QueryResult {
    var start_buf: [32]u8 = undefined;
    var end_buf: [32]u8 = undefined;
    const start_str = try std.fmt.bufPrint(&start_buf, "{d}", .{start_unix_s});
    const end_str = try std.fmt.bufPrint(&end_buf, "{d}", .{end_unix_s});

    return runQuery(allocator, io, config, "/api/v1/query_range", &.{
        .{ .name = "query", .value = expr },
        .{ .name = "start", .value = start_str },
        .{ .name = "end", .value = end_str },
        .{ .name = "step", .value = step },
    });
}

// --------------------------------------------------------- //

const QueryParam = struct {
    name: []const u8,
    value: []const u8,
};

fn runQuery(allocator: std.mem.Allocator, io: std.Io, config: QueryConfig, path: []const u8, params: []const QueryParam) !*QueryResult {
    var path_buf: std.ArrayList(u8) = .empty;
    defer path_buf.deinit(allocator);

    try path_buf.appendSlice(allocator, path);
    for (params, 0..) |param, index| {
        try path_buf.append(allocator, if (index == 0) '?' else '&');
        try path_buf.appendSlice(allocator, param.name);
        try path_buf.append(allocator, '=');
        try urlEncodeAppend(&path_buf, allocator, param.value);
    }

    var response = try http_client.get(allocator, io, config.ip, config.port, path_buf.items, .{
        .connect_timeout_ms = config.conn_timeout_ms,
        .max_response_body = config.max_response_body,
    });
    defer response.deinit();

    if (response.status() != 200) return error.PrometheuzQueryFailed;

    return parseResponse(allocator, response.body());
}

fn urlEncodeAppend(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    const hex_digits = "0123456789ABCDEF";

    for (text) |byte| {
        const is_unreserved = std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '~';
        if (is_unreserved) {
            try out.append(allocator, byte);
        } else {
            try out.append(allocator, '%');
            try out.append(allocator, hex_digits[byte >> 4]);
            try out.append(allocator, hex_digits[byte & 0x0f]);
        }
    }
}

// --------------------------------------------------------- //

fn parseResponse(allocator: std.mem.Allocator, body: []const u8) !*QueryResult {
    const self = try allocator.create(QueryResult);
    errdefer allocator.destroy(self);

    self.arena = std.heap.ArenaAllocator.init(allocator);
    errdefer self.arena.deinit();
    const arena = self.arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return error.PrometheuzInvalidResponse;
    const root_object = jsonObject(root) orelse return error.PrometheuzInvalidResponse;

    const status = jsonString(root_object.get("status")) orelse return error.PrometheuzInvalidResponse;
    if (!std.mem.eql(u8, status, "success")) return error.PrometheuzQueryFailed;

    const data = jsonObject(root_object.get("data") orelse return error.PrometheuzInvalidResponse) orelse return error.PrometheuzInvalidResponse;
    const result_type_str = jsonString(data.get("resultType")) orelse return error.PrometheuzInvalidResponse;
    const result_array = jsonArray(data.get("result") orelse return error.PrometheuzInvalidResponse) orelse return error.PrometheuzInvalidResponse;

    self.allocator = allocator;
    self.vector = &.{};
    self.matrix = &.{};

    if (std.mem.eql(u8, result_type_str, "vector")) {
        self.result_type = .vector;
        self.vector = try parseVector(arena, result_array);
    } else if (std.mem.eql(u8, result_type_str, "matrix")) {
        self.result_type = .matrix;
        self.matrix = try parseMatrix(arena, result_array);
    } else if (std.mem.eql(u8, result_type_str, "scalar")) {
        self.result_type = .scalar;
    } else if (std.mem.eql(u8, result_type_str, "string")) {
        self.result_type = .string;
    } else {
        self.result_type = .unknown;
    }

    return self;
}

fn parseVector(arena: std.mem.Allocator, entries: []const std.json.Value) ![]const VectorEntry {
    var out = try arena.alloc(VectorEntry, entries.len);

    for (entries, 0..) |entry_value, index| {
        const entry_object = jsonObject(entry_value) orelse return error.PrometheuzInvalidResponse;
        const metric = try parseMetric(arena, entry_object.get("metric"));
        const point_array = jsonArray(entry_object.get("value") orelse return error.PrometheuzInvalidResponse) orelse return error.PrometheuzInvalidResponse;
        if (point_array.len != 2) return error.PrometheuzInvalidResponse;

        out[index] = .{
            .metric = metric,
            .timestamp = try jsonNumber(point_array[0]),
            .value = try jsonNumber(point_array[1]),
        };
    }

    return out;
}

fn parseMatrix(arena: std.mem.Allocator, entries: []const std.json.Value) ![]const MatrixEntry {
    var out = try arena.alloc(MatrixEntry, entries.len);

    for (entries, 0..) |entry_value, index| {
        const entry_object = jsonObject(entry_value) orelse return error.PrometheuzInvalidResponse;
        const metric = try parseMetric(arena, entry_object.get("metric"));
        const points_array = jsonArray(entry_object.get("values") orelse return error.PrometheuzInvalidResponse) orelse return error.PrometheuzInvalidResponse;

        var points = try arena.alloc(Point, points_array.len);
        for (points_array, 0..) |point_value, point_index| {
            const point_array = jsonArray(point_value) orelse return error.PrometheuzInvalidResponse;
            if (point_array.len != 2) return error.PrometheuzInvalidResponse;

            points[point_index] = .{
                .timestamp = try jsonNumber(point_array[0]),
                .value = try jsonNumber(point_array[1]),
            };
        }

        out[index] = .{ .metric = metric, .values = points };
    }

    return out;
}

fn parseMetric(arena: std.mem.Allocator, metric_value: ?std.json.Value) ![]const Label {
    const metric_object = jsonObject(metric_value orelse return &.{}) orelse return &.{};

    var labels = try arena.alloc(Label, metric_object.count());
    var iterator = metric_object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| {
        labels[index] = .{
            .name = entry.key_ptr.*,
            .value = jsonString(entry.value_ptr.*) orelse "",
        };
        index += 1;
    }

    return labels;
}

fn jsonObject(value: ?std.json.Value) ?std.json.ObjectMap {
    const unwrapped = value orelse return null;
    return switch (unwrapped) {
        .object => |object| object,
        else => null,
    };
}

fn jsonArray(value: std.json.Value) ?[]const std.json.Value {
    return switch (value) {
        .array => |array| array.items,
        else => null,
    };
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const unwrapped = value orelse return null;
    return switch (unwrapped) {
        .string => |text| text,
        .number_string => |text| text,
        else => null,
    };
}

fn jsonNumber(value: std.json.Value) !f64 {
    return switch (value) {
        .float => |number| number,
        .integer => |number| @floatFromInt(number),
        .string, .number_string => |text| std.fmt.parseFloat(f64, text) catch error.PrometheuzInvalidResponse,
        else => error.PrometheuzInvalidResponse,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: query parses a vector result" {
    const body =
        \\{"status":"success","data":{"resultType":"vector","result":[
        \\  {"metric":{"__name__":"up","job":"prometheus"},"value":[1435781451.781,"1"]}
        \\]}}
    ;

    var result = try parseResponse(testing.allocator, body);
    defer result.deinit();

    try testing.expectEqual(ResultType.vector, result.result_type);
    try testing.expectEqual(@as(usize, 1), result.vector.len);
    try testing.expectEqual(@as(f64, 1), result.vector[0].value);
    try testing.expectEqual(@as(f64, 1435781451.781), result.vector[0].timestamp);

    var found_job = false;
    for (result.vector[0].metric) |label| {
        if (std.mem.eql(u8, label.name, "job")) {
            try testing.expectEqualStrings("prometheus", label.value);
            found_job = true;
        }
    }
    try testing.expect(found_job);
}

test "prometheuz: query parses a matrix result" {
    const body =
        \\{"status":"success","data":{"resultType":"matrix","result":[
        \\  {"metric":{"__name__":"up"},"values":[[1000,"1"],[1015,"0"]]}
        \\]}}
    ;

    var result = try parseResponse(testing.allocator, body);
    defer result.deinit();

    try testing.expectEqual(ResultType.matrix, result.result_type);
    try testing.expectEqual(@as(usize, 1), result.matrix.len);
    try testing.expectEqual(@as(usize, 2), result.matrix[0].values.len);
    try testing.expectEqual(@as(f64, 1), result.matrix[0].values[0].value);
    try testing.expectEqual(@as(f64, 0), result.matrix[0].values[1].value);
}

test "prometheuz: query surfaces an error status" {
    const body =
        \\{"status":"error","errorType":"bad_data","error":"parse error"}
    ;

    try testing.expectError(error.PrometheuzQueryFailed, parseResponse(testing.allocator, body));
}

test "prometheuz: query rejects malformed json" {
    try testing.expectError(error.PrometheuzInvalidResponse, parseResponse(testing.allocator, "not json"));
}

test "prometheuz: query url-encodes the expression" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);

    try urlEncodeAppend(&buf, testing.allocator, "up{job=\"prometheus\"}");

    try testing.expectEqualStrings("up%7Bjob%3D%22prometheus%22%7D", buf.items);
}
