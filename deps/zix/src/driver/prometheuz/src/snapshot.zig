//! Snapshot: an immutable, refcounted parsed scrape result. Returned
//! directly by scrapeOnce(), or published by Scraper (RCU-style).

const std = @import("std");
const sample_mod = @import("sample.zig");
const parser = @import("parser.zig");

const MetricFamily = sample_mod.MetricFamily;
const Sample = sample_mod.Sample;

// --------------------------------------------------------- //

/// One scrape result: either a parsed set of families/samples (up = true),
/// or a captured failure reason (up = false). A failed scrape is
/// observable through the fields, never thrown at the reader.
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    up: bool,
    /// Wall-clock time the scrape completed, milliseconds since epoch.
    timestamp_ms: i64,
    duration_ms: u64,
    last_error: ?[]const u8,
    families: []const MetricFamily,
    /// Every family's samples, flattened. Shape remote_write's caller needs.
    samples: []const Sample,
    refcount: std.atomic.Value(u32),

    /// The metric family with this name. null when absent.
    pub fn family(self: *const Snapshot, name: []const u8) ?MetricFamily {
        for (self.families) |current_family| {
            if (std.mem.eql(u8, current_family.name, name)) return current_family;
        }

        return null;
    }

    /// Bump the refcount before handing this snapshot to another reader.
    /// Used by Scraper.latest(). Pair with release().
    pub fn retain(self: *Snapshot) void {
        _ = self.refcount.fetchAdd(1, .acq_rel);
    }

    /// Drop a reference. Frees the snapshot's arena once the count reaches
    /// zero.
    pub fn release(self: *Snapshot) void {
        if (self.refcount.fetchSub(1, .acq_rel) == 1) {
            const owner = self.allocator;
            self.arena.deinit();
            owner.destroy(self);
        }
    }

    /// Alias for release(), for scrapeOnce()'s single-owner call site.
    pub fn deinit(self: *Snapshot) void {
        self.release();
    }
};

// --------------------------------------------------------- //

/// Build a successful Snapshot by parsing `text` into a fresh arena.
///
/// Return:
/// - *Snapshot (refcount 1, caller owns)
/// - error.OutOfMemory
/// - error.PrometheuzInvalidSample (malformed text 0.0.4 body)
pub fn fromText(allocator: std.mem.Allocator, timestamp_ms: i64, duration_ms: u64, text: []const u8) !*Snapshot {
    const self = try allocator.create(Snapshot);
    errdefer allocator.destroy(self);

    self.arena = std.heap.ArenaAllocator.init(allocator);
    errdefer self.arena.deinit();

    const arena = self.arena.allocator();
    const families = try parser.parse(arena, text);
    const samples = try flattenSamples(arena, families);

    self.allocator = allocator;
    self.up = true;
    self.timestamp_ms = timestamp_ms;
    self.duration_ms = duration_ms;
    self.last_error = null;
    self.families = families;
    self.samples = samples;
    self.refcount = std.atomic.Value(u32).init(1);

    return self;
}

/// Build a failed Snapshot (up = false), carrying only the error text.
///
/// Return:
/// - *Snapshot (refcount 1, caller owns)
/// - error.OutOfMemory
pub fn failed(allocator: std.mem.Allocator, timestamp_ms: i64, duration_ms: u64, reason: []const u8) !*Snapshot {
    const self = try allocator.create(Snapshot);
    errdefer allocator.destroy(self);

    self.arena = std.heap.ArenaAllocator.init(allocator);
    errdefer self.arena.deinit();

    const arena = self.arena.allocator();

    self.allocator = allocator;
    self.up = false;
    self.timestamp_ms = timestamp_ms;
    self.duration_ms = duration_ms;
    self.last_error = try arena.dupe(u8, reason);
    self.families = &.{};
    self.samples = &.{};
    self.refcount = std.atomic.Value(u32).init(1);

    return self;
}

fn flattenSamples(arena: std.mem.Allocator, families: []const MetricFamily) ![]const Sample {
    var total: usize = 0;
    for (families) |current_family| total += current_family.samples.len;

    const flat = try arena.alloc(Sample, total);
    var index: usize = 0;
    for (families) |current_family| {
        for (current_family.samples) |current_sample| {
            flat[index] = current_sample;
            index += 1;
        }
    }

    return flat;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: snapshot fromText parses and flattens samples" {
    const text =
        "# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.\n" ++
        "# TYPE node_cpu_seconds_total counter\n" ++
        "node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 1234.5\n" ++
        "node_cpu_seconds_total{cpu=\"1\",mode=\"idle\"} 2345.6\n";

    var snapshot = try fromText(testing.allocator, 1_000, 5, text);
    defer snapshot.deinit();

    try testing.expect(snapshot.up);
    try testing.expectEqual(@as(?[]const u8, null), snapshot.last_error);
    try testing.expectEqual(@as(usize, 2), snapshot.samples.len);
    try testing.expectEqualStrings("node_cpu_seconds_total", snapshot.family("node_cpu_seconds_total").?.name);
    try testing.expectEqual(@as(?sample_mod.MetricFamily, null), snapshot.family("missing"));
}

test "prometheuz: snapshot failed captures the reason, never throws" {
    var snapshot = try failed(testing.allocator, 1_000, 0, "ConnectionRefused");
    defer snapshot.deinit();

    try testing.expect(!snapshot.up);
    try testing.expectEqualStrings("ConnectionRefused", snapshot.last_error.?);
    try testing.expectEqual(@as(usize, 0), snapshot.samples.len);
}

test "prometheuz: snapshot refcount frees only at zero" {
    var snapshot = try failed(testing.allocator, 0, 0, "x");

    snapshot.retain();
    try testing.expectEqual(@as(u32, 2), snapshot.refcount.load(.acquire));

    snapshot.release();
    try testing.expectEqual(@as(u32, 1), snapshot.refcount.load(.acquire));

    snapshot.release();
}
