//! registry.zig: an app-authored metric registry (Counter, Gauge).
//!
//! Note:
//! - Recording a value never allocates or blocks once a label combination
//!   is warm, and never returns an error to the caller: an allocation
//!   failure on a brand-new combination silently falls back to a shared
//!   discard cell rather than propagating into the app's hot path.
//! - `name`, `help`, and `label_names` are borrowed: they must outlive the
//!   Registry (string literals or process-lifetime constants, same as
//!   url.zig's parsed slices).

const std = @import("std");
const sample_mod = @import("sample.zig");

const Sample = sample_mod.Sample;
const Label = sample_mod.Label;
const MetricFamily = sample_mod.MetricFamily;
const MetricType = sample_mod.MetricType;

// --------------------------------------------------------- //

/// A monotonically-increasing counter cell. The value is a bit-cast f64
/// inside an atomic u64 (std has no atomic float primitive), so add() is a
/// CAS loop. inc() is the common add(1) case.
pub const Counter = struct {
    bits: std.atomic.Value(u64) = .init(0),

    pub fn inc(self: *Counter) void {
        self.add(1);
    }

    pub fn add(self: *Counter, delta: f64) void {
        addBits(&self.bits, delta);
    }

    pub fn get(self: *const Counter) f64 {
        return @bitCast(self.bits.load(.acquire));
    }
};

/// A gauge cell: can move up, down, or be set outright.
pub const Gauge = struct {
    bits: std.atomic.Value(u64) = .init(0),

    pub fn inc(self: *Gauge) void {
        self.add(1);
    }

    pub fn dec(self: *Gauge) void {
        self.add(-1);
    }

    pub fn add(self: *Gauge, delta: f64) void {
        addBits(&self.bits, delta);
    }

    pub fn set(self: *Gauge, new_value: f64) void {
        self.bits.store(@bitCast(new_value), .release);
    }

    pub fn get(self: *const Gauge) f64 {
        return @bitCast(self.bits.load(.acquire));
    }
};

fn addBits(bits: *std.atomic.Value(u64), delta: f64) void {
    while (true) {
        const current_bits = bits.load(.acquire);
        const next: f64 = @as(f64, @bitCast(current_bits)) + delta;
        if (bits.cmpxchgWeak(current_bits, @bitCast(next), .acq_rel, .acquire) == null) return;
    }
}

// --------------------------------------------------------- //

/// The registered cells for one metric name, keyed by label-value
/// combination. `CounterVec` and `GaugeVec` below are instantiations.
fn Vec(comptime Cell: type, comptime metric_type: MetricType) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            label_values: []const []const u8,
            cell: Cell,
        };

        allocator: std.mem.Allocator,
        name: []const u8,
        help: []const u8,
        label_names: []const []const u8,
        cells: std.StringHashMapUnmanaged(*Entry) = .empty,
        lock_flag: std.atomic.Value(bool) = .init(false),
        fallback: Cell = .{},

        fn init(allocator: std.mem.Allocator, name: []const u8, help: []const u8, label_names: []const []const u8) Self {
            return .{ .allocator = allocator, .name = name, .help = help, .label_names = label_names };
        }

        fn deinit(self: *Self) void {
            var it = self.cells.iterator();
            while (it.next()) |kv| {
                self.freeEntry(kv.value_ptr.*);
                self.allocator.free(kv.key_ptr.*);
            }
            self.cells.deinit(self.allocator);
        }

        fn freeEntry(self: *Self, entry: *Entry) void {
            for (entry.label_values) |value| self.allocator.free(value);
            self.allocator.free(entry.label_values);
            self.allocator.destroy(entry);
        }

        /// The cell for this exact label-value combination (matching
        /// label_names order), allocated and cached the first time it is
        /// seen. Never errors: an allocation failure on a brand-new
        /// combination returns a shared discard cell instead.
        pub fn with(self: *Self, label_values: []const []const u8) *Cell {
            var key_buf: [512]u8 = undefined;
            const key = buildKey(&key_buf, label_values) catch return &self.fallback;

            self.lock();
            defer self.unlock();

            if (self.cells.get(key)) |entry| return &entry.cell;

            return self.insertLocked(key, label_values) catch &self.fallback;
        }

        fn insertLocked(self: *Self, key: []const u8, label_values: []const []const u8) !*Cell {
            const entry = try self.allocator.create(Entry);
            errdefer self.allocator.destroy(entry);
            entry.* = .{ .label_values = &.{}, .cell = .{} };

            const owned_values = try self.allocator.alloc([]const u8, label_values.len);
            errdefer self.allocator.free(owned_values);
            var copied: usize = 0;
            errdefer for (owned_values[0..copied]) |value| self.allocator.free(value);
            for (label_values, 0..) |value, index| {
                owned_values[index] = try self.allocator.dupe(u8, value);
                copied += 1;
            }
            entry.label_values = owned_values;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);

            try self.cells.put(self.allocator, owned_key, entry);

            return &entry.cell;
        }

        /// Every recorded label combination for this vec, as samples,
        /// appended into `out`. Skips nothing: the fallback discard cell is
        /// not reachable from `cells`, so it never surfaces here.
        fn appendSamples(self: *Self, arena: std.mem.Allocator, out: *std.ArrayList(Sample)) !void {
            self.lock();
            defer self.unlock();

            var it = self.cells.iterator();
            while (it.next()) |kv| {
                const entry = kv.value_ptr.*;
                const labels = try arena.alloc(Label, self.label_names.len);
                for (self.label_names, entry.label_values, 0..) |label_name, label_value, index| {
                    labels[index] = .{ .name = label_name, .value = try arena.dupe(u8, label_value) };
                }

                try out.append(arena, .{
                    .name = self.name,
                    .labels = labels,
                    .value = entry.cell.get(),
                    .timestamp_ms = null,
                });
            }
        }

        fn family(self: *Self, arena: std.mem.Allocator) !MetricFamily {
            var samples: std.ArrayList(Sample) = .empty;
            try self.appendSamples(arena, &samples);

            return .{
                .name = self.name,
                .help = self.help,
                .metric_type = metric_type,
                .samples = try samples.toOwnedSlice(arena),
            };
        }

        fn lock(self: *Self) void {
            while (self.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
        }

        fn unlock(self: *Self) void {
            self.lock_flag.store(false, .release);
        }
    };
}

/// Join label values with a byte unlikely to appear in a real label
/// (0x1F, ASCII unit separator) so distinct combinations never collide.
fn buildKey(buf: []u8, label_values: []const []const u8) ![]const u8 {
    var writer = std.Io.Writer.fixed(buf);
    for (label_values, 0..) |value, index| {
        if (index > 0) try writer.writeByte(0x1f);
        try writer.writeAll(value);
    }

    return writer.buffered();
}

pub const CounterVec = Vec(Counter, .counter);
pub const GaugeVec = Vec(Gauge, .gauge);

// --------------------------------------------------------- //

/// An app-authored metric registry: register a Counter or Gauge once
/// (typically at startup), then record values inline from anywhere,
/// including a hot request path.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    counters: std.ArrayList(*CounterVec),
    gauges: std.ArrayList(*GaugeVec),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator, .counters = .empty, .gauges = .empty };
    }

    pub fn deinit(self: *Registry) void {
        for (self.counters.items) |vec| {
            vec.deinit();
            self.allocator.destroy(vec);
        }
        self.counters.deinit(self.allocator);

        for (self.gauges.items) |vec| {
            vec.deinit();
            self.allocator.destroy(vec);
        }
        self.gauges.deinit(self.allocator);
    }

    /// Register a labeled counter. `name`, `help`, and `label_names` must
    /// outlive the Registry.
    pub fn counter(self: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8) !*CounterVec {
        const vec = try self.allocator.create(CounterVec);
        errdefer self.allocator.destroy(vec);
        vec.* = CounterVec.init(self.allocator, name, help, label_names);

        try self.counters.append(self.allocator, vec);

        return vec;
    }

    /// Register a labeled gauge. `name`, `help`, and `label_names` must
    /// outlive the Registry.
    pub fn gauge(self: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8) !*GaugeVec {
        const vec = try self.allocator.create(GaugeVec);
        errdefer self.allocator.destroy(vec);
        vec.* = GaugeVec.init(self.allocator, name, help, label_names);

        try self.gauges.append(self.allocator, vec);

        return vec;
    }

    /// Every recorded value across every Counter/Gauge, flattened into
    /// `[]Sample` in `arena` - the push path, feeds directly into
    /// remoteWrite().
    pub fn snapshot(self: *Registry, arena: std.mem.Allocator) ![]const Sample {
        var out: std.ArrayList(Sample) = .empty;

        for (self.counters.items) |vec| try vec.appendSamples(arena, &out);
        for (self.gauges.items) |vec| try vec.appendSamples(arena, &out);

        return out.toOwnedSlice(arena);
    }

    /// Every registered family (name/help/type plus samples), in `arena` -
    /// the pull path, feeds expose().
    pub fn families(self: *Registry, arena: std.mem.Allocator) ![]const MetricFamily {
        var out = try arena.alloc(MetricFamily, self.counters.items.len + self.gauges.items.len);
        var index: usize = 0;

        for (self.counters.items) |vec| {
            out[index] = try vec.family(arena);
            index += 1;
        }
        for (self.gauges.items) |vec| {
            out[index] = try vec.family(arena);
            index += 1;
        }

        return out;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: registry counter records and reports a value" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});
    write_errors.with(&.{"user_create_failed"}).inc();
    write_errors.with(&.{"user_create_failed"}).inc();
    write_errors.with(&.{"tx_failed"}).add(3);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const samples = try registry.snapshot(arena_state.allocator());
    try testing.expectEqual(@as(usize, 2), samples.len);

    var found_create_failed = false;
    var found_tx_failed = false;
    for (samples) |current_sample| {
        const reason = current_sample.label("reason").?;
        if (std.mem.eql(u8, reason, "user_create_failed")) {
            try testing.expectEqual(@as(f64, 2), current_sample.value);
            found_create_failed = true;
        } else if (std.mem.eql(u8, reason, "tx_failed")) {
            try testing.expectEqual(@as(f64, 3), current_sample.value);
            found_tx_failed = true;
        }
    }
    try testing.expect(found_create_failed);
    try testing.expect(found_tx_failed);
}

test "prometheuz: registry gauge inc dec set" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    const in_flight = try registry.gauge("in_flight_requests", "Requests being handled", &.{});
    const cell = in_flight.with(&.{});
    cell.inc();
    cell.inc();
    cell.dec();
    try testing.expectEqual(@as(f64, 1), cell.get());

    cell.set(42);
    try testing.expectEqual(@as(f64, 42), cell.get());
}

test "prometheuz: registry with() returns the same cell for the same labels" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "help", &.{"reason"});
    const first = write_errors.with(&.{"x"});
    const second = write_errors.with(&.{"x"});

    try testing.expectEqual(first, second);
}

test "prometheuz: registry families carries name help and type" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    _ = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});
    _ = try registry.gauge("in_flight_requests", "Requests being handled", &.{});

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const registered = try registry.families(arena_state.allocator());
    try testing.expectEqual(@as(usize, 2), registered.len);
    try testing.expectEqual(MetricType.counter, registered[0].metric_type);
    try testing.expectEqualStrings("Failed write operations", registered[0].help);
    try testing.expectEqual(MetricType.gauge, registered[1].metric_type);
}
