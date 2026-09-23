//! zixer config fault collection: every problem carries a fix hint

const std = @import("std");

const cfg_math = @import("cfg_math.zig");
const cfg_scanner = @import("cfg_scanner.zig");

/// One validation problem: the config key it belongs to plus a fix hint.
pub const Fault = struct {
    key: []const u8,
    hint: []const u8,
};

/// Fault collector shared by the config schemas and the commands.
///
/// Note:
/// - key is not duplicated, it must outlive the list. Keys are slices into
///   config content living in the same arena, so this holds by construction.
pub const FaultList = struct {
    arena: std.mem.Allocator,
    items: std.ArrayList(Fault) = .empty,

    pub fn init(arena: std.mem.Allocator) FaultList {
        return .{ .arena = arena };
    }

    /// Add a fault with a formatted fix hint.
    ///
    /// Param:
    /// key - []const u8 (config key the fault belongs to)
    /// fmt - []const u8 (comptime std.fmt template for the hint)
    /// args - anytype (values for fmt)
    pub fn add(list: *FaultList, key: []const u8, comptime fmt: []const u8, args: anytype) !void {
        const hint = try std.fmt.allocPrint(list.arena, fmt, args);

        try list.items.append(list.arena, .{ .key = key, .hint = hint });
    }

    /// All collected faults in add order.
    pub fn slice(list: *const FaultList) []const Fault {
        return list.items.items;
    }
};

/// Record a scanner bad line as a fault, with the line number in the hint.
pub fn addBadLine(faults: *FaultList, bad: cfg_scanner.BadLine) !void {
    switch (bad.reason) {
        .MISSING_COLON => try faults.add(bad.text, "line {d} has no ':', write key: value", .{bad.line_no}),
        .EMPTY_KEY => try faults.add(bad.text, "line {d} has no key before ':'", .{bad.line_no}),
        .EMPTY_VALUE => try faults.add(bad.text, "line {d} has no value after ':'", .{bad.line_no}),
        .UNCLOSED_SECTION => try faults.add(bad.text, "line {d} opens '[' without closing ']' at the end, write [section_name]", .{bad.line_no}),
        .EMPTY_SECTION => try faults.add(bad.text, "line {d} has no name between the brackets, write [section_name]", .{bad.line_no}),
    }
}

/// Evaluate a numeric config value, faulting instead of failing.
///
/// Return:
/// - i64 when the value evaluates
/// - null when it does not, with the fault already recorded
pub fn evalNumber(faults: *FaultList, entry: cfg_scanner.Entry) !?i64 {
    const value = cfg_math.evaluate(entry.value) catch |err| {
        try faults.add(entry.key, "{s}", .{cfg_math.hint(err)});
        return null;
    };

    return value;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: fault list, add keeps order and formats hints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = FaultList.init(arena.allocator());
    try faults.add("workers", "workers exceed from available threads ({d}), set to 0 or 1", .{8});
    try faults.add("dispatch", "unknown value", .{});

    const listed = faults.slice();
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("workers", listed[0].key);
    try std.testing.expectEqualStrings("workers exceed from available threads (8), set to 0 or 1", listed[0].hint);
    try std.testing.expectEqualStrings("dispatch", listed[1].key);
}

test "zix zixer: fault list, bad lines carry their line number" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = FaultList.init(arena.allocator());
    try addBadLine(&faults, .{ .text = "no colon", .line_no = 7, .reason = .MISSING_COLON });

    try std.testing.expectEqualStrings("no colon", faults.slice()[0].key);
    try std.testing.expectEqualStrings("line 7 has no ':', write key: value", faults.slice()[0].hint);
}

test "zix zixer: fault list, a broken section line says how to write one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = FaultList.init(arena.allocator());
    try addBadLine(&faults, .{ .text = "[response_headers", .line_no = 3, .reason = .UNCLOSED_SECTION });
    try addBadLine(&faults, .{ .text = "[]", .line_no = 4, .reason = .EMPTY_SECTION });

    try std.testing.expectEqualStrings("line 3 opens '[' without closing ']' at the end, write [section_name]", faults.slice()[0].hint);
    try std.testing.expectEqualStrings("line 4 has no name between the brackets, write [section_name]", faults.slice()[1].hint);
}

test "zix zixer: fault list, evalNumber faults instead of failing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = FaultList.init(arena.allocator());

    const good = try evalNumber(&faults, .{ .key = "max_recv_buf", .value = "16 * 1024", .line_no = 1 });
    try std.testing.expectEqual(@as(?i64, 16384), good);
    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);

    const bad = try evalNumber(&faults, .{ .key = "max_recv_buf", .value = "10 / 4", .line_no = 2 });
    try std.testing.expectEqual(@as(?i64, null), bad);
    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("max_recv_buf", faults.slice()[0].key);
}
