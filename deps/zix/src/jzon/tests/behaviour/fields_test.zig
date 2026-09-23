//! Behaviour tests: jzon.fields, which of a target's fields a document filled.
//! Verifies the count matches the target, that marking and filling agree, and that
//! a field the document left out takes the default its type declares.

const std = @import("std");
const jzon = @import("jzon");

const fields = jzon.fields;

const Status = enum { PENDING, SHIPPED };

const Order = struct {
    id: u64,
    customer: []const u8,
    status: Status = .PENDING,
    note: ?[]const u8 = null,
    retries: u8 = 3,
};

test "jzon behaviour: seen counts the fields the target declares" {
    try std.testing.expectEqual(@as(usize, 5), fields.Seen(Order).COUNT);
    try std.testing.expectEqual(@as(usize, 0), fields.Seen(struct {}).COUNT);
}

test "jzon behaviour: seen starts with every field unread" {
    const Tracker = fields.Seen(Order);
    const seen: Tracker = .{};

    for (0..Tracker.COUNT) |index| {
        try std.testing.expect(!seen.isMarked(index));
    }
}

test "jzon behaviour: seen remembers exactly the fields that were marked" {
    var seen: fields.Seen(Order) = .{};

    try seen.mark(0);
    try seen.mark(3);

    try std.testing.expect(seen.isMarked(0));
    try std.testing.expect(!seen.isMarked(1));
    try std.testing.expect(!seen.isMarked(2));
    try std.testing.expect(seen.isMarked(3));
    try std.testing.expect(!seen.isMarked(4));
}

test "jzon behaviour: seen fills what the document left out" {
    var seen: fields.Seen(Order) = .{};
    try seen.mark(0);
    try seen.mark(1);

    var order: Order = undefined;
    order.id = 9;
    order.customer = "Rekha Nair";

    try seen.fill(&order);

    try std.testing.expectEqual(@as(u64, 9), order.id);
    try std.testing.expectEqualStrings("Rekha Nair", order.customer);
    try std.testing.expectEqual(Status.PENDING, order.status);
    try std.testing.expect(order.note == null);
    try std.testing.expectEqual(@as(u8, 3), order.retries);
}

test "jzon behaviour: seen leaves a field the document did fill alone" {
    var seen: fields.Seen(Order) = .{};

    inline for (0..fields.Seen(Order).COUNT) |index| {
        try seen.mark(index);
    }

    var order: Order = .{
        .id = 1,
        .customer = "x",
        .status = .SHIPPED,
        .note = "keep me",
        .retries = 7,
    };

    try seen.fill(&order);

    try std.testing.expectEqual(Status.SHIPPED, order.status);
    try std.testing.expectEqualStrings("keep me", order.note.?);
    try std.testing.expectEqual(@as(u8, 7), order.retries);
}

test "jzon behaviour: seen reports a field with nothing to fall back to" {
    var seen: fields.Seen(Order) = .{};
    try seen.mark(0);

    var order: Order = undefined;
    order.id = 1;

    try std.testing.expectError(error.JzonMissingField, seen.fill(&order));
}
