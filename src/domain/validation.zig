//! `zurtr.domain` validation: field-keyed error accumulation.
//!
//! A `Validation(T)` is the only failure channel of an action's structural
//! checks. Every error carries a caller-supplied field name, a stable machine
//! code and a presentation message; surfaces and clients branch on the field
//! and the code, never on the message.
//!
//! ```zig
//! pub fn validate(alloc: std.mem.Allocator, input: Input) Validation(Input) {
//!     var v = Validation(Input).init(alloc);
//!     if (input.amount <= 0) v = v.fail("amount", "min", "must be positive");
//!     return v.ok(input);
//! }
//! ```
//!
//! The allocator is supplied at construction and owns every copy the value
//! makes, so a validation stays usable after the source field/code/message
//! buffers die; `deinit` releases those copies. `ok`, `fail` and `merge` take
//! `self` by value and return the updated value, so always reassign
//! (`v = v.fail(...)`): the value returned by a call owns the copies, and
//! dropping it leaks them.
//!
//! A validation is *failing* as soon as anything was recorded, including
//! failures that could not be stored: past `max_errors`, and allocation failure
//! while copying. Both are counted in `dropped`, and a non-zero `dropped`
//! makes `isOk` false, so a failure can never be silently turned into an
//! acceptance.

const std = @import("std");

/// Hard cap on errors retained by one validation, so hostile input cannot make
/// a failing request allocate without bound.
pub const max_errors: usize = 32;

/// One field-keyed failure. All three strings are owned copies (see
/// `Validation.fail`).
pub const FieldError = struct {
    /// Field name as supplied by the caller of `fail`.
    field: []const u8,
    /// Stable machine-readable code; clients render off this.
    code: []const u8,
    /// Human-readable presentation of the failure.
    message: []const u8,
};

/// Error accumulator for values of type `T`.
pub fn Validation(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Type of the value a successful validation carries.
        pub const Value = T;

        allocator: std.mem.Allocator,
        store: std.ArrayList(FieldError) = .empty,
        carried: ?T = null,
        lost: u32 = 0,

        /// An empty, successful validation. `allocator` owns every copy made
        /// from here on.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Releases the copies held by this value. The value must not be used
        /// afterwards (only `init` produces a reusable one).
        pub fn deinit(self: *Self) void {
            for (self.store.items) |e| {
                self.allocator.free(e.field);
                self.allocator.free(e.code);
                self.allocator.free(e.message);
            }
            self.store.deinit(self.allocator);
            self.store = .empty;
            self.carried = null;
            self.lost = 0;
        }

        /// Records the value of a successful validation. Recorded errors are
        /// *not* cleared: a validation that failed stays failing.
        pub fn ok(self: Self, payload: T) Self {
            var next = self;
            next.carried = payload;
            return next;
        }

        /// Records one field failure, copying `field`, `code` and `message`.
        ///
        /// Past `max_errors`, and when a copy cannot be allocated, the failure
        /// is not stored but is counted in `dropped` instead — the validation
        /// still fails.
        pub fn fail(self: Self, field: []const u8, code: []const u8, message: []const u8) Self {
            var next = self;
            if (next.store.items.len >= max_errors) {
                next.lost +|= 1;
                return next;
            }
            const field_copy = next.allocator.dupe(u8, field) catch {
                next.lost +|= 1;
                return next;
            };
            const code_copy = next.allocator.dupe(u8, code) catch {
                next.allocator.free(field_copy);
                next.lost +|= 1;
                return next;
            };
            const message_copy = next.allocator.dupe(u8, message) catch {
                next.allocator.free(field_copy);
                next.allocator.free(code_copy);
                next.lost +|= 1;
                return next;
            };
            next.store.append(next.allocator, .{
                .field = field_copy,
                .code = code_copy,
                .message = message_copy,
            }) catch {
                next.allocator.free(field_copy);
                next.allocator.free(code_copy);
                next.allocator.free(message_copy);
                next.lost +|= 1;
                return next;
            };
            return next;
        }

        /// Accumulates `other`'s errors after this value's own, in order.
        ///
        /// The errors are copied: `other` still owns its copies and must still
        /// be deinited. `dropped` counts add up. The carried value of this
        /// validation wins; `other`'s is adopted only when this one has none.
        pub fn merge(self: Self, other: Self) Self {
            var next = self;
            for (other.store.items) |e| next = next.fail(e.field, e.code, e.message);
            next.lost +|= other.lost;
            if (next.carried == null) next.carried = other.carried;
            return next;
        }

        /// True when nothing at all was recorded, stored or dropped.
        pub fn isOk(self: Self) bool {
            return self.store.items.len == 0 and self.lost == 0;
        }

        /// The value recorded by `ok`, if any. Independent of `isOk`.
        pub fn value(self: Self) ?T {
            return self.carried;
        }

        /// Retained errors, in the order they were recorded.
        pub fn errors(self: Self) []const FieldError {
            return self.store.items;
        }

        /// Failures that were counted but not retained (see `fail`).
        pub fn dropped(self: Self) u32 {
            return self.lost;
        }

        /// True when `errors` holds an entry for `field` with `code`.
        pub fn hasError(self: Self, field: []const u8, code: []const u8) bool {
            for (self.store.items) |e| {
                if (std.mem.eql(u8, e.field, field) and std.mem.eql(u8, e.code, code)) return true;
            }
            return false;
        }
    };
}

const testing = std.testing;

test "ok carries the value and reports no errors" {
    var v = Validation(u32).init(testing.allocator);
    defer v.deinit();

    try testing.expect(v.isOk());
    try testing.expectEqual(@as(?u32, null), v.value());

    var good = v.ok(7);
    defer good.deinit();

    try testing.expect(good.isOk());
    try testing.expectEqual(@as(?u32, 7), good.value());
    try testing.expectEqual(@as(usize, 0), good.errors().len);
    try testing.expectEqual(@as(u32, 0), good.dropped());
}

test "errors accumulate in order with stable codes" {
    var second = Validation(u32).init(testing.allocator);
    defer second.deinit();
    second = second.fail("email", "shape", "not an email address");
    second = second.fail("age", "min", "below the minimum age");

    var v = Validation(u32).init(testing.allocator);
    defer v.deinit();
    v = v.fail("name", "required", "must not be empty");
    v = v.merge(second);

    try testing.expect(!v.isOk());
    try testing.expectEqual(@as(?u32, null), v.value());

    const errors = v.errors();
    try testing.expectEqual(@as(usize, 3), errors.len);
    try testing.expectEqualStrings("name", errors[0].field);
    try testing.expectEqualStrings("required", errors[0].code);
    try testing.expectEqualStrings("must not be empty", errors[0].message);
    try testing.expectEqualStrings("email", errors[1].field);
    try testing.expectEqualStrings("shape", errors[1].code);
    try testing.expectEqualStrings("age", errors[2].field);
    try testing.expectEqualStrings("min", errors[2].code);

    try testing.expect(v.hasError("age", "min"));
    try testing.expect(!v.hasError("age", "shape"));

    // `second` keeps its own copies after the merge.
    try testing.expectEqual(@as(usize, 2), second.errors().len);
}

test "fail copies the strings it is given" {
    var field: [8]u8 = undefined;
    var message: [8]u8 = undefined;
    @memcpy(field[0..4], "name");
    @memcpy(message[0..4], "bad!");
    var source = Validation(u8).init(testing.allocator);
    defer source.deinit();
    source = source.fail(field[0..4], "code", message[0..4]);

    // The caller's buffers die (here: are overwritten) after the call.
    @memset(&field, 'x');
    @memset(&message, 'y');

    try testing.expectEqualStrings("name", source.errors()[0].field);
    try testing.expectEqualStrings("code", source.errors()[0].code);
    try testing.expectEqualStrings("bad!", source.errors()[0].message);
}

test "past the cap errors are dropped, counted, and still fail" {
    var v = Validation(u8).init(testing.allocator);
    defer v.deinit();

    var i: usize = 0;
    while (i < max_errors + 8) : (i += 1) {
        v = v.fail("field", "code", "message");
    }

    try testing.expect(!v.isOk());
    try testing.expectEqual(max_errors, v.errors().len);
    try testing.expectEqual(@as(u32, 8), v.dropped());
    try testing.expectEqualStrings("field", v.errors()[0].field);
    try testing.expectEqualStrings("field", v.errors()[max_errors - 1].field);
}

test "dropped errors from a merge keep the validation failing" {
    var other = Validation(u8).init(testing.allocator);
    defer other.deinit();
    other = other.fail("a", "x", "m");

    var v = Validation(u8).init(testing.allocator);
    defer v.deinit();
    var i: usize = 0;
    while (i < max_errors) : (i += 1) {
        v = v.fail("field", "code", "message");
    }
    v = v.merge(other);

    try testing.expectEqual(max_errors, v.errors().len);
    try testing.expectEqual(@as(u32, 1), v.dropped());
    try testing.expect(!v.isOk());
}

test "a failure that cannot be allocated is counted and keeps the validation failing" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });

    var v = Validation(u8).init(failing.allocator());
    defer v.deinit();
    v = v.fail("name", "required", "must not be empty");

    try testing.expectEqual(@as(usize, 0), v.errors().len);
    try testing.expectEqual(@as(u32, 1), v.dropped());
    try testing.expect(!v.isOk());
}

test "merge adopts the other value only when this one has none" {
    var left = Validation(u8).init(testing.allocator);
    defer left.deinit();
    var right = Validation(u8).init(testing.allocator);
    defer right.deinit();

    const merged = left.merge(right.ok(3));
    try testing.expectEqual(@as(?u8, 3), merged.value());

    const kept = (left.ok(9)).merge(right.ok(3));
    try testing.expectEqual(@as(?u8, 9), kept.value());
}

test "ok records the value without clearing recorded errors" {
    var v = Validation(u8).init(testing.allocator);
    defer v.deinit();
    v = v.fail("amount", "min", "must be positive");
    v = v.ok(0);

    try testing.expect(!v.isOk());
    try testing.expectEqual(@as(?u8, 0), v.value());
    try testing.expectEqual(@as(usize, 1), v.errors().len);
}

test "void payloads work" {
    var v = Validation(void).init(testing.allocator);
    defer v.deinit();
    v = v.ok({});

    try testing.expect(v.isOk());
    try testing.expect(v.value() != null);
}
