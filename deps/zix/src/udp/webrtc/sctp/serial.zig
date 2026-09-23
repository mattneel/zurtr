//! zix SCTP serial number arithmetic (RFC 9260 1.6, from RFC 1982).
//!
//! What:
//! - Comparisons for the two counters SCTP wraps: the 32-bit TSN that numbers every DATA chunk,
//!   and the 16-bit stream sequence number that orders messages inside one stream.
//! - Both start at a random value and wrap around, so a plain `<` says the wrong thing exactly
//!   once per cycle, at the point where it matters most.
//!
//! Note:
//! - The rule is distance, not magnitude: `left` is before `right` when stepping forward from
//!   `left` reaches `right` in fewer than half the counter's range. TSN 0 is one past
//!   4294967295, and this file is the only place that knows it.
//! - Two values exactly half a cycle apart have no order. RFC 1982 leaves that case undefined,
//!   and here it reads as neither before nor after, so a comparison in either direction is
//!   false. A peer cannot reach that gap without first going far outside its window.
//! - There is no arithmetic on a raw TSN anywhere else in this tree. Anything comparing or
//!   stepping one goes through here.

const std = @import("std");

/// Comparisons for one wrapping counter width.
///
/// Note:
/// - Instantiate it once per counter type and use the alias, rather than passing the width in at
///   every call.
///
/// Param:
/// Value - type (unsigned integer, the counter's width on the wire)
///
/// Return:
/// - type
pub fn Serial(comptime Value: type) type {
    return struct {
        /// The counter's width on the wire.
        pub const Counter = Value;

        /// Half the counter's range. A distance below this is forward, above it is backward.
        pub const HALF: Value = 1 << (@bitSizeOf(Value) - 1);

        /// Whether `left` comes before `right`.
        ///
        /// Param:
        /// left - Value
        /// right - Value
        ///
        /// Return:
        /// - bool, false when they are equal or exactly half a cycle apart
        pub fn lessThan(left: Value, right: Value) bool {
            const forward = right -% left;

            return forward != 0 and forward < HALF;
        }

        /// Whether `left` comes before `right` or equals it.
        ///
        /// Param:
        /// left - Value
        /// right - Value
        ///
        /// Return:
        /// - bool
        pub fn lessOrEqual(left: Value, right: Value) bool {
            return left == right or lessThan(left, right);
        }

        /// Whether `left` comes after `right`.
        ///
        /// Param:
        /// left - Value
        /// right - Value
        ///
        /// Return:
        /// - bool
        pub fn greaterThan(left: Value, right: Value) bool {
            return lessThan(right, left);
        }

        /// Whether `left` comes after `right` or equals it.
        ///
        /// Param:
        /// left - Value
        /// right - Value
        ///
        /// Return:
        /// - bool
        pub fn greaterOrEqual(left: Value, right: Value) bool {
            return left == right or lessThan(right, left);
        }

        /// How many steps forward it takes to get from `from` to `to`.
        ///
        /// Note:
        /// - Always the forward distance, even when `to` is behind `from`, in which case it is
        ///   the long way round. Compare first if that matters.
        ///
        /// Param:
        /// from - Value
        /// to - Value
        ///
        /// Return:
        /// - Value
        pub fn distance(from: Value, to: Value) Value {
            return to -% from;
        }

        /// Step a counter forward, wrapping.
        ///
        /// Param:
        /// value - Value
        /// count - Value (how many steps)
        ///
        /// Return:
        /// - Value
        pub fn advance(value: Value, count: Value) Value {
            return value +% count;
        }

        /// The next value after this one.
        ///
        /// Param:
        /// value - Value
        ///
        /// Return:
        /// - Value
        pub fn next(value: Value) Value {
            return value +% 1;
        }

        /// The value before this one.
        ///
        /// Param:
        /// value - Value
        ///
        /// Return:
        /// - Value
        pub fn previous(value: Value) Value {
            return value -% 1;
        }

        /// Whichever of the two comes later.
        ///
        /// Param:
        /// left - Value
        /// right - Value
        ///
        /// Return:
        /// - Value
        pub fn later(left: Value, right: Value) Value {
            return if (lessThan(left, right)) right else left;
        }
    };
}

/// The transmission sequence number that numbers every DATA chunk (RFC 9260 3.3.1).
pub const Tsn = Serial(u32);

/// The per-stream sequence number that orders messages inside one stream (RFC 9260 6.5).
pub const StreamSequence = Serial(u16);

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: serial compare, plain values compare the obvious way" {
    try std.testing.expect(Tsn.lessThan(1, 2));
    try std.testing.expect(!Tsn.lessThan(2, 1));
    try std.testing.expect(!Tsn.lessThan(2, 2));

    try std.testing.expect(Tsn.greaterThan(2, 1));
    try std.testing.expect(Tsn.lessOrEqual(2, 2));
    try std.testing.expect(Tsn.greaterOrEqual(2, 2));
}

test "zix sctp: serial compare, a TSN just past the wrap is newer than one just before it" {
    const before: u32 = 0xFFFFFFFF;
    const after: u32 = 0;

    // A plain `<` gets this exactly backwards, which is the whole reason this file exists.
    try std.testing.expect(Tsn.lessThan(before, after));
    try std.testing.expect(Tsn.greaterThan(after, before));
    try std.testing.expect(!Tsn.lessThan(after, before));
}

test "zix sctp: serial compare, a window straddling the wrap stays ordered" {
    const window: [5]u32 = .{ 0xFFFFFFFE, 0xFFFFFFFF, 0, 1, 2 };

    for (window[0 .. window.len - 1], window[1..]) |earlier, later_value| {
        try std.testing.expect(Tsn.lessThan(earlier, later_value));
    }
}

test "zix sctp: serial compare, values exactly half a cycle apart have no order" {
    const left: u32 = 0;
    const right: u32 = Tsn.HALF;

    try std.testing.expect(!Tsn.lessThan(left, right));
    try std.testing.expect(!Tsn.lessThan(right, left));
    try std.testing.expect(!Tsn.greaterThan(left, right));
}

test "zix sctp: serial compare, one step inside half a cycle is still ordered" {
    const left: u32 = 0;
    const right: u32 = Tsn.HALF - 1;

    try std.testing.expect(Tsn.lessThan(left, right));
    try std.testing.expect(Tsn.greaterThan(right, left));
}

test "zix sctp: serial distance, the forward step count wraps with the counter" {
    try std.testing.expectEqual(@as(u32, 3), Tsn.distance(10, 13));
    try std.testing.expectEqual(@as(u32, 3), Tsn.distance(0xFFFFFFFF, 2));

    // Backwards is the long way round, never a negative number.
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFD), Tsn.distance(13, 10));
}

test "zix sctp: serial advance, stepping past the top lands on zero" {
    try std.testing.expectEqual(@as(u32, 1), Tsn.advance(0xFFFFFFFF, 2));
    try std.testing.expectEqual(@as(u32, 0), Tsn.next(0xFFFFFFFF));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), Tsn.previous(0));
}

test "zix sctp: serial later, the newer of two values is picked across the wrap" {
    try std.testing.expectEqual(@as(u32, 5), Tsn.later(3, 5));
    try std.testing.expectEqual(@as(u32, 5), Tsn.later(5, 3));
    try std.testing.expectEqual(@as(u32, 1), Tsn.later(0xFFFFFFFF, 1));
}

test "zix sctp: serial stream sequence, the 16-bit counter wraps at its own width" {
    try std.testing.expect(StreamSequence.lessThan(0xFFFF, 0));
    try std.testing.expect(StreamSequence.greaterThan(0, 0xFFFF));
    try std.testing.expectEqual(@as(u16, 0x8000), StreamSequence.HALF);
    try std.testing.expectEqual(@as(u16, 0), StreamSequence.next(0xFFFF));
}

test "zix sctp: serial stream sequence, half a cycle is half of 65536 not of 4294967296" {
    // Reusing the TSN width for a stream sequence number would put this boundary in the wrong
    // place and quietly reorder messages.
    try std.testing.expect(StreamSequence.lessThan(0, 0x7FFF));
    try std.testing.expect(!StreamSequence.lessThan(0, 0x8000));
}
