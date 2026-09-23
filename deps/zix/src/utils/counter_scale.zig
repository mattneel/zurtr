//! Overflow-safe conversion of a raw hardware counter reading into a time unit.
//!
//! What:
//! - A platform that reports time as a tick counter plus a tick frequency needs
//!   those two turned into nanoseconds or microseconds. The direct form,
//!   counter * scale / frequency, overflows u64 long before the counter itself
//!   does, because the multiply runs first.
//! - Windows is the caller that matters: its performance counter runs at 10 MHz,
//!   so the direct nanosecond form dies at about 31 minutes of machine uptime
//!   and the microsecond form at about 21 days.
//!
//! Note:
//! - Portable on purpose. The Windows clock helpers live in windows_io.zig,
//!   which cannot be analyzed off Windows, so the arithmetic sits here where
//!   every target can test it.

const std = @import("std");

/// Express a raw counter reading in a time unit, without overflowing u64.
///
/// Note:
/// - Dividing before multiplying keeps both products small: the remainder is
///   always below frequency, and whole seconds only overflow after several
///   centuries.
/// - A frequency of 0 is the caller's problem to reject, this would divide by
///   zero on it.
///
/// Param:
/// counter - u64 (raw counter reading)
/// frequency - u64 (counter ticks per second, must not be 0)
/// scale - u64 (units per second, 1_000_000_000 for nanoseconds)
///
/// Return:
/// - u64 (the reading expressed in the requested unit)
pub fn scaleCounter(counter: u64, frequency: u64, scale: u64) u64 {
    const seconds = counter / frequency;
    const rest = counter % frequency;

    return seconds * scale + rest * scale / frequency;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix utils: counter_scale converts a reading below one whole second" {
    const frequency: u64 = 10_000_000;

    try testing.expectEqual(@as(u64, 0), scaleCounter(0, frequency, std.time.ns_per_s));
    try testing.expectEqual(@as(u64, 100), scaleCounter(1, frequency, std.time.ns_per_s));
    try testing.expectEqual(@as(u64, std.time.ns_per_s), scaleCounter(frequency, frequency, std.time.ns_per_s));
}

test "zix utils: counter_scale holds past the direct-form nanosecond overflow" {
    // the frequency Windows reports, where counter * ns_per_s overflows u64
    // above 18_446_744_073 ticks, roughly 31 minutes of uptime
    const frequency: u64 = 10_000_000;
    const day_ticks: u64 = 86_400 * frequency;

    try testing.expectEqual(@as(u64, 2_000 * std.time.ns_per_s), scaleCounter(2_000 * frequency, frequency, std.time.ns_per_s));
    try testing.expectEqual(@as(u64, 86_400 * std.time.ns_per_s), scaleCounter(day_ticks, frequency, std.time.ns_per_s));

    // the sub-second remainder still lands, it is not truncated away
    try testing.expectEqual(@as(u64, 86_400 * std.time.ns_per_s + 100), scaleCounter(day_ticks + 1, frequency, std.time.ns_per_s));
}

test "zix utils: counter_scale holds past the direct-form microsecond overflow" {
    // counter * us_per_s overflows u64 above 18_446_744_073_709 ticks, which at
    // 10 MHz is about 21 days of uptime
    const frequency: u64 = 10_000_000;
    const days_21: u64 = 21 * 86_400 * frequency;

    try testing.expectEqual(@as(u64, 21 * 86_400 * std.time.us_per_s), scaleCounter(days_21, frequency, std.time.us_per_s));
    try testing.expectEqual(@as(u64, 21 * 86_400 * std.time.us_per_s + 1), scaleCounter(days_21 + 10, frequency, std.time.us_per_s));
}

test "zix utils: counter_scale converts under a frequency that divides nothing evenly" {
    const frequency: u64 = 3_579_545;

    try testing.expectEqual(@as(u64, std.time.ns_per_s), scaleCounter(frequency, frequency, std.time.ns_per_s));
    try testing.expectEqual(@as(u64, 2 * std.time.ns_per_s), scaleCounter(2 * frequency, frequency, std.time.ns_per_s));

    // one tick is 279.3 ns, so the truncated answer is 279
    try testing.expectEqual(@as(u64, 279), scaleCounter(1, frequency, std.time.ns_per_s));
}

test "zix utils: counter_scale keeps rising across the overflow boundary" {
    // a monotonic clock must never step backward, which the direct form does
    // the moment it wraps: sample either side of the boundary and compare
    const frequency: u64 = 10_000_000;
    const boundary: u64 = std.math.maxInt(u64) / std.time.ns_per_s;

    const before = scaleCounter(boundary - 1, frequency, std.time.ns_per_s);
    const after = scaleCounter(boundary + 1, frequency, std.time.ns_per_s);

    try testing.expect(after > before);
}
