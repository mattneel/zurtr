//! Monotonic clock in milliseconds: the timebase a duration bound is measured on.
//!
//! What:
//!   A deadline is a duration, not a date. Read it off the wall clock and every live bound in the
//!   process moves the instant the system time steps: a backward step postpones them all, a forward
//!   step fires them all at once. This clock cannot step, so a bound armed for 30 seconds expires
//!   30 seconds later whatever happens to the system time.
//!
//! Note:
//! - The clock is std.Io's `.awake`, the same one std.Io.sleep parks on. A loop that sleeps in
//!   slices and checks a deadline between them then measures both sides on one timebase. On linux
//!   that is CLOCK_MONOTONIC, on macOS CLOCK_UPTIME_RAW, on windows the performance counter.
//! - `.awake` asks to leave out time the system spends suspended, `.boot` asks to count it. Not
//!   every platform can honour that split (windows serves both from the performance counter, which
//!   keeps counting through a suspend), so a bound here is guaranteed against a time step, not
//!   against a suspend. Every sleep in the tree already picks `.awake`, and a bound has to agree
//!   with the sleep that waits it out.
//! - The value counts from an unspecified point, so on its own it means nothing. Only the
//!   difference between two reads is meaningful, and it is never a date to show anyone.

const std = @import("std");

// --------------------------------------------------------- //

/// Read the monotonic clock, in milliseconds.
///
/// Note:
/// - Compare a read only against another read from this same function. Two stamps that reach the
///   same comparison must come from one clock, mixing this with a wall-clock stamp is a bug.
///
/// Param:
/// io - std.Io (the same io the caller sleeps and polls on)
///
/// Return:
/// - i64 (milliseconds since an unspecified point, never decreasing between calls)
pub fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.toMilliseconds();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: monotonic_clock nowMs never decreases across repeated reads" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var previous = nowMs(io);
    var reads: usize = 0;
    while (reads < 2_000) : (reads += 1) {
        const current = nowMs(io);
        try std.testing.expect(current >= previous);

        previous = current;
    }
}

test "zix utils: monotonic_clock nowMs advances by roughly the slept duration" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const began = nowMs(io);
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake);
    const elapsed = nowMs(io) - began;

    // The lower bound is loose because a loaded CI box rounds the sleep down, the upper bound only
    // has to catch a clock reading in the wrong unit.
    try std.testing.expect(elapsed >= 40);
    try std.testing.expect(elapsed < 10_000);
}

test "zix utils: monotonic_clock nowMs is not the wall clock" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const wall_ms = std.Io.Clock.Timestamp.now(io, .real).raw.toMilliseconds();
    const mono_ms = nowMs(io);

    // A wall-clock read counts from 1970, decades ahead of any machine's time since boot. This is
    // the guard that catches a `.real` put back into the helper.
    const ten_years_ms: i64 = 10 * 365 * 24 * 60 * 60 * 1000;
    try std.testing.expect(wall_ms - mono_ms > ten_years_ms);
}

test "zix utils: monotonic_clock a deadline built from nowMs is not already expired" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const deadline_ms = nowMs(io) + 1_000;
    try std.testing.expect(nowMs(io) < deadline_ms);

    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake);

    // Still armed after a slice that is far shorter than the budget.
    try std.testing.expect(nowMs(io) < deadline_ms);
}

test "zix utils: monotonic_clock two io backends read one timebase" {
    var first: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer first.deinit();

    var second: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer second.deinit();

    const began = nowMs(first.io());
    const crossed = nowMs(second.io());
    const ended = nowMs(first.io());

    // A stamp taken through one io has to be comparable with a stamp taken through another, the
    // engines hand these across worker threads that each carry their own io.
    try std.testing.expect(crossed >= began);
    try std.testing.expect(ended >= crossed);
}
