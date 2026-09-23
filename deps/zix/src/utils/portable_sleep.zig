//! Short blocking sleep for background OS threads, on every supported target.
//!
//! What:
//! - Zig 0.16 std has no sleep outside `std.Io`: `std.Thread` carries spawn, join, and yield only,
//!   and Mutex, Condition, and Futex all live behind an `Io` instance now. A thread that must stay
//!   free of `std.Io` (the logger flush thread) therefore needs its own portable nap.
//!
//! Note:
//! - Linux goes straight to the raw syscall, so the sleep works with or without libc.
//! - Windows uses the same ntdll surface the rest of the tree uses for platform calls.
//! - Every other supported target links libc, so `std.c.nanosleep` is the portable path there.
//!   std already maps the NetBSD spelling (`__nanosleep50`) behind that name.

const std = @import("std");
const builtin = @import("builtin");

// --------------------------------------------------------- //

/// Sleep for roughly the given nanoseconds, best effort.
///
/// Note:
/// - A signal cutting the sleep short is not retried. Every caller is a polling loop that will
///   simply come back around, so a short nap costs nothing and a retry loop would only risk
///   sleeping longer than asked.
///
/// Param:
/// nanoseconds - u64 (how long to nap, 0 returns immediately)
///
/// Return:
/// - void
pub fn sleepNs(nanoseconds: u64) void {
    if (nanoseconds == 0) return;

    if (comptime builtin.os.tag == .windows) {
        // NT relative delays are negative and counted in 100 nanosecond units.
        const interval: std.os.windows.LARGE_INTEGER = -@as(i64, @intCast(nanoseconds / 100));
        _ = std.os.windows.ntdll.NtDelayExecution(.FALSE, &interval);

        return;
    }

    const seconds = nanoseconds / std.time.ns_per_s;
    const remainder = nanoseconds % std.time.ns_per_s;

    if (comptime builtin.os.tag == .linux) {
        const request = std.os.linux.timespec{
            .sec = @intCast(seconds),
            .nsec = @intCast(remainder),
        };
        _ = std.os.linux.nanosleep(&request, null);

        return;
    }

    const request = std.posix.timespec{
        .sec = @intCast(seconds),
        .nsec = @intCast(remainder),
    };
    _ = std.c.nanosleep(&request, null);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils sleep: a zero nap returns without calling the platform" {
    // Nothing to assert beyond it returning: the guard is what keeps a 0 from becoming a syscall.
    sleepNs(0);
}

test "zix utils sleep: a short nap actually waits" {
    const monotonic_clock = @import("monotonic_clock.zig");

    const start = monotonic_clock.nowMs(std.testing.io);

    // Ten naps rather than one: a single 5 ms nap can round to 0 ms elapsed on a coarse clock.
    for (0..10) |_| sleepNs(5 * std.time.ns_per_ms);

    const elapsed = monotonic_clock.nowMs(std.testing.io) - start;
    std.log.info(".SLEEP: ten 5ms naps took {d}ms", .{elapsed});

    // A signal can cut a nap short, so the floor is deliberately loose. The ceiling is what
    // matters: a nap that never returned would hang the suite instead of failing it.
    try std.testing.expect(elapsed >= 10);
    try std.testing.expect(elapsed < 5_000);
}
