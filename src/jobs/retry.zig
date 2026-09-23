//! Retry timing: how long a failed attempt waits before it is available again.
//!
//! The contract (`docs/modules/jobs.md`) asks for exponential backoff with jitter, capped by
//! `max_backoff`. This module is the arithmetic and nothing else: no database, no clock, no I/O, so
//! the policy is provable on its own and the queue only has to apply it.
//!
//! Two decisions worth naming:
//!
//!   * **The attempt count is bumped by the claim, not by the failure.** A worker that dies mid-job
//!     still consumed an attempt, which is what makes a crash loop visible as a number instead of as
//!     silence. `delayMs` therefore takes the attempt number *that just failed*, not the next one.
//!   * **Jitter is a parameter of the policy, and its default for production is full jitter**
//!     (`uniform(0, ceiling)`), which is what stops a fleet of workers that failed together from
//!     retrying together. Tests set `.none` so the arithmetic is exact rather than probabilistic.

const std = @import("std");

/// How much of the computed ceiling a single delay gets to use.
pub const Jitter = enum {
    /// The full computed ceiling, every time. Deterministic: this is what tests use.
    none,
    /// A uniform draw in `[0, ceiling]`. The production default; spreads a thundering herd.
    full,
};

pub const Policy = struct {
    /// Milliseconds for the first retry, before any growth.
    base_ms: i64 = 1_000,
    /// Growth per attempt. An integer on purpose: `base * factor^(attempt-1)` is exactly
    /// reproducible, and a float would make two runs disagree in the last millisecond.
    factor: u32 = 2,
    /// The ceiling on the computed delay, before jitter.
    max_ms: i64 = 300_000,
    jitter: Jitter = .full,

    /// The ceiling for the attempt that just failed, ignoring jitter.
    ///
    /// `attempt` is 1-based and is the attempt that failed, so `attempt = 1` waits `base_ms`.
    pub fn ceilingMs(self: Policy, attempt: u32) i64 {
        if (attempt <= 1) return @min(self.base_ms, self.max_ms);

        var value = self.base_ms;
        var remaining = attempt - 1;
        while (remaining > 0) : (remaining -= 1) {
            // Saturating, because the ceiling is the point of the cap: an attempt count large
            // enough to overflow is an attempt count that has already waited longer than it will
            // ever wait again. Overflow here would be a panic in a release-safe build, which is a
            // worse answer than "the cap".
            value = std.math.mul(i64, value, self.factor) catch return self.max_ms;
            if (value >= self.max_ms) return self.max_ms;
        }

        return @min(value, self.max_ms);
    }

    /// The delay for the attempt that just failed. `draw` is only used by `.full` jitter, and is passed
    /// in rather than drawn here, so the policy stays a pure function of its inputs.
    ///
    /// The draw is scaled by the ceiling and divided by the draw's own maximum, which is what puts the
    /// extremes exactly on the ends of the range: a draw of 0 waits no time at all and the largest draw
    /// waits the whole ceiling. Dividing by `2^64` instead would make the ceiling unreachable, and the
    /// difference shows up the first time someone asserts the cap.
    pub fn delayMs(self: Policy, attempt: u32, draw: u64) i64 {
        const ceiling = self.ceilingMs(attempt);

        return switch (self.jitter) {
            .none => ceiling,
            .full => if (ceiling <= 0) 0 else @intCast(
                (@as(u128, draw) * @as(u128, @intCast(ceiling))) / std.math.maxInt(u64),
            ),
        };
    }

    /// Whether the attempt that just failed gets another one. `max_attempts` is the row's, not the
    /// policy's: the enqueue site decides how patient one job is, and the policy decides how long it
    /// waits between tries.
    pub fn retries(self: Policy, attempt: u32, max_attempts: u32) bool {
        _ = self;

        return attempt < max_attempts;
    }
};

test "the ceiling grows by the factor, and the cap is a ceiling rather than a suggestion" {
    const policy = Policy{ .base_ms = 100, .factor = 3, .max_ms = 1_000, .jitter = .none };

    try std.testing.expectEqual(@as(i64, 100), policy.ceilingMs(1));
    try std.testing.expectEqual(@as(i64, 300), policy.ceilingMs(2));
    try std.testing.expectEqual(@as(i64, 900), policy.ceilingMs(3));
    // 2700 would be the uncapped value; the cap is what a caller configures.
    try std.testing.expectEqual(@as(i64, 1_000), policy.ceilingMs(4));
    try std.testing.expectEqual(@as(i64, 1_000), policy.ceilingMs(40));
}

test "an attempt count large enough to overflow saturates at the cap instead of panicking" {
    const policy = Policy{ .base_ms = 1_000, .factor = 2, .max_ms = 60_000, .jitter = .none };

    // 2^63 would overflow long before this; the answer is the cap, not a panic.
    try std.testing.expectEqual(@as(i64, 60_000), policy.ceilingMs(9_000));
}

test "the cap holds even when the base is already above it" {
    const policy = Policy{ .base_ms = 5_000, .factor = 2, .max_ms = 1_000, .jitter = .none };

    try std.testing.expectEqual(@as(i64, 1_000), policy.ceilingMs(1));
    try std.testing.expectEqual(@as(i64, 1_000), policy.ceilingMs(2));
}

test "full jitter stays inside the ceiling and spreads across it" {
    const policy = Policy{ .base_ms = 1_000, .factor = 2, .max_ms = 60_000, .jitter = .full };

    // The extremes of the draw, and the middle: whatever the draw, the delay is inside [0, ceiling].
    try std.testing.expectEqual(@as(i64, 0), policy.delayMs(1, 0));
    try std.testing.expectEqual(@as(i64, 1_000), policy.delayMs(1, std.math.maxInt(u64)));
    const middle = policy.delayMs(1, 1 << 63);
    try std.testing.expect(middle > 0 and middle <= 1_000);

    // Two workers that failed together do not retry together: a draw from the bottom quarter of the
    // range and one from the top quarter land on different delays. Note what is *not* asserted — two
    // draws one apart usually agree, because scaling 2^64 draws onto a few thousand milliseconds is
    // many-to-one. The spread is the property; the neighbourhood is not.
    try std.testing.expect(policy.delayMs(2, 1 << 61) != policy.delayMs(2, 3 << 61));
}

test "a failed attempt retries only while attempts remain" {
    const policy = Policy{};

    try std.testing.expect(policy.retries(1, 3));
    try std.testing.expect(policy.retries(2, 3));
    try std.testing.expect(!policy.retries(3, 3));
    // max_attempts = 1 means "try once, then fail": the first failure is terminal.
    try std.testing.expect(!policy.retries(1, 1));
}
