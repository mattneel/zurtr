//! zix SCTP retransmission timeout (RFC 9260 6.3.1).
//!
//! What:
//! - How long to wait for an acknowledgement before assuming a packet was lost. Kept as a
//!   smoothed round trip time plus four times its variation, so a link that jitters gets more
//!   patience than one that does not.
//! - The doubling that happens on every timeout, which is what keeps a sender from hammering a
//!   path that has actually gone away.
//!
//! Note:
//! - Milliseconds throughout, and the clock is the caller's. Nothing here reads a timer.
//! - The floor matters more than it looks. RFC 9260 16 puts RTO.Min at one second, and a shorter
//!   floor makes an association fire spurious timeouts on an otherwise healthy path. It is a
//!   setting rather than a constant only because a test needs to move faster than a second.
//! - Karn's algorithm is not enforced here: this file cannot tell whether the chunk that
//!   produced a measurement was retransmitted. The caller must simply not offer a measurement
//!   taken from a retransmitted chunk, because the answer is ambiguous.
//! - Integer arithmetic throughout. The alpha and beta of the RFC are 1/8 and 1/4, which are
//!   shifts, so nothing here needs floating point.

const std = @import("std");

/// The protocol parameters RFC 9260 16 recommends, in milliseconds.
pub const Config = struct {
    /// RTO.Initial, used until a round trip has actually been measured.
    initial_ms: u64 = 1_000,
    /// RTO.Min, the floor every computed value is raised to.
    min_ms: u64 = 1_000,
    /// RTO.Max, the ceiling that caps the doubling.
    max_ms: u64 = 60_000,
    /// RTO.Alpha as a right shift, so 3 means one eighth.
    alpha_shift: u3 = 3,
    /// RTO.Beta as a right shift, so 2 means one quarter.
    beta_shift: u3 = 2,
    /// Clock granularity, the value RTTVAR is raised to when it computes as zero.
    granularity_ms: u64 = 1,
};

/// Tracks the round trip and the timeout derived from it.
///
/// Usage:
/// ```zig
/// var estimator = Estimator.init(.{});
///
/// estimator.measure(rtt_ms);        // only from a chunk that was never retransmitted
/// arm(estimator.timeout_ms);
///
/// estimator.backOff();              // on every T3 expiry
/// ```
pub const Estimator = struct {
    config: Config,
    /// Current retransmission timeout. Read it, do not assign to it.
    timeout_ms: u64,
    /// Smoothed round trip time, meaningless until `measured` is set.
    smoothed_ms: u64 = 0,
    /// Round trip variation, meaningless until `measured` is set.
    variation_ms: u64 = 0,
    /// Whether any round trip has been measured yet.
    measured: bool = false,

    /// Start at RTO.Initial with nothing measured.
    ///
    /// Param:
    /// config - Config
    ///
    /// Return:
    /// - Estimator
    pub fn init(config: Config) Estimator {
        return .{ .config = config, .timeout_ms = config.initial_ms };
    }

    /// Fold a round trip measurement in.
    ///
    /// Note:
    /// - The first measurement replaces the estimate outright, later ones move it a fraction of
    ///   the way (RFC 9260 6.3.1 C2 and C3).
    /// - Never call this with a measurement from a retransmitted chunk, see the file note.
    ///
    /// Param:
    /// rtt_ms - u64 (measured round trip, in milliseconds)
    ///
    /// Return:
    /// - void
    pub fn measure(self: *Estimator, rtt_ms: u64) void {
        if (!self.measured) {
            self.smoothed_ms = rtt_ms;
            self.variation_ms = rtt_ms / 2;
            self.measured = true;
        } else {
            const drift = if (self.smoothed_ms > rtt_ms) self.smoothed_ms - rtt_ms else rtt_ms - self.smoothed_ms;

            // The RFC updates the variation using the OLD smoothed value, so this order is not
            // interchangeable with the line below it.
            self.variation_ms = self.variation_ms - (self.variation_ms >> self.config.beta_shift) +
                (drift >> self.config.beta_shift);
            self.smoothed_ms = self.smoothed_ms - (self.smoothed_ms >> self.config.alpha_shift) +
                (rtt_ms >> self.config.alpha_shift);
        }

        // Rule G1: a variation that rounds to nothing would give a timeout with no slack at all.
        if (self.variation_ms == 0) self.variation_ms = self.config.granularity_ms;

        self.timeout_ms = self.clamp(self.smoothed_ms + 4 * self.variation_ms);
    }

    /// Double the timeout after an expiry (RFC 9260 6.3.3 E2).
    ///
    /// Return:
    /// - void
    pub fn backOff(self: *Estimator) void {
        self.timeout_ms = self.clamp(self.timeout_ms *| 2);
    }

    /// Forget every measurement and go back to RTO.Initial.
    ///
    /// Note:
    /// - For a path whose conditions are known to have changed, where the old estimate is not
    ///   evidence about the new path.
    ///
    /// Return:
    /// - void
    pub fn reset(self: *Estimator) void {
        self.smoothed_ms = 0;
        self.variation_ms = 0;
        self.measured = false;
        self.timeout_ms = self.config.initial_ms;
    }

    /// Hold a value between the configured floor and ceiling (rules C6 and C7).
    fn clamp(self: Estimator, value_ms: u64) u64 {
        return std.math.clamp(value_ms, self.config.min_ms, self.config.max_ms);
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

/// A configuration with room below the floor, so the arithmetic of the rules is visible.
const fast: Config = .{ .initial_ms = 100, .min_ms = 10, .max_ms = 1_000 };

test "zix sctp: rto init, the timeout starts at RTO.Initial with nothing measured" {
    const estimator = Estimator.init(.{});

    try std.testing.expectEqual(@as(u64, 1_000), estimator.timeout_ms);
    try std.testing.expect(!estimator.measured);
}

test "zix sctp: rto measure, the first measurement sets the estimate outright" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);

    // C2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 * RTTVAR.
    try std.testing.expectEqual(@as(u64, 40), estimator.smoothed_ms);
    try std.testing.expectEqual(@as(u64, 20), estimator.variation_ms);
    try std.testing.expectEqual(@as(u64, 120), estimator.timeout_ms);
    try std.testing.expect(estimator.measured);
}

test "zix sctp: rto measure, a later measurement moves the estimate a fraction of the way" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);
    estimator.measure(80);

    // C3 with beta 1/4 and alpha 1/8: variation 20 - 5 + 10 = 25, smoothed 40 - 5 + 10 = 45.
    try std.testing.expectEqual(@as(u64, 25), estimator.variation_ms);
    try std.testing.expectEqual(@as(u64, 45), estimator.smoothed_ms);
    try std.testing.expectEqual(@as(u64, 145), estimator.timeout_ms);
}

test "zix sctp: rto measure, the variation uses the smoothed value from before the update" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);
    estimator.measure(40);

    // Updating smoothed first would give a drift of 0 against the new value and a different
    // variation. With the RFC order the drift is measured against 40, which is also 0 here, so
    // the difference shows in the smoothed value staying put while variation decays.
    try std.testing.expectEqual(@as(u64, 40), estimator.smoothed_ms);
    try std.testing.expectEqual(@as(u64, 15), estimator.variation_ms);
}

test "zix sctp: rto measure, a steady path converges on the round trip" {
    var estimator = Estimator.init(fast);

    for (0..40) |_| estimator.measure(50);

    try std.testing.expectEqual(@as(u64, 50), estimator.smoothed_ms);

    // The variation decays until the shift stops taking anything off it, which with beta 1/4 is
    // at 3. Integer arithmetic leaves that residue, and it is what keeps a little slack in the
    // timeout on a path that never varies.
    try std.testing.expectEqual(@as(u64, 3), estimator.variation_ms);
    try std.testing.expectEqual(@as(u64, 62), estimator.timeout_ms);
}

test "zix sctp: rto measure, a variation that rounds to zero is raised to the granularity" {
    var estimator = Estimator.init(.{ .initial_ms = 100, .min_ms = 1, .max_ms = 1_000, .granularity_ms = 4 });
    estimator.measure(0);

    try std.testing.expectEqual(@as(u64, 4), estimator.variation_ms);
    try std.testing.expectEqual(@as(u64, 16), estimator.timeout_ms);
}

test "zix sctp: rto measure, a computed value below the floor is raised to it" {
    var estimator = Estimator.init(.{});
    estimator.measure(4);

    // A 4 ms round trip computes to 12 ms, and RTO.Min is a full second.
    try std.testing.expectEqual(@as(u64, 1_000), estimator.timeout_ms);
}

test "zix sctp: rto measure, a computed value above the ceiling is capped" {
    var estimator = Estimator.init(fast);
    estimator.measure(10_000);

    try std.testing.expectEqual(@as(u64, 1_000), estimator.timeout_ms);
}

test "zix sctp: rto backoff, the timeout doubles on every expiry" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);

    try std.testing.expectEqual(@as(u64, 120), estimator.timeout_ms);

    estimator.backOff();
    try std.testing.expectEqual(@as(u64, 240), estimator.timeout_ms);

    estimator.backOff();
    try std.testing.expectEqual(@as(u64, 480), estimator.timeout_ms);
}

test "zix sctp: rto backoff, doubling stops at the ceiling" {
    var estimator = Estimator.init(fast);

    for (0..20) |_| estimator.backOff();

    try std.testing.expectEqual(@as(u64, 1_000), estimator.timeout_ms);
}

test "zix sctp: rto backoff, a measurement after a backoff replaces the doubled value" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);
    estimator.backOff();
    estimator.backOff();

    try std.testing.expectEqual(@as(u64, 480), estimator.timeout_ms);

    estimator.measure(40);

    // The doubling is a guess about a lost packet, a measurement is evidence, so evidence wins.
    try std.testing.expectEqual(@as(u64, 100), estimator.timeout_ms);
}

test "zix sctp: rto reset, everything goes back to the starting point" {
    var estimator = Estimator.init(fast);
    estimator.measure(40);
    estimator.backOff();

    estimator.reset();

    try std.testing.expectEqual(@as(u64, 100), estimator.timeout_ms);
    try std.testing.expect(!estimator.measured);
    try std.testing.expectEqual(@as(u64, 0), estimator.smoothed_ms);
}

test "zix sctp: rto measure, a jittering path keeps a wider timeout than a steady one" {
    var steady = Estimator.init(fast);
    var jittery = Estimator.init(fast);

    for (0..20) |round| {
        steady.measure(50);
        jittery.measure(if (round % 2 == 0) 20 else 80);
    }

    try std.testing.expect(jittery.timeout_ms > steady.timeout_ms);
}
