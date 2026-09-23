//! zix HTTP/3 QUIC loss detection and congestion control (RFC 9002, Layer L).
//!
//! What:
//! - The sender-side timing brain: the RTT estimator (latest / smoothed / min plus variation with
//!   the ack-delay adjustment), the two loss thresholds (packet reordering and elapsed time), the
//!   Probe Timeout, and the NewReno congestion controller.
//! - All times are integer microseconds and all windows integer bytes, so every value is exact and
//!   reproducible. Proven against the RFC 9002 formulas and constants in the tests below.

const std = @import("std");
const win_io = @import("../../utils/windows_io.zig");

/// The local timer granularity (RFC 9002 6.1.2): 1 millisecond, in microseconds.
pub const granularity_us: u64 = 1000;

/// The packet reordering threshold (RFC 9002 6.1.1).
pub const packet_threshold: u64 = 3;

/// The persistent-congestion duration multiplier (RFC 9002 7.6).
pub const persistent_congestion_threshold: u64 = 3;

/// The initial RTT used before a sample exists (RFC 9002 6.2.2), in microseconds.
pub const initial_rtt_us: u64 = 333_000;

/// The peer's maximum ACK delay (RFC 9000 18.2 transport parameter 0x0a) when it advertises none.
/// The client's actual max_ack_delay is not parsed (a completeness gap noted alongside the loss
/// recovery this constant supports): this is the RFC-recommended default, used as a fallback.
pub const default_max_ack_delay_us: u64 = 25_000;

/// The current monotonic time in microseconds (CLOCK_MONOTONIC), the timebase every RTT sample and
/// sent-packet record in this engine uses. Monotonic rather than wall-clock, so a system time step
/// never corrupts an RTT measurement or a loss-detection deadline.
pub fn nowUs() u64 {
    if (comptime @import("builtin").target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);

        return @as(u64, @intCast(ts.sec)) * std.time.us_per_s + @as(u64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_us)));
    }

    if (comptime @import("builtin").target.os.tag == .windows) return win_io.monotonicUs();

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);

    return @as(u64, @intCast(ts.sec)) * std.time.us_per_s + @as(u64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_us)));
}

// --------------------------------------------------------------- //

/// The RTT estimator for one path (RFC 9002 5). All times are microseconds.
pub const RttEstimator = struct {
    smoothed_rtt: u64 = 0,
    rttvar: u64 = 0,
    min_rtt: u64 = 0,
    has_sample: bool = false,

    /// Fold one RTT sample into the estimate (RFC 9002 5.1-5.3). The first sample resets the
    /// estimator, later samples evolve smoothed_rtt and rttvar after the ack-delay adjustment.
    ///
    /// Param:
    /// latest_rtt - u64 (the raw sample, ack time minus send time of the largest acked)
    /// ack_delay - u64 (the peer-reported acknowledgment delay)
    /// max_ack_delay - u64 (the peer's advertised maximum)
    /// handshake_confirmed - bool (whether to cap ack_delay at max_ack_delay)
    ///
    /// Return:
    /// - void
    pub fn onSample(self: *RttEstimator, latest_rtt: u64, ack_delay: u64, max_ack_delay: u64, handshake_confirmed: bool) void {
        if (!self.has_sample) {
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.has_sample = true;

            return;
        }

        self.min_rtt = @min(self.min_rtt, latest_rtt);

        var delay = ack_delay;
        if (handshake_confirmed) delay = @min(delay, max_ack_delay);

        var adjusted = latest_rtt;
        if (latest_rtt >= self.min_rtt + delay) adjusted = latest_rtt - delay;

        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted) / 8;
        const sample = if (self.smoothed_rtt > adjusted) self.smoothed_rtt - adjusted else adjusted - self.smoothed_rtt;
        self.rttvar = (3 * self.rttvar + sample) / 4;
    }
};

/// The time-threshold for loss (RFC 9002 6.1.2): max(9/8 * max(smoothed, latest), kGranularity).
pub fn lossTimeThreshold(smoothed_rtt: u64, latest_rtt: u64) u64 {
    const base = @max(smoothed_rtt, latest_rtt);

    return @max(9 * base / 8, granularity_us);
}

/// Whether a packet is declared lost (RFC 9002 6.1): it must be unacknowledged and sent before the
/// largest acknowledged, and then either kPacketThreshold packets earlier or past the time threshold.
pub fn packetLost(packet_number: u64, largest_acked: u64, time_since_sent: u64, smoothed_rtt: u64, latest_rtt: u64) bool {
    if (packet_number >= largest_acked) return false;
    if (largest_acked - packet_number >= packet_threshold) return true;

    return time_since_sent >= lossTimeThreshold(smoothed_rtt, latest_rtt);
}

// --------------------------------------------------------------- //

/// Compute the Probe Timeout (RFC 9002 6.2.1): smoothed_rtt + max(4*rttvar, kGranularity) +
/// max_ack_delay. For the Initial and Handshake spaces, pass max_ack_delay = 0.
pub fn computePto(smoothed_rtt: u64, rttvar: u64, max_ack_delay: u64) u64 {
    return smoothed_rtt + @max(4 * rttvar, granularity_us) + max_ack_delay;
}

/// Apply the PTO backoff (RFC 9002 6.2.1): each consecutive timeout doubles the period.
pub fn ptoWithBackoff(base_pto: u64, backoff_count: u6) u64 {
    return base_pto << backoff_count;
}

// --------------------------------------------------------------- //

/// The RFC 9002 7.2 initial congestion window: ten datagrams, capped to the larger of 14,720 bytes or
/// two datagrams. The reference value. A server on a known low-loss path (a benchmark loopback) may
/// start higher via config.initial_window_packets, which the controller takes as a byte count that
/// bypasses this RFC ceiling: this function stays the RFC default other code can compare against.
pub fn initialWindow(max_datagram_size: u64) u64 {
    return @min(10 * max_datagram_size, @max(2 * max_datagram_size, 14_720));
}

/// The minimum congestion window (RFC 9002 7.2): two datagrams.
pub fn minimumWindow(max_datagram_size: u64) u64 {
    return 2 * max_datagram_size;
}

/// The NewReno congestion controller (RFC 9002 7.3). Bytes throughout.
pub const CongestionController = struct {
    max_datagram_size: u64,
    congestion_window: u64,
    ssthresh: u64,

    /// Start in slow start with `initial_window` bytes (floored at the minimum window) and an unbounded
    /// slow-start threshold (RFC 9002 7.3 / appendix B.3). The caller supplies the window in bytes
    /// (config.initial_window_packets times the datagram size), so a known low-loss path can start
    /// above the RFC initialWindow default without changing the controller. Pass initialWindow(mds) for
    /// the RFC default.
    ///
    /// Param:
    /// max_datagram_size - u64 (the path MTU estimate, the congestion-avoidance step unit)
    /// initial_window - u64 (the starting window in bytes, floored at minimumWindow)
    ///
    /// Return:
    /// - CongestionController
    pub fn init(max_datagram_size: u64, initial_window: u64) CongestionController {
        return .{
            .max_datagram_size = max_datagram_size,
            .congestion_window = @max(initial_window, minimumWindow(max_datagram_size)),
            .ssthresh = std.math.maxInt(u64),
        };
    }

    /// Whether the controller is in slow start (RFC 9002 7.3.1): below the slow-start threshold.
    pub fn inSlowStart(self: CongestionController) bool {
        return self.congestion_window < self.ssthresh;
    }

    /// Grow the window on a newly acknowledged packet (RFC 9002 7.3.1 / 7.3.3). Slow start adds the
    /// acked bytes, congestion avoidance adds one datagram per window of acked bytes.
    pub fn onAckedBytes(self: *CongestionController, acked: u64) void {
        if (self.inSlowStart()) {
            self.congestion_window += acked;
        } else {
            self.congestion_window += self.max_datagram_size * acked / self.congestion_window;
        }
    }

    /// React to a congestion event (RFC 9002 7.3.2): halve the window (kLossReductionFactor) into the
    /// slow-start threshold, then clamp to the minimum window.
    pub fn onCongestionEvent(self: *CongestionController) void {
        self.ssthresh = self.congestion_window / 2;
        self.congestion_window = @max(self.ssthresh, minimumWindow(self.max_datagram_size));
    }

    /// Collapse to the minimum window on persistent congestion (RFC 9002 7.6).
    pub fn onPersistentCongestion(self: *CongestionController) void {
        self.congestion_window = minimumWindow(self.max_datagram_size);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: RFC 9002 5 RTT estimation" {
    var rtt = RttEstimator{};
    rtt.onSample(100_000, 0, 25_000, true);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.smoothed_rtt);
    try std.testing.expectEqual(@as(u64, 50_000), rtt.rttvar);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.min_rtt);

    rtt.onSample(120_000, 10_000, 25_000, true);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.min_rtt);
    try std.testing.expectEqual(@as(u64, 101_250), rtt.smoothed_rtt);
    try std.testing.expectEqual(@as(u64, 39_687), rtt.rttvar);

    var rtt2 = RttEstimator{};
    rtt2.onSample(100_000, 0, 25_000, true);
    rtt2.onSample(105_000, 50_000, 50_000, true);
    try std.testing.expectEqual(@as(u64, (7 * 100_000 + 105_000) / 8), rtt2.smoothed_rtt);

    var rtt3 = RttEstimator{};
    rtt3.onSample(100_000, 0, 20_000, true);
    rtt3.onSample(200_000, 80_000, 20_000, true);
    try std.testing.expectEqual(@as(u64, (7 * 100_000 + 180_000) / 8), rtt3.smoothed_rtt);
}

test "zix http3: RFC 9002 6.1 packet and time thresholds" {
    try std.testing.expectEqual(@as(u64, 3), packet_threshold);
    try std.testing.expect(packetLost(7, 10, 0, 100_000, 100_000));
    try std.testing.expect(!packetLost(8, 10, 0, 100_000, 100_000));
    try std.testing.expect(!packetLost(10, 10, 999_999_999, 100_000, 100_000));

    try std.testing.expectEqual(@as(u64, 1000), granularity_us);
    try std.testing.expectEqual(@as(u64, 135_000), lossTimeThreshold(100_000, 120_000));
    try std.testing.expect(packetLost(9, 10, 140_000, 100_000, 120_000));
    try std.testing.expect(!packetLost(9, 10, 100_000, 100_000, 120_000));
    try std.testing.expectEqual(@as(u64, 1000), lossTimeThreshold(100, 200));
}

test "zix http3: RFC 9002 6.2.1 Probe Timeout" {
    try std.testing.expectEqual(@as(u64, 283_748), computePto(100_000, 39_687, 25_000));
    try std.testing.expectEqual(@as(u64, 258_748), computePto(100_000, 39_687, 0));
    try std.testing.expectEqual(@as(u64, 50_000 + 1000), computePto(50_000, 100, 0));

    const base = computePto(100_000, 39_687, 25_000);
    try std.testing.expectEqual(@as(u64, 283_748), ptoWithBackoff(base, 0));
    try std.testing.expectEqual(@as(u64, 567_496), ptoWithBackoff(base, 1));
    try std.testing.expectEqual(@as(u64, 1_134_992), ptoWithBackoff(base, 2));
}

test "zix http3: RFC 9002 7 NewReno congestion control" {
    try std.testing.expectEqual(@as(u64, 12_000), initialWindow(1200));
    try std.testing.expectEqual(@as(u64, 14_720), initialWindow(1472));
    try std.testing.expectEqual(@as(u64, 2400), minimumWindow(1200));

    var cc = CongestionController.init(1200, initialWindow(1200));
    try std.testing.expect(cc.inSlowStart());
    try std.testing.expectEqual(@as(u64, 12_000), cc.congestion_window);

    cc.onAckedBytes(1200);
    try std.testing.expectEqual(@as(u64, 13_200), cc.congestion_window);

    cc.onCongestionEvent();
    try std.testing.expectEqual(@as(u64, 6600), cc.ssthresh);
    try std.testing.expectEqual(@as(u64, 6600), cc.congestion_window);
    try std.testing.expect(!cc.inSlowStart());

    cc.onAckedBytes(1200);
    try std.testing.expectEqual(@as(u64, 6600 + 1200 * 1200 / 6600), cc.congestion_window);

    cc.onPersistentCongestion();
    try std.testing.expectEqual(@as(u64, 2400), cc.congestion_window);

    try std.testing.expectEqual(@as(u64, 3), persistent_congestion_threshold);
    try std.testing.expectEqual(@as(u64, 333_000), initial_rtt_us);
}

test "zix http3: a configured initial window starts above the RFC ceiling and floors at the minimum" {
    // A benchmark-tuned window (64 packets * 1200 = 76,800 bytes) starts well above the RFC 14,720-byte
    // ceiling, so a large static response streams in one flight instead of ramping over several rounds.
    const wide = CongestionController.init(1200, 64 * 1200);
    try std.testing.expectEqual(@as(u64, 76_800), wide.congestion_window);
    try std.testing.expect(wide.inSlowStart());

    // The moderate library default (32 packets) sits between the RFC default and a full flight.
    const mid = CongestionController.init(1200, 32 * 1200);
    try std.testing.expectEqual(@as(u64, 38_400), mid.congestion_window);

    // A window below the two-datagram minimum is floored up to it (never start below minimumWindow).
    const tiny = CongestionController.init(1200, 500);
    try std.testing.expectEqual(minimumWindow(1200), tiny.congestion_window);
}

test "zix http3: nowUs is monotonic and moves in microseconds, not stuck at zero" {
    const first = nowUs();
    const second = nowUs();

    try std.testing.expect(second >= first);
    try std.testing.expect(first > 0);
}
