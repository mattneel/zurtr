//! zix SCTP congestion control (RFC 9260 7.2).
//!
//! What:
//! - How many bytes a sender may have unacknowledged at once, and how that number moves: up
//!   quickly while the path is unexplored, slowly once it is, and sharply down on any sign of
//!   loss.
//! - The three variables the RFC names: cwnd, ssthresh, and partial_bytes_acked.
//!
//! Note:
//! - This is per association, not per stream. One slow channel and one fast channel share the
//!   same window, which is exactly why a large message on one data channel delays the next
//!   message on another.
//! - The window grows only while it is FULLY USED. Acknowledging a trickle of data must not
//!   raise a limit that was never reached, or an idle association would drift up to an
//!   enormous window and then burst.
//! - Loss halves the window, a timeout drops it to one packet. The difference is what a sender
//!   learned: gap reports mean packets are still getting through, silence means nothing is.
//! - The initial window uses the IPv4 constant from RFC 9260 7.2.1. Under DTLS the SCTP layer
//!   cannot see the address family (RFC 8261 6.1), and the IPv6 constant differs by 60 bytes,
//!   which is under one percent of the value either way.

const std = @import("std");

/// Ceiling on the initial window, from RFC 9260 7.2.1 for an IPv4 peer.
pub const INITIAL_WINDOW_CEILING: usize = 4404;

/// Floor the window is never reduced below, as a multiple of the path maximum.
pub const REDUCED_WINDOW_PACKETS: usize = 4;

/// Setup for one association's window.
pub const Config = struct {
    /// Largest SCTP packet that fits the path, in bytes. RFC 9260 calls this PMDCS.
    path_max_bytes: usize = 1200,
    /// Starting slow-start threshold. RFC 9260 7.2.1 wants it arbitrarily high, so the default
    /// is high enough that the window is never in congestion avoidance before any loss.
    initial_ssthresh: usize = std.math.maxInt(u32),
};

/// Which growth rule is in force.
pub const Phase = enum {
    /// The window doubles roughly every round trip.
    SLOW_START,
    /// The window grows by one packet every round trip.
    CONGESTION_AVOIDANCE,
};

/// One association's congestion state.
///
/// Usage:
/// ```zig
/// var window = Window.init(.{ .path_max_bytes = 1200 });
///
/// const room = window.available(in_flight, peer_rwnd);
/// // ... send up to `room` bytes, then on the SACK:
/// window.onAck(newly_acked_bytes, flight_before_the_sack);
/// ```
pub const Window = struct {
    path_max_bytes: usize,
    /// How many unacknowledged bytes are allowed on the path.
    cwnd: usize,
    /// The boundary between the two growth rules.
    ssthresh: usize,
    /// Progress towards the next one-packet increase, used in congestion avoidance only.
    partial_bytes_acked: usize,
    /// Set while recovering from a fast retransmit, when the window must not shrink again.
    in_fast_recovery: bool,
    /// Whether the idle reduction has already been applied since the last send.
    idle_reduced: bool,

    /// Start a fresh window.
    ///
    /// Param:
    /// config - Config
    ///
    /// Return:
    /// - Window
    pub fn init(config: Config) Window {
        return .{
            .path_max_bytes = config.path_max_bytes,
            .cwnd = initialWindow(config.path_max_bytes),
            .ssthresh = config.initial_ssthresh,
            .partial_bytes_acked = 0,
            .in_fast_recovery = false,
            .idle_reduced = false,
        };
    }

    /// Which growth rule applies right now.
    ///
    /// Return:
    /// - Phase
    pub fn phase(self: Window) Phase {
        return if (self.cwnd <= self.ssthresh) .SLOW_START else .CONGESTION_AVOIDANCE;
    }

    /// How many more bytes may be put on the path.
    ///
    /// Note:
    /// - Bounded by the peer's advertised window as well as this one. The window says what the
    ///   path will carry, the peer's says what it will hold.
    ///
    /// Param:
    /// in_flight - usize (bytes already sent and not yet acknowledged)
    /// peer_rwnd - usize (the peer's last advertised receive window)
    ///
    /// Return:
    /// - usize, zero when there is no room
    pub fn available(self: Window, in_flight: usize, peer_rwnd: usize) usize {
        return @min(self.cwnd, peer_rwnd) -| in_flight;
    }

    /// Account for data that has just been acknowledged.
    ///
    /// Note:
    /// - `flight_before` is how much was outstanding when the acknowledgement arrived, before
    ///   this data was removed. The window only grows when that number had reached the window,
    ///   which is the RFC's "fully utilized" condition.
    ///
    /// Param:
    /// acked_bytes - usize (newly acknowledged, chunk headers and padding included)
    /// flight_before - usize (bytes outstanding just before this acknowledgement)
    ///
    /// Return:
    /// - void
    pub fn onAck(self: *Window, acked_bytes: usize, flight_before: usize) void {
        self.idle_reduced = false;

        const fully_used = flight_before >= self.cwnd;

        if (self.phase() == .SLOW_START) {
            if (!fully_used or self.in_fast_recovery) return;

            // Capped at one packet per acknowledgement, which is what stops a peer splitting its
            // acknowledgements into slivers to inflate the window (RFC 9260 7.2.1).
            self.cwnd += @min(acked_bytes, self.path_max_bytes);

            return;
        }

        self.partial_bytes_acked += acked_bytes;

        if (!fully_used) {
            self.partial_bytes_acked = @min(self.partial_bytes_acked, self.cwnd);

            return;
        }

        if (self.partial_bytes_acked >= self.cwnd) {
            self.partial_bytes_acked -= self.cwnd;
            self.cwnd += self.path_max_bytes;
        }
    }

    /// Everything sent has been acknowledged, so there is no partial progress to carry.
    ///
    /// Return:
    /// - void
    pub fn onFullyAcked(self: *Window) void {
        self.partial_bytes_acked = 0;
    }

    /// Loss reported by gap blocks, so the window halves (RFC 9260 7.2.3).
    ///
    /// Note:
    /// - Does nothing while already in fast recovery. One loss episode reduces the window once,
    ///   however many chunks it covered.
    ///
    /// Return:
    /// - void
    pub fn onLoss(self: *Window) void {
        if (self.in_fast_recovery) return;

        self.ssthresh = self.reducedThreshold();
        self.cwnd = self.ssthresh;
        self.partial_bytes_acked = 0;
    }

    /// The retransmission timer expired, so the window drops to a single packet.
    ///
    /// Return:
    /// - void
    pub fn onTimeout(self: *Window) void {
        self.ssthresh = self.reducedThreshold();
        self.cwnd = self.path_max_bytes;
        self.partial_bytes_acked = 0;
        self.in_fast_recovery = false;
    }

    /// Nothing has been sent for a whole retransmission timeout (RFC 9260 7.2.1).
    ///
    /// Note:
    /// - Applies once per idle period. What the window learned about the path has expired, but
    ///   the threshold keeps the knowledge so recovery is not from scratch.
    ///
    /// Return:
    /// - void
    pub fn onIdle(self: *Window) void {
        if (self.idle_reduced) return;

        self.ssthresh = self.cwnd;
        self.cwnd = @max(self.cwnd / 2, REDUCED_WINDOW_PACKETS * self.path_max_bytes);
        self.idle_reduced = true;
    }

    /// Enter fast recovery, which pins the window until the exit point is acknowledged.
    ///
    /// Return:
    /// - void
    pub fn enterFastRecovery(self: *Window) void {
        self.in_fast_recovery = true;
    }

    /// Leave fast recovery.
    ///
    /// Return:
    /// - void
    pub fn exitFastRecovery(self: *Window) void {
        self.in_fast_recovery = false;
    }

    /// Half the window, but never below four packets.
    fn reducedThreshold(self: Window) usize {
        return @max(self.cwnd / 2, REDUCED_WINDOW_PACKETS * self.path_max_bytes);
    }
};

/// The window an association starts with (RFC 9260 7.2.1).
///
/// Param:
/// path_max_bytes - usize
///
/// Return:
/// - usize
pub fn initialWindow(path_max_bytes: usize) usize {
    return @min(4 * path_max_bytes, @max(2 * path_max_bytes, INITIAL_WINDOW_CEILING));
}

// --------------------------------------------------------------------------------------- //
// test cases

const path: usize = 1200;

test "zix sctp: congestion init, the starting window follows the RFC formula" {
    // min(4 * 1200, max(2 * 1200, 4404)) = min(4800, 4404) = 4404.
    try std.testing.expectEqual(@as(usize, 4404), initialWindow(1200));

    // A large path maximum makes the 4404 floor irrelevant, so two packets wins the inner max
    // and four packets loses the outer min.
    try std.testing.expectEqual(@as(usize, 8000), initialWindow(4000));

    // A small one makes four packets the whole answer.
    try std.testing.expectEqual(@as(usize, 2000), initialWindow(500));
}

test "zix sctp: congestion init, a fresh window is in slow start" {
    const window = Window.init(.{ .path_max_bytes = path });

    try std.testing.expectEqual(Phase.SLOW_START, window.phase());
    try std.testing.expectEqual(@as(usize, 4404), window.cwnd);
    try std.testing.expectEqual(@as(usize, 0), window.partial_bytes_acked);
}

test "zix sctp: congestion room, the smaller of the two windows decides" {
    const window = Window.init(.{ .path_max_bytes = path });

    try std.testing.expectEqual(@as(usize, 4404), window.available(0, 65536));
    try std.testing.expectEqual(@as(usize, 1404), window.available(3000, 65536));

    // A peer with a small receive window caps it regardless of the path.
    try std.testing.expectEqual(@as(usize, 2000), window.available(0, 2000));
    try std.testing.expectEqual(@as(usize, 0), window.available(5000, 65536));
}

test "zix sctp: congestion slow start, a full window grows by the acknowledged bytes" {
    var window = Window.init(.{ .path_max_bytes = path });
    const before = window.cwnd;

    window.onAck(1000, before);

    try std.testing.expectEqual(before + 1000, window.cwnd);
}

test "zix sctp: congestion slow start, growth is capped at one packet per acknowledgement" {
    var window = Window.init(.{ .path_max_bytes = path });
    const before = window.cwnd;

    window.onAck(4404, before);

    // Without the cap a peer could acknowledge a whole window and double it in one step.
    try std.testing.expectEqual(before + path, window.cwnd);
}

test "zix sctp: congestion slow start, a window that was not full does not grow" {
    var window = Window.init(.{ .path_max_bytes = path });
    const before = window.cwnd;

    window.onAck(1000, 1000);

    try std.testing.expectEqual(before, window.cwnd);
}

test "zix sctp: congestion slow start, no growth while in fast recovery" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.enterFastRecovery();

    const before = window.cwnd;
    window.onAck(1000, before);

    try std.testing.expectEqual(before, window.cwnd);
}

test "zix sctp: congestion phase, crossing the threshold switches the growth rule" {
    var window = Window.init(.{ .path_max_bytes = path, .initial_ssthresh = 5000 });

    try std.testing.expectEqual(Phase.SLOW_START, window.phase());

    window.onAck(1000, window.cwnd);

    try std.testing.expectEqual(@as(usize, 5404), window.cwnd);
    try std.testing.expectEqual(Phase.CONGESTION_AVOIDANCE, window.phase());
}

test "zix sctp: congestion avoidance, a full window of acknowledgements adds one packet" {
    var window = Window.init(.{ .path_max_bytes = path, .initial_ssthresh = 1000 });
    const before = window.cwnd;

    window.onAck(before, before);

    try std.testing.expectEqual(before + path, window.cwnd);
    try std.testing.expectEqual(@as(usize, 0), window.partial_bytes_acked);
}

test "zix sctp: congestion avoidance, progress accumulates until it reaches the window" {
    var window = Window.init(.{ .path_max_bytes = path, .initial_ssthresh = 1000 });
    const before = window.cwnd;

    window.onAck(2000, before);
    try std.testing.expectEqual(before, window.cwnd);
    try std.testing.expectEqual(@as(usize, 2000), window.partial_bytes_acked);

    window.onAck(2500, before);

    // 4500 covers the 4404 window, so one packet is added and the remainder carries over.
    try std.testing.expectEqual(before + path, window.cwnd);
    try std.testing.expectEqual(@as(usize, 96), window.partial_bytes_acked);
}

test "zix sctp: congestion avoidance, progress on a window that was not full is capped" {
    var window = Window.init(.{ .path_max_bytes = path, .initial_ssthresh = 1000 });

    window.onAck(9000, 100);

    try std.testing.expectEqual(window.cwnd, window.partial_bytes_acked);
    try std.testing.expectEqual(@as(usize, 4404), window.cwnd);
}

test "zix sctp: congestion avoidance, a fully drained queue clears the progress" {
    var window = Window.init(.{ .path_max_bytes = path, .initial_ssthresh = 1000 });
    window.onAck(2000, window.cwnd);

    window.onFullyAcked();

    try std.testing.expectEqual(@as(usize, 0), window.partial_bytes_acked);
}

test "zix sctp: congestion loss, the window halves and the threshold follows it" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;

    window.onLoss();

    try std.testing.expectEqual(@as(usize, 10_000), window.cwnd);
    try std.testing.expectEqual(@as(usize, 10_000), window.ssthresh);
    try std.testing.expectEqual(@as(usize, 0), window.partial_bytes_acked);
}

test "zix sctp: congestion loss, the window never halves below four packets" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 2_000;

    window.onLoss();

    try std.testing.expectEqual(4 * path, window.cwnd);
}

test "zix sctp: congestion loss, a second loss inside one recovery does not halve again" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;

    window.onLoss();
    window.enterFastRecovery();
    window.onLoss();

    try std.testing.expectEqual(@as(usize, 10_000), window.cwnd);

    window.exitFastRecovery();
    window.onLoss();

    try std.testing.expectEqual(@as(usize, 5_000), window.cwnd);
}

test "zix sctp: congestion timeout, the window drops to a single packet" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;
    window.enterFastRecovery();

    window.onTimeout();

    try std.testing.expectEqual(path, window.cwnd);
    try std.testing.expectEqual(@as(usize, 10_000), window.ssthresh);
    try std.testing.expect(!window.in_fast_recovery);
}

test "zix sctp: congestion timeout, the window is back in slow start afterwards" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;
    window.ssthresh = 20_000;

    window.onTimeout();

    try std.testing.expectEqual(Phase.SLOW_START, window.phase());
}

test "zix sctp: congestion idle, a quiet period halves the window once" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;

    window.onIdle();

    try std.testing.expectEqual(@as(usize, 10_000), window.cwnd);
    try std.testing.expectEqual(@as(usize, 20_000), window.ssthresh);

    // Staying idle does not keep halving it, the reduction is once per idle period.
    window.onIdle();
    try std.testing.expectEqual(@as(usize, 10_000), window.cwnd);
}

test "zix sctp: congestion idle, sending again arms the next reduction" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 20_000;

    window.onIdle();
    window.onAck(100, 100);
    window.onIdle();

    try std.testing.expectEqual(@as(usize, 5_000), window.cwnd);
}

test "zix sctp: congestion idle, the window never halves below four packets" {
    var window = Window.init(.{ .path_max_bytes = path });
    window.cwnd = 5_000;

    window.onIdle();

    try std.testing.expectEqual(4 * path, window.cwnd);
}
