//! zix WebRTC deadline set: the timers one peer runs on.
//!
//! What:
//! - A fixed set of named deadlines, each either armed at a monotonic millisecond or not armed at
//!   all. The engine loop asks two things of it: which deadline has passed, and how long it may
//!   wait before asking again.
//! - Reads no clock. Every call takes the time from the caller, so the whole file is testable
//!   without sleeping.
//!
//! Note:
//! - This is why WebRTC is its own engine rather than a handler over the raw UDP path. Three of
//!   these four fire into silence: a DTLS flight is retransmitted when nothing comes back
//!   (RFC 6347 4.2.4.1), an SCTP chunk the same (RFC 9260 6.3), and consent expires while the peer
//!   says nothing at all (RFC 7675 5.1). A handler that only runs when a datagram arrives cannot
//!   do any of them.
//! - `takeExpired` disarms what it hands back. A caller that acts on a deadline and re-arms it is
//!   the normal path, and one that acts and does not re-arm has a deadline that fires once, which
//!   is what IDLE wants.

const std = @import("std");

/// The deadlines one peer can have outstanding.
pub const Kind = enum {
    /// A DTLS handshake flight is outstanding and the peer has not answered (RFC 6347 4.2.4.1).
    DTLS_RETRANSMIT,
    /// SCTP has data outstanding past its retransmission timeout (RFC 9260 6.3).
    SCTP_RETRANSMIT,
    /// Consent to keep sending expires (RFC 7675 5.1).
    ICE_CONSENT,
    /// The peer has said nothing for long enough that the engine drops it.
    IDLE,
};

/// How many deadlines a peer holds. Kept as a constant rather than derived, because the two Zig
/// versions this project builds on do not agree on enum reflection.
pub const COUNT: usize = 4;

/// Where one kind sits in the deadline array.
///
/// Note:
/// - An exhaustive switch, so adding a Kind without giving it a slot fails to compile rather than
///   silently sharing a slot with another.
fn slotOf(kind: Kind) usize {
    return switch (kind) {
        .DTLS_RETRANSMIT => 0,
        .SCTP_RETRANSMIT => 1,
        .ICE_CONSENT => 2,
        .IDLE => 3,
    };
}

/// The deadlines one peer runs on.
///
/// Usage:
/// ```zig
/// var deadlines: Deadlines = .{};
/// deadlines.armIn(.DTLS_RETRANSMIT, now_ms, 1000);
///
/// while (deadlines.takeExpired(now_ms)) |kind| switch (kind) {
///     .DTLS_RETRANSMIT => resendFlight(),
///     else => {},
/// };
/// ```
pub const Deadlines = struct {
    at_ms: [COUNT]?u64 = @splat(null),

    /// Arm a deadline at an absolute monotonic millisecond, replacing whatever it held.
    ///
    /// Param:
    /// kind - Kind
    /// at_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    pub fn arm(self: *Deadlines, kind: Kind, at_ms: u64) void {
        self.at_ms[slotOf(kind)] = at_ms;
    }

    /// Arm a deadline a delay away from now.
    ///
    /// Param:
    /// kind - Kind
    /// now_ms - u64 (monotonic milliseconds)
    /// delay_ms - u64
    ///
    /// Return:
    /// - void
    pub fn armIn(self: *Deadlines, kind: Kind, now_ms: u64, delay_ms: u64) void {
        self.arm(kind, now_ms +| delay_ms);
    }

    /// Stop a deadline. Harmless when it was not armed.
    pub fn disarm(self: *Deadlines, kind: Kind) void {
        self.at_ms[slotOf(kind)] = null;
    }

    /// Stop every deadline.
    pub fn disarmAll(self: *Deadlines) void {
        self.at_ms = @splat(null);
    }

    /// When a deadline is set for, or null when it is not armed.
    pub fn deadline(self: Deadlines, kind: Kind) ?u64 {
        return self.at_ms[slotOf(kind)];
    }

    /// Whether a deadline is armed, whether or not it has passed.
    pub fn isArmed(self: Deadlines, kind: Kind) bool {
        return self.at_ms[slotOf(kind)] != null;
    }

    /// Whether a deadline is armed and its time has come.
    pub fn expired(self: Deadlines, kind: Kind, now_ms: u64) bool {
        const at = self.at_ms[slotOf(kind)] orelse return false;

        return now_ms >= at;
    }

    /// The soonest armed deadline, or null when nothing is armed.
    pub fn earliest(self: Deadlines) ?u64 {
        var soonest: ?u64 = null;

        for (self.at_ms) |slot| {
            const at = slot orelse continue;

            if (soonest == null or at < soonest.?) soonest = at;
        }

        return soonest;
    }

    /// Take the next deadline that has passed, disarming it.
    ///
    /// Note:
    /// - Ties break on slot order, which puts the DTLS retransmit ahead of the rest. A handshake
    ///   that has not finished is the only thing the others depend on.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?Kind (null when nothing has passed)
    pub fn takeExpired(self: *Deadlines, now_ms: u64) ?Kind {
        inline for (.{ Kind.DTLS_RETRANSMIT, .SCTP_RETRANSMIT, .ICE_CONSENT, .IDLE }) |kind| {
            if (self.expired(kind, now_ms)) {
                self.disarm(kind);

                return kind;
            }
        }

        return null;
    }

    /// How long a loop may wait before it has to look again.
    ///
    /// Note:
    /// - Zero when a deadline has already passed, so a caller that polls with this never sleeps
    ///   through work that is due.
    /// - The ceiling is what a caller waits when nothing at all is armed. A loop with no ceiling
    ///   would park on an idle socket and never notice a peer it should have dropped.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    /// ceiling_ms - u32 (longest wait the caller accepts)
    ///
    /// Return:
    /// - u32 (milliseconds to wait)
    pub fn waitMs(self: Deadlines, now_ms: u64, ceiling_ms: u32) u32 {
        const soonest = self.earliest() orelse return ceiling_ms;

        if (soonest <= now_ms) return 0;

        const remaining: u64 = soonest - now_ms;

        return @intCast(@min(remaining, @as(u64, ceiling_ms)));
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix webrtc: timer, a fresh set is armed for nothing" {
    var deadlines: Deadlines = .{};

    try std.testing.expect(!deadlines.isArmed(.DTLS_RETRANSMIT));
    try std.testing.expect(!deadlines.isArmed(.IDLE));
    try std.testing.expectEqual(@as(?u64, null), deadlines.earliest());
    try std.testing.expectEqual(@as(?Kind, null), deadlines.takeExpired(1_000_000));
}

test "zix webrtc: timer, every kind gets its own slot" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.DTLS_RETRANSMIT, 10);
    deadlines.arm(.SCTP_RETRANSMIT, 20);
    deadlines.arm(.ICE_CONSENT, 40);
    deadlines.arm(.IDLE, 50);

    try std.testing.expectEqual(@as(?u64, 10), deadlines.deadline(.DTLS_RETRANSMIT));
    try std.testing.expectEqual(@as(?u64, 20), deadlines.deadline(.SCTP_RETRANSMIT));
    try std.testing.expectEqual(@as(?u64, 40), deadlines.deadline(.ICE_CONSENT));
    try std.testing.expectEqual(@as(?u64, 50), deadlines.deadline(.IDLE));
}

test "zix webrtc: timer, armIn adds the delay to now" {
    var deadlines: Deadlines = .{};

    deadlines.armIn(.ICE_CONSENT, 5_000, 30_000);

    try std.testing.expectEqual(@as(?u64, 35_000), deadlines.deadline(.ICE_CONSENT));
}

test "zix webrtc: timer, armIn saturates instead of wrapping" {
    var deadlines: Deadlines = .{};

    deadlines.armIn(.IDLE, std.math.maxInt(u64) - 1, 1000);

    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), deadlines.deadline(.IDLE));
}

test "zix webrtc: timer, earliest reports the soonest of several" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.IDLE, 900);
    deadlines.arm(.DTLS_RETRANSMIT, 300);
    deadlines.arm(.SCTP_RETRANSMIT, 600);

    try std.testing.expectEqual(@as(?u64, 300), deadlines.earliest());

    deadlines.disarm(.DTLS_RETRANSMIT);
    try std.testing.expectEqual(@as(?u64, 600), deadlines.earliest());
}

test "zix webrtc: timer, expired only reports an armed deadline that has passed" {
    var deadlines: Deadlines = .{};

    try std.testing.expect(!deadlines.expired(.SCTP_RETRANSMIT, 999_999));

    deadlines.arm(.SCTP_RETRANSMIT, 500);
    try std.testing.expect(!deadlines.expired(.SCTP_RETRANSMIT, 499));
    try std.testing.expect(deadlines.expired(.SCTP_RETRANSMIT, 500));
    try std.testing.expect(deadlines.expired(.SCTP_RETRANSMIT, 501));
}

test "zix webrtc: timer, takeExpired disarms what it hands back" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.SCTP_RETRANSMIT, 100);

    try std.testing.expectEqual(@as(?Kind, .SCTP_RETRANSMIT), deadlines.takeExpired(150));
    try std.testing.expect(!deadlines.isArmed(.SCTP_RETRANSMIT));
    try std.testing.expectEqual(@as(?Kind, null), deadlines.takeExpired(150));
}

test "zix webrtc: timer, takeExpired drains several in one pass" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.DTLS_RETRANSMIT, 10);
    deadlines.arm(.ICE_CONSENT, 20);
    deadlines.arm(.IDLE, 5000);

    var seen: usize = 0;
    while (deadlines.takeExpired(100)) |_| seen += 1;

    try std.testing.expectEqual(@as(usize, 2), seen);
    try std.testing.expect(deadlines.isArmed(.IDLE));
}

test "zix webrtc: timer, a handshake retransmit is taken before anything else due at the same time" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.IDLE, 100);
    deadlines.arm(.SCTP_RETRANSMIT, 100);
    deadlines.arm(.DTLS_RETRANSMIT, 100);

    try std.testing.expectEqual(@as(?Kind, .DTLS_RETRANSMIT), deadlines.takeExpired(100));
}

test "zix webrtc: timer, waitMs falls back to the ceiling when nothing is armed" {
    const deadlines: Deadlines = .{};

    try std.testing.expectEqual(@as(u32, 250), deadlines.waitMs(1000, 250));
}

test "zix webrtc: timer, waitMs is zero for a deadline already passed" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.DTLS_RETRANSMIT, 400);

    try std.testing.expectEqual(@as(u32, 0), deadlines.waitMs(400, 250));
    try std.testing.expectEqual(@as(u32, 0), deadlines.waitMs(900, 250));
}

test "zix webrtc: timer, waitMs never returns more than the ceiling" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.IDLE, 30_000);

    try std.testing.expectEqual(@as(u32, 250), deadlines.waitMs(0, 250));
    try std.testing.expectEqual(@as(u32, 100), deadlines.waitMs(29_900, 250));
}

test "zix webrtc: timer, disarmAll clears every slot" {
    var deadlines: Deadlines = .{};

    deadlines.arm(.DTLS_RETRANSMIT, 1);
    deadlines.arm(.SCTP_RETRANSMIT, 2);
    deadlines.arm(.ICE_CONSENT, 4);
    deadlines.arm(.IDLE, 5);

    deadlines.disarmAll();

    try std.testing.expectEqual(@as(?u64, null), deadlines.earliest());
}

test "zix webrtc: timer, every kind has a distinct slot below the count" {
    const kinds = [_]Kind{ .DTLS_RETRANSMIT, .SCTP_RETRANSMIT, .ICE_CONSENT, .IDLE };
    try std.testing.expectEqual(COUNT, kinds.len);

    var seen: [COUNT]bool = @splat(false);
    for (kinds) |kind| {
        const slot = slotOf(kind);

        try std.testing.expect(slot < COUNT);
        try std.testing.expect(!seen[slot]);
        seen[slot] = true;
    }
}
