//! DTLS handshake retransmission (RFC 6347 4.2.4 and 4.2.4.1).
//!
//! What:
//! - The reason a DTLS handshake completes at all over a lossy datagram transport. Nothing below
//!   DTLS retransmits, so the handshake carries its own timer and resends whole flights.
//! - Two pieces: `Timer` holds the backoff policy, `Flight` holds the four-state machine that
//!   decides when the timer is even running.
//!
//! Note:
//! - Time comes in as a parameter, never from a clock inside. That keeps a retransmission
//!   schedule testable in microseconds instead of minutes, and leaves the choice of clock to the
//!   engine that owns the loop.
//! - Flights are retransmitted whole, never message by message (RFC 6347 4.2.4). A peer that
//!   lost one message of a flight is answered with all of it.
//! - The peer resending a flight already processed means ITS timer fired, so part of our last
//!   flight was lost. Resending immediately is faster than waiting for our own timer.
//! - A side that sent the last flight must keep answering retransmissions of the peer's last
//!   flight even after FINISHED (RFC 6347 4.2.4). Without that, a lost final Finished deadlocks
//!   a handshake both sides think is nearly done.

const std = @import("std");

/// First retransmission delay (RFC 6347 4.2.4.1). One second, the RFC 6298 minimum, chosen over
/// the RFC 6298 default of three because a handshake is latency-sensitive.
pub const INITIAL_TIMEOUT_MS: u64 = 1000;

/// Ceiling on the doubling (RFC 6347 4.2.4.1, the RFC 6298 maximum).
pub const MAX_TIMEOUT_MS: u64 = 60000;

/// Retransmissions before a handshake is declared dead.
///
/// Note:
/// - RFC 6347 sets no limit, so this is a zix choice: 6 retransmissions is 1 + 2 + 4 + 8 + 16 +
///   32, about 63 seconds of trying, past which a peer is not coming back.
pub const DEFAULT_MAX_RETRANSMITS: usize = 6;

/// Handshake transmission state (RFC 6347 4.2.4).
pub const State = enum {
    /// Building the next flight.
    PREPARING,
    /// The flight is buffered and going out.
    SENDING,
    /// The flight is out, waiting on the peer with a timer running.
    WAITING,
    /// The handshake is done. The last flight is still kept for retransmission.
    FINISHED,
};

/// What a fired timer means for the caller.
pub const TimeoutAction = enum {
    /// Send the buffered flight again.
    RETRANSMIT,
    /// Stop. The peer has had DEFAULT_MAX_RETRANSMITS chances.
    GIVE_UP,
};

/// Exponential backoff for one handshake (RFC 6347 4.2.4.1).
pub const Timer = struct {
    /// Current delay. Doubles on every expiry, capped at MAX_TIMEOUT_MS.
    timeout_ms: u64 = INITIAL_TIMEOUT_MS,
    /// When the current wait ends, or null when no flight is outstanding.
    deadline_ms: ?u64 = null,

    /// Start waiting, at the current delay.
    pub fn arm(self: *Timer, now_ms: u64) void {
        self.deadline_ms = now_ms + self.timeout_ms;
    }

    /// Stop waiting without changing the delay.
    pub fn disarm(self: *Timer) void {
        self.deadline_ms = null;
    }

    /// Whether the wait is over. False when nothing is armed.
    pub fn expired(self: *const Timer, now_ms: u64) bool {
        const deadline = self.deadline_ms orelse return false;

        return now_ms >= deadline;
    }

    /// Double the delay for the next attempt, up to the ceiling.
    pub fn backoff(self: *Timer) void {
        self.timeout_ms = @min(self.timeout_ms * 2, MAX_TIMEOUT_MS);
    }

    /// Back to the initial delay, disarmed. Called when a flight gets through, since the current
    /// delay is evidence about a loss that is no longer happening (RFC 6347 4.2.4.1).
    pub fn reset(self: *Timer) void {
        self.timeout_ms = INITIAL_TIMEOUT_MS;
        self.deadline_ms = null;
    }
};

/// The RFC 6347 4.2.4 timeout and retransmission state machine.
///
/// Note:
/// - A client starts in PREPARING because it sends first. A server starts in WAITING with no
///   timer, because it has nothing outstanding until a ClientHello arrives.
///
/// Usage:
/// ```zig
/// var flight = Flight.initServer();
///
/// // A flight is ready to go out.
/// flight.sending();
/// try sendFlight();
/// flight.sent(now_ms, true);
///
/// // Later, on every tick of the engine loop.
/// if (flight.onTick(now_ms)) |action| switch (action) {
///     .RETRANSMIT => {
///         try sendFlight();
///         flight.sent(now_ms, true);
///     },
///     .GIVE_UP => dropAssociation(),
/// };
/// ```
pub const Flight = struct {
    state: State,
    timer: Timer = .{},
    /// Retransmissions of the current flight so far.
    retransmits: usize = 0,
    max_retransmits: usize = DEFAULT_MAX_RETRANSMITS,

    /// A client sends first, so it starts by building a flight.
    pub fn initClient() Flight {
        return .{ .state = .PREPARING };
    }

    /// A server waits first, with nothing outstanding and no timer running.
    pub fn initServer() Flight {
        return .{ .state = .WAITING };
    }

    /// The next flight is buffered and about to be written to the wire.
    pub fn sending(self: *Flight) void {
        self.state = .SENDING;
    }

    /// The flight is on the wire.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds, the caller's clock)
    /// more_expected - bool (false when this was the last flight of the handshake)
    pub fn sent(self: *Flight, now_ms: u64, more_expected: bool) void {
        if (!more_expected) {
            self.state = .FINISHED;
            self.timer.disarm();

            return;
        }

        self.state = .WAITING;
        self.timer.arm(now_ms);
    }

    /// Check the retransmission deadline.
    ///
    /// Note:
    /// - Returns null unless a flight is outstanding and its deadline has passed, so it is cheap
    ///   to call on every loop tick.
    /// - GIVE_UP does not change state, it stays true on every later call. The caller is
    ///   expected to tear the association down on the first one.
    ///
    /// Return:
    /// - TimeoutAction when the timer fired
    /// - null while there is still time, or when nothing is outstanding
    pub fn onTick(self: *Flight, now_ms: u64) ?TimeoutAction {
        if (self.state != .WAITING) return null;
        if (!self.timer.expired(now_ms)) return null;
        if (self.retransmits >= self.max_retransmits) return .GIVE_UP;

        self.retransmits += 1;
        self.timer.backoff();
        self.state = .SENDING;

        return .RETRANSMIT;
    }

    /// The peer resent a flight already processed, which means part of ours was lost.
    ///
    /// Note:
    /// - Applies in FINISHED too. The side that sent the last flight owes a retransmission for
    ///   as long as it keeps the association, or a lost final flight deadlocks both ends.
    ///
    /// Return:
    /// - true when the caller should send its buffered flight again
    pub fn onPeerRetransmit(self: *Flight) bool {
        switch (self.state) {
            .WAITING, .FINISHED => {
                self.state = .SENDING;

                return true;
            },
            .PREPARING, .SENDING => return false,
        }
    }

    /// A complete new flight arrived from the peer.
    ///
    /// Note:
    /// - This is the only progress signal, so it is where the backoff resets. Getting a flight
    ///   through means the loss that grew the delay has passed (RFC 6347 4.2.4.1).
    ///
    /// Param:
    /// final - bool (true when that flight ends the handshake)
    pub fn onPeerFlight(self: *Flight, final: bool) void {
        self.retransmits = 0;
        self.timer.reset();
        self.state = if (final) .FINISHED else .PREPARING;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix dtls: flight timer, the delay doubles to the ceiling and stays there" {
    var timer: Timer = .{};
    const expected = [_]u64{ 1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000 };

    try std.testing.expectEqual(expected[0], timer.timeout_ms);

    for (expected[1..]) |delay| {
        timer.backoff();
        try std.testing.expectEqual(delay, timer.timeout_ms);
    }
}

test "zix dtls: flight timer, expiry is on the deadline, not before" {
    var timer: Timer = .{};

    // Nothing armed means nothing can fire.
    try std.testing.expect(!timer.expired(0));
    try std.testing.expect(!timer.expired(999999));

    timer.arm(5000);
    try std.testing.expect(!timer.expired(5000));
    try std.testing.expect(!timer.expired(5999));
    try std.testing.expect(timer.expired(6000));
    try std.testing.expect(timer.expired(9000));

    timer.disarm();
    try std.testing.expect(!timer.expired(9000));

    // Disarming leaves the delay alone, resetting puts it back.
    try std.testing.expectEqual(@as(u64, 1000), timer.timeout_ms);
    timer.backoff();
    timer.reset();
    try std.testing.expectEqual(@as(u64, 1000), timer.timeout_ms);
    try std.testing.expectEqual(@as(?u64, null), timer.deadline_ms);
}

test "zix dtls: flight state, a client starts preparing and a server starts waiting" {
    const client = Flight.initClient();
    try std.testing.expectEqual(State.PREPARING, client.state);

    var server = Flight.initServer();
    try std.testing.expectEqual(State.WAITING, server.state);

    // A server has nothing outstanding, so its timer cannot fire before it sends anything.
    try std.testing.expectEqual(@as(?TimeoutAction, null), server.onTick(0));
    try std.testing.expectEqual(@as(?TimeoutAction, null), server.onTick(1_000_000));
}

test "zix dtls: flight state, an unanswered flight retransmits on the growing delay" {
    var flight = Flight.initClient();

    flight.sending();
    flight.sent(0, true);
    try std.testing.expectEqual(State.WAITING, flight.state);

    // Nothing fires before the first deadline.
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(999));

    try std.testing.expectEqual(TimeoutAction.RETRANSMIT, flight.onTick(1000).?);
    try std.testing.expectEqual(State.SENDING, flight.state);
    try std.testing.expectEqual(@as(usize, 1), flight.retransmits);

    // The caller resends, and the next wait is twice as long.
    flight.sent(1000, true);
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(2999));
    try std.testing.expectEqual(TimeoutAction.RETRANSMIT, flight.onTick(3000).?);

    flight.sent(3000, true);
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(6999));
    try std.testing.expectEqual(TimeoutAction.RETRANSMIT, flight.onTick(7000).?);
}

test "zix dtls: flight state, a dead peer is given up on" {
    var flight = Flight.initClient();
    flight.sending();
    flight.sent(0, true);

    var now: u64 = 0;
    var attempts: usize = 0;

    while (attempts < DEFAULT_MAX_RETRANSMITS) : (attempts += 1) {
        now += flight.timer.timeout_ms;
        try std.testing.expectEqual(TimeoutAction.RETRANSMIT, flight.onTick(now).?);
        flight.sent(now, true);
    }

    now += flight.timer.timeout_ms;
    try std.testing.expectEqual(TimeoutAction.GIVE_UP, flight.onTick(now).?);

    // GIVE_UP keeps saying give up, it is not a one-shot the caller can miss.
    try std.testing.expectEqual(TimeoutAction.GIVE_UP, flight.onTick(now + 1).?);
    try std.testing.expectEqual(@as(usize, DEFAULT_MAX_RETRANSMITS), flight.retransmits);
}

test "zix dtls: flight state, a flight from the peer resets the backoff" {
    var flight = Flight.initClient();
    flight.sending();
    flight.sent(0, true);

    // Two losses grow the delay.
    _ = flight.onTick(1000);
    flight.sent(1000, true);
    _ = flight.onTick(3000);
    flight.sent(3000, true);
    try std.testing.expectEqual(@as(u64, 4000), flight.timer.timeout_ms);
    try std.testing.expectEqual(@as(usize, 2), flight.retransmits);

    // The peer answers, so the loss is over.
    flight.onPeerFlight(false);
    try std.testing.expectEqual(State.PREPARING, flight.state);
    try std.testing.expectEqual(@as(u64, INITIAL_TIMEOUT_MS), flight.timer.timeout_ms);
    try std.testing.expectEqual(@as(usize, 0), flight.retransmits);

    // And the next flight waits the initial delay again.
    flight.sending();
    flight.sent(3000, true);
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(3999));
    try std.testing.expectEqual(TimeoutAction.RETRANSMIT, flight.onTick(4000).?);
}

test "zix dtls: flight state, a peer retransmission triggers an immediate resend" {
    var flight = Flight.initClient();
    flight.sending();
    flight.sent(0, true);

    // Well before our own timer would fire.
    try std.testing.expect(flight.onPeerRetransmit());
    try std.testing.expectEqual(State.SENDING, flight.state);

    // It is not counted as one of our retransmissions, since our timer never fired.
    try std.testing.expectEqual(@as(usize, 0), flight.retransmits);
    try std.testing.expectEqual(@as(u64, INITIAL_TIMEOUT_MS), flight.timer.timeout_ms);
}

test "zix dtls: flight state, the last flight is still resent after finishing" {
    var flight = Flight.initServer();

    flight.onPeerFlight(false);
    flight.sending();
    flight.sent(0, false);

    try std.testing.expectEqual(State.FINISHED, flight.state);
    try std.testing.expectEqual(@as(?u64, null), flight.timer.deadline_ms);

    // No timer runs in FINISHED, so nothing fires on its own.
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(1_000_000));

    // But a peer still asking means our last flight was lost, and it has to go again.
    try std.testing.expect(flight.onPeerRetransmit());
    try std.testing.expectEqual(State.SENDING, flight.state);

    flight.sent(1000, false);
    try std.testing.expectEqual(State.FINISHED, flight.state);
}

test "zix dtls: flight state, a resend request while building or sending is ignored" {
    var flight = Flight.initClient();
    try std.testing.expectEqual(State.PREPARING, flight.state);
    try std.testing.expect(!flight.onPeerRetransmit());

    flight.sending();
    try std.testing.expect(!flight.onPeerRetransmit());
    try std.testing.expectEqual(State.SENDING, flight.state);

    // Nothing is outstanding in either state, so no timer runs.
    try std.testing.expectEqual(@as(?TimeoutAction, null), flight.onTick(1_000_000));
}

test "zix dtls: flight state, a full handshake walks the states in order" {
    var client = Flight.initClient();

    // Flight 1: ClientHello.
    client.sending();
    client.sent(0, true);
    try std.testing.expectEqual(State.WAITING, client.state);

    // Flight 2 arrives (HelloVerifyRequest), so flight 3 gets built.
    client.onPeerFlight(false);
    try std.testing.expectEqual(State.PREPARING, client.state);

    // Flight 3: ClientHello with cookie.
    client.sending();
    client.sent(100, true);

    // Flight 4 arrives (ServerHello through ServerHelloDone).
    client.onPeerFlight(false);

    // Flight 5: the client's last, but the server still owes a Finished.
    client.sending();
    client.sent(200, true);
    try std.testing.expectEqual(State.WAITING, client.state);

    // Flight 6 arrives and ends the handshake.
    client.onPeerFlight(true);
    try std.testing.expectEqual(State.FINISHED, client.state);
    try std.testing.expectEqual(@as(?TimeoutAction, null), client.onTick(1_000_000));
}
