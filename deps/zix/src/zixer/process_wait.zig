//! zixer process gate wait: how a task-per-connection edge waits out a ticket

const std = @import("std");
const zix = @import("zix");

const process_gate = @import("process_gate.zig");

const monotonic_clock = zix.utils.monotonic_clock;

/// How often a queued request looks at its ticket. The grpc and h3 relays
/// already wait on this tick, so a queued request wakes on the cadence the
/// rest of the edge runs on.
const POLL_MS: u64 = 1;

/// How a request's attempt to enter the gate ended.
pub const Outcome = enum {
    /// The caller holds a process slot and owes a release.
    ADMITTED,
    /// The limit was reached and the waiting room was full.
    REFUSED,
    /// The caller waited its whole budget without a slot coming free.
    EXPIRED,

    /// Status text for the 504 the two failures answer with.
    pub fn reason(outcome: Outcome) []const u8 {
        return switch (outcome) {
            .ADMITTED => "admitted",
            .REFUSED => "upstream queue full",
            .EXPIRED => "upstream queue timeout",
        };
    }
};

/// The rfc 9209 proxy-error both failures carry: the site hit the limit it
/// was configured with, which is the same cause whether the request was
/// refused outright or waited the budget out.
pub const PROXY_ERROR: []const u8 = "connection_limit_reached";

/// A held process slot that hands itself back exactly once.
///
/// Note:
/// - Exists for the legs that must not hold a slot for the whole exchange.
///   A websocket tunnel and a grpc stream live as long as their client, so
///   they release at handover and let the next request in. Everything else
///   just lets the deferred release run.
pub const Held = struct {
    gate: ?*process_gate.Gate,
    live: bool,

    /// Give the slot back. Calling it twice is safe and does nothing the
    /// second time, which is what lets an early release and a deferred one
    /// sit in the same function.
    pub fn release(held: *Held) void {
        if (!held.live) return;

        held.live = false;
        if (held.gate) |gate| gate.leave();
    }
};

/// Enter the site's gate, waiting out a place in line if it hands one.
///
/// Note:
/// - Only the caller's own task sleeps while it waits. Every zixer edge
///   serves one connection per task, so nothing else on the worker stalls.
/// - A readiness or completion loop must not call this: one thread drives
///   many connections there, so it checks its tickets from its own ready
///   pass instead. The gate never blocks, which is what lets both work off
///   the same structure.
/// - A null gate is a site that configured no limit, admitted at once.
///
/// Param:
/// gate - ?*process_gate.Gate (the site's gate, null when it has none)
/// io - std.Io
///
/// Return:
/// - ADMITTED, pair it with hold() and release the slot when done
/// - REFUSED or EXPIRED, answer 504 and hold nothing
pub fn admit(gate: ?*process_gate.Gate, io: std.Io) Outcome {
    const site_gate = gate orelse return .ADMITTED;

    return switch (site_gate.enter()) {
        .ADMITTED => .ADMITTED,
        .QUEUED => |ticket| waitTicket(site_gate, ticket, io),
        .REFUSED => .REFUSED,
    };
}

/// Enter the site's gate without ever waiting, shedding instead of parking.
///
/// Note:
/// - For a caller whose thread drives other streams that are already
///   running. The grpc relay is the one in zixer: its frame loop pumps
///   every live stream on the connection, so parking it to wait for a slot
///   would stall work that was already admitted. Shedding a new stream
///   there is the honest answer, and a grpc client retries on it.
/// - The waiting room is still honoured in the sense that it is never
///   entered: a caller here occupies no place in line.
///
/// Param:
/// gate - ?*process_gate.Gate (the site's gate, null when it has none)
///
/// Return:
/// - ADMITTED, pair it with hold() and release the slot when done
/// - REFUSED, answer the caller's own overload status
pub fn admitNow(gate: ?*process_gate.Gate) Outcome {
    const site_gate = gate orelse return .ADMITTED;

    return switch (site_gate.enter()) {
        .ADMITTED => .ADMITTED,
        .QUEUED => |ticket| blk: {
            site_gate.abandon(ticket);

            break :blk .REFUSED;
        },
        .REFUSED => .REFUSED,
    };
}

/// Wait out one queued ticket until it is admitted or its budget runs out.
///
/// Param:
/// gate - *process_gate.Gate (the gate the ticket came from)
/// ticket - process_gate.Ticket (what enter handed back)
/// io - std.Io
///
/// Return:
/// - ADMITTED, the caller holds a process slot now
/// - EXPIRED, the gate already took the place in line back
pub fn waitTicket(gate: *process_gate.Gate, ticket: process_gate.Ticket, io: std.Io) Outcome {
    const deadline_ms = monotonic_clock.nowMs(io) + gate.settings.timeout_ms;

    while (true) {
        if (gate.poll(ticket) == .ADMITTED) return .ADMITTED;

        // Checked after the poll so a budget that already elapsed still
        // takes a slot that arrived in the meantime.
        if (monotonic_clock.nowMs(io) >= deadline_ms) {
            gate.abandon(ticket);

            return .EXPIRED;
        }

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(POLL_MS), .awake) catch {
            gate.abandon(ticket);

            return .EXPIRED;
        };
    }
}

/// Wrap an admitted slot so it can be released early or on the way out.
pub fn hold(gate: ?*process_gate.Gate) Held {
    return .{ .gate = gate, .live = true };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: process wait, a site with no gate is admitted at once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    try std.testing.expectEqual(Outcome.ADMITTED, admit(null, threaded.io()));
}

test "zix zixer: process wait, an unarmed gate is admitted at once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var gate = try process_gate.Gate.init(std.testing.allocator, .{});
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, threaded.io()));
}

test "zix zixer: process wait, a free slot admits without waiting" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 2, .queue_len = 2, .timeout_ms = 50 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, threaded.io()));
    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, threaded.io()));
    try std.testing.expectEqual(@as(usize, 2), gate.inFlight());
}

test "zix zixer: process wait, a full waiting room is refused not delayed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 0, .timeout_ms = 30_000 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, threaded.io()));

    // No room at all, so this must come back now rather than sit out the
    // 30 second budget.
    const began_ms = monotonic_clock.nowMs(threaded.io());
    try std.testing.expectEqual(Outcome.REFUSED, admit(&gate, threaded.io()));

    try std.testing.expect(monotonic_clock.nowMs(threaded.io()) - began_ms < 1000);
}

test "zix zixer: process wait, a budget that runs out answers expired" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 1, .timeout_ms = 30 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, threaded.io()));
    try std.testing.expectEqual(Outcome.EXPIRED, admit(&gate, threaded.io()));

    // The place in line went back, so the next arrival can take it.
    try std.testing.expectEqual(@as(usize, 0), gate.waitingCount());
    try std.testing.expectEqual(Outcome.EXPIRED, admit(&gate, threaded.io()));
}

test "zix zixer: process wait, a slot freed mid-wait admits the waiter" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 1, .timeout_ms = 5000 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, io));

    const Runner = struct {
        fn leaveAfter(shared: *process_gate.Gate, runner_io: std.Io) void {
            std.Io.sleep(runner_io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
            shared.leave();
        }
    };

    const thread = try std.Thread.spawn(.{}, Runner.leaveAfter, .{ &gate, io });
    defer thread.join();

    // The runner is still holding the only slot, so this parks until the
    // spawned leave hands it over.
    try std.testing.expectEqual(Outcome.ADMITTED, admit(&gate, io));
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());
}

test "zix zixer: process wait, a held slot releases exactly once" {
    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 2, .queue_len = 1 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(process_gate.Admission.ADMITTED, gate.enter());
    try std.testing.expectEqual(process_gate.Admission.ADMITTED, gate.enter());

    var slot = hold(&gate);
    slot.release();
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());

    // The second release is the deferred one after an early handover, and
    // must not give back a slot this request no longer holds.
    slot.release();
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());
}

test "zix zixer: process wait, a held slot on a site with no gate is inert" {
    var slot = hold(null);

    slot.release();
    slot.release();

    try std.testing.expect(!slot.live);
}

test "zix zixer: process wait, admit now sheds instead of taking a place in line" {
    var gate = try process_gate.Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 4, .timeout_ms = 30_000 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Outcome.ADMITTED, admitNow(&gate));

    // Room to spare, and it is still refused rather than queued: this
    // caller cannot park without stalling streams already running.
    try std.testing.expectEqual(Outcome.REFUSED, admitNow(&gate));
    try std.testing.expectEqual(@as(usize, 0), gate.waitingCount());
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());
}

test "zix zixer: process wait, admit now on a site with no gate is admitted" {
    try std.testing.expectEqual(Outcome.ADMITTED, admitNow(null));
}

test "zix zixer: process wait, each outcome names itself" {
    try std.testing.expectEqualStrings("upstream queue full", Outcome.REFUSED.reason());
    try std.testing.expectEqualStrings("upstream queue timeout", Outcome.EXPIRED.reason());
}
