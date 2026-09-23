//! zixer process gate: how many requests a site may have running upstream

const std = @import("std");

/// Largest limit or waiting room a site may configure. The room is
/// allocated once at site start, so this is what bounds that allocation.
pub const MAX_SLOTS: usize = 65_536;

/// How long a queued request waits when nothing names a value.
pub const DEFAULT_TIMEOUT_MS: u32 = 6000;

/// Longest wait a site may configure. Past ten minutes no client is still
/// listening, so the answer would go nowhere.
pub const MAX_TIMEOUT_MS: u32 = 600_000;

/// Empty-list marker for the intrusive links below. A real index can never
/// reach it: MAX_SLOTS bounds the array far under this.
const NIL: u32 = std.math.maxInt(u32);

/// The three values one site runs the gate with, already resolved from the
/// site file and the main.cfg defaults.
pub const Settings = struct {
    /// Requests that may be running upstream at once, across every worker.
    /// 0 is the gate off, which is what a site that never asked for one gets.
    limit: usize = 0,
    /// Requests that may wait for a slot. 0 means refuse the moment the
    /// limit is reached, which is a valid choice: shed instead of queue.
    queue_len: usize = 0,
    /// How long one request may wait before the edge answers 504.
    timeout_ms: u32 = DEFAULT_TIMEOUT_MS,

    /// Whether the gate does anything at all.
    pub fn armed(settings: Settings) bool {
        return settings.limit > 0;
    }
};

/// Whether a configured limit is one a site may run.
///
/// Note:
/// - 0 is valid and means off, so only the ceiling is checked here.
pub fn limitInRange(limit: usize) bool {
    return limit <= MAX_SLOTS;
}

/// Whether a configured waiting room is one a site may run. 0 is valid and
/// means no room, so again only the ceiling is checked.
pub fn queueLenInRange(queue_len: usize) bool {
    return queue_len <= MAX_SLOTS;
}

/// Whether a configured wait is one a site may run. Zero is refused: a
/// waiting room nobody may wait in is the same as no room, and writing 0
/// here almost always means the room was meant to be 0 instead.
pub fn timeoutInRange(timeout_ms: u32) bool {
    return timeout_ms >= 1 and timeout_ms <= MAX_TIMEOUT_MS;
}

/// The site file's values over the daemon defaults, each null falling back.
///
/// Note:
/// - Every input already passed validation, so none can be out of range.
///   Clamping anyway keeps a caller that skipped validation (a test rig, a
///   future caller) inside what the gate can hold.
///
/// Param:
/// site_limit - ?usize (the site file value, null when it names none)
/// site_queue_len - ?usize (same)
/// site_timeout_ms - ?u32 (same)
/// daemon - Settings (the main.cfg values)
///
/// Return:
/// - Settings with every field inside its range
pub fn resolve(site_limit: ?usize, site_queue_len: ?usize, site_timeout_ms: ?u32, daemon: Settings) Settings {
    return .{
        .limit = @min(site_limit orelse daemon.limit, MAX_SLOTS),
        .queue_len = @min(site_queue_len orelse daemon.queue_len, MAX_SLOTS),
        .timeout_ms = std.math.clamp(site_timeout_ms orelse daemon.timeout_ms, 1, MAX_TIMEOUT_MS),
    };
}

/// Where one waiting-room slot stands.
const SlotState = enum(u8) {
    /// Nobody holds it, it sits on the free list.
    FREE,
    /// A request holds it and is still in line.
    WAITING,
    /// A leaving request handed its process slot to this waiter, who has
    /// not picked it up yet.
    ADMITTED,
};

/// One waiting-room slot. next threads the free list, next and prev
/// together thread the arrival-ordered wait list, so taking a slot, handing
/// one on, and giving one up are each constant time. That matters because
/// every one of them runs under the gate's spinlock.
const Slot = struct {
    state: SlotState = .FREE,
    next: u32 = NIL,
    prev: u32 = NIL,
};

/// A waiting request's claim on a waiting-room slot.
///
/// Note:
/// - Valid until poll reports ADMITTED once, or abandon is called. Past
///   that the slot belongs to whoever took it next, so a stale ticket must
///   not be polled again.
pub const Ticket = struct {
    index: u32,
};

/// What entering the gate gave the caller.
pub const Admission = union(enum) {
    /// The caller holds a process slot and owes leave().
    ADMITTED,
    /// The site is at its limit. The caller waits on this ticket.
    QUEUED: Ticket,
    /// The limit is reached and the waiting room is full.
    REFUSED,
};

/// Where a queued ticket stands right now.
pub const Wait = enum {
    /// Still in line.
    WAITING,
    /// The process slot is the caller's, and leave() owes it back.
    ADMITTED,
};

/// One site's admission gate, shared by every worker on that site.
///
/// Note:
/// - Site-wide on purpose. A per-worker split makes the configured number
///   mean a different thing on every box, because workers follows the
///   thread count, and a storm valve is sized to what the backend absorbs.
/// - Nothing here ever blocks. A request that cannot proceed is handed a
///   ticket and the caller decides how to wait, which is what lets one
///   gate serve a task-per-connection loop and a single-threaded readiness
///   or completion loop alike.
/// - A short spinlock guards the whole structure. Every operation is a few
///   pointer writes, and the measured cost of the shared counter is far
///   under what one proxied request spends.
pub const Gate = struct {
    settings: Settings,
    slots: []Slot,
    lock_flag: std.atomic.Value(bool) = .init(false),
    in_flight: usize = 0,
    free_head: u32 = NIL,
    wait_head: u32 = NIL,
    wait_tail: u32 = NIL,
    waiting: usize = 0,

    /// A gate that admits everything and owns nothing, for a site that
    /// configured no limit. deinit on it frees an empty slice, which is legal.
    pub const off: Gate = .{ .settings = .{}, .slots = &.{} };

    /// Build one site's gate.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the waiting room, outlives the site)
    /// settings - Settings (already resolved)
    ///
    /// Return:
    /// - Gate, off when settings name no limit
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, settings: Settings) !Gate {
        if (!settings.armed()) return off;

        const room = @min(settings.queue_len, MAX_SLOTS);
        const slots = try allocator.alloc(Slot, room);

        // Threaded back to front so index 0 is handed out first, which
        // keeps a slot dump in the order a reader expects.
        var free_head: u32 = NIL;
        var index = room;
        while (index > 0) {
            index -= 1;
            slots[index] = .{ .state = .FREE, .next = free_head, .prev = NIL };
            free_head = @intCast(index);
        }

        return .{
            .settings = .{
                .limit = @min(settings.limit, MAX_SLOTS),
                .queue_len = room,
                .timeout_ms = settings.timeout_ms,
            },
            .slots = slots,
            .free_head = free_head,
        };
    }

    pub fn deinit(gate: *Gate, allocator: std.mem.Allocator) void {
        allocator.free(gate.slots);
    }

    /// Ask for a process slot.
    ///
    /// Note:
    /// - An unarmed gate admits everything, so an edge calls this without
    ///   asking whether its site configured one.
    ///
    /// Return:
    /// - ADMITTED, the caller holds a slot and owes leave()
    /// - QUEUED with the ticket to wait on
    /// - REFUSED, the site is saturated and the edge answers 504
    pub fn enter(gate: *Gate) Admission {
        if (!gate.settings.armed()) return .ADMITTED;

        gate.acquire();
        defer gate.release();

        if (gate.in_flight < gate.settings.limit) {
            gate.in_flight += 1;

            return .ADMITTED;
        }

        const index = gate.free_head;
        if (index == NIL) return .REFUSED;

        gate.free_head = gate.slots[index].next;
        gate.slots[index] = .{ .state = .WAITING, .next = NIL, .prev = gate.wait_tail };
        gate.linkWaitTailLocked(index);
        gate.waiting += 1;

        return .{ .QUEUED = .{ .index = index } };
    }

    /// Where a queued ticket stands, taking the slot when one arrived.
    ///
    /// Note:
    /// - Reporting ADMITTED consumes the ticket: the waiting-room slot goes
    ///   back to the free list and the caller now owes leave(). Polling the
    ///   same ticket again is a caller bug, and answers ADMITTED without
    ///   touching any count so it can never hand out a second slot.
    ///
    /// Return:
    /// - WAITING, still in line
    /// - ADMITTED, the caller holds a process slot now
    pub fn poll(gate: *Gate, ticket: Ticket) Wait {
        if (!gate.settings.armed()) return .ADMITTED;

        gate.acquire();
        defer gate.release();

        switch (gate.slots[ticket.index].state) {
            .WAITING => return .WAITING,
            .ADMITTED => {
                gate.pushFreeLocked(ticket.index);

                return .ADMITTED;
            },
            .FREE => return .ADMITTED,
        }
    }

    /// Give up a queued ticket, because the wait ran out.
    ///
    /// Note:
    /// - Safe against the race it exists for: a request can be handed a slot
    ///   between its last poll and this call, and that slot is passed to the
    ///   next in line rather than lost.
    pub fn abandon(gate: *Gate, ticket: Ticket) void {
        if (!gate.settings.armed()) return;

        gate.acquire();
        defer gate.release();

        switch (gate.slots[ticket.index].state) {
            .WAITING => {
                gate.unlinkWaitLocked(ticket.index);
                gate.pushFreeLocked(ticket.index);
            },
            .ADMITTED => {
                gate.pushFreeLocked(ticket.index);
                gate.handOverLocked();
            },
            .FREE => {},
        }
    }

    /// Hand a held process slot back, to the next in line or to the site.
    pub fn leave(gate: *Gate) void {
        if (!gate.settings.armed()) return;

        gate.acquire();
        defer gate.release();

        gate.handOverLocked();
    }

    /// Requests running upstream right now. For tests and status output.
    pub fn inFlight(gate: *Gate) usize {
        gate.acquire();
        defer gate.release();

        return gate.in_flight;
    }

    /// Requests waiting in line right now. For tests and status output.
    pub fn waitingCount(gate: *Gate) usize {
        gate.acquire();
        defer gate.release();

        return gate.waiting;
    }

    /// Pass one process slot to the oldest waiter, or release it outright
    /// when nobody is in line.
    fn handOverLocked(gate: *Gate) void {
        const index = gate.wait_head;
        if (index != NIL) {
            gate.unlinkWaitLocked(index);
            gate.slots[index].state = .ADMITTED;

            return;
        }

        // Guarded rather than asserted: a caller that leaves twice should
        // cost an accounting error, never an underflow that wedges the site.
        if (gate.in_flight > 0) gate.in_flight -= 1;
    }

    /// Append an already-filled slot to the arrival-ordered wait list.
    fn linkWaitTailLocked(gate: *Gate, index: u32) void {
        if (gate.wait_tail == NIL) gate.wait_head = index else gate.slots[gate.wait_tail].next = index;

        gate.wait_tail = index;
    }

    /// Take a slot out of the wait list, wherever it sits in the order.
    fn unlinkWaitLocked(gate: *Gate, index: u32) void {
        const slot = gate.slots[index];

        if (slot.prev == NIL) gate.wait_head = slot.next else gate.slots[slot.prev].next = slot.next;
        if (slot.next == NIL) gate.wait_tail = slot.prev else gate.slots[slot.next].prev = slot.prev;

        gate.waiting -= 1;
    }

    /// Return a slot to the free list, whatever it was doing before.
    fn pushFreeLocked(gate: *Gate, index: u32) void {
        gate.slots[index] = .{ .state = .FREE, .next = gate.free_head, .prev = NIL };
        gate.free_head = index;
    }

    fn acquire(gate: *Gate) void {
        while (gate.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn release(gate: *Gate) void {
        gate.lock_flag.store(false, .release);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: process gate, an unarmed gate admits everything" {
    var gate = try Gate.init(std.testing.allocator, .{});
    defer gate.deinit(std.testing.allocator);

    try std.testing.expect(!gate.settings.armed());
    try std.testing.expectEqual(@as(usize, 0), gate.slots.len);

    for (0..1000) |_| {
        try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
        gate.leave();
    }

    try std.testing.expectEqual(@as(usize, 0), gate.inFlight());
}

test "zix zixer: process gate, the limit is what runs at once" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 3, .queue_len = 4 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
    try std.testing.expectEqual(@as(usize, 3), gate.inFlight());

    // The fourth finds the limit reached and takes a place in line.
    const fourth = gate.enter();
    try std.testing.expect(fourth == .QUEUED);
    try std.testing.expectEqual(@as(usize, 1), gate.waitingCount());
    try std.testing.expectEqual(@as(usize, 3), gate.inFlight());
}

test "zix zixer: process gate, a full waiting room refuses" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 2 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
    try std.testing.expect(gate.enter() == .QUEUED);
    try std.testing.expect(gate.enter() == .QUEUED);

    try std.testing.expectEqual(Admission.REFUSED, gate.enter());
    try std.testing.expectEqual(@as(usize, 2), gate.waitingCount());
}

test "zix zixer: process gate, no waiting room refuses at the limit" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 0 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
    try std.testing.expectEqual(Admission.REFUSED, gate.enter());
}

test "zix zixer: process gate, leaving hands the slot to the oldest waiter" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 3 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const first = gate.enter().QUEUED;
    const second = gate.enter().QUEUED;

    try std.testing.expectEqual(Wait.WAITING, gate.poll(first));
    try std.testing.expectEqual(Wait.WAITING, gate.poll(second));

    // The runner finishes: the slot moves to the head of the line, it is
    // not released, so in_flight stays at the limit.
    gate.leave();
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());
    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(first));
    try std.testing.expectEqual(Wait.WAITING, gate.poll(second));
    try std.testing.expectEqual(@as(usize, 1), gate.waitingCount());

    gate.leave();
    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(second));

    gate.leave();
    try std.testing.expectEqual(@as(usize, 0), gate.inFlight());
    try std.testing.expectEqual(@as(usize, 0), gate.waitingCount());
}

test "zix zixer: process gate, a claimed ticket gives its room slot back" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 1 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const ticket = gate.enter().QUEUED;
    try std.testing.expectEqual(Admission.REFUSED, gate.enter());

    gate.leave();
    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(ticket));

    // The one room slot is free again, so the next arrival can queue on it.
    try std.testing.expect(gate.enter() == .QUEUED);
}

test "zix zixer: process gate, abandoning from the middle keeps the order" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 3 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const first = gate.enter().QUEUED;
    const middle = gate.enter().QUEUED;
    const last = gate.enter().QUEUED;

    gate.abandon(middle);
    try std.testing.expectEqual(@as(usize, 2), gate.waitingCount());

    gate.leave();
    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(first));

    gate.leave();
    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(last));
}

test "zix zixer: process gate, abandoning the head still drains the line" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 2 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const head = gate.enter().QUEUED;
    const tail = gate.enter().QUEUED;

    gate.abandon(head);
    gate.leave();

    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(tail));
    try std.testing.expectEqual(@as(usize, 0), gate.waitingCount());
}

test "zix zixer: process gate, abandoning after the handover passes the slot on" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 2 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const giving_up = gate.enter().QUEUED;
    const next = gate.enter().QUEUED;

    // The runner leaves, so giving_up is handed the slot. It gives up
    // anyway, which is the race a deadline that fires here would hit.
    gate.leave();
    gate.abandon(giving_up);

    try std.testing.expectEqual(Wait.ADMITTED, gate.poll(next));
    try std.testing.expectEqual(@as(usize, 1), gate.inFlight());
}

test "zix zixer: process gate, an abandoned slot is reusable" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 1, .queue_len = 1 });
    defer gate.deinit(std.testing.allocator);

    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());

    const ticket = gate.enter().QUEUED;
    gate.abandon(ticket);

    try std.testing.expect(gate.enter() == .QUEUED);
    try std.testing.expectEqual(@as(usize, 1), gate.waitingCount());
}

test "zix zixer: process gate, leaving more than entering never underflows" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 2, .queue_len = 1 });
    defer gate.deinit(std.testing.allocator);

    gate.leave();
    gate.leave();

    try std.testing.expectEqual(@as(usize, 0), gate.inFlight());
    try std.testing.expectEqual(Admission.ADMITTED, gate.enter());
}

test "zix zixer: process gate, a site value overrides the daemon default" {
    const daemon = Settings{ .limit = 10, .queue_len = 20, .timeout_ms = 3000 };

    const overridden = resolve(4, 8, 1500, daemon);
    try std.testing.expectEqual(@as(usize, 4), overridden.limit);
    try std.testing.expectEqual(@as(usize, 8), overridden.queue_len);
    try std.testing.expectEqual(@as(u32, 1500), overridden.timeout_ms);

    const inherited = resolve(null, null, null, daemon);
    try std.testing.expectEqual(@as(usize, 10), inherited.limit);
    try std.testing.expectEqual(@as(usize, 20), inherited.queue_len);
    try std.testing.expectEqual(@as(u32, 3000), inherited.timeout_ms);
}

test "zix zixer: process gate, resolve clamps an unvalidated value into range" {
    const resolved = resolve(MAX_SLOTS * 4, MAX_SLOTS * 4, 0, .{});

    try std.testing.expectEqual(MAX_SLOTS, resolved.limit);
    try std.testing.expectEqual(MAX_SLOTS, resolved.queue_len);
    try std.testing.expectEqual(@as(u32, 1), resolved.timeout_ms);
}

test "zix zixer: process gate, the range checks accept the ends" {
    try std.testing.expect(limitInRange(0));
    try std.testing.expect(limitInRange(MAX_SLOTS));
    try std.testing.expect(!limitInRange(MAX_SLOTS + 1));

    try std.testing.expect(queueLenInRange(0));
    try std.testing.expect(queueLenInRange(MAX_SLOTS));
    try std.testing.expect(!queueLenInRange(MAX_SLOTS + 1));

    try std.testing.expect(!timeoutInRange(0));
    try std.testing.expect(timeoutInRange(1));
    try std.testing.expect(timeoutInRange(DEFAULT_TIMEOUT_MS));
    try std.testing.expect(timeoutInRange(MAX_TIMEOUT_MS));
    try std.testing.expect(!timeoutInRange(MAX_TIMEOUT_MS + 1));
}

test "zix zixer: process gate, a room slot is only allocated when armed" {
    var armed = try Gate.init(std.testing.allocator, .{ .limit = 2, .queue_len = 8 });
    defer armed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 8), armed.slots.len);

    // queue_len without a limit is the gate off, so nothing is allocated.
    var unarmed = try Gate.init(std.testing.allocator, .{ .limit = 0, .queue_len = 8 });
    defer unarmed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), unarmed.slots.len);
}

test "zix zixer: process gate, every worker shares one count" {
    var gate = try Gate.init(std.testing.allocator, .{ .limit = 64, .queue_len = 64 });
    defer gate.deinit(std.testing.allocator);

    const Runner = struct {
        fn run(shared: *Gate, rounds: usize) void {
            for (0..rounds) |_| {
                switch (shared.enter()) {
                    .ADMITTED => shared.leave(),
                    .QUEUED => |ticket| shared.abandon(ticket),
                    .REFUSED => {},
                }
            }
        }
    };

    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Runner.run, .{ &gate, @as(usize, 2000) });
    for (threads) |thread| thread.join();

    // Every entry was matched by a leave or an abandon, so the gate is idle.
    try std.testing.expectEqual(@as(usize, 0), gate.inFlight());
    try std.testing.expectEqual(@as(usize, 0), gate.waitingCount());
}
