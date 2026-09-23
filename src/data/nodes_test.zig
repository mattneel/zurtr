//! The `.distributed` tier's cross-process proof.
//!
//! Everything else about the tier is tested in one process, and a single process cannot test the
//! thing the tier exists for: two engines in one test binary share one allocator, one thread and one
//! process lifetime, so they prove the lease's arithmetic and never its coordination. These tests run
//! `src/data/node.zig` — a real program — as two unrelated processes over one database file.
//!
//! Two cases, because a holder can leave in two ways. The first is the handoff: a holder that exits
//! without releasing, and a follower that takes over when the expiry passes. The second is the crash —
//! `SIGKILL`, no handler, no flush, no release — which is the case the lease exists for: a node that
//! does not get to exit has nothing to release, and recovery is only recovery if it still works.
//!
//! ## The handoff
//!
//! `node.zig` runs twice, and each run asserts what it saw:
//!
//!   1. node A (leader) opens, writes one row and stays up holding the lease;
//!   2. node B (follower) starts *while A is up*, and reads A's row — a second live process on the
//!      same file, which the engine's default exclusive file lock would refuse outright;
//!   3. B's write is refused with `conflict` while A holds the lease, and B is told who holds it;
//!   4. A exits; B waits out the lease, writes, and its next read sees both rows — the recovery story
//!      for a holder that stopped renewing;
//!   5. the test opens the file itself and finds both rows, so the two writes are durable and not
//!      just visible to their authors.
//!
//! Both harness runs report their own pid, the pids are asserted to differ, and the test prints both
//! lines' outcome, so "two processes" is checkable from the output rather than assumed from the code.
//!
//! ## The crash
//!
//! The kill case is the one the contract's recovery sentence is about — a node that does not get to
//! exit — and it fails if the survivor's first attempt fails for anything other than the dead holder's
//! lease:
//!
//!   1. the holder opens, writes one row and holds, renewing, so that it is unambiguously a live holder
//!      and not a process still on its way into one;
//!   2. the test kills it mid-hold with `SIGKILL` and asserts the term it got back *is* that signal:
//!      killed, not exited, is the whole difference from the handoff above;
//!   3. the survivor opens the same file — nothing the kill left behind blocks a new process — reads
//!      exactly the killed holder's committed row and nothing half-written, and is refused with
//!      `conflict` by a lease whose holder is no longer in any process table;
//!   4. it waits for that lease's expiry, takes it, and sees both rows;
//!   5. an engine that was never part of the pair finds both titles afterwards.
//!
//! # Waiting
//!
//! The tier's interesting states are temporal, so the timing is part of the test rather than a
//! convenience:
//!
//!   * A *renews* the lease for `hold_ms` and then stops and exits. Renewal is what makes the first
//!     assertion independent of machine speed: B is refused because A is a live holder, not because B
//!     happened to arrive inside a lease window. B is started after A's first line is *read*, not after
//!     a guess, and the test checks A's pid is still alive at the moment B was refused (`/proc`, Linux
//!     only — supporting evidence; the proof is that B saw A as the lease holder).
//!   * B waits after the refusal for the lease row's expiry to pass, reading the row rather than
//!     sleeping for a guess (`--retry-ms` is the budget, not the wait), and then attempts the write
//!     once more. The test waits for A to exit in between, so the order "A gone, then B takes over" is
//!     the test's doing and not a race.
//!
//! The margins are wide on purpose (hundreds of milliseconds against a one-second expiry). If a
//! stalled machine eats them the test fails loudly instead of proving nothing: a write that succeeds
//! while a live holder is renewing would be a real bug in the lease, not a flake to paper over.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const data = @import("root.zig");
const adapter = @import("turso_adapter.zig");
const build_options = @import("build_options");

/// A path nothing else can be using.
///
/// Two processes over one file is the subject here, so the file has to be *this run's*: a fixed name
/// would let a previous run's leftovers (or a run that died before its cleanup) feed a stale row and a
/// stale lease to this one, and a test that inherits state is a test that proves nothing.
fn uniquePath(arena: std.mem.Allocator, io: Io, name: []const u8) ![]const u8 {
    const stamp = Io.Clock.Timestamp.now(io, .real).raw.toMicroseconds();

    return std.fmt.allocPrint(arena, "zig-cache-data-nodes-{s}-{d}.db", .{ name, stamp });
}

/// Every file a `.distributed` database is made of, so a test removes what it created: SQLite's
/// `-wal` (and `-shm`, when the engine keeps one) plus the `-tshm` shared-WAL coordination file the
/// engine's multiprocess mode adds.
fn siblingsOf(arena: std.mem.Allocator, path: []const u8) ![][]const u8 {
    const files = try arena.alloc([]const u8, 4);
    files[0] = path;
    files[1] = try std.fmt.allocPrint(arena, "{s}-wal", .{path});
    files[2] = try std.fmt.allocPrint(arena, "{s}-shm", .{path});
    files[3] = try std.fmt.allocPrint(arena, "{s}-tshm", .{path});

    return files;
}

/// How long the killed holder would keep renewing for. Far past anything this test does: it never
/// reaches the end of that hold, which is the point of killing it.
const killed_hold_ms = 5_000;

/// How long the test lets the holder run before killing it, so it has renewed at least once and is
/// unambiguously *in* its hold rather than still on its way into one.
const settled_ms = 300;

/// The survivor's budget for the wait after its refusal: it ends when the dead holder's lease row
/// expires (at most `settled_ms + lease_ms` after the kill, since a holder renews every 150ms), with
/// room to spare for the process start-up between the kill and the survivor's first attempt.
const killed_retry_ms = 3_000;

/// One harness line, field-for-field with `src/data/node.zig`'s `Report`.
const Report = struct {
    attempt: u32,
    node: []const u8,
    pid: i32,
    role: []const u8,
    read: []const u8,
    rows: i64,
    rows_after: i64,
    write: []const u8,
    lease_holder: ?[]const u8,
    lease_mine: bool,
    now_micros: i64,
    lease_until: ?i64,
};

/// How long a claimed lease stays valid, in milliseconds. Not this test's to set: `claimLease` gives
/// every lease a one-second expiry, and the timing below is sized around it.
const lease_ms = 1_000;

/// How long A keeps the lease, renewing it, before it stops renewing and exits. Long enough that B's
/// start-up and first write land inside it even on a machine that is busy compiling the thing it is
/// about to run.
const hold_ms = 1_200;

/// B's budget for the wait after its refusal. The wait itself ends when the lease row's expiry passes —
/// B reads the row rather than guessing — so this only has to cover the worst case: A's whole hold
/// (`hold_ms`) plus the life of the last renewal it wrote (`lease_ms`) plus margin.
const retry_ms = 3_000;

test "two live processes over one database file: reads anywhere, one writer at a time" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const path = try uniquePath(arena, io, "handoff");
    const siblings = try siblingsOf(arena, path);
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};

    const exe = build_options.data_node_exe;

    // --- node A: writes, then holds ------------------------------------------------------------
    var a = try std.process.spawn(io, .{
        .argv = &.{
            exe,                                      "--db",   path,      "--node",          "node-a",
            "--role",                                 "leader", "--write", "from the leader", "--hold-ms",
            std.fmt.comptimePrint("{d}", .{hold_ms}),
        },
        .stdout = .pipe,
    });

    var a_buffer: [4096]u8 = undefined;
    var a_out = a.stdout.?.reader(io, &a_buffer);
    const a_first = try takeReport(&a_out.interface, arena);

    try std.testing.expectEqual(@as(u32, 1), a_first.attempt);
    try std.testing.expectEqualStrings("node-a", a_first.node);
    try std.testing.expectEqualStrings("leader", a_first.role);
    try std.testing.expectEqualStrings("ok", a_first.read);
    // A fresh file: A reads nothing before its write, one row after it, and is the holder.
    try std.testing.expectEqual(@as(i64, 0), a_first.rows);
    try std.testing.expectEqual(@as(i64, 1), a_first.rows_after);
    try std.testing.expectEqualStrings("committed", a_first.write);
    try std.testing.expectEqualStrings("node-a", a_first.lease_holder.?);
    try std.testing.expect(a_first.lease_mine);

    // --- node B: starts while A holds ----------------------------------------------------------
    var b = try std.process.spawn(io, .{
        .argv = &.{
            exe,                                       "--db",     path,      "--node",            "node-b",
            "--role",                                  "follower", "--write", "from the follower", "--retry-ms",
            std.fmt.comptimePrint("{d}", .{retry_ms}),
        },
        .stdout = .pipe,
    });

    var b_buffer: [4096]u8 = undefined;
    var b_out = b.stdout.?.reader(io, &b_buffer);
    const b_first = try takeReport(&b_out.interface, arena);

    // Two unrelated processes, which is the whole point: the pids in the output say so.
    try std.testing.expect(a_first.pid > 0);
    try std.testing.expect(b_first.pid > 0);
    try std.testing.expect(a_first.pid != b_first.pid);

    // B opened the same file while A had it open, read what A committed, and was refused the write
    // while A held the lease — told who holds it rather than left to guess.
    try std.testing.expectEqualStrings("node-b", b_first.node);
    try std.testing.expectEqualStrings("follower", b_first.role);
    try std.testing.expectEqualStrings("ok", b_first.read);
    try std.testing.expectEqual(@as(i64, 1), b_first.rows);
    // Still one row after the refusal: a refused write changes nothing.
    try std.testing.expectEqual(@as(i64, 1), b_first.rows_after);
    try std.testing.expectEqualStrings("conflict", b_first.write);
    try std.testing.expectEqualStrings("node-a", b_first.lease_holder.?);
    try std.testing.expect(!b_first.lease_mine);

    if (builtin.os.tag == .linux) {
        // A had not exited when it refused B. The hold above is what makes this true, and asserting it
        // is what keeps the refusal from being read as "A had already died".
        try std.testing.expect(try running(io, a_first.pid));
    }

    // --- A exits, then B takes over -------------------------------------------------------------
    // Waiting for A here is what makes the next line's meaning unambiguous: B's second attempt
    // happened after its holder was gone *and* after the lease's expiry.
    const a_term = try a.wait(io);
    try std.testing.expect(a_term.success());
    if (builtin.os.tag == .linux) try std.testing.expect(!try running(io, a_first.pid));

    const b_second = try takeReport(&b_out.interface, arena);

    try std.testing.expectEqual(@as(u32, 2), b_second.attempt);
    try std.testing.expectEqual(b_first.pid, b_second.pid);
    try std.testing.expectEqualStrings("committed", b_second.write);
    try std.testing.expectEqualStrings("node-b", b_second.lease_holder.?);
    try std.testing.expect(b_second.lease_mine);
    // Both rows *after* its own write: the takeover continues the same database rather than starting
    // a second one, and the two writers are visible in one file across two processes.
    try std.testing.expectEqual(@as(i64, 1), b_second.rows);
    try std.testing.expectEqual(@as(i64, 2), b_second.rows_after);

    const b_term = try b.wait(io);
    try std.testing.expect(b_term.success());

    // What a person running `zig build test-data-nodes` can check by eye.
    std.debug.print(
        "two-process distributed proof: A pid {d} wrote and held the lease; B pid {d} read {d} row(s) and was refused ({s}); after A exited, B took the lease and saw {d} rows\n",
        .{ a_first.pid, b_first.pid, b_first.rows, b_first.write, b_second.rows_after },
    );

    // --- the file itself: two writers, two durable rows -----------------------------------------
    // Opened at the tier the writers used. The engine's multiprocess mode keeps its WAL index in the
    // shared `-tshm` mapping, and a single-process open of that same file is a different view of it —
    // proven durable means read back the way it was written.
    var reader = try adapter.open(arena, io, .{ .distributed = .{
        .path = path,
        .remote = "https://example.invalid",
        .node = "reader",
    } });
    defer reader.close();

    var titles = Titles{ .arena = arena };
    try reader.query(null, "SELECT title FROM notes ORDER BY id", &.{}, titles.sink());

    try std.testing.expectEqual(@as(usize, 2), titles.seen.items.len);
    try std.testing.expectEqualStrings("from the leader", titles.seen.items[0]);
    try std.testing.expectEqualStrings("from the follower", titles.seen.items[1]);
}

test "a killed holder's lease expires, and the survivor takes over" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const killed_path = try uniquePath(arena, io, "killed");
    const siblings = try siblingsOf(arena, killed_path);
    for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};
    defer for (siblings) |file| std.Io.Dir.cwd().deleteFile(io, file) catch {};

    const exe = build_options.data_node_exe;

    // --- the holder: writes, then holds and renews ----------------------------------------------
    var holder = try std.process.spawn(io, .{
        .argv = &.{
            exe,                                             "--db",   killed_path, "--node",                 "node-dead",
            "--role",                                        "leader", "--write",   "from the killed holder", "--hold-ms",
            std.fmt.comptimePrint("{d}", .{killed_hold_ms}),
        },
        .stdout = .pipe,
    });
    // Whatever happens below, no harness process outlives this test.
    defer holder.kill(io);

    var holder_buffer: [4096]u8 = undefined;
    var holder_out = holder.stdout.?.reader(io, &holder_buffer);
    const holder_first = try takeReport(&holder_out.interface, arena);

    try std.testing.expectEqualStrings("committed", holder_first.write);
    try std.testing.expectEqualStrings("node-dead", holder_first.lease_holder.?);
    try std.testing.expect(holder_first.lease_mine);

    // Deliberate timing, not a race: the holder renews every 150ms, so waiting longer than that puts
    // it inside its hold with a lease it has already pushed forward once more.
    try Io.sleep(io, Io.Duration.fromMilliseconds(settled_ms), .awake);

    // SIGKILL: uncatchable, so there is no handler to flush anything and no release to run. The lease
    // row it wrote is now all that is left of it.
    try std.posix.kill(holder_first.pid, .KILL);
    const holder_term = try holder.wait(io);

    const was_killed = switch (holder_term) {
        .signal => |signal| signal == .KILL,
        else => false,
    };
    if (!was_killed) {
        // Killed, not exited: if this is ever false the test below is proving something else.
        std.debug.print("the holder did not die by SIGKILL: {f}\n", .{holder_term});
        return error.TestUnexpectedResult;
    }

    // --- the survivor: opens the file the killed process still holds a lease on -----------------
    var survivor = try std.process.spawn(io, .{
        .argv = &.{
            exe,                                              "--db",     killed_path, "--node",            "node-alive",
            "--role",                                         "follower", "--write",   "from the survivor", "--retry-ms",
            std.fmt.comptimePrint("{d}", .{killed_retry_ms}),
        },
        .stdout = .pipe,
    });
    defer survivor.kill(io);

    var survivor_buffer: [4096]u8 = undefined;
    var survivor_out = survivor.stdout.?.reader(io, &survivor_buffer);
    const survivor_first = try takeReport(&survivor_out.interface, arena);

    // Opening the file worked — nothing the kill left behind (a `-tshm` coordination file, a WAL that
    // was not checkpointed) blocks a new process — and what the survivor read is exactly the row the
    // killed holder committed: no half-written row, no row missing.
    try std.testing.expectEqualStrings("ok", survivor_first.read);
    try std.testing.expectEqual(@as(i64, 1), survivor_first.rows);
    try std.testing.expectEqual(@as(i64, 1), survivor_first.rows_after);

    // And its first write is refused by a lease whose holder no longer exists: the lease is a timestamp
    // in the database, not a lock a dead process keeps holding.
    try std.testing.expectEqualStrings("conflict", survivor_first.write);
    try std.testing.expectEqualStrings("node-dead", survivor_first.lease_holder.?);
    try std.testing.expect(!survivor_first.lease_mine);

    // --- the survivor waits out the expiry and takes over ---------------------------------------
    const survivor_second = try takeReport(&survivor_out.interface, arena);

    try std.testing.expectEqualStrings("committed", survivor_second.write);
    try std.testing.expectEqualStrings("node-alive", survivor_second.lease_holder.?);
    try std.testing.expect(survivor_second.lease_mine);
    try std.testing.expectEqual(@as(i64, 2), survivor_second.rows_after);

    const survivor_term = try survivor.wait(io);
    try std.testing.expect(survivor_term.success());

    std.debug.print(
        "killed-holder proof: node-dead pid {d} committed and was SIGKILLed mid-hold; node-alive pid {d} opened the file, read {d} row(s), was refused ({s}) by the dead holder's lease, then took it and saw {d} rows\n",
        .{ holder_first.pid, survivor_first.pid, survivor_first.rows, survivor_first.write, survivor_second.rows_after },
    );

    // --- and the file itself, read by an engine that was never part of the pair -----------------
    var reader = try adapter.open(arena, io, .{ .distributed = .{
        .path = killed_path,
        .remote = "https://example.invalid",
        .node = "reader",
    } });
    defer reader.close();

    var titles = Titles{ .arena = arena };
    try reader.query(null, "SELECT title FROM notes ORDER BY id", &.{}, titles.sink());

    try std.testing.expectEqual(@as(usize, 2), titles.seen.items.len);
    try std.testing.expectEqualStrings("from the killed holder", titles.seen.items[0]);
    try std.testing.expectEqualStrings("from the survivor", titles.seen.items[1]);
}

fn takeLine(reader: *Io.Reader) ![]const u8 {
    return std.mem.trimEnd(u8, try reader.takeDelimiterInclusive('\n'), "\r\n");
}

/// Read one line from a harness process and echo it. Assertions name one field at a time; echoing the
/// line is what turns a failure into a diagnosis, and it is what a person running the step by hand
/// wants to see anyway.
fn takeReport(reader: *Io.Reader, arena: std.mem.Allocator) !Report {
    const line = try takeLine(reader);
    std.debug.print("  {s}\n", .{line});

    return parse(arena, line);
}

fn parse(arena: std.mem.Allocator, line: []const u8) !Report {
    // `.alloc_always`: without it the strings would borrow the reader's buffer, and the next line read
    // would overwrite the line being asserted on. Copying into the arena is what makes each report
    // independent of when the next one arrives.
    const parsed = try std.json.parseFromSlice(Report, arena, line, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });

    return parsed.value;
}

/// Whether a process still exists. Linux only, and only ever supporting evidence.
fn running(io: Io, pid: i32) !bool {
    var buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, "/proc/{d}", .{pid});

    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;

    return true;
}

/// The titles the test's own reader saw, copied out of the borrow scope the contract gives them.
const Titles = struct {
    seen: std.ArrayList([]const u8) = .empty,
    arena: std.mem.Allocator,

    fn sink(self: *Titles) data.RowSink {
        return .{ .context = self, .push = push };
    }

    fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
        const self: *Titles = @ptrCast(@alignCast(context));

        self.seen.append(self.arena, self.arena.dupe(u8, columns[0].text) catch return error.Internal) catch return error.Internal;
    }
};
