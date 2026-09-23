//! The `.distributed` tier's cross-process proof.
//!
//! Everything else about the tier is tested in one process, and a single process cannot test the
//! thing the tier exists for: two engines in one test binary share one allocator, one thread and one
//! process lifetime, so they prove the lease's arithmetic and never its coordination. This test runs
//! `src/data/node.zig` — a real program — twice, as two unrelated processes over one database file,
//! and asserts what each of them saw:
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
//!   * B retries `retry_ms` after the refusal: past A's exit and past the expiry of A's last renewal,
//!     which is what it is really waiting for. The test waits for A to exit in between, so the order
//!     "A gone, then B takes over" is the test's doing and not a race.
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
};

/// How long a claimed lease stays valid, in milliseconds. Not this test's to set: `claimLease` gives
/// every lease a one-second expiry, and the timing below is sized around it.
const lease_ms = 1_000;

/// How long A keeps the lease, renewing it, before it stops renewing and exits. Long enough that B's
/// start-up and first write land inside it even on a machine that is busy compiling the thing it is
/// about to run.
const hold_ms = 1_200;

/// How long B waits after its refusal before trying again. It has to outlast two things: A's exit
/// (`hold_ms` from A's claim) and the expiry of the last renewal A wrote (`hold_ms + lease_ms`). The
/// value below clears the second with room to spare, which is why B is still waiting after A is gone.
const retry_ms = 3_000;

test "two live processes over one database file: reads anywhere, one writer at a time" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const path = "zig-cache-data-nodes-test.db";
    const siblings = [_][]const u8{ path, path ++ "-wal", path ++ "-tshm" };
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
    const a_first = try parse(arena, try takeLine(&a_out.interface));

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
    const b_first = try parse(arena, try takeLine(&b_out.interface));

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

    const b_second = try parse(arena, try takeLine(&b_out.interface));

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
    var reader = try adapter.open(arena, io, .{ .file = path });
    defer reader.close();

    var titles = Titles{ .arena = arena };
    try reader.query(null, "SELECT title FROM notes ORDER BY id", &.{}, titles.sink());

    try std.testing.expectEqual(@as(usize, 2), titles.seen.items.len);
    try std.testing.expectEqualStrings("from the leader", titles.seen.items[0]);
    try std.testing.expectEqualStrings("from the follower", titles.seen.items[1]);
}

fn takeLine(reader: *Io.Reader) ![]const u8 {
    return std.mem.trimEnd(u8, try reader.takeDelimiterInclusive('\n'), "\r\n");
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
