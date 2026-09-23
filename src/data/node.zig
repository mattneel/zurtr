//! One `.distributed` node, as its own process.
//!
//! The tier's claim is about more than one machine, and an in-process test cannot reach it: two
//! engines in one test binary share one allocator, one thread and one process lifetime, so they prove
//! the lease's *arithmetic* and never its *coordination*. This harness is the missing half — a real
//! process that opens one `.distributed` engine over one database file, attempts one read and one
//! write transaction, and reports what happened as a machine-readable line. Running it twice is the
//! test.
//!
//! It is deliberately a tool, not a framework API: nothing here is imported by the adapter, and the
//! only contract is the JSON line and the exit status.
//!
//! ```text
//! zurtr-data-node --db <path> --node <id> [--role leader|follower]
//!                 [--write <title>] [--hold-ms N] [--retry-ms N] [--remote <url>]
//! ```
//!
//! Each attempt prints one line to stdout:
//!
//! ```json
//! {"attempt":1,"node":"node-a","pid":4242,"role":"leader","read":"ok","rows":0,"rows_after":1,
//!  "write":"committed","lease_holder":"node-a","lease_mine":true}
//! ```
//!
//! `read` is `ok` or the error name the read failed with; `rows` is what the read saw *before* the
//! write and `rows_after` what it saw *after* it (`-1` when the read failed); `write` is `committed`,
//! `conflict`, `skipped` (no `--write` given) or an error name; `lease_holder`/`lease_mine` are the
//! lease row as this process sees it *after* its attempt, read through the same connection as the
//! data.
//!
//! Two flags exist because the tier's interesting states are temporal:
//!
//!   * `--hold-ms` keeps the lease for that long after the attempt, by *renewing* it and staying up.
//!     That is what holding means here: the lease is one row with an expiry, and a holder is a process
//!     that keeps pushing that expiry forward. A node that stops renewing — because it exited, or
//!     died — loses the lease when the expiry it last wrote passes, with no coordination step.
//!   * `--retry-ms` waits that long after a *refused* write and attempts it once more. It is how a
//!     follower exercises the recovery story: refused while the holder's lease is unexpired, taking
//!     over once it has expired.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const data = @import("root.zig");
const adapter = @import("turso_adapter.zig");

const usage =
    \\zurtr-data-node — one node of a `.distributed` deployment, as a process.
    \\
    \\  zurtr-data-node --db <path> --node <id> [--role leader|follower]
    \\                  [--write <title>] [--hold-ms N] [--retry-ms N] [--remote <url>]
    \\
    \\Opens <path> at the distributed tier, then attempts one read and one write transaction. One JSON
    \\line per attempt goes to stdout; --hold-ms keeps the lease alive that long after the attempt, and
    \\--retry-ms retries a refused write once, that long after the refusal.
    \\
;

const Options = struct {
    db: []const u8 = "",
    node: []const u8 = "",
    role: data.Tier.Role = .follower,
    write: ?[]const u8 = null,
    hold_ms: i64 = 0,
    retry_ms: i64 = 0,
    /// Never dialled at this tier: `.distributed` is local-first, and its remote half is the same
    /// transport `.sync` is waiting on.
    remote: []const u8 = "https://example.invalid",
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    var options: Options = .{};
    var index: usize = 1;
    while (index < argv.len) : (index += 1) {
        const flag = argv[index];

        if (std.mem.eql(u8, flag, "--help")) return complain(init.io, usage);
        if (index + 1 == argv.len) return complain(init.io, usage);

        index += 1;
        const value = argv[index];

        if (std.mem.eql(u8, flag, "--db")) {
            options.db = value;
        } else if (std.mem.eql(u8, flag, "--node")) {
            options.node = value;
        } else if (std.mem.eql(u8, flag, "--role")) {
            options.role = std.meta.stringToEnum(data.Tier.Role, value) orelse return complain(init.io, usage);
        } else if (std.mem.eql(u8, flag, "--write")) {
            options.write = value;
        } else if (std.mem.eql(u8, flag, "--hold-ms")) {
            options.hold_ms = std.fmt.parseInt(i64, value, 10) catch return complain(init.io, usage);
        } else if (std.mem.eql(u8, flag, "--retry-ms")) {
            options.retry_ms = std.fmt.parseInt(i64, value, 10) catch return complain(init.io, usage);
        } else if (std.mem.eql(u8, flag, "--remote")) {
            options.remote = value;
        } else {
            return complain(init.io, usage);
        }
    }

    if (options.db.len == 0 or options.node.len == 0) return complain(init.io, usage);

    var db = try adapter.open(arena, init.io, .{ .distributed = .{
        .path = options.db,
        .remote = options.remote,
        .node = options.node,
        .role = options.role,
    } });
    defer db.close();

    try schema(&db);

    var frame: Frame = .{ .attempt = 1, .node = options.node, .role = options.role };
    try frame.emit(init.io, &db, try attempt(&db, options.write));

    // The holder's half: renew the lease and stay up, so the orchestrator can observe a second node
    // being refused for as long as it needs, however slow the machine is.
    if (options.hold_ms > 0) try hold(init.io, &db, options.node, options.hold_ms);

    if (options.retry_ms > 0 and std.mem.eql(u8, frame.first_write, "conflict")) {
        // The follower's half: wait out the holder's lease and try again, which is the whole recovery
        // story for a node that stopped renewing.
        try Io.sleep(init.io, Io.Duration.fromMilliseconds(options.retry_ms), .awake);

        try frame.retry(init.io, &db, try attempt(&db, options.write));
    }
}

/// The table both nodes of the proof use. One row per write, ids assigned by the engine so two
/// processes cannot collide on a hardcoded key.
fn schema(db: *data.Database) !void {
    _ = try db.exec(null,
        \\CREATE TABLE IF NOT EXISTS notes (
        \\  id integer PRIMARY KEY,
        \\  title text NOT NULL UNIQUE,
        \\  word_count integer
        \\)
    , &.{});
}

const Attempt = struct {
    read: []const u8,
    /// What the read saw before the write, and what a read saw after it. Both, because they answer
    /// different questions: "could this node see the other node's work" and "did its own write land
    /// on top of it".
    rows: i64,
    rows_after: i64,
    write: []const u8,
};

/// One read and one write transaction, in the order a node experiences them.
fn attempt(db: *data.Database, title: ?[]const u8) !Attempt {
    var result: Attempt = .{ .read = "ok", .rows = -1, .rows_after = -1, .write = "skipped" };

    result.rows = count(db) catch |err| {
        result.read = @errorName(err);
        return result;
    };

    const inserted = title orelse {
        result.rows_after = result.rows;
        return result;
    };

    // A write transaction is where the tier's gate lives: `begin(.read_write)` is refused with
    // `conflict` when another node holds an unexpired lease, and takes the lease when it does not.
    result.write = write: {
        var tx = db.begin(.read_write) catch |err| break :write writeOutcome(err);

        _ = db.exec(tx, "INSERT INTO notes (title) VALUES (?1)", &.{.{ .text = inserted }}) catch |err| {
            tx.rollback();
            break :write writeOutcome(err);
        };

        tx.commit() catch |err| break :write writeOutcome(err);

        break :write "committed";
    };

    result.rows_after = count(db) catch |err| {
        result.read = @errorName(err);
        return result;
    };

    return result;
}

fn count(db: *data.Database) data.Error!i64 {
    var counter = Counter{};
    try db.query(null, "SELECT title FROM notes", &.{}, counter.sink());

    return counter.rows;
}

fn writeOutcome(err: anyerror) []const u8 {
    return switch (err) {
        error.Conflict => "conflict",
        else => @errorName(err),
    };
}

/// Counts rows without keeping them: the harness only reports how much it could see.
const Counter = struct {
    rows: i64 = 0,

    fn sink(self: *Counter) data.RowSink {
        return .{ .context = self, .push = push };
    }

    fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
        _ = columns;
        const self: *Counter = @ptrCast(@alignCast(context));
        self.rows += 1;
    }
};

/// What one line says. Any added field is a breaking change for the orchestrator, which is the only
/// reader.
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

/// One process's run, and the line it prints per attempt.
const Frame = struct {
    attempt: u32,
    node: []const u8,
    role: data.Tier.Role,
    /// The reported write outcome of the attempt this frame already printed, kept only so a retry can
    /// tell a refusal from a success.
    first_write: []const u8 = "",

    fn emit(self: *Frame, io: Io, db: *data.Database, outcome: Attempt) !void {
        self.first_write = outcome.write;
        try self.write(io, db, outcome);
    }

    fn retry(self: *Frame, io: Io, db: *data.Database, outcome: Attempt) !void {
        try self.write(io, db, outcome);
    }

    fn write(self: *Frame, io: Io, db: *data.Database, outcome: Attempt) !void {
        const lease = try leaseHolder(db);

        var buffer: [4096]u8 = undefined;
        var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
        const stdout = &file_writer.interface;

        try std.json.Stringify.value(Report{
            .attempt = self.attempt,
            .node = self.node,
            .pid = processId(),
            .role = @tagName(self.role),
            .read = outcome.read,
            .rows = outcome.rows,
            .rows_after = outcome.rows_after,
            .write = outcome.write,
            .lease_holder = if (lease) |held| held.holder[0..held.holder_len] else null,
            .lease_mine = if (lease) |held| std.mem.eql(u8, held.holder[0..held.holder_len], self.node) else false,
        }, .{}, stdout);

        try stdout.writeByte('\n');
        try stdout.flush();

        self.attempt += 1;
    }
};

/// Keep the lease for `hold_ms`, renewing it as a live holder does, then stop renewing — the process
/// exits next, and what it held expires on the lease's own clock.
fn hold(io: Io, db: *data.Database, node: []const u8, hold_ms: i64) !void {
    const engine = adapter.engine(db);
    const start = nowMicros(io);

    while (true) {
        if (!try engine.claimLease(adapter.default_lease, node, nowMicros(io))) return error.LeaseLost;
        if (nowMicros(io) - start >= hold_ms) return;

        try Io.sleep(io, Io.Duration.fromMilliseconds(renew_ms), .awake);
    }
}

/// How often a holder pushes its expiry forward. Well inside the lease's one-second life, so a
/// renewal that lands late still lands before the expiry it is replacing.
const renew_ms = 150;

/// The wall clock in microseconds, the unit the lease is written in. The lease API takes the time as
/// a parameter so callers own the clock; this is the harness's clock.
fn nowMicros(io: Io) i64 {
    const stamp = Io.Clock.Timestamp.now(io, .real);

    return @intCast(@divTrunc(stamp.raw.toNanoseconds(), std.time.ns_per_us));
}

/// The lease row as this process sees it, through the same connection the data uses.
fn leaseHolder(db: *data.Database) data.Error!?adapter.Engine.Held {
    return adapter.engine(db).leaseHolder(adapter.default_lease);
}

fn complain(io: Io, message: []const u8) error{InvalidArguments} {
    var buffer: [1024]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), io, &buffer);
    file_writer.interface.print("{s}\n", .{message}) catch {};
    file_writer.interface.flush() catch {};

    return error.InvalidArguments;
}

fn processId() i32 {
    return switch (builtin.os.tag) {
        .linux => std.os.linux.getpid(),
        else => if (builtin.link_libc) @intCast(std.c.getpid()) else 0,
    };
}
