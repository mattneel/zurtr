//! zigeval_listen: evaluate Zig expressions at comptime by driving one long-lived
//! `zig build-obj -fno-emit-bin -fincremental --listen=-` process.
//!
//! Standalone (std only), no build.zig change:
//!   zig run tools/zigeval_listen.zig                 self-test + timings; exit 1 on any failure
//!   zig run tools/zigeval_listen.zig -- '1 + 2' ...  evaluate expressions, print what the compiler prints
//!   zig test tools/zigeval_listen.zig                the pinned assertions on their own
//!
//! The evaluating compiler is the one running this file (`ZIG_EXE`, which `zig run` and
//! `zig test` export to their child), so every result is pinned to that compiler.
//!
//! Compiler behaviours this depends on. The self-test exercises each one, so a rebase
//! that changes any of them fails loudly instead of silently:
//!  1. `--listen=-` framing: little-endian `{ tag: u32, bytes_len: u32 }` then the body.
//!     The compiler greets with `zig_version`; we send `update` and `exit`.
//!  2. Every update ends with exactly one `error_bundle` message, sent empty when there
//!     are no errors (`serveUpdateResults`, src/main.zig).
//!  3. `@compileLog` output arrives as the bundle's compile-log text: one line per call,
//!     values printed as `@as(T, v)`. With no other errors the bundle also carries a
//!     "found compile log statement" error; with other errors the text still arrives
//!     but that error is left out (`getAllErrorsAlloc`, src/Compilation.zig).
//!  4. Incremental change detection is metadata only: size, mtime in ns, inode
//!     (`updateFile`, src/Zcu/PerThread.zig). A same-size rewrite inside one mtime tick
//!     would be missed and the previous result served again. So every eval writes a temp
//!     file and renames it over eval.zig, which always yields a new inode, and every eval
//!     logs a nonce first; a result carrying any other nonce is rejected as stale.
//!  5. The incremental compiler recovers from parse errors and semantic errors without
//!     a restart.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ErrorBundle = std.zig.ErrorBundle;
const Client = std.zig.Client;
const Server = std.zig.Server;

pub const Options = struct {
    /// The zig executable that evaluates. Callers normally pass $ZIG_EXE.
    zig_exe: []const u8 = "zig",
    /// Scratch directory (created if missing): eval.zig, a lock file, the local cache.
    /// One evaluator per directory; a second one gets `error.WorkDirBusy`.
    work_dir: []const u8 = ".zig-cache/zigeval-listen",
    /// Top-level declarations, placed below the comptime block.
    prelude: []const u8 = "const std = @import(\"std\");",
};

pub const Result = union(enum) {
    /// Exactly what the compiler printed for the expression, e.g. `@as(u32, 42)`.
    value: []u8,
    /// Parse or semantic errors, rendered the way `zig build` renders them.
    errors: []u8,

    pub fn deinit(r: Result, gpa: Allocator) void {
        switch (r) {
            inline else => |s| gpa.free(s),
        }
    }
};

/// The message the compiler attaches to a successful update that hit `@compileLog`.
const compile_log_msg = "found compile log statement";

/// Line in eval.zig where the expression starts (1-based), for mapping error locations
/// back onto the expression. The prelude goes below the comptime block so this stays fixed.
pub const expr_first_line = 5;

pub const Evaluator = struct {
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    lock: Io.File,
    child: std.process.Child,
    prelude: []u8,
    /// Version string from the compiler's `zig_version` greeting.
    version: []u8,
    nonce: u64 = 0,
    stdout_reader: Io.File.Reader,
    stdin_writer: Io.File.Writer,
    stdout_buffer: [64 * 1024]u8,
    stdin_buffer: [64]u8,

    /// Spawns the compiler and waits for its greeting. Heap-allocated because the
    /// reader and writer interfaces must not move.
    pub fn create(gpa: Allocator, io: Io, options: Options) !*Evaluator {
        const ev = try gpa.create(Evaluator);
        errdefer gpa.destroy(ev);

        ev.dir = try Io.Dir.cwd().createDirPathOpen(io, options.work_dir, .{});
        errdefer ev.dir.close(io);

        ev.lock = ev.dir.createFile(io, "lock", .{
            .lock = .exclusive,
            .lock_nonblocking = true,
        }) catch |err| switch (err) {
            error.WouldBlock => return error.WorkDirBusy,
            else => |e| return e,
        };
        errdefer ev.lock.close(io);

        ev.gpa = gpa;
        ev.io = io;
        ev.nonce = 0;
        ev.prelude = try gpa.dupe(u8, options.prelude);
        errdefer gpa.free(ev.prelude);

        // The root file must exist before the compiler starts.
        try ev.dir.writeFile(io, .{ .sub_path = "eval.zig", .data = "comptime {}\n" });

        ev.child = try std.process.spawn(io, .{
            .argv = &.{
                options.zig_exe, "build-obj",   "-fno-emit-bin", "-fincremental",
                "--listen=-",    "--cache-dir", "cache",         "eval.zig",
            },
            .cwd = .{ .dir = ev.dir },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit, // compiler crashes and panics stay visible
        });
        errdefer ev.child.kill(io);

        ev.stdout_reader = ev.child.stdout.?.readerStreaming(io, &ev.stdout_buffer);
        ev.stdin_writer = ev.child.stdin.?.writerStreaming(io, &ev.stdin_buffer);

        const header = try ev.client().receiveMessage();
        if (header.tag != .zig_version) return error.ProtocolUnexpectedGreeting;
        ev.version = try ev.stdout_reader.interface.readAllocAll(gpa, header.bytes_len);
        return ev;
    }

    pub fn destroy(ev: *Evaluator) void {
        const gpa = ev.gpa;
        const io = ev.io;
        if (ev.client().serveBodylessMessage(.exit)) |_| {
            _ = ev.child.wait(io) catch ev.child.kill(io);
        } else |_| {
            ev.child.kill(io);
        }
        ev.lock.close(io);
        ev.dir.close(io);
        gpa.free(ev.prelude);
        gpa.free(ev.version);
        gpa.destroy(ev);
    }

    fn client(ev: *Evaluator) Client {
        return .{ .in = &ev.stdout_reader.interface, .out = &ev.stdin_writer.interface };
    }

    /// Evaluates `expr` at comptime. Returns either the compiler's printed value or its
    /// rendered errors; Zig errors are reserved for protocol failures and stale results.
    /// Caller owns the result (`Result.deinit`).
    pub fn eval(ev: *Evaluator, expr: []const u8) !Result {
        const gpa = ev.gpa;
        const io = ev.io;
        ev.nonce += 1;

        // The expression sits on its own lines so a trailing `//` comment can't
        // swallow the closing paren.
        const source = try std.fmt.allocPrint(gpa,
            \\// zigeval_listen scratch file, rewritten on every eval. Do not edit.
            \\comptime {{
            \\    @compileLog(@as(u64, {d}));
            \\    @compileLog(
            \\{s}
            \\    );
            \\}}
            \\{s}
            \\
        , .{ ev.nonce, expr, ev.prelude });
        defer gpa.free(source);

        // Behaviour 4: temp file + rename, so the compiler always sees a new inode.
        try ev.dir.writeFile(io, .{ .sub_path = "eval.zig.tmp", .data = source });
        try ev.dir.rename("eval.zig.tmp", ev.dir, "eval.zig", io);

        const c = ev.client();
        try c.serveBodylessMessage(.update);

        // Behaviour 2: skip anything else until the bundle that ends the update.
        var bundle: ErrorBundle = while (true) {
            const header = try c.receiveMessage();
            const body = try c.in.readAllocAll(gpa, header.bytes_len);
            defer gpa.free(body);
            switch (header.tag) {
                .error_bundle => break try Server.allocErrorBundle(gpa, body),
                else => continue,
            }
        };
        defer bundle.deinit(gpa);

        return interpret(gpa, bundle, ev.nonce) catch |err| {
            switch (err) {
                error.StaleResult => std.log.err(
                    "compile log does not start with nonce {d}; the compiler served an old result:\n{s}",
                    .{ ev.nonce, bundle.getCompileLogOutput() },
                ),
                error.NoCompileLogOutput => std.log.err(
                    "update ended with neither errors nor compile log output",
                    .{},
                ),
                else => {},
            }
            return err;
        };
    }
};

/// Turns the bundle that ended an update into a `Result`. Pure, so the stale path is
/// testable without a compiler.
fn interpret(gpa: Allocator, bundle: ErrorBundle, nonce: u64) !Result {
    // Behaviour 3.
    const log_text: []const u8 = if (bundle.extra.len == 0) "" else bundle.getCompileLogOutput();

    // Behaviour 4: the first log line must be this eval's nonce.
    var nonce_buf: [64]u8 = undefined;
    const nonce_line = try std.fmt.bufPrint(&nonce_buf, "@as(u64, {d})\n", .{nonce});
    if (log_text.len != 0 and !std.mem.startsWith(u8, log_text, nonce_line)) return error.StaleResult;

    var real_errors: usize = 0;
    for (bundle.getMessages()) |msg_index| {
        const msg = bundle.nullTerminatedString(bundle.getErrorMessage(msg_index).msg);
        if (!std.mem.eql(u8, msg, compile_log_msg)) real_errors += 1;
    }

    if (real_errors != 0) {
        var aw: Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try bundle.renderToWriter(.{
            .include_reference_trace = false,
            .include_log_text = false,
        }, &aw.writer);
        return .{ .errors = try aw.toOwnedSlice() };
    }

    if (log_text.len == 0) return error.NoCompileLogOutput;

    const value = std.mem.trimEnd(u8, log_text[nonce_line.len..], "\n");
    return .{ .value = try gpa.dupe(u8, value) };
}

// ---------------------------------------------------------------------------
// Self-test and timings (`zig run`), expression mode (`zig run ... -- expr`).

const Check = struct {
    expr: []const u8,
    /// `null` means this eval must produce errors.
    want: ?[]const u8,
};

fn nsSince(io: Io, t0: Io.Timestamp) f64 {
    return @floatFromInt(t0.untilNow(io, .awake).toNanoseconds());
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const zig_exe = init.environ_map.get("ZIG_EXE") orelse "zig";

    var out_buffer: [4096]u8 = undefined;
    var out_writer = Io.File.stdout().writerStreaming(io, &out_buffer);
    const out = &out_writer.interface;
    defer out.flush() catch {};

    const t_spawn = Io.Timestamp.now(io, .awake);
    const ev = try Evaluator.create(gpa, io, .{ .zig_exe = zig_exe });
    defer ev.destroy();
    const spawn_ms = nsSince(io, t_spawn) / std.time.ns_per_ms;

    try out.print("zigeval_listen against zig {s} ({s})\n", .{ ev.version, zig_exe });

    if (args.len > 1) {
        for (args[1..]) |expr| {
            const t0 = Io.Timestamp.now(io, .awake);
            const result = try ev.eval(expr);
            defer result.deinit(gpa);
            const ms = nsSince(io, t0) / std.time.ns_per_ms;
            switch (result) {
                .value => |v| try out.print("{s}\n  => {s}   ({d:.1} ms)\n", .{ expr, v, ms }),
                .errors => |e| try out.print("{s}\n  => error   ({d:.1} ms)\n{s}", .{ expr, ms, e }),
            }
        }
        return;
    }

    var failures: usize = 0;
    try out.print("spawn + greeting            {d:>7.1} ms\n", .{spawn_ms});

    // Eval 1, cold: the pinned value.
    {
        const t0 = Io.Timestamp.now(io, .awake);
        failures += try expect(ev, out, .{
            .expr = "\"hi\" ++ \" there\"",
            .want = "@as(*const [8:0]u8, \"hi there\")",
        });
        try out.print("  first eval                {d:>7.1} ms\n", .{nsSince(io, t0) / std.time.ns_per_ms});
    }

    // Evals 2-11: same-size rewrites back to back (behaviour 4), every value checked.
    {
        var total: f64 = 0;
        var worst: f64 = 0;
        var ten_failures: usize = 0;
        for (0..10) |i| {
            var expr_buf: [16]u8 = undefined;
            var want_buf: [32]u8 = undefined;
            const expr = try std.fmt.bufPrint(&expr_buf, "1 + {d}", .{i});
            const want = try std.fmt.bufPrint(&want_buf, "@as(comptime_int, {d})", .{i + 1});
            const t0 = Io.Timestamp.now(io, .awake);
            ten_failures += try expectQuiet(ev, out, .{ .expr = expr, .want = want });
            const ns = nsSince(io, t0);
            total += ns;
            worst = @max(worst, ns);
        }
        failures += ten_failures;
        try out.print("{s} ten same-size evals 1 + 0 .. 1 + 9\n", .{passFail(ten_failures)});
        try out.print("  ten evals total           {d:>7.1} ms  (mean {d:.2} ms, worst {d:.2} ms)\n", .{
            total / std.time.ns_per_ms, total / 10 / std.time.ns_per_ms, worst / std.time.ns_per_ms,
        });
    }

    // Behaviour 5: semantic error, then recovery; parse error, then recovery.
    failures += try expect(ev, out, .{ .expr = "undeclared_thing + 1", .want = null });
    failures += try expect(ev, out, .{ .expr = "2 + 2", .want = "@as(comptime_int, 4)" });
    failures += try expect(ev, out, .{ .expr = "1 +", .want = null });
    failures += try expect(ev, out, .{ .expr = "3 + 3", .want = "@as(comptime_int, 6)" });

    // A template-shaped eval through std.
    {
        const t0 = Io.Timestamp.now(io, .awake);
        failures += try expect(ev, out, .{
            .expr = "std.fmt.comptimePrint(\"{s}-{d}\", .{ \"v\", 42 })",
            .want = "@as(*const [4:0]u8, \"v-42\")",
        });
        try out.print("  first std.fmt eval        {d:>7.1} ms\n", .{nsSince(io, t0) / std.time.ns_per_ms});
        const t1 = Io.Timestamp.now(io, .awake);
        failures += try expect(ev, out, .{
            .expr = "std.fmt.comptimePrint(\"{s}-{d}\", .{ \"w\", 7 })",
            .want = "@as(*const [3:0]u8, \"w-7\")",
        });
        try out.print("  next std.fmt eval         {d:>7.1} ms\n", .{nsSince(io, t1) / std.time.ns_per_ms});
    }

    if (failures != 0) {
        try out.print("{d} check(s) FAILED\n", .{failures});
        out.flush() catch {};
        std.process.exit(1);
    }
    try out.print("all checks passed\n", .{});
}

fn passFail(failures: usize) []const u8 {
    return if (failures == 0) "PASS" else "FAIL";
}

/// Returns the number of failures (0 or 1) and prints a line for the check.
fn expect(ev: *Evaluator, out: *Io.Writer, check: Check) !usize {
    const failed = try expectQuiet(ev, out, check);
    const shown = check.want orelse "(errors)";
    try out.print("{s} {s}  =>  {s}\n", .{ passFail(failed), check.expr, shown });
    return failed;
}

/// Like `expect`, but only prints on failure.
fn expectQuiet(ev: *Evaluator, out: *Io.Writer, check: Check) !usize {
    const result = try ev.eval(check.expr);
    defer result.deinit(ev.gpa);
    if (check.want) |want| switch (result) {
        .value => |got| if (std.mem.eql(u8, got, want)) return 0 else {
            try out.print("FAIL {s}\n  want: {s}\n  got:  {s}\n", .{ check.expr, want, got });
            return 1;
        },
        .errors => |e| {
            try out.print("FAIL {s}\n  want: {s}\n  got errors:\n{s}", .{ check.expr, want, e });
            return 1;
        },
    } else switch (result) {
        .errors => return 0,
        .value => |got| {
            try out.print("FAIL {s}\n  want: errors\n  got:  {s}\n", .{ check.expr, got });
            return 1;
        },
    }
}

// ---------------------------------------------------------------------------

test "pinned: the compiler prints \"hi\" ++ \" there\" as @as(*const [8:0]u8, \"hi there\")" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const zig_exe = std.testing.environ.getAlloc(gpa, "ZIG_EXE") catch |err| switch (err) {
        error.EnvironmentVariableMissing => try gpa.dupe(u8, "zig"),
        else => |e| return e,
    };
    defer gpa.free(zig_exe);

    const ev = try Evaluator.create(gpa, io, .{
        .zig_exe = zig_exe,
        .work_dir = ".zig-cache/zigeval-listen-test",
    });
    defer ev.destroy();

    const hi = try ev.eval("\"hi\" ++ \" there\"");
    defer hi.deinit(gpa);
    try std.testing.expectEqualStrings("@as(*const [8:0]u8, \"hi there\")", hi.value);

    // Same size as the previous file, written immediately after it.
    const again = try ev.eval("\"hi\" ++ \" where\"");
    defer again.deinit(gpa);
    try std.testing.expectEqualStrings("@as(*const [8:0]u8, \"hi where\")", again.value);

    const bad = try ev.eval("1 +");
    defer bad.deinit(gpa);
    try std.testing.expect(bad == .errors);

    const recovered = try ev.eval("\"hi\" ++ \" there\"");
    defer recovered.deinit(gpa);
    try std.testing.expectEqualStrings("@as(*const [8:0]u8, \"hi there\")", recovered.value);
}

test "a result carrying an older nonce is rejected, never returned" {
    const gpa = std.testing.allocator;
    var wip: ErrorBundle.Wip = undefined;
    try wip.init(gpa);
    defer wip.deinit();
    try wip.addRootErrorMessage(.{ .msg = try wip.addString(compile_log_msg) });
    var bundle = try wip.toOwnedBundle("@as(u64, 1)\n@as(comptime_int, 2)\n");
    defer bundle.deinit(gpa);

    // What a same-(size, mtime, inode) rewrite looks like: eval 2 gets eval 1's bundle.
    try std.testing.expectError(error.StaleResult, interpret(gpa, bundle, 2));

    const fresh = try interpret(gpa, bundle, 1);
    defer fresh.deinit(gpa);
    try std.testing.expectEqualStrings("@as(comptime_int, 2)", fresh.value);
}
