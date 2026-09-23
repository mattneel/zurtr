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
//!     "found compile log statement" error; with semantic errors the text still arrives
//!     but that error is left out. With *parse* errors the text does not arrive at all
//!     (`getAllErrorsAlloc` returns "" while `skip_analysis_this_update` is set,
//!     src/Compilation.zig).
//!  4. Incremental change detection is metadata only: size, mtime in ns, inode
//!     (`updateFile`, src/Zcu/PerThread.zig). A same-size rewrite inside one mtime tick
//!     would be missed and the previous result served again. So every eval writes a temp
//!     file and renames it over eval.zig, which always yields a new inode, and every eval
//!     logs a nonce first; a result carrying any other nonce is rejected as stale.
//!  5. The incremental compiler recovers from parse errors and semantic errors without
//!     a restart. This one is tested rather than cited: there is no single line of
//!     compiler source that promises it.
//!  6. **The compiler sizes its worker pool from the CPU affinity mask** — `main.zig`
//!     uses `std.Thread.getCpuCount` (sched_getaffinity plus CPU_COUNT) as the job limit
//!     unless `-j` is given. That is why this tool passes `-j1`: one expression is one
//!     unit of work, so extra workers cannot help, and spreading a tiny update across
//!     them costs 4x (unpinned, ten same-size evals: 102 ms with the default pool, 26 ms
//!     with `-j1`, and a pinned run looks the same because `taskset` shrinks the mask).
//!
//! Four things this depends on that are *not* contracts, documented here because a rebase
//! could change any of them without breaking the self-test:
//!  6. **Anything that logs corrupts a value.** The log text is one line per `@compileLog`
//!     call in the whole update, and this tool's value is read as "the text after the
//!     nonce". So an expression (or a prelude helper) that logs turns into extra lines in
//!     the middle of the value. `interpret` now refuses any shape other than exactly two
//!     lines rather than returning the concatenation, which is what it used to do: the
//!     failure was a plausible wrong answer, not an error.
//!  7. **The nonce being first is incidental.** With more than one logging unit the text
//!     is sorted by resolved source location, so the nonce arrives first today because
//!     `eval.zig` sorts first — not because anything promises it. Change the sort key and
//!     a correct eval becomes `error.StaleResult`, with the self-test still green.
//!  8. **A compiler-bug panic ends the session.** `Compilation.zig` panics on some
//!     incremental inconsistencies, and `eval` has no recreate path; its escape hatch,
//!     `--debug-incremental`, needs a compiler built with debug extensions.
//!  9. **A built binary falls back to `"zig"`.** `zig run` and `zig test` export `ZIG_EXE`;
//!     anything else resolves through PATH with the child's cwd set to the work dir, where
//!     a version-resolving launcher shim cannot work and the handshake fails. Pass
//!     `Options.zig_exe` explicitly, which a build step can do with `b.graph.zig_exe`.

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
    /// Parse or semantic errors, rendered the way `zig build` renders them, or the raw log
    /// text when an eval's output could not be attributed to it (`error.UnattributableResult`).
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
                // `-j1` (behaviour 6): the worker pool would otherwise follow the affinity
                // mask, and one expression cannot use more than one worker.
                options.zig_exe, "build-obj",   "-fno-emit-bin", "-fincremental",
                "--listen=-",    "--cache-dir", "cache",         "eval.zig", "-j1",
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
                error.UnattributableResult => std.log.err(
                    "the update logged {d} lines where 2 were expected (the nonce and the value); " ++
                        "the expression or a prelude helper used @compileLog:\n{s}",
                    .{ std.mem.count(u8, bundle.getCompileLogOutput(), "\n"), bundle.getCompileLogOutput() },
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
    //
    // A *parse* error is the hole in this check, and it is worth naming: the compiler stops
    // before analysis, so neither @compileLog runs, the log text is empty, and the nonce
    // vouches for nothing. Only the temp-file rename stands between a parse error and the
    // previous update's result being served as this one's.
    var nonce_buf: [64]u8 = undefined;
    const nonce_line = try std.fmt.bufPrint(&nonce_buf, "@as(u64, {d})\n", .{nonce});
    if (log_text.len != 0 and !std.mem.startsWith(u8, log_text, nonce_line)) return error.StaleResult;

    var real_errors: usize = 0;
    for (bundle.getMessages()) |msg_index| {
        const msg = bundle.nullTerminatedString(bundle.getErrorMessage(msg_index).msg);
        if (!std.mem.eql(u8, msg, compile_log_msg)) real_errors += 1;
    }

    // Behaviour 6: the log text is one line per logging call in the update, so exactly
    // two lines are ours — the nonce and the expression's value. Anything else means
    // something in the update logged, and the "value" would be a concatenation of the
    // two. Refusing is the whole point: silently returning the concatenation is how a
    // side-channel becomes a wrong answer with no error.
    if (log_text.len != 0 and std.mem.count(u8, log_text, "\n") != 2) return error.UnattributableResult;

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

    // `--bench N`: N evals of a rotating same-size expression, reported with a p99. Ten
    // samples cannot show a tail, and the tail is what a keystroke feels.
    if (args.len == 3 and std.mem.eql(u8, args[1], "--bench")) {
        const count = try std.fmt.parseInt(usize, args[2], 10);
        const samples = try gpa.alloc(f64, count);
        defer gpa.free(samples);

        for (samples, 0..) |*sample, i| {
            var expr_buf: [16]u8 = undefined;
            var want_buf: [32]u8 = undefined;
            const expr = try std.fmt.bufPrint(&expr_buf, "1 + {d}", .{i});
            const want = try std.fmt.bufPrint(&want_buf, "@as(comptime_int, {d})", .{i + 1});

            const t0 = Io.Timestamp.now(io, .awake);
            const failed = try expectQuiet(ev, out, .{ .expr = expr, .want = want });
            sample.* = nsSince(io, t0) / std.time.ns_per_ms;
            if (failed != 0) {
                try out.print("{d} check(s) FAILED\n", .{failed});

                return;
            }
        }

        std.mem.sort(f64, samples, {}, std.sort.asc(f64));
        const at = struct {
            fn f(list: []const f64, q: f64) f64 {
                return list[@min(list.len - 1, @as(usize, @intFromFloat(q * @as(f64, @floatFromInt(list.len)))))];
            }
        }.f;
        var total: f64 = 0;
        for (samples) |sample| total += sample;
        try out.print("bench {d} evals of 1 + i (same-size rewrites)\n", .{count});
        try out.print("  mean {d:.2} ms   p50 {d:.2} ms   p99 {d:.2} ms   max {d:.2} ms\n", .{
            total / @as(f64, @floatFromInt(count)), at(samples, 0.50), at(samples, 0.99), samples[samples.len - 1],
        });

        return;
    }

    if (args.len > 1) {
        for (args[1..]) |expr| {
            const t0 = Io.Timestamp.now(io, .awake);
            // An expression whose output cannot be attributed is a *report*, not a crash: this
            // mode is what an editor drives, and a stack trace is not an answer it can show.
            const result = ev.eval(expr) catch |err| {
                try out.print("{s}\n  => error: {s}   ({d:.1} ms)\n", .{
                    expr,
                    switch (err) {
                        error.UnattributableResult => "the eval logged, so its value cannot be told apart from the log",
                        error.StaleResult => "the compiler served an earlier eval's result",
                        else => @errorName(err),
                    },
                    nsSince(io, t0) / std.time.ns_per_ms,
                });

                continue;
            };
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

test "an expression that logs is refused, not concatenated into a value" {
    const gpa = std.testing.allocator;
    var wip: ErrorBundle.Wip = undefined;
    try wip.init(gpa);
    defer wip.deinit();
    try wip.addRootErrorMessage(.{ .msg = try wip.addString(compile_log_msg) });

    // Three lines when two are ours: the nonce, a side-channel, and the value. This is the
    // shape a live `@compileLog` inside the expression produces, and the old `interpret`
    // returned the side-channel and the value joined as one string with no error.
    var bundle = try wip.toOwnedBundle("@as(u64, 7)\n\"side-channel\"\n@as(comptime_int, 1)\n");
    defer bundle.deinit(gpa);
    try std.testing.expectError(error.UnattributableResult, interpret(gpa, bundle, 7));

    // A prelude helper logging lands the same way, one line later.
    var wip2: ErrorBundle.Wip = undefined;
    try wip2.init(gpa);
    defer wip2.deinit();
    try wip2.addRootErrorMessage(.{ .msg = try wip2.addString(compile_log_msg) });
    var bundle2 = try wip2.toOwnedBundle("@as(u64, 8)\n@as(comptime_int, 2)\nhelper says hi\n");
    defer bundle2.deinit(gpa);
    try std.testing.expectError(error.UnattributableResult, interpret(gpa, bundle2, 8));
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
