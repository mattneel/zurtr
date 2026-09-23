//! zeex-live: lower a JSX template and show what the compiler produced, on every save.
//!
//!   zig build zeex-live -Dzscript=true -- path/to/template.jsx           watch
//!   zig build zeex-live -Dzscript=true -- --once path/to/template.jsx    one pass, then exit
//!
//! This is the first half of the live editor: the feedback loop that turns a keystroke into
//! "here is the Zig your template lowered to, or here is the line it rejected". The second
//! half — evaluating the lowered expression and showing a value — is what the persistent
//! `zigeval_listen` client exists for, and it is not wired in here yet.
//!
//! Two things carried over from the evaluator, because both cost an afternoon to learn:
//!
//!  - **The engine's first call is expensive, so it happens at startup.** One representative
//!    template is lowered before the first file is read and its cost is reported, so the
//!    first keystroke never pays it. (Measured: the first lowering is ~10x a steady one.)
//!  - **Changes are detected by content, not by metadata.** The compiler's incremental mode
//!    taught us that size/mtime/inode comparisons serve stale results; a template editor that
//!    did the same would show you the previous render of the line you just fixed.

const std = @import("std");
const zurtr = @import("zurtr");

/// Lowered once at startup to warm the engine. Deliberately small: it only has to be a
/// template the transform walks end to end — an element, an interpolation, a conditional.
const warm_up_template =
    \\<div class="warm">
    \\  <h1>{props.title}</h1>
    \\  {props.show && <p>{props.body}</p>}
    \\</div>
;

const Options = struct {
    path: []const u8,
    once: bool = false,
    interval_ms: u64 = 250,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var out_buffer: [8192]u8 = undefined;
    var out_writer = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const out = &out_writer.interface;
    defer out.flush() catch {};

    const options = parseOptions(args) catch {
        try out.writeAll(
            \\usage: zeex-live [--once] <template.jsx>
            \\
        );

        return;
    };

    // Warm-up (see the header): pay the engine's first call here, and say what it cost.
    {
        const started = std.Io.Timestamp.now(io, .awake);
        const warm = zurtr.zeex.compile_template(gpa, warm_up_template) catch |err| {
            try out.print("zeex-live: the warm-up template failed to lower: {s}\n", .{@errorName(err)});

            return err;
        };
        defer gpa.free(warm);

        try out.print("warm-up lowering {d:.1} ms\n", .{msSince(io, started)});
        try out.flush();
    }

    lower(gpa, io, out, options.path) catch |err| {
        try out.print("zeex-live: {s}\n", .{@errorName(err)});
        // `--once` is the scriptable mode: a file it cannot read is an exit code, not a loop.
        if (options.once) return err;
        try out.writeAll("watching anyway; the next save will be tried\n");
    };

    if (options.once) return;

    try out.print("watching {s} (content changes, not mtimes)\n", .{options.path});
    try out.flush();

    // Seeded with the content already lowered above, or the first poll would report the
    // unchanged file a second time.
    var last: ?u64 = hashFile(gpa, io, options.path) catch null;
    while (true) {
        const digest = hashFile(gpa, io, options.path) catch null;
        if (digest) |now| {
            if (now != last.?) {
                last = now;
                // In the loop a rejection is normal — you are mid-keystroke — so it is
                // reported and the loop continues.
                lower(gpa, io, out, options.path) catch {};
            }
        }
        std.Io.sleep(io, .fromMilliseconds(@intCast(options.interval_ms)), .awake) catch {};
    }
}

fn parseOptions(args: []const [:0]const u8) !Options {
    var options: Options = .{ .path = "" };
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--once")) {
            options.once = true;
        } else if (std.mem.startsWith(u8, arg, "--interval=")) {
            options.interval_ms = try std.fmt.parseInt(u64, arg["--interval=".len..], 10);
        } else if (options.path.len == 0) {
            options.path = arg;
        } else {
            return error.UnusedArgument;
        }
    }
    if (options.path.len == 0) return error.MissingPath;

    return options;
}

/// Reads the template, lowers it, and reports the result: the errors, or the generated Zig.
fn lower(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, path: []const u8) !void {
    const source = try readFile(gpa, io, path);
    defer gpa.free(source);

    const started = std.Io.Timestamp.now(io, .awake);
    const generated = zurtr.zeex.compile_template(gpa, source) catch |err| {
        // The transform prints its own message with the template's line number before this
        // error is returned, so the useful part is already on stderr.
        try out.print("{s}: rejected ({s}) at {d:.1} ms\n", .{ path, @errorName(err), msSince(io, started) });

        // Propagate rather than swallow: a template the compiler refused is a failure in
        // `--once`, which is the mode a script or a pre-commit check would drive. A loop that
        // kept the exit code would be a check that cannot fail.
        return err;
    };
    defer gpa.free(generated);

    const elapsed = msSince(io, started);

    // Syntax is not the whole contract: `std.zig.Ast` is the compiler's own parser, and a
    // generated file that parses can still name something that does not exist. Say both.
    var ast = try std.zig.Ast.parse(gpa, generated, .{ .mode = .zig });
    defer ast.deinit(gpa);
    if (ast.errors.len != 0) {
        try out.print("{s}: generated {d} bytes, {d} parse error(s)\n", .{ path, generated.len, ast.errors.len });
        try out.print("{s}\n", .{generated});

        return;
    }

    try out.print("{s}: {d} bytes of Zig, parses clean ({d:.1} ms)\n", .{ path, generated.len, elapsed });
    try out.print("{s}\n", .{generated});

    // A watch loop never returns, so a deferred flush would never run: every report is
    // flushed as it is produced. Without this the tool prints nothing at all in the mode
    // it exists for, which is exactly what happened the first time it was started.
    try out.flush();
}

/// The change detector: a digest of the *content*. Metadata is what the compiler's
/// incremental mode compares, and it is how a same-size rewrite inside one timestamp tick
/// gets served the previous answer — the exact failure this tool exists to make visible.
fn hashFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !u64 {
    const source = try readFile(gpa, io, path);
    defer gpa.free(source);

    return std.hash.Wyhash.hash(0, source);
}

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(16 * 1024 * 1024));
}

fn msSince(io: std.Io, started: std.Io.Timestamp) f64 {
    return @as(f64, @floatFromInt(started.untilNow(io, .awake).toNanoseconds())) / std.time.ns_per_ms;
}

test "the warm-up template lowers to the generated shape" {
    const gpa = std.testing.allocator;
    const generated = try zurtr.zeex.compile_template(gpa, warm_up_template);
    defer gpa.free(generated);

    // The two names ZEEX depends on, asserted on real output rather than on the emitter's
    // source: `props: anytype` at the call site, and the render-tree Builder in the signature.
    try std.testing.expect(std.mem.indexOf(u8, generated, "pub fn render(props: anytype") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "zurtr.live.tree.Builder") != null);
}
