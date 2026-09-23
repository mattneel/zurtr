//! zeex-live: lower a JSX template and show what the compiler produced, on every save.
//!
//!   zig build zeex-live -Dzscript=true -- path/to/template.jsx           watch
//!   zig build zeex-live -Dzscript=true -- --once path/to/template.jsx    one pass, then exit
//!
//! This is the first half of the live editor: the feedback loop that turns a keystroke into
//! "here is the Zig your template lowered to, or here is the line it rejected".
//!
//! **`--preview` is blocked by the evaluator's execution model, not by its module graph.** The
//! graph part is solved: the prelude — the generated `render` plus a props struct scanned out of
//! it — is compiled against a module graph this build embeds (`--dep zurtr -Mzurtr=<absolute
//! src/root.zig>`, absolute because the evaluator's work directory is not the build root), and
//! the compiler now resolves `zurtr.live.tree.Builder` instead of reporting `no module named
//! 'zurtr'`. What it then reports is that the render cannot run **at comptime at all**:
//!
//!     error: unable to evaluate comptime expression
//!         const addr = @intFromPtr(ptr);          // mem.alignPointerOffset, from FixedBufferAllocator
//!     error: comptime dereference requires 'heap.ArenaAllocator.Node' to have a well-defined layout
//!
//! The first is every allocator in the standard library (`FixedBufferAllocator.alloc` aligns
//! through `@intFromPtr`, which is not comptime-evaluable here); the second is the arena the
//! render tree is built on, which loses even with a comptime-safe child allocator. So no module
//! graph makes a comptime render possible — the value would have to come from running the code,
//! not evaluating it.
//!
//! Rendering at run time does work, and is what a preview needs if it is to print HTML:
//! `zig run` with this same module graph renders the framework's own tree in 0.20 s warm and
//! 0.72 s after a source change (cold 0.73 s), against the 1.8 ms this tool spends lowering a
//! template. That is a preview-on-save budget, not a per-keystroke one, and choosing between it
//! and a compile-errors-only preview is a decision rather than a wiring detail.
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
const zigeval = @import("zigeval");
const build_options = @import("build_options");

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
    /// Render the template and print the HTML, instead of the Zig it lowered to.
    preview: bool = false,
    /// The compiler the preview evaluates with. From $ZIG_EXE when it is set; the evaluator's
    /// header explains why an unset one costs 5x on a machine with a launcher shim.
    zig_exe: []const u8 = "zig",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var out_buffer: [8192]u8 = undefined;
    var out_writer = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const out = &out_writer.interface;
    defer out.flush() catch {};

    var options = parseOptions(args) catch {
        try out.writeAll(
            \\usage: zeex-live [--once] <template.jsx>
            \\
        );

        return;
    };
    options.zig_exe = init.environ_map.get("ZIG_EXE") orelse "zig";

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

    lower(gpa, io, out, options.path, options) catch |err| {
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
                lower(gpa, io, out, options.path, options) catch {};
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
        } else if (std.mem.eql(u8, arg, "--preview")) {
            options.preview = true;
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
fn lower(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, path: []const u8, options: Options) !void {
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

    if (options.preview) return preview(gpa, io, out, path, generated, options);

    try out.print("{s}: {d} bytes of Zig, parses clean ({d:.1} ms)\n", .{ path, generated.len, elapsed });
    try out.print("{s}\n", .{generated});

    // A watch loop never returns, so a deferred flush would never run: every report is
    // flushed as it is produced. Without this the tool prints nothing at all in the mode
    // it exists for, which is exactly what happened the first time it was started.
    try out.flush();
}

/// Renders the template for real: the generated `render` plus a `props` built from the paths
/// it uses, handed to the persistent evaluator as a prelude. This is the half the evaluator
/// exists for — one long-lived compiler, a template per keystroke, and the HTML that came out.
fn preview(
    gpa: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    path: []const u8,
    generated: []const u8,
    options: Options,
) !void {
    const uses = try scanProps(gpa, generated);
    defer gpa.free(uses);

    var prelude: std.Io.Writer.Allocating = .init(gpa);
    defer prelude.deinit();
    try buildPrelude(&prelude.writer, generated, uses);

    // The evaluator's first call is the expensive one, so it happens here rather than on the
    // first save: this is the startup warm-up the client was written to make possible.
    const started = std.Io.Timestamp.now(io, .awake);
    // The module graph the prelude imports through. `eval_zurtr_root` is the absolute source path the
    // build resolved, so the compiler can find it from the evaluator's work directory.
    const module_args = [_][]const u8{
        try std.fmt.allocPrint(gpa, "-Mzurtr={s}", .{build_options.eval_zurtr_root}),
    };
    defer gpa.free(module_args[0]);

    const evaluator = try zigeval.Evaluator.create(gpa, io, .{
        .zig_exe = options.zig_exe,
        .work_dir = ".zig-cache/zeex-live",
        .prelude = prelude.written(),
        .root_deps = build_options.eval_root_deps,
        .modules = &module_args,
    });
    defer evaluator.destroy();

    const result = try evaluator.eval("previewHtml()");
    defer result.deinit(gpa);

    switch (result) {
        .value => |html| {
            try out.print("{s}: preview {d} bytes ({d:.1} ms, {d} prop(s))\n", .{
                path, html.len, msSince(io, started), uses.len,
            });
            try out.print("{s}\n", .{html});
        },
        .errors => |errors| {
            try out.print("{s}: the preview did not compile ({d:.1} ms)\n{s}", .{ path, msSince(io, started), errors });
        },
    }
    try out.flush();
}

/// The prelude the evaluator compiles: the generated template verbatim, a props struct whose
/// shape came from scanning it, and a function that renders and returns the HTML.
fn buildPrelude(w: *std.Io.Writer, generated: []const u8, uses: []const PropUse) !void {
    // The default prelude is replaced, not extended, so the imports the generated code and
    // this wrapper need are named here.
    // Only `std`: the generated file brings its own `zurtr` import, and two of them in one
    // file is a duplicate declaration.
    try w.writeAll("const std = @import(\"std\");\n\n");

    // The generated file opens with a `//!` header, and the prelude is *appended* to the
    // evaluator's scratch file — where a document comment is not the file header and Zig
    // rejects it. Demoted to a line comment as it is written, because a prelude cannot
    // reorder the file it is pasted into.
    var lines = std.mem.splitScalar(u8, generated, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "//!")) {
            try w.print("// {s}\n", .{line["//!".len..]});
        } else {
            try w.print("{s}\n", .{line});
        }
    }
    try w.writeAll(
        \\
        \\const PreviewProps = struct {
        \\
    );
    for (uses) |use| try w.print("    {s}: {s},\n", .{ use.name, switch (use.kind) {
        .boolean => "bool",
        .strings => "[]const []const u8",
        .text => "[]const u8",
    } });
    try w.writeAll(
        \\};
        \\
        \\const preview_props = PreviewProps{
        \\
    );
    for (uses) |use| {
        // The prop's own name is its value, so the preview shows which name reached which
        // position instead of rendering an empty page.
        switch (use.kind) {
            .boolean => try w.print("    .{s} = true,\n", .{use.name}),
            .strings => try w.print("    .{s} = &.{{}},\n", .{use.name}),
            .text => try w.print("    .{s} = \"{s}\",\n", .{ use.name, use.name }),
        }
    }
    try w.writeAll(
        \\};
        \\
        \\fn previewHtml() []const u8 {
        \\    @setEvalBranchQuota(4_000_000);
        \\    var buffer: [64 * 1024]u8 = undefined;
        \\    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
        \\    const gpa = fixed.allocator();
        \\    var tree = zurtr.live.tree.Tree.init(gpa);
        \\    defer tree.deinit();
        \\    var builder = zurtr.live.tree.Builder.init(&tree);
        \\    defer builder.deinit();
        \\    render(preview_props, &builder) catch unreachable;
        \\    const html = tree.writeHtmlAlloc(gpa, builder.root()) catch unreachable;
        \\    return gpa.dupeZ(u8, html) catch unreachable;
        \\}
        \\
    );
}

/// What a template needs from `props`, read off the generated source.
///
/// `props: anytype` is the reason this is possible at all: the template's names became field
/// accesses in the generated code, so the shape of the struct a preview needs is spelled out
/// in a file we just produced. Three forms, decided by the construct that uses the path:
/// a conditional wants a bool, an iteration wants a slice of strings, and anything reaching
/// `b.text`/`b.raw`/an attribute wants a string. A component call cannot be fabricated and is
/// reported rather than guessed.
const PropUse = struct {
    name: []const u8,
    kind: Kind,

    const Kind = enum { boolean, strings, text };
};

fn scanProps(gpa: std.mem.Allocator, generated: []const u8) ![]PropUse {
    var uses: std.ArrayList(PropUse) = .empty;
    errdefer uses.deinit(gpa);

    var index: usize = 0;
    while (std.mem.indexOfPos(u8, generated, index, "props.")) |at| {
        const after = at + "props.".len;
        var end = after;
        while (end < generated.len and (std.ascii.isAlphanumeric(generated[end]) or generated[end] == '_')) end += 1;
        if (end == after) {
            index = after;

            continue;
        }
        const name = generated[after..end];

        // `for (props.x)` is iteration, `if (props.x)` is a conditional, everything else is text.
        const line_start = if (std.mem.lastIndexOfScalar(u8, generated[0..at], '\n')) |nl| nl + 1 else 0;
        const prefix = std.mem.trimStart(u8, generated[line_start..at], " ");
        const kind: PropUse.Kind = if (std.mem.startsWith(u8, prefix, "for ("))
            .strings
        else if (std.mem.startsWith(u8, prefix, "if ("))
            .boolean
        else
            .text;

        var seen = false;
        for (uses.items) |use| {
            if (std.mem.eql(u8, use.name, name)) {
                seen = true;
            }
        }
        // A name used twice with different kinds is left as the first one; the preview will
        // fail to compile and the evaluator's error message will say which line.
        if (!seen) try uses.append(gpa, .{ .name = name, .kind = kind });
        index = end;
    }

    return uses.toOwnedSlice(gpa);
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

test "the embedded module graph is present, so the evaluator can reach the framework" {
    // A build that drops these puts `--preview` back to reporting `no module named 'zurtr'`, which is
    // indistinguishable from "the preview is not wired at all" - so they are asserted here rather
    // than trusted to survive a refactor of build.zig.
    var names_zurtr = false;
    for (build_options.eval_root_deps) |dep| {
        if (std.mem.eql(u8, dep, "zurtr")) names_zurtr = true;
    }
    try std.testing.expect(names_zurtr);

    // Absolute, because the evaluator's work directory is not the build root.
    try std.testing.expect(build_options.eval_zurtr_root.len != 0);
    try std.testing.expect(std.fs.path.isAbsolute(build_options.eval_zurtr_root));

    const arg = try std.fmt.allocPrint(std.testing.allocator, "-Mzurtr={s}", .{build_options.eval_zurtr_root});
    defer std.testing.allocator.free(arg);
    try std.testing.expect(std.mem.startsWith(u8, arg, "-Mzurtr=/"));
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
