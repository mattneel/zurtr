//! Evaluate a Zig expression at build time by asking the Zig compiler to print
//! it. The compiler is the interpreter; nothing here links or reimplements it.
//!
//! The mechanism, in full:
//!
//!  1. generate a root module holding the caller's declarations, then
//!     `comptime { @compileLog("zigeval:value", (<expression>)); }`, with the
//!     expression written on lines of its own so that its coordinates are the
//!     caller's own and a multiline string literal is still one token;
//!  2. run `zig build-obj -fno-emit-bin` on it;
//!  3. read the value back out of the compiler's own "Compile Log Output"
//!     section, which `@compileLog` renders through the compiler's value
//!     printer verbatim (`@as(u64, 6765)`, `@as([3]u8, "\x01\x02\x03".*)`, ...);
//!  4. report success only if that section contains our marker *and* the
//!     compiler reported no other error; everything else comes back as a
//!     `Failure` carrying the compiler's message and source location.
//!
//! The marker is a first argument to the same `@compileLog` call as the
//! expression, so the two are printed in one log entry and cannot be separated
//! by a declaration that happens to log something itself.
//!
//! Do not link this file into anything that ships. It shells out to `zig`; its
//! only purpose is to be built and run as a build-time tool:
//!
//!     zig run tools/zigeval.zig -- "1 + 1"
//!     zig test tools/zigeval.zig
//!
//! Pass the compiler explicitly, with `Options.zig_exe`: a build already has
//! the right value in `b.graph.zig_exe`. This is load-bearing rather than
//! tidiness. Where `zig` on PATH is a version-resolving launcher (mise, anyzig,
//! zvm), the launcher is spawned for every eval and the eval costs about five
//! times as much, and nothing fails or warns about it - see the numbers below.
//!
//! # Cost
//!
//! Measured with the compiler named explicitly, on the machine this was written
//! on (AMD Ryzen 9 9955HX3D, warm page cache, Zig 0.17.0-dev.2264+230c63650):
//!
//!   * one eval, from a clean cache: ~50ms of wall clock, almost all of it
//!     compiler process startup. Cold and warm differ by a few milliseconds,
//!     because the compiler's cache is not what the cost is made of;
//!   * ten evals in one process through one evaluator, again from a clean
//!     cache: 44.2, 43.6, 43.0, 43.5, 40.4, 42.3, 44.2, 52.4, 44.9, 43.7 ms,
//!     442ms in total. Fifty templates in a build step is a couple of seconds,
//!     not a minute, and it is a predictable couple of seconds;
//!   * the same eval with `zig` left to PATH on a machine whose `zig` is a
//!     mise/anyzig launcher: ~230ms, spent in the launcher, once per eval.
//!
//! A persistent client - the compiler's own `-fincremental --listen=-`
//! protocol, which `zig build` speaks - would take this to ~2-3ms per eval.
//! That is worth writing for a dev loop that evaluates as you edit, and not for
//! a build, where a process per template is already negligible next to the rest
//! of the build and does not depend on cache state.
//!
//! Constraints inherited from comptime, because comptime is what runs:
//! no I/O, no syscalls, no runtime state. Work is bounded by the eval branch
//! quota (`Options.branch_quota`), which the generated module raises for you.
//!
//! Pinned against Zig 0.17.0-dev.2264+230c63650. The fragile dependencies on
//! compiler behaviour are listed next to `log_header` and `marker` below.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Dir = Io.Dir;

/// First argument of the generated `@compileLog` call. The expression's value
/// follows it as the next argument of the same log entry, so a declaration that
/// logs something itself can never separate the two.
///
/// Depends on compiler behaviour: `@compileLog` prints its arguments through the
/// value printer, comma separated on one line, so the entry reads
/// `@as(*const [13:0]u8, "zigeval:value"), @as(u64, 6765)`. Caller
/// `declarations` must not contain `@compileLog` at all: every compile log
/// statement is an error in the generated module, and only this tool's own is
/// filtered back out of the diagnostics.
pub const marker = "zigeval:value";

/// Header line the compiler prints before `@compileLog` output. Searching for
/// it is what splits diagnostics from values.
///
/// Depends on compiler behaviour: with `-fno-emit-bin`, `@compileLog` is
/// reported as `error: found compile log statement` and the logged values are
/// appended under this header, on stderr, as one line per `@compileLog` call.
pub const log_header = "Compile Log Output:";

/// Base name of the generated root module.
///
/// Depends on compiler behaviour: anonymous struct literals evaluated in a
/// comptime block are named `<module-file-stem>.comptime__struct_N`, so an
/// expression using `.{ ... }` prints a type name derived from this. Keeping
/// the name fixed keeps that output stable between runs.
pub const root_basename = "zigeval.zig";

const compile_log_message = "found compile log statement";
const zig_cache_subdir = "cache";
const max_source_bytes = 1 << 20;

pub const Options = struct {
    /// Zig source placed in the generated module before the expression, for
    /// example a helper function. Must be a sequence of declarations, not
    /// statements. Borrowed, not copied: it must outlive the `Evaluator`.
    declarations: []const u8 = "",

    /// `@setEvalBranchQuota` for the generated module. Comptime's default of
    /// 1000 backwards branches is far too small for real expressions.
    branch_quota: u32 = 1_000_000,

    /// The Zig compiler to run.
    ///
    /// Pass it explicitly; a build already has the right value in
    /// `b.graph.zig_exe`. The default resolves `zig` through PATH, which on a
    /// machine where `zig` is a version-resolving launcher (mise, anyzig, zvm)
    /// means spawning that launcher for every eval: about five times the cost,
    /// with nothing failing to say so. The default is only there so a one-off
    /// run works out of the box.
    zig_exe: []const u8 = "zig",

    /// Directory to keep the generated root module in; created if missing, and
    /// may be relative to the current working directory. Absolute paths are
    /// treated as such. Borrowed, not copied: it must outlive the `Evaluator`.
    cache_dir: []const u8,

    /// Leave the scratch directory (generated module, compiler cache) in place
    /// when the evaluator is deinitialised, for a human who wants to read what
    /// the compiler was given. Off by default: cleanup is otherwise a single
    /// directory removal in `deinit`.
    keep_scratch_dir: bool = false,
};

/// Which text a `Location` refers to.
pub const Origin = enum {
    /// The caller's `Options.declarations`.
    declarations,
    /// The caller's expression.
    expression,
    /// Compiler scaffolding or a library file: not the caller's text.
    generated,
};

/// Where the compiler reported the primary error, in the coordinates of the
/// text the caller supplied, as if `declarations` and the expression had been
/// written one after the other: declarations occupy lines `1..n`, and the
/// expression starts on line `n + 1`.
pub const Location = struct {
    line: u32,
    column: u32,
    origin: Origin,
};

/// The compiler refused to produce a value.
pub const Failure = struct {
    /// The compiler's message for the primary error, e.g.
    /// `use of undeclared identifier 'nope'`.
    message: []const u8,
    /// `null` only if the compiler reported no error *and* printed no value,
    /// which means its output did not look like anything this tool knows.
    location: ?Location,
    /// The compiler's rendered diagnostics. The only changes are that the
    /// `found compile log statement` error belonging to the generated
    /// `@compileLog` call itself is removed, and the generated module's path is
    /// replaced by `zigeval.zig`, so this text does not depend on where the
    /// cache directory happens to be. When nothing could be parsed this is the
    /// compiler's raw stderr, so no output is ever swallowed.
    rendered: []const u8,
};

pub const Outcome = union(enum) {
    /// The expression's value, printed by the compiler's own value printer.
    value: []const u8,
    failed: Failure,
};

/// Evaluates expressions by running the Zig compiler over a generated module.
///
/// The strings in the returned `Outcome` are owned by the evaluator and stay
/// valid until the next call to `eval` or to `deinit`.
///
/// Not thread safe (it reuses one root module path per instance). Separate
/// instances are independent: each gets its own directory and its own
/// compiler cache.
pub const Evaluator = struct {
    allocator: Allocator,
    io: Io,
    options: Options,
    /// `<cache_dir>/<nonce>`: everything this evaluator writes lives here, so
    /// `deinit` cleans up deterministically with a single directory removal.
    scratch_path: [:0]u8,
    /// `<scratch_path>/zigeval.zig`.
    root_path: []u8,
    /// `<scratch_path>/cache`, the compiler's own cache directory, kept inside
    /// the scratch directory so the calling project's `.zig-cache` is never
    /// touched. Passed to the compiler as an absolute path because the child
    /// runs with the caller's working directory.
    compiler_cache_path: []u8,
    /// Backs the generated source and every string returned by `eval`.
    arena: std.heap.ArenaAllocator,
    /// Reused across evals, so an unchanged expression is not rewritten.
    root_source: Io.Writer.Allocating,

    pub fn init(allocator: Allocator, io: Io, options: Options) !Evaluator {
        std.debug.assert(options.cache_dir.len != 0);

        // A random suffix, not the pid: two evaluators in the same process, or
        // two processes, must never share a root module path.
        var nonce: [12]u8 = undefined;
        io.random(&nonce);
        var suffix: [std.base64.url_safe.Encoder.calcSize(nonce.len)]u8 = undefined;
        const suffix_slice = std.base64.url_safe.Encoder.encode(&suffix, &nonce);

        const relative_scratch = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
            options.cache_dir, std.fs.path.sep, suffix_slice,
        });
        defer allocator.free(relative_scratch);
        try Dir.cwd().createDirPath(io, relative_scratch);
        // Absolute from here on, so the compiler can be run without changing
        // its working directory: a `zig` front end found through PATH (mise,
        // anyzig) resolves its version from the caller's directory, and must
        // see the directory the caller is actually in.
        const scratch_path = try Dir.cwd().realPathFileAlloc(io, relative_scratch, allocator);
        errdefer allocator.free(scratch_path);
        const root_path = try std.fs.path.join(allocator, &.{ scratch_path, root_basename });
        errdefer allocator.free(root_path);
        const compiler_cache_path = try std.fs.path.join(allocator, &.{ scratch_path, zig_cache_subdir });
        errdefer allocator.free(compiler_cache_path);

        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .scratch_path = scratch_path,
            .root_path = root_path,
            .compiler_cache_path = compiler_cache_path,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .root_source = .init(allocator),
        };
    }

    pub fn deinit(self: *Evaluator) void {
        if (!self.options.keep_scratch_dir) {
            Dir.cwd().deleteTree(self.io, self.scratch_path) catch {};
        }
        self.root_source.deinit();
        self.arena.deinit();
        self.allocator.free(self.compiler_cache_path);
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.* = undefined;
    }

    /// Path of the generated root module. Rewritten only when the generated
    /// source changes, so repeated evals of one expression keep the file
    /// untouched. Useful for reading back what the compiler was given.
    pub fn rootPath(self: *const Evaluator) []const u8 {
        return self.root_path;
    }

    /// Evaluates `expression` and returns what the compiler printed for it.
    pub fn eval(self: *Evaluator, expression: []const u8) !Outcome {
        _ = self.arena.reset(.retain_capacity);
        const allocator = self.arena.allocator();

        const layout = try self.writeRoot(allocator, expression);

        // The compiler's own cache goes under the scratch directory too, so the
        // evaluator never touches the calling project's `.zig-cache`. The
        // working directory is deliberately left alone: `zig` may be a front
        // end that resolves which compiler to run from the current directory.
        const result = std.process.run(allocator, self.io, .{
            .argv = &.{
                self.options.zig_exe, "build-obj",
                "-fno-emit-bin",      "--color",
                "off",                "-freference-trace=0",
                "--cache-dir",        self.compiler_cache_path,
                self.root_path,
            },
        }) catch |err| switch (err) {
            error.FileNotFound => return error.ZigNotFound,
            else => |e| return e,
        };

        return interpret(allocator, result.stderr, layout);
    }

    const Layout = struct {
        /// 1-based line the caller's `declarations` start on, and how many
        /// lines they occupy. Zero when there are no declarations.
        decl_line: u32,
        decl_lines: u32,
        /// Line the generated `@compileLog` statement starts on.
        stmt_line: u32,
        /// Line the expression starts on. The expression is given its own
        /// lines, starting in column 1, so its coordinates need no adjusting
        /// and a multiline string literal is still a single token.
        expr_line: u32,
    };

    fn writeRoot(self: *Evaluator, allocator: Allocator, expression: []const u8) !Layout {
        const out = &self.root_source;
        out.clearRetainingCapacity();
        const w = &out.writer;

        try w.writeAll("// Generated by tools/zigeval.zig; rewritten on every eval. Do not edit.\n");
        try w.writeAll("const std = @import(\"std\");\n");

        var decl_line: u32 = 0;
        var decl_lines: u32 = 0;
        if (self.options.declarations.len != 0) {
            decl_line = lineIndexOfLast(w);
            try w.writeAll(self.options.declarations);
            if (self.options.declarations[self.options.declarations.len - 1] != '\n') try w.writeByte('\n');
            decl_lines = lineCount(self.options.declarations);
            try w.writeByte('\n');
        }

        try w.print("comptime {{\n    @setEvalBranchQuota({d});\n", .{self.options.branch_quota});
        // Line numbers are recorded from the buffer as it is written, so the
        // mapping in `locate` cannot drift away from what is generated.
        const stmt_line = lineIndexOfLast(w);
        try w.print("    @compileLog(\"{s}\", (\n", .{marker});
        const expr_line = lineIndexOfLast(w);
        try w.writeAll(expression);
        try w.writeAll("\n    ));\n}\n");

        const source = out.written();
        if (!try self.rootIsCurrent(allocator, source)) {
            try Dir.cwd().writeFile(self.io, .{ .sub_path = self.root_path, .data = source });
        }

        return .{
            .decl_line = decl_line,
            .decl_lines = decl_lines,
            .stmt_line = stmt_line,
            .expr_line = expr_line,
        };
    }

    fn rootIsCurrent(self: *Evaluator, allocator: Allocator, source: []const u8) !bool {
        const existing = Dir.cwd().readFileAlloc(
            self.io,
            self.root_path,
            allocator,
            .limited(max_source_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound, error.StreamTooLong => return false,
            else => |e| return e,
        };
        return std.mem.eql(u8, existing, source);
    }
};

/// 1-based number of the line currently being written.
fn lineIndexOfLast(w: *const Io.Writer) u32 {
    return @intCast(std.mem.countScalar(u8, w.buffered(), '\n') + 1);
}

fn lineCount(text: []const u8) u32 {
    return @intCast(std.mem.countScalar(u8, text, '\n') + 1);
}

const Diagnostic = struct {
    file: []const u8,
    line: u32,
    column: u32,
    kind: enum { @"error", warning, note },
    message: []const u8,
};

/// Parses the compiler's `<file>:<line>:<column>: <kind>: <message>` prefix.
fn parseDiagnostic(line: []const u8) ?Diagnostic {
    const markers = [_]struct { text: []const u8, kind: @FieldType(Diagnostic, "kind") }{
        .{ .text = ": error: ", .kind = .@"error" },
        .{ .text = ": warning: ", .kind = .warning },
        .{ .text = ": note: ", .kind = .note },
    };
    for (markers) |m| {
        const idx = std.mem.indexOf(u8, line, m.text) orelse continue;
        const where = line[0..idx];
        const col_sep = std.mem.lastIndexOfScalar(u8, where, ':') orelse continue;
        const line_sep = std.mem.lastIndexOfScalar(u8, where[0..col_sep], ':') orelse continue;
        return .{
            .file = where[0..line_sep],
            .line = std.fmt.parseInt(u32, where[line_sep + 1 .. col_sep], 10) catch continue,
            .column = std.fmt.parseInt(u32, where[col_sep + 1 ..], 10) catch continue,
            .kind = m.kind,
            .message = line[idx + m.text.len ..],
        };
    }
    return null;
}

fn interpret(allocator: Allocator, stderr: []const u8, layout: Evaluator.Layout) !Outcome {
    const sections = splitLogSection(stderr);
    const value = markerValue(sections.log);
    const diagnostics = try stripCompileLogError(allocator, sections.diagnostics, layout);
    const primary = primaryError(diagnostics);

    if (value) |v| {
        if (primary == null) return .{ .value = v };
    }
    // The raw stderr is kept whenever nothing parsed, so a change in the
    // compiler's rendering shows up as output rather than as silence.
    const raw = if (primary == null and value == null) stderr else diagnostics;
    return .{ .failed = .{
        .message = if (primary) |p| p.message else "compiler printed no value in its compile log",
        .location = if (primary) |p| locate(p, layout) else null,
        .rendered = try normalizePath(allocator, raw),
    } };
}

/// Rewrites the location prefix of diagnostics about the generated module so
/// they name it `zigeval.zig` instead of wherever the cache directory happens
/// to be. The compiler prints that path either absolutely or relative to its
/// own working directory, whichever is shorter, so the prefix is rebuilt from
/// the parsed location rather than matched as a string.
fn normalizePath(allocator: Allocator, text: []const u8) ![]const u8 {
    var rewritten: std.ArrayList(u8) = .empty;
    var rest = text;
    while (rest.len != 0) {
        const newline = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (newline) |i| rest[0..i] else rest;
        rest = if (newline) |i| rest[i + 1 ..] else rest[rest.len..];

        const diagnostic = parseDiagnostic(line);
        if (diagnostic) |d| {
            if (std.mem.eql(u8, std.fs.path.basename(d.file), root_basename)) {
                const rebuilt = try std.fmt.allocPrint(allocator, "{s}:{d}:{d}: {s}: {s}", .{
                    root_basename, d.line, d.column, @tagName(d.kind), d.message,
                });
                try rewritten.appendSlice(allocator, rebuilt);
                try rewritten.append(allocator, '\n');
                continue;
            }
        }
        try rewritten.appendSlice(allocator, line);
        try rewritten.append(allocator, '\n');
    }
    return std.mem.trimEnd(u8, rewritten.items, "\n");
}

const Sections = struct {
    /// Everything before the compile log section.
    diagnostics: []const u8,
    /// Everything after the `Compile Log Output:` line.
    log: []const u8,
};

fn splitLogSection(stderr: []const u8) Sections {
    var rest = stderr;
    while (rest.len != 0) {
        const newline = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (newline) |i| rest[0..i] else rest;
        if (std.mem.eql(u8, line, log_header)) {
            const diagnostics_len = stderr.len - rest.len;
            return .{
                .diagnostics = stderr[0..diagnostics_len],
                .log = if (newline) |i| rest[i + 1 ..] else "",
            };
        }
        const i = newline orelse break;
        rest = rest[i + 1 ..];
    }
    return .{ .diagnostics = stderr, .log = "" };
}

/// Value of the log entry carrying `marker`, i.e. what `@compileLog(expression)`
/// on its own would have printed.
fn markerValue(log: []const u8) ?[]const u8 {
    const quoted = "\"" ++ marker ++ "\"";
    var rest = log;
    while (rest.len != 0) {
        const newline = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (newline) |i| rest[0..i] else rest;
        if (std.mem.indexOf(u8, line, quoted)) |idx| {
            // The marker is itself printed through the value printer, as
            // `@as(*const [13:0]u8, "zigeval:value")`, so the next argument
            // follows the wrapper's closing parenthesis.
            const after = line[idx + quoted.len ..];
            const value = if (std.mem.startsWith(u8, after, "), "))
                after[3..]
            else if (std.mem.startsWith(u8, after, ", "))
                after[2..]
            else
                continue;
            return std.mem.trimEnd(u8, value, "\r");
        }
        const i = newline orelse break;
        rest = rest[i + 1 ..];
    }
    return null;
}

/// Drops the `found compile log statement` error for the generated
/// `@compileLog` call: it is an artifact of how values are extracted, not
/// something the caller did. The renderer follows that error with the offending
/// source line and a caret line.
///
/// The returned slice is owned by `allocator` (intentionally: the caller passes
/// an arena, and the slice outlives this function's `std.ArrayList` value).
fn stripCompileLogError(allocator: Allocator, diagnostics: []const u8, layout: Evaluator.Layout) ![]const u8 {
    var kept: std.ArrayList(u8) = .empty;
    var rest = diagnostics;
    var skip: u8 = 0;
    while (rest.len != 0) {
        const newline = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (newline) |i| rest[0..i] else rest;
        rest = if (newline) |i| rest[i + 1 ..] else rest[rest.len..];
        if (skip != 0) {
            skip -= 1;
            continue;
        }
        if (parseDiagnostic(line)) |d| {
            if (d.kind == .@"error" and
                d.line == layout.stmt_line and
                std.mem.eql(u8, d.message, compile_log_message))
            {
                skip = 2;
                continue;
            }
        }
        try kept.appendSlice(allocator, line);
        try kept.append(allocator, '\n');
    }
    return std.mem.trimEnd(u8, kept.items, "\n");
}

fn primaryError(diagnostics: []const u8) ?Diagnostic {
    var rest = diagnostics;
    while (rest.len != 0) {
        const newline = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (newline) |i| rest[0..i] else rest;
        if (parseDiagnostic(line)) |d| {
            if (d.kind == .@"error") return d;
        }
        const i = newline orelse break;
        rest = rest[i + 1 ..];
    }
    return null;
}

fn locate(d: Diagnostic, layout: Evaluator.Layout) Location {
    // Diagnostics name the generated module by whatever path was passed to the
    // compiler, which is absolute; only its base name is meaningful here.
    if (!std.mem.eql(u8, std.fs.path.basename(d.file), root_basename)) {
        return .{ .line = d.line, .column = d.column, .origin = .generated };
    }
    if (layout.decl_lines != 0 and
        d.line >= layout.decl_line and
        d.line < layout.decl_line + layout.decl_lines)
    {
        return .{
            .line = d.line - layout.decl_line + 1,
            .column = d.column,
            .origin = .declarations,
        };
    }
    if (d.line >= layout.expr_line) {
        return .{
            .line = layout.decl_lines + (d.line - layout.expr_line) + 1,
            .column = d.column,
            .origin = .expression,
        };
    }
    return .{ .line = d.line, .column = d.column, .origin = .generated };
}

// -- CLI ---------------------------------------------------------------------

const usage =
    \\zigeval: evaluate a Zig expression with the Zig compiler as the interpreter.
    \\
    \\Usage: zigeval [options] <expression>
    \\
    \\Options:
    \\  --declare <src>      Zig declarations to place before the expression
    \\  --quota <n>          @setEvalBranchQuota for the generated module (1000000)
    \\  --zig <path>         Zig compiler, and worth passing: default $ZIGEVAL_ZIG,
    \\                       then $ZIG, then PATH
    \\  --cache-dir <path>   where to keep the generated module; default
    \\                       $ZIGEVAL_CACHE_DIR, then $XDG_CACHE_HOME/zigeval, then
    \\                       $HOME/.cache/zigeval, then $TMPDIR/zigeval
    \\  --repeat <n>         evaluate n times, reporting each eval's wall-clock cost
    \\  --keep-root          keep the generated module and report where it is
    \\  -h, --help           show this help
    \\
    \\The value is printed to stdout exactly as the compiler prints it, e.g.
    \\`@as(u64, 6765)`; diagnostics go to stderr and the exit status is 1.
    \\
    \\Pass the compiler. Where `zig` on PATH is a version-resolving launcher
    \\(mise, anyzig, zvm) it is spawned for every eval, which costs about five
    \\times the eval itself, silently. A build should pass b.graph.zig_exe.
    \\
;

const Cli = struct {
    expression: []const u8 = "",
    declarations: []const u8 = "",
    cache_dir: ?[]const u8 = null,
    zig_exe: ?[]const u8 = null,
    branch_quota: u32 = 1_000_000,
    repeat: u32 = 1,
    keep_root: bool = false,
    help: bool = false,
};

const UsageError = error{Usage};

fn optionValue(args: []const [:0]const u8, i: *usize, name: []const u8) UsageError![]const u8 {
    i.* += 1;
    if (i.* >= args.len) {
        std.debug.print("zigeval: {s} needs a value\n", .{name});
        return error.Usage;
    }
    return args[i.*];
}

fn optionInt(comptime T: type, args: []const [:0]const u8, i: *usize, name: []const u8) UsageError!T {
    const text = try optionValue(args, i, name);
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("zigeval: {s} expects an integer, got '{s}'\n", .{ name, text });
        return error.Usage;
    };
}

fn parseArgs(args: []const [:0]const u8) UsageError!Cli {
    var cli: Cli = .{};
    var have_expression = false;
    var options_ended = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!options_ended and arg.len > 1 and arg[0] == '-') {
            // A bare separator ends option parsing. `zig run` passes one
            // through to the program, and it is also how an expression such as
            // `-1`, which starts with a dash, is written unambiguously.
            if (std.mem.eql(u8, arg, "--")) {
                options_ended = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                cli.help = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--declare")) {
                cli.declarations = try optionValue(args, &i, arg);
                continue;
            }
            if (std.mem.eql(u8, arg, "--cache-dir")) {
                cli.cache_dir = try optionValue(args, &i, arg);
                continue;
            }
            if (std.mem.eql(u8, arg, "--zig")) {
                cli.zig_exe = try optionValue(args, &i, arg);
                continue;
            }
            if (std.mem.eql(u8, arg, "--quota")) {
                cli.branch_quota = try optionInt(u32, args, &i, arg);
                continue;
            }
            if (std.mem.eql(u8, arg, "--repeat")) {
                cli.repeat = try optionInt(u32, args, &i, arg);
                if (cli.repeat == 0) {
                    std.debug.print("zigeval: --repeat must be at least 1\n", .{});
                    return error.Usage;
                }
                continue;
            }
            if (std.mem.eql(u8, arg, "--keep-root")) {
                cli.keep_root = true;
                continue;
            }
            std.debug.print("zigeval: unknown option '{s}'\n", .{arg});
            return error.Usage;
        }

        if (have_expression) {
            std.debug.print("zigeval: expected one expression, got a second: '{s}'\n", .{arg});
            return error.Usage;
        }
        cli.expression = arg;
        have_expression = true;
    }
    if (!cli.help and !have_expression) {
        std.debug.print("zigeval: missing expression\n", .{});
        return error.Usage;
    }
    return cli;
}

fn defaultCacheDir(allocator: Allocator, environ: *const std.process.Environ.Map) ![]const u8 {
    if (environ.get("ZIGEVAL_CACHE_DIR")) |dir| {
        if (dir.len != 0) return dir;
    }
    if (environ.get("XDG_CACHE_HOME")) |dir| {
        if (dir.len != 0) return std.fs.path.join(allocator, &.{ dir, "zigeval" });
    }
    if (environ.get("HOME")) |dir| {
        if (dir.len != 0) return std.fs.path.join(allocator, &.{ dir, ".cache", "zigeval" });
    }
    const tmp = environ.get("TMPDIR") orelse "/tmp";
    return std.fs.path.join(allocator, &.{ tmp, "zigeval" });
}

/// Resolves the compiler the way the environment asks for it, so the tool uses
/// whatever Zig the surrounding build already picked.
fn defaultZigExe(environ: *const std.process.Environ.Map) []const u8 {
    for ([_][]const u8{ "ZIGEVAL_ZIG", "ZIG" }) |key| {
        if (environ.get(key)) |exe| {
            if (exe.len != 0) return exe;
        }
    }
    return "zig";
}

pub fn main(init: std.process.Init) u8 {
    const io = init.io;
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const code = run(init, stderr) catch |err| blk: {
        stderr.print("zigeval: {s}\n", .{@errorName(err)}) catch {};
        break :blk 2;
    };
    stderr.flush() catch {};
    return code;
}

fn run(init: std.process.Init, stderr: *Io.Writer) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    const cli = parseArgs(args) catch return 2;
    if (cli.help) {
        var stdout_buffer: [usage.len]u8 = undefined;
        var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
        try stdout_writer.interface.writeAll(usage);
        try stdout_writer.interface.flush();
        return 0;
    }

    const cache_dir = cli.cache_dir orelse try defaultCacheDir(arena, init.environ_map);
    const zig_exe = cli.zig_exe orelse defaultZigExe(init.environ_map);

    var evaluator = try Evaluator.init(init.gpa, io, .{
        .declarations = cli.declarations,
        .branch_quota = cli.branch_quota,
        .zig_exe = zig_exe,
        .cache_dir = cache_dir,
        .keep_scratch_dir = cli.keep_root,
    });
    defer evaluator.deinit();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var total: i96 = 0;
    var i: u32 = 0;
    while (i < cli.repeat) : (i += 1) {
        const started = Io.Clock.Timestamp.now(io, .real);
        const outcome = try evaluator.eval(cli.expression);
        const elapsed = started.untilNow(io);

        switch (outcome) {
            .value => |value| {
                try stdout.print("{s}\n", .{value});
                try stdout.flush();
            },
            .failed => |failure| {
                try stderr.print("zigeval: the expression did not compile\n", .{});
                if (failure.rendered.len != 0) {
                    try stderr.print("{s}\n", .{failure.rendered});
                } else {
                    try stderr.print("zigeval: {s}\n", .{failure.message});
                }
                if (failure.location) |loc| {
                    try stderr.print("zigeval: at {s} line {d}, column {d}\n", .{
                        @tagName(loc.origin), loc.line, loc.column,
                    });
                }
                if (cli.keep_root) try stderr.print("zigeval: generated root kept at {s}\n", .{evaluator.rootPath()});
                return 1;
            },
        }

        total += elapsed.raw.toNanoseconds();
        if (cli.repeat > 1) {
            try stderr.print("zigeval: eval {d}/{d} in {d} ns\n", .{ i + 1, cli.repeat, elapsed.raw.toNanoseconds() });
            try stderr.flush();
        }
    }

    if (cli.repeat > 1) {
        try stderr.print("zigeval: {d} evals in {d} ns\n", .{ cli.repeat, total });
        try stderr.flush();
    }

    if (cli.keep_root) try stderr.print("zigeval: generated root kept at {s}\n", .{evaluator.rootPath()});
    return 0;
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

/// One evaluator plus the temporary directory holding its cache.
const Harness = struct {
    tmp: testing.TmpDir,
    cache_dir: []u8,
    evaluator: Evaluator,

    fn init(declarations: []const u8) !Harness {
        const io = testing.io;
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &path_buffer);
        const cache_dir = try testing.allocator.dupe(u8, path_buffer[0..len]);
        errdefer testing.allocator.free(cache_dir);

        return .{
            .tmp = tmp,
            .cache_dir = cache_dir,
            .evaluator = try Evaluator.init(testing.allocator, io, .{
                .declarations = declarations,
                .cache_dir = cache_dir,
            }),
        };
    }

    fn deinit(self: *Harness) void {
        self.evaluator.deinit();
        testing.allocator.free(self.cache_dir);
        self.tmp.cleanup();
    }
};

test "values come back as the compiler's printer spells them" {
    var h = try Harness.init(
        \\fn fib(n: u64) u64 {
        \\    return if (n < 2) n else fib(n - 1) + fib(n - 2);
        \\}
    );
    defer h.deinit();

    // An integer. 6765 is fib(20), so this also proves the declarations above
    // were in scope and that the branch quota is high enough to compute it.
    try testing.expectEqualStrings("@as(u64, 6765)", (try h.evaluator.eval("fib(20)")).value);

    // An array, which the printer renders as a string when it can.
    try testing.expectEqualStrings(
        "@as([3]u8, \"\\x01\\x02\\x03\".*)",
        (try h.evaluator.eval("@as([3]u8, .{ 1, 2, 3 })")).value,
    );

    // A struct, whose anonymous type name is derived from the generated root
    // module's file stem.
    try testing.expectEqualStrings(
        "@as(zigeval.comptime__struct_0, .{ .x = 1.5, .ok = true })",
        (try h.evaluator.eval(".{ .x = 1.5, .ok = true }")).value,
    );

    // Comptime's own errors surface unchanged.
    try testing.expectEqualStrings(
        "@as(comptime_int, 6)",
        (try h.evaluator.eval("blk: { break :blk 6; }")).value,
    );

    // A multiline string literal is a single token spanning lines, which is
    // only true because the expression is generated on lines of its own.
    try testing.expectEqualStrings(
        "@as(*const [10:0]u8, \"alpha\\nbeta\")",
        (try h.evaluator.eval("\\\\alpha\n\\\\beta")).value,
    );
}

test "a bad expression reports the compiler's message and location" {
    var h = try Harness.init("");
    defer h.deinit();

    const outcome = try h.evaluator.eval("nosuch_identifier + 1");
    const failure = outcome.failed;
    try testing.expectEqualStrings("use of undeclared identifier 'nosuch_identifier'", failure.message);
    const location = failure.location.?;
    try testing.expectEqual(Origin.expression, location.origin);
    // Relative to the expression the caller wrote, not to the generated file.
    try testing.expectEqual(1, location.line);
    try testing.expectEqual(1, location.column);
    // Asserted as a suffix: a `zig` front end such as mise's may print lines of
    // its own to stderr, and those are kept rather than swallowed.
    try testing.expect(std.mem.endsWith(u8, failure.rendered,
        \\zigeval.zig:6:1: error: use of undeclared identifier 'nosuch_identifier'
        \\nosuch_identifier + 1
        \\^~~~~~~~~~~~~~~~~
    ));
}

test "an error in the caller's declarations is located there" {
    var h = try Harness.init("const bad: u32 = \"nope\";");
    defer h.deinit();

    const failure = (try h.evaluator.eval("bad")).failed;
    try testing.expectEqualStrings("expected type 'u32', found '*const [4:0]u8'", failure.message);
    const location = failure.location.?;
    try testing.expectEqual(Origin.declarations, location.origin);
    try testing.expectEqual(1, location.line);
    try testing.expect(std.mem.endsWith(u8, failure.rendered,
        \\zigeval.zig:3:18: error: expected type 'u32', found '*const [4:0]u8'
        \\const bad: u32 = "nope";
        \\                 ^~~~~~
    ));
}

test "a repeated expression does not rewrite the root module" {
    var h = try Harness.init("");
    defer h.deinit();

    try testing.expectEqualStrings("@as(comptime_int, 2)", (try h.evaluator.eval("1 + 1")).value);

    const io = testing.io;
    const path = h.evaluator.rootPath();
    const before = try Dir.cwd().statFile(io, path, .{});

    // Long enough that a rewrite cannot produce an identical mtime.
    try Io.sleep(io, .fromMilliseconds(10), .awake);
    try testing.expectEqualStrings("@as(comptime_int, 2)", (try h.evaluator.eval("1 + 1")).value);

    const after = try Dir.cwd().statFile(io, path, .{});
    try testing.expectEqual(before.mtime.nanoseconds, after.mtime.nanoseconds);
}

test "the evaluator is not reachable from the shipped library" {
    // The module doc says this file must not be linked into anything that
    // ships. build.zig is off limits for this change, so the build graph cannot
    // be inspected; what can be checked is the thing that would make it
    // linkable, namely any reference to the tool from the library or the build.
    const io = testing.io;
    const src_dir = std.fs.path.dirname(@src().file) orelse ".";
    const root = if (std.fs.path.isAbsolute(src_dir))
        std.fs.path.dirname(src_dir).?
    else
        ".";

    const library = try std.fs.path.join(testing.allocator, &.{ root, "src" });
    defer testing.allocator.free(library);

    var offenders: std.ArrayList(u8) = .empty;
    defer offenders.deinit(testing.allocator);

    var dir = Dir.cwd().openDir(io, library, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return, // not run from the repository
        else => |e| return e,
    };
    defer dir.close(io);

    var walker = try dir.walk(testing.allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const source = try entry.dir.readFileAlloc(
            io,
            entry.basename,
            testing.allocator,
            .limited(max_source_bytes),
        );
        defer testing.allocator.free(source);
        if (std.mem.indexOf(u8, source, "zigeval") != null) {
            try offenders.appendSlice(testing.allocator, entry.path);
            try offenders.append(testing.allocator, '\n');
        }
    }

    if (offenders.items.len != 0) {
        std.debug.print("zigeval must not be referenced by the library:\n{s}", .{offenders.items});
        return error.EvaluatorLinkedIntoLibrary;
    }
}
