//! The project generator's template engine.
//!
//! `zurtr new` renders a couple of dozen files from `src/scaffold/templates`, and the templates are
//! nearly source, so the language here is deliberately small: `{{name}}` substitutes a value, and
//! `{{#if flag}}`/`{{#unless flag}}` include or drop a block. Everything else is text.
//!
//! What the engine does with a mistake is the point of it. A generator that answers `{{typo}}` with
//! an empty string writes `pub const app_name = "";` into a project that otherwise looks finished,
//! and its user finds out inside generated code, at the first build, with nothing pointing back at
//! the template. So a name nothing binds is an error, a flag written as a substitution is an error,
//! a value written as a condition is an error, and each of them is reported with the line and the
//! tag it was found on — the reader just typed `zurtr new` and has never seen the template.
//!
//! Two properties the scanner keeps, both of which a later simplification could quietly break:
//!
//! * **A substituted value is never scanned.** `{{name}}` writes the value's bytes and moves on, so
//!   a project named `{{weird}}` generates code that says `{{weird}}`; no part of a value can open a
//!   block, end a tag early, or become a name.
//! * **Text is copied, never escaped.** A template with no placeholders yields its source byte for
//!   byte, including bytes that are not text at all.
//!
//! Rendering is one pass over the source into one allocating writer: no string per substitution, no
//! intermediate output, and no allocation besides the result's own buffer.

const std = @import("std");

const testing = std.testing;

/// Every way a render can fail.
///
/// The names are for the caller's `switch`. The detail — which name, which line — travels in
/// `Diagnostic` instead, because an error set cannot carry a payload and `error.UnknownName` on its
/// own is not something a caller can turn into a sentence for the user.
pub const Error = error{
    /// A flag was substituted: `{{data}}`. A flag is a condition, never text.
    FlagSubstituted,
    /// The tag's contents are not one of the five forms: a name, `#if <flag>`, `#unless <flag>`,
    /// `/if`, `/unless`.
    MalformedTag,
    /// A close tag for the other directive: `{{#if live}}` ended by `{{/unless}}`.
    MismatchedBlock,
    /// The template nests blocks deeper than `max_depth`.
    NestingTooDeep,
    /// The output could not be allocated.
    OutOfMemory,
    /// Nothing binds this name, as a substitution or as a condition's flag.
    UnknownName,
    /// A `#` or `/` tag naming a directive this engine does not have.
    UnknownDirective,
    /// A close tag with no block open.
    UnopenedBlock,
    /// A `{{` with no closing `}}`.
    UnterminatedTag,
    /// A block that is still open at the end of the template: the innermost one, since that is the
    /// block the scan was inside when the input ran out.
    UnterminatedBlock,
    /// A `#if`/`#unless` over a value: a value is substituted, never tested.
    ValueAsCondition,
};

/// The names the template language binds, and which side of the value/flag line each is on.
///
/// This table is the whole declaration of the generator's name space: `Params.lookup` resolves
/// against it, and an unknown-name error lists it. A name added here cannot be missing from the
/// message that reports a typo in another, which is the failure a second copy of the list would
/// eventually cause.
const bindings = [_]struct { text: []const u8, is_flag: bool }{
    .{ .text = "name", .is_flag = false },
    .{ .text = "data", .is_flag = true },
    .{ .text = "live", .is_flag = true },
    .{ .text = "zscript", .is_flag = true },
};

/// A name the language binds, resolved to what it holds.
pub const Binding = union(enum) {
    /// Text, written where `{{name}}` appears.
    value: []const u8,
    /// A flag, read by `{{#if data}}` and `{{#unless data}}`. Never substituted.
    flag: bool,
};

/// What the templates may say, and where a failure is described.
///
/// Values and flags are separate kinds of thing: `data`, `live` and `zscript` are booleans that
/// switch whole sections of a generated project on and off, and a template that asks for one as text
/// — `{{data}}` — is asking for a section, or for a literal "true", depending on who reads it. There
/// is no correct answer to that, so the engine refuses the question rather than picking one.
pub const Params = struct {
    /// The generated project's name: `{{name}}`.
    name: []const u8,
    /// Flags, conditions only. `data` has a data layer, `live` a LiveView layer, `zscript` a script
    /// engine; a cleared flag means the generated project has no such thing in it.
    data: bool = false,
    live: bool = false,
    zscript: bool = false,
    /// Where to put the detail of a failure instead of printing it.
    ///
    /// The default is to print, because the default caller is `zurtr new` talking to a terminal, and
    /// a render that stopped with a bare error name would leave its user to guess. A caller that
    /// passes this takes the detail itself — it can then name the template file the source came from,
    /// which the engine cannot know.
    diagnostic: ?*Diagnostic = null,

    /// What `key` names, or null if it names nothing. The only place a template name is resolved.
    pub fn lookup(self: Params, key: []const u8) ?Binding {
        inline for (bindings) |binding| {
            if (std.mem.eql(u8, key, binding.text)) {
                if (binding.is_flag) return .{ .flag = @field(self, binding.text) };
                return .{ .value = @field(self, binding.text) };
            }
        }
        return null;
    }
};

/// Why a render failed, and where.
///
/// A position is filled in for every failure, because the position is the part a person can act on.
/// `render` either prints this or hands it to `Params.diagnostic`, and `write` is how it reads.
pub const Diagnostic = struct {
    /// Which failure. Always the error `render` returned.
    failure: Error = error.MalformedTag,
    /// Byte offset into the source that the failure is about.
    offset: usize = 0,
    /// 1-based line of `offset`, counted in bytes.
    line: usize = 1,
    /// 1-based byte column of `offset` within `line`.
    column: usize = 1,
    /// The tag's contents without braces: `typo` in `{{typo}}`, `#each x` in `{{#each x}}`. Empty
    /// when the failure is about a position rather than something a tag said.
    tag: []const u8 = "",
    /// The block a close tag failed to close, when a block was open. `open_line` is where its
    /// opening tag is, since that is the tag the author has to look at.
    open_tag: []const u8 = "",
    open_line: usize = 0,

    /// Writes the message `render` prints: the position, what is wrong, and the source line with a
    /// caret under it, line-terminated.
    pub fn write(self: Diagnostic, w: *std.Io.Writer, source: []const u8) std.Io.Writer.Error!void {
        try w.print("line {d}, column {d}: ", .{ self.line, self.column });

        switch (self.failure) {
            error.UnknownName => {
                try w.print("no name `{s}`: this generator binds ", .{self.tag});
                try writeBindings(w);
            },
            error.FlagSubstituted => {
                try w.print("`{s}` is a flag, and a flag is a condition: write ", .{self.tag});
                try writeTag(w, &.{ "#if ", self.tag });
            },
            error.ValueAsCondition => {
                try w.print("`{s}` is a value, and only a flag can be a condition: write ", .{self.tag});
                try writeTag(w, &.{self.tag});
            },
            error.MalformedTag => {
                try w.writeAll("not a tag this engine has: ");
                try writeTag(w, &.{self.tag});
                try w.writeAll("; a tag is a name, `#if <flag>`, `#unless <flag>`, `/if`, or `/unless`");
            },
            error.UnknownDirective => {
                try w.writeAll("no such directive: ");
                try writeTag(w, &.{self.tag});
                try w.writeAll("; this engine has `#if`, `#unless`, `/if`, and `/unless`");
            },
            error.UnterminatedTag => try w.writeAll("`{{` is never closed with `}}`"),
            error.UnterminatedBlock => {
                try w.writeAll("this block is never closed: ");
                try writeTag(w, &.{self.tag});
            },
            error.UnopenedBlock => {
                try w.writeAll("this close has no block to close: ");
                try writeTag(w, &.{self.tag});
            },
            error.MismatchedBlock => {
                try writeTag(w, &.{self.tag});
                try w.writeAll(" cannot close ");
                try writeTag(w, &.{self.open_tag});
                try w.print(", opened at line {d}", .{self.open_line});
            },
            error.NestingTooDeep => try w.print("blocks are nested deeper than {d} here", .{max_depth}),
            // Unreachable: the engine allocates nothing, so its only writer failure is the
            // allocator's, which `render` reports as `OutOfMemory` without a diagnostic. The name is
            // in `Error` for the caller's benefit, so it is answered here for the reader's.
            error.OutOfMemory => try w.writeAll("the renderer ran out of memory"),
        }

        try w.writeAll("\n");
        try self.writeSnippet(w, source);
    }

    /// The source line the failure is on, with a caret under the column. One line of the template
    /// answers "where is that" faster than any line number can, and the line is trimmed to keep a
    /// generated file's long line from burying the caret.
    fn writeSnippet(self: Diagnostic, w: *std.Io.Writer, source: []const u8) std.Io.Writer.Error!void {
        const before = source[0..self.offset];
        const start = if (std.mem.lastIndexOfScalar(u8, before, '\n')) |index| index + 1 else 0;
        const end = std.mem.indexOfScalarPos(u8, source, self.offset, '\n') orelse source.len;

        var line = source[start..end];
        // A CRLF template should not print a carriage return into the middle of the message.
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

        // The caret is a byte column, matching `column`; tabs in a template will look off by
        // whatever the terminal makes of them, which is a price a generated project does not pay.
        var caret = self.column - 1;
        var shown = line;
        if (line.len > max_snippet) {
            const skip = if (caret + 8 < max_snippet) 0 else caret + 8 - max_snippet;
            shown = line[skip..@min(line.len, skip + max_snippet)];
            caret -= skip;
        }

        try w.writeAll("  | ");
        try w.writeAll(shown);
        try w.writeAll("\n  | ");
        try w.splatByteAll(' ', caret);
        try w.writeAll("^\n");
    }
};

/// Renders `source` with `params`. The result is the caller's to free.
///
/// A failure has already been described — into `params.diagnostic` if one was given, on stderr
/// otherwise — by the time it is returned, so a caller can report the template it was rendering and
/// leave the rest alone.
pub fn render(gpa: std.mem.Allocator, source: []const u8, params: Params) Error![]u8 {
    var out = std.Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();

    var engine: Engine = .{ .source = source, .params = params, .out = &out.writer };
    engine.run() catch |err| switch (err) {
        // The allocating writer reports a refused allocation as `WriteFailed`, being built for
        // streams that can fail for their own reasons. Nothing here is a stream: say what happened.
        error.WriteFailed => return error.OutOfMemory,
        // Every other member is the template's own failure, which `@errorCast` promises: the writer's
        // single failure was the case above.
        else => |failure| {
            engine.report();
            return @errorCast(failure);
        },
    };

    return out.toOwnedSlice() catch error.OutOfMemory;
}

/// Deepest block nesting. A template nesting deeper than this is a mistake in the template, and a
/// bound that fails loudly beats unbounded recursion, which would overflow the stack first.
const max_depth = 32;

/// How much of a source line a diagnostic shows. Long enough for a line of generated Zig, short
/// enough that the caret is still visible on a terminal.
const max_snippet = 60;

/// Whitespace that may pad a tag's contents. `{{ name }}` is `{{name}}` and `{{#if  live }}` is
/// `{{#if live}}`: the braces are the syntax, the spacing around them is the author's.
const padding = " \t\r\n";

/// The two blocks, which differ only in how their flag is read.
const Directive = enum { @"if", unless };

/// A block the scan is inside.
///
/// The opening tag is kept, not just its directive, so that a close which does not match it, or a
/// block that never closes, can point at the tag that has to change rather than at the end of file.
const Block = struct {
    directive: Directive,
    offset: usize,
    tag: []const u8,
};

/// Where a byte offset falls, 1-based and counted in bytes.
const Position = struct { line: usize, column: usize };

fn locate(source: []const u8, offset: usize) Position {
    const before = source[0..offset];
    const line_start = if (std.mem.lastIndexOfScalar(u8, before, '\n')) |index| index + 1 else 0;
    return .{ .line = std.mem.count(u8, before, "\n") + 1, .column = offset - line_start + 1 };
}

/// A directive tag split into its word and its argument: `#if  live ` becomes `if` and `live`.
const Parts = struct { word: []const u8, argument: []const u8 };

fn splitTag(tag: []const u8) Parts {
    const end = std.mem.indexOfAny(u8, tag, padding) orelse tag.len;
    return .{ .word = tag[0..end], .argument = std.mem.trim(u8, tag[end..], padding) };
}

/// The scanner. It allocates nothing, so the only failure it can inherit is the writer's, which is
/// the allocator's in disguise; `render` turns that one into `OutOfMemory` at the boundary.
const Engine = struct {
    source: []const u8,
    params: Params,
    out: *std.Io.Writer,
    /// How far the scan has come.
    pos: usize = 0,
    /// Set by the failure that stops the scan.
    failure: ?Diagnostic = null,

    /// The template's own failures, plus the writer's one.
    const Failures = Error || std.Io.Writer.Error;

    fn run(self: *Engine) Failures!void {
        try self.body(null, true, 0);
    }

    /// Renders from the current position to the end of the template, or to the close of the block
    /// this body belongs to, which it consumes.
    ///
    /// `active` is whether the result is being written. A body whose flag is cleared is still
    /// scanned: a typo in a branch this build does not take is still a template bug, and a template
    /// that only breaks under one flag combination breaks on a user's machine instead of here.
    fn body(self: *Engine, open: ?Block, active: bool, depth: usize) Failures!void {
        while (true) {
            const brace = std.mem.indexOfPos(u8, self.source, self.pos, "{{") orelse {
                try self.text(self.source[self.pos..], active);
                self.pos = self.source.len;

                // Nothing closed this block. The tag that opened it is the one to fix, so that is
                // the tag reported.
                if (open) |block| return self.fail(error.UnterminatedBlock, block.offset, block.tag);
                return;
            };

            try self.text(self.source[self.pos..brace], active);

            const close = std.mem.indexOfPos(u8, self.source, brace + 2, "}}") orelse
                return self.fail(error.UnterminatedTag, brace, "");
            const raw = self.source[brace + 2 .. close];
            self.pos = close + 2;

            const tag = std.mem.trim(u8, raw, padding);
            if (tag.len == 0) return self.fail(error.MalformedTag, brace, tag);

            switch (tag[0]) {
                '#' => {
                    const parts = splitTag(tag[1..]);
                    if (parts.word.len == 0) return self.fail(error.MalformedTag, self.offsetOf(tag), tag);

                    const directive: Directive = if (std.mem.eql(u8, parts.word, "if"))
                        .@"if"
                    else if (std.mem.eql(u8, parts.word, "unless"))
                        .unless
                    else
                        return self.fail(error.UnknownDirective, self.offsetOf(tag), tag[0 .. 1 + parts.word.len]);

                    // One flag, whole: `{{#if}}` has none and `{{#if a b}}` has two names where the
                    // language has one.
                    if (parts.argument.len == 0 or std.mem.indexOfAny(u8, parts.argument, padding) != null)
                        return self.fail(error.MalformedTag, self.offsetOf(tag), tag);

                    const found = self.params.lookup(parts.argument) orelse
                        return self.fail(error.UnknownName, self.offsetOf(parts.argument), parts.argument);
                    const set = switch (found) {
                        .flag => |value| value,
                        .value => return self.fail(error.ValueAsCondition, self.offsetOf(parts.argument), parts.argument),
                    };
                    const take = if (directive == .@"if") set else !set;

                    if (depth == max_depth) return self.fail(error.NestingTooDeep, brace, tag);

                    try self.body(.{ .directive = directive, .offset = brace, .tag = tag }, active and take, depth + 1);
                },

                '/' => {
                    const parts = splitTag(tag[1..]);
                    if (parts.word.len == 0 or parts.argument.len != 0)
                        return self.fail(error.MalformedTag, self.offsetOf(tag), tag);

                    const directive: Directive = if (std.mem.eql(u8, parts.word, "if"))
                        .@"if"
                    else if (std.mem.eql(u8, parts.word, "unless"))
                        .unless
                    else
                        return self.fail(error.UnknownDirective, self.offsetOf(tag), tag);

                    const block = open orelse return self.fail(error.UnopenedBlock, self.offsetOf(tag), tag);
                    if (block.directive != directive) return self.failMismatch(tag, block);

                    return;
                },

                else => {
                    // A name is one token: `{{ name extra }}` is a mistake, not a name nothing
                    // binds, and saying which mistake it is is the difference between a fix and a
                    // search.
                    if (std.mem.indexOfAny(u8, tag, padding) != null)
                        return self.fail(error.MalformedTag, self.offsetOf(tag), tag);

                    const value = switch (self.params.lookup(tag) orelse
                        return self.fail(error.UnknownName, self.offsetOf(tag), tag)) {
                        .value => |literal| literal,
                        .flag => return self.fail(error.FlagSubstituted, self.offsetOf(tag), tag),
                    };

                    // The value's bytes go to the output as they are. Nothing re-reads them: this is
                    // where a project named `{{weird}}` stays a project named `{{weird}}`.
                    try self.text(value, active);
                },
            }
        }
    }

    /// Writes a run of the template's text, or drops it when the enclosing block is not taken.
    fn text(self: *Engine, bytes: []const u8, active: bool) std.Io.Writer.Error!void {
        if (!active or bytes.len == 0) return;
        try self.out.writeAll(bytes);
    }

    /// `piece` is a slice of the source; a tag's contents are worth pointing at, and the braces are
    /// not where the author's mistake is.
    fn offsetOf(self: *Engine, piece: []const u8) usize {
        return @intFromPtr(piece.ptr) - @intFromPtr(self.source.ptr);
    }

    fn fail(self: *Engine, failure: Error, offset: usize, tag: []const u8) Failures {
        return self.record(failure, offset, tag, null);
    }

    /// A close that names the wrong directive: the failure is at the close, but the tag that has to
    /// be looked at first is the open one.
    fn failMismatch(self: *Engine, tag: []const u8, block: Block) Failures {
        return self.record(error.MismatchedBlock, self.offsetOf(tag), tag, block);
    }

    /// Records the failure and returns it, so a call site reads as one statement.
    ///
    /// Only the first failure is kept: it is the one the author has to fix, and the rest are its
    /// consequences — a template missing an `{{/if}}` does not need to hear about it twice.
    fn record(self: *Engine, failure: Error, offset: usize, tag: []const u8, block: ?Block) Failures {
        if (self.failure != null) return failure;

        const at = locate(self.source, offset);
        self.failure = .{
            .failure = failure,
            .offset = offset,
            .line = at.line,
            .column = at.column,
            .tag = tag,
            .open_tag = if (block) |open| open.tag else "",
            .open_line = if (block) |open| locate(self.source, open.offset).line else 0,
        };

        return failure;
    }

    /// Says what went wrong, in the way the caller asked for it.
    fn report(self: *Engine) void {
        const failure = self.failure orelse return;

        if (self.params.diagnostic) |out| {
            out.* = failure;
            return;
        }

        var buffer: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);
        // A message too long for the buffer is still a message: `fixed` keeps the part of it that
        // fit, and the line, the reason and the caret are written before the snippet is cut off.
        failure.write(&w, self.source) catch {};
        const written = w.buffered();
        std.debug.print("zurtr templ: {s}{s}", .{
            written,
            // A message that outgrew the buffer ends mid-line, and a shell prompt continuing the
            // caret line is the one thing worse than a truncated message.
            if (written.len > 0 and written[written.len - 1] == '\n') "" else "\n",
        });
    }
};

/// `{{#if live}}` — a tag as the author would have to write it. The messages here are mostly tags,
/// and a `print` format string carrying braces is mostly escapes, so a tag is written, not formatted.
///
/// The contents are shown with their whitespace visible: `padding` includes the newlines, so
/// `{{#if\nlive}}` is a legal tag, and a message that inherited its line break would break the one
/// rule this reporting has — that the reader can see where it starts and where it points.
fn writeTag(w: *std.Io.Writer, parts: []const []const u8) std.Io.Writer.Error!void {
    try w.writeAll("{{");
    for (parts) |part| for (part) |byte| switch (byte) {
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (byte < 0x20 or byte == 0x7f) {
            try w.print("\\x{x:0>2}", .{byte});
        } else {
            try w.writeByte(byte);
        },
    };
    try w.writeAll("}}");
}

/// `values {name} and flags {data, live, zscript}` — what an unknown name could have been, listed
/// from the same table the lookup uses.
fn writeBindings(w: *std.Io.Writer) std.Io.Writer.Error!void {
    inline for (.{ false, true }) |is_flag| {
        try w.writeAll(if (is_flag) "flags {" else "values {");
        var first = true;
        inline for (bindings) |binding| {
            if (binding.is_flag == is_flag) {
                if (!first) try w.writeAll(", ");
                try w.writeAll(binding.text);
                first = false;
            }
        }
        try w.writeAll("}");
        if (!is_flag) try w.writeAll(" and ");
    }
}

/// Params for a test whose subject is the template rather than the params: a name that is only ever
/// substituted, with the flags left to the caller.
fn paramsFor(flags: struct { data: bool = false, live: bool = false, zscript: bool = false }) Params {
    return .{
        .name = "p",
        .data = flags.data,
        .live = flags.live,
        .zscript = flags.zscript,
    };
}

/// Renders with the testing allocator, requires the exact result, and frees it. A diagnostic sink is
/// not attached, so a render that fails here prints where a test run can see it.
fn expectRender(expected: []const u8, source: []const u8, params: Params) !void {
    const rendered = try render(testing.allocator, source, params);
    defer testing.allocator.free(rendered);
    try testing.expectEqualStrings(expected, rendered);
}

/// Requires the failure *and* its diagnostic. An error whose detail did not arrive is the failure
/// mode this engine exists to avoid, so the two are one contract in these tests.
fn expectFailure(expected: Error, source: []const u8, params: Params) !Diagnostic {
    var diagnostic: Diagnostic = undefined;
    var with_sink = params;
    with_sink.diagnostic = &diagnostic;

    try testing.expectError(expected, render(testing.allocator, source, with_sink));
    try testing.expectEqual(expected, diagnostic.failure);
    return diagnostic;
}

test "substitution writes the name and the padding inside the braces is not part of it" {
    try expectRender(
        "proj proj\tproj\n",
        "{{name}} {{ name }}\t{{  name  }}\n",
        .{ .name = "proj" },
    );
}

test "a value that looks like a tag is copied, never scanned again" {
    // Re-scanned, the first would open an `#if`, and then fail as unterminated.
    try expectRender("<{{#if live}}>", "<{{name}}>", .{ .name = "{{#if live}}" });

    // And a value containing a tag would be substituted a second time, from inside itself.
    try expectRender("a{{name}}!b", "a{{name}}b", .{ .name = "{{name}}!" });
}

test "#if takes its body when the flag is set and drops it when it is not" {
    const source = "a{{#if live}}L{{/if}}b";
    try expectRender("aLb", source, paramsFor(.{ .live = true }));
    try expectRender("ab", source, paramsFor(.{ .live = false }));

    // The padding around a directive's flag is not part of the flag, either.
    try expectRender("L", "{{#if   live }}L{{/if}}", paramsFor(.{ .live = true }));

    // Each flag the generator declares, so a name missing from the table is a test failure rather
    // than a template that mysteriously does not build.
    try expectRender("S", "{{#if zscript}}S{{/if}}", paramsFor(.{ .zscript = true }));
}

test "#unless is the inverse, and blocks nest inside blocks" {
    const source = "{{#if live}}{{#unless data}}live, no data{{/unless}}{{/if}}";
    try expectRender("live, no data", source, paramsFor(.{ .live = true }));
    try expectRender("", source, paramsFor(.{ .live = true, .data = true }));
    try expectRender("", source, paramsFor(.{ .live = false }));

    // Two levels of the same directive: the inner close ends the inner block, not the outer one.
    const same = "{{#if live}}x{{#if data}}y{{/if}}{{/if}}";
    try expectRender("xy", same, paramsFor(.{ .live = true, .data = true }));
    try expectRender("x", same, paramsFor(.{ .live = true }));
}

test "an unknown name is an error that says which name and which line" {
    const diag = try expectFailure(error.UnknownName, "a\nb {{typo}} c\n", paramsFor(.{}));
    try testing.expectEqualStrings("typo", diag.tag);
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectEqual(@as(usize, 5), diag.column);

    // A condition's flag is a name like any other, and a typo in it is reported the same way.
    const flag = try expectFailure(error.UnknownName, "{{#if lvie}}x{{/if}}", paramsFor(.{}));
    try testing.expectEqualStrings("lvie", flag.tag);
    try testing.expectEqual(@as(usize, 1), flag.line);
}

test "a block that is never closed is reported at the tag that opened it" {
    const source =
        \\{{#if live}}
        \\pub const x = 1;
        \\{{#unless data}}
    ;

    // Taken and not taken report the same tag: structure is checked whether or not the body is
    // written, so a template that only breaks under one flag combination cannot ship.
    for ([_]bool{ true, false }) |live| {
        const diag = try expectFailure(error.UnterminatedBlock, source, paramsFor(.{
            .live = live,
        }));
        try testing.expectEqualStrings("#unless data", diag.tag);
        try testing.expectEqual(@as(usize, 3), diag.line);
    }

    // A closed inner block leaves the outer one as the one that is still open.
    const outer = try expectFailure(error.UnterminatedBlock, "{{#if live}}{{#if data}}x{{/if}}", paramsFor(.{
        .live = true,
    }));
    try testing.expectEqualStrings("#if live", outer.tag);
    try testing.expectEqual(@as(usize, 1), outer.line);
}

test "a close tag that closes nothing, and one that closes the wrong block, are told apart" {
    const stray = try expectFailure(error.UnopenedBlock, "x{{/if}}", paramsFor(.{}));
    try testing.expectEqualStrings("/if", stray.tag);
    try testing.expectEqual(@as(usize, 1), stray.line);

    const wrong = try expectFailure(error.MismatchedBlock,
        \\{{#if live}}
        \\x{{/unless}}
    , paramsFor(.{ .live = true }));
    try testing.expectEqualStrings("/unless", wrong.tag);
    try testing.expectEqual(@as(usize, 2), wrong.line);
    try testing.expectEqualStrings("#if live", wrong.open_tag);
    try testing.expectEqual(@as(usize, 1), wrong.open_line);
}

test "a `{{` with no `}}` is an error, and a lone brace is not a tag" {
    const diag = try expectFailure(error.UnterminatedTag, "a\nb {{name", paramsFor(.{}));
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectEqual(@as(usize, 3), diag.column);

    try expectRender("a { b } c }}}", "a { b } c }}}", paramsFor(.{}));
}

test "a template with no placeholders is copied byte for byte" {
    // Every byte value, so an escaping refactor cannot pass: text is copied, not encoded.
    var binary: [256]u8 = undefined;
    for (&binary, 0..) |*byte, index| byte.* = @intCast(index);
    try expectRender(&binary, &binary, paramsFor(.{}));

    // And the bytes around a substitution come out as they went in.
    try expectRender("\x00\x01proj\xff", "\x00\x01{{name}}\xff", .{ .name = "proj" });
}

test "a flag cannot be substituted and a value cannot be a condition" {
    // `data` is set here, so the failure is the usage and not a missing name.
    const substituted = try expectFailure(error.FlagSubstituted, "x {{data}} y", paramsFor(.{
        .data = true,
    }));
    try testing.expectEqualStrings("data", substituted.tag);

    const conditioned = try expectFailure(error.ValueAsCondition, "{{#if name}}x{{/if}}", paramsFor(.{}));
    try testing.expectEqualStrings("name", conditioned.tag);
}

test "a malformed tag and an unknown directive are told apart from an unknown name" {
    const malformed = try expectFailure(error.MalformedTag, "{{ name extra }}", paramsFor(.{}));
    try testing.expectEqualStrings("name extra", malformed.tag);

    const empty = try expectFailure(error.MalformedTag, "{{}}", paramsFor(.{}));
    try testing.expectEqualStrings("", empty.tag);

    const directive = try expectFailure(error.UnknownDirective, "{{#each x}}y{{/each}}", paramsFor(.{}));
    try testing.expectEqualStrings("#each", directive.tag);
    try testing.expectEqual(@as(usize, 3), directive.column);
}

test "a tag may span a line, and a message about one stays on one line" {
    try expectRender("x", "{{#if\n   live}}x{{/if}}", paramsFor(.{ .live = true }));

    // The tag is quoted with its whitespace visible: the reader has to be able to tell where the
    // message ends and the template's own line break begins.
    const source = "a\n{{ name\nextra }}\n";
    const diag = try expectFailure(error.MalformedTag, source, paramsFor(.{}));

    var buffer: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buffer);
    try diag.write(&w, source);
    try testing.expectEqualStrings(
        \\line 2, column 4: not a tag this engine has: {{name\nextra}}; a tag is a name, `#if <flag>`, `#unless <flag>`, `/if`, or `/unless`
        \\  | {{ name
        \\  |    ^
        \\
    , w.buffered());
}

test "the diagnostic reads as a position, a reason, and the source line with a caret" {
    const source =
        \\//! The generated app.
        \\pub const app_name = "{{nam}}";
        \\
    ;
    const diag = try expectFailure(error.UnknownName, source, .{ .name = "proj" });

    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectEqual(@as(usize, 25), diag.column);

    var buffer: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buffer);
    try diag.write(&w, source);
    try testing.expectEqualStrings(
        \\line 2, column 25: no name `nam`: this generator binds values {name} and flags {data, live, zscript}
        \\  | pub const app_name = "{{nam}}";
        \\  |                         ^
        \\
    , w.buffered());
}

test "nesting deeper than the limit is refused instead of recursed into" {
    const open = "{{#if live}}\n";
    var source: [(max_depth + 1) * open.len]u8 = undefined;

    var len: usize = 0;
    for (0..max_depth) |_| {
        @memcpy(source[len..][0..open.len], open);
        len += open.len;
    }

    // At the limit the blocks are simply never closed, which is what the scan says about them.
    const at_limit = try expectFailure(error.UnterminatedBlock, source[0..len], paramsFor(.{
        .live = true,
    }));
    try testing.expectEqualStrings("#if live", at_limit.tag);
    // Every one of them is unclosed; the last one opened is the one reported, being the block the
    // scan was inside when the input ran out.
    try testing.expectEqual(@as(usize, max_depth), at_limit.line);

    @memcpy(source[len..][0..open.len], open);
    len += open.len;

    const too_deep = try expectFailure(error.NestingTooDeep, source[0..len], paramsFor(.{
        .live = true,
    }));
    try testing.expectEqual(@as(usize, max_depth + 1), too_deep.line);
}
