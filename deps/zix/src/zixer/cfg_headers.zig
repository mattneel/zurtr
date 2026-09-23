//! zixer cfg header sections: the [response_headers] and [request_headers] lines, compiled once

const std = @import("std");

const cfg_scanner = @import("cfg_scanner.zig");
const fault = @import("fault.zig");
const header_syntax = @import("header_syntax.zig");
const proxy_headers = @import("proxy_headers.zig");

/// Which leg a table is written on.
///
/// Note:
/// - A proxy has two of them and one [headers] section could not say which,
///   so the direction is part of the section name.
pub const Direction = enum {
    RESPONSE,
    REQUEST,

    /// The cfg section name this direction is written under.
    ///
    /// Return:
    /// - []const u8, without the brackets
    pub fn sectionName(direction: Direction) []const u8 {
        return switch (direction) {
            .RESPONSE => "response_headers",
            .REQUEST => "request_headers",
        };
    }
};

/// Ceiling on one compiled block, in bytes.
///
/// Note:
/// - An edge stages a head in a fixed buffer, so a table has to fit beside the
///   request it rides with. Refusing an oversized section at load beats a site
///   that starts and then answers every request 400.
pub const MAX_BLOCK_BYTES: usize = 1024;

/// A per-request value the operator names with a `$` sigil.
///
/// Note:
/// - The set is closed. A name outside it faults at load rather than reaching
///   a client as the literal text the operator typed.
pub const Token = enum {
    CLIENT_IP,
    SCHEME,
    HOST,
};

/// What every token stands for on one request.
///
/// Note:
/// - An empty field writes nothing, which is what a request with no Host
///   should produce: the header still goes out, with no value.
pub const TokenValues = struct {
    client_ip: []const u8 = "",
    scheme: []const u8 = "",
    host: []const u8 = "",

    /// The bytes one token writes.
    ///
    /// Param:
    /// token - Token (which value the compiled table asked for)
    ///
    /// Return:
    /// - []const u8
    pub fn get(values: TokenValues, token: Token) []const u8 {
        return switch (token) {
            .CLIENT_IP => values.client_ip,
            .SCHEME => values.scheme,
            .HOST => values.host,
        };
    }
};

/// One piece of a compiled table: bytes to copy out, or a token to fill in.
pub const Piece = union(enum) {
    literal: []const u8,
    token: Token,
};

/// Widest one rendered value can be: the whole block ceiling, plus room for
/// the tokens an authority and an address expand to.
pub const MAX_VALUE_BYTES: usize = MAX_BLOCK_BYTES + 512;

/// One compiled header line on its own.
///
/// Note:
/// - h1 writes the block as one run of bytes, but h2 and h3 encode each field
///   into their own header table, so those need the lines apart.
pub const Line = struct {
    name: []const u8,
    value: []const Piece,

    /// Render this line's value with its tokens filled in.
    ///
    /// Param:
    /// buf - []u8 (scratch, MAX_VALUE_BYTES covers any accepted line)
    /// values - TokenValues (this request's token values)
    ///
    /// Return:
    /// - []const u8, a slice into buf
    /// - error.WriteFailed when the rendered value does not fit
    pub fn renderValue(line: Line, buf: []u8, values: TokenValues) ![]const u8 {
        var out = std.Io.Writer.fixed(buf);
        for (line.value) |piece| {
            switch (piece) {
                .literal => |bytes| try out.writeAll(bytes),
                .token => |token| try out.writeAll(values.get(token)),
            }
        }

        return out.buffered();
    }
};

/// The compiled header block for one direction.
///
/// Note:
/// - pieces is the h1 view: every line with no token in it merges into the
///   neighbouring literal, so a table that names no token is one piece and one
///   copy per request.
/// - lines is the same headers apart, for h2 and h3, which encode each field
///   into their own header table instead of writing a run of bytes.
/// - The line names are the operator's own spelling, which is what lets an
///   edge drop the relayed copy of a name the cfg sets.
pub const Table = struct {
    pieces: []const Piece = &.{},
    lines: []const Line = &.{},
    /// The bytes every literal piece points into. Kept so a table copied out
    /// of the cfg arena can be released again.
    blob: []const u8 = "",
    /// The array every line's value slices. Kept for the same reason.
    value_pieces: []const Piece = &.{},

    /// Copy this table into allocator so it can outlive the arena it was
    /// compiled in.
    ///
    /// Note:
    /// - A serve state lives past the parse, and the cfg arena does not, so an
    ///   edge that keeps a table has to own it. Every other cfg string an edge
    ///   keeps is duplicated for the same reason.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the copy, freed by deinit)
    ///
    /// Return:
    /// - Table, owning every byte it points at
    pub fn dupe(table: Table, allocator: std.mem.Allocator) !Table {
        return build(allocator, table.lines);
    }

    /// Release a table that dupe allocated. A table compiled into an arena is
    /// released with that arena instead, and never through here.
    pub fn deinit(table: Table, allocator: std.mem.Allocator) void {
        if (table.blob.len != 0) allocator.free(table.blob);
        if (table.pieces.len != 0) allocator.free(table.pieces);
        if (table.value_pieces.len != 0) allocator.free(table.value_pieces);
        if (table.lines.len != 0) allocator.free(table.lines);
    }

    /// True when this table writes nothing at all.
    pub fn isEmpty(table: Table) bool {
        return table.lines.len == 0;
    }

    /// True when the cfg sets this header name, case-insensitive.
    ///
    /// Note:
    /// - An edge calls this on a relayed header so the configured line
    ///   replaces it instead of standing beside it. Two lines of the same name
    ///   read as one comma-joined value (rfc 9110 5.2), which silently breaks
    ///   a single-value header like X-Frame-Options.
    ///
    /// Param:
    /// name - []const u8 (a header name coming off the wire)
    ///
    /// Return:
    /// - bool
    pub fn owns(table: Table, name: []const u8) bool {
        for (table.lines) |line| {
            if (std.ascii.eqlIgnoreCase(line.name, name)) return true;
        }

        return false;
    }

    /// Write the whole block, tokens filled in, each line ending in CRLF.
    ///
    /// Param:
    /// out - *std.Io.Writer (head in progress, before its blank line)
    /// values - TokenValues (this request's token values)
    ///
    /// Return:
    /// - void
    pub fn write(table: Table, out: *std.Io.Writer, values: TokenValues) !void {
        for (table.pieces) |piece| {
            switch (piece) {
                .literal => |bytes| try out.writeAll(bytes),
                .token => |token| try out.writeAll(values.get(token)),
            }
        }
    }
};

/// A compiled table carrying one request's token values, which is what an edge
/// hands down to its head writers.
///
/// Note:
/// - The default is empty, so an edge on a site with no section configured
///   still passes one down and every call on it is a no-op.
pub const Block = struct {
    table: Table = .{},
    values: TokenValues = .{},

    /// True when this block writes nothing at all.
    pub fn isEmpty(block: Block) bool {
        return block.table.isEmpty();
    }

    /// True when the cfg sets this header name, case-insensitive.
    pub fn owns(block: Block, name: []const u8) bool {
        return block.table.owns(name);
    }

    /// The compiled lines apart, for a wire that encodes each field on its own.
    pub fn lines(block: Block) []const Line {
        return block.table.lines;
    }

    /// Write the whole block, tokens filled in, each line ending in CRLF.
    pub fn write(block: Block, out: *std.Io.Writer) !void {
        return block.table.write(out, block.values);
    }
};

/// A literal run recorded as an offset, because the byte buffer it points into
/// still moves while the table is being built.
const Mark = union(enum) {
    literal: struct { start: usize, len: usize },
    token: Token,
};

/// One `$name` occurrence found in a value.
const Sigil = struct {
    /// Offset of the '$'.
    start: usize,
    /// Offset just past the name.
    end: usize,
    /// The name without its '$'.
    name: []const u8,
    /// Null when the name is outside the closed set.
    token: ?Token,
};

/// Compile one section's lines into the block an edge writes per request.
///
/// Note:
/// - Every rule runs here, at load. An operator has no compiler to catch a
///   header the wire would reject, so nothing is left to per-request time.
/// - A line that faults is left out of the table. The rest still compile, so
///   one typo does not hide the next problem.
///
/// Param:
/// arena - std.mem.Allocator (owns the returned block, must outlive the site)
/// lines - []const cfg_scanner.Entry (the section's lines, in file order)
/// direction - Direction (which leg the block is written on)
/// tls - bool (the site's tls flag, HSTS needs it)
/// faults - *fault.FaultList (collects every refused line)
///
/// Return:
/// - Table, empty when the section had no usable line
pub fn compile(
    arena: std.mem.Allocator,
    lines: []const cfg_scanner.Entry,
    direction: Direction,
    tls: bool,
    faults: *fault.FaultList,
) !Table {
    var drafts: std.ArrayList(Line) = .empty;
    var parts: std.ArrayList(Piece) = .empty;
    var spans: std.ArrayList(Span) = .empty;

    for (lines) |line| {
        if (!try nameUsable(line, direction, tls, drafts.items, faults)) continue;
        if (!try valueUsable(line, faults)) continue;

        // The parts of every value share one growing array, so each line keeps
        // the span it owns and the slices are cut once the array settles.
        const start = parts.items.len;
        var pos: usize = 0;
        while (nextSigil(line.value, pos)) |sigil| {
            if (sigil.start != pos) try parts.append(arena, .{ .literal = line.value[pos..sigil.start] });

            try parts.append(arena, .{ .token = sigil.token.? });
            pos = sigil.end;
        }
        if (pos != line.value.len) try parts.append(arena, .{ .literal = line.value[pos..] });

        try spans.append(arena, .{ .start = start, .end = parts.items.len });
        try drafts.append(arena, .{ .name = line.key, .value = &.{} });
    }

    for (drafts.items, spans.items) |*draft, span| {
        draft.value = parts.items[span.start..span.end];
    }

    const total = blockBytes(drafts.items);
    if (total > MAX_BLOCK_BYTES) {
        try faults.add(
            direction.sectionName(),
            "the section compiles to {d} bytes and the ceiling is {d}, keep fewer or shorter lines",
            .{ total, MAX_BLOCK_BYTES },
        );

        return .{};
    }

    return build(arena, drafts.items);
}

/// The bytes a set of lines writes as an h1 block, tokens counted as nothing.
fn blockBytes(lines: []const Line) usize {
    var total: usize = 0;
    for (lines) |line| {
        total += line.name.len + ": \r\n".len;
        for (line.value) |piece| {
            switch (piece) {
                .literal => |bytes| total += bytes.len,
                .token => {},
            }
        }
    }

    return total;
}

/// Lay out validated lines as a table that owns its own bytes.
///
/// Note:
/// - This is the one place a Table is made, so a table compiled from a cfg and
///   a table copied out of one have the same shape by construction.
/// - Both views come out of the same walk: the block cursor runs past a line
///   end and merges neighbours, the value cursor stops at every line.
///
/// Param:
/// allocator - std.mem.Allocator (owns the whole table)
/// lines - []const Line (already validated, values may point anywhere)
///
/// Return:
/// - Table, empty when lines is empty
fn build(allocator: std.mem.Allocator, lines: []const Line) !Table {
    if (lines.len == 0) return .{};

    // Only the byte buffer survives this call, and it leaves as an owned
    // slice. Everything else is scaffolding, and dupe hands in a real
    // allocator rather than an arena, so it has to be given back.
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var marks: std.ArrayList(Mark) = .empty;
    defer marks.deinit(allocator);
    var value_marks: std.ArrayList(Mark) = .empty;
    defer value_marks.deinit(allocator);
    var spans: std.ArrayList(Span) = .empty;
    defer spans.deinit(allocator);
    var names: std.ArrayList(Span) = .empty;
    defer names.deinit(allocator);

    var block_flushed: usize = 0;

    for (lines) |line| {
        const name_start = bytes.items.len;
        try bytes.appendSlice(allocator, line.name);
        try names.append(allocator, .{ .start = name_start, .end = bytes.items.len });
        try bytes.appendSlice(allocator, ": ");

        var value_flushed = bytes.items.len;
        const value_start = value_marks.items.len;

        for (line.value) |piece| {
            switch (piece) {
                .literal => |literal| try bytes.appendSlice(allocator, literal),
                .token => |token| {
                    try flushLiteral(allocator, &marks, bytes.items.len, &block_flushed);
                    try marks.append(allocator, .{ .token = token });

                    try flushLiteral(allocator, &value_marks, bytes.items.len, &value_flushed);
                    try value_marks.append(allocator, .{ .token = token });
                },
            }
        }

        try flushLiteral(allocator, &value_marks, bytes.items.len, &value_flushed);
        try bytes.appendSlice(allocator, "\r\n");
        try spans.append(allocator, .{ .start = value_start, .end = value_marks.items.len });
    }

    try flushLiteral(allocator, &marks, bytes.items.len, &block_flushed);

    const blob = try bytes.toOwnedSlice(allocator);
    const pieces = try resolve(allocator, marks.items, blob);
    const value_pieces = try resolve(allocator, value_marks.items, blob);

    const compiled = try allocator.alloc(Line, lines.len);
    for (compiled, names.items, spans.items) |*line, name, span| {
        line.* = .{ .name = blob[name.start..name.end], .value = value_pieces[span.start..span.end] };
    }

    return .{ .pieces = pieces, .lines = compiled, .blob = blob, .value_pieces = value_pieces };
}

/// A half-open range, used for a value's marks and for a name's bytes.
const Span = struct {
    start: usize,
    end: usize,
};

/// Close the literal run in progress, if there is one, as a mark.
fn flushLiteral(allocator: std.mem.Allocator, marks: *std.ArrayList(Mark), blob_len: usize, flushed: *usize) !void {
    if (blob_len == flushed.*) return;

    try marks.append(allocator, .{ .literal = .{ .start = flushed.*, .len = blob_len - flushed.* } });
    flushed.* = blob_len;
}

/// Turn build-time marks into pieces now that the byte blob has stopped moving.
fn resolve(allocator: std.mem.Allocator, marks: []const Mark, blob: []const u8) ![]const Piece {
    const pieces = try allocator.alloc(Piece, marks.len);
    for (marks, 0..) |mark, index| {
        pieces[index] = switch (mark) {
            .literal => |span| .{ .literal = blob[span.start..][0..span.len] },
            .token => |token| .{ .token = token },
        };
    }

    return pieces;
}

/// Whether this line's name may be set at all, faulting with the reason when
/// it may not.
fn nameUsable(
    line: cfg_scanner.Entry,
    direction: Direction,
    tls: bool,
    taken: []const Line,
    faults: *fault.FaultList,
) !bool {
    if (!header_syntax.isFieldName(line.key)) {
        try faults.add(line.key, "line {d} is not a header name, use letters, digits, and - . _ ~ (rfc 9110 5.1)", .{line.line_no});
        return false;
    }

    for (taken) |already| {
        if (std.ascii.eqlIgnoreCase(already.name, line.key)) {
            try faults.add(line.key, "duplicate header on line {d}, keep one line", .{line.line_no});
            return false;
        }
    }

    // Checked before the hop-by-hop list, which covers these two as well: the
    // reason an operator needs to hear is different, and so is the fix.
    if (std.ascii.eqlIgnoreCase(line.key, "content-length") or std.ascii.eqlIgnoreCase(line.key, "transfer-encoding")) {
        try faults.add(line.key, "zixer writes the message framing itself, remove it", .{});
        return false;
    }

    if (proxy_headers.isStripped(line.key)) {
        try faults.add(line.key, "is hop-by-hop and never crosses a proxy (rfc 9110), remove it", .{});
        return false;
    }

    if (std.ascii.eqlIgnoreCase(line.key, "via")) {
        try faults.add(line.key, "zixer writes its own Via element on every hop, remove it", .{});
        return false;
    }

    return switch (direction) {
        .RESPONSE => try responseNameUsable(line, tls, faults),
        .REQUEST => try requestNameUsable(line, faults),
    };
}

/// The rules that hold only for the leg back to the client.
fn responseNameUsable(line: cfg_scanner.Entry, tls: bool, faults: *fault.FaultList) !bool {
    if (std.ascii.eqlIgnoreCase(line.key, "date")) {
        try faults.add(line.key, "zixer sends Date from its own clock, setting it here would send two", .{});
        return false;
    }

    // rfc 6797 7.2: a client must ignore HSTS that arrived over cleartext, so
    // a site with no https would be shipping a header nothing acts on.
    if (std.ascii.eqlIgnoreCase(line.key, "strict-transport-security") and !tls) {
        try faults.add(line.key, "needs tls: true, a cleartext answer must not carry HSTS (rfc 6797 7.2)", .{});
        return false;
    }

    return true;
}

/// The rules that hold only for the leg out to the upstream.
fn requestNameUsable(line: cfg_scanner.Entry, faults: *fault.FaultList) !bool {
    if (std.ascii.eqlIgnoreCase(line.key, "host")) {
        try faults.add(line.key, "the upstream Host comes from the client request, setting it here would send two", .{});
        return false;
    }

    if (std.ascii.eqlIgnoreCase(line.key, "forwarded")) {
        try faults.add(line.key, "zixer writes it from the accepted connection (rfc 7239), use $client_ip in a header of your own", .{});
        return false;
    }

    if (std.ascii.eqlIgnoreCase(line.key, "strict-transport-security")) {
        try faults.add(line.key, "is a header for the client, move it to [response_headers]", .{});
        return false;
    }

    return true;
}

/// Whether this line's value may be written, faulting with the reason when it
/// may not.
fn valueUsable(line: cfg_scanner.Entry, faults: *fault.FaultList) !bool {
    if (header_syntax.firstBadValueChar(line.value)) |byte| {
        try faults.add(line.key, "line {d} has byte 0x{X:0>2} in its value, a header value is one line of visible characters", .{ line.line_no, byte });
        return false;
    }

    var pos: usize = 0;
    while (nextSigil(line.value, pos)) |sigil| {
        if (sigil.token == null) {
            try faults.add(line.key, "unknown token '${s}' on line {d}, use $client_ip, $scheme, or $host", .{ sigil.name, line.line_no });
            return false;
        }

        pos = sigil.end;
    }

    return true;
}

/// The next `$name` at or after from, null when the rest of value has none.
///
/// Note:
/// - A '$' with no name behind it is ordinary text, so a value may still carry
///   one. Only `$` plus lowercase letters or underscores reads as a token.
fn nextSigil(value: []const u8, from: usize) ?Sigil {
    var pos = from;
    while (std.mem.indexOfScalarPos(u8, value, pos, '$')) |at| {
        const name_start = at + 1;
        var name_end = name_start;
        while (name_end < value.len and isTokenNameChar(value[name_end])) name_end += 1;

        if (name_end != name_start) {
            const name = value[name_start..name_end];

            return .{ .start = at, .end = name_end, .name = name, .token = tokenNamed(name) };
        }

        pos = name_start;
    }

    return null;
}

/// True when byte may stand in a token name.
fn isTokenNameChar(byte: u8) bool {
    return switch (byte) {
        'a'...'z', '_' => true,
        else => false,
    };
}

/// The token one name stands for, null when the name is outside the set.
fn tokenNamed(name: []const u8) ?Token {
    if (std.mem.eql(u8, name, "client_ip")) return .CLIENT_IP;
    if (std.mem.eql(u8, name, "scheme")) return .SCHEME;
    if (std.mem.eql(u8, name, "host")) return .HOST;

    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Build the section lines a test compiles, mirroring what the scanner hands
/// the site schema.
fn lineOf(key: []const u8, value: []const u8, line_no: usize) cfg_scanner.Entry {
    return .{ .key = key, .value = value, .line_no = line_no };
}

/// Compile into a fixed buffer and hand back what an edge would write.
fn written(table: Table, buf: []u8, values: TokenValues) ![]const u8 {
    var out = std.Io.Writer.fixed(buf);
    try table.write(&out, values);

    return out.buffered();
}

test "zix zixer: cfg headers, a token-free section is one literal piece" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-frame-options", "DENY", 3),
        lineOf("cache-control", "public, max-age=3600", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expectEqual(@as(usize, 0), faults.slice().len);

    // The whole block is one copy per request, which is the point of
    // compiling it at load.
    try testing.expectEqual(@as(usize, 1), table.pieces.len);

    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "x-frame-options: DENY\r\ncache-control: public, max-age=3600\r\n",
        try written(table, &buf, .{}),
    );
}

test "zix zixer: cfg headers, a value splits only where a token sits" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-real-ip", "$client_ip", 3),
        lineOf("x-forwarded-proto", "$scheme", 4),
        lineOf("x-origin", "$scheme://$host/edge", 5),
        lineOf("x-static", "no token here", 6),
    };

    const table = try compile(arena.allocator(), &lines, .REQUEST, false, &faults);
    try testing.expectEqual(@as(usize, 0), faults.slice().len);

    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "x-real-ip: 192.0.2.60\r\n" ++
            "x-forwarded-proto: https\r\n" ++
            "x-origin: https://example.com/edge\r\n" ++
            "x-static: no token here\r\n",
        try written(table, &buf, .{ .client_ip = "192.0.2.60", .scheme = "https", .host = "example.com" }),
    );
}

test "zix zixer: cfg headers, an empty token value writes the header with no value" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{lineOf("x-forwarded-host", "$host", 3)};

    const table = try compile(arena.allocator(), &lines, .REQUEST, false, &faults);

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("x-forwarded-host: \r\n", try written(table, &buf, .{}));
}

test "zix zixer: cfg headers, a lone dollar sign stays text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-price", "$ 40 USD", 3),
        lineOf("x-svn", "$Revision$", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);
    try testing.expectEqual(@as(usize, 0), faults.slice().len);

    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("x-price: $ 40 USD\r\nx-svn: $Revision$\r\n", try written(table, &buf, .{}));
}

test "zix zixer: cfg headers, an unknown token faults and the line is left out" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-request-id", "$request_id", 3),
        lineOf("x-frame-options", "DENY", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expectEqual(@as(usize, 1), faults.slice().len);
    try testing.expectEqualStrings("x-request-id", faults.slice()[0].key);
    try testing.expectEqualStrings("unknown token '$request_id' on line 3, use $client_ip, $scheme, or $host", faults.slice()[0].hint);

    // The good line after it still compiles, so one typo does not hide the
    // next problem.
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("x-frame-options: DENY\r\n", try written(table, &buf, .{}));
    try testing.expect(!table.owns("x-request-id"));
}

test "zix zixer: cfg headers, a value carrying CRLF is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-frame-options", "DENY\r\nx-injected: yes", 3),
        lineOf("x-nul", "a\x00b", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expect(table.isEmpty());
    try testing.expectEqual(@as(usize, 2), faults.slice().len);
    try testing.expectEqualStrings("line 3 has byte 0x0D in its value, a header value is one line of visible characters", faults.slice()[0].hint);
    try testing.expectEqualStrings("line 4 has byte 0x00 in its value, a header value is one line of visible characters", faults.slice()[1].hint);
}

test "zix zixer: cfg headers, a name outside the token set is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{lineOf("x frame options", "DENY", 3)};

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expect(table.isEmpty());
    try testing.expectEqualStrings("line 3 is not a header name, use letters, digits, and - . _ ~ (rfc 9110 5.1)", faults.slice()[0].hint);
}

test "zix zixer: cfg headers, the same name twice is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-frame-options", "DENY", 3),
        lineOf("X-Frame-Options", "SAMEORIGIN", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expectEqual(@as(usize, 1), faults.slice().len);
    try testing.expectEqualStrings("duplicate header on line 4, keep one line", faults.slice()[0].hint);

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("x-frame-options: DENY\r\n", try written(table, &buf, .{}));
}

test "zix zixer: cfg headers, the names zixer writes itself are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("Content-Length", "0", 3),
        lineOf("transfer-encoding", "chunked", 4),
        lineOf("Connection", "close", 5),
        lineOf("upgrade", "websocket", 6),
        lineOf("via", "1.1 other", 7),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expect(table.isEmpty());
    try testing.expectEqual(@as(usize, 5), faults.slice().len);
    try testing.expectEqualStrings("zixer writes the message framing itself, remove it", faults.slice()[0].hint);
    try testing.expectEqualStrings("zixer writes the message framing itself, remove it", faults.slice()[1].hint);
    try testing.expectEqualStrings("is hop-by-hop and never crosses a proxy (rfc 9110), remove it", faults.slice()[2].hint);
    try testing.expectEqualStrings("is hop-by-hop and never crosses a proxy (rfc 9110), remove it", faults.slice()[3].hint);
    try testing.expectEqualStrings("zixer writes its own Via element on every hop, remove it", faults.slice()[4].hint);
}

test "zix zixer: cfg headers, HSTS needs tls on the response leg" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const lines = [_]cfg_scanner.Entry{lineOf("strict-transport-security", "max-age=31536000", 3)};

    var cleartext_faults = fault.FaultList.init(arena.allocator());
    const cleartext = try compile(arena.allocator(), &lines, .RESPONSE, false, &cleartext_faults);
    try testing.expect(cleartext.isEmpty());
    try testing.expectEqualStrings("needs tls: true, a cleartext answer must not carry HSTS (rfc 6797 7.2)", cleartext_faults.slice()[0].hint);

    var secure_faults = fault.FaultList.init(arena.allocator());
    const secure = try compile(arena.allocator(), &lines, .RESPONSE, true, &secure_faults);
    try testing.expectEqual(@as(usize, 0), secure_faults.slice().len);

    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings("strict-transport-security: max-age=31536000\r\n", try written(secure, &buf, .{}));
}

test "zix zixer: cfg headers, the upstream leg refuses what it does not own" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("Host", "backend.internal", 3),
        lineOf("forwarded", "for=1.2.3.4", 4),
        lineOf("strict-transport-security", "max-age=1", 5),
    };

    const table = try compile(arena.allocator(), &lines, .REQUEST, true, &faults);

    try testing.expect(table.isEmpty());
    try testing.expectEqual(@as(usize, 3), faults.slice().len);
    try testing.expectEqualStrings("the upstream Host comes from the client request, setting it here would send two", faults.slice()[0].hint);
    try testing.expectEqualStrings("zixer writes it from the accepted connection (rfc 7239), use $client_ip in a header of your own", faults.slice()[1].hint);
    try testing.expectEqualStrings("is a header for the client, move it to [response_headers]", faults.slice()[2].hint);
}

test "zix zixer: cfg headers, the response leg refuses Date and keeps Host" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("Date", "Sat, 09 Aug 2026 00:00:00 GMT", 3),
        lineOf("content-location", "https://$host/here", 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, true, &faults);

    try testing.expectEqual(@as(usize, 1), faults.slice().len);
    try testing.expectEqualStrings("zixer sends Date from its own clock, setting it here would send two", faults.slice()[0].hint);

    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings(
        "content-location: https://example.com/here\r\n",
        try written(table, &buf, .{ .host = "example.com" }),
    );
}

test "zix zixer: cfg headers, a configured name is owned so the relayed copy can go" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{lineOf("x-frame-options", "DENY", 3)};

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    try testing.expect(table.owns("x-frame-options"));
    try testing.expect(table.owns("X-Frame-Options"));
    try testing.expect(!table.owns("x-frame-option"));
    try testing.expect(!table.owns("content-type"));
}

test "zix zixer: cfg headers, a section with no lines compiles to nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const table = try compile(arena.allocator(), &.{}, .RESPONSE, false, &faults);

    try testing.expect(table.isEmpty());
    try testing.expectEqual(@as(usize, 0), faults.slice().len);
    try testing.expect(!table.owns("x-frame-options"));

    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("", try written(table, &buf, .{}));
}

test "zix zixer: cfg headers, the per-line view carries the same values as the block" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-frame-options", "DENY", 3),
        lineOf("x-real-ip", "$client_ip", 4),
        lineOf("x-origin", "$scheme://$host/edge", 5),
        lineOf("x-static", "no token here", 6),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);
    const values = TokenValues{ .client_ip = "192.0.2.60", .scheme = "https", .host = "example.com" };

    try testing.expectEqual(@as(usize, 4), table.lines.len);
    try testing.expectEqualStrings("x-frame-options", table.lines[0].name);
    try testing.expectEqualStrings("x-static", table.lines[3].name);

    // The h2 and h3 view renders each value on its own, and rendering all of
    // them back in order has to give the same bytes the h1 view writes.
    var joined_buf: [256]u8 = undefined;
    var joined = std.Io.Writer.fixed(&joined_buf);
    var value_buf: [MAX_VALUE_BYTES]u8 = undefined;
    for (table.lines) |line| {
        try joined.print("{s}: {s}\r\n", .{ line.name, try line.renderValue(&value_buf, values) });
    }

    var block_buf: [256]u8 = undefined;
    try testing.expectEqualStrings(joined.buffered(), try written(table, &block_buf, values));

    // A line whose value is one long literal still renders, and a line with
    // no value pieces at all is possible when the whole value is a token.
    try testing.expectEqualStrings("192.0.2.60", try table.lines[1].renderValue(&value_buf, values));
    try testing.expectEqualStrings("https://example.com/edge", try table.lines[2].renderValue(&value_buf, values));
    try testing.expectEqualStrings("no token here", try table.lines[3].renderValue(&value_buf, values));
}

test "zix zixer: cfg headers, a rendered value past the scratch buffer errors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{lineOf("x-origin", "$host", 3)};
    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    var tiny: [4]u8 = undefined;
    try testing.expectError(
        error.WriteFailed,
        table.lines[0].renderValue(&tiny, .{ .host = "far-too-long.example" }),
    );
}

test "zix zixer: cfg headers, a section past the byte ceiling is refused whole" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var long_value: [MAX_BLOCK_BYTES]u8 = @splat('x');

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{
        lineOf("x-frame-options", "DENY", 3),
        lineOf("x-long", &long_value, 4),
    };

    const table = try compile(arena.allocator(), &lines, .RESPONSE, false, &faults);

    // Refused whole, not trimmed: half a block is not what the file asked for.
    try testing.expect(table.isEmpty());
    try testing.expectEqual(@as(usize, 1), faults.slice().len);
    try testing.expectEqualStrings("response_headers", faults.slice()[0].key);
    try testing.expect(std.mem.startsWith(u8, faults.slice()[0].hint, "the section compiles to "));
}

test "zix zixer: cfg headers, an empty block writes nothing and owns nothing" {
    const block = Block{};

    try testing.expect(block.isEmpty());
    try testing.expect(!block.owns("x-frame-options"));

    var buf: [8]u8 = undefined;
    var out = std.Io.Writer.fixed(&buf);
    try block.write(&out);
    try testing.expectEqualStrings("", out.buffered());
}

test "zix zixer: cfg headers, a block carries its request's token values" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const lines = [_]cfg_scanner.Entry{lineOf("x-real-ip", "$client_ip", 3)};
    const table = try compile(arena.allocator(), &lines, .REQUEST, false, &faults);

    const first = Block{ .table = table, .values = .{ .client_ip = "192.0.2.60" } };
    const second = Block{ .table = table, .values = .{ .client_ip = "198.51.100.7" } };

    var buf: [64]u8 = undefined;
    var first_out = std.Io.Writer.fixed(&buf);
    try first.write(&first_out);
    try testing.expectEqualStrings("x-real-ip: 192.0.2.60\r\n", first_out.buffered());

    var second_out = std.Io.Writer.fixed(&buf);
    try second.write(&second_out);
    try testing.expectEqualStrings("x-real-ip: 198.51.100.7\r\n", second_out.buffered());

    try testing.expect(first.owns("X-Real-IP"));
}

test "zix zixer: cfg headers, a duped table owns every byte it points at" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const owned = built: {
        // The inner arena stands in for the cfg arena, which an edge outlives.
        var cfg_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer cfg_arena.deinit();

        var faults = fault.FaultList.init(cfg_arena.allocator());
        const source = [_]cfg_scanner.Entry{
            lineOf("x-frame-options", "DENY", 3),
            lineOf("x-origin", "$scheme://$host/edge", 4),
        };
        const table = try compile(cfg_arena.allocator(), &source, .RESPONSE, false, &faults);

        try testing.expectEqual(@as(usize, 0), faults.slice().len);

        break :built try table.dupe(testing.allocator);
    };
    defer owned.deinit(testing.allocator);

    // Everything the copy points at was allocated by the copy, so the cfg
    // arena going away above changes nothing here.
    const values = TokenValues{ .scheme = "https", .host = "example.com" };
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "x-frame-options: DENY\r\nx-origin: https://example.com/edge\r\n",
        try written(owned, &buf, values),
    );

    try testing.expect(owned.owns("X-Frame-Options"));
    try testing.expectEqual(@as(usize, 2), owned.lines.len);
    try testing.expectEqualStrings("x-origin", owned.lines[1].name);

    var value_buf: [MAX_VALUE_BYTES]u8 = undefined;
    try testing.expectEqualStrings("https://example.com/edge", try owned.lines[1].renderValue(&value_buf, values));

    // The token-free line merged into its neighbour rather than standing on
    // its own, so a copy costs the same per request as the table it came from.
    // Five pieces: the first line plus the second line's name, then scheme,
    // "://", host, and the tail.
    try testing.expectEqual(@as(usize, 5), owned.pieces.len);
    try testing.expectEqualStrings("x-frame-options: DENY\r\nx-origin: ", owned.pieces[0].literal);
}

test "zix zixer: cfg headers, an empty table dupes and releases as nothing" {
    const owned = try (Table{}).dupe(testing.allocator);
    defer owned.deinit(testing.allocator);

    try testing.expect(owned.isEmpty());
}

test "zix zixer: cfg headers, each direction names its own section" {
    try testing.expectEqualStrings("response_headers", Direction.RESPONSE.sectionName());
    try testing.expectEqualStrings("request_headers", Direction.REQUEST.sectionName());
}
