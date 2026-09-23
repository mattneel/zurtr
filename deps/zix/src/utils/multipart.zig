//! zix multipart utils

const std = @import("std");

// --------------------------------------------------------- //

/// What a multipart body can be wrong about.
///
/// Note:
/// - Both mean the same thing to a handler: do not save this upload. They are separate so a caller
///   can tell a body that never arrived from one that arrived only in part.
pub const ParseError = error{
    /// No opening boundary anywhere in the body. An empty body reaches here, which is how a caller
    /// tells "the upload never arrived" apart from "the upload carried no fields".
    ZixMultipartNoBoundary,
    /// Parts were found but the closing boundary never was, so the body is cut short.
    ZixMultipartUnterminated,
};

/// One parsed part of a multipart body.
///
/// Note:
/// - Every slice here borrows the body passed to parse, file data included. Nothing is copied, so a
///   large upload costs no memory beyond the body itself, and nothing outlives the body: copy what
///   has to survive the handler call.
pub const Field = struct {
    name: []const u8,
    filename: ?[]const u8,
    content_type: ?[]const u8,
    data: []const u8,
    is_file: bool,
};

/// Position of the next real boundary delimiter at or after `from`.
///
/// Note:
/// - The boundary text counts as a delimiter only when CRLF (another part follows) or `--` (the
///   body ends) comes after it, so a file that happens to contain the boundary is not split in two.
/// - Scanning resumes from the last position instead of restarting, which is what keeps a body with
///   many parts linear rather than one scan per part.
///
/// Param:
/// body - []const u8 (full request body)
/// from - usize (byte offset to start scanning at)
/// delimiter - []const u8 (the boundary with its leading two dashes)
///
/// Return:
/// - usize (offset of the delimiter's first dash)
/// - null when no delimiter follows `from`
fn findDelimiter(body: []const u8, from: usize, delimiter: []const u8) ?usize {
    var at = from;

    while (std.mem.indexOfPos(u8, body, at, delimiter)) |found| {
        const after = found + delimiter.len;

        if (after + 1 < body.len) {
            if (body[after] == '-' and body[after + 1] == '-') return found;
            if (body[after] == '\r' and body[after + 1] == '\n') return found;
        }

        at = found + 1;
    }

    return null;
}

/// Whether a match starting at `at` begins a new Content-Disposition parameter rather than ending a
/// longer one. Walks back over spacing to the separator that precedes it.
///
/// Param:
/// disposition - []const u8 (the Content-Disposition value)
/// at - usize (offset the match starts at)
///
/// Return:
/// - bool
fn startsParam(disposition: []const u8, at: usize) bool {
    var back = at;

    while (back > 0) {
        back -= 1;

        switch (disposition[back]) {
            ' ', '\t' => continue,
            ';' => return true,
            else => return false,
        }
    }

    return true;
}

/// Value of a quoted Content-Disposition parameter, so `name="upload"` yields `upload`.
///
/// Note:
/// - The key must sit at a parameter boundary, which is what keeps a lookup of `name` from finding
///   the one spelled inside `filename`. Clients are free to write the two in either order.
///
/// Param:
/// disposition - []const u8 (the Content-Disposition value, everything after the colon)
/// key - []const u8 (parameter name, e.g. "name" or "filename")
///
/// Return:
/// - []const u8 (the value between the quotes)
/// - null when the parameter is absent or its closing quote never arrives
fn dispositionParam(disposition: []const u8, key: []const u8) ?[]const u8 {
    var at: usize = 0;

    while (std.mem.indexOfPos(u8, disposition, at, key)) |found| {
        const after = found + key.len;
        at = after;

        if (!startsParam(disposition, found)) continue;
        if (after + 1 >= disposition.len or disposition[after] != '=' or disposition[after + 1] != '"') continue;

        const value_start = after + 2;
        const value_end = std.mem.indexOfScalarPos(u8, disposition, value_start, '"') orelse return null;

        return disposition[value_start..value_end];
    }

    return null;
}

pub const Parser = struct {
    boundary: []const u8,
    fields: std.ArrayList(Field),
    allocator: std.mem.Allocator,

    /// Initialize the multipart parser with the given boundary
    ///
    /// Param:
    /// allocator - std.mem.Allocator
    /// boundary - []const u8 (boundary string from the Content-Type header)
    ///
    /// Return:
    /// - Parser
    pub fn init(allocator: std.mem.Allocator, boundary: []const u8) Parser {
        return .{
            .boundary = boundary,
            .fields = .empty,
            .allocator = allocator,
        };
    }

    /// Free the fields list
    ///
    /// Note:
    /// - Every slice in a Field borrows the body passed to parse, so the list is all there is to free
    pub fn deinit(self: *Parser) void {
        self.fields.deinit(self.allocator);
    }

    /// Parse the multipart body into individual fields
    ///
    /// Note:
    /// - The body must be whole. A short one is refused rather than parsed part way, so a handler
    ///   never stores a truncated upload as though it were complete. The engine answers the size
    ///   question first: check req.bodyComplete(), and req.bodyReceived() against req.body().len,
    ///   before calling this.
    /// - One forward pass over the body, so cost stays linear in its size no matter how many parts
    ///   it carries.
    /// - Every field slice borrows the body, so a parsed upload costs no memory beyond it.
    ///
    /// Param:
    /// body - []const u8 (full request body)
    ///
    /// Return:
    /// - !void
    /// - error.ZixMultipartNoBoundary when the opening boundary is absent, which an empty body is
    /// - error.ZixMultipartUnterminated when the closing boundary never arrived
    pub fn parse(self: *Parser, body: []const u8) !void {
        const delimiter = try self.allocator.alloc(u8, self.boundary.len + 2);
        defer self.allocator.free(delimiter);

        delimiter[0] = '-';
        delimiter[1] = '-';
        @memcpy(delimiter[2..][0..self.boundary.len], self.boundary);

        var cursor = findDelimiter(body, 0, delimiter) orelse return ParseError.ZixMultipartNoBoundary;

        while (true) {
            const after = cursor + delimiter.len;

            // findDelimiter already proved these two bytes are either `--` or CRLF, so the one dash
            // is enough to tell the closing delimiter from the start of another part.
            if (body[after] == '-') return;

            const part_start = after + 2;
            const next = findDelimiter(body, part_start, delimiter) orelse return ParseError.ZixMultipartUnterminated;

            try self.appendPart(body[part_start..next]);

            cursor = next;
        }
    }

    /// Pull one part's headers and content out of the bytes between two delimiters
    ///
    /// Note:
    /// - A part carrying no name in its Content-Disposition is skipped, since nothing could look it
    ///   up afterwards.
    ///
    /// Param:
    /// raw - []const u8 (bytes from just after one delimiter's CRLF up to the next delimiter)
    ///
    /// Return:
    /// - !void
    fn appendPart(self: *Parser, raw: []const u8) !void {
        const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return;

        const headers = raw[0..header_end];
        var content = raw[header_end + 4 ..];

        // The CRLF in front of the next delimiter is framing, not content. Exactly those two bytes
        // come off, so a file whose own last bytes are CR or LF keeps them.
        if (std.mem.endsWith(u8, content, "\r\n")) content = content[0 .. content.len - 2];

        var field_name: ?[]const u8 = null;
        var field_filename: ?[]const u8 = null;
        var field_content_type: ?[]const u8 = null;

        var header_iter = std.mem.splitScalar(u8, headers, '\n');
        while (header_iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, "\r\n ");
            if (std.mem.startsWith(u8, trimmed, "Content-Disposition:")) {
                const disposition = trimmed["Content-Disposition:".len..];
                field_name = dispositionParam(disposition, "name");
                field_filename = dispositionParam(disposition, "filename");
            } else if (std.mem.startsWith(u8, trimmed, "Content-Type:")) {
                field_content_type = std.mem.trim(u8, trimmed["Content-Type:".len..], " \r\n");
            }
        }

        const name = field_name orelse return;

        try self.fields.append(self.allocator, .{
            .name = name,
            .filename = field_filename,
            .content_type = field_content_type,
            .data = content,
            .is_file = (field_filename != null),
        });
    }

    /// Look up a parsed field by name
    ///
    /// Note:
    /// - null if no field with that name was parsed
    ///
    /// Param:
    /// name - []const u8
    ///
    /// Return:
    /// - ?*Field
    pub fn getField(self: *Parser, name: []const u8) ?*Field {
        for (self.fields.items) |*f| {
            if (std.mem.eql(u8, f.name, name)) return f;
        }
        return null;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: multipart Parser parses form and file fields" {
    const boundary = "boundary123";
    const body =
        "--boundary123\r\n" ++
        "Content-Disposition: form-data; name=\"field1\"\r\n" ++
        "\r\n" ++
        "value1\r\n" ++
        "--boundary123\r\n" ++
        "Content-Disposition: form-data; name=\"file1\"; filename=\"test.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello world\r\n" ++
        "--boundary123--\r\n";

    var parser = Parser.init(std.testing.allocator, boundary);
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 2), parser.fields.items.len);

    const f1 = parser.getField("field1").?;
    try std.testing.expectEqualStrings("field1", f1.name);
    try std.testing.expectEqualStrings("value1", f1.data);
    try std.testing.expect(!f1.is_file);

    const f2 = parser.getField("file1").?;
    try std.testing.expectEqualStrings("file1", f2.name);
    try std.testing.expectEqualStrings("test.txt", f2.filename.?);
    try std.testing.expectEqualStrings("text/plain", f2.content_type.?);
    try std.testing.expectEqualStrings("hello world", f2.data);
    try std.testing.expect(f2.is_file);
}

test "zix utils: multipart keeps file bytes that are themselves CR or LF" {
    // A binary upload whose own first and last bytes are line terminators. Only the two framing
    // bytes in front of the next delimiter belong to the protocol, the other four are file data.
    const payload = "\r\nPAYLOAD\n\n";
    const body =
        "--bin\r\n" ++
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n" ++
        "\r\n" ++
        payload ++ "\r\n" ++
        "--bin--\r\n";

    var parser = Parser.init(std.testing.allocator, "bin");
    defer parser.deinit();

    try parser.parse(body);

    const field = parser.getField("f").?;
    try std.testing.expectEqualStrings(payload, field.data);
    try std.testing.expectEqual(@as(usize, 11), field.data.len);
}

test "zix utils: multipart accepts a closing boundary with no trailing CRLF" {
    // Plenty of clients stop right after the closing dashes. The last part must still be parsed.
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"one\"\r\n" ++
        "\r\n" ++
        "1\r\n" ++
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"two\"\r\n" ++
        "\r\n" ++
        "2\r\n" ++
        "--b--";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 2), parser.fields.items.len);
    try std.testing.expectEqualStrings("1", parser.getField("one").?.data);
    try std.testing.expectEqualStrings("2", parser.getField("two").?.data);
}

test "zix utils: multipart reports an empty body instead of parsing nothing" {
    // The shape an engine hands over when an upload was larger than it can deliver. Silence here
    // would read to the handler as a request that simply carried no fields.
    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try std.testing.expectError(ParseError.ZixMultipartNoBoundary, parser.parse(""));
    try std.testing.expectEqual(@as(usize, 0), parser.fields.items.len);
}

test "zix utils: multipart reports a body cut off before its closing boundary" {
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n" ++
        "\r\n" ++
        "half of the fi";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try std.testing.expectError(ParseError.ZixMultipartUnterminated, parser.parse(body));
}

test "zix utils: multipart keeps a part whose content spells the boundary" {
    // The boundary text inside a file is not a delimiter unless CRLF or the closing dashes follow.
    const payload = "before--zixB!after";
    const body =
        "--zixB\r\n" ++
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n" ++
        "\r\n" ++
        payload ++ "\r\n" ++
        "--zixB--\r\n";

    var parser = Parser.init(std.testing.allocator, "zixB");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 1), parser.fields.items.len);
    try std.testing.expectEqualStrings(payload, parser.getField("f").?.data);
}

test "zix utils: multipart skips the preamble in front of the first boundary" {
    const body =
        "this text is not part of any field\r\n" ++
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"one\"\r\n" ++
        "\r\n" ++
        "1\r\n" ++
        "--b--\r\n";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 1), parser.fields.items.len);
    try std.testing.expectEqualStrings("1", parser.getField("one").?.data);
}

test "zix utils: multipart skips a part carrying no name" {
    const body =
        "--b\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "orphan\r\n" ++
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"kept\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--b--\r\n";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 1), parser.fields.items.len);
    try std.testing.expectEqualStrings("value", parser.getField("kept").?.data);
}

test "zix utils: multipart reads the name even when filename is written first" {
    // `filename="` spells `name="` inside itself, so a plain substring search finds the wrong one
    // whenever a client writes the parameters in this order.
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; filename=\"a.bin\"; name=\"upload\"\r\n" ++
        "\r\n" ++
        "payload\r\n" ++
        "--b--\r\n";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 1), parser.fields.items.len);

    const field = parser.getField("upload").?;
    try std.testing.expectEqualStrings("upload", field.name);
    try std.testing.expectEqualStrings("a.bin", field.filename.?);
    try std.testing.expectEqualStrings("payload", field.data);
    try std.testing.expect(field.is_file);
}

test "zix utils: multipart skips a part carrying a filename but no name" {
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; filename=\"a.bin\"\r\n" ++
        "\r\n" ++
        "payload\r\n" ++
        "--b--\r\n";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    try std.testing.expectEqual(@as(usize, 0), parser.fields.items.len);
}

test "zix utils: multipart points a file field at the body rather than copying it" {
    // A copy would double what a large upload costs, and it would outlive nothing, since every other
    // slice already borrows the body.
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n" ++
        "\r\n" ++
        "payload\r\n" ++
        "--b--\r\n";

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body);

    const field = parser.getField("f").?;
    const content_offset = std.mem.indexOf(u8, body, "payload").?;

    try std.testing.expectEqual(@intFromPtr(body.ptr) + content_offset, @intFromPtr(field.data.ptr));
}

test "zix utils: multipart parses a body of many parts in one pass" {
    const part_count: usize = 200;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);

    var scratch: [32]u8 = undefined;
    var index: usize = 0;
    while (index < part_count) : (index += 1) {
        try body.appendSlice(std.testing.allocator, "--b\r\nContent-Disposition: form-data; name=\"");
        try body.appendSlice(std.testing.allocator, try std.fmt.bufPrint(&scratch, "f{d}", .{index}));
        try body.appendSlice(std.testing.allocator, "\"\r\n\r\n");
        try body.appendSlice(std.testing.allocator, try std.fmt.bufPrint(&scratch, "v{d}", .{index}));
        try body.appendSlice(std.testing.allocator, "\r\n");
    }
    try body.appendSlice(std.testing.allocator, "--b--\r\n");

    var parser = Parser.init(std.testing.allocator, "b");
    defer parser.deinit();

    try parser.parse(body.items);

    try std.testing.expectEqual(part_count, parser.fields.items.len);
    try std.testing.expectEqualStrings("v0", parser.getField("f0").?.data);
    try std.testing.expectEqualStrings("v199", parser.getField("f199").?.data);
}
