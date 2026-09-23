//! Server error representation: the first word of an error reply is a
//! stable prefix, mapped to an enum with the raw line always kept alongside.
//!
//! Note:
//! - Unmapped prefixes become .UNKNOWN, the raw line still carries the
//!   original text.

const std = @import("std");

/// Known error reply prefixes.
pub const Prefix = enum {
    ERR,
    WRONGTYPE,
    NOAUTH,
    WRONGPASS,
    NOPERM,
    NOPROTO,
    OOM,
    BUSY,
    BUSYGROUP,
    BUSYKEY,
    NOGROUP,
    NOSCRIPT,
    NOTBUSY,
    LOADING,
    READONLY,
    MISCONF,
    MASTERDOWN,
    NOREPLICAS,
    EXECABORT,
    UNKILLABLE,
    MOVED,
    ASK,
    CLUSTERDOWN,
    CROSSSLOT,
    TRYAGAIN,
    UNKNOWN,
};

/// The last error reply captured on a connection.
pub const ServerError = struct {
    prefix: Prefix = .UNKNOWN,
    line_buf: [512]u8 = undefined,
    line_len: usize = 0,

    /// Capture one raw error line (prefix word included). Longer lines
    /// truncate to the buffer.
    pub fn capture(self: *ServerError, line: []const u8) void {
        const word_end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
        self.prefix = std.meta.stringToEnum(Prefix, line[0..word_end]) orelse .UNKNOWN;

        const keep = @min(line.len, self.line_buf.len);
        @memcpy(self.line_buf[0..keep], line[0..keep]);
        self.line_len = keep;
    }

    /// The full raw error line.
    pub fn raw(self: *const ServerError) []const u8 {
        return self.line_buf[0..self.line_len];
    }

    /// The text after the prefix word (the raw line when no space exists).
    pub fn message(self: *const ServerError) []const u8 {
        const line = self.raw();
        const word_end = std.mem.indexOfScalar(u8, line, ' ') orelse return line;

        return line[word_end + 1 ..];
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz: server error maps known prefixes" {
    var server_error = ServerError{};

    server_error.capture("ERR unknown command 'FOO'");
    try testing.expectEqual(Prefix.ERR, server_error.prefix);
    try testing.expectEqualStrings("unknown command 'FOO'", server_error.message());
    try testing.expectEqualStrings("ERR unknown command 'FOO'", server_error.raw());

    server_error.capture("WRONGTYPE Operation against a key holding the wrong kind of value");
    try testing.expectEqual(Prefix.WRONGTYPE, server_error.prefix);

    server_error.capture("NOAUTH Authentication required.");
    try testing.expectEqual(Prefix.NOAUTH, server_error.prefix);

    server_error.capture("MOVED 3999 127.0.0.1:6381");
    try testing.expectEqual(Prefix.MOVED, server_error.prefix);
    try testing.expectEqualStrings("3999 127.0.0.1:6381", server_error.message());
}

test "rediz: server error keeps unknown prefixes raw" {
    var server_error = ServerError{};

    server_error.capture("SOMENEWTHING details here");
    try testing.expectEqual(Prefix.UNKNOWN, server_error.prefix);
    try testing.expectEqualStrings("SOMENEWTHING details here", server_error.raw());

    server_error.capture("nolowercasematch");
    try testing.expectEqual(Prefix.UNKNOWN, server_error.prefix);
    try testing.expectEqualStrings("nolowercasematch", server_error.message());
}

test "rediz: server error truncates an oversized line" {
    var server_error = ServerError{};

    var long_line: [604]u8 = undefined;
    @memcpy(long_line[0..4], "ERR ");
    @memset(long_line[4..], 'x');

    server_error.capture(&long_line);
    try testing.expectEqual(Prefix.ERR, server_error.prefix);
    try testing.expectEqual(@as(usize, 512), server_error.raw().len);
}
