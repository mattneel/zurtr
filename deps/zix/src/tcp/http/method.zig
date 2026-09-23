//! zix http method

const std = @import("std");

/// zix http method code
pub const Code = enum(u8) {
    const Self = @This();

    // --------------------------------------------------------- //

    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    TRACE,
    CONNECT,
    /// RFC 10008. Safe and idempotent like GET, carries content like POST.
    QUERY,

    // --------------------------------------------------------- //

    /// Get self object as a string
    ///
    /// Note:
    /// - The method-call spelling of stringFromEnum. One switch backs
    ///   both, so the two forms cannot report different strings
    ///
    /// Return:
    /// - []const u8
    pub fn asString(self: Self) []const u8 {
        return stringFromEnum(self);
    }
};

// --------------------------------------------------------- //

/// Longest method token this engine knows, in bytes ("OPTIONS", "CONNECT").
/// A token longer than this names no known method.
pub const MAX_TOKEN_LEN: usize = 7;

/// Get enum from string, reporting no match
///
/// Note:
/// - This is the one method table for this engine. The request-line parser
///   calls it rather than keeping its own copy, so an engine cannot drift from
///   the table it publishes
/// - RFC 9110 section 9.1 makes method names case-sensitive, so the match is
///   exact. A lowercase token names no method and reports null
/// - Returns null when the token names no method this engine knows, which lets
///   a caller answer 501 Not Implemented instead of acting on a wrong method
/// - The length switch rejects an oversized token before any compare, so a
///   token from the wire costs one length test and one compare
///
/// Param:
/// method_string - []const u8 (the raw token, matched exactly)
///
/// Return:
/// - zix.Tcp.Http.Method.Code
/// - null when the token matches no known method
pub fn codeFromString(method_string: []const u8) ?Code {
    return switch (method_string.len) {
        3 => if (std.mem.eql(u8, method_string, "GET")) Code.GET else if (std.mem.eql(u8, method_string, "PUT")) Code.PUT else null,
        4 => if (std.mem.eql(u8, method_string, "HEAD")) Code.HEAD else if (std.mem.eql(u8, method_string, "POST")) Code.POST else null,
        5 => if (std.mem.eql(u8, method_string, "PATCH")) Code.PATCH else if (std.mem.eql(u8, method_string, "TRACE")) Code.TRACE else if (std.mem.eql(u8, method_string, "QUERY")) Code.QUERY else null,
        6 => if (std.mem.eql(u8, method_string, "DELETE")) Code.DELETE else null,
        7 => if (std.mem.eql(u8, method_string, "OPTIONS")) Code.OPTIONS else if (std.mem.eql(u8, method_string, "CONNECT")) Code.CONNECT else null,
        else => null,
    };
}

/// Get enum from string
///
/// Note:
/// - If not match, it will return GET
/// - Callers that must tell an unknown method apart from a real GET use
///   codeFromString instead, which reports the no-match case as null
///
/// Param:
/// method_string - []const u8 (the raw token, matched exactly)
///
/// Return:
/// - zix.Tcp.Http.Method.Code
pub fn enumFromString(method_string: []const u8) Code {
    return codeFromString(method_string) orelse Code.GET;
}

/// Get string from enum
///
/// Note:
/// - Exhaustive
/// - Seperated by it's enum
///
/// Param:
/// method_enum - zix.Tcp.Http.Method.Code
///
/// Return:
/// - []const u8
pub fn stringFromEnum(method_enum: Code) []const u8 {
    return switch (method_enum) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
        .PATCH => "PATCH",
        .OPTIONS => "OPTIONS",
        .TRACE => "TRACE",
        .CONNECT => "CONNECT",
        .QUERY => "QUERY",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: method every code round-trips through its string" {
    const all_codes = [_]Code{
        Code.GET,
        Code.HEAD,
        Code.POST,
        Code.PUT,
        Code.DELETE,
        Code.PATCH,
        Code.OPTIONS,
        Code.TRACE,
        Code.CONNECT,
        Code.QUERY,
    };

    for (all_codes) |code| {
        const code_string = stringFromEnum(code);

        try std.testing.expectEqualStrings(code_string, code.asString());
        try std.testing.expectEqual(code, codeFromString(code_string).?);
    }
}

test "zix http: method QUERY resolves from its wire token" {
    try std.testing.expectEqual(Code.QUERY, enumFromString("QUERY"));
    try std.testing.expectEqual(Code.QUERY, codeFromString("QUERY").?);
}

test "zix http: method QUERY is not reported as GET" {
    // The pre-RFC-10008 behaviour answered GET for every unknown token, which
    // made a QUERY request indistinguishable from a GET to every handler.
    try std.testing.expect(enumFromString("QUERY") != Code.GET);
}

test "zix http: method token matching is case-sensitive" {
    // RFC 9110 section 9.1 makes method names case-sensitive, so a lowercase
    // token names no method. Both HTTP/1 engines read this one table, so a
    // fold here would put them back out of step with each other.
    try std.testing.expect(codeFromString("query") == null);
    try std.testing.expect(codeFromString("QuErY") == null);
    try std.testing.expect(codeFromString("get") == null);
    try std.testing.expect(codeFromString("Post") == null);
}

test "zix http: method codeFromString reports an unknown token as null" {
    try std.testing.expect(codeFromString("BREW") == null);
    try std.testing.expect(codeFromString("") == null);
}

test "zix http: method codeFromString rejects a token past MAX_TOKEN_LEN" {
    // Longer than any known method, so the length switch refuses it before any
    // compare rather than reading past the tokens it knows.
    try std.testing.expect(codeFromString("PROPPATCH") == null);
    try std.testing.expect(codeFromString("QUERYQUERYQUERY") == null);
}

test "zix http: method enumFromString keeps its GET fallback for unknown tokens" {
    try std.testing.expectEqual(Code.GET, enumFromString("BREW"));
    try std.testing.expectEqual(Code.GET, enumFromString("PROPPATCH"));
}
