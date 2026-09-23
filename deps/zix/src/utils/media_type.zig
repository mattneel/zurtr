//! zix media type
//!
//! A Content-Type header value carries a media type followed by optional
//! parameters, as in `application/sql; charset=utf-8`. Deciding whether a
//! request carries a type a route accepts is a comparison of the type and
//! subtype alone, so the parameters come off first.
//!
//! RFC 10008 section 2 makes that decision mandatory for the QUERY method: a
//! request whose content type is missing or unsupported is refused, and a
//! server may not sniff the body to guess. Both HTTP/1 engines share this
//! helper so the two answer identically.

const std = @import("std");

/// Longest media type string either engine can name, with room to grow.
/// `application/x-www-form-urlencoded` is 33 bytes, the current longest.
pub const MAX_LEN: usize = 64;

/// Drop the parameters from a Content-Type header value
///
/// Note:
/// - Surrounding spaces and tabs are trimmed from what remains
/// - A value with no parameters is returned trimmed but otherwise unchanged
/// - The result borrows header_value, it is not copied
///
/// Param:
/// header_value - []const u8 (a raw Content-Type value)
///
/// Return:
/// - []const u8 (the type and subtype, e.g. "application/sql")
pub fn stripParameters(header_value: []const u8) []const u8 {
    const semicolon_pos = std.mem.indexOfScalar(u8, header_value, ';') orelse header_value.len;
    const type_only = header_value[0..semicolon_pos];

    return std.mem.trim(u8, type_only, " \t");
}

/// Compare a Content-Type header value against a bare media type
///
/// Note:
/// - Case-insensitive, because media types are case-insensitive on the wire
/// - Parameters on header_value are ignored, so
///   `application/sql; charset=utf-8` matches `application/sql`
///
/// Param:
/// header_value - []const u8 (a raw Content-Type value, parameters allowed)
/// media_type - []const u8 (a bare type/subtype to match against)
///
/// Return:
/// - bool
pub fn equalIgnoreParameters(header_value: []const u8, media_type: []const u8) bool {
    return std.ascii.eqlIgnoreCase(stripParameters(header_value), media_type);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: media type strips a charset parameter" {
    try std.testing.expectEqualStrings("application/sql", stripParameters("application/sql; charset=utf-8"));
}

test "zix utils: media type leaves a bare value unchanged" {
    try std.testing.expectEqualStrings("application/json", stripParameters("application/json"));
}

test "zix utils: media type trims the space before a parameter" {
    try std.testing.expectEqualStrings("text/plain", stripParameters("text/plain ; charset=us-ascii"));
}

test "zix utils: media type keeps a multipart boundary out of the result" {
    const header_value = "multipart/form-data; boundary=----zixBoundary1234567890";

    try std.testing.expectEqualStrings("multipart/form-data", stripParameters(header_value));
}

test "zix utils: media type handles more than one parameter" {
    try std.testing.expectEqualStrings("application/sql", stripParameters("application/sql; charset=utf-8; v=1"));
}

test "zix utils: media type on an empty value yields empty" {
    try std.testing.expectEqualStrings("", stripParameters(""));
}

test "zix utils: media type on a lone semicolon yields empty" {
    try std.testing.expectEqualStrings("", stripParameters(";"));
}

test "zix utils: media type comparison ignores case" {
    try std.testing.expect(equalIgnoreParameters("APPLICATION/SQL", "application/sql"));
    try std.testing.expect(equalIgnoreParameters("Application/Sql; charset=utf-8", "application/sql"));
}

test "zix utils: media type comparison rejects a different subtype" {
    try std.testing.expect(!equalIgnoreParameters("application/json", "application/sql"));
}

test "zix utils: media type comparison rejects a prefix that is not the whole type" {
    // "application/sqlite" must not answer to "application/sql".
    try std.testing.expect(!equalIgnoreParameters("application/sqlite", "application/sql"));
}
