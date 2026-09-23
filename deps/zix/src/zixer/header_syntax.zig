//! zixer header field syntax: what rfc 9110 allows in a field name and a field value

const std = @import("std");

/// True when byte is a tchar, the only class rfc 9110 5.6.2 allows in a field
/// name.
///
/// Note:
/// - The punctuation set is fixed by the rfc, it is not a zixer choice.
///
/// Param:
/// byte - u8 (one candidate character)
///
/// Return:
/// - bool
pub fn isTokenChar(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// True when name is a usable field name: one or more tchar and nothing else
/// (rfc 9110 5.1).
///
/// Param:
/// name - []const u8 (candidate field name)
///
/// Return:
/// - bool
pub fn isFieldName(name: []const u8) bool {
    if (name.len == 0) return false;

    for (name) |byte| {
        if (!isTokenChar(byte)) return false;
    }

    return true;
}

/// True when byte may stand inside a field value: a visible character, a tab,
/// a space, or an obs-text byte (rfc 9110 5.5).
///
/// Note:
/// - CR and LF are excluded on purpose. A value carrying either would end the
///   line early and let the rest of it be read as a header of its own, which
///   is header injection.
/// - The high range 0x80 to 0xFF is obs-text. The rfc keeps it for values that
///   were written before the field grammar settled, so it stays allowed.
///
/// Param:
/// byte - u8 (one candidate character)
///
/// Return:
/// - bool
pub fn isValueChar(byte: u8) bool {
    return switch (byte) {
        '\t', ' ' => true,
        0x21...0x7E => true,
        0x80...0xFF => true,
        else => false,
    };
}

/// The first byte of value that may not stand in a field value, null when the
/// whole value is usable.
///
/// Note:
/// - The position is what the caller needs for a fix hint, so this answers
///   with the offending byte rather than a plain bool.
///
/// Param:
/// value - []const u8 (candidate field value)
///
/// Return:
/// - u8, the first byte that is not allowed
/// - null, when every byte is allowed
pub fn firstBadValueChar(value: []const u8) ?u8 {
    for (value) |byte| {
        if (!isValueChar(byte)) return byte;
    }

    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: header syntax, a field name is one or more tchar" {
    try testing.expect(isFieldName("x-frame-options"));
    try testing.expect(isFieldName("X-Frame-Options"));
    try testing.expect(isFieldName("Content-Security-Policy"));
    try testing.expect(isFieldName("x_custom.name~1"));
    try testing.expect(isFieldName("!#$%&'*+-.^_`|~"));
}

test "zix zixer: header syntax, a field name refuses everything outside the token set" {
    try testing.expect(!isFieldName(""));
    try testing.expect(!isFieldName("x frame options"));
    try testing.expect(!isFieldName("x-frame:options"));
    try testing.expect(!isFieldName("x-frame\toptions"));
    try testing.expect(!isFieldName("(comment)"));
    try testing.expect(!isFieldName("x/y"));
    try testing.expect(!isFieldName("x-caf\xc3\xa9"));
}

test "zix zixer: header syntax, a field value keeps visible bytes tabs and spaces" {
    try testing.expectEqual(@as(?u8, null), firstBadValueChar("DENY"));
    try testing.expectEqual(@as(?u8, null), firstBadValueChar("public, max-age=3600"));
    try testing.expectEqual(@as(?u8, null), firstBadValueChar("</app.css#v2>; rel=preload"));
    try testing.expectEqual(@as(?u8, null), firstBadValueChar("one\ttwo"));
    try testing.expectEqual(@as(?u8, null), firstBadValueChar("caf\xc3\xa9"));
    try testing.expectEqual(@as(?u8, null), firstBadValueChar(""));
}

test "zix zixer: header syntax, a field value refuses the injection bytes" {
    try testing.expectEqual(@as(?u8, '\r'), firstBadValueChar("DENY\r\nX-Injected: yes"));
    try testing.expectEqual(@as(?u8, '\n'), firstBadValueChar("DENY\nX-Injected: yes"));
    try testing.expectEqual(@as(?u8, 0x00), firstBadValueChar("DE\x00NY"));
    try testing.expectEqual(@as(?u8, 0x7F), firstBadValueChar("DENY\x7F"));
    try testing.expectEqual(@as(?u8, 0x1B), firstBadValueChar("\x1b[31m"));
}
