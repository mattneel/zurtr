//! zixer config numeric math: integer expressions with D.M.A.S. precedence

const std = @import("std");

/// Cap on '(' nesting so a pathological value cannot exhaust the stack.
const MAX_DEPTH: usize = 32;

pub const Error = error{
    ZixerBadExpression,
    ZixerDivisionByZero,
    ZixerInexactDivision,
    Overflow,
};

/// Read position over one expression, skipping spaces and tabs.
const Cursor = struct {
    text: []const u8,
    pos: usize = 0,

    /// Next meaningful byte without consuming it, null at end of input.
    fn peek(cursor: *Cursor) ?u8 {
        while (cursor.pos < cursor.text.len) {
            const byte = cursor.text[cursor.pos];
            if (byte != ' ' and byte != '\t') return byte;

            cursor.pos += 1;
        }

        return null;
    }
};

/// Evaluate a config numeric value.
///
/// Note:
/// - Integers only, operators + - * /, parentheses allowed.
/// - D.M.A.S. precedence: * and / bind first left-to-right, then + and -.
/// - Division must be exact: a remainder is an error, silent truncation hides typos.
///
/// Param:
/// text - []const u8 (the raw config value, i.e. "16 * 1024")
///
/// Return:
/// - i64 result of the expression
/// - error.ZixerBadExpression when the text is not an expression the grammar covers
/// - error.ZixerDivisionByZero, error.ZixerInexactDivision, error.Overflow on bad arithmetic
pub fn evaluate(text: []const u8) Error!i64 {
    var cursor = Cursor{ .text = text };
    const result = try parseSum(&cursor, 0);

    if (cursor.peek() != null) return error.ZixerBadExpression;

    return result;
}

/// Describe an evaluate() error as a config fault hint.
///
/// Return:
/// - []const u8 (static hint text, junior-readable)
pub fn hint(err: Error) []const u8 {
    return switch (err) {
        error.ZixerBadExpression => "not a number or integer math (i.e. 16 * 1024)",
        error.ZixerDivisionByZero => "division by zero",
        error.ZixerInexactDivision => "division leaves a remainder, config values must be exact",
        error.Overflow => "number does not fit 64-bit integer math",
    };
}

/// Sum level: + and -, lowest precedence, left-to-right.
fn parseSum(cursor: *Cursor, depth: usize) Error!i64 {
    var total = try parseProduct(cursor, depth);

    while (cursor.peek()) |op| {
        if (op != '+' and op != '-') break;
        cursor.pos += 1;

        const rhs = try parseProduct(cursor, depth);
        total = if (op == '+')
            std.math.add(i64, total, rhs) catch return error.Overflow
        else
            std.math.sub(i64, total, rhs) catch return error.Overflow;
    }

    return total;
}

/// Product level: * and /, binds before + and -, left-to-right.
fn parseProduct(cursor: *Cursor, depth: usize) Error!i64 {
    var total = try parseFactor(cursor, depth);

    while (cursor.peek()) |op| {
        if (op != '*' and op != '/') break;
        cursor.pos += 1;

        const rhs = try parseFactor(cursor, depth);
        if (op == '*') {
            total = std.math.mul(i64, total, rhs) catch return error.Overflow;
        } else {
            if (rhs == 0) return error.ZixerDivisionByZero;
            if (@rem(total, rhs) != 0) return error.ZixerInexactDivision;

            total = @divTrunc(total, rhs);
        }
    }

    return total;
}

/// Factor level: a plain integer or a parenthesized sub-expression.
fn parseFactor(cursor: *Cursor, depth: usize) Error!i64 {
    const first = cursor.peek() orelse return error.ZixerBadExpression;

    if (first == '(') {
        if (depth >= MAX_DEPTH) return error.ZixerBadExpression;
        cursor.pos += 1;

        const inner = try parseSum(cursor, depth + 1);
        if (cursor.peek() != ')') return error.ZixerBadExpression;
        cursor.pos += 1;

        return inner;
    }

    if (first < '0' or first > '9') return error.ZixerBadExpression;

    var value: i64 = 0;
    while (cursor.pos < cursor.text.len) {
        const byte = cursor.text[cursor.pos];
        if (byte < '0' or byte > '9') break;

        value = std.math.mul(i64, value, 10) catch return error.Overflow;
        value = std.math.add(i64, value, byte - '0') catch return error.Overflow;
        cursor.pos += 1;
    }

    return value;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: cfg math, plain number" {
    try std.testing.expectEqual(@as(i64, 1472), try evaluate("1472"));
    try std.testing.expectEqual(@as(i64, 0), try evaluate("0"));
}

test "zix zixer: cfg math, multiplication and division before addition" {
    try std.testing.expectEqual(@as(i64, 7), try evaluate("1 + 2 * 3"));
    try std.testing.expectEqual(@as(i64, 12), try evaluate("10 + 8 / 4"));
    try std.testing.expectEqual(@as(i64, 16384), try evaluate("16 * 1024"));
    try std.testing.expectEqual(@as(i64, 256), try evaluate("1 * 1024 / 4"));
}

test "zix zixer: cfg math, same precedence runs left-to-right" {
    try std.testing.expectEqual(@as(i64, 1), try evaluate("8 / 4 / 2"));
    try std.testing.expectEqual(@as(i64, 5), try evaluate("10 - 2 - 3"));
}

test "zix zixer: cfg math, parentheses override precedence" {
    try std.testing.expectEqual(@as(i64, 9), try evaluate("(1 + 2) * 3"));
    try std.testing.expectEqual(@as(i64, 2), try evaluate("((2))"));
    try std.testing.expectEqual(@as(i64, 6), try evaluate("12 / (4 - 2)"));
}

test "zix zixer: cfg math, spaces and tabs are skipped" {
    try std.testing.expectEqual(@as(i64, 2048), try evaluate("  2\t* 1024 "));
}

test "zix zixer: cfg math, inexact division is an error" {
    try std.testing.expectError(error.ZixerInexactDivision, evaluate("10 / 4"));
    try std.testing.expectError(error.ZixerInexactDivision, evaluate("1 / 2"));
}

test "zix zixer: cfg math, division by zero is an error" {
    try std.testing.expectError(error.ZixerDivisionByZero, evaluate("1 / 0"));
    try std.testing.expectError(error.ZixerDivisionByZero, evaluate("1 / (2 - 2)"));
}

test "zix zixer: cfg math, overflow is an error" {
    try std.testing.expectError(error.Overflow, evaluate("9223372036854775807 + 1"));
    try std.testing.expectError(error.Overflow, evaluate("99999999999999999999"));
}

test "zix zixer: cfg math, syntax the grammar does not cover is an error" {
    try std.testing.expectError(error.ZixerBadExpression, evaluate(""));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("abc"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("1 +"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("(1"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("1)"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("1 2"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("-1"));
    try std.testing.expectError(error.ZixerBadExpression, evaluate("1.5"));
}

test "zix zixer: cfg math, nesting past the depth cap is an error" {
    var deep_buf: [MAX_DEPTH * 2 + 3]u8 = undefined;
    const opens: [MAX_DEPTH + 1]u8 = @splat('(');
    const closes: [MAX_DEPTH + 1]u8 = @splat(')');

    const deep = try std.fmt.bufPrint(&deep_buf, "{s}1{s}", .{ opens, closes });
    try std.testing.expectError(error.ZixerBadExpression, evaluate(deep));
}
