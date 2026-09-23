//! zix utils check string.

const std = @import("std");

/// Check if string is numeric signed.
fn isNumericSigned(str: []const u8) bool {
    if (str.len == 0) return false;

    var start_index: usize = 0;

    // Negative handle
    if (str[0] == '-') {
        if (str.len == 1) return false;
        start_index = 1;
    }

    // Leading zero check
    if (str[start_index] == '0') {
        if (str.len - start_index > 1) return false; 
        return true; // For "0" or "-0"
    }

    // Ensure the rest is digit
    for (str[start_index..]) |chr| {
        if (!std.ascii.isDigit(chr)) return false;
    }

    return true;
}

/// Check if string is numeric unsigned.
fn isNumericUnsigned(str: []const u8) bool {
    if (str.len == 0) return false;

    if (str[0] == '-') return false;

    // Leading zero check
    if (str[0] == '0') {
        if (str.len > 1) return false; 
        return true; 
    }

    // Ensure the rest is digit
    for (str) |chr| {
        if (!std.ascii.isDigit(chr)) return false;
    }

    return true;
}

/// Check if string is decimal.
///
/// Note:
/// - Must `N.N`
/// - `N.` is false
fn isDecimal(str: []const u8) bool {
    if (str.len == 0) return false;

    var start_index: usize = 0;

    // Negative handle
    if (str[0] == '-') {
        if (str.len == 1) return false;
        start_index = 1;
    }

    // First char after opt negative must digit
    if (!std.ascii.isDigit(str[start_index])) return false;

    var has_dot = false;

    // Leading zero check
    if (str[start_index] == '0') {
        // `0` or `-0` without . is wrong
        if (str.len - start_index == 1) return false;
        
        // Prevent `.0N`
        if (str[start_index + 1] != '.') return false;
        
        has_dot = true;
        
        // Prevent `0.`
        if (str.len - start_index < 3) return false;
        
        // Ensure the rest is digit
        for (str[start_index + 2 ..]) |chr| {
            if (!std.ascii.isDigit(chr)) return false;
        }
        return true;
    }

    // For N start with 1-9
    for (str[start_index..]) |chr| {
        if (chr == '.') {
            // Prevent multiple dot
            if (has_dot) return false;
            has_dot = true;
        } else if (!std.ascii.isDigit(chr)) {
            return false;
        }
    }

    // Extra requirement after . decimal and no `.` at the end
    if (!has_dot or str[str.len - 1] == '.') return false;

    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: check string isNumericSigned" {
    const case0 = "0"; // true
    const case1 = "-0"; // true
    const case2 = "0a"; // false
    const case3 = "-0a"; // false
    const case4 = "0123"; // false
    const case5 = "-0123"; // false
    const case6 = "123"; // true
    const case7 = "-123"; // true
    const case8 = "a0basdw"; // false
    const case9 = "3.14"; // false
    const case10 = "-3.14"; // false

    try std.testing.expectEqual(true, isNumericSigned(case0));
    try std.testing.expectEqual(true, isNumericSigned(case1));
    try std.testing.expectEqual(false, isNumericSigned(case2));
    try std.testing.expectEqual(false, isNumericSigned(case3));
    try std.testing.expectEqual(false, isNumericSigned(case4));
    try std.testing.expectEqual(false, isNumericSigned(case5));
    try std.testing.expectEqual(true, isNumericSigned(case6));
    try std.testing.expectEqual(true, isNumericSigned(case7));
    try std.testing.expectEqual(false, isNumericSigned(case8));
    try std.testing.expectEqual(false, isNumericSigned(case9));
    try std.testing.expectEqual(false, isNumericSigned(case10));
}

test "zix utils: check string isNumericUnsigned" {
    const case0 = "0";        // true
    const case1 = "123";      // true
    const case2 = "999999";   // true

    const case3 = "-0";       // false
    const case4 = "-123";     // false
    const case5 = "0123";     // false
    const case6 = "00";       // false
    const case7 = "123a";     // false
    const case8 = "a123";     // false
    const case9 = "3.14";     // false
    const case10 = "";        // false
    const case11 = " ";       // false

    try std.testing.expectEqual(true, isNumericUnsigned(case0));
    try std.testing.expectEqual(true, isNumericUnsigned(case1));
    try std.testing.expectEqual(true, isNumericUnsigned(case2));
    
    try std.testing.expectEqual(false, isNumericUnsigned(case3));
    try std.testing.expectEqual(false, isNumericUnsigned(case4));
    try std.testing.expectEqual(false, isNumericUnsigned(case5));
    try std.testing.expectEqual(false, isNumericUnsigned(case6));
    try std.testing.expectEqual(false, isNumericUnsigned(case7));
    try std.testing.expectEqual(false, isNumericUnsigned(case8));
    try std.testing.expectEqual(false, isNumericUnsigned(case9));
    try std.testing.expectEqual(false, isNumericUnsigned(case10));
    try std.testing.expectEqual(false, isNumericUnsigned(case11));
}

test "zix utils: check string isDecimal" {
    const case0 = "0";        // false
    const case1 = "-0";       // false
    const case2 = "0.0";      // true
    const case3 = "-0.5";     // true
    const case4 = "123";      // false
    const case5 = "123.45";   // true
    const case6 = "-3.14";    // true

    const case7 = "0.";       // false
    const case8 = ".5";       // false
    const case9 = "-.5";      // false
    const case10 = "05";      // false
    const case11 = "123.";    // false
    const case12 = "123.45.67"; // false
    const case13 = "a0basdw"; // false
    const case14 = "-";       // false

    try std.testing.expectEqual(false, isDecimal(case0));
    try std.testing.expectEqual(false, isDecimal(case1));
    try std.testing.expectEqual(true, isDecimal(case2));
    try std.testing.expectEqual(true, isDecimal(case3));
    try std.testing.expectEqual(false, isDecimal(case4));
    try std.testing.expectEqual(true, isDecimal(case5));
    try std.testing.expectEqual(true, isDecimal(case6));
    
    try std.testing.expectEqual(false, isDecimal(case7));
    try std.testing.expectEqual(false, isDecimal(case8));
    try std.testing.expectEqual(false, isDecimal(case9));
    try std.testing.expectEqual(false, isDecimal(case10));
    try std.testing.expectEqual(false, isDecimal(case11));
    try std.testing.expectEqual(false, isDecimal(case12));
    try std.testing.expectEqual(false, isDecimal(case13));
    try std.testing.expectEqual(false, isDecimal(case14));
}
