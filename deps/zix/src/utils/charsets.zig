//! Zix charsets for utils and as source of truth.
//!
//! Note:
//! - Any repeatable charsets or strings will use from here.

const std = @import("std");

// --------------------------------------------------------- //

/// 0123456789abcdef
pub const hex = "0123456789abcdef";

/// Alphabet set lower case
pub const alphabet = "abcdefghijklmnopqrs";

/// Alphabet set upper case
pub const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Numeric set as string
pub const NUMERIC_STRING = "0123456789";

/// Alphanumeric set
pub const ALPHANUMERIC = alphabet ++ ALPHABET ++ NUMERIC_STRING;

/// !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
pub const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
pub const ALPHANUMERIC_PUNCTUATION = ALPHANUMERIC ++ punctuation;

/// ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
pub const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
pub const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// --------------------------------------------------------- //
// --------------------------------------------------------- //

// hex: check correctness and correct length
test "zix charsets: hex" {
    const compare = "0123456789abcdef";

    try std.testing.expectEqual(@as(usize, compare.len), hex.len);
    try std.testing.expectEqualStrings(compare, hex);
}

// alphabet: check correctness and correct length
test "zix charsets: alphabet check" {
    const compare = "abcdefghijklmnopqrs";

    try std.testing.expectEqual(@as(usize, compare.len), alphabet.len);
    try std.testing.expectEqualStrings(compare, alphabet);
}

// ALPHABET: check correctness and correct length
test "zix charsets: ALPHABET check" {
    const compare = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    try std.testing.expectEqual(@as(usize, compare.len), ALPHABET.len);
    try std.testing.expectEqualStrings(compare, ALPHABET);
}

// NUMERIC_STRING: check correctness and correct length
test "zix charsets: NUMERIC_STRING check" {
    const compare = "0123456789";

    try std.testing.expectEqual(@as(usize, compare.len), NUMERIC_STRING.len);
    try std.testing.expectEqualStrings(compare, NUMERIC_STRING);
}

// ALPHANUMERIC: check correctness and correct length
test "zix charsets: ALPHANUMERIC check" {
    const set1 = "abcdefghijklmnopqrs";
    const set2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const set3 = "0123456789";
    const compare = set1 ++ set2 ++ set3;

    try std.testing.expectEqual(@as(usize, compare.len), ALPHANUMERIC.len);
    try std.testing.expectEqualStrings(compare, ALPHANUMERIC);
}

// punctuation: check correctness and correct length
test "zix charsets: punctuation check" {
    const compare = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    try std.testing.expectEqual(@as(usize, compare.len), punctuation.len);
    try std.testing.expectEqualStrings(compare, punctuation);
}

// ALPHANUMERIC_PUNCTUATION: check correctness and correct length
test "zix charsets: ALPHANUMERIC_PUNCTUATION check" {
    const set1 = "abcdefghijklmnopqrs";
    const set2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const set3 = "0123456789";
    const set4 = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    const compare = set1 ++ set2 ++ set3 ++ set4;

    try std.testing.expectEqual(@as(usize, compare.len), ALPHANUMERIC_PUNCTUATION.len);
    try std.testing.expectEqualStrings(compare, ALPHANUMERIC_PUNCTUATION);
}

// base32: check correctness and correct length
test "zix charsets: base32" {
    const compare = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    try std.testing.expectEqual(@as(usize, compare.len), base32.len);
    try std.testing.expectEqualStrings(compare, base32);
}

// base64: check correctness and correct length
test "zix charsets: base64" {
    const compare = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    try std.testing.expectEqual(@as(usize, compare.len), base64.len);
    try std.testing.expectEqualStrings(compare, base64);
}
