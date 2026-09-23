//! Zix utils generator.

const std = @import("std");

const charsets = @import("charsets.zig");

// --------------------------------------------------------- //

/// Generate random strings based on lenth and charset.
///
/// Param:
/// length - usize (length string you want to generate)
/// charset - []const u8 (set of characters)
/// io - std.Io
/// allocator - std.mem.Allocator
///
/// Return:
/// - ![]u8
pub fn strings(
    length: usize,
    charset: []const u8,
    io: std.Io,
    allocator: std.mem.Allocator
) ![]u8 {
    if (length == 0) {
        return error.ZixGeneratorStringsLengthParamIsZero;
    }
    if (charset.len == 0) {
        return error.ZixGeneratorStringsCharsetLenParamIsEmpty;
    }

    const random: std.Random.IoSource = .{ .io = io };
    const random_secure = random.interface();

    const result = try allocator.alloc(u8, length);

    for (result) |*char| {
        const idx = random_secure.intRangeAtMost(usize, 0, charset.len - 1);
        char.* = charset[idx];
    }

    return result;
}

pub fn numbers(
    comptime T: type,
    min: T,
    max: T,
    io: std.Io
) T {
    const random: std.Random.IoSource = .{ .io = io };
    const random_secure = random.interface();

    return random_secure.intRangeAtMost(T, min, max);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const StrAndLen = struct {
    str: []const u8,
    len: usize
};

test "zix utils: generator strings" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;

    const sets = [_]StrAndLen{
        StrAndLen{ .str = charsets.alphabet, .len = 8 },
        StrAndLen{ .str = charsets.ALPHABET, .len = 16 },
        StrAndLen{ .str = charsets.NUMERIC_STRING, .len = 32 },
        StrAndLen{ .str = charsets.ALPHANUMERIC, .len = 64 },
        StrAndLen{. str = charsets.punctuation, .len = 128 },
        StrAndLen{ .str = charsets.ALPHANUMERIC_PUNCTUATION, .len = 256 },
    };
    for (sets) |set| {
        const res = try strings(set.len, set.str, io, alloc);
        defer alloc.free(res);

        try std.testing.expectEqual(@as(usize, set.len), res.len);
    }
}

test "zix utils: generator numbers" {
    const io = std.testing.io;

    const case1 = numbers(u8, 1, 10, io);
    const case2 = numbers(u16, 10, 100, io);
    const case3 = numbers(u32, 100, 1000, io);
    const case4 = numbers(u64, 1000, 10000, io);
    const case5 = numbers(u128, 10000, 100000, io);

    try std.testing.expect(case1 >= 1 or case1 <= 10);
    try std.testing.expect(case2 >= 10 or case2 <= 100);
    try std.testing.expect(case3 >= 100 or case3 <= 1000);
    try std.testing.expect(case4 >= 1000 or case4 <= 10000);
    try std.testing.expect(case5 >= 10000 or case5 <= 100000);

    for (0..1_000) |i| {
        const case = numbers(usize, 1, i+1, io);

        try std.testing.expect(case >= 1 or case <= i+1);
    }
}
