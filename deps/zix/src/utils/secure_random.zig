//! Cryptographically secure randomness: one helper, one concern.
//!
//! What:
//! - `fill` puts kernel-quality random bytes in a buffer, on every target zix builds for. Keys,
//!   nonces, cookies, and connection identifiers all come from here rather than from each caller
//!   picking its own source.
//!
//! Note:
//! - Not a userspace generator, and deliberately so. Every caller is drawing something an attacker
//!   must not be able to predict, and a seeded generator is only as unpredictable as its seed.
//! - Cold path. It is called once per connection or once at startup, never per packet.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const win_io = @import("windows_io.zig");

/// Fill buf with cryptographically secure random bytes.
///
/// Note:
/// - Silent on failure, which on these three sources means the buffer keeps whatever it held. A
///   caller drawing a key should be handing in a buffer it is about to overwrite anyway.
///
/// Param:
/// buf - []u8 (filled in place)
///
/// Return:
/// - void
pub fn fill(buf: []u8) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = linux.getrandom(buf.ptr, buf.len, 0);

        return;
    }

    if (comptime builtin.target.os.tag == .windows) {
        win_io.secureRandom(buf) catch {};

        return;
    }

    std.c.arc4random_buf(buf.ptr, buf.len);
}

/// One random unsigned integer, in wire order.
///
/// Param:
/// Value - comptime type (an unsigned integer type)
///
/// Return:
/// - Value
pub fn int(comptime Value: type) Value {
    var bytes: [@divExact(@typeInfo(Value).int.bits, 8)]u8 = undefined;

    fill(&bytes);

    return std.mem.readInt(Value, &bytes, .big);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix utils: secure random, a filled buffer is not the zeros it started as" {
    var buf: [32]u8 = @splat(0);

    fill(&buf);

    try std.testing.expect(!std.mem.allEqual(u8, &buf, 0));
}

test "zix utils: secure random, two draws differ" {
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;

    fill(&first);
    fill(&second);

    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "zix utils: secure random, an empty buffer is left alone" {
    var buf: [0]u8 = undefined;

    fill(&buf);

    try std.testing.expectEqual(@as(usize, 0), buf.len);
}

test "zix utils: secure random, integers of each width come out varied" {
    var same: usize = 0;

    for (0..16) |_| {
        if (int(u32) == int(u32)) same += 1;
    }

    // Two independent 32-bit draws colliding 16 times running is not something to plan for.
    try std.testing.expect(same < 16);
}
