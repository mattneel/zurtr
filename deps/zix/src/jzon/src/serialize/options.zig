//! jzon serialize options.
//!
//! What:
//! - What a caller hands a render, and what a render can hand back. Every
//!   strategy writes the same bytes for the same value, which is what makes
//!   picking one a cost decision and never a correctness one.

const std = @import("std");

/// Which write path a render runs.
///
/// Note:
/// - The default is the std-backed one, so `.{}` renders every shape std
///   renders. A generated strategy is opt-in, and asking for one on a shape it
///   has no JSON form for is a compile error naming the type.
/// - Read by the entry point that picks a path. The path under it is handed what
///   it needs and never sees which strategy named it.
pub const Strategy = enum {
    /// `std.json.Stringify`, which renders anything std renders.
    STD,
    /// Generated from the type, integers through `std.fmt`.
    GENERATED_FMT,
    /// Generated from the type, integer digits written straight into the buffer.
    GENERATED,
    /// As GENERATED, with strings scanned for escapes one vector lane at a time.
    /// It pays on long strings and costs on short ones.
    GENERATED_VECTOR,
};

/// The options a render runs with.
pub const Options = struct {
    strategy: Strategy = .STD,
};

/// How a render can fail.
///
/// Note:
/// - Nothing is allocated on the write side, so a buffer with no room left is
///   the whole failure surface.
pub const Error = @import("../sink.zig").Error;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "jzon: serialize options default to the capable path" {
    const options: Options = .{};

    try std.testing.expectEqual(Strategy.STD, options.strategy);
}

test "jzon: serialize reports through the write cursor's own error" {
    try std.testing.expectEqual(@import("../sink.zig").Error, Error);
    try std.testing.expectError(error.NoSpaceLeft, @as(Error!void, error.NoSpaceLeft));
}
