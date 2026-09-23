//! jzon deserialize options.
//!
//! What:
//! - What a caller hands a parse, and what a parse can hand back. Every path
//!   reads the same options and reports the same errors, which is what lets one
//!   be swapped for another without a line changing around the call.

const std = @import("std");

/// Which read path a parse runs.
///
/// Note:
/// - The default is the std-backed one, so `.{}` parses every shape std parses.
///   A generated strategy is opt-in, and asking for one on a shape it has no
///   JSON form for is a compile error naming the type.
/// - Read by the entry point that picks a path. The path under it is handed what
///   it needs and never sees which strategy named it.
pub const Strategy = enum {
    /// `std.json` reflection, which parses anything std parses.
    STD,
    /// Tokens from `std.json.Scanner`, with the field dispatch generated from
    /// the type. std still decides what a valid document is.
    SCANNER,
    /// Generated from the type, over jzon's own read cursor, scanning one byte
    /// at a time.
    GENERATED,
    /// As GENERATED, scanning one vector lane at a time. It pays on documents
    /// that arrive laid out with whitespace or carry long strings.
    GENERATED_VECTOR,
};

/// Where a parsed string's bytes live.
pub const Strings = enum {
    /// Every string is copied into the allocator, so the value outlives the
    /// document it came from.
    COPY,
    /// A string with no escape in it points into the document instead of being
    /// copied. A string that carries an escape is still copied, because its
    /// decoded bytes are not in the document anywhere. The document has to
    /// outlive the value.
    BORROW,
};

/// What happens to a key the target type does not declare.
pub const Unknown = enum {
    /// The document is wrong for this type, so the parse fails.
    REJECT,
    /// The key and its whole value are stepped over, however deep they nest.
    SKIP,
};

/// The options a parse runs with.
pub const Options = struct {
    strategy: Strategy = .STD,
    strings: Strings = .COPY,
    unknown: Unknown = .REJECT,
};

/// How a parse can fail.
///
/// Note:
/// - Every path maps onto this one set, so what a caller has to handle does not
///   change when the path under it does.
/// - Truncated means the document ended early. Unexpected means what is there is
///   not what the type wants: a syntax error, a value of the wrong shape, or the
///   same key twice.
/// - A path may never raise some of these. The std-backed one reports a bad
///   escape as a syntax error rather than as BadEscape, because std does not
///   separate the two. The set stays whole either way.
/// - None of these names says WHICH field or WHERE, because an error value cannot carry either.
///   jzon.lastFailure() answers that, read right after the parse returned. JzonUnknownField,
///   JzonMissingField and JzonUnknownEnumValue fill in the field. JzonTruncated, JzonUnexpected,
///   JzonBadNumber and JzonBadEscape fill in the byte on the cursor paths. The std-backed path
///   reports neither, because std surfaces neither.
pub const Error = error{
    JzonUnknownField,
    JzonMissingField,
    JzonUnknownEnumValue,
    JzonTruncated,
    JzonUnexpected,
    JzonBadNumber,
    JzonBadEscape,
    OutOfMemory,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "jzon: deserialize options default to the capable path and the safe pair" {
    const options: Options = .{};

    try std.testing.expectEqual(Strategy.STD, options.strategy);
    try std.testing.expectEqual(Strings.COPY, options.strings);
    try std.testing.expectEqual(Unknown.REJECT, options.unknown);
}
