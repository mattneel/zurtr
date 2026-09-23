//! Cleartext password authentication.
//!
//! Note:
//! - Supported for compatibility only. Every use logs a warning: the
//!   password crosses the wire as-is, acceptable only over TLS or a
//!   trusted link. Prefer SCRAM.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("../protocol/frontend.zig");

const log = std.log.scoped(.postgrez);

/// Append the PasswordMessage reply to AuthenticationCleartextPassword and
/// log the warning the driver mandates for this method.
///
/// Note:
/// - The warning is suppressed under the test runner only, where stderr
///   output poisons the build summary.
pub fn respond(allocator: std.mem.Allocator, out: *std.ArrayList(u8), password: []const u8) !void {
    if (!builtin.is_test) {
        log.warn("cleartext password authentication in use, password crosses the wire unhashed, prefer SCRAM", .{});
    }

    try frontend.passwordCleartext(allocator, out, password);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez auth: cleartext respond frames the password message" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try respond(testing.allocator, &out, "pw");

    try testing.expectEqualSlices(u8, &.{ 'p', 0, 0, 0, 7, 'p', 'w', 0 }, out.items);
}
