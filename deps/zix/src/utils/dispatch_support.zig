//! zix dispatch support: the platform gate for DispatchModel (ADR-065).
//!
//! Note:
//! - .EPOLL and .URING are Linux-only. Off Linux there is no silent downgrade: an engine's run()
//!   rejects the model so the caller fixes the config instead of unknowingly getting a different
//!   model than the one asked for.
//! - .ASYNC is the only model available on every platform, so a portable caller either picks it
//!   unconditionally or selects per target at comptime.
//! - The check is comptime-folded on the target's os tag, so a Linux build keeps no runtime branch.

const std = @import("std");
const builtin = @import("builtin");

const DispatchModel = @import("../tcp/config.zig").DispatchModel;

/// The error every engine's run() returns when the configured model cannot run on this platform.
pub const Error = error{ZixDispatchModelUnsupported};

/// Whether the model can run on the target this build targets.
///
/// Param:
/// model - DispatchModel (the value taken from the engine's config)
///
/// Return:
/// - true on Linux for every model, and off Linux only for .ASYNC
pub fn isSupported(model: DispatchModel) bool {
    if (comptime builtin.target.os.tag == .linux) return true;

    return model == .ASYNC;
}

/// The reason line an engine logs before returning the error, so an operator sees which model was
/// rejected rather than only the error name.
///
/// Param:
/// model - DispatchModel (the rejected value)
///
/// Return:
/// - []const u8 (a static tag name, no allocation)
pub fn rejectedName(model: DispatchModel) []const u8 {
    return @tagName(model);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix dispatch: ASYNC is supported on every platform" {
    try std.testing.expect(isSupported(.ASYNC));
}

test "zix dispatch: EPOLL and URING support follows the target os" {
    const linux_target = comptime builtin.target.os.tag == .linux;

    try std.testing.expectEqual(linux_target, isSupported(.EPOLL));
    try std.testing.expectEqual(linux_target, isSupported(.URING));
}

test "zix dispatch: rejectedName reports the model tag" {
    try std.testing.expectEqualStrings("EPOLL", rejectedName(.EPOLL));
    try std.testing.expectEqualStrings("URING", rejectedName(.URING));
    try std.testing.expectEqualStrings("ASYNC", rejectedName(.ASYNC));
}

test "zix dispatch: Error carries the single canonical reject error" {
    const failing: Error!void = error.ZixDispatchModelUnsupported;

    try std.testing.expectError(error.ZixDispatchModelUnsupported, failing);
}
