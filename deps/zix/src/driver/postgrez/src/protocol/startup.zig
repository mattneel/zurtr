//! postgrez startup flow: protocol version request, NegotiateProtocolVersion
//! downgrade, and the server version gate.
//!
//! Note:
//! - The driver requests protocol 3.2 by default. PostgreSQL 18+ accepts it
//!   and continues into auth. Older servers reply NegotiateProtocolVersion
//!   and the driver downgrades to 3.0 in place, same connection, no
//!   reconnect. Minimum supported server is PostgreSQL 15, everything below
//!   is a hard reject.

const std = @import("std");
const frontend = @import("frontend.zig");
const backend = @import("backend.zig");

/// Config knob: which protocol version to request at startup.
pub const ProtocolVersion = enum {
    /// Request 3.2, downgrade to 3.0 in place when the server negotiates.
    AUTO,
    /// Request 3.0 directly, no negotiation round.
    V3_0,
    /// Request 3.2 strictly, refuse to connect when the server negotiates down.
    V3_2,
};

/// Oldest server major version the driver accepts.
pub const MIN_SERVER_MAJOR: u32 = 15;

pub const StartupError = error{
    PostgrezProtocolNotSupported,
    PostgrezUnsupportedServerVersion,
};

// --------------------------------------------------------- //

/// Wire code to request for a knob value.
pub fn requestedCode(knob: ProtocolVersion) i32 {
    return switch (knob) {
        .AUTO, .V3_2 => frontend.PROTOCOL_V3_2,
        .V3_0 => frontend.PROTOCOL_V3_0,
    };
}

/// Append the StartupMessage for `knob` to `out`.
pub fn buildStartup(allocator: std.mem.Allocator, out: *std.ArrayList(u8), knob: ProtocolVersion, options: frontend.StartupOptions) !void {
    try frontend.startup(allocator, out, requestedCode(knob), options);
}

/// Resolve a NegotiateProtocolVersion reply into the protocol code to
/// continue with.
///
/// Return:
/// - frontend.PROTOCOL_V3_0 when the downgrade is acceptable
/// - error.PostgrezProtocolNotSupported under the strict .V3_2 knob, or when the
///   server's newest supported version is not a 3.x protocol
pub fn handleNegotiate(knob: ProtocolVersion, negotiate: backend.NegotiateProtocolVersion) StartupError!i32 {
    if (knob == .V3_2) return error.PostgrezProtocolNotSupported;
    if (@divTrunc(negotiate.newest_code, 0x0001_0000) != 3) return error.PostgrezProtocolNotSupported;

    return frontend.PROTOCOL_V3_0;
}

/// Major version from a server_version ParameterStatus value. Handles
/// release ("18.0", "15.13") and pre-release ("18beta1", "16devel") forms.
pub fn serverVersionMajor(text: []const u8) ?u32 {
    var end: usize = 0;
    while (end < text.len and text[end] >= '0' and text[end] <= '9') end += 1;
    if (end == 0) return null;

    return std.fmt.parseInt(u32, text[0..end], 10) catch null;
}

/// Gate the reported server version against MIN_SERVER_MAJOR.
///
/// Return:
/// - void when the server is PostgreSQL 15 or newer
/// - error.PostgrezUnsupportedServerVersion below 15 or on an unparseable version
pub fn checkServerVersion(text: []const u8) StartupError!void {
    const major = serverVersionMajor(text) orelse return error.PostgrezUnsupportedServerVersion;

    if (major < MIN_SERVER_MAJOR) return error.PostgrezUnsupportedServerVersion;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez protocol: requestedCode maps knob to wire code" {
    try testing.expectEqual(frontend.PROTOCOL_V3_2, requestedCode(.AUTO));
    try testing.expectEqual(frontend.PROTOCOL_V3_0, requestedCode(.V3_0));
    try testing.expectEqual(frontend.PROTOCOL_V3_2, requestedCode(.V3_2));
}

test "postgrez protocol: buildStartup writes the knob's protocol code" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try buildStartup(testing.allocator, &out, .V3_0, .{ .user = "u" });

    const code = std.mem.readInt(i32, out.items[4..8], .big);
    try testing.expectEqual(frontend.PROTOCOL_V3_0, code);
}

test "postgrez protocol: handleNegotiate downgrades AUTO to 3.0 in place" {
    const negotiate = backend.NegotiateProtocolVersion{
        .newest_code = frontend.PROTOCOL_V3_0,
        .unsupported_count = 0,
        .options_payload = "",
    };

    try testing.expectEqual(frontend.PROTOCOL_V3_0, try handleNegotiate(.AUTO, negotiate));
}

test "postgrez protocol: handleNegotiate rejects under strict V3_2" {
    const negotiate = backend.NegotiateProtocolVersion{
        .newest_code = frontend.PROTOCOL_V3_0,
        .unsupported_count = 0,
        .options_payload = "",
    };

    try testing.expectError(error.PostgrezProtocolNotSupported, handleNegotiate(.V3_2, negotiate));
}

test "postgrez protocol: handleNegotiate rejects a non-3.x server" {
    const negotiate = backend.NegotiateProtocolVersion{
        .newest_code = 0x0002_0000,
        .unsupported_count = 0,
        .options_payload = "",
    };

    try testing.expectError(error.PostgrezProtocolNotSupported, handleNegotiate(.AUTO, negotiate));
}

test "postgrez protocol: serverVersionMajor parses release and pre-release" {
    try testing.expectEqual(@as(?u32, 18), serverVersionMajor("18.0"));
    try testing.expectEqual(@as(?u32, 15), serverVersionMajor("15.13"));
    try testing.expectEqual(@as(?u32, 18), serverVersionMajor("18beta1"));
    try testing.expectEqual(@as(?u32, 16), serverVersionMajor("16devel"));
    try testing.expectEqual(@as(?u32, null), serverVersionMajor("devel"));
}

test "postgrez protocol: checkServerVersion gates below 15" {
    try checkServerVersion("15.2");
    try checkServerVersion("18beta1");

    try testing.expectError(error.PostgrezUnsupportedServerVersion, checkServerVersion("14.8"));
    try testing.expectError(error.PostgrezUnsupportedServerVersion, checkServerVersion("9.6.24"));
    try testing.expectError(error.PostgrezUnsupportedServerVersion, checkServerVersion("garbage"));
}
