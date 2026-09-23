//! zix utils available.
//! Check for what is available on the machine.

const std = @import("std");

/// Check if port is available.
pub fn networkPort(
    io: std.Io,
    ip: []const u8,
    port: u16,
    mode: std.Io.net.Socket.Mode,
    protocol: std.Io.net.Protocol,
) bool {
    var address = std.Io.net.IpAddress.resolve(io, ip, port) catch return false;
    var network = address.listen(
        io,
        .{ .mode = mode, .protocol = protocol },
    ) catch return false;
    defer network.deinit(io);

    return true;
}
