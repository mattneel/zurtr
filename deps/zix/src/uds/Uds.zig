//! zix uds namespace aggregator

const config = @import("config.zig");

// --------------------------------------------------------- //

pub const ServerConfig = config.UdsServerConfig;
pub const ClientConfig = config.UdsClientConfig;

// --------------------------------------------------------- //

/// UDS stream server.
/// Example: var server = try zix.Uds.Server.init(zix.Uds.echoHandler, .{ .io = io, .path = "/tmp/app.sock", .allocator = alloc });
pub const Server = @import("server.zig").UdsServer;

/// Per-connection handler type: fn(stream, io) void.
pub const HandlerFn = @import("server.zig").HandlerFn;

/// UDS stream client.
/// Example: var client = try zix.Uds.Client.connect(.{ .path = "/tmp/app.sock" }, io);
pub const Client = @import("client.zig").UdsClient;

/// Default echo handler: reads length-prefixed frames and echoes each back.
pub const echoHandler = @import("server.zig").echoHandler;
