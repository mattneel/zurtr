//! zix udp namespace aggregator

const config = @import("config.zig");
const packet = @import("packet.zig");

// --------------------------------------------------------- //

const raw = @import("raw.zig");

pub const Endianness = config.Endianness;
pub const DispatchModel = config.DispatchModel;
pub const ServerConfig = config.UdpServerConfig;
pub const ClientConfig = config.UdpClientConfig;
pub const FeedbackResult = packet.FeedbackResult;
pub const toEndian = packet.toEndian;
pub const fromEndian = packet.fromEndian;

/// Raw-bytes datagram server handler type (ADR-049).
pub const HandlerFn = raw.HandlerFn;
/// Reply queue handed to a raw handler.
pub const Sink = raw.Sink;

// --------------------------------------------------------- //

/// UDP server typed to the user's extern struct packet.
/// Example: const MyServer = zix.Udp.Server(MyPacket);
pub fn Server(comptime Packet: type) type {
    return @import("server.zig").UdpServer(Packet);
}

/// UDP client typed to the user's extern struct packet.
/// Example: const MyClient = zix.Udp.Client(MyPacket);
pub fn Client(comptime Packet: type) type {
    return @import("client.zig").UdpClient(Packet);
}

/// Raw-bytes datagram server (ADR-049): variable-length datagrams, recvmmsg / sendmmsg batching,
/// SO_REUSEPORT workers. No fixed packet struct.
/// Example: const Echo = zix.Udp.Raw(handlerFn);
pub fn Raw(comptime handler: raw.HandlerFn) type {
    return raw.Raw(handler);
}
