//! zix channel namespace aggregator

/// Typed, fiber-safe buffered channel for in-process message passing.
/// Example:
/// ```zig
/// const MyChan = zix.Channel(u32);
/// var ch = try MyChan.init(allocator, 8);
/// defer ch.deinit();
/// try ch.send(io, 42);
/// const v = try ch.recv(io);
/// ```
pub const Channel = @import("channel.zig").Channel;
