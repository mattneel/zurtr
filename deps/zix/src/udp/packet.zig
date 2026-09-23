//! zix udp packet
//! Endianness helpers for extern struct packets.
//! No hardcoded packet type, user defines their own extern struct.

const std = @import("std");
const Endianness = @import("config.zig").Endianness;
const ZIG_SEMVER = @import("../lib.zig").ZIG_SEMVER;

// --------------------------------------------------------- //

/// Feedback received from the server.
/// Packet type is the same extern struct the user defined for their server/client pair.
pub fn FeedbackResult(comptime Packet: type) type {
    return union(enum) {
        /// Server acknowledged receipt (0x06).
        ack,
        /// Server rejected the packet (0x15), malformed or wrong size.
        nack,
        /// Server sent back a full packet, echo or broadcast relay.
        packet: Packet,
    };
}

// --------------------------------------------------------- //

/// Convert packet field bytes to the target endianness before sending over the wire.
/// No-op if the platform's native endian already matches the target.
/// Swaps integers and floats (including array elements). Skips u8 arrays (byte strings like id fields).
pub fn toEndian(comptime Packet: type, pkt: Packet, endianness: Endianness) Packet {
    if (endianness == .NATIVE) return pkt;
    const native = @import("builtin").cpu.arch.endian();
    const target: std.builtin.Endian = if (endianness == .LITTLE) .little else .big;
    if (native == target) return pkt;
    var result = pkt;
    swapFields(Packet, &result);
    return result;
}

/// Convert received wire bytes back to native endianness after receiving.
/// Byte swap is its own inverse, identical operation to toEndian().
pub fn fromEndian(comptime Packet: type, pkt: Packet, endianness: Endianness) Packet {
    return toEndian(Packet, pkt, endianness);
}

// --------------------------------------------------------- //

fn swapFields(comptime T: type, ptr: *T) void {
    if (comptime ZIG_SEMVER.MINOR == 16) {
        inline for (@typeInfo(T).@"struct".fields) |field| {
            swapField(field.type, &@field(ptr.*, field.name));
        }
    } else {
        const struct_info = @typeInfo(T).@"struct";
        inline for (struct_info.field_names, struct_info.field_types) |field_name, FieldType| {
            swapField(FieldType, &@field(ptr.*, field_name));
        }
    }
}

fn swapField(comptime T: type, ptr: *T) void {
    switch (@typeInfo(T)) {
        .int => ptr.* = @byteSwap(ptr.*),
        .float => |info| {
            const Int = if (comptime ZIG_SEMVER.MINOR == 16)
                std.meta.Int(.unsigned, info.bits)
            else
                @Int(.unsigned, info.bits);
            ptr.* = @bitCast(@byteSwap(@as(Int, @bitCast(ptr.*))));
        },
        .array => |arr| {
            // skip u8 arrays, byte strings (e.g. id fields) do not need swapping
            if (@sizeOf(arr.child) > 1) {
                for (ptr) |*elem| swapField(arr.child, elem);
            }
        },
        else => {},
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const TestPacket = extern struct {
    id: [4]u8,
    value: i32,
    ratio: f32,
    coords: [2]f64,
};

// RFC 768: these tests verify correct wire-format encoding/decoding of packet fields.
// Endianness discipline is required for cross-language interoperability (Go, C++, Rust, etc.).
// All integer and float fields must be swapped. u8 arrays (e.g. id) must not be touched.

test "zix udp: toEndian, NATIVE is a no-op" {
    const pkt = TestPacket{ .id = "abcd".*, .value = 42, .ratio = 1.5, .coords = .{ 1.0, -2.0 } };
    const result = toEndian(TestPacket, pkt, .NATIVE);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&pkt), std.mem.asBytes(&result));
}

test "zix udp: toEndian, u8 array fields are never byte-swapped" {
    const pkt = TestPacket{ .id = "abcd".*, .value = 1, .ratio = 1.0, .coords = .{ 0.0, 0.0 } };
    const result_le = toEndian(TestPacket, pkt, .LITTLE);
    const result_be = toEndian(TestPacket, pkt, .BIG);
    try std.testing.expectEqualSlices(u8, &pkt.id, &result_le.id);
    try std.testing.expectEqualSlices(u8, &pkt.id, &result_be.id);
}

test "zix udp: toEndian/fromEndian, round-trip is identity for LITTLE" {
    const pkt = TestPacket{ .id = "test".*, .value = -12345, .ratio = 3.14, .coords = .{ 1.5, -2.5 } };
    const wire = toEndian(TestPacket, pkt, .LITTLE);
    const back = fromEndian(TestPacket, wire, .LITTLE);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&pkt), std.mem.asBytes(&back));
}

test "zix udp: toEndian/fromEndian, round-trip is identity for BIG" {
    const pkt = TestPacket{ .id = "test".*, .value = -12345, .ratio = 3.14, .coords = .{ 1.5, -2.5 } };
    const wire = toEndian(TestPacket, pkt, .BIG);
    const back = fromEndian(TestPacket, wire, .BIG);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&pkt), std.mem.asBytes(&back));
}

test "zix udp: toEndian, non-native endian swaps integer fields" {
    const builtin = @import("builtin");
    const non_native: Endianness = if (builtin.cpu.arch.endian() == .little) .BIG else .LITTLE;
    const pkt = TestPacket{ .id = "abcd".*, .value = 0x01020304, .ratio = 1.0, .coords = .{ 1.0, 0.0 } };
    const result = toEndian(TestPacket, pkt, non_native);
    try std.testing.expectEqual(@byteSwap(pkt.value), result.value);
}

test "zix udp: toEndian, non-native endian swaps float array elements" {
    const builtin = @import("builtin");
    const non_native: Endianness = if (builtin.cpu.arch.endian() == .little) .BIG else .LITTLE;
    const pkt = TestPacket{ .id = "abcd".*, .value = 1, .ratio = 1.0, .coords = .{ 1.0, 2.0 } };
    const result = toEndian(TestPacket, pkt, non_native);
    const expected_x: f64 = @bitCast(@byteSwap(@as(u64, @bitCast(pkt.coords[0]))));
    const expected_y: f64 = @bitCast(@byteSwap(@as(u64, @bitCast(pkt.coords[1]))));
    try std.testing.expectEqual(expected_x, result.coords[0]);
    try std.testing.expectEqual(expected_y, result.coords[1]);
}

test "test zix: FeedbackResult, all variants are reachable" {
    const FB = FeedbackResult(TestPacket);
    const ack: FB = .ack;
    const nack: FB = .nack;
    const echo: FB = .{ .packet = std.mem.zeroes(TestPacket) };
    try std.testing.expect(std.meta.activeTag(ack) == .ack);
    try std.testing.expect(std.meta.activeTag(nack) == .nack);
    try std.testing.expect(std.meta.activeTag(echo) == .packet);
}
