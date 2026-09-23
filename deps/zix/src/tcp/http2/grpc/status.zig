//! gRPC status codes.

const std = @import("std");

// --------------------------------------------------------- //

/// gRPC canonical status codes (grpc.io/docs/guides/status-codes/).
pub const GrpcStatus = enum(u8) {
    OK = 0,
    CANCELLED = 1,
    UNKNOWN = 2,
    INVALID_ARGUMENT = 3,
    DEADLINE_EXCEEDED = 4,
    NOT_FOUND = 5,
    ALREADY_EXISTS = 6,
    PERMISSION_DENIED = 7,
    RESOURCE_EXHAUSTED = 8,
    FAILED_PRECONDITION = 9,
    ABORTED = 10,
    OUT_OF_RANGE = 11,
    UNIMPLEMENTED = 12,
    INTERNAL = 13,
    UNAVAILABLE = 14,
    DATA_LOSS = 15,
    UNAUTHENTICATED = 16,
    _,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: GrpcStatus OK is 0" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(GrpcStatus.OK));
}

test "zix grpc: GrpcStatus UNAUTHENTICATED is 16" {
    try std.testing.expectEqual(@as(u8, 16), @intFromEnum(GrpcStatus.UNAUTHENTICATED));
}

test "zix grpc: GrpcStatus UNIMPLEMENTED is 12" {
    try std.testing.expectEqual(@as(u8, 12), @intFromEnum(GrpcStatus.UNIMPLEMENTED));
}
