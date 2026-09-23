//! zix fix router: comptime route dispatch for FIX application messages.

const std = @import("std");
const core = @import("core.zig");
const Field = core.Field;
const FixContext = core.FixContext;
const FixRequest = core.FixRequest;
const FixResponse = core.FixResponse;
const FixRoute = core.FixRoute;
const wallClockNs = core.wallClockNs;

// --------------------------------------------------------- //

/// Comptime FIX application message router.
/// Routes are dispatched via inline for, zero overhead vs hand-written if/else.
/// Session messages (A, 0, 1, 5) are not dispatched. Only application MsgTypes are routed.
///
/// Usage:
/// ```zig
/// const router = zix.Fix.Router(&[_]zix.Fix.Route{
///     .{ .msg_type = "D", .handler = handleOrder },
///     .{ .msg_type = "F", .handler = handleCancel, .timeout_ms = 500 },
/// });
/// var server = try zix.Fix.Server.init(router.dispatch, .{ .io = io, .ip = "0.0.0.0", .port = 9500, .comp_id = "SRV", .dispatch_model = .ASYNC });
/// try server.run();
/// ```
///
/// Param:
/// routes - []const FixRoute (comptime-known route table)
pub fn FixRouter(comptime routes: []const FixRoute) type {
    return struct {
        /// Runtime-accessible slice of the comptime route table.
        pub const route_slice: []const FixRoute = routes;

        /// Dispatch to the matching route handler. Usable as a HandlerFn.
        /// If no route matches, the message is silently ignored. A route with its
        /// own timeout_ms tightens ctx.deadline_ns (already seeded from the
        /// server-wide handler_timeout_ms at Context build), never widens it.
        ///
        /// Param:
        /// req - *FixRequest (typed view over the received message's fields)
        /// res - *FixResponse (builder for the reply)
        /// ctx - *FixContext (per-connection context)
        pub fn dispatch(req: *FixRequest, res: *FixResponse, ctx: *FixContext) anyerror!void {
            const msgtype = req.getField(.MsgType) orelse return;

            inline for (routes) |route| {
                if (std.mem.eql(u8, msgtype, route.msg_type)) {
                    if (route.timeout_ms > 0) {
                        const route_deadline = wallClockNs() + @as(u64, route.timeout_ms) * std.time.ns_per_ms;
                        ctx.deadline_ns = if (ctx.deadline_ns) |server_deadline| @min(server_deadline, route_deadline) else route_deadline;
                    }

                    return route.handler(req, res, ctx);
                }
            }
        }
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix fix: dispatch calls the matching handler" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const called = struct {
        var count: u32 = 0;
        fn handler(_: *FixRequest, _: *FixResponse, _: *FixContext) anyerror!void {
            count += 1;
        }
    };

    const router = FixRouter(&[_]FixRoute{
        .{ .msg_type = "D", .handler = called.handler },
    });

    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = 0,
        ._seq_out = &seq,
    };

    const fields = [_]Field{
        .{ .tag = .MsgType, .value = "D" },
        .{ .tag = .Symbol, .value = "AAPL" },
    };
    var req = FixRequest{ .fields = &fields };
    var res = FixResponse{ .sender_comp_id = ctx.sender_comp_id, .target_comp_id = ctx.target_comp_id, ._fd = ctx._fd, ._seq_out = ctx._seq_out };
    try router.dispatch(&req, &res, &ctx);
    try std.testing.expectEqual(@as(u32, 1), called.count);
}

test "zix fix: no match leaves handler uncalled" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const called = struct {
        var count: u32 = 0;
        fn handler(_: *FixRequest, _: *FixResponse, _: *FixContext) anyerror!void {
            count += 1;
        }
    };
    called.count = 0;

    const router = FixRouter(&[_]FixRoute{
        .{ .msg_type = "D", .handler = called.handler },
    });

    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = 0,
        ._seq_out = &seq,
    };

    const fields = [_]Field{.{ .tag = .MsgType, .value = "F" }};
    var req = FixRequest{ .fields = &fields };
    var res = FixResponse{ .sender_comp_id = ctx.sender_comp_id, .target_comp_id = ctx.target_comp_id, ._fd = ctx._fd, ._seq_out = ctx._seq_out };
    try router.dispatch(&req, &res, &ctx);
    try std.testing.expectEqual(@as(u32, 0), called.count);
}

test "zix fix: route timeout sets deadline_ns" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const noop = struct {
        fn handler(_: *FixRequest, _: *FixResponse, _: *FixContext) anyerror!void {}
    };

    const router = FixRouter(&[_]FixRoute{
        .{ .msg_type = "D", .handler = noop.handler, .timeout_ms = 100 },
    });

    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .deadline_ns = null,
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = 0,
        ._seq_out = &seq,
    };

    const fields = [_]Field{.{ .tag = .MsgType, .value = "D" }};
    var req = FixRequest{ .fields = &fields };
    var res = FixResponse{ .sender_comp_id = ctx.sender_comp_id, .target_comp_id = ctx.target_comp_id, ._fd = ctx._fd, ._seq_out = ctx._seq_out };
    try router.dispatch(&req, &res, &ctx);
    try std.testing.expect(ctx.deadline_ns != null);
}

test "zix fix: route timeout tightens a wider server-wide deadline, never widens it" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const noop = struct {
        fn handler(_: *FixRequest, _: *FixResponse, _: *FixContext) anyerror!void {}
    };

    const router = FixRouter(&[_]FixRoute{
        .{ .msg_type = "D", .handler = noop.handler, .timeout_ms = 50 },
    });

    var seq: u32 = 1;
    const server_deadline = wallClockNs() + 10 * std.time.ns_per_s;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .deadline_ns = server_deadline,
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = 0,
        ._seq_out = &seq,
    };

    const fields = [_]Field{.{ .tag = .MsgType, .value = "D" }};
    var req = FixRequest{ .fields = &fields };
    var res = FixResponse{ .sender_comp_id = ctx.sender_comp_id, .target_comp_id = ctx.target_comp_id, ._fd = ctx._fd, ._seq_out = ctx._seq_out };
    try router.dispatch(&req, &res, &ctx);
    try std.testing.expect(ctx.deadline_ns.? < server_deadline);
}
