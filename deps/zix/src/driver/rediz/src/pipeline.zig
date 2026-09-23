//! Command pipelining: batch several commands into one send, one flush,
//! one round trip.
//!
//! Note:
//! - add() only appends to the connection send buffer, nothing hits the
//!   wire before sync().
//! - config.max_pending_replies bounds the queued commands (0 = no bound).
//!   Beyond the bound add() sheds with error.RedizQueueFull instead of growing
//!   memory.
//! - sync() returns raw replies in add() order. A failed command comes back
//!   as its .err reply (data, not error.RedizServerError): one bad command must
//!   not abort draining the rest of the batch.
//! - No other commands on the connection between begin and sync.

const std = @import("std");
const conn_mod = @import("conn.zig");
const resp = @import("protocol/resp.zig");

const Conn = conn_mod.Conn;

pub const Pipeline = struct {
    conn: *Conn,
    command_count: usize = 0,

    /// Open a pipeline. Resets the per-command arena: replies of a previous
    /// command on this connection become invalid.
    pub fn begin(conn: *Conn) !Pipeline {
        _ = conn.reply_arena.reset(.retain_capacity);
        conn.send_buf.clearRetainingCapacity();

        return .{ .conn = conn };
    }

    /// Queue one command.
    ///
    /// Return:
    /// - void on success
    /// - error.RedizQueueFull when max_pending_replies is set and reached
    pub fn add(self: *Pipeline, args: []const []const u8) !void {
        const bound = self.conn.config.max_pending_replies;
        if (bound != 0 and self.command_count >= bound) return error.RedizQueueFull;

        try resp.encodeCommand(self.conn.allocator, &self.conn.send_buf, args);
        self.command_count += 1;
    }

    /// Send the batch and collect one reply per queued command, in add()
    /// order. The slice lives in the per-command arena: valid until the
    /// next command on this connection.
    pub fn sync(self: *Pipeline) ![]resp.Reply {
        const conn = self.conn;

        try conn.flushSend();

        // Replies owed by deferred commands precede the batch replies.
        try conn.drainDeferred();

        const replies = try conn.reply_arena.allocator().alloc(resp.Reply, self.command_count);
        for (replies) |*reply| {
            reply.* = try conn.receiveReply(false);
            if (reply.errLine()) |line| conn.last_server_error.capture(line);
        }

        return replies;
    }
};
