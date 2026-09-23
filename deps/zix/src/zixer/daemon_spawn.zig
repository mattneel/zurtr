//! zixer daemon auto-spawn: launch the daemon when the control socket is silent

const std = @import("std");

const control = @import("control.zig");
const control_client = @import("control_client.zig");

/// Ping attempts after a spawn before giving up, one every SPAWN_WAIT_STEP_MS.
const SPAWN_WAIT_TRIES: usize = 50;
const SPAWN_WAIT_STEP_MS: u64 = 100;

/// Make sure a daemon answers on socket_path, spawning one when it is silent.
///
/// Note:
/// - The spawned child is `<exe> daemon --dir <root>` with all stdio ignored,
///   so it keeps running after this process exits.
///
/// Param:
/// io - std.Io
/// exe_path - []const u8 (argv[0] of this process, respawned as the daemon)
/// root_path - []const u8 (resolved root dir, forwarded via --dir)
/// socket_path - []const u8 (control socket, as control.socketPath built it)
///
/// Return:
/// - void once a daemon answers ping
/// - error.ZixerDaemonStartTimeout when the spawned daemon never answers
pub fn ensure(io: std.Io, exe_path: []const u8, root_path: []const u8, socket_path: []const u8) !void {
    if (control_client.ping(io, socket_path)) return;

    _ = try std.process.spawn(io, .{
        .argv = &.{ exe_path, "daemon", "--dir", root_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });

    var tries: usize = 0;
    while (tries < SPAWN_WAIT_TRIES) : (tries += 1) {
        if (control_client.ping(io, socket_path)) return;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(SPAWN_WAIT_STEP_MS), .awake) catch {};
    }

    return error.ZixerDaemonStartTimeout;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

fn answerOnePing(io: std.Io, socket_path: []const u8) void {
    // A crashed earlier run may have left the socket file behind, the same
    // stale-file rule the real daemon applies before binding.
    std.Io.Dir.deleteFileAbsolute(io, socket_path) catch {};

    const unix_addr = std.Io.net.UnixAddress.init(socket_path) catch return;
    var server = unix_addr.listen(io, .{}) catch return;
    defer server.deinit(io);

    const stream = server.accept(io) catch return;
    defer stream.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll("ok: zixer daemon\n") catch return;
    writer.interface.flush() catch return;
}

test "zix zixer: daemon spawn, ensure returns without spawning when a daemon answers" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.Io.Dir.cwd().createDirPath(io, "tmp/zixer_spawn_test") catch {};
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zixer_spawn_test") catch {};

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const socket_path = try control.socketPath(io, arena.allocator(), "tmp/zixer_spawn_test");

    const answer_thread = try std.Thread.spawn(.{}, answerOnePing, .{ io, socket_path });

    // Bounded wait for the fake daemon socket, then ensure must take the
    // early-return path: a bogus exe path proves nothing was spawned.
    var tries: usize = 0;
    while (tries < 100) : (tries += 1) {
        std.Io.Dir.cwd().access(io, "tmp/zixer_spawn_test/control.sock", .{}) catch {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
            continue;
        };
        break;
    }
    try std.testing.expect(tries < 100);

    try ensure(io, "zixer-exe-that-does-not-exist", "tmp/zixer_spawn_test", socket_path);

    answer_thread.join();
}
