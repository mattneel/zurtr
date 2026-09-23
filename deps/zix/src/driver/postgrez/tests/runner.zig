//! postgrez example runner: verifies every example binary against the live
//! PostgreSQL 18 container.
//!
//! Note:
//! - `zig build test-runner` owns the container lifecycle (build, replace,
//!   run, teardown) and passes the example binary paths as argv.
//! - The runner polls readiness by connecting with the driver itself, then
//!   runs each example sequentially: PASS needs exit code 0 and the final
//!   "done" marker on the example's output.
//! - Examples print via std.debug.print (stderr). stderr is drained to EOF
//!   before wait() so a chatty example cannot deadlock the pipe.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

const READY_ATTEMPTS = 240;
const READY_DELAY_MS = 500;
const MAX_CAPTURED_OUTPUT = 64 * 1024;

// --------------------------------------------------------- //

/// Poll until the container accepts a driver connection (pull + initdb on
/// first start take a while).
fn waitForServer(io: std.Io, allocator: std.mem.Allocator) !void {
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        const conn = postgrez.Conn.connect(allocator, io, .{
            .ip = IP,
            .port = PORT,
            .user = USER,
            .password = PASSWORD,
            .database = DATABASE,
        }) catch {
            if (attempt >= READY_ATTEMPTS) return error.PostgrezServerNeverBecameReady;
            std.Io.sleep(io, .fromMilliseconds(READY_DELAY_MS), .awake) catch {};

            continue;
        };
        conn.deinit();

        return;
    }
}

/// Read a child pipe to EOF into `out`, truncating at its capacity.
/// Args iterator that also works on Windows: std's Iterator.init is POSIX-only
/// in Zig 0.16, Windows needs the allocating variant.
fn argsIterator(args: std.process.Args) std.process.Args.Iterator {
    if (comptime @import("builtin").target.os.tag == .windows) {
        return std.process.Args.Iterator.initAllocator(args, std.heap.smp_allocator) catch {
            std.debug.print("FAIL: args iterator allocation failed\n", .{});
            std.process.exit(1);
        };
    }

    return std.process.Args.Iterator.init(args);
}

fn drainPipe(file: ?std.Io.File, out: []u8) usize {
    // std.posix.read is POSIX-only in Zig 0.16: no pipe capture on Windows.
    if (comptime @import("builtin").target.os.tag == .windows) return 0;

    const handle = (file orelse return 0).handle;

    var total: usize = 0;
    while (true) {
        const free_space = out[total..];
        if (free_space.len == 0) {
            // sink the rest so the child never blocks on a full pipe
            var sink: [4096]u8 = undefined;
            const n = std.posix.read(handle, &sink) catch return total;
            if (n == 0) return total;

            continue;
        }

        const n = std.posix.read(handle, free_space) catch return total;
        if (n == 0) return total;
        total += n;
    }
}

const Outcome = struct {
    pass: bool,
    exit_code: ?u8,
    output_len: usize,
};

/// Run one example to completion and judge it.
fn runExample(io: std.Io, path: []const u8, output_buf: []u8) Outcome {
    var child = std.process.spawn(io, .{
        .argv = &.{path},
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch return .{ .pass = false, .exit_code = null, .output_len = 0 };

    const output_len = drainPipe(child.stderr, output_buf);
    const term = child.wait(io) catch return .{ .pass = false, .exit_code = null, .output_len = output_len };

    const exit_code: ?u8 = switch (term) {
        .exited => |code| code,
        else => null,
    };
    const has_marker = std.mem.indexOf(u8, output_buf[0..output_len], "done") != null;

    return .{
        .pass = exit_code == 0 and has_marker,
        .exit_code = exit_code,
        .output_len = output_len,
    };
}

fn exampleLabel(path: []const u8) []const u8 {
    return std.fs.path.basename(path);
}

pub fn main(process: std.process.Init) !void {
    const io = process.io;

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var arg_iter = argsIterator(process.minimal.args);
    _ = arg_iter.skip();

    var paths: std.ArrayList([]const u8) = .empty;
    while (arg_iter.next()) |arg| try paths.append(allocator, arg);
    if (paths.items.len == 0) {
        std.debug.print("usage: postgrez-runner <example binaries...> (use zig build test-runner)\n", .{});

        return error.PostgrezNoExamplesGiven;
    }

    std.debug.print("waiting for the container on {s}:{d} ...\n", .{ IP, PORT });
    try waitForServer(io, allocator);
    std.debug.print("server ready, running {d} example(s)\n", .{paths.items.len});

    const output_buf = try allocator.alloc(u8, MAX_CAPTURED_OUTPUT);

    var failed: usize = 0;
    for (paths.items) |path| {
        const outcome = runExample(io, path, output_buf);

        if (outcome.pass) {
            std.debug.print("PASS {s}\n", .{exampleLabel(path)});
        } else {
            failed += 1;
            std.debug.print("FAIL {s} (exit={?d})\n", .{ exampleLabel(path), outcome.exit_code });
            std.debug.print("---- output ----\n{s}\n----------------\n", .{output_buf[0..outcome.output_len]});
        }
    }

    if (failed > 0) {
        std.debug.print("\n{d}/{d} example(s) failed\n", .{ failed, paths.items.len });

        return error.PostgrezExamplesFailed;
    }

    std.debug.print("postgrez: all {d} examples passed\n", .{paths.items.len});
}
