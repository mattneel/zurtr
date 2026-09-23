//! prometheuz example runner: verifies every example binary against the
//! live node-exporter + prometheus containers.
//!
//! Note:
//! - `zig build test-runner` owns both containers' lifecycle (build,
//!   replace, run, teardown) and passes the example binary paths as argv.
//! - Readiness: scrapeOnce() against node-exporter, query("up") against
//!   prometheus, both retried until they stop erroring.
//! - PASS needs exit code 0 and the final "done" marker on the example's
//!   output, same convention as postgrez/rediz.
//! - Examples print via std.debug.print (stderr). stderr is drained to EOF
//!   before wait() so a chatty example cannot deadlock the pipe.

const std = @import("std");
const prometheuz = @import("prometheuz");

const NODE_EXPORTER_IP: []const u8 = "127.0.0.1";
const NODE_EXPORTER_PORT: u16 = 19100;
const PROMETHEUS_IP: []const u8 = "127.0.0.1";
const PROMETHEUS_PORT: u16 = 19090;

const READY_ATTEMPTS = 240;
const READY_DELAY_MS = 500;
const MAX_CAPTURED_OUTPUT = 64 * 1024;

// --------------------------------------------------------- //

/// Poll until node-exporter answers a real scrape.
fn waitForNodeExporter(io: std.Io, allocator: std.mem.Allocator) !void {
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        var snapshot = try prometheuz.scrapeOnce(allocator, io, .{
            .ip = NODE_EXPORTER_IP,
            .port = NODE_EXPORTER_PORT,
            .conn_timeout_ms = 500,
        });
        defer snapshot.deinit();

        if (snapshot.up) return;
        if (attempt >= READY_ATTEMPTS) return error.PrometheuzServerNeverBecameReady;
        std.Io.sleep(io, .fromMilliseconds(READY_DELAY_MS), .awake) catch {};
    }
}

/// Poll until Prometheus answers a real query.
fn waitForPrometheus(io: std.Io, allocator: std.mem.Allocator) !void {
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        var result = prometheuz.query(allocator, io, .{
            .ip = PROMETHEUS_IP,
            .port = PROMETHEUS_PORT,
            .conn_timeout_ms = 500,
        }, "up") catch {
            if (attempt >= READY_ATTEMPTS) return error.PrometheuzServerNeverBecameReady;
            std.Io.sleep(io, .fromMilliseconds(READY_DELAY_MS), .awake) catch {};

            continue;
        };
        result.deinit();

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
        std.debug.print("usage: prometheuz-runner <example binaries...> (use zig build test-runner)\n", .{});

        return error.PrometheuzNoExamplesGiven;
    }

    std.debug.print("waiting for node-exporter on {s}:{d} ...\n", .{ NODE_EXPORTER_IP, NODE_EXPORTER_PORT });
    try waitForNodeExporter(io, allocator);
    std.debug.print("waiting for prometheus on {s}:{d} ...\n", .{ PROMETHEUS_IP, PROMETHEUS_PORT });
    try waitForPrometheus(io, allocator);
    std.debug.print("both ready, running {d} example(s)\n", .{paths.items.len});

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

        return error.PrometheuzExamplesFailed;
    }

    std.debug.print("prometheuz: all {d} examples passed\n", .{paths.items.len});
}
