//! prometheuz example: the one long-running, container-self-managing demo.
//! Brings up node-exporter + prometheus on a shared docker network (so
//! prometheus can scrape node-exporter by name), then loops forever: bump
//! an app-authored error counter, push it via remote_write, query it back
//! and print. Open the printed URL in a browser to watch it update live.
//!
//! Note:
//! - No zix.Http1, no server, no listening socket anywhere in this file.
//!   The only outbound calls are the driver's own remoteWrite()/query().
//!   node-exporter and prometheus talk to each other over their own HTTP
//!   as stock containers - nothing zix runs inside them.
//! - Not part of `zig build test-runner`: this never exits on its own, so
//!   there is no exit code or "done" marker to check against.
//! - Shares host ports 19100/19090 with the test-runner's own containers;
//!   do not run both at once (the same caveat postgrez/rediz's own
//!   test-integration vs test-runner already carry, see their build.zig).
//! - On Ctrl+C: stops, removes only the container(s)/network this run
//!   itself started, never one found already alive.

const std = @import("std");
const prometheuz = @import("prometheuz");

const NETWORK: []const u8 = "zix-prometheuz-live-demo-net";
const NODE_EXPORTER_CONTAINER: []const u8 = "zix-prometheuz-live-demo-node-exporter";
const PROMETHEUS_CONTAINER: []const u8 = "zix-prometheuz-live-demo-prometheus";
const IP: []const u8 = "127.0.0.1";
const NODE_EXPORTER_PORT: u16 = 19100;
const PROMETHEUS_PORT: u16 = 19090;
const TICK_MS: u32 = 3_000;

const PROMETHEUS_CONFIG_PATH: []const u8 = "/tmp/zix-prometheuz-live-demo-prometheus.yml";
const PROMETHEUS_CONFIG =
    \\global:
    \\  scrape_interval: 15s
    \\scrape_configs:
    \\  - job_name: node-exporter
    \\    static_configs:
    \\      - targets: ["node-exporter:9100"]
    \\
;

var running: std.atomic.Value(bool) = .init(true);

fn onSigint(_: std.posix.SIG) callconv(.c) void {
    running.store(false, .release);
}

// --------------------------------------------------------- //

fn runCommand(io: std.Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(io);

    switch (term) {
        .exited => |code| if (code != 0) return error.PrometheuzCommandFailed,
        else => return error.PrometheuzCommandFailed,
    }
}

fn commandOutputNonEmpty(io: std.Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    }) catch return false;

    var buf: [256]u8 = undefined;
    var total: usize = 0;
    if (child.stdout) |file| {
        while (total < buf.len) {
            const n = std.posix.read(file.handle, buf[total..]) catch break;
            if (n == 0) break;
            total += n;
        }
    }
    _ = child.wait(io) catch {};

    return std.mem.trim(u8, buf[0..total], " \t\r\n").len > 0;
}

fn networkExists(io: std.Io) bool {
    return commandOutputNonEmpty(io, &.{ "docker", "network", "ls", "--filter", "name=" ++ NETWORK, "-q" });
}

fn containerRunning(io: std.Io, comptime name: []const u8) bool {
    return commandOutputNonEmpty(io, &.{ "docker", "ps", "--filter", "name=" ++ name, "--filter", "status=running", "-q" });
}

// --------------------------------------------------------- //

/// Returns whether this call created the network (false if it already existed).
fn ensureNetwork(io: std.Io) !bool {
    if (networkExists(io)) return false;

    try runCommand(io, &.{ "docker", "network", "create", NETWORK });

    return true;
}

/// Returns whether this call started node-exporter (false if already running).
fn ensureNodeExporter(io: std.Io) !bool {
    if (containerRunning(io, NODE_EXPORTER_CONTAINER)) return false;

    try runCommand(io, &.{
        "docker",                              "run",
        "--rm",                                "-d",
        "--network",                           NETWORK,
        "--network-alias",                     "node-exporter",
        "--name",                              NODE_EXPORTER_CONTAINER,
        "-p",                                  "127.0.0.1:19100:9100",
        "docker.io/prom/node-exporter:latest",
    });

    return true;
}

/// Returns whether this call started prometheus (false if already running).
fn ensurePrometheus(io: std.Io) !bool {
    if (containerRunning(io, PROMETHEUS_CONTAINER)) return false;

    try writeConfigFile(io);

    try runCommand(io, &.{
        "docker",                             "run",
        "--rm",                               "-d",
        "--network",                          NETWORK,
        "--name",                             PROMETHEUS_CONTAINER,
        "-p",                                 "127.0.0.1:19090:9090",
        "-v",                                 PROMETHEUS_CONFIG_PATH ++ ":/etc/prometheus/prometheus.yml:ro",
        "docker.io/prom/prometheus:latest",   "--config.file=/etc/prometheus/prometheus.yml",
        "--web.enable-remote-write-receiver",
    });

    return true;
}

fn writeConfigFile(io: std.Io) !void {
    const file = try std.Io.Dir.cwd().createFile(io, PROMETHEUS_CONFIG_PATH, .{});
    defer file.close(io);

    var write_buf: [512]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(PROMETHEUS_CONFIG);
    try writer.interface.flush();
}

fn teardown(io: std.Io, node_exporter_started: bool, prometheus_started: bool, network_created: bool) void {
    if (prometheus_started) runCommand(io, &.{ "docker", "rm", "-f", PROMETHEUS_CONTAINER }) catch {};
    if (node_exporter_started) runCommand(io, &.{ "docker", "rm", "-f", NODE_EXPORTER_CONTAINER }) catch {};
    if (network_created) runCommand(io, &.{ "docker", "network", "rm", NETWORK }) catch {};
}

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    const io = process.io;

    // Two allocators, deliberately not one: the Registry (and its internal
    // label-combination cells) must survive for the whole run, while the
    // per-tick snapshot/push/query work wants a scratch arena reset every
    // loop. Resetting a single shared arena each tick would free the
    // Registry's own state out from under it.
    const allocator = std.heap.smp_allocator;
    var tick_arena = std.heap.ArenaAllocator.init(allocator);
    defer tick_arena.deinit();

    const network_created = try ensureNetwork(io);
    const node_exporter_started = try ensureNodeExporter(io);
    const prometheus_started = try ensurePrometheus(io);
    defer teardown(io, node_exporter_started, prometheus_started, network_created);

    var act = std.posix.Sigaction{
        .handler = .{ .handler = onSigint },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);

    std.debug.print("prometheus:    http://{s}:{d}/graph?g0.expr=app_write_errors_total\n", .{ IP, PROMETHEUS_PORT });
    std.debug.print("node-exporter: http://{s}:{d}/metrics\n", .{ IP, NODE_EXPORTER_PORT });
    std.debug.print("press Ctrl+C to stop\n\n", .{});

    var registry = prometheuz.Registry.init(allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});

    const write_config = prometheuz.WriteConfig{ .ip = IP, .port = PROMETHEUS_PORT };
    const query_config = prometheuz.QueryConfig{ .ip = IP, .port = PROMETHEUS_PORT };

    while (running.load(.acquire)) {
        write_errors.with(&.{"user_create_failed"}).inc();

        _ = tick_arena.reset(.retain_capacity);
        const tick_allocator = tick_arena.allocator();

        const samples = registry.snapshot(tick_allocator) catch |err| {
            std.debug.print("snapshot failed: {t}\n", .{err});
            std.Io.sleep(io, .fromMilliseconds(TICK_MS), .awake) catch {};

            continue;
        };

        prometheuz.remoteWrite(tick_allocator, io, write_config, samples) catch |err| {
            std.debug.print("push failed: {t}\n", .{err});
            std.Io.sleep(io, .fromMilliseconds(TICK_MS), .awake) catch {};

            continue;
        };

        if (prometheuz.query(tick_allocator, io, query_config, "app_write_errors_total")) |result| {
            var owned_result = result;
            defer owned_result.deinit();

            if (owned_result.vector.len > 0) {
                std.debug.print("app_write_errors_total = {d}\n", .{owned_result.vector[0].value});
            }
        } else |err| {
            std.debug.print("query failed: {t}\n", .{err});
        }

        std.Io.sleep(io, .fromMilliseconds(TICK_MS), .awake) catch {};
    }

    std.debug.print("\nstopping\n", .{});
}
