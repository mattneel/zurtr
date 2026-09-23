//! One-shot scrape: GET the target, parse the text 0.0.4 body into an
//! arena-owned Snapshot. The testable core. Scraper wraps this in a
//! background poller loop.

const std = @import("std");
const config_mod = @import("config.zig");
const http_client = @import("http_client.zig");
const snapshot_mod = @import("snapshot.zig");

const ScrapeConfig = config_mod.ScrapeConfig;
const Snapshot = snapshot_mod.Snapshot;

/// Synchronous GET config.path from config.ip:config.port, parse the text
/// 0.0.4 body, and return an owned Snapshot. Blocks the calling context
/// only. Never returns a network or parse error: failure is captured in the
/// returned Snapshot (up = false, last_error set) so a bad scrape is
/// observable, not thrown.
///
/// Return:
/// - *Snapshot (caller must snapshot.deinit())
/// - error.OutOfMemory
pub fn scrapeOnce(allocator: std.mem.Allocator, io: std.Io, config: ScrapeConfig) !*Snapshot {
    const start = std.Io.Clock.awake.now(io);
    const timestamp_ms = std.Io.Clock.real.now(io).toMilliseconds();

    var response = http_client.get(allocator, io, config.ip, config.port, config.path, .{
        .connect_timeout_ms = config.conn_timeout_ms,
        .max_response_body = config.max_response_body,
    }) catch |err| {
        return snapshot_mod.failed(allocator, timestamp_ms, durationSince(io, start), @errorName(err));
    };
    defer response.deinit();

    if (response.status() != 200) {
        return snapshot_mod.failed(allocator, timestamp_ms, durationSince(io, start), "non-200 scrape response");
    }

    return snapshot_mod.fromText(allocator, timestamp_ms, durationSince(io, start), response.body()) catch |err| {
        return snapshot_mod.failed(allocator, timestamp_ms, durationSince(io, start), @errorName(err));
    };
}

fn durationSince(io: std.Io, start: std.Io.Timestamp) u64 {
    const elapsed_ms = start.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();

    return @intCast(@max(0, elapsed_ms));
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: scrapeOnce captures a failure without throwing" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 1 is reserved and never accepts, so this always fails fast.
    var snapshot = try scrapeOnce(testing.allocator, io, .{ .ip = "127.0.0.1", .port = 1, .conn_timeout_ms = 200 });
    defer snapshot.deinit();

    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
}
