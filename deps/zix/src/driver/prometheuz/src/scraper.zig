//! Scraper: a background worker thread that polls scrapeOnce() on an
//! interval and publishes the latest Snapshot. Publish and read are
//! protected by a tiny spinlock (atomic.Value(bool), the zix concurrency
//! idiom, not std.Thread.Mutex) around the pointer swap and refcount bump
//! only: scrapeOnce()'s network call itself runs outside the lock, so
//! readers never wait on it.

const std = @import("std");
const config_mod = @import("config.zig");
const scrape_mod = @import("scrape.zig");
const snapshot_mod = @import("snapshot.zig");

const ScrapeConfig = config_mod.ScrapeConfig;
const Snapshot = snapshot_mod.Snapshot;

pub const Scraper = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: ScrapeConfig,
    published: *Snapshot,
    lock_flag: std.atomic.Value(bool) = .init(false),
    running: std.atomic.Value(bool),
    thread: std.Thread,

    /// Start the background poller. Publishes an initial (up = false, "not
    /// yet scraped") snapshot immediately so latest() always has something
    /// to hand back, then loops scrapeOnce/publish/sleep(scrape_interval_ms)
    /// until deinit().
    pub fn start(allocator: std.mem.Allocator, io: std.Io, config: ScrapeConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const initial = try snapshot_mod.failed(allocator, 0, 0, "not yet scraped");

        self.allocator = allocator;
        self.config = config;
        self.published = initial;
        self.lock_flag = .init(false);
        self.running = .init(true);
        self.thread = try std.Thread.spawn(.{}, run, .{ self, io });

        return self;
    }

    /// The most recently published snapshot. Never blocks on network I/O,
    /// never allocates. Bumps the refcount: the caller must release() when
    /// done reading.
    pub fn latest(self: *Self) *Snapshot {
        self.lock();
        defer self.unlock();

        self.published.retain();

        return self.published;
    }

    /// Stop the worker thread and release the scraper's own reference to
    /// the last published snapshot.
    pub fn deinit(self: *Self) void {
        self.running.store(false, .release);
        self.thread.join();

        self.published.release();
        self.allocator.destroy(self);
    }

    // --------------------------------------------------------- //

    fn run(self: *Self, io: std.Io) void {
        while (self.running.load(.acquire)) {
            const fresh = scrape_mod.scrapeOnce(self.allocator, io, self.config) catch null;

            if (fresh) |snapshot| {
                self.lock();
                const previous = self.published;
                self.published = snapshot;
                self.unlock();

                previous.release();
            }

            std.Io.sleep(io, .fromMilliseconds(@as(i64, self.config.scrape_interval_ms)), .awake) catch {};
        }
    }

    fn lock(self: *Self) void {
        while (self.lock_flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Self) void {
        self.lock_flag.store(false, .release);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

test "prometheuz: scraper publishes an initial snapshot immediately" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var scraper = try Scraper.start(testing.allocator, io, .{ .ip = "127.0.0.1", .port = 1, .scrape_interval_ms = 50, .conn_timeout_ms = 100 });
    defer scraper.deinit();

    var snapshot = scraper.latest();
    defer snapshot.release();

    try testing.expect(!snapshot.up);
    try testing.expect(snapshot.last_error != null);
}

test "prometheuz: scraper latest refcount is independent per call" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var scraper = try Scraper.start(testing.allocator, io, .{ .ip = "127.0.0.1", .port = 1, .scrape_interval_ms = 10_000, .conn_timeout_ms = 100 });
    defer scraper.deinit();

    var first = scraper.latest();
    var second = scraper.latest();

    try testing.expectEqual(@as(u32, 3), first.refcount.load(.acquire)); // 1 owner + 2 readers

    first.release();
    second.release();
}
