//! zixer main.cfg schema: parse, validate, defaults

const std = @import("std");
const builtin = @import("builtin");
const zix = @import("zix");

const cfg_scanner = @import("cfg_scanner.zig");
const conn_buffer = @import("conn_buffer.zig");
const daemon_log = @import("daemon_log.zig");
const deadline_table = @import("deadline_table.zig");
const fault = @import("fault.zig");
const process_gate = @import("process_gate.zig");
const static_cached = @import("static_cached.zig");
const upstream_conn = @import("upstream_conn.zig");

/// Dispatch enum is the zix one, so the daemon hands it straight to the engines.
pub const Dispatch = zix.Http1.DispatchModel;

/// Parsed main.cfg with every default applied.
pub const MainCfg = struct {
    workers: usize = 1,
    dispatch: Dispatch = .ASYNC,
    logs_dir: []const u8 = "",
    /// Lowest severity the daemon writes, to the log file and to the console
    /// alike. info keeps the lifecycle lines, warn and error narrow it to
    /// what needs acting on, debug opens the per-request detail.
    log_level: daemon_log.Level = .INFO,
    sites_dir: []const u8 = "",
    kernel_backlog: u31 = 1024,
    max_recv_buf: usize = conn_buffer.DEFAULT_BYTES,
    /// How long one client exchange may take before the edge cuts it. 0 is
    /// the bound off, which is what a daemon that never asked for one runs
    /// with: a site that serves long uploads or its own slow clients keeps
    /// working untouched until the value is set deliberately.
    client_timeout_ms: u32 = 0,
    /// Client connections one site tracks at once while the bound is on.
    /// Nothing is tracked and nothing is refused while the bound is off.
    client_conn_limit: usize = deadline_table.DEFAULT_CONN_LIMIT,
    /// How long a connect to an upstream may take before the edge answers
    /// 504. 0 waits on whatever the operating system decides.
    upstream_connect_timeout_ms: u32 = upstream_conn.DEFAULT_CONNECT_TIMEOUT_MS,
    /// How long an unused upstream connection is kept for the next request.
    /// 0 keeps none, so every exchange opens its own.
    upstream_idle_ttl_ms: u32 = upstream_conn.DEFAULT_IDLE_TTL_MS,
    /// Requests one site may have running upstream at once. 0 is the gate
    /// off, which is what a daemon that never asked for one runs with.
    process_limit: usize = 0,
    /// Requests that may wait for a process slot. 0 refuses the moment the
    /// limit is reached, which is shed-instead-of-queue.
    process_queue_len: usize = 0,
    /// How long a waiting request holds on before the edge answers 504.
    process_queue_timeout_ms: u32 = process_gate.DEFAULT_TIMEOUT_MS,
    /// How long a cached public_dir file stays fresh. 0 keeps caching off, so
    /// every static request re-opens and re-stats the file.
    public_dir_cache_ttl_ms: u32 = static_cached.DEFAULT_TTL_MS,
    /// Files the shared cache may hold. Daemon-wide on purpose: there is one
    /// table per process and its size is fixed the first time a site needs it.
    public_dir_cache_max_entries: u32 = static_cached.DEFAULT_MAX_ENTRIES,
};

/// Known main.cfg keys. Field names mirror the cfg key strings exactly so
/// stringToEnum does the lookup, hence lower_case here.
const Key = enum {
    workers,
    dispatch,
    logs_dir,
    log_level,
    sites_dir,
    kernel_backlog,
    max_recv_buf,
    client_timeout_ms,
    client_conn_limit,
    upstream_connect_timeout_ms,
    upstream_idle_ttl_ms,
    process_limit,
    process_queue_len,
    process_queue_timeout_ms,
    public_dir_cache_ttl_ms,
    public_dir_cache_max_entries,
};

/// Parse and validate main.cfg content.
///
/// Note:
/// - Faults never abort the parse: every problem lands in faults with a fix
///   hint, and the returned config keeps the default for a bad field.
/// - String values are slices into content, so content must outlive the result.
///
/// Param:
/// arena - std.mem.Allocator (owns the logs_dir/sites_dir defaults)
/// content - []const u8 (main.cfg bytes)
/// root_path - []const u8 (resolved zixer root dir, builds the dir defaults)
/// available_threads - usize (cpu thread count bounding workers)
/// faults - *fault.FaultList (collects every validation problem)
///
/// Return:
/// - MainCfg with defaults applied where the file was silent or wrong
pub fn parse(
    arena: std.mem.Allocator,
    content: []const u8,
    root_path: []const u8,
    available_threads: usize,
    faults: *fault.FaultList,
) !MainCfg {
    var cfg = MainCfg{};
    var seen: std.EnumSet(Key) = .empty;

    var scanner = cfg_scanner.Scanner.init(content);
    while (scanner.next()) |line| {
        const entry = switch (line) {
            .bad => |bad| {
                try fault.addBadLine(faults, bad);
                continue;
            },
            // main.cfg is flat on purpose. A section here would need a rule
            // for how it merges into every site, and there is none, so the
            // operator is sent to the file that does own sections.
            .section => |section| {
                try faults.add(section.name, "sections belong in a site cfg, main.cfg takes plain key: value lines only", .{});
                continue;
            },
            .entry => |entry| entry,
        };

        const key = std.meta.stringToEnum(Key, entry.key) orelse {
            try faults.add(entry.key, "unknown key, remove it or fix the typo", .{});
            continue;
        };

        if (seen.contains(key)) {
            try faults.add(entry.key, "duplicate key, keep one line", .{});
            continue;
        }
        seen.insert(key);

        switch (key) {
            .workers => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const workers_count = std.math.cast(usize, value) orelse {
                    try faults.add(entry.key, "must be 0 or a positive count", .{});
                    continue;
                };

                if (workers_count > available_threads) {
                    try faults.add(entry.key, "workers exceed from available threads ({d}), set to 0 or 1", .{available_threads});
                    continue;
                }

                cfg.workers = workers_count;
            },
            .dispatch => {
                const model = parseDispatch(entry.value) orelse {
                    try faults.add(entry.key, "unknown value '{s}', use async, epoll, or uring", .{entry.value});
                    continue;
                };

                if (comptime builtin.os.tag != .linux) {
                    if (model != .ASYNC) {
                        try faults.add(entry.key, "{s} needs linux, use async on this platform", .{entry.value});
                        continue;
                    }
                }

                cfg.dispatch = model;
            },
            .logs_dir => cfg.logs_dir = entry.value,
            .log_level => {
                const level = daemon_log.parseLevel(entry.value) orelse {
                    try faults.add(entry.key, "unknown value '{s}', use debug, info, warn, or error", .{entry.value});
                    continue;
                };

                cfg.log_level = level;
            },
            .sites_dir => cfg.sites_dir = entry.value,
            .kernel_backlog => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const backlog = std.math.cast(u31, value) orelse {
                    try faults.add(entry.key, "must be 1-{d}", .{std.math.maxInt(u31)});
                    continue;
                };

                if (backlog == 0) {
                    try faults.add(entry.key, "must be at least 1", .{});
                    continue;
                }

                cfg.kernel_backlog = backlog;
            },
            .max_recv_buf => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const bytes = std.math.cast(usize, value) orelse {
                    try faults.add(entry.key, "must be {d}-{d} bytes", .{ conn_buffer.MIN_BYTES, conn_buffer.MAX_BYTES });
                    continue;
                };

                if (!conn_buffer.inRange(bytes)) {
                    try faults.add(entry.key, "must be {d}-{d} bytes", .{ conn_buffer.MIN_BYTES, conn_buffer.MAX_BYTES });
                    continue;
                }

                cfg.max_recv_buf = bytes;
            },
            .client_timeout_ms => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const budget = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 turns the bound off", .{deadline_table.MAX_TIMEOUT_MS});
                    continue;
                };

                if (!deadline_table.timeoutInRange(budget)) {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 turns the bound off", .{deadline_table.MAX_TIMEOUT_MS});
                    continue;
                }

                cfg.client_timeout_ms = budget;
            },
            .client_conn_limit => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const conn_limit = std.math.cast(usize, value) orelse {
                    try faults.add(entry.key, "must be 1-{d}, set client_timeout_ms: 0 to track nothing", .{deadline_table.MAX_SLOTS});
                    continue;
                };

                if (!deadline_table.connLimitInRange(conn_limit)) {
                    try faults.add(entry.key, "must be 1-{d}, set client_timeout_ms: 0 to track nothing", .{deadline_table.MAX_SLOTS});
                    continue;
                }

                cfg.client_conn_limit = conn_limit;
            },
            .upstream_connect_timeout_ms => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const budget = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 waits on the operating system", .{upstream_conn.MAX_CONNECT_TIMEOUT_MS});
                    continue;
                };

                if (!upstream_conn.connectTimeoutInRange(budget)) {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 waits on the operating system", .{upstream_conn.MAX_CONNECT_TIMEOUT_MS});
                    continue;
                }

                cfg.upstream_connect_timeout_ms = budget;
            },
            .upstream_idle_ttl_ms => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const ttl_ms = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 keeps no connection", .{upstream_conn.MAX_IDLE_TTL_MS});
                    continue;
                };

                if (!upstream_conn.idleTtlInRange(ttl_ms)) {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 keeps no connection", .{upstream_conn.MAX_IDLE_TTL_MS});
                    continue;
                }

                cfg.upstream_idle_ttl_ms = ttl_ms;
            },
            .process_limit => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const limit = std.math.cast(usize, value) orelse {
                    try faults.add(entry.key, "must be 0-{d}, 0 turns the gate off", .{process_gate.MAX_SLOTS});
                    continue;
                };

                if (!process_gate.limitInRange(limit)) {
                    try faults.add(entry.key, "must be 0-{d}, 0 turns the gate off", .{process_gate.MAX_SLOTS});
                    continue;
                }

                cfg.process_limit = limit;
            },
            .process_queue_len => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const queue_len = std.math.cast(usize, value) orelse {
                    try faults.add(entry.key, "must be 0-{d}, 0 refuses instead of queueing", .{process_gate.MAX_SLOTS});
                    continue;
                };

                if (!process_gate.queueLenInRange(queue_len)) {
                    try faults.add(entry.key, "must be 0-{d}, 0 refuses instead of queueing", .{process_gate.MAX_SLOTS});
                    continue;
                }

                cfg.process_queue_len = queue_len;
            },
            .process_queue_timeout_ms => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const timeout_ms = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 1-{d} ms", .{process_gate.MAX_TIMEOUT_MS});
                    continue;
                };

                if (!process_gate.timeoutInRange(timeout_ms)) {
                    try faults.add(entry.key, "must be 1-{d} ms", .{process_gate.MAX_TIMEOUT_MS});
                    continue;
                }

                cfg.process_queue_timeout_ms = timeout_ms;
            },
            .public_dir_cache_ttl_ms => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const ttl_ms = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 turns the cache off", .{static_cached.MAX_TTL_MS});
                    continue;
                };

                if (!static_cached.ttlInRange(ttl_ms)) {
                    try faults.add(entry.key, "must be 0-{d} ms, 0 turns the cache off", .{static_cached.MAX_TTL_MS});
                    continue;
                }

                cfg.public_dir_cache_ttl_ms = ttl_ms;
            },
            .public_dir_cache_max_entries => {
                const value = try fault.evalNumber(faults, entry) orelse continue;
                const entries = std.math.cast(u32, value) orelse {
                    try faults.add(entry.key, "must be 1-{d} files", .{static_cached.MAX_ENTRIES});
                    continue;
                };

                if (!static_cached.maxEntriesInRange(entries)) {
                    try faults.add(entry.key, "must be 1-{d} files", .{static_cached.MAX_ENTRIES});
                    continue;
                }

                cfg.public_dir_cache_max_entries = entries;
            },
        }
    }

    if (!seen.contains(.logs_dir)) cfg.logs_dir = try std.fs.path.join(arena, &.{ root_path, "logs" });
    if (!seen.contains(.sites_dir)) cfg.sites_dir = try std.fs.path.join(arena, &.{ root_path, "sites" });

    // A waiting room with nothing to wait for is a config mistake, not a
    // setting: without a limit no request ever queues, so the line would
    // silently do nothing.
    if (cfg.process_limit == 0 and cfg.process_queue_len > 0) {
        try faults.add("process_queue_len", "needs process_limit above 0, otherwise nothing ever queues", .{});
        cfg.process_queue_len = 0;
    }

    return cfg;
}

/// Cfg spelling to dispatch value, null when unknown.
fn parseDispatch(value: []const u8) ?Dispatch {
    if (std.mem.eql(u8, value, "async")) return .ASYNC;
    if (std.mem.eql(u8, value, "epoll")) return .EPOLL;
    if (std.mem.eql(u8, value, "uring")) return .URING;

    return null;
}

/// Lowercase cfg spelling of a dispatch value, for status output.
pub fn dispatchName(model: Dispatch) []const u8 {
    return switch (model) {
        .ASYNC => "async",
        .EPOLL => "epoll",
        .URING => "uring",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: main cfg, empty content keeps defaults with dirs from root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(usize, 1), cfg.workers);
    try std.testing.expectEqual(Dispatch.ASYNC, cfg.dispatch);
    try std.testing.expectEqual(@as(u31, 1024), cfg.kernel_backlog);
    try std.testing.expectEqual(conn_buffer.DEFAULT_BYTES, cfg.max_recv_buf);

    const expected_logs = try std.fs.path.join(arena.allocator(), &.{ "/srv/zixer", "logs" });
    const expected_sites = try std.fs.path.join(arena.allocator(), &.{ "/srv/zixer", "sites" });
    try std.testing.expectEqualStrings(expected_logs, cfg.logs_dir);
    try std.testing.expectEqualStrings(expected_sites, cfg.sites_dir);
}

test "zix zixer: main cfg, full valid content with math values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const content =
        "workers: 0\n" ++
        "dispatch: uring\n" ++
        "logs_dir: /var/log/zixer\n" ++
        "sites_dir: /etc/zixer/sites\n" ++
        "kernel_backlog: 2 * 1024\n" ++
        "max_recv_buf: 16 * 1024\n";

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    // epoll and uring are Linux dispatch models, elsewhere the same line faults.
    if (comptime builtin.os.tag == .linux) {
        try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
        try std.testing.expectEqual(Dispatch.URING, cfg.dispatch);
    } else {
        try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
        try std.testing.expectEqualStrings("dispatch", faults.slice()[0].key);
        try std.testing.expectEqual(Dispatch.ASYNC, cfg.dispatch);
    }

    try std.testing.expectEqual(@as(usize, 0), cfg.workers);
    try std.testing.expectEqualStrings("/var/log/zixer", cfg.logs_dir);
    try std.testing.expectEqualStrings("/etc/zixer/sites", cfg.sites_dir);
    try std.testing.expectEqual(@as(u31, 2048), cfg.kernel_backlog);
    try std.testing.expectEqual(@as(usize, 16384), cfg.max_recv_buf);
}

test "zix zixer: main cfg, workers above available threads faults and keeps default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "workers: 64\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("workers", faults.slice()[0].key);
    try std.testing.expectEqualStrings("workers exceed from available threads (8), set to 0 or 1", faults.slice()[0].hint);
    try std.testing.expectEqual(@as(usize, 1), cfg.workers);
}

test "zix zixer: main cfg, unknown and duplicate keys fault" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const content =
        "wrokers: 2\n" ++
        "workers: 2\n" ++
        "workers: 3\n";

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 2), faults.slice().len);
    try std.testing.expectEqualStrings("wrokers", faults.slice()[0].key);
    try std.testing.expectEqualStrings("unknown key, remove it or fix the typo", faults.slice()[0].hint);
    try std.testing.expectEqualStrings("duplicate key, keep one line", faults.slice()[1].hint);
    try std.testing.expectEqual(@as(usize, 2), cfg.workers);
}

test "zix zixer: main cfg, bad dispatch and bad math fault with hints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const content =
        "dispatch: turbo\n" ++
        "kernel_backlog: 10 / 4\n" ++
        "no colon line\n";

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 3), faults.slice().len);
    try std.testing.expectEqualStrings("unknown value 'turbo', use async, epoll, or uring", faults.slice()[0].hint);
    try std.testing.expectEqualStrings("division leaves a remainder, config values must be exact", faults.slice()[1].hint);
    try std.testing.expectEqualStrings("no colon line", faults.slice()[2].key);
    try std.testing.expectEqual(Dispatch.ASYNC, cfg.dispatch);
    try std.testing.expectEqual(@as(u31, 1024), cfg.kernel_backlog);
}

test "zix zixer: main cfg, a max recv buf outside the range faults and keeps the default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const content = "max_recv_buf: 64\n";

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("max_recv_buf", faults.slice()[0].key);
    try std.testing.expect(std.mem.indexOf(u8, faults.slice()[0].hint, "bytes") != null);
    try std.testing.expectEqual(conn_buffer.DEFAULT_BYTES, cfg.max_recv_buf);
}

test "zix zixer: main cfg, a max recv buf above the ceiling faults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [64]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "max_recv_buf: {d}\n", .{conn_buffer.MAX_BYTES + 1});

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqual(conn_buffer.DEFAULT_BYTES, cfg.max_recv_buf);
}

test "zix zixer: main cfg, the range ends are both accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var low_buf: [64]u8 = undefined;
    const low_content = try std.fmt.bufPrint(&low_buf, "max_recv_buf: {d}\n", .{conn_buffer.MIN_BYTES});
    var low_faults = fault.FaultList.init(arena.allocator());
    const low = try parse(arena.allocator(), low_content, "/srv/zixer", 8, &low_faults);

    var high_buf: [64]u8 = undefined;
    const high_content = try std.fmt.bufPrint(&high_buf, "max_recv_buf: {d}\n", .{conn_buffer.MAX_BYTES});
    var high_faults = fault.FaultList.init(arena.allocator());
    const high = try parse(arena.allocator(), high_content, "/srv/zixer", 8, &high_faults);

    try std.testing.expectEqual(@as(usize, 0), low_faults.slice().len);
    try std.testing.expectEqual(conn_buffer.MIN_BYTES, low.max_recv_buf);
    try std.testing.expectEqual(@as(usize, 0), high_faults.slice().len);
    try std.testing.expectEqual(conn_buffer.MAX_BYTES, high.max_recv_buf);
}

test "zix zixer: main cfg, the process gate defaults to off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_limit);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
    try std.testing.expectEqual(process_gate.DEFAULT_TIMEOUT_MS, cfg.process_queue_timeout_ms);
}

test "zix zixer: main cfg, a full process gate parses with math values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const content =
        "process_limit: 64\n" ++
        "process_queue_len: 4 * 64\n" ++
        "process_queue_timeout_ms: 2 * 1000\n";

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(usize, 64), cfg.process_limit);
    try std.testing.expectEqual(@as(usize, 256), cfg.process_queue_len);
    try std.testing.expectEqual(@as(u32, 2000), cfg.process_queue_timeout_ms);
}

test "zix zixer: main cfg, a queue with no limit faults and is turned off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "process_queue_len: 32\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("process_queue_len", faults.slice()[0].key);
    try std.testing.expectEqualStrings("needs process_limit above 0, otherwise nothing ever queues", faults.slice()[0].hint);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
}

test "zix zixer: main cfg, a limit with no queue is a valid shedding site" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "process_limit: 8\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(usize, 8), cfg.process_limit);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
}

test "zix zixer: main cfg, a zero queue timeout faults and keeps the default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "process_queue_timeout_ms: 0\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("process_queue_timeout_ms", faults.slice()[0].key);
    try std.testing.expectEqual(process_gate.DEFAULT_TIMEOUT_MS, cfg.process_queue_timeout_ms);
}

test "zix zixer: main cfg, process gate values above their ceilings fault" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "process_limit: {d}\nprocess_queue_len: {d}\nprocess_queue_timeout_ms: {d}\n", .{
        process_gate.MAX_SLOTS + 1,
        process_gate.MAX_SLOTS + 1,
        process_gate.MAX_TIMEOUT_MS + 1,
    });

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 3), faults.slice().len);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_limit);
    try std.testing.expectEqual(@as(usize, 0), cfg.process_queue_len);
    try std.testing.expectEqual(process_gate.DEFAULT_TIMEOUT_MS, cfg.process_queue_timeout_ms);
}

test "zix zixer: main cfg, the process gate ceilings are accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "process_limit: {d}\nprocess_queue_len: {d}\nprocess_queue_timeout_ms: {d}\n", .{
        process_gate.MAX_SLOTS,
        process_gate.MAX_SLOTS,
        process_gate.MAX_TIMEOUT_MS,
    });

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(process_gate.MAX_SLOTS, cfg.process_limit);
    try std.testing.expectEqual(process_gate.MAX_SLOTS, cfg.process_queue_len);
    try std.testing.expectEqual(process_gate.MAX_TIMEOUT_MS, cfg.process_queue_timeout_ms);
}

test "zix zixer: main cfg, the static cache defaults to off with room reserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), cfg.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(static_cached.DEFAULT_MAX_ENTRIES, cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, the static cache keys parse with math values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(
        arena.allocator(),
        "public_dir_cache_ttl_ms: 5 * 1000\npublic_dir_cache_max_entries: 4 * 256\n",
        "/srv/zixer",
        8,
        &faults,
    );

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 5000), cfg.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(@as(u32, 1024), cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, entries stay meaningful while the window is off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Unlike a process queue with no limit, this pair is not dead config: a
    // site may switch its own window on and the entry count is what it gets.
    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "public_dir_cache_max_entries: 64\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), cfg.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(@as(u32, 64), cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, static cache values above their ceilings fault" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "public_dir_cache_ttl_ms: {d}\npublic_dir_cache_max_entries: {d}\n", .{
        static_cached.MAX_TTL_MS + 1,
        static_cached.MAX_ENTRIES + 1,
    });

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 2), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), cfg.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(static_cached.DEFAULT_MAX_ENTRIES, cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, a zero entry count faults and keeps the default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "public_dir_cache_max_entries: 0\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("public_dir_cache_max_entries", faults.slice()[0].key);
    try std.testing.expectEqual(static_cached.DEFAULT_MAX_ENTRIES, cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, the static cache ceilings are accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "public_dir_cache_ttl_ms: {d}\npublic_dir_cache_max_entries: {d}\n", .{
        static_cached.MAX_TTL_MS,
        static_cached.MAX_ENTRIES,
    });

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(static_cached.MAX_TTL_MS, cfg.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(static_cached.MAX_ENTRIES, cfg.public_dir_cache_max_entries);
}

test "zix zixer: main cfg, dispatch names round trip" {
    try std.testing.expectEqual(Dispatch.ASYNC, parseDispatch("async").?);
    try std.testing.expectEqual(Dispatch.EPOLL, parseDispatch("epoll").?);
    try std.testing.expectEqual(Dispatch.URING, parseDispatch("uring").?);
    try std.testing.expectEqual(@as(?Dispatch, null), parseDispatch("ASYNC"));

    try std.testing.expectEqualStrings("async", dispatchName(.ASYNC));
    try std.testing.expectEqualStrings("epoll", dispatchName(.EPOLL));
    try std.testing.expectEqualStrings("uring", dispatchName(.URING));
}

test "zix zixer: main cfg, the client bound defaults to off with a limit reserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    // Off by default: an upgrade must not start cutting connections a site
    // has always been allowed to hold.
    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), cfg.client_timeout_ms);
    try std.testing.expectEqual(deadline_table.DEFAULT_CONN_LIMIT, cfg.client_conn_limit);
}

test "zix zixer: main cfg, the client bound keys parse with math values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "client_timeout_ms: 30 * 1000\nclient_conn_limit: 8 * 1024\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 30_000), cfg.client_timeout_ms);
    try std.testing.expectEqual(@as(usize, 8192), cfg.client_conn_limit);
}

test "zix zixer: main cfg, a limit stays meaningful while the bound is off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Unlike a process queue with no limit, this pair is not dead config: a
    // site may switch its own bound on and this is the limit it inherits.
    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "client_conn_limit: 64\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), cfg.client_timeout_ms);
    try std.testing.expectEqual(@as(usize, 64), cfg.client_conn_limit);
}

test "zix zixer: main cfg, client bound values outside their range fault" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "client_timeout_ms: {d}\nclient_conn_limit: 0\n", .{deadline_table.MAX_TIMEOUT_MS + 1});

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 2), faults.slice().len);
    try std.testing.expectEqualStrings("client_timeout_ms", faults.slice()[0].key);
    try std.testing.expectEqualStrings("client_conn_limit", faults.slice()[1].key);
    try std.testing.expectEqual(@as(u32, 0), cfg.client_timeout_ms);
    try std.testing.expectEqual(deadline_table.DEFAULT_CONN_LIMIT, cfg.client_conn_limit);
}

test "zix zixer: main cfg, the upstream connect and idle keys default to the built-in values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(upstream_conn.DEFAULT_CONNECT_TIMEOUT_MS, cfg.upstream_connect_timeout_ms);
    try std.testing.expectEqual(upstream_conn.DEFAULT_IDLE_TTL_MS, cfg.upstream_idle_ttl_ms);
}

test "zix zixer: main cfg, the upstream connect and idle keys parse and accept zero" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "upstream_connect_timeout_ms: 2 * 1000\nupstream_idle_ttl_ms: 60 * 1000\n", "/srv/zixer", 8, &faults);
    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(@as(u32, 2000), cfg.upstream_connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), cfg.upstream_idle_ttl_ms);

    var off_faults = fault.FaultList.init(arena.allocator());
    const off = try parse(arena.allocator(), "upstream_connect_timeout_ms: 0\nupstream_idle_ttl_ms: 0\n", "/srv/zixer", 8, &off_faults);
    try std.testing.expectEqual(@as(usize, 0), off_faults.slice().len);
    try std.testing.expectEqual(@as(u32, 0), off.upstream_connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), off.upstream_idle_ttl_ms);
}

test "zix zixer: main cfg, upstream connect and idle values above their ceilings fault" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var content_buf: [160]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "upstream_connect_timeout_ms: {d}\nupstream_idle_ttl_ms: {d}\n", .{
        upstream_conn.MAX_CONNECT_TIMEOUT_MS + 1,
        upstream_conn.MAX_IDLE_TTL_MS + 1,
    });

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), content, "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 2), faults.slice().len);
    try std.testing.expectEqual(upstream_conn.DEFAULT_CONNECT_TIMEOUT_MS, cfg.upstream_connect_timeout_ms);
    try std.testing.expectEqual(upstream_conn.DEFAULT_IDLE_TTL_MS, cfg.upstream_idle_ttl_ms);
}

test "zix zixer: main cfg, log_level defaults to info" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
    try std.testing.expectEqual(daemon_log.Level.INFO, cfg.log_level);
}

test "zix zixer: main cfg, every log_level spelling parses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { line: []const u8, want: daemon_log.Level }{
        .{ .line = "log_level: debug\n", .want = .DEBUG },
        .{ .line = "log_level: info\n", .want = .INFO },
        .{ .line = "log_level: warn\n", .want = .WARN },
        .{ .line = "log_level: error\n", .want = .ERROR },
    };

    for (cases) |case| {
        var faults = fault.FaultList.init(arena.allocator());
        const cfg = try parse(arena.allocator(), case.line, "/srv/zixer", 8, &faults);

        try std.testing.expectEqual(@as(usize, 0), faults.slice().len);
        try std.testing.expectEqual(case.want, cfg.log_level);
    }
}

test "zix zixer: main cfg, an unknown log_level faults and keeps the default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var faults = fault.FaultList.init(arena.allocator());
    const cfg = try parse(arena.allocator(), "log_level: loud\n", "/srv/zixer", 8, &faults);

    try std.testing.expectEqual(@as(usize, 1), faults.slice().len);
    try std.testing.expectEqualStrings("log_level", faults.slice()[0].key);
    try std.testing.expectEqualStrings("unknown value 'loud', use debug, info, warn, or error", faults.slice()[0].hint);
    try std.testing.expectEqual(daemon_log.Level.INFO, cfg.log_level);
}
