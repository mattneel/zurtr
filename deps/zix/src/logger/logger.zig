//! zix logger

const std = @import("std");
const builtin = @import("builtin");
const ZIG_SEMVER = @import("../lib.zig").ZIG_SEMVER;
const win_io = @import("../utils/windows_io.zig");
const win_file = @import("windows_file.zig");
const Sink = @import("sink.zig").Sink;
const Flusher = @import("flush.zig").Flusher;

// --------------------------------------------------------- //

/// Which destination a batch of bytes is headed for.
const SinkKind = enum { CONSOLE, FILE };

/// Stack buffer for formatting one log line before it is written.
const LINE_BUF_SIZE: usize = 4096;

/// Stack buffer for formatting one system() message before it is written.
const MSG_BUF_SIZE: usize = 2048;

/// Stack buffer for building the per-day log directory path (sentinel-terminated for mkdirat).
const DIR_PATH_BUF_SIZE: usize = 512;

/// Stack buffer for building the full log file path.
const FILE_PATH_BUF_SIZE: usize = 600;

/// What ends a record the buffer could not hold, so a short line is never read as a complete one.
const TRUNCATION_MARK = " ...[truncated]";

const Timestamp = struct {
    date: [10]u8,
    time: [12]u8,
};

fn getTimestamp() Timestamp {
    var secs: u64 = 0;
    var ms_part: u64 = 0;

    if (comptime builtin.target.os.tag == .linux) {
        var spec: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &spec);
        secs = if (spec.sec >= 0) @intCast(spec.sec) else 0;
        ms_part = if (spec.nsec >= 0) @as(u64, @intCast(spec.nsec)) / 1_000_000 else 0;
    } else if (comptime builtin.target.os.tag == .windows) {
        const ns = win_io.wallClockNs();
        secs = ns / std.time.ns_per_s;
        ms_part = (ns % std.time.ns_per_s) / 1_000_000;
    } else {
        var spec: std.posix.timespec = undefined;
        _ = std.posix.system.clock_gettime(.REALTIME, &spec);
        secs = if (spec.sec >= 0) @intCast(spec.sec) else 0;
        ms_part = if (spec.nsec >= 0) @as(u64, @intCast(spec.nsec)) / 1_000_000 else 0;
    }

    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const year: u16 = year_day.year;
    const month: u4 = month_day.month.numeric();
    const day: u5 = month_day.day_index + 1;
    const hour: u5 = day_secs.getHoursIntoDay();
    const minute: u6 = day_secs.getMinutesIntoHour();
    const second: u6 = day_secs.getSecondsIntoMinute();

    var timestamp: Timestamp = undefined;
    _ = std.fmt.bufPrint(&timestamp.date, "{d:0>4}-{d:0>2}-{d:0>2}", .{ year, month, day }) catch {};
    _ = std.fmt.bufPrint(&timestamp.time, "{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{ hour, minute, second, ms_part }) catch {};
    return timestamp;
}

/// Sentinel for "no log file open". Windows descriptors are opaque pointers, POSIX are ints.
const NO_FILE_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// Whether fd refers to an open log file (is not the NO_FILE_FD sentinel).
fn hasFileFd(fd: std.posix.fd_t) bool {
    if (comptime builtin.os.tag == .windows) return fd != std.os.windows.INVALID_HANDLE_VALUE;

    return fd >= 0;
}

/// Stderr descriptor for console output: the PEB handle on Windows, the POSIX
/// descriptor elsewhere.
fn stderrFd() std.posix.fd_t {
    if (comptime builtin.os.tag == .windows) return std.Io.File.stderr().handle;

    return std.posix.STDERR_FILENO;
}

/// Write every byte of data to fd.
///
/// Note:
/// - .INTR and .AGAIN are retried rather than treated as the end. A signal arriving mid-write, or a
///   pipe that is momentarily full, is not a reason to lose the line.
/// - A write of zero bytes is reported as .IO rather than looped on, because retrying it forever
///   would spin the caller.
///
/// Param:
/// fd - std.posix.fd_t (the log file, or the console descriptor)
///
/// Return:
/// - null when the whole slice went out
/// - the errno that stopped it otherwise, for the caller to report once
fn rawWrite(fd: std.posix.fd_t, data: []const u8) ?std.posix.E {
    if (comptime builtin.os.tag == .windows) {
        // On Windows this only ever carries console output and the suspend report: the log file
        // has its own ntdll path in windows_file.zig. A console redirected by config is a real
        // file, so it takes that same path, and stderr keeps the std.debug lock writer, which is
        // the portable no-allocation way to reach it.
        if (fd != stderrFd()) {
            win_file.writeAll(fd, data) catch return .IO;

            return null;
        }

        const stderr = std.debug.lockStderr(&.{});
        defer std.debug.unlockStderr();

        stderr.file_writer.interface.writeAll(data) catch return .IO;

        return null;
    }

    var remaining = data;
    while (remaining.len > 0) {
        const write_result = std.posix.system.write(fd, remaining.ptr, remaining.len);
        switch (std.posix.errno(write_result)) {
            .SUCCESS => {
                const n: usize = @intCast(write_result);
                if (n == 0) return .IO;

                remaining = remaining[n..];
            },
            .INTR, .AGAIN => continue,
            else => |errno| return errno,
        }
    }

    return null;
}

/// Format one record into buf, keeping a truncated line rather than dropping it.
///
/// Note:
/// - A dropped record is worse than a short one: the reader loses the fact that anything happened
///   at all. What does not fit is replaced by TRUNCATION_MARK, so a short line is always readable
///   as short.
/// - buf has to be wider than the mark, which every caller's buffer is by hundreds of bytes.
///
/// Param:
/// buf - []u8 (the caller's stack buffer)
///
/// Return:
/// - the formatted slice, marked when it did not all fit
fn formatRecord(buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    const room = buf.len - TRUNCATION_MARK.len;

    var writer = std.Io.Writer.fixed(buf[0..room]);
    writer.print(fmt, args) catch {
        const kept = writer.buffered().len;
        @memcpy(buf[kept..][0..TRUNCATION_MARK.len], TRUNCATION_MARK);

        return buf[0 .. kept + TRUNCATION_MARK.len];
    };

    return writer.buffered();
}

// --------------------------------------------------------- //

pub const Logger = struct {
    pub const Level = enum(u8) {
        DEBUG = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
    };

    pub const ConsoleMode = enum(u8) {
        OFF = 0,
        DEBUG_ONLY = 1,
        ALWAYS = 2,
    };

    /// Transfer direction for packet() and frame() log calls.
    pub const Dir = enum(u8) {
        RECV = 0,
        SEND = 1,
    };

    pub const Config = struct {
        /// Console output mode.
        console: ConsoleMode = .OFF,
        /// Minimum level for console output.
        console_min_level: Level = .INFO,
        /// Descriptor console records and the file-suspension notice are written to. null, the
        /// default, means stderr. A test points this at a file so that running a suite writes
        /// nothing to the terminal, and a daemon can send console output wherever it already keeps
        /// its own stream.
        console_fd: ?std.posix.fd_t = null,
        /// Directory for log files. Must already exist, caller's responsibility. Empty string disables file logging.
        save_path: []const u8 = "",
        /// Base name for log files (e.g. "log" -> "log-000000.log").
        save_file: []const u8 = "log",
        /// Minimum level for file output.
        save_min_level: Level = .INFO,
        /// Lines per file before rotating to the next sequence number.
        max_lines: u64 = 1_000_000,
        /// Bytes per write buffer. Each enabled destination holds two of these: producers fill one
        /// while the flush thread writes the other, so one write carries a whole buffer of lines
        /// instead of a single line. Raised to fit one whole record if it is set smaller than that.
        write_buf_size: usize = 64 * 1024,
    };

    // --------------------------------------------------------- //

    config: Config,
    allocator: std.mem.Allocator,
    locked: std.atomic.Value(bool) = .init(false),

    file_fd: std.posix.fd_t = NO_FILE_FD,
    current_date: [10]u8 = undefined,
    file_seq: u32 = 0,
    line_count: u64 = 0,
    file_suspended: bool = false,

    /// Buffered bytes on their way to the log file.
    file_sink: Sink = .{},
    /// Buffered bytes on their way to the console descriptor.
    console_sink: Sink = .{},
    /// The thread that owns every batched write.
    flusher: Flusher = .{},
    /// Set when the thread could not be spawned, so the logger stops retrying and drains inline.
    flusher_unavailable: bool = false,

    const Self = @This();

    // --------------------------------------------------------- //

    fn statusLevel(status: u16) Level {
        return if (status >= 500) .ERROR else if (status >= 400) .WARN else if (status >= 200) .INFO else .DEBUG;
    }

    fn levelLabel(level: Level) *const [5]u8 {
        return switch (level) {
            .DEBUG => "DEBUG",
            .INFO => "INFO ",
            .WARN => "WARN ",
            .ERROR => "ERROR",
        };
    }

    // --------------------------------------------------------- //

    /// Build a logger and open its log file straight away.
    ///
    /// Note:
    /// - The file is opened here rather than on the first record that passes the level gate, so a
    ///   quiet engine still produces a file and an operator can tell logging apart from silence.
    /// - The flush thread is not started here. `init` returns by value, so the struct still has to
    ///   move into the caller's variable, and the thread needs the address it will finally live at.
    ///   The first record starts it.
    ///
    /// Return:
    /// - Logger
    /// - error.OutOfMemory when a write buffer cannot be allocated
    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        var self = Self{
            .config = config,
            .allocator = allocator,
        };

        // A record that cannot fit an empty buffer could never be written at all, so the buffer is
        // never allowed to be narrower than one whole record plus its newline.
        const each = @max(config.write_buf_size, LINE_BUF_SIZE + 1);

        if (config.console != .OFF) try self.console_sink.alloc(allocator, each);
        errdefer self.console_sink.free(allocator);

        if (config.save_path.len > 0) {
            try self.file_sink.alloc(allocator, each);

            const timestamp = getTimestamp();
            self.current_date = timestamp.date;
            self.openFileLocked(&timestamp.date);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        // Stop the thread before touching the buffers: it writes out of them with the lock
        // released, so freeing them under it would pull the slice out from under a write.
        self.flusher.stop();

        self.spinLock();
        defer self.spinUnlock();

        self.drainLocked();
        self.closeFileLocked();

        self.file_sink.free(self.allocator);
        self.console_sink.free(self.allocator);
    }

    /// Write out everything logged so far before returning.
    pub fn flush(self: *Self) void {
        self.spinLock();
        defer self.spinUnlock();

        self.drainLocked();
    }

    /// How many times a producer had to wait because both of a destination's buffers were spoken
    /// for. Non-zero means the disk could not keep up and records were delayed, never dropped.
    pub fn stallCount(self: *Self) u64 {
        self.spinLock();
        defer self.spinUnlock();

        return self.file_sink.stalls + self.console_sink.stalls;
    }

    /// Records buffered for the log file, and batches actually written out for it. The ratio is
    /// how much batching the write buffer achieved.
    ///
    /// Return:
    /// - a struct of lines and writes
    pub fn fileBatchCounts(self: *Self) struct { lines: u64, writes: u64 } {
        self.spinLock();
        defer self.spinUnlock();

        return .{ .lines = self.file_sink.lines, .writes = self.file_sink.writes };
    }

    // --------------------------------------------------------- //

    fn spinLock(self: *Self) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn spinUnlock(self: *Self) void {
        self.locked.store(false, .release);
    }

    /// Start the flush thread if it is not already running. Called under the lock on the first
    /// record, because that is the first moment the logger's final address is known.
    fn ensureFlusherLocked(self: *Self) void {
        if (self.flusher.running() or self.flusher_unavailable) return;

        // A logger with no destination has nothing to write, so it gets no thread. That is the
        // shape a caller builds by hand to silence a component it does not want to hear from.
        if (!self.console_sink.enabled() and !self.file_sink.enabled()) return;

        self.flusher.start(self, pumpTrampoline) catch {
            // A logger without its thread still works: every drain simply happens inline, which is
            // the behaviour this replaced. Retrying per record would cost a spawn attempt each time.
            self.flusher_unavailable = true;
        };
    }

    fn pumpTrampoline(context: *anyopaque, urgent_only: bool) bool {
        const self: *Self = @ptrCast(@alignCast(context));

        return self.pump(urgent_only);
    }

    /// One flush-thread pass: hand both destinations' buffered bytes to their descriptors.
    ///
    /// Param:
    /// urgent_only - bool (true writes only what cannot wait, so a trickle of records is left to
    ///   accumulate over the thread's nap instead of costing a syscall each)
    ///
    /// Return:
    /// - true when a batch went out, so the thread comes straight back rather than napping
    /// - false when there was nothing worth writing
    fn pump(self: *Self, urgent_only: bool) bool {
        self.spinLock();
        defer self.spinUnlock();

        const console_moved = self.pumpSinkLocked(&self.console_sink, .CONSOLE, urgent_only);
        const file_moved = self.pumpSinkLocked(&self.file_sink, .FILE, urgent_only);

        return console_moved or file_moved;
    }

    /// Write one destination's buffer, with the lock released across the write.
    ///
    /// Note:
    /// - Releasing the lock is the whole point: a producer only ever waits for a memcpy, never for
    ///   a disk. The buffer being written is safe to touch unlocked because `pending != 0` is what
    ///   stops anyone else from swapping, rotating, or freeing it.
    ///
    /// Return:
    /// - true when a batch was written
    fn pumpSinkLocked(self: *Self, sink: *Sink, kind: SinkKind, urgent_only: bool) bool {
        if (!sink.enabled() or sink.isIdle()) return false;

        // A handed-over buffer always goes now, because a producer may already be waiting on it.
        // A half-full one goes now too, so a fast producer never runs into the nap. Anything less
        // waits for the nap to end, which is what keeps a trickle from costing a write per line.
        if (urgent_only and sink.pending == 0 and sink.fill * 2 < sink.capacity()) return false;

        if (sink.pending == 0) sink.swap();

        const bytes = sink.pendingBytes();
        const fd = self.fdFor(kind);

        self.spinUnlock();
        const failure = writeOut(kind, fd, bytes);
        self.spinLock();

        sink.pending = 0;
        sink.writes += 1;

        if (failure) |cause| {
            if (kind == .FILE) self.suspendFileLocked(cause, self.config.save_path);
        }

        return true;
    }

    /// Write out both destinations on this thread, before returning. The lock is held throughout,
    /// which is what makes this the synchronous path used by flush, deinit, rotation, and errors.
    fn drainLocked(self: *Self) void {
        self.drainSinkLocked(&self.console_sink, .CONSOLE);
        self.drainSinkLocked(&self.file_sink, .FILE);
    }

    fn drainSinkLocked(self: *Self, sink: *Sink, kind: SinkKind) void {
        if (!sink.enabled()) return;

        // Anything the flush thread is already writing has to land first, or the records would
        // reach the file out of order.
        self.waitPendingClearLocked(sink, kind);

        if (sink.fill == 0) return;

        sink.swap();
        self.writePendingLocked(sink, kind);
    }

    /// Write the handed-over buffer on this thread and mark it done. The lock is held throughout.
    fn writePendingLocked(self: *Self, sink: *Sink, kind: SinkKind) void {
        const failure = writeOut(kind, self.fdFor(kind), sink.pendingBytes());

        sink.pending = 0;
        sink.writes += 1;

        if (failure) |cause| {
            if (kind == .FILE) self.suspendFileLocked(cause, self.config.save_path);
        }
    }

    /// Wait until the buffer handed to the flush thread has been written.
    ///
    /// Note:
    /// - The lock is released while waiting, otherwise the flush thread could never take it back
    ///   to report the write as done.
    /// - With no flush thread nothing would ever come and write it, so the waiter does the write
    ///   itself. That is the path a logger takes when the thread could not be spawned.
    fn waitPendingClearLocked(self: *Self, sink: *Sink, kind: SinkKind) void {
        while (sink.pending != 0) {
            if (!self.flusher.running()) {
                self.writePendingLocked(sink, kind);

                return;
            }

            self.spinUnlock();
            std.Thread.yield() catch std.atomic.spinLoopHint();
            self.spinLock();
        }
    }

    /// Copy one record into a destination's active buffer, waiting rather than dropping it.
    ///
    /// Note:
    /// - A record is never lost. When the active buffer is full it is handed over and the record
    ///   goes into the other one. When both are spoken for the producer waits for the write in
    ///   flight, which is counted as a stall so a disk that cannot keep up is visible.
    /// - A record longer than a whole buffer is the one case that cannot be served, and `init`
    ///   makes the buffer wide enough for any record the formatter can produce.
    fn appendLocked(self: *Self, sink: *Sink, kind: SinkKind, line: []const u8) void {
        if (!sink.enabled() or !sink.couldEverFit(line)) return;

        while (!sink.tryAppend(line)) {
            if (sink.pending != 0) {
                sink.stalls += 1;
                self.waitPendingClearLocked(sink, kind);
            }

            sink.swap();
        }
    }

    fn closeFileLocked(self: *Self) void {
        if (!hasFileFd(self.file_fd)) return;

        if (comptime builtin.os.tag == .windows) {
            win_file.closeFile(self.file_fd);
        } else {
            _ = std.posix.system.close(self.file_fd);
        }

        self.file_fd = NO_FILE_FD;
    }

    fn openFileLocked(self: *Self, date: *const [10]u8) void {
        if (comptime builtin.os.tag == .windows) {
            self.openFileWindowsLocked(date);
            return;
        }

        var dir_buf: [DIR_PATH_BUF_SIZE:0]u8 = undefined;
        const dir_z = if (comptime ZIG_SEMVER.MINOR == 16)
            std.fmt.bufPrintZ(&dir_buf, "{s}/{s}", .{ self.config.save_path, date }) catch {
                // Without the suspend the logger would rebuild this same path for every record and
                // fail the same way, silently, for the life of the process.
                self.suspendFileLocked("the day directory path is longer than the logger allows", self.config.save_path);
                return;
            }
        else
            std.fmt.bufPrintSentinel(&dir_buf, "{s}/{s}", .{ self.config.save_path, date }, 0) catch {
                self.suspendFileLocked("the day directory path is longer than the logger allows", self.config.save_path);
                return;
            };

        const mkdir_rc = std.posix.system.mkdirat(@as(i32, std.posix.AT.FDCWD), dir_z, 0o755);
        switch (std.posix.errno(mkdir_rc)) {
            .SUCCESS, .EXIST => {},
            else => |errno| {
                self.suspendFileLocked(@tagName(errno), dir_z);
                return;
            },
        }

        var file_buf: [FILE_PATH_BUF_SIZE]u8 = undefined;
        const file_path = std.fmt.bufPrint(
            &file_buf,
            "{s}/{s}/{s}-{d:0>6}.log",
            .{ self.config.save_path, date, self.config.save_file, self.file_seq },
        ) catch {
            self.suspendFileLocked("the log file path is longer than the logger allows", self.config.save_path);
            return;
        };

        self.file_fd = std.posix.openat(
            @as(std.posix.fd_t, std.posix.AT.FDCWD),
            file_path,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
            0o644,
        ) catch |err| {
            self.suspendFileLocked(@errorName(err), file_path);
            return;
        };
    }

    /// The Windows arm of openFileLocked: same day directory and same file name, over ntdll.
    fn openFileWindowsLocked(self: *Self, date: *const [10]u8) void {
        var dir_buf: [DIR_PATH_BUF_SIZE]u8 = undefined;
        const dir_path = std.fmt.bufPrint(&dir_buf, "{s}/{s}", .{ self.config.save_path, date }) catch {
            // Without the suspend the logger would rebuild this same path for every record and
            // fail the same way, silently, for the life of the process.
            self.suspendFileLocked("the day directory path is longer than the logger allows", self.config.save_path);
            return;
        };

        win_file.createDir(dir_path) catch |err| {
            self.suspendFileLocked(@errorName(err), dir_path);
            return;
        };

        var file_buf: [FILE_PATH_BUF_SIZE]u8 = undefined;
        const file_path = std.fmt.bufPrint(
            &file_buf,
            "{s}/{s}/{s}-{d:0>6}.log",
            .{ self.config.save_path, date, self.config.save_file, self.file_seq },
        ) catch {
            self.suspendFileLocked("the log file path is longer than the logger allows", self.config.save_path);
            return;
        };

        self.file_fd = win_file.openAppend(file_path) catch |err| {
            self.suspendFileLocked(@errorName(err), file_path);
            return;
        };
    }

    /// Send one batch of bytes to its destination.
    ///
    /// Note:
    /// - A failed console write has nowhere left to be reported, so it is dropped rather than
    ///   looped on. A failed file write is named so the caller can suspend the file sink once.
    ///
    /// Param:
    /// fd - std.posix.fd_t (the log file descriptor, ignored for the console)
    ///
    /// Return:
    /// - null when the batch went out, or when there was nothing to send
    /// - the cause name when a file write failed
    /// The descriptor one destination writes to. Console output goes to stderr unless the config
    /// named another one, which is what makes a suite able to read back what it wrote.
    fn fdFor(self: *const Self, kind: SinkKind) std.posix.fd_t {
        return switch (kind) {
            .CONSOLE => self.config.console_fd orelse stderrFd(),
            .FILE => self.file_fd,
        };
    }

    fn writeOut(kind: SinkKind, fd: std.posix.fd_t, bytes: []const u8) ?[]const u8 {
        if (bytes.len == 0) return null;

        if (kind == .CONSOLE) {
            _ = rawWrite(fd, bytes);

            return null;
        }

        if (!hasFileFd(fd)) return null;

        if (comptime builtin.os.tag == .windows) {
            win_file.writeAll(fd, bytes) catch |err| return @errorName(err);

            return null;
        }

        if (rawWrite(fd, bytes)) |errno| return @tagName(errno);

        return null;
    }

    /// Stop writing to the log file and say why, once, on the console descriptor.
    ///
    /// Note:
    /// - The console is the only destination left: the thing that failed IS the log file. The old
    ///   line guessed one cause ("ensure save_path exists") for every failure and never printed the
    ///   path, so a permission problem and a typo read the same.
    /// - file_suspended is what makes this once. Every later record skips the file sink.
    ///
    /// Param:
    /// cause - []const u8 (the errno or error name, or a sentence when there is no errno)
    /// subject - []const u8 (the path it happened to, empty when there is none)
    fn suspendFileLocked(self: *Self, cause: []const u8, subject: []const u8) void {
        self.file_suspended = true;

        var report_buf: [FILE_PATH_BUF_SIZE + 192]u8 = undefined;
        const line = if (subject.len > 0)
            formatRecord(&report_buf, "zix: logger: {s}: {s}, file logging suspended, console logging continues\n", .{ cause, subject })
        else
            formatRecord(&report_buf, "zix: logger: {s}, file logging suspended, console logging continues\n", .{cause});

        _ = rawWrite(self.fdFor(.CONSOLE), line);
    }

    fn ensureFileLocked(self: *Self, date: *const [10]u8) void {
        if (self.file_suspended) return;

        if (!hasFileFd(self.file_fd)) {
            self.current_date = date.*;
            self.file_seq = 0;
            self.line_count = 0;
            self.openFileLocked(date);
            return;
        }

        const date_changed = !std.mem.eql(u8, &self.current_date, date);
        if (date_changed) {
            self.drainSinkLocked(&self.file_sink, .FILE);
            self.closeFileLocked();
            self.current_date = date.*;
            self.file_seq = 0;
            self.line_count = 0;
            self.openFileLocked(date);
            return;
        }

        if (self.line_count >= self.config.max_lines) {
            if (self.file_seq >= 999_999) {
                self.drainSinkLocked(&self.file_sink, .FILE);
                self.closeFileLocked();
                self.suspendFileLocked("the day's file sequence is exhausted at 999999", self.config.save_path);
                return;
            }

            self.drainSinkLocked(&self.file_sink, .FILE);
            self.closeFileLocked();
            self.file_seq += 1;
            self.line_count = 0;
            self.openFileLocked(date);
        }
    }

    /// The tail every log method shares: gate, buffer, and let the flush thread do the writing.
    ///
    /// Note:
    /// - The level gates are read before the lock by each caller, so a logger with both
    ///   destinations disabled never reaches this and costs nothing but the comparison.
    /// - An ERROR is written out before this returns. Everything else rides the flush thread's
    ///   next pass, so a crash cannot swallow the record that explains it.
    fn emit(self: *Self, level: Level, date: *const [10]u8, line: []const u8) void {
        self.spinLock();
        defer self.spinUnlock();

        self.ensureFlusherLocked();

        if (self.consoleActive(level)) self.appendLocked(&self.console_sink, .CONSOLE, line);

        if (self.fileActive(level)) {
            self.ensureFileLocked(date);
            if (!self.file_suspended) {
                self.appendLocked(&self.file_sink, .FILE, line);
                self.line_count += 1;
            }
        }

        if (level == .ERROR) self.drainLocked();
    }

    fn consoleActive(self: *const Self, level: Level) bool {
        return switch (self.config.console) {
            .OFF => false,
            .DEBUG_ONLY => blk: {
                if (comptime if (ZIG_SEMVER.MINOR == 16) builtin.mode != .Debug else builtin.mode != .debug) break :blk false;
                break :blk @intFromEnum(level) >= @intFromEnum(self.config.console_min_level);
            },
            .ALWAYS => @intFromEnum(level) >= @intFromEnum(self.config.console_min_level),
        };
    }

    fn fileActive(self: *const Self, level: Level) bool {
        return self.config.save_path.len > 0 and
            !self.file_suspended and
            @intFromEnum(level) >= @intFromEnum(self.config.save_min_level);
    }

    // --------------------------------------------------------- //

    /// Log an HTTP access entry.
    ///
    /// Note:
    /// - Level comes from the status: 5xx is ERROR, 4xx is WARN, 2xx and 3xx are INFO, anything
    ///   below 200 is DEBUG. All four are reachable, so a 1xx record needs a lowered threshold.
    /// - The record carries a [component:access] tag, so access lines can be filtered out of a
    ///   mixed file and two engines sharing one file stay distinguishable.
    /// - Absent client_ip, ua, or origin are passed as empty strings and render as "-".
    ///
    /// Param:
    /// component - []const u8 (the engine, e.g. "http", "http1", "http2", "http3")
    /// client_ip - []const u8 (the real client, see utils/peer_addr.zig for how engines resolve it)
    ///
    /// Return:
    /// - void
    pub fn access(
        self: *Self,
        component: []const u8,
        method: []const u8,
        path: []const u8,
        status: u16,
        bytes: usize,
        client_ip: []const u8,
        ua: []const u8,
        origin: []const u8,
    ) void {
        const level = statusLevel(status);
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();
        const client_ip_out = if (client_ip.len > 0) client_ip else "-";
        const ua_out = if (ua.len > 0) ua else "-";
        const origin_out = if (origin.len > 0) origin else "-";

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [{s}:access] {s} {s} {d} {d} \"{s}\" \"{s}\" \"{s}\"", .{ &timestamp.date, &timestamp.time, levelLabel(level), component, method, path, status, bytes, client_ip_out, ua_out, origin_out });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a TCP connection lifecycle event.
    /// peer: "1.2.3.4:54321" or "-" when unavailable.
    /// dur_ms: connection duration in milliseconds.
    /// err: null for a clean close. Non-null error tag string (e.g. "read_fail") otherwise.
    /// Level: INFO on clean close, WARN on error.
    pub fn conn(
        self: *Self,
        peer: []const u8,
        dur_ms: u64,
        err: ?[]const u8,
    ) void {
        const level: Level = if (err == null) .INFO else .WARN;
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();
        const err_out = err orelse "-";

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [tcp:conn] {s} dur={d}ms {s}", .{ &timestamp.date, &timestamp.time, levelLabel(level), peer, dur_ms, err_out });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a UDP datagram event.
    /// dir: RECV or SEND.
    /// peer: "1.2.3.4:5000".
    /// size: datagram size in bytes.
    /// err: null on success. Non-null error tag string otherwise.
    /// Level: INFO on success, WARN on error.
    pub fn packet(
        self: *Self,
        dir: Dir,
        peer: []const u8,
        size: usize,
        err: ?[]const u8,
    ) void {
        const level: Level = if (err == null) .INFO else .WARN;
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();
        const dir_out: []const u8 = if (dir == .RECV) "recv" else "send";
        const err_out = err orelse "-";

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [udp:pkt] {s} {s} size={d} {s}", .{ &timestamp.date, &timestamp.time, levelLabel(level), dir_out, peer, size, err_out });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a UDS frame event.
    /// dir: RECV or SEND.
    /// sock_path: socket filesystem path (e.g. "/var/run/zix.sock").
    /// size: frame payload size in bytes.
    /// err: null on success. Non-null error tag string otherwise.
    /// Level: INFO on success, WARN on error.
    pub fn frame(
        self: *Self,
        dir: Dir,
        sock_path: []const u8,
        size: usize,
        err: ?[]const u8,
    ) void {
        const level: Level = if (err == null) .INFO else .WARN;
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();
        const dir_out: []const u8 = if (dir == .RECV) "recv" else "send";
        const err_out = err orelse "-";

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [uds:frame] {s} {s} size={d} {s}", .{ &timestamp.date, &timestamp.time, levelLabel(level), dir_out, sock_path, size, err_out });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a FIX session message event. Always INFO level.
    /// msg_type: tag 35 value (e.g. "A", "D", "5", "0").
    /// sender: SenderCompID from the message (tag 49).
    /// target: our TargetCompID (tag 56).
    /// seq: MsgSeqNum from the message (tag 34).
    /// state: label (e.g. "Logon", "Logout", "Heartbeat", "msg").
    pub fn session(
        self: *Self,
        msg_type: []const u8,
        sender: []const u8,
        target: []const u8,
        seq: u64,
        state: []const u8,
    ) void {
        const level: Level = .INFO;
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [fix:sess] 35={s} sender={s} target={s} seq={d} {s}", .{ &timestamp.date, &timestamp.time, levelLabel(level), msg_type, sender, target, seq, state });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a gRPC RPC event. Called once per dispatched stream.
    /// peer: "1.2.3.4:54321" or "-" when unavailable.
    /// path: full gRPC path (e.g. "/location.Location/SendLocationAndSave").
    /// grpc_status: numeric status code. 0=OK -> INFO, non-zero -> WARN.
    /// recv_bytes: total request body bytes buffered from all DATA frames.
    /// sent_bytes: total response body bytes sent by the handler.
    /// dur_ms: handler wall-clock duration in milliseconds.
    pub fn rpc(
        self: *Self,
        peer: []const u8,
        path: []const u8,
        grpc_status: u8,
        recv_bytes: usize,
        sent_bytes: usize,
        dur_ms: u64,
    ) void {
        const level: Level = if (grpc_status == 0) .INFO else .WARN;
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [grpc:rpc] {s} {s} status={d} recv={d} sent={d} dur={d}ms", .{ &timestamp.date, &timestamp.time, levelLabel(level), peer, path, grpc_status, recv_bytes, sent_bytes, dur_ms });

        self.emit(level, &timestamp.date, line);
    }

    /// Log a system event.
    /// component identifies the source (e.g. "http", "udp", "payment").
    /// fmt and args follow std.fmt.bufPrint conventions.
    pub fn system(
        self: *Self,
        level: Level,
        component: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (!self.consoleActive(level) and !self.fileActive(level)) return;

        const timestamp = getTimestamp();

        var msg_buf: [MSG_BUF_SIZE]u8 = undefined;
        const msg = formatRecord(&msg_buf, fmt, args);

        var line_buf: [LINE_BUF_SIZE]u8 = undefined;
        const line = formatRecord(&line_buf, "{s} {s} {s}  [{s}] {s}", .{ &timestamp.date, &timestamp.time, levelLabel(level), component, msg });

        self.emit(level, &timestamp.date, line);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix logger: Logger init and deinit, no file" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{});
    defer logger.deinit();
}

test "zix logger: Logger.Config write_buf_size default" {
    const cfg = Logger.Config{};
    try std.testing.expectEqual(@as(usize, 64 * 1024), cfg.write_buf_size);
}

test "zix logger: Logger system call below min_level is silent" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{ .save_min_level = .ERROR });
    defer logger.deinit();
    logger.system(.DEBUG, "test", "should not panic", .{});
    logger.system(.INFO, "test", "should not panic", .{});
    logger.system(.WARN, "test", "should not panic", .{});
}

test "zix logger: Logger access call below min_level is silent" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{ .save_min_level = .ERROR });
    defer logger.deinit();
    logger.access("http", "GET", "/", 200, 0, "", "", "");
}

test "zix logger: Logger access does not panic with empty client_ip" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{});
    defer logger.deinit();
    logger.access("http", "GET", "/", 200, 0, "", "", "");
}

test "zix logger: Logger access does not panic with non-empty client_ip" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{});
    defer logger.deinit();
    logger.access("http", "GET", "/", 200, 0, "10.0.0.1", "Mozilla/5.0", "https://example.com");
}

test "zix logger: Logger rpc call below min_level is silent" {
    const allocator = std.testing.allocator;
    var logger = try Logger.init(allocator, .{ .save_min_level = .ERROR });
    defer logger.deinit();
    logger.rpc("-", "/svc.Svc/Method", 0, 0, 0, 1);
}

test "zix logger: formatRecord returns the whole record when it fits" {
    var buf: [64]u8 = undefined;
    const line = formatRecord(&buf, "{s}:{d}", .{ "port", 8080 });

    try std.testing.expectEqualStrings("port:8080", line);
}

test "zix logger: formatRecord keeps a marked short line instead of dropping the record" {
    var buf: [32]u8 = undefined;
    const line = formatRecord(&buf, "{s}", .{"0123456789012345678901234567890123456789"});

    // The record survives: what fits, then the mark, and nothing longer than the buffer.
    try std.testing.expect(line.len <= buf.len);
    try std.testing.expect(std.mem.endsWith(u8, line, TRUNCATION_MARK));
    try std.testing.expect(std.mem.startsWith(u8, line, "0123456789"));
}

test "zix logger: formatRecord marks a record that only just overflows" {
    var buf: [24]u8 = undefined;
    const room = buf.len - TRUNCATION_MARK.len;

    const exact = formatRecord(&buf, "{s}", .{"abcdefghi"});
    try std.testing.expectEqualStrings("abcdefghi", exact);
    try std.testing.expect(exact.len <= room);

    var over_buf: [24]u8 = undefined;
    const over = formatRecord(&over_buf, "{s}", .{"abcdefghijklmnop"});
    try std.testing.expect(std.mem.endsWith(u8, over, TRUNCATION_MARK));
}

test "zix logger: system writes an oversize message as a marked line, not as nothing" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    var long_buf: [MSG_BUF_SIZE * 2]u8 = undefined;
    @memset(&long_buf, 'x');

    logger.system(.ERROR, "test", "{s}", .{&long_buf});
    logger.flush();

    const written = try readLoggedLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(written);

    try std.testing.expect(std.mem.indexOf(u8, written, "ERROR") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, TRUNCATION_MARK) != null);
}

test "zix logger: a save_path that cannot be opened suspends the file sink and keeps the console" {
    // No such directory, so the open fails and the logger has to say so rather than retry forever.
    // init reports it straight away, which is why the capture has to be named in the config: there
    // is no moment between the open and the report for a test to step in.
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var capture = try tmp.dir.createFile(std.testing.io, CONSOLE_CAPTURE, .{});
    defer capture.close(std.testing.io);

    var logger = try Logger.init(std.testing.allocator, .{
        .console = .OFF,
        .console_fd = capture.handle,
        .save_path = ".zig-cache/tmp/zix-logger-absent-root",
        .save_min_level = .DEBUG,
    });
    defer logger.deinit();

    logger.system(.ERROR, "test", "first record", .{});

    try std.testing.expect(logger.file_suspended);
    try std.testing.expect(!logger.fileActive(.ERROR));

    // The second record must not try again: the suspend is what makes the report land once.
    logger.system(.ERROR, "test", "second record", .{});
    try std.testing.expect(logger.file_suspended);

    const content = try readConsoleCapture(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(content);

    // One report, naming the cause and the path, no matter how many records followed it.
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    const report = lines.next() orelse return error.ZixMissingSuspendReport;

    // The cause is whatever the platform names its own open failure: NOENT comes from mkdirat on
    // POSIX, ZixLogOpenFailed from the ntdll path on Windows.
    const cause = if (comptime builtin.os.tag == .windows) "ZixLogOpenFailed" else "NOENT";

    try std.testing.expect(std.mem.indexOf(u8, report, cause) != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "zix-logger-absent-root") != null);
    try std.testing.expectEqual(@as(?[]const u8, null), lines.next());
}

test "zix logger: rawWrite reports the errno instead of dropping the write" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, test skipped", .{});
        return;
    }

    // A descriptor that was never opened: the write cannot succeed and the caller must learn why.
    const errno = rawWrite(@as(std.posix.fd_t, 4096), "line\n");

    try std.testing.expect(errno != null);
    try std.testing.expectEqual(std.posix.E.BADF, errno.?);
}

test "zix logger: rawWrite answers null when the whole slice went out" {
    if (comptime builtin.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, test skipped", .{});
        return;
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [96]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/raw.txt", .{tmp.sub_path}) catch unreachable;

    const fd = try std.posix.openat(
        @as(std.posix.fd_t, std.posix.AT.FDCWD),
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    );
    defer _ = std.posix.system.close(fd);

    try std.testing.expectEqual(@as(?std.posix.E, null), rawWrite(fd, "one line\n"));
}

test "zix logger: init creates the day file before any record is logged" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    // Nothing logged at all: the file still has to be there, so a quiet engine cannot be mistaken
    // for a logger that failed to open anything.
    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    std.log.info(".FILE: the day file exists at init with {d} bytes in it", .{content.len});

    try std.testing.expectEqual(@as(usize, 0), content.len);
    try std.testing.expect(!logger.file_suspended);
}

test "zix logger: the write buffer batches many records into far fewer writes" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const RECORDS = 5_000;
    for (0..RECORDS) |seq| logger.system(.INFO, "batch", "record {d} of the run", .{seq});
    logger.flush();

    const counts = logger.fileBatchCounts();
    std.log.info(".BATCH: {d} records left in {d} writes", .{ counts.lines, counts.writes });

    try std.testing.expectEqual(@as(u64, RECORDS), counts.lines);

    // The old shape wrote once per record. Ten to one is far below what the buffer actually
    // achieves and still fails loudly if the unconditional flush ever comes back.
    try std.testing.expect(counts.writes * 10 < counts.lines);
}

test "zix logger: records reach the file in the order they were logged" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const RECORDS = 500;
    for (0..RECORDS) |seq| logger.system(.INFO, "order", "seq={d}", .{seq});
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    var expected: usize = 0;
    while (lines.next()) |line| : (expected += 1) {
        var wanted_buf: [32]u8 = undefined;
        const wanted = try std.fmt.bufPrint(&wanted_buf, "seq={d}", .{expected});

        try std.testing.expect(std.mem.endsWith(u8, line, wanted));
    }

    std.log.info(".ORDER: {d} records read back in order", .{expected});
    try std.testing.expectEqual(@as(usize, RECORDS), expected);
}

const Racer = struct {
    logger: *Logger,
    id: usize,

    const LINES_PER_THREAD = 500;

    fn run(self: Racer) void {
        for (0..LINES_PER_THREAD) |seq| {
            self.logger.system(.INFO, "race", "thread={d} seq={d}", .{ self.id, seq });
        }
    }
};

test "zix logger: eight threads logging at once lose no record and tear none" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const THREADS = 8;
    var threads: [THREADS]std.Thread = undefined;
    for (&threads, 0..) |*thread, id| {
        thread.* = try std.Thread.spawn(.{}, Racer.run, .{Racer{ .logger = &logger, .id = id }});
    }
    for (&threads) |*thread| thread.join();

    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    const unseen_row: [Racer.LINES_PER_THREAD]bool = @splat(false);
    var seen: [THREADS][Racer.LINES_PER_THREAD]bool = @splat(unseen_row);
    var counted: usize = 0;

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        // Every record ends "thread=<id> seq=<n>". A torn line cannot parse, which is the check.
        const marker = std.mem.indexOf(u8, line, "thread=") orelse return error.ZixTornRecord;
        const tail = line[marker + "thread=".len ..];

        var parts = std.mem.tokenizeAny(u8, tail, " =");
        const id = try std.fmt.parseInt(usize, parts.next() orelse return error.ZixTornRecord, 10);
        _ = parts.next() orelse return error.ZixTornRecord;
        const seq = try std.fmt.parseInt(usize, parts.next() orelse return error.ZixTornRecord, 10);

        try std.testing.expect(!seen[id][seq]);
        seen[id][seq] = true;
        counted += 1;
    }

    // Stalls are expected here and are not a failure: eight saturating threads can fill both
    // buffers faster than the disk drains them. The contract is that a stall delays a record and
    // never drops one, which is what the count above proves.
    std.log.info(".RACE: {d} threads wrote {d} records, none lost, none torn, {d} stalls", .{
        THREADS,
        counted,
        logger.stallCount(),
    });

    try std.testing.expectEqual(@as(usize, THREADS * Racer.LINES_PER_THREAD), counted);
}

test "zix logger: deinit writes out what was still buffered" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    {
        var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
        defer logger.deinit();

        // No flush on purpose: deinit is the only thing that can put these on the descriptor.
        for (0..20) |seq| logger.system(.INFO, "closing", "record {d}", .{seq});
    }

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    var counted: usize = 0;
    while (lines.next()) |_| counted += 1;

    std.log.info(".DEINIT: {d} buffered records reached the file on deinit", .{counted});
    try std.testing.expectEqual(@as(usize, 20), counted);
}

test "zix logger: an ERROR record is on the descriptor without waiting for a flush" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    logger.system(.INFO, "quiet", "this one may sit in the buffer", .{});
    logger.system(.ERROR, "loud", "this one cannot wait", .{});

    // Deliberately no flush call: an ERROR has to survive a crash that happens right here.
    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    std.log.info(".ERROR: the record reached the file with no flush call", .{});
    try std.testing.expect(std.mem.indexOf(u8, content, "this one cannot wait") != null);

    // The INFO ahead of it rides along, because the drain cannot write out of order.
    try std.testing.expect(std.mem.indexOf(u8, content, "this one may sit in the buffer") != null);
}

test "zix logger: flush puts everything logged so far on the descriptor" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    for (0..64) |seq| logger.system(.INFO, "contract", "record {d}", .{seq});
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    for (0..64) |seq| {
        var wanted_buf: [32]u8 = undefined;
        const wanted = try std.fmt.bufPrint(&wanted_buf, "record {d}\n", .{seq});

        try std.testing.expect(std.mem.indexOf(u8, content, wanted) != null);
    }
}

test "zix logger: rotation still splits files while the flush thread is running" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{
        .console = .OFF,
        .save_path = root,
        .save_min_level = .DEBUG,
        .max_lines = 10,
    });
    defer logger.deinit();

    for (0..25) |seq| logger.system(.INFO, "rotate", "record {d}", .{seq});
    logger.flush();

    var total: usize = 0;
    for (0..3) |seq| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "log-{d:0>6}.log", .{seq});

        const content = try readDayFile(tmp.dir, std.testing.allocator, name);
        defer std.testing.allocator.free(content);

        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            try std.testing.expect(std.mem.indexOf(u8, line, "[rotate]") != null);
            total += 1;
        }
    }

    std.log.info(".ROTATE: 25 records split across 3 files with the flush thread running", .{});
    try std.testing.expectEqual(@as(usize, 25), total);
}

test "zix logger: a narrow write buffer still loses no record" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    // Below one record, so init has to widen it. A buffer narrower than a record could never hold
    // one, and the append loop would have nothing to swap to.
    var logger = try Logger.init(std.testing.allocator, .{
        .console = .OFF,
        .save_path = root,
        .save_min_level = .DEBUG,
        .write_buf_size = 64,
    });
    defer logger.deinit();

    const RECORDS = 2_000;
    for (0..RECORDS) |seq| logger.system(.INFO, "narrow", "record {d}", .{seq});
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    var counted: usize = 0;
    while (lines.next()) |_| counted += 1;

    std.log.info(".NARROW: {d} records survived a {d} byte buffer request, {d} stalls", .{
        counted,
        @as(usize, 64),
        logger.stallCount(),
    });

    try std.testing.expectEqual(@as(usize, RECORDS), counted);
    try std.testing.expect(logger.file_sink.capacity() >= LINE_BUF_SIZE + 1);
}

/// Bytes of fixed-width prefix on every record: "YYYY-MM-DD HH:MM:SS.mmm LEVEL  ".
const RECORD_PREFIX_LEN: usize = 10 + 1 + 12 + 1 + 5 + 2;

test "zix logger: an access record renders its tag, request, and quoted fields exactly" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    logger.access("http1", "GET", "/api/v1/items?page=2", 200, 4096, "203.0.113.7", "curl/8.5.0", "https://example.com");
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    const line = std.mem.trimEnd(u8, content, "\n");
    try std.testing.expect(line.len > RECORD_PREFIX_LEN);

    std.log.info(".ACCESS: {s}", .{line});

    try std.testing.expectEqualStrings("INFO ", line[24..29]);
    try std.testing.expectEqualStrings(
        "[http1:access] GET /api/v1/items?page=2 200 4096 \"203.0.113.7\" \"curl/8.5.0\" \"https://example.com\"",
        line[RECORD_PREFIX_LEN..],
    );
}

test "zix logger: an access record renders absent fields as a dash" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    logger.access("http", "HEAD", "/", 204, 0, "", "", "");
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    const line = std.mem.trimEnd(u8, content, "\n");
    try std.testing.expectEqualStrings(
        "[http:access] HEAD / 204 0 \"-\" \"-\" \"-\"",
        line[RECORD_PREFIX_LEN..],
    );
}

test "zix logger: every Level is reachable through an access record" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    // DEBUG threshold, because a 1xx record files at DEBUG and would be gated out at the default.
    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const cases = [_]struct { status: u16, label: []const u8 }{
        .{ .status = 100, .label = "DEBUG" },
        .{ .status = 200, .label = "INFO " },
        .{ .status = 304, .label = "INFO " },
        .{ .status = 404, .label = "WARN " },
        .{ .status = 502, .label = "ERROR" },
    };
    for (cases) |case| logger.access("http2", "GET", "/", case.status, 0, "", "", "");
    logger.flush();

    const content = try readDayFile(tmp.dir, std.testing.allocator, "log-000000.log");
    defer std.testing.allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    for (cases) |case| {
        const line = lines.next() orelse return error.ZixMissingAccessRecord;

        try std.testing.expectEqualStrings(case.label, line[24..29]);
        try std.testing.expect(std.mem.indexOf(u8, line, "[http2:access]") != null);
    }

    std.log.info(".ACCESS: all four levels reachable, 1xx files at DEBUG", .{});
    try std.testing.expectEqual(@as(?[]const u8, null), lines.next());
}

test "zix logger: an access record reaches the console under ALWAYS at every level it passes" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // The capture file is opened before the logger and closed after it, so the drain deinit runs
    // still has somewhere to go.
    var capture = try tmp.dir.createFile(std.testing.io, CONSOLE_CAPTURE, .{});
    defer capture.close(std.testing.io);

    var logger = try Logger.init(std.testing.allocator, .{
        .console = .ALWAYS,
        .console_min_level = .DEBUG,
        .console_fd = capture.handle,
    });
    defer logger.deinit();

    logger.access("http3", "GET", "/", 100, 0, "", "", "");
    logger.access("http3", "GET", "/", 200, 0, "", "", "");
    logger.access("http3", "GET", "/", 404, 0, "", "", "");
    logger.access("http3", "GET", "/", 500, 0, "", "", "");
    logger.flush();

    try std.testing.expectEqual(@as(u64, 4), logger.console_sink.lines);
    try std.testing.expectEqual(@as(u64, 0), logger.file_sink.lines);

    const content = try readConsoleCapture(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(content);

    // The bytes, not only the counter: each record has to arrive rendered, under the level its
    // status put it at.
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    for ([_][]const u8{ "DEBUG", "INFO ", "WARN ", "ERROR" }) |label| {
        const line = lines.next() orelse return error.ZixMissingAccessRecord;

        try std.testing.expectEqualStrings(label, line[24..29]);
        try std.testing.expect(std.mem.indexOf(u8, line, "[http3:access]") != null);
    }

    try std.testing.expectEqual(@as(?[]const u8, null), lines.next());
}

test "zix logger: the console threshold gates an access record like any other" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var capture = try tmp.dir.createFile(std.testing.io, CONSOLE_CAPTURE, .{});
    defer capture.close(std.testing.io);

    var logger = try Logger.init(std.testing.allocator, .{
        .console = .ALWAYS,
        .console_min_level = .WARN,
        .console_fd = capture.handle,
    });
    defer logger.deinit();

    // Below the threshold, so neither reaches the console.
    logger.access("http", "GET", "/", 100, 0, "", "", "");
    logger.access("http", "GET", "/", 200, 0, "", "", "");
    try std.testing.expectEqual(@as(u64, 0), logger.console_sink.lines);

    // At and above it, so both do.
    logger.access("http", "GET", "/", 404, 0, "", "", "");
    logger.access("http", "GET", "/", 500, 0, "", "", "");
    try std.testing.expectEqual(@as(u64, 2), logger.console_sink.lines);

    logger.flush();

    const content = try readConsoleCapture(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    try std.testing.expectEqualStrings("WARN ", (lines.next() orelse return error.ZixMissingAccessRecord)[24..29]);
    try std.testing.expectEqualStrings("ERROR", (lines.next() orelse return error.ZixMissingAccessRecord)[24..29]);
    try std.testing.expectEqual(@as(?[]const u8, null), lines.next());
}

test "zix logger: DEBUG_ONLY delivers an access record in a debug build and nothing otherwise" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var capture = try tmp.dir.createFile(std.testing.io, CONSOLE_CAPTURE, .{});
    defer capture.close(std.testing.io);

    var logger = try Logger.init(std.testing.allocator, .{
        .console = .DEBUG_ONLY,
        .console_min_level = .DEBUG,
        .console_fd = capture.handle,
    });
    defer logger.deinit();

    logger.access("http", "GET", "/", 200, 0, "", "", "");
    logger.flush();

    const is_debug = comptime if (ZIG_SEMVER.MINOR == 16) builtin.mode == .Debug else builtin.mode == .debug;
    const expected: u64 = if (is_debug) 1 else 0;

    std.log.info(".ACCESS: DEBUG_ONLY delivered {d} record in this build mode", .{logger.console_sink.lines});
    try std.testing.expectEqual(expected, logger.console_sink.lines);

    const content = try readConsoleCapture(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(content);

    // A build mode that gates the record leaves the capture empty, which is the same statement as
    // the counter making no other destination carry it.
    try std.testing.expectEqual(expected, @as(u64, @intFromBool(content.len > 0)));
}

test "zix logger: the console descriptor defaults to stderr and follows the config when it is set" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var capture = try tmp.dir.createFile(std.testing.io, CONSOLE_CAPTURE, .{});
    defer capture.close(std.testing.io);

    const unset = Logger{ .config = .{}, .allocator = std.testing.allocator };
    const named = Logger{ .config = .{ .console_fd = capture.handle }, .allocator = std.testing.allocator };

    try std.testing.expectEqual(stderrFd(), unset.fdFor(.CONSOLE));
    try std.testing.expectEqual(capture.handle, named.fdFor(.CONSOLE));

    // Naming a console descriptor says nothing about the file sink, which keeps its own.
    try std.testing.expectEqual(NO_FILE_FD, named.fdFor(.FILE));
}

test "zix logger: a logger with no destination writes nothing and starts no flush thread" {
    var quiet = Logger{ .config = .{}, .allocator = std.testing.allocator };
    defer quiet.deinit();

    quiet.system(.ERROR, "test", "nowhere to go", .{});
    quiet.access("http1", "GET", "/", 200, 0, "", "", "");

    try std.testing.expect(!quiet.flusher.running());
    try std.testing.expectEqual(@as(u64, 0), quiet.console_sink.lines);
    try std.testing.expectEqual(@as(u64, 0), quiet.file_sink.lines);
}

/// Name of the file a test points config.console_fd at, so nothing reaches the terminal.
const CONSOLE_CAPTURE = "console-capture.log";

/// Read back everything the console sink wrote into the capture file. Empty content is a valid
/// answer: it is what a gated record leaves behind.
fn readConsoleCapture(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
    return root.readFileAlloc(std.testing.io, CONSOLE_CAPTURE, allocator, .limited(64 * 1024));
}

/// Read one named file out of the single day directory under root. Empty content is a valid answer.
fn readDayFile(root: std.Io.Dir, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var days = root.iterate();

    while (try days.next(std.testing.io)) |entry| {
        if (entry.kind != .directory) continue;

        var day = try root.openDir(std.testing.io, entry.name, .{});
        defer day.close(std.testing.io);

        return day.readFileAlloc(std.testing.io, name, allocator, .limited(8 * 1024 * 1024)) catch continue;
    }

    return error.ZixNoLogFile;
}

/// Read back the one log file written under a temp root, for the tests above.
fn readLoggedLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
    var days = root.iterate();

    while (try days.next(std.testing.io)) |entry| {
        if (entry.kind != .directory) continue;

        var day = try root.openDir(std.testing.io, entry.name, .{});
        defer day.close(std.testing.io);

        const bytes = day.readFileAlloc(std.testing.io, "log-000000.log", allocator, .limited(64 * 1024)) catch continue;
        if (bytes.len > 0) return bytes;

        allocator.free(bytes);
    }

    return error.ZixNoLogLine;
}
