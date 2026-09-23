//! zixer control plane contract: socket location and the one-line wire format

const std = @import("std");

/// Control socket file name under the root dir.
pub const SOCKET_FILE: []const u8 = "control.sock";

/// Longest request or reply line on the control socket, newline included.
pub const MAX_LINE: usize = 512;

/// Longest site name accepted on the wire, so every reply fits MAX_LINE.
pub const MAX_NAME: usize = 128;

/// Control verbs. On the wire they travel lowercase (`start <site.cfg>`).
pub const Verb = enum {
    START,
    STOP,
    RESTART,
    PING,
    SHUTDOWN,
};

/// One parsed request line. name stays empty for ping and shutdown.
pub const Request = struct {
    verb: Verb,
    name: []const u8 = "",
};

/// One parsed reply line.
pub const Reply = struct {
    ok: bool,
    text: []const u8,
};

pub const PathError = error{ ZixerDirectoryUnavailable, OutOfMemory };

/// Absolute path of the control socket under the root dir.
///
/// Note:
/// - Windows AF_UNIX rejects a relative path at bind time, so a relative root
///   (from --dir) is prefixed with the working directory. Client and daemon
///   run from the same working directory, so both derive the same string.
///
/// Param:
/// io - std.Io
/// arena - std.mem.Allocator (owns the returned path)
/// root_path - []const u8 (resolved zixer root dir)
///
/// Return:
/// - []const u8 absolute socket path
/// - error.ZixerDirectoryUnavailable when the working directory cannot be read
pub fn socketPath(io: std.Io, arena: std.mem.Allocator, root_path: []const u8) PathError![]const u8 {
    if (std.fs.path.isAbsolute(root_path)) {
        return std.fs.path.join(arena, &.{ root_path, SOCKET_FILE });
    }

    var cwd_buf: [512]u8 = undefined;
    const cwd_len = std.process.currentPath(io, &cwd_buf) catch return error.ZixerDirectoryUnavailable;

    return std.fs.path.join(arena, &.{ cwd_buf[0..cwd_len], root_path, SOCKET_FILE });
}

/// True when the platform accepts path as a unix socket address.
/// POSIX caps sun_path at 108 bytes, a longer root dir cannot host one.
pub fn fitsSocket(path: []const u8) bool {
    return path.len <= std.Io.net.UnixAddress.max_len;
}

/// Parse one request line, null when it is not a valid request.
///
/// Note:
/// - Site verbs require a name, ping and shutdown reject one.
pub fn parseRequest(line: []const u8) ?Request {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;

    var verb_word = trimmed;
    var name: []const u8 = "";
    if (std.mem.indexOfScalar(u8, trimmed, ' ')) |space| {
        verb_word = trimmed[0..space];
        name = std.mem.trim(u8, trimmed[space + 1 ..], " \t");
    }

    const verb = verbFromWire(verb_word) orelse return null;

    const wants_name = switch (verb) {
        .START, .STOP, .RESTART => true,
        .PING, .SHUTDOWN => false,
    };
    if (wants_name and name.len == 0) return null;
    if (!wants_name and name.len != 0) return null;

    return .{ .verb = verb, .name = name };
}

/// Parse one reply line, null when it carries neither prefix.
pub fn parseReply(line: []const u8) ?Reply {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");

    if (std.mem.startsWith(u8, trimmed, "ok: ")) return .{ .ok = true, .text = trimmed["ok: ".len..] };
    if (std.mem.startsWith(u8, trimmed, "error: ")) return .{ .ok = false, .text = trimmed["error: ".len..] };

    return null;
}

/// Wire spelling of a verb, for request lines the cli builds.
pub fn verbWire(verb: Verb) []const u8 {
    return switch (verb) {
        .START => "start",
        .STOP => "stop",
        .RESTART => "restart",
        .PING => "ping",
        .SHUTDOWN => "shutdown",
    };
}

/// Site name with its .cfg suffix, matching the file-name identity.
pub fn normalizeSiteName(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (std.mem.endsWith(u8, name, ".cfg")) return name;

    return std.fmt.allocPrint(arena, "{s}.cfg", .{name});
}

/// True when name is a bare `<stem>.cfg` file name the daemon may resolve
/// under sites_dir. Anything with path parts could escape that directory.
pub fn siteNameSafe(name: []const u8) bool {
    if (name.len <= ".cfg".len or name.len > MAX_NAME) return false;
    if (!std.mem.endsWith(u8, name, ".cfg")) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;

    return true;
}

fn verbFromWire(word: []const u8) ?Verb {
    if (std.mem.eql(u8, word, "start")) return .START;
    if (std.mem.eql(u8, word, "stop")) return .STOP;
    if (std.mem.eql(u8, word, "restart")) return .RESTART;
    if (std.mem.eql(u8, word, "ping")) return .PING;
    if (std.mem.eql(u8, word, "shutdown")) return .SHUTDOWN;

    return null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: control request, site verbs parse with their name" {
    const started = parseRequest("start service_api_h1.cfg\n").?;
    try std.testing.expectEqual(Verb.START, started.verb);
    try std.testing.expectEqualStrings("service_api_h1.cfg", started.name);

    const stopped = parseRequest("stop a.cfg").?;
    try std.testing.expectEqual(Verb.STOP, stopped.verb);

    const restarted = parseRequest("restart  a.cfg \r\n").?;
    try std.testing.expectEqual(Verb.RESTART, restarted.verb);
    try std.testing.expectEqualStrings("a.cfg", restarted.name);
}

test "zix zixer: control request, ping and shutdown carry no name" {
    try std.testing.expectEqual(Verb.PING, parseRequest("ping\n").?.verb);
    try std.testing.expectEqual(Verb.SHUTDOWN, parseRequest("shutdown").?.verb);

    try std.testing.expectEqual(@as(?Request, null), parseRequest("ping extra"));
    try std.testing.expectEqual(@as(?Request, null), parseRequest("shutdown now"));
}

test "zix zixer: control request, missing name and unknown verb are rejected" {
    try std.testing.expectEqual(@as(?Request, null), parseRequest("start"));
    try std.testing.expectEqual(@as(?Request, null), parseRequest("start "));
    try std.testing.expectEqual(@as(?Request, null), parseRequest("reload a.cfg"));
    try std.testing.expectEqual(@as(?Request, null), parseRequest(""));
    try std.testing.expectEqual(@as(?Request, null), parseRequest("  \r\n"));
}

test "zix zixer: control reply, ok and error prefixes parse, others reject" {
    const good = parseReply("ok: a.cfg started on 0.0.0.0:8080\n").?;
    try std.testing.expect(good.ok);
    try std.testing.expectEqualStrings("a.cfg started on 0.0.0.0:8080", good.text);

    const bad = parseReply("error: a.cfg is not started").?;
    try std.testing.expect(!bad.ok);
    try std.testing.expectEqualStrings("a.cfg is not started", bad.text);

    try std.testing.expectEqual(@as(?Reply, null), parseReply("started"));
    try std.testing.expectEqual(@as(?Reply, null), parseReply(""));
}

test "zix zixer: control verbWire, round trips through parseRequest" {
    var line_buf: [64]u8 = undefined;

    const site_verbs = [_]Verb{ .START, .STOP, .RESTART };
    for (site_verbs) |verb| {
        const line = try std.fmt.bufPrint(&line_buf, "{s} a.cfg", .{verbWire(verb)});
        try std.testing.expectEqual(verb, parseRequest(line).?.verb);
    }

    const bare_verbs = [_]Verb{ .PING, .SHUTDOWN };
    for (bare_verbs) |verb| {
        try std.testing.expectEqual(verb, parseRequest(verbWire(verb)).?.verb);
    }
}

test "zix zixer: control normalizeSiteName, appends .cfg only when missing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectEqualStrings("a.cfg", try normalizeSiteName(arena.allocator(), "a"));
    try std.testing.expectEqualStrings("a.cfg", try normalizeSiteName(arena.allocator(), "a.cfg"));
}

test "zix zixer: control siteNameSafe, path escapes and bad shapes are rejected" {
    try std.testing.expect(siteNameSafe("service_api_h1.cfg"));

    try std.testing.expect(!siteNameSafe("../evil.cfg"));
    try std.testing.expect(!siteNameSafe("sub/site.cfg"));
    try std.testing.expect(!siteNameSafe("sub\\site.cfg"));
    try std.testing.expect(!siteNameSafe("site"));
    try std.testing.expect(!siteNameSafe(".cfg"));

    var long_name: [MAX_NAME + 6]u8 = @splat('a');
    @memcpy(long_name[long_name.len - ".cfg".len ..], ".cfg");
    try std.testing.expect(!siteNameSafe(&long_name));
}

test "zix zixer: control socketPath, absolute root joins, relative root gets cwd prefix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const separator = if (@import("builtin").os.tag == .windows) "\\" else "/";

    const absolute_root = if (@import("builtin").os.tag == .windows) "C:\\srv\\zixer" else "/srv/zixer";
    const absolute = try socketPath(io, arena.allocator(), absolute_root);
    try std.testing.expect(std.mem.endsWith(u8, absolute, separator ++ SOCKET_FILE));
    try std.testing.expect(std.mem.startsWith(u8, absolute, absolute_root));

    const relative = try socketPath(io, arena.allocator(), "tmp/zixer_root");
    try std.testing.expect(std.fs.path.isAbsolute(relative));
    try std.testing.expect(std.mem.endsWith(u8, relative, separator ++ SOCKET_FILE));
    try std.testing.expect(std.mem.indexOf(u8, relative, "zixer_root") != null);
}

test "zix zixer: control fitsSocket, short passes and past-limit fails" {
    try std.testing.expect(fitsSocket("/tmp/zixer/control.sock"));

    var long_path: [std.Io.net.UnixAddress.max_len + 1]u8 = @splat('a');
    long_path[0] = '/';
    try std.testing.expect(!fitsSocket(&long_path));
}
