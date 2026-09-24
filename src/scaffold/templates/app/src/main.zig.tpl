//! {{name}} — a zurtr application.
//!
//! One process: an HTTP/1.1 origin from the vendored transport, the routes this application declares,
//! and the lifecycle around them. The framework's modules arrive as they are built; what is here is
//! the seam they hang off, wired so that a route is one line and a handler is one function.

const std = @import("std");
const builtin = @import("builtin");
const zurtr = @import("zurtr");
const zix = zurtr.zix;
{{#if live}}const live = zurtr.live;
{{/if}}{{#if data}}const data = zurtr.data;
{{/if}}
/// The name the project was generated with. A constant rather than something read back at runtime: it
/// names the page, this process's own lines, and — where there is one — the database file, and none
/// of those should be able to disagree with the directory a user typed.
const app_name = "{{name}}";

/// Where this process listens. The interface is fixed and the port is not: a supervisor usually
/// decides the port and rarely the interface.
const host = "127.0.0.1";
const default_port: u16 = 8080;
{{#if data}}
/// The database file, relative to the working directory: the engine resolves it where the process was
/// started, so a service and the file it owns move together.
const database_file = "{{name}}.db";
{{/if}}
/// The route table, fixed at compile time. `Router` partitions it by kind — exact matches go into a
/// comptime hash, parameters and prefixes into arrays walked in order — so adding a route costs a line
/// here and nothing at startup.
const routes = [_]zix.Http1.Route{
    .{ .path = "/", .handler = index },
    .{ .path = "/healthz", .handler = health },
{{#if live}}    .{ .path = "/live", .handler = liveSocket },
{{/if}}};

const Router = zix.Http1.Router(&routes);

/// What the origin answers at `/`: the name it was built as, so that hitting the address of a
/// process nobody labelled says which process it is.
fn index(_: *zix.Http1.Request, res: *zix.Http1.Response, _: *zix.Http1.Context) anyerror!void {
    res.setContentType(.TEXT_HTML);

    try res.send("<h1>" ++ app_name ++ "</h1>\n<p>Served by zurtr over the vendored zix transport.</p>\n");
}

/// A machine-readable liveness route, so that a supervisor has something cheaper to poll than a page.
fn health(_: *zix.Http1.Request, res: *zix.Http1.Response, _: *zix.Http1.Context) anyerror!void {
    try res.sendJson("{\"status\":\"ok\"}");
}
{{#if live}}
/// The live channel's endpoint. The upgrade is the handler's whole job: the engine takes the
/// connection over once this returns and drives the frame pump, so nothing here waits for a message.
/// `Sec-WebSocket-Key` is the client's nonce, the handshake's accept hash is derived from it, and a
/// plain GET is therefore answered as the mistake it is rather than left as a silent close.
fn liveSocket(req: *zix.Http1.Request, res: *zix.Http1.Response, ctx: *zix.Http1.Context) anyerror!void {
    const key = req.header("Sec-WebSocket-Key") orelse {
        res.setStatus(.BAD_REQUEST);

        return res.sendText("this endpoint is the live channel: connect with a websocket upgrade\n");
    };

    try zix.Http1.WebSocket.serve(ctx.fd, key, onLiveFrame);
}

/// One text frame from a live client. The session lifecycle — attach, resume, terminate, and the
/// state a view owns — is the live module's next piece rather than this project's, so no state is
/// retained between frames and every message is answered with the full page: the protocol's
/// `resync`, which is always correct because a full render is the same operation as a patch. `rev`
/// stays at 1 for the same reason — with no retained tree, no patch could be relative to anything.
fn onLiveFrame(fd: std.posix.fd_t, opcode: u8, payload: []const u8) void {
    // Ping and close never reach a handler: the pump answers both itself.
    _ = opcode;

    // A frame arrives on a thread the engine owns and with no scratch of its own, so each one gets a
    // short-lived arena. Its growth is bounded by the protocol's own message limits.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const message = live.protocol.decodeClientMsg(arena, payload) catch {
        sendMessage(arena, fd, .{ .err = .{
            .event = null,
            .kind = .internal,
            .fields_json = null,
            .message = "frame is not one of the client messages the protocol defines",
        } }) catch {};

        return;
    };

    switch (message) {
        // `hello` carries the session token and the client's last revision. There is nothing to
        // resume, so the page is the answer.
        .hello => sendPage(arena, fd, "attached"),
        .resync_req => sendPage(arena, fd, "resynced"),
        // An events batch is what a view's `handleEvent` would consume. With no view bound, the page
        // says what arrived — the render path, exercised end to end without a session to keep it in.
        .events => |batch| sendPage(arena, fd, describeEvents(arena, batch.batch) catch "an event arrived"),
        // Nothing is retained, so there is nothing to acknowledge, and the resync that answered the
        // batch already carried a revision the client can use.
        .ack => {},
    }
}

/// What the page says about a batch: how many events arrived and what the last one was called. The
/// name is the client's, so it reaches the page as text — escaped by the tree, and already bounded by
/// the protocol's limit on an event name.
fn describeEvents(arena: std.mem.Allocator, batch: []const live.protocol.Event) ![]const u8 {
    if (batch.len == 0) return "an empty batch arrived";

    const last = batch[batch.len - 1];

    return std.fmt.allocPrint(arena, "{d} event(s) arrived, the last named '{s}'", .{ batch.len, last.name });
}

/// Renders the page for `note` and sends it as the protocol's full-render message.
fn sendPage(arena: std.mem.Allocator, fd: std.posix.fd_t, note: []const u8) void {
    const html = renderPage(arena, note) catch return;

    sendMessage(arena, fd, .{ .resync = .{ .rev = 1, .html = html } }) catch {};
}

/// The page, as a `live.tree`: the same tree a patch addresses by node id, which is what makes the
/// live route a route rather than a second way to write HTML.
fn renderPage(arena: std.mem.Allocator, note: []const u8) ![]u8 {
    var tree = live.tree.Tree.init(arena);
    defer tree.deinit();

    var builder = live.tree.Builder.init(&tree);
    defer builder.deinit();

    try builder.element("main", &.{}, 0);
    try builder.element("h1", &.{}, 0);
    try builder.text(app_name);
    try builder.close();
    try builder.element("p", &.{}, 0);
    try builder.text(note);
    try builder.close();
    try builder.close();

    return tree.writeHtmlAlloc(arena, builder.root());
}

/// Encodes one server message and writes it as a single text frame. The buffer is sized from what the
/// message carries because encoding escapes it — one byte can leave as six, as `\uXXXX` — and the
/// writer is fixed over that buffer, so the frame is built in place and the peer sees one write.
fn sendMessage(arena: std.mem.Allocator, fd: std.posix.fd_t, message: live.protocol.ServerMsg) !void {
    const html_bytes = switch (message) {
        .resync => |resync| resync.html.len,
        else => 0,
    };

    const buffer = try arena.alloc(u8, 128 + html_bytes * 6);
    var writer: std.Io.Writer = .fixed(buffer);
    try live.protocol.encodeServerMsg(&writer, message);

    try zix.Http1.WebSocket.sendFD(fd, .text, writer.buffered());
}

test "the page escapes a note instead of rendering it" {
    // The note is the client's own bytes on the wire — an event name travels this path — so this is
    // where markup has to stop being markup.
    const page = try renderPage(std.testing.allocator, "<script>alert(1)</script>");
    defer std.testing.allocator.free(page);

    try std.testing.expect(std.mem.indexOf(u8, page, "<script>") == null);
    try std.testing.expect(std.mem.indexOf(u8, page, "&lt;script&gt;") != null);
    try std.testing.expect(std.mem.indexOf(u8, page, app_name) != null);
}
{{/if}}{{#if data}}
/// Opens what the process needs and records this start, returning what the file answered.
///
/// Every statement is idempotent, which is what makes restarting onto the same file the normal case
/// rather than a migration event: the schema is created if it is absent, the insert is a new row, and
/// the count is a query — the three things the contract's `Database` does.
fn bootDatabase(db: *data.Database) !BootCount {
    _ = try db.exec(null,
        \\CREATE TABLE IF NOT EXISTS boots (
        \\  id integer PRIMARY KEY,
        \\  zig text NOT NULL
        \\)
    , &.{});

    _ = try db.exec(null, "INSERT INTO boots (zig) VALUES (?)", &.{.{ .text = builtin.zig_version_string }});

    var counted: BootCount = .{};
    try db.query(null, "SELECT id FROM boots", &.{}, .{ .context = &counted, .push = BootCount.push });

    return counted;
}

/// What the boot record says: how many rows the file holds and the highest id among them.
///
/// `push` is written for the one statement that feeds it — `SELECT id FROM boots`, three lines above —
/// so it reads the first column without checking. A sink that had to accept any shape would have to
/// carry the schema it is reading, which is exactly what the contract keeps out of this layer.
const BootCount = struct {
    rows: usize = 0,
    newest_id: i64 = 0,

    fn push(context: *anyopaque, columns: []const data.Value) data.Error!void {
        const self: *BootCount = @ptrCast(@alignCast(context));
        self.rows += 1;
        self.newest_id = @max(self.newest_id, switch (columns[0]) {
            .integer => |n| n,
            else => 0,
        });
    }
};
{{/if}}
pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const port = portFromEnv(init.environ_map) catch {
        try stdout.print("{s}: PORT is not a port number: '{s}'\n", .{
            app_name,
            init.environ_map.get("PORT") orelse "",
        });

        return error.InvalidPort;
    };
{{#if data}}
    // The file tier: one machine, one file, one writer, and the engine is what enforces the writer.
    // The handle belongs to this process rather than to a route — the contract's `Database` is not
    // thread-safe, and handlers run on the engine's worker threads — so what uses it here is the boot
    // record above, which exercises the file rather than only opening it. A route that reads or
    // writes goes through the per-request transaction scope the `app` module is specified to provide.
    var db = try data.turso.open(init.arena.allocator(), init.io, .{ .file = database_file });
    const boots = bootDatabase(&db) catch |err| {
        db.close();

        return err;
    };
    try stdout.print("{s}: data at the file tier in {s}: {d} boot(s) recorded, newest id {d}\n", .{
        app_name,
        database_file,
        boots.rows,
        boots.newest_id,
    });
{{/if}}{{#if live}}
    try stdout.print("{s}: live channel on ws://{s}:{d}/live\n", .{ app_name, host, port });
{{/if}}
    // The address the engine is about to bind, and the whole of it: `run` takes exactly this host and
    // port and refuses port 0, so there is no ephemeral port to read back afterwards, and the engine
    // announces the address only to a logger. A bind that fails reports on the next line rather than
    // leaving this one standing alone.
    try stdout.print("{s}: listening on http://{s}:{d}\n", .{ app_name, host, port });
    try stdout.flush();

    var server = zix.Http1.Server.init(Router.dispatch, .{
        .io = init.io,
        .ip = host,
        .port = port,
        .dispatch_model = .ASYNC,
    });

    // The engine has no drain or shutdown entry point yet — that belongs to the `app` module — so the
    // process's lifecycle is this file's: the accept loop gets a thread of its own, and the main
    // thread waits for a signal, which is where what the process holds is released, in order.
    installShutdownHandler();

    const serving = try std.Thread.spawn(.{}, serve, .{&server});
    serving.detach();

    while (!shutdown_requested.load(.monotonic)) {
        try std.Io.sleep(init.io, std.Io.Duration.fromMilliseconds(shutdown_poll_ms), .real);
    }
{{#if data}}
    // Closed here rather than left to process death: releasing the file lock is the file tier's whole
    // promise, and a process that exits without it leaves the next boot reasoning about a lock
    // nobody is holding.
    db.close();
    try stdout.print("{s}: database closed\n", .{app_name});
    try stdout.flush();
{{/if}}
    std.process.exit(0);
}

/// The accept loop, on its own thread. A failure here is a process-level event — the port is taken,
/// the interface does not exist — and a thread's void has nowhere to return it to, so it is turned
/// into a non-zero exit where it happened.
fn serve(server: anytype) void {
    server.run() catch |err| {
        std.debug.print("{s}: server stopped: {s}\n", .{ app_name, @errorName(err) });

        std.process.exit(1);
    };
}

/// Set by the signal handler and read by the wait above. The handler does one store and nothing else:
/// everything else a signal context could reach — allocation, locks, a writer — is unsafe there.
var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// How long the wait sleeps between checks. Nothing is served from this path, so a tenth of a second
/// of shutdown latency costs the process nothing, and it needs no condition variable to achieve it.
const shutdown_poll_ms: i64 = 100;

// 0.17's Sigaction wants the platform's signal enum, not a bare `c_int`.
fn requestShutdown(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .monotonic);
}

/// SIGINT and SIGTERM both mean stop, and neither is fatal on its own any more: the process is meant
/// to release what it holds and exit 0. Windows delivers console events instead of POSIX signals, and
/// there the process still ends with the console, so there is nothing to install.
fn installShutdownHandler() void {
    if (comptime builtin.os.tag != .windows) {
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = requestShutdown },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };

        std.posix.sigaction(.INT, &action, null);
        std.posix.sigaction(.TERM, &action, null);
    }
}

/// The port to serve on: the environment's answer when it gave one, the default when it did not. A
/// value that is not a port is refused rather than defaulted — a service listening somewhere nobody
/// asked for, and saying nothing about it, is the worst of the available failures.
fn portFromEnv(environ: *std.process.Environ.Map) !u16 {
    const text = environ.get("PORT") orelse return default_port;

    return std.fmt.parseInt(u16, text, 10) catch error.InvalidPort;
}
