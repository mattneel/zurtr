//! postgrez connection: the state machine on std.Io.
//!
//! Note:
//! - connect() runs the startup flow: protocol 3.2 request with in-place 3.0
//!   downgrade (NegotiateProtocolVersion), auth (SCRAM or cleartext), and the
//!   server version gate (below PostgreSQL 15 hard rejects).
//! - Queries use the extended protocol, binary first: a Describe round
//!   learns the result OIDs, then Bind requests binary format for every
//!   column the driver can decode and text for the rest.
//! - Conn lives on the heap (connect returns *Conn) because the stream
//!   reader and writer pin internal pointers.
//! - conn_timeout_ms bounds the connect + startup phase. Established
//!   connections block until the server answers.

const std = @import("std");
const lib = @import("lib.zig");
const frontend = @import("protocol/frontend.zig");
const backend = @import("protocol/backend.zig");
const startup_mod = @import("protocol/startup.zig");
const scram_mod = @import("auth/scram.zig");
const cleartext = @import("auth/cleartext.zig");
const oid_mod = @import("types/oid.zig");
const binary_mod = @import("types/binary.zig");
const row_mod = @import("types/row.zig");
const sqlstate = @import("sqlstate.zig");
const statement_mod = @import("statement.zig");
const pipeline_mod = @import("pipeline.zig");
const copy_mod = @import("copy.zig");
const notify_mod = @import("notify.zig");
const tls_mod = @import("tls.zig");

const READ_BUF_LEN = 32 * 1024;
const WRITE_BUF_LEN = 16 * 1024;
/// Sanity bound on one backend message payload (a DataRow can be large, a
/// bigger claim is treated as protocol corruption).
const MAX_MESSAGE_LEN = 1 << 30;

/// A NOTIFY captured while pumping messages, owned copies (the receive
/// buffer is reused). Consumed through nextNotification.
pub const OwnedNotification = struct {
    pid: i32,
    channel: []u8,
    payload: []u8,
};

/// One row of a streaming Result. Cell slices point into the receive
/// buffer: valid until the next Result.next() call.
pub const Row = struct {
    columns: []const row_mod.ColumnInfo,
    cells: []const ?[]const u8,
    arena: std.mem.Allocator,

    /// Decode the cell at `index` into T. Slices returned here stay valid
    /// until the next query on the connection.
    ///
    /// Return:
    /// - T on success
    /// - error.PostgrezColumnIndexOutOfRange / decode errors / error.PostgrezNullIntoNonOptional
    pub fn get(self: Row, comptime T: type, index: usize) !T {
        if (index >= self.cells.len) return error.PostgrezColumnIndexOutOfRange;

        return row_mod.decodeField(T, self.arena, self.columns[index], self.cells[index]);
    }
};

/// Streaming result iterator. Must be driven to the end (next() until null)
/// or deinit()ed so the connection returns to ready.
pub const Result = struct {
    conn: *Conn,
    columns: []row_mod.ColumnInfo,
    cells: []?[]const u8,
    affected: u64 = 0,
    done: bool = false,
    failed: bool = false,
    /// True for a Statement.awaitRows result: it ends at its own
    /// CommandComplete, only the last one of the batch consumes the shared
    /// ReadyForQuery.
    batched: bool = false,

    /// Next row, null when the result set ends.
    pub fn next(self: *Result) !?Row {
        if (self.done) return null;

        while (true) {
            const msg = try self.conn.nextMessage();

            switch (msg) {
                .bind_complete, .no_data => {},
                .data_row => |data| {
                    if (data.column_count != self.columns.len) return error.PostgrezProtocolViolation;

                    var cell_it = data.iterator();
                    var index: usize = 0;
                    while (try cell_it.next()) |cell| : (index += 1) self.cells[index] = cell;

                    return .{
                        .columns = self.columns,
                        .cells = self.cells,
                        .arena = self.conn.query_arena.allocator(),
                    };
                },
                .command_complete => |tag| {
                    self.affected = backend.commandCompleteRows(tag);

                    if (self.batched and self.conn.batch_pending > 0) {
                        self.done = true;

                        return null;
                    }
                },
                .empty_query_response, .portal_suspended => {},
                .error_response => |fields| {
                    self.conn.last_server_error.capture(fields);
                    self.failed = true;
                    // the server discards the rest of a batch until Sync
                    if (self.batched) self.conn.batch_aborted = self.conn.batch_pending != 0;
                },
                .notice_response => {},
                .ready_for_query => |status| {
                    self.conn.transaction_status = status;
                    self.done = true;
                    if (self.failed) return error.PostgrezServerError;

                    return null;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Drain the remaining messages so the connection is reusable.
    pub fn deinit(self: *Result) void {
        while (true) {
            const maybe_row = self.next() catch return;
            if (maybe_row == null) return;
        }
    }
};

// --------------------------------------------------------- //

pub const Conn = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: lib.Config,
    stream: std.Io.net.Stream,
    stream_reader: std.Io.net.Stream.Reader,
    stream_writer: std.Io.net.Stream.Writer,
    read_buf: []u8,
    write_buf: []u8,

    /// Payload of the backend message being processed, reused per message.
    msg_buf: std.ArrayList(u8) = .empty,
    /// Outgoing message batch, flushed as one send.
    send_buf: std.ArrayList(u8) = .empty,
    /// Per-query scratch (param encoding, column metadata), reset at the
    /// start of every query.
    query_arena: std.heap.ArenaAllocator,

    protocol_code: i32,
    server_version_major: u32 = 0,
    backend_pid: i32 = 0,
    backend_key_buf: [256]u8 = undefined,
    backend_key_len: usize = 0,
    /// TLS session after a successful SSLRequest upgrade, null on cleartext.
    tls_session: ?*tls_mod.TlsSession = null,
    /// The SASL mechanism the startup used, null for non-SASL auth.
    sasl_mechanism: ?scram_mod.Mechanism = null,
    transaction_status: backend.TransactionStatus = .IDLE,
    last_server_error: sqlstate.ServerError = .{},
    pending_notifications: std.ArrayList(OwnedNotification) = .empty,
    /// The notification handed out by nextNotification, freed on the next call.
    current_notification: ?OwnedNotification = null,
    /// Names prepared statements (postgrez_1, postgrez_2, ...).
    statement_seq: u32 = 0,
    /// Statements queued by Statement.sendRows whose results were not yet
    /// consumed by awaitRows. Bounded by config.max_pending_replies.
    batch_pending: usize = 0,
    /// Whether the current sendRows batch already went to the wire (the
    /// first awaitRows appends the Sync and flushes).
    batch_flushed: bool = false,
    /// Set when a batched statement failed with results still pending: the
    /// server discarded the rest of the batch until Sync, the remaining
    /// awaitRows calls report error.PostgrezBatchAborted.
    batch_aborted: bool = false,

    const Self = @This();

    // --------------------------------------------------------- //

    /// Connect and run the startup flow.
    ///
    /// Return:
    /// - *Conn ready for queries
    /// - error.PostgrezPortNotConfigured / connect errors
    /// - error.PostgrezUnsupportedServerVersion (server below PostgreSQL 15)
    /// - error.PostgrezProtocolNotSupported (strict .V3_2 refused)
    /// - error.PostgrezUnsupportedAuth (MD5 or another method out of scope)
    /// - error.PostgrezServerError (startup rejected, see lastServerError)
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, config: lib.Config) !*Self {
        if (config.port == 0) return error.PostgrezPortNotConfigured;

        const stream = try connectTcp(io, config.ip, config.port);

        return fromStream(allocator, io, config, stream);
    }

    /// TCP connect to an IP literal or a hostname. A literal skips the
    /// resolver, anything else goes through the hosts/DNS lookup
    /// (a DATABASE_URL commonly carries a hostname, e.g. localhost).
    fn connectTcp(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
        if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
            return addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        } else |_| {
            const host_name = try std.Io.net.HostName.init(host);

            return host_name.connect(io, port, .{ .mode = .stream, .protocol = .tcp });
        }
    }

    /// Run the startup flow over an already-connected stream. The Conn owns
    /// the stream from here on, failure included.
    pub fn fromStream(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, stream: std.Io.net.Stream) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const read_buf = try allocator.alloc(u8, READ_BUF_LEN);
        errdefer allocator.free(read_buf);
        const write_buf = try allocator.alloc(u8, WRITE_BUF_LEN);
        errdefer allocator.free(write_buf);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .stream = stream,
            .stream_reader = undefined,
            .stream_writer = undefined,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .query_arena = std.heap.ArenaAllocator.init(allocator),
            .protocol_code = startup_mod.requestedCode(config.protocol_version),
        };
        self.stream_reader = self.stream.reader(io, read_buf);
        self.stream_writer = self.stream.writer(io, write_buf);

        errdefer {
            if (self.tls_session) |session| allocator.destroy(session);
            self.msg_buf.deinit(allocator);
            self.send_buf.deinit(allocator);
            self.query_arena.deinit();
            self.stream.close(io);
        }

        if (config.tls != .OFF) {
            const maybe_session = try tls_mod.upgrade(allocator, io, &self.stream_reader.interface, &self.stream_writer.interface);

            if (maybe_session) |session| {
                self.tls_session = session;
            } else if (config.tls == .REQUIRE) {
                return error.PostgrezTlsRefused;
            }
        }

        try self.runStartup();

        return self;
    }

    /// Terminate (best effort), close the stream, free everything.
    pub fn deinit(self: *Self) void {
        const allocator = self.allocator;

        self.send_buf.clearRetainingCapacity();
        frontend.terminate(allocator, &self.send_buf) catch {};
        self.flushSend() catch {};
        self.stream.close(self.io);

        if (self.tls_session) |session| allocator.destroy(session);
        self.msg_buf.deinit(allocator);
        self.send_buf.deinit(allocator);
        self.query_arena.deinit();
        self.clearNotifications();
        self.pending_notifications.deinit(allocator);
        self.freeCurrentNotification();
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
        allocator.destroy(self);
    }

    /// The last ErrorResponse the server sent on this connection.
    pub fn lastServerError(self: *const Self) *const sqlstate.ServerError {
        return &self.last_server_error;
    }

    // --------------------------------------------------------- //

    /// Run a statement with no interest in its rows.
    ///
    /// Return:
    /// - affected row count from CommandComplete (0 for tag-less commands)
    /// - error.PostgrezServerError with lastServerError filled
    pub fn exec(self: *Self, sql: []const u8, args: anytype) !u64 {
        _ = self.query_arena.reset(.retain_capacity);
        const arena = self.query_arena.allocator();
        const params = try encodeParams(arena, args);

        self.send_buf.clearRetainingCapacity();
        try frontend.parse(self.allocator, &self.send_buf, "", sql, &params.oids);
        try frontend.bind(self.allocator, &self.send_buf, "", "", &params.formats, &params.values, &.{});
        try frontend.execute(self.allocator, &self.send_buf, "", 0);
        try frontend.sync(self.allocator, &self.send_buf);
        try self.flushSend();

        return self.readCommandCompletion();
    }

    /// Internal: drain one extended-query cycle to ReadyForQuery, ignoring
    /// any rows, and report the CommandComplete count. Shared by exec and
    /// the prepared statement path.
    pub fn readCommandCompletion(self: *Self) !u64 {
        var affected: u64 = 0;
        var failed = false;
        while (true) {
            const msg = try self.nextMessage();

            switch (msg) {
                .parse_complete, .bind_complete, .no_data, .data_row, .row_description, .parameter_description, .empty_query_response, .notice_response, .close_complete => {},
                .command_complete => |tag| affected = backend.commandCompleteRows(tag),
                .error_response => |fields| {
                    self.last_server_error.capture(fields);
                    failed = true;
                },
                .ready_for_query => |status| {
                    self.transaction_status = status;
                    if (failed) return error.PostgrezServerError;

                    return affected;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Stream the result set of a query. Binary-first: a Describe round
    /// learns the OIDs before Bind picks per-column formats.
    pub fn rows(self: *Self, sql: []const u8, args: anytype) !Result {
        _ = self.query_arena.reset(.retain_capacity);
        const arena = self.query_arena.allocator();
        const params = try encodeParams(arena, args);

        // round 1: parse + describe, learn the result columns
        self.send_buf.clearRetainingCapacity();
        try frontend.parse(self.allocator, &self.send_buf, "", sql, &params.oids);
        try frontend.describeStatement(self.allocator, &self.send_buf, "");
        try frontend.flush(self.allocator, &self.send_buf);
        try self.flushSend();

        var columns: []row_mod.ColumnInfo = &.{};
        describe: while (true) {
            const msg = try self.nextMessage();

            switch (msg) {
                .parse_complete, .parameter_description, .notice_response => {},
                .no_data => break :describe,
                .row_description => |desc| {
                    columns = try materializeColumns(arena, desc);

                    break :describe;
                },
                .error_response => |fields| {
                    self.last_server_error.capture(fields);
                    try self.syncAndDrain();

                    return error.PostgrezServerError;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }

        // round 2: bind with per-column formats, execute
        const result_formats = try arena.alloc(frontend.Format, columns.len);
        for (result_formats, columns) |*format, column| format.* = column.format;

        self.send_buf.clearRetainingCapacity();
        try frontend.bind(self.allocator, &self.send_buf, "", "", &params.formats, &params.values, result_formats);
        try frontend.execute(self.allocator, &self.send_buf, "", 0);
        try frontend.sync(self.allocator, &self.send_buf);
        try self.flushSend();

        return .{
            .conn = self,
            .columns = columns,
            .cells = try arena.alloc(?[]const u8, columns.len),
        };
    }

    /// All rows mapped into `[]T` (see types/row.zig for the mapping rules).
    /// The slice and its strings are allocated from the connection
    /// allocator, an arena reset per request cycle is the intended pattern.
    pub fn query(self: *Self, comptime T: type, sql: []const u8, args: anytype) ![]T {
        var result = try self.rows(sql, args);
        defer result.deinit();

        var list: std.ArrayList(T) = .empty;
        errdefer list.deinit(self.allocator);

        while (try result.next()) |row_view| {
            const item = try row_mod.parseRow(T, self.allocator, result.columns, row_view.cells, .{});
            try list.append(self.allocator, item);
        }

        return list.toOwnedSlice(self.allocator);
    }

    /// First row mapped into T, null on an empty result. Extra rows are
    /// drained and ignored.
    pub fn queryRow(self: *Self, comptime T: type, sql: []const u8, args: anytype) !?T {
        var result = try self.rows(sql, args);
        defer result.deinit();

        const first = (try result.next()) orelse return null;

        return try row_mod.parseRow(T, self.allocator, result.columns, first.cells, .{});
    }

    // --------------------------------------------------------- //

    /// Open an explicit transaction.
    ///
    /// Usage:
    /// ```zig
    /// var transaction = try conn.begin();
    /// defer transaction.rollback();
    /// _ = try transaction.exec("INSERT ...", .{});
    /// try transaction.commit();
    /// ```
    pub fn begin(self: *Self) !Transaction {
        _ = try self.exec("BEGIN", .{});

        return .{ .conn = self };
    }

    /// Callback transaction: BEGIN, run `func(&transaction, args...)`, COMMIT.
    /// Any error rolls back.
    pub fn transaction(self: *Self, comptime func: anytype, args: anytype) !void {
        var active = try self.begin();
        defer active.rollback();

        try @call(.auto, func, .{&active} ++ args);

        try active.commit();
    }

    // --------------------------------------------------------- //

    /// Prepare a named server-side statement for reuse.
    pub fn prepare(self: *Self, sql: []const u8) !statement_mod.Statement {
        return statement_mod.Statement.prepare(self, sql);
    }

    /// Open a pipeline: batch several statements into one round trip.
    /// No other queries on this connection until sync() ran.
    pub fn pipeline(self: *Self) !pipeline_mod.Pipeline {
        return pipeline_mod.Pipeline.begin(self);
    }

    /// Start COPY FROM STDIN.
    pub fn copyIn(self: *Self, sql: []const u8) !copy_mod.CopyIn {
        return copy_mod.CopyIn.begin(self, sql);
    }

    /// Start COPY TO STDOUT.
    pub fn copyOut(self: *Self, sql: []const u8) !copy_mod.CopyOut {
        return copy_mod.CopyOut.begin(self, sql);
    }

    /// Subscribe this connection to a channel.
    pub fn listen(self: *Self, channel: []const u8) !void {
        return notify_mod.listen(self, channel);
    }

    /// Unsubscribe from a channel.
    pub fn unlisten(self: *Self, channel: []const u8) !void {
        return notify_mod.unlisten(self, channel);
    }

    /// Send a NOTIFY through pg_notify.
    pub fn notify(self: *Self, channel: []const u8, payload: []const u8) !void {
        return notify_mod.send(self, channel, payload);
    }

    /// Deliver the next notification, blocking until one arrives. The
    /// returned slices stay valid until the next nextNotification call.
    pub fn nextNotification(self: *Self) !?OwnedNotification {
        return notify_mod.next(self);
    }

    // --------------------------------------------------------- //

    fn runStartup(self: *Self) !void {
        self.send_buf.clearRetainingCapacity();
        try startup_mod.buildStartup(self.allocator, &self.send_buf, self.config.protocol_version, .{
            .user = self.config.user,
            .database = self.config.database,
            .application_name = self.config.application_name,
        });
        try self.flushSend();

        var exchange: scram_mod.Scram = undefined;
        var exchange_active = false;
        var cbind_hash: [32]u8 = undefined;

        while (true) {
            try self.waitReadable();
            const msg = try self.readMessage();

            switch (msg) {
                .negotiate_protocol_version => |negotiate| {
                    self.protocol_code = try startup_mod.handleNegotiate(self.config.protocol_version, negotiate);
                },
                .auth => |auth| switch (auth) {
                    .ok => {},
                    .cleartext_password => {
                        self.send_buf.clearRetainingCapacity();
                        try cleartext.respond(self.allocator, &self.send_buf, self.config.password);
                        try self.flushSend();
                    },
                    .sasl => |mechanisms| {
                        // channel binding when the connection is TLS and the
                        // server offers PLUS
                        var mechanism: scram_mod.Mechanism = .SCRAM_SHA_256;
                        var cbind_data: []const u8 = "";
                        if (self.tls_session) |session| {
                            if (mechanisms.has("SCRAM-SHA-256-PLUS")) {
                                mechanism = .SCRAM_SHA_256_PLUS;
                                cbind_hash = session.channelBindingHash();
                                cbind_data = &cbind_hash;
                            }
                        }
                        if (!mechanisms.has(mechanism.name())) return error.PostgrezUnsupportedAuth;

                        var raw_nonce: [18]u8 = undefined;
                        self.io.random(&raw_nonce);
                        var nonce_text: [24]u8 = undefined;
                        scram_mod.encodeNonce(raw_nonce, &nonce_text);

                        exchange = try scram_mod.Scram.init(mechanism, "", self.config.password, &nonce_text, cbind_data);
                        exchange_active = true;
                        self.sasl_mechanism = mechanism;

                        var first_buf: [256]u8 = undefined;
                        const client_first = try exchange.clientFirst(&first_buf);

                        self.send_buf.clearRetainingCapacity();
                        try frontend.saslInitialResponse(self.allocator, &self.send_buf, mechanism.name(), client_first);
                        try self.flushSend();
                    },
                    .sasl_continue => |server_first| {
                        if (!exchange_active) return error.PostgrezProtocolViolation;

                        const client_final = try exchange.handleServerFirst(server_first);

                        self.send_buf.clearRetainingCapacity();
                        try frontend.saslResponse(self.allocator, &self.send_buf, client_final);
                        try self.flushSend();
                    },
                    .sasl_final => |server_final| {
                        if (!exchange_active) return error.PostgrezProtocolViolation;

                        try exchange.handleServerFinal(server_final);
                    },
                    .md5_password => return error.PostgrezUnsupportedAuth,
                    .unsupported => return error.PostgrezUnsupportedAuth,
                },
                .parameter_status => |status| {
                    if (std.mem.eql(u8, status.name, "server_version")) {
                        try startup_mod.checkServerVersion(status.value);
                        self.server_version_major = startup_mod.serverVersionMajor(status.value) orelse 0;
                    }
                },
                .backend_key_data => |key_data| {
                    self.backend_pid = key_data.pid;
                    self.backend_key_len = @min(key_data.key.len, self.backend_key_buf.len);
                    @memcpy(self.backend_key_buf[0..self.backend_key_len], key_data.key[0..self.backend_key_len]);
                },
                .error_response => |fields| {
                    self.last_server_error.capture(fields);

                    return error.PostgrezServerError;
                },
                .notice_response => {},
                .ready_for_query => |status| {
                    self.transaction_status = status;

                    return;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Internal: read one backend message. The returned view borrows
    /// msg_buf: valid until the next readMessage call.
    pub fn readMessage(self: *Self) !backend.BackendMessage {
        var header_bytes: [5]u8 = undefined;
        try self.transportReadAll(&header_bytes);
        const header = try backend.parseHeader(header_bytes);
        if (header.payload_len > MAX_MESSAGE_LEN) return error.PostgrezProtocolViolation;

        self.msg_buf.clearRetainingCapacity();
        try self.msg_buf.resize(self.allocator, header.payload_len);
        try self.transportReadAll(self.msg_buf.items);

        return backend.decode(header.tag, self.msg_buf.items);
    }

    /// Read exactly buf.len bytes through the transport (TLS or cleartext).
    fn transportReadAll(self: *Self, buf: []u8) !void {
        if (self.tls_session) |session| {
            session.readAll(&self.stream_reader.interface, buf) catch return error.PostgrezConnectionClosed;

            return;
        }

        self.stream_reader.interface.readSliceAll(buf) catch return error.PostgrezConnectionClosed;
    }

    /// Internal: readMessage + transparent capture of notifications.
    pub fn nextMessage(self: *Self) !backend.BackendMessage {
        while (true) {
            const msg = try self.readMessage();

            switch (msg) {
                .notification => |note| {
                    try self.storeNotification(note);

                    continue;
                },
                else => return msg,
            }
        }
    }

    /// Internal: send everything batched in send_buf.
    pub fn flushSend(self: *Self) !void {
        const writer = &self.stream_writer.interface;

        if (self.tls_session) |session| {
            session.writeAll(writer, self.send_buf.items) catch return error.PostgrezConnectionClosed;
        } else {
            writer.writeAll(self.send_buf.items) catch return error.PostgrezConnectionClosed;
        }
        writer.flush() catch return error.PostgrezConnectionClosed;
        self.send_buf.clearRetainingCapacity();
    }

    /// Internal: recover after an error mid extended-query batch: the server
    /// discards until Sync, so send one and drain to ReadyForQuery.
    pub fn syncAndDrain(self: *Self) !void {
        self.send_buf.clearRetainingCapacity();
        try frontend.sync(self.allocator, &self.send_buf);
        try self.flushSend();

        while (true) {
            const msg = try self.nextMessage();

            switch (msg) {
                .ready_for_query => |status| {
                    self.transaction_status = status;

                    return;
                },
                else => {},
            }
        }
    }

    /// Bound the startup phase by conn_timeout_ms (0 disables).
    fn waitReadable(self: *Self) !void {
        // No poll over the ntdll path: conn_timeout_ms degrades to a blocking
        // read on Windows.
        if (comptime @import("builtin").target.os.tag == .windows) return;

        if (self.config.conn_timeout_ms == 0) return;
        if (self.stream_reader.interface.bufferedLen() > 0) return;
        if (self.tls_session) |session| {
            if (session.bufferedLen() > 0) return;
        }

        var poll_fds = [1]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const timeout_ms: i32 = @intCast(@min(self.config.conn_timeout_ms, @as(u32, std.math.maxInt(i32))));

        const ready = std.posix.poll(&poll_fds, timeout_ms) catch return error.PostgrezConnectionClosed;
        if (ready == 0) return error.PostgrezConnectTimeout;
    }

    fn storeNotification(self: *Self, note: backend.Notification) !void {
        const channel = try self.allocator.dupe(u8, note.channel);
        errdefer self.allocator.free(channel);
        const payload = try self.allocator.dupe(u8, note.payload);
        errdefer self.allocator.free(payload);

        try self.pending_notifications.append(self.allocator, .{
            .pid = note.pid,
            .channel = channel,
            .payload = payload,
        });
    }

    fn clearNotifications(self: *Self) void {
        for (self.pending_notifications.items) |note| {
            self.allocator.free(note.channel);
            self.allocator.free(note.payload);
        }
        self.pending_notifications.clearRetainingCapacity();
    }

    /// Internal: free the notification handed out by the previous
    /// nextNotification call.
    pub fn freeCurrentNotification(self: *Self) void {
        if (self.current_notification) |note| {
            self.allocator.free(note.channel);
            self.allocator.free(note.payload);
            self.current_notification = null;
        }
    }
};

// --------------------------------------------------------- //

/// Explicit transaction handle. rollback() after commit() is a no-op.
pub const Transaction = struct {
    conn: *Conn,
    done: bool = false,

    pub fn exec(self: *Transaction, sql: []const u8, args: anytype) !u64 {
        return self.conn.exec(sql, args);
    }

    pub fn query(self: *Transaction, comptime T: type, sql: []const u8, args: anytype) ![]T {
        return self.conn.query(T, sql, args);
    }

    pub fn queryRow(self: *Transaction, comptime T: type, sql: []const u8, args: anytype) !?T {
        return self.conn.queryRow(T, sql, args);
    }

    pub fn rows(self: *Transaction, sql: []const u8, args: anytype) !Result {
        return self.conn.rows(sql, args);
    }

    pub fn commit(self: *Transaction) !void {
        _ = try self.conn.exec("COMMIT", .{});
        self.done = true;
    }

    pub fn rollback(self: *Transaction) void {
        if (self.done) return;

        _ = self.conn.exec("ROLLBACK", .{}) catch {};
        self.done = true;
    }
};

// --------------------------------------------------------- //

/// Internal: the three parallel arrays Bind needs, sized per args tuple.
pub fn Params(comptime count: usize) type {
    return struct {
        oids: [count]u32,
        formats: [count]frontend.Format,
        values: [count]?[]const u8,
    };
}

/// Internal: encode an args tuple into the three parallel arrays Bind needs.
pub fn encodeParams(arena: std.mem.Allocator, args: anytype) !Params(row_mod.fieldCount(@TypeOf(args))) {
    const count = comptime row_mod.fieldCount(@TypeOf(args));

    var out: Params(count) = undefined;
    inline for (0..count) |index| {
        const encoded = try binary_mod.encode(arena, args[index]);
        out.oids[index] = encoded.oid;
        out.formats[index] = encoded.format;
        out.values[index] = encoded.bytes;
    }

    return out;
}

/// Internal: copy RowDescription into arena-owned ColumnInfo, deciding the
/// requested format per OID (binary first, text fallback).
pub fn materializeColumns(arena: std.mem.Allocator, desc: backend.RowDescription) ![]row_mod.ColumnInfo {
    const columns = try arena.alloc(row_mod.ColumnInfo, desc.column_count);

    var column_it = desc.iterator();
    var index: usize = 0;
    while (try column_it.next()) |column| : (index += 1) {
        columns[index] = .{
            .name = try arena.dupe(u8, column.name),
            .type_oid = column.type_oid,
            .format = if (oid_mod.hasBinaryDecode(@enumFromInt(column.type_oid))) .BINARY else .TEXT,
        };
    }

    return columns;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn appendServerMsg(allocator: std.mem.Allocator, script: *std.ArrayList(u8), tag: u8, payload: []const u8) !void {
    try script.append(allocator, tag);
    var len_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_bytes, @intCast(payload.len + 4), .big);
    try script.appendSlice(allocator, &len_bytes);
    try script.appendSlice(allocator, payload);
}

fn appendStartupOk(allocator: std.mem.Allocator, script: *std.ArrayList(u8), server_version: []const u8) !void {
    try appendServerMsg(allocator, script, 'R', &.{ 0, 0, 0, 0 });

    var param: std.ArrayList(u8) = .empty;
    defer param.deinit(allocator);
    try param.appendSlice(allocator, "server_version");
    try param.append(allocator, 0);
    try param.appendSlice(allocator, server_version);
    try param.append(allocator, 0);
    try appendServerMsg(allocator, script, 'S', param.items);

    try appendServerMsg(allocator, script, 'K', &.{ 0, 0, 0, 9, 0xca, 0xfe, 0xba, 0xbe });
    try appendServerMsg(allocator, script, 'Z', "I");
}

/// A scripted mock backend: all server bytes are pre-written into one end
/// of a loopback TCP pair, the Conn reads them as the flow advances. Client
/// writes land in the socket buffer unread, which is fine for scripted flows.
const MOCK_BACKEND_PORT: u16 = 19100;

const MockBackend = struct {
    conn_fd: std.posix.fd_t,
    script_stream: std.Io.net.Stream,

    fn init(io: std.Io, script: []const u8) !MockBackend {
        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", MOCK_BACKEND_PORT);
        var listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        defer listener.deinit(io);

        const Accepted = struct {
            listener: *std.Io.net.Server,
            io: std.Io,
            stream: std.Io.net.Stream = undefined,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.stream = self.listener.accept(self.io) catch |e| {
                    self.err = e;
                    return;
                };
            }
        };

        var accepted = Accepted{ .listener = &listener, .io = io };
        const t = try std.Thread.spawn(.{}, Accepted.run, .{&accepted});

        const client_stream = try addr.connect(io, .{ .mode = .stream });
        t.join();
        if (accepted.err) |e| return e;

        var write_buf: [4096]u8 = undefined;
        var writer = accepted.stream.writer(io, &write_buf);
        try writer.interface.writeAll(script);
        try writer.interface.flush();

        return .{ .conn_fd = client_stream.socket.handle, .script_stream = accepted.stream };
    }

    fn stream(self: *const MockBackend) std.Io.net.Stream {
        return .{ .socket = .{ .handle = self.conn_fd, .address = .{ .ip4 = .loopback(0) } } };
    }
};

/// A live scripted connection. The script side of the loopback pair stays
/// open for the whole test so post-startup sends do not hit EPIPE.
const Scripted = struct {
    conn: *Conn,
    script_stream: std.Io.net.Stream,

    fn deinit(self: *const Scripted, io: std.Io) void {
        self.conn.deinit();
        self.script_stream.close(io);
    }
};

const TEST_CONFIG = lib.Config{
    .user = "tester",
    .password = "pw",
    .database = "testdb",
};

fn connectScripted(io: std.Io, script: []const u8, config: lib.Config) !Scripted {
    const mock = try MockBackend.init(io, script);
    errdefer mock.script_stream.close(io);

    const conn = try Conn.fromStream(testing.allocator, io, config, mock.stream());

    return .{ .conn = conn, .script_stream = mock.script_stream };
}

test "postgrez: conn mock startup reaches ready" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectEqual(@as(u32, 18), conn.server_version_major);
    try testing.expectEqual(@as(i32, 9), conn.backend_pid);
    try testing.expectEqual(frontend.PROTOCOL_V3_2, conn.protocol_code);
    try testing.expectEqual(backend.TransactionStatus.IDLE, conn.transaction_status);
}

test "postgrez: conn mock NegotiateProtocolVersion downgrades in place" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'v', &.{ 0, 0x03, 0, 0, 0, 0, 0, 0 });
    try appendStartupOk(testing.allocator, &script, "16.4");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectEqual(frontend.PROTOCOL_V3_0, conn.protocol_code);
    try testing.expectEqual(@as(u32, 16), conn.server_version_major);
}

test "postgrez: conn mock server below 15 hard rejects" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'v', &.{ 0, 0x03, 0, 0, 0, 0, 0, 0 });
    try appendStartupOk(testing.allocator, &script, "14.8");

    try testing.expectError(error.PostgrezUnsupportedServerVersion, connectScripted(threaded.io(), script.items, TEST_CONFIG));
}

test "postgrez: conn mock strict V3_2 refuses negotiation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'v', &.{ 0, 0x03, 0, 0, 0, 0, 0, 0 });
    try appendStartupOk(testing.allocator, &script, "16.4");

    var config = TEST_CONFIG;
    config.protocol_version = .V3_2;

    try testing.expectError(error.PostgrezProtocolNotSupported, connectScripted(threaded.io(), script.items, config));
}

test "postgrez: conn mock cleartext auth flow" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'R', &.{ 0, 0, 0, 3 });
    try appendStartupOk(testing.allocator, &script, "18.0");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectEqual(@as(u32, 18), conn.server_version_major);
}

test "postgrez: conn mock md5 auth is rejected" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'R', &.{ 0, 0, 0, 5, 1, 2, 3, 4 });

    try testing.expectError(error.PostgrezUnsupportedAuth, connectScripted(threaded.io(), script.items, TEST_CONFIG));
}

test "postgrez: conn mock startup ErrorResponse surfaces state" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendServerMsg(testing.allocator, &script, 'E', "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00");

    try testing.expectError(error.PostgrezServerError, connectScripted(threaded.io(), script.items, TEST_CONFIG));
}

test "postgrez: conn mock exec returns affected rows" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "UPDATE 3\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    const affected = try conn.exec("UPDATE t SET x = $1", .{7});
    try testing.expectEqual(@as(u64, 3), affected);
}

test "postgrez: conn mock exec server error maps SQLSTATE" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'E', "SERROR\x00C23505\x00Mduplicate key\x00\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectError(error.PostgrezServerError, conn.exec("INSERT ...", .{}));
    try testing.expectEqual(sqlstate.SqlState.UNIQUE_VIOLATION, conn.lastServerError().state);
    try testing.expectEqualStrings("duplicate key", conn.lastServerError().message());
}

fn appendQueryScript(allocator: std.mem.Allocator, script: *std.ArrayList(u8)) !void {
    // round 1 answers: ParseComplete, ParameterDescription(0), RowDescription
    try appendServerMsg(allocator, script, '1', "");
    try appendServerMsg(allocator, script, 't', &.{ 0, 0 });

    var desc: std.ArrayList(u8) = .empty;
    defer desc.deinit(allocator);
    try desc.appendSlice(allocator, &.{ 0, 2 });
    try desc.appendSlice(allocator, "id\x00");
    try desc.appendSlice(allocator, &.{ 0, 0, 0, 1, 0, 1, 0, 0, 0, 20, 0, 8, 0xff, 0xff, 0xff, 0xff, 0, 0 });
    try desc.appendSlice(allocator, "name\x00");
    try desc.appendSlice(allocator, &.{ 0, 0, 0, 1, 0, 2, 0, 0, 0, 25, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 });
    try appendServerMsg(allocator, script, 'T', desc.items);

    // round 2 answers: BindComplete, rows (binary cells), CommandComplete, Ready
    try appendServerMsg(allocator, script, '2', "");

    var row_one: std.ArrayList(u8) = .empty;
    defer row_one.deinit(allocator);
    try row_one.appendSlice(allocator, &.{ 0, 2 });
    try row_one.appendSlice(allocator, &.{ 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 7 });
    try row_one.appendSlice(allocator, &.{ 0, 0, 0, 5 });
    try row_one.appendSlice(allocator, "Alice");
    try appendServerMsg(allocator, script, 'D', row_one.items);

    var row_two: std.ArrayList(u8) = .empty;
    defer row_two.deinit(allocator);
    try row_two.appendSlice(allocator, &.{ 0, 2 });
    try row_two.appendSlice(allocator, &.{ 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 8 });
    try row_two.appendSlice(allocator, &.{ 0, 0, 0, 3 });
    try row_two.appendSlice(allocator, "Bob");
    try appendServerMsg(allocator, script, 'D', row_two.items);

    try appendServerMsg(allocator, script, 'C', "SELECT 2\x00");
    try appendServerMsg(allocator, script, 'Z', "I");
}

test "postgrez: conn mock query maps typed rows" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendQueryScript(testing.allocator, &script);

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    const User = struct {
        id: i64,
        name: []const u8,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // query() allocates from the conn allocator: use an arena-backed conn
    // pattern in real use. Here rows are mapped manually off the stream.
    var result = try conn.rows("SELECT id, name FROM users", .{});
    defer result.deinit();

    var users: std.ArrayList(User) = .empty;
    defer users.deinit(testing.allocator);
    while (try result.next()) |row_view| {
        try users.append(testing.allocator, try row_mod.parseRow(User, arena.allocator(), result.columns, row_view.cells, .{}));
    }

    try testing.expectEqual(@as(usize, 2), users.items.len);
    try testing.expectEqual(@as(i64, 7), users.items[0].id);
    try testing.expectEqualStrings("Alice", users.items[0].name);
    try testing.expectEqual(@as(i64, 8), users.items[1].id);
    try testing.expectEqualStrings("Bob", users.items[1].name);
    try testing.expectEqual(@as(u64, 2), result.affected);
}

test "postgrez: conn mock rows streams with row.get" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendQueryScript(testing.allocator, &script);

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    var result = try conn.rows("SELECT id, name FROM users", .{});
    defer result.deinit();

    const first = (try result.next()).?;
    try testing.expectEqual(@as(i64, 7), try first.get(i64, 0));
    try testing.expectEqualStrings("Alice", try first.get([]const u8, 1));

    const second = (try result.next()).?;
    try testing.expectEqual(@as(i64, 8), try second.get(i64, 0));

    try testing.expectEqual(@as(?Row, null), try result.next());
    try testing.expectError(error.PostgrezColumnIndexOutOfRange, second.get(i64, 5));
}

test "postgrez: conn mock queryRow returns null on empty result" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, 't', &.{ 0, 0 });

    var desc: std.ArrayList(u8) = .empty;
    defer desc.deinit(testing.allocator);
    try desc.appendSlice(testing.allocator, &.{ 0, 1 });
    try desc.appendSlice(testing.allocator, "id\x00");
    try desc.appendSlice(testing.allocator, &.{ 0, 0, 0, 1, 0, 1, 0, 0, 0, 20, 0, 8, 0xff, 0xff, 0xff, 0xff, 0, 0 });
    try appendServerMsg(testing.allocator, &script, 'T', desc.items);

    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 0\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    const Narrow = struct { id: i64 };
    const maybe_row = try conn.queryRow(Narrow, "SELECT id FROM t WHERE false", .{});
    try testing.expectEqual(@as(?Narrow, null), maybe_row);
}

test "postgrez: conn mock parse error recovers via sync" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    // round 1 fails at parse
    try appendServerMsg(testing.allocator, &script, 'E', "SERROR\x00C42601\x00Msyntax error\x00\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // the connection stays usable: a following exec succeeds
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "UPDATE 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    try testing.expectError(error.PostgrezServerError, conn.rows("SELEC 1", .{}));
    try testing.expectEqual(sqlstate.SqlState.SYNTAX_ERROR, conn.lastServerError().state);

    const affected = try conn.exec("UPDATE t SET x = 1", .{});
    try testing.expectEqual(@as(u64, 1), affected);
}

test "postgrez: conn mock transaction callback commits" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    // BEGIN
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "BEGIN\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "T");
    // INSERT inside the callback
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "T");
    // COMMIT
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "COMMIT\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    const insertOne = struct {
        fn run(transaction: *Transaction, amount: i64) !void {
            const affected = try transaction.exec("INSERT INTO ledger (amount) VALUES ($1)", .{amount});
            try testing.expectEqual(@as(u64, 1), affected);
        }
    }.run;

    try conn.transaction(insertOne, .{@as(i64, 100)});
    try testing.expectEqual(backend.TransactionStatus.IDLE, conn.transaction_status);
}

test "postgrez: conn mock prepared statement lifecycle" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    // prepare: ParseComplete, ParameterDescription (one int8), RowDescription (one int8 col), Ready
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, 't', &.{ 0, 1, 0, 0, 0, 20 });
    var desc: std.ArrayList(u8) = .empty;
    defer desc.deinit(testing.allocator);
    try desc.appendSlice(testing.allocator, &.{ 0, 1 });
    try desc.appendSlice(testing.allocator, "id\x00");
    try desc.appendSlice(testing.allocator, &.{ 0, 0, 0, 1, 0, 1, 0, 0, 0, 20, 0, 8, 0xff, 0xff, 0xff, 0xff, 0, 0 });
    try appendServerMsg(testing.allocator, &script, 'T', desc.items);
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // exec: BindComplete, CommandComplete, Ready
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // rows: BindComplete, one DataRow, CommandComplete, Ready
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'D', &.{ 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 7 });
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // deinit: CloseComplete, Ready
    try appendServerMsg(testing.allocator, &script, '3', "");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var prepared = try scripted.conn.prepare("INSERT INTO t (id) VALUES ($1)");
    defer prepared.deinit();

    try testing.expectEqualStrings("postgrez_1", prepared.name());
    try testing.expectEqual(@as(usize, 1), prepared.param_oids.len);
    try testing.expectEqual(@as(u32, 20), prepared.param_oids[0]);
    try testing.expectEqual(@as(usize, 1), prepared.columns.len);

    const affected = try prepared.exec(.{@as(i64, 5)});
    try testing.expectEqual(@as(u64, 1), affected);

    var result = try prepared.rows(.{@as(i64, 5)});
    defer result.deinit();
    const first = (try result.next()).?;
    try testing.expectEqual(@as(i64, 7), try first.get(i64, 0));
    try testing.expectEqual(@as(?Row, null), try result.next());
}

test "postgrez: conn mock pipeline collects per-statement results" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    // three statements in one batch
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'D', &.{ 0, 1, 0, 0, 0, 1, '2' });
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var pipe = try scripted.conn.pipeline();
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"b"});
    try pipe.add("SELECT count(*) FROM logs", .{});

    const results = try pipe.sync();
    try testing.expectEqual(@as(usize, 3), results.len);
    for (results) |result| try testing.expectEqual(pipeline_mod.PipelineStatus.OK, result.status);
    try testing.expectEqual(@as(u64, 1), results[0].affected);
}

test "postgrez: conn mock pipeline failure aborts the rest" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'E', "SERROR\x00C23505\x00Mduplicate key\x00\x00");
    // statement three is discarded by the server until Sync
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var pipe = try scripted.conn.pipeline();
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"c"});

    const results = try pipe.sync();
    try testing.expectEqual(pipeline_mod.PipelineStatus.OK, results[0].status);
    try testing.expectEqual(pipeline_mod.PipelineStatus.FAILED, results[1].status);
    try testing.expectEqual(pipeline_mod.PipelineStatus.ABORTED, results[2].status);
    try testing.expectEqual(sqlstate.SqlState.UNIQUE_VIOLATION, scripted.conn.lastServerError().state);
}

test "postgrez: conn mock pipeline sheds beyond max_pending_replies" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "INSERT 0 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    var config = TEST_CONFIG;
    config.max_pending_replies = 2;

    const scripted = try connectScripted(threaded.io(), script.items, config);
    defer scripted.deinit(threaded.io());

    var pipe = try scripted.conn.pipeline();
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"b"});
    try testing.expectError(error.PostgrezQueueFull, pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"c"}));

    const results = try pipe.sync();
    try testing.expectEqual(@as(usize, 2), results.len);
}

test "postgrez: conn mock copy in writes and finishes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, 'G', &.{ 0, 0, 2, 0, 0, 0, 0 });
    try appendServerMsg(testing.allocator, &script, 'C', "COPY 2\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var copy_in = try scripted.conn.copyIn("COPY metrics (ts, value) FROM STDIN");
    try copy_in.write("2026-07-14 10:00:00\t42\n");
    try copy_in.write("2026-07-14 10:00:01\t43\n");

    const copied = try copy_in.finish();
    try testing.expectEqual(@as(u64, 2), copied);
}

test "postgrez: conn mock copy out streams chunks" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, 'H', &.{ 0, 0, 2, 0, 0, 0, 0 });
    try appendServerMsg(testing.allocator, &script, 'd', "a\t1\n");
    try appendServerMsg(testing.allocator, &script, 'd', "b\t2\n");
    try appendServerMsg(testing.allocator, &script, 'c', "");
    try appendServerMsg(testing.allocator, &script, 'C', "COPY 2\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var copy_out = try scripted.conn.copyOut("COPY metrics TO STDOUT");
    defer copy_out.deinit();

    try testing.expectEqualStrings("a\t1\n", (try copy_out.next()).?);
    try testing.expectEqualStrings("b\t2\n", (try copy_out.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try copy_out.next());
}

test "postgrez: conn mock listen and nextNotification, pending then wire" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var note_payload: std.ArrayList(u8) = .empty;
    defer note_payload.deinit(testing.allocator);
    try note_payload.appendSlice(testing.allocator, &.{ 0, 0, 0, 42 });
    try note_payload.appendSlice(testing.allocator, "jobs\x00job-1\x00");

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    // LISTEN responses, a notification interleaved BEFORE ready: pending path
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'A', note_payload.items);
    try appendServerMsg(testing.allocator, &script, 'C', "LISTEN\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // a second notification arriving later: wire path
    var second_note: std.ArrayList(u8) = .empty;
    defer second_note.deinit(testing.allocator);
    try second_note.appendSlice(testing.allocator, &.{ 0, 0, 0, 43 });
    try second_note.appendSlice(testing.allocator, "jobs\x00job-2\x00");
    try appendServerMsg(testing.allocator, &script, 'A', second_note.items);

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    try scripted.conn.listen("jobs");

    const first = (try scripted.conn.nextNotification()).?;
    try testing.expectEqualStrings("jobs", first.channel);
    try testing.expectEqualStrings("job-1", first.payload);
    try testing.expectEqual(@as(i32, 42), first.pid);

    const second = (try scripted.conn.nextNotification()).?;
    try testing.expectEqualStrings("job-2", second.payload);
    try testing.expectEqual(@as(i32, 43), second.pid);
}

test "postgrez: conn mock tls PREFER continues cleartext on N" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.append(testing.allocator, 'N');
    try appendStartupOk(testing.allocator, &script, "18.0");

    var config = TEST_CONFIG;
    config.tls = .PREFER;

    const scripted = try connectScripted(threaded.io(), script.items, config);
    defer scripted.deinit(threaded.io());

    try testing.expectEqual(@as(?*tls_mod.TlsSession, null), scripted.conn.tls_session);
    try testing.expectEqual(@as(u32, 18), scripted.conn.server_version_major);
}

test "postgrez: conn mock tls REQUIRE fails on N" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.append(testing.allocator, 'N');
    try appendStartupOk(testing.allocator, &script, "18.0");

    var config = TEST_CONFIG;
    config.tls = .REQUIRE;

    try testing.expectError(error.PostgrezTlsRefused, connectScripted(threaded.io(), script.items, config));
}

test "postgrez: conn mock notification is captured while pumping" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendServerMsg(testing.allocator, &script, '1', "");
    var note: std.ArrayList(u8) = .empty;
    defer note.deinit(testing.allocator);
    try note.appendSlice(testing.allocator, &.{ 0, 0, 0, 42 });
    try note.appendSlice(testing.allocator, "jobs\x00job-42\x00");
    try appendServerMsg(testing.allocator, &script, 'A', note.items);
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "UPDATE 0\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());
    const conn = scripted.conn;

    _ = try conn.exec("UPDATE t SET x = 1", .{});

    try testing.expectEqual(@as(usize, 1), conn.pending_notifications.items.len);
    try testing.expectEqualStrings("jobs", conn.pending_notifications.items[0].channel);
    try testing.expectEqualStrings("job-42", conn.pending_notifications.items[0].payload);
}

/// Prepare script for a one-int8-param, one-int8-column statement.
fn appendPrepareScript(allocator: std.mem.Allocator, script: *std.ArrayList(u8)) !void {
    try appendServerMsg(allocator, script, '1', "");
    try appendServerMsg(allocator, script, 't', &.{ 0, 1, 0, 0, 0, 20 });

    var desc: std.ArrayList(u8) = .empty;
    defer desc.deinit(allocator);
    try desc.appendSlice(allocator, &.{ 0, 1 });
    try desc.appendSlice(allocator, "id\x00");
    try desc.appendSlice(allocator, &.{ 0, 0, 0, 1, 0, 1, 0, 0, 0, 20, 0, 8, 0xff, 0xff, 0xff, 0xff, 0, 0 });
    try appendServerMsg(allocator, script, 'T', desc.items);
    try appendServerMsg(allocator, script, 'Z', "I");
}

fn appendBinaryInt8Row(allocator: std.mem.Allocator, script: *std.ArrayList(u8), value: u8) !void {
    try appendServerMsg(allocator, script, 'D', &.{ 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, value });
}

test "postgrez: conn mock statement batch collects results in order" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendPrepareScript(testing.allocator, &script);
    // two executions in one batch, one ReadyForQuery at the end
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendBinaryInt8Row(testing.allocator, &script, 7);
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendBinaryInt8Row(testing.allocator, &script, 8);
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // the connection stays usable: a following exec succeeds
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "UPDATE 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var prepared = try scripted.conn.prepare("SELECT id FROM t WHERE id = $1");

    try prepared.sendRows(.{@as(i64, 7)});
    try prepared.sendRows(.{@as(i64, 8)});
    try testing.expectEqual(@as(usize, 2), scripted.conn.batch_pending);

    var first_result = try prepared.awaitRows();
    const first = (try first_result.next()).?;
    try testing.expectEqual(@as(i64, 7), try first.get(i64, 0));
    try testing.expectEqual(@as(?Row, null), try first_result.next());

    var second_result = try prepared.awaitRows();
    const second = (try second_result.next()).?;
    try testing.expectEqual(@as(i64, 8), try second.get(i64, 0));
    try testing.expectEqual(@as(?Row, null), try second_result.next());
    try testing.expectEqual(@as(usize, 0), scripted.conn.batch_pending);

    const affected = try scripted.conn.exec("UPDATE t SET x = 1", .{});
    try testing.expectEqual(@as(u64, 1), affected);

    // deinit sends Close on a scripted socket with no reply: skip it, the
    // conn teardown frees the statement resources
    prepared.arena.deinit();
}

test "postgrez: conn mock statement batch sheds beyond max_pending_replies" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendPrepareScript(testing.allocator, &script);
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendBinaryInt8Row(testing.allocator, &script, 7);
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendBinaryInt8Row(testing.allocator, &script, 8);
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    var config = TEST_CONFIG;
    config.max_pending_replies = 2;

    const scripted = try connectScripted(threaded.io(), script.items, config);
    defer scripted.deinit(threaded.io());

    var prepared = try scripted.conn.prepare("SELECT id FROM t WHERE id = $1");

    try prepared.sendRows(.{@as(i64, 7)});
    try prepared.sendRows(.{@as(i64, 8)});
    try testing.expectError(error.PostgrezQueueFull, prepared.sendRows(.{@as(i64, 9)}));

    var first_result = try prepared.awaitRows();
    first_result.deinit();
    var second_result = try prepared.awaitRows();
    second_result.deinit();
    try testing.expectError(error.PostgrezBatchEmpty, prepared.awaitRows());

    prepared.arena.deinit();
}

test "postgrez: conn mock statement batch failure aborts the rest" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try appendStartupOk(testing.allocator, &script, "18.0");
    try appendPrepareScript(testing.allocator, &script);
    // execution one succeeds, two fails, three is discarded until Sync
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendBinaryInt8Row(testing.allocator, &script, 7);
    try appendServerMsg(testing.allocator, &script, 'C', "SELECT 1\x00");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'E', "SERROR\x00C23505\x00Mduplicate key\x00\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");
    // the connection stays usable: a following exec succeeds
    try appendServerMsg(testing.allocator, &script, '1', "");
    try appendServerMsg(testing.allocator, &script, '2', "");
    try appendServerMsg(testing.allocator, &script, 'C', "UPDATE 1\x00");
    try appendServerMsg(testing.allocator, &script, 'Z', "I");

    const scripted = try connectScripted(threaded.io(), script.items, TEST_CONFIG);
    defer scripted.deinit(threaded.io());

    var prepared = try scripted.conn.prepare("SELECT id FROM t WHERE id = $1");

    try prepared.sendRows(.{@as(i64, 7)});
    try prepared.sendRows(.{@as(i64, 7)});
    try prepared.sendRows(.{@as(i64, 9)});

    var first_result = try prepared.awaitRows();
    const first = (try first_result.next()).?;
    try testing.expectEqual(@as(i64, 7), try first.get(i64, 0));
    try testing.expectEqual(@as(?Row, null), try first_result.next());

    var second_result = try prepared.awaitRows();
    try testing.expectError(error.PostgrezServerError, second_result.next());
    try testing.expectEqual(sqlstate.SqlState.UNIQUE_VIOLATION, scripted.conn.lastServerError().state);

    try testing.expectError(error.PostgrezBatchAborted, prepared.awaitRows());
    try testing.expectEqual(@as(usize, 0), scripted.conn.batch_pending);

    const affected = try scripted.conn.exec("UPDATE t SET x = 1", .{});
    try testing.expectEqual(@as(u64, 1), affected);

    prepared.arena.deinit();
}
