//! zix grpc https serve path (gRPC over TLS 1.3 / 1.2, RFC 8446 + 7540 + 7301 ALPN).
//!
//! Note:
//! - Gated on config.tls (a *Tls.Context). An accept loop hands each connection to its own worker
//!   thread, which runs the shared h2-over-TLS terminator (../../tls/h2_terminator.zig): the
//!   handshake negotiates ALPN h2, then the inline-mux driver below drives the resumable gRPC h2
//!   state machine (mux.grpcMuxProcessRing) directly over the decrypted stream. The mux's frames are
//!   sealed into TLS records through a thread-local hook on frame.writeAllFD plus the staged reply
//!   cork, so there is NO socketpair and NO second thread per connection. This is what lets the gRPC
//!   TLS path scale to high connection counts instead of livelocking on a per-connection socketpair.
//! - The cleartext dispatch models (ASYNC / EPOLL / URING) are untouched. https is a
//!   separate path on its own perf band.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const fd_io = @import("../../../utils/fd_io.zig");
const core = @import("core.zig");
const Logger = @import("../../../logger/logger.zig").Logger;
const mux = @import("mux.zig");
const GrpcServerConfig = @import("config.zig").GrpcServerConfig;
const common = @import("dispatch/common.zig");
const terminator = @import("../../tls/h2_terminator.zig");
const Tls = @import("../../../tls/Tls.zig");
const frame = @import("../frame.zig");

/// The most plaintext one TLS record carries (RFC 8446 5.1). The mux's reply is sealed in chunks of
/// at most this, so the seal buffer holds one record (plaintext + AEAD + content-type + header).
const max_plaintext: usize = 16 * 1024;

/// AEAD tag, inner content-type, and record header overhead added over one
/// record's plaintext when sizing the seal buffer.
const seal_overhead: usize = 1024;

/// Drive the resumable gRPC h2 mux inline over a decrypted TLS connection: read a record, decrypt it,
/// feed the plaintext to the mux, and seal the staged reply back into records. No socketpair, no
/// second thread. Generic over the TLS connection type (1.3 or 1.2).
fn runInlineGrpcMux(comptime RouterType: type, opts: core.GrpcServeOpts, fd: posix.fd_t, conn: anytype, record_buf: []u8, io: std.Io) void {
    const mux_conn = mux.GrpcMuxConn.init(fd, opts, io) orelse return;
    defer mux_conn.deinit();

    // The mux's reply (staged cork + any direct frame.writeAllFD) routes through this hook, which
    // seals the plaintext into TLS records and writes them to the socket.
    const Encryptor = struct {
        conn: @TypeOf(conn),
        fd: posix.fd_t,
        plain: [max_plaintext]u8 = undefined,
        plain_len: usize = 0,
        seal: [max_plaintext + seal_overhead]u8 = undefined,
        failed: bool = false,

        fn flush(self: *@This()) void {
            if (self.plain_len == 0 or self.failed) return;

            const sealed = self.conn.writeAppData(self.plain[0..self.plain_len], &self.seal);
            terminator.writeAllFD(self.fd, sealed) catch {
                self.failed = true;
            };
            self.plain_len = 0;
        }

        fn append(self: *@This(), bytes: []const u8) void {
            var rest = bytes;
            while (rest.len > 0 and !self.failed) {
                if (self.plain_len == self.plain.len) self.flush();
                if (self.failed) return;

                const n = @min(rest.len, self.plain.len - self.plain_len);
                @memcpy(self.plain[self.plain_len..][0..n], rest[0..n]);
                self.plain_len += n;
                rest = rest[n..];
            }
        }
    };

    var enc = Encryptor{ .conn = conn, .fd = fd };

    const hook = struct {
        fn call(ctx: *anyopaque, bytes: []const u8) void {
            const e: *Encryptor = @ptrCast(@alignCast(ctx));
            e.append(bytes);
        }
    }.call;

    frame.write_hook = hook;
    frame.write_hook_ctx = &enc;
    defer {
        frame.write_hook = null;
        frame.write_hook_ctx = null;
    }

    var decrypt: [max_plaintext]u8 = undefined;
    while (true) {
        // Compact the read accumulator before the next record (mirrors the URING armRecv compaction).
        if (mux_conn.rstart == mux_conn.rend) {
            mux_conn.rstart = 0;
            mux_conn.rend = 0;
        } else if (mux_conn.rend == mux_conn.rbuf.len) {
            const n = mux_conn.rend - mux_conn.rstart;
            std.mem.copyForwards(u8, mux_conn.rbuf[0..n], mux_conn.rbuf[mux_conn.rstart..mux_conn.rend]);
            mux_conn.rstart = 0;
            mux_conn.rend = n;
        }

        if (mux_conn.rend == mux_conn.rbuf.len) break; // a single frame larger than the buffer

        const rec = terminator.readRecord(fd, record_buf) catch {
            // The peer went away. If it left a request part way through, say so with a GOAWAY
            // instead of a bare close, exactly as the cleartext models do. The write hook is still
            // installed, so the frame seals into a record on its way out.
            _ = mux.stageHangupGoaway(mux_conn);
            mux_conn.flushStage();
            enc.flush();

            break;
        };
        if (rec.content_type == terminator.content_type_change_cipher_spec) continue;
        if (rec.content_type != terminator.content_type_application_data) break; // alert / close_notify

        const plain = conn.readAppData(rec.full, &decrypt) catch break;

        // Feed the decrypted plaintext into the mux read accumulator (the record fits post-compaction).
        if (plain.len > mux_conn.rbuf.len - mux_conn.rend) break;
        @memcpy(mux_conn.rbuf[mux_conn.rend..][0..plain.len], plain);
        mux_conn.rend += plain.len;

        const outcome = mux.grpcMuxProcessRing(RouterType, mux_conn);
        mux_conn.flushStage(); // staged reply -> frame.writeAllFD -> hook -> enc
        enc.flush();
        if (enc.failed or outcome == .close) break;
    }

    // close_notify so the client finalizes the connection cleanly.
    var close_buf: [64]u8 = undefined;
    terminator.writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};
}

/// Terminator driver: drives the resumable gRPC mux inline over the decrypted stream (no socketpair).
fn MuxDriver(comptime RouterType: type) type {
    return struct {
        opts: core.GrpcServeOpts,
        io: std.Io,

        pub fn drive(self: @This(), fd: posix.fd_t, conn: anytype, record_buf: []u8) void {
            runInlineGrpcMux(RouterType, self.opts, fd, conn, record_buf, self.io);
        }
    };
}

/// Per-connection TLS worker: terminate TLS and serve the inline mux, then close the socket. One
/// thread per connection so the accept loop never blocks in the terminator.
fn TlsConn(comptime RouterType: type) type {
    return struct {
        const Ctx = struct {
            fd: posix.fd_t,
            opts: core.GrpcServeOpts,
            io: std.Io,
            ctx: *const Tls.Context,
            /// The server's logger, borrowed, so a handshake that fails is not simply a closed socket.
            logger: ?*Logger = null,
        };

        fn entry(conn_ctx: Ctx) void {
            defer fd_io.close(conn_ctx.fd);

            // A failed handshake used to close the socket with nothing said. It files at DEBUG
            // rather than WARN because one remote peer drives it, and a scanner would flood.
            terminator.serveConnTls(conn_ctx.fd, conn_ctx.ctx, conn_ctx.io, MuxDriver(RouterType){ .opts = conn_ctx.opts, .io = conn_ctx.io }) catch |err| {
                if (conn_ctx.logger) |lg| lg.system(.DEBUG, "grpc", "tls connection ended: {s}", .{@errorName(err)});
            };
        }
    };
}

/// Listen and serve gRPC over TLS. The cert / key / policy are loaded and validated once in the
/// context (config.tls). Each accepted connection is handed to its own worker thread. The Router
/// type is baked in at compile time, so the driver is generated per route table.
pub fn runTls(comptime RouterType: type, config: GrpcServerConfig) !void {
    const io = config.io;
    const ctx = config.tls.?;

    const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
    var srv = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = config.kernel_backlog });

    common.logSystem(config, .INFO, "listening on {s}:{d} (grpc, TLS)", .{ config.ip, config.port });

    const opts = common.serveOpts(config);

    while (true) {
        const stream = srv.accept(io) catch continue;
        const conn_fd = stream.socket.handle;

        const worker = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, TlsConn(RouterType).entry, .{
            TlsConn(RouterType).Ctx{ .fd = conn_fd, .opts = opts, .io = io, .ctx = ctx, .logger = config.logger },
        }) catch {
            // Spawn failed (thread / pids limit under extreme load): drop this connection and keep
            // accepting. Serving inline here would block the accept loop for the connection's whole
            // lifetime, wedging every other pending connection. The client retries the dropped one.
            fd_io.close(conn_fd);

            continue;
        };

        worker.detach();
    }
}
