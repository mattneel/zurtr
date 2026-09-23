//! zixer site runtime: the bound listener a started site owns, and the cleartext companion beside it

const std = @import("std");

const acme_listener = @import("acme_listener.zig");
const bind_options = @import("bind_options.zig");
const h3_edge = @import("h3_edge.zig");
const port_probe = @import("port_probe.zig");
const site_cfg = @import("site_cfg.zig");
const site_serve = @import("site_serve.zig");
const udp_forward = @import("udp_forward.zig");

/// The port the CA validates http-01 on (rfc 8555 8.3).
pub const ACME_HTTP_PORT: u16 = 80;

/// One started site inside the daemon.
///
/// Note:
/// - An http1, http2, or grpc site with upstreams or public_dir serves
///   the edge loop, an http3 site with either serves the quic edge, and a
///   udp site with upstreams serves the per-flow forward (phases 3, 4, 7,
///   8, 9, and 10). Anything else binds and holds its socket, so the port
///   is owned and a collision surfaces at start time.
/// - A TLS site with acme keys or force_https also owns the port 80
///   companion listener, see companionPort.
pub const SiteRuntime = struct {
    name: []const u8,
    engine: site_cfg.Engine,
    port: u16,
    listener: Listener,
    /// The bound cleartext companion, held by a TLS site with acme keys,
    /// force_https, or both.
    challenge: ?*acme_listener.State = null,

    /// What the site holds: a serving proxy edge, a serving udp forward,
    /// or the bare bound socket (tcp engines listen, udp engines bind a
    /// datagram socket).
    const Listener = union(enum) {
        proxy_edge: *site_serve.ServeState,
        quic_edge: *h3_edge.EdgeState,
        udp_forward: *udp_forward.ForwardState,
        tcp: std.Io.net.Server,
        udp: std.Io.net.Socket,
    };

    /// Bind the listener for one validated site cfg.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the duped name, long-lived)
    /// io - std.Io
    /// name - []const u8 (site file name, copied)
    /// cfg - site_cfg.SiteCfg (must have passed validation: engine and port set)
    /// options - bind_options.BindOptions (the main.cfg values a bind needs)
    ///
    /// Return:
    /// - SiteRuntime holding the bound socket
    /// - error.ZixerSiteCfgIncomplete when engine, port, or ip did not survive parse
    /// - error.AddressInUse when another listener owns ip:port
    /// - error.ZixerChallengePortInUse when another listener owns the acme companion port
    pub fn bind(allocator: std.mem.Allocator, io: std.Io, name: []const u8, cfg: site_cfg.SiteCfg, options: bind_options.BindOptions) !SiteRuntime {
        const kernel_backlog = options.kernel_backlog;
        const engine = cfg.engine orelse return error.ZixerSiteCfgIncomplete;
        const port = cfg.port orelse return error.ZixerSiteCfgIncomplete;
        const addr = std.Io.net.IpAddress.parse(cfg.ip, port) catch return error.ZixerSiteCfgIncomplete;

        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);

        // Tcp listens with reuse_address like every zix engine: without it a
        // restart right after live traffic hits TIME_WAIT and fails the
        // rebind. Std pairs that flag with SO_REUSEPORT on posix, so the
        // kernel reports no collision at all here: a second daemon would join
        // the port and take half its traffic. Sites inside this daemon are the
        // registry's check, an owner in another process is the probe's. Udp
        // has no TIME_WAIT, so it keeps the strict bind and needs neither.
        var listener: Listener = switch (engine) {
            .HTTP1, .HTTP2, .GRPC => blk: {
                if (port_probe.isTaken(io, addr)) return error.AddressInUse;

                var server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = kernel_backlog });

                if ((engine == .HTTP1 or engine == .HTTP2 or engine == .GRPC) and (cfg.upstreams.len > 0 or cfg.public_dir != null)) {
                    const state = site_serve.ServeState.create(allocator, io, server, &cfg, port, options) catch |err| {
                        server.deinit(io);
                        return err;
                    };

                    break :blk .{ .proxy_edge = state };
                }

                break :blk .{ .tcp = server };
            },
            .HTTP3, .UDP => blk: {
                const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });

                if (engine == .UDP and cfg.upstreams.len > 0) {
                    const state = udp_forward.ForwardState.create(allocator, io, socket, &cfg, port) catch |err| {
                        socket.close(io);
                        return err;
                    };

                    break :blk .{ .udp_forward = state };
                }

                if (engine == .HTTP3 and (cfg.upstreams.len > 0 or cfg.public_dir != null)) {
                    const state = h3_edge.EdgeState.create(allocator, io, socket, &cfg, port, options) catch |err| {
                        socket.close(io);
                        return err;
                    };

                    break :blk .{ .quic_edge = state };
                }

                break :blk .{ .udp = socket };
            },
        };
        errdefer closeListener(&listener, io);

        // A TLS site that asked for acme, force_https, or both answers on
        // port 80 beside its main listener. A bind failure (port taken, no
        // privilege) fails the whole start: a silent half-start would break
        // renewal, and would leave cleartext clients with no answer at all.
        var challenge: ?*acme_listener.State = null;
        if (companionPort(&cfg)) |challenge_port| {
            const challenge_addr = std.Io.net.IpAddress.parse(cfg.ip, challenge_port) catch return error.ZixerSiteCfgIncomplete;
            if (port_probe.isTaken(io, challenge_addr)) return error.ZixerChallengePortInUse;

            const challenge_server = try challenge_addr.listen(io, .{ .reuse_address = true, .kernel_backlog = kernel_backlog });

            challenge = acme_listener.State.create(allocator, io, challenge_server, cfg.acme_webroot, cfg.acme_proxy, cfg.ip, challenge_port, port, cfg.redirect_host) catch |err| {
                var orphan = challenge_server;
                orphan.deinit(io);
                return err;
            };
        }

        return .{ .name = owned_name, .engine = engine, .port = port, .listener = listener, .challenge = challenge };
    }

    /// Stop any serve loop, close the listeners, release the name.
    pub fn unbind(runtime: *SiteRuntime, allocator: std.mem.Allocator, io: std.Io) void {
        if (runtime.challenge) |state| state.shutdown();
        closeListener(&runtime.listener, io);

        allocator.free(runtime.name);
    }

    /// Whether this started site holds the given port (its own listener or
    /// its acme companion). The daemon registry checks collisions with it.
    pub fn ownsPort(runtime: *const SiteRuntime, port: u16) bool {
        if (runtime.port == port) return true;
        if (runtime.challenge) |state| return state.port == port;

        return false;
    }
};

fn closeListener(listener: *SiteRuntime.Listener, io: std.Io) void {
    switch (listener.*) {
        .proxy_edge => |state| state.shutdown(),
        .quic_edge => |state| state.shutdown(),
        .udp_forward => |state| state.shutdown(),
        .tcp => |*server| server.deinit(io),
        .udp => |socket| socket.close(io),
    }
}

/// The cleartext companion port a validated cfg calls for: port 80 on a TLS
/// site that has acme keys, force_https, or both.
///
/// Note:
/// - Two jobs share one listener because both need the same thing, a
///   cleartext ear on the port a CA and a browser each reach first. acme
///   needs it to answer the challenge path (rfc 8555 8.3 allows port 80
///   only), force_https needs it to redirect. A site that asks for both gets
///   one listener doing both.
/// - A cleartext site never gets one: it answers the challenge path on its
///   own listener, and it has no https origin to redirect to.
/// - A site already on port 80 needs no companion either, it is the port.
///
/// Param:
/// cfg - *const site_cfg.SiteCfg (already validated)
///
/// Return:
/// - u16 the companion port to bind
/// - null when this site needs none
pub fn companionPort(cfg: *const site_cfg.SiteCfg) ?u16 {
    if (!cfg.tls) return null;

    const wants_acme = cfg.acme_webroot != null or cfg.acme_proxy != null;
    if (!wants_acme and !cfg.force_https) return null;
    if ((cfg.port orelse 0) == ACME_HTTP_PORT) return null;

    return ACME_HTTP_PORT;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: site runtime, incomplete cfg refuses to bind" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const no_engine = site_cfg.SiteCfg{ .port = 18860 };
    try std.testing.expectError(error.ZixerSiteCfgIncomplete, SiteRuntime.bind(std.testing.allocator, io, "a.cfg", no_engine, .{ .kernel_backlog = 64 }));

    const no_port = site_cfg.SiteCfg{ .engine = .HTTP1 };
    try std.testing.expectError(error.ZixerSiteCfgIncomplete, SiteRuntime.bind(std.testing.allocator, io, "a.cfg", no_port, .{ .kernel_backlog = 64 }));
}

test "zix zixer: site runtime, tcp bind rebinds cleanly after unbind" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18861 };

    var first = try SiteRuntime.bind(std.testing.allocator, io, "a.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expectEqualStrings("a.cfg", first.name);
    try std.testing.expectEqual(@as(u16, 18861), first.port);
    try std.testing.expect(first.listener == .tcp);

    first.unbind(std.testing.allocator, io);

    // reuse_address makes the rebind immediate: the probe only refuses a port
    // a listener still answers on, never one left in TIME_WAIT.
    var again = try SiteRuntime.bind(std.testing.allocator, io, "a.cfg", cfg, .{ .kernel_backlog = 64 });
    again.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, a tcp port a live listener owns is refused" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18934 };

    var first = try SiteRuntime.bind(std.testing.allocator, io, "a.cfg", cfg, .{ .kernel_backlog = 64 });

    // Without the probe this second bind succeeds: reuse_address carries
    // SO_REUSEPORT, so the kernel hands the port to both and splits the
    // traffic. The collision has to be refused here or it surfaces on a
    // client as a reply that never arrives.
    try std.testing.expectError(error.AddressInUse, SiteRuntime.bind(std.testing.allocator, io, "b.cfg", cfg, .{ .kernel_backlog = 64 }));

    first.unbind(std.testing.allocator, io);

    var rebound = try SiteRuntime.bind(std.testing.allocator, io, "b.cfg", cfg, .{ .kernel_backlog = 64 });
    rebound.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, udp engine binds a datagram socket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .UDP, .ip = "127.0.0.1", .port = 18862 };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "media.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .udp);

    try std.testing.expectError(error.AddressInUse, SiteRuntime.bind(std.testing.allocator, io, "b.cfg", cfg, .{ .kernel_backlog = 64 }));

    runtime.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, http1 with upstreams serves and unbind frees the port" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18859 }};
    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18872, .upstreams = &upstreams };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "proxy.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .proxy_edge);

    runtime.unbind(std.testing.allocator, io);

    var rebound = try SiteRuntime.bind(std.testing.allocator, io, "proxy.cfg", cfg, .{ .kernel_backlog = 64 });
    rebound.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, http1 static-only site serves without upstreams" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18882, .public_dir = "/var/www/pages" };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "static.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .proxy_edge);

    runtime.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, udp site with upstreams serves the forward" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18839 }};
    const cfg = site_cfg.SiteCfg{ .engine = .UDP, .ip = "127.0.0.1", .port = 18888, .upstreams = &upstreams };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "media.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .udp_forward);

    runtime.unbind(std.testing.allocator, io);

    // Udp binds strict, so a clean rebind proves unbind released the port.
    var rebound = try SiteRuntime.bind(std.testing.allocator, io, "media.cfg", cfg, .{ .kernel_backlog = 64 });
    rebound.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, http3 engine without planes only binds" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .HTTP3, .ip = "127.0.0.1", .port = 18863 };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "pages.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .udp);

    runtime.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, http3 site with upstreams serves the quic edge" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: site runtime quic edge test needs linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18801 }};
    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP3,
        .ip = "127.0.0.1",
        .port = 18800,
        .tls = true,
        .tls_cert = "examples/certs/ecdsa_p256_cert.pem",
        .tls_key = "examples/certs/ecdsa_p256_key.pem",
        .upstreams = &upstreams,
    };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "pages_h3.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.listener == .quic_edge);

    runtime.unbind(std.testing.allocator, io);

    // Udp binds strict, so a clean rebind proves unbind released the port.
    var rebound = try SiteRuntime.bind(std.testing.allocator, io, "pages_h3.cfg", cfg, .{ .kernel_backlog = 64 });
    rebound.unbind(std.testing.allocator, io);
}

test "zix zixer: site runtime, companion port only for tls acme sites off 80" {
    const tls_acme = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 443, .tls = true, .acme_webroot = "/var/www/acme" };
    try std.testing.expectEqual(@as(?u16, 80), companionPort(&tls_acme));

    const tls_relay = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 443, .tls = true, .acme_proxy = .{ .host = "127.0.0.1", .port = 9080 } };
    try std.testing.expectEqual(@as(?u16, 80), companionPort(&tls_relay));

    const tls_only = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 443, .tls = true };
    try std.testing.expectEqual(@as(?u16, null), companionPort(&tls_only));

    const cleartext = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 80, .acme_webroot = "/var/www/acme" };
    try std.testing.expectEqual(@as(?u16, null), companionPort(&cleartext));

    const tls_on_80 = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 80, .tls = true, .acme_webroot = "/var/www/acme" };
    try std.testing.expectEqual(@as(?u16, null), companionPort(&tls_on_80));
}

test "zix zixer: site runtime, force_https earns the companion port on its own" {
    // No acme anywhere, so the companion can only be the redirect asking for
    // it.
    const forced = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 443, .tls = true, .force_https = true };
    try std.testing.expectEqual(@as(?u16, 80), companionPort(&forced));

    // Both jobs asked for, still one listener.
    const forced_with_acme = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 443, .tls = true, .force_https = true, .acme_webroot = "/var/www/acme" };
    try std.testing.expectEqual(@as(?u16, 80), companionPort(&forced_with_acme));

    // A quic site reaches its clients over tcp first, so it earns one too.
    const quic = site_cfg.SiteCfg{ .engine = .HTTP3, .port = 443, .tls = true, .force_https = true };
    try std.testing.expectEqual(@as(?u16, 80), companionPort(&quic));

    // Nothing to redirect to, so nothing to bind.
    const cleartext = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 8080, .force_https = true };
    try std.testing.expectEqual(@as(?u16, null), companionPort(&cleartext));

    // Already the port a browser reaches first.
    const on_80 = site_cfg.SiteCfg{ .engine = .HTTP1, .port = 80, .tls = true, .force_https = true };
    try std.testing.expectEqual(@as(?u16, null), companionPort(&on_80));
}

test "zix zixer: site runtime, owns port covers the main listener" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{ .engine = .HTTP1, .ip = "127.0.0.1", .port = 18896 };

    var runtime = try SiteRuntime.bind(std.testing.allocator, io, "own.cfg", cfg, .{ .kernel_backlog = 64 });
    try std.testing.expect(runtime.ownsPort(18896));
    try std.testing.expect(!runtime.ownsPort(80));
    try std.testing.expect(runtime.challenge == null);

    runtime.unbind(std.testing.allocator, io);
}

/// True when this process may bind the privileged http-01 port. Probed
/// with raw syscalls: a failing privileged bind through std prints the
/// unexpected-errno trace in debug builds, the probe keeps unprivileged
/// runs silent.
fn canBindPort80() bool {
    const linux = std.os.linux;

    const fd_raw = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (@as(isize, @bitCast(fd_raw)) < 0) return false;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, 80),
        .addr = std.mem.nativeToBig(u32, 0x7F00_0001),
    };

    return linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)) == 0;
}

test "zix zixer: site runtime, tls acme site binds the port 80 companion" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    if (!canBindPort80()) {
        std.log.info("binding the privileged port 80 needs a capability this run lacks, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = site_cfg.SiteCfg{
        .engine = .HTTP1,
        .ip = "127.0.0.1",
        .port = 18897,
        .tls = true,
        .tls_cert = "examples/certs/ecdsa_p256_cert.pem",
        .tls_key = "examples/certs/ecdsa_p256_key.pem",
        .acme_webroot = "/var/www/acme",
        .public_dir = "/var/www/pages",
    };

    var runtime = SiteRuntime.bind(std.testing.allocator, io, "tls.cfg", cfg, .{ .kernel_backlog = 64 }) catch |err| {
        // port 80 is privileged: without the capability (or as non-root)
        // the companion bind cannot be exercised, skip explicitly. The
        // EACCES from a privileged bind surfaces as Unexpected through the
        // std listen error mapping.
        if (err == error.AccessDenied or err == error.PermissionDenied or err == error.AddressInUse or err == error.Unexpected) {
            std.log.info("binding the privileged port 80 needs a capability this run lacks, test skipped", .{});
            return;
        }

        return err;
    };

    try std.testing.expect(runtime.challenge != null);
    try std.testing.expect(runtime.ownsPort(18897));
    try std.testing.expect(runtime.ownsPort(80));

    runtime.unbind(std.testing.allocator, io);
}
