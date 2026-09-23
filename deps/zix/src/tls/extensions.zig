//! TLS 1.3 server extensions: ALPN (RFC 7301), SNI (RFC 6066), EncryptedExtensions (8446 4.3.1).
//!
//! Note:
//! - The server side of extension handling: select one ALPN protocol, validate SNI, and build
//!   the EncryptedExtensions message. Client-side extension parsing lives in handshake.zig.
//! - Verified against the RFC 8448 trace EncryptedExtensions in-file.

const std = @import("std");
const wire = @import("wire.zig");
const alert = @import("alert.zig");
const handshake = @import("handshake.zig");

const Reader = wire.Reader;
const Writer = wire.Writer;
const Alert = alert.Alert;
const ExtensionType = handshake.ExtensionType;

const server_name_type_host_name: u8 = 0;

/// ALPN protocol identifiers zix can negotiate over TLS (RFC 7301). The valid set is closed,
/// h3 is QUIC ALPN (a different layer).
pub const Alpn = enum(u8) {
    HTTP_1_1,
    H2,

    /// The wire ProtocolName bytes carried in the ALPN extension.
    pub fn token(self: Alpn) []const u8 {
        return switch (self) {
            .HTTP_1_1 => "http/1.1",
            .H2 => "h2",
        };
    }
};

// --------------------------------------------------------------- //

/// Select exactly one protocol from the client list, in server preference order (RFC 7301 3.2).
/// Null means no overlap, which the caller turns into a no_application_protocol alert.
pub fn negotiateAlpn(client_protocols: []const u8, prefs: []const Alpn) ?Alpn {
    for (prefs) |candidate| {
        var r = Reader{ .buf = client_protocols };
        const list_len = r.readU16() catch return null;
        const list = r.readBytes(list_len) catch return null;

        var lr = Reader{ .buf = list };
        while (lr.remaining() >= 1) {
            const name_len = lr.readU8() catch break;
            const name = lr.readBytes(name_len) catch break;
            if (std.mem.eql(u8, name, candidate.token())) return candidate;
        }
    }

    return null;
}

/// Reject a ServerNameList carrying more than one host_name (RFC 6066 3, MUST NOT).
fn validateSni(server_name_list: []const u8) ?Alert {
    var r = Reader{ .buf = server_name_list };
    const list_len = r.readU16() catch return .DECODE_ERROR;
    const list = r.readBytes(list_len) catch return .DECODE_ERROR;

    var lr = Reader{ .buf = list };
    var host_names: usize = 0;
    while (lr.remaining() >= 3) {
        const name_type = lr.readU8() catch return .DECODE_ERROR;
        const name_len = lr.readU16() catch return .DECODE_ERROR;
        _ = lr.readBytes(name_len) catch return .DECODE_ERROR;
        if (name_type == server_name_type_host_name) host_names += 1;
    }

    if (host_names > 1) return .ILLEGAL_PARAMETER;

    return null;
}

// --------------------------------------------------------------- //

/// What to emit in EncryptedExtensions (RFC 8446 4.3.1). Each field is optional, emitted only
/// when present, and only extensions the client offered may be set (4.3.1 MUST NOT).
pub const EncryptedExtensionsOptions = struct {
    groups_list: ?[]const u8 = null,
    record_size_limit: ?u16 = null,
    alpn_selected: ?Alpn = null,
    server_name_ack: bool = false,
};

/// Build the EncryptedExtensions message into `buf`, returning the wire slice.
pub fn buildEncryptedExtensions(buf: []u8, opts: EncryptedExtensionsOptions) []const u8 {
    var w = Writer{ .buf = buf };

    w.writeU8(@intFromEnum(handshake.HandshakeType.ENCRYPTED_EXTENSIONS));
    const header = w.placeU24();

    const extensions = w.placeU16();

    if (opts.groups_list) |groups| {
        w.writeU16(@intFromEnum(ExtensionType.SUPPORTED_GROUPS));
        const ext = w.placeU16();
        const list = w.placeU16();
        w.writeBytes(groups);
        w.patchU16(list);
        w.patchU16(ext);
    }

    if (opts.record_size_limit) |limit| {
        w.writeU16(@intFromEnum(ExtensionType.RECORD_SIZE_LIMIT));
        w.writeU16(2);
        w.writeU16(limit);
    }

    if (opts.alpn_selected) |protocol| {
        w.writeU16(@intFromEnum(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION));
        const ext = w.placeU16();
        const list = w.placeU16();
        const token = protocol.token();
        w.writeU8(@intCast(token.len));
        w.writeBytes(token);
        w.patchU16(list);
        w.patchU16(ext);
    }

    if (opts.server_name_ack) {
        w.writeU16(@intFromEnum(ExtensionType.SERVER_NAME));
        w.writeU16(0); // empty acknowledgement (RFC 6066 3)
    }

    w.patchU16(extensions);
    w.patchU24(header);

    return w.slice();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: extensions, EncryptedExtensions byte-exact vs RFC 8448" {
    var groups: [18]u8 = undefined;
    _ = try std.fmt.hexToBytes(&groups, "001d00170018001901000101010201030104");

    var expected: [40]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000");

    var buf: [256]u8 = undefined;
    const ee = buildEncryptedExtensions(&buf, .{ .groups_list = &groups, .record_size_limit = 0x4001, .server_name_ack = true });
    try std.testing.expectEqualSlices(u8, &expected, ee);
}

test "zix tls: extensions, ALPN negotiate + emit + no overlap" {
    var client_alpn: [14]u8 = undefined; // ["h2","http/1.1"]
    _ = try std.fmt.hexToBytes(&client_alpn, "000c02683208687474702f312e31");

    const prefs = [_]Alpn{ .H2, .HTTP_1_1 };
    try std.testing.expectEqual(Alpn.H2, negotiateAlpn(&client_alpn, &prefs).?);

    var buf: [64]u8 = undefined;
    const ee = buildEncryptedExtensions(&buf, .{ .alpn_selected = .H2 });
    var want_alpn: [9]u8 = undefined; // 00 10 00 05 00 03 02 68 32
    _ = try std.fmt.hexToBytes(&want_alpn, "001000050003026832");
    try std.testing.expectEqualSlices(u8, &want_alpn, ee[6..]);

    var no_overlap: [9]u8 = undefined; // ["spdy/3"]
    _ = try std.fmt.hexToBytes(&no_overlap, "000706737064792f33");
    try std.testing.expect(negotiateAlpn(&no_overlap, &prefs) == null);
}

test "zix tls: extensions, SNI single ok + duplicate rejected" {
    var single: [11]u8 = undefined;
    _ = try std.fmt.hexToBytes(&single, "0009000006736572766572");
    try std.testing.expect(validateSni(&single) == null);

    var dup: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dup, "0012000006736572766572000006736572766572");
    try std.testing.expect(validateSni(&dup) == .ILLEGAL_PARAMETER);
}
