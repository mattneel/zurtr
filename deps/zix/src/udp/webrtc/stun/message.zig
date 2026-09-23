//! zix STUN message codec (RFC 8489 5 / 14).
//!
//! What:
//! - The wire container every STUN-based layer rides on: a 20-byte header (class, method, magic
//!   cookie, transaction id) followed by zero or more type-length-value attributes, each padded
//!   out to a 4-byte boundary.
//! - `parse` validates the entire attribute region up front, so walking a parsed message cannot
//!   fail and callers never repeat bounds checks.
//! - Carries the three attribute codecs that cover a prefix of the message rather than standing
//!   alone: XOR-MAPPED-ADDRESS (14.2), MESSAGE-INTEGRITY (14.5), and FINGERPRINT (14.7).
//!
//! Note:
//! - This file is the container only. Which class may arrive, and what a server answers with, is
//!   the transaction's concern (see binding.zig, and ice/lite.zig for connectivity checks).
//! - Padding is required, including on the last attribute, because the header length counts it.
//!   A message whose final attribute drops its padding is rejected as malformed.

const std = @import("std");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const IpAddress = std.Io.net.IpAddress;

/// Fixed value in every STUN header (RFC 8489 5), and the XOR mask for the mapped address.
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// Size of the STUN header. The header length field counts everything after these bytes.
pub const HEADER_LEN: usize = 20;

/// Size of the transaction id, 96 bits (RFC 8489 5).
pub const TRANSACTION_ID_LEN: usize = 12;

/// Size of a TLV attribute header: 16-bit type plus 16-bit length (RFC 8489 14).
pub const ATTRIBUTE_HEADER_LEN: usize = 4;

/// Size of a FINGERPRINT attribute on the wire: the TLV header plus a 4-byte CRC.
pub const FINGERPRINT_LEN: usize = ATTRIBUTE_HEADER_LEN + 4;

/// Size of a MESSAGE-INTEGRITY value, one HMAC-SHA1 output (RFC 8489 14.5).
pub const MESSAGE_INTEGRITY_VALUE_LEN: usize = HmacSha1.mac_length;

/// Size of a MESSAGE-INTEGRITY attribute on the wire: the TLV header plus the HMAC.
pub const MESSAGE_INTEGRITY_LEN: usize = ATTRIBUTE_HEADER_LEN + MESSAGE_INTEGRITY_VALUE_LEN;

/// XOR mask applied to the CRC-32 that FINGERPRINT carries (RFC 8489 14.7). It keeps a plain
/// CRC-32 from another protocol reading as a valid STUN fingerprint.
const FINGERPRINT_XOR: u32 = 0x5354554E;

/// First attribute type of the comprehension-optional range (RFC 8489 14).
const COMPREHENSION_OPTIONAL_MIN: u16 = 0x8000;

/// Address family byte inside a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value (RFC 8489 14.1).
const FAMILY_IP4: u8 = 0x01;
const FAMILY_IP6: u8 = 0x02;

/// Message class, the 2 bits interleaved into the message type field (RFC 8489 5).
pub const Class = enum(u2) {
    REQUEST = 0b00,
    INDICATION = 0b01,
    SUCCESS_RESPONSE = 0b10,
    ERROR_RESPONSE = 0b11,
};

/// Message method. RFC 8489 defines Binding alone, any other value decodes as an unnamed tag so
/// an extension method (TURN Allocate, for one) round-trips without being understood.
pub const Method = enum(u12) {
    BINDING = 0x001,
    _,
};

/// Attribute type registry (RFC 8489 18.3, plus the ICE types RFC 8445 16.1 registers). A type
/// below 0x8000 is comprehension-required: a receiver that does not understand it cannot process
/// the message and must answer 420.
///
/// Note:
/// - The four ICE types are here rather than in ice/, because the registry is one namespace and a
///   type number understood by one file has to be understood by every file that scans for unknown
///   attributes. Their values are decoded in ice/check.zig, which is where they mean something.
pub const AttributeType = enum(u16) {
    MAPPED_ADDRESS = 0x0001,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    ERROR_CODE = 0x0009,
    UNKNOWN_ATTRIBUTES = 0x000A,
    REALM = 0x0014,
    NONCE = 0x0015,
    MESSAGE_INTEGRITY_SHA256 = 0x001C,
    PASSWORD_ALGORITHM = 0x001D,
    USERHASH = 0x001E,
    XOR_MAPPED_ADDRESS = 0x0020,
    PRIORITY = 0x0024,
    USE_CANDIDATE = 0x0025,
    PASSWORD_ALGORITHMS = 0x8002,
    ALTERNATE_DOMAIN = 0x8003,
    SOFTWARE = 0x8022,
    ALTERNATE_SERVER = 0x8023,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLED = 0x8029,
    ICE_CONTROLLING = 0x802A,
    _,
};

/// Whether a FINGERPRINT attribute was present, and if so whether its CRC matched.
pub const FingerprintState = enum { ABSENT, VALID, INVALID };

/// Whether a MESSAGE-INTEGRITY attribute was present, and if so whether its HMAC matched the key.
pub const IntegrityState = enum { ABSENT, VALID, INVALID };

/// One attribute of a parsed message.
///
/// Note:
/// - value excludes the padding bytes, offset includes the header, so `bytes[offset]` is the
///   first byte of the attribute type. FINGERPRINT needs that offset to know what the CRC covers.
pub const Attribute = struct {
    kind: AttributeType,
    value: []const u8,
    offset: usize,
};

/// Why a datagram is not a usable STUN message.
///
/// Note:
/// - NotStun means the bytes fail a cheap identity check (top 2 bits, magic cookie), which is the
///   expected outcome when another protocol shares the port. The rest mean it looked like STUN
///   but did not hold together.
pub const ParseError = error{
    ZixTruncated,
    ZixNotStun,
    ZixBadLength,
    ZixBadAttribute,
};

/// A validated STUN message. Borrows the datagram, it copies nothing.
pub const Message = struct {
    class: Class,
    method: Method,
    transaction_id: [TRANSACTION_ID_LEN]u8,
    /// The whole message, header included. FINGERPRINT covers a prefix of this.
    bytes: []const u8,

    /// Walk the attributes in wire order.
    pub fn attributes(self: Message) AttributeIterator {
        return .{ .bytes = self.bytes, .pos = HEADER_LEN };
    }

    /// First attribute of a type, or null. RFC 8489 14 says only the first occurrence needs
    /// processing, so a duplicate is skipped rather than being an error.
    pub fn find(self: Message, kind: AttributeType) ?Attribute {
        var iterator = self.attributes();
        while (iterator.next()) |attr| {
            if (attr.kind == kind) return attr;
        }

        return null;
    }

    /// Check the FINGERPRINT attribute (RFC 8489 14.7).
    ///
    /// Note:
    /// - The CRC covers the message up to but excluding the attribute itself, while the header
    ///   length field already counts it.
    /// - ABSENT is not a failure. FINGERPRINT is optional in plain STUN, so the caller decides
    ///   whether its usage requires one.
    ///
    /// Return:
    /// - FingerprintState
    pub fn fingerprint(self: Message) FingerprintState {
        const attr = self.find(.FINGERPRINT) orelse return .ABSENT;

        if (attr.value.len != 4) return .INVALID;

        const carried = std.mem.readInt(u32, attr.value[0..4], .big);
        const expected = std.hash.Crc32.hash(self.bytes[0..attr.offset]) ^ FINGERPRINT_XOR;

        return if (carried == expected) .VALID else .INVALID;
    }

    /// Check the MESSAGE-INTEGRITY attribute against a key (RFC 8489 14.5).
    ///
    /// Note:
    /// - The HMAC covers the message up to but excluding the attribute, with the header length
    ///   field rewritten to end at it. That rewrite is what lets FINGERPRINT be appended
    ///   afterwards without invalidating the MAC.
    /// - RFC 8489 14.5 says to ignore every attribute after MESSAGE-INTEGRITY except FINGERPRINT.
    ///   `find` returns the first occurrence of a type, so credentials read through it already
    ///   come from before the attribute and a second copy appended after it changes nothing.
    /// - ABSENT is not a failure. Whether credentials are required is the transaction's rule, not
    ///   the container's.
    ///
    /// Param:
    /// key - []const u8 (short-term credential: the password itself, RFC 8489 9.1.1)
    ///
    /// Return:
    /// - IntegrityState
    pub fn messageIntegrity(self: Message, key: []const u8) IntegrityState {
        const attr = self.find(.MESSAGE_INTEGRITY) orelse return .ABSENT;

        if (attr.value.len != MESSAGE_INTEGRITY_VALUE_LEN) return .INVALID;

        const expected = integrityMac(self.bytes, attr.offset, key);
        const carried: [MESSAGE_INTEGRITY_VALUE_LEN]u8 = attr.value[0..MESSAGE_INTEGRITY_VALUE_LEN].*;

        // Constant time: a MAC check that leaks how many bytes matched can be forged byte by byte.
        return if (std.crypto.timing_safe.eql([MESSAGE_INTEGRITY_VALUE_LEN]u8, expected, carried)) .VALID else .INVALID;
    }
};

/// Walks the attribute region of an already validated message, so `next` cannot fail.
pub const AttributeIterator = struct {
    bytes: []const u8,
    pos: usize,

    pub fn next(self: *AttributeIterator) ?Attribute {
        if (self.pos + ATTRIBUTE_HEADER_LEN > self.bytes.len) return null;

        const kind: AttributeType = @enumFromInt(std.mem.readInt(u16, self.bytes[self.pos..][0..2], .big));
        const value_len = std.mem.readInt(u16, self.bytes[self.pos + 2 ..][0..2], .big);
        const value_start = self.pos + ATTRIBUTE_HEADER_LEN;
        const attr: Attribute = .{
            .kind = kind,
            .value = self.bytes[value_start..][0..value_len],
            .offset = self.pos,
        };

        self.pos = value_start + padTo4(value_len);

        return attr;
    }
};

/// Decode and validate a datagram as a STUN message (RFC 8489 5 / 6.3).
///
/// Note:
/// - The datagram must hold exactly one message. Trailing bytes are BadLength rather than being
///   ignored, because a UDP datagram carries one message and silence about junk hides bugs.
/// - Every attribute is bounds-checked here, which is what lets `attributes` be infallible.
///
/// Param:
/// datagram - []const u8 (one received datagram)
///
/// Return:
/// - Message (borrowing datagram)
/// - ParseError
pub fn parse(datagram: []const u8) ParseError!Message {
    if (datagram.len < HEADER_LEN) return error.ZixTruncated;
    if (datagram[0] & 0xC0 != 0) return error.ZixNotStun;
    if (std.mem.readInt(u32, datagram[4..8], .big) != MAGIC_COOKIE) return error.ZixNotStun;

    const message_type = std.mem.readInt(u16, datagram[0..2], .big);
    const body_len = std.mem.readInt(u16, datagram[2..4], .big);

    if (body_len % 4 != 0) return error.ZixBadLength;
    if (HEADER_LEN + body_len > datagram.len) return error.ZixTruncated;
    if (HEADER_LEN + body_len < datagram.len) return error.ZixBadLength;

    var pos: usize = HEADER_LEN;
    while (pos < datagram.len) {
        if (pos + ATTRIBUTE_HEADER_LEN > datagram.len) return error.ZixBadAttribute;

        const value_len = std.mem.readInt(u16, datagram[pos + 2 ..][0..2], .big);
        const attr_len = ATTRIBUTE_HEADER_LEN + padTo4(value_len);

        if (pos + attr_len > datagram.len) return error.ZixBadAttribute;

        pos += attr_len;
    }

    return .{
        .class = @enumFromInt(((message_type >> 4) & 0x1) | ((message_type >> 7) & 0x2)),
        .method = @enumFromInt((message_type & 0x000F) | ((message_type >> 1) & 0x0070) | ((message_type >> 2) & 0x0F80)),
        .transaction_id = datagram[8..HEADER_LEN].*,
        .bytes = datagram,
    };
}

/// Builds a STUN message in place. The header length field is kept correct after every append,
/// so the buffer is a complete message at all times.
pub const Writer = struct {
    buf: []u8,
    len: usize,

    pub const Error = error{ZixNoSpace};

    /// Start a message with an empty attribute region.
    ///
    /// Param:
    /// buf - []u8 (destination, at least HEADER_LEN bytes)
    /// class - Class
    /// method - Method
    /// transaction_id - [12]u8 (echoed from the request when answering)
    ///
    /// Return:
    /// - Writer
    /// - error.ZixNoSpace when buf cannot hold the header
    pub fn init(buf: []u8, class: Class, method: Method, transaction_id: [TRANSACTION_ID_LEN]u8) Error!Writer {
        if (buf.len < HEADER_LEN) return error.ZixNoSpace;

        const class_bits: u16 = @intFromEnum(class);
        const method_bits: u16 = @intFromEnum(method);
        const message_type: u16 = (method_bits & 0x000F) |
            ((method_bits & 0x0070) << 1) |
            ((method_bits & 0x0F80) << 2) |
            ((class_bits & 0x1) << 4) |
            ((class_bits & 0x2) << 7);

        std.mem.writeInt(u16, buf[0..2], message_type, .big);
        std.mem.writeInt(u16, buf[2..4], 0, .big);
        std.mem.writeInt(u32, buf[4..8], MAGIC_COOKIE, .big);
        @memcpy(buf[8..HEADER_LEN], &transaction_id);

        return .{ .buf = buf, .len = HEADER_LEN };
    }

    /// Append one TLV attribute, padding the value out to a 4-byte boundary.
    pub fn addAttribute(self: *Writer, kind: AttributeType, value: []const u8) Error!void {
        const dst = try self.reserve(value.len);
        @memcpy(dst[0..value.len], value);

        std.mem.writeInt(u16, self.buf[self.len..][0..2], @intFromEnum(kind), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value.len), .big);

        self.commit(value.len);
    }

    /// Append XOR-MAPPED-ADDRESS for a peer (RFC 8489 14.2), obfuscated with this message's own
    /// magic cookie and transaction id.
    pub fn addXorMappedAddress(self: *Writer, peer: IpAddress) Error!void {
        const value_len = xorMappedAddressLen(peer);
        const dst = try self.reserve(value_len);
        const transaction_id: *const [TRANSACTION_ID_LEN]u8 = self.buf[8..HEADER_LEN];

        encodeXorMappedAddress(dst[0..value_len], peer, transaction_id);
        std.mem.writeInt(u16, self.buf[self.len..][0..2], @intFromEnum(AttributeType.XOR_MAPPED_ADDRESS), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value_len), .big);

        self.commit(value_len);
    }

    /// Append ERROR-CODE (RFC 8489 14.8): 2 reserved bytes, the hundreds digit, the remainder,
    /// then the reason phrase.
    ///
    /// Param:
    /// code - u16 (300 to 699)
    /// reason - []const u8 (UTF-8 diagnostic text, not machine-read)
    pub fn addErrorCode(self: *Writer, code: u16, reason: []const u8) Error!void {
        const value_len = 4 + reason.len;
        const dst = try self.reserve(value_len);

        dst[0] = 0;
        dst[1] = 0;
        dst[2] = @intCast(code / 100);
        dst[3] = @intCast(code % 100);
        @memcpy(dst[4..value_len], reason);

        std.mem.writeInt(u16, self.buf[self.len..][0..2], @intFromEnum(AttributeType.ERROR_CODE), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value_len), .big);

        self.commit(value_len);
    }

    /// Append UNKNOWN-ATTRIBUTES (RFC 8489 14.9), the list a 420 response owes the sender.
    pub fn addUnknownAttributes(self: *Writer, kinds: []const AttributeType) Error!void {
        const value_len = kinds.len * 2;
        const dst = try self.reserve(value_len);

        for (kinds, 0..) |kind, i| std.mem.writeInt(u16, dst[i * 2 ..][0..2], @intFromEnum(kind), .big);

        std.mem.writeInt(u16, self.buf[self.len..][0..2], @intFromEnum(AttributeType.UNKNOWN_ATTRIBUTES), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value_len), .big);

        self.commit(value_len);
    }

    /// Append MESSAGE-INTEGRITY (RFC 8489 14.5), an HMAC-SHA1 over everything written so far.
    ///
    /// Note:
    /// - Only FINGERPRINT may follow it. Any other attribute appended afterwards is one the peer
    ///   is required to ignore, so it would be carried at full cost and never read.
    ///
    /// Param:
    /// key - []const u8 (short-term credential: the password itself, RFC 8489 9.1.1)
    pub fn addMessageIntegrity(self: *Writer, key: []const u8) Error!void {
        _ = try self.reserve(MESSAGE_INTEGRITY_VALUE_LEN);

        const attr_start = self.len;
        std.mem.writeInt(u16, self.buf[attr_start..][0..2], @intFromEnum(AttributeType.MESSAGE_INTEGRITY), .big);
        std.mem.writeInt(u16, self.buf[attr_start + 2 ..][0..2], @intCast(MESSAGE_INTEGRITY_VALUE_LEN), .big);

        // The length field must count this attribute before the MAC is taken, so commit first.
        self.commit(MESSAGE_INTEGRITY_VALUE_LEN);

        const mac = integrityMac(self.buf[0..self.len], attr_start, key);
        @memcpy(self.buf[attr_start + ATTRIBUTE_HEADER_LEN ..][0..MESSAGE_INTEGRITY_VALUE_LEN], &mac);
    }

    /// Append FINGERPRINT (RFC 8489 14.7). It must be the last attribute, since its CRC covers
    /// every byte before it and the header length must already count the attribute itself.
    pub fn addFingerprint(self: *Writer) Error!void {
        _ = try self.reserve(4);

        const attr_start = self.len;
        std.mem.writeInt(u16, self.buf[attr_start..][0..2], @intFromEnum(AttributeType.FINGERPRINT), .big);
        std.mem.writeInt(u16, self.buf[attr_start + 2 ..][0..2], 4, .big);

        // The length field must count this attribute before the CRC is taken, so commit first.
        self.commit(4);

        const crc = std.hash.Crc32.hash(self.buf[0..attr_start]) ^ FINGERPRINT_XOR;
        std.mem.writeInt(u32, self.buf[attr_start + ATTRIBUTE_HEADER_LEN ..][0..4], crc, .big);
    }

    /// The finished message.
    pub fn finish(self: *const Writer) []const u8 {
        return self.buf[0..self.len];
    }

    /// Space for one attribute value, padding included. The TLV header is written by the caller,
    /// which is why this hands back the value slice and not the whole attribute.
    fn reserve(self: *Writer, value_len: usize) Error![]u8 {
        if (value_len > std.math.maxInt(u16)) return error.ZixNoSpace;

        const attr_len = ATTRIBUTE_HEADER_LEN + padTo4(value_len);

        if (self.len + attr_len > self.buf.len) return error.ZixNoSpace;

        const value_start = self.len + ATTRIBUTE_HEADER_LEN;
        @memset(self.buf[value_start .. self.len + attr_len], 0);

        return self.buf[value_start .. self.len + attr_len];
    }

    /// Account for an appended attribute and refresh the header length field.
    fn commit(self: *Writer, value_len: usize) void {
        self.len += ATTRIBUTE_HEADER_LEN + padTo4(value_len);

        std.mem.writeInt(u16, self.buf[2..4], @intCast(self.len - HEADER_LEN), .big);
    }
};

/// Bytes an XOR-MAPPED-ADDRESS value occupies: 4 fixed bytes plus the address itself.
pub fn xorMappedAddressLen(peer: IpAddress) usize {
    return switch (peer) {
        .ip4 => 8,
        .ip6 => 20,
    };
}

/// Encode an XOR-MAPPED-ADDRESS value (RFC 8489 14.2).
///
/// Note:
/// - The port is masked with the top 16 bits of the magic cookie. An IPv4 address is masked with
///   the whole cookie, an IPv6 address with the cookie followed by the transaction id.
///
/// Param:
/// out - []u8 (exactly xorMappedAddressLen(peer) bytes)
/// peer - IpAddress (the reflexive address being reported)
/// transaction_id - *const [12]u8 (this message's transaction id, part of the IPv6 mask)
pub fn encodeXorMappedAddress(out: []u8, peer: IpAddress, transaction_id: *const [TRANSACTION_ID_LEN]u8) void {
    var mask: [16]u8 = undefined;
    std.mem.writeInt(u32, mask[0..4], MAGIC_COOKIE, .big);
    @memcpy(mask[4..16], transaction_id);

    out[0] = 0;

    switch (peer) {
        .ip4 => |addr| {
            out[1] = FAMILY_IP4;
            std.mem.writeInt(u16, out[2..4], addr.port, .big);
            @memcpy(out[4..8], &addr.bytes);
        },
        .ip6 => |addr| {
            out[1] = FAMILY_IP6;
            std.mem.writeInt(u16, out[2..4], addr.port, .big);
            @memcpy(out[4..20], &addr.bytes);
        },
    }

    out[2] ^= mask[0];
    out[3] ^= mask[1];
    for (out[4..], 0..) |*byte, i| byte.* ^= mask[i];
}

/// Decode an XOR-MAPPED-ADDRESS value (RFC 8489 14.2).
///
/// Param:
/// value - []const u8 (the attribute value, padding excluded)
/// transaction_id - *const [12]u8 (from the message carrying the attribute)
///
/// Return:
/// - IpAddress
/// - error.ZixBadAttribute when the length does not match the family, or the family is unknown
pub fn decodeXorMappedAddress(value: []const u8, transaction_id: *const [TRANSACTION_ID_LEN]u8) error{ZixBadAttribute}!IpAddress {
    if (value.len < 4) return error.ZixBadAttribute;

    var mask: [16]u8 = undefined;
    std.mem.writeInt(u32, mask[0..4], MAGIC_COOKIE, .big);
    @memcpy(mask[4..16], transaction_id);

    const port = std.mem.readInt(u16, value[2..4], .big) ^ @as(u16, MAGIC_COOKIE >> 16);

    switch (value[1]) {
        FAMILY_IP4 => {
            if (value.len != 8) return error.ZixBadAttribute;

            var bytes: [4]u8 = value[4..8].*;
            for (&bytes, 0..) |*byte, i| byte.* ^= mask[i];

            return .{ .ip4 = .{ .bytes = bytes, .port = port } };
        },
        FAMILY_IP6 => {
            if (value.len != 20) return error.ZixBadAttribute;

            var bytes: [16]u8 = value[4..20].*;
            for (&bytes, 0..) |*byte, i| byte.* ^= mask[i];

            return .{ .ip6 = .{ .bytes = bytes, .port = port } };
        },
        else => return error.ZixBadAttribute,
    }
}

/// Whether a receiver that does not understand this type must reject the message (RFC 8489 14).
pub fn isComprehensionRequired(kind: AttributeType) bool {
    return @intFromEnum(kind) < COMPREHENSION_OPTIONAL_MIN;
}

/// Whether this codec knows the attribute type, which is what an unknown-attribute scan asks.
pub fn isKnown(kind: AttributeType) bool {
    return switch (kind) {
        .MAPPED_ADDRESS,
        .USERNAME,
        .MESSAGE_INTEGRITY,
        .ERROR_CODE,
        .UNKNOWN_ATTRIBUTES,
        .REALM,
        .NONCE,
        .MESSAGE_INTEGRITY_SHA256,
        .PASSWORD_ALGORITHM,
        .USERHASH,
        .XOR_MAPPED_ADDRESS,
        .PRIORITY,
        .USE_CANDIDATE,
        .PASSWORD_ALGORITHMS,
        .ALTERNATE_DOMAIN,
        .SOFTWARE,
        .ALTERNATE_SERVER,
        .FINGERPRINT,
        .ICE_CONTROLLED,
        .ICE_CONTROLLING,
        => true,
        _ => false,
    };
}

/// Collect the comprehension-required attribute types this codec does not know, which is exactly
/// the list a 420 error response owes the sender (RFC 8489 6.3.1).
///
/// Note:
/// - A repeated type is listed once, and collection stops when out is full. The list is
///   diagnostic, never machine-read, so truncating it costs the sender nothing.
///
/// Param:
/// msg - Message (an already parsed request)
/// out - []AttributeType (caller storage, its length is the cap)
///
/// Return:
/// - []AttributeType (a prefix of out, empty when every attribute is understood)
pub fn collectUnknownRequired(msg: Message, out: []AttributeType) []AttributeType {
    var count: usize = 0;

    var iterator = msg.attributes();
    while (iterator.next()) |attr| {
        if (count == out.len) break;
        if (!isComprehensionRequired(attr.kind)) continue;
        if (isKnown(attr.kind)) continue;
        if (listed(out[0..count], attr.kind)) continue;

        out[count] = attr.kind;
        count += 1;
    }

    return out[0..count];
}

/// HMAC-SHA1 over the message prefix a MESSAGE-INTEGRITY attribute covers (RFC 8489 14.5).
///
/// Note:
/// - The header is copied so the length field can be rewritten to end at the attribute without
///   touching the caller's bytes. Everything after the header is hashed in place.
fn integrityMac(bytes: []const u8, attr_offset: usize, key: []const u8) [MESSAGE_INTEGRITY_VALUE_LEN]u8 {
    var header: [HEADER_LEN]u8 = bytes[0..HEADER_LEN].*;
    std.mem.writeInt(u16, header[2..4], @intCast(attr_offset + MESSAGE_INTEGRITY_LEN - HEADER_LEN), .big);

    var mac = HmacSha1.init(key);
    mac.update(&header);
    mac.update(bytes[HEADER_LEN..attr_offset]);

    var out: [MESSAGE_INTEGRITY_VALUE_LEN]u8 = undefined;
    mac.final(&out);

    return out;
}

/// Whether a type is already collected, so a repeated attribute is named once.
fn listed(kinds: []const AttributeType, kind: AttributeType) bool {
    for (kinds) |seen| {
        if (seen == kind) return true;
    }

    return false;
}

/// Round a value length up to the 4-byte boundary every attribute ends on (RFC 8489 14).
fn padTo4(value_len: usize) usize {
    return (value_len + 3) & ~@as(usize, 3);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_TRANSACTION_ID: [TRANSACTION_ID_LEN]u8 = .{ 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

/// A binding request with no attributes, the smallest legal STUN message.
fn testBindingRequest(buf: []u8) []const u8 {
    var writer = Writer.init(buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID) catch unreachable;

    return writer.finish();
}

test "zix stun: message parse, binding request header decodes" {
    var buf: [64]u8 = undefined;
    const datagram = testBindingRequest(&buf);

    try std.testing.expectEqual(@as(usize, HEADER_LEN), datagram.len);
    try std.testing.expectEqual(@as(u16, 0x0001), std.mem.readInt(u16, datagram[0..2], .big));

    const message = try parse(datagram);
    try std.testing.expectEqual(Class.REQUEST, message.class);
    try std.testing.expectEqual(Method.BINDING, message.method);
    try std.testing.expectEqualSlices(u8, &TEST_TRANSACTION_ID, &message.transaction_id);
    try std.testing.expectEqual(FingerprintState.ABSENT, message.fingerprint());
}

test "zix stun: message type, all four classes round trip" {
    const cases = [_]struct { class: Class, wire: u16 }{
        .{ .class = .REQUEST, .wire = 0x0001 },
        .{ .class = .INDICATION, .wire = 0x0011 },
        .{ .class = .SUCCESS_RESPONSE, .wire = 0x0101 },
        .{ .class = .ERROR_RESPONSE, .wire = 0x0111 },
    };

    for (cases) |case| {
        var buf: [32]u8 = undefined;
        var writer = try Writer.init(&buf, case.class, .BINDING, TEST_TRANSACTION_ID);
        const datagram = writer.finish();

        try std.testing.expectEqual(case.wire, std.mem.readInt(u16, datagram[0..2], .big));

        const message = try parse(datagram);
        try std.testing.expectEqual(case.class, message.class);
        try std.testing.expectEqual(Method.BINDING, message.method);
    }
}

test "zix stun: message method, an unknown method survives the round trip" {
    const allocate: Method = @enumFromInt(0x003);

    var buf: [32]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, allocate, TEST_TRANSACTION_ID);

    const message = try parse(writer.finish());
    try std.testing.expectEqual(allocate, message.method);
    try std.testing.expect(message.method != .BINDING);
}

test "zix stun: message parse, non-stun bytes are rejected before anything else" {
    var buf: [64]u8 = undefined;
    const datagram = testBindingRequest(&buf);

    try std.testing.expectError(error.ZixTruncated, parse(datagram[0 .. HEADER_LEN - 1]));
    try std.testing.expectError(error.ZixTruncated, parse(&[_]u8{}));

    // A DTLS handshake record shares the port and must not read as STUN (RFC 7983).
    var dtls_record: [23]u8 = @splat(0);
    dtls_record[0] = 0x16;
    dtls_record[1] = 0xfe;
    dtls_record[2] = 0xfd;
    try std.testing.expectError(error.ZixNotStun, parse(&dtls_record));

    var wrong_cookie: [HEADER_LEN]u8 = datagram[0..HEADER_LEN].*;
    wrong_cookie[4] = 0x00;
    try std.testing.expectError(error.ZixNotStun, parse(&wrong_cookie));

    var high_bits: [HEADER_LEN]u8 = datagram[0..HEADER_LEN].*;
    high_bits[0] = 0x40;
    try std.testing.expectError(error.ZixNotStun, parse(&high_bits));
}

test "zix stun: message parse, length field must agree with the datagram" {
    var buf: [64]u8 = undefined;
    const datagram = testBindingRequest(&buf);

    var not_multiple: [HEADER_LEN]u8 = datagram[0..HEADER_LEN].*;
    std.mem.writeInt(u16, not_multiple[2..4], 3, .big);
    try std.testing.expectError(error.ZixBadLength, parse(&not_multiple));

    var claims_more: [HEADER_LEN]u8 = datagram[0..HEADER_LEN].*;
    std.mem.writeInt(u16, claims_more[2..4], 8, .big);
    try std.testing.expectError(error.ZixTruncated, parse(&claims_more));

    var trailing: [HEADER_LEN + 4]u8 = undefined;
    @memcpy(trailing[0..HEADER_LEN], datagram[0..HEADER_LEN]);
    @memset(trailing[HEADER_LEN..], 0);
    try std.testing.expectError(error.ZixBadLength, parse(&trailing));
}

test "zix stun: message parse, an attribute running past the end is rejected" {
    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.SOFTWARE, "zix");

    const datagram = writer.finish();
    var overrun: [HEADER_LEN + 8]u8 = datagram[0 .. HEADER_LEN + 8].*;

    // Value length 8 needs 12 bytes of attribute, only 8 are present.
    std.mem.writeInt(u16, overrun[HEADER_LEN + 2 ..][0..2], 8, .big);
    try std.testing.expectError(error.ZixBadAttribute, parse(&overrun));
}

test "zix stun: message attributes, padding is written and skipped" {
    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.SOFTWARE, "zix");
    try writer.addAttribute(.USERNAME, "abcd");

    const datagram = writer.finish();

    // 3-byte value takes 4 bytes of padded room, 4-byte value takes 4.
    try std.testing.expectEqual(@as(usize, HEADER_LEN + 8 + 8), datagram.len);
    try std.testing.expectEqual(@as(u8, 0), datagram[HEADER_LEN + 4 + 3]);

    const message = try parse(datagram);
    var iterator = message.attributes();

    const first = iterator.next().?;
    try std.testing.expectEqual(AttributeType.SOFTWARE, first.kind);
    try std.testing.expectEqualStrings("zix", first.value);
    try std.testing.expectEqual(@as(usize, HEADER_LEN), first.offset);

    const second = iterator.next().?;
    try std.testing.expectEqual(AttributeType.USERNAME, second.kind);
    try std.testing.expectEqualStrings("abcd", second.value);

    try std.testing.expectEqual(@as(?Attribute, null), iterator.next());
}

test "zix stun: message find, returns the first occurrence and null when absent" {
    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.SOFTWARE, "first");
    try writer.addAttribute(.SOFTWARE, "second");

    const message = try parse(writer.finish());
    try std.testing.expectEqualStrings("first", message.find(.SOFTWARE).?.value);
    try std.testing.expectEqual(@as(?Attribute, null), message.find(.USERNAME));
}

test "zix stun: xor-mapped-address, RFC 5769 ipv4 sample encodes byte for byte" {
    // 192.0.2.1:32853 masked with the magic cookie gives port 0xA147 and address E1 12 A6 43.
    const peer: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };

    var value: [8]u8 = undefined;
    encodeXorMappedAddress(&value, peer, &TEST_TRANSACTION_ID);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43 }, &value);

    const decoded = try decodeXorMappedAddress(&value, &TEST_TRANSACTION_ID);
    try std.testing.expectEqualSlices(u8, &peer.ip4.bytes, &decoded.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 32853), decoded.ip4.port);
}

test "zix stun: xor-mapped-address, ipv6 masks with the transaction id" {
    const peer: IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
        .port = 32853,
    } };

    var value: [20]u8 = undefined;
    encodeXorMappedAddress(&value, peer, &TEST_TRANSACTION_ID);

    try std.testing.expectEqual(FAMILY_IP6, value[1]);
    try std.testing.expectEqual(@as(u8, 0x20 ^ 0x21), value[4]);
    try std.testing.expectEqual(@as(u8, 0x77 ^ TEST_TRANSACTION_ID[11]), value[19]);

    const decoded = try decodeXorMappedAddress(&value, &TEST_TRANSACTION_ID);
    try std.testing.expectEqualSlices(u8, &peer.ip6.bytes, &decoded.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 32853), decoded.ip6.port);

    // The same bytes under a different transaction id must not decode back to the same address.
    var other_id: [TRANSACTION_ID_LEN]u8 = TEST_TRANSACTION_ID;
    other_id[0] +%= 1;

    const wrong = try decodeXorMappedAddress(&value, &other_id);
    try std.testing.expect(!std.mem.eql(u8, &peer.ip6.bytes, &wrong.ip6.bytes));
}

test "zix stun: xor-mapped-address, a bad family or length is rejected" {
    var value: [8]u8 = .{ 0x00, 0x09, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43 };
    try std.testing.expectError(error.ZixBadAttribute, decodeXorMappedAddress(&value, &TEST_TRANSACTION_ID));

    value[1] = FAMILY_IP4;
    try std.testing.expectError(error.ZixBadAttribute, decodeXorMappedAddress(value[0..7], &TEST_TRANSACTION_ID));
    try std.testing.expectError(error.ZixBadAttribute, decodeXorMappedAddress(value[0..3], &TEST_TRANSACTION_ID));

    value[1] = FAMILY_IP6;
    try std.testing.expectError(error.ZixBadAttribute, decodeXorMappedAddress(&value, &TEST_TRANSACTION_ID));
}

test "zix stun: xor-mapped-address, the writer reports the peer it was handed" {
    const peer: IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 9 }, .port = 41000 } };

    var buf: [64]u8 = undefined;
    var writer = try Writer.init(&buf, .SUCCESS_RESPONSE, .BINDING, TEST_TRANSACTION_ID);
    try writer.addXorMappedAddress(peer);

    const message = try parse(writer.finish());
    const attr = message.find(.XOR_MAPPED_ADDRESS).?;
    const decoded = try decodeXorMappedAddress(attr.value, &message.transaction_id);

    try std.testing.expectEqualSlices(u8, &peer.ip4.bytes, &decoded.ip4.bytes);
    try std.testing.expectEqual(peer.ip4.port, decoded.ip4.port);
}

test "zix stun: fingerprint, verifies clean and fails on a single flipped byte" {
    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .SUCCESS_RESPONSE, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.SOFTWARE, "zix");
    try writer.addFingerprint();

    const datagram = writer.finish();
    const message = try parse(datagram);

    try std.testing.expectEqual(FingerprintState.VALID, message.fingerprint());

    // The header length counts the fingerprint, the CRC covers everything before it.
    const attr = message.find(.FINGERPRINT).?;
    try std.testing.expectEqual(datagram.len, attr.offset + FINGERPRINT_LEN);
    try std.testing.expectEqual(
        std.hash.Crc32.hash(datagram[0..attr.offset]) ^ FINGERPRINT_XOR,
        std.mem.readInt(u32, attr.value[0..4], .big),
    );

    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..datagram.len], datagram);
    tampered[HEADER_LEN + 5] ^= 0x01;

    const bad = try parse(tampered[0..datagram.len]);
    try std.testing.expectEqual(FingerprintState.INVALID, bad.fingerprint());
}

test "zix stun: writer, refuses to overflow the caller buffer" {
    var buf: [HEADER_LEN + 7]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);

    // 4 bytes of TLV header plus a padded 4-byte value needs 8, only 7 are left.
    try std.testing.expectError(error.ZixNoSpace, writer.addAttribute(.SOFTWARE, "zix"));
    try std.testing.expectEqual(@as(usize, HEADER_LEN), writer.finish().len);

    var too_small: [HEADER_LEN - 1]u8 = undefined;
    try std.testing.expectError(error.ZixNoSpace, Writer.init(&too_small, .REQUEST, .BINDING, TEST_TRANSACTION_ID));
}

test "zix stun: attribute ranges, comprehension-required and known are separate questions" {
    try std.testing.expect(isComprehensionRequired(.XOR_MAPPED_ADDRESS));
    try std.testing.expect(isComprehensionRequired(@enumFromInt(0x7FFF)));
    try std.testing.expect(!isComprehensionRequired(.FINGERPRINT));
    try std.testing.expect(!isComprehensionRequired(@enumFromInt(0x8000)));

    try std.testing.expect(isKnown(.XOR_MAPPED_ADDRESS));
    try std.testing.expect(isKnown(.FINGERPRINT));
    try std.testing.expect(!isKnown(@enumFromInt(0x0002)));
    try std.testing.expect(!isKnown(@enumFromInt(0x8888)));

    // The ICE attributes are comprehension-required in the request, so a receiver that did not
    // know them would answer 420 to every connectivity check.
    try std.testing.expect(isComprehensionRequired(.PRIORITY));
    try std.testing.expect(isComprehensionRequired(.USE_CANDIDATE));
    try std.testing.expect(isKnown(.PRIORITY));
    try std.testing.expect(isKnown(.USE_CANDIDATE));
    try std.testing.expect(isKnown(.ICE_CONTROLLED));
    try std.testing.expect(isKnown(.ICE_CONTROLLING));
}

test "zix stun: unknown attributes, the scan dedups and stops at the caller cap" {
    var request_buf: [256]u8 = undefined;
    var writer = try Writer.init(&request_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.SOFTWARE, "known optional");
    try writer.addAttribute(.USERNAME, "known required");
    try writer.addAttribute(@enumFromInt(0x8042), "unknown optional");
    try writer.addAttribute(@enumFromInt(0x0042), "unknown required");
    try writer.addAttribute(@enumFromInt(0x0042), "same one again");
    try writer.addAttribute(@enumFromInt(0x0043), "another");

    const message = try parse(writer.finish());

    var room_for_two: [2]AttributeType = undefined;
    const both = collectUnknownRequired(message, &room_for_two);
    try std.testing.expectEqual(@as(usize, 2), both.len);
    try std.testing.expectEqual(@as(AttributeType, @enumFromInt(0x0042)), both[0]);
    try std.testing.expectEqual(@as(AttributeType, @enumFromInt(0x0043)), both[1]);

    var room_for_one: [1]AttributeType = undefined;
    try std.testing.expectEqual(@as(usize, 1), collectUnknownRequired(message, &room_for_one).len);
}

test "zix stun: unknown attributes, a message of understood types collects nothing" {
    var request_buf: [128]u8 = undefined;
    var writer = try Writer.init(&request_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.USERNAME, "zix:peer");
    try writer.addAttribute(.PRIORITY, &[_]u8{ 0x6e, 0x00, 0x01, 0xff });
    try writer.addAttribute(.USE_CANDIDATE, "");
    try writer.addFingerprint();

    const message = try parse(writer.finish());

    var room: [4]AttributeType = undefined;
    try std.testing.expectEqual(@as(usize, 0), collectUnknownRequired(message, &room).len);
}

test "zix stun: message-integrity, RFC 5769 sample request verifies byte for byte" {
    // RFC 5769 2.1, the short-term credential sample: username evtj:h6vY, software "STUN test
    // client", carrying PRIORITY and ICE-CONTROLLED as a real connectivity check does.
    const sample = [_]u8{
        0x00, 0x01, 0x00, 0x58,
        0x21, 0x12, 0xa4, 0x42,
        0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86,
        0xfa, 0x87, 0xdf, 0xae,
        0x80, 0x22, 0x00, 0x10,
        0x53, 0x54, 0x55, 0x4e,
        0x20, 0x74, 0x65, 0x73,
        0x74, 0x20, 0x63, 0x6c,
        0x69, 0x65, 0x6e, 0x74,
        0x00, 0x24, 0x00, 0x04,
        0x6e, 0x00, 0x01, 0xff,
        0x80, 0x29, 0x00, 0x08,
        0x93, 0x2f, 0xf9, 0xb1,
        0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09,
        0x65, 0x76, 0x74, 0x6a,
        0x3a, 0x68, 0x36, 0x76,
        0x59, 0x20, 0x20, 0x20,
        0x00, 0x08, 0x00, 0x14,
        0x9a, 0xea, 0xa7, 0x0c,
        0xbf, 0xd8, 0xcb, 0x56,
        0x78, 0x1e, 0xf2, 0xb5,
        0xb2, 0xd3, 0xf2, 0x49,
        0xc1, 0xb5, 0x71, 0xa2,
        0x80, 0x28, 0x00, 0x04,
        0xe5, 0x7a, 0x3b, 0xcf,
    };
    const password: []const u8 = "VOkJxbRl1RmTxUk/WvJxBt";

    const message = try parse(&sample);
    try std.testing.expectEqual(Class.REQUEST, message.class);
    try std.testing.expectEqualStrings("evtj:h6vY", message.find(.USERNAME).?.value);

    // FINGERPRINT covers everything before it, so a clean CRC proves the bytes above are intact
    // before the MAC is judged.
    try std.testing.expectEqual(FingerprintState.VALID, message.fingerprint());
    try std.testing.expectEqual(IntegrityState.VALID, message.messageIntegrity(password));
    try std.testing.expectEqual(IntegrityState.INVALID, message.messageIntegrity("wrong password"));
}

test "zix stun: message-integrity, the mac survives a fingerprint appended after it" {
    const password: []const u8 = "VOkJxbRl1RmTxUk/WvJxBt";

    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.USERNAME, "zix:peer");
    try writer.addMessageIntegrity(password);

    // The length field counts the integrity attribute and stops there.
    const before_fingerprint = writer.finish();
    const attr = (try parse(before_fingerprint)).find(.MESSAGE_INTEGRITY).?;
    try std.testing.expectEqual(before_fingerprint.len, attr.offset + MESSAGE_INTEGRITY_LEN);

    // Appending FINGERPRINT rewrites that length field, and the MAC must still verify.
    try writer.addFingerprint();

    const message = try parse(writer.finish());
    try std.testing.expectEqual(IntegrityState.VALID, message.messageIntegrity(password));
    try std.testing.expectEqual(FingerprintState.VALID, message.fingerprint());
}

test "zix stun: message-integrity, absent reads as absent and a tampered body fails" {
    const password: []const u8 = "VOkJxbRl1RmTxUk/WvJxBt";

    var plain_buf: [64]u8 = undefined;
    var plain = try Writer.init(&plain_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try plain.addAttribute(.USERNAME, "zix:peer");

    try std.testing.expectEqual(IntegrityState.ABSENT, (try parse(plain.finish())).messageIntegrity(password));

    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.USERNAME, "zix:peer");
    try writer.addMessageIntegrity(password);
    try writer.addFingerprint();

    const datagram = writer.finish();

    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..datagram.len], datagram);
    tampered[HEADER_LEN + 4] ^= 0x01;

    // The username changed, so the MAC no longer matches even though nothing else moved.
    const bad = try parse(tampered[0..datagram.len]);
    try std.testing.expectEqual(IntegrityState.INVALID, bad.messageIntegrity(password));
}

test "zix stun: message-integrity, a truncated value is rejected rather than compared short" {
    const password: []const u8 = "VOkJxbRl1RmTxUk/WvJxBt";

    var buf: [128]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.MESSAGE_INTEGRITY, "short");

    try std.testing.expectEqual(IntegrityState.INVALID, (try parse(writer.finish())).messageIntegrity(password));
}

test "zix stun: message-integrity, the writer refuses to overflow the caller buffer" {
    var buf: [HEADER_LEN + MESSAGE_INTEGRITY_LEN - 1]u8 = undefined;
    var writer = try Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);

    try std.testing.expectError(error.ZixNoSpace, writer.addMessageIntegrity("password"));
    try std.testing.expectEqual(@as(usize, HEADER_LEN), writer.finish().len);
}
