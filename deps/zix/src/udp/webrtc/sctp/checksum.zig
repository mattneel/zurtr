//! zix SCTP packet checksum (RFC 9260 6.8, algorithm in Appendix A).
//!
//! What:
//! - The CRC32c every SCTP packet carries in its common header, and the three things a sender
//!   and a receiver need: compute it, write it into a finished packet, and check the one that
//!   arrived.
//!
//! Note:
//! - The field sits at bytes 8 to 11 and counts as zero while the CRC runs, on both sides.
//!   `compute` never writes to the packet it is given, so a receiver has nothing to restore
//!   after checking.
//! - The value goes in LITTLE endian, which is the one surprise here, since every other integer
//!   in SCTP is network byte order. RFC 9260 Appendix A byte-swaps the reflected CRC and then
//!   applies htonl, and those two cancel into a plain little-endian store. Writing it big endian
//!   produces a packet that looks right and that every peer discards.
//! - The polynomial is Castagnoli (0x1EDC6F41), not the IEEE one used by zip and by the STUN
//!   FINGERPRINT attribute. Picking the wrong constant is silent: both are 32 bits wide and both
//!   look like noise.
//! - Under DTLS (RFC 8261) this checksum protects nothing the record layer has not already
//!   authenticated. It is computed anyway because the field is not optional and a peer is free
//!   to discard a packet whose CRC does not match.

const std = @import("std");

/// The catalog entry was renamed between zig 0.16 and 0.17, from a camel-case identifier to the
/// registry's own name. Same algorithm and same init, update, final surface either way.
const Crc32c = if (@hasDecl(std.hash.crc, "Crc32Iscsi"))
    std.hash.crc.Crc32Iscsi
else
    std.hash.crc.@"CRC-32/ISCSI";

/// Where the checksum field starts in the common header (RFC 9260 3.1).
pub const FIELD_OFFSET: usize = 8;

/// Width of the checksum field.
pub const FIELD_LEN: usize = 4;

/// Shortest slice the checksum can be read from or written to, which is the common header.
pub const MIN_PACKET_LEN: usize = FIELD_OFFSET + FIELD_LEN;

/// A slice too short to hold a common header, so it has no checksum field.
pub const Error = error{ZixShortPacket};

/// CRC32c of the packet with its checksum field counted as zero.
///
/// Note:
/// - Reads only. The four checksum bytes are skipped and four zeros are fed in their place, so
///   the same call works for a packet that already carries a checksum and one that does not.
///
/// Param:
/// packet - []const u8 (whole SCTP packet, common header and all chunks)
///
/// Return:
/// - u32 checksum in host order, ready for `write`
/// - error.ZixShortPacket if the slice cannot hold a common header
pub fn compute(packet: []const u8) Error!u32 {
    if (packet.len < MIN_PACKET_LEN) return error.ZixShortPacket;

    const zeros: [FIELD_LEN]u8 = @splat(0);

    var digest = Crc32c.init();
    digest.update(packet[0..FIELD_OFFSET]);
    digest.update(&zeros);
    digest.update(packet[FIELD_OFFSET + FIELD_LEN ..]);

    return digest.final();
}

/// The checksum currently in the packet, as the sender wrote it.
///
/// Param:
/// packet - []const u8 (whole SCTP packet)
///
/// Return:
/// - u32 in host order
/// - error.ZixShortPacket if the slice cannot hold a common header
pub fn read(packet: []const u8) Error!u32 {
    if (packet.len < MIN_PACKET_LEN) return error.ZixShortPacket;

    return std.mem.readInt(u32, packet[FIELD_OFFSET..][0..FIELD_LEN], .little);
}

/// Compute the checksum of a finished packet and store it in the header.
///
/// Note:
/// - Call this last. Any later edit to any byte invalidates it.
///
/// Param:
/// packet - []u8 (whole SCTP packet, complete except for this field)
///
/// Return:
/// - void
/// - error.ZixShortPacket if the slice cannot hold a common header
pub fn insert(packet: []u8) Error!void {
    const value = try compute(packet);

    std.mem.writeInt(u32, packet[FIELD_OFFSET..][0..FIELD_LEN], value, .little);
}

/// Whether the checksum a packet carries matches the packet.
///
/// Note:
/// - A packet that fails is discarded silently (RFC 9260 6.8), never answered, so this returns a
///   plain bool rather than an error. A slice too short to hold the field fails the same way.
///
/// Param:
/// packet - []const u8 (whole SCTP packet as it arrived)
///
/// Return:
/// - bool
pub fn verify(packet: []const u8) bool {
    const carried = read(packet) catch return false;
    const expected = compute(packet) catch return false;

    return carried == expected;
}

/// An INIT packet with its checksum field zeroed, used by every test below.
///
/// Ports 5000 both ways (the data channel default), zero verification tag because the packet
/// carries an INIT chunk, then a 20-byte INIT: initiate tag, a_rwnd 128 KiB, 1024 streams each
/// way, initial TSN.
const sample_init: [32]u8 = .{
    0x13, 0x88, 0x13, 0x88,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x14,
    0x12, 0x34, 0x56, 0x78,
    0x00, 0x02, 0x00, 0x00,
    0x04, 0x00, 0x04, 0x00,
    0x00, 0x00, 0xab, 0xcd,
};

/// CRC32c of `sample_init`, from a bit-by-bit reference implementation that shares no code with
/// the table-driven one in std.
const sample_init_crc: u32 = 0x2c18e805;

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: checksum algorithm, the check value pins Castagnoli not the IEEE polynomial" {
    // Every CRC-32C states this value for "123456789". The IEEE polynomial gives 0xCBF43926, so
    // a wrong constant fails here rather than three files later against a real peer.
    try std.testing.expectEqual(@as(u32, 0xe3069283), Crc32c.hash("123456789"));
    try std.testing.expect(std.hash.Crc32.hash("123456789") != Crc32c.hash("123456789"));
}

test "zix sctp: checksum compute, an INIT packet matches an independent reference" {
    try std.testing.expectEqual(sample_init_crc, try compute(&sample_init));
}

test "zix sctp: checksum compute, a packet carrying a checksum gives the same value" {
    var packet = sample_init;
    try insert(&packet);

    // The field reads as zero either way, so computing over a stamped packet is the same work.
    try std.testing.expectEqual(sample_init_crc, try compute(&packet));
}

test "zix sctp: checksum compute, the packet is left untouched" {
    const packet = sample_init;
    _ = try compute(&packet);

    try std.testing.expectEqualSlices(u8, &sample_init, &packet);
}

test "zix sctp: checksum insert, the value is stored little endian" {
    var packet = sample_init;
    try insert(&packet);

    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0xe8, 0x18, 0x2c }, packet[8..12]);
    try std.testing.expectEqual(sample_init_crc, try read(&packet));
}

test "zix sctp: checksum verify, a stamped packet passes" {
    var packet = sample_init;
    try insert(&packet);

    try std.testing.expect(verify(&packet));
}

test "zix sctp: checksum verify, the same value stored big endian fails" {
    var packet = sample_init;
    std.mem.writeInt(u32, packet[8..12], sample_init_crc, .big);

    // The byte order is the whole test: the number is right and the packet is still rejected.
    try std.testing.expect(!verify(&packet));
}

test "zix sctp: checksum verify, a flipped payload byte fails" {
    var packet = sample_init;
    try insert(&packet);
    packet[31] ^= 0x01;

    try std.testing.expect(!verify(&packet));
}

test "zix sctp: checksum verify, a flipped byte inside the checksum field fails" {
    var packet = sample_init;
    try insert(&packet);
    packet[9] ^= 0x80;

    try std.testing.expect(!verify(&packet));
}

test "zix sctp: checksum verify, an unstamped packet fails" {
    // A zero field is what the sender starts from, so it must not read as a valid checksum.
    try std.testing.expect(!verify(&sample_init));
}

test "zix sctp: checksum read, a slice shorter than the common header errors" {
    try std.testing.expectError(error.ZixShortPacket, read(sample_init[0..11]));
    try std.testing.expectError(error.ZixShortPacket, compute(sample_init[0..11]));
    try std.testing.expect(!verify(sample_init[0..11]));
}

test "zix sctp: checksum compute, a bare common header is long enough" {
    var header: [MIN_PACKET_LEN]u8 = @splat(0);
    std.mem.writeInt(u16, header[0..2], 5000, .big);

    try insert(&header);
    try std.testing.expect(verify(&header));
}
