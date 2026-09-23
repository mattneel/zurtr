//! zix WebRTC media section writer (RFC 3264 6.1, RFC 8829 5.3.1, RFC 5761 5.1.3).
//!
//! What:
//! - Writes ONE media section of an answer, either carrying the offered stream or refusing it.
//!   answer.zig writes the session level around these and decides which each section gets.
//!
//! Note:
//! - Every offered section gets one written back, in the same position (RFC 3264 6). A refusal is
//!   a section with a port of zero, not a section left out. Leaving one out shifts every section
//!   behind it onto the wrong stream, which a peer reads as an answer to a different offer.
//! - The formats answered are the ones offered, echoed as the peer wrote them. zix carries no
//!   codecs, so it has no opinion about Opus over PCMU and no business narrowing the list. What
//!   it does drop is what it cannot honour: retransmission streams, because nothing here keeps
//!   the packet history RFC 4588 needs.
//! - Feedback is answered only where it is both offered and implemented. See
//!   rtcp_feedback.zig for why answering more is worse than answering less.
//! - `a=rtcp-mux` always goes out on a carried section. zix has one socket, so there is no
//!   version of this where RTCP arrives somewhere else.
//! - The ICE credentials, the fingerprint, the setup role, and the candidate are repeated in every
//!   section. RFC 8843 lets a bundled session carry them once on the tagged section, and every
//!   browser writes them per section, so writing them per section is what interoperates.
//! - Leaving the candidate out is the mistake worth naming. A browser reads the remote candidates
//!   off the tagged section of the bundle group, which is whichever section the OFFER put first.
//!   With media offered, that is an audio or a video section, and a section with credentials but
//!   no candidate leaves the browser nothing to send a check to: ICE goes straight to failed with
//!   nothing on the wire and nothing in any log.

const std = @import("std");

const address = @import("address.zig");
const builder = @import("builder.zig");
const candidate = @import("candidate.zig");
const direction = @import("direction.zig");
const ice = @import("../ice/candidate.zig");
const fingerprint = @import("fingerprint.zig");
const fmtp = @import("fmtp.zig");
const format = @import("format.zig");
const media = @import("media.zig");
const media_offer = @import("media_offer.zig");
const rtcp_feedback = @import("rtcp_feedback.zig");
const rtpmap = @import("rtpmap.zig");
const setup = @import("setup.zig");

const IpAddress = std.Io.net.IpAddress;

/// Room for the longest section this writes, with a full format list.
pub const MAX_SECTION_BYTES: usize = 4096;

/// The port that refuses a section (RFC 3264 6).
pub const REJECTED_PORT: u16 = 0;

/// The address a refused section names, since it carries nothing.
pub const REJECTED_ADDRESS: []const u8 = "0.0.0.0";

/// What stops a section from being written.
pub const Error = error{
    /// The output buffer is too small.
    ZixNoSpace,
};

/// The transport facts every section repeats.
pub const Transport = struct {
    /// Where this endpoint listens.
    address: IpAddress,
    /// This endpoint's ICE username fragment.
    ice_ufrag: []const u8,
    /// This endpoint's ICE password.
    ice_pwd: []const u8,
    /// The hash of the certificate this endpoint presents.
    fingerprint: fingerprint.Fingerprint,
    /// The DTLS role this endpoint took.
    setup: setup.Role,
};

/// What was written back for one section.
pub const Section = struct {
    /// The section text, borrowing the caller's buffer.
    text: []const u8,
    /// Whether the stream was carried or refused.
    carried: bool,
    /// The direction this endpoint answered with, meaningful only when carried.
    direction: direction.Direction,
    /// How many payload types the answer kept.
    format_count: usize,
};

/// Write the answer to one offered media section.
///
/// Note:
/// - A section is refused when the offer already refused it, when the peer will not share a port
///   between RTP and RTCP, or when nothing is left after retransmission streams are dropped.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// offered - media_offer.MediaOffer
/// transport - Transport
/// accept - bool (false refuses the section whatever it offered)
///
/// Return:
/// - Section, whose text borrows `out`
/// - error.ZixNoSpace
pub fn write(
    out: []u8,
    offered: media_offer.MediaOffer,
    transport: Transport,
    accept: bool,
) Error!Section {
    if (!accept or !offered.isCarryable()) return refuseSection(out, offered.media_line, offered.mid);

    var appender = builder.Builder{ .out = out };
    const answered = direction.answerFor(offered.direction);

    try mediaLine(&appender, offered, address.portOf(transport.address));
    try connectionLine(&appender, transport.address);

    if (offered.mid) |tag| try appender.addAttribute("mid", tag);

    try appender.addAttribute(answered.name(), null);
    try appender.addAttribute(media_offer.RTCP_MUX, null);
    try appender.addAttribute("ice-ufrag", transport.ice_ufrag);
    try appender.addAttribute("ice-pwd", transport.ice_pwd);
    try fingerprintLine(&appender, &transport.fingerprint);
    try appender.addAttribute(setup.ATTRIBUTE, transport.setup.name());

    var count: usize = 0;
    for (offered.formats.slice()) |entry| {
        if (entry.is_retransmission) continue;

        count += 1;

        if (entry.rtpmap_value) |value| try appender.addAttribute(rtpmap.ATTRIBUTE, value);
        if (entry.fmtp_value) |value| try appender.addAttribute(fmtp.ATTRIBUTE, value);

        try feedbackLines(&appender, entry);
    }

    try candidateLine(&appender, transport.address);
    try appender.addAttribute(candidate.END_OF_CANDIDATES, null);

    return .{
        .text = appender.written(),
        .carried = true,
        .direction = answered,
        .format_count = count,
    };
}

/// Refuse a section: the same media type in the same place, with a port of zero.
///
/// Note:
/// - Takes the offered `m=` line rather than a media kind, so a section of a type zix does not
///   read at all can still be refused in the right position with the right shape.
/// - The format list is echoed because an `m=` line needs one, and RFC 3264 6 says the list of a
///   refused stream carries no meaning.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// media_line - media.Media (as the offer wrote it)
/// mid - ?[]const u8 (the offered tag, echoed when there was one)
///
/// Return:
/// - Section, whose text borrows `out`
/// - error.ZixNoSpace
pub fn refuseSection(out: []u8, media_line: media.Media, mid: ?[]const u8) Error!Section {
    var appender = builder.Builder{ .out = out };

    var value: [4 * format_ceiling + 64]u8 = undefined;
    const written = media.write(
        &value,
        media_line.media,
        REJECTED_PORT,
        media_line.proto,
        media_line.formats,
    ) catch return error.ZixNoSpace;

    try appender.addLine(.MEDIA, written);
    try connectionText(&appender, .IP4, REJECTED_ADDRESS);

    if (mid) |tag| try appender.addAttribute("mid", tag);

    return .{
        .text = appender.written(),
        .carried = false,
        .direction = .INACTIVE,
        .format_count = 0,
    };
}

/// Append the `m=` line of a carried section, listing the formats that were kept.
fn mediaLine(appender: *builder.Builder, offered: media_offer.MediaOffer, port: u16) Error!void {
    var formats: [4 * format_ceiling]u8 = undefined;
    var at: usize = 0;

    for (offered.formats.slice()) |entry| {
        if (entry.is_retransmission) continue;

        if (at != 0) {
            if (at + 1 > formats.len) return error.ZixNoSpace;

            formats[at] = ' ';
            at += 1;
        }

        var digits: [builder.MAX_DIGITS]u8 = undefined;
        const text = builder.writeNumber(&digits, entry.payload_type);

        if (at + text.len > formats.len) return error.ZixNoSpace;

        at += builder.copy(formats[at..], text);
    }

    try mediaLineWith(appender, offered.kind, port, formats[0..at]);
}

/// Append an `m=` line for a carried section.
fn mediaLineWith(
    appender: *builder.Builder,
    kind: media_offer.Kind,
    port: u16,
    formats: []const u8,
) Error!void {
    var value: [4 * format_ceiling + 64]u8 = undefined;
    const written = media.write(&value, kind.name(), port, media.RTP_PROTO, formats) catch
        return error.ZixNoSpace;

    try appender.addLine(.MEDIA, written);
}

/// Append the connection line for an address.
fn connectionLine(appender: *builder.Builder, host: IpAddress) Error!void {
    var text: [address.MAX_ADDRESS_LEN]u8 = undefined;
    const host_text = address.writeAddress(&text, host) catch return error.ZixNoSpace;

    try connectionText(appender, address.familyOf(host), host_text);
}

/// Append the connection line for an address already in text.
fn connectionText(appender: *builder.Builder, family: address.Family, host: []const u8) Error!void {
    var value: [address.MAX_CONNECTION_LEN]u8 = undefined;
    const written = address.writeConnection(&value, family, host) catch return error.ZixNoSpace;

    try appender.addLine(.CONNECTION, written);
}

/// Append the one host candidate this endpoint has, and close the list.
///
/// Note:
/// - An ice-lite agent gathers nothing and has nothing to trickle, so saying so at once saves the
///   peer waiting (RFC 8838 8).
fn candidateLine(appender: *builder.Builder, host: IpAddress) Error!void {
    const entry = ice.Candidate.host(host, .RTP, ice.SINGLE_ADDRESS_PREFERENCE);

    var value: [candidate.MAX_VALUE_LEN]u8 = undefined;
    const written = candidate.write(&value, entry) catch return error.ZixNoSpace;

    try appender.addAttribute(candidate.ATTRIBUTE, written);
}

/// Append the fingerprint attribute.
fn fingerprintLine(appender: *builder.Builder, value: *const fingerprint.Fingerprint) Error!void {
    var text: [fingerprint.MAX_VALUE_LEN]u8 = undefined;
    const written = fingerprint.write(&text, value) catch return error.ZixNoSpace;

    try appender.addAttribute(fingerprint.ATTRIBUTE, written);
}

/// Append the feedback entries that were both offered and are implemented.
fn feedbackLines(appender: *builder.Builder, entry: format.Format) Error!void {
    if (entry.offers_nack) try feedbackLine(appender, entry.payload_type, "nack", null);
    if (entry.offers_nack_pli) try feedbackLine(appender, entry.payload_type, "nack", "pli");
}

/// Append one feedback entry.
fn feedbackLine(appender: *builder.Builder, payload_type: u7, kind: []const u8, parameter: ?[]const u8) Error!void {
    var value: [rtcp_feedback.MAX_VALUE_LEN]u8 = undefined;
    const written = rtcp_feedback.write(&value, .{
        .applies = .{ .ONE = payload_type },
        .kind = kind,
        .parameter = parameter,
    }) catch return error.ZixNoSpace;

    try appender.addAttribute(rtcp_feedback.ATTRIBUTE, written);
}

/// How many formats the `m=` line buffer is sized for.
const format_ceiling: usize = format.MAX_FORMATS;

// --------------------------------------------------------------------------------------- //
// test cases

const attribute = @import("attribute.zig");
const session = @import("session.zig");

const browser_offer: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0 1\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:0\r\n" ++
    "a=sendrecv\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:1\r\n" ++
    "a=sendonly\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtpmap:96 VP8/90000\r\n" ++
    "a=rtcp-fb:96 goog-remb\r\n" ++
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n" ++
    "a=fmtp:97 apt=96\r\n";

fn testTransport() Transport {
    return .{
        .address = IpAddress.parse("192.0.2.1", 9091) catch unreachable,
        .ice_ufrag = "zixU",
        .ice_pwd = "zixPasswordOfProperLength01",
        .fingerprint = fingerprint.Fingerprint{
            .function = .SHA_256,
            .digest = @splat(0xAB),
            .len = 32,
        },
        .setup = .PASSIVE,
    };
}

fn offeredAt(index: usize) !media_offer.MediaOffer {
    const description = try session.parse(browser_offer);
    const section = description.section(index) orelse return error.TestUnexpectedResult;

    return media_offer.read(description, section);
}

test "zix sdp: media answer write, a carried audio section names the offered formats" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    try std.testing.expect(answered.carried);
    try std.testing.expectEqual(@as(usize, 2), answered.format_count);
    try std.testing.expect(std.mem.startsWith(u8, answered.text, "m=audio 9091 UDP/TLS/RTP/SAVPF 111 0\r\n"));
}

test "zix sdp: media answer write, the offered mapping and settings are echoed unchanged" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    try std.testing.expectEqualStrings("111 opus/48000/2", attribute.findValue(answered.text, "rtpmap").?);
    try std.testing.expectEqualStrings("111 minptime=10;useinbandfec=1", attribute.findValue(answered.text, "fmtp").?);
}

test "zix sdp: media answer write, the direction is the rfc 3264 answer" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;

    const audio = try write(&buf, try offeredAt(0), testTransport(), true);
    try std.testing.expectEqual(direction.Direction.SENDRECV, audio.direction);
    try std.testing.expect(attribute.has(audio.text, "sendrecv"));

    var other: [MAX_SECTION_BYTES]u8 = undefined;
    const video = try write(&other, try offeredAt(1), testTransport(), true);

    // The offer said sendonly, so the answer says recvonly and nothing else.
    try std.testing.expectEqual(direction.Direction.RECVONLY, video.direction);
    try std.testing.expect(attribute.has(video.text, "recvonly"));
    try std.testing.expect(!attribute.has(video.text, "sendonly"));
    try std.testing.expect(!attribute.has(video.text, "sendrecv"));
}

test "zix sdp: media answer write, a retransmission stream is left out" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(1), testTransport(), true);

    // 96 and 97 were offered, 97 is rtx, and nothing here keeps a packet history.
    try std.testing.expectEqual(@as(usize, 1), answered.format_count);
    try std.testing.expect(std.mem.startsWith(u8, answered.text, "m=video 9091 UDP/TLS/RTP/SAVPF 96\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "rtx") == null);
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "apt=96") == null);
}

test "zix sdp: media answer write, only implemented feedback is promised" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(1), testTransport(), true);

    try std.testing.expect(std.mem.indexOf(u8, answered.text, "a=rtcp-fb:96 nack\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "a=rtcp-fb:96 nack pli\r\n") != null);

    // Offered and not implemented, so not answered. Promising it would leave the peer waiting on
    // bandwidth estimates that never arrive.
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "goog-remb") == null);
}

test "zix sdp: media answer write, feedback that was not offered is not invented" {
    // The audio section offered no feedback at all.
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    try std.testing.expect(std.mem.indexOf(u8, answered.text, "rtcp-fb") == null);
}

test "zix sdp: media answer write, a carried section always shares the port" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    try std.testing.expect(attribute.has(answered.text, "rtcp-mux"));
}

test "zix sdp: media answer write, the transport facts are repeated per section" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    try std.testing.expectEqualStrings("zixU", attribute.findValue(answered.text, "ice-ufrag").?);
    try std.testing.expectEqualStrings("zixPasswordOfProperLength01", attribute.findValue(answered.text, "ice-pwd").?);
    try std.testing.expectEqualStrings("passive", attribute.findValue(answered.text, "setup").?);
    try std.testing.expect(attribute.findValue(answered.text, "fingerprint") != null);
}

test "zix sdp: media answer write, the mid is echoed back" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(1), testTransport(), true);

    try std.testing.expectEqualStrings("1", attribute.findValue(answered.text, "mid").?);
}

test "zix sdp: media answer write, refusing keeps the section in its place" {
    // The rule the whole file turns on: a refusal is a section with a zero port, never a section
    // left out, or every section behind it answers the wrong stream.
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), false);

    try std.testing.expect(!answered.carried);
    try std.testing.expectEqual(@as(usize, 0), answered.format_count);
    try std.testing.expect(std.mem.startsWith(u8, answered.text, "m=audio 0 UDP/TLS/RTP/SAVPF 111 0\r\n"));
    try std.testing.expectEqualStrings("0", attribute.findValue(answered.text, "mid").?);
}

test "zix sdp: media answer write, a refusal carries no transport and no codecs" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), false);

    try std.testing.expect(std.mem.indexOf(u8, answered.text, "ice-ufrag") == null);
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "fingerprint") == null);
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "rtpmap") == null);
    try std.testing.expect(std.mem.indexOf(u8, answered.text, "rtcp-mux") == null);
}

test "zix sdp: media answer write, a section without rtcp-mux is refused even when accepted" {
    const no_mux: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    const description = try session.parse(no_mux);
    const offered = try media_offer.read(description, description.section(0).?);

    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, offered, testTransport(), true);

    try std.testing.expect(!answered.carried);
    try std.testing.expect(std.mem.startsWith(u8, answered.text, "m=audio 0 "));
}

test "zix sdp: media answer write, an offer that refused itself stays refused" {
    const refused: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 0 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:1\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtpmap:96 VP8/90000\r\n";

    const description = try session.parse(refused);
    const offered = try media_offer.read(description, description.section(0).?);

    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, offered, testTransport(), true);

    try std.testing.expect(!answered.carried);
}

test "zix sdp: media answer write, what was written parses as a media section" {
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);

    var document: [MAX_SECTION_BYTES + 128]u8 = undefined;
    const head = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";

    @memcpy(document[0..head.len], head);
    @memcpy(document[head.len..][0..answered.text.len], answered.text);

    const parsed = try session.parse(document[0 .. head.len + answered.text.len]);
    const section = parsed.section(0).?;
    const media_line = try section.mediaLine();

    try std.testing.expectEqual(@as(usize, 1), parsed.sectionCount());
    try std.testing.expect(media_line.isRtpMedia());
    try std.testing.expectEqual(@as(u16, 9091), media_line.port);
    try std.testing.expectEqualStrings("111 0", media_line.formats);
}

test "zix sdp: media answer write, a short buffer errors" {
    var buf: [32]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, try offeredAt(0), testTransport(), true));
    try std.testing.expectError(error.ZixNoSpace, write(buf[0..8], try offeredAt(0), testTransport(), false));
}

test "zix sdp: media answer write, a static payload type answers without a mapping" {
    // Payload type 0 has no a=rtpmap in the offer and needs none in the answer either.
    var buf: [MAX_SECTION_BYTES]u8 = undefined;
    const answered = try write(&buf, try offeredAt(0), testTransport(), true);
    var walk = attribute.Iterator.begin(answered.text);
    var mappings: usize = 0;

    while (walk.next()) |entry| {
        if (std.mem.eql(u8, entry.name, "rtpmap")) mappings += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), answered.format_count);
    try std.testing.expectEqual(@as(usize, 1), mappings);
}
