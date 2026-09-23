//! zix WebRTC answer builder (RFC 3264 6, RFC 8829 5.3, RFC 8839 4.3.2, RFC 8841 10.3).
//!
//! What:
//! - Turns an offer into the answer that goes back, and hands out the facts the layers under it
//!   need: which DTLS role zix took, which stream identifiers that leaves it, and which
//!   certificate hash to hold the peer to.
//!
//! Note:
//! - The origin line names 0.0.0.0 whatever address the answer is really on. RFC 8829 5.2.1 asks
//!   for a non-meaningful address there so a local address does not leak into a field nothing
//!   reads (RFC 8828). The real address goes in the connection line and the candidate, which are
//!   the two places it means something.
//! - The answer is always `a=setup:passive`, so zix is the DTLS server and opens data channels on
//!   odd stream identifiers. An offer that leaves no such role is refused rather than answered
//!   with a role no layer here can take.
//! - The transport port and the SCTP port are separate. The `m=` line carries the UDP port the
//!   candidate is on, and `a=sctp-port` carries the port inside the association.
//! - `a=tls-id` goes out only if the offer had one (RFC 8842 5.3), and the caller supplies it.
//!   Inventing one for an offer that carried none puts an attribute in the answer that RFC 8842
//!   says must not be there.
//! - One host candidate goes out, followed by `a=end-of-candidates`. An ice-lite agent gathers
//!   nothing and has nothing to trickle, so saying so at once saves the peer waiting
//!   (RFC 8838 8).
//! - EVERY offered section is answered, in the order the offer put them (RFC 3264 6). A section
//!   zix will not carry gets a port of zero, never omission. An answer with fewer sections than
//!   the offer lines each one up against the wrong stream, and a browser reads that as an answer
//!   to a different offer.
//! - Audio and video are carried only when the caller asks for it. The default is to refuse them
//!   properly, which is what the data-channel-only peer wants and is still a valid answer.

const std = @import("std");

const address = @import("address.zig");
const attribute = @import("attribute.zig");
const builder = @import("builder.zig");
const candidate = @import("candidate.zig");
const fingerprint = @import("fingerprint.zig");
const ice = @import("../ice/candidate.zig");
const line = @import("line.zig");
const media = @import("media.zig");
const media_answer = @import("media_answer.zig");
const media_offer = @import("media_offer.zig");
const offer = @import("offer.zig");
const session = @import("session.zig");
const setup = @import("setup.zig");
const stream_id = @import("../datachannel/stream_id.zig");

const IpAddress = std.Io.net.IpAddress;

/// Room for the longest answer this builds: a data channel section, an audio section, and a
/// video section, each with a full format list and the transport facts repeated.
pub const MAX_ANSWER_BYTES: usize = 8192;

/// The most sections one answer will write. An offer with more is refused rather than answered
/// short, because a short answer is worse than none.
pub const MAX_SECTIONS: usize = 16;

/// The SCTP port a WebRTC data channel uses (RFC 8832 6).
pub const DEFAULT_SCTP_PORT: u16 = 5000;

/// The largest message this endpoint will take, matching what browsers offer.
pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 256 * 1024;

/// The address the origin line names, so no local address leaks (RFC 8828).
pub const ORIGIN_ADDRESS: []const u8 = "IN IP4 0.0.0.0";

/// The largest session id to draw, and a mask that turns any draw into a legal one.
///
/// Note:
/// - RFC 8829 5.2.1 wants a value representable as a 64-bit SIGNED integer, which is what browsers
///   read it into. A full-range u64 draw is over that half the time, and the answer is then refused
///   whole with "Invalid owner session id" before anything else in it is looked at.
/// - It is 62 bits rather than 63 so the value stays clear of the signed boundary in every parser
///   that reads it, and it is still far more than enough to be unique per session.
pub const MAX_SESSION_ID: u64 = (@as(u64, 1) << 62) - 1;

/// Everything that stops an answer from being built.
pub const Error = error{
    /// The output buffer is too small.
    ZixNoSpace,
    /// The offer leaves this endpoint no DTLS role it can take.
    ZixUnsupportedRole,
    /// The offer has more sections than MAX_SECTIONS.
    ZixTooManySections,
    /// A media section this endpoint could not read far enough to answer.
    ZixBadMediaSection,
};

/// What this endpoint answers with.
pub const Config = struct {
    /// This endpoint's ICE username fragment.
    ice_ufrag: []const u8,
    /// This endpoint's ICE password, which is the key connectivity checks are signed with.
    ice_pwd: []const u8,
    /// The hash of the certificate this endpoint will present in the DTLS handshake.
    fingerprint: fingerprint.Fingerprint,
    /// Where this endpoint listens, which becomes the connection line and the one candidate.
    address: IpAddress,
    /// The SCTP port inside the association.
    sctp_port: u16 = DEFAULT_SCTP_PORT,
    /// The largest message this endpoint will take, or zero for any size.
    max_message_size: u32 = DEFAULT_MAX_MESSAGE_SIZE,
    /// Unique per session (RFC 8829 5.2.1), drawn by the caller. Keep it at or below
    /// MAX_SESSION_ID: a browser reads this field into a signed 64-bit integer and refuses the
    /// whole answer if it does not fit.
    session_id: u64,
    /// This endpoint's identifier for the DTLS association, sent only when the offer had one.
    tls_id: ?[]const u8 = null,
    /// Whether to carry offered audio and video. Off by default, which answers a media section
    /// with a proper refusal rather than pretending zix will relay it.
    carry_media: bool = false,
};

/// The answer, and everything the layers under it need out of the exchange.
pub const Answer = struct {
    /// The answer text, borrowing the caller's output buffer.
    text: []const u8,
    /// The role this endpoint took, which is always passive.
    setup: setup.Role,
    /// Which half of the data channel identifier space that leaves this endpoint.
    stream_role: stream_id.Role,
    /// How many sections the answer carries, which is always how many the offer had.
    section_count: usize,
    /// How many of those carry media rather than refusing it.
    carried_media_count: usize,
    /// The certificate hash the peer's DTLS handshake has to match.
    peer_fingerprint: fingerprint.Fingerprint,
    /// The peer's ICE username fragment, borrowed from the offer.
    peer_ice_ufrag: []const u8,
    /// The peer's ICE password, borrowed from the offer.
    peer_ice_pwd: []const u8,
    /// The SCTP port the peer will use.
    peer_sctp_port: u16,
    /// The largest message the peer will take, or zero for any size.
    peer_max_message_size: u32,
};

/// Build the answer to an offer.
///
/// Note:
/// - Everything borrowed in the result points either at `out` or at the offer, so both have to
///   outlive it.
/// - One section is written per offered section, in the offer's own order. The data channel one
///   is carried, audio and video are carried when `config.carry_media` says so, and everything
///   else is refused with a port of zero.
///
/// Param:
/// out - []u8 (at least MAX_ANSWER_BYTES)
/// offered - offer.Offer
/// config - Config
///
/// Return:
/// - Answer, whose text borrows `out`
/// - error.ZixUnsupportedRole if the offer leaves no DTLS role this endpoint can take
/// - error.ZixTooManySections, error.ZixBadMediaSection, error.ZixNoSpace
pub fn write(out: []u8, offered: offer.Offer, config: Config) Error!Answer {
    const role = setup.answerFor(offered.setup) catch return error.ZixUnsupportedRole;
    const role_streams = setup.streamRole(role) catch return error.ZixUnsupportedRole;

    var appender = builder.Builder{ .out = out };

    try appender.addLine(.VERSION, "0");
    try originLine(&appender, config.session_id);
    try appender.addLine(.SESSION_NAME, "-");
    try appender.addLine(.TIME, "0 0");

    // The group is echoed as the offer wrote it, because an answer that changes the tags in a
    // BUNDLE group is answering a different grouping (RFC 8843 7.2).
    if (offered.bundle) |group| try appender.addAttribute("group", group);

    try appender.addAttribute("ice-lite", null);

    const transport = media_answer.Transport{
        .address = config.address,
        .ice_ufrag = config.ice_ufrag,
        .ice_pwd = config.ice_pwd,
        .fingerprint = config.fingerprint,
        .setup = role,
    };

    var index: usize = 0;
    var carried_media: usize = 0;

    while (offered.description.section(index)) |section| : (index += 1) {
        if (index == MAX_SECTIONS) return error.ZixTooManySections;

        // Pointer identity, because two sections can read alike and only one of them is the one
        // offer.zig chose to answer as the data channel.
        if (section.text.ptr == offered.section.text.ptr) {
            try dataChannelSection(&appender, offered, config, role);
            continue;
        }

        const written = try mediaSection(out[appender.at..], offered, section, transport, config);

        if (written.carried) carried_media += 1;

        appender.at += written.text.len;
    }

    return .{
        .text = appender.written(),
        .setup = role,
        .stream_role = role_streams,
        .section_count = index,
        .carried_media_count = carried_media,
        .peer_fingerprint = offered.fingerprint,
        .peer_ice_ufrag = offered.ice_ufrag,
        .peer_ice_pwd = offered.ice_pwd,
        .peer_sctp_port = offered.sctp_port,
        .peer_max_message_size = offered.max_message_size,
    };
}

/// Append the data channel section.
fn dataChannelSection(
    appender: *builder.Builder,
    offered: offer.Offer,
    config: Config,
    role: setup.Role,
) Error!void {
    try dataChannelMediaLine(appender, address.portOf(config.address));
    try connectionLine(appender, config.address);
    try appender.addAttribute("ice-ufrag", config.ice_ufrag);
    try appender.addAttribute("ice-pwd", config.ice_pwd);
    try appender.addAttribute("ice-options", "ice2");
    try fingerprintLine(appender, &config.fingerprint);
    try appender.addAttribute(setup.ATTRIBUTE, role.name());

    if (offered.mid) |tag| try appender.addAttribute("mid", tag);
    if (offered.tls_id != null) {
        if (config.tls_id) |own| try appender.addAttribute("tls-id", own);
    }

    try appender.addNumber("sctp-port", config.sctp_port);
    try appender.addNumber("max-message-size", config.max_message_size);
    try candidateLine(appender, config.address);
    try appender.addAttribute(candidate.END_OF_CANDIDATES, null);
}

/// Write one section that is not the data channel: audio or video when it can be carried, and a
/// refusal otherwise.
fn mediaSection(
    out: []u8,
    offered: offer.Offer,
    section: session.Section,
    transport: media_answer.Transport,
    config: Config,
) Error!media_answer.Section {
    if (media_offer.isMediaSection(section)) {
        const parsed = media_offer.read(offered.description, section) catch
            return error.ZixBadMediaSection;

        return media_answer.write(out, parsed, transport, config.carry_media) catch
            return error.ZixNoSpace;
    }

    // A media type this endpoint does not read at all, including a second data channel section
    // and an unencrypted RTP profile. It still needs a place in the answer.
    const media_line = section.mediaLine() catch return error.ZixBadMediaSection;
    const mid = attribute.findValue(section.text, "mid");

    return media_answer.refuseSection(out, media_line, mid) catch return error.ZixNoSpace;
}

/// Append the origin line.
fn originLine(appender: *builder.Builder, session_id: u64) Error!void {
    var value: [64]u8 = undefined;
    var digits: [builder.MAX_DIGITS]u8 = undefined;

    const identifier = builder.writeNumber(&digits, session_id);
    const total = 2 + identifier.len + 3 + ORIGIN_ADDRESS.len;

    if (value.len < total) return error.ZixNoSpace;

    var at: usize = 0;
    at += builder.copy(value[at..], "- ");
    at += builder.copy(value[at..], identifier);
    at += builder.copy(value[at..], " 1 ");
    at += builder.copy(value[at..], ORIGIN_ADDRESS);

    try appender.addLine(.ORIGIN, value[0..at]);
}

/// Append the media line for the data channel section.
fn dataChannelMediaLine(appender: *builder.Builder, port: u16) Error!void {
    var value: [96]u8 = undefined;
    const written = media.write(
        &value,
        media.DATA_CHANNEL_MEDIA,
        port,
        media.DATA_CHANNEL_PROTO,
        media.DATA_CHANNEL_FORMAT,
    ) catch return error.ZixNoSpace;

    try appender.addLine(.MEDIA, written);
}

/// Append the connection line.
fn connectionLine(appender: *builder.Builder, host: IpAddress) Error!void {
    var text: [address.MAX_ADDRESS_LEN]u8 = undefined;
    const host_text = address.writeAddress(&text, host) catch return error.ZixNoSpace;

    var value: [address.MAX_CONNECTION_LEN]u8 = undefined;
    const written = address.writeConnection(&value, address.familyOf(host), host_text) catch
        return error.ZixNoSpace;

    try appender.addLine(.CONNECTION, written);
}

/// Append the fingerprint attribute.
fn fingerprintLine(appender: *builder.Builder, value: *const fingerprint.Fingerprint) Error!void {
    var text: [fingerprint.MAX_VALUE_LEN]u8 = undefined;
    const written = fingerprint.write(&text, value) catch return error.ZixNoSpace;

    try appender.addAttribute(fingerprint.ATTRIBUTE, written);
}

/// Append the one host candidate this endpoint has.
fn candidateLine(appender: *builder.Builder, host: IpAddress) Error!void {
    const entry = ice.Candidate.host(host, .RTP, ice.SINGLE_ADDRESS_PREFERENCE);

    var value: [candidate.MAX_VALUE_LEN]u8 = undefined;
    const written = candidate.write(&value, entry) catch return error.ZixNoSpace;

    try appender.addAttribute(candidate.ATTRIBUTE, written);
}

// --------------------------------------------------------------------------------------- //
// test cases

const session_mod = @import("session.zig");

const browser_offer: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0\r\n" ++
    "a=msid-semantic: WMS\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=ice-ufrag:4ZcD\r\n" ++
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
    "a=ice-options:trickle\r\n" ++
    "a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:" ++
    "DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
    "a=setup:actpass\r\n" ++
    "a=mid:0\r\n" ++
    "a=sctp-port:5000\r\n" ++
    "a=max-message-size:262144\r\n";

/// The same exchange with a camera and a microphone alongside the data channel, which is what a
/// browser sends when getUserMedia has been called.
const bundled_offer: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0 1 2\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=ice-ufrag:4ZcD\r\n" ++
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
    "a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:" ++
    "DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
    "a=setup:actpass\r\n" ++
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
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n" ++
    "a=fmtp:97 apt=96\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=mid:2\r\n" ++
    "a=sctp-port:5000\r\n" ++
    "a=max-message-size:262144\r\n";

const listen_address: IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 200 }, .port = 9091 } };

fn testConfig() Config {
    return .{
        .ice_ufrag = "zixA",
        .ice_pwd = "zixPasswordThatIsLongEnough",
        .fingerprint = fingerprint.compute("a certificate", .SHA_256),
        .address = listen_address,
        .session_id = 4_611_731_400_430_051_337,
    };
}

/// Build the answer to the browser offer, for the tests below.
fn answerText(out: []u8) ![]const u8 {
    const parsed = try offer.read(browser_offer);

    return (try write(out, parsed, testConfig())).text;
}

test "zix sdp: answer write, the result is a description that parses" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);

    try std.testing.expectEqual(@as(usize, 1), parsed.sectionCount());
    try std.testing.expect(parsed.dataChannelSection() != null);
}

test "zix sdp: answer write, the first four lines are the ones JSEP requires" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);

    try std.testing.expect(std.mem.startsWith(u8, text, "v=0\r\no=- 4611731400430051337 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"));
}

test "zix sdp: answer write, the origin line does not carry the real address" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const origin = line.find(parsed.session, .ORIGIN) orelse return error.TestUnexpectedResult;

    // RFC 8828: the address in this field is read by nobody and leaks a local address.
    try std.testing.expect(std.mem.indexOf(u8, origin.value, "203.0.113.200") == null);
    try std.testing.expect(std.mem.endsWith(u8, origin.value, ORIGIN_ADDRESS));
}

test "zix sdp: answer write, the answer is passive so zix is the DTLS server" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed = try offer.read(browser_offer);
    const result = try write(&out, parsed, testConfig());

    try std.testing.expectEqual(setup.Role.PASSIVE, result.setup);
    try std.testing.expectEqual(stream_id.Role.DTLS_SERVER, result.stream_role);
    try std.testing.expect(std.mem.indexOf(u8, result.text, "a=setup:passive\r\n") != null);
}

test "zix sdp: answer write, an offer that needs zix to start the handshake is refused" {
    var text: [browser_offer.len]u8 = undefined;
    @memcpy(&text, browser_offer);

    const at = std.mem.indexOf(u8, &text, "setup:actpass").?;
    @memcpy(text[at..][0.."setup:passive".len], "setup:passive");

    const parsed = try offer.read(&text);

    var out: [MAX_ANSWER_BYTES]u8 = undefined;

    try std.testing.expectError(error.ZixUnsupportedRole, write(&out, parsed, testConfig()));
}

test "zix sdp: answer write, the media section keeps the offered shape" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;
    const media_line = try section.mediaLine();

    try std.testing.expect(media_line.isDataChannel());
    try std.testing.expect(!media_line.isRejected());
    try std.testing.expectEqual(@as(u16, 9091), media_line.port);
}

test "zix sdp: answer write, the transport port and the SCTP port are the two different numbers" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(u16, 9091), (try section.mediaLine()).port);
    try std.testing.expectEqualStrings("5000", attribute.findValue(section.text, "sctp-port").?);
}

test "zix sdp: answer write, the connection line carries the real address" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;
    const connection = line.find(section.text, .CONNECTION) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("IN IP4 203.0.113.200", connection.value);
}

test "zix sdp: answer write, an ice-lite agent says so and names its credentials" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expect(attribute.has(parsed.session, "ice-lite"));
    try std.testing.expectEqualStrings("zixA", attribute.findValue(section.text, "ice-ufrag").?);
    try std.testing.expectEqualStrings(
        "zixPasswordThatIsLongEnough",
        attribute.findValue(section.text, "ice-pwd").?,
    );
    try std.testing.expectEqualStrings("ice2", attribute.findValue(section.text, "ice-options").?);
}

test "zix sdp: answer write, the fingerprint is this endpoint's own" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    const written = attribute.findValue(section.text, fingerprint.ATTRIBUTE).?;
    const read_back = try fingerprint.read(written);
    const own = fingerprint.compute("a certificate", .SHA_256);

    try std.testing.expect(own.matches(&read_back));
}

test "zix sdp: answer write, the peer's fingerprint comes back to be pinned against" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed = try offer.read(browser_offer);
    const result = try write(&out, parsed, testConfig());

    try std.testing.expectEqual(fingerprint.Function.SHA_256, result.peer_fingerprint.function);
    try std.testing.expectEqual(@as(u8, 0x6B), result.peer_fingerprint.digest[0]);
    try std.testing.expectEqualStrings("4ZcD", result.peer_ice_ufrag);
    try std.testing.expectEqualStrings("2/1muCWoOi3uLifh0NuRHlZ6", result.peer_ice_pwd);
    try std.testing.expectEqual(@as(u16, 5000), result.peer_sctp_port);
    try std.testing.expectEqual(@as(u32, 262_144), result.peer_max_message_size);
}

test "zix sdp: answer write, the bundle group and mid are echoed back" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("BUNDLE 0", attribute.findValue(parsed.session, "group").?);
    try std.testing.expectEqualStrings("0", attribute.findValue(section.text, "mid").?);
}

test "zix sdp: answer write, an offer with no bundle group gets no group back" {
    const plain: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:4ZcD\r\n" ++
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
        "a=fingerprint:sha-1 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01\r\n" ++
        "a=setup:actpass\r\n" ++
        "a=sctp-port:5000\r\n";

    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed_offer = try offer.read(plain);
    const result = try write(&out, parsed_offer, testConfig());
    const parsed = try session_mod.parse(result.text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expect(!attribute.has(parsed.session, "group"));
    try std.testing.expect(!attribute.has(section.text, "mid"));
}

test "zix sdp: answer write, one host candidate goes out and the list is closed" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try session_mod.parse(text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    const written = attribute.findValue(section.text, candidate.ATTRIBUTE).?;
    const entry = try candidate.read(written);

    try std.testing.expectEqualStrings("203.0.113.200", entry.address);
    try std.testing.expectEqual(@as(u16, 9091), entry.port);
    try std.testing.expectEqual(ice.Type.HOST, entry.kind);
    try std.testing.expect(attribute.has(section.text, candidate.END_OF_CANDIDATES));
}

test "zix sdp: answer write, a tls-id goes out only when the offer had one" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed_offer = try offer.read(browser_offer);

    var config = testConfig();
    config.tls_id = "dbc8de77cddef001be90";

    const result = try write(&out, parsed_offer, config);
    const parsed = try session_mod.parse(result.text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    // RFC 8842 5.3: the offer carried none, so the answer must not carry one either.
    try std.testing.expect(!attribute.has(section.text, "tls-id"));
}

test "zix sdp: answer write, a tls-id is echoed when the offer carried one" {
    const with_id: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=tls-id:abc3de65cddef001be82\r\n" ++
        "a=ice-ufrag:4ZcD\r\n" ++
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
        "a=fingerprint:sha-1 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01\r\n" ++
        "a=setup:actpass\r\n" ++
        "a=sctp-port:5000\r\n";

    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed_offer = try offer.read(with_id);

    var config = testConfig();
    config.tls_id = "dbc8de77cddef001be90";

    const result = try write(&out, parsed_offer, config);
    const parsed = try session_mod.parse(result.text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("dbc8de77cddef001be90", attribute.findValue(section.text, "tls-id").?);
}

test "zix sdp: answer write, an IPv6 address comes out compressed in both places" {
    var bytes: [16]u8 = @splat(0);
    bytes[0] = 0x20;
    bytes[1] = 0x01;
    bytes[2] = 0x0d;
    bytes[3] = 0xb8;
    bytes[15] = 0x01;

    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed_offer = try offer.read(browser_offer);

    var config = testConfig();
    config.address = .{ .ip6 = .{ .bytes = bytes, .port = 9091 } };

    const result = try write(&out, parsed_offer, config);
    const parsed = try session_mod.parse(result.text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;
    const connection = line.find(section.text, .CONNECTION) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("IN IP6 2001:db8::1", connection.value);
    try std.testing.expect(std.mem.indexOf(u8, section.text, "2001:db8::1 9091 typ host") != null);
}

test "zix sdp: answer write, the max message size is this endpoint's own" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed_offer = try offer.read(browser_offer);

    var config = testConfig();
    config.max_message_size = 65_536;

    const result = try write(&out, parsed_offer, config);
    const parsed = try session_mod.parse(result.text);
    const section = parsed.dataChannelSection() orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("65536", attribute.findValue(section.text, "max-message-size").?);
}

test "zix sdp: answer write, a short buffer errors instead of writing a partial answer" {
    var out: [64]u8 = undefined;
    const parsed_offer = try offer.read(browser_offer);

    try std.testing.expectError(error.ZixNoSpace, write(&out, parsed_offer, testConfig()));
}

test "zix sdp: answer write, the answer reads back as an offer would" {
    // The strongest check available without a peer: the answer this endpoint builds is itself a
    // description the reader accepts, with every field it was given.
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const text = try answerText(&out);
    const parsed = try offer.read(text);

    try std.testing.expectEqualStrings("zixA", parsed.ice_ufrag);
    try std.testing.expectEqualStrings("zixPasswordThatIsLongEnough", parsed.ice_pwd);
    try std.testing.expectEqual(setup.Role.PASSIVE, parsed.setup);
    try std.testing.expectEqual(@as(u16, 5000), parsed.sctp_port);
    try std.testing.expectEqual(DEFAULT_MAX_MESSAGE_SIZE, parsed.max_message_size);
    try std.testing.expect(parsed.ice_lite);
    try std.testing.expect(parsed.ice2);
}

test "zix sdp: answer write, every offered section is answered in its own place" {
    // The rule the section walk exists for: three offered, three answered, same order. An answer
    // with only the data channel lines each section up against the wrong stream.
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed = try offer.read(bundled_offer);
    const answered = try write(&out, parsed, testConfig());
    const description = try session_mod.parse(answered.text);

    try std.testing.expectEqual(@as(usize, 3), answered.section_count);
    try std.testing.expectEqual(@as(usize, 3), description.sectionCount());

    try std.testing.expectEqualStrings("audio", (try description.section(0).?.mediaLine()).media);
    try std.testing.expectEqualStrings("video", (try description.section(1).?.mediaLine()).media);
    try std.testing.expect((try description.section(2).?.mediaLine()).isDataChannel());
}

test "zix sdp: answer write, the mid of each answered section matches the offer" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed = try offer.read(bundled_offer);
    const description = try session_mod.parse((try write(&out, parsed, testConfig())).text);

    try std.testing.expectEqualStrings("0", attribute.findValue(description.section(0).?.text, "mid").?);
    try std.testing.expectEqualStrings("1", attribute.findValue(description.section(1).?.text, "mid").?);
    try std.testing.expectEqualStrings("2", attribute.findValue(description.section(2).?.text, "mid").?);
}

test "zix sdp: answer write, media is refused properly by default" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    const parsed = try offer.read(bundled_offer);
    const answered = try write(&out, parsed, testConfig());
    const description = try session_mod.parse(answered.text);

    try std.testing.expectEqual(@as(usize, 0), answered.carried_media_count);
    try std.testing.expect((try description.section(0).?.mediaLine()).isRejected());
    try std.testing.expect((try description.section(1).?.mediaLine()).isRejected());

    // And the data channel is still carried on the real port.
    try std.testing.expect(!(try description.section(2).?.mediaLine()).isRejected());
    try std.testing.expectEqual(@as(u16, 9091), (try description.section(2).?.mediaLine()).port);
}

test "zix sdp: answer write, media is carried when the caller asks for it" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    var config = testConfig();
    config.carry_media = true;

    const parsed = try offer.read(bundled_offer);
    const answered = try write(&out, parsed, config);
    const description = try session_mod.parse(answered.text);

    try std.testing.expectEqual(@as(usize, 2), answered.carried_media_count);

    const audio = try description.section(0).?.mediaLine();
    try std.testing.expect(!audio.isRejected());
    try std.testing.expectEqual(@as(u16, 9091), audio.port);
    try std.testing.expectEqualStrings("111 0", audio.formats);

    // The retransmission stream is dropped, so the video list is shorter than what was offered.
    const video = try description.section(1).?.mediaLine();
    try std.testing.expectEqualStrings("96", video.formats);
}

test "zix sdp: answer write, a carried media section answers the offered direction" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    var config = testConfig();
    config.carry_media = true;

    const parsed = try offer.read(bundled_offer);
    const description = try session_mod.parse((try write(&out, parsed, config)).text);

    try std.testing.expect(attribute.has(description.section(0).?.text, "sendrecv"));
    try std.testing.expect(attribute.has(description.section(1).?.text, "recvonly"));
    try std.testing.expect(attribute.has(description.section(1).?.text, "rtcp-mux"));
}

test "zix sdp: answer write, a carried media section repeats the transport facts" {
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    var config = testConfig();
    config.carry_media = true;

    const parsed = try offer.read(bundled_offer);
    const description = try session_mod.parse((try write(&out, parsed, config)).text);
    const audio = description.section(0).?.text;

    try std.testing.expectEqualStrings("zixA", attribute.findValue(audio, "ice-ufrag").?);
    try std.testing.expectEqualStrings("passive", attribute.findValue(audio, "setup").?);
    try std.testing.expect(attribute.findValue(audio, "fingerprint") != null);
}

test "zix sdp: answer write, the data channel answer is unchanged by the sections around it" {
    // The data channel half of the answer must read exactly as it did before media sections
    // existed, whichever position the offer put it in.
    var bundled_out: [MAX_ANSWER_BYTES]u8 = undefined;
    const bundled = try write(&bundled_out, try offer.read(bundled_offer), testConfig());
    const bundled_section = (try session_mod.parse(bundled.text)).dataChannelSection().?;

    var plain_out: [MAX_ANSWER_BYTES]u8 = undefined;
    const plain = try write(&plain_out, try offer.read(browser_offer), testConfig());
    const plain_section = (try session_mod.parse(plain.text)).dataChannelSection().?;

    try std.testing.expectEqualStrings("5000", attribute.findValue(bundled_section.text, "sctp-port").?);
    try std.testing.expectEqualStrings(
        attribute.findValue(plain_section.text, "sctp-port").?,
        attribute.findValue(bundled_section.text, "sctp-port").?,
    );
    try std.testing.expect(attribute.has(bundled_section.text, "end-of-candidates"));
    try std.testing.expectEqual(bundled.stream_role, plain.stream_role);
}

test "zix sdp: answer write, an unencrypted media section is refused even when media is carried" {
    const plain_rtp: []const u8 =
        "v=0\r\n" ++
        "o=- 1 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 49170 RTP/AVP 0\r\n" ++
        "a=mid:0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:4ZcD\r\n" ++
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
        "a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:" ++
        "DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
        "a=setup:actpass\r\n" ++
        "a=mid:1\r\n" ++
        "a=sctp-port:5000\r\n";

    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    var config = testConfig();
    config.carry_media = true;

    const answered = try write(&out, try offer.read(plain_rtp), config);
    const description = try session_mod.parse(answered.text);

    try std.testing.expectEqual(@as(usize, 2), answered.section_count);
    try std.testing.expectEqual(@as(usize, 0), answered.carried_media_count);

    // The refusal keeps the offered media type and transport, so the peer can line it up.
    const refused = try description.section(0).?.mediaLine();
    try std.testing.expect(refused.isRejected());
    try std.testing.expectEqualStrings("audio", refused.media);
    try std.testing.expectEqualStrings("RTP/AVP", refused.proto);
}

test "zix sdp: answer write, an offer with more sections than the ceiling is refused" {
    // A short answer is worse than none, so this errors rather than writing what fits.
    var text: [4096]u8 = undefined;
    const head = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const data_channel = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:4ZcD\r\na=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6\r\n" ++
        "a=fingerprint:sha-256 6B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:" ++
        "DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
        "a=setup:actpass\r\na=sctp-port:5000\r\n";
    const spare = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtcp-mux\r\n";

    var at: usize = 0;
    @memcpy(text[at..][0..head.len], head);
    at += head.len;
    @memcpy(text[at..][0..data_channel.len], data_channel);
    at += data_channel.len;

    for (0..MAX_SECTIONS) |_| {
        @memcpy(text[at..][0..spare.len], spare);
        at += spare.len;
    }

    var out: [MAX_ANSWER_BYTES]u8 = undefined;

    try std.testing.expectError(error.ZixTooManySections, write(&out, try offer.read(text[0..at]), testConfig()));
}

test "zix sdp: answer write, a carried media answer reads back through the media reader" {
    // The far side of the exchange: what zix wrote has to parse as a media section that a reader
    // can take apart again.
    var out: [MAX_ANSWER_BYTES]u8 = undefined;
    var config = testConfig();
    config.carry_media = true;

    const answered = try write(&out, try offer.read(bundled_offer), config);
    const description = try session_mod.parse(answered.text);
    const read_back = try media_offer.read(description, description.section(1).?);

    try std.testing.expectEqual(media_offer.Kind.VIDEO, read_back.kind);
    try std.testing.expect(read_back.rtcp_mux);
    try std.testing.expect(read_back.isCarryable());
    try std.testing.expectEqual(@as(usize, 1), read_back.formats.len);
    try std.testing.expect(read_back.formats.find(96).?.offers_nack_pli);
}
