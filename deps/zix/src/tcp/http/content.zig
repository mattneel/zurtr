//! zix http content

const std = @import("std");
const media_type = @import("../../utils/media_type.zig");

pub const Type = enum(u8) {
    const Self = @This();

    // --------------------------------------------------------- //

    TEXT_PLAIN,
    TEXT_HTML,
    TEXT_CSS, // css, min.css
    TEXT_CSV,
    TEXT_EVENT_STREAM,

    AUDIO_MPEG,
    AUDIO_WAV,
    AUDIO_FLAC,
    AUDIO_MIDI, // mid, midi

    APPLICATION_JAVASCRIPT, // js, min.js
    APPLICATION_JSON, // json, map
    APPLICATION_PDF,
    APPLICATION_XML,
    APPLICATION_RTF,
    APPLICATION_ZIP,
    APPLICATION_GZIP,
    APPLICATION_TAR,
    APPLICATION_7Z_COMPRESSED,
    APPLICATION_VND_RAR,
    APPLICATION_LD_JSON,
    APPLICATION_RDF_XML,
    APPLICATION_RSS_XML,
    APPLICATION_ATOM_XML,
    APPLICATION_GRAPHQL, // graphql and graphqls
    APPLICATION_JSONPATH, // RFC 10008 query content
    APPLICATION_SQL, // RFC 10008 query content
    APPLICATION_X_WWW_FORM_URLENCODED, // RFC 10008 query content
    APPLICATION_WASM,
    APPLICATION_MANIFEST_JSON, // manifest, webmanifest
    APPLICATION_OCTET_STREAM,

    MULTIPART_FORM_DATA, // RFC 10008 query content

    IMAGE_PNG,
    IMAGE_JPEG, // jpeg, jpg
    IMAGE_GIF,
    IMAGE_SVG_XML,
    IMAGE_WEBP,
    IMAGE_X_ICON,

    VIDEO_MP4,
    VIDEO_WEBM,
    VIDEO_OGG,
    VIDEO_MPEG,
    VIDEO_AVI,
    VIDEO_MOV,
    VIDEO_WMV,
    VIDEO_FLV,
    VIDEO_MKV,

    FONT_TTF,
    FONT_OTF,
    FONT_WOFF,
    FONT_WOFF2,

    // --------------------------------------------------------- //

    /// Get self object as a string
    ///
    /// Note:
    /// - The method-call spelling of stringFromEnum. One switch backs
    ///   both, so the two forms cannot report different strings
    ///
    /// Return:
    /// - []const u8
    pub fn asString(self: Self) []const u8 {
        return stringFromEnum(self);
    }
};

/// Longest media type string this table can name, in bytes.
/// The current longest is `application/x-www-form-urlencoded` at 33 bytes. A
/// value past this length names nothing here, so it is refused before the
/// lowercase copy rather than overrunning the buffer.
pub const MAX_TYPE_LEN: usize = 40;

/// Get type from string
///
/// Note:
/// - Expects a bare type and subtype. A raw header value carrying parameters
///   goes through typeFromHeader instead
/// - A value longer than MAX_TYPE_LEN reports no match without copying
///
/// Param:
/// type_string - []const u8 (insensitive, forced to lowercase)
///
/// Return:
/// - zix.Tcp.Http.Content.Type
/// - null when the value names no type this table knows
pub fn typeFromString(type_string: []const u8) ?Type {
    if (type_string.len > MAX_TYPE_LEN) return null;

    var data: [MAX_TYPE_LEN]u8 = undefined;
    const lower_type = std.ascii.lowerString(&data, type_string);

    if (std.mem.eql(u8, lower_type, "text/plain")) {
        return Type.TEXT_PLAIN;
    }
    if (std.mem.eql(u8, lower_type, "text/html")) {
        return Type.TEXT_HTML;
    }
    if (std.mem.eql(u8, lower_type, "text/css")) {
        return Type.TEXT_CSS;
    }
    if (std.mem.eql(u8, lower_type, "text/csv")) {
        return Type.TEXT_CSV;
    }
    if (std.mem.eql(u8, lower_type, "text/event-stream")) {
        return Type.TEXT_EVENT_STREAM;
    }

    if (std.mem.eql(u8, lower_type, "audio/mpeg")) {
        return Type.AUDIO_MPEG;
    }
    if (std.mem.eql(u8, lower_type, "audio/wav")) {
        return Type.AUDIO_WAV;
    }
    if (std.mem.eql(u8, lower_type, "audio/flac")) {
        return Type.AUDIO_FLAC;
    }
    if (std.mem.eql(u8, lower_type, "audio/midi")) {
        return Type.AUDIO_MIDI;
    }

    if (std.mem.eql(u8, lower_type, "application/javascript")) {
        return Type.APPLICATION_JAVASCRIPT;
    }
    if (std.mem.eql(u8, lower_type, "application/json")) {
        return Type.APPLICATION_JSON;
    }
    if (std.mem.eql(u8, lower_type, "application/pdf")) {
        return Type.APPLICATION_PDF;
    }
    if (std.mem.eql(u8, lower_type, "application/xml")) {
        return Type.APPLICATION_XML;
    }
    if (std.mem.eql(u8, lower_type, "application/rtf")) {
        return Type.APPLICATION_RTF;
    }
    if (std.mem.eql(u8, lower_type, "application/zip")) {
        return Type.APPLICATION_ZIP;
    }
    if (std.mem.eql(u8, lower_type, "application/gzip")) {
        return Type.APPLICATION_GZIP;
    }
    if (std.mem.eql(u8, lower_type, "application/x-tar")) {
        return Type.APPLICATION_TAR;
    }
    if (std.mem.eql(u8, lower_type, "application/x-7z-compressed")) {
        return Type.APPLICATION_7Z_COMPRESSED;
    }
    if (std.mem.eql(u8, lower_type, "application/vnd.rar")) {
        return Type.APPLICATION_VND_RAR;
    }
    if (std.mem.eql(u8, lower_type, "application/jsonld")) {
        return Type.APPLICATION_LD_JSON;
    }
    if (std.mem.eql(u8, lower_type, "application/rdf+xml")) {
        return Type.APPLICATION_RDF_XML;
    }
    if (std.mem.eql(u8, lower_type, "application/rss+xml")) {
        return Type.APPLICATION_RSS_XML;
    }
    if (std.mem.eql(u8, lower_type, "application/atom+xml")) {
        return Type.APPLICATION_ATOM_XML;
    }
    if (std.mem.eql(u8, lower_type, "application/graphql")) {
        return Type.APPLICATION_GRAPHQL;
    }
    if (std.mem.eql(u8, lower_type, "application/jsonpath")) {
        return Type.APPLICATION_JSONPATH;
    }
    if (std.mem.eql(u8, lower_type, "application/sql")) {
        return Type.APPLICATION_SQL;
    }
    if (std.mem.eql(u8, lower_type, "application/x-www-form-urlencoded")) {
        return Type.APPLICATION_X_WWW_FORM_URLENCODED;
    }
    if (std.mem.eql(u8, lower_type, "application/wasm")) {
        return Type.APPLICATION_WASM;
    }
    if (std.mem.eql(u8, lower_type, "application/manifest+json")) {
        return Type.APPLICATION_MANIFEST_JSON;
    }
    if (std.mem.eql(u8, lower_type, "application/octet-stream")) {
        return Type.APPLICATION_OCTET_STREAM;
    }

    if (std.mem.eql(u8, lower_type, "multipart/form-data")) {
        return Type.MULTIPART_FORM_DATA;
    }

    if (std.mem.eql(u8, lower_type, "image/png")) {
        return Type.IMAGE_PNG;
    }
    if (std.mem.eql(u8, lower_type, "image/jpeg")) {
        return Type.IMAGE_JPEG;
    }
    if (std.mem.eql(u8, lower_type, "image/gif")) {
        return Type.IMAGE_GIF;
    }
    if (std.mem.eql(u8, lower_type, "image/svg+xml")) {
        return Type.IMAGE_SVG_XML;
    }
    if (std.mem.eql(u8, lower_type, "image/webp")) {
        return Type.IMAGE_WEBP;
    }
    if (std.mem.eql(u8, lower_type, "image/x-icon")) {
        return Type.IMAGE_X_ICON;
    }

    if (std.mem.eql(u8, lower_type, "video/mp4")) {
        return Type.VIDEO_MP4;
    }
    if (std.mem.eql(u8, lower_type, "video/webm")) {
        return Type.VIDEO_WEBM;
    }
    if (std.mem.eql(u8, lower_type, "video/ogg")) {
        return Type.VIDEO_OGG;
    }
    if (std.mem.eql(u8, lower_type, "video/mpeg")) {
        return Type.VIDEO_MPEG;
    }
    if (std.mem.eql(u8, lower_type, "video/x-msvideo")) {
        return Type.VIDEO_AVI;
    }
    if (std.mem.eql(u8, lower_type, "video/quicktime")) {
        return Type.VIDEO_MOV;
    }
    if (std.mem.eql(u8, lower_type, "video/x-ms-wmv")) {
        return Type.VIDEO_WMV;
    }
    if (std.mem.eql(u8, lower_type, "video/x-flv")) {
        return Type.VIDEO_FLV;
    }
    if (std.mem.eql(u8, lower_type, "video/x-matroska")) {
        return Type.VIDEO_MKV;
    }

    if (std.mem.eql(u8, lower_type, "font/ttf")) {
        return Type.FONT_TTF;
    }
    if (std.mem.eql(u8, lower_type, "font/otf")) {
        return Type.FONT_OTF;
    }
    if (std.mem.eql(u8, lower_type, "font/woff")) {
        return Type.FONT_WOFF;
    }
    if (std.mem.eql(u8, lower_type, "font/woff2")) {
        return Type.FONT_WOFF2;
    }

    return null;
}

/// Get string from enum
///
/// Note:
/// - Exhaustive
/// - Seperated by it's enum
///
/// Param:
/// method_enum - zix.Tcp.Http.Content.Type
///
/// Return:
/// - []const u8
pub fn stringFromEnum(content_enum: Type) []const u8 {
    return switch (content_enum) {
        .TEXT_PLAIN => "text/plain",
        .TEXT_HTML => "text/html",
        .TEXT_CSS => "text/css",
        .TEXT_CSV => "text/csv",
        .TEXT_EVENT_STREAM => "text/event-stream",

        .AUDIO_MPEG => "audio/mpeg",
        .AUDIO_WAV => "audio/wav",
        .AUDIO_FLAC => "audio/flac",
        .AUDIO_MIDI => "audio/midi",

        .APPLICATION_JAVASCRIPT => "application/javascript",
        .APPLICATION_JSON => "application/json",
        .APPLICATION_PDF => "application/pdf",
        .APPLICATION_XML => "application/xml",
        .APPLICATION_RTF => "application/rtf",
        .APPLICATION_ZIP => "application/zip",
        .APPLICATION_GZIP => "application/gzip",
        .APPLICATION_TAR => "application/x-tar",
        .APPLICATION_7Z_COMPRESSED => "application/x-7z-compressed",
        .APPLICATION_VND_RAR => "application/vnd.rar",
        .APPLICATION_LD_JSON => "application/jsonld",
        .APPLICATION_RDF_XML => "application/rdf+xml",
        .APPLICATION_RSS_XML => "application/rss+xml",
        .APPLICATION_ATOM_XML => "application/atom+xml",
        .APPLICATION_GRAPHQL => "application/graphql",
        .APPLICATION_JSONPATH => "application/jsonpath",
        .APPLICATION_SQL => "application/sql",
        .APPLICATION_X_WWW_FORM_URLENCODED => "application/x-www-form-urlencoded",
        .APPLICATION_WASM => "application/wasm",
        .APPLICATION_MANIFEST_JSON => "application/manifest+json",
        .APPLICATION_OCTET_STREAM => "application/octet-stream",

        .MULTIPART_FORM_DATA => "multipart/form-data",

        .IMAGE_PNG => "image/png",
        .IMAGE_JPEG => "image/jpeg",
        .IMAGE_GIF => "image/gif",
        .IMAGE_SVG_XML => "image/svg+xml",
        .IMAGE_WEBP => "image/webp",
        .IMAGE_X_ICON => "image/x-icon",

        .VIDEO_MP4 => "video/mp4",
        .VIDEO_WEBM => "video/webm",
        .VIDEO_OGG => "video/ogg",
        .VIDEO_MPEG => "video/mpeg",
        .VIDEO_AVI => "video/x-msvideo",
        .VIDEO_MOV => "video/quicktime",
        .VIDEO_WMV => "video/x-ms-wmv",
        .VIDEO_FLV => "video/x-flv",
        .VIDEO_MKV => "video/x-matroska",

        .FONT_TTF => "font/ttf",
        .FONT_OTF => "font/otf",
        .FONT_WOFF => "font/woff",
        .FONT_WOFF2 => "font/woff2",
    };
}

/// Get Content.Type enum from a raw Content-Type header value
///
/// Note:
/// - Parameters are dropped first, so `application/sql; charset=utf-8` and a
///   bare `application/sql` resolve to the same type
/// - Never sniffs the body. An unrecognised declared type stays unrecognised
///
/// Usage:
/// ```zig
/// const declared = req.header("content-type") orelse
///     return res.sendStatus(400); // RFC 10008 section 2.1: nothing declared
///
/// const kind = Content.typeFromHeader(declared) orelse
///     return res.sendStatus(415); // declared, but not one this route takes
/// ```
///
/// Param:
/// header_value - []const u8 (a raw Content-Type value, parameters allowed)
///
/// Return:
/// - Type
/// - null when the value names no type this table knows. A QUERY handler turns
///   that into a 415 with an Accept-Query header (RFC 10008 section 2.1), which
///   is a different answer from the 400 an absent header earns
pub fn typeFromHeader(header_value: []const u8) ?Type {
    return typeFromString(media_type.stripParameters(header_value));
}

/// Get Content.Type enum from a file extension
///
/// Note:
/// - Case-insensitive
/// - .APPLICATION_OCTET_STREAM for unknown extensions
///
/// Param:
/// ext - []const u8 (without leading dot, e.g. "html", "png")
///
/// Return:
/// - Type
pub fn typeFromExtension(ext: []const u8) Type {
    if (std.ascii.eqlIgnoreCase(ext, "html") or std.ascii.eqlIgnoreCase(ext, "htm")) return .TEXT_HTML;
    if (std.ascii.eqlIgnoreCase(ext, "css")) return .TEXT_CSS;
    if (std.ascii.eqlIgnoreCase(ext, "js") or std.ascii.eqlIgnoreCase(ext, "min.js")) return .APPLICATION_JAVASCRIPT;
    if (std.ascii.eqlIgnoreCase(ext, "json") or std.ascii.eqlIgnoreCase(ext, "map")) return .APPLICATION_JSON;
    if (std.ascii.eqlIgnoreCase(ext, "txt")) return .TEXT_PLAIN;
    if (std.ascii.eqlIgnoreCase(ext, "csv")) return .TEXT_CSV;
    if (std.ascii.eqlIgnoreCase(ext, "xml")) return .APPLICATION_XML;
    if (std.ascii.eqlIgnoreCase(ext, "rtf")) return .APPLICATION_RTF;
    if (std.ascii.eqlIgnoreCase(ext, "pdf")) return .APPLICATION_PDF;
    if (std.ascii.eqlIgnoreCase(ext, "wasm")) return .APPLICATION_WASM;
    if (std.ascii.eqlIgnoreCase(ext, "zip")) return .APPLICATION_ZIP;
    if (std.ascii.eqlIgnoreCase(ext, "gz")) return .APPLICATION_GZIP;
    if (std.ascii.eqlIgnoreCase(ext, "tar")) return .APPLICATION_TAR;
    if (std.ascii.eqlIgnoreCase(ext, "7z")) return .APPLICATION_7Z_COMPRESSED;
    if (std.ascii.eqlIgnoreCase(ext, "rar")) return .APPLICATION_VND_RAR;
    if (std.ascii.eqlIgnoreCase(ext, "png")) return .IMAGE_PNG;
    if (std.ascii.eqlIgnoreCase(ext, "jpg") or std.ascii.eqlIgnoreCase(ext, "jpeg")) return .IMAGE_JPEG;
    if (std.ascii.eqlIgnoreCase(ext, "gif")) return .IMAGE_GIF;
    if (std.ascii.eqlIgnoreCase(ext, "svg")) return .IMAGE_SVG_XML;
    if (std.ascii.eqlIgnoreCase(ext, "webp")) return .IMAGE_WEBP;
    if (std.ascii.eqlIgnoreCase(ext, "ico")) return .IMAGE_X_ICON;
    if (std.ascii.eqlIgnoreCase(ext, "mp4")) return .VIDEO_MP4;
    if (std.ascii.eqlIgnoreCase(ext, "webm")) return .VIDEO_WEBM;
    if (std.ascii.eqlIgnoreCase(ext, "ogg")) return .VIDEO_OGG;
    if (std.ascii.eqlIgnoreCase(ext, "mpeg")) return .VIDEO_MPEG;
    if (std.ascii.eqlIgnoreCase(ext, "avi")) return .VIDEO_AVI;
    if (std.ascii.eqlIgnoreCase(ext, "mov")) return .VIDEO_MOV;
    if (std.ascii.eqlIgnoreCase(ext, "wmv")) return .VIDEO_WMV;
    if (std.ascii.eqlIgnoreCase(ext, "flv")) return .VIDEO_FLV;
    if (std.ascii.eqlIgnoreCase(ext, "mkv")) return .VIDEO_MKV;
    if (std.ascii.eqlIgnoreCase(ext, "mp3")) return .AUDIO_MPEG;
    if (std.ascii.eqlIgnoreCase(ext, "wav")) return .AUDIO_WAV;
    if (std.ascii.eqlIgnoreCase(ext, "flac")) return .AUDIO_FLAC;
    if (std.ascii.eqlIgnoreCase(ext, "mid") or std.ascii.eqlIgnoreCase(ext, "midi")) return .AUDIO_MIDI;
    if (std.ascii.eqlIgnoreCase(ext, "woff")) return .FONT_WOFF;
    if (std.ascii.eqlIgnoreCase(ext, "woff2")) return .FONT_WOFF2;
    if (std.ascii.eqlIgnoreCase(ext, "ttf")) return .FONT_TTF;
    if (std.ascii.eqlIgnoreCase(ext, "otf")) return .FONT_OTF;
    return .APPLICATION_OCTET_STREAM;
}

/// Get MIME type string from a file extension
///
/// Note:
/// - Case-insensitive
/// - "application/octet-stream" for unknown extensions
/// - Convenience wrapper around typeFromExtension().asString()
///
/// Param:
/// ext - []const u8 (without leading dot, e.g. "html", "png")
///
/// Return:
/// - []const u8
pub fn fromExtension(ext: []const u8) []const u8 {
    return typeFromExtension(ext).asString();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: content every type round-trips through its string" {
    const all_types = [_]Type{
        Type.TEXT_PLAIN,
        Type.TEXT_HTML,
        Type.TEXT_CSS, // css, min.css
        Type.TEXT_CSV,
        Type.TEXT_EVENT_STREAM,

        Type.AUDIO_MPEG,
        Type.AUDIO_WAV,
        Type.AUDIO_FLAC,
        Type.AUDIO_MIDI, // mid, midi

        Type.APPLICATION_JAVASCRIPT, // js, min.js
        Type.APPLICATION_JSON, // json, map
        Type.APPLICATION_PDF,
        Type.APPLICATION_XML,
        Type.APPLICATION_RTF,
        Type.APPLICATION_ZIP,
        Type.APPLICATION_GZIP,
        Type.APPLICATION_TAR,
        Type.APPLICATION_7Z_COMPRESSED,
        Type.APPLICATION_VND_RAR,
        Type.APPLICATION_LD_JSON,
        Type.APPLICATION_RDF_XML,
        Type.APPLICATION_RSS_XML,
        Type.APPLICATION_ATOM_XML,
        Type.APPLICATION_GRAPHQL, // graphql and graphqls
        Type.APPLICATION_JSONPATH,
        Type.APPLICATION_SQL,
        Type.APPLICATION_X_WWW_FORM_URLENCODED,
        Type.APPLICATION_WASM,
        Type.APPLICATION_MANIFEST_JSON, // manifest, webmanifest
        Type.APPLICATION_OCTET_STREAM,

        Type.MULTIPART_FORM_DATA,

        Type.IMAGE_PNG,
        Type.IMAGE_JPEG, // jpeg, jpg
        Type.IMAGE_GIF,
        Type.IMAGE_SVG_XML,
        Type.IMAGE_WEBP,
        Type.IMAGE_X_ICON,

        Type.VIDEO_MP4,
        Type.VIDEO_WEBM,
        Type.VIDEO_OGG,
        Type.VIDEO_MPEG,
        Type.VIDEO_AVI,
        Type.VIDEO_MOV,
        Type.VIDEO_WMV,
        Type.VIDEO_FLV,
        Type.VIDEO_MKV,

        Type.FONT_TTF,
        Type.FONT_OTF,
        Type.FONT_WOFF,
        Type.FONT_WOFF2,
    };

    for (all_types) |content_type| {
        const content_type_string = stringFromEnum(content_type);

        try std.testing.expectEqualStrings(content_type_string, content_type.asString());
        try std.testing.expectEqual(content_type, typeFromString(content_type_string).?);
    }
}

test "zix http: content the RFC 10008 query types resolve from their strings" {
    try std.testing.expectEqual(Type.APPLICATION_SQL, typeFromString("application/sql").?);
    try std.testing.expectEqual(Type.APPLICATION_JSONPATH, typeFromString("application/jsonpath").?);
    try std.testing.expectEqual(Type.APPLICATION_GRAPHQL, typeFromString("application/graphql").?);
    try std.testing.expectEqual(Type.MULTIPART_FORM_DATA, typeFromString("multipart/form-data").?);
    try std.testing.expectEqual(
        Type.APPLICATION_X_WWW_FORM_URLENCODED,
        typeFromString("application/x-www-form-urlencoded").?,
    );
}

test "zix http: content the longest media type string fits the lowercase buffer" {
    // 33 bytes, one past the buffer this table used to declare. A safe build
    // panicked here and a release build wrote past the end.
    const longest = "application/x-www-form-urlencoded";

    try std.testing.expectEqual(@as(usize, 33), longest.len);
    try std.testing.expect(longest.len <= MAX_TYPE_LEN);
    try std.testing.expectEqual(Type.APPLICATION_X_WWW_FORM_URLENCODED, typeFromString(longest).?);
}

test "zix http: content a value past MAX_TYPE_LEN reports no match instead of panicking" {
    // A peer controls this header, so an absurd value must be refused, not copied.
    const prefix = "application/";
    var oversized: [prefix.len + 200]u8 = @splat('x');
    @memcpy(oversized[0..prefix.len], prefix);

    try std.testing.expect(typeFromString(&oversized) == null);
}

test "zix http: content typeFromHeader drops parameters before matching" {
    try std.testing.expectEqual(Type.APPLICATION_SQL, typeFromHeader("application/sql; charset=utf-8").?);
    try std.testing.expectEqual(Type.APPLICATION_JSON, typeFromHeader("application/json;charset=utf-8").?);
    try std.testing.expectEqual(
        Type.MULTIPART_FORM_DATA,
        typeFromHeader("multipart/form-data; boundary=----zixBoundary").?,
    );
}

test "zix http: content typeFromHeader matches a bare value unchanged" {
    try std.testing.expectEqual(Type.APPLICATION_SQL, typeFromHeader("application/sql").?);
}

test "zix http: content typeFromHeader reports no match for an unknown type" {
    // RFC 10008 section 2.1 forbids sniffing the body, so an unrecognised
    // declared type stays unrecognised and the handler answers 415.
    try std.testing.expect(typeFromHeader("application/vnd.zix.not-real") == null);
    try std.testing.expect(typeFromHeader("") == null);
}

test "zix http: content typeFromHeader is case-insensitive on the type" {
    try std.testing.expectEqual(Type.APPLICATION_SQL, typeFromHeader("APPLICATION/SQL").?);
    try std.testing.expectEqual(Type.APPLICATION_SQL, typeFromHeader("Application/SQL; charset=UTF-8").?);
}
