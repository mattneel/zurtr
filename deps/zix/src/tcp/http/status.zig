//! zix http status

const std = @import("std");

// --------------------------------------------------------- //

/// zix tcp http status code
pub const Code = enum(u16) {
    const Self = @This();

    // --------------------------------------------------------- //

    // 1xx : informational
    CONTINUE = 100,
    SWITCHING_PROTOCOL = 101,
    PROCESSING = 102,
    EARLY_HINTS = 103,

    // 2xx : success
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NON_AUTHORITATIVE_INFORMATION = 203,
    NO_CONTENT = 204,
    RESET_CONTENT = 205,
    PARTIAL_CONTENT = 206,
    MULTI_STATUS = 207,
    ALREADY_REPORTED = 208,
    IM_USED = 226,

    // 3xx : redirect
    MULTIPLE_CHOICES = 300,
    MOVED_PERMANENTLY = 301,
    FOUND = 302,
    SEE_OTHER = 303,
    NOT_MODIFIED = 304,
    USE_PROXY = 305,
    TEMPORARY_REDIRECT = 307,
    PERMANENT_REDIRECT = 308,

    // 4xx : client error
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    PAYMENT_REQUIRED = 402,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    NOT_ACCEPTABLE = 406,
    PROXY_AUTHENTICATION_REQUIRED = 407,
    REQUEST_TIMEOUT = 408,
    CONFLICT = 409,
    GONE = 410,
    LENGTH_REQUIRED = 411,
    PRECONDITION_FAILED = 412,
    PAYLOAD_TOO_LARGE = 413,
    URI_TOO_LONG = 414,
    UNSUPPORTED_MEDIA_TYPE = 415,
    RANGE_NOT_SATISFIABLE = 416,
    EXPECTATION_FAILED = 417,
    IM_A_TEAPOT = 418,
    MISDIRECTED_REQUEST = 421,
    UNPROCESSABLE_ENTITY = 422,
    LOCKED = 423,
    FAILED_DEPENDENCY = 424,
    TOO_EARLY = 425,
    UPGRADE_REQUIRED = 426,
    PRECONDITION_REQUIRED = 428,
    TOO_MANY_REQUESTS = 429,
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    // 5xx : server error
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503,
    GATEWAY_TIMEOUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505,
    VARIANT_ALSO_NEGOTIATES = 506,
    INSUFFICIENT_STORAGE = 507,
    LOOP_DETECTED = 508,
    NOT_EXTENDED = 510,
    NETWORK_AUTHENTICATION_REQUIRED = 511,

    // --------------------------------------------------------- //

    /// Get self object as string
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

// --------------------------------------------------------- //

/// Get enum from string
///
/// Note:
/// - If not match, it will return Code.IM_A_TEAPOT
///
/// Param:
/// method_string - []const u8 (insensitive, forced to lowercase)
///
/// Return:
/// - zix.Tcp.Http.Status.Code
pub fn enumFromString(status_string: []const u8) Code {
    var data: [32]u8 = undefined;
    const lower_str = std.ascii.lowerString(&data, status_string);

    // 1xx : informational
    if (std.mem.eql(u8, lower_str, "continue")) {
        return Code.CONTINUE;
    }
    if (std.mem.eql(u8, lower_str, "switching protocols")) {
        return Code.SWITCHING_PROTOCOL;
    }
    if (std.mem.eql(u8, lower_str, "processing")) {
        return Code.PROCESSING;
    }
    if (std.mem.eql(u8, lower_str, "early hints")) {
        return Code.EARLY_HINTS;
    }

    // 2xx : success
    if (std.mem.eql(u8, lower_str, "ok")) {
        return Code.OK;
    }
    if (std.mem.eql(u8, lower_str, "created")) {
        return Code.CREATED;
    }
    if (std.mem.eql(u8, lower_str, "accepted")) {
        return Code.ACCEPTED;
    }
    if (std.mem.eql(u8, lower_str, "non-authoritative information")) {
        return Code.NON_AUTHORITATIVE_INFORMATION;
    }
    if (std.mem.eql(u8, lower_str, "no content")) {
        return Code.NO_CONTENT;
    }
    if (std.mem.eql(u8, lower_str, "reset content")) {
        return Code.RESET_CONTENT;
    }
    if (std.mem.eql(u8, lower_str, "partial content")) {
        return Code.PARTIAL_CONTENT;
    }
    if (std.mem.eql(u8, lower_str, "multi-status")) {
        return Code.MULTI_STATUS;
    }
    if (std.mem.eql(u8, lower_str, "already reported")) {
        return Code.ALREADY_REPORTED;
    }
    if (std.mem.eql(u8, lower_str, "im used")) {
        return Code.IM_USED;
    }

    // 3xx : redirect
    if (std.mem.eql(u8, lower_str, "multiple choices")) {
        return Code.MULTIPLE_CHOICES;
    }
    if (std.mem.eql(u8, lower_str, "moved permanently")) {
        return Code.MOVED_PERMANENTLY;
    }
    if (std.mem.eql(u8, lower_str, "found")) {
        return Code.FOUND;
    }
    if (std.mem.eql(u8, lower_str, "see other")) {
        return Code.SEE_OTHER;
    }
    if (std.mem.eql(u8, lower_str, "not modified")) {
        return Code.NOT_MODIFIED;
    }
    if (std.mem.eql(u8, lower_str, "use proxy")) {
        return Code.USE_PROXY;
    }
    if (std.mem.eql(u8, lower_str, "temporary redirect")) {
        return Code.TEMPORARY_REDIRECT;
    }
    if (std.mem.eql(u8, lower_str, "permanent redirect")) {
        return Code.PERMANENT_REDIRECT;
    }

    // 4xx : client error
    if (std.mem.eql(u8, lower_str, "bad request")) {
        return Code.BAD_REQUEST;
    }
    if (std.mem.eql(u8, lower_str, "unauthorized")) {
        return Code.UNAUTHORIZED;
    }
    if (std.mem.eql(u8, lower_str, "payment required")) {
        return Code.PAYMENT_REQUIRED;
    }
    if (std.mem.eql(u8, lower_str, "forbidden")) {
        return Code.FORBIDDEN;
    }
    if (std.mem.eql(u8, lower_str, "not found")) {
        return Code.NOT_FOUND;
    }
    if (std.mem.eql(u8, lower_str, "method not allowed")) {
        return Code.METHOD_NOT_ALLOWED;
    }
    if (std.mem.eql(u8, lower_str, "not acceptable")) {
        return Code.NOT_ACCEPTABLE;
    }
    if (std.mem.eql(u8, lower_str, "proxy authentication required")) {
        return Code.PROXY_AUTHENTICATION_REQUIRED;
    }
    if (std.mem.eql(u8, lower_str, "request timeout")) {
        return Code.REQUEST_TIMEOUT;
    }
    if (std.mem.eql(u8, lower_str, "conflict")) {
        return Code.CONFLICT;
    }
    if (std.mem.eql(u8, lower_str, "gone")) {
        return Code.GONE;
    }
    if (std.mem.eql(u8, lower_str, "length required")) {
        return Code.LENGTH_REQUIRED;
    }
    if (std.mem.eql(u8, lower_str, "precondition failed")) {
        return Code.PRECONDITION_FAILED;
    }
    if (std.mem.eql(u8, lower_str, "payload too large")) {
        return Code.PAYLOAD_TOO_LARGE;
    }
    if (std.mem.eql(u8, lower_str, "uri too long")) {
        return Code.URI_TOO_LONG;
    }
    if (std.mem.eql(u8, lower_str, "unsupported media type")) {
        return Code.UNSUPPORTED_MEDIA_TYPE;
    }
    if (std.mem.eql(u8, lower_str, "range not satisfiable")) {
        return Code.RANGE_NOT_SATISFIABLE;
    }
    if (std.mem.eql(u8, lower_str, "expectation failed")) {
        return Code.EXPECTATION_FAILED;
    }
    if (std.mem.eql(u8, lower_str, "i'm a teapot")) {
        return Code.IM_A_TEAPOT;
    }
    if (std.mem.eql(u8, lower_str, "misdirected request")) {
        return Code.MISDIRECTED_REQUEST;
    }
    if (std.mem.eql(u8, lower_str, "unprocessable entity")) {
        return Code.UNPROCESSABLE_ENTITY;
    }
    if (std.mem.eql(u8, lower_str, "locked")) {
        return Code.LOCKED;
    }
    if (std.mem.eql(u8, lower_str, "failed dependency")) {
        return Code.FAILED_DEPENDENCY;
    }
    if (std.mem.eql(u8, lower_str, "too early")) {
        return Code.TOO_EARLY;
    }
    if (std.mem.eql(u8, lower_str, "upgrade required")) {
        return Code.UPGRADE_REQUIRED;
    }
    if (std.mem.eql(u8, lower_str, "precondition required")) {
        return Code.PRECONDITION_REQUIRED;
    }
    if (std.mem.eql(u8, lower_str, "too many requests")) {
        return Code.TOO_MANY_REQUESTS;
    }
    if (std.mem.eql(u8, lower_str, "request header fields too large")) {
        return Code.REQUEST_HEADER_FIELDS_TOO_LARGE;
    }
    if (std.mem.eql(u8, lower_str, "unavailable for legal reasons")) {
        return Code.UNAVAILABLE_FOR_LEGAL_REASONS;
    }

    // 5xx : server error
    if (std.mem.eql(u8, lower_str, "internal server error")) {
        return Code.INTERNAL_SERVER_ERROR;
    }
    if (std.mem.eql(u8, lower_str, "not implemented")) {
        return Code.NOT_IMPLEMENTED;
    }
    if (std.mem.eql(u8, lower_str, "bad gateway")) {
        return Code.BAD_GATEWAY;
    }
    if (std.mem.eql(u8, lower_str, "service unavailable")) {
        return Code.SERVICE_UNAVAILABLE;
    }
    if (std.mem.eql(u8, lower_str, "gateway timeout")) {
        return Code.GATEWAY_TIMEOUT;
    }
    if (std.mem.eql(u8, lower_str, "http version not supported")) {
        return Code.HTTP_VERSION_NOT_SUPPORTED;
    }
    if (std.mem.eql(u8, lower_str, "variant also negotiates")) {
        return Code.VARIANT_ALSO_NEGOTIATES;
    }
    if (std.mem.eql(u8, lower_str, "insufficient storage")) {
        return Code.INSUFFICIENT_STORAGE;
    }
    if (std.mem.eql(u8, lower_str, "loop detected")) {
        return Code.LOOP_DETECTED;
    }
    if (std.mem.eql(u8, lower_str, "not extended")) {
        return Code.NOT_EXTENDED;
    }
    if (std.mem.eql(u8, lower_str, "network authentication required")) {
        return Code.NETWORK_AUTHENTICATION_REQUIRED;
    }

    return Code.IM_A_TEAPOT;
}

/// Get string from enum
///
/// Note:
/// - Exhaustive
/// - Separated by its enum
///
/// Param:
/// self - zix.Tcp.Http.Status.Code
///
/// Return:
/// - []const u8
pub fn stringFromEnum(status_enum: Code) []const u8 {
    return switch (status_enum) {
        // 1xx : informational
        .CONTINUE => "Continue",
        .SWITCHING_PROTOCOL => "Switching Protocols",
        .PROCESSING => "Processing",
        .EARLY_HINTS => "Early Hints",

        // 2xx : success
        .OK => "Ok",
        .CREATED => "Created",
        .ACCEPTED => "Accepted",
        .NON_AUTHORITATIVE_INFORMATION => "Non-Authoritative Information",
        .NO_CONTENT => "No Content",
        .RESET_CONTENT => "Reset Content",
        .PARTIAL_CONTENT => "Partial Content",
        .MULTI_STATUS => "Multi-Status",
        .ALREADY_REPORTED => "Already Reported",
        .IM_USED => "IM Used",

        // 3xx : redirect
        .MULTIPLE_CHOICES => "Multiple Choices",
        .MOVED_PERMANENTLY => "Moved Permanently",
        .FOUND => "Found",
        .SEE_OTHER => "See Other",
        .NOT_MODIFIED => "Not Modified",
        .USE_PROXY => "Use Proxy",
        .TEMPORARY_REDIRECT => "Temporary Redirect",
        .PERMANENT_REDIRECT => "Permanent Redirect",

        // 4xx : client error
        .BAD_REQUEST => "Bad Request",
        .UNAUTHORIZED => "Unauthorized",
        .PAYMENT_REQUIRED => "Payment Required",
        .FORBIDDEN => "Forbidden",
        .NOT_FOUND => "Not Found",
        .METHOD_NOT_ALLOWED => "Method Not Allowed",
        .NOT_ACCEPTABLE => "Not Acceptable",
        .PROXY_AUTHENTICATION_REQUIRED => "Proxy Authentication Required",
        .REQUEST_TIMEOUT => "Request Timeout",
        .CONFLICT => "Conflict",
        .GONE => "Gone",
        .LENGTH_REQUIRED => "Length Required",
        .PRECONDITION_FAILED => "Precondition Failed",
        .PAYLOAD_TOO_LARGE => "Payload Too Large",
        .URI_TOO_LONG => "URI Too Long",
        .UNSUPPORTED_MEDIA_TYPE => "Unsupported Media Type",
        .RANGE_NOT_SATISFIABLE => "Range Not Satisfiable",
        .EXPECTATION_FAILED => "Expectation Failed",
        .IM_A_TEAPOT => "I'm a teapot",
        .MISDIRECTED_REQUEST => "Misdirected Request",
        .UNPROCESSABLE_ENTITY => "Unprocessable Entity",
        .LOCKED => "Locked",
        .FAILED_DEPENDENCY => "Failed Dependency",
        .TOO_EARLY => "Too Early",
        .UPGRADE_REQUIRED => "Upgrade Required",
        .PRECONDITION_REQUIRED => "Precondition Required",
        .TOO_MANY_REQUESTS => "Too Many Requests",
        .REQUEST_HEADER_FIELDS_TOO_LARGE => "Request Header Fields Too Large",
        .UNAVAILABLE_FOR_LEGAL_REASONS => "Unavailable For Legal Reasons",

        // 5xx : server error
        .INTERNAL_SERVER_ERROR => "Internal Server Error",
        .NOT_IMPLEMENTED => "Not Implemented",
        .BAD_GATEWAY => "Bad Gateway",
        .SERVICE_UNAVAILABLE => "Service Unavailable",
        .GATEWAY_TIMEOUT => "Gateway Timeout",
        .HTTP_VERSION_NOT_SUPPORTED => "HTTP Version Not Supported",
        .VARIANT_ALSO_NEGOTIATES => "Variant Also Negotiates",
        .INSUFFICIENT_STORAGE => "Insufficient Storage",
        .LOOP_DETECTED => "Loop Detected",
        .NOT_EXTENDED => "Not Extended",
        .NETWORK_AUTHENTICATION_REQUIRED => "Network Authentication Required",
    };
}

/// Pre-built complete status line for the hot-path response writer
///
/// Note:
/// - "HTTP/1.1 NNN Reason\r\n" verbatim for common status codes
/// - "" for uncommon codes, caller falls back to bufPrint
/// - Reason phrases match stringFromEnum() so behavior is unchanged for clients
pub fn statusLine(code: Code) []const u8 {
    return switch (code) {
        .OK => "HTTP/1.1 200 Ok\r\n",
        .CREATED => "HTTP/1.1 201 Created\r\n",
        .ACCEPTED => "HTTP/1.1 202 Accepted\r\n",
        .NO_CONTENT => "HTTP/1.1 204 No Content\r\n",
        .MOVED_PERMANENTLY => "HTTP/1.1 301 Moved Permanently\r\n",
        .FOUND => "HTTP/1.1 302 Found\r\n",
        .NOT_MODIFIED => "HTTP/1.1 304 Not Modified\r\n",
        .TEMPORARY_REDIRECT => "HTTP/1.1 307 Temporary Redirect\r\n",
        .PERMANENT_REDIRECT => "HTTP/1.1 308 Permanent Redirect\r\n",
        .BAD_REQUEST => "HTTP/1.1 400 Bad Request\r\n",
        .UNAUTHORIZED => "HTTP/1.1 401 Unauthorized\r\n",
        .FORBIDDEN => "HTTP/1.1 403 Forbidden\r\n",
        .NOT_FOUND => "HTTP/1.1 404 Not Found\r\n",
        .METHOD_NOT_ALLOWED => "HTTP/1.1 405 Method Not Allowed\r\n",
        .REQUEST_TIMEOUT => "HTTP/1.1 408 Request Timeout\r\n",
        .CONFLICT => "HTTP/1.1 409 Conflict\r\n",
        .UNSUPPORTED_MEDIA_TYPE => "HTTP/1.1 415 Unsupported Media Type\r\n",
        .UNPROCESSABLE_ENTITY => "HTTP/1.1 422 Unprocessable Entity\r\n",
        .TOO_MANY_REQUESTS => "HTTP/1.1 429 Too Many Requests\r\n",
        .INTERNAL_SERVER_ERROR => "HTTP/1.1 500 Internal Server Error\r\n",
        .NOT_IMPLEMENTED => "HTTP/1.1 501 Not Implemented\r\n",
        .BAD_GATEWAY => "HTTP/1.1 502 Bad Gateway\r\n",
        .SERVICE_UNAVAILABLE => "HTTP/1.1 503 Service Unavailable\r\n",
        .GATEWAY_TIMEOUT => "HTTP/1.1 504 Gateway Timeout\r\n",
        else => "",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: statusLine pre-built lines" {
    // Every pre-built entry must produce exactly what bufPrint + stringFromEnum would.
    const pre_built = [_]Code{
        .OK,                     .CREATED,              .ACCEPTED,            .NO_CONTENT,
        .MOVED_PERMANENTLY,      .FOUND,                .NOT_MODIFIED,        .TEMPORARY_REDIRECT,
        .PERMANENT_REDIRECT,     .BAD_REQUEST,          .UNAUTHORIZED,        .FORBIDDEN,
        .NOT_FOUND,              .METHOD_NOT_ALLOWED,   .REQUEST_TIMEOUT,     .CONFLICT,
        .UNSUPPORTED_MEDIA_TYPE, .UNPROCESSABLE_ENTITY, .TOO_MANY_REQUESTS,   .INTERNAL_SERVER_ERROR,
        .NOT_IMPLEMENTED,        .BAD_GATEWAY,          .SERVICE_UNAVAILABLE, .GATEWAY_TIMEOUT,
    };
    var buf: [64]u8 = undefined;
    for (pre_built) |code| {
        const line = statusLine(code);
        try std.testing.expect(line.len > 0);
        const expected = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(code), stringFromEnum(code) });
        try std.testing.expectEqualStrings(expected, line);
    }

    // Uncommon codes fall back to bufPrint, statusLine must return empty.
    try std.testing.expectEqualStrings("", statusLine(.CONTINUE));
    try std.testing.expectEqualStrings("", statusLine(.PROCESSING));
    try std.testing.expectEqualStrings("", statusLine(.LOCKED));
    try std.testing.expectEqualStrings("", statusLine(.LOOP_DETECTED));
    try std.testing.expectEqualStrings("", statusLine(.IM_USED));
}

test "zix http: status every code round-trips through its string" {
    const all_codes = [_]Code{
        // 1xx : informational
        Code.CONTINUE,
        Code.SWITCHING_PROTOCOL,
        Code.PROCESSING,
        Code.EARLY_HINTS,

        // 2xx : success
        Code.OK,
        Code.CREATED,
        Code.ACCEPTED,
        Code.NON_AUTHORITATIVE_INFORMATION,
        Code.NO_CONTENT,
        Code.RESET_CONTENT,
        Code.PARTIAL_CONTENT,
        Code.MULTI_STATUS,
        Code.ALREADY_REPORTED,
        Code.IM_USED,

        // 3xx : redirect
        Code.MULTIPLE_CHOICES,
        Code.MOVED_PERMANENTLY,
        Code.FOUND,
        Code.SEE_OTHER,
        Code.NOT_MODIFIED,
        Code.USE_PROXY,
        Code.TEMPORARY_REDIRECT,
        Code.PERMANENT_REDIRECT,

        // 4xx : client error
        Code.BAD_REQUEST,
        Code.UNAUTHORIZED,
        Code.PAYMENT_REQUIRED,
        Code.FORBIDDEN,
        Code.NOT_FOUND,
        Code.METHOD_NOT_ALLOWED,
        Code.NOT_ACCEPTABLE,
        Code.PROXY_AUTHENTICATION_REQUIRED,
        Code.REQUEST_TIMEOUT,
        Code.CONFLICT,
        Code.GONE,
        Code.LENGTH_REQUIRED,
        Code.PRECONDITION_FAILED,
        Code.PAYLOAD_TOO_LARGE,
        Code.URI_TOO_LONG,
        Code.UNSUPPORTED_MEDIA_TYPE,
        Code.RANGE_NOT_SATISFIABLE,
        Code.EXPECTATION_FAILED,
        Code.IM_A_TEAPOT,
        Code.MISDIRECTED_REQUEST,
        Code.UNPROCESSABLE_ENTITY,
        Code.LOCKED,
        Code.FAILED_DEPENDENCY,
        Code.TOO_EARLY,
        Code.UPGRADE_REQUIRED,
        Code.PRECONDITION_REQUIRED,
        Code.TOO_MANY_REQUESTS,
        Code.REQUEST_HEADER_FIELDS_TOO_LARGE,
        Code.UNAVAILABLE_FOR_LEGAL_REASONS,

        // 5xx : server error
        Code.INTERNAL_SERVER_ERROR,
        Code.NOT_IMPLEMENTED,
        Code.BAD_GATEWAY,
        Code.SERVICE_UNAVAILABLE,
        Code.GATEWAY_TIMEOUT,
        Code.HTTP_VERSION_NOT_SUPPORTED,
        Code.VARIANT_ALSO_NEGOTIATES,
        Code.INSUFFICIENT_STORAGE,
        Code.LOOP_DETECTED,
        Code.NOT_EXTENDED,
        Code.NETWORK_AUTHENTICATION_REQUIRED,
    };

    for (all_codes) |code| {
        const code_string = stringFromEnum(code);

        try std.testing.expectEqualStrings(code_string, code.asString());
        try std.testing.expectEqual(code, enumFromString(code_string));
    }
}
