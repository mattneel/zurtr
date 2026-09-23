//! jzon: JSON, in both directions.
//!
//! What:
//! - The surface a jzon caller reaches. Two calls carry it: `serialize` turns a
//!   typed value into JSON text, `deserialize` turns JSON text back into a typed
//!   value, and each takes a comptime options struct naming which path runs.
//! - Under them sit the pieces, each owning one concern: a bounds-checked write
//!   cursor, a bounds-checked read cursor, the string escape rules and their
//!   vector scan, the integer paths, the float path, the questions a type is
//!   asked, and the ways a value is rendered and read back.
//! - Serialize allocates nothing: a writer is handed a buffer it must fit in.
//!   Deserialize allocates only what the result points at, out of the allocator
//!   the caller hands over.

pub const sink = @import("sink.zig");
pub const cursor = @import("cursor.zig");
pub const cursor_vector = @import("cursor_vector.zig");
pub const escape = @import("escape.zig");
pub const escape_vector = @import("escape_vector.zig");
pub const integer = @import("integer.zig");
pub const float = @import("float.zig");
pub const reflect = @import("reflect.zig");

/// What a caller hands a render, and what a render can hand back.
pub const serialize_options = @import("serialize/options.zig");

/// Render a value the way std does, which takes every shape std takes.
pub const std_emitter = @import("serialize/std_emitter.zig");

/// Render a value through code generated from its type.
pub const generated_emitter = @import("serialize/generated_emitter.zig");

/// What a caller hands a parse, and what a parse can hand back.
pub const deserialize_options = @import("deserialize/options.zig");

/// Which field and which byte the last failed parse on this thread was about.
pub const diagnostic = @import("deserialize/diagnostic.zig");

/// Which of a target's fields a document filled in.
pub const fields = @import("deserialize/fields.zig");

/// How many bytes a read scan classifies at once.
pub const scan = @import("deserialize/scan.zig");

/// Step over a whole value without building anything out of it.
pub const skip = @import("deserialize/skip.zig");

/// The value of one string token, borrowed or copied.
pub const string_value = @import("deserialize/string_value.zig");

/// Read a value the way std does, which parses every shape std parses.
pub const std_parser = @import("deserialize/std_parser.zig");

/// Read a value through std's tokens and dispatch generated from the type.
pub const scanner_parser = @import("deserialize/scanner_parser.zig");

/// Read a value through jzon's own cursor and code generated from the type.
pub const generated_parser = @import("deserialize/generated_parser.zig");

/// Turn a typed value into JSON text, through the write path the options name.
pub const serialize = @import("serialize/serialize.zig").serialize;

/// Turn JSON text into a typed value, through the read path the options name.
pub const deserialize = @import("deserialize/deserialize.zig").deserialize;

/// What the last failed parse on this thread was about: the field, the byte, or both.
///
/// Note:
/// - An error value has nowhere to put a field name or an offset. Read this immediately after a
///   parse returned an error, before another parse on the same thread replaces it.
pub const lastFailure = @import("deserialize/diagnostic.zig").lastFailure;

/// A write cursor over a caller-owned buffer.
pub const Sink = sink.Sink;

/// A read cursor over a caller-owned document.
pub const Cursor = cursor.Cursor;

/// A located string token: the bytes between the quotes, plus whether they hold
/// an escape.
pub const StringSpan = cursor.StringSpan;

/// The options a render runs with.
pub const SerializeOptions = serialize_options.Options;

/// The one error a render reports through.
pub const SerializeError = serialize_options.Error;

/// Which write path a render runs.
pub const SerializeStrategy = serialize_options.Strategy;

/// The options every deserialize path reads.
pub const DeserializeOptions = deserialize_options.Options;

/// The one error set every deserialize path reports through.
pub const DeserializeError = deserialize_options.Error;

/// Which read path a parse runs.
pub const DeserializeStrategy = deserialize_options.Strategy;

/// Where a parsed string's bytes live.
pub const Strings = deserialize_options.Strings;

/// What happens to a key the target type does not declare.
pub const Unknown = deserialize_options.Unknown;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test {
    _ = sink;
    _ = cursor;
    _ = cursor_vector;
    _ = escape;
    _ = escape_vector;
    _ = integer;
    _ = float;
    _ = reflect;
    _ = serialize_options;
    _ = std_emitter;
    _ = generated_emitter;
    _ = deserialize_options;
    _ = fields;
    _ = scan;
    _ = skip;
    _ = string_value;
    _ = std_parser;
    _ = scanner_parser;
    _ = generated_parser;

    // The two entry points are functions rather than namespaces, so the files
    // holding them are named directly.
    _ = @import("serialize/serialize.zig");
    _ = @import("deserialize/deserialize.zig");
}
