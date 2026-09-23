//! Windows log-file backend over ntdll: create the day directory, open the file for append,
//! write, and close.
//!
//! What:
//! - The logger writes from a background thread it owns and must stay free of `std.Io`, so the
//!   file sink cannot go through `std.Io.File`. These four calls are the ntdll equivalents of the
//!   POSIX mkdirat, openat, write, and close the sink uses everywhere else.
//! - Paths arrive as ordinary slashed relative or absolute strings. `sliceToPrefixedFileW` is the
//!   std path converter (pure string work, no `Io` instance) that turns one into the `\??\` form
//!   NtCreateFile wants.
//!
//! Note:
//! - Windows-only: every caller comptime-gates on builtin.os.tag == .windows, nothing here is
//!   analyzed on other targets. That is also why the file carries no tests of its own, the logger
//!   suite covers this path when it runs on Windows.
//! - Append is requested as APPEND_DATA without WRITE_DATA, which is what makes every write land
//!   at the end of the file the way O_APPEND does, so a restart never overwrites the day's log.

const std = @import("std");
const windows = std.os.windows;

// --------------------------------------------------------- //

/// What a call could not do, for the logger's suspend report.
pub const Error = error{
    /// The path could not be expressed as an NT path (bad encoding, or too long).
    ZixLogPathBad,
    /// The directory or file could not be created or opened.
    ZixLogOpenFailed,
    /// The write did not complete.
    ZixLogWriteFailed,
};

/// NtWriteFile offset meaning "append at the end of the file".
const WRITE_TO_END_OF_FILE: windows.LARGE_INTEGER = -1;

/// Convert a slashed path into the `\??\` NT form NtCreateFile expects.
///
/// Note:
/// - allow_relative is off so the result is always absolute. A relative NT path would need a
///   directory handle in the object attributes, and the logger only ever has a path string.
fn ntPath(path: []const u8) Error!std.Io.Threaded.WindowsPathSpace {
    return std.Io.Threaded.sliceToPrefixedFileW(null, path, .{ .allow_relative = false }) catch
        return error.ZixLogPathBad;
}

/// Create one directory, treating "it is already there" as success.
///
/// Param:
/// path - []const u8 (the day directory, e.g. "logs/2026-08-10")
///
/// Return:
/// - void
/// - error.ZixLogPathBad when the path cannot be converted
/// - error.ZixLogOpenFailed when the create fails for any other reason
pub fn createDir(path: []const u8) Error!void {
    const space = try ntPath(path);
    var name = space.string();
    const attributes = windows.OBJECT.ATTRIBUTES{ .ObjectName = &name };

    var handle: windows.HANDLE = undefined;
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true }, .SPECIFIC = .{ .FILE = .{ .READ_DATA = true } } },
        &attributes,
        &iosb,
        null,
        .{ .DIRECTORY = true },
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT },
        null,
        0,
    );
    if (status != .SUCCESS) return error.ZixLogOpenFailed;

    _ = windows.ntdll.NtClose(handle);
}

/// Open a log file for append, creating it when it is not there yet.
///
/// Param:
/// path - []const u8 (the full log file path)
///
/// Return:
/// - windows.HANDLE (close it with closeFile)
/// - error.ZixLogPathBad when the path cannot be converted
/// - error.ZixLogOpenFailed when the open fails
pub fn openAppend(path: []const u8) Error!windows.HANDLE {
    const space = try ntPath(path);
    var name = space.string();
    const attributes = windows.OBJECT.ATTRIBUTES{ .ObjectName = &name };

    var handle: windows.HANDLE = undefined;
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true }, .SPECIFIC = .{ .FILE = .{ .APPEND_DATA = true } } },
        &attributes,
        &iosb,
        null,
        .{ .NORMAL = true },
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .NON_DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT },
        null,
        0,
    );
    if (status != .SUCCESS) return error.ZixLogOpenFailed;

    return handle;
}

/// Write every byte to an append handle.
///
/// Note:
/// - A short write is looped rather than treated as the end, matching the POSIX write loop. A
///   write of zero bytes is reported instead of looped on, because retrying it forever would spin
///   the flush thread.
///
/// Return:
/// - void
/// - error.ZixLogWriteFailed when a write does not complete
pub fn writeAll(handle: windows.HANDLE, data: []const u8) Error!void {
    var remaining = data;
    while (remaining.len > 0) {
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var offset: windows.LARGE_INTEGER = WRITE_TO_END_OF_FILE;
        const status = windows.ntdll.NtWriteFile(
            handle,
            null,
            null,
            null,
            &iosb,
            remaining.ptr,
            std.math.lossyCast(windows.ULONG, remaining.len),
            &offset,
            null,
        );
        if (status != .SUCCESS) return error.ZixLogWriteFailed;

        const written = iosb.Information;
        if (written == 0) return error.ZixLogWriteFailed;

        remaining = remaining[written..];
    }
}

pub fn closeFile(handle: windows.HANDLE) void {
    _ = windows.ntdll.NtClose(handle);
}
