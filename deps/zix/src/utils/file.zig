//! zix file utils

const std = @import("std");
const builtin = @import("builtin");

/// Largest "dir/filename" path save() can assemble on the stack. Longer paths return error.ZixPathTooLong.
const MAX_PATH_LEN: usize = 512;
/// Scratch buffer size backing the file writer in save().
const WRITE_BUF_SIZE: usize = 8192;
/// Targets where a directory can be opened and read, handing back its raw entries instead of
/// failing the read. Every other target refuses, so the cause is already in the failure.
const READ_SUCCEEDS_ON_DIRECTORY: bool = builtin.os.tag == .netbsd;

// --------------------------------------------------------- //

/// Get file if exists or nor
///
/// Param:
/// io - std.Io
/// file_path - []const u8
///
/// Return:
/// - !bool
pub fn exists(io: std.Io, file_path: []const u8) !bool {
    const file = std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only }) catch {
        return false;
    }; 
    defer file.close(io);

    return true;
}

/// Get file extension from file path
///
/// Note:
/// - "" if '.' is not found or '.' is the last character
///
/// Param:
/// file_path - []const u8
///
/// Return:
/// - []const u8
pub fn extension(file_path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, file_path, '.')) |dot_pos| {
        if (dot_pos + 1 < file_path.len) {
            return file_path[dot_pos + 1 ..];
        }
    }
    return "";
}

/// Read a whole file into memory
///
/// Note:
/// - max_bytes is a hard ceiling, not a hint. A larger file fails rather than allocating, so
///   an unexpected input cannot exhaust memory.
/// - max_bytes is INCLUSIVE: a file of exactly max_bytes loads. The underlying std limit is
///   exclusive (it rejects a file whose size equals the limit), so one byte is added here to
///   make the parameter mean what its name says.
/// - The path is resolved against the process working directory, so a relative path only
///   resolves when the process is launched from the expected directory.
/// - A directory named as the path is rejected on every target. NetBSD allows a directory to be
///   read, so the kind is asked for there before the read rather than inferred from it.
///
/// Param:
/// io - std.Io
/// allocator - std.mem.Allocator (owns the returned bytes, caller frees)
/// file_path - []const u8 (path to read)
/// max_bytes - usize (largest file accepted, inclusive)
///
/// Return:
/// - []u8 (caller-owned file content)
/// - error.ZixFileNotFound (the path does not resolve)
/// - error.ZixFilePathIsDirectory (the path names a directory)
/// - error.ZixFileTooLarge (the file is larger than max_bytes)
/// - error.ZixFileUnreadable (the path resolves and the read still failed, most often permissions)
/// - error.OutOfMemory
pub fn load(io: std.Io, allocator: std.mem.Allocator, file_path: []const u8, max_bytes: usize) ![]u8 {
    // NetBSD hands back directory entries rather than refusing the read, so without this the
    // caller there receives binary dirent bytes as if they were file content.
    if (comptime READ_SUCCEEDS_ON_DIRECTORY) {
        const info = std.Io.Dir.cwd().statFile(io, file_path, .{}) catch |err| return switch (err) {
            error.FileNotFound => error.ZixFileNotFound,
            else => error.ZixFileUnreadable,
        };

        if (info.kind == .directory) return error.ZixFilePathIsDirectory;
    }

    // A caller that only learns "NotFound" cannot tell a typo from a permission problem, and the
    // name is all it gets: an error value has nowhere to put the path. Four causes, four names,
    // and the caller names the path it passed in.
    return std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_bytes +| 1)) catch |err| switch (err) {
        error.FileNotFound => error.ZixFileNotFound,
        error.IsDir => error.ZixFilePathIsDirectory,
        error.StreamTooLong => error.ZixFileTooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => error.ZixFileUnreadable,
    };
}

/// Save file data to a directory, creating it if it does not exist
///
/// Param:
/// io - std.Io
/// allocator - std.mem.Allocator (used to return an owned copy of the saved path)
/// dir - []const u8 (destination directory path)
/// filename - []const u8
/// data - []const u8 (file content)
///
/// Return:
/// - ![]const u8 (caller-owned full path of the saved file)
pub fn save(io: std.Io, allocator: std.mem.Allocator, dir: []const u8, filename: []const u8, data: []const u8) ![]const u8 {
    std.Io.Dir.cwd().createDirPath(io, dir) catch {};

    var path_buf: [MAX_PATH_LEN]u8 = undefined;
    if (dir.len + 1 + filename.len > path_buf.len) return error.ZixPathTooLong;
    @memcpy(path_buf[0..dir.len], dir);
    path_buf[dir.len] = '/';
    @memcpy(path_buf[dir.len + 1 ..][0..filename.len], filename);
    const full_path = path_buf[0 .. dir.len + 1 + filename.len];

    const f = try std.Io.Dir.cwd().createFile(io, full_path, .{});
    defer f.close(io);

    var write_buf: [WRITE_BUF_SIZE]u8 = undefined;
    var writer = f.writer(io, &write_buf);
    try writer.interface.writeAll(data);
    try writer.interface.flush();

    return try allocator.dupe(u8, full_path);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: file exists" {
    const io = std.testing.io;
    const content = "abcdefg";
    const file_save = "exists.txt";
    const file_error = "not-exists.txt";

    const file = try std.Io.Dir.cwd().createFile(io, file_save, .{ .read = true });
    defer file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, file_save) catch {};
    _ = try file.writePositionalAll(io, content, 0);

    try std.testing.expect(try exists(io, file_save));
    try std.testing.expect(!try exists(io, file_error));
}

test "zix utils: file extension" {
    try std.testing.expectEqualStrings("txt", extension("file.txt"));
    try std.testing.expectEqualStrings("gz", extension("file.tar.gz"));
    try std.testing.expectEqualStrings("", extension("file"));
    try std.testing.expectEqualStrings("", extension("file."));
    try std.testing.expectEqualStrings("hidden", extension(".hidden"));
}

test "zix utils: file load, round trip through save" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    const allocator = std.testing.allocator;
    const content = "<h1>zix</h1>\n";

    const saved_path = try save(io, allocator, "tmp/zix_file_load_test", "page.html", content);
    defer allocator.free(saved_path);
    defer std.Io.Dir.cwd().deleteFile(io, saved_path) catch {};

    const read_back = try load(io, allocator, saved_path, 4096);
    defer allocator.free(read_back);

    try std.testing.expectEqualStrings(content, read_back);
}

test "zix utils: file load, over max_bytes fails instead of allocating" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    const allocator = std.testing.allocator;
    const content = "0123456789";

    const saved_path = try save(io, allocator, "tmp/zix_file_load_test", "oversize.txt", content);
    defer allocator.free(saved_path);
    defer std.Io.Dir.cwd().deleteFile(io, saved_path) catch {};

    // A ceiling below the file size must fail. Exactly the file size must succeed, which is
    // the whole point of the inclusive adjustment inside load().
    try std.testing.expectError(error.ZixFileTooLarge, load(io, allocator, saved_path, content.len - 1));

    const exact = try load(io, allocator, saved_path, content.len);
    defer allocator.free(exact);

    try std.testing.expectEqualStrings(content, exact);
}

test "zix utils: file load, a missing path is named as missing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    try std.testing.expectError(
        error.ZixFileNotFound,
        load(threaded.io(), std.testing.allocator, "tmp/zix_file_load_test/definitely_absent.html", 4096),
    );
}

test "zix utils: file load, a directory is named as a directory, not as missing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    std.Io.Dir.cwd().createDirPath(io, "tmp/zix_file_load_test/a_directory") catch {};
    defer std.Io.Dir.cwd().deleteTree(io, "tmp/zix_file_load_test/a_directory") catch {};

    try std.testing.expectError(
        error.ZixFilePathIsDirectory,
        load(io, std.testing.allocator, "tmp/zix_file_load_test/a_directory", 4096),
    );
}
