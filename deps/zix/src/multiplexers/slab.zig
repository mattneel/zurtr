//! Shared demand-paging primitives for the per-worker EPOLL/URING connection
//! tables. Per ADR-042 the per-engine tables stay per-engine, only these
//! byte-identical primitives are shared.
//!
//! Two ideas, both about letting Linux demand-paging do the work:
//! - A connection slots array is mmap'd (kernel-zeroed, demand-paged) instead of
//!   allocated and memset, so an untouched slot costs no physical memory. The std
//!   allocators scribble 0xAA over fresh memory in safe builds, so they cannot be
//!   used where a slot is read before it is written.
//! - A closed connection's slab pages are handed back to the OS, so resident
//!   memory tracks live connections, not the lifetime high-water of fd indices.

const std = @import("std");
const builtin = @import("builtin");

/// mmap a zero-filled, demand-paged slots array of `count` elements of T. Works
/// for an inline-struct slot (zero == empty) or a pointer slot (zero == null).
///
/// Param:
/// T - type (the slot element type)
/// count - usize (how many slots)
///
/// Return:
/// - []T (page-aligned, all zero, demand-paged)
pub fn mapZeroedSlots(comptime T: type, count: usize) ![]T {
    if (comptime builtin.os.tag == .windows) {
        // Kernel-zeroed demand-paged pages over ntdll, same contract as the
        // POSIX mmap below.
        const bytes = count * @sizeOf(T);
        const base = std.heap.PageAllocator.map(bytes, .fromByteUnits(std.heap.page_size_min)) orelse return error.OutOfMemory;
        const mapped: [*]align(std.heap.page_size_min) u8 = @alignCast(base);

        return std.mem.bytesAsSlice(T, mapped[0..bytes]);
    }

    const mapped = try std.posix.mmap(
        null,
        count * @sizeOf(T),
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );

    return std.mem.bytesAsSlice(T, mapped);
}

/// Unmap a slots array obtained from mapZeroedSlots.
pub fn unmapSlots(slots: anytype) void {
    if (comptime builtin.os.tag == .windows) {
        std.heap.PageAllocator.unmap(@alignCast(std.mem.sliceAsBytes(slots)));
        return;
    }

    std.posix.munmap(@alignCast(std.mem.sliceAsBytes(slots)));
}

/// Return the slab pages backing a closed connection to the OS, so resident
/// memory tracks live connections instead of the lifetime high-water of fd
/// indices touched. The slab is anonymous demand-paged memory, so the next first
/// touch on a reused fd faults a fresh zero page.
///
/// Note:
/// - MADV_DONTNEED needs a page-aligned range, so only the pages fully covered
///   by the slice are advised. With a page-aligned slab base and a page-multiple
///   buf_size that is the whole slice.
/// - Best-effort: a failed advise is ignored, the slot is reusable either way.
///
/// Param:
/// buf - []u8 (the connection slab slice handed out by the table alloc)
///
/// Return:
/// - void
pub fn releaseSlabPages(buf: []u8) void {
    const page = std.heap.page_size_min;
    const base = @intFromPtr(buf.ptr);
    const start = std.mem.alignForward(usize, base, page);
    const end = std.mem.alignBackward(usize, base + buf.len, page);
    if (end <= start) return;

    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(start);
    if (comptime builtin.os.tag == .windows) {
        // MEM_RESET is the ntdll analog of MADV_DONTNEED: content is discardable,
        // the range stays mapped and refaults zero-filled.
        var reset_addr: ?*anyopaque = ptr;
        var reset_size: std.os.windows.SIZE_T = end - start;
        _ = std.os.windows.ntdll.NtAllocateVirtualMemory(std.os.windows.GetCurrentProcess(), @ptrCast(&reset_addr), 0, &reset_size, .{ .RESET = true }, .{ .NOACCESS = true });
        return;
    }

    std.posix.madvise(ptr, end - start, std.posix.MADV.DONTNEED) catch {};
}

/// Best-effort MADV_NOHUGEPAGE over the pages fully covered by buf, so a slab
/// keeps plain 4 KiB demand paging even on a host whose THP policy is
/// "always". A contiguous slab is a perfect THP target there: any touch
/// materializes a whole 2 MiB extent (dozens of neighbor slots) and khugepaged
/// re-collapse undoes MADV_DONTNEED reclaim, so resident memory tracks the
/// touched extent high-water instead of the live set. Opting out keeps
/// resident memory equal to the pages actually written, on every host, every
/// run. A kernel without THP ignores the advise. MADV_NOHUGEPAGE is Linux-only,
/// so this is a no-op elsewhere.
///
/// Param:
/// buf - []u8 (the slab, page-aligned when it comes from mapZeroedSlots)
///
/// Return:
/// - void
pub fn adviseNoHugePages(buf: []u8) void {
    if (comptime builtin.os.tag != .linux) return;

    const page = std.heap.page_size_min;
    const base = @intFromPtr(buf.ptr);
    const start = std.mem.alignForward(usize, base, page);
    const end = std.mem.alignBackward(usize, base + buf.len, page);
    if (end <= start) return;

    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(start);
    std.posix.madvise(ptr, end - start, std.posix.MADV.NOHUGEPAGE) catch {};
}

/// Fault buf's pages in now (one byte written per page), so a slab's residency
/// is a startup property instead of a first-recv fault during the load ramp.
/// Writes zero, so a fresh anonymous mapping keeps its content.
///
/// Param:
/// buf - []u8 (the slab prefix to make resident)
///
/// Return:
/// - void
pub fn pretouch(buf: []u8) void {
    var pos: usize = 0;
    while (pos < buf.len) : (pos += std.heap.page_size_min) buf[pos] = 0;
}

test "zix multiplexers: slab mapZeroedSlots returns zeroed, releaseSlabPages re-zeros" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("slab slots are mapped through a Linux mmap, test skipped", .{});
        return;
    }

    // Pointer slots come back all null (zero bits).
    const ptr_slots = try mapZeroedSlots(?*u8, 4096);
    defer unmapSlots(ptr_slots);
    for (ptr_slots) |p| try std.testing.expectEqual(@as(?*u8, null), p);

    // releaseSlabPages hands an anonymous page back, so the next read is zero.
    const page = std.heap.page_size_min;
    const mem = try std.heap.page_allocator.alloc(u8, page * 2);
    defer std.heap.page_allocator.free(mem);

    @memset(mem, 0xAA);
    releaseSlabPages(mem);

    try std.testing.expectEqual(@as(u8, 0), mem[0]);
    try std.testing.expectEqual(@as(u8, 0), mem[page]);
}

test "zix multiplexers: slab pretouch keeps a fresh mapping zeroed and leaves data intact" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("slab slots are mapped through a Linux mmap, test skipped", .{});
        return;
    }

    const page = std.heap.page_size_min;
    const buf = try mapZeroedSlots(u8, page * 3);
    defer unmapSlots(buf);

    // Fresh mapping: pretouch faults the pages, content stays zero.
    pretouch(buf);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[page * 2]);

    // Already-written pages keep their bytes past the touched first byte.
    buf[1] = 0xBB;
    pretouch(buf[0..page]);
    try std.testing.expectEqual(@as(u8, 0xBB), buf[1]);
}

test "zix multiplexers: slab adviseNoHugePages is a safe no-op on any page-aligned slab" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("slab slots are mapped through a Linux mmap, test skipped", .{});
        return;
    }

    const page = std.heap.page_size_min;
    const buf = try mapZeroedSlots(u8, page * 2);
    defer unmapSlots(buf);

    // Best-effort advise: never faults, never alters content.
    buf[0] = 0x11;
    adviseNoHugePages(buf);
    try std.testing.expectEqual(@as(u8, 0x11), buf[0]);

    // A sub-page slice covers no full page and must be skipped without error.
    adviseNoHugePages(buf[1 .. page - 1]);
}
