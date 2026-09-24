//! The smallest thing that proves the native GPU stack is real: a window from `zglfw`, a device
//! from `zgpu` (Dawn), and a swapchain that actually presents frames on screen.
//!
//! There is no triangle here on purpose. A clear-and-present loop exercises every layer that has to
//! work — window creation, platform handle extraction, surface creation, adapter selection, device
//! acquisition, swapchain configuration, command submission, vsync — and fails loudly at whichever
//! one is broken. Geometry can wait until the pixels are on screen.
//!
//! Run with: zig build run

const std = @import("std");
const zglfw = @import("zglfw");
const zgpu = @import("zgpu");
const wgpu = zgpu.wgpu;

/// `zgpu` wants plain function pointers, and GLFW's are C-convention, so each one gets a thin
/// wrapper rather than a cast. This is also where a platform mismatch would show up as a compile
/// error instead of a null pointer at runtime.
const Provider = struct {
    pub fn getTime() f64 {
        return zglfw.getTime();
    }

    pub fn getFramebufferSize(window: *const anyopaque) [2]u32 {
        const w: *zglfw.Window = @constCast(@ptrCast(@alignCast(window)));
        const size = w.getFramebufferSize();
        return .{ @intCast(@max(size[0], 0)), @intCast(@max(size[1], 0)) };
    }

    pub fn getX11Display() callconv(.c) *anyopaque {
        return @ptrCast(zglfw.getX11Display());
    }

    pub fn getX11Window(window: *const anyopaque) callconv(.c) u32 {
        const w: *zglfw.Window = @constCast(@ptrCast(@alignCast(window)));
        return zglfw.getX11Window(w);
    }

    pub fn getWaylandDisplay() callconv(.c) *anyopaque {
        return @ptrCast(zglfw.getWaylandDisplay());
    }

    pub fn getWaylandSurface(window: *const anyopaque) callconv(.c) *anyopaque {
        const w: *zglfw.Window = @constCast(@ptrCast(@alignCast(window)));
        return zglfw.getWaylandWindow(w) orelse unreachable;
    }
};

/// A slow colour cycle, so a frozen window is distinguishable from a running one at a glance.
fn tint(seconds: f64) wgpu.Color {
    const phase: f32 = @floatCast(seconds * 0.25);
    return .{
        .r = 0.5 + 0.5 * @sin(phase),
        .g = 0.5 + 0.5 * @sin(phase + 2.094),
        .b = 0.5 + 0.5 * @sin(phase + 4.188),
        .a = 1.0,
    };
}

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    try zglfw.init();
    defer zglfw.terminate();

    if (!zglfw.isVulkanSupported()) {
        std.debug.print("This platform reports no Vulkan support - Dawn has nothing to present with.\n", .{});
        return error.NoVulkan;
    }

    // Dawn owns the graphics context; GLFW exists only to open the window and hand over its handle.
    zglfw.windowHint(.client_api, .no_api);
    const window = try zglfw.createWindow(960, 600, "zurtr - zgpu - hello", null, null);
    defer window.destroy();

    const gctx = try zgpu.GraphicsContext.create(gpa, .{
        .window = window,
        .fn_getTime = &Provider.getTime,
        .fn_getFramebufferSize = &Provider.getFramebufferSize,
        .fn_getX11Display = &Provider.getX11Display,
        .fn_getX11Window = &Provider.getX11Window,
        .fn_getWaylandDisplay = &Provider.getWaylandDisplay,
        .fn_getWaylandSurface = &Provider.getWaylandSurface,
    }, .{});
    defer gctx.destroy(gpa);

    std.debug.print("presenting on {s}; close the window to exit\n", .{
        if (zglfw.getPlatform() == .wayland) "Wayland" else "X11",
    });

    var frames: u64 = 0;
    while (!window.shouldClose()) {
        zglfw.pollEvents();

        const back_view = gctx.swapchain.getCurrentTextureView();
        defer back_view.release();

        const encoder = gctx.device.createCommandEncoder(null);
        defer encoder.release();

        const pass = zgpu.beginRenderPassSimple(encoder, .clear, back_view, tint(zglfw.getTime()), null, null);
        zgpu.endReleasePass(pass);

        gctx.queue.submit(&.{encoder.finish(null)});
        _ = gctx.present();

        frames += 1;
    }

    std.debug.print("{d} frames presented\n", .{frames});
}
