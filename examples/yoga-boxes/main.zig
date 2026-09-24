//! Yoga's layout engine and zgpu's renderer in one process: every rectangle drawn is a rectangle
//! Yoga computed.
//!
//! `examples/hello-gpu` proved the window, device, swapchain and present path are real, and
//! `deps/yoga` proves the layout engine runs and computes geometry, but nothing has ever fed one
//! into the other. This example is that conjunction, with no more machinery than it takes: build a
//! nested flex tree, ask Yoga for every node's box, turn each box into two triangles, draw them all
//! in one call.
//!
//! Nothing in the vertex buffer is a hand-written rectangle. The boxes come out of
//! `YGNodeLayoutGet*()` and the one constant that reaches the geometry — the root's size — is read
//! from the window's framebuffer. Change any style number in `specs` and every box downstream of it
//! moves, because there is no other source of coordinates in this file.
//!
//! Run with: zig build run

const std = @import("std");
const zglfw = @import("zglfw");
const zgpu = @import("zgpu");
const wgpu = zgpu.wgpu;

/// Yoga's C API, declared instead of imported.
///
/// Zig 0.17 removed `@cImport`, and `translate-c` over `yoga/Yoga.h` would drag in the C++ side of
/// the headers (the `YG_ENUM_DECL` enums are `enum class` under `__cplusplus`). What this example
/// actually touches is small — one opaque node type, six int-backed enums, eighteen functions — so
/// the declarations live here, in one screen, with no generated module and no build step.
///
/// `YG_EXTERN_C` gives every function below C linkage, so these are exactly the symbols `libyoga.a`
/// exports; `nm` on the artifact shows `YGNodeNew`, `YGNodeStyleSetPadding`, `YGNodeCalculateLayout`
/// and friends unmangled. `YG_ENUM_DECL` builds a plain C enum whose members take their values from
/// declaration order, which is why each `enum(c_int)` here lists members in the same order as
/// `deps/yoga/yoga/YGEnums.h` — the implicit values match member for member, and `c_int` is the
/// width the C++ `enum class` defaults to.
const yoga = struct {
    const Node = opaque {};
    pub const NodeRef = *Node;
    pub const NodeConstRef = *const Node;

    pub const Direction = enum(c_int) { inherit, ltr, rtl };
    pub const FlexDirection = enum(c_int) { column, column_reverse, row, row_reverse };
    pub const Align = enum(c_int) { auto, flex_start, center, flex_end, stretch, baseline, space_between, space_around, space_evenly, start, end };
    pub const Justify = enum(c_int) { auto, flex_start, center, flex_end, space_between, space_around, space_evenly, stretch, start, end };
    pub const Edge = enum(c_int) { left, top, right, bottom, start, end, horizontal, vertical, all };
    pub const Gutter = enum(c_int) { column, row, all };

    pub extern "c" fn YGNodeNew() NodeRef;
    pub extern "c" fn YGNodeFreeRecursive(node: NodeRef) void;
    pub extern "c" fn YGNodeInsertChild(node: NodeRef, child: NodeRef, index: usize) void;
    pub extern "c" fn YGNodeGetChildCount(node: NodeConstRef) usize;
    pub extern "c" fn YGNodeStyleSetFlexDirection(node: NodeRef, flex_direction: FlexDirection) void;
    pub extern "c" fn YGNodeStyleSetJustifyContent(node: NodeRef, justify_content: Justify) void;
    pub extern "c" fn YGNodeStyleSetAlignItems(node: NodeRef, align_items: Align) void;
    pub extern "c" fn YGNodeStyleSetWidth(node: NodeRef, width: f32) void;
    pub extern "c" fn YGNodeStyleSetHeight(node: NodeRef, height: f32) void;
    pub extern "c" fn YGNodeStyleSetFlexGrow(node: NodeRef, flex_grow: f32) void;
    pub extern "c" fn YGNodeStyleSetFlexShrink(node: NodeRef, flex_shrink: f32) void;
    pub extern "c" fn YGNodeStyleSetPadding(node: NodeRef, edge: Edge, padding: f32) void;
    pub extern "c" fn YGNodeStyleSetGap(node: NodeRef, gutter: Gutter, gap_length: f32) void;
    pub extern "c" fn YGNodeCalculateLayout(node: NodeRef, available_width: f32, available_height: f32, owner_direction: Direction) void;
    pub extern "c" fn YGNodeLayoutGetLeft(node: NodeConstRef) f32;
    pub extern "c" fn YGNodeLayoutGetTop(node: NodeConstRef) f32;
    pub extern "c" fn YGNodeLayoutGetWidth(node: NodeConstRef) f32;
    pub extern "c" fn YGNodeLayoutGetHeight(node: NodeConstRef) f32;
};

/// The window and the time source handed to `zgpu`, which wants plain function pointers. GLFW's are
/// C-convention, so each one gets a thin wrapper rather than a cast — a platform mismatch then shows
/// up as a compile error instead of a null pointer at run time.
///
/// The Wayland pair is registered *conditionally* (see `main`): `glfwGetWaylandDisplay` returns null
/// off Wayland, and `WindowProvider`'s Wayland slots are optional precisely so a caller can leave
/// them unset. Wiring them unconditionally — which is what `examples/hello-gpu` does — panics with
/// "cast causes pointer to be null" the moment the same binary runs on X11.
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

// ---------------------------------------------------------------------------------------------------
// The scene: a flex tree written as style input, plus the colour each box is painted in.
// ---------------------------------------------------------------------------------------------------

/// One box. Everything except `name`, `parent` and `color` is fed to Yoga as style; a null style
/// field means "leave Yoga's default alone", so the tree below reads as the CSS-shaped rules it is.
const Spec = struct {
    name: []const u8,
    parent: ?usize = null,
    color: [4]f32,
    flex_direction: ?yoga.FlexDirection = null,
    justify: ?yoga.Justify = null,
    align_items: ?yoga.Align = null,
    width: ?f32 = null,
    height: ?f32 = null,
    flex_grow: f32 = 0,
    /// Yoga's own default is 0 (CSS's is 1), so the field says 0 and the two rows that are meant to
    /// shrink inside a too-small column set it to 1 explicitly.
    flex_shrink: f32 = 0,
    padding: ?f32 = null,
    gap: ?f32 = null,
};

/// An app-shell-shaped tree: a sidebar of three fixed rows inside a deliberately short column (so
/// flex shrink has something to do), and a content column whose header and body split the rest.
/// Parents are listed before their children, which lets `relayout` accumulate absolute origins in a
/// single forward pass — the assertion below is what keeps that true.
const specs = [_]Spec{
    // 0: sized from the framebuffer, so the whole layout follows the window, not a constant here.
    .{ .name = "root", .color = .{ 0.05, 0.06, 0.08, 1 }, .flex_direction = .row },
    .{ .name = "sidebar", .parent = 0, .color = .{ 0.12, 0.16, 0.22, 1 }, .flex_direction = .column, .width = 220, .height = 320, .padding = 12, .gap = 8 },
    // Three 140pt rows in a 296pt content box (320 - 2x12 padding), which is 280pt once the two 8pt
    // gaps are taken out. They cannot fit, so each shrinks by the same weight: 280/3 = 93.33, which
    // Yoga rounds onto its pixel grid as 93 / 94 / 93 (visible in the print-out). Only 140 is written
    // down here; 280, 93.33 and the rounding step are all Yoga's.
    .{ .name = "brand", .parent = 1, .color = .{ 0.30, 0.52, 0.92, 1 }, .height = 140, .flex_shrink = 1 },
    .{ .name = "nav.a", .parent = 1, .color = .{ 0.24, 0.32, 0.45, 1 }, .height = 140, .flex_shrink = 1 },
    .{ .name = "nav.b", .parent = 1, .color = .{ 0.24, 0.32, 0.45, 1 }, .height = 140, .flex_shrink = 1 },
    // The one row item that grows: it takes whatever the sidebar has left over.
    .{ .name = "content", .parent = 0, .color = .{ 0.08, 0.10, 0.13, 1 }, .flex_direction = .column, .flex_grow = 1, .padding = 16, .gap = 12 },
    .{ .name = "header", .parent = 5, .color = .{ 0.15, 0.18, 0.24, 1 }, .flex_direction = .row, .height = 64, .padding = 8, .gap = 8 },
    .{ .name = "title", .parent = 6, .color = .{ 0.45, 0.68, 1.0, 1 }, .flex_grow = 1 },
    .{ .name = "action", .parent = 6, .color = .{ 0.95, 0.63, 0.22, 1 }, .width = 96 },
    .{ .name = "body", .parent = 5, .color = .{ 0.11, 0.13, 0.17, 1 }, .flex_direction = .row, .flex_grow = 1, .gap = 12 },
    // Grow weights 3:1 split the body's width; the nested column inside the main card splits its
    // height in half — three levels of tree, all of them flex-derived.
    .{ .name = "card.main", .parent = 9, .color = .{ 0.18, 0.44, 0.37, 1 }, .flex_direction = .column, .flex_grow = 3, .padding = 12, .gap = 10 },
    .{ .name = "card.side", .parent = 9, .color = .{ 0.52, 0.29, 0.53, 1 }, .flex_grow = 1 },
    .{ .name = "stat.a", .parent = 10, .color = .{ 0.24, 0.58, 0.48, 1 }, .flex_grow = 1 },
    .{ .name = "stat.b", .parent = 10, .color = .{ 0.30, 0.68, 0.56, 1 }, .flex_grow = 1 },
};

comptime {
    for (specs, 0..) |spec, i| {
        if (spec.parent) |parent| {
            if (parent >= i) @compileError("every parent must be declared before its child: " ++ spec.name);
        } else if (i != 0) {
            @compileError("only the root may have no parent: " ++ spec.name);
        }
    }
}

const node_count = specs.len;
/// Two triangles per box: (l,t) (r,t) (l,b), then (r,t) (r,b) (l,b).
const vertices_per_box = 6;
const vertex_count = node_count * vertices_per_box;

const Rect = struct {
    /// Pixels, relative to the window's top-left corner — the space the shader maps to clip space.
    left: f32,
    top: f32,
    width: f32,
    height: f32,
};

const Box = struct {
    name: []const u8,
    color: [4]f32,
    rect: Rect,
};

/// What one vertex is: `position` in pixels, `color` straight through to the fragment stage.
/// `extern` because the struct is uploaded verbatim; 24 bytes, which is the vertex stride.
const Vertex = extern struct {
    position: [2]f32,
    color: [4]f32,
};

/// 16 bytes so the uniform binding size is a multiple of the 16 WebGPU asks of uniform data. The
/// `_padding` member is spelled the same in both shaders.
const Uniforms = extern struct {
    viewport: [2]f32,
    _padding: [2]f32,
};

const Scene = struct {
    /// Yoga's nodes, one per spec, in spec order.
    nodes: [node_count]yoga.NodeRef,
    /// What Yoga computed for each of them, in absolute pixels.
    boxes: [node_count]Box,
    /// The same boxes as triangle soup, ready to upload.
    vertices: [vertex_count]Vertex,
};

fn createTree(scene: *Scene) void {
    for (specs, 0..) |spec, i| {
        const node = yoga.YGNodeNew();
        if (spec.flex_direction) |d| yoga.YGNodeStyleSetFlexDirection(node, d);
        if (spec.justify) |j| yoga.YGNodeStyleSetJustifyContent(node, j);
        if (spec.align_items) |a| yoga.YGNodeStyleSetAlignItems(node, a);
        if (spec.width) |w| yoga.YGNodeStyleSetWidth(node, w);
        if (spec.height) |h| yoga.YGNodeStyleSetHeight(node, h);
        if (spec.padding) |p| yoga.YGNodeStyleSetPadding(node, .all, p);
        if (spec.gap) |g| yoga.YGNodeStyleSetGap(node, .all, g);
        yoga.YGNodeStyleSetFlexGrow(node, spec.flex_grow);
        yoga.YGNodeStyleSetFlexShrink(node, spec.flex_shrink);
        scene.nodes[i] = node;
    }
    // Second pass: every node exists before any child is attached, so a spec may name any parent
    // and the child order is the spec order.
    for (specs, 0..) |spec, i| {
        if (spec.parent) |parent| {
            yoga.YGNodeInsertChild(scene.nodes[parent], scene.nodes[i], yoga.YGNodeGetChildCount(scene.nodes[parent]));
        }
    }
}

fn destroyTree(scene: *Scene) void {
    yoga.YGNodeFreeRecursive(scene.nodes[0]);
}

/// Lay the tree out for a viewport and rebuild the vertex data from the result. Called once at
/// startup and again whenever the framebuffer changes size.
fn relayout(scene: *Scene, viewport: [2]f32) void {
    // The root's size is style input like any other; it comes from the window rather than from a
    // constant, so the layout is a function of the framebuffer.
    yoga.YGNodeStyleSetWidth(scene.nodes[0], viewport[0]);
    yoga.YGNodeStyleSetHeight(scene.nodes[0], viewport[1]);
    yoga.YGNodeCalculateLayout(scene.nodes[0], viewport[0], viewport[1], .ltr);

    // Yoga reports a node's box relative to its parent. Parents come first in `specs`, so one
    // forward pass carries the absolute origin down the tree.
    for (specs, 0..) |spec, i| {
        const origin: [2]f32 = if (spec.parent) |parent|
            .{ scene.boxes[parent].rect.left, scene.boxes[parent].rect.top }
        else
            .{ 0, 0 };
        scene.boxes[i] = .{
            .name = spec.name,
            .color = spec.color,
            .rect = .{
                .left = origin[0] + yoga.YGNodeLayoutGetLeft(scene.nodes[i]),
                .top = origin[1] + yoga.YGNodeLayoutGetTop(scene.nodes[i]),
                .width = yoga.YGNodeLayoutGetWidth(scene.nodes[i]),
                .height = yoga.YGNodeLayoutGetHeight(scene.nodes[i]),
            },
        };
    }

    // Every box becomes two triangles in pixel space, in tree order: parents first, so a child is
    // painted over the container it sits in.
    for (scene.boxes, 0..) |box, i| {
        const l = box.rect.left;
        const t = box.rect.top;
        const r = l + box.rect.width;
        const b = t + box.rect.height;
        const corners = [4][2]f32{ .{ l, t }, .{ r, t }, .{ l, b }, .{ r, b } };
        const order = [vertices_per_box]usize{ 0, 1, 2, 1, 3, 2 };
        for (order, 0..) |corner, v| {
            scene.vertices[i * vertices_per_box + v] = .{
                .position = corners[corner],
                .color = box.color,
            };
        }
    }
}

/// Indentation for the tree print-out, indexed by depth.
const indent = "                                        ";

fn depthOf(i: usize) usize {
    var depth: usize = 0;
    var cursor = specs[i].parent;
    while (cursor) |parent| : (cursor = specs[parent].parent) depth += 1;
    return depth;
}

fn printLayout(scene: *const Scene, viewport: [2]f32) void {
    std.debug.print("yoga-boxes: {d} nodes laid out for a {d:.0}x{d:.0} viewport\n", .{
        node_count,
        viewport[0],
        viewport[1],
    });
    std.debug.print("  {s: <26}{s: <14}{s: >8}{s: >8}{s: >8}{s: >8}\n", .{
        "box (nested)", "parent", "left", "top", "width", "height",
    });
    for (specs, 0..) |spec, i| {
        const box = scene.boxes[i];
        std.debug.print("{s}{s: <26}{s: <14}", .{
            indent[0 .. 2 + depthOf(i) * 2],
            spec.name,
            if (spec.parent) |parent| specs[parent].name else "-",
        });
        std.debug.print("{d: >8.2}{d: >8.2}{d: >8.2}{d: >8.2}\n", .{
            box.rect.left, box.rect.top, box.rect.width, box.rect.height,
        });
    }

    // The one invariant that ties the two layers together: the root Yoga laid out is the window.
    const root = scene.boxes[0].rect;
    const fills_viewport = root.left == 0 and root.top == 0 and
        root.width == viewport[0] and root.height == viewport[1];
    std.debug.print("root rect covers the viewport: {s}; {d} boxes -> {d} vertices -> {d} triangles\n", .{
        if (fills_viewport) "yes" else "NO",
        node_count,
        vertex_count,
        vertex_count / 3,
    });
}

/// `createRenderPipelineSimple` hard-codes `main` as the entry point for both stages — and takes the
/// two stages as separate modules, so one `main` in each is exactly what it wants.
///
/// Vertex positions arrive in the pixel space Yoga reports, and the viewport uniform is the only
/// thing that turns them into clip space. That is deliberate: it keeps the numbers in the vertex
/// buffer identical to the numbers Yoga returned.
const vs_wgsl =
    \\struct Uniforms {
    \\    viewport: vec2<f32>,
    \\    _padding: vec2<f32>,
    \\};
    \\
    \\@group(0) @binding(0) var<uniform> uniforms: Uniforms;
    \\
    \\struct VertexOutput {
    \\    @builtin(position) clip: vec4<f32>,
    \\    @location(0) color: vec4<f32>,
    \\};
    \\
    \\@vertex
    \\fn main(@location(0) position: vec2<f32>, @location(1) color: vec4<f32>) -> VertexOutput {
    \\    // Yoga's origin is the top-left corner with +y down; clip space is centred with +y up.
    \\    let ndc = vec2<f32>(
    \\        position.x / uniforms.viewport.x * 2.0 - 1.0,
    \\        1.0 - position.y / uniforms.viewport.y * 2.0,
    \\    );
    \\    var out: VertexOutput;
    \\    out.clip = vec4<f32>(ndc, 0.0, 1.0);
    \\    out.color = color;
    \\    return out;
    \\}
;

const fs_wgsl =
    \\@fragment
    \\fn main(@location(0) color: vec4<f32>) -> @location(0) vec4<f32> {
    \\    return color;
    \\}
;

/// `createRenderPipelineSimple` compiles WGSL asynchronously (`enable_async_shader_compilation` is
/// on inside zgpu), so the handle is filled in from the completion callback rather than returned.
/// The callback runs while the device is being ticked, and `pipeline` has to be passed *by pointer*:
/// a copy taken before the callback runs would read as nil forever, which is what a first version of
/// this did.
fn waitForPipeline(gctx: *zgpu.GraphicsContext, pipeline: *zgpu.RenderPipelineHandle) !void {
    var ticks: u32 = 0;
    while (gctx.lookupResource(pipeline.*) == null) : (ticks += 1) {
        // Bounded so a shader that fails to compile ends as an error instead of a hang; zgpu logs
        // the reason from the callback.
        if (ticks >= 1_000_000) return error.RenderPipelineNotCompiled;
        gctx.device.tick();
    }
    std.debug.print("render pipeline compiled after {d} device tick(s)\n", .{ticks});
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
    const window = try zglfw.createWindow(960, 600, "zurtr - yoga boxes", null, null);
    defer window.destroy();

    // Only the running platform's handles are handed over; the other platform's accessors return
    // null, and a non-optional function pointer that returns null panics on the cast.
    const on_wayland = zglfw.getPlatform() == .wayland;

    const gctx = try zgpu.GraphicsContext.create(gpa, .{
        .window = window,
        .fn_getTime = &Provider.getTime,
        .fn_getFramebufferSize = &Provider.getFramebufferSize,
        .fn_getX11Display = &Provider.getX11Display,
        .fn_getX11Window = &Provider.getX11Window,
        .fn_getWaylandDisplay = if (on_wayland) &Provider.getWaylandDisplay else null,
        .fn_getWaylandSurface = if (on_wayland) &Provider.getWaylandSurface else null,
    }, .{});
    defer gctx.destroy(gpa);

    // --- Yoga ------------------------------------------------------------------------------------
    var scene: Scene = undefined;
    createTree(&scene);
    defer destroyTree(&scene);

    var viewport = currentViewport(window);
    relayout(&scene, viewport);
    printLayout(&scene, viewport);

    // --- GPU -------------------------------------------------------------------------------------
    // One static vertex buffer holds every box; only its contents ever change, when the window is
    // resized and Yoga hands back different rects.
    const vertex_buffer = gctx.createBuffer(.{
        .label = "yoga-boxes vertices",
        .usage = .{ .vertex = true, .copy_dst = true },
        .size = vertex_count * @sizeOf(Vertex),
    });
    defer gctx.releaseResource(vertex_buffer);
    gctx.queue.writeBuffer(gctx.lookupResource(vertex_buffer).?, 0, Vertex, &scene.vertices);

    // The viewport uniform is a dynamic offset into zgpu's own uniform buffer, so the binding is
    // declared with `has_dynamic_offset` and bound with the offset `uniformsAllocate` returns.
    const bgl = gctx.createBindGroupLayout(&.{
        zgpu.bufferEntry(0, .{ .vertex = true }, .uniform, true, @sizeOf(Uniforms)),
    });
    defer gctx.releaseResource(bgl);

    const vertex_attribs = [_]wgpu.VertexAttribute{
        .{ .format = .float32x2, .offset = 0, .shader_location = 0 },
        .{ .format = .float32x4, .offset = 8, .shader_location = 1 },
    };

    var pipeline: zgpu.RenderPipelineHandle = .{};
    zgpu.createRenderPipelineSimple(
        gpa,
        gctx,
        &.{bgl},
        vs_wgsl,
        fs_wgsl,
        @sizeOf(Vertex),
        &vertex_attribs,
        .{ .topology = .triangle_list, .cull_mode = .none },
        zgpu.GraphicsContext.swapchain_format,
        null, // No depth attachment: painter's order over a flat tree needs no z-buffer.
        &pipeline,
    );
    try waitForPipeline(gctx, &pipeline);
    defer gctx.releaseResource(pipeline);

    const bind_group = gctx.createBindGroup(bgl, &.{.{
        .binding = 0,
        .buffer_handle = gctx.uniforms.buffer,
        .offset = 0,
        .size = @sizeOf(Uniforms),
    }});
    defer gctx.releaseResource(bind_group);

    std.debug.print("presenting {d} boxes on {s}; close the window to exit\n", .{
        node_count,
        if (zglfw.getPlatform() == .wayland) "Wayland" else "X11",
    });

    var frames: u64 = 0;
    while (!window.shouldClose()) {
        zglfw.pollEvents();

        const resized = currentViewport(window);
        if (resized[0] == 0 or resized[1] == 0) continue; // Minimised: nothing to lay out or draw.
        if (resized[0] != viewport[0] or resized[1] != viewport[1]) {
            viewport = resized;
            relayout(&scene, viewport);
            gctx.queue.writeBuffer(gctx.lookupResource(vertex_buffer).?, 0, Vertex, &scene.vertices);
            std.debug.print("window is now {d:.0}x{d:.0}: Yoga re-ran and {d} vertices were rewritten\n", .{
                viewport[0], viewport[1], vertex_count,
            });
            printLayout(&scene, viewport);
        }

        // The frame's viewport, which is everything the shader needs to place Yoga's pixel-space
        // vertices — the vertex data itself stays as Yoga computed it.
        const uniforms = gctx.uniformsAllocate(Uniforms, 1);
        uniforms.slice[0] = .{ .viewport = viewport, ._padding = .{ 0, 0 } };

        const back_view = gctx.swapchain.getCurrentTextureView();
        defer back_view.release();

        const encoder = gctx.device.createCommandEncoder(null);
        defer encoder.release();

        const pass = zgpu.beginRenderPassSimple(
            encoder,
            .clear,
            back_view,
            .{ .r = 0.02, .g = 0.02, .b = 0.03, .a = 1.0 },
            null,
            null,
        );
        pass.setPipeline(gctx.lookupResource(pipeline).?);
        pass.setBindGroup(0, gctx.lookupResource(bind_group).?, &.{uniforms.offset});
        pass.setVertexBuffer(0, gctx.lookupResource(vertex_buffer).?, 0, vertex_count * @sizeOf(Vertex));
        pass.draw(vertex_count, 1, 0, 0);
        zgpu.endReleasePass(pass);

        gctx.submit(&.{encoder.finish(null)});
        _ = gctx.present();

        frames += 1;
        // Progress on stdout: the boxes are static, so a frozen window and a running one look alike
        // in a screenshot, and a bounded run is killed before the final count prints.
        if (frames == 1 or frames % 30 == 0) {
            std.debug.print("{d} frames presented\n", .{frames});
        }
    }

    std.debug.print("{d} frames presented\n", .{frames});
}

fn currentViewport(window: *zglfw.Window) [2]f32 {
    const size = window.getFramebufferSize();
    return .{ @floatFromInt(@max(size[0], 0)), @floatFromInt(@max(size[1], 0)) };
}
