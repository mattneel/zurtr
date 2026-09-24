//! A zurtr live view in a native window: `live`'s tree in, Yoga's layout, zgpu's rectangles, and a
//! patch in between. One process, no network.
//!
//! `examples/yoga-boxes` proved a hand-written list of specs can drive Yoga and that every rectangle
//! on screen can be a rectangle Yoga computed. What it cannot show is the thing that makes a
//! LiveViewZ client a client: the boxes come from a **server-authored render tree**, and a later
//! revision reaches the canvas **only as patch ops**. This example is that path, end to end:
//!
//!   1. `live.tree.Builder` authors a nested flex view - revision 1 - whose layout is expressed as
//!      style attributes, the way an application would write it. The server keeps the tree, exactly
//!      as `live/tree.zig`'s doc comment describes (it is the same tree the HTML render walks).
//!   2. The client installs it: one canvas node per tree node, one Yoga node per canvas node, and
//!      the tree's `NodeId` kept as the canvas node's id - the same number the markup carries as
//!      `z-id`. That mapping is what makes the next step possible at all.
//!   3. After a couple of seconds the view is rendered again with one thing changed. `patch.diff`
//!      derives the ops between the two trees, `patch.writeJson` serialises them, the client's op
//!      applier mutates the canvas, Yoga lays it out again and the frame is redrawn. **The second
//!      frame differs from the first because of those ops** - there is no timer-driven animation and
//!      no second hard-coded scene in this file to confuse the two.
//!
//! Run with: `zig build run`. The program opens the window, draws revision 1, applies the patch,
//! draws revision 2 and exits by itself; every number it prints comes from the layout it drew.
//!
//! # Reaching `src/live` from here
//!
//! Zig requires an imported file to live inside the importing module's root directory, so
//! `@import("../../src/live/tree.zig")` is rejected - "import of file outside module path" - and
//! `src/live/patch.zig` is not re-exported from `src/root.zig` either (`zurtr.live` exports
//! `protocol`, `tree` and `pubsub`). `vendor/live` is a symlink to `src/live`, which puts the real
//! sources - not copies that could drift - inside this example's module. It matters that both files
//! arrive through the same symlink: `patch.zig` imports `tree.zig` itself, and a file that is the
//! root of one module and imported by another is a compile error ("file exists in modules ..."), so
//! one module has to see both or the two `Tree` types would not be the same type.

const std = @import("std");
const zglfw = @import("zglfw");
const zgpu = @import("zgpu");
const wgpu = zgpu.wgpu;

const live = @import("vendor/live/tree.zig");
const patch = @import("vendor/live/patch.zig");

// ------------------------------------------------------------------------------------------------
// Yoga's C API, declared instead of imported
// ------------------------------------------------------------------------------------------------
//
// Zig 0.17 removed `@cImport`, and `translate-c` over `yoga/Yoga.h` would drag in the C++ side of the
// headers (the `YG_ENUM_DECL` enums are `enum class` under `__cplusplus`). What this example touches
// is one opaque node type, six int-backed enums and twenty functions, so the declarations live here,
// in the same shape `examples/yoga-boxes` established. `YG_EXTERN_C` gives every function below C
// linkage, so these are exactly the symbols `libyoga.a` exports; each `enum(c_int)` lists its members
// in declaration order as `deps/yoga/yoga/YGEnums.h` does, so the implicit values match member for
// member, and `c_int` is the width the C++ `enum class` defaults to.
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
    pub extern "c" fn YGNodeRemoveChild(node: NodeRef, child: NodeRef) void;
    pub extern "c" fn YGNodeStyleSetFlexDirection(node: NodeRef, flex_direction: FlexDirection) void;
    pub extern "c" fn YGNodeStyleSetJustifyContent(node: NodeRef, justify_content: Justify) void;
    pub extern "c" fn YGNodeStyleSetAlignItems(node: NodeRef, align_items: Align) void;
    pub extern "c" fn YGNodeStyleSetWidth(node: NodeRef, width: f32) void;
    pub extern "c" fn YGNodeStyleSetWidthPercent(node: NodeRef, width: f32) void;
    pub extern "c" fn YGNodeStyleSetWidthAuto(node: NodeRef) void;
    pub extern "c" fn YGNodeStyleSetHeight(node: NodeRef, height: f32) void;
    pub extern "c" fn YGNodeStyleSetHeightPercent(node: NodeRef, height: f32) void;
    pub extern "c" fn YGNodeStyleSetHeightAuto(node: NodeRef) void;
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
/// C-convention, so each one gets a thin wrapper rather than a cast - a platform mismatch then shows
/// up as a compile error instead of a null pointer at run time.
///
/// The Wayland pair is registered *conditionally* (see `main`): `glfwGetWaylandDisplay` returns null
/// off Wayland, and `WindowProvider`'s Wayland slots are optional precisely so a caller can leave
/// them unset. Wiring them unconditionally panics with "cast causes pointer to be null" the moment
/// the same binary runs on X11.
const Provider = struct {
    pub fn getTime() f64 {
        return zglfw.getTime();
    }

    pub fn getFramebufferSize(window: *const anyopaque) [2]u32 {
        const w: *zglfw.Window = @ptrCast(@alignCast(@constCast(window)));
        const size = w.getFramebufferSize();
        return .{ @intCast(@max(size[0], 0)), @intCast(@max(size[1], 0)) };
    }

    pub fn getX11Display() callconv(.c) *anyopaque {
        return @ptrCast(zglfw.getX11Display());
    }

    pub fn getX11Window(window: *const anyopaque) callconv(.c) u32 {
        const w: *zglfw.Window = @ptrCast(@alignCast(@constCast(window)));
        return zglfw.getX11Window(w);
    }

    pub fn getWaylandDisplay() callconv(.c) *anyopaque {
        return @ptrCast(zglfw.getWaylandDisplay());
    }

    pub fn getWaylandSurface(window: *const anyopaque) callconv(.c) *anyopaque {
        const w: *zglfw.Window = @ptrCast(@alignCast(@constCast(window)));
        return zglfw.getWaylandWindow(w) orelse unreachable;
    }
};

// ------------------------------------------------------------------------------------------------
// The view: a nested flex tree authored with `live.tree.Builder`
// ------------------------------------------------------------------------------------------------

const Revision = enum {
    first,
    second,
};

/// Renders the view into `t`. A pure function of `revision`: the same state produces the same tree,
/// which is what makes two revisions diffable *and* what keeps their ids lined up. `live.tree`'s ids
/// are creation order over an append-only node list, so a revision that only appends nodes and
/// rewrites attributes leaves every existing id exactly where it was - which is the property the
/// op path depends on, because every op addresses nodes by those ids.
///
/// The second revision changes four things, each chosen to land on a different arm of the op path:
///
///   * `sidebar`'s style - a **size** change (`width:220px` -> `width:180px`), one `attr` op;
///   * `card.side`'s `bg` - a **colour** change, one `attr` op;
///   * `brand`'s text - one `text` op;
///   * a `footer` element **appended** to `content`'s children - one `insert` op.
///
/// The footer is authored *last*, after every other element, even though it sits in the middle of
/// the document: a node created in the middle would renumber every id after it, and the whole point
/// of this revision is that the four ops address nodes the client already has.
fn renderView(t: *live.Tree, revision: Revision) !void {
    var b = live.Builder.init(t);
    defer b.deinit();

    const sidebar_style: []const u8 = switch (revision) {
        .first => "display:flex;flex-direction:column;width:220px;padding:12px;gap:10px",
        .second => "display:flex;flex-direction:column;width:180px;padding:12px;gap:10px",
    };
    const brand_text: []const u8 = switch (revision) {
        .first => "zurtr",
        .second => "zurtr / rev 2",
    };

    // <div id="root">      z-id 1   - the document, sized from the framebuffer
    try b.element("div", &.{
        .{ .name = "id", .value = "root" },
        .{ .name = "bg", .value = "#101318" },
        .{ .name = "style", .value = "display:flex;flex-direction:row;width:100%;height:100%;padding:16px;gap:16px" },
    }, 0);
    {
        // <div id="sidebar">   z-id 2
        try b.element("div", &.{
            .{ .name = "id", .value = "sidebar" },
            .{ .name = "bg", .value = "#182230" },
            .{ .name = "style", .value = sidebar_style },
        }, 0);
        {
            // <div id="brand">   z-id 3  with its text child at z-id 4
            try b.element("div", &.{
                .{ .name = "id", .value = "brand" },
                .{ .name = "bg", .value = "#4d84f0" },
                .{ .name = "style", .value = "height:56px" },
            }, 0);
            try b.text(brand_text);
            try b.close();

            // A keyed list, the way a rendered list of rows would be: the key is what lets a keyed
            // child that survives matching be relocated by a single `move` instead of a
            // remove+insert. These two never move in this example, so no `move` is derived - and a
            // revision that reordered them would have to author them in the new order, which
            // renumbers their ids (creation order) and is exactly why this example keeps the view
            // append-only.
            try b.element("div", &.{
                .{ .name = "id", .value = "nav.a" },
                .{ .name = "bg", .value = "#3d4a5c" },
                .{ .name = "style", .value = "height:40px" },
            }, 1);
            try b.close();
            try b.element("div", &.{
                .{ .name = "id", .value = "nav.b" },
                .{ .name = "bg", .value = "#3d4a5c" },
                .{ .name = "style", .value = "height:40px" },
            }, 2);
            try b.close();
        }
        try b.close();

        // <div id="content">   z-id 7
        try b.element("div", &.{
            .{ .name = "id", .value = "content" },
            .{ .name = "bg", .value = "#0d1015" },
            .{ .name = "style", .value = "display:flex;flex-direction:column;flex-grow:1;padding:16px;gap:12px" },
        }, 0);
        {
            // <div id="header">   z-id 8
            try b.element("div", &.{
                .{ .name = "id", .value = "header" },
                .{ .name = "bg", .value = "#232c3a" },
                .{ .name = "style", .value = "display:flex;flex-direction:row;align-items:center;height:64px;padding:8px;gap:8px" },
            }, 0);
            try b.element("div", &.{
                .{ .name = "id", .value = "title" },
                .{ .name = "bg", .value = "#6f9dfb" },
                .{ .name = "style", .value = "flex-grow:1;height:32px" },
            }, 0);
            try b.close();
            try b.element("div", &.{
                .{ .name = "id", .value = "action" },
                .{ .name = "bg", .value = "#f2a33c" },
                .{ .name = "style", .value = "width:96px;height:32px" },
            }, 0);
            try b.close();
            try b.close();

            // <div id="body">   z-id 11
            try b.element("div", &.{
                .{ .name = "id", .value = "body" },
                .{ .name = "bg", .value = "#131922" },
                .{ .name = "style", .value = "display:flex;flex-direction:row;flex-grow:1;gap:12px" },
            }, 0);
            {
                // <div id="card.main">   z-id 12 - grow weights 3:1 split the body's width
                try b.element("div", &.{
                    .{ .name = "id", .value = "card.main" },
                    .{ .name = "bg", .value = "#2e6f60" },
                    .{ .name = "style", .value = "display:flex;flex-direction:column;flex-grow:3;padding:12px;gap:10px" },
                }, 0);
                try b.element("div", &.{
                    .{ .name = "id", .value = "stat.a" },
                    .{ .name = "bg", .value = "#3d9880" },
                    .{ .name = "style", .value = "flex-grow:1" },
                }, 0);
                try b.close();
                try b.element("div", &.{
                    .{ .name = "id", .value = "stat.b" },
                    .{ .name = "bg", .value = "#4cb18f" },
                    .{ .name = "style", .value = "flex-grow:1" },
                }, 0);
                try b.close();
                try b.close();

                // <div id="card.side">   z-id 15 - the box the patch recolours
                try b.element("div", &.{
                    .{ .name = "id", .value = "card.side" },
                    .{ .name = "bg", .value = switch (revision) {
                        .first => "#854a87",
                        .second => "#c05a3e",
                    } },
                    .{ .name = "style", .value = "flex-grow:1;align-items:center;justify-content:center" },
                }, 0);
                try b.close();
            }
            try b.close();

            if (revision == .second) {
                // <div id="footer">   z-id 16 in revision 2 - created after every other element, so
                // no id in revision 2 differs from revision 1; it is content's third child, so the
                // diff sees it as an insert at index 2.
                try b.element("div", &.{
                    .{ .name = "id", .value = "footer" },
                    .{ .name = "bg", .value = "#22d3a7" },
                    .{ .name = "style", .value = "height:36px" },
                }, 0);
                try b.close();
            }
        }
        try b.close();
    }
    try b.close();
}

// ------------------------------------------------------------------------------------------------
// Styles: the attribute the view writes, mapped onto Yoga's setters
// ------------------------------------------------------------------------------------------------

/// A length that may be absent. `auto` has to be spelled out rather than folded into a null `f32`
/// because applying a style writes every property (`applyStyle`), so "no width" needs a setter call
/// of its own - `YGNodeStyleSetWidthAuto` - and not the absence of one.
const Dim = union(enum) { auto, px: f32, percent: f32 };

/// The subset of CSS this renderer implements. Every field has the value Yoga itself defaults to, so
/// a node whose `style` attribute says nothing about a property and a node whose style attribute
/// dropped that property end up identical.
///
/// The list is short on purpose: it is the mapping this example demonstrates, and `parseStyle` names
/// each member exactly once. Properties it does not know are ignored, the way a browser ignores a
/// declaration it does not understand.
const Style = struct {
    flex_direction: yoga.FlexDirection = .column,
    justify_content: yoga.Justify = .flex_start,
    align_items: yoga.Align = .stretch,
    width: Dim = .auto,
    height: Dim = .auto,
    flex_grow: f32 = 0,
    flex_shrink: f32 = 0,
    padding: f32 = 0,
    gap: f32 = 0,
};

/// Writes `style` into `node` - **every** property, every time.
///
/// Unconditional is the point. An `attr` op replaces a whole `style` attribute, so a property that
/// disappears from the string has to go back to Yoga's default, and there is no per-property diff to
/// get wrong if the only operation available is "write the whole style". This is also why the op
/// applier never has to know which properties moved: it re-parses and re-applies.
fn applyStyle(node: yoga.NodeRef, style: Style) void {
    yoga.YGNodeStyleSetFlexDirection(node, style.flex_direction);
    yoga.YGNodeStyleSetJustifyContent(node, style.justify_content);
    yoga.YGNodeStyleSetAlignItems(node, style.align_items);
    switch (style.width) {
        .auto => yoga.YGNodeStyleSetWidthAuto(node),
        .px => |v| yoga.YGNodeStyleSetWidth(node, v),
        .percent => |v| yoga.YGNodeStyleSetWidthPercent(node, v),
    }
    switch (style.height) {
        .auto => yoga.YGNodeStyleSetHeightAuto(node),
        .px => |v| yoga.YGNodeStyleSetHeight(node, v),
        .percent => |v| yoga.YGNodeStyleSetHeightPercent(node, v),
    }
    yoga.YGNodeStyleSetFlexGrow(node, style.flex_grow);
    yoga.YGNodeStyleSetFlexShrink(node, style.flex_shrink);
    yoga.YGNodeStyleSetPadding(node, .all, style.padding);
    yoga.YGNodeStyleSetGap(node, .all, style.gap);
}

fn parseLength(value: []const u8) ?f32 {
    const s = if (std.mem.endsWith(u8, value, "px")) value[0 .. value.len - 2] else value;
    return std.fmt.parseFloat(f32, std.mem.trim(u8, s, " \t")) catch null;
}

fn parseDim(value: []const u8) Dim {
    if (std.mem.eql(u8, value, "auto")) return .auto;
    if (std.mem.endsWith(u8, value, "%")) {
        const digits = std.mem.trim(u8, value[0 .. value.len - 1], " \t");
        const n = std.fmt.parseFloat(f32, digits) catch return .auto;
        return .{ .percent = n };
    }
    return .{ .px = parseLength(value) orelse return .auto };
}

fn parseStyle(text: []const u8) Style {
    var style: Style = .{};
    var declarations = std.mem.splitScalar(u8, text, ';');
    while (declarations.next()) |declaration| {
        const trimmed = std.mem.trim(u8, declaration, " \t");
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = std.mem.trim(u8, trimmed[0..colon], " \t");
        const value = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");

        if (std.mem.eql(u8, name, "display")) continue; // assumed flex; nothing to set
        if (std.mem.eql(u8, name, "flex-direction")) {
            if (std.mem.eql(u8, value, "row")) {
                style.flex_direction = .row;
            } else if (std.mem.eql(u8, value, "row-reverse")) {
                style.flex_direction = .row_reverse;
            } else if (std.mem.eql(u8, value, "column")) {
                style.flex_direction = .column;
            } else if (std.mem.eql(u8, value, "column-reverse")) {
                style.flex_direction = .column_reverse;
            }
        } else if (std.mem.eql(u8, name, "justify-content")) {
            if (std.mem.eql(u8, value, "flex-start")) {
                style.justify_content = .flex_start;
            } else if (std.mem.eql(u8, value, "center")) {
                style.justify_content = .center;
            } else if (std.mem.eql(u8, value, "flex-end")) {
                style.justify_content = .flex_end;
            } else if (std.mem.eql(u8, value, "space-between")) {
                style.justify_content = .space_between;
            } else if (std.mem.eql(u8, value, "space-around")) {
                style.justify_content = .space_around;
            } else if (std.mem.eql(u8, value, "space-evenly")) {
                style.justify_content = .space_evenly;
            }
        } else if (std.mem.eql(u8, name, "align-items")) {
            if (std.mem.eql(u8, value, "flex-start")) {
                style.align_items = .flex_start;
            } else if (std.mem.eql(u8, value, "center")) {
                style.align_items = .center;
            } else if (std.mem.eql(u8, value, "flex-end")) {
                style.align_items = .flex_end;
            } else if (std.mem.eql(u8, value, "stretch")) {
                style.align_items = .stretch;
            }
        } else if (std.mem.eql(u8, name, "width")) {
            style.width = parseDim(value);
        } else if (std.mem.eql(u8, name, "height")) {
            style.height = parseDim(value);
        } else if (std.mem.eql(u8, name, "flex-grow")) {
            style.flex_grow = std.fmt.parseFloat(f32, value) catch style.flex_grow;
        } else if (std.mem.eql(u8, name, "flex-shrink")) {
            style.flex_shrink = std.fmt.parseFloat(f32, value) catch style.flex_shrink;
        } else if (std.mem.eql(u8, name, "padding")) {
            style.padding = parseLength(value) orelse style.padding;
        } else if (std.mem.eql(u8, name, "gap")) {
            style.gap = parseLength(value) orelse style.gap;
        }
    }
    return style;
}

const background_default = [4]f32{ 0.06, 0.07, 0.09, 1 };

/// `#rrggbb`. The bytes go to the fragment stage as they were written: the swapchain is
/// `bgra8_unorm`, not an sRGB format, so there is no transfer function between the attribute and the
/// pixel.
fn parseColor(text: []const u8) ?[4]f32 {
    const s = std.mem.trim(u8, text, " \t");
    if (s.len != 7 or s[0] != '#') return null;
    const rgb = std.fmt.parseInt(u24, s[1..], 16) catch return null;
    return .{
        @as(f32, @floatFromInt((rgb >> 16) & 0xff)) / 255.0,
        @as(f32, @floatFromInt((rgb >> 8) & 0xff)) / 255.0,
        @as(f32, @floatFromInt(rgb & 0xff)) / 255.0,
        1.0,
    };
}

// ------------------------------------------------------------------------------------------------
// The client canvas: the tree's nodes, their Yoga nodes, and the op applier
// ------------------------------------------------------------------------------------------------

const Rect = struct {
    /// Pixels, from the window's top-left corner - the space the shader maps to clip space.
    left: f32 = 0,
    top: f32 = 0,
    width: f32 = 0,
    height: f32 = 0,
};

const CanvasNode = struct {
    /// The tree's `NodeId` for this node: its `z-id` in the markup, and the key every op addresses
    /// it by. Installing a node under a *new* id (from the next tree) is what an `insert` does.
    id: live.NodeId,
    kind: live.Kind,
    /// Element tag, or "" for text/fragment. Borrowed from the tree that installed the node.
    tag: []const u8 = "",
    /// The element's `id` attribute, for the print-out - not the tree's id. Borrowed.
    name: []const u8 = "",
    /// The element's `bg` attribute as written (borrowed), and the colour it parsed to.
    bg_text: []const u8 = "",
    bg: [4]f32 = background_default,
    /// The element's `style` attribute, parsed. Held parsed rather than as text so the applier has
    /// one representation to re-apply; `setAttr` re-parses on the way in.
    style: Style = .{},
    /// Content of a `text`/`raw` node. The `text` op writes here; nothing draws it (this example has
    /// no font engine), but the node is in the layout all the same.
    text: []const u8 = "",
    yoga_node: yoga.NodeRef,
    parent: ?*CanvasNode = null,
    /// Canvas children in document order, mirroring `yoga_node`'s children exactly: a node in this
    /// list at index i is Yoga's child i. Both lists are moved together, which is what makes an
    /// `insert`/`move` index a plain index here.
    children: std.ArrayList(*CanvasNode) = .empty,
    depth: u32 = 0,
    rect: Rect = .{},

    fn setAttr(self: *CanvasNode, name: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, name, "style")) {
            self.style = parseStyle(value);
        } else if (std.mem.eql(u8, name, "bg")) {
            self.bg = parseColor(value) orelse background_default;
            self.bg_text = value;
        } else if (std.mem.eql(u8, name, "id")) {
            self.name = value;
        }
        // Any other attribute (`class`, `data-`, a form field's `value`) is carried by the tree and
        // reaches this client, but nothing in this renderer reads it.
    }

    fn childIndex(self: *const CanvasNode) ?usize {
        const parent = self.parent orelse return null;
        return std.mem.indexOfScalar(*CanvasNode, parent.children.items, @constCast(self));
    }
};

const ApplySummary = struct { applied: u32 = 0, skipped: u32 = 0 };

const Canvas = struct {
    gpa: std.mem.Allocator,
    /// Every canvas node and child list lives here; freed as a unit at exit. Strings are *not* arena
    /// memory: they are borrowed from the trees, exactly as `live/patch.zig` specifies ("both trees
    /// must outlive the op list"), which is why the example keeps every revision's tree alive.
    arena: std.heap.ArenaAllocator,
    by_id: std.AutoHashMapUnmanaged(live.NodeId, *CanvasNode) = .empty,
    root: ?*CanvasNode = null,
    node_count: usize = 0,

    fn init(gpa: std.mem.Allocator) Canvas {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    fn deinit(self: *Canvas) void {
        self.by_id.deinit(self.gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Builds a canvas node for every node of `tree`'s subtree at `id`, in document order, hanging it
    /// off `parent` at child index `index` (the document root when `parent` is null).
    ///
    /// This is the "install the content verbatim" step in `live.md` §Patch ops: ids come from the
    /// tree being installed - the next tree for an `insert`/`replace`, the first revision at startup
    /// - so a client that installs an `insert` ends up holding the same ids the server's next
    /// revision uses.
    fn install(
        self: *Canvas,
        tree_: *const live.Tree,
        id: live.NodeId,
        parent: ?*CanvasNode,
        index: usize,
    ) !*CanvasNode {
        const source = tree_.node(id);
        const alloc = self.arena.allocator();
        const node = try alloc.create(CanvasNode);
        node.* = .{
            .id = id,
            .kind = source.kind,
            .tag = tree_.str(source.tag),
            .yoga_node = yoga.YGNodeNew(),
            .parent = parent,
            .depth = if (parent) |p| p.depth + 1 else 0,
        };
        switch (source.kind) {
            .text, .raw => node.text = tree_.str(source.text),
            .element => for (source.attrs) |attribute| {
                node.setAttr(tree_.str(attribute.name), tree_.str(attribute.value));
            },
            .fragment => {},
        }
        // `source.key` is the server's matching aid and is deliberately not copied: keys decide
        // *which* children the diff pairs up, and by the time an op reaches a client the pairing has
        // already happened - every op addresses an id.
        applyStyle(node.yoga_node, node.style);

        if (parent) |p| {
            const at = @min(index, p.children.items.len);
            try p.children.insert(alloc, at, node);
            yoga.YGNodeInsertChild(p.yoga_node, node.yoga_node, at);
        } else {
            self.root = node;
        }
        // The id is what the next patch's ops will address this node by, so installing the same id
        // twice would silently corrupt the map rather than misplace one node. It can only happen if
        // the server's render renumbered its nodes between revisions: `live.tree`'s ids are creation
        // order, so a view that inserts a node *in the middle* (rather than appending it) shifts
        // every id created after it, and the op that carries the new node would name an id an
        // existing node already holds. The revisions here append for exactly that reason.
        std.debug.assert(self.by_id.get(id) == null);
        try self.by_id.put(self.gpa, id, node);
        self.node_count += 1;

        for (source.children, 0..) |child, i| {
            _ = try self.install(tree_, child, node, i);
        }
        return node;
    }

    /// Applies a patch batch.
    ///
    /// The same switch as `assets/zurtr_live.js`'s `applyOp` - including the reading that decided
    /// `move`'s index ("k indexes the list without the moved element") - with Yoga nodes instead of
    /// DOM nodes. One place this applier is stricter than the browser bridge: it resolves an op whose
    /// parent is a `fragment`, which the JS client cannot (a fragment has no `z-id` to look up, so
    /// `q()` returns null and the op is counted as skipped). Every tree node has a canvas node here,
    /// so the index needs none of the inlining-and-offsetting that `live.md` describes.
    fn applyOps(self: *Canvas, next: *const live.Tree, ops: []const patch.Op) !ApplySummary {
        var summary: ApplySummary = .{};
        for (ops) |op| {
            switch (op) {
                .attr => |a| {
                    const node = self.by_id.get(a.id) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    node.setAttr(a.name, a.value orelse "");
                    applyStyle(node.yoga_node, node.style);
                    summary.applied += 1;
                },
                .text => |t| {
                    const node = self.by_id.get(t.id) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    node.text = t.value;
                    summary.applied += 1;
                },
                .insert => |ins| {
                    const parent = self.by_id.get(ins.parent) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    _ = try self.install(next, ins.new_id, parent, ins.index);
                    summary.applied += 1;
                },
                .replace => |r| {
                    const old = self.by_id.get(r.id) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    const parent = old.parent;
                    const at = old.childIndex() orelse 0;
                    self.detach(old);
                    self.forget(old);
                    yoga.YGNodeFreeRecursive(old.yoga_node);
                    _ = try self.install(next, r.new_id, parent, at);
                    summary.applied += 1;
                },
                .remove => |r| {
                    const node = self.by_id.get(r.id) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    self.detach(node);
                    self.forget(node);
                    yoga.YGNodeFreeRecursive(node.yoga_node);
                    summary.applied += 1;
                },
                .move => |m| {
                    const node = self.by_id.get(m.id) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    const parent = self.by_id.get(m.parent) orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    const from = node.childIndex() orelse {
                        summary.skipped += 1;
                        continue;
                    };
                    _ = parent.children.orderedRemove(from);
                    yoga.YGNodeRemoveChild(parent.yoga_node, node.yoga_node);
                    const to = @min(m.index, parent.children.items.len);
                    try parent.children.insert(self.arena.allocator(), to, node);
                    yoga.YGNodeInsertChild(parent.yoga_node, node.yoga_node, to);
                    summary.applied += 1;
                },
            }
        }
        return summary;
    }

    /// Takes `node` out of its parent's child list and out of Yoga's, leaving the node itself alive.
    fn detach(self: *Canvas, node: *CanvasNode) void {
        const parent = node.parent orelse {
            if (self.root == node) self.root = null;
            return;
        };
        const at = node.childIndex() orelse return;
        _ = parent.children.orderedRemove(at);
        yoga.YGNodeRemoveChild(parent.yoga_node, node.yoga_node);
    }

    /// Drops `node` and its canvas descendants from the id map. The Yoga subtree is freed separately,
    /// with one `YGNodeFreeRecursive` on the subtree's root - freeing each node here would free the
    /// same Yoga subtree once per canvas node.
    fn forget(self: *Canvas, node: *CanvasNode) void {
        _ = self.by_id.remove(node.id);
        self.node_count -= 1;
        for (node.children.items) |child| self.forget(child);
        node.children = .empty;
    }

    /// Lays the canvas out for `viewport` and records every node's absolute box.
    ///
    /// Yoga reports boxes relative to the parent, so one forward pass down the canvas - parents
    /// always before their children - carries the absolute origin.
    fn relayout(self: *Canvas, viewport: [2]f32) void {
        const root = self.root orelse return;
        // The document's size is style input like any other, and it comes from the framebuffer
        // rather than from a constant, so the whole layout is a function of the window.
        yoga.YGNodeStyleSetWidth(root.yoga_node, viewport[0]);
        yoga.YGNodeStyleSetHeight(root.yoga_node, viewport[1]);
        yoga.YGNodeCalculateLayout(root.yoga_node, viewport[0], viewport[1], .ltr);
        self.place(root, 0, 0);
    }

    fn place(self: *Canvas, node: *CanvasNode, origin_x: f32, origin_y: f32) void {
        node.rect = .{
            .left = origin_x + yoga.YGNodeLayoutGetLeft(node.yoga_node),
            .top = origin_y + yoga.YGNodeLayoutGetTop(node.yoga_node),
            .width = yoga.YGNodeLayoutGetWidth(node.yoga_node),
            .height = yoga.YGNodeLayoutGetHeight(node.yoga_node),
        };
        for (node.children.items) |child| {
            self.place(child, node.rect.left, node.rect.top);
        }
    }
};

// ------------------------------------------------------------------------------------------------
// Geometry: every laid-out box becomes two triangles
// ------------------------------------------------------------------------------------------------

const Vertex = extern struct {
    /// Pixels; the shader turns these into clip space with the viewport uniform. Keeping the buffer
    /// in Yoga's own coordinates is what lets the printed table and the drawn frame be the same
    /// numbers.
    position: [2]f32,
    color: [4]f32,
};

const vertices_per_box = 6;
/// Comfortably above what either revision paints (14 and 15 boxes); a revision that outgrew it would
/// be a bug in this example, not a reason to reallocate the GPU buffer every frame.
const max_painted_boxes = 32;

/// `_padding` keeps the uniform binding a multiple of 16 bytes, which is what WebGPU asks of uniform
/// data; the member is spelled the same in the shader.
const Uniforms = extern struct {
    viewport: [2]f32,
    _padding: [2]f32,
};

/// Fills `out` with two triangles per painted box, in tree order (parents before children, so a
/// child is painted over the container it sits in) and returns the vertex count.
///
/// Only `element` nodes paint. A `fragment` emits no markup and its canvas node has no box of its
/// own, and a `text` node has no font engine behind it here - both are laid out and both are
/// addressable by ops, which is what the canvas node per tree node buys, but neither is filled.
fn paint(canvas: *const Canvas, out: []Vertex) usize {
    var count: usize = 0;
    if (canvas.root) |root| paintNode(root, out, &count);
    return count;
}

fn paintNode(node: *const CanvasNode, out: []Vertex, count: *usize) void {
    if (node.kind == .element and node.rect.width > 0 and node.rect.height > 0) {
        const l = node.rect.left;
        const t = node.rect.top;
        const r = l + node.rect.width;
        const b = t + node.rect.height;
        const corners = [4][2]f32{ .{ l, t }, .{ r, t }, .{ l, b }, .{ r, b } };
        const order = [vertices_per_box]usize{ 0, 1, 2, 1, 3, 2 };
        for (order) |corner| {
            out[count.*] = .{ .position = corners[corner], .color = node.bg };
            count.* += 1;
        }
    }
    for (node.children.items) |child| paintNode(child, out, count);
}

/// Hash of the vertex data a frame is drawn from: two frames with the same hash draw the same
/// pixels, so comparing the hash across revisions is the machine-checkable form of "the window
/// changed", and comparing the *table* below is the human-readable one.
fn vertexHash(vertices: []const Vertex) u64 {
    return std.hash.Wyhash.hash(0x6c6976657a, std.mem.sliceAsBytes(vertices));
}

// ------------------------------------------------------------------------------------------------
// Print-out: the canvas as ids and boxes
// ------------------------------------------------------------------------------------------------

/// One row of the canvas print-out, kept so the state before a patch can be compared with the state
/// after it. Pointers into the canvas would be enough for a print-out; copies are what make the
/// before/after comparison possible once the canvas has moved.
const Row = struct {
    id: live.NodeId,
    kind: live.Kind,
    tag: []const u8,
    name: []const u8,
    bg_text: []const u8,
    text: []const u8,
    depth: u32,
    rect: Rect,
};

fn snapshot(canvas: *const Canvas, gpa: std.mem.Allocator, out: *std.ArrayList(Row)) !void {
    if (canvas.root) |root| try snapshotNode(root, out, gpa);
}

fn snapshotNode(node: *const CanvasNode, out: *std.ArrayList(Row), gpa: std.mem.Allocator) !void {
    try out.append(gpa, .{
        .id = node.id,
        .kind = node.kind,
        .tag = node.tag,
        .name = node.name,
        .bg_text = node.bg_text,
        .text = node.text,
        .depth = node.depth,
        .rect = node.rect,
    });
    for (node.children.items) |child| try snapshotNode(child, out, gpa);
}

const indent = "                                        ";

fn printRows(title: []const u8, rows: []const Row, viewport: [2]f32) void {
    std.debug.print("{s} - {d} nodes laid out for a {d:.0}x{d:.0} viewport\n", .{
        title,
        rows.len,
        viewport[0],
        viewport[1],
    });
    std.debug.print("  {s: >4}  {s: <30}{s: >9}{s: >9}{s: >9}{s: >9}  {s}\n", .{
        "z-id", "node", "left", "top", "width", "height", "bg / text",
    });
    for (rows) |row| {
        var label: [96]u8 = undefined;
        const kind_label: []const u8 = if (row.kind == .element) row.tag else @tagName(row.kind);
        const text = std.fmt.bufPrint(&label, "{s}<{s}>{s}{s}", .{
            if (row.depth * 2 <= indent.len) indent[0 .. row.depth * 2] else "",
            kind_label,
            if (row.name.len == 0) "" else " ",
            row.name,
        }) catch row.tag;
        // The last column is the element's background colour, or the content of a text node - which
        // is where the `text` op's effect shows up, since nothing here draws glyphs.
        var value_buf: [64]u8 = undefined;
        var value: []const u8 = "-";
        if (row.kind == .element) {
            if (row.bg_text.len != 0) value = row.bg_text;
        } else if (row.text.len != 0) {
            value = std.fmt.bufPrint(&value_buf, "\"{s}\"", .{row.text}) catch row.text;
        }
        std.debug.print("  {d: >4}  {s: <30}{d: >9.2}{d: >9.2}{d: >9.2}{d: >9.2}  {s}\n", .{
            row.id, text, row.rect.left, row.rect.top, row.rect.width, row.rect.height, value,
        });
    }
}

fn findRow(rows: []const Row, id: live.NodeId) ?Row {
    for (rows) |row| if (row.id == id) return row;
    return null;
}

/// What a row is called in the change report: the element's `id` attribute when it has one, else the
/// kind, since a `fragment` or a `text` node has no tag of its own to name.
fn rowLabel(row: Row) []const u8 {
    if (row.name.len != 0) return row.name;
    if (row.tag.len != 0) return row.tag;
    return @tagName(row.kind);
}

/// Prints what the patch changed, row by row. Ids are compared directly because the two revisions
/// keep them: an id that exists on both sides is the same node, one that exists only after is
/// inserted, one that exists only before is removed.
fn reportChanges(before: []const Row, after: []const Row) u32 {
    var changes: u32 = 0;
    for (after) |a| {
        const b = findRow(before, a.id) orelse {
            std.debug.print("  + z-id {d} ({s}) inserted: {d:.2},{d:.2} {d:.2}x{d:.2} {s}\n", .{
                a.id, rowLabel(a), a.rect.left, a.rect.top, a.rect.width, a.rect.height, a.bg_text,
            });
            changes += 1;
            continue;
        };
        if (!std.mem.eql(u8, b.text, a.text)) {
            std.debug.print("  ~ z-id {d} ({s}) text \"{s}\" -> \"{s}\"\n", .{ a.id, rowLabel(a), b.text, a.text });
            changes += 1;
        }
        if (!std.mem.eql(u8, b.bg_text, a.bg_text)) {
            std.debug.print("  ~ z-id {d} ({s}) bg {s} -> {s}\n", .{
                a.id, rowLabel(a), if (b.bg_text.len == 0) "-" else b.bg_text, a.bg_text,
            });
            changes += 1;
        }
        if (b.rect.left != a.rect.left or b.rect.top != a.rect.top or
            b.rect.width != a.rect.width or b.rect.height != a.rect.height)
        {
            std.debug.print("  ~ z-id {d} ({s}) box {d:.2},{d:.2} {d:.2}x{d:.2} -> {d:.2},{d:.2} {d:.2}x{d:.2}\n", .{
                a.id,         rowLabel(a),
                b.rect.left,  b.rect.top,
                b.rect.width, b.rect.height,
                a.rect.left,  a.rect.top,
                a.rect.width, a.rect.height,
            });
            changes += 1;
        }
    }
    for (before) |b| {
        if (findRow(after, b.id) == null) {
            std.debug.print("  - z-id {d} ({s}) removed\n", .{ b.id, rowLabel(b) });
            changes += 1;
        }
    }
    return changes;
}

// ------------------------------------------------------------------------------------------------
// Shaders
// ------------------------------------------------------------------------------------------------

/// `createRenderPipelineSimple` hard-codes `main` as the entry point for both stages - and takes the
/// two stages as separate modules, so one `main` in each is exactly what it wants.
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

/// `createRenderPipelineSimple` compiles WGSL asynchronously (`enable_async_shader_compilation` is on
/// inside zgpu), so the handle is filled in from the completion callback rather than returned. The
/// callback runs while the device is being ticked, and `pipeline` has to be passed *by pointer*: a
/// copy taken before the callback runs would read as nil forever.
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

fn currentViewport(window: *zglfw.Window) [2]f32 {
    const size = window.getFramebufferSize();
    return .{ @floatFromInt(@max(size[0], 0)), @floatFromInt(@max(size[1], 0)) };
}

// ------------------------------------------------------------------------------------------------
// main
// ------------------------------------------------------------------------------------------------

/// How long each revision stays on screen. The timer decides only *when* the patch is applied - what
/// changes between the two frames is the ops and nothing else: no colour cycle, no animated value.
const phase_seconds = 2.0;

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
    const window = try zglfw.createWindow(960, 600, "zurtr - live view, native", null, null);
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

    std.debug.print("livez-native: zurtr live tree -> Yoga -> zgpu, one process, no network\n", .{});
    std.debug.print("window: {s}; swapchain format {s}\n", .{
        if (on_wayland) "Wayland" else "X11",
        @tagName(zgpu.GraphicsContext.swapchain_format),
    });

    // --- the server: render revision 1 into a tree it keeps --------------------------------
    var first = live.Tree.init(gpa);
    defer first.deinit();
    try renderView(&first, .first);

    const html = try first.writeHtmlAlloc(gpa, first.rootId());
    defer gpa.free(html);
    std.debug.print("\n--- revision 1: the view the server authored ({d} nodes) ---\n", .{first.nodeCount()});
    std.debug.print("{s}\n", .{html});

    // --- the client: install it, one canvas node and one Yoga node per tree node -----------
    var canvas = Canvas.init(gpa);
    defer canvas.deinit();
    _ = try canvas.install(&first, first.rootId(), null, 0);

    var viewport = currentViewport(window);
    canvas.relayout(viewport);

    var vertices: [max_painted_boxes * vertices_per_box]Vertex = undefined;
    var vertex_count = paint(&canvas, &vertices);

    std.debug.print("\n--- canvas, installed from that tree ---\n", .{});
    std.debug.print("{d} canvas nodes, one Yoga node each: a canvas node's id is the tree's NodeId, the\n", .{canvas.node_count});
    std.debug.print("same number the markup carries as z-id, and the key every op addresses it by.\n", .{});
    std.debug.print("{d} painted boxes -> {d} vertices\n", .{ vertex_count / vertices_per_box, vertex_count });

    // --- GPU --------------------------------------------------------------------------------
    // One static vertex buffer holds every box of both revisions; only its contents change, and only
    // when a patch or a resize says so.
    const vertex_buffer = gctx.createBuffer(.{
        .label = "livez-native vertices",
        .usage = .{ .vertex = true, .copy_dst = true },
        .size = max_painted_boxes * vertices_per_box * @sizeOf(Vertex),
    });
    defer gctx.releaseResource(vertex_buffer);
    gctx.queue.writeBuffer(gctx.lookupResource(vertex_buffer).?, 0, Vertex, vertices[0..vertex_count]);

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

    std.debug.print("\npresenting revision 1 for {d:.1}s, then patching to revision 2\n", .{phase_seconds});

    // --- the loop ---------------------------------------------------------------------------
    var phase: Revision = .first;
    var phase_started = zglfw.getTime();
    var frames: [2]u64 = .{ 0, 0 };
    var ops: std.ArrayList(patch.Op) = .empty;
    defer ops.deinit(gpa);
    var second = live.Tree.init(gpa);
    defer second.deinit();
    var change_count_last: u32 = 0;

    while (!window.shouldClose()) {
        zglfw.pollEvents();

        const resized = currentViewport(window);
        if (resized[0] == 0 or resized[1] == 0) continue; // Minimised: nothing to lay out or draw.
        if (resized[0] != viewport[0] or resized[1] != viewport[1]) {
            viewport = resized;
            canvas.relayout(viewport);
            vertex_count = paint(&canvas, &vertices);
            gctx.queue.writeBuffer(gctx.lookupResource(vertex_buffer).?, 0, Vertex, vertices[0..vertex_count]);
            std.debug.print("window is now {d:.0}x{d:.0}: relaid out, {d} vertices rewritten\n", .{
                viewport[0], viewport[1], vertex_count,
            });
        }

        // The frame's viewport, which is everything the shader needs to place Yoga's pixel-space
        // vertices - the vertex data itself stays as Yoga computed it.
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
        pass.draw(@intCast(vertex_count), 1, 0, 0);
        zgpu.endReleasePass(pass);

        gctx.submit(&.{encoder.finish(null)});
        _ = gctx.present();

        frames[@backingInt(phase)] += 1;
        const now = zglfw.getTime();
        if (now - phase_started < phase_seconds) continue;

        switch (phase) {
            .first => {
                // --- the state the ops are about to be applied to -------------------------------
                // Snapshot here rather than at startup: the framebuffer is not necessarily the size
                // the window was created with by the time the first frame is drawn (a Wayland
                // compositor sends its configure afterwards - the resize line above is that
                // happening). Taking both tables at the same viewport is what makes them comparable:
                // every difference printed below is attributable to an op and not to the window
                // changing size underneath them.
                var rows_first: std.ArrayList(Row) = .empty;
                defer rows_first.deinit(gpa);
                try snapshot(&canvas, gpa, &rows_first);
                const hash_first = vertexHash(vertices[0..vertex_count]);
                std.debug.print("\n--- {d} frames of revision 1 presented (t={d:.2}s) ---\n", .{ frames[0], now });
                printRows("revision 1: the canvas as drawn", rows_first.items, viewport);
                std.debug.print("  {d} vertices ({d} painted boxes) -> {d} triangles, vertex hash 0x{x}\n", .{
                    vertex_count, vertex_count / vertices_per_box, vertex_count / 3, hash_first,
                });

                // --- the second render, and the patch derived from it --------------------------
                std.debug.print("\nre-rendering the same view with four changes, and diffing it against revision 1\n", .{});
                try renderView(&second, .second);
                try patch.diff(gpa, &first, &second, &ops);
                const ops_json = try patch.writeJsonAlloc(gpa, &second, ops.items);
                defer gpa.free(ops_json);
                std.debug.print("patch.diff(revision 1, revision 2) derived {d} ops:\n{s}\n", .{
                    ops.items.len, ops_json,
                });

                const summary = try canvas.applyOps(&second, ops.items);
                std.debug.print("client applied {d} ops, skipped {d}\n", .{
                    summary.applied, summary.skipped,
                });

                canvas.relayout(viewport);
                vertex_count = paint(&canvas, &vertices);
                gctx.queue.writeBuffer(gctx.lookupResource(vertex_buffer).?, 0, Vertex, vertices[0..vertex_count]);

                var rows_second: std.ArrayList(Row) = .empty;
                defer rows_second.deinit(gpa);
                try snapshot(&canvas, gpa, &rows_second);
                const hash_second = vertexHash(vertices[0..vertex_count]);

                std.debug.print("\n--- canvas after the patch (nothing else touched it) ---\n", .{});
                printRows("revision 2: the same canvas, mutated only by those ops", rows_second.items, viewport);
                std.debug.print("  {d} vertices ({d} painted boxes) -> {d} triangles, vertex hash 0x{x}\n", .{
                    vertex_count, vertex_count / vertices_per_box, vertex_count / 3, hash_second,
                });

                const change_count = reportChanges(rows_first.items, rows_second.items);
                std.debug.print("\n{d} canvas rows differ; the two frames' vertex data differs: {s}\n", .{
                    change_count,
                    if (hash_first != hash_second) "yes - the second frame is drawn from op-applied state" else "NO",
                });
                change_count_last = change_count;

                phase = .second;
                phase_started = now;
            },
            .second => {
                std.debug.print("\n{d} frames of revision 2 presented; exiting with both revisions exercised\n", .{frames[1]});
                std.debug.print("frames: {d} revision 1, {d} revision 2; {d} ops applied, {d} canvas rows changed\n", .{
                    frames[0], frames[1], ops.items.len, change_count_last,
                });
                break;
            },
        }
    }
}
