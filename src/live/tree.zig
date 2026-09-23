//! Live UI render representation.
//!
//! One tree type serves both the initial HTML render and every later patch:
//! the server renders a view into a `Tree` with a `Builder`, ships the HTML of
//! the root (which carries `data-z="<id>"` on every element), keeps the tree,
//! and diffs the next render against it (`patch.zig`).
//!
//! Invariants:
//!
//! * Every node has an id equal to its index in the tree's node list, so
//!   `node(id).id == id`. Ids are the patch addressing scheme and are stable
//!   for as long as the tree lives.
//! * Every `element` emits `data-z="<its own id>"` in addition to its user
//!   attributes; `fragment` emits only its children and never a `data-z`;
//!   `raw` emits its bytes verbatim; `text` emits escaped text.
//! * Strings are interned per tree; the empty string is id 0 and is never
//!   stored. All tree memory (nodes, string bytes, children/attr slices, the
//!   interning index) lives in one arena freed as a unit by `Tree.deinit`.
//! * Serialization is deterministic: the same tree always produces the same
//!   bytes.
//!
//! `raw` nodes are client-owned DOM regions: they render verbatim and are
//! never patched into (`patch.zig` treats a matched `raw` node as opaque).

const std = @import("std");

/// Interned string handle. `0` is the empty string.
pub const StrId = u32;
/// Node handle, equal to the node's index in the tree. `0` is the root of a
/// `Builder`-built tree.
pub const NodeId = u32;

/// The empty string.
pub const empty_str: StrId = 0;

pub const Attr = struct { name: StrId, value: StrId };

/// Attribute as supplied by render code: `null` value means "omit this
/// attribute entirely".
pub const AttrSpec = struct { name: []const u8, value: ?[]const u8 };

pub const Kind = enum { element, text, raw, fragment };

pub const Node = struct {
    kind: Kind,
    /// Assigned by `Tree.addNode`; equals the node's index in the tree.
    id: NodeId,
    /// `element`: the tag name. Other kinds: `empty_str`.
    tag: StrId = 0,
    /// `text`/`raw`: the node's content. Other kinds: `empty_str`.
    text: StrId = 0,
    /// `element`: user attributes, in render order.
    attrs: []const Attr = &.{},
    /// `element`/`fragment`: child node ids, in render order.
    children: []const NodeId = &.{},
    /// Identity for list children: `0` means "keyless". Keyed children match
    /// across positions when diffing; keyless children match positionally.
    key: u32 = 0,
};

/// Tags rendered without a closing tag. A void element's children (illegal in
/// HTML, and never produced by well-formed render code) are still emitted so
/// that the markup stays a faithful serialization of the tree; the element
/// simply has no closing tag.
pub fn isVoidTag(tag: []const u8) bool {
    for (void_tags) |candidate| {
        if (std.mem.eql(u8, candidate, tag)) return true;
    }
    return false;
}

const void_tags = [_][]const u8{
    "area",  "base", "br",   "col",   "embed",  "hr",    "img",
    "input", "link", "meta", "param", "source", "track", "wbr",
};

/// A render tree. All memory comes from the tree's arena; `deinit` releases
/// everything at once.
pub const Tree = struct {
    arena: std.heap.ArenaAllocator,
    /// Interned strings; index `id - 1` holds the bytes of `id`. The empty
    /// string is implicit.
    strings: std.ArrayList([]const u8) = .empty,
    /// String bytes -> `StrId`.
    interned: std.StringHashMapUnmanaged(StrId) = .empty,
    /// Nodes; a node's index is its `NodeId`.
    nodes: std.ArrayList(Node) = .empty,

    pub fn init(gpa: std.mem.Allocator) Tree {
        return .{ .arena = .init(gpa) };
    }

    /// Releases every allocation made by this tree.
    pub fn deinit(self: *Tree) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn nodeCount(self: *const Tree) usize {
        return self.nodes.items.len;
    }

    /// The root node id. `Builder`-built trees always have their root at id 0.
    /// Asserts the tree is not empty.
    pub fn rootId(self: *const Tree) NodeId {
        std.debug.assert(self.nodes.items.len != 0);
        return 0;
    }

    /// Interns `s` and returns its id. Repeats return the same id.
    ///
    /// Infallible by contract: on allocation failure this panics rather than
    /// handing back an id that does not denote `s`. Callers that can report
    /// errors should use `internOrError`.
    pub fn intern(self: *Tree, s: []const u8) StrId {
        return self.internOrError(s) catch
            @panic("zurtr.live.tree: out of memory while interning");
    }

    /// Fallible form of `intern`. Additive helper.
    pub fn internOrError(self: *Tree, s: []const u8) std.mem.Allocator.Error!StrId {
        if (s.len == 0) return empty_str;
        if (self.interned.get(s)) |id| return id;
        const alloc = self.arena.allocator();
        const owned = try alloc.dupe(u8, s);
        const id: StrId = @intCast(self.strings.items.len + 1);
        try self.strings.append(alloc, owned);
        try self.interned.put(alloc, owned, id);
        return id;
    }

    /// The bytes of `id`. The result points into the tree and lives as long as
    /// it does.
    pub fn str(self: *const Tree, id: StrId) []const u8 {
        if (id == empty_str) return "";
        std.debug.assert(id <= self.strings.items.len);
        return self.strings.items[id - 1];
    }

    /// Appends `node`, assigning `node.id`. `node.attrs` and `node.children`
    /// are stored as given; they must stay valid for as long as the tree does
    /// (the `Builder` allocates them from the tree's arena).
    pub fn addNode(self: *Tree, new_node: Node) !NodeId {
        const id: NodeId = @intCast(self.nodes.items.len);
        var n = new_node;
        n.id = id;
        try self.nodes.append(self.arena.allocator(), n);
        return id;
    }

    pub fn node(self: *const Tree, id: NodeId) *const Node {
        std.debug.assert(id < self.nodes.items.len);
        return &self.nodes.items[id];
    }

    /// Writes the HTML of the `root` subtree.
    pub fn writeHtml(self: *const Tree, w: *std.Io.Writer, root: NodeId) std.Io.Writer.Error!void {
        try self.writeNodeHtml(w, root);
    }

    /// Convenience wrapper: renders `root` into a freshly allocated buffer the
    /// caller owns.
    pub fn writeHtmlAlloc(self: *const Tree, gpa: std.mem.Allocator, root: NodeId) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        errdefer aw.deinit();
        try self.writeHtml(&aw.writer, root);
        return try aw.toOwnedSlice();
    }

    fn writeNodeHtml(self: *const Tree, w: *std.Io.Writer, id: NodeId) std.Io.Writer.Error!void {
        const n = self.node(id);
        switch (n.kind) {
            .element => {
                const tag = self.str(n.tag);
                try w.writeByte('<');
                try w.writeAll(tag);
                for (n.attrs) |a| {
                    try w.writeByte(' ');
                    try w.writeAll(self.str(a.name));
                    try w.writeAll("=\"");
                    try writeAttrEscaped(w, self.str(a.value));
                    try w.writeByte('"');
                }
                try w.writeAll(" data-z=\"");
                try w.print("{d}", .{n.id});
                try w.writeByte('"');
                try w.writeByte('>');
                if (isVoidTag(tag)) return;
                for (n.children) |child| try self.writeNodeHtml(w, child);
                try w.writeAll("</");
                try w.writeAll(tag);
                try w.writeByte('>');
            },
            .text => try writeTextEscaped(w, self.str(n.text)),
            .raw => try w.writeAll(self.str(n.text)),
            .fragment => for (n.children) |child| try self.writeNodeHtml(w, child),
        }
    }
};

fn writeTextEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        else => try w.writeByte(c),
    };
}

fn writeAttrEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '"' => try w.writeAll("&quot;"),
        else => try w.writeByte(c),
    };
}

/// Incremental tree builder.
///
/// `init` creates the root fragment (node 0), so `root()` is always valid and
/// the tree always renders. `element`/`fragment` open a node that the next
/// `close` closes; `text`/`raw` append leaves to the innermost open node.
/// Nodes left open when `deinit` runs are closed implicitly, so a forgotten
/// `close` cannot silently drop children.
pub const Builder = struct {
    tree: *Tree,
    root_id: NodeId,
    stack: std.ArrayList(Frame) = .empty,

    const Frame = struct {
        id: NodeId,
        children: std.ArrayList(NodeId) = .empty,
    };

    /// Opens a builder on `tree`, adding the root fragment node.
    /// Panics on allocation failure (the tree arena could not serve its first
    /// node); the builder API itself is infallible at this point by contract.
    pub fn init(tree: *Tree) Builder {
        const id = tree.addNode(.{ .kind = .fragment, .id = 0 }) catch
            @panic("zurtr.live.tree: out of memory creating the root node");
        var b: Builder = .{ .tree = tree, .root_id = id };
        b.stack.append(tree.arena.allocator(), .{ .id = id }) catch
            @panic("zurtr.live.tree: out of memory opening the root frame");
        return b;
    }

    /// Closes every still-open node and drops the builder's bookkeeping. Tree
    /// memory is owned by the tree's arena, not by the builder.
    pub fn deinit(self: *Builder) void {
        while (self.stack.items.len != 0) self.closeFrame();
        self.* = undefined;
    }

    pub fn root(self: *const Builder) NodeId {
        return self.root_id;
    }

    /// Opens an `element` node with the given tag, attributes and key.
    /// `AttrSpec.value == null` omits the attribute.
    pub fn element(self: *Builder, tag: []const u8, attrs: []const AttrSpec, key: u32) !void {
        const alloc = self.tree.arena.allocator();
        const tag_id = try self.tree.internOrError(tag);
        var kept: std.ArrayList(Attr) = .empty;
        for (attrs) |spec| {
            const value = spec.value orelse continue;
            try kept.append(alloc, .{
                .name = try self.tree.internOrError(spec.name),
                .value = try self.tree.internOrError(value),
            });
        }
        const node_attrs: []const Attr = if (kept.items.len == 0) &.{} else kept.items;
        try self.open(.{ .kind = .element, .id = 0, .tag = tag_id, .attrs = node_attrs, .key = key });
    }

    /// Opens a `fragment` node: a container with identity for diffing that
    /// renders only its children.
    pub fn fragment(self: *Builder, key: u32) !void {
        try self.open(.{ .kind = .fragment, .id = 0, .key = key });
    }

    /// Closes the innermost open node.
    pub fn close(self: *Builder) !void {
        if (self.stack.items.len == 0) return error.NotOpen;
        self.closeFrame();
    }

    /// Appends an escaped text node to the innermost open node.
    pub fn text(self: *Builder, s: []const u8) !void {
        try self.leaf(.text, s);
    }

    /// Appends a client-owned region rendered verbatim; never patched into.
    pub fn raw(self: *Builder, s: []const u8) !void {
        try self.leaf(.raw, s);
    }

    fn leaf(self: *Builder, kind: Kind, s: []const u8) !void {
        const id = try self.tree.addNode(.{
            .kind = kind,
            .id = 0,
            .text = try self.tree.internOrError(s),
        });
        try self.attach(id);
    }

    fn open(self: *Builder, node: Node) !void {
        const id = try self.tree.addNode(node);
        try self.attach(id);
        try self.stack.append(self.tree.arena.allocator(), .{ .id = id });
    }

    fn attach(self: *Builder, id: NodeId) !void {
        if (self.stack.items.len == 0) return error.NotOpen;
        // Keep the containing node's `children` slice current as children are
        // attached, so a node never goes stale because a `close` was forgotten
        // (the root in particular is only closed by `deinit`).
        const frame = &self.stack.items[self.stack.items.len - 1];
        try frame.children.append(self.tree.arena.allocator(), id);
        self.tree.nodes.items[frame.id].children = frame.children.items;
    }

    fn closeFrame(self: *Builder) void {
        const frame = self.stack.pop().?;
        self.tree.nodes.items[frame.id].children = frame.children.items;
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn render(gpa: std.mem.Allocator, t: *const Tree, root: NodeId) ![]u8 {
    return t.writeHtmlAlloc(gpa, root);
}

test "html: golden element, text escaping and data-z ids" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);
    defer b.deinit();

    try b.element("div", &.{.{ .name = "class", .value = "box" }}, 0);
    try b.text("hi & <bye>");
    try b.close();

    try testing.expectEqual(@as(NodeId, 0), b.root());
    try testing.expect(t.node(b.root()).kind == .fragment);

    const html = try render(testing.allocator, &t, b.root());
    defer testing.allocator.free(html);
    try testing.expectEqualStrings("<div class=\"box\" data-z=\"1\">hi &amp; &lt;bye&gt;</div>", html);
}

test "html: attribute escaping, omitted attributes and ordering" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);

    try b.element("a", &.{
        .{ .name = "href", .value = "/x?a=1&b=2" },
        .{ .name = "title", .value = "a\"b<c>d" },
        .{ .name = "hidden", .value = null },
        .{ .name = "data-n", .value = "3" },
    }, 0);
    try b.close();

    const html = try render(testing.allocator, &t, b.root());
    defer testing.allocator.free(html);
    try testing.expectEqualStrings(
        "<a href=\"/x?a=1&amp;b=2\" title=\"a&quot;b&lt;c>d\" data-n=\"3\" data-z=\"1\"></a>",
        html,
    );
}

test "html: void elements emit no closing tag" {
    try testing.expect(isVoidTag("br"));
    try testing.expect(isVoidTag("wbr"));
    try testing.expect(!isVoidTag("div"));
    try testing.expect(!isVoidTag(""));

    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);

    try b.element("img", &.{.{ .name = "src", .value = "a.png" }}, 0);
    try b.close();
    try b.element("br", &.{}, 0);
    try b.close();
    try b.element("div", &.{}, 0);
    try b.close();

    const html = try render(testing.allocator, &t, b.root());
    defer testing.allocator.free(html);
    try testing.expectEqualStrings(
        "<img src=\"a.png\" data-z=\"1\"><br data-z=\"2\"><div data-z=\"3\"></div>",
        html,
    );
}

test "html: raw passes through verbatim, fragment has no wrapper" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);

    try b.raw("<b>x</b>&amp;");
    try b.fragment(7);
    try b.text("t<");
    try b.element("span", &.{}, 0);
    try b.text("s");
    try b.close();
    try b.close();

    const html = try render(testing.allocator, &t, b.root());
    defer testing.allocator.free(html);
    try testing.expectEqualStrings("<b>x</b>&amp;t&lt;<span data-z=\"4\">s</span>", html);

    // The fragment is a node with identity, but contributes no markup and no id.
    const frag = t.node(2);
    try testing.expect(frag.kind == .fragment);
    try testing.expectEqual(@as(u32, 7), frag.key);
    try testing.expectEqualStrings("", t.str(frag.tag));
}

test "html: ids are assigned in creation order and serialize deterministically" {
    var a = Tree.init(testing.allocator);
    defer a.deinit();
    var b1 = Builder.init(&a);
    var b = Tree.init(testing.allocator);
    defer b.deinit();
    var b2 = Builder.init(&b);

    for ([_]*Builder{ &b1, &b2 }) |builder| {
        try builder.element("ul", &.{}, 0);
        try builder.element("li", &.{}, 1);
        try builder.text("one");
        try builder.close();
        try builder.element("li", &.{}, 2);
        try builder.text("two");
        try builder.close();
        try builder.close();
    }

    const html_a = try render(testing.allocator, &a, b1.root());
    defer testing.allocator.free(html_a);
    const html_b = try render(testing.allocator, &b, b2.root());
    defer testing.allocator.free(html_b);
    try testing.expectEqualStrings(html_a, html_b);
    try testing.expectEqualStrings(
        "<ul data-z=\"1\"><li data-z=\"2\">one</li><li data-z=\"4\">two</li></ul>",
        html_a,
    );

    for (a.nodes.items, 0..) |n, i| try testing.expectEqual(@as(NodeId, @intCast(i)), n.id);
}

test "intern: dedupes, round-trips, rejects nothing" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();

    const a = t.intern("hello");
    const b = t.intern("hello");
    try testing.expectEqual(a, b);
    try testing.expectEqual(empty_str, t.intern(""));
    try testing.expectEqualStrings("", t.str(empty_str));
    try testing.expectEqualStrings("hello", t.str(a));

    const c = try t.internOrError("hello");
    try testing.expectEqual(a, c);
    try testing.expect(t.str(a).ptr != "hello".ptr);
}

test "builder: unclosed nodes are closed by deinit; stray close is an error" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);

    const root = b.root();
    try b.element("div", &.{}, 0);
    try b.text("x");
    const div = root + 1;
    b.deinit();

    try testing.expectEqualSlices(NodeId, &.{div}, t.node(root).children);
    try testing.expectEqualSlices(NodeId, &.{t.node(div).id + 1}, t.node(div).children);

    const html = try render(testing.allocator, &t, 0);
    defer testing.allocator.free(html);
    try testing.expectEqualStrings("<div data-z=\"1\">x</div>", html);
}

test "builder: element after the root is closed is an error" {
    var t = Tree.init(testing.allocator);
    defer t.deinit();
    var b = Builder.init(&t);

    try b.close();
    try testing.expectError(error.NotOpen, b.element("div", &.{}, 0));
    try testing.expectError(error.NotOpen, b.text("x"));
    try testing.expectError(error.NotOpen, b.raw("x"));
    try testing.expectError(error.NotOpen, b.fragment(0));
    try testing.expectError(error.NotOpen, b.close());
    b.deinit();
}
