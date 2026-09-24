//! Live UI patch generation: structural diff of two render trees, plus the
//! JSON wire encoding of the resulting ops.
//!
//! # Coordinate spaces
//!
//! Every op addresses nodes in the **previous** (currently rendered) tree —
//! `Op.replace.id`, `Op.insert.parent`, `Op.move.parent`, `Op.remove.id` — while
//! anything that brings in new markup (`Op.replace.new_id`, `Op.insert.new_id`)
//! refers to the **next** tree, whose HTML the client installs verbatim. String
//! values (`Op.text.value`, `Op.attr.name`, `Op.attr.value`) are raw strings and
//! point into whichever tree owns them; both trees must outlive the op list.
//!
//! `index` on `Op.insert` and `Op.move` is a position in the **final** child
//! list of the parent: 0 is "first child", `child_count` (from `next`) is
//! "append". Clients apply ops in order with remove-then-insert semantics.
//!
//! A parent is the matched node itself, so a matched `fragment` is named by its
//! own id even though it emits no markup of its own: a client resolves a
//! fragment parent by inlining its children into the nearest rendered ancestor
//! and offsetting the index into that ancestor's child list. The same applies
//! to a fragment appearing as a target (`replace`/`remove`/`move`): it denotes
//! the rendered run of its children, which the client expands in place.
//!
//! # Matching rules
//!
//! * Nodes match on (kind, tag). Keys decide *which* children are candidates:
//!   keyed children match across positions by key (the n-th child with key `k`
//!   on one side matches the n-th child with key `k` on the other side), and
//!   the remaining keyless children match positionally by rank within each
//!   side's keyless subsequence.
//! * The root is always matched when (kind, tag) agree.
//! * A candidate pair whose (kind, tag) disagree is a `replace` when it keeps
//!   its position, otherwise `remove` + `insert`.
//! * Unmatched previous children are `remove`d; unmatched next children are
//!   `insert`ed.
//! * Identical trees produce zero ops; `raw` nodes are opaque and are never
//!   patched into once matched.
//!
//! # Move policy
//!
//! A keyed child that survives matching but must change position under the same
//! parent is emitted as a single `move`. The implementation simulates the
//! client's child list while walking the next children in document order, so a
//! move is emitted only when the target index is to the left of the node's
//! current position — the case where both plausible client semantics ("remove
//! then insert at index" and "insert before the child currently at index")
//! agree. Anything it cannot express that way (a displaced *keyless* child, or
//! a displaced child whose (kind, tag) also changed) falls back to
//! `remove` + `insert`, which is always correct. A keyed reorder therefore
//! costs one op per displaced child, never a whole-list replace.
//!
//! Matching is allocation-free: `diff` allocates nothing beyond appends to the
//! caller's `out` list, and every child list is reconciled with a handful of
//! linear scans -- O(n^2) work per parent, where `n` is its child count.

const std = @import("std");
const tree = @import("tree.zig");

pub const NodeId = tree.NodeId;
pub const StrId = tree.StrId;

/// The only thing `diff` can fail on: growing the caller's op list.
pub const DiffError = std.mem.Allocator.Error;

pub const Op = union(enum) {
    /// Matched text node whose content changed. `id` is a node in the previous
    /// tree; `value` is the new text (a string in `next`).
    text: struct { id: NodeId, value: []const u8 },
    /// Changed or added attribute (`value` non-null), or removed attribute
    /// (`value` null).
    attr: struct { id: NodeId, name: []const u8, value: ?[]const u8 },
    /// The subtree at `id` (previous tree) is replaced by the subtree at
    /// `new_id` (next tree).
    replace: struct { id: NodeId, new_id: NodeId },
    /// The subtree at `new_id` (next tree) is inserted as child `index` of
    /// `parent` (previous tree).
    insert: struct { parent: NodeId, index: u32, new_id: NodeId },
    /// The subtree at `id` (previous tree) is removed.
    remove: struct { id: NodeId },
    /// The subtree at `id` (previous tree) becomes child `index` of `parent`
    /// (previous tree), which it already belongs to.
    move: struct { id: NodeId, parent: NodeId, index: u32 },
};

/// Appends the ops that turn `prev` into `next`.
///
/// `prev.nodes` and `next.nodes` describe the same session revision pair: both
/// trees are rooted at `rootId()`. Either tree being empty means there is
/// nothing to diff (no ops). Appends to `out`; nothing else is allocated.
pub fn diff(
    gpa: std.mem.Allocator,
    prev: *const tree.Tree,
    next: *const tree.Tree,
    out: *std.ArrayList(Op),
) !void {
    if (prev.nodeCount() == 0 or next.nodeCount() == 0) return;
    const prev_root = prev.rootId();
    const next_root = next.rootId();
    if (!sameShape(prev, prev.node(prev_root), next, next.node(next_root))) {
        try out.append(gpa, .{ .replace = .{ .id = prev_root, .new_id = next_root } });
        return;
    }
    try diffNode(gpa, prev, next, prev_root, next_root, out);
}

fn diffNode(
    gpa: std.mem.Allocator,
    prev: *const tree.Tree,
    next: *const tree.Tree,
    prev_id: NodeId,
    next_id: NodeId,
    out: *std.ArrayList(Op),
) DiffError!void {
    const p = prev.node(prev_id);
    const n = next.node(next_id);
    std.debug.assert(p.kind == n.kind);
    switch (p.kind) {
        .element => {
            try diffAttrs(gpa, prev, next, prev_id, p.attrs, n.attrs, out);
            try diffChildren(gpa, prev, next, prev_id, next_id, out);
        },
        .fragment => try diffChildren(gpa, prev, next, prev_id, next_id, out),
        .text => {
            if (!strEq(prev, p.text, next, n.text)) {
                try out.append(gpa, .{ .text = .{ .id = prev_id, .value = next.str(n.text) } });
            }
        },
        // Client-owned region: once matched, a raw node is opaque.
        .raw => {},
    }
}

fn diffAttrs(
    gpa: std.mem.Allocator,
    prev: *const tree.Tree,
    next: *const tree.Tree,
    id: NodeId,
    prev_attrs: []const tree.Attr,
    next_attrs: []const tree.Attr,
    out: *std.ArrayList(Op),
) DiffError!void {
    for (prev_attrs) |pa| {
        const name = prev.str(pa.name);
        const new_value = findAttr(next, next_attrs, name) orelse {
            try out.append(gpa, .{ .attr = .{ .id = id, .name = name, .value = null } });
            continue;
        };
        const value = next.str(new_value);
        if (!std.mem.eql(u8, prev.str(pa.value), value)) {
            try out.append(gpa, .{ .attr = .{ .id = id, .name = name, .value = value } });
        }
    }
    for (next_attrs) |na| {
        const name = next.str(na.name);
        if (findAttr(prev, prev_attrs, name) == null) {
            try out.append(gpa, .{ .attr = .{ .id = id, .name = name, .value = next.str(na.value) } });
        }
    }
}

fn findAttr(t: *const tree.Tree, attrs: []const tree.Attr, name: []const u8) ?StrId {
    for (attrs) |a| {
        if (std.mem.eql(u8, t.str(a.name), name)) return a.value;
    }
    return null;
}

fn diffChildren(
    gpa: std.mem.Allocator,
    prev: *const tree.Tree,
    next: *const tree.Tree,
    prev_parent: NodeId,
    next_parent: NodeId,
    out: *std.ArrayList(Op),
) DiffError!void {
    const pchildren = prev.node(prev_parent).children;
    const nchildren = next.node(next_parent).children;
    if (pchildren.len == 0 and nchildren.len == 0) return;

    // Removals first: they are position independent, and taking them out
    // up front is the child list the placement pass below simulates.
    for (pchildren, 0..) |pid, i| {
        if (matchedNextIndex(prev, pchildren, next, nchildren, @intCast(i)) == null) {
            try out.append(gpa, .{ .remove = .{ .id = pid } });
        }
    }

    // Placement pass: walk the next children in document order, maintaining the
    // invariant "the children for next indices < i are already in final
    // position". The children for next indices >= i are exactly the matched
    // previous children that nothing has placed yet, still in previous order,
    // so the head of that tail (`front`) is the child that is already at index
    // `i` -- and every other candidate has to be relocated there.
    var front: u32 = 0;
    advanceFront(prev, pchildren, next, nchildren, &front);
    var i: u32 = 0;
    while (i < nchildren.len) : (i += 1) {
        const nid = nchildren[i];
        const n_node = next.node(nid);
        const pidx = matchedPrevIndex(prev, pchildren, next, nchildren, i) orelse {
            try out.append(gpa, .{ .insert = .{ .parent = prev_parent, .index = i, .new_id = nid } });
            continue;
        };
        const pid = pchildren[pidx];
        const p_node = prev.node(pid);
        const shape_matches = sameShape(prev, p_node, next, n_node);

        if (pidx == front) {
            if (shape_matches) {
                try diffNode(gpa, prev, next, pid, nid, out);
            } else {
                try out.append(gpa, .{ .replace = .{ .id = pid, .new_id = nid } });
            }
            front = pidx + 1;
            advanceFront(prev, pchildren, next, nchildren, &front);
        } else if (shape_matches and p_node.key != 0) {
            // Keyed identity survives: relocate the existing node, then patch
            // what changed inside it.
            try out.append(gpa, .{ .move = .{ .id = pid, .parent = prev_parent, .index = i } });
            try diffNode(gpa, prev, next, pid, nid, out);
        } else {
            // Keyless or re-shaped: no stable DOM identity to relocate.
            try out.append(gpa, .{ .remove = .{ .id = pid } });
            try out.append(gpa, .{ .insert = .{ .parent = prev_parent, .index = i, .new_id = nid } });
        }
    }
}

// --- matching ---------------------------------------------------------------

fn strEq(prev: *const tree.Tree, a: StrId, next: *const tree.Tree, b: StrId) bool {
    return std.mem.eql(u8, prev.str(a), next.str(b));
}

fn sameShape(
    prev: *const tree.Tree,
    p: *const tree.Node,
    next: *const tree.Tree,
    n: *const tree.Node,
) bool {
    return p.kind == n.kind and strEq(prev, p.tag, next, n.tag);
}

/// Previous child `pidx` -> next child index, or null when nothing matches it.
fn matchedNextIndex(
    prev: *const tree.Tree,
    pchildren: []const NodeId,
    next: *const tree.Tree,
    nchildren: []const NodeId,
    pidx: u32,
) ?u32 {
    const key = prev.node(pchildren[pidx]).key;
    if (key == 0) {
        const rank = keylessRank(prev, pchildren, pidx);
        if (rank >= keylessPairCount(prev, pchildren, next, nchildren)) return null;
        return keylessIndexOf(next, nchildren, rank);
    }
    const rank = keyedRank(prev, pchildren, key, pidx);
    return nthKeyed(next, nchildren, key, rank);
}

/// Next child `nidx` -> previous child index, or null when it is a new node.
fn matchedPrevIndex(
    prev: *const tree.Tree,
    pchildren: []const NodeId,
    next: *const tree.Tree,
    nchildren: []const NodeId,
    nidx: u32,
) ?u32 {
    const key = next.node(nchildren[nidx]).key;
    if (key == 0) {
        const rank = keylessRank(next, nchildren, nidx);
        if (rank >= keylessPairCount(prev, pchildren, next, nchildren)) return null;
        return keylessIndexOf(prev, pchildren, rank);
    }
    const rank = keyedRank(next, nchildren, key, nidx);
    return nthKeyed(prev, pchildren, key, rank);
}

/// Moves `front` to the first previous child that is matched and still waiting
/// to be placed (removed children are skipped). Called once, plus once per
/// child placed in order, so the whole pass stays quadratic.
fn advanceFront(
    prev: *const tree.Tree,
    pchildren: []const NodeId,
    next: *const tree.Tree,
    nchildren: []const NodeId,
    front: *u32,
) void {
    while (front.* < pchildren.len) : (front.* += 1) {
        if (matchedNextIndex(prev, pchildren, next, nchildren, front.*) != null) return;
    }
}

fn keylessRank(t: *const tree.Tree, children: []const NodeId, idx: u32) u32 {
    var rank: u32 = 0;
    for (children[0..idx]) |c| {
        if (t.node(c).key == 0) rank += 1;
    }
    return rank;
}

fn keyedRank(t: *const tree.Tree, children: []const NodeId, key: u32, idx: u32) u32 {
    var rank: u32 = 0;
    for (children[0..idx]) |c| {
        if (t.node(c).key == key) rank += 1;
    }
    return rank;
}

fn keylessCount(t: *const tree.Tree, children: []const NodeId) u32 {
    var count: u32 = 0;
    for (children) |c| {
        if (t.node(c).key == 0) count += 1;
    }
    return count;
}

/// How many keyless children pair up positionally.
fn keylessPairCount(
    prev: *const tree.Tree,
    pchildren: []const NodeId,
    next: *const tree.Tree,
    nchildren: []const NodeId,
) u32 {
    return @min(keylessCount(prev, pchildren), keylessCount(next, nchildren));
}

/// Index of the `rank`-th keyless child, if it exists.
fn keylessIndexOf(t: *const tree.Tree, children: []const NodeId, rank: u32) ?u32 {
    var seen: u32 = 0;
    for (children, 0..) |c, i| {
        if (t.node(c).key != 0) continue;
        if (seen == rank) return @intCast(i);
        seen += 1;
    }
    return null;
}

/// Index of the `rank`-th child carrying `key`, if it exists.
fn nthKeyed(t: *const tree.Tree, children: []const NodeId, key: u32, rank: u32) ?u32 {
    var seen: u32 = 0;
    for (children, 0..) |c, i| {
        if (t.node(c).key != key) continue;
        if (seen == rank) return @intCast(i);
        seen += 1;
    }
    return null;
}

// --- JSON wire format -------------------------------------------------------

/// Writes `ops` as the JSON array carried by a `patch` message
/// (`{"t":"patch",...,"ops":[...]}`). `html` values are rendered from `next`.
/// Allocation-free.
pub fn writeJson(
    w: *std.Io.Writer,
    next: *const tree.Tree,
    ops: []const Op,
) std.Io.Writer.Error!void {
    try w.writeByte('[');
    for (ops, 0..) |op, i| {
        if (i != 0) try w.writeByte(',');
        try writeOpJson(w, next, op);
    }
    try w.writeByte(']');
}

/// Convenience wrapper: encodes `ops` into a freshly allocated buffer the
/// caller owns. Additive helper.
pub fn writeJsonAlloc(
    gpa: std.mem.Allocator,
    next: *const tree.Tree,
    ops: []const Op,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try writeJson(&aw.writer, next, ops);
    return try aw.toOwnedSlice();
}

fn writeOpJson(w: *std.Io.Writer, next: *const tree.Tree, op: Op) std.Io.Writer.Error!void {
    switch (op) {
        .text => |t| {
            try w.writeAll("{\"op\":\"text\",\"id\":");
            try w.print("{d}", .{t.id});
            try w.writeAll(",\"value\":");
            try writeJsonString(w, t.value);
            try w.writeByte('}');
        },
        .attr => |a| {
            try w.writeAll("{\"op\":\"attr\",\"id\":");
            try w.print("{d}", .{a.id});
            try w.writeAll(",\"name\":");
            try writeJsonString(w, a.name);
            try w.writeAll(",\"value\":");
            if (a.value) |v| try writeJsonString(w, v) else try w.writeAll("null");
            try w.writeByte('}');
        },
        .replace => |r| {
            try w.writeAll("{\"op\":\"replace\",\"id\":");
            try w.print("{d}", .{r.id});
            try w.writeAll(",\"html\":");
            try writeHtmlJson(w, next, r.new_id);
            try w.writeByte('}');
        },
        .insert => |ins| {
            try w.writeAll("{\"op\":\"insert\",\"parent\":");
            try w.print("{d}", .{ins.parent});
            try w.writeAll(",\"index\":");
            try w.print("{d}", .{ins.index});
            try w.writeAll(",\"html\":");
            try writeHtmlJson(w, next, ins.new_id);
            try w.writeByte('}');
        },
        .remove => |r| {
            try w.writeAll("{\"op\":\"remove\",\"id\":");
            try w.print("{d}", .{r.id});
            try w.writeByte('}');
        },
        .move => |m| {
            try w.writeAll("{\"op\":\"move\",\"id\":");
            try w.print("{d}", .{m.id});
            try w.writeAll(",\"parent\":");
            try w.print("{d}", .{m.parent});
            try w.writeAll(",\"index\":");
            try w.print("{d}", .{m.index});
            try w.writeByte('}');
        },
    }
}

/// Writes `next`'s subtree at `id` as a JSON string.
fn writeHtmlJson(w: *std.Io.Writer, next: *const tree.Tree, id: NodeId) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var escaping: JsonEscapingWriter = undefined;
    escaping.init(w);
    try next.writeHtml(&escaping.writer, id);
    try escaping.writer.flush();
    try w.writeByte('"');
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    try writeJsonEscaped(w, s);
    try w.writeByte('"');
}

fn writeJsonEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (c < 0x20) {
            try w.print("\\u{x:0>4}", .{c});
        } else {
            try w.writeByte(c);
        },
    };
}

/// Forwards everything written to it into `out` as the body of a JSON string.
/// This is how a rendered subtree becomes an `html` value without buffering it.
const JsonEscapingWriter = struct {
    out: *std.Io.Writer,
    buffer: [4096]u8 = undefined,
    writer: std.Io.Writer = undefined,

    fn init(self: *JsonEscapingWriter, out: *std.Io.Writer) void {
        self.out = out;
        self.writer = .{ .vtable = &vtable, .buffer = &self.buffer };
    }

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .rebase = rebase,
    };

    fn drain(
        w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *JsonEscapingWriter = @fieldParentPtr("writer", w);
        std.debug.assert(data.len != 0);
        try writeJsonEscaped(self.out, w.buffer[0..w.end]);
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |chunk| {
            try writeJsonEscaped(self.out, chunk);
            consumed += chunk.len;
        }
        const last = data[data.len - 1];
        var reps: usize = 0;
        while (reps < splat) : (reps += 1) {
            try writeJsonEscaped(self.out, last);
            consumed += last.len;
        }
        return consumed;
    }

    fn rebase(
        w: *std.Io.Writer,
        preserve: usize,
        minimum_len: usize,
    ) std.Io.Writer.Error!void {
        _ = preserve;
        // The buffer cannot grow, so a request it cannot satisfy is a hard
        // failure rather than an endless drain loop.
        if (minimum_len > w.buffer.len) return error.WriteFailed;
        _ = try drain(w, &.{""}, 1);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const Item = struct { key: u32, text: []const u8 };

/// Builds `<fragment>[<li key=..>text</li>...]`; the tile list is the root's
/// only child when `keyed` items are all that is passed.
fn buildKeyedList(t: *tree.Tree, items: []const Item) !void {
    var b = tree.Builder.init(t);
    errdefer b.deinit();
    for (items) |it| {
        try b.element("li", &.{}, it.key);
        try b.text(it.text);
        try b.close();
    }
    b.deinit();
}

fn keyedChild(t: *const tree.Tree, parent: NodeId, key: u32) NodeId {
    for (t.node(parent).children) |c| {
        if (t.node(c).key == key) return c;
    }
    unreachable;
}

fn runDiff(
    gpa: std.mem.Allocator,
    prev: *const tree.Tree,
    next: *const tree.Tree,
) !std.ArrayList(Op) {
    var ops: std.ArrayList(Op) = .empty;
    errdefer ops.deinit(gpa);
    try diff(gpa, prev, next, &ops);
    return ops;
}

fn tagOf(op: Op) std.meta.Tag(Op) {
    return std.meta.activeTag(op);
}

// A stand-in for the browser side of the protocol: it applies ops to a copy of
// the previous tree's DOM shape and renders the result canonically (ids
// elided). Used to prove that the op stream really does describe the move from
// `prev` to `next`, including every index.
const Sim = struct {
    arena: std.heap.ArenaAllocator,
    root: *Inst = undefined,

    const Space = enum { prev, next };

    const Inst = struct {
        space: Space,
        id: NodeId,
        kind: tree.Kind,
        tag: []const u8,
        text: []const u8,
        attrs: std.ArrayList(KV) = .empty,
        children: std.ArrayList(*Inst) = .empty,
    };

    const KV = struct { name: []const u8, value: []const u8 };

    fn init(gpa: std.mem.Allocator, prev: *const tree.Tree) !Sim {
        var self: Sim = .{ .arena = .init(gpa) };
        errdefer self.arena.deinit();
        self.root = try self.instantiate(prev, .prev, prev.rootId());
        return self;
    }

    fn deinit(self: *Sim) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn instantiate(self: *Sim, t: *const tree.Tree, space: Space, id: NodeId) !*Inst {
        const alloc = self.arena.allocator();
        const n = t.node(id);
        const inst = try alloc.create(Inst);
        inst.* = .{
            .space = space,
            .id = id,
            .kind = n.kind,
            .tag = t.str(n.tag),
            .text = t.str(n.text),
        };
        for (n.attrs) |a| {
            try inst.attrs.append(alloc, .{ .name = t.str(a.name), .value = t.str(a.value) });
        }
        for (n.children) |c| {
            try inst.children.append(alloc, try self.instantiate(t, space, c));
        }
        return inst;
    }

    fn find(self: *Sim, inst: *Inst, space: Space, id: NodeId) ?*Inst {
        if (inst.space == space and inst.id == id) return inst;
        for (inst.children.items) |child| {
            if (self.find(child, space, id)) |hit| return hit;
        }
        return null;
    }

    fn parentOf(self: *Sim, inst: *Inst, target: *Inst) ?*Inst {
        for (inst.children.items) |child| {
            if (child == target) return inst;
            if (self.parentOf(child, target)) |hit| return hit;
        }
        return null;
    }

    fn apply(self: *Sim, next: *const tree.Tree, ops: []const Op) !void {
        const alloc = self.arena.allocator();
        for (ops) |op| switch (op) {
            .text => |t| {
                const target = self.find(self.root, .prev, t.id) orelse return error.NoSuchNode;
                target.text = t.value;
            },
            .attr => |a| {
                const target = self.find(self.root, .prev, a.id) orelse return error.NoSuchNode;
                var i: usize = 0;
                while (i < target.attrs.items.len) : (i += 1) {
                    if (!std.mem.eql(u8, target.attrs.items[i].name, a.name)) continue;
                    if (a.value) |v| {
                        target.attrs.items[i].value = v;
                    } else {
                        _ = target.attrs.orderedRemove(i);
                    }
                    break;
                } else {
                    try target.attrs.append(alloc, .{ .name = a.name, .value = a.value orelse return error.BadOp });
                }
            },
            .replace => |r| {
                const target = self.find(self.root, .prev, r.id) orelse return error.NoSuchNode;
                const parent = self.parentOf(self.root, target) orelse return error.BadOp;
                const slot = indexOf(parent.children.items, target) orelse return error.BadOp;
                parent.children.items[slot] = try self.instantiate(next, .next, r.new_id);
            },
            .insert => |ins| {
                const parent = self.find(self.root, .prev, ins.parent) orelse return error.NoSuchNode;
                if (ins.index > parent.children.items.len) return error.BadOp;
                const fresh = try self.instantiate(next, .next, ins.new_id);
                try parent.children.insert(alloc, ins.index, fresh);
            },
            .remove => |r| {
                const target = self.find(self.root, .prev, r.id) orelse return error.NoSuchNode;
                const parent = self.parentOf(self.root, target) orelse return error.BadOp;
                const slot = indexOf(parent.children.items, target) orelse return error.BadOp;
                _ = parent.children.orderedRemove(slot);
            },
            .move => |m| {
                const target = self.find(self.root, .prev, m.id) orelse return error.NoSuchNode;
                const parent = self.find(self.root, .prev, m.parent) orelse return error.NoSuchNode;
                const from = indexOf(parent.children.items, target) orelse return error.BadOp;
                _ = parent.children.orderedRemove(from);
                if (m.index > parent.children.items.len) return error.BadOp;
                try parent.children.insert(alloc, m.index, target);
            },
        };
    }

    fn write(self: *Sim, w: *std.Io.Writer, inst: *Inst) std.Io.Writer.Error!void {
        switch (inst.kind) {
            .element => {
                try w.writeByte('<');
                try w.writeAll(inst.tag);
                for (inst.attrs.items) |a| {
                    try w.print(" {s}=\"{s}\"", .{ a.name, a.value });
                }
                try w.writeByte('>');
                if (tree.isVoidTag(inst.tag)) return;
                for (inst.children.items) |c| try write(self, w, c);
                try w.writeAll("</");
                try w.writeAll(inst.tag);
                try w.writeByte('>');
            },
            .text => try w.writeAll(inst.text),
            .raw => try w.writeAll(inst.text),
            .fragment => for (inst.children.items) |c| try write(self, w, c),
        }
    }
};

fn indexOf(list: []const *Sim.Inst, target: *Sim.Inst) ?usize {
    for (list, 0..) |item, i| {
        if (item == target) return i;
    }
    return null;
}

/// Canonical (id-free) rendering of a tree, for structural comparison.
fn canonical(gpa: std.mem.Allocator, t: *const tree.Tree) ![]u8 {
    var sim = try Sim.init(gpa, t);
    defer sim.deinit();
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try sim.write(&aw.writer, sim.root);
    return try aw.toOwnedSlice();
}

/// Applies `ops` to `prev` and returns the canonical rendering of the result.
fn appliedCanonical(gpa: std.mem.Allocator, prev: *const tree.Tree, next: *const tree.Tree, ops: []const Op) ![]u8 {
    var sim = try Sim.init(gpa, prev);
    defer sim.deinit();
    try sim.apply(next, ops);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try sim.write(&aw.writer, sim.root);
    return try aw.toOwnedSlice();
}

fn expectApplied(prev: *const tree.Tree, next: *const tree.Tree) !void {
    var ops = try runDiff(testing.allocator, prev, next);
    defer ops.deinit(testing.allocator);

    const applied = try appliedCanonical(testing.allocator, prev, next, ops.items);
    defer testing.allocator.free(applied);
    const expected = try canonical(testing.allocator, next);
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, applied);

    if (ops.items.len == 0) return;
    // The encoder must accept every op the differ can emit.
    const json = try writeJsonAlloc(testing.allocator, next, ops.items);
    defer testing.allocator.free(json);
}

test "diff: a permutation of keyed children applies cleanly" {
    const permutations = [_][]const u32{
        &.{ 1, 2, 3, 4 },
        &.{ 4, 1, 2, 3 },
        &.{ 2, 1, 4, 3 },
        &.{ 4, 3, 2, 1 },
        &.{ 1, 3, 2, 4 },
    };
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    try buildKeyedList(&prev, &.{
        .{ .key = 1, .text = "a" },
        .{ .key = 2, .text = "b" },
        .{ .key = 3, .text = "c" },
        .{ .key = 4, .text = "d" },
    });

    for (permutations) |order| {
        var next = tree.Tree.init(testing.allocator);
        defer next.deinit();
        var items: [4]Item = undefined;
        for (order, 0..) |key, i| {
            items[i] = .{ .key = key, .text = (&[_][]const u8{ "a", "b", "c", "d" })[key - 1] };
        }
        try buildKeyedList(&next, &items);
        try expectApplied(&prev, &next);

        var ops = try runDiff(testing.allocator, &prev, &next);
        defer ops.deinit(testing.allocator);
        const bound = 2 * prev.node(prev.rootId()).children.len;
        try testing.expect(ops.items.len < bound);
    }
}

test "diff: mixed insert, remove, move, text and attribute edits apply cleanly" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{.{ .name = "class", .value = "root" }}, 0);
    try b1.text("head");
    try b1.element("span", &.{}, 0);
    try b1.text("keep");
    try b1.close();
    try b1.element("ul", &.{}, 0);
    for ([_]u32{ 1, 2, 3, 4, 5 }) |key| {
        try b1.element("li", &.{.{ .name = "n", .value = "x" }}, key);
        try b1.raw("<b>c</b>");
        try b1.close();
    }
    try b1.close();
    try b1.close();
    b1.deinit();

    var b2 = tree.Builder.init(&next);
    try b2.element("div", &.{ .{ .name = "class", .value = "root" }, .{ .name = "id", .value = "d" } }, 0);
    try b2.text("tail");
    try b2.element("span", &.{}, 0);
    try b2.text("keep");
    try b2.close();
    try b2.element("ul", &.{}, 0);
    for ([_]u32{ 5, 1 }) |key| {
        try b2.element("li", &.{.{ .name = "n", .value = "y" }}, key);
        try b2.raw("<b>c</b>");
        try b2.close();
    }
    try b2.element("li", &.{}, 0);
    try b2.text("fresh");
    try b2.close();
    try b2.element("li", &.{}, 2);
    try b2.raw("<b>c</b>");
    try b2.close();
    try b2.close();
    try b2.close();
    b2.deinit();

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expect(ops.items.len > 0);
    try expectApplied(&prev, &next);
}

test "diff: randomized keyed lists always apply to the next tree" {
    var prng = std.Random.DefaultPrng.init(0x5eed_1234);
    const random = prng.random();

    var total_moves: usize = 0;
    var iteration: usize = 0;
    while (iteration < 200) : (iteration += 1) {
        const keys = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };

        var prev = tree.Tree.init(testing.allocator);
        defer prev.deinit();
        var next = tree.Tree.init(testing.allocator);
        defer next.deinit();

        var prev_items: [keys.len]Item = undefined;
        for (&prev_items, keys) |*it, key| {
            it.* = .{ .key = key, .text = "same" };
        }
        try buildKeyedList(&prev, &prev_items);

        // Keep a random subset of the keys in a random order, sometimes with
        // edited text, sometimes with a new keyless item mixed in.
        var kept: [keys.len]u32 = undefined;
        var kept_len: usize = 0;
        for (keys) |key| {
            if (random.boolean()) {
                kept[kept_len] = key;
                kept_len += 1;
            }
        }
        random.shuffle(u32, kept[0..kept_len]);

        const next_len = kept_len + @as(usize, @intFromBool(random.boolean()));
        var next_items = try testing.allocator.alloc(Item, next_len);
        defer testing.allocator.free(next_items);
        for (next_items[0..kept_len], kept[0..kept_len]) |*it, key| {
            it.* = .{ .key = key, .text = if (random.boolean()) "edited" else "same" };
        }
        if (next_len > kept_len) {
            const at = random.uintLessThan(usize, next_items.len);
            std.mem.copyBackwards(Item, next_items[at + 1 ..], next_items[at .. next_items.len - 1]);
            next_items[at] = .{ .key = 0, .text = "keyless" };
        }
        try buildKeyedList(&next, next_items);

        try expectApplied(&prev, &next);

        var ops = try runDiff(testing.allocator, &prev, &next);
        defer ops.deinit(testing.allocator);
        try testing.expect(ops.items.len <= 2 * prev.node(prev.rootId()).children.len + next_len);
        for (ops.items) |op| {
            if (tagOf(op) == .move) total_moves += 1;
        }
    }

    // The keyed path really is exercised: some shuffled revision produced
    // relocations rather than rebuilds.
    try testing.expect(total_moves > 0);
}

test "diff: identical trees produce zero ops" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    const items = [_]Item{ .{ .key = 1, .text = "one" }, .{ .key = 2, .text = "two" } };
    try buildKeyedList(&prev, &items);
    try buildKeyedList(&next, &items);

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ops.items.len);

    // Byte-identical renders are what makes "zero ops" meaningful.
    const html_prev = try prev.writeHtmlAlloc(testing.allocator, prev.rootId());
    defer testing.allocator.free(html_prev);
    const html_next = try next.writeHtmlAlloc(testing.allocator, next.rootId());
    defer testing.allocator.free(html_next);
    try testing.expectEqualStrings(html_prev, html_next);
}

test "diff: empty trees produce zero ops" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();
    var populated = tree.Tree.init(testing.allocator);
    defer populated.deinit();
    const items = [_]Item{.{ .key = 1, .text = "one" }};
    try buildKeyedList(&populated, &items);

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ops.items.len);

    ops.clearRetainingCapacity();
    try diff(testing.allocator, &prev, &populated, &ops);
    try testing.expectEqual(@as(usize, 0), ops.items.len);
    ops.clearRetainingCapacity();
    try diff(testing.allocator, &populated, &next, &ops);
    try testing.expectEqual(@as(usize, 0), ops.items.len);
}

test "diff: text change emits one text op carrying the new string" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    try buildKeyedList(&prev, &.{.{ .key = 7, .text = "before" }});
    try buildKeyedList(&next, &.{.{ .key = 7, .text = "after <&>" }});

    const prev_root = prev.rootId();
    const next_root = next.rootId();
    const prev_li = keyedChild(&prev, prev_root, 7);
    const next_li = keyedChild(&next, next_root, 7);
    const prev_text = prev.node(prev_li).children[0];
    const next_text = next.node(next_li).children[0];

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).text, tagOf(ops.items[0]));
    const text = ops.items[0].text;
    try testing.expectEqual(prev_text, text.id);
    try testing.expectEqualStrings("after <&>", text.value);
    // The value points at the next tree's interned string, not a copy.
    try testing.expectEqualStrings(next.str(next.node(next_text).text), text.value);
}

test "diff: attribute change, removal and addition" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{
        .{ .name = "id", .value = "a" },
        .{ .name = "class", .value = "old" },
        .{ .name = "gone", .value = "1" },
    }, 0);
    b1.deinit();
    var b2 = tree.Builder.init(&next);
    try b2.element("div", &.{
        .{ .name = "id", .value = "a" },
        .{ .name = "class", .value = "new" },
        .{ .name = "added", .value = "2" },
    }, 0);
    b2.deinit();

    const div = prev.node(prev.rootId()).children[0];
    try testing.expectEqual(div, next.node(next.rootId()).children[0]);

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).attr, tagOf(ops.items[0]));
    try testing.expectEqualStrings("class", ops.items[0].attr.name);
    try testing.expectEqualStrings("new", ops.items[0].attr.value.?);
    try testing.expectEqualStrings("gone", ops.items[1].attr.name);
    try testing.expect(ops.items[1].attr.value == null);
    try testing.expectEqualStrings("added", ops.items[2].attr.name);
    try testing.expectEqualStrings("2", ops.items[2].attr.value.?);
    try testing.expectEqual(div, ops.items[0].attr.id);
}

test "diff: keyed insert at head, middle and tail" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    try buildKeyedList(&prev, &.{ .{ .key = 1, .text = "a" }, .{ .key = 2, .text = "b" } });
    try buildKeyedList(&next, &.{
        .{ .key = 3, .text = "c" },
        .{ .key = 1, .text = "a" },
        .{ .key = 4, .text = "d" },
        .{ .key = 2, .text = "b" },
        .{ .key = 5, .text = "e" },
    });

    const next_root = next.rootId();
    const next_ids = next.node(next_root).children;

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), ops.items.len);

    const expected = [_]struct { index: u32, key: u32 }{
        .{ .index = 0, .key = 3 },
        .{ .index = 2, .key = 4 },
        .{ .index = 4, .key = 5 },
    };
    for (ops.items, expected) |op, want| {
        try testing.expectEqual(std.meta.Tag(Op).insert, tagOf(op));
        try testing.expectEqual(prev.rootId(), op.insert.parent);
        try testing.expectEqual(want.index, op.insert.index);
        try testing.expectEqual(next_ids[want.index], op.insert.new_id);
    }
}

test "diff: keyed remove emits one remove per dropped child" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    try buildKeyedList(&prev, &.{
        .{ .key = 1, .text = "a" },
        .{ .key = 2, .text = "b" },
        .{ .key = 3, .text = "c" },
    });
    try buildKeyedList(&next, &.{.{ .key = 1, .text = "a" }});

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).remove, tagOf(ops.items[0]));
    try testing.expectEqual(keyedChild(&prev, prev.rootId(), 2), ops.items[0].remove.id);
    try testing.expectEqual(keyedChild(&prev, prev.rootId(), 3), ops.items[1].remove.id);
}

test "diff: keyed reorder costs one move per displaced child" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    // Same four keyed children; the last one becomes the first.
    try buildKeyedList(&prev, &.{
        .{ .key = 1, .text = "a" },
        .{ .key = 2, .text = "b" },
        .{ .key = 3, .text = "c" },
        .{ .key = 4, .text = "d" },
    });
    try buildKeyedList(&next, &.{
        .{ .key = 4, .text = "d" },
        .{ .key = 1, .text = "a" },
        .{ .key = 2, .text = "b" },
        .{ .key = 3, .text = "c" },
    });

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);

    // One op, and in any case well under 2 * children (no whole-list replace).
    try testing.expectEqual(@as(usize, 1), ops.items.len);
    try testing.expect(ops.items.len < 2 * prev.node(prev.rootId()).children.len);
    try testing.expectEqual(std.meta.Tag(Op).move, tagOf(ops.items[0]));
    const move = ops.items[0].move;
    try testing.expectEqual(keyedChild(&prev, prev.rootId(), 4), move.id);
    try testing.expectEqual(prev.rootId(), move.parent);
    try testing.expectEqual(@as(u32, 0), move.index);

    // A reversed list is the worst case: n-1 moves.
    var reversed = tree.Tree.init(testing.allocator);
    defer reversed.deinit();
    try buildKeyedList(&reversed, &.{
        .{ .key = 4, .text = "d" },
        .{ .key = 3, .text = "c" },
        .{ .key = 2, .text = "b" },
        .{ .key = 1, .text = "a" },
    });
    var ops2 = try runDiff(testing.allocator, &prev, &reversed);
    defer ops2.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), ops2.items.len);
    try testing.expect(ops2.items.len < 2 * prev.node(prev.rootId()).children.len);
    for (ops2.items) |op| try testing.expectEqual(std.meta.Tag(Op).move, tagOf(op));
}

test "diff: keyless displacement falls back to remove and insert" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    // prev: [<div key=1>, text "t"] -> next: [text "t", <div key=1>]
    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{}, 1);
    try b1.close();
    try b1.text("t");
    const text_node = prev.node(prev.rootId()).children[1];
    b1.deinit();

    var b2 = tree.Builder.init(&next);
    try b2.text("t");
    try b2.element("div", &.{}, 1);
    try b2.close();
    const new_text = next.node(next.rootId()).children[0];
    b2.deinit();

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    // The keyless child cannot be relocated, so it is dropped and re-inserted;
    // the keyed child then lands on its final index without any op of its own.
    try testing.expectEqual(@as(usize, 2), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).remove, tagOf(ops.items[0]));
    try testing.expectEqual(text_node, ops.items[0].remove.id);
    try testing.expectEqual(std.meta.Tag(Op).insert, tagOf(ops.items[1]));
    try testing.expectEqual(new_text, ops.items[1].insert.new_id);
    try testing.expectEqual(@as(u32, 0), ops.items[1].insert.index);
    try testing.expectEqual(prev.rootId(), ops.items[1].insert.parent);

    // The keyed child keeps its previous node identity: no op drops or
    // re-creates it.
    const keyed_prev = keyedChild(&prev, prev.rootId(), 1);
    for (ops.items) |op| {
        switch (op) {
            .remove => |r| try testing.expect(r.id != keyed_prev),
            .replace => |r| try testing.expect(r.id != keyed_prev),
            else => {},
        }
    }
}

test "diff: tag change at a matched key replaces the subtree" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{}, 3);
    try b1.text("old");
    try b1.close();
    b1.deinit();
    var b2 = tree.Builder.init(&next);
    try b2.element("span", &.{}, 3);
    try b2.text("new");
    try b2.close();
    b2.deinit();

    const prev_div = keyedChild(&prev, prev.rootId(), 3);
    const next_span = keyedChild(&next, next.rootId(), 3);

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).replace, tagOf(ops.items[0]));
    try testing.expectEqual(prev_div, ops.items[0].replace.id);
    try testing.expectEqual(next_span, ops.items[0].replace.new_id);
}

test "diff: root kind change replaces the root" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    // A `Builder` always roots a tree at a fragment, so the root kind can only
    // differ for trees assembled directly.
    _ = try prev.addNode(.{ .kind = .text, .id = 0, .text = try prev.internOrError("a") });
    _ = try next.addNode(.{ .kind = .element, .id = 0, .tag = try next.internOrError("main") });

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), ops.items.len);
    try testing.expectEqual(std.meta.Tag(Op).replace, tagOf(ops.items[0]));
    try testing.expectEqual(prev.rootId(), ops.items[0].replace.id);
    try testing.expectEqual(next.rootId(), ops.items[0].replace.new_id);
}

test "diff: nested fragments are transparent but addressable" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    // root -> div -> fragment(key=9) -> [text, span]
    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{}, 0);
    try b1.fragment(9);
    try b1.text("a");
    try b1.element("span", &.{}, 0);
    try b1.close();
    try b1.close();
    try b1.close();
    b1.deinit();

    var b2 = tree.Builder.init(&next);
    try b2.element("div", &.{}, 0);
    try b2.fragment(9);
    try b2.text("b");
    try b2.element("span", &.{}, 0);
    try b2.close();
    try b2.element("em", &.{}, 0);
    try b2.close();
    try b2.close();
    try b2.close();
    b2.deinit();

    const prev_div = prev.node(prev.rootId()).children[0];
    const next_div = next.node(next.rootId()).children[0];
    const prev_frag = prev.node(prev_div).children[0];
    const next_frag = next.node(next_div).children[0];
    try testing.expect(prev.node(prev_frag).kind == .fragment);
    try testing.expect(next.node(next_frag).kind == .fragment);
    // The fragment is matched, so its own identity is never an op target.
    try testing.expectEqual(prev_frag, 2);
    try testing.expectEqual(next_frag, 2);

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), ops.items.len);

    try testing.expectEqual(std.meta.Tag(Op).text, tagOf(ops.items[0]));
    try testing.expectEqual(prev.node(prev_frag).children[0], ops.items[0].text.id);
    try testing.expectEqualStrings("b", ops.items[0].text.value);

    try testing.expectEqual(std.meta.Tag(Op).insert, tagOf(ops.items[1]));
    try testing.expectEqual(prev_frag, ops.items[1].insert.parent);
    try testing.expectEqual(@as(u32, 2), ops.items[1].insert.index);
    try testing.expectEqual(next.node(next_frag).children[2], ops.items[1].insert.new_id);

    // A matched fragment contributes no op of its own: only its two children
    // changed.
    try testing.expectEqual(2, prev_frag);
    try testing.expectEqual(2, next_frag);
}

test "diff: matched raw nodes are opaque" {
    var prev = tree.Tree.init(testing.allocator);
    defer prev.deinit();
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    var b1 = tree.Builder.init(&prev);
    try b1.element("div", &.{}, 0);
    try b1.raw("<b>client</b>");
    try b1.close();
    b1.deinit();
    var b2 = tree.Builder.init(&next);
    try b2.element("div", &.{}, 0);
    try b2.raw("<i>server rewrote this</i>");
    try b2.close();
    b2.deinit();

    var ops = try runDiff(testing.allocator, &prev, &next);
    defer ops.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ops.items.len);
}

test "json: every op kind encodes to the wire format" {
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();
    var b = tree.Builder.init(&next);
    try b.element("div", &.{}, 0);
    try b.text("hi");
    try b.close();
    try b.raw("<em>keep</em>");
    b.deinit();

    const div = 1;
    const ops = [_]Op{
        .{ .text = .{ .id = 4, .value = "a\"b\\c\n\u{7}" } },
        .{ .attr = .{ .id = 4, .name = "class", .value = "x y" } },
        .{ .attr = .{ .id = 4, .name = "gone", .value = null } },
        .{ .replace = .{ .id = 2, .new_id = div } },
        .{ .insert = .{ .parent = 1, .index = 2, .new_id = div } },
        .{ .remove = .{ .id = 9 } },
        .{ .move = .{ .id = 5, .parent = 1, .index = 0 } },
    };

    const json = try writeJsonAlloc(testing.allocator, &next, &ops);
    defer testing.allocator.free(json);
    const expected =
        "[{\"op\":\"text\",\"id\":4,\"value\":\"a\\\"b\\\\c\\n\\u0007\"}" ++
        ",{\"op\":\"attr\",\"id\":4,\"name\":\"class\",\"value\":\"x y\"}" ++
        ",{\"op\":\"attr\",\"id\":4,\"name\":\"gone\",\"value\":null}" ++
        ",{\"op\":\"replace\",\"id\":2,\"html\":\"<div z-id=\\\"1\\\">hi</div>\"}" ++
        ",{\"op\":\"insert\",\"parent\":1,\"index\":2,\"html\":\"<div z-id=\\\"1\\\">hi</div>\"}" ++
        ",{\"op\":\"remove\",\"id\":9}" ++
        ",{\"op\":\"move\",\"id\":5,\"parent\":1,\"index\":0}]";
    try testing.expectEqualStrings(expected, json);
}

test "json: html values are escaped correctly across writer buffer flushes" {
    var next = tree.Tree.init(testing.allocator);
    defer next.deinit();

    // Longer than the encoder's internal buffer, so the html reaches the wire
    // in several escaped chunks.
    const filler_len = 5000;
    const filler = try testing.allocator.alloc(u8, filler_len);
    defer testing.allocator.free(filler);
    @memset(filler, '&');

    var b = tree.Builder.init(&next);
    try b.element("div", &.{.{ .name = "title", .value = "a\"b<c" }}, 0);
    try b.text("t");
    try b.raw(filler);
    try b.close();
    b.deinit();

    const ops = [_]Op{.{ .replace = .{ .id = 0, .new_id = next.node(next.rootId()).children[0] } }};
    const json = try writeJsonAlloc(testing.allocator, &next, &ops);
    defer testing.allocator.free(json);

    const prefix = "[{\"op\":\"replace\",\"id\":0,\"html\":\"<div title=\\\"a&quot;b&lt;c\\\" z-id=\\\"1\\\">t";
    const suffix = "</div>\"}]";
    try testing.expectEqualStrings(prefix, json[0..prefix.len]);
    try testing.expectEqualStrings(suffix, json[json.len - suffix.len ..]);

    // The raw region is client-owned and passes through unescaped, but the
    // surrounding markup must be intact after the buffer flushes.
    const middle = json[prefix.len .. json.len - suffix.len];
    try testing.expectEqual(@as(usize, filler_len), middle.len);
    try testing.expectEqualStrings(filler, middle);
}
