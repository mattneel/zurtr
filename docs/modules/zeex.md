# Module contract: ZEEX (`zurtr.zeex`)

Scope: JSX templates lowered to Zig at **build time**. A view is authored as
markup, a script running inside the vendored engine turns it into an IR, and this
module turns the IR into a Zig source file whose `render` builds the render tree.
It is a *layer*, like `zscript`: nothing in the dependency order depends on it, and
it is the only layer that leaves nothing of itself in the running program — the
generated file needs the framework and nothing else.

Status: implemented behind `-Dzscript` (`src/zeex/compile.zig`,
`src/zeex/transform.js`). The compiler needs an engine to run the transform, so in
a build without one `zurtr.zeex` is an empty struct (`src/root.zig`).

## The two halves and the seam

| Half | What it is | Where it runs |
| :- | :- | :- |
| `transform.js` | JSX → IR | inside `zurtr.zscript` (QuickJS), **at build time** |
| `compile.zig` | IR → Zig source | in the build, as ordinary Zig |
| the seam | JSON: `{ "ops": [ … ] }` | between them |

The transform is embedded in the compiler (`@embedFile("transform.js")`), so
there is no path to find and no file to ship. No Node, no npm, no Babel: the build
already carries an engine, and this is a script it runs.

```zig
pub fn compile_template(allocator: std.mem.Allocator, template: []const u8) Error![:0]u8
```

The result is a complete file. Writing it where a build can import it is the
caller's job — today that is an application-side step (`zig-cache/zeex/tasks.zig`
in the example), not a framework build step.

Four errors, exactly:

| Error | Means | Does it say what? |
| :- | :- | :- |
| `TemplateRejected` | the template did not parse, or used something outside the subset | yes — the script's own message, with the line number |
| `MalformedIr` | the IR is not one this emitter understands | partly: a non-empty `otherwise` prints what it refused; an unknown op, attribute kind, or a path naming a value this scope cannot reach returns silently |
| `TransformFailed` | the engine could not be started | no |
| `OutOfMemory` | allocation failed | no |

The output is **sentinel-terminated** (`[:0]u8`) because a Zig source file is:
`std.zig.Ast.parse` takes it that way, and so does anything that writes it to
disk.

## Why generate instead of interpret

The generated function is:

```zig
const zurtr = @import("zurtr");

pub fn render(props: anytype, b: *zurtr.live.tree.Builder) !void { … }
```

`props: anytype` is the whole trick. The template's `props.title` becomes
`props.title` in Zig, so a name the caller's struct does not have is a **compile
error at the call site**, not a blank spot on a page. Nothing about a template can
fail at runtime for a reason a compile could have caught, which is what makes this
worth generating rather than interpreting. (The generated file therefore has to be
compiled in a module that can `@import("zurtr")`, and `zurtr.live.tree` has to stay
exported from the framework root — it is named in every file this module emits. That export
was added at `dae8366`, and `src/root.zig`'s test block is what holds it: the compiler
cannot import the framework, so the one place both sides are visible asserts the two names
the emitter writes.)

Escaping is the render tree's business, not the template's: `text` escapes and
`raw` does not, so a template never chooses which interpolation was the safe one.

## The subset

Accepted — everything else is refused:

| Form | Example |
| :- | :- |
| element, static attributes | `<div class="card">…</div>` |
| element, interpolated attribute | `<a href={props.url}>…</a>` |
| bare attribute (present, rendered empty) | `<input disabled>` |
| self-closing, and void elements | `<br/>`, `<img src={props.src}>` |
| interpolation: a member path | `{props.title}`, `{props.user.name}` |
| verbatim interpolation | `{__raw(props.html)}` |
| conditional (no `else`) | `{props.show && <p>{props.body}</p>}` |
| iteration, function or arrow | `{props.items.map(item => <li>{item}</li>)}`, and the ES5 `function (item) { … }` form |
| component call (a capitalised tag) | `<Card title={props.title}/>` |
| children on a component, as that component's slot | `<Card><p>{props.body}</p></Card>` |

Refused, **with the line number**:

- anything in braces that is not `props.<field>`, a loop variable, or `__raw(…)` —
  so `{foo}` and `{props}` are errors, not blanks;
- a path segment that is not a field name (`^[A-Za-z_][A-Za-z0-9_]*$`):
  `{props.a + 1}` is refused rather than written into the generated source as an
  expression, which is what "a path, never an expression" has to mean;
- a loop variable with properties (`{r.cells}` inside `map(r => …)`) — nested
  iteration goes through a `props` path;
- a loop variable named `b`, `props` or `zurtr`, or one an enclosing loop already
  bound: the emitter writes the name into `for (…) |name|` verbatim, so those
  would shadow something the generated function needs;
- a bare `}` that opens no interpolation, an unterminated element/interpolation,
  trailing input, and an attribute value that is neither quoted nor braced.

Boundaries worth stating as boundaries:

- there is no `else` and no ternary: only `{cond && <el>}`;
- iteration is single-variable; a loop variable cannot itself be iterated;
- a component's children are a slot it may render, or ignore (see below);
- a void element's children are not parsed: `<br>x</br>` is a closing tag without
  an opening tag, not an ignored child.

## The IR

Six ops, and the emitter has a branch for each; anything else is `MalformedIr`.

| Op | Shape | Emitted as |
| :- | :- | :- |
| `text` | `{value}` | `try b.text("…");` (escaped) |
| `expr` | `{path}` | `try b.text(props.x);` |
| `raw` | `{path}` | `try b.raw(props.x);` (never escaped) |
| `if` | `{path, then, otherwise}` | `if (props.x) { … }` (`otherwise` must be empty) |
| `for` | `{path, item, body}` | `for (props.x) |item| { … }` |
| `element` | `{tag, attrs, children}` | see "Components": children become a slot when the tag is capitalised |

A path is an array. `["$item"]` — the `$` form — is the enclosing `for`'s loop
variable and must be a single segment; anything else is a field of `props`, so a
loop variable can never be mistaken for a property. Attribute values are
`{kind:"static",value}`, `{kind:"path",path}`, or `{kind:"toggle"}` (a bare
attribute: present, rendered as an empty value, which is what an HTML boolean
attribute means). `AttrSpec.value == null` would *omit* an attribute, so a bare
attribute must not go that route.

## Components: a capitalised tag, and children as a slot

A capitalised tag is a component call. `props` carries the component as a
*declaration*, the attributes become its argument struct, and the call is a
namespace call — `@TypeOf(props).Card(…)`, never `props.Card(…)`, which would
bind `props` as a method receiver and pass one argument too many. That is also
what makes a component the props type does not declare a **compile error at the
call site**, which is the same guarantee `props.title` gives for a field: this
module's tests cannot see it (they parse the generated source), so it surfaces in
the application's build — as intended, and worth knowing when a template "parses
clean" while calling a component that does not exist.

```
<Card title={props.title}/>
```
```zig
try @TypeOf(props).Card(.{ .title = props.title, .children = @as(?Slot0, null) }, b);
```

A lowercase tag becomes the render-tree calls instead: `try b.element("div", &.{ …attrs… }, 0);`,
then its children, then `try b.close();`.

**A component's children become a slot the component calls.** The children are lowered into a generated
struct with a `render` method, and the component decides whether, when and how often to call it — a
LiveView component's `inner_block`:

```
<Card title="t"><p>{props.body}</p></Card>
```
```zig
const Slot0 = struct {
    props: @TypeOf(props),
    pub fn render(self: @This(), slot_b0: *zurtr.live.tree.Builder) anyerror!void {
        try slot_b0.element("p", &.{}, 0);
        try slot_b0.text(self.props.body);
        try slot_b0.close();
    }
};
try @TypeOf(props).Card(.{ .title = "t", .children = @as(?Slot0, .{ .props = props }) }, b);
```

The component's side is one line, and it names no generated type:

```zig
pub fn Card(attrs: anytype, b: *zurtr.live.tree.Builder) !void {
    try b.element("card", &.{}, 0);
    if (attrs.children) |slot| try slot.render(b); // null when the tag had no children
    try b.close();
}
```

`attrs.children` is always present, and `null` for a tag with none — the `inner_block`-absent case.
Component parameters are therefore `anytype` (as they already were): a slot's type is generated at the
call site, so no component could name it.

### What a slot carries, and why it is a value

The children are written in the *caller's* template, so they name the caller's values. A slot carries
each one it uses **by value** — the caller's `props`, and every enclosing loop variable the children
reference (`item: @TypeOf(item)`), reached inside as `self.item`. Both reasons are structural:

- **A nested function cannot read the enclosing function's runtime values.** Reading a runtime field of
  `props` from inside the generated `fn render` fails to compile (`"props" not accessible from inner
  function`) as soon as the caller's props is a named struct value rather than a comptime-known literal.
  So a function-pointer slot (`?*const fn (*Builder) anyerror!void`, the shape this convention was first
  sketched as) cannot carry the caller's props at all; making it work needs a `*anyopaque` context and a
  cast at every call — more machinery, and an unsafe one.
- **A loop variable cannot be captured at all**, so without carrying, a `<Card>` inside a `map` could not
  use the item — the most common thing a slot wants to render.

The cost is a copy: constructing a component call copies the caller's props and each loop variable the
children use. Props are small view structs, and a slot that outlives the call holds slices of the
caller's data, like any other value.

Names the generated code owns are refused as loop variables, with the line number: `b`, `props`,
`zurtr`, `self`, `render`, and anything matching `slot_b<N>` or `Slot<N>`.

Why this shape at all: a template language that has to know where a component puts its content is a
layout engine; a component system lets the component decide. The slot is the smallest Zig value with
that property — the component calls it, or does not.

## What the compiler trusts, and what it does not

- It validates the **template**, not the IR: every check above happens in the
  transform, where the line number is. The emitter then trusts the IR's shape
  (unchecked field access on the JSON), which is safe because the only producer
  is the transform embedded beside it. If a second producer ever appears, that
  becomes a real boundary and the emitter needs the same guards.
- It does not type-check the generated code. `std.zig.Ast.parse` is syntax; a
  semantic mistake — a name that does not resolve, a field the props struct does
  not have — surfaces in the application's build, which is the design's whole
  intent, but it also means a wrong *prologue* (an import path, a type name)
  passes every test in this module. That is not hypothetical, and the case is worth
  keeping: the emitted signature named `zurtr.live.tree` before the framework root
  exported `tree`, so **every** generated template failed in the caller's build while
  this module's tests stayed green — they lower a template and parse the result, and
  `zurtr.live.tree` is a semantic lookup that parsing never performs (`dae8366`). The
  repair was two things, and the second is the one that stops it recurring: export
  `tree`, and make the names the emitter depends on checkable where both sides are
  visible. `compile.zig` cannot import `zurtr` — that would be a module cycle — so the
  check lives in `src/root.zig`'s test block, which fails the build on
  `@hasDecl(live, "tree")` and `@hasDecl(live.tree, "Builder")` with a message naming
  what broke, instead of leaving the application's build to discover it.

## Testing

`zig build test-zeex -Dzscript=true` runs this module's tests on their own;
`zig build test -Dzscript=true` aggregates them. The compiler can be its own test
root because it imports `zscript` as a **named module** rather than reaching
across a directory boundary — the same reason `jobs`' database-backed tests are
gated through its module root instead of getting a step of their own
(`docs/modules/dev.md`).

The tests pin: the generated source parses (`std.zig.Ast`, the compiler's own
parser, printing the source and token positions when it does not); a bare
attribute lowers to a present attribute with an empty value; a component with
children emits the slot and passes it, a component without them passes `null`, and
a slot carries the loop variables its children use; and the refusals come back as
`TemplateRejected` — an expression after `props.`, and a loop variable named after
something the generated code binds.

They do **not** pin the generated code's types, and they cannot run without
`-Dzscript`, so a base build exercises none of this. The one exception is deliberate:
the two names every emitted file's prologue depends on are asserted in
`src/root.zig`'s test block, because this module's tests cannot see them (`dae8366`).

## Not yet

- No framework build step that lowers a template as part of an application's
  build: the app calls `zeex.compile_template(allocator, @embedFile("tasks.jsx"))`
  and writes/imports the result itself.
- No schema for `props`: the caller's struct is the contract, which is the point,
  but nothing checks that two templates rendering the same shape agree.
- The transform is a hand-written parser over a closed subset; it is not a JSX
  implementation, and it does not intend to become one.
