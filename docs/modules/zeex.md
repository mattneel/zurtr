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
| `MalformedIr` | the IR is not one this emitter understands | partly: a component carrying children, and a non-empty `otherwise`, print what they refused; an unknown op or attribute kind returns silently |
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
exported from the framework root — it is named in every file this module emits;
see `docs/architecture/decisions.md` and `src/root.zig`.)

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
- children on a component (below);
- a bare `}` that opens no interpolation, an unterminated element/interpolation,
  trailing input, and an attribute value that is neither quoted nor braced.

Boundaries worth stating as boundaries:

- there is no `else` and no ternary: only `{cond && <el>}`;
- iteration is single-variable; a loop variable cannot itself be iterated;
- a component takes attributes only (see below);
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
| `element` | `{tag, attrs, children}` | see "Components" |

A path is an array. `["$item"]` — the `$` form — is the enclosing `for`'s loop
variable and must be a single segment; anything else is a field of `props`, so a
loop variable can never be mistaken for a property. Attribute values are
`{kind:"static",value}`, `{kind:"path",path}`, or `{kind:"toggle"}` (a bare
attribute: present, rendered as an empty value, which is what an HTML boolean
attribute means). `AttrSpec.value == null` would *omit* an attribute, so a bare
attribute must not go that route.

## Components are a spelling convention

A capitalised tag is a component call. `props` carries the component, the
attributes become its argument struct, and the Builder comes last:

```
<Card title={props.title}/>   →   try props.Card(.{ .title = props.title }, b);
```

A lowercase tag becomes the render-tree calls instead — `try b.element("div",
&.{ …attrs… }, 0);`, then its children, then `try b.close();`.

**Open: a component may not take children.** Children are currently *refused*
(`<Card><p>…</p></Card>` is a `TemplateRejected` naming the line), because the
emitter has nowhere to put them and silently dropping them is worse. Whether a
component takes them as `props.children`, takes a fragment, or stays
unsupported is a product decision that has not been made; the emitter also
refuses an IR that carries children for a capitalised tag, so a second producer
cannot reintroduce the silent drop.

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
  passes every test in this module. That happened: the emitted signature named
  `zurtr.live.tree` before the framework root exported it, so every generated
  template failed in the caller's build while this module's tests stayed green.

## Testing

`zig build test-zeex -Dzscript=true` runs this module's tests on their own;
`zig build test -Dzscript=true` aggregates them. The compiler can be its own test
root because it imports `zscript` as a **named module** rather than reaching
across a directory boundary — the same reason `jobs`' database-backed tests are
gated through its module root instead of getting a step of their own
(`docs/modules/dev.md`).

The tests pin: the generated source parses (`std.zig.Ast`, the compiler's own
parser, printing the source and token positions when it does not); a bare
attribute lowers to a present attribute with an empty value; and the refusals come
back as `TemplateRejected` — component children, an expression after `props.`,
a loop variable the generated code binds.

They do **not** pin the generated code's types, and they cannot run without
`-Dzscript`, so a base build exercises none of this.

## Not yet

- No framework build step that lowers a template as part of an application's
  build: the app calls `zeex.compile_template(allocator, @embedFile("tasks.jsx"))`
  and writes/imports the result itself.
- No schema for `props`: the caller's struct is the contract, which is the point,
  but nothing checks that two templates rendering the same shape agree.
- Component children (open, above).
- The transform is a hand-written parser over a closed subset; it is not a JSX
  implementation, and it does not intend to become one.
