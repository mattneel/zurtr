# Module contract: ZScript (`zurtr.zscript`)

Scope: ZScript, the optional scripting layer. QuickJS-ng through the vendored binding at
`deps/quickjs-ng`, giving the application behavior the host can replace without a
native rebuild. It is a *layer* rather than one of the seven modules: nothing
below it depends on it, and everything above it can.

Status: implemented behind `-Dzscript` (`src/zscript/root.zig`); the base build
contains no engine, and the `zeex` template compiler (`src/zeex/compile.zig`) is
the one caller in the tree — it runs the JSX transform as a build-time script.

## The boundary

Scripts define behavior; the host defines what behavior is allowed to *reach*.

- The script's reach is exactly the set of host functions registered with
  `Script.registerHost`. It cannot open a database, a socket, or a file on its
  own, and it does not need to: a host function is where an action's rules live.
- A host function applies authorization, validation and transaction rules in
  Zig — the same code an HTTP request or a live event would go through — and
  returns a value. The script's opinion about its own authority is not an input
  to that decision.
- Durable state lives outside the JavaScript heap, in `zurtr.data`. A reload
  changes the rules the next event is decided under; it never erases the
  application.

## Revisions

A loaded script carries a revision (`Script.revision`). Loading a new revision
into the same runtime replaces what the next call runs. Anything that recorded
the revision it started with keeps running it — the rule `contracts.md` §7
already states for actions, jobs and agent workflows, applied to script:

- a new event is decided by the current revision;
- an action already in flight finishes under the revision it began with;
- a durable job records its revision and retries under it, so a retry cannot
  silently start behaving differently;
- a snapshot whose version does not match the running code is discarded rather
  than partially migrated.

Enforcement is the caller's: this module records the revision, and the caller is
the one that knows what a job recorded.

## What the engine requires of the host

Two rules that are easy to get wrong, both of which cost time here:

- **Input is a C string, and the length parameter is what makes that easy to get
  wrong.** `Context.eval` parses its input as NUL-terminated, so a slice with an
  undefined tail is read past the end. `load` takes `[:0]const u8` for that
  reason, and `callInt` terminates its own buffer. Zig string literals already
  satisfy it; anything read from a file or built at runtime must be terminated by
  its producer.

  The engine is the origin of the rule, not an innocent above it: `JS_Eval()`
  scans while `*p == '\0' && p >= s->buf_end`, so the sentinel is the contract
  and the length is not. The trap is that these APIs *take* a length, which reads
  as "so I do not need a terminator" — three layers of this stack have been
  caught by it, and every time the failure was a plausible wrong answer rather
  than an error. The engine's own instance reported `ReferenceError: Datea is not
  defined`, having absorbed the byte after the buffer and made an identifier of
  it.
- **The wasm stack region and the engine's default limit are both 1 MiB.**
  QuickJS defaults to a 1 MiB stack, which in a `wasm32-freestanding` module is
  the entire stack the host gave it: `stack_top - stack_size` wraps, the guard
  fails every evaluation, and nothing says why until `updateStackTop` is told the
  real depth.

- **A host function's result owns a reference.** The arguments are borrowed for
  the call, and returning one of them unmodified under-retains it: the engine
  then frees something it still counts as live. Return a fresh value
  (`Value.init*`) or `dup` the borrowed one. The mirror image is just as costly
  — a value the host creates and hands to `setPropertyStr` is *adopted*, and
  releasing it again over-releases the property.

Both mistakes surface as assertions inside QuickJS at runtime teardown rather
than as errors at the call site, which is why they are written down here.

## Surface

```zig
pub const Script = struct {
    pub fn init() Error!Script;
    pub fn deinit(self: *Script) void;
    pub fn load(self: *Script, name: [:0]const u8, source: [:0]const u8, revision: Revision) Error!void;
    pub fn registerHost(self: *Script, comptime func: quickjs.cfunc.Func, name: [:0]const u8, argc: c_int) Error!void;
    pub fn callInt(self: *Script, name: [:0]const u8, argument: i32) Error!i32;
    pub fn callText(self: *Script, name: [:0]const u8, input: []const u8, allocator: std.mem.Allocator) Error![]u8;
    pub fn errorDetail(self: *const Script) []const u8;
};
```

`callInt` is deliberately small — a call is built as `name(argument)` and
evaluated — and it is the shape that proves the seam: a revision loads, a call
runs it, and a second revision changes the answer. Typed arguments for domain
actions, QuickJS module definitions (`ModuleDef`, which `jzs` uses for exactly
this), and per-context host state through `Context.setOpaque` come next, and
none of them changes this shape.

`errorDetail` exists because a host that cannot say why a script threw is a poor
host: the engine's own message for the last throw is kept, not discarded.

## Build

The engine compiles QuickJS-ng's C through Zig and needs the LLVM backend, so it
is behind `-Dzscript`: the base build does not ask for it, and the `quickjs`
import resolves to a file whose whole content is a compile error naming the flag.
`zig build test-zscript -Dzscript=true` runs the layer's tests.

## Testing requirements

- A revision loads, is called, and is replaced: the second revision changes the
  answer with no rebuild.
- A script reaches host functions and nothing else.
- A revision that throws is not adopted, and the host survives it.
