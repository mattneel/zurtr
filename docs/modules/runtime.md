# Module contract: Runtime (`zurtr.runtime`)

Scope: the concurrency primitives the modules above share — a bounded worker pool with completion
delivery (`src/runtime/pool.zig`), a bounded lock-free MPMC queue (`src/runtime/mpmc.zig`), and
structured tasks with scopes (`src/runtime/task.zig`). Every file here imports `std` and nothing else
in the tree, so the layer adds no dependency of its own; the pool and the task executor are the two
ways work leaves the reactor thread, for a module that needs it.

Status: **implemented** — read the status from `src/root.zig`'s `modules` table, which is the
inventory of record (`zurtr modules` prints it), and whose surface for this module is `pool`. The
rules the rest of the framework holds it to are `contracts.md` §1 — rule 5 (no blocking on a loop
thread, which is why a pool exists at all) and rule 6 (scopes own their tasks, which is the task
layer's whole contract) — and §2, which decides who owns a payload once it crosses a thread.

What the tree shows: `src/root.zig` exports the three files and references them in its test block, so
their tests are part of the binary `zig build test-zurtr` runs. No other module constructs a `Pool`
or an `Executor` yet: the pool's named consumer is the `.ASYNC` lane's fiber, which a completion
resumes (`decisions.md` D2), and the task layer's is a role that wants structured concurrency under a
request.

## The queue (`src/runtime/mpmc.zig`)

`Queue(T)` is Dmitry Vyukov's bounded MPMC queue: a ring of cells, each carrying a sequence number
that says whether the slot is free, filled, or being reserved. Producers and consumers reserve by CAS
on a position counter and then wait for the slot's sequence to catch up, which is what makes it safe
without locks, without hazard pointers, and without the ABA problem a plain index would have — a
slot's sequence is the generation count an index would lose.

Properties, and the price of each, as the file states them:

- **Bounded, allocated once.** Capacity is fixed at `init` and must be a power of two, because the
  ring is indexed by a mask; `push` never allocates. A queue of two is the smallest there is.
- **Non-blocking on both sides.** `push` returns `false` when full and `pop` returns `null` when
  empty; there is no waiting in here at all. The caller decides whether to spin, park, shed or grow,
  because only the caller knows whether a dropped item is a lost job or a stale preview.
- **Linearizable per operation**, not a transaction: a push either happened before a pop observed it
  or after, and nothing else is promised.
- **Value semantics.** `T` is copied through the slot; the queue is a hand-off, not a mailbox, so keep
  it small.
- **One cache line per slot**, so neighbouring slots do not share a line between a producer and a
  consumer. `len` is a plain atomic for diagnostics and bounds — the algorithm never reads it.

Its own doc names the three things it is the substrate for: the pool's per-worker intake rings, where
a thief takes work from another worker; cross-worker completion delivery, where a job or agent thread
hands a result to the worker that owns the session (the deferred-handle model in `overview.md`
§Execution model); and the boundary where the framework's "worker-local, no shared mutable state" rule
becomes explicit, because a queue is exactly as much sharing as two threads are allowed to have.

## The pool (`src/runtime/pool.zig`)

`Pool` is a bounded worker pool with completion delivery: work items run on pool threads, and results
are pushed to a bounded completion queue the consumer drains. The contract the file states:

- `submit` never blocks the caller beyond a bounded queue push: when every worker's ring is full it
  returns `error.QueueFull`, and the caller decides whether to shed, park or retry. The pool never
  grows without bound.
- A completion is delivered exactly once: either drained by the consumer, or freed by `drain`/
  `deinit`.
- The work function runs on a pool thread with no reactor state; it must not touch session state or
  transport structures, and it returns an owned payload that the completion carries back.

Intake is per-worker rings with stealing — round-robin push, then a bounded scan, and a worker with an
empty ring takes from a neighbour — so a submit never waits on whoever happens to be running. Two
choices are deliberate and stated: **parking is signalled**, with a timeout only as a guard against a
missed wakeup (the push is lock-free and therefore outside the mutex, so the signal is the mechanism
and the timeout bounds the damage if it is ever lost), and **the completion queue keeps one mutex**,
because its consumer is the reactor — single-threaded — and its producers are already the pool's own
threads: there is no stealing to do there, and the contention worth removing is on the intake, where
producers are arbitrary threads.

The consumer side has three shapes: `drain` (non-blocking, for the reactor), `drainBlocking` (for
tests and callers that want to wait), and `freePayload` — a payload belongs to whoever drains it
(`contracts.md` §2). `setWake` lets the owner name a wake callback, called after a completion is
enqueued so the consumer can be woken; there is no transport wake fd in this tree, which is the other
half of why completions are delivered in the `.ASYNC` lane (`decisions.md` D2).

## Structured tasks (`src/runtime/task.zig`)

A task does not outlive the scope that spawned it. `Scope.end` cancels and waits for every child
before it returns, and that is the whole contract: "the function returned" means "everything it
started is finished", without anyone remembering to join anything. Scopes nest implicitly in the task
rather than being wired up by the caller — a spawned task carries its own scope (`Task.scope`), which
is where its children go, and that scope is reaped (cancel, then wait) when the body returns. What
comes out is a tree:

```
caller's scope ── task A ── A's scope ── task A1 ── A1's scope ── …
```

Two consequences the file states plainly: a body that returns while its children are still running
has them cancelled, and a task's failure is reported to the scope that spawned it — never swallowed,
never left in a log line nobody reads.

### Cancellation

Cooperative, and one direction only: down the tree. `Scope.cancel` sets a flag, descendants read
their way up the parent chain (`Scope.isCancelled` is one atomic load per level, which is why a
cancel needs no child list to walk), and a task observes it at a yield point:

```zig
fn body(task: *zurtr.runtime.task.Task, args: Args) !void {
    while (true) {
        try task.checkCancel(); // error.Cancelled when this scope or an ancestor is cancelled
        do_one_unit(args);
    }
}
```

One atomic store to cancel and one atomic read at the yield point make `cancel` safe from any thread,
including from another task — which is exactly how `.cancel_scope` and `.fail_scope` reach their
siblings. A task that never checks is a bug its caller owns: nothing here preempts native code.

`error.Cancelled` is not a failure when the task was really cancelled — that is the answer
cancellation asks for, and counting it as failure would make every clean shutdown look broken — while
a task that returns `error.Cancelled` without being cancelled *is* one: it invented it. Cancellation
is therefore not in `WaitError`, and `Scope.isCancelled` is how a caller asks whether it happened.

### Failure

A failure goes to the scope that spawned the task, and the scope's `FailurePolicy` decides what it
means: `.ignore` (record it, keep going), `.cancel_scope` (record it, cancel the scope's other tasks),
`.fail_scope` (record it, cancel, and make `Scope.wait` return `error.Failed`) — the default, because
silence is the one thing this layer must not do by default. `Scope.wait` is the raising form;
`Scope.end` never raises, since cancellation is its own act.

Recording happens under every policy. "Ignore" decides a failure is not an emergency, never that it
did not happen, and `failureCount` is how a caller finds out it did; the details are capped at
`max_failures = 8` while the count keeps rising, because a failure list is a diagnostic, not a ledger.
A task whose own subtree failed re-reports that failure outward with `Failure.from_children` set and
the child's error rather than a synthetic "child failed" code, so a failure under `.fail_scope`
anywhere in a tree reaches the root's `wait`, and `Failure` names the task it happened in.

### Execution, and what helping costs

Tasks run on real threads. `Executor` is one lock-free intake ring per worker — pop your own, then
steal from the others, the same rule as the pool — with the same signalled parked wait and the same
timeout guard. Beyond that it does one thing the pool has no reason to: a thread waiting for a scope
to drain **helps**, stealing queued tasks and running them while it waits. On a bounded executor whose
workers can all end up waiting for their own children at once — which a nested tree makes the normal
case rather than a corner — a waiter that only slept would deadlock the tree it is waiting for, so
the wait is work.

That has exactly one consequence a body must respect, and the file writes it as a rule: **do not hold
a lock across a scope wait.** If the task this thread helps with needs the lock this thread is already
holding, the lock is not recursive and the thread waits for itself; `runtime/task.zig`'s
"a waiter holding a lock" test is the reproduction, written to be deterministic rather than a race.
Everything else about helping is safe by construction, and it is the failure shape a thread-local
design would have: scope parentage is explicit in the task (`Task.inner`, set when the task is
created) and never ambient, so a task running inside a waiter's frame still spawns into its own scope.

One workflow is worth naming, because it explains an absence: `Scope.spawn` submits, a worker takes
the task and never gives it back, and `Scope.wait`/`end` waits on a **count** rather than on a
completion queue. Nothing here needs a result path or a completion queue's mutex; the count and the
condition that carries it belong to the scope, which is the thing that has to know.

### Lifetime discipline

What Zig can enforce here at compile time is the shape of a task body — a plain function pointer
(`fn (*Task, Args) void` or `!void`), so nothing captures the spawning frame by accident. The rest is
enforced at runtime, cheaply:

- Task records for a whole tree come from one arena owned by the root scope. Nothing is freed per
  task, and nothing can be freed while a task in that tree is alive: the root's `deinit` frees it, and
  the root's `end` has already reaped everything below it.
- `Scope.end` asserts the pending count is zero before it closes, and a spawn into a closed scope is
  `error.ScopeClosed` — including into the scope of a task that has already returned.
- `Task.checkCancel` asserts, in debug builds, that the task is still running: a task executing after
  its scope returned is precisely the violation this layer exists to prevent, and its yield point is
  the cheapest place to catch it.

Handles stay readable until the *root* scope is destroyed, because their records live in that arena:
after `Scope.wait`, `Task.result` and `Task.scope().firstFailure()` are how a caller does the
post-mortem.

`Executor.deinit` is the other direction of the same rule, and it is not a cancel: a queued task will
never run, so it is *failed* with `error.ExecutorShutdown` rather than dropped on the floor — its
scope's pending count moves and no scope waits forever for a worker that no longer exists. Tasks
already running are not interrupted; nothing may be blocked in a scope wait while this runs, and
cancelling your scopes first is what `Scope.end` is for.

### ZScript

A long-running scripted task is not preempted by the engine either, and does not need to be: QuickJS
polls an interrupt callback every N reductions, so a scripted task gets the *same* flag at a different
yield point. Install the callback once per runtime with the task as its userdata and the handler body
is `Task.scriptInterrupt` — next to `Task.checkCancel` for native code, and deliberately not a second
cancellation mechanism. The host that evaluates a zscript body inside a task turns the engine's
interrupt into `error.Cancelled` for the task: preemption for scripts, cooperation for native, one
flag under both (`docs/modules/zscript.md`).

## Tests

`zig build test-zurtr` runs these. There is no `test-runtime` step and no need for one: the root's
test block references all three files, so their tests are in that binary already.

| File | What its tests pin |
| :- | :- |
| `mpmc.zig` | a queue of capacity two holds two and refuses the third; the ring wraps without losing or duplicating a value; capacity must be a power of two; four producers and eight consumers hand over every value exactly once |
| `pool.zig` | work runs and delivers an owned completion; a single worker preserves order; the pending bound is enforced (`QueueFull`); `deinit` frees completions nobody drained; work is shared across workers rather than serialized on one |
| `task.zig` | a scope waits for every child before it returns; tasks run on real threads and two of them can meet; returning from a scope cancels its children and waits; the zscript seam reads the same flag a native check does; cancellation is not failure and an invented cancellation is; the three policies do what they say; cancellation reaches inward while failure is observed outward; a scope that has returned refuses new tasks; an executor torn down with work queued fails that work instead of leaving a scope waiting; the waiter-and-lock reproduction; a 63-task, five-level tree making progress on two workers, which is the claim helping exists for; and a nested-spawn stress test where a leak fails the test |

## What is not here

- **No wake source for the loop models.** The pool's wake callback is a hook its owner sets, and
  nothing in the tree can wake `.EPOLL`/`.URING` from another thread; deferral is confined to
  `.ASYNC` (`decisions.md` D2).
- **No preemption and no per-task stack.** A body that blocks forever holds a worker thread. The
  framework's answer is the executor's size and the help rule, not a scheduler.
- **No priority, and no stealing across executors.** Every ring is FIFO, and a task is taken by a
  worker of its own executor (or by a waiter in that executor's tree).
