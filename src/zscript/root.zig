//! `zurtr.zscript` — the QuickJS seam.
//!
//! Scripts define behavior; the host defines what behavior is allowed to *reach*. That is the whole
//! boundary: a script can call the host functions the host registered and nothing else, so replacing a
//! script revision changes what the application decides without changing what it is permitted to do.
//!
//! # Why revisions
//!
//! A loaded script carries a revision. Loading a new revision into the same runtime replaces what the
//! next call runs, while anything that recorded the revision it started with keeps running it — the same
//! rule `docs/architecture/contracts.md` §7 states for actions and jobs. Durable state lives outside the
//! JavaScript heap (in `zurtr.data`), so a reload never erases the application: it changes the rules the
//! next event is decided under.
//!
//! # Scope
//!
//! This is the seam, not a language binding: loading a revision, registering host functions, and calling
//! a script function with one integer argument and one integer result. Typed arguments for domain
//! actions, module definitions (QuickJS's `ModuleDef`), and per-context host state through
//! `Context.setOpaque` are the next steps, and none of them changes the shape here.

const std = @import("std");
const quickjs = @import("quickjs");

/// Which revision of a script is loaded. Recorded, not enforced: enforcement is the caller's job, and
/// the caller is the one that knows what a job recorded.
pub const Revision = u32;

pub const Error = error{
    /// The script threw while being loaded, or while a call was running.
    ScriptThrew,
    /// The host function could not be published to the script.
    HostRegistrationFailed,
    /// The runtime could not be created.
    RuntimeUnavailable,
};

pub const Script = struct {
    runtime: *quickjs.Runtime,
    context: *quickjs.Context,
    /// The revision currently loaded. Zero before the first load.
    revision: Revision = 0,
    /// The engine's own message for the last throw, when it had one. A load or a call that failed says
    /// why out of this buffer rather than leaving the caller to guess.
    error_detail: [256]u8 = @splat(0),
    error_len: usize = 0,

    pub fn init() Error!Script {
        const runtime = quickjs.Runtime.init() catch return error.RuntimeUnavailable;
        errdefer runtime.deinit();

        const context = quickjs.Context.init(runtime) catch return error.RuntimeUnavailable;

        return .{ .runtime = runtime, .context = context };
    }

    pub fn deinit(self: *Script) void {
        self.context.deinit();
        self.runtime.deinit();
    }

    /// Load a script revision, replacing whatever the runtime had.
    ///
    /// The source is evaluated as a script in the global scope, so it may define functions the host
    /// calls later. A throw is reported as `error.ScriptThrew` — and the runtime keeps running, because a
    /// revision that does not load must not take the host with it.
    /// The source must be NUL-terminated: the engine parses it as a C string, and a slice with an
    /// undefined tail is read past the end. Zig string literals already are; anything read from a file
    /// or built at runtime has to be terminated by its producer.
    pub fn load(self: *Script, name: [:0]const u8, source: [:0]const u8, revision: Revision) Error!void {
        const result = self.context.eval(source, name, .{});
        defer result.deinit(self.context);

        if (result.isException()) {
            self.recordThrow();

            return error.ScriptThrew;
        }

        self.revision = revision;
    }

    /// What the last throw said, if it said anything.
    pub fn errorDetail(self: *const Script) []const u8 {
        return self.error_detail[0..self.error_len];
    }

    fn recordThrow(self: *Script) void {
        self.error_len = 0;

        // `eval` reports a throw as the engine's sentinel, which carries no text; the message lives in
        // the context's pending exception, and reading it clears that.
        const thrown = self.context.getException();
        defer thrown.deinit(self.context);

        const text = thrown.toCString(self.context) orelse return;
        defer self.context.freeCString(text);

        const message = std.mem.span(text);
        self.error_len = @min(message.len, self.error_detail.len);
        @memcpy(self.error_detail[0..self.error_len], message[0..self.error_len]);
    }

    /// Publish a host function to the script's global scope.
    ///
    /// This is the authority boundary: the script's reach is exactly the set of functions registered
    /// here, and each one runs host code that applies the host's own rules — authorization, validation,
    /// transactions — rather than trusting anything the script says about itself.
    pub fn registerHost(self: *Script, comptime func: quickjs.cfunc.Func, name: [:0]const u8, argc: c_int) Error!void {
        const function = quickjs.Value.initCFunction(self.context, func, name, argc);
        // The property adopts the reference, so there is nothing to release here even on success.
        const global = self.context.getGlobalObject();
        // The global object, on the other hand, is an owned reference: hanging on to it leaves an object
        // alive for the runtime's lifetime, and QuickJS refuses to free a runtime that still has one.
        defer global.deinit(self.context);

        global.setPropertyStr(self.context, name, function) catch {
            function.deinit(self.context);

            return error.HostRegistrationFailed;
        };
    }

    /// Call a script function with one string and read one string back, copying the result into
    /// `allocator`. Used by build-time tooling — the ZEEX transform is a script the build runs.
    ///
    /// The argument crosses as a JSON string literal, which is valid JavaScript, so the escaping is done
    /// once here rather than at every call site.
    pub fn callText(
        self: *Script,
        name: [:0]const u8,
        input: []const u8,
        allocator: std.mem.Allocator,
    ) Error![]u8 {
        var literal = std.ArrayList(u8).empty;
        defer literal.deinit(allocator);
        literal.append(allocator, '"') catch return error.ScriptThrew;
        for (input) |byte| {
            switch (byte) {
                '"' => literal.appendSlice(allocator, "\\\"") catch return error.ScriptThrew,
                '\\' => literal.appendSlice(allocator, "\\\\") catch return error.ScriptThrew,
                '\n' => literal.appendSlice(allocator, "\\n") catch return error.ScriptThrew,
                '\r' => literal.appendSlice(allocator, "\\r") catch return error.ScriptThrew,
                '\t' => literal.appendSlice(allocator, "\\t") catch return error.ScriptThrew,
                0...8, 11, 12, 14...31 => {
                    var escaped: [6]u8 = undefined;
                    const text = std.fmt.bufPrint(&escaped, "\\u{x:0>4}", .{byte}) catch return error.ScriptThrew;
                    literal.appendSlice(allocator, text) catch return error.ScriptThrew;
                },
                else => literal.append(allocator, byte) catch return error.ScriptThrew,
            }
        }
        literal.append(allocator, '"') catch return error.ScriptThrew;

        var call = std.ArrayList(u8).empty;
        defer call.deinit(allocator);
        call.appendSlice(allocator, name) catch return error.ScriptThrew;
        call.append(allocator, '(') catch return error.ScriptThrew;
        call.appendSlice(allocator, literal.items) catch return error.ScriptThrew;
        call.append(allocator, ')') catch return error.ScriptThrew;

        // The engine parses its input as a C string, so the call is terminated before it is evaluated.
        call.append(allocator, 0) catch return error.ScriptThrew;
        const terminated: [:0]u8 = call.items[0 .. call.items.len - 1 :0];

        const result = self.context.eval(terminated, "<zeex>", .{});
        defer result.deinit(self.context);

        if (result.isException()) {
            self.recordThrow();

            return error.ScriptThrew;
        }

        const text = result.toCString(self.context) orelse return error.ScriptThrew;
        defer self.context.freeCString(text);

        return allocator.dupe(u8, std.mem.span(text)) catch error.ScriptThrew;
    }

    /// Call a script function with one integer, and read one integer back.
    ///
    /// Deliberately small: a call is built as `name(argument)` and evaluated. Typed arguments will come
    /// through the binding's own call interface, and when they do, callers here do not change.
    pub fn callInt(self: *Script, name: [:0]const u8, argument: i32) Error!i32 {
        var buf: [128]u8 = undefined;
        const call = std.fmt.bufPrint(&buf, "{s}({d})", .{ name, argument }) catch return error.ScriptThrew;

        // Same rule as `load`: the buffer is terminated before the engine sees it.
        buf[call.len] = 0;

        const result = self.context.eval(buf[0..call.len :0], "<call>", .{});
        defer result.deinit(self.context);

        if (result.isException()) {
            self.recordThrow();

            return error.ScriptThrew;
        }

        return result.toInt32(self.context) catch error.ScriptThrew;
    }
};

test "a script revision can be replaced under a running host" {
    var script = try Script.init();
    defer script.deinit();

    // Revision one: the rule the application started with.
    script.load("rules-r1.js",
        \\globalThis.decide = function (score) { return score * 2; }
    , 1) catch |err| {
        std.debug.print("load failed: {s}\n", .{script.errorDetail()});

        return err;
    };
    try std.testing.expectEqual(@as(Revision, 1), script.revision);
    const doubled = script.callInt("decide", 21) catch |err| {
        std.debug.print("call failed: {s}\n", .{script.errorDetail()});

        return err;
    };
    try std.testing.expectEqual(@as(i32, 42), doubled);

    // Revision two into the same runtime, same host, same durable state: the decision changes and
    // nothing was rebuilt.
    try script.load("rules-r2.js",
        \\globalThis.decide = function (score) { return score + 100; }
    , 2);
    try std.testing.expectEqual(@as(Revision, 2), script.revision);
    try std.testing.expectEqual(@as(i32, 121), try script.callInt("decide", 21));
}

test "a script calls host functions and nothing else" {
    var script = try Script.init();
    defer script.deinit();

    try script.registerHost(hostGranted, "granted", 1);

    // The script's whole reach is what the host published. It calls in, and the host decides what the
    // answer is; the script cannot reach the database, the filesystem, or the network on its own.
    try script.load("uses-host.js",
        \\globalThis.ask = function (id) { return granted(id); }
    , 1);

    try std.testing.expectEqual(@as(i32, 7), try script.callInt("ask", 7));
}

test "a script that throws does not take the host with it" {
    var script = try Script.init();
    defer script.deinit();

    try std.testing.expectError(error.ScriptThrew, script.load("broken.js",
        \\function fine() { return 1; }
        \\throw new Error("no");
    , 1));

    // The failed revision is not adopted, and the runtime still works.
    try std.testing.expectEqual(@as(Revision, 0), script.revision);
    try script.load("ok.js",
        \\globalThis.fine = function () { return 5; }
    , 2);
    try std.testing.expectEqual(@as(i32, 5), try script.callInt("fine", 0));
}

/// A host function: the identity of one argument, standing in for a domain action that would check a
/// principal and run in a transaction.
fn hostGranted(ctx: ?*quickjs.Context, _: quickjs.Value, args: []const quickjs.c.JSValue) quickjs.Value {
    if (args.len < 1) return quickjs.Value.undefined;

    // The arguments are borrowed for the call, and a host function's result owns a reference: handing
    // the borrowed value straight back under-retains it, and the engine then frees something it still
    // counts as live.
    return quickjs.Value.fromCVal(args[0]).dup(ctx.?);
}
