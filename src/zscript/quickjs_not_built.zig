//! Placeholder for the `quickjs` import in builds that do not build the script layer.
//!
//! The seam names the binding, and a Zig import name has to resolve whether or not the branch using it
//! is ever analyzed. Reaching this file means asking for the script layer in a build that did not ask
//! for the engine, and the message says exactly that.

comptime {
    @compileError("the script layer is not built in this configuration: pass -Dzscript=true (it compiles QuickJS-ng through Zig and links it with LLVM)");
}
