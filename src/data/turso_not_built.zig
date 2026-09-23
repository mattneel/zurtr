//! Placeholder for the `turso` import in builds that do not build the adapter.
//!
//! The adapter's source names the binding, and a Zig import name has to resolve whether or not the
//! branch using it is ever analyzed — so a build without `-Dturso` still needs *something* here. This
//! file is that something, and nothing else: reaching it means asking for the Turso adapter in a build
//! that did not ask for the binding, and the message says exactly that instead of failing later at a
//! link step with a page of missing symbols.

comptime {
    @compileError("the Turso data adapter is not built in this configuration: pass -Dturso=true (it compiles the native SDK Kit from Rust source)");
}
