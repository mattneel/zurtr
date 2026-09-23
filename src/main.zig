//! zurtr — the framework's executable.
//!
//! Applications deploy as one static executable, and this is its entry point: the assembly layer
//! (`src/app/`) will hang off the role selection here. Until that layer lands, the binary still has
//! something true to say — what it was built from — so `zurtr modules` prints the module inventory, which
//! is the same inventory `zurtr build --report` is specified to emit.
//!
//! The command surface grows with the modules: `run --role=web|jobs|agents`, `migrate`, `test`, and
//! `build --report` arrive with the modules they drive. Nothing here pretends to be one of them.

const std = @import("std");
const Io = std.Io;

const zurtr = @import("zurtr");

const usage =
    \\zurtr — a native application framework built on zix.
    \\
    \\  zurtr modules    Print the module inventory this executable was built with.
    \\  zurtr help       Print this.
    \\
    \\Not yet: the assembly and role commands (`run`, `migrate`, `test`, `build --report`) arrive with
    \\the modules they drive.
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const command: []const u8 = if (args.len > 1) args[1] else "help";

    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help")) {
        try stdout.writeAll(usage);
    } else if (std.mem.eql(u8, command, "modules")) {
        try stdout.writeAll("modules:\n");
        for (zurtr.modules) |module| {
            try stdout.print("  {s:<9} {s:<12} {s}\n", .{ module.name, @tagName(module.state), module.surface });
        }
    } else {
        try stdout.print("zurtr: unknown command '{s}'\n\n", .{command});
        try stdout.writeAll(usage);

        try stdout.flush();

        return error.UnknownCommand;
    }

    try stdout.flush();
}

test {
    _ = zurtr;
}
