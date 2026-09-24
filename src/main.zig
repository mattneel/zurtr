//! zurtr — the framework's executable.
//!
//! Applications deploy as one static executable, and this is its entry point. Two commands exist
//! today: `modules`, which prints the inventory this executable was built with, and `new`, which
//! generates an application.
//!
//! `new` runs the toolchain's own scaffold and then lays this framework over it — `zig init`, then
//! `zig fetch --save` for the dependency, then the template in `src/scaffold.zig`. That order is why
//! there is no `build.zig.zon` in the template: zig writes it, including the fingerprint it
//! validates against a CRC of the project name, and `zig fetch --save` patches the dependency in.
//!
//! The command surface grows with the modules: `run --role=web|jobs|agents`, `migrate`, `test`, and
//! `build --report` arrive with the modules they drive. Nothing here pretends to be one of them.

const std = @import("std");
const Io = std.Io;
const clap = @import("clap");

const zurtr = @import("zurtr");
const scaffold = @import("scaffold.zig");
const cli_options = @import("cli_options");

/// The whole command surface, and the help text at once: clap renders this string for `--help`.
///
/// `--no-` spellings rather than `--with-`: the default scaffold is the one worth having, and a
/// generator whose defaults are wrong is a generator nobody reads the flags of.
const params = clap.parseParamsComptime(
    \\-h, --help                 Print this help and exit.
    \\    modules                Print the module inventory this executable was built with.
    \\    new                    Generate an application in a directory named after it.
    \\    --name <str>           The project name (default: the directory name).
    \\    --dir <str>            Where to generate (default: the project name).
    \\    --force                Generate into a directory that already exists.
    \\    --no-data              Leave out the persistence wiring.
    \\    --no-live              Leave out the live UI route.
    \\    --zscript              Include the script seam (costs a C toolchain and a slow first build).
    \\    --no-hooks             Skip the installer steps.
    \\    --install              Also run the steps that compile, which take minutes the first time.
    \\<str>...
    \\
);

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, init.minimal.args, .{
        .diagnostic = &diag,
        .allocator = gpa,
    }) catch |err| {
        // clap's own report is better than anything this file could say about a malformed command.
        try diag.reportToFile(init.io, .stderr(), err);

        return err;
    };
    defer res.deinit();

    const positionals = res.positionals[0];
    const command: []const u8 = if (positionals.len > 0) positionals[0] else "help";

    if (res.args.help != 0 or std.mem.eql(u8, command, "help")) {
        try clap.usage(stdout, clap.Help, &params);
    } else if (std.mem.eql(u8, command, "modules")) {
        try stdout.writeAll("modules:\n");
        for (zurtr.modules) |module| {
            try stdout.print("  {s:<9} {s:<12} {s}\n", .{ module.name, @tagName(module.state), module.surface });
        }
    } else if (std.mem.eql(u8, command, "new")) {
        try generate(init, res.args, positionals, stdout);
    } else {
        try stdout.print("zurtr: unknown command '{s}'\n\n", .{command});
        try clap.usage(stdout, clap.Help, &params);
        try stdout.flush();

        return error.UnknownCommand;
    }

    try stdout.flush();
}

fn generate(
    init: std.process.Init,
    args: anytype,
    positionals: []const []const u8,
    stdout: *std.Io.Writer,
) !void {
    // The name comes from `--name` or from the positional, in that order, because `new` is spelled
    // two ways in practice: `zurtr new blog` and `zurtr new --name blog`.
    const name = args.name orelse blk: {
        if (positionals.len < 2) {
            try stdout.writeAll("zurtr new: a project name is required\n");

            return error.NameRequired;
        }

        break :blk positionals[1];
    };

    // clap names each result field after the flag verbatim, so `--no-data` is `@"no-data"` — the
    // dashes are part of the identifier. Spellings without dashes would read better here and worse
    // at the command line, and the command line is the thing a user types.
    const options: scaffold.Options = .{
        .name = name,
        .dir = args.dir orelse name,
        .force = args.force != 0,
        .data = args.@"no-data" == 0,
        .live = args.@"no-live" == 0,
        .zscript = args.zscript != 0,
        .hooks = args.@"no-hooks" == 0,
        .install = args.install != 0,
    };

    // The executable carries both of these from the build rather than discovering them: where this
    // checkout is, so the generated project can depend on it, and which compiler to drive, because
    // a `zig` on PATH may be a launcher shim that cannot resolve a version in an empty directory.
    const toolchain: scaffold.Toolchain = .{
        .zurtr_path = cli_options.zurtr_source_path,
        .zig_exe = cli_options.zig_exe,
    };

    try stdout.print("generating {s} in {s}\n", .{ options.name, options.dir });
    try stdout.flush();

    scaffold.generate(init.gpa, init.io, options, toolchain, stdout) catch |err| {
        // The state is worth reporting: a generator that fails halfway leaves a directory, and the
        // person reading this has to decide whether to keep it.
        try stdout.print("zurtr new: failed at {s}, leaving {s} as it is\n", .{ @errorName(err), options.dir });
        try stdout.flush();

        return err;
    };

    try stdout.print("\n{s} is ready:\n  cd {s}\n  zig build run\n", .{ options.name, options.dir });
}

test {
    _ = zurtr;
    _ = scaffold;
}

// The generated project's `build.zig.zon` gets a path relative to *it*, computed from this one — and
// a relative value here is not a small error, it is the whole feature failing: the first version
// embedded `"."`, and `zig fetch --save` was handed `../../../.` from the new project, which is the
// filesystem root.
//
// At file scope rather than in a test block on purpose. `zig build` builds this executable and never
// runs its tests, so a guard inside `test {}` would have compiled and never fired — which is exactly
// what the first version of this guard was.
comptime {
    if (!std.fs.path.isAbsolute(cli_options.zurtr_source_path)) {
        @compileError("cli_options.zurtr_source_path is relative (" ++ cli_options.zurtr_source_path ++
            "); the generator cannot make it relative to a project it has not created yet");
    }
}
