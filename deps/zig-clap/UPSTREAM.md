# zig-clap, vendored

Vendored rather than fetched, like the rest of this tree's dependencies: `zig build` needs no
network, and a version that changes under a build is a build that changes under a user.

- **Upstream**: https://github.com/Hejsil/zig-clap
- **Commit**: `05faf3905e8548f5cc269a8836e154065e70128d` (2026-08-31T15:43:07+02:00)
- **Why**: `zurtr new` has enough flags that hand-rolled parsing would be wrong in the ways
  hand-rolled parsing is wrong — a missing option value silently becoming an empty string,
  `--flag=value` and `--flag value` disagreeing, an unknown flag ignored rather than reported.
- **Its minimum Zig** is `0.17.0-dev.1941`, this tree pins `0.17.0-dev.2264`.

The `.git` directory is removed on purpose: this is a copy, not a submodule, so the tree it is
vendored into stays the only history that matters.
