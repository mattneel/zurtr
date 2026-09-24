# {{name}}: what the build and the database leave behind. Nothing here is source.
.zig-cache/
zig-out/
{{#if data}}
# The file tier keeps its state in this file and in whatever the engine writes beside it.
{{name}}.db*
{{/if}}
