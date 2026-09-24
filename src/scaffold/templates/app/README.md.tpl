# {{name}}

A [zurtr](https://github.com/mattneel/zurtr) application: one static executable serving HTTP/1.1
through the vendored zix transport.

## Run it

```sh
zig build run
```

It prints the address it serves on before it binds it. The port comes from `PORT` and defaults to
8080; the interface is `127.0.0.1`, both in `src/main.zig`.

| Route | What it answers |
| :- | :- |
| `/` | a page naming this process |
| `/healthz` | `{"status":"ok"}`, for a supervisor |
{{#if live}}| `/live` | the live channel: a WebSocket carrying `zurtr.live.protocol` frames |

{{/if}}{{#if data}}At startup the process opens `{{name}}.db` at the data module's file tier, records one row per
start, and closes it when it is asked to stop with `SIGINT` or `SIGTERM`. That file is state rather
than source, which is why `.gitignore` lists it.

{{/if}}## Where the pieces are

| File | What it holds |
| :- | :- |
| `src/main.zig` | the routes, the live frame handler, and the process lifecycle |
| `build.zig` | the executable, and how the framework is asked for its optional modules |
| `build.zig.zon` | the package's identity, and the zurtr dependency `zig fetch --save` recorded |

`zurtr` is a path dependency: this project builds against the checkout it was generated from, so if
that checkout moves, the path in `build.zig.zon` moves with it.
