import { defineConfig } from "tsdown";

// This file is only read when it is named: tsdown's `--no-config` defaults to true, so a bare
// `tsdown` invocation ignores every setting below and quietly builds with the defaults. The
// package script passes `-c`, and that is load-bearing rather than tidiness.

// The output is `assets/zurtr_live.js`, served to a browser as a plain script tag — so three of
// these settings are load-bearing rather than taste:
//
//   format      iife, because the client installs `window.ZurtrLive` and the harness and any
//               application load it with a plain <script>. An ESM build would export a binding
//               nobody imports.
//   clean       false, because `assets/` also holds zurtr_live_test.html — the hand-written
//               harness. A clean build would delete the only test of this client.
//   minify      false, for now: what is served is what a person reads when they open devtools on
//               a live page. Minification is a release decision, not a build default.
//
// `dts: false` because nothing imports this: a script tag cannot read a `.d.ts`, and the
// declaration files would describe an API with no consumers.
export default defineConfig({
  entry: { zurtr_live: "src/index.ts" },
  // tsdown appends the format name by default, so an iife build lands as `zurtr_live.iife.js` and
  // the served path would need changing to match a bundler's convention. The client is at a fixed
  // path that the server, the harness and every application already reference.
  // tsdown names an iife bundle `zurtr_live.iife.js`: the format is part of the *filename*, not the
  // extension, so neither `outExtensions` nor `fixedExtension` reaches it. The served path is fixed
  // — the server, the harness and every application reference it — so the name is set underneath,
  // at rolldown's own output options.
  outputOptions: { entryFileNames: "[name].js" },
  outDir: "../assets",
  format: "iife",
  globalName: "ZurtrLive",
  platform: "browser",
  minify: false,
  dts: false,
  sourcemap: "inline",
  clean: false,
});
