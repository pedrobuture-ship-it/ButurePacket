# UI harness

A tiny way to drive the web UI without the desktop shell: headless Chromium + the Chrome DevTools
Protocol, with a stand-in for the Tauri bridge (`shim.js`). Used for screenshots and for checking
UI performance. Needs `chromium` on the PATH and Node 22+ (global `WebSocket`/`fetch`).

```bash
npm run dev                                   # serves the UI on http://localhost:1431
node scripts/ui-harness/screenshots.mjs       # regenerates docs/screenshots/*.png from demo data
node scripts/ui-harness/perfui.mjs 1000000    # stream 1M rows at ~100k/s, report frame times
node scripts/ui-harness/perfui.mjs 500000 "tcp && dst.port > 40100"   # …with a live filter
```

- `cdp.mjs` – launches Chromium, evaluates code in the page, takes screenshots, sends key/mouse events.
- `shim.js` – answers the few backend commands the UI needs at startup; everything else returns `undefined`.
- `seed.mjs` – fills the stores with a believable capture (DNS lookup, TLS flows, a retransmission, problems).

Notes:

- Seeding imports the app's own store modules from the dev server. If you edit a store while the dev
  server is running, restart it first: Vite can otherwise serve two instances of the same module and
  the seed data lands in the wrong one.
- This is not an end-to-end test of the Rust backend; that is covered by the Rust tests
  (`cargo test`), including a pipeline test that reads a real capture file.
