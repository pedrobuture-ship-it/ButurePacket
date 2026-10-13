// Streams synthetic packet rows into the packet table at ~100k packets/s and reports frame times,
// long tasks and heap use.
//   node scripts/ui-harness/perfui.mjs [rows=100000] [filter] [url]
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { launch } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const N = Number(process.argv[2] || 100000);
const filter = process.argv[3] || "";
const url = process.argv[4] ?? "http://localhost:1431";
const b = await launch({ url, initScript: readFileSync(join(here, "shim.js"), "utf8"), width: 1440, height: 900 });
await b.eval(`(async () => {
  window.__long = []; window.__frames = [];
  new PerformanceObserver((l) => l.getEntries().forEach((e) => window.__long.push(e.duration))).observe({ entryTypes: ["longtask"] });
  let last = performance.now();
  const tick = () => { const n = performance.now(); window.__frames.push(n - last); last = n; requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
  const m = await import("/src/stores/packets.ts");
  (await import("/src/stores/ui.ts")).useUiStore.getState().setView("packets");
  window.__m = m;
  window.__mk = (i) => ({ id: i, flowId: i % 800, timestamp: 1.7e15 + i * 100, capturedLength: 1454, originalLength: 1454, sourceMac: "02:00:00:00:00:01", destinationMac: "02:00:00:00:00:02", sourceIp: "140.82." + (i % 250) + "." + ((i * 7) % 250), destinationIp: "192.168.1.20", sourcePort: 443, destinationPort: 40000 + (i % 800), networkProtocol: "IPv4", transportProtocol: i % 5 ? "TCP" : "UDP", applicationProtocol: i % 5 ? "TLS" : "DNS", tcpFlags: ["ACK"], ttl: 64, payloadLength: 1400, info: "443 → " + (40000 + (i % 800)) + " [ACK] Seq=" + i * 1400 + " Win=64240 Len=1400", domain: null, latency: null, issues: [] });
})()`);
await b.wait(500);
if (filter) await b.eval(`import("/src/stores/ui.ts").then((m) => m.useUiStore.getState().applyFilter(${JSON.stringify(filter)}))`);
const t0 = Date.now();
await b.eval(`new Promise((resolve) => { let i = 0; const total = ${N}; const timer = setInterval(() => { const batch = []; for (let k = 0; k < 5000 && i < total; k++) batch.push(window.__mk(++i)); window.__m.usePacketsStore.getState().append(batch); if (i >= total) { clearInterval(timer); resolve(); } }, 50); })`);
await b.wait(1500);
const r = JSON.parse(await b.eval(`(() => { const f = window.__frames.slice(5).sort((a, b) => a - b); const l = window.__long; return JSON.stringify({ rows: window.__m.usePacketsStore.getState().count, frames: f.length, p50: f[Math.floor(f.length * 0.5)], p95: f[Math.floor(f.length * 0.95)], max: f[f.length - 1], longTasks: l.length, longMaxMs: Math.max(0, ...l), heapMB: Math.round((performance.memory?.usedJSHeapSize || 0) / 1048576) }); })()`));
console.log(`rows=${N}${filter ? ` filter="${filter}"` : ""} wall=${((Date.now() - t0) / 1000).toFixed(1)}s`, r);
b.close();
