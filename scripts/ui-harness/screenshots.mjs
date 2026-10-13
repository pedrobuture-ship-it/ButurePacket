// Renders every main screen with demo data into docs/screenshots/.
//   npm run dev            (in another terminal)
//   node scripts/ui-harness/screenshots.mjs [http://localhost:1431]
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { launch } from "./cdp.mjs";
import { SEED } from "./seed.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "../../docs/screenshots");
mkdirSync(out, { recursive: true });
const url = process.argv[2] ?? "http://localhost:1431";

const detail = {
  summary: {},
  bytes: Array.from({ length: 78 }, (_, i) => (i * 7 + 13) & 0xff),
  sections: [
    { id: "summary", title: "Summary", offset: null, length: 0, fields: [{ name: "Protocol", value: "TLS", offset: null, length: 0 }, { name: "Info", value: "Client Hello (SNI: github.com)", offset: null, length: 0 }] },
    { id: "frame", title: "Frame", offset: 0, length: 78, fields: [{ name: "Frame number", value: "6", offset: null, length: 0 }, { name: "Captured length", value: "517 bytes", offset: null, length: 0 }] },
    { id: "ethernet", title: "Ethernet II", offset: 0, length: 14, fields: [{ name: "Destination MAC", value: "52:54:00:12:34:56", offset: 0, length: 6 }, { name: "Source MAC", value: "3c:fd:fe:12:34:56", offset: 6, length: 6 }, { name: "Type", value: "IPv4 (0x0800)", offset: 12, length: 2 }] },
    { id: "network", title: "Internet Protocol v4", offset: 14, length: 20, fields: [{ name: "TTL", value: "64", offset: 22, length: 1 }, { name: "Protocol", value: "TCP (6)", offset: 23, length: 1 }, { name: "Source IP", value: "192.168.1.20", offset: 26, length: 4 }, { name: "Destination IP", value: "140.82.121.4", offset: 30, length: 4 }] },
    { id: "transport", title: "Transmission Control Protocol", offset: 34, length: 20, fields: [{ name: "Source port", value: "53214", offset: 34, length: 2 }, { name: "Destination port", value: "443", offset: 36, length: 2 }, { name: "Flags", value: "0x018 (PSH, ACK)", offset: 46, length: 2 }] },
    { id: "application", title: "Transport Layer Security", offset: 54, length: 24, fields: [{ name: "Summary", value: "Client Hello (SNI: github.com)", offset: 54, length: 5 }, { name: "SNI", value: "github.com", offset: null, length: 0 }, { name: "ALPN offered", value: "h2, http/1.1", offset: null, length: 0 }] },
  ],
};

const b = await launch({ url, width: 1536, height: 1024, initScript: readFileSync(join(here, "shim.js"), "utf8") + `\nwindow.__packetDetail = ${JSON.stringify(detail)};` });
await b.eval(SEED);
await b.wait(900);

const shots = [
  ["overview", "overview"],
  ["packets", "packets"],
  ["flows", "flows"],
  ["map", "network-map"],
  ["timeline", "timeline"],
  ["dns", "dns"],
  ["analytics", "analytics"],
  ["capture", "capture-permission"],
];
for (const [view, name] of shots) {
  await b.eval(`import("/src/stores/ui.ts").then((m) => m.useUiStore.getState().setView(${JSON.stringify(view)}))`);
  await b.wait(view === "map" ? 1600 : 900);
  if (view === "packets") {
    // show the start of the conversation (DNS lookup, handshake, TLS hello) instead of the live tail
    await b.eval(`document.querySelector('[role=table][aria-label=Packets] [tabindex="0"]').scrollTop = 0`);
    await b.wait(300);
  }
  await b.shot(join(out, `${name}.png`));
  console.log("wrote", `docs/screenshots/${name}.png`);
}
b.close();
