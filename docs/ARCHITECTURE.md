# Architecture

## Layers

```text
src/                      React + TypeScript UI
  app/                    shell: titlebar, toolbar, sidebar, status bar, overlays, command palette
  components/ui/          design system primitives (Button, Panel, Tabs, DataTable, ResizablePanel…)
  features/<area>/        one folder per screen: packets, flows, topology, timeline, dns, analytics,
                          overview, capture (permission), saved, settings, story
  lib/                    api.ts (typed IPC), filter/ (lexer, parser, evaluator, autocomplete),
                          format, sanitize, errors, commands, shortcuts…
  stores/                 Zustand stores (mutable buffers + a cheap version counter for big data)

src-tauri/src/            Rust engine
  capture/                libpcap session, PCAP/PCAPNG reader/writer, link-layer normalisation,
                          offline streaming, permission probing
  protocols/              dissector, summaries, byte-mapped detail, DNS and TLS decoders
  flows/                  flow keys, TCP state, retransmission heuristics, flow table
  analytics/              DNS tracker, TLS tracker, timeline events, metrics/rankings/problems
  storage/                bounded raw-packet store, SQLite schema/queries, background writer
  pipeline.rs             one batch → parse → flows → correlation → analytics
  commands/               the only IPC surface (Tauri commands and events)
```

The UI never parses packets. It receives compact summaries and asks for detail (`get_packet_detail`)
or payload bytes only when a packet is selected.

## Data flow

```text
libpcap / file reader
  → RawPacket batches (bounded buffer, ~50 ms)
  → Pipeline::process
       dissect → PacketSummary rows            → "capture://packets" every batch
       FlowEngine / DnsTracker / TlsTracker /
       EventEngine / MetricsEngine             → accumulate
  → Pipeline::drain_updates (≈ 4 Hz)           → "capture://flows|dns|events"
  → analytics snapshot (≈ 1 Hz)                → "capture://analytics"
  → StorageWriter (own thread, batched SQLite) → derived records only
```

Both live capture and file imports use the same pipeline; the only differences are the packet source
and that imports can wait for the database writer instead of dropping work.

## IPC contract

Commands are declared in one place on each side: `src-tauri/src/lib.rs` (`generate_handler!`) and
`src/lib/api.ts` (the `Commands` / `Events` maps). Errors are always
`{ kind, message, hint? }`, where `kind` is a stable identifier and `message` a sentence meant for
people.

| Command | Purpose |
| --- | --- |
| `list_capture_interfaces`, `check_capture_permission` | interfaces and what the OS allows |
| `capture_start/pause/resume/stop`, `clear_capture` | live capture lifecycle |
| `pick_and_open_capture`, `open_recent_capture`, `cancel_open` | open files (dialogs and recents live in the backend) |
| `pick_and_save_capture` | write the retained packets as PCAP |
| `get_packet_detail`, `get_packet_bytes`, `get_flow`, `get_flows`, `get_dns`, `get_events`, `get_analytics` | on-demand data |
| `query_stored_packets` | search the whole stored capture by indexed fields |
| `set_persistence`, `list_recent_captures`, `forget_recent_capture` | settings and recents |

Events: `capture://state | stats | packets | flows | dns | events | analytics | progress | storage | notice`.

## Why some things look the way they do

- **Mutable buffers in stores.** Packet rows live in a plain array; the Zustand store only carries a
  counter. Copying an immutable array on every batch would be O(n) at 100k+ rows.
- **Backend-held file paths.** The web view cannot name a file to read or write; dialogs and
  drag-and-drop are handled in Rust and recents are referred to by id.
- **Derived records only in SQLite.** Raw bytes stay in memory (bounded) or in the user's files; the
  database holds summaries, flows, DNS and events, so it stays small and fast to query.
- **Observed vs inferred.** Anything the packets do not prove (domain ↔ address, "probably HTTPS",
  "may have lost packets") is labelled as an inference and says what it is based on.
