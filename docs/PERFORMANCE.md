# Performance

Goals for the packet pipeline and UI:

| Capture size | Goal |
| --- | --- |
| 20k packets | very fast |
| 100k packets | fluid UI |
| 500k packets | usable |
| 1M packets | navigable |

Everything below was measured on the development machine (release builds for Rust, headless
Chromium for the UI). Numbers are for relative comparison, not promises.

## How to measure

```bash
# synthetic traffic (DNS, TLS-over-TCP conversations, UDP bursts); deterministic
cd src-tauri
cargo test --release --lib perf_pipeline  -- --ignored --nocapture   # end-to-end pipeline + SQLite + IPC size
cargo test --release --lib perf_breakdown -- --ignored --nocapture   # where per-packet time goes
cargo test --release --lib insert_throughput -- --ignored --nocapture # SQLite writer
cargo run --release --features testgen --example gen_pcap -- 1000000 /tmp/synthetic.pcap  # open it in the app

# frontend probes (parse + append, filtering, sorting, graph building)
npm run perf
```

A browser harness (`scripts/ui-harness/perfui.mjs`, see its README) streams 5,000-row batches every
50 ms (≈100k packets/s) into the packet table while sampling frame times and long tasks; the results
are in the table below.

## Findings

### Bottlenecks found (before)

1. **Flow updates were re-sent on every batch.** With ~800 concurrent flows, each 50 ms batch carried
   hundreds of flow objects (each with a 60-point sparkline). That made ~940 bytes of IPC JSON per
   packet, about half of it flows.
2. **Rankings allocated per flow.** `analytics()` formatted several strings per flow and built a
   `FlowView` just to read a protocol label: 28 ms for 34k flows, once a second, while holding the
   flow table lock.
3. **Applying a filter to 1M rows blocked the UI for ~1.2 s.** Matching `ip = <CIDR>` re-parsed the
   address (BigInt) on every row.
4. **Row memory.** Each parsed packet row cost ~690 bytes in the web view; a million rows ≈ 690 MB.
5. SQLite inserts competed with parsing on the same thread-time budget (~270k packets/s end to end).

### Changes

- Flow, DNS and event changes accumulate in the engines and are drained **4 times a second**
  (`Pipeline::drain_updates`); packet rows still stream every batch. Drains are forced when a capture
  stops so nothing is left behind. Database upserts are coalesced the same way.
- Sparklines are no longer part of flow list updates; the inspector asks for one flow (`get_flow`)
  once a second while its Overview tab is open.
- `rank()` uses typed keys (`IpAddr`, `(port, proto)`, borrowed `&str`) and only formats the top
  entries; protocol labels come from a static helper instead of a throw-away `FlowView`.
- Parsed IP addresses are cached in the filter evaluator.
- Packet filtering runs in **8 ms slices** (with a "Filtering… n%" hint) so a huge buffer never blocks
  a frame; results extend incrementally as packets arrive.
- Repeated strings (addresses, MACs, protocol names) and flag lists are **interned**; the pool is
  capped. Rows without issues share one empty array.
- Flow table refresh slows down automatically as it grows (250 ms → up to 2 s).
- Per-flow sparkline buckets 300 → 64, flow limit 500k → 200k, bounded bookkeeping sets, TLS
  reassembly budget (see `docs/SECURITY.md`).

### Before / after

| Metric | Before | After |
| --- | --- | --- |
| Pipeline throughput (parse + flows + DNS + TLS + events + metrics), 1M packets | 425k pkt/s | 515k pkt/s |
| …with SQLite persistence | 270k pkt/s | 360k pkt/s |
| IPC JSON per packet (rows + flow updates) | ~940 B | ~640 B |
| `analytics()` at 34k flows | 28 ms | 10 ms |
| Filter on 1M rows (`tcp && dst.port > … && ip = CIDR`) | 1,167 ms, blocking | 296 ms of work, sliced into 8 ms steps |
| Filter, 5,000 new rows | — | 1.5 ms (incremental) |
| Memory per packet row (web view) | ~690 B | ~394 B |
| UI at 100k packets/s streaming, up to 1M rows | n/a | frame p95 16.8 ms, no long tasks, ~290 MB heap at 1M rows |

### Where per-packet time goes (Rust, release, 200k packets)

| Stage | Throughput |
| --- | --- |
| Dissection (all layers) | ~7.4M pkt/s |
| Flow engine | ~4.6M pkt/s |
| Summaries (strings for the UI) | ~0.9M pkt/s ← largest single stage |
| JSON for packet rows | ~2.5M pkt/s (≈500 B/row) |
| Whole pipeline | ~0.5M pkt/s |
| SQLite writer (indexed / import with deferred indexes) | ~135k / ~360k rows/s |

The pipeline is roughly five times faster than the 100k packets/s the UI is tested against, so the
UI, not the backend, is the limiting factor on very busy links.

### Frontend probes (`npm run perf`)

| Probe | Result |
| --- | --- |
| JSON.parse + append, 1M rows | ~1.9 s (≈530k rows/s) |
| Sort 100k flows by traffic | ~50 ms |
| Filter 100k flows | ~26 ms |
| Build network graph from 20k flows | ~100 ms |
| Order 300k timeline events | ~5 ms |

## Remaining limits and ideas

- The packet list keeps at most 1,000,000 rows (oldest dropped); `query_stored_packets` can search the
  whole stored capture by indexed fields, but the list does not page from the database yet.
- Packet summaries are still sent as JSON objects. A columnar encoding would roughly halve the wire
  size and parse time if very high packet rates need it.
- `summarize` allocates strings per packet; precomputed address/protocol string caches would speed
  it up.
- Cytoscape is capped at 150 host nodes plus clusters by design; larger graphs aggregate instead of
  drawing thousands of nodes.
