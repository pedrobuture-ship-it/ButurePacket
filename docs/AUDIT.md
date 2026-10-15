# Technical audit

Reviewer's pass over the whole of B&M Packet, written **before** any fixes. Findings are ranked
CRITICAL → LOW. Each entry gives the file, the location, the problem, the impact and the recommended
fix. A final section records what was done about each one.

Scope: Rust engine, IPC layer, SQLite layer, React UI, build and tooling. Method: read every module
with an adversarial eye, trace each lock and each buffer, grep for panics/unwraps/console output, and
exercise the pipeline with hostile inputs.

## Summary

| Severity | Count |
| --- | --- |
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 8 |
| LOW | 8 |

No finding allows code execution, file disclosure or a crash on malformed traffic. The HIGH items are
about the app getting stuck, corrupting its own state, or using more memory than intended.

---

## CRITICAL

None found.

---

## HIGH

### H1 — A failed open job leaves the app "busy" forever
- **File:** `src-tauri/src/commands/files.rs`
- **Location:** `start_open` (sets `offline_running = true` before spawning the worker; resets it only at the end of the closure)
- **Problem:** if the worker thread panics, or `thread::Builder::spawn` fails, `offline_running` is never reset. `busy()` then reports true for the rest of the session.
- **Impact:** Start, Open, Clear and Save all refuse to work until the app is restarted. Any bug in analysis of one odd file becomes a dead app.
- **Recommended fix:** own the flag with a guard that clears it on drop (covers panic and early return), run the job under `catch_unwind` and report the failure to the UI, and reset on spawn error.

### H2 — Live capture can start while a file is opening (and Clear can run mid-import)
- **File:** `src-tauri/src/commands/capture.rs`
- **Location:** `capture_start`, `clear_capture`
- **Problem:** the backend never checks `offline_running`. Only the UI greys the buttons out.
- **Impact:** a live session and a file import then write into the same pipeline, flow table and database: interleaved ids, mixed flows, a corrupted picture. A stale or scripted call from the web view bypasses the UI guard.
- **Recommended fix:** enforce the invariant in the backend: `capture_start` and `clear_capture` return a `Busy` error while an import runs; imports already refuse while live.

### H3 — Slow disk can make the live database queue hold hundreds of megabytes
- **File:** `src-tauri/src/storage/writer.rs`
- **Location:** `StorageConfig::live` (`queue: 256`)
- **Problem:** each queued job is an `Arc` of up to a full batch of packet summaries (thousands of rows). 256 of them, plus cloned flow/DNS/event jobs, can sit in memory if the disk stalls.
- **Impact:** at high packet rates a stalled disk turns into ~1 GB of retained summaries before the "dropping" path engages — the opposite of a bounded buffer.
- **Recommended fix:** bound the queue by *rows*, not jobs; a small job count (≈32) keeps the worst case around 100 MB while still absorbing bursts.

### H4 — Truncated or fragmented TCP/UDP packets collapse into one port-0 flow
- **File:** `src-tauri/src/flows/input.rs`
- **Location:** `FlowInput::from_dissection` (`Some(L4::Other(_)) | None => Proto::from_number(proto_num)` with ports 0)
- **Problem:** when the transport header could not be decoded (small snap length, non-first fragment) the packet is attributed to `Tcp`/`Udp` with both ports 0.
- **Impact:** with a truncated capture every TCP packet between two hosts lands in a single bogus flow: wrong counts, wrong TCP state, wrong rankings, wrong timeline.
- **Recommended fix:** only create flows for TCP/UDP when ports are known; otherwise do not attribute the packet to a flow (it still appears in the packet list with its issue text).

### H5 — Flow-update IPC payload is unbounded under flow churn
- **File:** `src-tauri/src/pipeline.rs`, `src-tauri/src/flows/engine.rs`
- **Location:** `Pipeline::drain_updates` / `FlowEngine::take_changed`
- **Problem:** a drain returns *every* flow touched since the last drain. A port scan or a burst of distinct connections can touch 100k flows in 250 ms.
- **Impact:** tens of megabytes of JSON per drain, a stalled web view and runaway memory in the event queue.
- **Recommended fix:** cap a drain at a few thousand flows and keep the rest dirty for the next drain (same for DNS).

---

## MEDIUM

### M1 — Two simultaneous "open" requests can both pass the busy check
- **File:** `src-tauri/src/commands/files.rs` — `busy()` then `offline_running.store(true)` (time-of-check/time-of-use).
- **Impact:** two import threads on one pipeline. **Fix:** claim the flag atomically (`compare_exchange`) as the first step.

### M2 — TCP port reuse merges a new connection into a finished flow
- **File:** `src-tauri/src/flows/engine.rs` — `observe_detailed`.
- **Problem:** a new SYN on a 5-tuple whose flow is `Closed`/`Reset` updates the old flow, whose state stays `CLOSED`.
- **Impact:** wrong state, wrong handshake RTT, double counting, missing "connection established" events. **Fix:** a pure SYN on a closed or reset TCP flow starts a new flow.

### M3 — Saving follows a symlink at the temporary file name
- **File:** `src-tauri/src/commands/files.rs` — `save_packets` (`File::create(tmp)` where `tmp` is `<name>.tmp-<pid>`).
- **Problem:** the temporary name is predictable and `File::create` follows symlinks and truncates.
- **Impact:** a local attacker who can write in the target folder can redirect the write. **Fix:** create the temporary file exclusively (`create_new`) so an existing path of that name is never opened.

### M4 — Filter autocomplete does heavy work on every keystroke
- **File:** `src/app/FilterBar.tsx` — `collectRecents()` copies and sorts every flow on each change.
- **Impact:** noticeable typing lag with large flow tables (up to 200k flows). **Fix:** compute recents only when the data changes (memoise by flows/DNS version) and from a bounded sample.

### M5 — Modals and drawers do not trap keyboard focus
- **File:** `src/components/ui/Overlay.tsx`
- **Problem:** focus moves into the dialog but Tab can leave it, behind the backdrop.
- **Impact:** keyboard and screen-reader users can interact with hidden content. **Fix:** cycle Tab inside the dialog.

### M6 — Whole-store subscriptions re-render at the statistics rate
- **File:** `src/app/CaptureToolbar.tsx`, `src/app/FilterBar.tsx` (`useCaptureStore()` / `useUiStore()` without selectors)
- **Impact:** the toolbar (a dozen components) re-renders ~20×/s for no reason. **Fix:** select only what is needed, with a shallow comparison.

### M7 — Unused IPC surface
- **File:** `src-tauri/src/commands/capture.rs`, `src-tauri/src/commands/storage.rs`, `src/lib/api.ts`
- **Problem:** `get_flows`, `get_dns`, `get_events`, `get_analytics`, `get_packet_bytes` and `query_stored_packets` are not used by the UI (data arrives through events).
- **Impact:** dead code, extra attack surface and extra things to keep correct. **Fix:** remove them and their TypeScript wrappers; keep the storage query functions as tested library code.

### M8 — UDP and ICMP flows never end
- **File:** `src-tauri/src/flows/engine.rs`
- **Problem:** without TCP state, a flow lives until evicted, so port reuse minutes later merges unrelated exchanges (DNS clients reuse ports constantly).
- **Impact:** inflated durations and counts for UDP/ICMP. **Fix:** an idle gap (2 minutes) starts a new flow for UDP/ICMP.

---

## LOW

- **L1 — Faint text is below WCAG contrast.** `src/styles/index.css`: `--color-faint` (#4d6257) on the dark background is ≈3:1; it is used for hints and secondary labels. *Fix:* lighten to reach 4.5:1.
- **L2 — Filter history is a disabled placeholder button.** `src/app/FilterBar.tsx`. *Fix:* implement a small recent-filters menu.
- **L3 — Duplicate well-known-port tables.** `src-tauri/src/protocols/summary.rs` (`guess_application`) and `src-tauri/src/flows/engine.rs` (`guess_app_label`) must be kept in sync by hand. *Fix:* one shared function.
- **L4 — Duplicated helpers.** `Rows` description list (flows and map inspectors), clipboard copy (four places), `formatClock` vs `formatTimestamp`, `fmt_ms` vs `ms` (Rust). *Fix:* one implementation each.
- **L5 — A live session that ends in error keeps its database writer open.** `src-tauri/src/commands/capture.rs`. *Fix:* flush and close the writer when the session reports Stopped/Error.
- **L6 — Rankings hold the flow-table lock.** `src-tauri/src/pipeline.rs` `analytics()` takes ≈60 ms at 200k flows once a second, briefly stalling the parser. *Fix:* acceptable; shorten by skipping when nothing changed.
- **L7 — Many `eslint-disable react-hooks/exhaustive-deps`.** The "mutable buffer + version counter" pattern is repeated ad hoc. *Fix:* one documented hook.
- **L8 — Window resizing on the frameless window is untested on Wayland.** `src-tauri/tauri.conf.json` (`decorations: false`). *Fix:* verify on the target compositor; documented as a limitation.

---

## Resolution


| ID | Status | What was done |
| --- | --- | --- |
| H1 | Fixed | Import claim is an RAII guard released on drop; worker runs under `catch_unwind`; tests incl. panicking worker |
| H2 | Fixed | `capture_start` / `clear_capture` refuse while importing; imports refuse while live (checked under the session lock) |
| H3 | Fixed | Live writer queue 256 → 32 jobs |
| H4 | Fixed | No flow for TCP/UDP with unreadable headers; tests over every truncation |
| H5 | Fixed | Flow drains capped at 5,000 (DNS 2,000); the rest stay queued; tests |
| M1 | Fixed | `compare_exchange` claim |
| M2 | Fixed | A pure SYN on a closed/reset flow starts a new flow; eviction no longer unmaps the newer flow |
| M3 | Fixed | Temp file created exclusively with a unique name |
| M4 | Fixed | Recents cached per data version |
| M5 | Fixed | Tab cycles inside modals/drawers/palette |
| M6 | Fixed | Toolbar and filter bar use shallow selectors |
| M7 | Fixed | Unused IPC commands and wrappers removed; `query_stored_packets` is now used by the stored-capture search in Packets |
| M8 | Fixed | UDP/ICMP idle gap (2 min) starts a new flow |
| L1 | Fixed (usage) | Informational text moved from `faint` to `muted`; the prescribed palette tokens are unchanged |
| L2 | Fixed | Recent-filters menu (12 entries, persisted) |
| L3 | Fixed | `protocols/ports.rs` is the single table |
| L4 | Fixed | One clipboard helper, one clock formatter, one Rust duration formatter (the duplicated description list remains in two inspectors) |
| L5 | Fixed | Writer closed when a session stops or errors |
| L6 | Accepted | ~60 ms once a second at 200k flows; documented |
| L7 | Accepted | The mutable-buffer + version pattern keeps its explicit `eslint-disable` lines |
| L8 | Open | Window edge resizing on Wayland is unverified |

Final state: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (with and without the
`testgen` feature) and `cargo test` pass; `npm run typecheck`, `lint` and `test` pass.
