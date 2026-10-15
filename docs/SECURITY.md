# Security notes

B&M Packet reads data that other people control: network traffic and capture files. Everything
that comes from either of them is treated as hostile. This document records the threat model, what
is enforced, and where.

## Principles

- **Local-first.** No network access of its own, no telemetry, no accounts, no cloud backend.
- **No privilege tricks.** The app never runs `sudo`, never prompts for a password, never executes
  commands, and never changes its own privileges. When capture permission is missing it explains the
  situation and shows a command the *user* may choose to run (`Capture` screen).
- **No offensive features.** No packet injection, no active scanning, no decryption of TLS.
- **No shell.** The backend never spawns processes (`grep Command::new` finds nothing), so user or
  packet data can't reach a shell.

## Review checklist

| Area | Risk | What prevents it | Where |
| --- | --- | --- | --- |
| Command injection | Data reaching a shell | No process is ever spawned. The only command shown to users is quoted for POSIX shells and never executed | `capture/permission.rs` (`shell_quote`, tests) |
| Path traversal | A page or file choosing arbitrary paths | The web view cannot supply paths: file dialogs and drag-and-drop are handled by the Rust side, and the dialog plugin is not exposed to the web view (no `dialog:*` capability) | `commands/files.rs`, `capabilities/default.json` |
| Symlink escape | Writing through a link to somewhere unexpected | Opening canonicalises and requires a regular file; saving refuses symlink destinations and non-regular files; writes go to a temp file then an atomic rename | `capture/offline.rs`, `commands/files.rs` |
| Malformed PCAP/PCAPNG | Crashes, huge allocations, hangs | Every length is validated before use; per-packet and per-block limits (256 KiB / 16 MiB); typed errors with byte offsets; truncated tails are tolerated; mutation and truncation fuzz tests over both formats | `capture/file.rs` |
| Malformed packets | Panics, out-of-bounds reads | Hand-written, bounds-checked parsers return `ParseError`; DNS pointer loops and name length are bounded; TLS/DER readers use checked slicing; exhaustive prefix and single-byte mutation tests | `protocols/*` |
| Integer overflow | Wrapping lengths/offsets | Checked or saturating arithmetic on attacker-controlled sizes, `split_at_checked`, `u128` for timestamp scaling, wrap-aware sequence comparison | parsers, `capture/file.rs`, `flows/flow.rs` |
| Memory exhaustion | Unbounded growth from traffic | Capture buffer (64 MiB), raw packet store (512 MiB), flow table (200k, LRU-ish), per-flow sparkline buckets (64), DNS history (100k) and relations, event history (200k) and tracking sets, TLS reassembly (32 KiB/stream, 64 MiB total, in-order only), frontend row/flow/DNS/event caps, database size cap | `capture/session.rs`, `storage/*`, `analytics/*`, `stores/*` |
| Event flooding | UI freezes from IPC volume | Packets are batched (≈50 ms), events capped per batch, analytics at 1 Hz, progress at 10 Hz, frontend updates coalesced per animation frame | `capture/session.rs`, `pipeline.rs`, `stores/*` |
| ANSI / control characters | Terminal-style escapes or bidi tricks in captured strings | Parsers escape non-printables (`\027`, `\x1b`) at the source; the UI additionally neutralises control and bidi characters before display and in notices | `protocols/dns.rs`, `protocols/tls.rs`, `lib/sanitize.ts` |
| HTML / script injection | Captured text executed as markup | Everything is rendered as React text nodes; there is no `dangerouslySetInnerHTML`, `innerHTML` or `eval`; the filter language is parsed, never evaluated; CSP forbids inline scripts, objects, base URIs and forms | `tauri.conf.json`, `lib/filter/*` |
| SQL injection | Filter values reaching SQL | All values are bound parameters; column names come from constants; tested with hostile strings; query plans are asserted to use indexes | `storage/*` |
| Panics in the pipeline | One bad batch killing capture | Batches run under `catch_unwind` (reported, skipped); mutexes recover from poisoning instead of cascading | `pipeline.rs`, `util.rs` |
| Privilege | Silent escalation | None implemented; the permission screen only reads `/proc/self/status` and probes interfaces non-promiscuously | `capture/permission.rs` |

## Known limits

- The in-memory raw packet store evicts the oldest packets past its limit; saving then reports that
  older packets are missing.
- TLS handshake metadata needs in-order bytes; handshakes with gaps are reported as unavailable
  rather than guessed.
- Interface probing opens each interface briefly (non-promiscuous) to learn whether capture is
  permitted.
- The capture database is stored unencrypted in the application data directory and holds packet
  metadata (addresses, domains, info text) but never payload bytes.

## Reporting

Please open an issue with a minimal capture file or traffic description. Do not attach captures that
contain data you are not allowed to share.
