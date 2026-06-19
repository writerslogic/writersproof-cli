# CLI Feature Parity & Windows App Completion Plan

## Overview

The CPoE engine exposes **125 FFI functions** across 18 categories. The CLI currently
implements **~18 subcommands** (plus nested sub-subcommands). This document maps every
FFI function to a CLI subcommand, assigns priorities, and outlines the Windows GUI app
requirements.

---

## Part 1: CLI Feature Gaps

### Priority Definitions

- **P0**: Required for feature parity with macOS GUI app
- **P1**: Valuable for power users and automation
- **P2**: Future/niche; implement when needed

### Category: Forensics & Analysis

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_get_forensic_breakdown(path)` | `forensics breakdown <path>` | JSON | P0 |
| `ffi_get_live_scores(path)` | `forensics live <path>` | JSON | P1 |
| `ffi_compute_process_score(path)` | `forensics score <path>` | table | P0 |
| `ffi_calibrate_swf()` | `calibrate` (exists, hidden) | plain | P1 |
| `ffi_get_provenance_metrics(session_id)` | `forensics provenance --session <id>` | JSON | P1 |
| `ffi_get_provenance_metrics_for_document(path)` | `forensics provenance <path>` | JSON | P0 |
| `ffi_get_dictation_analytics(path)` | `forensics dictation <path>` | JSON | P1 |

**Clap structure:**
```
writersproof-cli forensics <SUBCOMMAND>
    breakdown <path>       Detailed forensic breakdown
    live <path>            Live polling scores (--watch for 1Hz loop)
    score <path>           Compute process score
    provenance <path>      Provenance metrics (--session <id> for session-level)
    dictation <path>       Dictation analytics
```

### Category: Beacons

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_submit_beacon(path, timeout)` | `beacon submit <path> [--timeout <secs>]` | JSON | P0 |
| `ffi_check_beacon_status(path)` | `beacon status <path>` | table | P0 |
| `ffi_list_beacons(path)` | `beacon list <path>` | table | P0 |

**Clap structure:**
```
writersproof-cli beacon <SUBCOMMAND>
    submit <path>          Submit temporal beacon
    status <path>          Check beacon status
    list <path>            List all beacons
```

### Category: Ephemeral Sessions

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_start_ephemeral_session(label)` | `ephemeral start <label>` | JSON | P0 |
| `ffi_ephemeral_checkpoint(id, content, msg)` | `ephemeral checkpoint <id> --content <text> [--message <msg>]` | JSON | P0 |
| `ffi_ephemeral_inject_jitter(id, intervals)` | `ephemeral inject-jitter <id> --intervals <csv>` | plain | P1 |
| `ffi_ephemeral_finalize(...)` | `ephemeral finalize <id>` | JSON | P0 |
| `ffi_ephemeral_status(id)` | `ephemeral status <id>` | JSON | P0 |
| `ffi_ephemeral_session_exists(id)` | (covered by `ephemeral status`) | - | - |
| `ffi_ephemeral_checkpoint_hash(...)` | `ephemeral hash <id>` | plain | P1 |
| `ffi_ephemeral_set_canary_seed(id, hex)` | `ephemeral set-canary <id> <hex>` | plain | P2 |

**Clap structure:**
```
writersproof-cli ephemeral <SUBCOMMAND>
    start <label>          Start ephemeral session
    checkpoint <id>        Create checkpoint (--content, --message)
    finalize <id>          Finalize and export
    status <id>            Session status
    inject-jitter <id>     Inject jitter samples
    hash <id>              Get checkpoint hash
    set-canary <id> <hex>  Set canary seed
```

### Category: Text Fragments

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_text_fragment_store(...)` | `fragment store --text <text> --session <id>` | JSON | P0 |
| `ffi_text_fragment_lookup(hash)` | `fragment lookup <hash>` | JSON | P0 |
| `ffi_text_fragment_list_for_session(id)` | `fragment list --session <id>` | table | P0 |
| `ffi_attest_text(...)` | `attest` (exists, hidden) | JSON | P0 |
| `ffi_sentinel_record_paste(...)` | (internal; triggered by sentinel) | - | - |
| `ffi_mark_fragment_for_sync(id)` | `fragment sync mark <id>` | plain | P1 |
| `ffi_update_fragment_sync_state(...)` | `fragment sync update <id> --state <state>` | plain | P1 |
| `ffi_get_pending_sync_count()` | `fragment sync pending` | plain | P1 |
| `ffi_apply_remote_fragment(...)` | `fragment sync apply --data <json>` | JSON | P1 |
| `ffi_resolve_sync_conflict(...)` | `fragment sync resolve <id> --strategy <s>` | JSON | P2 |

**Clap structure:**
```
writersproof-cli fragment <SUBCOMMAND>
    store                  Store text fragment (--text, --session)
    lookup <hash>          Lookup fragment by hash
    list                   List fragments (--session <id>)
    sync <SUBCOMMAND>
        mark <id>          Mark for sync
        update <id>        Update sync state
        pending            Count pending syncs
        apply              Apply remote fragment
        resolve <id>       Resolve sync conflict
```

### Category: Credentials & Attestation

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_create_authorship_credential(...)` | `credential create <path>` | JSON | P0 |
| `ffi_sign_credential(hex)` | `credential sign <hex>` | JSON | P0 |
| `ffi_verify_credential(...)` | `credential verify <file>` | JSON | P0 |
| `ffi_get_credential_status(hex)` | `credential status <hex>` | JSON | P1 |
| `ffi_get_attestation_info()` | `credential info` | JSON | P0 |
| `ffi_reseal_identity()` | `identity reseal` | plain | P1 |
| `ffi_is_hardware_bound()` | `identity hw-status` | plain | P1 |
| `ffi_sign_attestation_challenge(b64)` | `identity sign-challenge <b64>` | plain | P1 |
| `ffi_get_device_public_key()` | `identity pubkey` | plain | P0 |

**Clap structure:**
```
writersproof-cli credential <SUBCOMMAND>
    create <path>          Create authorship credential
    sign <hex>             Sign credential CBOR
    verify <file>          Verify credential
    status <hex>           Check credential status
    info                   Attestation info
```

### Category: Snapshots

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_snapshot_save(path, text)` | `snapshot save <path> [--stdin]` | JSON | P0 |
| `ffi_snapshot_list(path)` | `snapshot list <path>` | table | P0 |
| `ffi_snapshot_get(id)` | `snapshot get <id>` | plain | P0 |
| `ffi_snapshot_diff(id, text)` | `snapshot diff <id> [--stdin]` | plain | P0 |
| `ffi_snapshot_mark_draft(id, label)` | `snapshot mark-draft <id> <label>` | plain | P1 |
| `ffi_snapshot_restore(...)` | `snapshot restore <id>` | plain | P1 |

**Clap structure:**
```
writersproof-cli snapshot <SUBCOMMAND>
    save <path>            Save snapshot (--stdin for piped content)
    list <path>            List snapshots
    get <id>               Get snapshot content
    diff <id>              Diff snapshot vs current (--stdin)
    mark-draft <id>        Mark as named draft
    restore <id>           Restore from snapshot
```

### Category: Evidence Derivatives & Provenance

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_link_derivative(src, export, msg)` | `link` (exists) | plain | - |
| `ffi_export_c2pa_manifest(...)` | `export --format c2pa <path>` | plain | P0 |
| `ffi_get_compact_ref(path)` | `export compact-ref <path>` | JSON | P1 |
| `ffi_extract_document(cpoe, out)` | `extract <cpoe_file> <output>` | plain | P1 |

### Category: WritersProof Integration

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_anchor_to_writers_proof(path)` | `anchor <path>` | JSON | P0 |
| `ffi_publish_evidence(...)` | `publish <path>` | JSON | P1 |
| `ffi_sync_text_attestation(...)` | `sync attestations` | JSON | P1 |
| `ffi_drain_text_attestation_queue()` | `sync drain` | JSON | P1 |
| `ffi_provision_ca_cert()` | `provision-cert` | plain | P1 |

### Category: DID & Identity (feature: did-webvh)

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_create_webvh_identity(addr)` | `identity webvh create <addr>` | JSON | P1 |
| `ffi_get_webvh_did()` | `identity webvh show` | plain | P1 |
| `ffi_get_active_did()` | `identity did` | plain | P1 |
| `ffi_deactivate_webvh_identity()` | `identity webvh deactivate` | plain | P2 |

### Category: Collaboration

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_collaboration_role_values()` | `collab roles` | table | P1 |
| `ffi_collaboration_signing_payload(...)` | `collab sign <path> --role <role>` | JSON | P1 |
| `ffi_collaboration_verify_attestation(...)` | `collab verify <attestation>` | JSON | P1 |

### Category: Archive & Query

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_archive_old_events(days)` | `archive --age <days>` | plain | P1 |
| `ffi_list_archives()` | `archive list` | table | P1 |
| `ffi_query_events_spanning(path, start, end)` | `query <path> --start <ts> --end <ts>` | JSON | P1 |

### Category: Reporting

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_build_war_report(path)` | `report <path> --format json` | JSON | P0 |
| `ffi_render_war_html(path)` | `report <path> --format html` | HTML file | P0 |

### Category: User Apps

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_probe_app(bundle_id)` | `config app probe <bundle_id>` | JSON | P1 |
| `ffi_discover_recent_documents(hours)` | `discover [--age <hours>]` | table | P1 |

### Category: Fingerprinting (partially covered)

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_get_fingerprint_status()` | `fingerprint status` (exists) | - | - |
| `ffi_grant_style_consent()` | `fingerprint consent grant` | plain | P0 |
| `ffi_revoke_style_consent()` | `fingerprint consent revoke` | plain | P0 |
| `ffi_reset_fingerprint()` | `fingerprint reset` | plain | P1 |
| `ffi_export_fingerprint_json()` | `fingerprint export` | JSON | P1 |
| `ffi_verify_fingerprint_match(...)` | `fingerprint verify <id1> <id2>` | JSON | P1 |
| `ffi_get_fingerprint_history()` | `fingerprint history` | table | P2 |
| `ffi_get_keystroke_timing_arrays()` | `fingerprint timing` | JSON | P2 |

### Category: Sentinel (internal; mostly covered)

Most sentinel FFI functions are internal to the GUI apps. CLI exposure:

| FFI Function | CLI Subcommand | Output | Priority |
|---|---|---|---|
| `ffi_sentinel_status()` | `status` (exists) | - | - |
| `ffi_sentinel_witnessing_status()` | `status --verbose` | JSON | P1 |
| `ffi_sentinel_es_ai_tools_active()` | `status --ai-tools` | table | P1 |

Sentinel keystroke injection, ES events, and dictation functions are **not CLI-appropriate**
(they are called by GUI apps and the browser extension native messaging host).

### Summary: P0 Commands Needed

| New Subcommand | FFI Functions | Category |
|---|---|---|
| `forensics` (4 sub) | breakdown, score, provenance, dictation | Analysis |
| `beacon` (3 sub) | submit, status, list | Temporal |
| `ephemeral` (5 sub) | start, checkpoint, finalize, status, hash | Sessions |
| `fragment` (3 sub) | store, lookup, list | Text |
| `credential` (5 sub) | create, sign, verify, status, info | Identity |
| `snapshot` (4 sub) | save, list, get, diff | Versioning |
| `report` (1 cmd) | build_war_report, render_war_html | Output |
| `export --format c2pa` | export_c2pa_manifest | Provenance |
| `anchor` (1 cmd) | anchor_to_writers_proof | Integration |
| `fingerprint consent` (2 sub) | grant, revoke | Fingerprint |

**Total P0 new subcommands: ~28** (grouped under 10 top-level commands)

---

## Part 2: Windows App Completion Plan

### Current Engine Platform Layer Status

The Windows platform layer in `crates/cpoe/src/platform/windows.rs` (716 lines) is
**fully implemented**:

| Capability | Status | Implementation |
|---|---|---|
| Keystroke capture | Complete | `WH_KEYBOARD_LL` low-level hook |
| Mouse capture | Complete | `WH_MOUSE_LL` hook with idle-only mode |
| Focus tracking | Complete | `GetForegroundWindow` + `QueryFullProcessImageNameW` |
| Synthetic detection | Complete | `LLKHF_INJECTED` flag filtering |
| Hook coordination | Complete | Atomic state + message pump thread |
| TPM 2.0 | Complete | `tss-esapi` via `crates/cpoe/src/tpm/` |

The engine compiles and runs on Windows with full keystroke, mouse, and focus capture.
No additional platform work is needed.

### What the Windows GUI App Needs

#### Architecture Recommendation: Tauri 2.0

**Rationale:**
- Shares web-based UI with potential browser/web dashboard
- Rust backend integrates directly with cpoe engine (no FFI layer needed)
- System tray support via `tauri-plugin-system-tray`
- Small binary size (~5 MB vs ~80 MB for WPF + UniFFI C#)
- Cross-platform potential (same UI for Linux)
- Active ecosystem with Windows-specific plugins

**Alternative: WPF + UniFFI C# bindings**
- Pro: Native Windows look and feel
- Con: Requires building UniFFI C# bindings (not yet implemented)
- Con: Larger binary, Windows-only
- Con: Significant additional work to generate and maintain C# FFI layer

#### Required Components

1. **System tray icon + menu**
   - Show/hide main window
   - Start/stop witnessing
   - Current session status
   - Quit

2. **Status popover window**
   - Active sessions list
   - Per-session: file path, keystroke count, duration, writing mode, cadence score
   - Real-time updates via `ffi_get_live_scores` (1Hz polling)
   - Dimension radar chart (reuse HTML report component in webview)

3. **Settings panel**
   - Excluded paths configuration
   - Allowed file extensions
   - Monitored applications list
   - Identity management (mnemonic display, reseal)
   - Fingerprint consent toggle
   - Beacon configuration

4. **Export UI**
   - File picker for export destination
   - Tier selection (basic/standard/maximum)
   - Format selection (CBOR/JSON/HTML report/C2PA)
   - Progress indicator for large exports

5. **Notification system**
   - Checkpoint created
   - Beacon anchored
   - Export complete
   - AI tool detected (EndpointSecurity equivalent)

#### Build System Requirements

```toml
# Cargo.toml for Tauri app
[dependencies]
cpoe = { path = "../../crates/cpoe" }
tauri = { version = "2", features = ["system-tray"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```
# Build commands
cargo tauri build --target x86_64-pc-windows-msvc
cargo tauri build --target aarch64-pc-windows-msvc
```

- MSVC toolchain required (not MinGW)
- WebView2 runtime (ships with Windows 10 1803+)
- Code signing via Windows SDK `signtool`
- MSI installer via WiX or NSIS

#### Feature Matrix vs macOS App

| Feature | macOS | Windows (planned) |
|---|---|---|
| System tray | Menu bar item | System tray icon |
| Keystroke capture | CGEventTap + IOKit HID | WH_KEYBOARD_LL |
| Mouse capture | CGEventTap | WH_MOUSE_LL |
| Focus tracking | NSWorkspace + AX API | GetForegroundWindow |
| Hardware attestation | Secure Enclave | TPM 2.0 |
| EndpointSecurity | ES framework (entitlement) | ETW (Event Tracing) |
| Dictation detection | macOS Dictation API | Windows Speech Recognition |
| AI tool detection | ES process monitoring | ETW process monitoring |
| Status popover | NSPopover (detachable) | Tauri webview window |
| WAR report | WebView rendering | WebView2 rendering |
| Behavioral fingerprint | Full | Full |
| Text attestation | Services + AppIntent | (future: context menu) |
| Export formats | CBOR, JSON, HTML, C2PA | CBOR, JSON, HTML, C2PA |
| Identity | Keychain + Secure Enclave | DPAPI + TPM 2.0 |
| Auto-update | Sparkle | (Tauri updater plugin) |
| Installer | DMG + notarization | MSI + code signing |

#### Implementation Phases

**Phase 1: Core (2 weeks)**
- Tauri project scaffold
- System tray with start/stop/quit
- Basic status window showing active sessions
- Direct Rust integration with cpoe engine

**Phase 2: Feature parity (3 weeks)**
- Full status popover with live scores
- Settings panel
- Export UI with all formats
- WAR report HTML rendering in WebView2
- Notification system

**Phase 3: Platform integration (2 weeks)**
- ETW integration for AI tool detection
- Windows Speech Recognition dictation detection
- Auto-update via Tauri updater
- MSI installer with code signing
- Windows Store submission (optional)

### EndpointSecurity Equivalent on Windows

The macOS `ffi_sentinel_es_*` functions use Apple's Endpoint Security framework.
On Windows, equivalent functionality comes from:

- **ETW (Event Tracing for Windows)**: Process creation/termination, file I/O
- **WMI (Windows Management Instrumentation)**: Process monitoring
- **Minifilter driver**: File system monitoring (requires driver signing)

For the initial release, ETW-based process monitoring is recommended (no driver signing
required). This covers AI tool detection and file write monitoring.
