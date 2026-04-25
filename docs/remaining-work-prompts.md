# Remaining Work — Production Readiness Prompts

Use these prompts sequentially within each section. Each is self-contained with full context,
relevant file paths, and explicit success criteria. Prompts within the same section may be
run in parallel if they touch disjoint files.

**Organization:**
- Section A: Feature Completeness & Wiring (Prompts 3, 8; ~~1, 2, 4, 5, 6, 7~~ done)
- Section B: macOS Application Reliability (Prompts 9-13)
- Section C: CLI Application Reliability (Prompts 14-17)
- Section D: WritersProof API, Verify Portal & Nonce (Prompts 18-22)
- Section E: Security Hardening & User-as-Adversary (Prompts 26-27, 29-30; ~~23, 24, 25, 28~~ done)
- Section F: ~~Dependency & Test Audit~~ (~~39, 40~~ done; ~~31, 35, 37~~ done; 32-34, 36, 38 removed)
- Section G: Final Quality Gates (Prompts 42-43; ~~41~~ done)

**Completed prompts (removed from this file):**
- Prompt 1: FFI Export Audit — all 94 symbols cataloged, 23 unwired functions wired to Swift (2026-04-25)
- Prompt 2: Native Messaging Handler — text attestation verified complete (2026-04-25)
- Prompt 25: Cryptographic Operations Audit — completed in parallel session (2026-04-25)
- Prompt 4: Checkpoint Chain Integrity — AUD-026 fixed: Ed25519 verification added to verify_key_provenance (2026-04-25)
- Prompt 5: Sentinel Session Lifecycle — H-NEW-1/H-NEW-2 fixed: final checkpoints on stop(), idle stats persist (2026-04-25)
- Prompt 6: Key Hierarchy — cert expiry added to signature data, 24h default expiry set (2026-04-25)
- Prompt 7: Forensics Pipeline — NaN guards 85% via Probability newtype, cross-modal integrated, all 8 forgery components present (2026-04-25)
- Prompt 21: Verify Portal Hash Consistency — PASS, Rust/JS match perfectly (2026-04-25)
- Prompt 23: Keystroke Injection — audited, FFI bypass is architectural (sandboxed NSEvent), clipboard stub noted (2026-04-25)
- Prompt 24: Key Material Extraction — AUD-089 already fixed, ~90% zeroize coverage, IPC mandatory encryption (2026-04-25)
- Prompt 28: Error Path Security — no silent failures audit completed (2026-04-25)
- Prompt 31: FFI Module Deduplication — get_running_sentinel() helper, load_events_for_path() adoption (2026-04-25)
- Prompt 35: Report HTML Sections Decomposition — sections.rs (1940 lines) split into 6 files (2026-04-25)
- Prompt 37: Dead Code Cleanup — 8 dead items removed, 20+ justified (2026-04-25)
- Prompt 39: Dependency Audit and Cleanup — completed in parallel session (2026-04-25)
- Prompt 40: Test Coverage Gaps — completed in parallel session (2026-04-25)
- Prompt 41: Full Workspace Build/Lint/Test — fmt 0 issues, clippy 0 warnings, protocol 230 pass, jitter 21 pass, engine 1375 tests (4 pre-existing failures in language_model, checkpoint, security) (2026-04-25)

**Removed prompts (maintainability-only, not production-blocking):**
- Prompt 32: Forensics Module — Consolidate Overlapping Analysis (refactoring)
- Prompt 33: Sentinel Module — Reduce God-Object Core (file size reduction)
- Prompt 34: Store Module — Consolidate Query Patterns (refactoring)
- Prompt 36: Cross-Module Utility Extraction (deduplication)
- Prompt 38: Module Boundary Optimization — Reduce Unnecessary Re-exports (API surface cleanup)

---

## Section A: Feature Completeness & Wiring

### Prompt 3: Evidence Export Pipeline End-to-End Verification

```
Verify that the evidence export pipeline works end-to-end for all 6 output
formats: json, cpoe, cwar, html, pdf, c2pa. Each format has different code
paths and some may have bitrot.

Relevant files:
- CLI export command: `apps/cpoe_cli/src/cmd_export/` (directory-based module)
- Evidence builder: `crates/cpoe/src/evidence/builder/`, `crates/cpoe/src/evidence/packet.rs`,
  `crates/cpoe/src/evidence/types.rs`
- COSE signing: `crates/cpoe/src/evidence/wire_conversion.rs`,
  `crates/cpoe/src/war/encoding.rs`
- HTML report: `crates/cpoe/src/report/html/` (sections.rs is 1940 lines)
- PDF report: `crates/cpoe/src/report/pdf/`
- C2PA: `crates/cpoe/src/evidence/rfc_conversion.rs`
- WAR types: `crates/cpoe/src/war/types.rs`, `crates/cpoe/src/war/verification.rs`
- FFI export: `crates/cpoe/src/ffi/evidence_export.rs` (ffi_export_evidence at line 58,
  ffi_export_evidence_json at line 15, ffi_get_compact_ref at line 407)
- Wire format: `crates/authorproof-protocol/src/` (CBOR/COSE wire types)

Tasks:
1. Read the export command handler for each format
2. Trace the code path for each: CLI invocation -> builder -> serialization -> output
3. Verify COSE_Sign1 signatures are applied to .cpoe and .cwar outputs
4. Verify HTML report renders without broken references
5. Verify PDF generation doesn't panic on empty/minimal evidence
6. Verify C2PA assertion JSON matches the C2PA spec schema
7. Run `cargo test -p cpoe --lib -- evidence` to verify evidence tests pass
8. Run `cargo test -p cpoe --lib -- report` to verify report tests pass

Success criteria:
- [ ] All 6 formats produce valid output from a minimal test session
- [ ] COSE signatures verify successfully on .cpoe and .cwar files
- [ ] HTML report is self-contained (no external resource references)
- [ ] PDF generation handles edge cases (empty session, no keystrokes)
- [ ] C2PA JSON validates against schema
- [ ] All evidence and report tests pass
- [ ] No panics, unwraps, or swallowed errors in export paths
```

---

### _REMOVE_START
- Checkpoint types: `crates/cpoe/src/checkpoint/types.rs`
- Checkpoint tests: `crates/cpoe/src/checkpoint/tests.rs` (1542 lines)
- MMR: `crates/cpoe/src/checkpoint_mmr/`, `crates/cpoe/src/mmr/`
- VDF proofs: `crates/cpoe/src/vdf/swf_argon2.rs` (810 lines)
- Lamport signatures: `crates/cpoe/src/crypto/lamport.rs`
- WAL: `crates/cpoe/src/wal/operations.rs` (721 lines)
- Store events: `crates/cpoe/src/store/events.rs`
- FFI checkpoint: `crates/cpoe/src/ffi/evidence_checkpoint.rs`

Known blocking audit findings:
- AUD-026: Checkpoint signature never verified cryptographically (garbage sigs may pass)
- AUD-030, AUD-032: Evidence packet chain linkage and VDF params potentially incorrect

Tasks:
1. Read the checkpoint chain creation and verification code
2. FIX AUD-026: Verify checkpoint signatures are cryptographically verified (not just present)
3. Verify each checkpoint's prev_hash correctly references the previous checkpoint
4. Verify VDF proofs are bound to checkpoint content (not just timestamps)
5. Verify Lamport signatures are applied at checkpoint time and stored in DB
5. Verify MMR anchoring correctly includes checkpoint hashes
6. Test: create 10 checkpoints, verify chain, tamper with one, verify detection
7. Run `cargo test -p cpoe --lib -- checkpoint` (1542 lines of existing tests)

Success criteria:
- [ ] Chain hash linkage is correct (each checkpoint hashes prev_hash + content)
- [ ] VDF proofs are bound to specific checkpoint data (not replayable)
- [ ] Lamport one-shot signatures are consumed and stored correctly
- [ ] MMR cross-checkpoint anchoring works for chains of 1, 10, 100 checkpoints
- [ ] Tampering with any checkpoint field causes verification failure
- [ ] All 1542+ lines of checkpoint tests pass
- [ ] WAL entries for checkpoints include complete chain state
```

---

### Prompt 5: Sentinel Session Lifecycle — Start, Monitor, Checkpoint, Stop

```
Verify the sentinel daemon correctly manages document sessions through their
complete lifecycle: start monitoring -> capture keystrokes/focus/mouse ->
create checkpoints -> stop monitoring. This is the core behavioral capture
pipeline.

Relevant files:
- Sentinel core: `crates/cpoe/src/sentinel/core.rs` (1469 lines — the main event loop)
- Sentinel setup: `crates/cpoe/src/sentinel/core_setup.rs` (190 lines)
- Session management: `crates/cpoe/src/sentinel/core_session.rs` (483 lines)
- Sentinel types: `crates/cpoe/src/sentinel/types.rs` (823 lines)
- Sentinel helpers: `crates/cpoe/src/sentinel/helpers.rs` (1315 lines)
- Sentinel daemon: `crates/cpoe/src/sentinel/daemon.rs` (670 lines)
- Focus monitoring: `crates/cpoe/src/sentinel/focus.rs` (261 lines),
  `crates/cpoe/src/sentinel/macos_focus.rs` (327 lines)
- Clipboard: `crates/cpoe/src/sentinel/clipboard.rs` (652 lines)
- IPC handler: `crates/cpoe/src/sentinel/ipc_handler.rs` (768 lines)
- Behavioral key: `crates/cpoe/src/sentinel/behavioral_key.rs` (118 lines)
- App registry: `crates/cpoe/src/sentinel/app_registry.rs` (1115 lines)
- Shadow manager: `crates/cpoe/src/sentinel/shadow.rs` (174 lines)
- Sentinel tests: `crates/cpoe/src/sentinel/tests.rs` (453 lines)
- FFI sentinel: `crates/cpoe/src/ffi/sentinel.rs` (ffi_sentinel_start, ffi_sentinel_stop,
  ffi_sentinel_is_running, ffi_sentinel_restart_keystroke_capture)
- FFI witnessing: `crates/cpoe/src/ffi/sentinel_witnessing.rs`
  (ffi_sentinel_start_witnessing, ffi_sentinel_stop_witnessing, ffi_sentinel_status,
  ffi_sentinel_witnessing_status)
- FFI ES: `crates/cpoe/src/ffi/sentinel_es.rs` (6 Endpoint Security functions)
- FFI config: `crates/cpoe/src/ffi/sentinel_config.rs` (6 config functions)
- FFI inject: `crates/cpoe/src/ffi/sentinel_inject.rs` (ffi_sentinel_inject_keystroke)

Tasks:
1. Trace the full session lifecycle: FFI start -> sentinel core -> session create ->
   keystroke capture -> checkpoint trigger -> session close -> evidence persist
2. Verify focus transitions correctly pause/resume sessions (including unfocused keystroke buffering)
3. Verify clipboard monitoring integrates with paste detection
4. Verify the behavioral key is rotated correctly
5. Verify sleep/wake handling preserves sessions
6. Verify the app registry correctly identifies supported applications
7. Verify Endpoint Security file-write triggers create checkpoints
8. Run `cargo test -p cpoe --lib -- sentinel` to verify sentinel tests pass

Success criteria:
- [ ] Session lifecycle is complete: start -> capture -> checkpoint -> stop -> persist
- [ ] Focus transitions are handled without losing keystrokes
- [ ] Clipboard paste events are correlated with keystroke context
- [ ] Behavioral key entropy accumulates correctly during sessions
- [ ] Sleep/wake doesn't corrupt session state
- [ ] App registry identifies all 25+ allowlisted applications
- [ ] Endpoint Security hooks create checkpoints on file writes
- [ ] All sentinel tests pass
- [ ] No race conditions in concurrent session access (uses Arc<RwLock<>>)
```

---

### Prompt 6: Key Hierarchy & Identity Management Completeness

```
Verify the key hierarchy (master identity -> session keys -> checkpoint signatures)
is complete, secure, and correctly handles recovery, migration, and hardware binding.

Relevant files:
- Key hierarchy: `crates/cpoe/src/keyhierarchy/` — manager.rs, identity.rs, session.rs,
  crypto.rs, verification.rs, types.rs, recovery.rs, migration.rs, puf.rs, error.rs,
  tests.rs
- Identity: `crates/cpoe/src/identity/` — look for secure_storage.rs (934 lines),
  did_webvh.rs (1098 lines)
- Sealed identity: `crates/cpoe/src/sealed_identity/`
- TPM/Secure Enclave: `crates/cpoe/src/tpm/` — mod.rs, signer.rs, software.rs,
  verification.rs, types.rs, secure_enclave/, linux.rs, windows/
- FFI attestation: `crates/cpoe/src/ffi/attestation.rs` (ffi_get_attestation_info,
  ffi_reseal_identity, ffi_is_hardware_bound, ffi_sign_attestation_challenge,
  ffi_get_device_public_key)
- FFI credentials: `crates/cpoe/src/ffi/credentials.rs` (ffi_create_authorship_credential,
  ffi_sign_credential, ffi_verify_credential, ffi_get_credential_status)
- Config: `crates/cpoe/src/config/types.rs`

Tasks:
1. Trace key derivation: mnemonic -> master identity -> session certificates -> signing keys
2. Verify hardware binding (Secure Enclave on macOS, TPM on Windows, software fallback)
3. Verify key recovery from mnemonic produces identical identity
4. Verify session certificates are bound to specific time windows
5. Verify checkpoint signatures use the correct session key
6. Verify PUF binding strengthens hardware attestation
7. Verify credential creation, signing, and verification round-trip
8. Run `cargo test -p cpoe --lib -- keyhierarchy`
9. Run `cargo test -p cpoe --lib -- identity`
10. Run `cargo test -p cpoe --lib -- tpm`

Success criteria:
- [ ] Key derivation is deterministic from mnemonic
- [ ] Hardware binding works on macOS (Secure Enclave) with software fallback
- [ ] Recovery from mnemonic produces byte-identical keys
- [ ] Session certificates expire and cannot be reused
- [ ] Checkpoint signatures verify against session public key
- [ ] All zeroize() calls use RAII (Zeroizing<T>) not manual cleanup
- [ ] Credential lifecycle is complete (create -> sign -> verify -> revoke)
- [ ] All keyhierarchy, identity, and TPM tests pass
```

---

### Prompt 7: Forensics & Behavioral Analysis Pipeline

```
Verify the forensics analysis pipeline correctly computes all behavioral metrics,
produces accurate scores, and the scoring model is well-calibrated.

Relevant files:
- Forensics engine: `crates/cpoe/src/forensics/engine.rs`
- Analysis: `crates/cpoe/src/forensics/analysis.rs`
- Assessment: `crates/cpoe/src/forensics/assessment.rs`
- Scoring: `crates/cpoe/src/forensics/scoring.rs`
- Velocity: `crates/cpoe/src/forensics/velocity.rs`
- Cadence: `crates/cpoe/src/forensics/cadence.rs`
- Topology: `crates/cpoe/src/forensics/topology.rs`
- Cross-modal: `crates/cpoe/src/forensics/cross_modal.rs`
- Forgery cost: `crates/cpoe/src/forensics/forgery_cost.rs`
- Dictation detection: `crates/cpoe/src/forensics/dictation.rs`
- Transcription: `crates/cpoe/src/transcription/`
- Content detector: `crates/cpoe/src/analysis/content_detector.rs` (1206 lines)
- Writing mode: `crates/cpoe/src/forensics/writing_mode.rs`
- Correlation: `crates/cpoe/src/forensics/correlation.rs`
- Advanced metrics: `crates/cpoe/src/forensics/advanced_metrics.rs`
- Cognitive accumulator: `crates/cpoe/src/forensics/cognitive_accumulator.rs`
- Provenance metrics: `crates/cpoe/src/forensics/provenance_metrics.rs`
- Event validation: `crates/cpoe/src/forensics/event_validation.rs`
- Forensics tests: `crates/cpoe/src/forensics/tests.rs` (1140 lines)
- FFI forensics: `crates/cpoe/src/ffi/forensics.rs` (ffi_get_provenance_metrics,
  ffi_compute_process_score, ffi_calibrate_swf)
- FFI forensic detail: `crates/cpoe/src/ffi/forensics_detail.rs` (ffi_get_forensic_breakdown)
- Jitter analysis: `crates/cpoe/src/jitter/` (with tests.rs at 889 lines)

Tasks:
1. Verify all scoring functions handle NaN/Inf inputs (systemic pattern SYS-001 from audits)
2. Verify cross-modal consistency checks actually run during forensic analysis
3. Verify forgery cost estimation produces reasonable values
4. Verify transcription/dictation detection flags suspicious patterns
5. Verify content_detector correctly identifies AI-generated vs human-written patterns
6. Run `cargo test -p cpoe --lib -- forensics` (1140 lines of tests)
7. Run `cargo test -p cpoe --lib -- jitter` (889 lines of tests)
8. Run `cargo test -p cpoe --lib -- analysis`

Success criteria:
- [ ] No NaN/Inf propagation in any scoring function (all guarded)
- [ ] Cross-modal checks integrate into final verdict
- [ ] Forgery cost model accounts for all 8 components
- [ ] Transcription detection catches burst_speed_cv < 0.15
- [ ] Content detector produces calibrated confidence scores
- [ ] Assessment score correctly combines all sub-scores
- [ ] All forensics, jitter, and analysis tests pass
- [ ] FFI functions return complete data (no missing fields)
```

---

### Prompt 8: IPC Server & Secure Channel Verification

```
Verify the IPC server (Unix socket on macOS/Linux, named pipe on Windows)
correctly handles all message types, maintains encrypted channels, and
enforces rate limiting and RBAC.

Relevant files:
- IPC server: `crates/cpoe/src/ipc/server.rs`, `crates/cpoe/src/ipc/server_handler.rs`,
  `crates/cpoe/src/ipc/server_windows.rs`
- Async client: `crates/cpoe/src/ipc/async_client.rs` (706 lines)
- Sync client: `crates/cpoe/src/ipc/sync_client.rs`
- Secure channel: `crates/cpoe/src/ipc/secure_channel.rs`
- Crypto: `crates/cpoe/src/ipc/crypto.rs`
- RBAC: `crates/cpoe/src/ipc/rbac.rs`
- Messages: `crates/cpoe/src/ipc/messages.rs`
- Unix socket: `crates/cpoe/src/ipc/unix_socket.rs`
- IPC tests: `crates/cpoe/src/ipc/tests.rs`
- CLI daemon: `apps/cpoe_cli/src/cmd_daemon.rs`

Tasks:
1. Verify all message types in messages.rs have handlers in server_handler.rs
2. Verify the secure channel (ChaCha20-Poly1305) is correctly negotiated via ECDH
3. Verify rate limiting applies to all operation types (IpcOperation enum)
4. Verify RBAC permissions are checked before operations
5. Verify the Unix socket has correct file permissions (owner-only)
6. Verify graceful shutdown: stop signal -> drain pending -> close connections
7. Verify no circular dependency between sentinel <-> IPC (sentinel spawns IPC server,
   IPC handler calls back into sentinel via ipc_handler.rs — should use traits/channels)
8. Run `cargo test -p cpoe --lib -- ipc`

Success criteria:
- [ ] Every message type has a handler (no unhandled variants)
- [ ] ECDH key exchange correctly derives ChaCha20-Poly1305 session key
- [ ] Rate limiting uses IpcOperation enum (not strings) per SYS-006
- [ ] RBAC denies unauthorized operations
- [ ] Socket permissions are 0o600 (owner read/write only)
- [ ] Shutdown is graceful (no orphaned connections)
- [ ] Sentinel <-> IPC coupling uses trait abstraction (no direct module imports creating cycles)
- [ ] All IPC tests pass
- [ ] No plaintext secrets transit the socket
```

---

## Section B: macOS Application Reliability

### Prompt 9: macOS App — Full Build & Launch Verification

```
Verify the macOS application builds from clean state, launches, and all
major features are accessible from the UI.

Relevant files:
- macOS app: `apps/cpoe_macos/` (git submodule)
- Xcode project: `apps/cpoe_macos/cpoe.xcodeproj/`
- Xcconfig: `apps/cpoe_macos/CPoEEngine.xcconfig`
- Swift sources: `apps/cpoe_macos/cpoe/`
- Safari extension: `apps/cpoe_macos/CPoESafariExtension/`
- Static library: built from `crates/cpoe/` with `--features ffi`
- Build scripts: `apps/cpoe_macos/scripts/`
- Tests: `apps/cpoe_macos/WritersLogicTests/`, `apps/cpoe_macos/WritersLogicUITests/`
- StoreKit config: `apps/cpoe_macos/WritersProof.storekit`

Tasks:
1. Verify the submodule is initialized and up to date
2. Build the Rust static library: `cargo build -p cpoe --features ffi --release`
3. Verify the Xcconfig correctly references the static library path
4. Build the macOS app via `xcodebuild` (archive or build for running)
5. Verify all Swift source files compile without warnings
6. Run the unit tests: `xcodebuild test -scheme WritersLogic -destination 'platform=macOS'`
7. List all view controllers / SwiftUI views and verify each has corresponding FFI calls

Success criteria:
- [ ] Rust static library builds successfully (libcpoe_engine.a)
- [ ] macOS app builds without errors or warnings
- [ ] App launches without crashing
- [ ] Unit tests pass
- [ ] All major UI views load (dashboard, sessions, export, settings, identity)
- [ ] Safari extension compiles and installs
```

---

### Prompt 10: macOS App — Sentinel Integration Reliability

```
Verify that the macOS app correctly starts/stops the sentinel daemon,
handles keystroke capture permissions, and maintains session state across
app lifecycle events (launch, quit, sleep, wake).

Relevant files:
- FFI sentinel: `crates/cpoe/src/ffi/sentinel.rs` (ffi_sentinel_start/stop/is_running/restart)
- FFI witnessing: `crates/cpoe/src/ffi/sentinel_witnessing.rs`
- FFI ES: `crates/cpoe/src/ffi/sentinel_es.rs`
- Swift sentinel integration: search `apps/cpoe_macos/cpoe/` for files calling
  ffi_sentinel_start, ffi_sentinel_stop, sentinel_witnessing
- Endpoint Security entitlement: `apps/cpoe_macos/cpoe.xcodeproj/` (entitlements file)
- Accessibility permissions: macOS requires TCC permission for CGEventTap

Tasks:
1. Trace the app launch -> sentinel start sequence in Swift
2. Verify CGEventTap accessibility permission is requested and handled gracefully
3. Verify Endpoint Security entitlement is properly declared
4. Verify sleep/wake notifications trigger stop/start cycle
5. Verify session state persists across sleep/wake
6. Verify the app handles sentinel crash (bridge thread dies) gracefully

Success criteria:
- [ ] App requests accessibility permission on first launch
- [ ] Sentinel starts automatically when app launches
- [ ] Endpoint Security file monitoring activates
- [ ] Sleep/wake preserves session state
- [ ] Sentinel crash is detected and reported to user
- [ ] App can restart sentinel after crash without relaunch
```

---

### Prompt 11: macOS App — Text Attestation Flow (Services + AppIntent)

```
Verify the macOS text attestation feature works end-to-end: user selects text
in any app, invokes the Services menu or AppIntent, text is attested and synced
to WritersProof API.

Relevant files:
- FFI text fragment: `crates/cpoe/src/ffi/text_fragment.rs` (ffi_attest_text at line 451,
  ffi_text_fragment_store at line 214, normalization functions)
- FFI WritersProof sync: `crates/cpoe/src/ffi/writersproof_ffi.rs`
  (ffi_sync_text_attestation at line 306, ffi_drain_text_attestation_queue at line 479)
- Store text fragments: `crates/cpoe/src/store/text_fragments.rs` (952 lines)
- Offline queue: `crates/cpoe/src/writersproof/queue.rs`
- Swift Services handler: search `apps/cpoe_macos/cpoe/` for Services, AppIntent,
  NSServicesProvider, text attestation
- Normalization: text_fragment.rs contains normalize_for_attestation()

Tasks:
1. Verify the macOS Services menu entry is declared in Info.plist
2. Verify the AppIntent is declared for Shortcuts integration
3. Trace: user selects text -> Services menu -> Swift handler -> ffi_attest_text ->
   store + sign -> ffi_sync_text_attestation -> API
4. Verify normalization matches between Rust (text_fragment.rs) and any JS counterpart
5. Verify offline queue correctly retries failed syncs
6. Verify the 3-tier attestation system (Verified/Corroborated/Declared) works

Success criteria:
- [ ] Services menu shows "Attest with WritersProof" for text selections
- [ ] AppIntent is accessible from Shortcuts app
- [ ] Text is normalized identically in Rust and JS (NFC, lowercase, strip punctuation)
- [ ] Ed25519 signature with domain tag "witnessd-text-attest-v1" is correct
- [ ] Offline queue drains when network returns
- [ ] All 3 attestation tiers produce valid attestations
- [ ] writersproof_id matches first 8 chars of content hash
```

---

### Prompt 12: macOS App — Export, Report & Verification UI

```
Verify the macOS app's export functionality: user can export evidence in all
formats, generate WAR reports, and verify evidence packets from the UI.

Relevant files:
- FFI export: `crates/cpoe/src/ffi/evidence_export.rs` (ffi_export_evidence at line 58,
  ffi_export_evidence_json at line 15, ffi_extract_document at line 440)
- FFI report: `crates/cpoe/src/ffi/report.rs` (ffi_build_war_report at line 1034,
  ffi_render_war_html at line 1051)
- FFI verify: `crates/cpoe/src/ffi/verify_detail.rs` (ffi_verify_evidence_detailed at line 44)
- FFI forensic breakdown: `crates/cpoe/src/ffi/forensics_detail.rs`
  (ffi_get_forensic_breakdown at line 107)
- FFI chain: `crates/cpoe/src/ffi/chain.rs` (checkpoint chain display)
- Swift export views: search `apps/cpoe_macos/cpoe/` for export, report, verify views

Tasks:
1. Verify each export format (json, cpoe, cwar, html, pdf, c2pa) works from the UI
2. Verify WAR report generation and HTML rendering
3. Verify evidence verification shows detailed results (signatures, chain integrity, metrics)
4. Verify forensic breakdown UI displays all analysis categories
5. Verify checkpoint chain visualization is correct

Success criteria:
- [ ] All 6 export formats accessible from UI
- [ ] Save dialog shows correct file extensions (.json, .cpoe, .cwar, .html, .pdf)
- [ ] WAR report renders in WKWebView without broken references
- [ ] Verification shows pass/fail for each check (signatures, chain, timestamps)
- [ ] Forensic breakdown shows velocity, cadence, topology, cross-modal scores
```

---

### Prompt 13: macOS App — Ephemeral Sessions & Snapshots

```
Verify ephemeral sessions (for in-app text composition) and document snapshots
work correctly.

Relevant files:
- FFI ephemeral: `crates/cpoe/src/ffi/ephemeral.rs` (775 lines, 7 functions:
  ffi_start_ephemeral_session, ffi_ephemeral_checkpoint, ffi_ephemeral_inject_jitter,
  ffi_ephemeral_finalize, ffi_ephemeral_status, ffi_ephemeral_checkpoint_hash,
  ffi_ephemeral_set_canary_seed)
- FFI snapshot: `crates/cpoe/src/ffi/snapshot.rs` (6 functions: ffi_snapshot_save,
  ffi_snapshot_list, ffi_snapshot_get, ffi_snapshot_diff, ffi_snapshot_mark_draft,
  ffi_snapshot_restore)
- Store: `crates/cpoe/src/store/` (events, document_stats, baselines)
- Swift: search `apps/cpoe_macos/cpoe/` for ephemeral, snapshot views

Tasks:
1. Verify ephemeral session lifecycle: start -> checkpoint -> inject jitter -> finalize
2. Verify canary seed mechanism for tamper detection
3. Verify snapshot save/list/get/diff/restore works correctly
4. Verify snapshot diff produces correct edit operations
5. Verify draft labels can be set and displayed

Success criteria:
- [ ] Ephemeral sessions create valid evidence from in-app text input
- [ ] Canary seed detects if session was replayed
- [ ] Snapshots save document state at checkpoint time
- [ ] Diff shows character-level changes between snapshots
- [ ] Draft labels persist and display correctly
- [ ] Snapshot restore brings back previous document state
```

---

## Section C: CLI Application Reliability

### Prompt 14: CLI — All Commands Execute Without Error

```
Verify every CLI command runs without panicking and produces sensible output
for both normal and edge cases.

Relevant files:
- CLI definition: `apps/cpoe_cli/src/cli.rs` (full command enum with subcommands)
- Command implementations:
  - `apps/cpoe_cli/src/cmd_attest.rs` (ephemeral attestation)
  - `apps/cpoe_cli/src/cmd_commit.rs` (checkpoint creation)
  - `apps/cpoe_cli/src/cmd_config.rs` (config management)
  - `apps/cpoe_cli/src/cmd_daemon.rs` (daemon start/stop)
  - `apps/cpoe_cli/src/cmd_export/` (evidence export, directory module)
  - `apps/cpoe_cli/src/cmd_fingerprint.rs` (behavioral fingerprints)
  - `apps/cpoe_cli/src/cmd_identity.rs` (identity management)
  - `apps/cpoe_cli/src/cmd_init.rs` (environment init)
  - `apps/cpoe_cli/src/cmd_link.rs` (derivative linking)
  - `apps/cpoe_cli/src/cmd_log.rs` (checkpoint history)
  - `apps/cpoe_cli/src/cmd_presence.rs` (presence challenges)
  - `apps/cpoe_cli/src/cmd_status.rs` (status display)
  - `apps/cpoe_cli/src/cmd_track/` (file tracking, directory module)
  - `apps/cpoe_cli/src/cmd_verify.rs` (evidence verification)
- Main: `apps/cpoe_cli/src/main.rs`
- Output formatting: `apps/cpoe_cli/src/output.rs`
- Smart defaults: `apps/cpoe_cli/src/smart_defaults.rs`
- Spec: `apps/cpoe_cli/src/spec.rs`
- Utils: `apps/cpoe_cli/src/util.rs`
- CLI tests: `apps/cpoe_cli/tests/`

Tasks:
1. Read each command implementation and verify error handling
2. Test each command with: no args, minimal valid args, invalid args
3. Verify --json flag produces valid JSON for all commands
4. Verify --quiet flag suppresses informational output
5. Verify shell completions generate for bash/zsh/fish
6. Run `cargo test -p cpoe_cli`
7. Verify man page generation works

Success criteria:
- [ ] All commands run without panicking on valid input
- [ ] All commands produce helpful error messages on invalid input
- [ ] --json flag produces parseable JSON output
- [ ] --quiet suppresses info (errors still shown)
- [ ] Shell completions are valid
- [ ] Man page content matches actual commands
- [ ] All CLI tests pass
- [ ] Exit codes are correct (0 success, 1 error, 2 usage error)
```

---

### Prompt 15: CLI — Daemon Auto-Start and IPC Communication

```
Verify the CLI correctly auto-starts the daemon when needed and communicates
via IPC for commands that require it.

Relevant files:
- Auto-start logic: `apps/cpoe_cli/src/main.rs` (needs_auto_start method at cli.rs:249)
- Daemon command: `apps/cpoe_cli/src/cmd_daemon.rs`
- IPC clients: `crates/cpoe/src/ipc/sync_client.rs`, `crates/cpoe/src/ipc/async_client.rs`
- IPC server: `crates/cpoe/src/ipc/server.rs`
- Unix socket: `crates/cpoe/src/ipc/unix_socket.rs`
- CLI needs_auto_start: `apps/cpoe_cli/src/cli.rs:244-261`

Tasks:
1. Verify needs_auto_start correctly identifies which commands need the daemon
2. Verify daemon auto-start creates the IPC socket
3. Verify CLI -> daemon communication works for: track, commit, export, verify
4. Verify daemon stop gracefully terminates
5. Verify CLI handles daemon not running (auto-start or clear error)
6. Verify CLI handles daemon crash (connection reset)

Success criteria:
- [ ] Commands that need daemon auto-start it if not running
- [ ] Commands that don't need daemon (config, status, init, etc.) work without it
- [ ] IPC communication is encrypted (ChaCha20-Poly1305 secure channel)
- [ ] Daemon stop drains pending operations before exit
- [ ] CLI detects dead daemon and restarts
- [ ] No orphaned socket files after daemon stop
```

---

### Prompt 16: CLI — Native Messaging Host Completeness

```
Verify the native messaging host handles all message types the browser extension
can send and correctly interfaces with the engine.

Relevant files:
- Native messaging host: `apps/cpoe_cli/src/native_messaging_host/mod.rs`,
  `apps/cpoe_cli/src/native_messaging_host/handlers.rs`,
  `apps/cpoe_cli/src/native_messaging_host/protocol.rs`,
  `apps/cpoe_cli/src/native_messaging_host/types.rs`,
  `apps/cpoe_cli/src/native_messaging_host/jitter.rs`,
  `apps/cpoe_cli/src/native_messaging_host/tests.rs`
- Browser extension messages: `apps/cpoe_browser_extension/background.js`
  (sends: start_session, stop_session, checkpoint, jitter, text_attestation, etc.)
- Native manifests: `apps/cpoe_browser_extension/native-manifests/`
  (Chrome/Firefox/Edge manifest JSONs)

Tasks:
1. List all message types sent by background.js
2. List all message handlers in the native messaging host
3. Verify 1:1 mapping (every message type has a handler)
4. Verify response format matches what background.js expects
5. Verify native manifest paths are correct for all browsers
6. Verify the install script sets up manifests correctly
7. Run native messaging host tests

Success criteria:
- [ ] Every browser message type has a corresponding handler
- [ ] Response format matches browser extension expectations
- [ ] Native manifests point to correct binary path
- [ ] Install script works on macOS and Linux
- [ ] Message size respects MAX_MESSAGE_SIZE (1MB)
- [ ] Error responses are structured (not just strings)
- [ ] All native messaging tests pass
```

---

### Prompt 17: CLI — Evidence Export Format Correctness

```
Verify the CLI's export command produces correct output for all 6 formats and
the verify command can validate what export produces.

Relevant files:
- Export command: `apps/cpoe_cli/src/cmd_export/` (directory-based module)
- Verify command: `apps/cpoe_cli/src/cmd_verify.rs`
- Evidence export FFI: `crates/cpoe/src/ffi/evidence_export.rs`
- Wire format: `crates/authorproof-protocol/src/` (CBOR/COSE types)
- Report modules: `crates/cpoe/src/report/html/`, `crates/cpoe/src/report/pdf/`

Tasks:
1. Export a test document in all 6 formats: json, cpoe, cwar, html, pdf, c2pa
2. Verify each exported file: json is valid JSON, cpoe is valid CBOR, cwar is
   valid COSE, html renders in browser, pdf opens in Preview, c2pa matches schema
3. Run `cpoe verify` on each exported file that supports verification (.json, .cpoe, .cwar)
4. Verify export -> verify round-trip passes for all verifiable formats
5. Test edge cases: empty document, very large document, document with no keystrokes

Success criteria:
- [ ] All 6 formats produce non-empty output
- [ ] JSON export is well-formed and contains expected fields
- [ ] CBOR export uses correct tag (1129336656)
- [ ] COSE export has valid Ed25519 signature
- [ ] HTML is self-contained with embedded CSS/JS
- [ ] PDF has correct metadata and anti-forgery features
- [ ] C2PA JSON matches the assertion schema
- [ ] Verify command accepts all verifiable exports
- [ ] Edge cases (empty/large/no keystrokes) don't panic
```

---

## Section D: WritersProof API, Verify Portal & Nonce

### Prompt 18: WritersProof API — Text Attestation Endpoint Verification

```
Verify the WritersProof API at writersproof.com correctly handles text attestation
POST and GET requests with proper authentication, validation, and storage.

NOTE: The WritersProof API is a SEPARATE repository at
~/workspace_local/Writerslogic/writersproof/ — NOT in this repo.
The Rust client that calls it is in this repo.

Relevant files (this repo):
- WritersProof client: `crates/cpoe/src/writersproof/client.rs` (804 lines)
- WritersProof types: `crates/cpoe/src/writersproof/types.rs`
- WritersProof queue: `crates/cpoe/src/writersproof/queue.rs`
- FFI sync: `crates/cpoe/src/ffi/writersproof_ffi.rs`
  (ffi_anchor_to_writers_proof at line 15, ffi_publish_evidence at line 144,
  ffi_sync_text_attestation at line 306, ffi_drain_text_attestation_queue at line 479)

Relevant files (writersproof repo — ~/workspace_local/Writerslogic/writersproof/):
- API routes: `apps/api/src/routes/` (textAttestation.ts, nonce.ts, verify.ts, anchor.ts)
- Auth middleware: `apps/api/src/middleware/`
- Cron handler: `apps/api/src/cron.ts`
- Supabase migrations: `supabase/migrations/`
- Verify portal: `apps/verify/`

Known API endpoints (from Rust client at client.rs):
- POST /v1/nonce — request challenge nonce (32-byte hex, with TTL)
- POST /v1/enroll — device enrollment (public_key, attestation_certificate)
- POST /v1/attest — submit CBOR evidence with nonce + hardware key + signature
- POST /v1/anchor — submit to transparency log (evidence_hash, author_did, signature)
- POST /v1/beacon — temporal beacon (drand/NIST)
- POST /v1/pulse — presence challenge/response
- GET /v1/verify — verify evidence on server
- POST /v1/credential/issue — issue W3C authorship credential
- GET /v1/credential/{id}/status — credential status check
- POST /v1/challenge — attestation challenge request
- POST /v1/confirm-nonce — nonce confirmation
- POST /v1/text-attestation — text attestation submission
- GET /v1/text-attestation/:hash — text attestation lookup

Tasks:
1. Read the Rust client code that calls the API
2. Read the API route handlers
3. Verify POST /v1/text-attestation: auth check, Zod validation, Ed25519 signature
   verification with DST "witnessd-text-attest-v1", Supabase insert, KV cache
4. Verify GET /v1/text-attestation/:hash: public access, KV cache -> Supabase fallback
5. Verify the Rust client sends correct headers, body format, and signature
6. Verify error responses from API are parsed correctly by Rust client
7. Verify the offline queue retries on network failure

Success criteria:
- [ ] POST endpoint validates all fields (content_hash, tier, signature, public_key)
- [ ] Ed25519 signature verified with correct domain separation tag
- [ ] writersproof_id collision handling works (reject if different content)
- [ ] GET endpoint returns attestation details including tier and timestamp
- [ ] KV cache is populated on POST and read on GET
- [ ] Rust client correctly parses success and error responses
- [ ] Offline queue retries with exponential backoff
- [ ] Rate limiting prevents abuse
```

---

### Prompt 19: WritersProof API — Nonce Endpoint Verification

```
Verify the nonce endpoint provides secure, single-use nonces for challenge-response
attestation.

Relevant files (this repo):
- Nonce usage in client: `crates/cpoe/src/writersproof/client.rs` (search for "nonce")
- FFI: `crates/cpoe/src/ffi/sentinel_es.rs` (ffi_sentinel_set_challenge_nonce at line 194)
- FFI attestation: `crates/cpoe/src/ffi/attestation.rs`
  (ffi_sign_attestation_challenge at line 78)

Relevant files (writersproof repo):
- Nonce route: `apps/api/src/routes/nonce.ts`
- Nonce migration: `supabase/migrations/` (search for nonce table/cleanup)

Tasks:
1. Read the nonce generation endpoint
2. Verify nonces are cryptographically random (sufficient entropy)
3. Verify nonces are single-use (consumed after verification)
4. Verify nonce expiration (TTL cleanup per migration 00008 pattern)
5. Verify the Rust client requests and uses nonces correctly
6. Verify challenge-response: request nonce -> sign with device key -> verify signature

Success criteria:
- [ ] Nonces are >= 32 bytes of cryptographic randomness
- [ ] Each nonce can only be used once (consumed on verify)
- [ ] Expired nonces are cleaned up by cron job
- [ ] Nonce TTL is reasonable (5-15 minutes)
- [ ] Rust client handles nonce request/response correctly
- [ ] Challenge signature uses correct key and domain tag
- [ ] Replay attacks are prevented (same nonce can't be reused)
```

---

### Prompt 20: WritersProof API — Evidence Anchoring & Transparency Log

```
Verify evidence anchoring to the WritersProof transparency log works correctly.

Relevant files (this repo):
- Anchor client: `crates/cpoe/src/writersproof/client.rs` (search for "anchor")
- FFI anchor: `crates/cpoe/src/ffi/writersproof_ffi.rs`
  (ffi_anchor_to_writers_proof at line 15, ffi_publish_evidence at line 144)
- Anchoring modules: `crates/cpoe/src/anchors/` (ots.rs at 1071 lines, rfc3161.rs at 868 lines)
- Beacon: `crates/cpoe/src/ffi/beacon.rs` (ffi_submit_beacon, ffi_check_beacon_status,
  ffi_list_beacons)

Relevant files (writersproof repo):
- Anchor route: `apps/api/src/routes/anchor.ts`
- Verify route: `apps/api/src/routes/verify.ts`

Tasks:
1. Trace the anchoring flow: export evidence -> hash -> submit to API -> store anchor receipt
2. Verify the anchor receipt is cryptographically bound to the evidence hash
3. Verify beacon (drand + NIST) integration provides time attestation
4. Verify anchor verification works (given receipt, verify against transparency log)
5. Verify the CLI `--anchor` flag triggers anchoring during export
6. Verify timeout handling (beacon_timeout parameter, default 5s)

Success criteria:
- [ ] Anchoring submits evidence hash (not full evidence) to API
- [ ] Anchor receipt includes timestamp and counter-signature
- [ ] Beacon integration provides drand + NIST time proofs
- [ ] Verification confirms anchor receipt against log
- [ ] Timeout prevents hanging on slow network
- [ ] Anchoring failure doesn't block export (graceful degradation)
```

---

### Prompt 21: Verify Portal — Cross-Platform Hash Consistency

```
Verify that the verify portal at writersproof.com produces identical hashes
to the Rust engine for all text inputs. This is CRITICAL — any divergence
breaks the entire text attestation verification system.

Relevant files (this repo):
- Rust normalization: `crates/cpoe/src/ffi/text_fragment.rs`
  (normalize_for_attestation function — find the exact implementation)
- Rust hashing: same file, SHA-256 of normalized text

Relevant files (writersproof repo):
- JS normalization: `packages/crypto/src/` (normalizeForAttestation, hashTextForAttestation)
- Verify page: `apps/verify/src/pages/VerifyTextPage.tsx`

Tasks:
1. Read the Rust normalize_for_attestation implementation completely
2. Read the JS normalizeForAttestation implementation completely
3. Create a test matrix of inputs and verify IDENTICAL output:
   - ASCII: "Hello, World!" -> normalized form -> SHA-256
   - Unicode NFC: "cafe\u0301" vs "caf\u00e9" (must produce same output)
   - CJK: "写作 证明"
   - Emoji: "Hello 👋 World"
   - Empty after strip: "!@#$%"
   - Whitespace: "Hello\n\n  World\t!!"
   - RTL: Arabic/Hebrew text
   - Mixed scripts: "Hello こんにちは World"
4. Document any divergences and fix them
5. Add cross-validation tests in both Rust and JS

Success criteria:
- [ ] Normalization rules are identical: NFC normalize, lowercase, strip non-alphanumeric
  (preserving Unicode letters/digits)
- [ ] SHA-256 output is byte-identical for all test inputs
- [ ] NFC/NFD equivalence is handled (combining characters normalized)
- [ ] Empty-after-strip case handled identically (both return empty hash or error)
- [ ] Cross-validation tests exist in both Rust and JS with shared test vectors
- [ ] No platform-specific Unicode handling differences
```

---

### Prompt 22: Verify Portal — Full Verification Flow

```
Verify the writersproof.com verify portal correctly handles all verification
scenarios: text attestation lookup, evidence file upload, and compact reference
resolution.

Relevant files (writersproof repo):
- Verify pages: `apps/verify/src/pages/` (VerifyTextPage.tsx, VerifyFilePage.tsx, etc.)
- Crypto package: `packages/crypto/src/`
- API integration: verify portal calls GET /v1/text-attestation/:hash

Relevant files (this repo):
- Compact reference: `crates/cpoe/src/ffi/evidence_export.rs`
  (ffi_get_compact_ref at line 407)
- Verification: `crates/cpoe/src/verify/` (pipeline.rs, verdict.rs, seals.rs)
- WAR verification: `crates/cpoe/src/war/verification.rs` (747 lines)

Tasks:
1. Verify text attestation lookup: user pastes text -> normalize -> hash -> API lookup ->
   display result (tier, timestamp, author public key)
2. Verify file upload: user uploads .cpoe/.cwar/.json -> client-side verification ->
   display chain integrity, signatures, scores
3. Verify compact reference: user enters compact ref -> resolve to full evidence
4. Verify error states: unknown hash, invalid file, network error
5. Verify the portal works without JavaScript errors in latest Chrome/Firefox/Safari

Success criteria:
- [ ] Text lookup returns correct attestation details for known hashes
- [ ] Text lookup shows "not found" for unknown hashes
- [ ] File upload parses and verifies .cpoe (CBOR), .cwar (COSE), .json formats
- [ ] Verification results show: signature validity, chain integrity, forensic scores
- [ ] Compact reference resolves correctly
- [ ] Error states show user-friendly messages
- [ ] Portal works in Chrome, Firefox, and Safari
- [ ] No console errors or warnings
```

---

## Section E: Security Hardening & User-as-Adversary

**Note:** The repo has two audit trackers with open findings:
- `todo.md` (root) — 1206 findings, 31 systemic tasks, ~574 per-site remaining
- `audit-todo.md` (root) — 190 findings (14 High, 52 Medium, 124 Low), 52 fixed, 138 remaining
- Key blocking issues: ~~AUD-026 (checkpoint sig never verified)~~ FIXED, ~~AUD-089 (signing key world-readable)~~ FIXED,
  AUD-124 (TSA cert chain missing), AUD-183 (baseline auto-trusts first session)

### Prompt 26: Input Validation at System Boundaries

```
Audit all system boundaries for input validation: FFI functions (Swift -> Rust),
IPC messages (CLI -> daemon), native messaging (browser -> CLI), file parsing
(evidence files from disk).

Relevant files:
- All FFI functions: `crates/cpoe/src/ffi/` (94 pub fn ffi_* functions)
- IPC message handler: `crates/cpoe/src/ipc/server_handler.rs`
- IPC messages: `crates/cpoe/src/ipc/messages.rs`
- Native messaging: `apps/cpoe_cli/src/native_messaging_host/handlers.rs`
- Evidence parsing: `crates/cpoe/src/evidence/packet.rs`,
  `crates/authorproof-protocol/src/` (CBOR deserialization)
- Config parsing: `crates/cpoe/src/config/types.rs`
- File path handling: across sentinel, store, export modules

Tasks:
1. For each FFI function: verify String parameters are length-checked, paths are
   validated (no directory traversal), numeric parameters have range checks
2. For IPC messages: verify deserialization has size limits, field validation
3. For native messaging: verify JSON parsing has size limits (MAX_MESSAGE_SIZE)
4. For evidence parsing: verify CBOR deserialization bounds allocations
5. For file paths: verify no symlink TOCTOU attacks (SYS-006 pattern)
6. Verify no format string injection in error messages

Success criteria:
- [ ] All FFI String parameters have length limits
- [ ] File paths are canonicalized and checked for traversal
- [ ] IPC messages respect MAX_MESSAGE_SIZE (1MB)
- [ ] CBOR deserialization limits nested depth and allocation size
- [ ] Numeric parameters have explicit range validation
- [ ] No format string injection possible
- [ ] TOCTOU mitigations on file operations (hash-then-open, open-then-hash)
- [ ] Config values are validated on load (not just at use time)
```

---

### Prompt 27: TOCTOU and Race Condition Audit

```
Audit for time-of-check-time-of-use vulnerabilities and race conditions across
concurrent operations.

Relevant files:
- File operations: `crates/cpoe/src/sentinel/core.rs` (file monitoring),
  `crates/cpoe/src/checkpoint/chain.rs` (file hashing),
  `crates/cpoe/src/wal/operations.rs` (WAL writes)
- Concurrent state: `crates/cpoe/src/sentinel/types.rs` (Arc<RwLock<>> patterns),
  `crates/cpoe/src/sentinel/core.rs` (event loop with shared state)
- Store: `crates/cpoe/src/store/mod.rs` (SQLite with concurrent access)
- IPC: `crates/cpoe/src/ipc/server.rs` (concurrent connections)
- DashMap usage: grep for DashMap across codebase
- Lock ordering: `crates/cpoe/src/sentinel/` (signing_key before sessions per AUD-041)

Tasks:
1. Identify all file operations and verify atomic/TOCTOU-safe patterns
2. Map all lock acquisitions and verify consistent ordering (no deadlock)
3. Verify DashMap usage doesn't have read-then-write races
4. Verify SQLite transactions are used for multi-step operations
5. Verify WAL writes are atomic (tempfile + rename pattern)
6. Check for any `unwrap()` on lock acquisition (should use MutexRecover)

Success criteria:
- [ ] File hashing uses open-then-hash (not stat-then-open)
- [ ] Lock ordering is documented and consistent (signing_key -> sessions)
- [ ] No lock held across await points
- [ ] DashMap entry API used (not get-then-insert patterns)
- [ ] SQLite uses BEGIN TRANSACTION for multi-statement operations
- [ ] WAL uses atomic writes (tempfile + persist)
- [ ] All lock acquisition uses MutexRecover (not unwrap)
- [ ] No data races under concurrent FFI calls
```

---

### Prompt 29: Timestamp Integrity and Anti-Replay

```
Audit timestamp handling across the system to prevent clock manipulation
and replay attacks.

Relevant files:
- Timestamp enforcement: `crates/cpoe/src/sentinel/core.rs` (monotonic timestamps)
- VDF time proofs: `crates/cpoe/src/vdf/` (swf_argon2.rs, MerkleVdfProof)
- Roughtime: `crates/cpoe/src/vdf/` (RoughtimeClient, TimeKeeper, TimeAnchor)
- Beacon integration: `crates/cpoe/src/ffi/beacon.rs`
- Checkpoint timestamps: `crates/cpoe/src/checkpoint/types.rs`
- Evidence timestamps: `crates/cpoe/src/evidence/types.rs`
- WAL timestamps: `crates/cpoe/src/wal/`
- SWF duration bounds: documented as named constants (0.5x-3.0x)

Tasks:
1. Verify monotonic timestamp enforcement (>1s regression = error)
2. Verify VDF proofs bind to wall-clock time (not just CPU time)
3. Verify Roughtime/beacon timestamps are checked for consistency
4. Verify checkpoint timestamps can't be backdated
5. Verify evidence packet timestamps match checkpoint chain
6. Test: set system clock back 1 hour, verify detection
7. Verify SWF duration bounds are enforced (0.5x-3.0x)

Success criteria:
- [ ] Monotonic timestamp enforcement catches clock regression > 1s
- [ ] VDF proofs require minimum wall-clock duration
- [ ] Roughtime timestamps are verified against multiple sources
- [ ] Checkpoint timestamps are strictly increasing within a session
- [ ] Evidence packet timestamps are bound to checkpoint chain
- [ ] SWF duration bounds (0.5x-3.0x) are named constants (not magic numbers)
- [ ] Replay detection: resubmitting old evidence is rejected
```

---

### Prompt 30: Denial-of-Service Resilience

```
Audit the system for resource exhaustion and denial-of-service vectors.

Relevant files:
- IPC rate limiting: `crates/cpoe/src/ipc/crypto.rs` (rate limiter),
  `crates/cpoe/src/ipc/rbac.rs`
- FFI injection rate: `crates/cpoe/src/ffi/sentinel_inject.rs` (50 KPS cap)
- Store: `crates/cpoe/src/store/mod.rs` (SQLite, unbounded growth?)
- WAL: `crates/cpoe/src/wal/operations.rs` (write-ahead log size)
- MMR: `crates/cpoe/src/mmr/` (append-only, memory usage)
- Checkpoint chain: `crates/cpoe/src/checkpoint/chain.rs`
- Config: `crates/cpoe/src/config/types.rs` (MAX_FILE_SIZE = 500MB)
- Native messaging: `apps/cpoe_cli/src/native_messaging_host/` (message size limits)

Tasks:
1. Verify SQLite database has size limits or cleanup policies
2. Verify WAL doesn't grow unbounded (rotation or compaction)
3. Verify MMR memory usage is bounded
4. Verify IPC connections have timeout and max connection limits
5. Verify native messaging respects MAX_MESSAGE_SIZE
6. Verify no allocation based on untrusted size (e.g., Vec::with_capacity from user input)
7. Verify file operations respect MAX_FILE_SIZE (500MB)

Success criteria:
- [ ] SQLite has VACUUM or size monitoring
- [ ] WAL rotates or compacts old entries
- [ ] MMR operations are O(log n) memory
- [ ] IPC has connection timeout and max concurrent limit
- [ ] Native messaging rejects messages > MAX_MESSAGE_SIZE
- [ ] No unbounded allocations from untrusted input
- [ ] MAX_FILE_SIZE (500MB) enforced before reading file content
- [ ] Checkpoint count per session is bounded
```

---

## Section G: Final Quality Gates

### Prompt 42: Production Readiness Checklist

```
Go through this production readiness checklist and verify each item.
This is a final sweep before declaring the application production-ready.

Checklist:
1. **Build reproducibility**: Clean build from git clone succeeds
2. **License compliance**: All files have SPDX headers, deny.toml passes
3. **Documentation**: README.md accurate, man pages current, API docs complete
4. **Error messages**: All user-facing errors are actionable (not "failed")
5. **Logging**: Structured logging at appropriate levels, no secrets in logs
6. **Configuration**: All config values have sensible defaults, validation on load
7. **Graceful shutdown**: Daemon, IPC, sentinel all shut down cleanly
8. **Data integrity**: HMAC on all stored events, checkpoint chain verified on load
9. **Backup/recovery**: Identity recoverable from mnemonic, evidence exportable
10. **Versioning**: Cargo.toml versions are consistent, wire format has version field
11. **Telemetry**: No phone-home, no tracking, privacy-preserving
12. **Accessibility**: macOS app supports VoiceOver, keyboard navigation
13. **Performance**: No O(n^2) in hot paths, memory bounded, disk bounded
14. **Concurrency**: No data races, no deadlocks, lock ordering documented
15. **Platform support**: macOS builds on ARM + Intel, CLI on macOS/Linux/Windows

Relevant files:
- README: `README.md` (root), `apps/cpoe_macos/README.md`
- Config: `crates/cpoe/src/config/types.rs`
- Error module: `crates/cpoe/src/error.rs`
- Cargo.toml files: all 5 crate Cargo.toml files
- License headers: all .rs files should have SPDX header

Success criteria:
- [ ] Every checklist item verified with evidence (file path + line number)
- [ ] Any failures documented with specific fix instructions
- [ ] Overall production readiness score: X/15
```

---

### Prompt 43: Comprehensive Security Audit Summary

```
Produce a final security audit summary that covers all findings from prompts
23-30 and any additional issues discovered.

Run these skills in sequence:
1. /security-audit on crates/cpoe/src/crypto/
2. /security-audit on crates/cpoe/src/keyhierarchy/
3. /security-audit on crates/cpoe/src/ipc/
4. /security-audit on crates/cpoe/src/ffi/
5. /audit-file on crates/cpoe/src/sentinel/core.rs
6. /audit-file on crates/cpoe/src/writersproof/client.rs
7. /review on all staged changes

Produce a summary report with:
- Total findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Attack surface map (entry points and their defenses)
- Residual risk assessment
- Comparison to previous audit findings (todo.md tracks 1206 findings)

Success criteria:
- [ ] All CRITICAL findings fixed or documented with mitigation
- [ ] All HIGH findings fixed or documented with accepted risk
- [ ] Attack surface mapped (FFI: 94 entry points, IPC: N message types,
      native messaging: N message types, file parsing: N formats)
- [ ] No regressions from previously fixed findings
- [ ] Residual risk is documented and accepted
```

---

## Execution Order

### Phase 1: Foundation (Prompts 3, 8)
~~Prompts 1, 2, 4, 5, 6, 7 done.~~ 3+8 can run in parallel

### Phase 2: Platform Reliability (Prompts 9-17, partially parallel)
- macOS (9-13) can run in parallel with CLI (14-17)
- Within each group, run sequentially (each builds on prior)

### Phase 3: API & Portal (Prompts 18-22, sequential)
- These touch the same API code and must run in sequence

### Phase 4: Security (Prompts 26-27, 29-30)
~~Prompts 23, 24, 25, 28 done.~~ Run in parallel: 26+27, 29+30

### Phase 5: ~~Complete~~
~~All prompts done (31, 35, 37, 39, 40). Prompts 32-34, 36, 38 removed.~~

### Phase 6: Final Gates (Prompts 42-43, sequential)
~~Prompt 41 done.~~ 42 (checklist) -> 43 (security summary)

---

## Notes

- **Test timing**: `cargo test -p cpoe --lib` takes ~2 minutes.
  `cargo test --features ffi` takes 10+ minutes (do not run iteratively).
  Use `cargo check` for fast feedback loops.
- **macOS submodule**: `apps/cpoe_macos/` is a git submodule. Run
  `git submodule update --init` before macOS prompts.
- **WritersProof API**: Located in a SEPARATE repo at
  `~/workspace_local/Writerslogic/writersproof/` — not in this repo.
- **Current test counts** (verified 2026-04-25):
  Engine: 1375 running, 1107+ pass, 4 pre-existing fail (language_model x2, checkpoint x1, security x1), 4 slow (error_context).
  Protocol: 230 pass. Jitter: 21 pass.
