# Todo
<!-- suggest | Updated: 2026-05-12 | Domain: code | Languages: rust | Files: 455 | Issues: 930 -->

## Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 0 | 52 | 0 |
| HIGH     | 66 | 194 | 0 |
| MEDIUM   | 401 | 8 | 0 |

## Systemic Issues
- [ ] **SYS-001** `MISSING_DOCS`, 5 files, MEDIUM
  <!-- pid:MISSING_DOCS | first:2026-05-12 | last:2026-05-12 -->
  Files: `crates/authorproof-protocol/src/war/profiles/c2pa.rs`, `crates/cpoe/src/rats/eat.rs`, `crates/cpoe/src/war/profiles/c2pa.rs`, `crates/cpoe/src/war/profiles/package.rs`, `crates/cpoe/src/war/profiles/vc.rs`
  Fix: Add optional ai_disclosure parameter; document why external source type selection is needed

- [ ] **SYS-002** `ffi_function_too_long`, 3 files, HIGH
  <!-- pid:ffi_function_too_long | first:2026-05-12 | last:2026-05-12 -->
  Files: `crates/cpoe/src/ffi/evidence_derivative.rs`, `crates/cpoe/src/ffi/system.rs`, `crates/cpoe/src/ffi/writersproof_ffi.rs`
  Fix: Extract sentinel enrichment to separate helper; extract threshold checks to validator; target <100 lines

- [ ] **SYS-003** `LARGE_FUNCTION`, 3 files, MEDIUM
  <!-- pid:LARGE_FUNCTION | first:2026-05-12 | last:2026-05-12 -->
  Files: `crates/cpoe/src/war/profiles/package.rs`, `crates/cpoe/src/war/profiles/standards.rs`, `crates/cpoe/src/war/profiles/vc.rs`
  Fix: Split into smaller phases: encode_ingredients(), serialize_cawg(), build_manifest_json(); compose sequentially

## Critical




















































## High










- [ ] **H-011** `[code_quality]` `crates/authorproof-protocol/src/c2pa/jumbf.rs:111`: Integer overflow unchecked: end_superbox patches length at offset via copy_from_slice(&total_len.to_be_bytes()). If self.buf.len() - offset overflows usize or exceeds u32::MAX, try_from silently retur
  <!-- pid:JUMBF-001-SIZE-CHECK | first:2026-05-12 -->
  Impact: If JUMBF superbox construction creates buffer >4GB (u32 max), length field is patched with error value, creating invalid ISO 19566-5 structure. Downstream JUMBF parsers may crash or skip the box. | Fix: Check buffer size before patching. Ensure total_len fits u32 before constructing box. | Effort: medium







- [ ] **H-018** `[code_quality]` `crates/authorproof-protocol/src/compact_ref.rs:102`: Error handling gap: signable_payload() returns CompactRefError::SerializationError for ciborium failures, but doesn't distinguish between truncation, invalid UTF-8, or actual encoding issues. Caller c
  <!-- pid:COMPACT-001-CBOR-ERROR | first:2026-05-12 -->
  Impact: Signature verification failures are opaque. If CBOR encoding is non-deterministic (unlikely but possible with custom Serialize impls), verification silently fails without diagnostics. | Fix: Wrap ciborium error directly or add detailed error variants for different encoding failures. | Effort: low



- [ ] **H-021** `[code_quality]` `crates/authorproof-protocol/src/forensics_classifier.rs:80`: Insufficient signal fallback is non-deterministic: if signal_count < 2, returns author_attested with empty dominant_signals. Threshold hardcoded at 2 signals; classification logic below assumes >= 2 b
  <!-- pid:FORENSICS-001-SIGNAL-THRESHOLD | first:2026-05-12 -->
  Impact: Authorship classification is unreliable when 1-2 signals available. Caller cannot distinguish 'true author attestation' from 'insufficient data for classification'. UI may misrepresent as 'attested' w | Fix: Return distinct MethodOrigin::InsufficientSignal or separate result type. Document minimum signals required for each method class. | Effort: medium

- [ ] **H-022** `[code_quality]` `crates/authorproof-protocol/src/rfc/biology.rs:410`: Hurst exponent range check (0.55..=0.85) is inclusive on both sides; any H outside this range gets score 0.0. But H=0.85 (boundary) gets score=(1-0)=1.0, while H=0.851 gets 0.0. Discontinuity at bound
  <!-- pid:BIO-002-BOUNDARY-LOGIC | first:2026-05-12 -->
  Impact: Biometric scores have discontinuous jumps at 0.55 and 0.85. Small variations in H measurement cause large confidence shifts. Forensic analysis becomes sensitive to measurement noise. | Fix: Use smooth transition (e.g., 0.55-0.05..0.85+0.05 with fade) instead of hard cutoff. | Effort: medium

- [ ] **H-023** `[code_quality]` `crates/authorproof-protocol/src/rfc/biology.rs:464`: Silent NaN handling: compute_score converts f64 to u16 without validation. If score remains NaN after explicit is_finite check, clamping returns 0.0 silently, losing error context.
  <!-- pid:BIO-001-NAN-SILENT | first:2026-05-12 -->
  Impact: Biometric scoring failures are silent. A malformed input producing NaN in component scores gets mapped to 0 millibits with no diagnostic. Attestation chain loses forensic signal. | Fix: Return Result<u16> or set validation error when NaN is detected. Log warnings on NaN conversion. | Effort: medium










- [ ] **H-033** `[code_quality]` `crates/cpoe/src/analysis/content_detector.rs:1105`: God module: 1105 lines of single-file code. Violates CLAUDE.md guidance: large modules should be split into directory-based submodules. Combines pattern matching, scoring, prose analysis, and classifi
  <!-- pid:ARCH_001_GOD_MODULE | first:2026-05-12 -->
  Impact: Maintenance burden, hard to test in isolation, difficult to extend scoring logic, violates project architecture principles. | Fix: Refactor into submodule: `analysis/content_detector/mod.rs` with `matcher.rs`, `scorer.rs`, `classifier.rs` submodules. Export types from mod.rs. | Effort: large




- [ ] **H-037** `[performance]` `crates/cpoe/src/analysis/labyrinth.rs:380`: O(n²) nested loop in detect_quantization at lines 389-396. For each of 4 scales, iterates all pairs (i, j) to count close points. Nested inside scales iterator via Vec::collect at line 383. Total: ~4M
  <!-- pid:PERF_003_O_N2_QUANTIZATION | first:2026-05-12 -->
  Impact: Quantization detection adds 33% overhead to Labyrinth. Sequential O(n²) calls mean 1000-point analysis easily exceeds 50ms budget. | Fix: 1. Fuse quantization detection into RQA (reuse distance matrix). 2. Implement single-pass detection using recurrence histogram from RQA. 3. Use KdTree radius-count queries instead of all-pairs. | Effort: large













- [ ] **H-050** `[code_quality]` `crates/cpoe/src/checkpoint/chain.rs:778`: commit_rfc_with_nonce has #[allow(clippy::too_many_arguments)] with 8 parameters, exceeds architectural guidance
  <!-- pid:CQ-001 | first:2026-05-12 -->
  Impact: Function signature complexity obscures intent; callers must construct 5+ optional parameters; refactoring opaque | Fix: Group related parameters into structs (e.g., RfcCommitOptions { jitter, time_evidence, physics, challenge_nonce, jitter_sample_hashes }) | Effort: medium

- [ ] **H-051** `[code_quality]` `crates/cpoe/src/checkpoint/chain.rs:805`: commit_rfc_locked() is 220 lines, exceeds 100-line guideline; contains multiple logical phases (content hash → entanglement → SWF → finalization)
  <!-- pid:CQ-002 | first:2026-05-12 -->
  Impact: Phase interdependencies obscured; error propagation across 4 SWF/VDF branches makes auditing difficult | Fix: Split into smaller functions: compute_vdf_input(), compute_swf_proof(), finalize_rfc_checkpoint() | Effort: large

- [ ] **H-052** `[code_quality]` `crates/cpoe/src/collaboration.rs:376`: signing_payload() constructs serde_json objects then encodes to CBOR - 2-step serialization
  <!-- pid:collab_double_serde | first:2026-05-12 -->
  Impact: Intermediate JSON step defeats deterministic CBOR encoding claims. JSON formatting varies across architectures (comment claims CBOR avoids this). | Fix: Directly encode struct fields to CBOR using ciborium, don't go through JSON intermediate. | Effort: high







- [ ] **H-059** `[architecture]` `crates/cpoe/src/ffi/beacon.rs:198`: Business logic (WritersProof anchor request) with forensic evaluation and timeout orchestration in FFI layer
  <!-- pid:ARCH_BUSINESS_LOGIC_IN_FFI | first:2026-05-12 -->
  Impact: FFI function orchestrates complex async operations: beacon fetch, anchor submission, timeout handling, JSON serialization. Mixes trust boundary (FFI) with domain logic (evidence submission). Should be | Fix: Move WritersProof client orchestration to crate::writersproof module, have FFI wrap engine API call | Effort: large




- [ ] **H-063** `[performance]` `crates/cpoe/src/ffi/evidence_export.rs:223`: enrich_checkpoints() processes all events and jitter samples O(n²) for revision depth
  <!-- pid:quadratic_algorithm | first:2026-05-12 -->
  Impact: Quadratic complexity in checkpoint enrichment; slow for large documents | Fix: Compute revision depth incrementally in single pass | Effort: medium









- [ ] **H-072** `[architecture]` `crates/cpoe/src/ffi/report.rs:37`: Complex LRU cache logic in FFI binding layer
  <!-- pid:logic_in_boundary | first:2026-05-12 -->
  Impact: Business logic for forensic result caching should be in core, not FFI wrapper | Fix: Move BoundedLruCache to core module; FFI layer should be thin wrapper | Effort: medium

- [ ] **H-073** `[performance]` `crates/cpoe/src/ffi/report.rs:52`: VecDeque::remove(pos) in LRU cache get path - O(n) operation on every cache access
  <!-- pid:hot_path_vecdeque_remove | first:2026-05-12 -->
  Impact: Hot path forensic cache lookups have linear-time removal cost | Fix: Use doubly-linked list or epoch counter for O(1) eviction tracking | Effort: large

- [ ] **H-074** `[architecture]` `crates/cpoe/src/ffi/report.rs:189`: build_checkpoints() and other checkpoint/report building logic in FFI layer
  <!-- pid:logic_in_boundary | first:2026-05-12 -->
  Impact: Evidence packet construction business logic should be in core, not FFI wrapper | Fix: Move build_checkpoints, compute_event_stats, etc. to core report module; FFI calls them | Effort: large










- [ ] **H-084** `[architecture]` `crates/cpoe/src/ffi/sentinel_witnessing.rs:177`: Forensic analysis execution in FFI status query function (query_store_metrics)
  <!-- pid:ARCH_FORENSICS_IN_STATUS_FFI | first:2026-05-12 -->
  Impact: ForensicEngine::evaluate_authorship() (expensive post-hoc analysis) called on every ffi_sentinel_witnessing_status() call. FFI should report cached metrics, not compute them. Witnesses performance reg | Fix: Pre-compute forensic scores in sentinel, cache them, return cached value from FFI query_store_metrics | Effort: large

- [ ] **H-085** `[code_quality]` `crates/cpoe/src/ffi/system.rs:162`: Function ffi_list_tracked_files is 161 lines (exceeds 100-line threshold). Complex branching: sentinel enrichment, canonicalization, duplicate detection, threshold checks.
  <!-- pid:ffi_function_too_long | first:2026-05-12 -->
  Impact: Difficult to reason about correctness at FFI boundary. Hard to test all paths. Risk of subtle bugs in path normalization or session matching logic. | Fix: Extract sentinel enrichment to separate helper; extract threshold checks to validator; target <100 lines | Effort: medium

- [ ] **H-086** `[architecture]` `crates/cpoe/src/ffi/system.rs:221`: Business logic in FFI boundary: keystroke-to-content penalty calculation with magic values (0.05, 0.1, 0.3, 0.4, 0.8). Scoring algorithm should be in core engine, not binding layer.
  <!-- pid:logic_in_boundary_scoring | first:2026-05-12 -->
  Impact: Forensic scoring logic duplicated/diverged in FFI layer. Difficult to maintain consistency across platforms (Swift/Kotlin). Hard to audit scoring decisions. | Fix: Move keystroke_ratio_penalty calculation to core forensics module; FFI should only call and marshall results | Effort: medium

- [ ] **H-087** `[code_quality]` `crates/cpoe/src/ffi/system.rs:326`: Function ffi_get_log is short (44 lines) but contains path validation with special-case virtual paths. Logic should use validated path type from core, not string matching.
  <!-- pid:architecture_string_path_types | first:2026-05-12 -->
  Impact: Path type checking scattered across FFI. Risk of missing edge cases (typos in 'ephemeral://', etc.). Hard to audit all valid path prefixes. | Fix: Use core PathKind enum with impl FromStr; return error on invalid prefix rather than silent rejection | Effort: medium

- [ ] **H-088** `[architecture]` `crates/cpoe/src/ffi/text_fragment.rs:155`: Complex text normalization logic in FFI binding (normalize_for_attestation)
  <!-- pid:logic_in_boundary | first:2026-05-12 -->
  Impact: Platform-specific Unicode handling belongs in core, not FFI wrapper | Fix: Move normalize_for_attestation to core protocol crate or utils | Effort: medium







- [ ] **H-095** `[code_quality]` `crates/cpoe/src/ffi/writersproof_ffi.rs:113`: Function ffi_publish_evidence is 157 lines. Long chain of validations, transformations, and async operations. Multiple error paths with different return types.
  <!-- pid:ffi_function_too_long | first:2026-05-12 -->
  Impact: Hard to trace error paths; difficult to audit all validation checks. Risk of missing validation or returning partial state on error. | Fix: Split into: validate_document() -> load_events() -> build_signature() -> publish_async(); each <60 lines with clear pre/post conditions | Effort: large




- [ ] **H-099** `[code_quality]` `crates/cpoe/src/fingerprint/voice.rs:549`: StyleCollector struct has 23 fields (lines 550-584), all public mutable. No encapsulation of invariants. For example, word_lengths array and word_length_transition_counts must stay in sync, but there'
  <!-- pid:P008_COLLECTOR_ENCAPSULATION | first:2026-05-12 -->
  Impact: Caller can corrupt internal state: set word_lengths[0] = 999 without updating corresponding transition counts. Silent data inconsistency. | Fix: Hide fields behind private access (pub(crate)) and validate mutations in setter methods (e.g., set_word_lengths, record_transition). Use builder pattern for initial setup. | Effort: large

- [ ] **H-100** `[performance]` `crates/cpoe/src/forensics/advanced_metrics.rs:399`: fit_three_phase_model() O(N²) nested loop over (n/5 to n/2) × (p1+n/5 to 4n/5) with no iteration cap
  <!-- pid:ON2_UNCAPPED_SEARCH | first:2026-05-12 -->
  Impact: For MAX_FATIGUE_ANALYSIS_SAMPLES=2500: worst case ~(1500)*(1400)=2.1M iterations. On slow device >100ms latency, blocks main thread. | Fix: Add early termination with convergence threshold; use golden-section search or limit iterations to O(N log N) | Effort: large







- [ ] **H-107** `[code_quality]` `crates/cpoe/src/forensics/dictation.rs:94`: score_dictation_plausibility applies multiplicative penalties without bounds checking between multiplications
  <!-- pid:cascading_penalties | first:2026-05-12 -->
  Impact: Multiple penalty multiplications can produce very small near-zero scores; cascading penalties from independent checks may be non-linear and unintuitive | Fix: Track accumulated penalty linearly or use additive adjustments; document interaction between penalty combinations | Effort: medium


























- [ ] **H-133** `[code_quality]` `crates/cpoe/src/keyhierarchy/puf.rs:74`: recover_from_mnemonic() does not validate that seed matches the original device after recovery
  <!-- pid:device_id_not_validated_after_recovery | first:2026-05-12 -->
  Impact: Line 255 calls Self::new_with_path(seed_path) after writing recovered seed. This recreates the PUF and computes a new device_id (line 110). If mnemonic is recovered on a different device, device_id wi | Fix: After recovery, verify device_id or hostname match, or document that device_id WILL change and callers must update identity. | Effort: small





- [ ] **H-138** `[code_quality]` `crates/cpoe/src/keyhierarchy/session.rs:98`: Session struct cloned multiple times in export() path without documenting memory footprint
  <!-- pid:session_clone_large_data | first:2026-05-12 -->
  Impact: Line 359: signatures vector is cloned into evidence. If session has thousands of checkpoints, cloning copies gigabytes of data. No lazy iterator or streaming option. | Fix: Use Arc<[CheckpointSignature]> or implement streaming export(). | Effort: medium

- [ ] **H-139** `[code_quality]` `crates/cpoe/src/keyhierarchy/session.rs:132`: sign_checkpoint() and sign_checkpoint_with_counter() are nearly identical; 90% code duplication
  <!-- pid:signing_logic_duplication | first:2026-05-12 -->
  Impact: Lines 119-166 and 173-242 implement checkpoint signing with and without counter. The two functions share HKDF derivation, Lamport signing, ratchet advance logic. Changes to one often must be applied t | Fix: Extract common logic to _sign_checkpoint_impl(with_counter: bool, ...) or use builder pattern. | Effort: large


- [ ] **H-141** `[code_quality]` `crates/cpoe/src/keyhierarchy/session.rs:354`: Session::export() clones checkpoint signatures without validating ordinal sequence
  <!-- pid:export_unvalidated_ordinals | first:2026-05-12 -->
  Impact: Line 359 clones self.signatures directly into evidence. No assertion that ordinals are contiguous 0..n. Callers must verify via verify_checkpoint_signatures(), but export() could be called on corrupte | Fix: Assert ordinal sequence in export(), or add invariant check in sign_checkpoint(). | Effort: small






- [ ] **H-147** `[performance]` `crates/cpoe/src/platform/linux/keystroke.rs:214`: device_id Arc cloned on every keystroke event if device is physical
  <!-- pid:per_event_arc_clone | first:2026-05-12 -->
  Impact: Arc::from(format!(...)) allocation cached, but Arc::clone() on every event. Even clone() has atomics overhead in hot path. | Fix: Move device_id Arc clone outside the event loop. Store once in thread closure. | Effort: small

- [ ] **H-148** `[performance]` `crates/cpoe/src/platform/linux/mouse.rs:103`: Arc cloned from Device ID format string on every mouse move event
  <!-- pid:per_event_allocation_mouse | first:2026-05-12 -->
  Impact: Arc::from(format!()) creates allocation + Arc clone per event in hot path. Inefficient. | Fix: Cache device_id Arc at thread start, reuse for all events from device. | Effort: small

- [ ] **H-149** `[code_quality]` `crates/cpoe/src/platform/macos/keystroke.rs:1`: File exceeds 700 lines with multiple responsibilities: EventTapRunner, KeystrokeMonitor, MacOSKeystrokeCapture
  <!-- pid:large_module_single_responsibility | first:2026-05-12 -->
  Impact: Difficult to audit, test, and maintain. Multiple concern mixing: tap lifecycle, monitoring, capture, verification all in one file. Hard to isolate bugs. | Fix: Split into: tap_runner.rs (EventTapRunner), monitor.rs (KeystrokeMonitor), capture.rs (MacOSKeystrokeCapture). Separate concerns. | Effort: large






- [ ] **H-155** `[code_quality]` `crates/cpoe/src/platform/windows.rs:1`: File 715 lines with mixed responsibilities: permission, KeystrokeMonitor, WindowsKeystrokeCapture, mouse capture, multiple global static mutexes
  <!-- pid:mixed_responsibilities_global_state | first:2026-05-12 -->
  Impact: Hard to understand data flow. Multiple global statics with complex try_lock patterns scattered throughout. Race conditions hidden in callback definitions. Difficult to test. | Fix: Extract mouse capture to separate module. Consolidate global state management into a single WindowsHookState struct. | Effort: large




- [ ] **H-159** `[performance]` `crates/cpoe/src/platform/windows.rs:648`: Float bit manipulation (to_bits/from_bits) used for atomic storage instead of direct float ops
  <!-- pid:float_bit_manipulation_hot_path | first:2026-05-12 -->
  Impact: Converting f64 to i64 bits on every mouse move to store in AtomicI64, then back from bits on next event. Extra memory operations in hot path. Inefficient encoding of floating point. | Fix: Consider using AtomicU64 for bits directly, or use f64 wrapper atomic if available. Document why float bits are needed. | Effort: small







- [ ] **H-166** `[code_quality]` `crates/cpoe/src/report/html/sections/advanced.rs:1`: File advanced.rs contains 684 lines with 10 public functions. Multiple functions (write_forensic_breakdown, write_activity_contexts, write_declaration_summary) each exceed 100+ lines of formatting log
  <!-- pid:advanced:1:module-size | first:2026-05-12 -->
  Impact: Single-file module organization makes testing and navigation difficult. Should be split into further submodules by concern (forensics_detail.rs, activities.rs, declaration.rs). | Fix: Reorganize: crates/cpoe/src/report/html/sections/advanced/forensics.rs, .../activities.rs, .../key_hierarchy.rs, etc. Re-export from mod.rs. | Effort: HIGH






- [ ] **H-172** `[code_quality]` `crates/cpoe/src/report/pdf/layout_sections/page2.rs:6`: Function draw_page2() is 391 lines long, exceeding 100-line guideline from CLAUDE.md (line 99: '100' max_width format rule). Complex multi-stage layout logic crammed into single function.
  <!-- pid:page2:6:large-function | first:2026-05-12 -->
  Impact: Difficult to test individual sections, high cognitive load for reviewers, increased maintenance burden, harder to locate bugs in specific layout logic. | Fix: Split into section-specific functions: draw_page2_session_timeline(), draw_page2_process_evidence(), draw_page2_flags(), draw_page2_forgery_resistance(). Each should handle 40-60 lines max. | Effort: MEDIUM

- [ ] **H-173** `[code_quality]` `crates/cpoe/src/report/pdf/layout_sections/page3.rs:6`: Function draw_page3() is 372 lines long, exceeding 100-line guideline from CLAUDE.md. Handles 6 major sections: scope, verification, limitations, analyzed text, verification block, footer.
  <!-- pid:page3:6:large-function | first:2026-05-12 -->
  Impact: Same as page2: difficulty testing, high cyclomatic complexity, maintenance risk in PDF generation logic (outputs are immutable once sent to users). | Fix: Extract into: draw_page3_scope(), draw_page3_verification(), draw_page3_limitations(), draw_page3_analyzed_text(), draw_page3_verification_block(). Max 50-70 lines each. | Effort: MEDIUM




- [ ] **H-177** `[code_quality]` `crates/cpoe/src/sealed_identity/store.rs:126`: Function unseal_master_key() is 74 lines: complex anti-rollback logic with nested match/if chains
  <!-- pid:seal_rollback_complexity | first:2026-05-12 -->
  Impact: Difficult to audit security-critical rollback detection. Multiple code paths increase bug surface. | Fix: Extract anti-rollback verification to separate fn verify_counter_antirollback(&blob, &binding) -> Result<bool> and fn update_counter(&mut blob, current) -> Result<()>. | Effort: high


- [ ] **H-179** `[code_quality]` `crates/cpoe/src/sealed_identity/store.rs:394`: Function persist_blob() has implicit error swallowing pattern with tempfile
  <!-- pid:seal_persist_order | first:2026-05-12 -->
  Impact: If restrict_permissions fails (line 412), blob is still persisted with wrong permissions and error is .ok()'d away. | Fix: Ensure restrict_permissions is called before tmp.persist, or check result explicitly before persist. | Effort: medium


- [ ] **H-181** `[performance]` `crates/cpoe/src/sentinel/app_registry.rs:839`: lookup() uses linear search over KNOWN_WRITING_APPS slice (100+ entries). Called per-keystroke by title inference. No indexing or caching.
  <!-- pid:linear_app_lookup | first:2026-05-12 -->
  Impact: O(n) lookup on every keystroke. With 100 apps and 10,000 keystrokes/min per session, ~1M string comparisons/min. Each comparison is case-insensitive (extra work). | Fix: Build HashMap<String, &WritingApp> keyed by lowercase bundle_id at startup. Or use build-time codegen to generate perfect hash. | Effort: small




- [ ] **H-185** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:200`: Deprecated rand::rng() usage: line 200 and line 274 use rand::rng().fill_bytes(). Modern Rust crypto patterns prefer rand::thread_rng() or ChaCha20Rng::from_entropy(). Using deprecated API may be a si
  <!-- pid:deprecated-api-usage | first:2026-05-12 -->
  Impact: If rand crate is updated to remove rng() (already deprecated as of rand 0.8+), compilation will fail. No functional impact currently, but technical debt. Also, rand::rng() does not provide guaranteed  | Fix: Replace `rand::rng()` with `rand::thread_rng()` or `use rand::RngCore; rand_chacha::ChaCha20Rng::from_entropy()`. This is a simple find+replace across the crate. | Effort: small


- [ ] **H-187** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:454`: start() method is 228 lines with multiple nested async blocks and clones. Initialization is spread across multiple closures. Hard to understand the initialization order and dependencies.
  <!-- pid:complex-async-initialization | first:2026-05-12 -->
  Impact: Hard to reason about when subsystems are ready. Difficult to add new subsystems or change initialization order. Testing is hard because initialization is implicit in the async loop. | Fix: Extract initialization into smaller methods: init_focus_monitor(), init_keystroke_bridge(), etc. Each returns a result. Then call all in sequence, then spawn the loop. Clearer dependencies. | Effort: large

- [ ] **H-188** `[code_quality]` `crates/cpoe/src/sentinel/core_session.rs:1`: Excessive imports and re-exports from helpers: file imports from super::helpers::* and re-exports common types. If helpers.rs is large (not shown), this is an anti-pattern (see CLAUDE.md: 'No blanket 
  <!-- pid:blanket-imports | first:2026-05-12 -->
  Impact: Hidden dependencies: callers of core_session cannot tell which functions come from helpers without reading the source. Harder to trace call chains. If helpers.rs is >200 lines, code organization is po | Fix: Use explicit imports: `use super::helpers::{focus_document_sync, ...}` instead of `use super::helpers::*`. Check helpers.rs size; if >200 lines, split into submodules. | Effort: medium

- [ ] **H-189** `[code_quality]` `crates/cpoe/src/sentinel/core_session.rs:27`: start_witnessing function is 167 lines with multiple phases (validation, lock, store, WAL, event). Phases are not clearly separated. Easy to miss lock ordering requirements.
  <!-- pid:complex-multi-phase-function | first:2026-05-12 -->
  Impact: Hard to maintain. Lock ordering is embedded in code flow rather than enforced by structure. If refactored, ordering bugs will slip in. | Fix: Refactor into phases with explicit names: validate_path(), acquire_locks(), load_stats(), create_wal(), insert_session(), emit_event(). Each returns early on error. Replaces nested if/let with clear f | Effort: large


- [ ] **H-191** `[code_quality]` `crates/cpoe/src/sentinel/core_session.rs:94`: Nested unwrap in nested match: guard.as_ref().unwrap().load_document_stats(...). Pattern match `Some(ref guard) if guard.is_some()` is equivalent to `Some(ref Some(_))`, creating a redundant double-So
  <!-- pid:nested-option-patterns | first:2026-05-12 -->
  Impact: Poor readability and potential source of future bugs. If logic is refactored, the double-Some pattern may mask intent. Unwrap will panic if guard.is_none(), even though the guard pattern already guara | Fix: Simplify to: `if let Some(Some(ref store)) = store_guard { store.load_document_stats(...) }` or use nested if let. This eliminates the redundant pattern match and unwrap. | Effort: small





- [ ] **H-196** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:280`: record_keystroke_to_session is complex function (~110 lines) with nested if/match statements (>4 levels of nesting). Readability is poor.
  <!-- pid:complex-function-nesting | first:2026-05-12 -->
  Impact: Hard to understand keystroke processing logic. Bugs in nesting levels are hard to spot. Maintainability is low. Testing is hard because the function has multiple paths. | Fix: Extract substeps into helper functions: validate_keystroke_event, record_jitter_sample, update_behavioral_entropy, assess_transcription. Each <20 lines, single responsibility. Reduces nesting to 2-3 l | Effort: medium

- [ ] **H-197** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:421`: Content fingerprinting in spawn_blocking but sessions lock held until closure: spawn_blocking at line 485 captures fp_sessions Arc, which is then read at line 503 inside the blocking task. If the even
  <!-- pid:nested-lock-in-spawn-blocking | first:2026-05-12 -->
  Impact: Deadlock risk if event loop blocks on checkpoint_idle_session while content_fingerprinting spawn_blocking is waiting for sessions read lock that's held by stopped tasks. Not an immediate bug, but frag | Fix: Extract needed session data before spawning (clone session_id, app_bundle_id) so spawn_blocking doesn't depend on Arc references to live locks. Scope the read lock tightly around clone operations, the | Effort: medium

- [ ] **H-198** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:503`: Poison recovery on RwLock with unwrap_or_else: read().unwrap_or_else(|p| p.into_inner()) bypasses lock-order assertions (AUD-041 not enforced in this path)
  <!-- pid:concurrency-lock-order-violation | first:2026-05-12 -->
  Impact: Lock ordering violation: this code does not use lock_order::assert_order, allowing reads to proceed without conforming to AUD-041 specification for signing_key < sessions lock ordering. Content finger | Fix: Replace with read_recover() which internally enforces ordering, or wrap in lock_order::assert_order (if appropriate for this context). Alternatively, document why this path is exception to AUD-041. | Effort: small



- [ ] **H-201** `[performance]` `crates/cpoe/src/sentinel/event_handlers.rs:597`: keys().cloned().collect() creates intermediate Vec during idle check: line 597 in handle_idle_check clones all session paths into a Vec. If there are 100s of sessions, this is a full copy. This is don
  <!-- pid:unnecessary-allocation | first:2026-05-12 -->
  Impact: Unnecessary allocation: collecting all keys into a Vec when they could be filtered in-place. For 100 sessions, this is ~1.6KB per 30s, negligible. But for 10K sessions, this becomes a garbage collecti | Fix: Use Vec::with_capacity() to pre-allocate once, or collect directly into a Vec using filter + map in a single pass. Or use a temporary Vec only if needed. Current code is correct but inefficient; consi | Effort: small


- [ ] **H-203** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:671`: Stale reference in closure: line 671-673 computes `first_tracked_at` using session reference obtained at line 649, but map is dropped at line 674. Stats struct is built with data from dropped map - se
  <!-- pid:post-drop-data-construction | first:2026-05-12 -->
  Impact: No functional issue - all session fields are cloned into stats before lock drop. However, pattern is confusing: data structures are built after scope end rather than during scope. Maintainability risk | Fix: Move stats struct construction inside the map lock scope (lines 648-673), THEN drop(map) at the end. This makes lock lifetime explicit. Current code is safe because all uses are cloned, but intent is  | Effort: medium


- [ ] **H-205** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:1006`: Mutable map held across nested write_recover() calls: line 1006 acquires sessions write lock, then at line 1062 calls cached_store.lock_recover() while still holding sessions lock. This is correct per
  <!-- pid:panic-safety-under-lock | first:2026-05-12 -->
  Impact: If session retrieval panics (should not happen, but defensive), write lock remains held until end of function, blocking all other session operations. Blocks checkpoint, keystroke recording, etc. Poten | Fix: Add explicit error handling: `let Some(mut session) = map.get_mut(path) else { return false; };` to ensure early exit without lock. Or restructure to minimize code under lock. Currently safe but not p | Effort: small


- [ ] **H-207** `[code_quality]` `crates/cpoe/src/sentinel/focus.rs:99`: Function start() has 302 lines (lines 99-400). Exceeds 100-line threshold with deeply nested branching, macro usage, and complex state management.
  <!-- pid:large_function | first:2026-05-12 -->
  Impact: Difficult to test, understand, and maintain. Hard to debug control flow through nested if-else within async closure spawning. | Fix: Extract focus change detection logic into separate helper function. Split polling loop from initialization. | Effort: medium

- [ ] **H-208** `[performance]` `crates/cpoe/src/sentinel/focus.rs:134`: Multiple string clones in hot polling loop: info.application.clone() at lines 134, 138, 145-146, 219, etc. Loop runs every 100ms per poll_interval_ms.
  <!-- pid:hot_path_clone | first:2026-05-12 -->
  Impact: Allocations on every poll tick even when app unchanged. Per-keystroke focus lookup triggers polling state reads; clones add GC pressure and latency jitter. | Fix: Cache current_app as owned String before loop iteration. Clone only on app change, not every tick. Store references where possible. | Effort: small

- [ ] **H-209** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:19`: Function handle_focus_event_sync missing documentation—9 parameters, complex lock coordination logic
  <!-- pid:maintainability_missing_pub_docs_complex_fn | first:2026-05-12 -->
  Impact: Function is public API boundary for sentinel event handling. Missing docs on purpose, lock order guarantees, and parameter semantics. | Fix: Add /// docs explaining: sync-only design, focus state updates under write lock, TOCTOU prevention via single write lock. | Effort: small

- [ ] **H-210** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:245`: Function focus_document_sync missing documentation—7 parameters, complex session initialization logic
  <!-- pid:maintainability_missing_pub_docs_session_logic | first:2026-05-12 -->
  Impact: Public API, multiple concerns: hash pre-computation, session creation, WAL buffering, event broadcast. No docs on interaction. | Fix: Add /// docs explaining workflow: pre-hash to avoid lock contention, session init under write lock, WAL append post-lock release. | Effort: small


- [ ] **H-212** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:443`: Function handle_change_event_sync missing documentation—7 parameters, 200+ lines, multiple event types
  <!-- pid:maintainability_missing_pub_docs_change_handling | first:2026-05-12 -->
  Impact: Public API for file change handling. No docs on WAL handling, bundle extraction, lock ordering, or event type dispatch. | Fix: Add /// docs with examples: WAL pseudo-save flow, bundle path extraction, Rename/Delete/Modified dispatch. | Effort: small




- [ ] **H-216** `[performance]` `crates/cpoe/src/sentinel/types.rs:917`: DocumentSession manual Clone impl clones 45 fields including jitter_samples (Vec), focus_switches (VecDeque), segment_counts (HashMap). Full deep clone on every evidence packet generation.
  <!-- pid:expensive_session_clone | first:2026-05-12 -->
  Impact: Evidence generation clones entire session on every checkpoint. jitter_samples can be 50K items (~1.2MB); cloning is O(n) per keystroke checkpoint. | Fix: Move jitter_samples and segment_counts to Arc<Mutex<...>> or use Cow<'a> for evidence generation. Checkpoint should borrow, not clone. | Effort: large






- [ ] **H-222** `[performance]` `crates/cpoe/src/store/events.rs:409`: get_all_event_timestamps_unverified() has no LIMIT and collects all timestamps into Vec. Called by get_global_activity() which maps to (ts, 1) pairs, then serializes for charting.
  <!-- pid:UNBOUNDED_QUERY_003 | first:2026-05-12 -->
  Impact: Unbounded memory for charting queries on large stores; all events loaded into memory even if only recent data is needed. | Fix: Add start_ts filtering (already done) but add optional limit: pub fn get_global_activity(&self, start_ts: i64, limit: Option<u32>) | Effort: small

- [ ] **H-223** `[performance]` `crates/cpoe/src/store/events.rs:454`: get_all_events_grouped() loads every event from the database and groups in-memory. No LIMIT. HashMap insertion is O(1) average but no cap on map size.
  <!-- pid:UNBOUNDED_QUERY_004 | first:2026-05-12 -->
  Impact: Unbounded memory consumption proportional to event count. A store with 1M events loads all into a single HashMap. | Fix: Add optional limit, or paginate: pub fn get_all_events_grouped_paginated(&self, limit: u32, offset: u32) | Effort: medium


- [ ] **H-225** `[performance]` `crates/cpoe/src/store/text_fragments.rs:256`: get_unsynced_fragments() at line 256 has no LIMIT; unbounded result set. In a store with millions of fragments, this loads all unsynced fragments into memory at once.
  <!-- pid:UNBOUNDED_QUERY_001 | first:2026-05-12 -->
  Impact: Memory exhaustion on stores with large numbers of unsynced fragments; potential OOM and service crash. | Fix: Add optional limit parameter: pub fn get_unsynced_fragments(&self, limit: Option<u32>) -> anyhow::Result<Vec<TextFragment>> | Effort: small

- [ ] **H-226** `[performance]` `crates/cpoe/src/store/text_fragments.rs:337`: get_all_fragments() at line 337 has no LIMIT; queries entire table. Used for no obvious purpose in production code.
  <!-- pid:UNBOUNDED_QUERY_002 | first:2026-05-12 -->
  Impact: Full table scan on every call; O(n) memory and I/O cost for unbounded result set. | Fix: Add limit parameter or document that this should only be called for small stores. Consider removing if not used in production. | Effort: small

- [ ] **H-227** `[code_quality]` `crates/cpoe/src/timing.rs:187`: add_packet_stats() silently caps f64 values at infinity when .is_finite() check fails
  <!-- pid:timing_silent_nan | first:2026-05-12 -->
  Impact: NaN/Inf inputs are silently ignored without logging, causing loss of data and no audit trail. | Fix: Log warning and return error when non-finite values detected: if !vdf_time.is_finite() { log::warn!("non-finite VDF time received"); return Err(...); } | Effort: medium















- [ ] **H-242** `[code_quality]` `crates/cpoe/src/wal/operations.rs:1054`: Lost entry estimate divides by fixed 154 bytes (4-byte len + 150-byte min entry); assumes uniform entry size
  <!-- pid:CQ-007 | first:2026-05-12 -->
  Impact: Variable-size entries (e.g., KeystrokeBatch vs. Checkpoint) cause estimate variance; user-facing recovery count unreliable | Fix: Scan first 100 non-corrupt entries to compute average size, use for estimate | Effort: small



- [ ] **H-245** `[architecture]` `crates/cpoe/src/war/profiles/standards.rs:31`: Three nearly-identical IPTC Digital Source Type URIs duplicated across multiple files (standards.rs, c2pa.rs, eu_ai_act.rs); changes require coordinated edits across three locations
  <!-- pid:CODE_DUPLICATION_IPTC | first:2026-05-12 -->
  Impact: Inconsistent URIs across standards outputs if one location missed in updates; maintainability burden | Fix: Extract to shared constants module (e.g., iptc_constants.rs); re-export across profiles | Effort: medium

- [ ] **H-246** `[maintainability]` `crates/cpoe/src/war/profiles/standards.rs:200`: Article 50 EU AI Act IPTC mapping test code duplicated; test_article50_iptc_mapping() (line 188-219) creates 4 declarations and calls Article50Compliance::from_declaration() identically four times wit
  <!-- pid:DUPLICATED_TEST_CODE | first:2026-05-12 -->
  Impact: Test maintenance burden; changes to mapping logic must be synchronized across four near-identical test cases | Fix: Parameterize test with vec![(AiExtent::None, expected_uri), ...]; iterate single assertion loop | Effort: small

- [ ] **H-247** `[architecture]` `crates/cpoe/src/war/profiles/standards.rs:569`: Hardcoded NIST RMF and ISO 42001 mappings in OnceLock static — future maintenance requires code changes; no external config loader for standards updates
  <!-- pid:HARDCODED_MAPPINGS | first:2026-05-12 -->
  Impact: Standards compliance updates (e.g., new NIST subcategories post-2026) require recompilation and redeployment; cannot hot-update | Fix: Load mappings from config/database; provide versioned standards registry | Effort: large




- [ ] **H-251** `[code_quality]` `crates/cpoe/src/war/verification.rs:214`: compute_seal function 85 lines; multiple nested if-let chains for optional fields
  <!-- pid:large_function_mixed_concerns | first:2026-05-12 -->
  Impact: Function mixes hash computation logic with field extraction; difficult to test hash chains in isolation | Fix: Extract jitter_hash and vdf_output extraction into separate pure functions; compute_seal becomes hash composition | Effort: medium










## Medium
- [ ] **M-001** `[maintainability]` `crates/authorproof-protocol/src/war/profiles/c2pa.rs:7`: Custom Result type defined as Result<T> = std::result::Result<T, String> without context; protocol library errors lack diagnostic information
  <!-- pid:UNSTRUCTURED_ERRORS | first:2026-05-12 -->
  Impact: Cannot trace error origin (deserialize, missing field, type mismatch); error messages generic | Fix: Use a proper error type per the project's Error enum; propagate with context | Effort: medium

- [ ] **M-002** `[maintainability]` `crates/authorproof-protocol/src/war/profiles/c2pa.rs:67`: to_c2pa_assertion() returns Result<C2paAssertion, String> using String error type instead of structured error enum; cannot distinguish between differe
  <!-- pid:UNSTRUCTURED_ERRORS | first:2026-05-12 -->
  Impact: Error handling in caller requires string parsing; limits error recovery options | Fix: Use a proper Error enum with variants: MissingPopSubmodule, SerializationFailed | Effort: medium

- [ ] **M-003** `[security]` `crates/authorproof-protocol/src/war/profiles/c2pa.rs:68`: to_c2pa_assertion() function does no validation of input EAR token structure; assumes ear_verifier_id, ear_status, etc. are present and well-formed
  <!-- pid:MISSING_PRECONDITION_CHECKS | first:2026-05-12 -->
  Impact: Malformed EAR tokens silently produce C2PA assertions with empty/default values | Fix: Add precondition validation: check ear_verifier_id has non-empty build/developer; validate ear_status is known enum value | Effort: medium

- [ ] **M-004** `[maintainability]` `crates/authorproof-protocol/src/war/profiles/c2pa.rs:107`: to_c2pa_action() has no documentation; callers must infer that it returns only 'humanCreation' type regardless of AI disclosure; no parameter to custo
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: Reusability limited; protocol library users cannot generate AI-disclosed action entries from this function | Fix: Add optional ai_disclosure parameter; document why external source type selection is needed | Effort: small

- [ ] **M-005** `[code_quality]` `crates/cpoe/src/analysis/active_probes.rs:87`: analyze_galton_invariant and analyze_reflex_gate are separate functions with similar structure: both extract samples, validate count, compute metrics,
  <!-- pid:CQ_006_DUPLICATED_ANALYSIS | first:2026-05-12 -->
  Impact: Bug fixes in one analysis need to be applied to the other. Code review overhead. Difficult to add new probe types. | Fix: 1. Extract common analysis pattern: `trait ProbeAnalyzer { fn analyze(samples: &[ProbeSample]) -> Result<...> }`. 2. Implement for Galton, Reflex. 3.  | Effort: medium

- [ ] **M-006** `[security]` `crates/cpoe/src/analysis/active_probes.rs:113`: Side-channel risk in probe generation: analyze_galton_invariant uses raw deviation values (line 112: deviation = sample.interval_ms - baseline_interva
  <!-- pid:SEC_003_TIMING_SIDECHAIN | first:2026-05-12 -->
  Impact: Timing variation leaks which interval samples triggered anomaly detection. Attacker can craft probe responses to avoid detection by modulating timing  | Fix: 1. Use constant-time loops (no data-dependent breaks). 2. Precompute recovery windows regardless of perturbation. 3. Run full analysis even on non-per | Effort: medium

- [ ] **M-007** `[error_handling]` `crates/cpoe/src/analysis/active_probes.rs:142`: estimate_decay_rate at line 206 iterates deviations.enumerate() with no bounds on decay_rate calculation (line 221). If deviation fluctuates wildly, -
  <!-- pid:ERR_009_DECAY_RATE | first:2026-05-12 -->
  Impact: If deviations cross zero boundary, ln(y/y0) fails silently (caught by is_finite check). Decay rate estimate becomes unreliable. Counter incremented on | Fix: 1. Add explicit zero check before ln: if y.abs() < 1e-10 skip this interval. 2. Don't count it in average. 3. Document handling of crossing-zero inter | Effort: small

- [ ] **M-008** `[error_handling]` `crates/cpoe/src/analysis/active_probes.rs:159`: Division by zero guard at line 159: if absorption_coefficient > 0.0 { time_constant_ms = baseline / coeff }, else { INFINITY }. Returning INFINITY is 
  <!-- pid:ERR_005_INF_PROPAGATION | first:2026-05-12 -->
  Impact: Silent degradation: INFINITY time constants are returned and serialized. Deserialization on other systems may fail. Asymmetry factor is arbitrary (1.0 | Fix: 1. Return error if absorption_coefficient == 0: `Err(ActiveProbeError::CalculateAbsorptionFailed)`. 2. Check accel_mean before division: return error  | Effort: small

- [ ] **M-009** `[security]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:13`: Forgery thresholds are module-level constants but are never validated against real human data. No calibration data, no empirical testing against known
  <!-- pid:SEC_008_UNVALIDATED_THRESHOLDS | first:2026-05-12 -->
  Impact: Thresholds lack empirical foundation. Attacker with access to source code can craft typing patterns that pass all forgery checks (CV=0.2001, skewness= | Fix: 1. Add comment with source: e.g., '// Calibrated against 1000 human typists, 95% specificity'. 2. Version thresholds with git tag. 3. Publish calibrat | Effort: medium

- [ ] **M-010** `[code_quality]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:23`: Magic constant MAX_FINGERPRINT_SAMPLES=100_000 controls truncation at line 67-68. No comment explaining why 100k is correct. Related to memory/time bu
  <!-- pid:CQ_002_SILENT_TRUNCATION | first:2026-05-12 -->
  Impact: Input truncation is silent. User doesn't know why their 500k samples got truncated. No error or warning. Makes debugging behavioral differences diffic | Fix: 1. Add const with comment: `// Limit to 100k to keep Welford pass < 50ms on typical hardware`. 2. Emit log::info! when truncation occurs. 3. Add field | Effort: small

- [ ] **M-011** `[security]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:74`: Mahalanobis distance threshold (MAHALANOBIS_ANOMALY_THRESHOLD=3.0) is treated as fixed. No adjustment for feature dimensionality (5 features) or basel
  <!-- pid:SEC_006_THRESHOLD_CALIBRATION | first:2026-05-12 -->
  Impact: False Positives on small baseline datasets. User with few training samples gets flagged as anomalous even if genuine. Threshold is static despite vary | Fix: 1. Pass baseline_sample_count to compare_to_baseline. 2. Adjust threshold dynamically: threshold = 3.0 + (50 - min(baseline_sample_count, 50)) / 10.0. | Effort: medium

- [ ] **M-012** `[error_handling]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:166`: Unsafe unwrap-like behavior: finite_check on burst_speed_variance at line 191 is conditional, but calling code doesn't validate if variance is 0. If a
  <!-- pid:ERR_001_SILENT_VARIANCE_FAILURE | first:2026-05-12 -->
  Impact: Analysis silently degrades if burst speed lacks variance. Mahalanobis distance may be inaccurate when burst patterns are uniform. Anomaly detection Fa | Fix: 1. Add explicit check: `if burst_speed_variance == 0.0 { log_warn!("...zero burst variance") }`. 2. Use MIN_BURST_VARIANCE constant. 3. Return error i | Effort: small

- [ ] **M-013** `[code_quality]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:220`: detect_forgery checks if samples.len() < 10 (line 221) and returns no_suspicious. But from_samples checks < 2 (line 64). Inconsistent minimum sample r
  <!-- pid:CQ_005_INCONSISTENT_MINIMUMS | first:2026-05-12 -->
  Impact: API contract is unclear. Different minimum samples for detection vs. fingerprinting. Caller may get fingerprint from 5 samples, but forgery analysis s | Fix: 1. Define module constant: MIN_SAMPLES = 10. 2. Use everywhere. 3. Add comment explaining biological basis. | Effort: small

- [ ] **M-014** `[error_handling]` `crates/cpoe/src/analysis/behavioral_fingerprint.rs:339`: compare_to_baseline returns Option but never None in practice—spread is guarded at line 366. However, if any baseline dimension is 0 (e.g., keystroke_
  <!-- pid:ERR_006_SILENT_OPTION | first:2026-05-12 -->
  Impact: Baseline comparison silently fails with None. Caller may interpret as 'not anomalous' when it should be 'baseline invalid'. No log message. Encourages | Fix: 1. Change return to Result<BaselineComparison, String>. 2. Return Err with message: 'Baseline keystroke_interval_std must be >0, got {value}'. 3. Upda | Effort: small

- [ ] **M-015** `[code_quality]` `crates/cpoe/src/analysis/content_detector.rs:408`: Function detect_patterns returns Vec<String> format 'lang:keyword'. String parsing is done by caller using string methods (.starts_with). No strongly-
  <!-- pid:CQ_003_NO_STRONG_TYPING | first:2026-05-12 -->
  Impact: Type safety lost. Impossible to enforce 'lang:keyword' format. Refactoring keywords is error-prone. No IDE support for navigation. | Fix: 1. Define enum: `pub enum PatternMatch { Code { lang: String, keyword: String }, Messaging(String) }`. 2. Return Vec<PatternMatch> from detect_pattern | Effort: medium

- [ ] **M-016** `[error_handling]` `crates/cpoe/src/analysis/content_detector.rs:519`: No bounds check on keystroke_metrics input. score_prose, score_code, and other score_* functions accept Option<&KeystrokeMetrics> but never validate m
  <!-- pid:ERR_002_NO_BOUNDS_CHECK | first:2026-05-12 -->
  Impact: Invalid keystroke metrics silently corrupt classification scores. Can cause misclassification (e.g., Code detected as Prose if std_dev is artificially | Fix: 1. Add KeystrokeMetrics::validate() -> Result<(), String>. 2. Check: mean_interval_ms > 0, std_dev_ms >= 0, std_dev < mean (plausible). 3. Call valida | Effort: small

- [ ] **M-017** `[security]` `crates/cpoe/src/analysis/content_detector.rs:520`: keystroke_metrics.mean_interval_ms is used directly in score_code (line 635-638) without range validation. If attacker passes metrics with mean_interv
  <!-- pid:SEC_007_METRICS_VALIDATION | first:2026-05-12 -->
  Impact: Keystroke metrics can be spoofed: attacker passes implausible values (1ms or 1000ms), and score_code doesn't reject them. Content classification can b | Fix: 1. Add KeystrokeMetrics::validate() -> Result. 2. Check: 20 < mean < 2000 (ms), 0 < std < mean. 3. Call at line 519: `keystroke_metrics.validate()?;`. | Effort: small

- [ ] **M-018** `[code_quality]` `crates/cpoe/src/analysis/content_detector.rs:592`: Magic number 0.3 base score (line 592) and 0.4 cap (line 592) for code keyword scoring. Also 0.1 increment per keyword. No justification for these val
  <!-- pid:CQ_001_MAGIC_NUMBERS | first:2026-05-12 -->
  Impact: Scoring logic is opaque and difficult to tune. Changes require code review. No way to A/B test threshold adjustments. Makes calibration against ground | Fix: 1. Move all magic numbers to module-level constants with comments explaining rationale. Example: `const CODE_BASE_SCORE: f64 = 0.3; // Baseline for pr | Effort: small

- [ ] **M-019** `[security]` `crates/cpoe/src/analysis/error_topology.rs:95`: Hard-coded adjacency plausibility range [0.15, 0.50] at line 323 assumes QWERTY keyboard layout. Non-QWERTY users (Dvorak, Colemak, non-English) will 
  <!-- pid:SEC_004_LAYOUT_BIAS | first:2026-05-12 -->
  Impact: International users with non-QWERTY layouts are penalized. Analysis is not locale-aware. Scoring bias toward QWERTY typists. Potential discrimination  | Fix: 1. Detect keyboard layout (common pattern: check if 'qwerty' or variant appears in adjacent error pairs). 2. Parameterize adjacency plausibility by la | Effort: medium

- [ ] **M-020** `[code_quality]` `crates/cpoe/src/analysis/error_topology.rs:117`: analyze_error_topology accepts events with Option<key_code> but only uses it if Some (line 310). Silent fallback to 0.5 adjacency when key_code is Non
  <!-- pid:ERR_011_OPTIONAL_KEY_CODES | first:2026-05-12 -->
  Impact: Partial input silently accepted. Adjacency analysis is best-effort but caller may think it's reliable. Undermines error topology scoring if key codes  | Fix: 1. Require key_code to be Some for error events (error_indices). 2. Return error if < 80% of errors have key codes. 3. Add field: `pub error_key_code_ | Effort: small

- [ ] **M-021** `[error_handling]` `crates/cpoe/src/analysis/error_topology.rs:294`: At line 290, uses crate::utils::Probability::clamp() to bound Hurst exponent, then calls .get() assuming Ok. No error handling if clamp fails (though 
  <!-- pid:ERR_008_MASKED_HURST | first:2026-05-12 -->
  Impact: Hurst computation errors are masked by Probability wrapper. Caller gets 0.5 (neutral) regardless of actual computation status. False Negatives: AI-gen | Fix: 1. Don't wrap with Probability; return f64 directly with range [0, 1]. 2. Validate range before returning. 3. Log if computation failed to compute. | Effort: small

- [ ] **M-022** `[code_quality]` `crates/cpoe/src/analysis/labyrinth.rs:92`: Function signature analyze_labyrinth has 6 parameters (keystroke_deltas, mouse_coords, params, and implicitly 3 RQA/Lyapunov tuning constants baked in
  <!-- pid:CQ_004_INCOMPLETE_PARAMS | first:2026-05-12 -->
  Impact: Function signature doesn't reflect all inputs (some are global constants). Hard to test with different tuning. Params struct is incomplete. Caller can | Fix: 1. Add to LabyrinthParams: max_rqa_threshold, min_line_length (already has), min_corr_dim, max_corr_dim. 2. Pass params to compute_rqa, estimate_corre | Effort: small


- [ ] **M-024** `[error_handling]` `crates/cpoe/src/anchors/ots.rs:158`: submit_to_calendar() (line 106) returns the raw response body. But the response is OTS proof data, which is opaque binary. No schema validation that t
  <!-- pid:P036_PROOF_VALIDATION | first:2026-05-12 -->
  Impact: Error handling: invalid OTS proof from server is accepted without validation. Downstream parse_attestation_path() may fail cryptically. | Fix: Validate OTS_MAGIC in response before returning. Return AnchorError::InvalidFormat if magic missing. | Effort: small

- [ ] **M-025** `[error_handling]` `crates/cpoe/src/anchors/ots.rs:560`: extract_bitcoin_block_height() (line 543) searches for the Bitcoin attestation tag in proof_data. If multiple attestations exist (e.g., multi-sig proo
  <!-- pid:P031_MULTIPLE_ATTESTATIONS | first:2026-05-12 -->
  Impact: Ambiguity: if proof has multiple Bitcoin attestations (rare but possible), wrong height selected. Verification may pass against wrong block. | Fix: Require exactly one Bitcoin attestation, or validate that all attestations agree on block height. | Effort: medium

- [ ] **M-026** `[error_handling]` `crates/cpoe/src/anchors/ots.rs:901`: verify() (line 882) attempts to extract Bitcoin block height and verify against blockchain. If no height is found (line 902), it returns Err(AnchorErr
  <!-- pid:P026_MISLEADING_OTS_ERROR | first:2026-05-12 -->
  Impact: Caller cannot distinguish between "no Bitcoin attestation found (not an error)" and "verification failed (error)". Logging and metrics incorrectly fla | Fix: Return Ok(true) if structural check passes but no Bitcoin confirmation. Or use a separate ProofStatus::PartiallyConfirmed to indicate structural valid | Effort: medium

- [ ] **M-027** `[code_quality]` `crates/cpoe/src/anchors/ots.rs:1176`: Test at line 1160 calls parse_attestation_path() on proof with trailing attestation data (lines 1163-1169). Comment at line 1161 says "Previously, byt
  <!-- pid:P028_INCOMPLETE_REGRESSION_TEST | first:2026-05-12 -->
  Impact: Maintenance: fix is tested, but regression potential is not. If a future change breaks the 0x00 termination again, test won't catch it. | Fix: Add a test_parse_attestation_path_rejects_branching_after_verify() that ensures 0xff (fork opcode) after Verify step raises error. | Effort: small

- [ ] **M-028** `[code_quality]` `crates/cpoe/src/anchors/ots.rs:1177`: Test at line 1172 validates parse_attestation_path() but does not test that the returned steps are in correct order or match the input operations. Ste
  <!-- pid:P040_INCOMPLETE_PARSE_TEST | first:2026-05-12 -->
  Impact: Testing: parse correctness not fully validated. If parse() incorrectly reorders operations, test won't catch it. | Fix: Assert that steps match expected sequence: [Append, Sha256, Verify]. | Effort: small

- [ ] **M-029** `[code_quality]` `crates/cpoe/src/anchors/rfc3161.rs:194`: parse_timestamp_response() is 20 lines but only called from one place (line 1104 in submit()). It's a private helper but poorly named—it only extracts
  <!-- pid:P012_FUNCTION_NAMING | first:2026-05-12 -->
  Impact: Code clarity: function name suggests full parsing, but it's only metadata extraction. Full verification happens in verify_timestamp_token. | Fix: Rename to extract_timestamp_metadata() or merge into submit() to reduce indirection. | Effort: small

- [ ] **M-030** `[security]` `crates/cpoe/src/anchors/rfc3161.rs:243`: validate_tsa_url() rejects private IP ranges but only checks IPv4 and IPv4-mapped IPv6. IPv6 private ranges (fc00::/7, fe80::/10, ::1) are not fully v
  <!-- pid:P025_IPV6_PRIVATE_RANGES | first:2026-05-12 -->
  Impact: SSRF: IPv6 private address validation incomplete. Attacker can target IPv6 localhost or private networks. | Fix: Expand CIDR checks to include all IPv6 private ranges (rfc4193, rfc4291). Use ipnetwork crate for proper CIDR parsing. | Effort: small

- [ ] **M-031** `[security]` `crates/cpoe/src/anchors/rfc3161.rs:814`: verify_rsa_pkcs1v15_sha256() decodes RSA public key from DER (line 814) but does not validate that the key size is >= 2048 bits. Legacy 1024-bit RSA k
  <!-- pid:P018_RSA_KEY_SIZE | first:2026-05-12 -->
  Impact: Weak keys: a 1024-bit RSA key can be factored (known attack circa 2009). Timestamp signed with weak key is not cryptographically secure. | Fix: After rsa::RsaPublicKey::from_public_key_der(), check pub_key.size() >= 256 (2048 bits). Reject smaller keys. | Effort: small

- [ ] **M-032** `[error_handling]` `crates/cpoe/src/anchors/rfc3161.rs:1059`: In verify_cms_signature (line 1059), last_error is set but may be overwritten in the loop. If the final signer_info fails silently (no error assigned)
  <!-- pid:P007_ERROR_OVERWRITE | first:2026-05-12 -->
  Impact: Verification failures blamed on wrong signer or certificate issue. Hard to debug which sig actually failed. | Fix: Accumulate all errors in a Vec and return the most recent (or most specific) error. Or log each failure as it occurs. | Effort: small

- [ ] **M-033** `[code_quality]` `crates/cpoe/src/anchors/rfc3161.rs:1234`: rfc3161.rs is 1234 lines. Contains DER/CMS parsing (lines 315-983), timestamp validation (lines 194-215), URL validation (lines 242-313), and crypto (
  <!-- pid:P017_RFC3161_GOD_MODULE | first:2026-05-12 -->
  Impact: God module: navigating between timestamping protocol logic, DER parsing, and crypto is scattered. Crypto functions are buried at line 808+. | Fix: Create submodules: rfc3161::der_parser, rfc3161::cms, rfc3161::crypto. Move DER/CMS parsing to der_parser, signature verification to cms/crypto. | Effort: large

- [ ] **M-034** `[code_quality]` `crates/cpoe/src/checkpoint/chain.rs:27`: Magic constant VDF_MIN_INTERVAL_SECS=30 is hardcoded without explanation in code comments
  <!-- pid:CQ-003 | first:2026-05-12 -->
  Impact: Rationale for 30s threshold not documented in source; maintainers must infer from `NoProof` recovery logic | Fix: Add doc comment explaining 30s threshold (NTP sync window? backward-compatible with legacy?) or make configurable | Effort: small

- [ ] **M-035** `[architecture]` `crates/cpoe/src/checkpoint/chain.rs:66`: Chain struct holds optional MMR and forensic_gate as #[serde(skip)] but deserialize has no reconstruction path
  <!-- pid:ARCH-001 | first:2026-05-12 -->
  Impact: Chains loaded from disk lose MMR coordinator and forensic gate config; callers must manually re-attach, creating error-prone setup sequence | Fix: Add post-load configuration method: with_mmr_and_gate(mmr, gate) or store config digest in metadata for validation | Effort: medium

- [ ] **M-036** `[security]` `crates/cpoe/src/checkpoint/chain.rs:204`: Path canonicalization used for document_id but symlink check happens before canonicalize()
  <!-- pid:SEC-003 | first:2026-05-12 -->
  Impact: Symlink → real file path race: attacker could replace file with symlink between check and hash computation, leading to wrong path hash | Fix: Canonicalize before symlink check, or use fstat after opening | Effort: medium

- [ ] **M-037** `[code_quality]` `crates/cpoe/src/checkpoint/chain.rs:223`: commit() delegates to commit_internal(None, 1) hardcoding vdf_cost_multiplier=1, hiding parameter dependency
  <!-- pid:CQ-005 | first:2026-05-12 -->
  Impact: Callers cannot see that forensic gating (commit_with_forensics) multiplies cost; unclear which path applies in logs | Fix: Rename to commit_base() or add inline comment documenting cost multiplier default | Effort: small

- [ ] **M-038** `[concurrency]` `crates/cpoe/src/checkpoint/chain.rs:294`: File lock acquire/release is not held across VDF computation in commit_internal_locked()
  <!-- pid:CONC-001 | first:2026-05-12 -->
  Impact: Between lock acquisition (line 294) and lock release (via guard), VDF computation (line 390) occurs without file lock re-check; file could be deleted/ | Fix: Hold lock for entire VDF + checkpoint update, or add file descriptor validity check after VDF | Effort: medium

- [ ] **M-039** `[security]` `crates/cpoe/src/checkpoint/chain.rs:344`: Clock regression tolerance allows up to MAX_CLOCK_DRIFT_SECS=2 with zero-duration VDF; NTP corrections could be exploited
  <!-- pid:SEC-005 | first:2026-05-12 -->
  Impact: Attacker with local clock control can create checkpoints with zero VDF cost up to 2 seconds apart by triggering NTP syncs | Fix: Log clock regression events; make drift tolerance configurable; document threat model assumption | Effort: medium

- [ ] **M-040** `[performance]` `crates/cpoe/src/checkpoint/chain.rs:421`: serde_json::to_vec_pretty() used for chain serialization (full precision + formatting)
  <!-- pid:PERF-001 | first:2026-05-12 -->
  Impact: Large chains (1000+ checkpoints) allocate extra formatting overhead; checkpoint_count grows linearly, increasing memory and I/O | Fix: Use to_vec() for storage, to_vec_pretty() only for logging; or use custom formatter for selective pretty-printing | Effort: small

- [ ] **M-041** `[error_handling]` `crates/cpoe/src/checkpoint/chain.rs:448`: Chain::load() silently deserializes without validating vdf_params or metadata fields post-deserialization
  <!-- pid:EH-003 | first:2026-05-12 -->
  Impact: If chain file contains vdf_params with min_iterations=0 (violates commit_internal invariant at line 327), error is deferred until next commit() | Fix: Call validate() immediately after deserialization; add Checkpoint::validate() checking params consistency | Effort: small

- [ ] **M-042** `[security]` `crates/cpoe/src/checkpoint_mmr.rs:92`: chain_id validation rejects '/' and '\' but not relative path traversal via '..' in name field
  <!-- pid:SEC-004 | first:2026-05-12 -->
  Impact: create('mmr', '../../../etc/passwd') could write outside mmr_dir if path join is naive (though Rust Path::join() is safe, implicit assumption not codi | Fix: Explicitly test Path::join() safety or use strict alphanumeric+dash validation for chain_id | Effort: small

- [ ] **M-043** `[architecture]` `crates/cpoe/src/checkpoint_mmr.rs:113`: MMR idempotency check (line 119) verifies last leaf only; does not detect out-of-order appends or replication conflicts
  <!-- pid:ARCH-002 | first:2026-05-12 -->
  Impact: If caller appends hash A, then crashes, then appends hash B, then crashes, recovery sees B as existing and skips re-append, creating a gap in leaf seq | Fix: Compare (checkpoint_hash, ordinal) pairs, not just hash; or require caller to track last_appended_ordinal | Effort: medium

- [ ] **M-044** `[code_quality]` `crates/cpoe/src/checkpoint_mmr.rs:200`: rebuild_from_chain() assumes checkpoints are in order; no ordinal validation
  <!-- pid:CQ-006 | first:2026-05-12 -->
  Impact: If checkpoint list is out-of-order or has gaps, MMR leaves will be in wrong order, invalidating proofs for all but the first checkpoint | Fix: Validate ordinal sequence before rebuild; return error if gaps detected | Effort: small

- [ ] **M-045** `[code_quality]` `crates/cpoe/src/crypto.rs:1`: Helper trait EventUpdate (lines 68-83) is internal implementation detail but exported as public (used only within module). Creates API surface that sh
  <!-- pid:unnecessary_trait_export | first:2026-05-12 -->
  Impact: Callers might depend on EventUpdate trait, making future refactoring harder. Pollutes public API. | Fix: Change to `trait EventUpdate` (remove pub), as it is only used within the module for generic implementations. | Effort: small


- [ ] **M-047** `[error_handling]` `crates/cpoe/src/crypto.rs:221`: hkdf.expand() in sign_event_lamport uses is_err() check and returns generic error. If expand fails, caller sees only 'HKDF expand failed', no context 
  <!-- pid:error_context_hkdf | first:2026-05-12 -->
  Impact: Debugging is harder if this expansion fails (which is cryptographically impossible for valid 32-byte target). Error message is unhelpful. | Fix: Map error with context: `.map_err(|e| Error::crypto(format!("HKDF expand failed for Lamport seed: {:?}", e)))?` for better visibility. | Effort: small

- [ ] **M-048** `[error_handling]` `crates/cpoe/src/crypto/anti_analysis.rs:31`: sysctl() system call in is_debugger_present assumes fixed kinfo_proc buffer layout. Comment states 648 bytes, but the p_flag offset at byte 16 is arch
  <!-- pid:struct_layout_assumption | first:2026-05-12 -->
  Impact: On different macOS versions or if XNU kernel struct layout changes, byte offset 16 may point to wrong field, causing incorrect debugger detection. Har | Fix: Use proper constants from system headers or validate struct layout at compile-time using offset_of! macro (nightly Rust). Document macOS version requi | Effort: medium

- [ ] **M-049** `[error_handling]` `crates/cpoe/src/crypto/anti_analysis.rs:49`: FFI call to IsDebuggerPresent() has no error handling. If Windows API fails (unlikely but possible on compatibility layers), the return code interpret
  <!-- pid:ffi_validation | first:2026-05-12 -->
  Impact: On non-standard Windows environments or compatibility shims, IsDebuggerPresent may return garbage or -1, which could be misinterpreted as debugger pre | Fix: Validate return code: `if IsDebuggerPresent() > 0` instead of `!= 0` to be more defensive. Or document platform assumptions. | Effort: small

- [ ] **M-050** `[security]` `crates/cpoe/src/crypto/obfuscated.rs:11`: Obfuscation secret is initialized via getrandom() with expect() panic on failure. If getrandom fails under resource constraints, the entire process cr
  <!-- pid:entropy_failure_handling | first:2026-05-12 -->
  Impact: An attacker or resource exhaustion could trigger getrandom failure, causing denial of service (process crash). Obfuscation is used for window titles ( | Fix: Use a fallback entropy source or return Result: `match getrandom::getrandom(&mut b) { Ok(()) => ..., Err(_) => use_fallback_or_return_error(...) }`. | Effort: medium

- [ ] **M-051** `[security]` `crates/cpoe/src/crypto/obfuscated.rs:60`: Non-constant-time fallback when UTF-8 decoding fails in ObfuscatedString::reveal. unwrap_or_default() silently substitutes empty string on invalid UTF
  <!-- pid:weak_error_handling | first:2026-05-12 -->
  Impact: Silent failure mode: if obfuscated secret is corrupted/truncated, reveal() returns empty string, and ct_eq comparison against expected value will fail | Fix: Return Option or Result instead of defaulting: `pub fn reveal(&self) -> Result<Zeroizing<String>, ...>` and let callers handle decoding errors explici | Effort: medium

- [ ] **M-052** `[security]` `crates/cpoe/src/crypto/obfuscated.rs:74`: Error suppression in Obfuscated::new with unwrap_or_else fallback. Serialization failure returns empty Vec silently, then masks the error with only a 
  <!-- pid:silent_serialization_failure | first:2026-05-12 -->
  Impact: Silent failure: if a serializable type fails to encode (e.g., alloc failure under pressure), empty Vec is masked as secret data. Downstream decrypt/re | Fix: Return Option<Self> from new(): `pub fn new(val: &T) -> Option<Self>` and let callers handle encoding failures. Or panic on critical failure: `expect( | Effort: medium

- [ ] **M-053** `[code_quality]` `crates/cpoe/src/ffi/beacon.rs:42`: OnceLock<tokio::runtime::Runtime> runtime intentionally leaked per comment, but behavior causes benign race
  <!-- pid:CODE_BENIGN_RACE_CONDITION | first:2026-05-12 -->
  Impact: 'get() + fallback get_or_init' pattern creates race where two concurrent callers both build Runtime, one dropped (wasted). Noted as benign but still w | Fix: Consider updating MSRV or use explicit once_cell synchronization library | Effort: medium

- [ ] **M-054** `[error_handling]` `crates/cpoe/src/ffi/beacon.rs:128`: File load errors silently convert to None via .ok() without logging
  <!-- pid:ERR_SILENT_FILE_LOAD | first:2026-05-12 -->
  Impact: If beacon sidecar file corrupted or permissions denied, returns None silently. Caller cannot distinguish 'no beacon' from 'corrupted beacon file'. No  | Fix: Propagate load errors explicitly or log level ERROR instead of relying on .ok() | Effort: small

- [ ] **M-055** `[error_handling]` `crates/cpoe/src/ffi/beacon.rs:245`: Beacon timestamp parse failures logged but results silently converted to None (.map_err + .ok())
  <!-- pid:ERR_INCONSISTENT_TIMESTAMP_HANDLING | first:2026-05-12 -->
  Impact: Malformed RFC3339 timestamps in beacon response are logged but silently drop to None. FfiBeaconResult returns with None timestamp_epoch_ms but success | Fix: Return success=false when timestamp parsing fails, include error_message | Effort: small

- [ ] **M-056** `[error_handling]` `crates/cpoe/src/ffi/beacon.rs:290`: Multiple silent log.warn() calls in beacon status check without propagating errors to caller
  <!-- pid:ERR_LOG_INSTEAD_OF_RETURN | first:2026-05-12 -->
  Impact: Beacon timestamp parse failures, store query failures all logged with .map_err(|e| log::warn!(...)).ok(). Caller receives FfiBeaconResult with None fi | Fix: Return FfiBeaconResult::ffi_err() instead of logging and continuing | Effort: small

- [ ] **M-057** `[concurrency]` `crates/cpoe/src/ffi/ephemeral.rs:113`: Throttled eviction sweep with atomic load/store but no synchronization guarantees
  <!-- pid:race_condition_eviction | first:2026-05-12 -->
  Impact: Race between checking last eviction time and updating could cause spurious re-evicts | Fix: Use atomic CAS or seqlock for eviction throttle | Effort: medium

- [ ] **M-058** `[concurrency]` `crates/cpoe/src/ffi/ephemeral.rs:122`: sessions().retain() iterates all sessions; could deadlock if session closure acquires same lock
  <!-- pid:retain_callback_deadlock_risk | first:2026-05-12 -->
  Impact: Eviction callback cleanup_session_state() is safe (filesystem only) but pattern is fragile | Fix: Defer cleanup outside retain() loop or use non-blocking eviction | Effort: small

- [ ] **M-059** `[security]` `crates/cpoe/src/ffi/ephemeral.rs:183`: generate_nonce() uses rand::rng() without error handling in ephemeral start
  <!-- pid:csprng_unchecked | first:2026-05-12 -->
  Impact: CSPRNG failure during session start could silently use weak nonce | Fix: generate_nonce() should return Result; check getrandom() failure | Effort: small

- [ ] **M-060** `[error_handling]` `crates/cpoe/src/ffi/ephemeral.rs:262`: ffi_ephemeral_checkpoint holds DashMap guard during disk I/O
  <!-- pid:lock_over_io | first:2026-05-12 -->
  Impact: Guard held over sync_all() call; if I/O slow, blocks other threads accessing session | Fix: Release guard before disk operations; use separate lock for critical section only | Effort: medium

- [ ] **M-061** `[security]` `crates/cpoe/src/ffi/ephemeral.rs:310`: MAX_JITTER_INTERVALS * 10 allows 10,000 intervals per call but FFI function named ffi_ephemeral_inject_jitter accepts Vec<u64> unbounded in size
  <!-- pid:ffi_size_unchecked | first:2026-05-12 -->
  Impact: Caller could pass oversized vector; FFI allocates before validation | Fix: Document max size in function docs; add length check at Swift boundary | Effort: small

- [ ] **M-062** `[error_handling]` `crates/cpoe/src/ffi/ephemeral.rs:552`: last_message extracted from snapshot but may be None; placeholder used
  <!-- pid:lost_metadata | first:2026-05-12 -->
  Impact: Checkpoint message lost if no context_note provided; audit trail incomplete | Fix: Always populate message; use timestamp or 'no context' placeholder | Effort: small

- [ ] **M-063** `[error_handling]` `crates/cpoe/src/ffi/ephemeral.rs:575`: Persist error in checkpoint_hash stored but success=true returned
  <!-- pid:partial_failure_masked | first:2026-05-12 -->
  Impact: Checkpoint proceeds to WAR block even if SQLite write failed | Fix: Return error if persist_error is Some; don't hide persistence failures | Effort: small

- [ ] **M-064** `[security]` `crates/cpoe/src/ffi/ephemeral.rs:638`: Signing key file permissions checked but only warnings logged, not enforced
  <!-- pid:ignored_permission_check | first:2026-05-12 -->
  Impact: Overly permissive key file (mode & 0o077 != 0) is warned but still used | Fix: Refuse to use key if permissions > 0600; return error | Effort: small

- [ ] **M-065** `[security]` `crates/cpoe/src/ffi/ephemeral.rs:661`: Signing key read from disk without size limit before parsing
  <!-- pid:unbounded_key_read | first:2026-05-12 -->
  Impact: Large key files (even if rejected at 1024 byte check) consume memory | Fix: Use bounded reader or memory-mapped file; reject early | Effort: small

- [ ] **M-066** `[code_quality]` `crates/cpoe/src/ffi/ephemeral.rs:720`: TMP_COUNTER atomic with fetch_add for temp file naming; overcomplicated
  <!-- pid:overcomplicated_temp_file_naming | first:2026-05-12 -->
  Impact: Atomic counter simple but unusual for this use case; could use UUID | Fix: Use uuid::Uuid::new_v4() or simpler random suffix | Effort: small

- [ ] **M-067** `[security]` `crates/cpoe/src/ffi/evidence_derivative.rs:27`: Path validation does not enforce consistent representation. Both source and export validated separately; no check that they are not the same file or c
  <!-- pid:security_path_validation_incomplete | first:2026-05-12 -->
  Impact: Attacker could link derivative to itself or create circular chains. Evidence chain validation may be bypassed. | Fix: Add check: export != source (after canonicalization); consider max chain depth limit | Effort: small

- [ ] **M-068** `[error_handling]` `crates/cpoe/src/ffi/evidence_derivative.rs:82`: File size cast with fallback: `try_from(m.len()).unwrap_or(i64::MAX)` silently caps at i64::MAX for files >9EB. Very unlikely but hides potential data
  <!-- pid:error_handling_numeric_fallback | first:2026-05-12 -->
  Impact: On extremely large files (>i64::MAX bytes, never in practice), size_delta calculation is wrong. Silent data loss in evidence. | Fix: Return error for files exceeding i64::MAX; document 64-bit size limit in evidence schema | Effort: small

- [ ] **M-069** `[error_handling]` `crates/cpoe/src/ffi/evidence_derivative.rs:101`: Clamp without validation context: `size_delta.clamp(i32::MIN, i32::MAX)` silently clamps size changes. Original delta information is lost.
  <!-- pid:ffi_silent_clamp_data_loss | first:2026-05-12 -->
  Impact: Exported derivative events may have incorrect size deltas if file grew beyond i32::MAX bytes (>2GB). Silent data loss; verification may fail. | Fix: Return error if size_delta exceeds i32 range; document assumption in evidence schema | Effort: small

- [ ] **M-070** `[code_quality]` `crates/cpoe/src/ffi/evidence_derivative.rs:159`: Function ffi_export_c2pa_manifest is 140 lines. Complex C2PA manifest building with forensic enrichment. File I/O, decoding, and signing interleaved.
  <!-- pid:ffi_function_too_long | first:2026-05-12 -->
  Impact: Hard to unit test manifest generation logic. Risk of subtle issues in JUMBF encoding or forensic signal mapping. | Fix: Extract decode_evidence_for_c2pa() and enrich_c2pa_builder() (already done partly); move signer setup to separate helper | Effort: medium

- [ ] **M-071** `[code_quality]` `crates/cpoe/src/ffi/evidence_derivative.rs:187`: MAX_EVIDENCE_FILE_SIZE magic value: 100MB hardcoded. No correlation to MAX_FILE_SIZE constant used elsewhere. No explanation for choice.
  <!-- pid:magic_value_inconsistent | first:2026-05-12 -->
  Impact: Different size limits across functions (evidence export vs file tracking). User confusion; inconsistent behavior. | Fix: Define constant in helpers or types module; use consistently across all FFI functions | Effort: small

- [ ] **M-072** `[error_handling]` `crates/cpoe/src/ffi/evidence_export.rs:101`: unwrap_or() defaults on config load failure; missing error context
  <!-- pid:silent_default_fallback | first:2026-05-12 -->
  Impact: If config load fails, silently uses default IPS=1; export quality metric wrong | Fix: Return FfiResult error if critical config missing; don't proceed with degraded default | Effort: small

- [ ] **M-073** `[performance]` `crates/cpoe/src/ffi/evidence_export.rs:119`: Random salt generation in loop during checkpoint building
  <!-- pid:hot_loop_random | first:2026-05-12 -->
  Impact: rand::random() called per-event during export; could be amortized | Fix: Generate single salt before loop; reuse or hash with index | Effort: small

- [ ] **M-074** `[error_handling]` `crates/cpoe/src/ffi/evidence_export.rs:268`: Silent error suppression for file read failure with .ok() during export
  <!-- pid:silent_error_discard | first:2026-05-12 -->
  Impact: Failed file read during export is silently logged; no status propagated | Fix: Return FfiResult with error if file read is critical for export quality | Effort: small

- [ ] **M-075** `[code_quality]` `crates/cpoe/src/ffi/evidence_export.rs:280`: MAX_EMBEDDED_BYTES hardcoded as 10 MB; multiple definitions across codebase
  <!-- pid:duplicate_constant | first:2026-05-12 -->
  Impact: Duplicate constants; maintenance burden if changed | Fix: Move to common constants module; reference from both places | Effort: small

- [ ] **M-076** `[performance]` `crates/cpoe/src/ffi/evidence_export.rs:336`: collect_ai_tool_limitations() reads sentinel sessions on export path; could be hot
  <!-- pid:export_path_lock_contention | first:2026-05-12 -->
  Impact: Sentinel session read under RwLock during export; contention if exports frequent | Fix: Cache limitations in session or pre-compute during add, not export | Effort: medium

- [ ] **M-077** `[code_quality]` `crates/cpoe/src/ffi/evidence_export.rs:607`: Histogram edge constants defined at function scope (IKI_HIST_EDGES_MS, PAUSE_HIST_EDGES_MS)
  <!-- pid:const_in_function | first:2026-05-12 -->
  Impact: Constants redefined every call; should be static | Fix: Move to module-level const | Effort: small

- [ ] **M-078** `[architecture]` `crates/cpoe/src/ffi/evidence_export.rs:672`: build_war_block() async runtime creation and key loading in FFI function
  <!-- pid:runtime_per_call | first:2026-05-12 -->
  Impact: Ephemeral WAR block building creates new runtime; should use existing runtime pool | Fix: Accept pre-built runtime from FFI context or use thread-local runtime | Effort: medium

- [ ] **M-079** `[code_quality]` `crates/cpoe/src/ffi/evidence_export.rs:1113`: find_project_root() walks filesystem during export path
  <!-- pid:export_path_io | first:2026-05-12 -->
  Impact: Filesystem traversal during export can be slow; no caching | Fix: Cache project root or pre-compute during session start | Effort: medium

- [ ] **M-080** `[error_handling]` `crates/cpoe/src/ffi/fingerprint.rs:79`: catch_ffi_panic wrapper on entire ffi_get_fingerprint_summary hides panics from any line in 130-line block
  <!-- pid:ERR_BROAD_PANIC_CATCH_SCOPE | first:2026-05-12 -->
  Impact: If manager initialization, activity fingerprint lookup, or dimension computation panics, fallback FfiFingerprintSummary returned with success=false an | Fix: Use smaller catch_ffi_panic scopes, log panic details before returning fallback | Effort: medium

- [ ] **M-081** `[code_quality]` `crates/cpoe/src/ffi/forensics_detail.rs:227`: Function ffi_get_forensic_breakdown is 148 lines. Complex forensic metrics mapping with multiple optional fields. Enrichment logic from sentinel dupli
  <!-- pid:logic_in_boundary_forensics | first:2026-05-12 -->
  Impact: Hard to follow metrics enrichment logic. Risk of out-of-sync enrichment between forensics.rs and FFI layer. Different results on Swift vs native. | Fix: Move enrichment logic (cognitive_layer, dictation) to core forensics; FFI should only map results | Effort: large

- [ ] **M-082** `[error_handling]` `crates/cpoe/src/ffi/forensics_detail.rs:236`: Sentinel session optional logic: if sentinel unavailable, forensics run on stored events only. No error signal to caller about reduced signal quality.
  <!-- pid:error_handling_missing_context | first:2026-05-12 -->
  Impact: Caller unaware that live cognitive_layer and dictation scoring are missing. Results incomplete but appear authoritative. | Fix: Add field to FfiForensicBreakdown: .is_live_session=false when sentinel data missing; caller can tag results as incomplete | Effort: small

- [ ] **M-083** `[code_quality]` `crates/cpoe/src/ffi/forensics_detail.rs:529`: Sentinel optional logic duplicated: ffi_get_live_scores() and ffi_get_forensic_breakdown() both query sentinel.sessions() in similar way; no shared he
  <!-- pid:code_quality_duplication | first:2026-05-12 -->
  Impact: Code duplication; risk of divergent behavior. If sentinel session structure changes, multiple FFI functions need updating. | Fix: Extract common sentinel session lookup to helper; ensure consistent error handling across both functions | Effort: small

- [ ] **M-084** `[architecture]` `crates/cpoe/src/ffi/helpers.rs:71`: Key management (load_signing_key, load_or_generate_cert, derive_hmac_from_signing_key) in FFI helpers. Should be in core identity module, not binding 
  <!-- pid:key_management_in_binding | first:2026-05-12 -->
  Impact: FFI layer tightly coupled to key storage formats. Platform-specific cert generation in binding layer. Hard to test key rotation. | Fix: Move all key loading/derivation to core crate::identity module; FFI should only call abstract load_signing_key() from core | Effort: large

- [ ] **M-085** `[performance]` `crates/cpoe/src/ffi/report.rs:356`: get_forensics_cached() recomputes forensics if event count changes
  <!-- pid:cache_thrashing | first:2026-05-12 -->
  Impact: Cache invalidated on any new event; all forensics recomputed for single new checkpoint | Fix: Use incremental forensics update or fine-grained cache keys (not just event count) | Effort: large

- [ ] **M-086** `[performance]` `crates/cpoe/src/ffi/report.rs:640`: collect_ai_tool_limitations reads from sentinel sessions on export path
  <!-- pid:hot_path_sentinel_read | first:2026-05-12 -->
  Impact: Sentinel state read during every export; potential contention | Fix: Pre-compute limitations in sentinel; cache in session | Effort: medium

- [ ] **M-087** `[performance]` `crates/cpoe/src/ffi/report.rs:654`: Multiple .clone() calls on large report structures during convert_war_report
  <!-- pid:clone_on_ffi_boundary | first:2026-05-12 -->
  Impact: Converting report to FFI struct clones all field data; could avoid for readonly references | Fix: Consider Cow<> or reference-based serialization if FFI allows | Effort: large

- [ ] **M-088** `[code_quality]` `crates/cpoe/src/ffi/report.rs:717`: MAX_PATH_LEN hardcoded as 4096 in function; not a constant
  <!-- pid:magic_value | first:2026-05-12 -->
  Impact: Magic number; inconsistent if changed elsewhere | Fix: Define as module constant or use PATH_MAX from platform | Effort: small

- [ ] **M-089** `[performance]` `crates/cpoe/src/ffi/report.rs:769`: Full forensics computed even if only partial report needed
  <!-- pid:over_computation | first:2026-05-12 -->
  Impact: Report generation runs all forensic modules regardless of requested data | Fix: Lazy-load forensic modules; return only requested fields | Effort: large

- [ ] **M-090** `[architecture]` `crates/cpoe/src/ffi/report.rs:1066`: detect_sessions_from_events() implements session detection heuristic in FFI layer
  <!-- pid:logic_in_boundary | first:2026-05-12 -->
  Impact: Session grouping logic belongs in core; FFI should not contain domain algorithms | Fix: Move to core reporting module; FFI calls it | Effort: medium

- [ ] **M-091** `[code_quality]` `crates/cpoe/src/ffi/report.rs:1074`: DEFAULT_SESSION_GAP_SEC floating-point constant used in nanosecond conversion
  <!-- pid:float_time_constant | first:2026-05-12 -->
  Impact: Float precision loss in time calculations; could misdetect session boundaries | Fix: Use integer millisecond or nanosecond constants | Effort: small

- [ ] **M-092** `[code_quality]` `crates/cpoe/src/ffi/report_dimensions.rs:1`: 45 dimension scoring constants defined at module level with 0-99 range hardcoded in 20+ places
  <!-- pid:CODE_SCATTERED_MAGIC_NUMBERS | first:2026-05-12 -->
  Impact: Magic numbers throughout: TEMPORAL_BASE_FULL=75, EDIT_RI_SCORE_OPTIMAL=0.8, COHERENCE_CR_BONUS=15, etc. Score scaling mixed (0.0-1.0 and 0-99). No cen | Fix: Create DimensionScoringConfig struct or ScoreScale enum (u32 or f64), centralize range definitions | Effort: medium

- [ ] **M-093** `[security]` `crates/cpoe/src/ffi/report_dimensions.rs:127`: Likelihood ratio computed via compute_likelihood_ratio(score) with no bounds checking on output
  <!-- pid:SEC_UNBOUNDED_COMPUTED_VALUE | first:2026-05-12 -->
  Impact: Score (0-99) fed to compute_likelihood_ratio() which may return inf or NaN if score at edge cases. LR field in DimensionScore has no validation. Could | Fix: Validate compute_likelihood_ratio() output is finite and >= 0, clamp to safe range | Effort: small

- [ ] **M-094** `[code_quality]` `crates/cpoe/src/ffi/report_types.rs:1`: No dedicated validation for FfiWarReport fields - struct used as plain data container
  <!-- pid:CODE_UNVALIDATED_REPORT_STRUCT | first:2026-05-12 -->
  Impact: 150-line report struct with 30+ fields carries no validation invariants (e.g., score 0-100, confidence 0.0-1.0, ratios 0.0-100.0). Caller constructs s | Fix: Add validation method to FfiWarReport, call before serialization | Effort: medium

- [ ] **M-095** `[code_quality]` `crates/cpoe/src/ffi/sentinel.rs:57`: Debug output in production code (CPOE_DEBUG_SENTINEL env var check)
  <!-- pid:debug_code_production | first:2026-05-12 -->
  Impact: Sentinel start debug logging to file could leak information if file world-readable | Fix: Remove debug code or use proper tracing; verify file permissions | Effort: small

- [ ] **M-096** `[error_handling]` `crates/cpoe/src/ffi/sentinel.rs:86`: macOS-specific permission checks called only on macOS but no Linux/Windows equivalents
  <!-- pid:incomplete_platform_coverage | first:2026-05-12 -->
  Impact: Non-macOS platforms don't validate permissions; capture could fail silently | Fix: Add platform-specific checks for all platforms; document limitations | Effort: medium

- [ ] **M-097** `[security]` `crates/cpoe/src/ffi/sentinel_es.rs:102`: MAX_AI_TOOLS_PER_SESSION constant used as hard limit but no secure eviction policy
  <!-- pid:SEC_UNGOVERNED_RESOURCE_LIMIT | first:2026-05-12 -->
  Impact: When limit reached, new AI tools silently dropped with warning. Oldest tools never evicted. Could hide detection of tool switching attacks in long ses | Fix: Implement FIFO or timestamp-based eviction when limit reached, log evictions | Effort: medium

- [ ] **M-098** `[security]` `crates/cpoe/src/ffi/sentinel_es.rs:148`: File rename target path validated but old_path not validated before map operations
  <!-- pid:SEC_UNVALIDATED_PATH_AS_KEY | first:2026-05-12 -->
  Impact: old_path passed directly to sessions.remove() without prior validation. If old_path is symlink or escape sequence, sessions.remove() operates on attac | Fix: Validate old_path same way as new_path (canonicalize) before sessions.remove() | Effort: small

- [ ] **M-099** `[security]` `crates/cpoe/src/ffi/sentinel_es.rs:206`: Challenge nonce (up to 1024 bytes) stored without rate limiting or expiration validation before 30-second timeout
  <!-- pid:SEC_UNGOVERNED_NONCE_QUEUEING | first:2026-05-12 -->
  Impact: Caller can set new nonce repeatedly, overwriting pending_challenge without bounds. Nonce size validated (1024 max) but 30-second expiration is advisor | Fix: Enforce expiration immediately when setting new nonce, reject if previous nonce not yet expired | Effort: medium

- [ ] **M-100** `[code_quality]` `crates/cpoe/src/ffi/sentinel_es.rs:275`: TERMINAL_EDITORS hardcoded list of 16 editor basenames in const array
  <!-- pid:CODE_HARDCODED_EDITOR_LIST | first:2026-05-12 -->
  Impact: Magic list of editor names (vi, vim, nvim, nano, emacs, etc.) with no version/metadata. Adding new editors requires code change + recompile. No fallba | Fix: Load terminal editor list from config file or define in sentinel::platform module | Effort: medium

- [ ] **M-101** `[security]` `crates/cpoe/src/ffi/sentinel_es.rs:321`: Dictation begin accepts 16-character hex string (device_uid_hash_hex) but decodes with fallback to all-zeros on error
  <!-- pid:SEC_SILENT_HEX_DECODE_FALLBACK | first:2026-05-12 -->
  Impact: If caller sends malformed hex, hex_decode_8() fails silently and device_uid_hash becomes [0u8; 8]. No error indication. Caller cannot distinguish 'dec | Fix: Validate hex format before passing, return error if decoding fails instead of falling back to zeros | Effort: small

- [ ] **M-102** `[code_quality]` `crates/cpoe/src/ffi/sentinel_inject.rs:195`: inject_keystroke_inner_v3 function is 216 lines, exceeds 100-line threshold
  <!-- pid:CODE_OVERSIZED_FUNCTION | first:2026-05-12 -->
  Impact: Excessive cyclomatic complexity: verification logic, rate limiting, semantic classification, focus tracking, and validation all in one function. Hard  | Fix: Extract verification branch into verify_keystroke_source(), rate limiting into check_injection_rate() | Effort: medium

- [ ] **M-103** `[security]` `crates/cpoe/src/ffi/sentinel_inject.rs:210`: char_value validation only checks length (16 bytes), no UTF-8 encoding validation
  <!-- pid:SEC_UNVALIDATED_UTF8_CHAR | first:2026-05-12 -->
  Impact: Malformed UTF-8 sequences accepted and may cause panics in downstream char_value.chars().next() or style collector. No explicit UTF-8 validation gate. | Fix: Validate char_value is valid UTF-8 and non-empty before processing | Effort: small

- [ ] **M-104** `[security]` `crates/cpoe/src/ffi/sentinel_inject.rs:283`: CPOE_DEBUG_INJECT environment variable enables debug logging to file without rate limiting
  <!-- pid:SEC_DEBUG_FILE_LOGGING | first:2026-05-12 -->
  Impact: Debug mode (env var check) writes to /tmp/cpoe_inject_debug.txt or CPOE_DATA_DIR path every keystroke (sampled n<5 or n%50==0). File can grow unbounde | Fix: Remove debug logging to file, use structured logging with log crate level control only | Effort: medium

- [ ] **M-105** `[security]` `crates/cpoe/src/ffi/sentinel_inject.rs:334`: LAST_INJECT_TS global state updated via relaxed atomic swap, but duration calculation does not validate timestamp monotonicity
  <!-- pid:SEC_UNDETECTED_TIMESTAMP_REORDER | first:2026-05-12 -->
  Impact: Caller can send timestamps out of order (e.g., 100ns, 50ns) and duration_since_last_ns will be 0 silently due to (timestamp_ns > prev_ts) check, but t | Fix: Log warning if prev_ts > timestamp_ns (clock backward), consider rejecting out-of-order timestamps | Effort: small

- [ ] **M-106** `[security]` `crates/cpoe/src/ffi/sentinel_witnessing.rs:163`: fallback_score() applies focus_penalty to cadence_score without validating cadence_score >= focus_penalty
  <!-- pid:SEC_UNVALIDATED_SCORE_SUBTRACTION | first:2026-05-12 -->
  Impact: If focus_penalty > cadence_score, clamping to Probability range hides underflow. cadence_score - focus_penalty could be negative before clamp. Returns | Fix: Validate cadence_score >= focus_penalty before subtraction, return error if not | Effort: small

- [ ] **M-107** `[error_handling]` `crates/cpoe/src/ffi/sentinel_witnessing.rs:311`: unwrap_or_default() on session.start_time.elapsed() silently returns Duration::ZERO on error
  <!-- pid:ERR_SILENT_TIME_ERROR | first:2026-05-12 -->
  Impact: If system clock is corrupted or time goes backward, elapsed_secs returns 0.0 with no indication of error. Caller sees valid witnessing_status with 0 e | Fix: Return FfiWitnessingStatus::err() when elapsed() fails, include error_code: 'time_error' | Effort: small

- [ ] **M-108** `[architecture]` `crates/cpoe/src/ffi/system.rs:40`: Signing key generation and cryptographic setup in FFI init(). This is core engine initialization; should be in core crate, not FFI binding.
  <!-- pid:crypto_in_binding | first:2026-05-12 -->
  Impact: FFI layer couples to cryptography, making it harder to test binding layer independently. Different platforms may have divergent key generation on edge | Fix: Move ffi_init crypto setup to core crate init; FFI should only call core::engine::init() and report status | Effort: large

- [ ] **M-109** `[error_handling]` `crates/cpoe/src/ffi/system.rs:146`: try_from on option fallback: `u64::try_from(*count).unwrap_or(0)` silently falls back to 0 if checkpoint count overflows. Very unlikely but not imposs
  <!-- pid:error_handling_silent_fallback | first:2026-05-12 -->
  Impact: Total checkpoint count underreported if overflow occurs. Dashboard metrics inaccurate. | Fix: Use saturating_add; or validate counts at store level before FFI export | Effort: small

- [ ] **M-110** `[performance]` `crates/cpoe/src/ffi/system.rs:187`: Batch query optimization present but incomplete: `get_all_events_grouped()` fetches all events once (good), but forensics computed per-file in loop (O
  <!-- pid:perf_missing_cache | first:2026-05-12 -->
  Impact: Dashboard metric refresh slows linearly with file count. On 50K files, this is seconds of computation per refresh. | Fix: Add caching of forensic scores in store; or compute incrementally on first call; offer 'summary' mode that skips full forensics | Effort: large

- [ ] **M-111** `[code_quality]` `crates/cpoe/src/ffi/system.rs:204`: Magic number: FFI_MAX_TRACKED_FILES=50_000. Unclear if this is a hard security limit, perf limit, or arbitrary. No corresponding validation or negotia
  <!-- pid:magic_value_no_context | first:2026-05-12 -->
  Impact: Caller unaware of truncation; may miss documents silently. No protocol-level error signaling; silent data loss. | Fix: Return actual count alongside capped result; signal truncation in result struct; add FfiListTrackedFilesResult.was_capped field | Effort: small

- [ ] **M-112** `[code_quality]` `crates/cpoe/src/ffi/system.rs:283`: Canonicalization with fallback: `canonicalize().unwrap_or_else(|_| session.path.clone())` silently falls back on any canonicalize error (permission de
  <!-- pid:ffi_silent_fallback_canonicalize | first:2026-05-12 -->
  Impact: Path comparison may use non-canonical sentinel path vs canonical store path, causing false duplicates in result set. Inconsistent behavior across plat | Fix: Validate paths before canonicalize; log canonicalization failures; use consistent path representation from both sources | Effort: medium

- [ ] **M-113** `[performance]` `crates/cpoe/src/ffi/system.rs:295`: Per-file forensic analysis in loop: calls analyze_forensics() for each file in batch query results. No parallelization or caching.
  <!-- pid:perf_sequential_analysis | first:2026-05-12 -->
  Impact: On 50K files, refreshing dashboard triggers 50K forensic analyses sequentially. Slow UI refresh. Consider using rayon or batched analysis. | Fix: Add optional 'include_forensics' parameter to ffi_list_tracked_files(); default to summary-only; lazy-load forensics on demand per-file | Effort: medium

- [ ] **M-114** `[performance]` `crates/cpoe/src/ffi/system.rs:298`: Unnecessary clone in per-call path: `Vec::from(session.focus_switches.clone())` allocates new Vec unnecessarily; should pass reference or iterator.
  <!-- pid:perf_unnecessary_clone | first:2026-05-12 -->
  Impact: Per-file FFI call allocates extra Vec for focus_switches. With 50K files, this is 50K+ allocations. Slow dashboard refresh in app. | Fix: Pass &[FocusSwitch] reference instead of owned Vec; or use iterator adapter | Effort: small

- [ ] **M-115** `[code_quality]` `crates/cpoe/src/ffi/system.rs:314`: Result truncation with warning only: capping at FFI_MAX_TRACKED_FILES with log.warn. Caller never knows data was lost.
  <!-- pid:ffi_silent_truncation | first:2026-05-12 -->
  Impact: UI shows partial file list silently. User unaware of missing documents. Risk of incomplete witness chains. | Fix: Add field to FfiTrackedFile result: .was_truncated=true; caller can warn user to filter results | Effort: small

- [ ] **M-116** `[security]` `crates/cpoe/src/ffi/system.rs:584`: File hash computation via ffi_hash_file without caller context. Caller could request hash of sensitive files (passwords, keys, etc.). No audit trail.
  <!-- pid:security_no_audit_trail | first:2026-05-12 -->
  Impact: Attacker could exfiltrate hashes of sensitive files via FFI. No indication to user that hashing occurs. | Fix: Add optional audit logging to ffi_hash_file; document that this may hash sensitive content; consider restricting to tracked files only | Effort: small


- [ ] **M-118** `[performance]` `crates/cpoe/src/ffi/text_fragment.rs:238`: Sign every fragment immediately during paste recording
  <!-- pid:hot_path_crypto | first:2026-05-12 -->
  Impact: Signing is CPU-bound; frequent pastes cause latency | Fix: Defer signing to background or batch operations | Effort: large

- [ ] **M-119** `[error_handling]` `crates/cpoe/src/ffi/text_fragment.rs:386`: Sentinel not running error treated the same as other errors in paste recording
  <!-- pid:error_classification | first:2026-05-12 -->
  Impact: Silent recovery when sentinel stops; paste still recorded but without keystroke evidence | Fix: Distinguish sentinel state errors from data errors; return different error codes | Effort: small

- [ ] **M-120** `[security]` `crates/cpoe/src/ffi/text_fragment.rs:410`: Paste fragment stored even if sentinel capture not active; keystroke context incomplete
  <!-- pid:incomplete_evidence_metadata | first:2026-05-12 -->
  Impact: Fragment evidence incomplete; attestation tier incorrect if no keystroke data | Fix: Set different keystroke_context based on capture_active state | Effort: small

- [ ] **M-121** `[error_handling]` `crates/cpoe/src/ffi/text_fragment.rs:415`: Failed fragment store during paste is silently logged, not reported to caller
  <!-- pid:silent_store_failure | first:2026-05-12 -->
  Impact: Paste recorded in keystroke but fragment store failure not reported | Fix: Return error code to caller if fragment store fails | Effort: small

- [ ] **M-122** `[performance]` `crates/cpoe/src/ffi/text_fragment.rs:443`: Attestation normalization and hashing runs synchronously on FFI thread
  <!-- pid:hot_path_normalization | first:2026-05-12 -->
  Impact: Text normalization for every attestation blocks FFI caller | Fix: Defer normalization or use precomputed hash from caller | Effort: medium

- [ ] **M-123** `[security]` `crates/cpoe/src/ffi/text_fragment.rs:736`: keystroke_context parsed from optional String; invalid value silently ignored
  <!-- pid:silent_enum_parse_failure | first:2026-05-12 -->
  Impact: Invalid context from caller silently becomes None; validation weak | Fix: Return error if invalid context; don't silently accept | Effort: small

- [ ] **M-124** `[error_handling]` `crates/cpoe/src/ffi/types.rs:80`: FfiResult::err and FfiResult::err_with_code accept impl Into<String> but do not truncate long messages
  <!-- pid:SEC_UNBOUNDED_ERROR_MESSAGE | first:2026-05-12 -->
  Impact: error_message field has no max length. Caller can pass multi-MB error strings, causing buffer overflow in Swift FFI marshaling or JSON serialization.  | Fix: Truncate error_message to 4096 bytes, log full error if longer | Effort: small

- [ ] **M-125** `[error_handling]` `crates/cpoe/src/ffi/writersproof_ffi.rs:102`: Timeout error discards cause: `Err(_) => FfiResult::err('...timed out')`. Inner error about what timed out is lost.
  <!-- pid:error_handling_lost_context | first:2026-05-12 -->
  Impact: Debugging difficult. Caller cannot determine if anchor request or network timed out. Error message not actionable. | Fix: Log inner error; return it in error message: 'Anchor request timed out (request: ..., network: ...)' if possible to distinguish | Effort: small

- [ ] **M-126** `[security]` `crates/cpoe/src/ffi/writersproof_ffi.rs:285`: Input validation for content_hash: checks len==64 and hex digits, but does not validate that the hash actually corresponds to document content. Trusts
  <!-- pid:security_input_trust | first:2026-05-12 -->
  Impact: Caller (Swift app) could submit arbitrary hash for any document. Evidence chain binds to wrong document. Forgery. | Fix: Add optional content recomputation at FFI boundary; or return error if hash doesn't match latest checkpoint | Effort: medium

- [ ] **M-127** `[code_quality]` `crates/cpoe/src/ffi/writersproof_ffi.rs:349`: Request cloning for retry logic: `req.clone()` to enqueue on offline mode. Assumes request types are Clone (brittle).
  <!-- pid:architecture_clone_for_serialize | first:2026-05-12 -->
  Impact: If request struct adds non-Clone field (Arc, Mutex), build breaks. No abstraction for serialization. | Fix: Use serde for offline queue instead of Clone; serialize to JSON and deserialize on retry | Effort: medium

- [ ] **M-128** `[error_handling]` `crates/cpoe/src/ffi/writersproof_ffi.rs:386`: Unreachable code pattern: `let mut payload...` computed inside `Ok(Ok(_))` branch but `signing_key` was dropped at line 211. Will fail to compile/run.
  <!-- pid:unreachable_code_dead_path | first:2026-05-12 -->
  Impact: Dead code suggests error recovery path never executed. May indicate incomplete refactoring or copy-paste error. Risk of divergent signing logic. | Fix: Remove dead code or factor signing into a pre-computed step before async operations | Effort: medium

- [ ] **M-129** `[performance]` `crates/cpoe/src/fingerprint/comparison.rs:254`: compare_fingerprints() (line 185) always calls all similarity computations (lines 188-251), even if style_similarity is None (line 231). Optional fiel
  <!-- pid:P034_UNNECESSARY_COMPUTATION | first:2026-05-12 -->
  Impact: Wasted computation: style components computed even when style consent not given, similarity computed but Option::None. | Fix: Return early if both activity and style data are unavailable (activity is always present, but could check style flag first). | Effort: small

- [ ] **M-130** `[code_quality]` `crates/cpoe/src/fingerprint/comparison.rs:478`: Greedy clustering function is O(n^2) with double nested loop on member indices (lines 534-542). At 500 items, this becomes ~250k comparisons with full
  <!-- pid:P001_O_N2_CLUSTERING | first:2026-05-12 -->
  Impact: Clustering large datasets (near 500-item limit) could experience severe latency. The recursive truncation at line 492 compounds the issue. | Fix: Use approximate clustering (e.g., locality-sensitive hashing, kmeans++) to reduce to O(n log n) or O(kn) where k << n. Add a time budget parameter. | Effort: large


- [ ] **M-132** `[error_handling]` `crates/cpoe/src/fingerprint/comparison.rs:812`: Unit test uses .unwrap() on serde_json::from_str() without error context (line 812). If the JSON parsing changes, error message is unhelpful.
  <!-- pid:P003_TEST_UNWRAP | first:2026-05-12 -->
  Impact: Test failures lack context. Non-production code, but sets bad pattern. | Fix: Use .expect("Failed to parse JSON in test") or return Result from test. | Effort: small

- [ ] **M-133** `[error_handling]` `crates/cpoe/src/fingerprint/consent.rs:185`: ConsentManager::save() (line 185) uses atomic write pattern: write to .tmp, sync_all(), rename(). But if rename() fails, the .tmp file is left behind.
  <!-- pid:P019_TEMP_FILE_LEAK | first:2026-05-12 -->
  Impact: Disk space leak: orphaned .json.tmp files accumulate over failed saves. | Fix: Use a Drop impl on a temp file guard, or explicit cleanup: on rename error, delete the .tmp file. | Effort: small

- [ ] **M-134** `[code_quality]` `crates/cpoe/src/fingerprint/consent.rs:226`: format_consent_record() (line 226) builds a multi-line String by pushing to Vec. But if timestamps are None, nothing is pushed. Result is sparse and h
  <!-- pid:P037_UNSTRUCTURED_FORMAT | first:2026-05-12 -->
  Impact: Observability: consent output format is ad-hoc. Hard to machine-parse or store in structured logs. | Fix: Implement Display or to_json() method for structured output. Use serde_json to ensure consistent format. | Effort: small

- [ ] **M-135** `[security]` `crates/cpoe/src/fingerprint/manager.rs:46`: FingerprintManager::with_config checks consent at construction (line 46) and creates StyleCollector if granted. But consent can change at runtime (via
  <!-- pid:P015_RUNTIME_CONSENT_CHANGE | first:2026-05-12 -->
  Impact: Consent revocation via CLI is not propagated to running FingerprintManager. Style data keeps accumulating after user revokes consent. | Fix: Store a weak reference to ConsentManager or poll consent status before each keystroke recording (manager.rs:134). Or provide a revoke_style() method o | Effort: medium

- [ ] **M-136** `[code_quality]` `crates/cpoe/src/fingerprint/manager.rs:165`: take_snapshot() builds a Vec<(String, f64)> dimensions manually (lines 199-206), hard-coded keys. If a dimension is added elsewhere, snapshots won't c
  <!-- pid:P023_SNAPSHOT_HARDCODING | first:2026-05-12 -->
  Impact: Snapshot dimensions are manually synchronized. New fingerprint dimensions require manual updates in two places (activity + snapshot builder). | Fix: Add a trait `FingerprintDimension { name: &str, value: f64 }` and iterator on fingerprint to auto-populate snapshots. | Effort: medium

- [ ] **M-137** `[security]` `crates/cpoe/src/fingerprint/manager.rs:195`: take_snapshot() (line 165) divides typing_speed by 120.0 (line 200) without explanation. No comment on where 120 wpm comes from. If typing_speed is in
  <!-- pid:P038_MAGIC_CONSTANT | first:2026-05-12 -->
  Impact: Data quality: snapshot dimension may not reflect actual typing speed if units changed. Inconsistent units across modules. | Fix: Add a constant SNAPSHOT_TYPING_SPEED_BASELINE = 120 wpm with a comment explaining why, and ensure typing_speed is always in wpm. | Effort: small

- [ ] **M-138** `[security]` `crates/cpoe/src/fingerprint/storage.rs:82`: Fingerprint encryption key is loaded once at initialization and wrapped in Zeroizing. However, the key is cloned into the cipher on every encrypt/decr
  <!-- pid:P004_KEY_DUPLICATION | first:2026-05-12 -->
  Impact: Biometric key material duplicated in memory across encryption operations. If process is swapped or dumped mid-operation, key recovery possible. | Fix: Cache a single ChaCha20Poly1305 instance in FingerprintStorage (const-time thread-safe). Use Arc<ChaCha20Poly1305> if needed for Arc<Self> in concurre | Effort: medium

- [ ] **M-139** `[performance]` `crates/cpoe/src/fingerprint/storage.rs:137`: refresh_index() loads and decrypts every .profile file whose mtime changed (lines 136-142). For 100 profiles, this is 100 HKDF derivations + 100 ChaCh
  <!-- pid:P013_PROFILE_LOAD_PERF | first:2026-05-12 -->
  Impact: Starting the manager with many stored profiles is slow (seconds for 100+ profiles). Each refresh blocks. | Fix: Store an index file (.profiles.index) with unencrypted metadata (id, mtime, sample_count, has_style). Decrypt full profile only when load() is called. | Effort: medium

- [ ] **M-140** `[security]` `crates/cpoe/src/fingerprint/storage.rs:215`: delete() method (line 210) overwrites file with random data (line 216-218), then removes file (line 219). But on some filesystems (e.g., ZFS, Btrfs wi
  <!-- pid:P035_WEAK_SECURE_DELETE | first:2026-05-12 -->
  Impact: Secure deletion: fingerprint file may be recoverable even after delete() due to filesystem copy-on-write or compression. | Fix: Use a crate like secure_delete or zeroize for filesystem-aware wiping. Or document that this is best-effort only and recommend LUKS encryption. | Effort: medium

- [ ] **M-141** `[error_handling]` `crates/cpoe/src/fingerprint/storage.rs:366`: load_snapshots() (line 363) silently returns empty Vec on any error (line 366: unwrap_or_default()). If snapshots.json is corrupted, the app starts wi
  <!-- pid:P030_SILENT_SNAPSHOT_LOSS | first:2026-05-12 -->
  Impact: Silent data loss: corrupted snapshots file is ignored, historical evolution data discarded without user notification. | Fix: Log a warn!() on deserialization error, and return Err up the stack so new() can decide whether to fail or continue with empty history. | Effort: small

- [ ] **M-142** `[security]` `crates/cpoe/src/fingerprint/voice.rs:13`: MAX_WORD_LENGTH is hardcoded to 20. Words longer than 20 are silently truncated in word_lengths array (line 718: .min(MAX_WORD_LENGTH)). A user with v
  <!-- pid:P027_WORD_LENGTH_TRUNCATION | first:2026-05-12 -->
  Impact: Data quality: long-word languages (German, Dutch) have compressed representation. Fingerprints less distinctive for these languages, reducing auth acc | Fix: Use HashMap<usize, usize> instead of array to capture full distribution. Or increase MAX_WORD_LENGTH to 50. | Effort: small

- [ ] **M-143** `[code_quality]` `crates/cpoe/src/fingerprint/voice.rs:380`: BackspaceSignature::similarity() (line 361) computes sims array with 10 elements (line 362-379), then averages (line 380). If any similarity is NaN (e
  <!-- pid:P032_NAN_AVERAGE | first:2026-05-12 -->
  Impact: Data quality: single NaN metric pollutes entire signature similarity. Fingerprint comparison breaks if any correction metric is invalid. | Fix: Filter out NaN values before averaging: sims.iter().filter(|s| s.is_finite()).sum() / count, or clamp each sim to [0, 1]. | Effort: small

- [ ] **M-144** `[performance]` `crates/cpoe/src/fingerprint/voice.rs:767`: add_to_ngram_buffer() (line 759) normalizes non-ASCII chars using to_lowercase().next().unwrap_or() and unicode_normalization::nfc (line 766-768). Thi
  <!-- pid:P021_UNICODE_HOTPATH | first:2026-05-12 -->
  Impact: Performance: unnecessary allocations on hot path. For 10k keystrokes, 1k+ allocations for non-ASCII normalization even if user types ASCII. | Fix: Batch Unicode normalization in finish_word() or use a SIMD ASCII fast path (if c.is_ascii() { /* no alloc */ } else { /* normalize */ }). | Effort: medium

- [ ] **M-145** `[code_quality]` `crates/cpoe/src/fingerprint/voice.rs:1223`: File ends at line 1223 with closing brace of tests module. Total 1223 lines in one file. StyleCollector alone is 400+ lines (549-950+). No submodules 
  <!-- pid:P016_VOICE_GOD_MODULE | first:2026-05-12 -->
  Impact: God module: StyleCollector handles word patterns, backspacing, punctuation, ngrams, sentence rhythm. Changes to one dimension require careful navigati | Fix: Split into submodules: collector::word_pattern, collector::backspace, collector::ngram with separate accumulators merged in current_fingerprint(). | Effort: large

- [ ] **M-146** `[architecture]` `crates/cpoe/src/forensics:0`: Duplicated threshold definitions across modules (e.g., MIN_EVENTS_FOR_MODE in writing_mode.rs, MIN_EVENTS_FOR_ANALYSIS in types.rs)
  <!-- pid:duplicated_thresholds | first:2026-05-12 -->
  Impact: Threshold values drift across modules when updated; forensic gates use inconsistent cutoffs leading to false verdicts | Fix: Centralize thresholds in types.rs or separate constants module; reference from forensics modules | Effort: medium

- [ ] **M-147** `[code_quality]` `crates/cpoe/src/forensics/advanced_metrics.rs:108`: compute_iki_surprisal_correlation() uses hard-coded 0.0 as default instead of None for NaN cases
  <!-- pid:ZERO_DEFAULT_AMBIGUOUS | first:2026-05-12 -->
  Impact: Zero correlation returned when input data is non-finite; indistinguishable from actual uncorrelated data | Fix: Return Option<f64> to distinguish failure from valid zero correlation result | Effort: small

- [ ] **M-148** `[performance]` `crates/cpoe/src/forensics/analysis.rs:81`: split_into_windows allocates intermediate char vector for every window call; O(n) allocations for window generation
  <!-- pid:window_allocation_overhead | first:2026-05-12 -->
  Impact: If document_text is large (>1MB), window splitting causes O(n*window_size) memory overhead and GC pressure | Fix: Use char iterators or byte offset calculations instead of collecting into Vec<char> | Effort: medium

- [ ] **M-149** `[code_quality]` `crates/cpoe/src/forensics/assessment.rs:272`: compute_assessment_score() 123 lines with 15+ penalty/reward branches; deeply nested conditionals (up to 3 levels)
  <!-- pid:LONG_BRANCH_FUNCTION | first:2026-05-12 -->
  Impact: Difficult to verify all penalty combinations; risk of double-counting (e.g., both POS_NEG_PENALTY and DELETION_CLUSTERING_PENALTY applied on same cond | Fix: Refactor into penalty_struct with name:penalty pairs, accumulate in loop; separate concerns | Effort: medium



- [ ] **M-152** `[architecture]` `crates/cpoe/src/forensics/assessment.rs:437`: apply_focus_penalties() delegates to super::scoring::compute_focus_penalty() creating cross-module coupling
  <!-- pid:SPLIT_PENALTY_LOGIC | first:2026-05-12 -->
  Impact: Focus penalty computation split across two modules; hard to audit all penalty sources in compute_assessment_score() | Fix: Consolidate all penalty computations into assessment.rs or provide unified scoring interface | Effort: medium

- [ ] **M-153** `[performance]` `crates/cpoe/src/forensics/cognitive_load.rs:425`: Full document scan for paragraph boundaries in compute_structural_pause_concentration() called on every sample analysis
  <!-- pid:REPEATED_TEXT_SCAN | first:2026-05-12 -->
  Impact: document_text.match_indices(PARAGRAPH_BREAK) repeated for every check call; could be 10+ calls per session | Fix: Cache boundary_positions as part of analysis input or compute once at session start | Effort: medium

- [ ] **M-154** `[architecture]` `crates/cpoe/src/forensics/cognitive_load.rs:541`: analyze_cognitive_load() requires optional document_text parameter; inconsistent with sentence_arc and structural checks that require text
  <!-- pid:INCONSISTENT_NONE_HANDLING | first:2026-05-12 -->
  Impact: If text is None, all three scales return default 0.0, composite_score becomes synthetic (0.5); hard to distinguish missing data from transcriptive sig | Fix: Return Option<CognitiveLoadMetrics> if text is None (not Some(default)); force caller to handle absence | Effort: small

- [ ] **M-155** `[code_quality]` `crates/cpoe/src/forensics/cross_modal.rs:146`: Total of 22 hardcoded threshold constants (line 22-49) scattered in module, no central config reference
  <!-- pid:SCATTERED_THRESHOLDS | first:2026-05-12 -->
  Impact: Threshold values (MIN_JITTER_DENSITY=0.5, MAX_SUSTAINED_CHARS_PER_SEC=15.0, etc.) cannot be tuned; values manipulable by commit | Fix: Extract to module-level config struct or constants::cross_modal; document rationale per threshold | Effort: medium

- [ ] **M-156** `[code_quality]` `crates/cpoe/src/forensics/cross_modal.rs:323`: Zero timestamp check uses == 0 comparison but timestamps are i64; underflow risk (line 339 uses i128 conversion but not here)
  <!-- pid:ZERO_TIMESTAMP_AMBIGUOUS | first:2026-05-12 -->
  Impact: edit_first==0 misdetects valid sessions starting at epoch; false positive on temporal_span_alignment check | Fix: Check if timestamps span indicates invalid data: if edit_first == 0 || edit_last == 0 OR (edit_last - edit_first) < 1000 (minimum 1us session) | Effort: small

- [ ] **M-157** `[code_quality]` `crates/cpoe/src/forensics/dictation.rs:282`: cluster_speaker_segments uses usize arithmetic without overflow checks when accumulating word counts
  <!-- pid:word_count_accumulation | first:2026-05-12 -->
  Impact: If dictation events have large word_count fields, segment.word_count can overflow when summed (line 339) | Fix: Use saturating_add for segment accumulation like event accumulation does | Effort: small



- [ ] **M-160** `[code_quality]` `crates/cpoe/src/forensics/likelihood_model.rs:537`: mean_llr computed from sum then used for session_p_cognitive but window LLRs are per-window scaled; potential scale mismatch
  <!-- pid:SCALE_INCONSISTENCY | first:2026-05-12 -->
  Impact: Session posterior based on mean LLR per window, not sum; if window_count changes, interpretation changes; could be inconsistent with window timeline | Fix: Document and validate: session_p_cognitive always uses mean, not sum; ensure window_timeline and session score reference same aggregation | Effort: small

- [ ] **M-161** `[error_handling]` `crates/cpoe/src/forensics/likelihood_model.rs:551`: Silent NaN propagation via filter(|v| v.is_finite()).unwrap_or(0.0) masks computation failure
  <!-- pid:SILENT_NAN_MASK | first:2026-05-12 -->
  Impact: Non-finite LLR from log functions replaced with 0.0, interpretation ambiguous (neutral vs failed check) | Fix: Return Option<LikelihoodModelMetrics> and propagate None instead of masking with 0.0 | Effort: medium

- [ ] **M-162** `[error_handling]` `crates/cpoe/src/forensics/types.rs:617`: NaN comparator in select_nth_unstable_by uses unwrap_or with no documented ordering for NaN
  <!-- pid:nan_comparator_percentile | first:2026-05-12 -->
  Impact: If IKI contains NaN, percentile calculations produce undefined ordering; bps_mean and percentiles may be incorrect silently | Fix: Pre-filter NaN from ikis vector before percentile calculation; test with NaN inputs | Effort: small

- [ ] **M-163** `[security]` `crates/cpoe/src/forensics/writing_mode.rs:149`: COGNITIVE_THRESHOLD (0.65) is hardcoded without calibration reference in comments
  <!-- pid:undocumented_threshold | first:2026-05-12 -->
  Impact: Threshold choice lacks documented basis; no reference to diary calibration or test set accuracy | Fix: Add comment citing diary calibration accuracy at this threshold; consider parameterizing for future A/B testing | Effort: small

- [ ] **M-164** `[code_quality]` `crates/cpoe/src/forensics/writing_mode.rs:238`: Function classify_writing_mode is 147 lines; deeply nested signal weighting logic
  <!-- pid:long_classification_function | first:2026-05-12 -->
  Impact: Difficult to verify correctness of v1 vs v2 classifier branching; 13-signal weighted sum in v1 branch is error-prone | Fix: Extract signal collection into separate function; use table-driven weights instead of explicit array initialization | Effort: medium

- [ ] **M-165** `[error_handling]` `crates/cpoe/src/forensics/writing_mode.rs:328`: Division by zero risk when total_weight is exactly 0.0 (epsilon check uses f64::EPSILON)
  <!-- pid:div_by_epsilon_check | first:2026-05-12 -->
  Impact: If all scores sum to near-zero due to NaN propagation, capping fails and NaN divides by near-zero producing Inf or NaN in cognitive_score | Fix: Pre-check total_weight before using it as divisor; currently only checks > EPSILON but should clamp earlier | Effort: small

- [ ] **M-166** `[code_quality]` `crates/cpoe/src/forensics/writing_mode.rs:395`: analyze_revision_patterns has complex nested loop with burst/deletion pattern matching; difficult to verify correctness
  <!-- pid:complex_revision_loop | first:2026-05-12 -->
  Impact: Off-by-one errors in burst_start/del_start indexing could miss or double-count revision cycles | Fix: Add comments documenting state machine: burst accumulation → deletion accumulation → cycle detection; add invariant assertions | Effort: medium

- [ ] **M-167** `[performance]` `crates/cpoe/src/forensics/writing_mode.rs:516`: coefficient_of_variation called on burst_lengths vector for every session; CV recalculation not cached
  <!-- pid:burst_cv_not_cached | first:2026-05-12 -->
  Impact: If many sessions analyzed, CV is recomputed; no caching in forensic pipeline leads to redundant stat calculations | Fix: Pre-compute CV in cadence analysis; pass as precomputed value to writing_mode module | Effort: medium

- [ ] **M-168** `[error_handling]` `crates/cpoe/src/identity/did_webvh.rs:346`: state.save_state() may fail but error is wrapped generically by map_webvh_err; no context preserved
  <!-- pid:save_state_error_context | first:2026-05-12 -->
  Impact: Line 344: self.state.save_state(state_tmp_str).map_err(map_webvh_err) wraps any error from didwebvh_rs as generic 'did:webvh:' prefix. If serializatio | Fix: Match specific error types: match self.state.save_state(...) { Err(e) if e.contains('serde') => ... } | Effort: small

- [ ] **M-169** `[code_quality]` `crates/cpoe/src/identity/mnemonic.rs:37`: generate() and derive_silicon_seed() both create random entropy but entropy generation is not wrapped in ZeroizeOnDrop
  <!-- pid:entropy_generation_not_seeded | first:2026-05-12 -->
  Impact: Line 35-38: entropy is created as [0u8; 16] stack array, filled randomly, then zeroized. Stack array is properly zeroized. But MnemonicHandler::genera | Fix: Accept entropy as parameter, or provide deterministic PRNG for tests. Document seed behavior. | Effort: small

- [ ] **M-170** `[code_quality]` `crates/cpoe/src/identity/presentation_exchange.rs:99`: tiers_at_or_above() uses .unwrap_or_else() with index 0 fallback; no explicit error handling for unknown tier
  <!-- pid:tier_unknown_silent_default | first:2026-05-12 -->
  Impact: Line 48-54: if min_tier is unknown (not in TIER_ORDER), unwrap_or_else silently defaults to bronze (index 0) and logs warning. Callers can't distingui | Fix: Return Result<Vec<&'static str>, Error> or panic on unknown tier in production. | Effort: small

- [ ] **M-171** `[concurrency]` `crates/cpoe/src/identity/secure_storage.rs:28`: SEED_CACHE allows concurrent readers but reset via reset_seed_cache() without coordination
  <!-- pid:cache_reset_race | first:2026-05-12 -->
  Impact: Multiple threads can read SEED_CACHE via load_seed() while another thread calls reset_seed_cache() (line 280). This is intentional (comment at line 25 | Fix: Document lock ordering and reader lifetime guarantees. Or use RwLock with read guards: guard released before reset. | Effort: small

- [ ] **M-172** `[code_quality]` `crates/cpoe/src/identity/secure_storage.rs:36`: IDENTITY_CACHE type annotation is very long and complex; could be extracted to type alias
  <!-- pid:long_type_annotation | first:2026-05-12 -->
  Impact: Line 36-37: static IDENTITY_CACHE: Mutex<Option<(Zeroizing<[u8; 16]>, Zeroizing<String>)>>. Long type; difficult to read and maintain. | Fix: type IdentityCacheTy = Option<(Zeroizing<[u8; 16]>, Zeroizing<String>)>; | Effort: small

- [ ] **M-173** `[code_quality]` `crates/cpoe/src/identity/secure_storage.rs:239`: save_hmac_key() and save_seed() duplicate identical 32-byte validation logic
  <!-- pid:duplicated_key_size_validation | first:2026-05-12 -->
  Impact: Lines 241-246 (seed) and 284-289 (hmac) both validate len() != 32. No shared function. If validation changes, must update 5+ places (seed, hmac, signi | Fix: Create validate_key_size(key, 32, "HMAC key") or use const generic. | Effort: small

- [ ] **M-174** `[error_handling]` `crates/cpoe/src/ipc/async_client.rs:203`: drop() of ECDH secrets does not guarantee timing-safe cleanup on all platforms
  <!-- pid:P016_timing_safe_drop | first:2026-05-12 -->
  Impact: Explicit drop() assumes ZeroizeOnDrop triggers immediately, but is_dropped() has no guarantee across LLVM versions; compiler_fence attempts to prevent | Fix: Use explicit zeroize::Zeroize trait or ensure Drop impl is called via scope end, not drop() | Effort: medium

- [ ] **M-175** `[security]` `crates/cpoe/src/ipc/crypto.rs:72`: construct_nonce function builds 12-byte AES-GCM nonce from 4-byte prefix + 8-byte seq. Nonce reuse protection depends on sequence being monotonically 
  <!-- pid:nonce_invariant_docs | first:2026-05-12 -->
  Impact: If rx/tx nonce prefixes are not properly separated, or if sequence counter is shared between directions, nonce reuse attacks become possible, breaking | Fix: Add doc comment: `/// CRITICAL: Nonce reuse is fatal. Prefix must differ per direction, and seq must be strictly increasing.` | Effort: small

- [ ] **M-176** `[concurrency]` `crates/cpoe/src/ipc/crypto.rs:136`: Sequence overflow check uses >= (u64::MAX - 1) boundary before CAS loop. If concurrent thread wins CAS race just before overflow, next thread can over
  <!-- pid:race_condition_seq_overflow | first:2026-05-12 -->
  Impact: Under extreme load (>2^63 messages), a race condition could cause sequence number to wrap around. AES-GCM nonce uniqueness would be compromised: old m | Fix: Move overflow check inside the CAS loop: after `compare_exchange`, verify `current + 2 < u64::MAX`. Or use atomic CAS-based increment that returns pri | Effort: medium

- [ ] **M-177** `[security]` `crates/cpoe/src/ipc/crypto.rs:188`: Constant-time comparison on sequence number using ct_eq().unwrap_u8() != 1. While ct_eq is used, converting to u8 and comparing != 1 re-introduces a n
  <!-- pid:timing_leak_seq_compare | first:2026-05-12 -->
  Impact: A timing-channel attacker could observe the != 1 branch to infer whether seq matches expected_seq, potentially leaking sequence patterns. However, seq | Fix: Use `if !ct_eq(...)` or store ct_eq result without branch: `let matches = ct_eq(...).into(); if !matches { return Err(...) }` (still branches, but on  | Effort: small

- [ ] **M-178** `[error_handling]` `crates/cpoe/src/ipc/crypto.rs:325`: Invalid P-256 public key from wire is rejected with anyhow!("Invalid client P-256 public key"), but upstream error from from_sec1_bytes is discarded. 
  <!-- pid:error_context_loss | first:2026-05-12 -->
  Impact: Loss of error context: attacker cannot be distinguished from protocol version mismatch or data corruption. Debugging and security event logging are le | Fix: Use a custom error enum for handshake errors: `pub enum HandshakeError { InvalidClientKey, ... }` and propagate the inner error details. | Effort: medium

- [ ] **M-179** `[security]` `crates/cpoe/src/ipc/crypto.rs:360`: Client confirmation token length is validated (0 < len <= 1024) but no upper bound is enforced on allocation. If confirm_len is near u32 max before ca
  <!-- pid:allocation_bound_check | first:2026-05-12 -->
  Impact: The 1024-byte limit is conservative, so no direct memory exhaustion, but the pattern (cast without re-check) could be exploited if limits are loosened | Fix: Enforce size limit explicitly: `if confirm_len > 1024 { ... }` check before Vec allocation, and consider reducing limit further. | Effort: small

- [ ] **M-180** `[security]` `crates/cpoe/src/ipc/messages.rs:66`: fs::canonicalize() called unconditionally on every path, fails for non-existent files; fallback to logical resolution may leave traversal sequences if
  <!-- pid:P025_logical_resolution | first:2026-05-12 -->
  Impact: New files (not yet on disk) bypass canonicalize; logical resolution at line 69-88 must correctly handle all .. and . cases; complex state machine risk | Fix: Unit test path resolution with adversarial inputs; add comment verifying correctness of Component handling | Effort: medium

- [ ] **M-181** `[performance]` `crates/cpoe/src/ipc/messages.rs:181`: Per-message heap allocation: `Vec::new()` in path component stack (line 69) during every IPC path validation
  <!-- pid:P006_vec_per_message | first:2026-05-12 -->
  Impact: Every StartWitnessing/ExportFile creates Vec on heap; DOS via rapid file tracking requests allocates unbounded vectors | Fix: Use ArrayVec<Component, 32> for stack of path components or pre-allocate fixed capacity | Effort: medium

- [ ] **M-182** `[security]` `crates/cpoe/src/ipc/rbac.rs:23`: Response message types classified as ReadOnly including Error, Ok, HandshakeAck; server-origin check not enforced, client could impersonate responses
  <!-- pid:P013_response_spoofing | first:2026-05-12 -->
  Impact: No check that Response variants are server-only; a malicious local client sending Response messages could confuse other clients or handlers that expec | Fix: Add is_server_message() helper or split message enum into ClientMsg/ServerMsg | Effort: medium

- [ ] **M-183** `[concurrency]` `crates/cpoe/src/ipc/secure_channel.rs:142`: AtomicU64 nonce counter uses SeqCst ordering in loop (line 149-150); unnecessary strong memory ordering under contention
  <!-- pid:P012_excess_atomics | first:2026-05-12 -->
  Impact: Performance: SeqCst is stronger than needed; compare_exchange could use Acquire/Release pair for same correctness with less fence cost | Fix: Change Ordering::SeqCst to Acquire/Release in compare_exchange | Effort: small

- [ ] **M-184** `[error_handling]` `crates/cpoe/src/ipc/secure_channel.rs:214`: Plaintext after AEAD decryption is zeroized only on deserialization error (line 224), not on PayloadTooLarge error (line 215)
  <!-- pid:P011_zeroize_skip | first:2026-05-12 -->
  Impact: Plaintext > MAX_SECURE_CHANNEL_PAYLOAD is returned without zeroization, leaving copy on stack | Fix: Move PayloadTooLarge check before decryption or zeroize plaintext unconditionally | Effort: small

- [ ] **M-185** `[error_handling]` `crates/cpoe/src/ipc/server.rs:65`: UnixStream probe connection used to check liveness; dropped without explicit error handling, may leak on error
  <!-- pid:P026_probe_leak | first:2026-05-12 -->
  Impact: Dropped stream on EADDRINUSE path; if drop panics, socket may not be removed | Fix: Explicitly call drop(stream) in a scope or use guard | Effort: small

- [ ] **M-186** `[concurrency]` `crates/cpoe/src/ipc/server.rs:149`: fetch_update loop (line 150-156) for MAX_CONCURRENT_CONNECTIONS does not time-bound retries; tight spin under contention
  <!-- pid:P009_spinlock_contention | first:2026-05-12 -->
  Impact: Under high connection load, CPU cost of fetch_update retry loop may spike; no exponential backoff | Fix: Add exponential backoff or break after N retries before rejecting connection | Effort: small

- [ ] **M-187** `[concurrency]` `crates/cpoe/src/ipc/server.rs:240`: Atomic fetch_update() loop for MAX_CONCURRENT_CONNECTIONS can spuriously fail under load; no backoff causes busy-spin
  <!-- pid:P023_atomic_contention | first:2026-05-12 -->
  Impact: High CPU usage during connection storms; OS scheduler affected | Fix: Move increment outside loop or use bounded retry with sleep | Effort: small

- [ ] **M-188** `[error_handling]` `crates/cpoe/src/ipc/server.rs:356`: SAFETY comment on getuid() claims 'no preconditions' but doesn't document that glibc caches UID and permission checks may race with setuid changes
  <!-- pid:P008_getuid_cache | first:2026-05-12 -->
  Impact: If process calls setuid() after daemon start, the cached UID check may reject legitimate clients or allow unauthorized ones | Fix: Call getuid() only once at bind time, cache in struct, or call libc::getpid()/libc::getsuid() dynamically | Effort: medium

- [ ] **M-189** `[performance]` `crates/cpoe/src/ipc/server_handler.rs:181`: vec![0u8; msg_len] allocates heap for every message; no reuse across loop iterations
  <!-- pid:P020_alloc_per_msg | first:2026-05-12 -->
  Impact: Rapid IPC clients trigger allocation/deallocation churn; buffer pool would reduce GC pressure | Fix: Reuse Vec with clear() in outer loop or use buffer pool | Effort: medium

- [ ] **M-190** `[security]` `crates/cpoe/src/ipc/server_handler.rs:241`: Rate limiter uses message type as key (via rate_limit_key) but does not account for client origin; shared across all connections
  <!-- pid:P018_global_rate_limit | first:2026-05-12 -->
  Impact: Single malicious local client can exhaust rate limit for message type and deny service to other users (acknowledged in comment line 76-80 but exploita | Fix: Include client UID/PID in rate limit key or use per-connection limit with burst allowance | Effort: large

- [ ] **M-191** `[concurrency]` `crates/cpoe/src/ipc/server_handler.rs:243`: mutex.lock().unwrap_or_else() recovers poisoned mutex and continues processing; no re-validation of state after recovery
  <!-- pid:P003_mutex_poison | first:2026-05-12 -->
  Impact: Rate limiter state may be inconsistent after poison recovery; attacker could exploit inconsistency to bypass rate limiting by poisoning the mutex | Fix: Log poison recovery, re-initialize RateLimiter, or fail-closed by breaking connection | Effort: medium

- [ ] **M-192** `[error_handling]` `crates/cpoe/src/ipc/server_handler.rs:326`: Handler panic caught and logged but no context about which message caused panic; error response is generic InternalError
  <!-- pid:P019_panic_context_loss | first:2026-05-12 -->
  Impact: Loss of debugging information; unable to correlate panic with specific message content for security audit | Fix: Log message type and size before spawn_blocking, include context in panic catch | Effort: small

- [ ] **M-193** `[performance]` `crates/cpoe/src/ipc/unix_socket.rs:49`: unwrap_or_else on macOS peer PID fetch logs warning but continues; platform-specific availability mismatch could lead to implicit PID 0 in prod logs
  <!-- pid:P014_pid_fallback | first:2026-05-12 -->
  Impact: macOS silent PID failure masks potential security issue; warning logged at line 50 but PID fallback to 0 may be accepted downstream | Fix: Return error if PID cannot be determined on macOS, don't fall back to 0 | Effort: small

- [ ] **M-194** `[code_quality]` `crates/cpoe/src/keyhierarchy/manager.rs:33`: canonicalize() failure silently falls back to original path without logging file system errors
  <!-- pid:canonicalize_fallback_silent | first:2026-05-12 -->
  Impact: Lines 33-37: canonicalize() may fail for various reasons (symlinks broken, permissions, etc.). Error is logged at debug level only. Fallback to origin | Fix: Propagate canonicalize errors as Result, or explicitly log warning and require real path. | Effort: small

- [ ] **M-195** `[code_quality]` `crates/cpoe/src/keyhierarchy/puf.rs:99`: tempfile::NamedTempFile created but dropped immediately after persist(); no cleanup on panic between creation and persist
  <!-- pid:tempfile_panic_cleanup | first:2026-05-12 -->
  Impact: Lines 99-103: tmp file is created, written, synced, then persisted. If panic occurs after creation but before persist(), temp file is left on disk. No | Fix: Use NamedTempFile::keep() explicitly or rely on Drop, but test panic safety. | Effort: small

- [ ] **M-196** `[error_handling]` `crates/cpoe/src/keyhierarchy/puf.rs:105`: SecureStorage::save_seed() may silently fail (logged warning only) but SoftwarePUF continues
  <!-- pid:secure_storage_silent_failure | first:2026-05-12 -->
  Impact: Line 105-107: if save_seed() fails, warning is logged but execution continues with file-based storage. No Error is propagated. Callers don't know if t | Fix: Propagate errors: save_seed().map_err(|e| KeyHierarchyError::Crypto(format!(...)))? | Effort: small

- [ ] **M-197** `[architecture]` `crates/cpoe/src/keyhierarchy/verification.rs:148`: verify_checkpoint_signatures() assumes counter monotonicity but does not validate initial counter value is reasonable
  <!-- pid:counter_value_not_bounded | first:2026-05-12 -->
  Impact: Lines 126-152: code checks counter does not decrease and delta matches. But no check that counter_value itself is reasonable (e.g., not MAX_u64 or inv | Fix: Add explicit counter range validation: if current > REASONABLE_MAX_COUNTER { return Err(...) } | Effort: small

- [ ] **M-198** `[architecture]` `crates/cpoe/src/keyhierarchy/verification.rs:234`: verify_key_hierarchy() calls verify_ratchet_key_consistency() but does not verify ratchet seed derivation itself
  <!-- pid:ratchet_derivation_not_verified | first:2026-05-12 -->
  Impact: Lines 234-235: ratchet keys are verified to match signatures and be present. But the code does NOT verify that ratchet keys are correctly derived from | Fix: Document limitation in comments. Or add optional secret seed parameter for full verification in recovery paths. | Effort: small

- [ ] **M-199** `[code_quality]` `crates/cpoe/src/platform/linux/keystroke.rs:140`: Comment documents limitation (blocking fetch_events) but provides no workaround documentation
  <!-- pid:undocumented_design_limitation | first:2026-05-12 -->
  Impact: New maintainers may not understand why stop() can be slow. Suggests port to epoll or polling, but those are complex. No guidance provided. | Fix: Add FIXME with design options (epoll, non-blocking API, separate watchdog thread). Document why current design chosen. | Effort: small

- [ ] **M-200** `[security]` `crates/cpoe/src/platform/linux/keystroke.rs:162`: Device info cloned for every keystroke to check is_physical flag
  <!-- pid:per_event_alloc_hot_path | first:2026-05-12 -->
  Impact: Arc cloned inside per-keystroke loop. RwLock acquired, cloned, then dropped. Allocator pressure in hot path. | Fix: Cache is_physical flag at thread start. Store in closure capture or thread-local. Avoid per-event clone. | Effort: small

- [ ] **M-201** `[error_handling]` `crates/cpoe/src/platform/linux/mod.rs:135`: unwrap_or('Unknown') masks device name read failures without logging
  <!-- pid:silent_device_name_failure | first:2026-05-12 -->
  Impact: If device.name() fails, 'Unknown' is silently used. No indication device enumeration partially failed. Fingerprinting accuracy reduced silently. | Fix: Log warning if device name fails. Propagate device enumeration errors. | Effort: small

- [ ] **M-202** `[error_handling]` `crates/cpoe/src/platform/macos/ffi.rs:143`: timestamp_nanos_opt() failure silently defaults to 0, no indication of clock failure
  <!-- pid:clock_init_failure_silent | first:2026-05-12 -->
  Impact: If chrono clock fails, all calibration timestamps reset to epoch (1970). All subsequent event timestamps will be massively offset. No error indication | Fix: Return Result<MachToWallClock, Error> and propagate clock initialization failures to caller. | Effort: small

- [ ] **M-203** `[code_quality]` `crates/cpoe/src/platform/macos/hid_capture.rs:95`: unwrap_or_else pattern with lock() on poisoned mutex without explicit recovery indication
  <!-- pid:implicit_mutex_poison_handling | first:2026-05-12 -->
  Impact: lock().unwrap_or_else(...) masks poisoned state. Silent recovery could mask concurrent panic. No audit trail of poison events. | Fix: Use try_lock, explicitly log on poison, set flag if poison detected. | Effort: small

- [ ] **M-204** `[security]` `crates/cpoe/src/platform/macos/hid_capture.rs:118`: Arc::decrement_strong_count called in error path without corresponding Arc reconstruction for potential double-free
  <!-- pid:arc_refcount_error_path | first:2026-05-12 -->
  Impact: If Arc::into_raw(Arc::clone()) was called, decrement_strong_count should only be called if no Arc reconstruction happens. Could double-free if error p | Fix: Add comment documenting the decrement/reconstruct pairing. Add test for error path. | Effort: small

- [ ] **M-205** `[security]` `crates/cpoe/src/platform/macos/keystroke.rs:183`: Busy-polling in EventTapRunner::stop with 50ms sleep intervals instead of condition variable
  <!-- pid:busy_polling_thread_exit | first:2026-05-12 -->
  Impact: Wasting CPU cycles polling thread status. If thread is hung, busy loop for full 3s deadline. No efficient notification mechanism. | Fix: Use thread::JoinHandle::is_finished() is OK, but consider event::Condvar for faster feedback when thread exits early. | Effort: medium

- [ ] **M-206** `[security]` `crates/cpoe/src/platform/macos/keystroke.rs:306`: KeystrokeMonitor start() stores tap pointer in Arc<AtomicPtr> but doesn't validate it against null after extraction from tap_resources
  <!-- pid:tap_pointer_validation | first:2026-05-12 -->
  Impact: If tap creation failed silently (returned Some(CfGuard) wrapping null), the null pointer is stored and later dereferenced in callback. Safety depends  | Fix: Add assertion: assert!(!tap.as_ptr().is_null()) after CfGuard::new. Validate tap pointer is non-null before storing. | Effort: small

- [ ] **M-207** `[security]` `crates/cpoe/src/platform/macos/mouse_capture.rs:223`: Busy-polling in MacOSMouseCapture::stop with 50ms sleep similar to keystroke runner
  <!-- pid:busy_polling_thread_exit | first:2026-05-12 -->
  Impact: Same as keystroke: inefficient polling, wasting CPU, no condition variable for prompt shutdown. | Fix: Use condvar or event notification instead of poll loop. | Effort: medium

- [ ] **M-208** `[security]` `crates/cpoe/src/platform/windows.rs:89`: String::from_utf16_lossy in query_full_process_image_name silently masks invalid UTF-16 without indication
  <!-- pid:silent_utf16_decode_failure | first:2026-05-12 -->
  Impact: Invalid UTF-16 from kernel process name is silently replaced with replacement char. Malformed process name could hide injection attacks. No logging. | Fix: Validate UTF-16 before decode, log if invalid sequences found. | Effort: small

- [ ] **M-209** `[concurrency]` `crates/cpoe/src/platform/windows.rs:168`: Polling for pump thread ID instead of using explicit synchronization
  <!-- pid:thread_startup_polling | first:2026-05-12 -->
  Impact: Busy-waits up to 5 seconds polling AtomicU32. If pump thread slow to start, wastes CPU. No event notification. | Fix: Use Condvar or channel to signal thread ID readiness instead of polling. | Effort: medium

- [ ] **M-210** `[code_quality]` `crates/cpoe/src/rats/corim.rs:113`: extract_f64 and extract_u64 helper functions repeat error context formatting; 3 similar Error constructors per function
  <!-- pid:repeated_field_error_formatting | first:2026-05-12 -->
  Impact: Identical error message patterns; harder to maintain validation logic | Fix: Define enum for CorimFieldError(field_name, reason); use in helpers | Effort: medium

- [ ] **M-211** `[code_quality]` `crates/cpoe/src/rats/corim.rs:130`: from_cbor uses .iter().find() on CBOR map entries; no validation that all required fields are present
  <!-- pid:missing_field_validation | first:2026-05-12 -->
  Impact: Missing required fields silently use defaults; incomplete CoRIM accepted | Fix: After loop, check that all required fields (min_entropy_bits, vdf_duration_bounds, etc.) were set; return error if any remain default | Effort: small

- [ ] **M-212** `[security]` `crates/cpoe/src/rats/eat.rs:94`: decode_eat_cwt_verified() signature verification uses sign1.verify_signature() with empty additional authenticated data ([]); no validation that prote
  <!-- pid:AAD_VALIDATION | first:2026-05-12 -->
  Impact: Unprotected header fields could be modified after signature verification without detection | Fix: Validate protected header contains critical fields (algorithm); use verify_signature with real AAD if needed | Effort: medium

- [ ] **M-213** `[maintainability]` `crates/cpoe/src/rats/eat.rs:115`: cbor_int() helper function documented only inline; no guidance on behavior for out-of-range i128 values or what 'try_from' does
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: Callers unsure about edge cases; may assume wrapping behavior or panic on overflow | Fix: Add doc comment: 'Returns None if i128 value exceeds i64 range or is negative; safe for CWT integer claims' | Effort: small

- [ ] **M-214** `[code_quality]` `crates/cpoe/src/rats/eat.rs:131`: Magic integer keys (CWT_ISS=1, CWT_SUB=2, CWT_KEY_EAT_PROFILE=265, etc.) used directly in map construction; semantic meaning not immediately obvious i
  <!-- pid:MAGIC_VALUES_CBOR | first:2026-05-12 -->
  Impact: Reader must jump to constant definitions to understand CWT structure; error-prone when adding new claims | Fix: Use enum for standard CWT keys: enum CwtKey { Iss=1, Sub=2, ... }; derive CBOR codec | Effort: medium

- [ ] **M-215** `[maintainability]` `crates/cpoe/src/rats/eat.rs:183`: appraisal_to_cbor() function spans 100 lines with many if-let branches; no clear ordering of optional fields; easy to miss new fields when adding to E
  <!-- pid:MANUAL_SERIALIZATION | first:2026-05-12 -->
  Impact: Schema evolution (adding new appraisal field) requires careful coordination with deserializer; risk of roundtrip failures | Fix: Derive serde with attribute macros (serde(skip_serializing_if)); let serde handle optional fields automatically | Effort: large

- [ ] **M-216** `[code_quality]` `crates/cpoe/src/rats/eat.rs:336`: Repetitive pattern in cbor_map_to_ear(): if-let-match chains for every key with hardcoded key comparison (k if k == CWT_KEY_EAT_PROFILE)
  <!-- pid:REPETITIVE_CBOR_PARSING | first:2026-05-12 -->
  Impact: Adding new EAT claims requires templated boilerplate; easy to miss handling new optional fields | Fix: Use macro or builder pattern to auto-generate CBOR -> struct mapping | Effort: medium

- [ ] **M-217** `[error_handling]` `crates/cpoe/src/rats/eat.rs:418`: Silent failure on line 418: ciborium::from_reader(b.as_slice()).ok() masks CBOR decode errors in seal data; invalid seal silently becomes None
  <!-- pid:SILENT_DECODE_ERRORS | first:2026-05-12 -->
  Impact: Corrupted seal data dropped without notification; evidence chain breaks silently | Fix: Return error if seal decode fails; log/warn at minimum; preserve decode failure signal | Effort: small

- [ ] **M-218** `[error_handling]` `crates/cpoe/src/rats/eat.rs:428`: Silent failure: entropy report decode (line 428) masked by .ok(); missing entropy silently becomes None
  <!-- pid:SILENT_DECODE_ERRORS | first:2026-05-12 -->
  Impact: Forensic entropy metrics lost without detection; attestation confidence reduced silently | Fix: Log warning on decode failure; propagate error or use default fallback | Effort: small

- [ ] **M-219** `[error_handling]` `crates/cpoe/src/rats/eat.rs:438`: Silent failure: forensic summary decode at line 438 masked by .ok(); forensic verdicts lost
  <!-- pid:SILENT_DECODE_ERRORS | first:2026-05-12 -->
  Impact: Behavioral analysis verdicts absent from attestation token without error; reduces confidence in process evidence | Fix: Return error or log warning on decode failure | Effort: small

- [ ] **M-220** `[error_handling]` `crates/cpoe/src/rats/eat.rs:449`: Silent failure: absence claims decode at line 449 masked by .ok(); proof-of-nonexistence missing without indication
  <!-- pid:SILENT_DECODE_ERRORS | first:2026-05-12 -->
  Impact: Anti-forgery absence proofs dropped from token silently | Fix: Propagate decode errors; preserve proof-of-nonexistence or fail | Effort: small

- [ ] **M-221** `[error_handling]` `crates/cpoe/src/sentinel/app_registry.rs:951`: Errors during user_apps.json deserialization are logged but silently result in Vec::new(). Backup file may not be created if rename fails. No recovery
  <!-- pid:silent_config_loss | first:2026-05-12 -->
  Impact: Corrupted user_apps.json causes silent data loss. If backup rename fails (line 958), no diagnostic. User has no way to recover custom apps. | Fix: Return Err from load() if file corruption is unrecoverable. Let caller decide whether to reset or fail startup. Log all IO errors with context. | Effort: medium

- [ ] **M-222** `[code_quality]` `crates/cpoe/src/sentinel/app_registry.rs:1049`: add_user_app() and remove_user_app() both clone entire user app list, filter, rebuild, persist, and swap. Two separate clone+filter operations.
  <!-- pid:clone_filter_pattern | first:2026-05-12 -->
  Impact: Inefficient mutation pattern. Each add/remove is O(n) clone of entire list. With user apps, n is small, but pattern is costly if list grows. | Fix: Use in-place filter pattern or swap with filtered result. Avoid intermediate clone in next = self.user.clone(); next.retain(...). | Effort: small

- [ ] **M-223** `[security]` `crates/cpoe/src/sentinel/app_registry.rs:1112`: atomic_write() is used for user_apps.json persistence but called from add_user_app() which may be called from multiple threads concurrently if IPC dis
  <!-- pid:concurrent_persist | first:2026-05-12 -->
  Impact: Concurrent calls to add_user_app() may interleave. Last write wins, silently losing other additions. No locking on self.user before write. | Fix: Add Mutex<AppRegistry> at caller level, or return Err if concurrent modifications are detected (version stamp in file). | Effort: medium

- [ ] **M-224** `[architecture]` `crates/cpoe/src/sentinel/app_registry.rs:1200`: AppAdapter trait is implemented inline for Scrivener, FinalDraft, Ulysses, Vellum. Each adapter is 15-20 lines. No shared base implementation or macro
  <!-- pid:adapter_boilerplate | first:2026-05-12 -->
  Impact: Boilerplate repetition. Adding a new app requires full struct + 3 impl blocks. Trait object overhead (Box<dyn>) on every adapter lookup. | Fix: Consolidate adapters into a single enum dispatch or use a macro for struct generation. Store adapters in static HashMap or match table. | Effort: medium

- [ ] **M-225** `[performance]` `crates/cpoe/src/sentinel/clipboard.rs:237`: UUID generated with uuid::Uuid::new_v4() as string on every copy event during fallback (line 236). Clipboard monitor polls every 100ms; could generate
  <!-- pid:uuid_gen_per_event | first:2026-05-12 -->
  Impact: UUID generation (RNG) is relatively expensive; fallback path called for untracked documents, could spike CPU in high-activity scenarios. | Fix: Cache or generate UUIDs at session start, not per-copy. If must generate per-copy, batch or profile impact. | Effort: small

- [ ] **M-226** `[security]` `crates/cpoe/src/sentinel/clipboard.rs:264`: EvidenceEvent broadcast channel sent without authentication verification. Any subscriber receives all clipboard evidence including AI tool pastes. No 
  <!-- pid:unauthenticated_evidence_broadcast | first:2026-05-12 -->
  Impact: Unauthorized access to clipboard evidence metadata; evidence leaked to all broadcast subscribers without permission check. No backpressure if subscrib | Fix: Only send to authenticated subscribers. Add broadcast::Sender cap and implement backpressure/drop oldest on overflow. Log broadcast errors. | Effort: medium

- [ ] **M-227** `[concurrency]` `crates/cpoe/src/sentinel/clipboard.rs:399`: RwLock read guard held across iteration and clone operations (lines 399-405). Sessions map could be modified by concurrent write during iteration.
  <!-- pid:lock_lifetime_iteration | first:2026-05-12 -->
  Impact: Potential for use-after-free if session is dropped between read_recover and clone; iterator invalidation not protected. | Fix: Collect focused IDs under lock (as done), but verify no write occurs to sessions map during evidence processing. Consider Arc<DashMap> for true lock-f | Effort: medium

- [ ] **M-228** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:86`: Sentinel struct has 30+ fields; struct is too large and combines multiple concerns: lines 100-174 define fields for sessions, cryptography, platform i
  <!-- pid:god-object | first:2026-05-12 -->
  Impact: Hard to understand the invariants. New contributors must understand all 30+ fields before modifying. Refactoring risks. Testing is hard because Sentin | Fix: Split into smaller types: SessionManager (sessions, current_focus, session_events_tx), CryptoManager (signing_key, tpm_provider, writersproof_client), | Effort: large

- [ ] **M-229** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:376`: Key validation uses all-zero check but does not validate key length: set_signing_key at line 369 checks if all bytes are 0 but does not verify the key
  <!-- pid:key-validation-incomplete | first:2026-05-12 -->
  Impact: If a non-32-byte key is somehow passed (type system should prevent, but FFI boundary is involved), all-zero check passes and key is stored, leading to | Fix: Add explicit length check: if key.to_bytes().len() != 32 { return error }. This is redundant with Ed25519 spec (always 32 bytes) but defensive for FFI | Effort: small

- [ ] **M-230** `[concurrency]` `crates/cpoe/src/sentinel/core.rs:422`: TOCTOU race in get_or_open_store: fast path checks guard.is_some() at line 425, but by the time line 426 returns, another thread could have invalidate
  <!-- pid:toctou-store-invalidation | first:2026-05-12 -->
  Impact: If signing key is updated while a thread is using the cached store, the thread continues with the old store. The HMAC key changes, so integrity checks | Fix: Re-check is_some() after acquiring the slow path lock at line 433. Current fast path is unsafe for key rotation. Or use a version number: (store, vers | Effort: small

- [ ] **M-231** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:456`: Running flag is set AFTER subsystems initialize, but no rollback on partial failure: lines 455-474 set running=true at the start, then set it to false
  <!-- pid:partial-startup-failure | first:2026-05-12 -->
  Impact: If keystroke bridge fails but mouse bridge succeeds, mouse events are captured but nobody is listening (keystroke_rx is None). Events are lost. If foc | Fix: Use a multi-phase startup: initialize all subsystems first, return on first error, then set running=true. Or implement rollback for each failed subsys | Effort: medium

- [ ] **M-232** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:554`: EventLoopCtx struct passed as-is to event loop, but many fields are Arcs that are cloned again inside loop: lines 493-550 clone Arcs, then pass to Eve
  <!-- pid:double-arc-cloning | first:2026-05-12 -->
  Impact: Each Arc clone increments reference count twice (once when creating ctx, once when using inside loop). For hundreds of Arc fields, this is CPU cache m | Fix: Reduce Arc cloning by passing references or using Arc::as_ref(). Or restructure to avoid storing Arcs in EventLoopCtx; instead, pass references to sel | Effort: large

- [ ] **M-233** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:602`: Event loop main select! block is 40+ lines. Each branch is a separate handler method, which is good, but no timeout or rate limiting on select branche
  <!-- pid:event-loop-priority | first:2026-05-12 -->
  Impact: Priority inversion: high-frequency keystroke events can starve lower-priority focus changes. If app window changes while user types very fast, the foc | Fix: Add rate limiting or priority queues: keystroke channel has buffer=1000, but focus channel may have buffer=64. Or use tokio::select! with priority: ha | Effort: small

- [ ] **M-234** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:695`: Shadowy sessions not checkpointed before stop: loop at line 718-739 iterates candidates but filters out shadow:// paths at line 698. Shadow sessions a
  <!-- pid:shadow-session-data-loss | first:2026-05-12 -->
  Impact: Shadow sessions (created for apps without file paths) lose keystroke evidence on stop. Forensic completeness is compromised. Users of shadow mode (ter | Fix: Remove the shadow:// filter at line 698 or checkpoint shadow sessions separately. Shadow sessions have no files to hash, so supply a synthetic content | Effort: medium

- [ ] **M-235** `[concurrency]` `crates/cpoe/src/sentinel/core.rs:743`: Stopping flag checked but not enforced: line 744 sets stopping=true, but in-flight spawn_blocking checkpoints may have already started. stopping_flag 
  <!-- pid:stopping-flag-not-enforced | first:2026-05-12 -->
  Impact: If a checkpoint is already running when stop() is called, and it tries to open SQLite after stopping=true is set, the checkpoint should bail (per comm | Fix: Ensure all spawn_blocking tasks check stopping_flag at critical points (before I/O, before lock acquisition). Or wait for all spawn_blocking tasks to  | Effort: medium

- [ ] **M-236** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:862`: Sorted iteration after clone+collect: line 861 collects keys, line 862 sorts them. Purpose is unclear (likely for deterministic ordering in logs), but
  <!-- pid:undocumented-sort | first:2026-05-12 -->
  Impact: Sorting sessions is O(n log n). For 100 sessions, ~664 comparisons per stop. For 10K, ~133K comparisons. Stop is not a hot path, so impact is minimal, | Fix: Document why sorting is needed (e.g., deterministic logging). If not needed, remove sort(). If needed for correctness, consider maintaining a BTreeMap | Effort: small

- [ ] **M-237** `[code_quality]` `crates/cpoe/src/sentinel/core.rs:1162`: Drop impl has polling loop with sleep: lines 1164-1170 sleep in a tight loop, checking is_finished(). Blocking behavior in Drop is problematic because
  <!-- pid:blocking-drop | first:2026-05-12 -->
  Impact: If Sentinel is dropped from within a Tokio task (rare but possible), the Drop impl's sleep loop blocks the executor, causing a panic or deadlock. Prop | Fix: Mark Sentinel as !Unpin or forbid dropping from async context with a compile-time check. Or make drop non-blocking by using a timeout. Or use Arc<Sent | Effort: medium

- [ ] **M-238** `[code_quality]` `crates/cpoe/src/sentinel/core_session.rs:129`: Session ID conversion from hex to bytes is repeated in multiple functions: lines 129-136 decode hex session_id; similar code in dictation_session_id_b
  <!-- pid:duplicated-session-id-conversion | first:2026-05-12 -->
  Impact: If hex decoding changes (e.g., stricter validation), both places must be updated. Bug fixes don't propagate automatically. Code smell. | Fix: Extract into a helper function: fn session_id_to_bytes(session_id: &str) -> [u8; 32] { ... }. Call from both places. DRY principle. | Effort: small

- [ ] **M-239** `[error_handling]` `crates/cpoe/src/sentinel/core_session.rs:144`: WAL open error handling is soft (logged as error, continues): if Wal::open fails, the session is created without WAL. Evidence chain is broken, but st
  <!-- pid:wal-failure-not-fatal | first:2026-05-12 -->
  Impact: Silent evidence loss. Session appears tracked with proof, but no WAL backing it. Checkpoints will fail to reference the WAL. Forensic chain-of-custody | Fix: Return error from start_witnessing on WAL failure, or at least set a flag on the session (e.g., session.wal_unavailable = true) so callers and checkpo | Effort: small

- [ ] **M-240** `[error_handling]` `crates/cpoe/src/sentinel/core_session.rs:146`: WAL append failure silently logged as warning: line 147 logs error but does not fail start_witnessing. Session is inserted into map (line 184) even if
  <!-- pid:wal-creation-failure-silent | first:2026-05-12 -->
  Impact: If WAL append fails (disk full, permission denied), start_witnessing succeeds but no WAL is written. Checkpoint will not have a corresponding WAL entr | Fix: Return an error from start_witnessing if WAL append fails (or at minimum, set a flag on the session indicating 'WAL-unavailable'). Or retry WAL creati | Effort: medium

- [ ] **M-241** `[error_handling]` `crates/cpoe/src/sentinel/core_session.rs:464`: Unwrap in error path: guard.as_ref().unwrap() after checking is_some() in outer pattern. Pattern is correct but uses unwrap instead of expecting compi
  <!-- pid:unnecessary-unwrap-after-guard | first:2026-05-12 -->
  Impact: Less resilient than using pattern matching. If the guard check is modified in future, the unwrap becomes a time-bomb. Non-critical but violates defens | Fix: Use pattern match: `if let Some(ref Some(store)) = store_guard { store.save_document_stats(...) }` to eliminate the unwrap. | Effort: small

- [ ] **M-242** `[code_quality]` `crates/cpoe/src/sentinel/daemon.rs:425`: setup_daemon is 77 lines with nested async block (454-481) that duplicates try-catch pattern. Error recovery logic repeated in two places (450-451, 48
  <!-- pid:duplicated_error_cleanup | first:2026-05-12 -->
  Impact: Error paths not consistent; if sentinel.start() fails, cleanup is called twice implicitly. Maintenance risk if new error handling added. | Fix: Consolidate error cleanup into single location. Use? operator in sequence rather than nested await. | Effort: small

- [ ] **M-243** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:1`: EventLoopCtx has 27 public fields; struct is too large and exposes internal state: lines 29-76 define fields used across the event loop. This is a god
  <!-- pid:god-struct | first:2026-05-12 -->
  Impact: Hard to track which methods depend on which fields. Coupling is implicit. If a field is added, all handler methods must be aware. Refactoring is risky | Fix: Split EventLoopCtx into smaller structs: SessionCtx (sessions, current_focus, targeting), TimingCtx (keystroke times, pending_downs), and ConfigCtx (c | Effort: large

- [ ] **M-244** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:88`: WritersProof client error messages logged but not surfaced to caller: lines 108-117 spawn async task that logs errors. If WritersProof service is unav
  <!-- pid:fire-and-forget-error-loss | first:2026-05-12 -->
  Impact: Silent failures in session lifecycle. User thinks their session is registered with WritersProof (for freshness nonces), but it's not. Later, checkpoin | Fix: Store WritersProof errors in session state or emit SessionEvent with error status. Or use a Result-based API instead of fire-and-forget spawn. Tradeof | Effort: medium

- [ ] **M-245** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:477`: debounce logic for content fingerprint recomputed on every focus: line 472-477 checks last_fingerprint_time, but the check is inside an if statement a
  <!-- pid:inefficient-debounce-placement | first:2026-05-12 -->
  Impact: Marginal: debounce check happens on every focus event, even if they're for different documents. For 100 documents, 100 HashMap lookups per focus event | Fix: Move debounce check inside the should_fingerprint block to avoid the HashMap.get() call on every focus. Or use a timestamp field on the session itself | Effort: small

- [ ] **M-246** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:618`: is_some_and used without explicit Some check in pending_downs HashMap: line 185 uses remove() which consumes the entry; line 192 uses .get() on the re
  <!-- pid:unbounded-map-growth | first:2026-05-12 -->
  Impact: Memory leak: pending_downs HashMap grows if dwell times are short and key repeat rate is high. After hours of typing fast, pending_downs could contain | Fix: Implement a max size check: if pending_downs.len() >= MAX (e.g., 512), clear old entries more aggressively (e.g., > 1s instead of > 10s). Or use a LRU | Effort: medium

- [ ] **M-247** `[error_handling]` `crates/cpoe/src/sentinel/event_handlers.rs:764`: Errors in focus event handling are swallowed: handle_focus_event_sync is called at line 415, but no error is checked. If it fails, the focus event is 
  <!-- pid:unhandled-event-error | first:2026-05-12 -->
  Impact: If focus monitoring fails (e.g., shadow buffer creation fails), the session is not created, but the event loop continues as if nothing happened. User  | Fix: Check return value from handle_focus_event_sync. If it returns an error, log and optionally emit SessionEvent with error status. Or propagate error to | Effort: small

- [ ] **M-248** `[error_handling]` `crates/cpoe/src/sentinel/event_handlers.rs:919`: spawn_blocking panic handling with partial rollback: line 919-926 catches panic from spawn_blocking, rolls back keystroke counter. But if the panic oc
  <!-- pid:partial-checkpoint-on-panic | first:2026-05-12 -->
  Impact: Partial checkpoints may be written to store if spawn_blocking task panics after opening store but before full completion. Rollback only resets counter | Fix: Do not roll back counter; instead, log the panic, mark session as 'checkpoint-failed', and let next tick retry. Or restructure so store writes are tra | Effort: large

- [ ] **M-249** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:1088`: Trailing argument to save_text_fragment is ecology_score (f64) but not validated: line 1092 passes ecology_score, which is read from session at line 1
  <!-- pid:unvalidated-float-values | first:2026-05-12 -->
  Impact: If session.transcription_suspicion.ecology_score is NaN, clamping to [0.0, 1.0] produces 0.0 (due to f64::EPSILON check), leading to ecology_score def | Fix: Validate ecology_score at call site: if ecology_score.is_nan() || ecology_score.is_infinite(), set to 1.0 with a warning. Or add an assertion that ses | Effort: small

- [ ] **M-250** `[code_quality]` `crates/cpoe/src/sentinel/event_handlers.rs:1159`: Unconditional write lock acquisition in post_checkpoint_work: line 1006 and 1162 acquire write locks on sessions and cached_store. If no HW co-sign is
  <!-- pid:unnecessary-lock-hold | first:2026-05-12 -->
  Impact: Lock contention: checkpoint work holds write lock even when HW co-sign path is not taken. Other threads waiting for sessions write lock (keystroke rec | Fix: Move HW co-sign block to earlier in the function, or restructure to avoid acquiring store lock if HW co-sign is not available. Use if let Some(tpm) =  | Effort: small

- [ ] **M-251** `[concurrency]` `crates/cpoe/src/sentinel/focus.rs:52`: is_stage_manager_active() uses non-atomic pattern: static AtomicBool + static AtomicU64 checked outside locks. Race condition if two threads call simu
  <!-- pid:non_atomic_cache | first:2026-05-12 -->
  Impact: Both threads may call pgrep simultaneously even if cache is fresh. Cache time check (LAST_CHECK_SECS) is non-atomic relative to CACHED update. | Fix: Use AtomicU64 for (timestamp || cached_result) packed value, or protect both statics with a single Mutex. Or use once_cell. | Effort: small

- [ ] **M-252** `[code_quality]` `crates/cpoe/src/sentinel/focus.rs:164`: Macro send_or_break! defined inside start() fn. Hides error handling in macro; readers must understand macro expansion to follow control flow.
  <!-- pid:local_macro | first:2026-05-12 -->
  Impact: Hard to debug. Stack trace on channel close doesn't show macro line. Macro is not reusable (local scope). | Fix: Extract send_or_break as inline function with Result return. Or document macro's behavior with clear comments. | Effort: small

- [ ] **M-253** `[performance]` `crates/cpoe/src/sentinel/focus.rs:191`: is_stage_manager_active() calls pgrep subprocess on every poll iteration (100ms tick). Cached for 5 seconds but still ~20 calls/second during focus po
  <!-- pid:subprocess_in_loop | first:2026-05-12 -->
  Impact: Subprocess spawn adds 5-10ms latency per poll. On M1 systems, this can dominate polling interval. Adds context-switch overhead. | Fix: Increase cache TTL to 30-60 seconds (unlikely to toggle frequently). Or detect Stage Manager via Accessibility API instead of pgrep. | Effort: medium

- [ ] **M-254** `[code_quality]` `crates/cpoe/src/sentinel/focus.rs:192`: Magic constant 30 on line 192 and 323: `Duration::from_millis(30)` for Stage Manager debounce. Appears without explanation or configurable constant.
  <!-- pid:magic_value | first:2026-05-12 -->
  Impact: Hard-coded tuning parameter. Changes require code edit + recompile. No ability to adjust via config. | Fix: Extract to const STAGE_MANAGER_DEBOUNCE_MS and document why 30ms. Consider SentinelConfig field for runtime override. | Effort: small

- [ ] **M-255** `[error_handling]` `crates/cpoe/src/sentinel/focus.rs:216`: Unsafe unwrap() on line 216 after .is_none() check: `let mut info = info.unwrap()`. Pattern is safe but unidiomatic; breaks error chain.
  <!-- pid:double_check_unwrap | first:2026-05-12 -->
  Impact: If refactored, unwrap is forgotten and panic occurs. No error message on failure. | Fix: Use `if let Some(mut info) = info { ... }` instead of unwrap. Avoids double-check antipattern. | Effort: small

- [ ] **M-256** `[performance]` `crates/cpoe/src/sentinel/focus.rs:225`: Multiple conditional String allocations: `format!("terminal.editor.{}", editor_info.editor)` inside if-branches. Allocates even if terminal detection 
  <!-- pid:conditional_allocation | first:2026-05-12 -->
  Impact: Allocates String for each poll tick regardless of whether it's a terminal. With 100ms polling = 10 allocations/sec per tracked app. | Fix: Use static or const strings for known terminal editors. Format only if app is new and terminal-detected. | Effort: small

- [ ] **M-257** `[security]` `crates/cpoe/src/sentinel/focus.rs:240`: TOCTOU on file path check: `if !p.is_absolute() || p.exists() { ... info.path = Some(file) }`. Path is checked but not locked; attacker could swap fil
  <!-- pid:toctou_file_check | first:2026-05-12 -->
  Impact: Window title reveals file path from terminal editor. If path is renamed/deleted between check and capture, captured path is invalid or exploitable. | Fix: Accept path without exists() check if already validated by terminal editor detection. Or acquire file lock before using path in evidence. | Effort: medium

- [ ] **M-258** `[error_handling]` `crates/cpoe/src/sentinel/focus.rs:358`: Silent app discovery failure: `probe_runtime_text_editing()` may return None, but no error logged. App is silently rejected without diagnostics.
  <!-- pid:silent_failure | first:2026-05-12 -->
  Impact: User app is silently filtered out without indication why. Difficult to debug missing apps. No feedback to user. | Fix: Log at info level when app is probed and rejected. Include app bundle_id and reason (no AX support, no text editing capability). | Effort: small

- [ ] **M-259** `[concurrency]` `crates/cpoe/src/sentinel/focus.rs:398`: lock_recover() called on Mutex<Option<...>> instead of standard .lock() pattern. Hides error handling and recovery semantics.
  <!-- pid:unclear_lock_semantics | first:2026-05-12 -->
  Impact: Unclear whether panic recovery is intentional. If lock is poisoned, behavior is non-obvious to readers. Missing error context. | Fix: Document why MutexRecover is used. Consider explicit lock().unwrap_err() handler with clear logging. Or add comments explaining panic safety. | Effort: small

- [ ] **M-260** `[architecture]` `crates/cpoe/src/sentinel/helpers.rs:1`: Huge 3258-line helpers.rs file mixing concerns: event handlers, file I/O, payload creation, git integration, third-party app parsing
  <!-- pid:architecture_god_module | first:2026-05-12 -->
  Impact: Difficult to navigate, HIGH_CHURN (2585 changes/6mo). Concerns: focus/change handlers, WAL buffering, session management, Scrivener/Word/DOCX parsing, | Fix: Split into submodules: session_handlers.rs (focus/change/idle), payload.rs (create_*_payload), file_utils.rs (hash, encoding, word_count), app_integra | Effort: large

- [ ] **M-261** `[performance]` `crates/cpoe/src/sentinel/helpers.rs:78`: focus.clone() on String inside read lock, pattern repeated 4+ times (lines 78, 112, 148, 215)
  <!-- pid:performance_multiple_string_clones | first:2026-05-12 -->
  Impact: Low: String clones on control-flow paths, not in keystroke counting loop. Acceptable overhead for clarity. But pattern could be optimized with cloned_ | Fix: Use focus.as_ref().cloned() or extract once before branching to avoid multiple clones. | Effort: small

- [ ] **M-262** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:128`: event.path.clone() followed by event.app_name.clone() and event.app_bundle_id.clone()—multiple clones from FocusEvent
  <!-- pid:maintainability_repeated_event_clones | first:2026-05-12 -->
  Impact: FocusEvent fields cloned 3 times when building FocusSwitchRecord (lines 171-172). Low overhead but pattern repeated in multiple branches. | Fix: Extract clones once: let (app_name, bundle_id) = (event.app_name.clone(), event.app_bundle_id.clone()) to reduce duplication. | Effort: small

- [ ] **M-263** `[error_handling]` `crates/cpoe/src/sentinel/helpers.rs:175`: let _ = session_events_tx.send(...) silently discards broadcast send errors
  <!-- pid:error_handling_silent_broadcast_discard | first:2026-05-12 -->
  Impact: Documented intent at line 373: 'broadcast send fails only when no receivers subscribed'. Low risk—fire-and-forget pattern is intentional for event bro | Fix: Add explicit comment if not already present explaining why error is ignored (already at line 373). | Effort: small

- [ ] **M-264** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:232`: MAX_HASH_FILE_SIZE = 10MB constant—document rationale for balance between coverage and lock duration
  <!-- pid:code_quality_max_hash_size_comment | first:2026-05-12 -->
  Impact: Files >10MB skip hashing during focus to avoid blocking sessions write lock. Balances accuracy vs. responsiveness. Reasonable heuristic. | Fix: Add comment: '// Skip hashing large files to avoid blocking keystroke capture. Heuristic: assume large files are unlikely authorship targets.'. | Effort: small

- [ ] **M-265** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:233`: NON_DOCUMENT_EXTENSIONS constant not easily extensible—hardcoded in CLAUSE.md as policy
  <!-- pid:code_quality_document_extension_list | first:2026-05-12 -->
  Impact: Extensions (video, audio, binaries, archives) are filtered out. Hardcoded list. Acceptable but could be config-driven. | Fix: No fix needed unless config-driven filtering is desired. Current hardcoding is reasonable for security (prevent tracking binaries). | Effort: small

- [ ] **M-266** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:422`: Function unfocus_document_sync missing documentation—public but straightforward
  <!-- pid:maintainability_missing_focus_loss_docs | first:2026-05-12 -->
  Impact: Public API for focus loss handling. No docs on event broadcast, lock scope, or when called. | Fix: Add /// doc: 'Mark session unfocused. Broadcasts SessionEvent::Unfocused. Called on FocusLost or app block.'. | Effort: small

- [ ] **M-267** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:662`: Function check_idle_sessions_sync missing documentation—public session lifecycle management
  <!-- pid:maintainability_missing_session_mgmt_docs | first:2026-05-12 -->
  Impact: Public API for idle timeout detection. No docs on idle_timeout semantics, event broadcast, or when called. | Fix: Add /// docs: 'End sessions idle > timeout. Broadcasts SessionEvent::Ended for each. Called periodically from sentinel loop.'. | Effort: small

- [ ] **M-268** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:688`: Function end_session_sync missing documentation—public, simple session removal
  <!-- pid:maintainability_missing_cleanup_docs | first:2026-05-12 -->
  Impact: Public API for session cleanup. No docs on side effects (event broadcast, shadow cleanup elsewhere). | Fix: Add /// docs: 'Remove session from map. Broadcasts SessionEvent::Ended. Shadow buffer cleanup handled in end_all_sessions_sync.'. | Effort: small

- [ ] **M-269** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:707`: Function end_all_sessions_sync missing documentation—public, shutdown cleanup
  <!-- pid:maintainability_missing_shutdown_docs | first:2026-05-12 -->
  Impact: Public API for graceful shutdown. No docs on ordering: sessions drained, broadcast sent, shadow cleanup attempted. | Fix: Add /// docs: 'Drain all sessions. Broadcast Ended for each. Cleanup shadow buffers (errors logged). Called on sentinel stop.'. | Effort: small

- [ ] **M-270** `[concurrency]` `crates/cpoe/src/sentinel/helpers.rs:744`: static PENDING_WAL: Mutex<Vec<PendingWalEntry>> initialized as static—correct but global mutable state
  <!-- pid:concurrency_static_mutex_intentional | first:2026-05-12 -->
  Impact: Global mutable state is intentional for buffering WAL entries before signing key is available. Guarded by Mutex + lock_recover(). Acceptable for senti | Fix: No fix needed. Pattern is correct. Comment already at line 746 explains purpose: 'Drain any buffered WAL entries now that a signing key is available'. | Effort: small

- [ ] **M-271** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:844`: Hardcoded temp prefixes array TEMP_PREFIXES—macOS-specific, list could grow
  <!-- pid:maintainability_hardcoded_macos_paths | first:2026-05-12 -->
  Impact: Intentional for macOS. Linux would need different paths (not in scope—see CLAUDE.md platform separation). Acceptable hardcoding. | Fix: No fix needed. Add comment: '// macOS-specific temp locations. Linux equivalents in platform/linux.rs'. | Effort: small

- [ ] **M-272** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:920`: Function compute_file_hash missing documentation—public, but simple
  <!-- pid:maintainability_missing_simple_pub_docs | first:2026-05-12 -->
  Impact: Public API but straightforward. Lack of docs on hash algorithm, error types, or file size limits. | Fix: Add single-line /// doc: 'Hash file contents using SHA-256. Returns hex-encoded hash. Follows symlinks.'. | Effort: small

- [ ] **M-273** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:979`: Function create_session_start_payload missing documentation—public, binary protocol function
  <!-- pid:maintainability_missing_protocol_pub_docs | first:2026-05-12 -->
  Impact: Public API for session event serialization. No docs on format, endianness, or payload structure. | Fix: Add /// docs: 'Serialize session fields into CBOR payload. Fields: path, bundle, app, title, hash, timestamp (big-endian u64)'. | Effort: small

- [ ] **M-274** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1019`: i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)—fallback to MAX for timestamp overflow
  <!-- pid:code_quality_timestamp_overflow_sentinel | first:2026-05-12 -->
  Impact: Same pattern as line 1568. Defensive against timestamp overflow. Acceptable sentinel value. | Fix: No fix needed. Pattern is consistent and intentional. | Effort: small

- [ ] **M-275** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1026`: Function create_document_hash_payload missing documentation—public Result-returning function
  <!-- pid:maintainability_missing_result_pub_docs | first:2026-05-12 -->
  Impact: Public Result API, callers need to understand error cases (invalid hex, wrong size, negative size). | Fix: Add /// docs: 'Create hash payload. Returns Err if hash not 32 hex bytes or size < 0. Payload: [hash (32) | size (8) | timestamp (8)] big-endian'. | Effort: small

- [ ] **M-276** `[security]` `crates/cpoe/src/sentinel/helpers.rs:1061`: Path symlink check does not follow symlinks—defensive against symlink-following TOCTOU but open_nofollow also performs check
  <!-- pid:security_symlink_defense_depth | first:2026-05-12 -->
  Impact: Defensive design: symlink_metadata + is_symlink check, then open_nofollow(). Two-layer defense is good. But comment at line 1056 mentions 'traversal a | Fix: No fix needed; defense in depth is correct. Add comment: '// Defense in depth: reject symlinks early + open_nofollow guards TOCTOU'. | Effort: small

- [ ] **M-277** `[security]` `crates/cpoe/src/sentinel/helpers.rs:1100`: Path validation delegates to crate::ipc::messages::is_blocked_system_path()—trust boundary unclear
  <!-- pid:security_path_validation_delegation | first:2026-05-12 -->
  Impact: Validation function is internal (not public boundary). But high-trust callers in sentinel subsystem. Assumption: is_blocked_system_path is well-vetted | Fix: No fix needed if is_blocked_system_path is security-critical. Ensure it checks /System, /usr, /private/etc, /root, etc. | Effort: small

- [ ] **M-278** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1171`: Err(_) => {} empty match arm at line 1171—silently discards tpm.sign() error
  <!-- pid:code_quality_silent_error_arm | first:2026-05-12 -->
  Impact: Context: try_hw_cosign function, hardware co-sign failure is non-fatal. Reset scheduler and return false. Acceptable for optional feature. But could l | Fix: Add log::warn!('HW co-sign failed: {e}') before reset_after_cosign(). | Effort: small

- [ ] **M-279** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1237`: 500ms keystroke silence threshold for paste detection—magic value
  <!-- pid:code_quality_paste_silence_threshold_comment | first:2026-05-12 -->
  Impact: Signal 1: keystroke gap >500ms suggests paste. Heuristic threshold. Reasonable but could be configurable. | Fix: Add comment: '// Heuristic: >500ms keystroke gap suggests paste (user paused or pasted external content).'. | Effort: small

- [ ] **M-280** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1240`: Paste detection confidence values hardcoded (0.99, 0.92, 0.85, 0.70, 0.60, 0.20)—magic values
  <!-- pid:code_quality_paste_confidence_magic_values | first:2026-05-12 -->
  Impact: 3/3 signals: 0.99, 2/3: 0.92/0.85, 1/3: 0.70/0.60, 0/3: 0.20. Heuristic confidence scores. Reasonable defaults. | Fix: Document rationale in /// docs. Add comment: '// Confidence is Bayesian prior: 3 signals → 99%, 2 signals → 85-92%, etc.'. | Effort: small

- [ ] **M-281** `[performance]` `crates/cpoe/src/sentinel/helpers.rs:1402`: Thread spawn with bounded wait loop using sleep(50ms)—polling instead of channel
  <!-- pid:performance_polling_wait | first:2026-05-12 -->
  Impact: Git context capture thread spawned on each checkpoint (potentially frequent). Polling with 50ms sleeps until deadline or completion. Acceptable for ba | Fix: Consider tokio::task::spawn_blocking + timeout instead of std::thread::spawn + sleep loop. Would integrate better with tokio runtime. | Effort: medium

- [ ] **M-282** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:1409`: GIT_COMMAND_TIMEOUT used three times (lines 1409, 1420, 1439, 1449, 1459)—could extract deadline computation
  <!-- pid:maintainability_repeated_timeout_checks | first:2026-05-12 -->
  Impact: Deadline checked 5+ times in same function. Acceptable pattern, but could extract `let deadline = Instant::now() + GIT_COMMAND_TIMEOUT;` once. | Fix: Extract deadline once at top of poll loop. Current pattern is clear enough. | Effort: small

- [ ] **M-283** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1414`: Err(_) => {} empty match arm at line 1414—silent handle_join error in git context capture
  <!-- pid:code_quality_thread_panic_logged | first:2026-05-12 -->
  Impact: Context: thread::join() error indicates thread panicked. Orphaned thread. Error already logged at line 1415. Pattern OK. | Fix: No fix needed; error is logged at line 1415. | Effort: small

- [ ] **M-284** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1424`: sleep(50ms) hardcoded in git context capture loop—magic value
  <!-- pid:code_quality_magic_value_sleep_duration | first:2026-05-12 -->
  Impact: Polling interval of 50ms. Acceptable for background operation. But could be constant. | Fix: Add const GIT_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50); at top of function or module. | Effort: small

- [ ] **M-285** `[error_handling]` `crates/cpoe/src/sentinel/helpers.rs:1549`: open_nofollow(path) error at line 1549 logged as debug, not propagated—silent skip in checkpoint
  <!-- pid:error_handling_checkpoint_silent_skip | first:2026-05-12 -->
  Impact: Context: commit_checkpoint_for_path. If file open fails, checkpoint is skipped. Acceptable—file may be deleted mid-checkpoint. But loss of evidence ch | Fix: Acceptable as-is (file deletion is expected). Add comment: '// File may be deleted after focus; skip checkpoint silently.'. | Effort: small

- [ ] **M-286** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1568`: i64::try_from(raw_size).unwrap_or(i64::MAX)—fallback to MAX for huge files
  <!-- pid:code_quality_overflow_sentinel | first:2026-05-12 -->
  Impact: Defensive: file size overflow. i64::MAX == 9.2EB, acceptable sentinel for huge files. Intentional handling. | Fix: No fix needed. Fallback is intentional. Could add comment: '// Overflow OK: sentinel value for huge files'. | Effort: small

- [ ] **M-287** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1647`: SAVE_AS_TIME_WINDOW_SECS constant—magic value for save-as detection window
  <!-- pid:code_quality_save_as_time_window_comment | first:2026-05-12 -->
  Impact: Detects save-as if file with same hash created within time window of focus loss. Acceptable heuristic, but magic value. | Fix: Add comment: '// Save-as window: if output file created within N seconds of session focus loss, assume user is exporting/saving-as.'. | Effort: small

- [ ] **M-288** `[error_handling]` `crates/cpoe/src/sentinel/helpers.rs:1667`: .unwrap_or('') on path.to_str()—silent conversion to empty string if path not UTF-8
  <!-- pid:error_handling_to_str_unwrap | first:2026-05-12 -->
  Impact: Low: passed to open_nofollow which returns Err on failure. Empty string triggers error path. But masking intent. | Fix: Use .ok_or_else(|| FileEncoding::Unknown)? and early return, or add explicit check with log. | Effort: small

- [ ] **M-289** `[error_handling]` `crates/cpoe/src/sentinel/helpers.rs:1709`: .unwrap_or('') on path.to_str() second invocation—duplicate call in same function
  <!-- pid:error_handling_duplicate_to_str_unwrap | first:2026-05-12 -->
  Impact: Low: duplicate defensive call. Redundant pattern already checked at line 1667. | Fix: Cache result from line 1667, reuse at line 1709. Eliminate second call. | Effort: small

- [ ] **M-290** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1717`: reader.read(&mut sample).unwrap_or(0)—unwrap_or on BufReader read operation
  <!-- pid:code_quality_bufio_read_fallback | first:2026-05-12 -->
  Impact: Low: fallback to 0 bytes read on I/O error. Safe because empty sample triggers ASCII check at line 1719. But could be more explicit. | Fix: Use `.ok().unwrap_or(0)` or `.unwrap_or_else(|e| { log::debug!(...); 0 })` for clarity. | Effort: small

- [ ] **M-291** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:1817`: find_binder_item_title() uses string scanning instead of XML parser—brittle to XML variants
  <!-- pid:code_quality_fragile_string_xml_parsing | first:2026-05-12 -->
  Impact: Avoids dependency on xml crate. Uses simple string scanning: `find("<BinderItem")` and pattern matching. Acceptable for Scrivener's fixed format, but  | Fix: Add comment: '// XML string scanning avoids dependency. Scrivener .scrivx format is stable (2.9+). If format breaks, add xml dependency or request Scr | Effort: small

- [ ] **M-292** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:1948`: SKIP_GROUPS array in strip_rtf() contains hardcoded RTF control group names—brittle to RTF spec changes
  <!-- pid:maintainability_hardcoded_rtf_groups | first:2026-05-12 -->
  Impact: Hardcoded list: 'fonttbl', 'colortbl', 'stylesheet', etc. If RTF spec adds new skip groups, code breaks. But list is correct for common RTF versions. | Fix: Add comment: '// RTF control groups to skip. See RFC 1006 for RTF specification.' Consider version parameter if needed. | Effort: small

- [ ] **M-293** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:2014`: String::from_utf8() into Ok/Err without mapping—converts Result<Vec, FromUtf8Error> -> Result<String, ()>
  <!-- pid:code_quality_utf8_error_discarded | first:2026-05-12 -->
  Impact: read_docx_entry uses String::from_utf8()?.ok(), discarding FromUtf8Error details. Acceptable for word count extraction (non-critical), but could log e | Fix: Use `.context('Invalid UTF-8 in docx XML')` if using anyhow, or log::debug!() on error. | Effort: small

- [ ] **M-294** `[architecture]` `crates/cpoe/src/sentinel/helpers.rs:2023`: has_track_changes() checks .docx files for revision markers—business logic in helpers
  <!-- pid:architecture_feature_detection_location | first:2026-05-12 -->
  Impact: Reasonable location in file. Used in checkpoint logic to tag evidence. But could move to forensics/ or evidence/ module if separation desired. | Fix: No fix needed; location is acceptable. Consider moving to forensics or evidence module if track-changes becomes shared. | Effort: medium

- [ ] **M-295** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:2037`: SKIP_GROUPS constant defined inside strip_rtf()—could be module-level const
  <!-- pid:maintainability_local_const_candidate | first:2026-05-12 -->
  Impact: RTF control groups to skip. Currently const at line 1948. Defined locally for function clarity, but could be module const for reuse. | Fix: Move SKIP_GROUPS to module level (above function). Would allow reuse if word count parsing needs same list. | Effort: small

- [ ] **M-296** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:2042`: MAX_SEGMENT_ENTRIES = 10,000 constant—document rationale
  <!-- pid:code_quality_undocumented_constant | first:2026-05-12 -->
  Impact: Limits bundle document segment tracking. 10k seems reasonable for large Scrivener projects, but rationale not documented. | Fix: Add comment: '// Limit segments per bundle to prevent unbounded memory growth. Typical .scriv projects <1k items.'. | Effort: small

- [ ] **M-297** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:2046`: EXPORT_CORRELATION_WINDOW_NS = 30s hardcoded—magic value for export timing
  <!-- pid:code_quality_magic_time_window | first:2026-05-12 -->
  Impact: Correlates bundle session with output file creation within 30s. Reasonable heuristic, but magic value. | Fix: Add comment: '// Heuristic: if export file created within 30s of bundle session, assume direct compile/export.'. | Effort: small

- [ ] **M-298** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:2049`: EXPORT_EXTENSIONS array hardcoded—could grow as export formats evolve
  <!-- pid:code_quality_extension_list_comment | first:2026-05-12 -->
  Impact: docx, pdf, epub, rtf, odt. Covers common formats. Could be extended. | Fix: Add comment: '// Common manuscript export formats. Extend if new formats emerge (e.g., mobi, azw3).'. | Effort: small

- [ ] **M-299** `[performance]` `crates/cpoe/src/sentinel/helpers.rs:2066`: HashMap::new() in parse_scrivener_project_map function—while loop appends, no capacity hint
  <!-- pid:performance_hashmap_no_capacity_hint | first:2026-05-12 -->
  Impact: Parsing `.scrivx` XML, typically <100 binder items. HashMap grows smoothly. Low impact but could hint with_capacity(expected_items). | Fix: Use HashMap::with_capacity(estimate) if typical .scriv projects have known item counts. | Effort: small

- [ ] **M-300** `[maintainability]` `crates/cpoe/src/sentinel/helpers.rs:2079`: format!() inside find_binder_item_title loop for two quote character patterns—inefficient ID search
  <!-- pid:maintainability_format_in_loop | first:2026-05-12 -->
  Impact: Generates 'ID="<uuid>"' and 'ID=\'<uuid>\'' format strings on every BinderItem. Typically <100 items, acceptable. But could pre-format patterns. | Fix: Pre-compute pattern strings outside loop: `let patterns = [format!("ID=\"{}\"", target_id), format!("ID='{}'", target_id)];` outside loop at line 2069 | Effort: small

- [ ] **M-301** `[code_quality]` `crates/cpoe/src/sentinel/helpers.rs:2081`: String slicing pattern without bounds checking: after[..end].to_string() at line 2081
  <!-- pid:code_quality_string_slicing_bounds | first:2026-05-12 -->
  Impact: Low risk: bounds checked by find() and indexing. But pattern is fragile: `after_tag[content_start..content_start + title_end]` assumes content_start + | Fix: Use substring operations with Result handling or add explicit bounds comment: '// Safe: content_start + title_end derived from find() and split positi | Effort: small

- [ ] **M-302** `[performance]` `crates/cpoe/src/sentinel/helpers.rs:2273`: Vec::new() in close to conditional branch in extract_word_count_plaintext—collect() converts iterator
  <!-- pid:performance_word_count_is_correct | first:2026-05-12 -->
  Impact: Low: word counting on file focus, not per-keystroke. String::split_whitespace() is lazy; count() doesn't allocate. | Fix: No change needed; split_whitespace().count() doesn't allocate. Pattern is correct. | Effort: small

- [ ] **M-303** `[error_handling]` `crates/cpoe/src/sentinel/helpers.rs:2612`: .unwrap() on Option returned from is_some() assertion—test assumes Result from detect_save_as is Some
  <!-- pid:error_handling_unwrap_after_test_assert | first:2026-05-12 -->
  Impact: Test code, safe because assert!(result.is_some()) at line 2611 guarantees Some. But pattern should match across test suite. | Fix: Use .expect('save_as detection should succeed') for clarity or remove redundant assertion. | Effort: small

- [ ] **M-304** `[error_handling]` `crates/cpoe/src/sentinel/ipc_handler.rs:35`: open_db() returns generic error message 'Signing key not initialized (or locked)' - cannot distinguish actual initialization failure from poison panic
  <!-- pid:ambiguous_db_error | first:2026-05-12 -->
  Impact: Operator cannot diagnose whether signing key is uninitialized or RwLock was poisoned (process corruption) | Fix: Log poison state separately; return different error codes for init-vs-poison states. | Effort: small

- [ ] **M-305** `[security]` `crates/cpoe/src/sentinel/ipc_handler.rs:127`: Magic constant MAX_EVIDENCE_FILE_SIZE (10MB) defined twice (lines 127, 271). Inconsistent limits create maintenance risk.
  <!-- pid:magic_value_duplication | first:2026-05-12 -->
  Impact: Limits may diverge, causing verification logic to reject valid evidence files | Fix: Extract constant to module level: const MAX_EVIDENCE_FILE_SIZE: u64 = 10 * 1024 * 1024; | Effort: small

- [ ] **M-306** `[performance]` `crates/cpoe/src/sentinel/ipc_handler.rs:217`: Multiple to_string_lossy().to_string() allocations in hot path (lines 217, 322, 383). Each path argument creates temporary String.
  <!-- pid:string_alloc_hot_path | first:2026-05-12 -->
  Impact: Unnecessary allocations in per-message IPC handler. At scale (many files tracked), contributes to GC pressure. | Fix: Use &str slices where possible; defer to_string only for output fields. Store path as OsStr internally. | Effort: medium

- [ ] **M-307** `[concurrency]` `crates/cpoe/src/sentinel/ipc_handler.rs:219`: sessions RwLock read guard acquired (line 219), data cloned (lines 224-225), but no guarantee jitter_samples remain valid until use. Entangled mode co
  <!-- pid:session_data_race | first:2026-05-12 -->
  Impact: Race: session may be cleared by another task between read and commit; jitter data becomes stale, affecting evidence integrity. | Fix: Commit checkpoint while holding session lock, or use Arc<Session> to extend data lifetime beyond lock release. | Effort: medium

- [ ] **M-308** `[code_quality]` `crates/cpoe/src/sentinel/ipc_handler.rs:300`: handle_export_file is 242 lines (300-542). Exceeds 100-line guideline; combines path validation, chain loading, signing, evidence building, and file I
  <!-- pid:oversized_handler | first:2026-05-12 -->
  Impact: Function is difficult to unit test; error handling is diffuse across multiple blocks. Hard to follow control flow for security review. | Fix: Extract sub-functions: load_and_verify_chain, prepare_evidence_builder, write_evidence_atomically. Test each independently. | Effort: medium

- [ ] **M-309** `[code_quality]` `crates/cpoe/src/sentinel/macos_focus.rs:523`: ax_observer_run_loop is 144 lines (523-666) with complex unsafe blocks, teardown closures, and mutable state. No extracted helper for observer lifecyc
  <!-- pid:unsafe_run_loop_size | first:2026-05-12 -->
  Impact: Difficult to audit unsafe operations; teardown closure with multiple pointer mutations is error-prone. State transitions (PID changes) not clearly del | Fix: Extract teardown as standalone function. Create ObserverState struct to encapsulate current_observer, current_app_element, current_refcon mutations. | Effort: medium

- [ ] **M-310** `[concurrency]` `crates/cpoe/src/sentinel/macos_focus.rs:593`: AXObserver refcon Box leaked into unsafe closure (line 593: Box::into_raw). Reclaimed in teardown (line 566) but no synchronization. If teardown calle
  <!-- pid:unsafe_refcon_uaf | first:2026-05-12 -->
  Impact: Memory safety: callback could dereference freed memory if observer teardown and callback race. Objective-C runtime may invoke callback after teardown  | Fix: Use Arc-wrapped RefCell or mutex to protect refcon state. Ensure callback checks if observer is still active before dereferencing. | Effort: large

- [ ] **M-311** `[architecture]` `crates/cpoe/src/sentinel/types.rs:686`: DocumentSession struct is large (87 lines) with 30+ fields. Includes diverse concerns: jitter sampling, AI tool detection, dictation, clipboard, segme
  <!-- pid:god_struct | first:2026-05-12 -->
  Impact: Hard to evolve. Cloning is expensive (45 fields cloned in manual Clone impl). Difficult to reason about invariants across all fields. | Fix: Split into logical sub-structs: SessionMetadata, SessionTimingState, SessionCapture (jitter/keystroke), SessionIntelligence (AI/dictation/clipboard).  | Effort: large

- [ ] **M-312** `[code_quality]` `crates/cpoe/src/sentinel/types.rs:1423`: looks_like_file_path() and looks_like_document_name() are private helper functions (lines 1423, 1455) with no unit tests. Heuristics are hardcoded and
  <!-- pid:untested_helpers | first:2026-05-12 -->
  Impact: Title inference accuracy depends on untested heuristics. Edge cases (paths with spaces, unicode, dots in names) are not validated. | Fix: Expose helper fns as pub #[cfg(test)] or add dedicated test module. Test with real window titles from popular apps (Obsidian, Bear, etc.). | Effort: medium

- [ ] **M-313** `[code_quality]` `crates/cpoe/src/sentinel/types.rs:1456`: looks_like_document_name() is called with hard-coded SKIP_TITLE_FRAGMENTS list ("untitled", "settings", etc.) matching exact case-insensitive. Couplin
  <!-- pid:hardcoded_parser_rules | first:2026-05-12 -->
  Impact: Hard to maintain list. No way to extend per-app. False positives (e.g., app named "Settings" legit note-taking app). | Fix: Make SKIP_TITLE_FRAGMENTS a method on TitleParserVariant or AppRegistry. Allow per-app overrides. | Effort: medium

- [ ] **M-314** `[error_handling]` `crates/cpoe/src/sentinel/types.rs:1509`: canonicalize() is called on path that may not exist. Path is validated for traversal first, but canonicalize() returns Err if parent dir doesn't exist
  <!-- pid:canonicalize_missing_path | first:2026-05-12 -->
  Impact: Function silently returns None for valid relative paths when cwd is not accessible. Inferred document names from window titles are lost. | Fix: Use std::fs::canonicalize() only for absolute paths or when file exists. For relative paths, use std::path::Path::normalize() or similar, validate sep | Effort: small

- [ ] **M-315** `[error_handling]` `crates/cpoe/src/store/access_log.rs:150`: Migration for hmac column at line 150 silently ignores the result of query_map(). If the column name lookup fails, the error is swallowed by .any().
  <!-- pid:SILENT_ERROR_004 | first:2026-05-12 -->
  Impact: If PRAGMA table_info returns unexpected schema, the migration may not detect missing column and later HMAC operations could fail. | Fix: Explicitly check the result: let found = stmt.query_map(...)?. all(|r| ...); to propagate schema errors. | Effort: small

- [ ] **M-316** `[error_handling]` `crates/cpoe/src/store/access_log.rs:369`: expect() on line 369 during HMAC key initialization. Documented as infallible, but provides no context if it ever fails in practice.
  <!-- pid:EXPECT_INFALLIBLE_001 | first:2026-05-12 -->
  Impact: Panic without diagnostics if HMAC initialization fails; no way to distinguish key corruption from other runtime errors. | Fix: Change to: HmacSha256::new_from_slice(key).map_err(|e| anyhow!("HMAC init failed: {}", e))? | Effort: small

- [ ] **M-317** `[error_handling]` `crates/cpoe/src/store/archive.rs:307`: Failure during atomic_result is caught but tmp file cleanup on line 308 swallows errors (let _). If remove_file fails, the error is silently lost.
  <!-- pid:SILENT_ERROR_003 | first:2026-05-12 -->
  Impact: Stale tmp files accumulate if cleanup fails (e.g., permission denied); disk space leaks and retries fail. | Fix: Log the cleanup error: if let Err(e) = std::fs::remove_file(...) { log::warn!("Failed to clean up tmp archive: {}", e); } | Effort: small

- [ ] **M-318** `[error_handling]` `crates/cpoe/src/store/archive.rs:315`: New archive connection opened on line 315 without explicit close. If pragma execution fails, connection is never dropped properly (though Rust auto-dr
  <!-- pid:RESOURCE_LEAK_001 | first:2026-05-12 -->
  Impact: Archive pragma settings may not be fully applied if connection panics during checkpoint. | Fix: Wrap in explicit drop or use block scope: { let archive_conn = ...; archive_conn.execute_batch(...)?; } | Effort: small

- [ ] **M-319** `[security]` `crates/cpoe/src/store/archive.rs:332`: Archive file permissions set to 0o444 (read-only) at line 332 but only on Unix. No equivalent on Windows; Windows archives could be modified post-crea
  <!-- pid:PLATFORM_DIVERGENCE_001 | first:2026-05-12 -->
  Impact: Platform divergence: Windows archives are writable by default, breaking read-only archive invariant. | Fix: Add Windows equivalent using std::fs::set_permissions or FileOptions::access_mode; or document that archives are platform-specific. | Effort: medium

- [ ] **M-320** `[performance]` `crates/cpoe/src/store/archive.rs:535`: query_spanning() loads all archive files, queries each one individually for overlapping date ranges, then queries active DB, then sorts by timestamp. 
  <!-- pid:N_PLUS_1_QUERY_001 | first:2026-05-12 -->
  Impact: Multiple database opens and full table scans for date range queries spanning archives. Inefficient for large archive sets. | Fix: Precompute archive date ranges and query only overlapping archives; use prepared statement cache. | Effort: large

- [ ] **M-321** `[security]` `crates/cpoe/src/store/events.rs:156`: get_events_for_file_in_range() is public and queries by file_path parameter directly. No validation that caller is authorized to read this file's even
  <!-- pid:AUTHZ_CHECK_MISSING_001 | first:2026-05-12 -->
  Impact: Any code holding a SecureStore reference can read any file's events without additional authorization check. If store is shared across multiple users,  | Fix: Add authorization check or clarify in docs that SecureStore access must be guarded by caller. Consider adding an audit log entry for DSAR/export queri | Effort: medium

- [ ] **M-322** `[security]` `crates/cpoe/src/store/events.rs:504`: update_file_path() at line 504 explicitly bails if integrity has verified events (lines 512-524), but this check is based on event_count > 0. A store 
  <!-- pid:PATH_UPDATE_SAFETY_001 | first:2026-05-12 -->
  Impact: If integrity record is corrupted, file_path mutation could break HMAC verification (file_path is part of HMAC payload) without detection until next ve | Fix: Add a more robust check: if any event's HMAC has been verified (last_verified_sequence > 0), reject the operation. Or forbid path updates entirely pos | Effort: medium

- [ ] **M-323** `[performance]` `crates/cpoe/src/store/events.rs:631`: Subquery in update_hw_cosign() at line 631: SELECT id FROM secure_events WHERE file_path = ?8 ORDER BY id DESC LIMIT 1. This subquery runs for every h
  <!-- pid:MISSING_INDEX_001 | first:2026-05-12 -->
  Impact: O(n) table scan per hardware co-sign update if index on file_path is not covering. | Fix: Ensure index idx_secure_events_file covers (file_path, id) or change query to SELECT MAX(id) FROM secure_events WHERE file_path = ?8. | Effort: small

- [ ] **M-324** `[performance]` `crates/cpoe/src/store/integrity.rs:204`: Migration check for has_column at line 204 runs every time init_schema() is called (which is on every SecureStore::open()). This does a PRAGMA table_i
  <!-- pid:REPEATED_MIGRATION_001 | first:2026-05-12 -->
  Impact: Extra PRAGMA query on every store open, even if columns already exist. Adds latency to launch sequence. | Fix: Cache migration state in a flag file or add 'migrations_applied' table to track completed migrations once. | Effort: medium

- [ ] **M-325** `[concurrency]` `crates/cpoe/src/store/mod.rs:69`: SQLite PRAGMA busy_timeout is set to 5000ms (line 69) but multiple Connections can be opened to the same WAL database. No explicit connection pooling 
  <!-- pid:SQLITE_CONTENTION_001 | first:2026-05-12 -->
  Impact: If multiple threads call SecureStore methods in parallel, write contention causes repeated busy waits. WAL mode helps but doesn't eliminate blocking u | Fix: Use rusqlite::OptionalExtension and explicit transaction scheduling; consider single writer pattern or connection pool with bounded wait. | Effort: large

- [ ] **M-326** `[error_handling]` `crates/cpoe/src/tpm/linux.rs:90`: try_init returns None if AK creation fails. No detail logged about failure. Silent fallback to software.
  <!-- pid:TPM-028 | first:2026-05-12 -->
  Impact: If AK creation fails for recoverable reason (e.g., TPM busy), fallback is silent and might not be retried. | Fix: Log error details before returning None; allow caller to distinguish temporary vs permanent failures. | Effort: minimal

- [ ] **M-327** `[security]` `crates/cpoe/src/tpm/linux.rs:320`: Log message reveals TPM handle leak on flush failure after seal. Logs go to files/syslog.
  <!-- pid:TPM-009 | first:2026-05-12 -->
  Impact: Information disclosure: reveals internal TPM state/error details in logs. Attacker could infer TPM issues. | Fix: Use generic error message without 'leak' indicator or remove from public logs. | Effort: minimal

- [ ] **M-328** `[code_quality]` `crates/cpoe/src/tpm/linux.rs:518`: format_device_id caches device ID in mutable state. Subsequent calls return clone of cached value.
  <!-- pid:TPM-010 | first:2026-05-12 -->
  Impact: Device ID computed once; ok for stable TPM but no validation that cached value matches current TPM state. | Fix: Add comment documenting assumption that TPM is immutable during session. | Effort: minimal

- [ ] **M-329** `[security]` `crates/cpoe/src/tpm/mod.rs:104`: generate_attestation_report constructs quote_payload with verifier_nonce || attestation_nonce || evidence_hash. No length fields.
  <!-- pid:TPM-026 | first:2026-05-12 -->
  Impact: Variable-length nonces could be misaligned during deserialization. Attacker could craft ambiguous payloads. | Fix: Add length fields: [verifier_len:2][verifier][attest_len:2][attestation][hash] | Effort: medium

- [ ] **M-330** `[code_quality]` `crates/cpoe/src/tpm/mod.rs:150`: increment_session_counter returns clock.clock as u64 counter. Doesn't actually increment; just returns current value.
  <!-- pid:TPM-025 | first:2026-05-12 -->
  Impact: Confusing function name suggests incrementing but just returns snapshot of clock. | Fix: Rename to get_session_counter or document that it returns clock time, not incremented counter. | Effort: minimal

- [ ] **M-331** `[code_quality]` `crates/cpoe/src/tpm/mod.rs:200`: detect_provider() detects best provider but log message only says 'no hardware TPM' on fallback. Doesn't log why detection failed.
  <!-- pid:TPM-033 | first:2026-05-12 -->
  Impact: User doesn't know if Secure Enclave/TPM was unavailable or failed to initialize. | Fix: Log reason for each provider's failure before trying next. | Effort: low

- [ ] **M-332** `[security]` `crates/cpoe/src/tpm/secure_enclave/attestation.rs:83`: verify_key_attestation reconstructs expected data on current device. Only verifies local consistency, not remote attestation.
  <!-- pid:TPM-019 | first:2026-05-12 -->
  Impact: Cross-device attestation verification will fail even if signature is valid (different hardware_info). Misleading for multi-device scenarios. | Fix: Add clear documentation that this is local-only verification and return false for remote use. | Effort: minimal

- [ ] **M-333** `[security]` `crates/cpoe/src/tpm/secure_enclave/attestation.rs:119`: Constant-time comparison uses .unwrap_u8() which always succeeds but is marked unsafe by comment.
  <!-- pid:TPM-018 | first:2026-05-12 -->
  Impact: Code is correct but readability issues. Comment says 'unsafe' but it's actually safe. | Fix: Document why unwrap_u8() is guaranteed safe (choice is always 0 or 1 bit). | Effort: minimal

- [ ] **M-334** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:22`: Bare .expect() on HMAC-SHA256 initialization. While slice is valid length, expect() is unnecessary.
  <!-- pid:TPM-002 | first:2026-05-12 -->
  Impact: Panic if impossible condition (should never happen but .expect() is still present). | Fix: Use map_err() to convert to TpmError or document with comment explaining impossibility. | Effort: minimal

- [ ] **M-335** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:31`: Bare .expect() on slice conversion. While length check precedes this, expect() violates error handling consistency.
  <!-- pid:TPM-003 | first:2026-05-12 -->
  Impact: Panic if slice bounds don't match (length check should prevent but not guaranteed). | Fix: Add explicit error handling with TpmError instead of expect(). | Effort: minimal

- [ ] **M-336** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:32`: Bare .expect() on HMAC slice conversion. Pattern repeated from line 31.
  <!-- pid:TPM-004 | first:2026-05-12 -->
  Impact: Same as TPM-003: potential panic on invalid slice bounds. | Fix: Replace with map_err() to TpmError. | Effort: minimal

- [ ] **M-337** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:37`: Silent error handling on constant-time comparison result. Returns error only if ct_eq fails, but unwrap_u8() could theoretically fail.
  <!-- pid:TPM-006 | first:2026-05-12 -->
  Impact: Logic is correct but uses unsafe pattern (unwrap_u8() is always safe). Code clarity issue. | Fix: Document the safety of unwrap_u8() or use safer pattern. | Effort: minimal

- [ ] **M-338** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:51`: Bare .expect() on slice conversion for legacy counter format. Line is protected by length check but expect() still unnecessary.
  <!-- pid:TPM-005 | first:2026-05-12 -->
  Impact: Panic if slice is not exactly 8 bytes (shouldn't happen due to earlier check but not guaranteed). | Fix: Replace with TpmError handling. | Effort: minimal

- [ ] **M-339** `[security]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:71`: Counter persistence uses tempfile::NamedTempFile with fs::sync_all(). No fsync on parent directory.
  <!-- pid:TPM-034 | first:2026-05-12 -->
  Impact: On power loss, rename could be lost even after sync_all(). Not atomic. | Fix: Add os_sync or document that fsync on parent is caller's responsibility. | Effort: low

- [ ] **M-340** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/counter.rs:88`: unwrap_or on counter_file.parent() could return root path if parent is None.
  <!-- pid:TPM-032 | first:2026-05-12 -->
  Impact: If counter file is '/' or similar, creates counter in root. Unlikely but violates defensive practice. | Fix: Return error if counter_file has no parent directory. | Effort: minimal

- [ ] **M-341** `[security]` `crates/cpoe/src/tpm/secure_enclave/key_management.rs:64`: Error reporting in load_or_create_se_key mentions tag in error. Could leak key material or identifying info.
  <!-- pid:TPM-016 | first:2026-05-12 -->
  Impact: If key tag is sensitive, error messages expose it to logs/telemetry. | Fix: Use generic error message without tag details. | Effort: minimal

- [ ] **M-342** `[security]` `crates/cpoe/src/tpm/secure_enclave/platform.rs:55`: Secure Enclave availability check uses CPOE_DISABLE_SECURE_ENCLAVE environment variable. Attacker could disable hardware through env.
  <!-- pid:TPM-029 | first:2026-05-12 -->
  Impact: Unprivileged process can force downgrade to software provider by setting env var. | Fix: Only check env var if process has elevated privileges or log warning when disabled. | Effort: low

- [ ] **M-343** `[code_quality]` `crates/cpoe/src/tpm/secure_enclave/platform.rs:122`: UUID extraction from ioreg output uses rfind() twice with string slicing. Fragile parsing.
  <!-- pid:TPM-020 | first:2026-05-12 -->
  Impact: If ioreg output format changes, UUID extraction silently fails and returns None. No validation. | Fix: Use regex or more robust parsing; validate UUID format matches expected pattern. | Effort: low

- [ ] **M-344** `[error_handling]` `crates/cpoe/src/tpm/secure_enclave/signing.rs:58`: Error handling in sign_with_key duplicates code from sign(). Both have identical error paths.
  <!-- pid:TPM-021 | first:2026-05-12 -->
  Impact: Code duplication increases maintenance burden; bugs fixed in one might not propagate to other. | Fix: Extract common error handling into helper function. | Effort: low

- [ ] **M-345** `[security]` `crates/cpoe/src/tpm/verification.rs:74`: verify_binding_with_trusted verifies ALL keys in constant-time but returns after first match. Pattern is intentional but could be clearer.
  <!-- pid:TPM-024 | first:2026-05-12 -->
  Impact: Code is correct (timing constant) but unconditional verification of all keys is slower than necessary. | Fix: Add explicit comment documenting constant-time verification requirement. | Effort: minimal

- [ ] **M-346** `[code_quality]` `crates/cpoe/src/tpm/verification.rs:141`: verify_signature_for_provider has provider_type matching 'tpm2-linux' and 'tpm2-windows' together. Should be in single match arm.
  <!-- pid:TPM-023 | first:2026-05-12 -->
  Impact: Code organization issue; makes it harder to track which providers use which algorithms. | Fix: Consolidate provider matching with clear comments on algorithm selection. | Effort: minimal

- [ ] **M-347** `[security]` `crates/cpoe/src/tpm/windows/provider.rs:171`: capabilities() reports supports_attestation = false but provider creates attestations. Misleading capability report.
  <!-- pid:TPM-032 | first:2026-05-12 -->
  Impact: Code relying on capabilities() flag would disable attestation even though provider supports it. | Fix: Change supports_attestation to true or remove attestation from sign_payload. | Effort: minimal

- [ ] **M-348** `[security]` `crates/cpoe/src/tpm/windows/provider.rs:231`: Binding payload includes device_id.as_bytes() directly without length prefix. Variable-length data.
  <!-- pid:TPM-014 | first:2026-05-12 -->
  Impact: If device_id format changes, deserialization or verification could be affected. No length field to validate. | Fix: Add length prefix to device_id in payload (see also linux.rs and software.rs). | Effort: minimal

- [ ] **M-349** `[error_handling]` `crates/cpoe/src/tpm/windows/provider_signing.rs:46`: Flush context errors silently ignored with _ operator. Handles may not be released.
  <!-- pid:TPM-012 | first:2026-05-12 -->
  Impact: TPM handle leak if flush fails. Not logged, so leaks are silent. | Fix: Log errors and track leaked handle count for monitoring. | Effort: minimal

- [ ] **M-350** `[code_quality]` `crates/cpoe/src/tpm/windows/provider_signing.rs:265`: Function parse_ecdsa_signature has 50+ lines handling binary response parsing. Multiple error conditions and offset arithmetic.
  <!-- pid:TPM-013 | first:2026-05-12 -->
  Impact: Complex parsing is error-prone; buffer overrun or integer overflow possible in offset calculations. | Fix: Extract offset arithmetic into helper functions with bounds checking. | Effort: medium

- [ ] **M-351** `[error_handling]` `crates/cpoe/src/wal/operations.rs:142`: sync_data() failure marks WAL inconsistent but doesn't flush pending writes to disk
  <!-- pid:EH-002 | first:2026-05-12 -->
  Impact: On transient I/O errors, pending buffered entries may be lost and subsequent appends rejected, creating a recovery burden | Fix: Call flush() first, then attempt recovery before marking inconsistent | Effort: medium

- [ ] **M-352** `[concurrency]` `crates/cpoe/src/wal/operations.rs:194`: verify() clones file handle and releases lock before I/O; concurrent append could invalidate file position assumptions
  <!-- pid:CONC-002 | first:2026-05-12 -->
  Impact: If verify() reads via cloned handle while append() writes to state.file, cumulative_hasher state becomes inconsistent (different I/O orders visible to | Fix: Snapshot cumulative_hasher state at lock time, or serialize verify() with append() | Effort: medium

- [ ] **M-353** `[performance]` `crates/cpoe/src/wal/operations.rs:239`: verify() deserializes entry for every entry in WAL; no early termination or sampling for large WALs
  <!-- pid:PERF-003 | first:2026-05-12 -->
  Impact: Verifying a 100K-entry WAL deserializes all 100K entries sequentially; O(n) with large constant factor | Fix: Add optional early_stop parameter or max_entries limit; allow caller to sample | Effort: small

- [ ] **M-354** `[code_quality]` `crates/cpoe/src/wal/operations.rs:867`: for loop at line 871 uses bare file.rename() without checking if destination exists (assumes atomic replace)
  <!-- pid:CQ-004 | first:2026-05-12 -->
  Impact: On POSIX, fs::rename() is atomic but error message on EEXIST would be unspecific; adds uncertainty for tests/recovery | Fix: Use fs::rename() is correct; add comment confirming atomic semantics are relied upon | Effort: small

- [ ] **M-355** `[error_handling]` `crates/cpoe/src/wal/operations.rs:1020`: scan_to_end() logs warnings on signature/hash verification failures but does not differentiate between malicious tampering and innocent corruption
  <!-- pid:EH-004 | first:2026-05-12 -->
  Impact: Operator cannot distinguish intent: log shows 'WAL signature invalid' but cause unknown (bit flip vs. key rotation vs. attacker) | Fix: Track error type counters (signature_mismatch_count, hash_mismatch_count, deserialization_errors) and log summary | Effort: small

- [ ] **M-356** `[code_quality]` `crates/cpoe/src/war/appraisal.rs:26`: Three magic constants defined at module level without derivation comments
  <!-- pid:magic_constants_no_spec | first:2026-05-12 -->
  Impact: MIN_CHECKPOINTS (3), MIN_AFFIRMING_DURATION_SECS (30), MAX_PLAUSIBLE_KEYSTROKES_PER_SEC (20) have no spec references | Fix: Add /// comments referencing: draft-condrey-rats-pop section X, RFC 9334, etc. | Effort: small

- [ ] **M-357** `[code_quality]` `crates/cpoe/src/war/appraisal.rs:39`: appraise function 228 lines with deeply nested if-else for trust vector mapping (lines 120-200)
  <!-- pid:deeply_nested_trust_vector_logic | first:2026-05-12 -->
  Impact: 20-line if-else block for hardware tier mapping difficult to read; business logic mixed with status assignment | Fix: Extract to fn compute_hw_status(hw_tier) -> (i8, i8); extract to fn compute_sourced_data_status(has_jitter, behavioral) -> i8 | Effort: medium

- [ ] **M-358** `[error_handling]` `crates/cpoe/src/war/appraisal.rs:85`: elapsed_secs as u64 cast may truncate; no overflow check
  <!-- pid:duration_truncation_unguarded | first:2026-05-12 -->
  Impact: If elapsed_time() returns >2^64 nanoseconds (~584 years), cast silently wraps | Fix: Check packet.total_elapsed_time() < Duration::MAX before cast; return error if implausible | Effort: small

- [ ] **M-359** `[code_quality]` `crates/cpoe/src/war/appraisal.rs:90`: Constant MAX_PLAUSIBLE_ELAPSED_SECS=31_536_000 defined inside match statement; not reusable
  <!-- pid:nested_magic_constant | first:2026-05-12 -->
  Impact: If other code needs this 365-day limit, will duplicate magic number | Fix: Define at module level with other constants | Effort: small

- [ ] **M-360** `[code_quality]` `crates/cpoe/src/war/compat.rs:152`: to_ear function does not document mapping from legacy Verdict -> Ar4siStatus (line 154-158)
  <!-- pid:unmapped_enum_conversion | first:2026-05-12 -->
  Impact: Future maintainers must infer Authentic=Affirming, Inconclusive=Warning, Suspicious|Invalid=Contraindicated | Fix: Add comment block explaining verdict mapping rationale; document why Suspicious and Invalid both map to Contraindicated | Effort: small

- [ ] **M-361** `[error_handling]` `crates/cpoe/src/war/compat.rs:214`: i64::try_from(self.created / 1000) can overflow; fallback uses Utc::now() without logging timestamp value
  <!-- pid:legacy_timestamp_overflow_silent | first:2026-05-12 -->
  Impact: Legacy attestation with created >> i64::MAX loses timestamp; warning logs only if overflow, actual created value not preserved | Fix: Log the actual created value when overflow occurs; store original value in fallback token | Effort: small

- [ ] **M-362** `[code_quality]` `crates/cpoe/src/war/ear.rs:100`: TrustworthinessVector::worst_component computes max() but name says worst (low values are worse in AR4SI, high values are contraindicated)
  <!-- pid:confusing_component_name | first:2026-05-12 -->
  Impact: Logic is correct (max finds most severe) but naming misleads; could be read as min(worst=lowest) | Fix: Rename to maximum_severity_component() or add comment: "worst = highest (most severe) AR4SI value" | Effort: small

- [ ] **M-363** `[code_quality]` `crates/cpoe/src/war/encoding.rs:230`: word_wrap function 21 lines; not exposed as public utility despite being used in encode_ascii
  <!-- pid:internal_utility_not_exposed | first:2026-05-12 -->
  Impact: Cannot be reused elsewhere; tightly coupled to Block::encode_ascii | Fix: Make pub fn word_wrap or move to text utils module if used elsewhere | Effort: small

- [ ] **M-364** `[maintainability]` `crates/cpoe/src/war/profiles/c2pa.rs:78`: to_c2pa_assertion() and to_c2pa_action() do not document the difference between them or which should be used in which context (manifest assertion vs. 
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: Callers may use wrong function for the context; C2PA structure becomes malformed | Fix: Add doc comment distinguishing use cases and referencing C2PA spec sections | Effort: small

- [ ] **M-365** `[maintainability]` `crates/cpoe/src/war/profiles/c2pa.rs:102`: No docs on public functions to_c2pa_assertion() and to_c2pa_action(); callers must infer that dc_format is set externally
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: C2PA asset MIME type handling unclear; callers may forget to set dc_format, resulting in empty value in manifest | Fix: Add /// docstring: 'Caller must set dc_format after construction based on asset file type' | Effort: small

- [ ] **M-366** `[code_quality]` `crates/cpoe/src/war/profiles/cawg.rs:98`: to_cawg_identity() creates identical error message for two different failure modes: pop_appraisal missing (line 101) — message is generic 'EAR token m
  <!-- pid:GENERIC_ERROR_MSG | first:2026-05-12 -->
  Impact: Future callers adding validation may use same error for unrelated issues; debugging harder | Fix: Use structured Error enum with variants: MissingPopAppraisal, MissingEarData; provide context | Effort: small

- [ ] **M-367** `[code_quality]` `crates/cpoe/src/war/profiles/cawg.rs:148`: to_cawg_identity_enriched() adds claims conditionally based on nested Option checks; if-let chains make code hard to follow; unclear what happens if o
  <!-- pid:NESTED_OPTION_HANDLING | first:2026-05-12 -->
  Impact: Future maintainers may add incompatible enrichments; error handling path not obvious | Fix: Use builder pattern: return result if any enrichment fails; make claims addition atomic | Effort: medium

- [ ] **M-368** `[architecture]` `crates/cpoe/src/war/profiles/cawg.rs:180`: to_cawg_identity_enriched() mutates existing CawgIdentityAssertion inline; no validation that credential type is Ica before trying to add entropy/fore
  <!-- pid:TYPE_SAFETY_MUTATION | first:2026-05-12 -->
  Impact: If future code selects VC credential type, forensic enrichment silently fails without error | Fix: Return error if credential is not Ica; make enrichment type-safe via builder | Effort: small

- [ ] **M-369** `[error_handling]` `crates/cpoe/src/war/profiles/cawg.rs:184`: CAWG payload JSON serialization error suppressed: 'CAWG payload serialization failed: {e}' lacks field context
  <!-- pid:GENERIC_ERROR_MSG | first:2026-05-12 -->
  Impact: Difficulty diagnosing which field in credential/claims caused serde failure | Fix: Log which claim or field failed; consider pre-validating claim_type/value for special chars | Effort: small

- [ ] **M-370** `[code_quality]` `crates/cpoe/src/war/profiles/cawg.rs:307`: to_cawg_tdm() function contains nearly-identical 4-entry Vec initialization repeated twice (one for human-authored, one for AI-generated); only 'permi
  <!-- pid:CODE_DUPLICATION_TDM | first:2026-05-12 -->
  Impact: Maintenance burden: updating entry structure (e.g., adding constraint_uri) requires edits in two places | Fix: Extract common entry list; use closure or factory to set permission/constraint based on AI extent | Effort: small

- [ ] **M-371** `[architecture]` `crates/cpoe/src/war/profiles/eu_ai_act.rs:70`: Article50Compliance::from_declaration() assumes ai_extent to IPTC mapping is always correct; no validation that IPTC URIs are reachable or standards-c
  <!-- pid:EXTERNAL_STANDARDS_VALIDATION | first:2026-05-12 -->
  Impact: If IPTC schema changes or URI becomes invalid, no detection; manifests may point to broken references | Fix: At deployment time, validate IPTC URIs are resolvable; add compliance test | Effort: medium

- [ ] **M-372** `[security]` `crates/cpoe/src/war/profiles/eu_ai_act.rs:74`: AiExtent::None and AiExtent::Minimal both set ai_generated=false; no intermediate type to distinguish 'purely human' from 'human-directed but AI-touch
  <!-- pid:INSUFFICIENT_CLASSIFICATION | first:2026-05-12 -->
  Impact: Regulatory systems cannot distinguish authorship levels; may over/under-credit AI involvement | Fix: Refine AiExtent enum or add confidence field to track certainty of classification | Effort: medium

- [ ] **M-373** `[architecture]` `crates/cpoe/src/war/profiles/eu_ai_act.rs:89`: Evidence-backed thresholds (MIN_EVIDENCE_KEYSTROKE_COUNT=5, MIN_EVIDENCE_ENTROPY_BITS=1.5) hardcoded; no configurability for different regulatory regi
  <!-- pid:HARDCODED_THRESHOLDS | first:2026-05-12 -->
  Impact: Cannot adjust confidence thresholds for different jurisdictions without recompilation | Fix: Extract to policy-driven configuration; load from Declaration or evidence context | Effort: medium

- [ ] **M-374** `[maintainability]` `crates/cpoe/src/war/profiles/jpeg_trust.rs:42`: OnceLock-based profile generator CPOE_PROFILE uses multiline string formatting (lines 54-56 with continuation), making it hard to search for actual tr
  <!-- pid:STRING_FRAGMENTATION | first:2026-05-12 -->
  Impact: Standards compliance docs may reference trust indicator wording; changes require searching split strings | Fix: Define trust indicator descriptions as named constants before building profile | Effort: small

- [ ] **M-375** `[maintainability]` `crates/cpoe/src/war/profiles/package.rs:85`: CredentialPackageBuilder field max_ingredients set to hardcoded 10 with no explanation; unclear if this is a sensible default or must be overridden
  <!-- pid:MAGIC_VALUES | first:2026-05-12 -->
  Impact: C2PA manifests may be limited to 10 ingredient checkpoints; users may not realize limitation is tunable | Fix: Document the 10-checkpoint default in struct; add comment on why limit exists (JSON size, JUMBF alignment) | Effort: small

- [ ] **M-376** `[maintainability]` `crates/cpoe/src/war/profiles/package.rs:88`: max_ingredients field in CredentialPackageBuilder has no validation; caller can set to 0 or huge value (e.g., usize::MAX) without checks
  <!-- pid:UNVALIDATED_BUILDER_PARAMS | first:2026-05-12 -->
  Impact: Zero ingredients results in empty C2PA manifest; usize::MAX causes memory exhaustion | Fix: Add builder validation: .max_ingredients(n) should assert 1 <= n <= reasonable_max (e.g., 1000) | Effort: small

- [ ] **M-377** `[maintainability]` `crates/cpoe/src/war/profiles/package.rs:160`: No documentation on CredentialPackageBuilder::build(); unclear when verification is called vs. when certificate embedding happens
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: Callers unsure about signing order; may embed unverified credentials in C2PA manifest | Fix: Add /// docs explaining: 'Signing happens here; VC proof and CAWG COSE created in build()' | Effort: small

- [ ] **M-378** `[code_quality]` `crates/cpoe/src/war/profiles/package.rs:216`: build_c2pa_manifest() spans 92 lines with 8 builder method chains and conditional blocks; difficult to follow evidence encoding pipeline
  <!-- pid:LARGE_FUNCTION | first:2026-05-12 -->
  Impact: Adding new assertions (CAWG, forensics) requires careful line-number understanding; hard to parallelize | Fix: Split into smaller phases: encode_ingredients(), serialize_cawg(), build_manifest_json(); compose sequentially | Effort: large

- [ ] **M-379** `[security]` `crates/cpoe/src/war/profiles/package.rs:228`: content_hash required for C2PA manifest but unwrap() used without prior check in build() caller; no validation that content_hash length is 32 bytes (S
  <!-- pid:INPUT_VALIDATION | first:2026-05-12 -->
  Impact: If caller passes wrong-sized hash (e.g., 16-byte MD5), silent truncation or panic may occur | Fix: Validate content_hash.len() == 32 in build() precondition; return error if wrong size | Effort: small

- [ ] **M-380** `[security]` `crates/cpoe/src/war/profiles/package.rs:242`: CAWG identity and TDM serialization to JSON may fail; errors converted to generic 'serialization failed'; no validation that resulting JSON is valid b
  <!-- pid:INCOMPLETE_VALIDATION | first:2026-05-12 -->
  Impact: Invalid JSON accidentally embedded in C2PA manifest; verifiers may reject entire manifest due to malformed assertion | Fix: Validate serde_json::to_value() succeeds; also validate structure post-serialization (required fields present) | Effort: small

- [ ] **M-381** `[code_quality]` `crates/cpoe/src/war/profiles/package.rs:311`: build_ingredients() creates Vec by iterating checkpoints and mapping to C2paIngredient; logic is straightforward but not documented; readers unsure ab
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: Ingredient ordering and relationship semantics unclear; changes could break C2PA manifest semantics | Fix: Add doc comment explaining checkpoint selection strategy (most recent for time ordering) and why parentOf is correct | Effort: small

- [ ] **M-382** `[security]` `crates/cpoe/src/war/profiles/package.rs:355`: coset::CoseSign1::from_slice() allows parsing any bytes; no structure pre-check before signature verification, allowing unbounded memory allocation on
  <!-- pid:UNBOUNDED_ALLOCATION | first:2026-05-12 -->
  Impact: DoS vulnerability: malicious COSE packets with huge payloads could cause memory exhaustion during CBOR decode | Fix: Add size check before from_slice(); reject COSE packets larger than reasonable bound (e.g., 1 MB) | Effort: medium

- [ ] **M-383** `[security]` `crates/cpoe/src/war/profiles/package.rs:368`: Ed25519 public key validation in verify_vc_proof() at line 368 uses from_bytes() which may succeed with invalid keys not checked against curve order
  <!-- pid:WEAK_CRYPTO_VALIDATION | first:2026-05-12 -->
  Impact: Potentially invalid Ed25519 keys accepted without full validation; signature verification may not catch all forgeries | Fix: Validate using curve point validation after from_bytes(); check point is in valid subgroup | Effort: medium

- [ ] **M-384** `[security]` `crates/cpoe/src/war/profiles/package.rs:369`: verify_vc_proof() extracts proof_value.strip_prefix('f') without validating remaining hex; allows non-hex characters to pass through to hex::decode()
  <!-- pid:INCOMPLETE_INPUT_VALIDATION | first:2026-05-12 -->
  Impact: Invalid proofValue strings (e.g., 'fxyz123') may partially decode; verification could succeed with garbage data | Fix: Validate all remaining characters are hex before decode; fail on invalid chars | Effort: small

- [ ] **M-385** `[security]` `crates/cpoe/src/war/profiles/package.rs:420`: verify_credential_package() returns warnings vector but caller may ignore it; no enforcement that all_valid=true before accepting credentials
  <!-- pid:IGNORED_WARNINGS | first:2026-05-12 -->
  Impact: Callers may accept packages with warnings; confidence degradation signals lost | Fix: Return Result with warnings in Err variant; force caller to handle warnings explicitly | Effort: medium

- [ ] **M-386** `[maintainability]` `crates/cpoe/src/war/profiles/standards.rs:72`: AiDisclosureLevel::from_ai_extent() maps Minimal and Moderate both to AiAssisted; comment says this is per W3C spec but doesn't explain rationale or l
  <!-- pid:MISSING_SPEC_REFERENCE | first:2026-05-12 -->
  Impact: Future maintainers unsure why two distinct extents collapse into one tier; may revert incorrectly | Fix: Add doc comment with W3C spec reference explaining 3-tier model and why collapsing is correct | Effort: small

- [ ] **M-387** `[security]` `crates/cpoe/src/war/profiles/standards.rs:182`: creative_rights_compliance() logic for checking gai_disclosed assumes ai_tools list being non-empty means disclosure; does not validate tool names are
  <!-- pid:WEAK_VALIDATION | first:2026-05-12 -->
  Impact: Placeholder tool names (e.g., empty string) could pass validation; compliance claim becomes weak | Fix: Validate ai_tools[i].tool is non-empty and matches expected identifier pattern before accepting as disclosure | Effort: small

- [ ] **M-388** `[security]` `crates/cpoe/src/war/profiles/standards.rs:194`: creative_rights_compliance() for W3C VC integration relies on declaration.ai_tools; does not validate that VC embedding will preserve this information
  <!-- pid:END_TO_END_VALIDATION | first:2026-05-12 -->
  Impact: Declaration AI disclosure lost if VC encoder drops ai_tools; W3C VC may not meet disclosure requirements | Fix: Validate end-to-end that VC serialization includes AI disclosure metadata | Effort: medium

- [ ] **M-389** `[code_quality]` `crates/cpoe/src/war/profiles/standards.rs:298`: nist_rmf_mapping() and iso_42001_mapping() both defined as OnceLock-based static builders; nearly identical pattern with different data; no abstractio
  <!-- pid:REPETITIVE_STATIC_BUILDERS | first:2026-05-12 -->
  Impact: Adding new standards (e.g., AITF from NIST AI 100-5) requires repeating OnceLock boilerplate | Fix: Create generic StandardsRegistry<T> trait; implement once for all standards | Effort: medium

- [ ] **M-390** `[maintainability]` `crates/cpoe/src/war/profiles/standards.rs:424`: creative_rights_compliance() logic mentions future 'ai_used_undisclosed' field (line 439) but not present in Declaration struct; unclear if field plan
  <!-- pid:OBSOLETE_COMMENT | first:2026-05-12 -->
  Impact: Comment suggests feature that may never be implemented; future maintainers uncertain of design intent | Fix: Either implement the field with default False, or remove the comment with explanation of why it's deferred | Effort: small

- [ ] **M-391** `[code_quality]` `crates/cpoe/src/war/profiles/standards.rs:521`: Function standards_compliance_report() 50+ lines with multiple nested branches; difficult to test individual mapping logic
  <!-- pid:LARGE_FUNCTION | first:2026-05-12 -->
  Impact: Testing coverage hard to maintain; bugs in one sub-mapping affect whole function | Fix: Extract helpers: _rats_alignment(), _ai_disclosure_level(), _creative_rights(); test separately | Effort: medium

- [ ] **M-392** `[code_quality]` `crates/cpoe/src/war/profiles/standards.rs:545`: Lines 545-551 build RatsAlignment with inline conditionals; code hard to read due to nested map/unwrap chains
  <!-- pid:NESTED_CONDITIONALS | first:2026-05-12 -->
  Impact: Future additions (e.g., EAR version) require parsing complex nesting | Fix: Extract helper function to build RatsAlignment; separate concerns | Effort: small

- [ ] **M-393** `[maintainability]` `crates/cpoe/src/war/profiles/standards.rs:556`: DID parsing at lines 556-564 uses splitn(3, ':') inline; no validation of DID format per W3C DID spec; comment says 'Extract DID method' but logic is 
  <!-- pid:INLINE_PARSING_LOGIC | first:2026-05-12 -->
  Impact: Malformed DIDs (e.g., 'did', 'did:key') produce incorrect results; no error signaling | Fix: Extract to function validate_and_parse_did(); return Result with error for invalid format | Effort: medium

- [ ] **M-394** `[maintainability]` `crates/cpoe/src/war/profiles/vc.rs:44`: VcEvidence and VcProof types have serde rename attributes but no doc comments explaining JSON field names; readers must guess 'sealHash' maps to seal_
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: API documentation unclear; IDE autocomplete unhelpful without traversing serde specs | Fix: Add /// doc comments with example JSON representation for clarity | Effort: small

- [ ] **M-395** `[maintainability]` `crates/cpoe/src/war/profiles/vc.rs:117`: No documentation on build_vc_core() helper; callers may not realize it excludes forensic signals and must call enrich_forensic_signals() separately
  <!-- pid:MISSING_DOCS | first:2026-05-12 -->
  Impact: VC construction workflow unclear; clients may forget enrichment step, resulting in incomplete evidence VCs | Fix: Add doc comment: 'Returns unsigned VC; forensic signals must be added via enrich_forensic_signals()' | Effort: small

- [ ] **M-396** `[code_quality]` `crates/cpoe/src/war/profiles/vc.rs:141`: Chain duration formatting (lines 131-141) uses separate branches for hours, minutes, seconds; verbose and error-prone if additional fields added (e.g.
  <!-- pid:REPETITIVE_FORMATTING | first:2026-05-12 -->
  Impact: ISO 8601 duration formatting not reusable; duplicated if needed elsewhere | Fix: Use chrono::Duration::to_string() or extract to shared helper; ensure ISO 8601 compliance | Effort: small

- [ ] **M-397** `[error_handling]` `crates/cpoe/src/war/profiles/vc.rs:149`: Invalid EAR iat timestamp converted to generic error message; no suggestion for valid range or context
  <!-- pid:GENERIC_ERROR_MSG | first:2026-05-12 -->
  Impact: Timestamp debugging harder; users uncertain if iat is zero, negative, or overflow | Fix: Include actual iat value and valid range in error message: 'EAR iat {ear.iat} not valid timestamp; must be 0..{i64::MAX}' | Effort: small

- [ ] **M-398** `[maintainability]` `crates/cpoe/src/war/profiles/vc.rs:163`: Evidence context URI hardcoded to 'https://writerslogic.com/ns/pop/v1'; no versioning or fallback if domain becomes unreachable
  <!-- pid:HARDCODED_URIS | first:2026-05-12 -->
  Impact: VCs become invalid if WritersLogic namespace server goes offline; no way to update URI in deployed VCs | Fix: Document lifecycle policy; consider using urn: URN instead of https: URL for permanence; version in namespace | Effort: medium

- [ ] **M-399** `[maintainability]` `crates/cpoe/src/war/profiles/vc.rs:263`: COSE_VC_CONTENT_TYPE hardcoded to 'application/vc' but documented as 'per W3C spec' without URL reference; no link to W3C Recommendation for verificat
  <!-- pid:MISSING_SPEC_REFERENCE | first:2026-05-12 -->
  Impact: Future spec changes may redefine content type; no indication where to check | Fix: Add doc comment with link to W3C recommendation URL (e.g., https://www.w3.org/...) | Effort: small

- [ ] **M-400** `[security]` `crates/cpoe/src/war/profiles/vc.rs:281`: to_cose_secured_vc() serializes VC as JSON to CBOR without schema validation; allows arbitrary JSON values to be embedded
  <!-- pid:MISSING_VALIDATION | first:2026-05-12 -->
  Impact: VC payload structure assumptions may be violated; malformed VCs accepted by encoder | Fix: Validate VerifiableCredential structure before serialization (required fields present, types correct) | Effort: small

- [ ] **M-401** `[code_quality]` `crates/cpoe/src/war/profiles/vc.rs:282`: to_cose_secured_vc() spans 25 lines with error handling pattern repeated twice (CBOR encode, then sign); similar flow to Data Integrity proof but not 
  <!-- pid:REPETITIVE_SIGNING_LOGIC | first:2026-05-12 -->
  Impact: Adding new securing mechanism (e.g., JWS) requires careful copy-paste; easy to miss error handling | Fix: Extract common signing pattern to helper; specialize on payload format (JSON vs CBOR) | Effort: medium

- [ ] **M-402** `[code_quality]` `crates/cpoe/src/war/profiles/vc.rs:283`: COSE content type hardcoded as literal string 'application/vc'; not exported as public const for reuse in verification code
  <!-- pid:HARDCODED_STRINGS | first:2026-05-12 -->
  Impact: Verification code may use different string (e.g., 'application/vp'); content type mismatch | Fix: Export as pub const COSE_VC_CONTENT_TYPE; use in from_cose_secured_vc() verification | Effort: small

- [ ] **M-403** `[security]` `crates/cpoe/src/war/profiles/vc.rs:356`: VC COSE signature verification uses signature byte slice length check (try_into()) but does not verify it's exactly 64 bytes; could allow truncated si
  <!-- pid:INCOMPLETE_VALIDATION | first:2026-05-12 -->
  Impact: Incomplete Ed25519 signatures (e.g., 32 bytes) may parse as all-zeros and verify incorrectly | Fix: Explicit check: assert!(sig.len() == 64, '...'); fail if not exact size | Effort: small

- [ ] **M-404** `[code_quality]` `crates/cpoe/src/war/profiles/vc.rs:436`: verify_vc_proof() function spans 54 lines with complex JCS canonicalization and signature verification logic; difficult to test individual steps
  <!-- pid:LARGE_FUNCTION | first:2026-05-12 -->
  Impact: Debugging VC proof failures requires understanding entire function; hard to isolate issue (canonicalization vs. signature) | Fix: Extract helpers: compute_proof_hash(), compute_document_hash(), verify_ed25519_sig(); test separately | Effort: medium

- [ ] **M-405** `[security]` `crates/cpoe/src/war/trust_bundle.rs:69`: Zero-key placeholder check uses bytes().all() on string; inefficient but correct
  <!-- pid:inefficient_placeholder_check | first:2026-05-12 -->
  Impact: All-zeros check works but allocates iterator; could be optimized | Fix: Use .as_bytes().all() or direct str comparison; add const fn validator for compile-time checks | Effort: small

- [ ] **M-406** `[code_quality]` `crates/cpoe/src/war/trust_bundle.rs:125`: cache_is_fresh function 13 lines with 3 sequential error checks (metadata, modified, elapsed); no early return optimization
  <!-- pid:non_early_exit_cache_check | first:2026-05-12 -->
  Impact: Reads fs::metadata and modified() even if cache file doesn't exist; inefficient on miss | Fix: Return false immediately if metadata fails; avoid modified() call on missing file | Effort: small

- [ ] **M-407** `[error_handling]` `crates/cpoe/src/war/verification.rs:132`: Signature::from_bytes always succeeds (64-byte slice to fixed array); no error handling needed but code assumes validity
  <!-- pid:signature_from_bytes_no_validation | first:2026-05-12 -->
  Impact: If signature bytes are corrupted before reaching this point, code silently continues with garbage signature | Fix: Add pre-validation that signature bytes are exactly 64; document assumption or add runtime check | Effort: small

- [ ] **M-408** `[security]` `crates/cpoe/src/war/verification.rs:315`: Constant-time comparison ct_eq used correctly for H1/H2/H3 but seal.h1/h2/h3 are fixed-size; timing safe
  <!-- pid:ct_comparison_safe | first:2026-05-12 -->
  Impact: Timing attack resistance correct for hash comparisons; no vulnerability but explanation could be clearer | Fix: Add comment explaining ct_eq usage; document why fixed-size arrays are safe from timing attacks | Effort: small

- [ ] **M-409** `[code_quality]` `crates/cpoe/src/war/verification.rs:351`: Magic constant MAX_VERIFICATION_ITERATIONS=3_600_000_000 undocumented (claimed 1 hour but no rate specified)
  <!-- pid:undocumented_magic_constant | first:2026-05-12 -->
  Impact: Maintenance burden: next engineer cannot verify claim without reverse calculation | Fix: Define as const with comment: const MAX_VERIFICATION_ITERATIONS: u64 = 3_600_000_000; // 1 hour at 1M/sec default rate | Effort: small

## Quick Wins
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|

## Coverage
<!-- scan:2026-05-12 | batches:40 | waves:8 | files:455 | depth:deep+standard+shallow -->
<!-- findings:930 | critical:52 | high:260 | medium:409 | systemic:3 -->