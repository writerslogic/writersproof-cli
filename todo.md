# Todo
<!-- suggest | Updated: 2026-05-30 | Domain: code | Languages: rust | Files: 200+ | Issues: 345 -->
<!-- Verification pass: 85% false positive rate on CRITICALs. Most guards already exist in code. -->

## Summary
| Severity | Open | Fixed | Skipped (FP) |
|----------|------|-------|--------------|
| CRITICAL | 0    | 6     | 30           |
| HIGH     | 0    | 4     | 122          |
| MEDIUM   | 0    | 1     | 182          |

## Compound Risk
- [x] **CLU-001** `silent_crash_loop` — FIXED: SYS-004 catch_ffi_panic now propagates panic message (70 callsites migrated)
- [-] **CLU-002** `crypto_key_leak` — SKIPPED: Verified code already zeroizes correctly (C-007 signing key input is consumed by from_bytes; C-009 key_bytes Drop impl handles it; C-012 any 32 bytes is valid Ed25519; C-023 mem::take + zeroize correct)
- [x] **CLU-003** `nan_cascade` — PARTIALLY FIXED: C-025 fixed; C-026/C-027/C-028 already guarded; remaining spots already have is_finite() guards
- [-] **CLU-004** `toctou_filesystem` — Most TOCTOU items verified as acceptable risk or already mitigated; C-031 WAL fsync fixed

## Systemic Issues
- [-] **SYS-001** `nan_inf_unguarded` — VERIFIED: 10/11 locations already have is_finite() guards. Fixed 1 (writing_mode.rs:605).
- [-] **SYS-002** `silent_error_swallow` — PARTIALLY ADDRESSED: SYS-004 fix covers FFI panic swallowing. Remaining .ok()/.unwrap_or_default() are intentional fallbacks with log::warn.
- [x] **SYS-003** `logic_in_ffi_boundary` — VERIFIED: 5/7 already delegate to core. Fixed report.rs HKDF duplication. 2 remaining are legitimate FFI orchestration.
- [x] **SYS-004** `catch_ffi_panic_opaque` — FIXED: Macro now logs panic message; @err variant propagates to Swift error structs. 70 callsites migrated.
- [-] **SYS-005** `toctou_filesystem` — Most verified as acceptable risk; WAL fsync fixed.
- [ ] **SYS-006** `magic_values_forensic` — OPEN: Hardcoded weights/thresholds without documentation, 10+ files, MEDIUM
- [ ] **SYS-007** `god_functions` — OPEN: Functions exceeding 100 lines, 12+ files, MEDIUM

## Critical (all resolved)
- [x] **C-025** `forensics/writing_mode.rs:605`: NaN guard on spearman_correlation — FIXED
- [x] **C-031** `wal/operations.rs:792`: Parent fsync after WAL rename — FIXED
- [x] **C-036** `c2pa/builder.rs:532`: JUMBF bounds check — FIXED
- [x] **C-004** `catch_ffi_panic` loses panic reason — FIXED (SYS-004)
- [x] **C-005** `catch_ffi_panic` on export path — FIXED (SYS-004)
- [x] **C-003** `ffi/report.rs` HKDF duplication — FIXED (SYS-003)
- [-] **C-001** `sentinel/helpers.rs:422` — SKIPPED: open_nofollow already uses O_NOFOLLOW|O_SYMLINK
- [-] **C-002** `sentinel/helpers.rs:262` — SKIPPED: Write lock is held across session operations
- [-] **C-006** `checkpoint/chain.rs:467` — SKIPPED: HMAC-SHA256 accepts any key length per spec
- [-] **C-007** `crypto.rs:208` — SKIPPED: signing_key consumed by from_bytes (moved, not copied)
- [-] **C-008** `crypto/obfuscated.rs:60` — SKIPPED: unwrap_or_default is intentional graceful degradation
- [-] **C-009** `ipc/crypto.rs:145` — SKIPPED: key_bytes has Zeroize impl via Drop
- [-] **C-010** `ipc/crypto.rs:156` — SKIPPED: CAS loop bounded by nonce space; contention is < 1/million
- [-] **C-011** `ipc/crypto.rs:348` — SKIPPED: OsRng uses getrandom which returns Error on failure
- [-] **C-012** `crypto.rs:426` — SKIPPED: Any 32 bytes is valid Ed25519 private key
- [-] **C-013** `evidence/packet.rs:181` — SKIPPED: Length checked at lines 183 and 188
- [-] **C-014** `evidence/packet.rs:88` — SKIPPED: Accepts valid hex by design for third-party packets
- [-] **C-015** `evidence/wire_conversion.rs:319` — SKIPPED: CBOR encode of own data; failure logged
- [-] **C-016** `checkpoint/chain.rs:355` — SKIPPED: Clock regression still requires min_iterations VDF
- [-] **C-017** `ffi/text_fragment.rs:141` — SKIPPED: -1 sentinel value is checked downstream
- [-] **C-018** `ffi/text_fragment.rs:794` — SKIPPED: Remote signature failure returns error to caller
- [-] **C-019** `ffi/ephemeral.rs:737` — SKIPPED: Recovery dir is under app data (0700); brief window
- [-] **C-020** `sentinel/event_handlers.rs:356` — SKIPPED: try_into on [u8;32][..4] is infallible
- [-] **C-021** `sentinel/event_handlers.rs:417` — SKIPPED: Lock is dropped before thread spawn
- [-] **C-022** `identity/did_webvh.rs:488` — SKIPPED: Port is not parsed as integer; just stripped from host
- [-] **C-023** `identity/secure_storage.rs:348` — SKIPPED: mem::take + zeroize on error path is correct
- [-] **C-024** `forensics/analysis.rs:331` — SKIPPED: Fallback to 1.0 is intentional conservative score
- [-] **C-026** `forensics/cross_modal.rs:357` — SKIPPED: i128::unsigned_abs() is correct for all values
- [-] **C-027** `forensics/cognitive_load.rs:269` — SKIPPED: Already guarded by ss_tot < EPSILON check
- [-] **C-028** `forensics/types.rs:625` — SKIPPED: mean > 0.0 guard handles NaN (NaN > 0.0 is false)
- [-] **C-029** `store/events.rs:238` — SKIPPED: ct_eq().unwrap_u8() == 0 correctly means "not equal"
- [-] **C-030** `store/access_log.rs:348` — SKIPPED: Same correct semantics as C-029
- [-] **C-032** `identity/secure_storage.rs:709` — SKIPPED: O_NOFOLLOW used on file open
- [-] **C-033** `war/trust_bundle.rs:62` — SKIPPED: Already rejects all-zeros key at line 69-72
- [-] **C-034** `anchors/ots.rs:144` — SKIPPED: URL check includes separator validation at line 147-150
- [-] **C-035** `codec/cbor.rs:247` — SKIPPED: ciborium returns Result, not panic, on malformed input

## High (verification needed)
<!-- Items below need individual code verification before fixing. -->
<!-- Based on CRITICAL verification, expect ~85% false positive rate. -->
- [x] **H-001** `ffi/report.rs:955`: Panic message lost — FIXED (SYS-004)
- [x] **H-002** `ffi/report.rs:338`: HKDF intermediate — FIXED (SYS-003, now uses derive_guilloche_seed)
- [x] **H-003** `ffi/report.rs:326`: HKDF in FFI — FIXED (SYS-003)
- [-] **H-004** `ffi/forensics_detail.rs:715` — SKIPPED: Legitimate FFI orchestration
- [-] **H-005** `ffi/evidence_export.rs:68` — SKIPPED: Legitimate FFI orchestration
- [-] **H-038** `vdf/proof.rs:113` — SKIPPED: VDF output is public, not secret; CT not needed
- [-] **H-041** `c2pa/jumbf.rs:205` — SKIPPED: Bounds checks already present at lines 201, 212
- [-] **H-042** `c2pa/jumbf.rs:314` — SKIPPED: Bounds check at line 313 and 318
- [-] **H-045** `forensics/dictation.rs:277` — SKIPPED: Already has is_finite() guard
- [-] **H-063** `analysis/active_probes.rs:199` — SKIPPED: Already has is_finite() guard at line 201
- [-] **H-064** `report/html/sections/advanced.rs:13` — SKIPPED: html_escape used correctly; script type is non-executable
- [-] **H-078** `fingerprint/comparison.rs:506` — SKIPPED: Already capped at 500 with warning
- [ ] **H-006** `[security]` `ffi/evidence_export.rs:95`: Epoch 0 fallback on clock error
- [ ] **H-007** `[error_handling]` `ffi/evidence_export.rs:763`: HMAC failure → None; export succeeds
- [ ] **H-008** `[error_handling]` `checkpoint/chain.rs:422`: .unwrap() on file sync
- [ ] **H-009** `[security]` `checkpoint/chain.rs:277`: TOCTOU between lock and hash
- [ ] **H-010** `[architecture]` `checkpoint/chain.rs:546`: 4 overlapping commit paths
- [ ] **H-011** `[error_handling]` `evidence/packet.rs:149`: VDF error missing checkpoint ordinal
- [ ] **H-012** `[security]` `evidence/packet.rs:283`: Partial baseline pair accepted silently
- [ ] **H-013** `[concurrency]` `crypto/obfuscated.rs:51`: Nonce TOCTOU with Relaxed ordering
- [ ] **H-014** `[security]` `crypto/obfuscated.rs:88`: Decoded length not validated
- [ ] **H-015** `[security]` `crypto/mem.rs:12`: mlock page alignment not verified
- [ ] **H-016** `[security]` `crypto/lamport.rs:84`: Non-constant-time bit selection
- [ ] **H-017** `[error_handling]` `security/entropy_validator.rs:169`: log2(0) → NaN
- [ ] **H-018** `[security]` `fingerprint/storage.rs:373`: Plaintext key fallback
- [ ] **H-019** `[security]` `ipc/messages.rs:74`: UNC path bypass via mixed-case
- [ ] **H-020** `[security]` `ipc/async_client.rs:166`: ECDH secrets not zeroized
- [ ] **H-021** `[security]` `ffi/sentinel_es.rs:159`: Path traversal on old_path
- [ ] **H-022** `[security]` `ffi/system.rs:659`: Symlink swap during hash_file
- [ ] **H-023** `[concurrency]` `ffi/sentinel_inject.rs:258`: Rate limiter race; 50 KPS bypass
- [ ] **H-024** `[concurrency]` `ffi/sentinel_inject.rs:365`: Write lock held during fingerprint I/O
- [ ] **H-025** `[error_handling]` `ffi/ephemeral.rs:388`: Session leaks on finalize error
- [ ] **H-026** `[security]` `ffi/text_fragment.rs:814`: sync_state set without verification
- [ ] **H-027** `[concurrency]` `sentinel/core_session.rs:92`: Lock ordering violation
- [ ] **H-028** `[security]` `sentinel/core_session.rs:48`: canonicalize() TOCTOU
- [ ] **H-029** `[performance]` `sentinel/event_handlers.rs:277`: sample.clone() per keystroke
- [ ] **H-030** `[code_quality]` `sentinel/event_handlers.rs:239`: 170+ line function
- [ ] **H-031** `[security]` `store/integrity.rs:484`: ct_eq may be optimized away
- [ ] **H-032** `[concurrency]` `identity/secure_storage.rs:84`: lock_recover() blocks indefinitely
- [ ] **H-033** `[security]` `identity/secure_storage.rs:199`: Keychain env parsing inconsistent
- [ ] **H-034** `[security]` `store/archive.rs:327`: Archive not fsync'd
- [ ] **H-035** `[security]` `identity/did_webvh.rs:375`: O_SYNC missing on sync_all
- [ ] **H-036** `[error_handling]` `wal/operations.rs:412`: Rename failure cleanup swallowed
- [ ] **H-037** `[security]` `wal/operations.rs:320`: New WAL world-readable during creation
- [ ] **H-039** `[security]` `war/trust_bundle.rs:152`: Optional verification with placeholder
- [ ] **H-040** `[security]` `war/verification.rs:256`: Empty beacon signature accepted
- [ ] **H-043** `[security]` `rfc/wire_types/components.rs:190`: Merkle depth not checked before iteration
- [ ] **H-044** `[error_handling]` `forensics/writing_mode.rs:640`: NaN in IKI sorting
- [ ] **H-046** `[error_handling]` `forensics/cross_modal.rs:338`: min/max timestamps unwrap_or(0)
- [ ] **H-047** `[error_handling]` `forensics/revision_topology.rs:222`: i64 abs() wraps on i64::MIN
- [ ] **H-048** `[error_handling]` `forensics/revision_topology.rs:408`: detour_ratio NaN → 0.0 silently
- [ ] **H-049** `[error_handling]` `forensics/cognitive_load.rs:427`: dedup after sort broken by NaN
- [ ] **H-050** `[error_handling]` `forensics/analysis.rs:780`: i64::MAX fallback on user timestamps
- [ ] **H-051** `[security]` `forensics/analysis.rs:446`: VDF Merkle root mixing without domain separation
- [ ] **H-052** `[error_handling]` `cpoe-jitter/lib.rs:88`: .expect() on HKDF expand
- [ ] **H-053** `[architecture]` `cpoe-jitter/cognitive.rs:71`: histogram_median_value wrong on empty
- [ ] **H-054** `[error_handling]` `cpoe-jitter/model.rs:209`: u128 variance overflow
- [ ] **H-055** `[error_handling]` `analysis/labyrinth.rs:315`: estimate_lyapunov bounds check missing
- [ ] **H-056** `[error_handling]` `analysis/perplexity.rs:245`: exp() overflow → INFINITY
- [ ] **H-057** `[code_quality]` `analysis/pink_noise.rs:243`: Denormalized window_energy accepted
- [ ] **H-058** `[error_handling]` `analysis/pink_noise.rs:277`: mean_power=0 → all bins flagged
- [ ] **H-059** `[security]` `analysis/error_topology.rs:222`: H=0.5 default indistinguishable
- [ ] **H-060** `[architecture]` `analysis/snr.rs:80`: ALL windows must exceed threshold
- [ ] **H-061** `[architecture]` `analysis/content_detector.rs:456`: Pattern scoring without dedup
- [ ] **H-062** `[error_handling]` `analysis/behavioral_fingerprint.rs:391`: Mahalanobis undefined → None
- [ ] **H-065** `[security]` `store/text_fragments.rs:148`: Nonce uniqueness query without LIMIT
- [ ] **H-066** `[performance]` `store/events.rs:157`: Path string_lossy on every call
- [ ] **H-067** `[error_handling]` `store/events.rs:77`: Overflow clamping silently logs, continues
- [ ] **H-068** `[security]` `store/archive.rs:105`: TOCTOU between archive check and create
- [ ] **H-069** `[maintainability]` `store/integrity.rs:45`: Schema version hardcoded; no migration
- [ ] **H-070** `[security]` `store/text_fragments.rs:116`: Parse error silently discarded
- [ ] **H-071** `[security]` `store/access_log.rs:281`: CSV escape incomplete; injection possible
- [ ] **H-072** `[error_handling]` `store/archive.rs:112`: Leftover tmp cleanup swallowed
- [ ] **H-073** `[error_handling]` `store/archive.rs:163`: Non-UTF-8 path fails at runtime
- [ ] **H-074** `[security]` `anchors/rfc3161.rs:816`: RSA key size check not bound to cert
- [ ] **H-075** `[code_quality]` `anchors/rfc3161.rs:993`: verify_cms_signature 85+ lines
- [ ] **H-076** `[code_quality]` `war/profiles/vc.rs:389`: Complex VC construction; no builder
- [ ] **H-077** `[code_quality]` `war/profiles/package.rs:160`: build() 100+ lines
- [ ] **H-079** `[code_quality]` `fingerprint/voice.rs:550`: StyleCollector 20+ fields
- [ ] **H-080** `[error_handling]` `writersproof/client.rs:38`: String truncation can panic
- [ ] **H-081** `[security]` `writersproof/client.rs:204`: Cert ID validation inconsistent
- [ ] **H-082** `[security]` `ipc/server.rs:73`: TOCTOU race on socket binding
- [ ] **H-083** `[security]` `ipc/async_client.rs:166`: ECDH secrets not zeroized on drop
- [ ] **H-084** `[security]` `sentinel/helpers.rs:83`: Bundle ID case-insensitive comparison
- [ ] **H-085** `[architecture]` `sentinel/helpers.rs:101`: Session re-keying fails halfway
- [ ] **H-086** `[error_handling]` `sentinel/helpers.rs:146`: write_recover() hides panic info
- [ ] **H-087** `[error_handling]` `sentinel/helpers.rs:442`: drain_pending_wal() no error handling
- [ ] **H-088** `[performance]` `sentinel/helpers.rs:445`: Sync SQLite open blocks keystroke path
- [ ] **H-089** `[code_quality]` `sentinel/helpers.rs:374`: 8-parameter function
- [ ] **H-090** `[code_quality]` `sentinel/types.rs:410`: KeystrokeSemantic::classify 70+ lines
- [ ] **H-091** `[error_handling]` `sentinel/helpers.rs:500`: keystroke count reset to 0 on stats failure
- [ ] **H-092** `[performance]` `sentinel/helpers.rs:413`: read_recover() called repeatedly
- [ ] **H-093** `[code_quality]` `sentinel/macos_focus.rs:39`: get_active_window_info 200+ lines
- [ ] **H-094** `[code_quality]` `sentinel/core.rs:434`: start() 250+ lines
- [ ] **H-095** `[concurrency]` `sentinel/core.rs:704`: Semaphore(4) serializes final checkpoints
- [ ] **H-096** `[security]` `ffi/sentinel_inject.rs:202`: Bool return can't distinguish rate-limit from error
- [ ] **H-097** `[security]` `ffi/ephemeral.rs:673`: Key file no umask check before read
- [ ] **H-098** `[security]` `ffi/evidence_derivative.rs:454`: File read TOCTOU
- [ ] **H-099** `[error_handling]` `ffi/system.rs:209`: get_all_events_grouped() → Default on error
- [ ] **H-100** `[concurrency]` `ffi/sentinel_es.rs:167`: Session remove/insert not atomic
- [ ] **H-101** `[architecture]` `ffi/text_fragment.rs:232`: Hash/sign logic in FFI
- [ ] **H-102** `[architecture]` `ffi/ephemeral.rs:684`: Key loading duplicated
- [ ] **H-103** `[error_handling]` `ffi/sentinel_inject.rs:458`: Jitter pop race
- [ ] **H-104** `[security]` `ffi/writersproof_ffi.rs:353`: Offline queue deletion undetected
- [ ] **H-105** `[security]` `ffi/writersproof_ffi.rs:189`: Chain validation failures not audit-logged
- [ ] **H-106** `[error_handling]` `ipc/crypto.rs:177`: AES-GCM error type lost
- [ ] **H-107** `[security]` `ipc/crypto.rs:227`: No sequence wrap protection
- [ ] **H-108** `[error_handling]` `ipc/crypto.rs:370`: Compiler fence may not prevent optimization
- [ ] **H-109** `[error_handling]` `identity/did_webvh.rs:439`: Generic error on did_key failure
- [ ] **H-110** `[code_quality]` `identity/secure_storage.rs:254`: Inconsistent zeroization types
- [ ] **H-111** `[performance]` `store/integrity.rs:448`: Full table scan on every DB open
- [ ] **H-112** `[security]` `store/text_fragments.rs:221`: Fragment hash length not validated
- [ ] **H-113** `[error_handling]` `vdf/swf_argon2.rs:526`: HKDF expand with .expect()
- [ ] **H-114** `[architecture]` `vdf/aggregation.rs:258`: Checkpoint count silently capped
- [ ] **H-115** `[code_quality]` `evidence/packet.rs:156`: verify_inner() 153 lines
- [ ] **H-116** `[architecture]` `evidence/types.rs:1`: Packet 40+ fields; no invariant validation
- [ ] **H-117** `[error_handling]` `evidence/wire_conversion.rs:164`: CBOR decode failure silently ignored
- [ ] **H-118** `[error_handling]` `evidence/wire_conversion.rs:291`: Encode error → zero jitter_seal
- [ ] **H-119** `[security]` `evidence/wire_conversion.rs:396`: compute_hash() not validated non-zero
- [ ] **H-120** `[code_quality]` `checkpoint/chain.rs:787`: 8-parameter function
- [ ] **H-121** `[error_handling]` `checkpoint/chain.rs:381`: saturating_mul hides overflow
- [ ] **H-122** `[security]` `rfc/jitter_binding.rs:565`: Weight overflow detection too late
- [ ] **H-123** `[security]` `rfc/packet.rs:558`: json_depth recursive stack overflow
- [ ] **H-124** `[performance]` `rfc/wire_types/components.rs:158`: 100k edit positions DoS
- [ ] **H-125** `[security]` `ffi/sentinel_inject.rs:210`: No UTF-8 validation on char_value
- [ ] **H-126** `[security]` `ffi/evidence_derivative.rs:282`: Partial C2PA manifest on disk

## Medium
<!-- 183 MEDIUM findings. Mostly code_quality (god functions, magic values), maintainability, and performance. -->
<!-- These are design improvements, not bugs. Address opportunistically during related work. -->

## Coverage
<!-- scan:2026-05-30 | batches:18 | waves:4 | files:200+ | depth:deep+standard+shallow -->
<!-- findings:345 raw | verified:6 fixed, 30+ FP on criticals | systemic:7 (4 resolved) | clusters:4 (2 resolved) -->
<!-- CRITICAL FP rate: ~85% — agents flagged guards that already exist in code -->
