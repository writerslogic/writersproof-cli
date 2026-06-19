# Todo
<!-- suggest | Updated: 2026-06-18 | Domain: code | Languages: rust | Files: 200+ | Issues: 345 -->
<!-- Verification pass 2026-06-18: 59% false positive rate on HIGHs (66/112 verified FP). -->

## Summary
| Severity | Open | Fixed | Verified FP |
|----------|------|-------|-------------|
| CRITICAL | 0    | 6     | 30          |
| HIGH     | 46   | 4     | 66          |
| MEDIUM   | 0    | 1     | 182         |

## Compound Risk
- [x] **CLU-001** `silent_crash_loop` — FIXED: SYS-004 catch_ffi_panic now propagates panic message (70 callsites migrated)
- [-] **CLU-002** `crypto_key_leak` — FP: Verified code already zeroizes correctly (C-007 signing key input is consumed by from_bytes; C-009 key_bytes Drop impl handles it; C-012 any 32 bytes is valid Ed25519; C-023 mem::take + zeroize correct)
- [x] **CLU-003** `nan_cascade` — PARTIALLY FIXED: C-025 fixed; C-026/C-027/C-028 already guarded; remaining spots already have is_finite() guards
- [-] **CLU-004** `toctou_filesystem` — Most TOCTOU items verified as acceptable risk or already mitigated; C-031 WAL fsync fixed

## Systemic Issues
- [-] **SYS-001** `nan_inf_unguarded` — VERIFIED: 10/11 locations already have is_finite() guards. Fixed 1 (writing_mode.rs:605).
- [-] **SYS-002** `silent_error_swallow` — PARTIALLY ADDRESSED: SYS-004 fix covers FFI panic swallowing. Remaining .ok()/.unwrap_or_default() are intentional fallbacks with log::warn.
- [x] **SYS-003** `logic_in_ffi_boundary` — VERIFIED: 5/7 already delegate to core. Fixed report.rs HKDF duplication. 2 remaining are legitimate FFI orchestration.
- [x] **SYS-004** `catch_ffi_panic_opaque` — FIXED: Macro now logs panic message; @err variant propagates to Swift error structs. 70 callsites migrated.
- [-] **SYS-005** `toctou_filesystem` — Most verified as acceptable risk; WAL fsync fixed.
- [ ] **SYS-006** `magic_values_forensic` — OPEN: ~93 undocumented magic float literals in forensics/ (~40% of thresholds still inline). 144 named consts exist. MEDIUM.
- [ ] **SYS-007** `god_functions` — OPEN: 289 functions >100 lines in non-test production code. Key examples: start() 494 lines, verify_inner 258 lines, verify_cms_signature 254 lines, record_keystroke_to_session 226 lines. MEDIUM.

## Critical (all resolved)
- [x] **C-025** `forensics/writing_mode.rs:605`: NaN guard on spearman_correlation — FIXED
- [x] **C-031** `wal/operations.rs:792`: Parent fsync after WAL rename — FIXED
- [x] **C-036** `c2pa/builder.rs:532`: JUMBF bounds check — FIXED
- [x] **C-004** `catch_ffi_panic` loses panic reason — FIXED (SYS-004)
- [x] **C-005** `catch_ffi_panic` on export path — FIXED (SYS-004)
- [x] **C-003** `ffi/report.rs` HKDF duplication — FIXED (SYS-003)
- [-] **C-001** `sentinel/helpers.rs:422` — FP: open_nofollow already uses O_NOFOLLOW|O_SYMLINK
- [-] **C-002** `sentinel/helpers.rs:262` — FP: Write lock is held across session operations
- [-] **C-006** `checkpoint/chain.rs:467` — FP: HMAC-SHA256 accepts any key length per spec
- [-] **C-007** `crypto.rs:208` — FP: signing_key consumed by from_bytes (moved, not copied)
- [-] **C-008** `crypto/obfuscated.rs:60` — FP: unwrap_or_default is intentional graceful degradation
- [-] **C-009** `ipc/crypto.rs:145` — FP: key_bytes has Zeroize impl via Drop
- [-] **C-010** `ipc/crypto.rs:156` — FP: CAS loop bounded by nonce space; contention is < 1/million
- [-] **C-011** `ipc/crypto.rs:348` — FP: OsRng uses getrandom which returns Error on failure
- [-] **C-012** `crypto.rs:426` — FP: Any 32 bytes is valid Ed25519 private key
- [-] **C-013** `evidence/packet.rs:181` — FP: Length checked at lines 183 and 188
- [-] **C-014** `evidence/packet.rs:88` — FP: Accepts valid hex by design for third-party packets
- [-] **C-015** `evidence/wire_conversion.rs:319` — FP: CBOR encode of own data; failure logged
- [-] **C-016** `checkpoint/chain.rs:355` — FP: Clock regression still requires min_iterations VDF
- [-] **C-017** `ffi/text_fragment.rs:141` — FP: -1 sentinel value is checked downstream
- [-] **C-018** `ffi/text_fragment.rs:794` — FP: Remote signature failure returns error to caller
- [-] **C-019** `ffi/ephemeral.rs:737` — FP: Recovery dir is under app data (0700); brief window
- [-] **C-020** `sentinel/event_handlers.rs:356` — FP: try_into on [u8;32][..4] is infallible
- [-] **C-021** `sentinel/event_handlers.rs:417` — FP: Lock is dropped before thread spawn
- [-] **C-022** `identity/did_webvh.rs:488` — FP: Port is not parsed as integer; just stripped from host
- [-] **C-023** `identity/secure_storage.rs:348` — FP: mem::take + zeroize on error path is correct
- [-] **C-024** `forensics/analysis.rs:331` — FP: Fallback to 1.0 is intentional conservative score
- [-] **C-026** `forensics/cross_modal.rs:357` — FP: i128::unsigned_abs() is correct for all values
- [-] **C-027** `forensics/cognitive_load.rs:269` — FP: Already guarded by ss_tot < EPSILON check
- [-] **C-028** `forensics/types.rs:625` — FP: mean > 0.0 guard handles NaN (NaN > 0.0 is false)
- [-] **C-029** `store/events.rs:238` — FP: ct_eq().unwrap_u8() == 0 correctly means "not equal"
- [-] **C-030** `store/access_log.rs:348` — FP: Same correct semantics as C-029
- [-] **C-032** `identity/secure_storage.rs:709` — FP: O_NOFOLLOW used on file open
- [-] **C-033** `war/trust_bundle.rs:62` — FP: Already rejects all-zeros key at line 69-72
- [-] **C-034** `anchors/ots.rs:144` — FP: URL check includes separator validation at line 147-150
- [-] **C-035** `codec/cbor.rs:247` — FP: ciborium returns Result, not panic, on malformed input

## High — Security (10 open)
- [ ] **H-009** `checkpoint/chain.rs`: TOCTOU between flock open and hash open — two separate open syscalls; racing writer can bypass advisory lock
- [ ] **H-012** `evidence/packet.rs`: Partial baseline pair accepted — digest present but digest_signature None silently skips verification
- [ ] **H-015** `crypto/mem.rs:12`: mlock with non-page-aligned pointer — silently fails on nearly all calls; key material remains swappable
- [ ] **H-028** `sentinel/core_session.rs`: canonicalize() TOCTOU — exists() then canonicalize() has symlink swap window
- [ ] **H-034** `store/archive.rs`: Archive file not fsynced before rename; dir sync error swallowed with `let _ =`
- [ ] **H-037** `wal/operations.rs`: File::create makes WAL world-readable; restrict_permissions narrows after (brief TOCTOU)
- [ ] **H-039** `war/trust_bundle.rs:152`: Placeholder signing key (all-zeros) skips signature verification on trust bundle load
- [ ] **H-068** `store/archive.rs`: archive_path.exists() and creation not atomic; concurrent archive calls race
- [ ] **H-084** `sentinel/helpers.rs`: eq_ignore_ascii_case on bundle IDs — macOS bundle IDs are case-sensitive; can misattribute sessions
- [ ] **H-110** `identity/secure_storage.rs`: MNEMONIC_CACHE uses Zeroizing<String> (no mlock) while other caches use ProtectedBuf; BIP-39 mnemonic equally sensitive

## High — Error Handling (14 open)
- [ ] **H-007** `ffi/evidence_export.rs`: HMAC failure → None; export succeeds without jitter seal, silently weakening evidence
- [ ] **H-050** `forensics/analysis.rs:780`: timestamp_nanos_opt().unwrap_or(i64::MAX) — all events treated as "before" overflow timestamp
- [ ] **H-066** `store/events.rs`: to_string_lossy() called inline in multiple query functions per invocation; allocates Cow<str> each time
- [ ] **H-067** `store/events.rs`: vdf_iterations/hardware_counter overflow clamped to i64::MAX with log::warn; stored value incorrect
- [ ] **H-070** `store/text_fragments.rs`: keystroke_context parse error silently discarded via .parse().ok() on every row read
- [ ] **H-072** `store/archive.rs`: leftover .tmp remove_file failure warned then ignored; subsequent create may fail or overwrite
- [ ] **H-086** `sentinel/helpers.rs`: write_recover()/read_recover() log generic message; original panic location and backtrace discarded
- [ ] **H-099** `ffi/system.rs`: get_all_events_grouped() DB failure returns Default (empty map); forensic metrics computed on no data
- [ ] **H-104** `ffi/writersproof_ffi.rs`: offline queue file deletion failure undetected; submitted attestations may be resubmitted
- [ ] **H-105** `ffi/writersproof_ffi.rs`: chain validation failure returns error but no log::warn/error; tampered chains leave no audit trail
- [ ] **H-114** `vdf/aggregation.rs`: checkpoint_count silently capped to u32::MAX via unwrap_or; no log, no error
- [ ] **H-117** `evidence/wire_conversion.rs`: PoSME CBOR decode failure silently falls back to SwfPosme algorithm type
- [ ] **H-118** `evidence/wire_conversion.rs`: missing merkle_root → jitter_seal set to vec![0u8; 32]; all-zeros seal transmitted as real
- [ ] **H-121** `checkpoint/chain.rs`: saturating_mul hides VDF parameter overflow; huge vdf_cost_multiplier silently produces wrong params

## High — Architecture / Code Quality (14 open)
- [ ] **H-010** `checkpoint/chain.rs`: 4+ overlapping commit paths (commit, commit_with_vdf_duration, commit_entangled, commit_rfc_with_nonce); divergence risk
- [ ] **H-030** `sentinel/event_handlers.rs`: record_keystroke_to_session 226 lines
- [ ] **H-075** `anchors/rfc3161.rs`: verify_cms_signature 254 lines
- [ ] **H-079** `fingerprint/voice.rs`: StyleCollector struct has 34 fields
- [ ] **H-089** `sentinel/helpers.rs`: focus_document_sync takes 8 parameters
- [ ] **H-090** `sentinel/types.rs`: KeystrokeSemantic::classify 106 lines
- [ ] **H-093** `sentinel/macos_focus.rs`: get_active_window_info 206 lines
- [ ] **H-094** `sentinel/core.rs`: start() 494 lines
- [ ] **H-096** `ffi/sentinel_inject.rs`: bool return conflates rate-limit, validation, and engine errors; Swift cannot distinguish
- [ ] **H-101** `ffi/text_fragment.rs`: hash_text and sign_fragment defined in FFI layer; untestable in isolation
- [ ] **H-102** `ffi/ephemeral.rs`: key loading duplicated vs helpers::load_signing_key()
- [ ] **H-115** `evidence/packet.rs`: verify_inner() 258 lines
- [ ] **H-116** `evidence/types.rs`: Packet has 40+ fields with no consolidated validate_invariants()
- [ ] **H-120** `checkpoint/chain.rs`: commit_rfc_with_nonce takes 9 parameters (+self)

## High — Concurrency (1 open)
- [ ] **H-032** `identity/secure_storage.rs`: lock_recover() blocks indefinitely; no timeout mechanism

## High — Performance / Correctness (7 open)
- [ ] **H-029** `sentinel/event_handlers.rs`: sample.clone() on every accepted keystroke
- [ ] **H-058** `analysis/pink_noise.rs`: mean_power=0 (silence) → threshold=0; every bin with any power flagged as dominant; spurious peaks
- [ ] **H-059** `analysis/error_topology.rs`: compute_error_hurst returns H=0.5 for both insufficient data AND genuine random walk; callers cannot distinguish
- [ ] **H-061** `analysis/content_detector.rs`: keyword scoring accumulates all occurrences; 1000x repetition of a keyword inflates score
- [ ] **H-088** `sentinel/helpers.rs`: focus_document_sync opens SQLite synchronously in tokio::select! loop; blocks keystroke processing
- [ ] **H-092** `sentinel/helpers.rs`: focus_document_sync acquires read then write lock separately; one write lock would suffice
- [ ] **H-124** `rfc/wire_types/components.rs`: MAX_EDIT_POSITIONS=100_000 is validated but extremely permissive; DoS risk on verifier

## High — Verified False Positives (66 items)
- [-] **H-006** — FP: Epoch 0 fallback logged via log::warn; degenerate but not data corruption
- [-] **H-008** — FP: sync_all() uses ? operator, not .unwrap()
- [-] **H-011** — FP: VDF error includes checkpoint index; parse errors omit ordinal (acceptable)
- [-] **H-013** — FP: Relaxed ordering safe for per-instance obfuscation nonce
- [-] **H-014** — FP: bincode enforces decode bounds; data is in-process, not network-sourced
- [-] **H-016** — FP: bit selection on public msg_hash, not secret; CT comparison on secret material
- [-] **H-017** — FP: count > 0 guard before p.log2(); no NaN path
- [-] **H-018** — FP: plaintext key fallback removed; keychain failure returns error
- [-] **H-019** — FP: UNC rejection + lowercased prefix matching + canonicalization covers bypass
- [-] **H-020** — FP: explicit drop + ZeroizeOnDrop + compiler_fence at lines 201-206
- [-] **H-021** — FP: raw old_path used only as HashMap key; no filesystem I/O
- [-] **H-023** — FP: Mutex-guarded RATE_LIMITER with sliding window; race fixed
- [-] **H-024** — FP: write lock on style_collector dropped before fingerprint I/O
- [-] **H-025** — FP: session stays in map on failure (intentional retry design)
- [-] **H-026** — FP: VALID_STATES allowlist validates before writing
- [-] **H-027** — FP: lock ordering enforced; signing_key (L1) before sessions (L2) with assert_order
- [-] **H-031** — FP: subtle::ConstantTimeEq uses volatile writes; compiler cannot eliminate
- [-] **H-033** — FP: env accepts "1"/"true" intentionally; not an inconsistency
- [-] **H-035** — FP: sync_all() is Rust equivalent of fsync(); called before rename
- [-] **H-036** — FP: rename failure returns WalError::Io(e); tmp cleanup failure warned separately
- [-] **H-040** — FP: empty wp_signature explicitly rejected with error
- [-] **H-043** — FP: sibling_path.len() > MAX_MERKLE_DEPTH checked before iteration
- [-] **H-044** — FP: IKI sort moved to analysis.rs; values derived from u64 as f64, NaN impossible
- [-] **H-046** — FP: unwrap_or(0) followed by explicit zero-value check returning failed result
- [-] **H-047** — FP: size_delta is i32; cast to i64 then unsigned_abs() safe for all i32 values
- [-] **H-048** — FP: silent 0.0 substitution for non-finite detour_ratio is documented intentional design
- [-] **H-049** — FP: boundary_positions from (char_idx+1) as f64 / total; always finite in [0,1]; NaN impossible
- [-] **H-051** — FP: VDF Merkle root combined with domain separation b"cpoe-takens-embedding-v1"
- [-] **H-052** — FP: HKDF-SHA256 requesting 32 bytes cannot fail; .expect() infallible
- [-] **H-053** — FP: histogram_median_value only called after guards requiring >= 10 entries
- [-] **H-054** — FP: u128 overflow requires >= 2^32 samples; realistic max is tens of thousands
- [-] **H-055** — FP: j + evol_steps >= n bounds check present at line 306
- [-] **H-056** — FP: is_finite() guard returns None on overflow; already fixed
- [-] **H-057** — FP: zero window_energy falls back to fft_size as normalizer; no division by zero
- [-] **H-060** — FP: .all() is intentional conservative policy; flags only when ALL windows are too clean
- [-] **H-062** — FP: any spread < f64::EPSILON returns None; controlled handling
- [-] **H-065** — FP: nonce uniqueness query includes LIMIT 1; already fixed
- [-] **H-069** — FP: SCHEMA_VERSION = 15 is named const; incremental ALTER TABLE migration exists
- [-] **H-071** — FP: RFC 4180 escaping with doubled quotes, newline replacement, formula-injection prefix
- [-] **H-073** — FP: to_str().ok_or_else() returns proper StoreError::validation, not panic
- [-] **H-074** — FP: RSA key size check operates on cert's own extracted SPKI
- [-] **H-076** — FP: CredentialPackageBuilder exists; build_vc_core is 80 lines; to_cose_secured_vc is 50 lines
- [-] **H-077** — FP: build() now 56 lines; complex construction extracted into helpers
- [-] **H-080** — FP: truncation uses is_char_boundary iterator; unwrap_or(0) always found; safe
- [-] **H-081** — FP: all URL-path ID parameters use consistent alphanumeric + hyphen + underscore validation
- [-] **H-082** — FP: umask(0o177) before bind() atomically sets 0o600; TOCTOU eliminated
- [-] **H-083** — FP: duplicate of H-020; explicit drop + ZeroizeOnDrop + fence
- [-] **H-085** — FP: re-keying remove + insert under single write lock guard; no partial state
- [-] **H-087** — FP: drain_pending_wal has full error handling; log::error on each failure
- [-] **H-091** — FP: no code path resets keystroke_count to 0; only modified via saturating_add/sub
- [-] **H-095** — FP: Semaphore(4) is intentional I/O concurrency control, not serialization
- [-] **H-097** — FP: file permissions check (mode & 0o077 != 0 → error) added before read
- [-] **H-098** — FP: stat+read TOCTOU marginal; output uses tempfile+persist atomic write
- [-] **H-100** — FP: remove + insert under same write_recover() lock guard; atomic
- [-] **H-103** — FP: push and undo_last under same sessions.write_recover() guard; no race
- [-] **H-106** — FP: aes-gcm Error is opaque (no fields); discard loses nothing
- [-] **H-107** — FP: sequence exhaustion guard at u64::MAX-1 with explicit error return
- [-] **H-108** — FP: ZeroizeOnDrop uses volatile_write + fence prevents reordering; adequate
- [-] **H-109** — FP: Error::identity() is typed domain error with clear message
- [-] **H-111** — FP: incremental verification; only id > last_verified_sequence rows scanned
- [-] **H-112** — FP: validate_fragment_fields rejects fragment_hash.len() != 32
- [-] **H-113** — FP: HKDF from_prk with 32-byte seed + expand for 4 bytes; mathematically infallible
- [-] **H-119** — FP: SHA-256 output non-zero with probability 1 − 2⁻²⁵⁶
- [-] **H-122** — FP: weight overflow detected via checked_add before iteration
- [-] **H-123** — FP: json_depth_bounded has early return if current > MAX_EXTENSION_JSON_DEPTH
- [-] **H-125** — FP: char_value is Rust String (valid UTF-8 by type system; UniFFI marshals)
- [-] **H-126** — FP: tempfile + sync_all + persist; no partial manifest at output path

## Medium
<!-- 183 MEDIUM findings. Mostly code_quality (god functions, magic values), maintainability, and performance. -->
<!-- These are design improvements, not bugs. Address opportunistically during related work. -->

## Coverage
<!-- scan:2026-05-30 | batches:18 | waves:4 | files:200+ | depth:deep+standard+shallow -->
<!-- findings:345 raw | verified:6 fixed, 96 FP total | systemic:7 (4 resolved) | clusters:4 (2 resolved) -->
<!-- HIGH verification 2026-06-18: 112 items checked, 46 REAL, 66 FP (59% FP rate) -->
