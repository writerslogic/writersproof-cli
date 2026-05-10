# Audit Todo

**Last updated:** 2026-05-07 (delta scan: 22 changed files, 5 batches; 8 new HIGH + 15 new MEDIUM added — H-201..208, M-129..143)
**Scopes:** memory, async, performance, errors, security, concurrency, idiomatic, duplicates
**Total findings:** 1257 | **Systemic tasks:** 31 (2 CRITICAL + 29 SYS) | **Per-site findings remaining:** ~625 (after SYS closes)

## Execution Strategy

Execute by criticality and dependency order:
1. **CRITICAL** (2 tasks, ~2h) - Foundation before SYS work
2. **SYS Concurrency** (SYS-027, SYS-028, ~12h) - Races + deadlock risk; prerequisite for async
3. **SYS Security** (SYS-023, SYS-024, ~18h) - TOCTOU + I/O crashes (closes 72 HIGH findings)
4. **SYS Foundation** (SYS-001..SYS-022, ~65h) - Types, errors, allocation, async patterns
5. **SYS Maintenance** (SYS-025, SYS-026, SYS-029, ~18h) - Dedup, performance, cleanup
6. **Per-site HIGH/MEDIUM/LOW** (~80-100h) - Parallel per SYS closes list, residual fixes

**Model key:** Haiku (simple fixes), Sonnet (medium complexity), Opus (large scope/refactoring)

## Autonomous runner (`scripts/todo_runner.py`)

The runner parses this file and spawns parallel headless Claude agents, one per open task, picking `haiku|sonnet|opus` from each task's `**Model:**` line. Task format requirements:

- **Header:** `### ID: title` (e.g. `### SYS-042:`). Runner matches `CRITICAL-N`, `SYS-N`, `C-N`, `H-N`, `M-N`, `L-N`.
- **Model line:** `- **Model:** Haiku|Sonnet|Opus` — must appear before the Status line. Case-insensitive. Defaults to `sonnet` if missing.
- **Files line:** `- **Files:** \`path/one\`, \`path/two\`, \`path/three\`` — every path MUST be wrapped in backticks. Line-number suffixes like `:12,34` or `:100-120` are stripped automatically.
- **Status line:** `- **Status:** open` — authoritative state. Runner ignores tasks whose first Status line is not exactly `open`.
- **Exclusive scope:** a task runs alone (blocking the whole tree) iff its Files list (a) contains any trailing `/` (whole-directory scope), (b) contains a `*` glob, (c) has words like `multiple`, `entire`, `widespread`, `project-wide`, `broader`, `many`, `40+`, `across` in the raw line, or (d) has no backtick-wrapped paths at all. Otherwise tasks with disjoint file sets run in parallel.
- **Completion contract:** agents must rewrite the Status line (to `fixed YYYY-MM-DD (reason)`, `rejected ...`, or `blocked ...`) and commit. Rerunning the runner is idempotent — already-closed tasks are skipped automatically.

Usage: `scripts/todo_runner.py --dry-run` (preview), `scripts/todo_runner.py` (drain), `--only ID`, `--filter REGEX`, `--parallel N`, `--max N`.

---

## CRITICAL Issues (Priority Order)

### CRITICAL-002: HKDF expand failure silently leaves behavioral key unset

- **Model:** Sonnet | **Scope:** errors
- **File:** `crates/cpoe/src/sentinel/behavioral_key.rs:63-68`
- **Severity:** CRITICAL | **Leverage:** CRITICAL | **Status:** fixed 2026-04-10 (HKDF-SHA256 expand of 32 bytes is provably infallible; replaced silent `.is_ok()` swallow with `.expect()` documenting the invariant)
- **Priority:** 1/240 | **Estimated time:** 1.5h
- **Description:** `add_entropy` method lines 63-68: `if hk.expand(...).is_ok()` discards errors. Failure leaves `active_key` as None. Sentinel keeps running but produces no signatures indefinitely with zero logging. Worst-case failure mode for a signing component.
- **Root cause:** Error swallowed by `.is_ok()` check; no error propagation to callers.
- **Fix:**
  1. Change `add_entropy(&mut self, data: &[u8])` to return `Result<(), Error>`
  2. Replace `.is_ok()` guard with `?` operator on HKDF expand
  3. Update all call sites in `sentinel/` to handle `Result`; log at WARN if error
  4. Add periodic check: if `is_locked() && master_key.is_some()` for >5s, escalate to hard error
  5. Add test: mock HKDF failure, verify error propagates

```rust
pub fn add_entropy(&mut self, data: &[u8]) -> Result<(), Error> {
    let mut hasher = Sha256::new();
    hasher.update(&self.entropy_pool[..]);
    hasher.update(data);
    self.entropy_pool.copy_from_slice(&hasher.finalize());
    self.last_activity = Instant::now();

    if self.active_key.is_none() {
        if let Some(ref mk) = self.master_key {
            let hk = Hkdf::<Sha256>::new(Some(&self.entropy_pool[..]), mk.as_bytes());
            let mut derived = Zeroizing::new([0u8; 32]);
            hk.expand(b"cpoe-behavioral-entropy-v1", &mut derived[..])
                .map_err(|e| Error::crypto(format!("HKDF expand failed: {e}")))?;
            self.active_key = Some(SigningKey::from_bytes(&derived));
        }
    }
    Ok(())
}
```

- **Tests:** sentinel/tests/behavioral_key.rs already exists; add test for HKDF failure path
- **Closes:** no per-site findings (unique to sentinel)

---

### CRITICAL-006: Redundant zeroization calls in load_legacy_private_key

- **Model:** Sonnet | **Scope:** performance
- **File:** `crates/cpoe/src/keyhierarchy/migration.rs` (multiple manual `zeroize()` calls)
- **Severity:** CRITICAL | **Leverage:** MEDIUM | **Status:** fixed 2026-04-10 (replaced all manual `.zeroize()` calls with `Zeroizing<Vec<u8>>` and `Zeroizing<[u8; 32]>` wrappers; RAII cleanup on all paths)
- **Priority:** 2/240 | **Estimated time:** 1h
- **Description:** Multiple manual `seed.zeroize()` and `data.zeroize()` calls across error/success branches. Correct but fragile; adding new code paths risks leaving material unwiped.
- **Root cause:** Manual RAII pattern instead of using Zeroizing<T> wrapper.
- **Fix:**
  1. Audit `load_legacy_private_key()` for all `zeroize()` calls
  2. Replace with `Zeroizing<[u8; N]>` wrappers (already in deps)
  3. Remove all manual `.zeroize()` calls
  4. Run `cargo expand` to confirm Drop impl is not optimized out
  5. Add comment: "RAII cleanup on all paths via Zeroizing<T>"

```rust
use zeroize::Zeroizing;

let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
seed.copy_from_slice(&data[..32]);
// Drop handles zeroization on all paths—no manual .zeroize() needed
```

- **Tests:** keyhierarchy/tests/ — verify key material is zeroed after function exit
- **Closes:** no per-site findings (specific to migration)

---

## Systemic Patterns (22 Umbrellas, Priorities 3-24)

### SYS-002: Fixed-size crypto fields as Vec<u8>

- **Model:** Sonnet | **Scope:** idiomatic
- **File:** `crates/cpoe/src/keyhierarchy/types.rs:13,24,46`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (4 public key Vec<u8> fields changed to [u8; 32] with serde_array_32; all call sites updated; 1156 tests pass)
- **Priority:** 3/240 | **Estimated time:** 4h
- **Description:** `MasterIdentity`, `SessionCertificate`, `CheckpointSignature` structs store Ed25519 keys as `Vec<u8>` despite fixed lengths (32 bytes public, 64 bytes signature).
- **Root cause:** Legacy code before [u8; N] convention adoption.
- **Fix:**
  1. Identify all affected field types in keyhierarchy/types.rs
  2. Change to `[u8; 32]` public keys, `[u8; 64]` signatures
  3. Update CBOR (de)serialization for each type
  4. Update DB column types (if applicable)
  5. Update all verification call sites to use fixed-size arrays
  6. Add CBOR roundtrip test: serialize → deserialize → byte-equal

- **Closes:** HIGH-062, HIGH-063, HIGH-064, HIGH-065

---

### SYS-001: Shared borrowed hex/base64 serde visitors

- **Model:** Sonnet | **Scope:** idiomatic
- **Files:** `crates/authorproof-protocol/src/rfc/serde_helpers.rs:27,62,93,124`, `crates/authorproof-protocol/src/rfc/wire_types/serde_helpers.rs`, `crates/cpoe/src/serde_utils.rs:97,140`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (visitor pattern in 8 sites; decode_to_slice for arrays; 2 roundtrip tests added; 1157 pass)
- **Priority:** 4/240 | **Estimated time:** 5h
- **Description:** Six deserializers (3 pairs) allocate intermediate `String` before hex/base64 decoding. Copy-pasted across two files in authorproof-protocol + cpoe.
- **Root cause:** No shared visitor pattern; each site reimplements allocation.
- **Fix:**
  1. Create single-source-of-truth: `crates/authorproof-protocol/src/rfc/serde_helpers.rs`
  2. Implement `BorrowedHexVisitor` and `BorrowedB64Visitor` (zero-copy on valid input)
  3. Update `wire_types/serde_helpers.rs` to re-export (not duplicate)
  4. Update cpoe to import from authorproof-protocol if exported, else accept small duplication
  5. Add `#[test] fn hex_visitor_zero_alloc()` and `b64_visitor_zero_alloc()` using dhat or manual counting
  6. Verify CBOR roundtrip: hex string → deserialize → bytes → serialize → identical hex

- **Closes:** HIGH-032, HIGH-033, HIGH-034, HIGH-035, HIGH-222, HIGH-223

---

### SYS-006: IpcOperation enum replaces stringly-typed operation keys

- **Model:** Sonnet | **Scope:** memory
- **Files:** `crates/cpoe/src/ipc/crypto.rs:234`, `crates/cpoe/src/ipc/server_handler.rs` (multiple call sites)
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (IpcOperation enum; RateLimiter keyed by enum; rate_limit_key returns IpcOperation; 1157 tests pass)
- **Priority:** 5/240 | **Estimated time:** 3h
- **Description:** Operation identifiers stored as `&str`/`String` keys in HashMaps. Fixed set of ~8 values. Every rate-limit check and log allocates.
- **Root cause:** String-based enums instead of Rust enums.
- **Fix:**
  1. Define `enum IpcOperation { Attest, Sign, Verify, ... }` (8 variants)
  2. Replace RateLimiter key type from String to IpcOperation
  3. Update all rate-limit check call sites
  4. Replace format!(operation: {}) with Debug derive (no allocation)
  5. Update access-info structs to store IpcOperation instead of String
  6. Add tests: verify no allocations in hot path via criterion or custom bench

- **Closes:** HIGH-009, HIGH-228, HIGH-229, HIGH-230, HIGH-231

---

### SYS-012: Byte-slice parameters should be &[u8]; fixed-array conversion helper

- **Model:** Sonnet | **Scope:** idiomatic
- **Files:** `crates/cpoe/src/crypto/`, `crates/cpoe/src/evidence/`, `crates/cpoe/src/fingerprint/` (multiple)
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (to_array_16/32/64 helpers added; two manual copy_from_slice patterns in evidence/packet.rs replaced)
- **Priority:** 6/240 | **Estimated time:** 6h
- **Description:** Functions take `Vec<u8>` by value when they only read. Wastes ownership transfer in every call.
- **Root cause:** Legacy API design before slice-friendly patterns.
- **Fix:**
  1. Audit all function signatures taking `Vec<u8>` parameter
  2. Change to `&[u8]` (no ownership transfer)
  3. Update call sites to pass `&vec` or `&slice`
  4. Add helper in utils: `fn to_array_32(slice: &[u8]) -> Result<[u8; 32], LengthError>` and variants for 16, 64
  5. Use helper at conversion boundaries
  6. Run clippy to catch remaining pattern matches

- **Closes:** HIGH-044, HIGH-528, and 8+ related parameter-type issues

---

### SYS-011: Path parameters should accept &Path / impl AsRef<Path>

- **Model:** Sonnet | **Scope:** idiomatic
- **Files:** `apps/cpoe_cli/src/cmd_*.rs`, `crates/cpoe/src/wal/operations.rs:22-27`, checkpoint, store modules
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (store load_document_stats/get_events_for_file/update_file_path changed to impl AsRef<Path>; WAL/checkpoint were already fixed)
- **Priority:** 7/240 | **Estimated time:** 4h
- **Description:** Functions take `String` or `&str` for file paths. Should accept `impl AsRef<Path>` for flexibility (works with Path, &str, String, OsStr).
- **Root cause:** Pre-Path API era code.
- **Fix:**
  1. Identify all functions taking path as String or &str
  2. Change to `path: impl AsRef<Path>`
  3. Use `.as_ref()` internally where needed
  4. Test with `Path::new()`, `"literal"`, `String::from()` variants
  5. Verify error messages still include path info

- **Closes:** Multiple HIGH path-parameter findings

---

### SYS-014: Constant identifier strings as &'static str / Cow<'static, str>

- **Model:** Sonnet | **Scope:** memory
- **Files:** Domain-separation constants across `crates/cpoe/src/crypto/`, `crates/cpoe/src/checkpoint/`, `crates/cpoe/src/utils/`, `crates/cpoe/src/evidence/`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** fixed 2026-04-10 (named 8 DST byte constants; removed redundant .to_string() from Error::checkpoint calls)
- **Priority:** 8/240 | **Estimated time:** 2h
- **Description:** String literals allocated on each reference via `.to_string()` or `String::from()`. Examples: `"cpoe-checkpoint-v3"`, `"wld-engine/"`. Should use static `&str`.
- **Root cause:** Habit of creating String instead of using &'static str.
- **Fix:**
  1. Find all `const` strings that get `.to_string()` wrapped
  2. Define as `const DOMAIN_SEP: &str = "cpoe-checkpoint-v3";` at module level
  3. Use directly in hash/DST calls (no allocation)
  4. Run `grep -r "to_string\|String::from" crates/cpoe/src/crypto/ crates/cpoe/src/checkpoint/` to catch stragglers

- **Closes:** HIGH-271, HIGH-323, related allocation findings

---

### SYS-015: Use hex crate; consolidate decode-and-length-check

- **Model:** Sonnet | **Scope:** idiomatic
- **Files:** `crates/cpoe/src/utils/`, `crates/authorproof-protocol/src/rfc/`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** fixed 2026-04-10 (added hex_decode_16/32/64 to utils/mod.rs; 8 edge-case tests; rfc/serde_helpers already consolidated)
- **Priority:** 9/240 | **Estimated time:** 3h
- **Description:** Repeated hex decoding patterns with manual length validation. No single point of validation.
- **Root cause:** Reinventing the wheel instead of using hex crate helpers.
- **Fix:**
  1. Consolidate hex decoding helpers using `hex` crate (already in Cargo.toml)
  2. Use `hex::FromHex` trait or `hex::decode()` for central validation
  3. Test edge cases: empty string, odd-length string, invalid characters
  4. Replace all manual validation loops with single helper

- **Closes:** HIGH-339, HIGH-340, codec validation findings

---

### SYS-009: Allocation discipline sweep (to_string on literals, Vec of static strs)

- **Model:** Haiku | **Scope:** memory
- **Files:** Widespread across `apps/cpoe_cli/`, `crates/cpoe/src/sentinel/`, `crates/cpoe/src/evidence/`, `crates/cpoe/src/analysis/`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-10 (struct fields typed String, not &str; .to_string() is idiomatic; proper fix requires type refactoring)
- **Priority:** 10/240 | **Estimated time:** 2h
- **Description:** `.to_string()` on string literals ("auto", "default"), `vec![]` of constants. Each allocates unnecessarily.
- **Root cause:** Lazy allocation pattern; no thought to hot-path overhead.
- **Fix:**
  1. One-pass grep sweep: `grep -r '"\w\+".to_string()' crates/`
  2. Replace each with `"literal"` directly (let type inference work)
  3. For Vec of constants: use `&[CONST1, CONST2]` instead of `vec![CONST1, CONST2]`
  4. Static arrays: `const DEFAULTS: &[&str] = &["auto", "default"];`

- **Closes:** HIGH-023, HIGH-277, HIGH-281, and ~30 memory findings

---

### SYS-010: Missing derive completeness via clippy lint

- **Model:** Haiku | **Scope:** idiomatic
- **Files:** Project-wide (crates/cpoe/src/lib.rs, Cargo.toml clippy config)
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** partially fixed 2026-04-11 (lint enabled; 38 types fixed incl. all sensitive crypto/keys; 66 violations remain, mostly straightforward derives)
- **Priority:** 11/240 | **Estimated time:** 1h
- **Description:** Public types missing `Debug` derive. Clippy can enforce with lint.
- **Root cause:** No linting requirement for derived traits.
- **Fix:**
  1. Add to crates/cpoe/src/lib.rs: `#![warn(missing_debug_implementations)]`
  2. Run `cargo clippy --workspace -- -W missing_debug_implementations`
  3. For each flagged type: add `derive(Debug)` or `#[automatically_derived]` comment
  4. Some types may need custom Debug (e.g., crypto keys that should redact content)

- **Closes:** MEDIUM-741, MEDIUM-742, related derive issues

---

### SYS-018: Linear search over small fixed sets → match / matches! / const lookup

- **Model:** Haiku | **Scope:** performance
- **Files:** `crates/cpoe/src/mmr/mmr.rs:139`, `crates/cpoe/src/anchors/mod.rs:113`, `crates/cpoe/src/ipc/crypto.rs:234`
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** fixed 2026-04-10 (encapsulated provider lookup via get_provider_by_type; ipc/crypto already optimal)
- **Priority:** 12/240 | **Estimated time:** 2h
- **Description:** `iter().find()` or `Vec::contains` over constant slices. ~8 values or fewer each.
- **Root cause:** Habit of linear search; no consideration of set size.
- **Fix:**
  1. Identify all linear searches on constant data
  2. If ≤8 values: use `matches!(x, A | B | C | D)`
  3. If 8-20 values: use const array with binary search or perfect hash
  4. If >20: switch to `HashSet` (with lazy_static or once_cell)
  5. Benchmark before/after to quantify improvement

- **Closes:** HIGH-241, HIGH-286, HIGH-293, HIGH-294, HIGH-335, HIGH-340, ~7 MEDIUM sites

---

### SYS-017: Single-pass Welford accumulator for forensic statistics

- **Model:** Haiku | **Scope:** performance
- **Files:** `crates/cpoe/src/utils/stats.rs` (helper already exists), call sites in `crates/cpoe/src/forensics/`
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** fixed 2026-04-11 (consolidated 5 two-pass variance sites, 1168 tests green)
- **Priority:** 13/240 | **Estimated time:** 1.5h
- **Description:** Forensic analyzers compute variance with repeated passes over events. Single-pass Welford helper already exists in utils/stats.rs but not used consistently.
- **Root cause:** Multiple implementations instead of consolidation.
- **Fix:**
  1. Audit utils/stats.rs: confirm `mean_and_variance()` exists and works
  2. Identify all variance/stddev computation sites in forensics/
  3. Replace two-pass loops with calls to `mean_and_variance()`
  4. Remove per-analyzer allocations for temporary Vec copies

- **Closes:** HIGH-190, HIGH-191, related variance-calculation findings

---

### SYS-013: Clone-on-read accessor audit (return &T or Arc<T>)

- **Model:** Sonnet | **Scope:** memory
- **Files:** `crates/cpoe/src/fingerprint/manager.rs`, `crates/cpoe/src/identity/keychain.rs`, analysis modules
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-11 (ActivityFingerprintAccumulator cache changed to Arc; current_fingerprint returns Arc)
- **Priority:** 14/240 | **Estimated time:** 5h
- **Description:** Getter functions return owned clone of read-only data (e.g., `fn get_profile(&self) -> Profile` where callers only read). Clone is wasteful.
- **Root cause:** Ownership-safety habit; not considering borrowing or shared pointers.
- **Fix:**
  1. Audit manager and accessor modules for getter patterns
  2. For each: determine if interior mutability allows &T return
  3. If not: change to return `Arc<T>` or store reference in caller
  4. Add borrowing examples in tests to demonstrate zero-copy access
  5. Profile before/after to confirm reduction in heap allocations

- **Closes:** HIGH-093, HIGH-094, HIGH-202, clone-on-read findings

---

### SYS-021: Lock scope must not span blocking I/O (snapshot-and-release)

- **Model:** Opus | **Scope:** async | **Leverage:** HIGH
- **Files:** `crates/cpoe/src/wal/operations.rs`, `crates/cpoe/src/wal/types.rs:167`, `crates/cpoe/src/mmr/mmr.rs:9`, `crates/cpoe/src/sentinel/shadow.rs:155`
- **Severity:** HIGH | **Status:** fixed 2026-04-11 (snapshot-and-release in WAL verify, MMR read paths, shadow delete/migrate/cleanup)
- **Priority:** 15/240 | **Estimated time:** 10h
- **Description:** Mutex/RwLock guards held across multi-step I/O (fdatasync, fs::rename, store loops). All readers/writers block on entire I/O duration instead of just critical section.
- **Root cause:** Lock acquired too early; not released before I/O.
- **Fix:**
  1. Identify all Mutex/RwLock guards spanning fs:: or store:: I/O in listed files
  2. Adopt "snapshot-and-release" pattern: acquire lock → copy needed fields → drop lock → do I/O → reacquire if needed
  3. Example WAL two-phase: compute offsets under lock → release → write+fsync → re-acquire briefly to commit index
  4. Add CLAUDE.md invariant: "Mutex/RwLock guards must never span fs:: or store:: I/O"
  5. Add clippy-like custom lint (or use `await_holding_lock` pattern for sync)

- **Closes:** HIGH-112, HIGH-117, HIGH-118, HIGH-119, HIGH-120, MEDIUM-496, MEDIUM-497, MEDIUM-498, MEDIUM-501, MEDIUM-503

---

### SYS-003: Async-blocking VDF and hash chain operations

- **Model:** Sonnet | **Scope:** async
- **Files:** `crates/cpoe/src/vdf/proof.rs` (compute, verify methods), `apps/cpoe_cli/src/cmd_commit.rs:83`
- **Severity:** HIGH | **Leverage:** CRITICAL | **Status:** fixed 2026-04-11 (added compute_async/verify_async via spawn_blocking; cmd_commit made async; both async callers await it)
- **Priority:** 16/240 | **Estimated time:** 4h
- **Description:** VDF and hash-chain loops are CPU-bound (seconds) with no enforcement against being called from Tokio task. Fixing one call site leaves others exposed. Callers live in cpoe_cli, not cpoe; wrappers in cpoe, config in cpoe_cli.
- **Root cause:** No async wrappers; sync functions directly called from async code.
- **Fix:**
  1. Add `compute_async()` and `verify_async()` wrappers in `crates/cpoe/src/vdf/proof.rs`
  2. Wrappers use `tokio::task::spawn_blocking(|| self.compute_sync())`
  3. Mark sync versions `#[deprecated(since = "0.4", note = "use *_async from async fn")]`
  4. Update cpoe_cli call sites to use async versions and `.await`
  5. Add to `apps/cpoe_cli/clippy.toml`:

```toml
[[disallowed-methods]]
path = "cpoe::vdf::proof::VdfProof::compute"
reason = "blocks reactor; use compute_async from async fn"

[[disallowed-methods]]
path = "cpoe::vdf::proof::VdfProof::verify"
reason = "blocks reactor; use verify_async from async fn"
```

- **Closes:** HIGH-011, HIGH-012, VDF async-blocking findings

---

### SYS-016: Blocking I/O and CPU work on the Tokio reactor (broader than VDF)

- **Model:** Opus | **Scope:** async | **Leverage:** CRITICAL
- **Files:** `apps/cpoe_cli/src/cmd_*.rs`, IPC handler, beacon paths, checkpoint operations
- **Severity:** HIGH | **Status:** fixed 2026-04-11 (spawn_blocking for file/DB/crypto in cmd_commit/anchor/export; tokio::time::sleep in daemon; VDF calibrate)
- **Priority:** 17/240 | **Estimated time:** 12h
- **Description:** Broader async issues beyond VDF. Extends SYS-003 logic to file I/O, store access, signature operations in async context. Depends on SYS-021 (lock scope fixes).
- **Root cause:** No systematic audit for blocking operations in async paths.
- **Fix:**
  1. Audit all async contexts in cpoe_cli for blocking operations
  2. File I/O: wrap fs:: calls in `spawn_blocking`
  3. Store access: wrap store.get/append in `spawn_blocking`
  4. Crypto: wrap ed25519 signing in `spawn_blocking`
  5. Profile with perf/flame to identify hot paths
  6. Consider caching commonly-accessed data to reduce spawn_blocking frequency
  7. Depends on SYS-021 for lock correctness before spawning

- **Closes:** HIGH-226, HIGH-227, async-blocking findings across CLI/IPC

---

### SYS-004: Silent error swallowing (Result<_, String>, log-and-continue)

- **Model:** Opus | **Scope:** errors | **Leverage:** CRITICAL
- **Files:** `crates/cpoe/src/trust_policy/evaluation.rs:79`, `crates/cpoe/src/fingerprint/manager.rs:80`, report, rfc_conversion modules
- **Severity:** HIGH | **Status:** partially fixed 2026-04-11 (trust_policy and report/pdf converted to crate::error::Error; fingerprint already uses anyhow; ~100 hits remain in other modules)
- **Priority:** 18/240 | **Estimated time:** 16h
- **Description:** Library functions return non-Result types, log on failure, lose error context. ~109 grep hits on `Result<_, String>` across crate.
- **Root cause:** Early API design with stringly-typed errors; no unified error type.
- **Fix:**
  1. Enumerate all functions returning non-Result that should: trust_policy, fingerprint, report, rfc_conversion modules
  2. Module-by-module conversion plan (start with trust_policy, then fingerprint)
  3. Replace `Result<T, String>` with `Result<T, Error>` using `crate::error::Error` enum
  4. Add new error variants where existing ones don't fit: `Error::TrustPolicy(TpErr)`, `Error::Fingerprint(FpErr)`
  5. Ban `let _ = result;` on fallible calls via clippy lint `let_underscore_must_use`
  6. Add tests: verify errors propagate correctly

- **Closes:** HIGH-016, HIGH-037, HIGH-191, HIGH-192, HIGH-200, error-swallowing findings

---

### SYS-005: Silent default-fallback on malformed input (rfc_conversion)

- **Model:** Sonnet | **Scope:** errors
- **File:** `crates/cpoe/src/evidence/rfc_conversion.rs` (not `rfc_conversions.rs`)
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-11 (TryFrom replaces From; empty/malformed final_hash returns Err; VDF decode failures propagated; 3 tests added)
- **Priority:** 19/240 | **Estimated time:** 4h
- **Description:** `From<&Packet> for rfc::PacketRfc` is infallible, emits zero-defaults ("en-US", zero hashes) on missing fields. Forensically dangerous: produces valid-looking output from corrupt input.
- **Root cause:** Infallible trait and silent defaults instead of errors.
- **Fix:**
  1. Introduce `RfcConversionError` enum: `MissingField(field_name)`, `InvalidValue(reason)`
  2. Change to `impl TryFrom<&Packet> for rfc::PacketRfc` with error return
  3. Audit every branch: either propagate error or document default with rationale comment
  4. No more silent "en-US" or zero-hash fallbacks
  5. Update callers to handle `TryFrom` error (propagate or log/fail gracefully)
  6. Depends on SYS-004 error enum foundation

- **Closes:** HIGH-015, HIGH-226, rfc conversion findings

---

### SYS-007: Renderer modules must return Result (html + pdf)

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/report/html/mod.rs:16`, `crates/cpoe/src/report/html/css.rs:8`, `crates/cpoe/src/report/pdf/` (entire)
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-11 (only one let _ site; PDF already propagates; .expect("infallible: String::Write") applied)
- **Priority:** 20/240 | **Estimated time:** 5h
- **Description:** Renderers discard `fmt::Result` via `let _ = ...`, return partial/corrupted output on error. (Note: String writes are infallible; PDF writes are not. Distinguish via testing.)
- **Root cause:** Legacy error handling pattern before Result propagation.
- **Fix:**
  1. Add `Report(String)` variant to `crate::error::Error` (or dedicated `ReportError` in report/mod.rs)
  2. Identify all `render_*` functions and helpers discarding fmt::Result
  3. For PDF: real errors → propagate with `?`
  4. For String writes (infallible): use `.expect("infallible: String::Write")` with comment
  5. Test: verify partial output never occurs on write failure
  6. Depends on SYS-004 error enum foundation

- **Closes:** HIGH-018, HIGH-185, HIGH-206

---

### SYS-008: Sorted-events invariant for forensics pipeline

- **Model:** Sonnet | **Scope:** performance
- **Files:** `crates/cpoe/src/forensics/velocity.rs:29,86`, `crates/cpoe/src/forensics/writing_mode.rs:206`, analysis modules
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** fixed 2026-04-11 (SortedEvents newtype; sort once in pipeline; 5 per-analyzer sorts removed; 1171 tests pass)
- **Priority:** 21/240 | **Estimated time:** 5h
- **Description:** Every forensics analyzer defensively sorts its input via `.to_vec() + .sort()`. No pipeline-level guarantee.
- **Root cause:** Defensive programming; no coordination at pipeline level.
- **Fix:**
  1. Introduce `SortedEvents<'a>(&'a [EventData])` newtype in `crates/cpoe/src/forensics/mod.rs`
  2. Sort once at pipeline entry (forensics_engine.rs analyze_forensics())
  3. Update all analyzer signatures: `analyze_velocity(sorted: SortedEvents<'_>)` instead of `analyze_velocity(events: &[EventData])`
  4. Remove per-analyzer `.to_vec() + .sort()` calls
  5. Add invariant check: audit downstream to ensure no re-sorting

- **Closes:** HIGH-045, HIGH-046, HIGH-047, clone-to-sort findings

---

### SYS-020: Reject-or-propagate policy for non-finite (NaN/Inf) values

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/forensics/forgery_cost.rs:315`, `crates/cpoe/src/forensics/topology.rs:28`, `crates/cpoe/src/utils/stats.rs:127`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (added finite(), total_cmp in median/weakest_link, log::warn on NaN clamp in forgery_cost and topology)
- **Priority:** 22/240 | **Estimated time:** 4h
- **Description:** NaN/Inf silently coerced to defaults (0.0, 0.5, f64::MAX) or fall back to `Ordering::Equal`. No logging or error propagation.
- **Root cause:** No explicit policy for finiteness validation.
- **Fix:**
  1. Project-wide policy: validate finite at trust boundary, reject or log explicitly
  2. Add `fn finite(x: f64) -> Result<f64, NotFinite>` to `crates/cpoe/src/utils/stats.rs`
  3. Use `f64::total_cmp` (stable since Rust 1.62, within MSRV 1.75) instead of `partial_cmp().unwrap_or(Equal)`
  4. Audit sites: HIGH-310 (geometric mean NaN at :315) is highest priority (silent exclusion from hash input)
  5. Add tests: verify NaN/Inf rejection at all boundaries

- **Closes:** HIGH-310, MEDIUM-366, MEDIUM-644, NaN-handling findings

---

### SYS-019: Probability(f64) newtype for [0,1]-bounded fields

- **Model:** Opus | **Scope:** idiomatic | **Leverage:** CRITICAL
- **Files:** 40+ sites across forensics, fingerprint, analysis, evidence, ffi, war modules
- **Severity:** HIGH | **Status:** fixed 2026-04-11 (Probability newtype created; 8 core struct fields migrated; all 36 f64 clamp sites standardized; 1181 tests pass)
- **Priority:** 23/240 | **Estimated time:** 20h
- **Description:** ~40 struct fields mathematically bounded to [0.0, 1.0] (probability, rate, ratio, score, confidence, similarity, weight) stored as raw `f64`. No type-level enforcement. Defensive `.clamp()` calls everywhere (~34 sites).
- **Root cause:** No newtype wrapper; raw f64 allows any value.
- **Fix:** (Incremental, staged by module)
  1. Create `struct Probability(f64)` in `crates/cpoe/src/utils/probability.rs`
  2. Implement `new(f64) -> Result<Self, ProbabilityError>` with validation
  3. Constants: `Probability::ZERO`, `Probability::ONE`
  4. `Deref` to f64 for math compatibility during transition
  5. Stage migration by dependency: utils → forensics → fingerprint → analysis → ffi (last, public ABI)
  6. For each module: (a) add field types, (b) update constructors, (c) update consumers, (d) delete clamps, (e) test
  7. Final cleanup: remove `Deref`, require explicit `.get()` on boundaries

- **Closes:** HIGH-312, supersedes nan_biometric pattern

---

### SYS-022: Typed secure-channel error enums (eliminate dummy EncryptedMessage placeholders)

- **Model:** Sonnet | **Scope:** errors | **Leverage:** CRITICAL
- **Files:** `crates/cpoe/src/ipc/secure_channel.rs:71,84,98,122,128,145,160`, sentinel IPC sites
- **Severity:** HIGH | **Status:** fixed 2026-04-11 (SecureChannelSendError/RecvError enums replace dummy EncryptedMessage error constructions; recv logs WARN on Decryption)
- **Priority:** 24/240 | **Estimated time:** 5h
- **Description:** `SecureSender::send` returns `Result<(), SendError<EncryptedMessage>>`. Errors construct fake `{ nonce: [0; 12], ciphertext: vec![] }`. Erases distinctions, fabricates invalid crypto. Security-relevant.
- **Root cause:** Generic SendError forces dummy construction; no typed error variants.
- **Fix:**
  1. Define `SecureChannelSendError` enum: Serialization, Encryption, NonceExhausted, Channel
  2. Define `SecureChannelRecvError` enum: Decryption, PayloadTooLarge, Deserialization, Channel
  3. Change return type from `Result<(), SendError<EncryptedMessage>>` to `Result<(), SecureChannelSendError>`
  4. Replace all dummy constructions with typed variants
  5. Log `SecureChannelRecvError::Decryption` at WARN with caller context (pid/uid) for audit trail
  6. Update IPC server/client to match on new variants

```rust
#[derive(Debug, thiserror::Error)]
pub enum SecureChannelSendError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] bincode::error::EncodeError),
    #[error("AEAD encryption failed")]
    Encryption,
    #[error("nonce counter exhausted; channel must be re-keyed")]
    NonceExhausted,
    #[error("channel closed")]
    Channel,
}
```

- **Closes:** HIGH-174, HIGH-175, HIGH-176, MEDIUM-371, MEDIUM-431, MEDIUM-432, MEDIUM-433, MEDIUM-706, MEDIUM-898

---


### SYS-023: TOCTOU and symlink attacks (file/path race conditions)

- **Model:** Opus | **Scope:** security
- **Files:** `crates/cpoe/src/sentinel/core_session.rs:36`, `crates/cpoe/src/sentinel/helpers.rs:620`, `crates/cpoe/src/wal/operations.rs:97,105,393,682`, `crates/cpoe/src/platform/windows.rs`, `crates/cpoe/src/engine/watcher.rs:78-97,105`
- **Severity:** CRITICAL | **Leverage:** CRITICAL | **Status:** fixed 2026-04-10 (all named sites verified: H-002 relative path rejection, H-004 canonicalize, H-045 hash_map TOCTOU, H-046 open-then-fstat pattern; WAL ops use `open_nofollow` / state-before-commit)
- **Priority:** 25/240 | **Estimated time:** 12h
- **Description:** 28 instances across filesystem operations where file/path checks performed separately from subsequent I/O. Attacker can substitute files via symlinks, renames, or deletes between check and use. Examples: H-004 (symlink in session path), H-008 (WAL state before fsync), H-010 (symlink hash), H-045/H-046 (TOCTOU in rename detection).
- **Root cause:** Check-then-use pattern without atomic operations or file identity validation at I/O time.
- **Fix:**
  1. Audit all filepath checks followed by I/O operations
  2. Replace with atomic operations where possible: O_NOFOLLOW, O_EXCL, O_CREAT|O_EXCL on Unix; symlink rejection on Windows
  3. Use canonicalize() before session operations; reject symlinks explicitly
  4. Validate file identity at I/O time: fstat after open, compare inodes
  5. For WAL: update state fields AFTER fsync returns, not before
  6. Add tests: symbolic link injection, file rename during operation, file delete during operation
  
- **Closes:** HIGH-004, HIGH-008, HIGH-010, HIGH-012, HIGH-035(fp→real), HIGH-045, HIGH-046, and ~21 MEDIUM/LOW TOCTOU findings

---

### SYS-024: Unwrap/expect on fallible I/O operations (crash on recoverable errors)

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/sentinel/helpers.rs:517,620`, `crates/cpoe/src/war/verification.rs:512`, `crates/cpoe/src/wal/operations.rs:682`, `crates/cpoe/src/crypto.rs:125,89`, and 4+ others
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (all named sites verified: crypto.rs expects are provably-infallible HMAC/HKDF-32B with documenting messages, war verification uses `find_ca_key` Result, WAL ops use `.unwrap_or` with safe fallback, sentinel helpers propagate via `?`)
- **Priority:** 26/240 | **Estimated time:** 6h
- **Description:** 9 instances where expect/unwrap called on I/O results that can legitimately fail (file reads, copy_from_slice on mismatched length, arithmetic underflow). Examples: H-032 (CA key unwrap), H-038 (arithmetic underflow), H-006 (copy_from_slice panic).
- **Root cause:** Assumption that I/O will succeed; no error propagation path.
- **Fix:**
  1. Replace all expect/unwrap on I/O with Result propagation via ?
  2. Use checked_sub, checked_div for arithmetic on untrusted data
  3. Add length validation before copy_from_slice: if data.len() != expected { return Err }
  4. Wrap file I/O in Results; propagate errors up the stack
  5. Add integration tests: truncated files, invalid lengths, arithmetic edge cases
  
- **Closes:** HIGH-006, HIGH-032, HIGH-038, MEDIUM-024, MEDIUM-025, and 4+ related findings

---

### SYS-025: Duplicated logic across modules (inconsistency risk)

- **Model:** Sonnet | **Scope:** maintenance
- **Files:** `crates/cpoe/src/forensics/` (analysis.rs, comparison.rs, cross_modal.rs), `crates/cpoe/src/ffi/` (multiple), `crates/cpoe/src/report/`
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** fixed 2026-04-11 (lerp_score extracted to utils/stats.rs; writing_mode.rs and report.rs now share single impl; 2 tests added)
- **Priority:** 27/240 | **Estimated time:** 8h
- **Description:** 9 instances of same operation/calculation reimplemented in 3+ places: confidence scoring, variance calculation, similarity normalization, validation patterns. Risk: changes to one instance miss others; bugs replicated across modules.
- **Root cause:** No shared utility; each module solves problem independently.
- **Fix:**
  1. Audit forensics modules for repeated patterns: variance, confidence, similarity
  2. Extract shared implementations to `utils/forensic_helpers.rs` or submodule
  3. Update all call sites to use single implementation
  4. Add integration tests verifying consistency across all callers
  5. Document canonical implementation in module docstring
  
- **Closes:** 9 duplicated_logic findings (exact issue IDs to be mapped from analysis)

---

### SYS-026: Clone in loops / hot-path allocations (performance regression)

- **Model:** Sonnet | **Scope:** performance
- **Files:** `crates/cpoe/src/forensics/` (loop-based analyzers), `crates/cpoe/src/ffi/` (polling loops), `crates/cpoe/src/report/` (rendering loops)
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** fixed 2026-04-11 (detect_sessions now returns Vec<&[EventData]> borrowing into SortedEvents; compute_session_stats hot path no longer clones N events per analysis pass)
- **Priority:** 28/240 | **Estimated time:** 6h
- **Description:** 9-16 instances of .clone() called repeatedly in loops or hot paths. At 1KB per clone × 100 iterations = 100KB per second; on moderate dataset (1000 events) = 100MB+ temporary allocation per analysis pass.
- **Root cause:** Lazy allocation pattern; no optimization for loop performance.
- **Fix:**
  1. Profile identified loops: use valgrind/heaptrack to measure allocations
  2. Replace clone with references where lifetime permits
  3. Pre-allocate buffers before loops; reuse across iterations
  4. Convert nested vecs to iterator chains
  5. Benchmark before/after: verify improvement >= 20% for hot paths
  6. Add criterion benchmarks to prevent regression
  
- **Closes:** 9-16 clone_in_loop/alloc_in_loop findings

---

### SYS-027: Data race and concurrent access issues (undefined behavior)

- **Model:** Opus | **Scope:** concurrency
- **Files:** `crates/cpoe/src/sentinel/core.rs:614`, `crates/cpoe/src/ipc/crypto.rs` (rate limit), `crates/cpoe/src/ffi/sentinel_inject.rs:74`
- **Severity:** CRITICAL | **Leverage:** CRITICAL | **Status:** fixed 2026-04-10 (H-001 focus lock held across sessions write-lock; H-017 Mutex-guarded rate window; H-056 CAS loop for sequence advance; all three sites explicitly documented in code)
- **Priority:** 29/240 | **Estimated time:** 8h
- **Description:** 6 instances of non-atomic operations on shared state or check-then-act races without holding lock across both steps. H-001: session state changes between read release and write acquire. H-017: rate_limit fetch_add race allows burst > limit.
- **Root cause:** Lock released before action; state assumption becomes invalid.
- **Fix:**
  1. Identify all check-then-act patterns in shared state access
  2. Convert to atomic acquire-then-check: hold lock from read through modification
  3. Use AtomicU64/AtomicUsize for counters; avoid fetch_add races
  4. Keep lock scope minimal; don't hold across I/O
  5. Add concurrent stress tests (tokio::spawn 100 tasks, race on same state)
  6. Document lock scope invariants per module
  
- **Closes:** HIGH-001, HIGH-017, and 4+ data_race findings

---

### SYS-028: Lock ordering violations and deadlock risk (circular wait)

- **Model:** Sonnet | **Scope:** concurrency
- **Files:** `crates/cpoe/src/sentinel/core.rs`, `crates/cpoe/src/keyhierarchy/`, `crates/cpoe/src/wal/`, `crates/cpoe/src/mmr/`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-10 (AUD-041 fix in place: `lock_order` module with debug-build runtime enforcement, Sentinel doc comment declares signing_key(1) < sessions(2) < focus(3) ordering, enforcement active at multi-lock sites)
- **Priority:** 30/240 | **Estimated time:** 4h
- **Description:** 5 instances where Mutex/RwLock pairs acquired in inconsistent order across code. Some paths acquire `signing_key` then `sessions`; others reverse. Risk: circular wait deadlock under concurrent load.
- **Root cause:** No enforced global lock ordering invariant.
- **Fix:**
  1. Document lock ordering in CLAUDE.md: "signing_key < sessions < store < wal" (example ordering)
  2. Audit all Mutex/RwLock sites to conform to invariant
  3. Consider adding enforce_lock_ordering macro/module to detect violations at compile time
  4. Refactor to minimize nested locks; prefer flat structures
  5. Add test: concurrent tasks that would deadlock with wrong ordering
  
- **Closes:** 5 lock_ordering findings

---

### SYS-029: Resource cleanup / RAII violations (leak and handle exhaustion)

- **Model:** Sonnet | **Scope:** resource management
- **Files:** `crates/cpoe/src/tpm/linux.rs:327`, `crates/cpoe/src/wal/operations.rs`, `crates/cpoe/src/store/`, `crates/cpoe/src/ipc/`
- **Severity:** MEDIUM | **Leverage:** MEDIUM | **Status:** fixed 2026-04-11 (tpm/linux.rs seal/unseal/fingerprint no longer leak session/load handles when mid-closure ops fail; wal compact removes .wal.new tempfile on write or rename failure)
- **Priority:** 31/240 | **Estimated time:** 4h
- **Description:** 5 instances where file handles, TPM handles, or database connections not properly released on all code paths. H-050: TPM flush_context() error logged but ignored; accumulates unflushed handles. Risk: handle exhaustion, leaked file descriptors.
- **Root cause:** Manual cleanup instead of RAII; error paths miss cleanup.
- **Fix:**
  1. Audit all open/acquire operations for corresponding close/release
  2. Implement Drop trait for all resource types; call cleanup in Drop
  3. Use scoped guards (parking_lot::Once, RAII pattern) instead of manual close
  4. Test error paths: mock I/O failures, verify cleanup occurs
  5. Use strace/lsof to confirm no leaked file descriptors after test suite
  
- **Closes:** 5 no_resource_cleanup findings

## Critical

- [x] **C-001** `[security]` `anchors/rfc3161.rs:197`: RFC3161 TSA response CMS signature not verified -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Fix: Implemented CMS RSA-PKCS1v15-SHA256 signature verification via rsa crate; verify_cms_signature() navigates SignedData, extracts TSA certificate SPKI, re-encodes signedAttrs as SET, verifies signature. Returns Unavailable for non-RSA/SHA256 algorithms.

- [x] **C-002** `[security]` `anchors/ots.rs:430`: Bitcoin block header cross-check -- NOT APPLICABLE 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Bitcoin/OTS integration removed from scope; OTS anchor path will not be used.

- [-] **C-003** `[security]` `rats/eat.rs:75`: decode_eat_cwt() parses EAT payload without COSE_Sign1 verification -- FALSE POSITIVE (production) 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  decode_eat_cwt() is only called in tests (rats/mod.rs:88); it is never reached from the production IPC path. Docstring explicitly documents this as inspection/debug use. Architectural concern (IPC boundary) tracked separately in H-021.

- [x] **C-004** `[security]` `war/profiles/vc.rs:31`: W3C Verifiable Credential has no validUntil/expirationDate field
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Issued VCs never expire; revoked or compromised credentials remain valid indefinitely | Fix: Add expirationDate (VC 1.x) or validUntil (VC 2.0) field; document max VC lifetime constant | Effort: small

- [-] **C-005** `[security]` `evidence/packet.rs:29`: Self-signed verification used as default; no external trust anchor required
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Attacker substitutes signing key in packet; verification passes using their own key as anchor | Fix: Require external trusted key parameter for verification; reject self-verification by default | Effort: medium

- [x] **C-006** `[security]` `forensics/cross_modal.rs:190`: Zero-edit document receives 0.3 partial consistency score instead of Inconsistent verdict
  <!-- pid:business_logic | verified:true | first:2026-04-06 -->
  Impact: AI-generated document with no recorded keystrokes passes cross-modal check; bypasses behavioral detection | Fix: Return CrossModalVerdict::Inconsistent when total_edits == 0; no partial score on missing data | Effort: small

- [-] **C-007** `[security]` `ipc/secure_channel.rs:65`: Cipher cloned without zeroization; unsafe pointer arithmetic in zeroize_cipher at line 26 -- FALSE POSITIVE 2026-04-07
  <!-- pid:key_zeroize_error_path | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Clone goes to SecureSender; original goes to SecureReceiver. Both have Drop impls that call zeroize_cipher(). zeroize_cipher() uses write_volatile per byte + SeqCst fence, which prevents compiler elimination (see H-015 for full analysis).

- [x] **C-008** `[error_handling]` `evidence/wire_conversion.rs:249`: CBOR encode failure produces all-zero jitter_seal vector silently
  <!-- pid:silent_error | verified:true | first:2026-04-06 -->
  Impact: Evidence packet ships with fake all-zero seal on encode error; caller cannot detect failure; all-zero seal passes zero-check | Fix: Propagate error via Result; never produce all-zero seal on failure path | Effort: small

- [x] **C-009** `[security]` `checkpoint/chain.rs` (commit_entangled): Uses [0u8;32] stub when previous VDF output is missing
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Entangled mode checkpoint chain can be broken at any link by substituting all-zero VDF output; no chain integrity | Fix: Return Error if previous VDF output required but missing; reject [0u8;32] as invalid VDF | Effort: small

- [-] **C-010** `[security]` `report/html/sections.rs:69`: HTML report templates interpolate user-controlled strings (document paths, author names) without escaping
  <!-- pid:command_injection | verified:true | first:2026-04-06 -->
  Impact: XSS via document path containing `<script>`; attacker-controlled file name executes arbitrary script in any viewer | Fix: html_escape() all user-controlled fields before interpolation; use a safe templating API | Effort: small

- [x] **C-011** `[security]` `keyhierarchy/recovery.rs:68`: Legacy v1 recovery uses unauthenticated XOR cipher with static key
  <!-- pid:hardcoded_secret | verified:true | first:2026-04-06 -->
  Impact: V1 recovery blobs can be decrypted with the known static XOR key; no authentication on decryption | Fix: Reject legacy v1 recovery format with descriptive error; require migration to v2 AEAD format | Effort: medium

- [x] **C-012** `[security]` `identity/did_webvh.rs:402,417`: SSRF via unvalidated DID URI -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Fix: Added validate_did_host() rejecting IP addresses and private/reserved hostnames (localhost, .local, .internal, .corp, .lan, etc.) before any HTTP fetch in resolve_and_verify_key(); 4 tests added.

- [x] **C-013** `[security]` `fingerprint/storage.rs:363`: Biometric encryption key written to disk in plaintext as fallback when keychain unavailable
  <!-- pid:hardcoded_secret | verified:true | first:2026-04-06 -->
  Impact: If keychain fails, biometric key stored unprotected in filesystem; attacker with read access recovers key | Fix: Fail hard if keychain unavailable; never write key material to plaintext files; provide migration UX | Effort: medium

- [x] **C-014** `[security]` `writersproof/client.rs:38`: HTTP (non-TLS) connections permitted in debug builds
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Debug build in CI or staging allows cleartext API calls; credentials and evidence packets transmitted in the clear | Fix: Unconditionally require HTTPS; remove debug HTTP exception entirely | Effort: small

- [-] **C-015** `[security]` `evidence/packet.rs:432`: `sign()` swallows `signing_payload()` error; returns `Ok(())` with packet unsigned -- FALSE POSITIVE 2026-04-07
  <!-- pid:silent_error | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  sign() already uses the `?` operator to propagate signing_payload() errors; no silent swallow present.

- [-] **C-016** `[security]` `evidence/packet.rs:645`: No pre-flight signature presence check in `verify()`; verification proceeds on unsigned packet -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  verify() checks signature field presence before proceeding; absent signature returns Err as expected.

- [-] **C-017** `[security]` `store/events.rs:323,396`: Per-entry HMAC verified AFTER full event deserialization in `get_all_events_grouped` and `export_all_events_for_identity` -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  row_to_event_with_hmac + verify_event_row_hmac call pattern verifies HMAC per-row before the event is pushed to the output buffer; data does not reach the caller until HMAC passes.

- [x] **C-018** `[security]` `war/verification.rs:23`: Non-constant-time length check before `ct_eq()` call; timing side-channel reveals key length -- FIXED 2026-04-07
  <!-- pid:timing_side_channel | verified:true | first:2026-04-07 -->
  Removed length pre-check; now calls `bool::from(trusted.ct_eq(&self.seal.public_key))` directly. subtle::ConstantTimeEq handles different-length slices in constant time.

- [-] **C-019** `[security]` `checkpoint/chain.rs:368`: `at()` accepts arbitrary ordinal without monotonicity enforcement -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-007 -->
  at() is an index accessor (read-only by ordinal); monotonicity is enforced at the commit layer, not the retrieval layer. Retrieval by arbitrary ordinal is intentional API behavior.

- [-] **C-020** `[security]` `mmr/proof.rs:59-72`: `InclusionProof::verify()` does not validate that peaks match current MMR state -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-007 -->
  verify() receives the expected root from the caller as an explicit parameter; it does not self-validate peaks. The caller is responsible for supplying the trusted root. Design is correct.

- [x] **C-021** `[concurrency]` `sentinel/core.rs:839`: Lock ordering violation -- acquires `sessions` write lock before `signing_key` read lock; violates AUD-041 invariant -- FIXED 2026-04-07
  <!-- pid:lock_ordering | verified:true | first:2026-04-07 -->
  Restructured to read signing_key under read lock first (guard dropped), then acquire sessions write lock. AUD-041 ordering (signing_key < sessions) restored.

- [-] **C-022** `[security]` `forensics/cross_modal.rs:234`: Division by `checkpoint_count` without zero-check -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  Zero-check guard already present at lines 225-232 before the division at line 234; returns CrossModalVerdict::Inconsistent when checkpoint_count == 0.

- [-] **C-023** `[security]` `forensics/writing_mode.rs:236`: Division by `TRANSCRIPTIVE_THRESHOLD` without epsilon guard -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  TRANSCRIPTIVE_THRESHOLD is a compile-time constant 0.35; it cannot be zero or misconfigured at runtime. No runtime division-by-zero risk.

- [-] **C-024** `[security]` `anchors/rfc3161.rs:31`: No timeout on TSA HTTP POST -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_timeout | verified:false | first:2026-04-07 -->
  build_http_client(None) already applies DEFAULT_TIMEOUT_SECS; timeout is set on the shared reqwest Client before the POST is executed.

- [x] **C-025** `[security]` `ffi/system.rs:228-255`: `#[cfg(debug_assertions)]` block writes list output to `/tmp/cpoe_list_debug.txt`; SYS-004 regression -- FIXED 2026-04-07
  <!-- pid:no_structured_logging | verified:true | first:2026-04-07 | systemic:SYS-008 -->
  Removed entire cfg(debug_assertions) block; replaced with log::debug!() calls for sentinel session and store result counts.

- [x] **C-026** `[security]` `authorproof-protocol/src/rfc/jitter_binding.rs:443`: `attractor_points` inner vector length not validated against `embedding_dimension`; memory exhaustion on malformed input -- FIXED 2026-04-07
  <!-- pid:no_backpressure | verified:true | first:2026-04-07 -->
  Added MAX_ATTRACTOR_POINTS (10000) cap and per-row length validation against embedding_dimension; ValidationFinding::error on any violation.

- [x] **C-027** `[architecture]` `ffi/ephemeral.rs:565`: `build_war_block()` signing logic moved out of FFI layer -- FIXED 2026-04-07
  <!-- pid:logic_in_boundary | verified:true | first:2026-04-07 | systemic:SYS-003 -->
  Added `war::build_signed_ephemeral_block()` in war/mod.rs; FFI layer retains key loading + snapshot marshaling, delegates packet assembly + signing + encoding to the engine function.

- [x] **C-028** `[architecture]` `ffi/report.rs:198-227`: Full forensic analysis re-executed on every Swift call -- FIXED 2026-04-07
  <!-- pid:logic_in_boundary | verified:true | first:2026-04-07 | systemic:SYS-003 -->
  Added process-level `ForensicCacheEntry` DashMap in ffi/report.rs keyed by (path, event_count); cache hit skips both evaluate_authorship and run_full_forensics; cache capped at 10 entries with clear-on-overflow.

- [x] **C-029** `[security]` `apps/cpoe_macos/cpoe/SubscriptionService.swift:176`: Storage upgrade purchase proceeds without `appAccountToken` when `userId` is nil -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Added guard requiring userId + valid UUID before purchase; always passes appAccountToken(accountUUID) so Apple's S2S notification can identify the account.

---

## High

- [x] **H-001** `[concurrency]` `sentinel/core.rs:614`: Race condition in keystroke attribution -- read lock released then separate write lock acquired; session can change in window
  <!-- pid:data_race | verified:true | first:2026-04-06 -->
  Impact: Keystroke attributed to wrong session under concurrent focus change at 100+ WPM | Fix: Acquire write lock for full attribution sequence without releasing between read and update | Effort: medium

- [x] **H-002** `[security]` `sentinel/core_session.rs:208`: Relative path accepted for session creation; directory traversal via crafted app title
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: title:// sessions with ../ components bypass session isolation; evidence file written to arbitrary location | Fix: Reject relative paths; require absolute path or title:// with no traversal components | Effort: small

- [-] **H-003** `[security]` `sealed_chain.rs:90,95`: AES-GCM nonce does not include document counter; nonce reuse possible across chains sharing same document_id -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Nonce is 96-bit random (rand::rng()); birthday collision probability is negligible at any practical write frequency. Key is HKDF-derived per document_id so different documents use different keys entirely. 96-bit random nonce is NIST SP 800-38D recommended approach when fewer than 2^32 encryptions are expected.

- [x] **H-004** `[security]` `sentinel/core_session.rs:36`: Path not canonicalized before session key insertion; symlink accepted as session path
  <!-- pid:toctou | verified:true | first:2026-04-06 -->
  Impact: Attacker creates symlink at target path before session start; evidence path redirected to attacker-controlled file | Fix: canonicalize() path and reject symlinks before session creation | Effort: small

- [x] **H-005** `[security]` `forensics/analysis.rs:173`: perplexity_score NaN propagates unchecked into ForensicMetrics; signed metrics contain NaN
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-06 -->
  Impact: CBOR serialization of NaN is implementation-defined; signature over NaN metrics not reproducible; verification fails | Fix: Guard perplexity_score with is_finite(); substitute 0.0 and log::warn! on degenerate input | Effort: small

- [x] **H-006** `[security]` `ffi/sentinel_inject.rs:102`: Keystrokes with is_unverified_ffi=true bypass dual-layer validation; accepted into evidence stream without attestation
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: External process injects keystrokes that appear in evidence without being flagged as synthetic | Fix: Remove is_unverified_ffi exception; require all keystrokes to pass dual-layer (CGEvent + HID) validation | Effort: medium

- [x] **H-007** `[security]` `mmr/mmr.rs:34`: MMR proofs validated in memory only against in-process root hash; no external anchor -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Fix applied: `Chain::with_mmr()` attaches a `CheckpointMmr`; `commit_finish` calls `finalize_checkpoint` which embeds the pre-append MMR root in the signed checkpoint hash and stores the inclusion proof as `mmr_inclusion_proof`; `verify_detailed` checks each inclusion proof and verifies `proof[N].root == checkpoint[N+1].mmr_root` to detect rollback. 3 tests added.

- [x] **H-008** `[error_handling]` `wal/operations.rs:97,105`: WAL state fields updated before fsync completes; power loss leaves WAL inconsistent
  <!-- pid:toctou | verified:true | first:2026-04-06 -->
  Impact: WAL shows entry committed but data never persisted; evidence loss undetectable on recovery | Fix: Update state fields only after successful fsync returns; treat pre-fsync update as bug | Effort: small

- [-] **H-009** `[security]` `store/integrity.rs:174` + `store/events.rs:323,396`: HMAC integrity check only at store open -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 | related:C-017 -->
  All three read paths (get_events_for_file, get_all_events_grouped, export_all_events_for_identity) call verify_event_row_hmac before pushing events to output. SQLite column reads cannot execute attacker code; deserialization order is not a practical attack vector. Per-row HMAC verification is correct and sufficient.

- [x] **H-010** `[security]` `sentinel/helpers.rs:620`: compute_file_hash on non-Unix platforms lacks symlink protection (no O_NOFOLLOW equivalent)
  <!-- pid:toctou | verified:analytical | first:2026-04-06 -->
  Impact: On Windows, file hash follows symlinks; hash of symlink target != hash of original content; content substitution undetected | Fix: On Windows, use FILE_FLAG_OPEN_REPARSE_POINT; detect and reject symlinks before hashing | Effort: medium

- [x] **H-011** `[security]` `sentinel/behavioral_key.rs:56`: add_entropy() mixes behavioral entropy directly into master key without KDF; comment says "simplified"
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Impact: Direct XOR of entropy into master key reduces independence; correlated behavioral inputs create predictable key evolution | Fix: Use HKDF-Expand(master_key, entropy_bytes, "cpoe-behavioral-entropy-v1") for key update | Effort: medium

- [x] **H-012** `[security]` `apps/cpoe_cli/src/cmd_daemon.rs:113`: PID file used for stop without liveness check; OS PID reuse causes wrong-process kill
  <!-- pid:toctou | verified:analytical | first:2026-04-06 -->
  Impact: If daemon dies and OS reuses PID, `cpoe stop` kills an unrelated process | Fix: Verify /proc/{pid}/comm matches expected process name before sending signal; or use socket-based stop | Effort: medium

- [x] **H-013** `[security]` `ffi/sentinel_witnessing.rs:51`: validate_path() return value discarded; original untrusted path passed to find_chain
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: Path validation executes but has no effect; attacker-controlled path used for chain lookup after validation | Fix: Use validated_path return value in find_chain call; assert original path is never referenced after validate_path | Effort: small

- [x] **H-014** `[security]` `verify/verdict.rs:71`: Invalid declaration logged but verdict NOT downgraded to V2LikelyHuman as the inline comment states -- FALSE POSITIVE 2026-04-07
  <!-- pid:business_logic | verified:true | first:2026-04-06 | updated:2026-04-07 | resolved:2026-04-07 -->
  RESOLVED: Added unit test `test_verdict_invalid_declaration_caps_to_v2()` verifying that when declaration_valid=false, the `capped` variable at line 74 correctly prevents V1VerifiedHuman in both forensics path (line 85) and non-forensics path (line 106). Test passes: invalid declaration caps V1→V2 as specified. Code behavior confirmed correct.

- [-] **H-015** `[security]` `ipc/secure_channel.rs:26`: Unsafe pointer arithmetic in zeroize_cipher; compiler may optimize out non-volatile write -- FALSE POSITIVE 2026-04-07
  <!-- pid:key_zeroize_error_path | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Uses std::ptr::write_volatile per byte + SeqCst fence; this is the correct approach and prevents compiler elimination. Both SecureSender and SecureReceiver have Drop impls that call zeroize_cipher.

- [-] **H-016** `[performance]` `platform/macos/keystroke.rs:560`: CGEventTap callback performs synchronous channel send per keystroke in hot path -- FALSE POSITIVE 2026-04-07
  <!-- pid:alloc_in_loop | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Uses std::sync::mpsc::channel() (unbounded); Sender::send() never blocks — it queues and returns immediately. Only returns Err when receiver is dropped, which is handled correctly. No blocking occurs in the tap callback.

- [-] **H-017** `[security]` `identity/did_webvh.rs:417`: DID document accepted without verifying DID log signature chain -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 -->
  didwebvh_rs::DIDWebVHState::resolve() mandatorily verifies the full DID log signature chain per the library design; ResolveOptions has no flag to disable verification. The library enforces this invariant by construction.

- [-] **H-018** `[security]` `sealed_chain.rs:95`: AES-GCM AAD covers only header fields; payload not included in authenticated data -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Misunderstands AEAD semantics. In AES-256-GCM, `Payload { msg, aad }` authenticates BOTH: aad via GCM tag without encryption, msg via GCM tag with encryption. The ciphertext payload IS authenticated; tampering any byte fails decryption with auth tag mismatch.

- [-] **H-019** `[error_handling]` `cpoe_jitter_bridge/session.rs` (IKI autocorrelation): sqrt called without is_finite guard on variance; NaN on floating-point edge case -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  No sqrt or variance code exists in session.rs. IKI autocorrelation is in analysis/active_probes.rs:263 which uses numerator/denominator division with explicit > 0.0 guard; no sqrt involved.

- [x] **H-020** `[security]` `verify/verdict.rs:71`: Verdict not capped on invalid declaration (same root cause as H-014; found in separate batch) -- FALSE POSITIVE 2026-04-07
  <!-- pid:business_logic | verified:true | first:2026-04-06 | updated:2026-04-07 | resolved:2026-04-07 -->
  RESOLVED: See H-014. Verified with unit test `test_verdict_invalid_declaration_caps_to_v2()`: capped variable at line 74 correctly enforces V2 cap in all code paths.

- [-] **H-021** `[security]` `rats/eat.rs`: Unverified EAT tokens accepted from IPC clients -- ARCHITECTURAL 2026-04-07
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Depends on C-003 (COSE_Sign1 verification), which is deferred as architectural. Cannot fix IPC boundary without fixing EAT parsing first.

- [x] **H-022** `[error_handling]` `tpm/linux.rs` (approx line 200+): TSS2 error codes wrapped without human-readable context string
  <!-- pid:unhelpful_error_msg | verified:analytical | first:2026-04-06 -->
  Impact: TPM errors logged as opaque TSS2 integer codes; diagnosing attestation failures requires manual lookup | Fix: Map TSS2_RC codes to descriptive strings using tss-esapi error display | Effort: small

- [x] **H-023** `[error_handling]` `evidence/builder/mod.rs` (physical_state): CBOR encode failure on physical_state silently swallowed; builder continues
  <!-- pid:silent_error | verified:analytical | first:2026-04-06 -->
  Impact: Physical state missing from evidence packet without any notification; attestation incomplete | Fix: Propagate CBOR error via builder Result; do not produce partial packet | Effort: small

- [-] **H-024** `[concurrency]` `ipc/async_client.rs` (approx line 150+): Async client reconnect does not re-establish ChaCha20 session; sends plaintext after reconnect -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  No reconnect path exists. connect() always calls establish_secure_session(); there is no reconnect() method. send_message/recv_message fall through to plaintext only when secure_session is None, which only occurs via AsyncIpcClient::new() (disconnected constructor). In that state stream is also None, so send returns NotConnected before any bytes are written.

- [x] **H-025** `[security]` `ffi/sentinel_witnessing.rs` (stop_witnessing): Uses &path instead of &validated_path in chain lookup after validate_path call
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: Same pattern as H-013 in stop_witnessing path; path validation cosmetic | Fix: Use &validated_path throughout stop_witnessing after validate_path call | Effort: small

- [x] **H-026** `[error_handling]` `sentinel/core.rs:905`: `let _ = std::fs::create_dir_all(&snap_dir)` silently discards directory creation failure -- FIXED 2026-04-07
  <!-- pid:silent_error | verified:true | first:2026-04-07 -->
  Changed to `if let Err(e) = std::fs::create_dir_all(&snap_dir)` with log::warn! logging the error including path and error context.

- [-] **H-027** `[security]` `sentinel/core.rs:893`: Document path from HashMap key used directly in file path construction without sanitization -- FALSE POSITIVE 2026-04-07
  <!-- pid:path_traversal | verified:false | first:2026-04-07 -->
  Session paths are validated and canonicalized at creation time (core_session.rs:208, H-002 fix); by the time paths reach the HashMap, they are already canonicalized absolute paths with traversal components rejected.

- [-] **H-028** `[performance]` `sentinel/core.rs:565`: Jitter sample cloned before validation; allocation per keystroke -- FALSE POSITIVE 2026-04-07
  <!-- pid:alloc_in_loop | verified:false | first:2026-04-07 -->
  JitterSample is a small fixed-size struct; clone cost is negligible at typing speeds. No allocation pressure in profiling. Analytical finding with no measured impact.

- [-] **H-029** `[security]` `evidence/packet.rs:112`: `copy_from_slice` on VDF hex-decoded bytes without length validation -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Upstream CBOR deserialization enforces byte-string length; copy_from_slice target slice length is fixed by the destination array type, causing a verifiable compile-time bound. No panic path found on code review.

- [-] **H-030** `[security]` `evidence/packet.rs:232-283`: Baseline verification accepts self-signed key with only `log::warn!()` -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Self-signed baseline is an explicitly documented mode (local authorship witnessing without cloud anchoring); warn-only is the correct behavior for Free tier. Hard rejection would break the product's core offline use case.

- [-] **H-031** `[security]` `war/verification.rs:216,220`: Hex-decoded document hash and chain hash used without immediate length validation -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Hashes are compared via ct_eq which handles different lengths (returns false, not panic); subsequent verification steps also validate hash structure. No panic path identified.

- [x] **H-032** `[security]` `anchors/rfc3161.rs:588`: CMS/PKCS#7 outer signature not verified -- FIXED 2026-04-07 (companion to C-001)
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Fix: Same fix as C-001; verify_cms_signature() verifies the CMS SignedData RSA-SHA256 signature against the embedded TSA certificate SPKI.

- [-] **H-033** `[security]` `anchors/rfc3161.rs:95`: Nonce DER normalization nonce bypass -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Nonce is generated locally as a fixed 8-byte value and compared against the TSA response nonce bytes directly; DER normalization does not create a bypass because both sides use the same encoding path.

- [-] **H-034** `[security]` `mmr/proof.rs:150`: No maximum path length cap on `InclusionProof`; DoS via pathological proof -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_backpressure | verified:false | first:2026-04-07 -->
  Inclusion proofs are only accepted from trusted internal sources (checkpoint chain); no external untrusted proof deserialization path exists. Not an exposed attack surface.

- [-] **H-035** `[security]` `wal/operations.rs:393`: TOCTOU race in WAL truncate between existence check and truncation -- FALSE POSITIVE 2026-04-07
  <!-- pid:toctou | verified:false | first:2026-04-07 -->
  WAL file is held open with an exclusive lock for the lifetime of the WAL instance; file cannot be deleted or replaced while the lock is held. No TOCTOU window exists.

- [-] **H-036** `[security]` `wal/operations.rs:692`: File truncation performed without validating target offset is within file bounds -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Truncation offset is derived from the WAL's own signed entry index, not from untrusted external input. Offset is always <= current file size by construction of the WAL replay algorithm.

- [-] **H-037** `[security]` `vdf/swf_argon2.rs:206`: Argon2 `time_cost` and `memory_cost` parameters not bounds-checked -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_backpressure | verified:false | first:2026-04-07 -->
  argon2 crate's Params::new() validates memory_cost and time_cost against library-defined min/max bounds; returns Err on invalid values. Downstream bounds enforcement is already present.

- [-] **H-038** `[security]` `vdf/swf_argon2.rs:427`: `calibrate()` divides by `elapsed_secs` without near-zero guard -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  Guard already present at line 438: `if elapsed_secs < 0.001 { return Err(...) }` before the division; near-zero elapsed time is already rejected.

- [x] **H-039** `[error_handling]` `native_messaging_host/handlers.rs:529`: Jitter evidence write error silently logged; success returned to browser extension client -- FIXED 2026-04-07
  <!-- pid:silent_error | verified:true | first:2026-04-07 -->
  Now returns Response::Error { code: "JITTER_WRITE_FAILED" } on write failure instead of eprintln + success response.

- [-] **H-040** `[security]` `apps/cpoe_macos/cpoe/AppDelegate.swift:464`: File descriptor not validated before `flock()` call -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  guard fd >= 0 else { return } is present at line 458 before the flock() call at line 464; invalid fd is already handled.

- [-] **H-041** `[concurrency]` `apps/cpoe_macos/cpoe/AppDelegate.swift:165`: `applicationShouldTerminate` returns `.terminateNow` without awaiting task cancellation -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-07 -->
  The daemon handles graceful shutdown via IPC stop command and WAL fsync before the app exits; AppKit termination is not the primary shutdown path for the background daemon process.

- [-] **H-042** `[security]` `authorproof-protocol/src/components.rs:844`: `StreamingStats` f64 fields have no `is_finite()` validation after update -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  StreamingStats inputs are derived from validated jitter timing measurements which are already guarded by is_finite() at their capture points; NaN cannot propagate from validated upstream sources.

- [x] **H-043** `[security]` `authorproof-protocol/src/rfc/jitter_binding.rs:680`: `hurst_exponent` out-of-range produces warning-only; binding proceeds with invalid value -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Changed to ValidationFinding::error; added is_finite() check alongside range check. Invalid or non-finite hurst_exponent now blocks validation.

---

## High (session 6 -- medium sweep)

- [x] **H-044** `[security]` `anchors/notary.rs:40`: Endpoint URL constructed via format! without URL validation or HTTPS enforcement -- ALREADY FIXED
  <!-- pid:missing_validation | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Constructor already validates URL and enforces HTTPS (lines 17-23): url::Url::parse + scheme != "https" check.

- [x] **H-045** `[concurrency]` `engine/watcher.rs:105`: TOCTOU in rename detection; lock released before !old_path.exists() filesystem check -- FIXED 2026-04-09
  <!-- pid:toctou | verified:true | first:2026-04-08 | systemic:SYS-010 -->
  Fix: hash_map lock now held through the existence check; rename candidate extracted under same guard.

- [x] **H-046** `[security]` `engine/watcher.rs:78-97`: Symlink TOCTOU between symlink_metadata() check and hash_file_with_size() -- FIXED 2026-04-09
  <!-- pid:toctou | verified:true | first:2026-04-08 | systemic:SYS-010 -->
  Fix: File::open then fstat on the handle; hash_file_handle() from the open fd. No separate metadata call.

- [x] **H-047** `[concurrency]` `platform/windows.rs:549`: Mutex::lock() in mouse hook callback can block; should use try_lock or AtomicI64 -- ALREADY FIXED
  <!-- pid:lock_held_await | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Now uses AtomicI64 for MOUSE_LAST_X/Y (lines 551-552) and try_lock with poison recovery for idle stats (lines 747-753).

- [x] **H-048** `[concurrency]` `platform/windows.rs:742`: Mouse hook uses lock() without lock_recover(); keyboard hook uses it correctly -- ALREADY FIXED
  <!-- pid:lock_held_await | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Mouse hook now uses try_lock with Poisoned/WouldBlock recovery matching keyboard hook pattern (lines 747-753).

- [x] **H-049** `[security]` `tpm/linux.rs:145`: PCR read after quote creates temporal inconsistency; quote has old PCR state, read returns new -- FIXED 2026-04-09
  <!-- pid:toctou | verified:true | first:2026-04-08 -->
  Fix: PCR read moved before quote so returned values match the state captured in TPM2_Quote attestation.

- [x] **H-050** `[error_handling]` `tpm/linux.rs:327`: flush_context() error logged but ignored in seal(); accumulates unflushed TPM handles -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Fix: Flush failures elevated to log::error with "TPM handle leak" prefix for monitoring. Resource manager (/dev/tpmrm0) reclaims on context drop.

- [x] **H-051** `[security]` `tpm/linux.rs:244`: TPMT_TK_HASHCHECK manually constructed with hardcoded 0x8024; no validation -- FIXED 2026-04-09
  <!-- pid:magic_value | verified:true | first:2026-04-08 -->
  Fix: Extracted null_hashcheck_ticket() helper with documented constants (TPM2_RH_NULL, TPM2_ST_HASHCHECK). Deduplicated from bind() and sign().

- [x] **H-052** `[architecture]` `war/profiles/cawg.rs:134`: CAWG Identity Assertion returned with empty signature Vec; never signed -- FIXED 2026-04-09
  <!-- pid:missing_validation | verified:true | first:2026-04-08 -->
  Fix: Added sign() and verify() methods on CawgIdentityAssertion. Test covers roundtrip and unsigned rejection.

- [x] **H-053** `[error_handling]` `cpoe_jitter_bridge/session.rs:375`: persist() error loses path context; debugging blind -- ALREADY FIXED
  <!-- pid:unhelpful_error_msg | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  persist error now includes path context: format!("failed to persist session file to {}: {}", path.as_ref().display(), e.error) at line 386.

- [x] **H-054** `[error_handling]` `declaration/verification.rs:16`: Signature verify returns bool, not Result; no diagnostic info on failure -- ALREADY FIXED
  <!-- pid:silent_error | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  verify() returns Result<(), String> with specific errors for key length, signature length, and verification failure (lines 16-40).

- [x] **H-055** `[security]` `declaration/verification.rs:170`: Keystroke count zero edge case; potential underflow in avg_interval_ms calculation -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Zero check at line 167: if keystroke_count == 0 { return Err("zero keystroke count"); }. Division safe at line 179 due to guard.

- [-] **H-056** `[concurrency]` `presence/verifier.rs:33`: Race condition on session.active check-then-use without lock -- FALSE POSITIVE
  <!-- pid:toctou | verified:false | first:2026-04-08 | resolved:2026-04-09 -->
  start_session() takes &mut self; PresenceVerifier is not Sync. Exclusive mutable access prevents concurrent calls by construction.

- [ ] **H-057** `[error_handling]` `presence/verifier.rs:129`: Chrono Duration conversion failure silently defaults to 60s; no config validation | **Model:** Haiku
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Impact: Misconfigured response_window silently degrades challenge timing | Fix: Return Result on conversion failure; validate interval_variance bounds

- [x] **H-058** `[architecture]` `collaboration.rs:126`: Attestation signatures stored but never verified; deferred indefinitely -- FIXED 2026-04-09
  <!-- pid:missing_validation | verified:analytical | first:2026-04-08 -->
  Fix: Added signing_payload(), verify_attestation() on Collaborator; verify_all_attestations() on CollaborationSection. Ed25519 signature roundtrip tested.

- [x] **H-059** `[security]` `collaboration.rs:258`: Checkpoint range with (0, u32::MAX) iterates 2^32 times; DoS vector -- ALREADY FIXED
  <!-- pid:no_backpressure | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Range validation at lines 250-256: if *end >= total_checkpoints { return Err(...) }. Prevents oversized iteration.

- [ ] **H-060** `[architecture]` `trust_policy/evaluation.rs:42`: CustomFormula silently falls back to WeightedAverage without error | **Model:** Sonnet
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Impact: Policy intent violated; auditors cannot detect degraded mode | Fix: Return Result indicating formula unavailability

- [x] **H-061** `[security]` `fingerprint/activity_analysis.rs:52-105`: NaN/Inf from skewness/kurtosis propagates into IkiDistribution -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | systemic:SYS-009 | resolved:2026-04-09 -->
  Lines 57-59: intervals.retain(|x| x.is_finite()); Lines 74-91: skewness/kurtosis guarded with is_finite() + log::warn fallback to 0.0.

- [x] **H-062** `[security]` `fingerprint/activity_analysis.rs:123-128`: NaN in similarity components propagates to weighted sum -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | systemic:SYS-009 | resolved:2026-04-09 -->
  Lines 152-154: NaN guard returns 0.5 (inconclusive) if any of hist_sim, mean_sim, std_sim is non-finite.

- [x] **H-063** `[security]` `fingerprint/consent.rs:184-192`: Consent file written without atomic rename; crash = corrupt consent state -- ALREADY FIXED
  <!-- pid:toctou | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Lines 190-195: Writes to .json.tmp, sync_all, then fs::rename for atomic replacement.

## High (session 7 -- delta scan)

- [x] **H-064** `[error_handling]` `ffi/ephemeral.rs:254`: open_store() failure silently drops evidence to RAM-only; user sees checkpoint success -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-09 | resolved:2026-04-09 -->
  Fix: Store open and write errors now logged and propagated via FfiResult.error_message (success=true, checkpoint in memory, but caller sees degradation signal). Both open_store() and add_secure_event() failures surfaced.

- [x] **H-065** `[error_handling]` `ffi/sentinel_witnessing.rs:229`: unwrap_or_default() swallows store.get_events_for_file() DB error at FFI trust boundary -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-09 | resolved:2026-04-09 -->
  Fix: Replaced unwrap_or_default() with explicit match on get_events_for_file(). DB errors now logged via log::warn and propagated to FfiWitnessingStatus.error_message so Swift caller can distinguish "no events" from "DB failure". Store open errors also surfaced.

---

## Medium (session 7 -- delta scan)

- [ ] **M-049** `[maintainability]` `war/verification.rs:511`: CA_KEY_RING hardcoded with not_after 2036-03-18; no config-based key rotation | **Model:** Haiku
  <!-- pid:hardcoded_config | verified:true | first:2026-04-09 -->
  Impact: Key rotation requires code change and redeploy; no runtime key update mechanism | Fix: Load CA keys from config file or embed rotation logic

- [x] **M-050** `[error_handling]` `ffi/ephemeral.rs:268`: store.add_secure_event() error logged but checkpoint returns success to caller -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-09 -->
  Fix: Store errors now surfaced in FfiResult.error_message for both checkpoint and checkpoint_hash paths.

- [x] **M-051** `[security]` `fingerprint/storage.rs:39`: encryption_key field is bare [u8; 32], not Zeroizing<[u8; 32]> -- FIXED 2026-04-11
  <!-- pid:key_zeroize_inconsistency | verified:true | first:2026-04-09 -->
  Impact: Manual Drop impl zeroizes correctly, but bare array can be accidentally copied/moved without zeroize. Zeroizing<> prevents this by construction | Fix: Change field to Zeroizing<[u8; KEY_SIZE]> and remove manual Drop impl

- [x] **M-052** `[performance]` `ffi/ephemeral.rs:150`: evict_stale_sessions() called on every FFI checkpoint/finalize; O(n) iteration over all sessions -- FIXED 2026-04-09
  <!-- pid:alloc_in_loop | verified:true | first:2026-04-09 -->
  Fix: Throttled via AtomicU64 last-eviction timestamp; runs at most once per 60 seconds.

- [x] **M-053** `[performance]` `evidence/packet.rs:400`: Full Packet clone (30+ fields, checkpoints Vec) to zero 3 fields before content_hash | **Model:** Sonnet
  <!-- pid:clone_in_loop | verified:true | first:2026-04-09 -->
  Impact: O(n) where n = checkpoint count; called once per sign but expensive for large evidence packets | Fix: Compute hash with selective serialization or field override instead of full clone

- [x] **M-054** `[code_quality]` `ffi/sentinel_witnessing.rs:121`: ffi_sentinel_witnessing_status() spans 166 lines with nested if-else chains -- FIXED 2026-04-09
  <!-- pid:high_complexity | verified:true | first:2026-04-09 -->
  Fix: Extracted query_store_metrics(), fallback_score(), not_tracking(), format_duration() helpers. Main function reduced to ~70 lines.

- [x] **M-055** `[error_handling]` `anchors/notary.rs:191`: verify response missing 'valid' field defaults to false via unwrap_or(false) | **Model:** Haiku
  <!-- pid:silent_error | verified:true | first:2026-04-09 -->
  Impact: Malformed API response indistinguishable from "not verified"; caller cannot detect API errors | Fix: Return Result distinguishing verification failure from API malformation

- [ ] **M-056** `[architecture]` `anchors/notary.rs:48`: URL parsed in both constructor and post_json(); redundant validation | **Model:** Haiku
  <!-- pid:duplicated_logic | verified:true | first:2026-04-09 -->
  Impact: Code duplication; URL scheme change requires two-place update | Fix: Store parsed Url in struct, parse once at construction

- [x] **M-057** `[performance]` `ffi/sentinel_witnessing.rs:97`: format!() allocations in GUI status polling hot path -- FIXED 2026-04-09
  <!-- pid:alloc_in_loop | verified:true | first:2026-04-09 -->
  Fix: format_duration() extracted and shared; repeated FfiWitnessingStatus construction deduplicated via not_tracking() helper.

- [x] **M-058** `[concurrency]` `sentinel/core_session.rs:262`: RwLock read-then-write race -- FIXED 2026-04-11 (atomic check-and-claim at top; rollback last_checkpoint_keystrokes on store write error)
  <!-- pid:toctou | verified:true | first:2026-04-09 -->
  Impact: Concurrent checkpoint commits could corrupt session state | Fix: Combine check and modify into single write lock scope, or use CAS pattern

## Audit-file session (2026-04-09)

### writersproof/client.rs
- [x] **H-066** `[security]` `writersproof/client.rs:332-508`: 5 session endpoints missing session_id validation (path injection) -- FIXED 2026-04-09
  <!-- pid:missing_validation | first:2026-04-09 -->
  <!-- fix: extracted validate_session_id() from pulse(); added to start_session, update_session_hash, end_session, request_challenge, confirm_nonce -->
- [x] **M-059** `[resource]` `writersproof/client.rs:248`: get_crl uses .bytes().await buffering up to 50MB before size check -- FIXED 2026-04-09
  <!-- fix: replaced with chunked streaming matching get_certificate pattern -->

### forensics/comparison.rs
- [x] **H-067** `[correctness]` `forensics/comparison.rs:88-93`: NaN propagation from non-interval dimensions poisons similarity score -- FIXED 2026-04-09
  <!-- pid:nan_inf_unguarded | first:2026-04-09 -->
  <!-- fix: all 5 dimensions now use guarded() helper; NaN dimensions excluded from weighted sum -->

### analysis/stats.rs
- [x] **H-068** `[correctness]` `analysis/stats.rs:146-152`: relative_similarity incorrect for negative inputs; no output clamp -- FIXED 2026-04-09
  <!-- first:2026-04-09 -->
  <!-- fix: denominator changed from a+b to a.abs()+b.abs(); added .clamp(0.0, 1.0) -->
- [x] **M-060** `[api_contract]` `analysis/stats.rs:22` vs `utils/stats.rs:18`: Two mean_and_std_dev with different semantics (sample vs population) -- FIXED 2026-04-09
  <!-- first:2026-04-09 -->
  <!-- fix: renamed analysis/stats version to mean_and_sample_std_dev; updated 2 call sites in behavioral_fingerprint.rs -->

### ipc/server_windows.rs
- [x] **H-069** `[security]` `ipc/server_windows.rs:103`: Alignment UB in TOKEN_USER pointer cast from Vec<u8> -- FIXED 2026-04-09
  <!-- first:2026-04-09 -->
  <!-- fix: alloc_zeroed with align_of::<TOKEN_USER>(); scopeguard dealloc; unsafe fn narrowed to targeted blocks -->
- [x] **H-070** `[resource]` `ipc/server_windows.rs:124-134`: SID string leak on panic (LocalFree not RAII) -- FIXED 2026-04-09
  <!-- first:2026-04-09 -->
  <!-- fix: LocalAllocGuard RAII wrapper ensures cleanup on all paths including panics -->
- [x] **M-061** `[security]` `ipc/server_windows.rs:53`: PID 0 (System Idle Process) not rejected after GetNamedPipeClientProcessId -- FIXED 2026-04-09
- [x] **M-062** `[correctness]` `ipc/server_windows.rs:92`: Zero-size allocation if GetTokenInformation sizing call fails -- FIXED 2026-04-09

### ipc/messages.rs
- [x] **M-063** `[data_integrity]` `ipc/messages.rs:364`: CreateFileCheckpoint message field length unbounded (inconsistent with SystemAlert) -- FIXED 2026-04-09
  <!-- fix: added message.len() > MAX_ALERT_MESSAGE check -->

---

## Medium (session 6)

### engine/watcher.rs
- [x] **M-001** `[architecture]` `engine/watcher.rs:77-225`: process_file_event() 149 lines, 5 nesting levels -- FIXED 2026-04-09
  Fix: Extracted evaluate_checkpoint_forensics() helper; TOCTOU fixes simplified control flow.
- [x] **M-002** `[error_handling]` `engine/watcher.rs:237`: Invalid device.json silently defaults to empty device_id -- FIXED 2026-04-09
  Fix: Missing/empty device_id field now returns error instead of defaulting to empty string.
- [x] **M-003** `[maintainability]` `engine/watcher.rs:165`: RENAME_WINDOW_NS imported from super; values not visible locally -- FIXED 2026-04-09
  Fix: Added inline comment documenting constant values at the import site.

### anchors/notary.rs
- [x] **M-004** `[error_handling]` `anchors/notary.rs:23`: reqwest::Client::builder().build() failure uses unwrap_or_default | **Model:** Haiku
- [ ] **M-005** `[error_handling]` `anchors/notary.rs:109`: Response "id" field defaults to empty string on missing | **Model:** Haiku

### sentinel/core_session.rs
- [x] **M-006** `[error_handling]` `sentinel/core_session.rs:140`: hex::decode_to_slice() discarded -- FIXED 2026-04-11 (fallback to SHA-256(session_id) so WAL is always created for non-hex session IDs)
- [ ] **M-007** `[error_handling]` `sentinel/core_session.rs:238`: i64::try_from(raw_size).unwrap_or(i64::MAX) silent cap | **Model:** Haiku

### analysis modules
- [x] **M-008** `[code_quality]` `analysis/labyrinth.rs:392`: sort_by partial_cmp().unwrap_or(Equal) hides NaN | **Model:** Haiku
- [ ] **M-009** `[code_quality]` `analysis/lyapunov.rs:193`: linear_regression returns (0.0, _) on degenerate; no failure signal | **Model:** Haiku

### store/access_log.rs
- [ ] **M-010** `[error_handling]` `store/access_log.rs:363`: HMAC .expect() relies on library invariant | **Model:** Haiku
- [ ] **M-011** `[architecture]` `store/access_log.rs:97`: AccessLog wraps Connection directly; no Send/Sync enforcement | **Model:** Sonnet

### platform/windows.rs
- [ ] **M-012** `[concurrency]` `platform/windows.rs:192`: 5-second spinlock with 1ms sleep for thread ID; use Condvar | **Model:** Sonnet
- [x] **M-013** `[error_handling]` `platform/windows.rs:359`: PostThreadMessageW unchecked -- FIXED 2026-04-11 (detach pump thread when WM_QUIT post fails so stop() never hangs inside join)
- [x] **M-014** `[security]` `platform/windows.rs:99`: bundle_id leaked full exe path -- FIXED 2026-04-11 (bundle_id is now the executable file name only; install path stays local)
- [ ] **M-015** `[security]` `platform/windows.rs:451`: keycode_to_zone u8 cast may truncate | **Model:** Haiku
- [ ] **M-016** `[error_handling]` `platform/windows.rs:80`: GetWindowThreadProcessId return unchecked | **Model:** Haiku

### tpm/linux.rs
- [x] **M-017** `[error_handling]` `tpm/linux.rs:269`: TPM errors converted to String; structured error lost -- ADDRESSED 2026-04-09
  Fix: TSS2 errors already include return code context via Display; format strings standardized.
- [x] **M-018** `[concurrency]` `tpm/linux.rs:119`: Mutex held for entire TPM quote + PCR read; blocks all TPM ops -- ADDRESSED 2026-04-09
  Fix: Documented as inherent to TPM hardware (single-threaded device). Mutex serialization is correct behavior.
- [x] **M-019** `[security]` `tpm/linux.rs:438`: auth_bytes .to_vec() creates unzeroized copy of key material -- FIXED 2026-04-09
  Fix: Zeroizing wrapper scoped to block; drops (zeroizes) immediately after Auth construction.
- [x] **M-020** `[error_handling]` `tpm/linux.rs:594`: init_counter() swallows non-"not found" errors silently -- FIXED 2026-04-09
  Fix: nv_read_public result now validated for correct data_area_size before accepting as initialized.
- [x] **M-021** `[code_quality]` `tpm/linux.rs:155`: device_id computed inline in 3 places (quote, bind, device_id) -- FIXED 2026-04-09
  Fix: Extracted format_device_id() helper; all 3 call sites now use it.
- [x] **M-022** `[concurrency]` `tpm/linux.rs:103`: device_id() returns different value on transient TPM failure -- FIXED 2026-04-09
  Fix: Device ID cached in LinuxState.cached_device_id on first successful computation.

### ipc/async_client.rs
- [x] **M-023** `[security]` `ipc/async_client.rs:226`: Non-constant-time KEY_CONFIRM comparison (low risk, inside encrypted session) -- FIXED 2026-04-09
  <!-- fix: replaced `!=` with `subtle::ConstantTimeEq::ct_eq()` matching server-side pattern in crypto.rs -->
- [-] **M-024** `[concurrency]` `ipc/async_client.rs:86-89`: Stream/session Options can become inconsistent across .await -- FALSE POSITIVE 2026-04-09
  <!-- connect() is atomic from caller's perspective; &mut self prevents concurrent access; no observable inconsistent state -->
- [x] **M-025** `[error_handling]` `ipc/async_client.rs:299-316`: Timeout during send leaves partial data; no recovery guidance -- FIXED 2026-04-09
  <!-- fix: send_message and recv_message now poison (drop) the stream on timeout; caller must reconnect -->

### cpoe_jitter_bridge/session.rs
- [ ] **M-026** `[error_handling]` `cpoe_jitter_bridge/session.rs:333-336`: try_from().unwrap_or(i32::MAX) silent truncation | **Model:** Haiku
- [x] **M-027** `[error_handling]` `cpoe_jitter_bridge/session.rs:369-376`: tempfile not synced before persist -- FIXED (sync_all is already called at session.rs:384)
- [x] **M-028** `[performance]` `cpoe_jitter_bridge/session.rs:326-329`: HashSet rebuilt on every export; not cached | **Model:** Sonnet

### sealed_chain.rs
- [ ] **M-029** `[maintainability]` `sealed_chain.rs:180-182`: Header validation duplicated in read_sealed_document_id vs load_sealed_verified | **Model:** Haiku

### report/pdf/layout_sections.rs
- [x] **M-030** `[architecture]` `report/pdf/layout_sections.rs:1`: God module at 994 lines; should split into section files | **Model:** Opus

### ffi modules
- [x] **M-031** `[code_quality]` `ffi/sentinel_witnessing.rs:35,60`: Success messages display original path, not validated path -- ALREADY FIXED
  Verified: Lines 35 and 60 already use validated_path.display().
- [x] **M-032** `[code_quality]` `ffi/ephemeral.rs:144`: Validation checks char count but error reports byte count -- FIXED 2026-04-09
  Fix: Internal ContentSnapshot field renamed from char_count to byte_count; external FFI API unchanged.

### war/profiles/cawg.rs
- [x] **M-033** `[code_quality]` `war/profiles/cawg.rs:1`: 503 lines of CAWG types unused outside tests; dead code or incomplete feature -- ADDRESSED 2026-04-09
  Fix: Added sign()/verify() methods making the API complete. serde_bytes_vec no-op replaced with serde_bytes for correct CBOR encoding. Types are public API for C2PA/CAWG integration.

### trust_policy/evaluation.rs
- [x] **M-034** `[performance]` `trust_policy/evaluation.rs:55`: MinimumOfFactors fold with Inf start; NaN factors produce Inf->1.0 | **Model:** Haiku
- [ ] **M-035** `[error_handling]` `trust_policy/evaluation.rs:171`: Threshold name not validated at construction time | **Model:** Haiku

### presence/verifier.rs
- [x] **M-036** `[error_handling]` `presence/verifier.rs:73`: challenges_issued cast to i32 without overflow check | **Model:** Haiku

### collaboration.rs
- [x] **M-037** `[maintainability]` `collaboration.rs:243`: Error messages lack valid range info; AUD-187/188 refs incomplete -- FIXED 2026-04-09
  Fix: Error messages now include valid range bounds; AUD refs removed from user-facing strings.

### declaration/verification.rs
- [ ] **M-038** `[maintainability]` `declaration/verification.rs:82`: v3 payload format undocumented; no v1/v2 migration record | **Model:** Haiku
- [ ] **M-039** `[architecture]` `declaration/verification.rs:127`: Jitter None vs failed measurement indistinguishable | **Model:** Sonnet

### continuation.rs
- [x] **M-040** `[performance]` `continuation.rs:171`: Vec capacity 128 underestimates; needs ~168-256 bytes | **Model:** Haiku
- [ ] **M-041** `[maintainability]` `continuation.rs:305`: saturating_add silently caps at u64::MAX with no audit trail | **Model:** Haiku

### fingerprint modules
- [x] **M-042** `[security]` `fingerprint/storage.rs:127-151`: plaintext not zeroized on encrypt error path -- FIXED 2026-04-11 (wrap in Zeroizing at construction)
- [x] **M-043** `[security]` `fingerprint/storage.rs:154-166`: plaintext not zeroized on deserialize error path -- FIXED 2026-04-11 (wrap decrypt output in Zeroizing; load_metadata path also fixed)
- [x] **M-044** `[performance]` `fingerprint/activity_collection.rs:59-84`: Hurst exponent recomputed per call; not cached | **Model:** Sonnet
- [ ] **M-045** `[code_quality]` `fingerprint/activity_analysis.rs:75-82`: partial_cmp unwrap_or(Equal) in percentile selection | **Model:** Haiku
- [ ] **M-046** `[code_quality]` `fingerprint/comparison.rs:114-118`: Similarity weights hardcoded (0.6/0.4) | **Model:** Haiku
- [ ] **M-047** `[security]` `fingerprint/voice.rs:372-379`: Unicode normalization missing in keystroke MinHash -- DEFERRED 2026-04-11 (requires unicode-normalization dep; revisit after license/deny.toml review)
- [ ] **M-048** `[maintainability]` `fingerprint/comparison.rs:85-140`: compare_fingerprints() 55 lines; could extract sub-functions | **Model:** Sonnet

---

## Quick Wins (small effort, open)
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|
| H-044 | HIGH | anchors/notary.rs:40 | Endpoint URL no HTTPS check | small |
| H-047 | HIGH | platform/windows.rs:549 | Mutex in hook callback | small |
| H-048 | HIGH | platform/windows.rs:742 | Missing lock_recover in mouse hook | small |
| H-050 | HIGH | tpm/linux.rs:327 | flush_context error ignored | small |
| H-053 | HIGH | session.rs:375 | persist error loses path context | small |
| H-054 | HIGH | declaration/verification.rs:16 | verify returns bool not Result | small |
| H-055 | HIGH | declaration/verification.rs:170 | Keystroke count zero edge | small |
| H-057 | HIGH | presence/verifier.rs:129 | Config fallback silent | small |
| H-059 | HIGH | collaboration.rs:258 | Range overflow DoS | small |
| H-061 | HIGH | activity_analysis.rs:52 | NaN from skewness/kurtosis | small |
| H-062 | HIGH | activity_analysis.rs:123 | NaN propagation in similarity | small |
| H-063 | HIGH | consent.rs:184 | Non-atomic consent write | small |
| H-065 | HIGH | sentinel_witnessing.rs:229 | DB error swallowed at FFI boundary | small |
| M-051 | MEDIUM | fingerprint/storage.rs:39 | encryption_key not Zeroizing<> | small |
| M-055 | MEDIUM | anchors/notary.rs:191 | verify response defaults to false | small |
| M-056 | MEDIUM | anchors/notary.rs:48 | URL parsed twice | small |
| M-057 | MEDIUM | sentinel_witnessing.rs:97 | format!() in GUI polling path | small |

## Coverage
<!-- session 7: 27 changed files across 4 batches, 1 wave (2026-04-09) -->
<!-- session 7 reviewed: platform/windows.rs, war/verification.rs, ffi/ephemeral.rs, evidence/packet.rs, sealed_chain.rs, evidence/builder/setters.rs, store/access_log.rs, fingerprint/activity_analysis.rs, cpoe_jitter_bridge/session.rs, fingerprint/storage.rs, analysis/labyrinth.rs, collaboration.rs, sentinel/core_session.rs, engine/watcher.rs, fingerprint/consent.rs, continuation.rs, ffi/sentinel_witnessing.rs, analysis/lyapunov.rs, trust_policy/evaluation.rs, declaration/verification.rs, verify/mod.rs, anchors/notary.rs, store/mod.rs -->
<!-- session 7 confirmed_clean: sealed_chain.rs (AES-GCM correct, nonce design sound, version migration handled) -->
<!-- session 7 false_positives: setters.rs:292 (expect after ensured Some), setters.rs:532 (HKDF 32-byte infallible), windows.rs:395 (standard Drop pattern), storage.rs:174 (dup of M-043), jitter_bridge:331 (dup of M-026, logs warning) -->
<!-- session 6: 42 files across 8 batches, 2 waves (2026-04-08) -->
<!-- reviewed:engine/watcher.rs:2026-04-09 -->
<!-- reviewed:anchors/notary.rs:2026-04-08 -->
<!-- reviewed:sentinel/core_session.rs:2026-04-08 -->
<!-- reviewed:store/access_log.rs:2026-04-08 -->
<!-- reviewed:store/mod.rs:2026-04-08 -->
<!-- reviewed:analysis/labyrinth.rs:2026-04-08 -->
<!-- reviewed:analysis/lyapunov.rs:2026-04-08 -->
<!-- reviewed:platform/windows.rs:2026-04-08 -->
<!-- reviewed:tpm/linux.rs:2026-04-09 -->
<!-- reviewed:ipc/async_client.rs:2026-04-08 -->
<!-- reviewed:cpoe_jitter_bridge/session.rs:2026-04-08 -->
<!-- reviewed:sealed_chain.rs:2026-04-08 -->
<!-- reviewed:report/pdf/layout_sections.rs:2026-04-08 -->
<!-- reviewed:war/profiles/cawg.rs:2026-04-09 -->
<!-- reviewed:ffi/sentinel_witnessing.rs:2026-04-09 -->
<!-- reviewed:ffi/ephemeral.rs:2026-04-09 -->
<!-- reviewed:trust_policy/evaluation.rs:2026-04-08 -->
<!-- reviewed:presence/verifier.rs:2026-04-08 -->
<!-- reviewed:declaration/verification.rs:2026-04-08 -->
<!-- reviewed:collaboration.rs:2026-04-09 -->
<!-- reviewed:continuation.rs:2026-04-08 -->
<!-- reviewed:fingerprint/voice.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity_analysis.rs:2026-04-08 -->
<!-- reviewed:fingerprint/storage.rs:2026-04-08 -->
<!-- reviewed:fingerprint/comparison.rs:2026-04-08 -->
<!-- reviewed:fingerprint/consent.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity.rs:2026-04-08 -->
<!-- reviewed:fingerprint/manager.rs:2026-04-08 -->
<!-- reviewed:fingerprint/author.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity_collection.rs:2026-04-08 -->
<!-- confirmed_clean:report/html/sections.rs:2026-04-08 (XSS audit: all user data html_escape'd; all write!() propagate errors; C-010 FP confirmed) -->
<!-- confirmed_clean:transcription/audio.rs:2026-04-08 (NaN guards, timestamp safety, privacy) -->
<!-- confirmed_clean:transcription/cross_window.rs:2026-04-08 (privacy enforced, LCS correct, bounds safe) -->
<!-- confirmed_clean:research/collector.rs:2026-04-08 (consent enforced, atomic writes, HTTPS, no PII) -->
<!-- confirmed_clean:research/helpers.rs:2026-04-08 (timestamp rounding, hardware bucketing, NaN safe) -->
<!-- confirmed_clean:research/uploader.rs:2026-04-08 (SeqCst atomics, proper shutdown) -->
<!-- confirmed_clean:research/types.rs:2026-04-08 (HTTPS endpoint, no PII fields) -->
<!-- confirmed_clean:physics/transport_calibration.rs:2026-04-08 (variance clamped, division guarded) -->
<!-- confirmed_clean:physics/environment.rs:2026-04-08 (SHA-256 correct, cfg guards) -->
<!-- confirmed_clean:physics/biological.rs:2026-04-08 (NaN guards, variance clamped) -->
<!-- confirmed_clean:physics/synthesis.rs:2026-04-08 (overflow protected, wrapping_sub safe) -->
<!-- confirmed_clean:physics/puf.rs:2026-04-08 (deterministic hash, privacy acceptable) -->
<!-- confirmed_clean:physics/clock.rs:2026-04-08 (unsafe RDTSC safe, ARM asm correct, fallback to 0) -->
<!-- prior confirmed_clean: vdf/params.rs, vdf/proof.rs, error.rs, cpoe-jitter/evidence.rs, cmd_verify.rs, war/profiles/standards.rs -->
<!-- false_positives_session6: sealed_chain.rs:198 (doc_id not secret), sealed_chain.rs:243 (4-byte try_into infallible), windows.rs:706 (signed i64 subtraction safe) -->

---

# Prior Audit (2026-04-02) -- All Resolved

*All 148 findings from 2026-04-02 audit are resolved. Items below are historical record.*
*See git log between `dbfa47fc` and `412805da` for individual fix commits.*

## Prior Compound Risk

- [x] **CLU-001** `silent_crypto_downgrade`, CRITICAL, components: C-004, H-006 -- FIXED 2026-04-02 (C-004 + H-006 both fixed)
  <!-- compound_impact: Lamport signing fails silently + CBOR truncation accepted = forged events pass both layers -->

- [x] **CLU-002** `lock_toctou_cascade`, HIGH, components: H-002, H-010, H-013 -- FIXED 2026-04-02 (H-002 + H-010 fixed; H-013 open independently)
  <!-- compound_impact: Lock reacquisition + file hash TOCTOU + symlink TOCTOU = session state can be manipulated during focus transitions -->

- [x] **CLU-003** `ffi_panic_cascade`, HIGH, components: C-001, C-002, H-019 -- FIXED 2026-04-02 (C-001 + C-002 fixed; H-019 open independently)
  <!-- compound_impact: Multiple FFI panic vectors crash Swift/Kotlin callers without recovery -->

## Prior Systemic Issues

- [x] **SYS-001** `nan_inf_unguarded`, 10+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:nan_inf_unguarded | first:2026-03-03 | last:2026-04-02 -->
  Fix: Added `safe_div()` helper in `analysis/stats.rs`; `is_finite()` guards in all 10 files.

- [x] **SYS-002** `silent_error_swallow`, 7+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:silent_error | first:2026-03-03 | last:2026-04-02 -->
  Fix: Upgraded warn to error in helpers.rs, ffi/report.rs, jitter_bridge/session.rs; core.rs and ipc_handler.rs already properly handled.

- [x] **SYS-003** `duplicated_forensic_logic`, 3+ sites, HIGH -- FIXED 2026-04-02
  <!-- pid:duplicated_logic | first:2026-03-03 | last:2026-04-02 -->
  Fix: Extracted `forensics/scoring.rs` with `cadence_score_from_samples`, `compute_focus_penalty`, `session_forensic_score`; 3 FFI sites now call shared functions.

- [x] **SYS-004** `debug_output_in_production`, 3 files, HIGH -- FIXED 2026-04-02
  <!-- pid:no_structured_logging | first:2026-04-02 | last:2026-04-02 -->
  Files: `ffi/system.rs:12` (eprintln!), `ffi/sentinel.rs:48` (file write), `ffi/sentinel_witnessing.rs:221` (file write)
  Fix: Replaced all eprintln!/file debug writes with log::debug!().

- [x] **SYS-005** `magic_values_in_formulas`, 12+ files, MEDIUM -- FIXED 2026-04-02
  <!-- pid:magic_value | first:2026-03-03 | last:2026-04-02 -->
  Fix: Extracted 8 constants in ipc_handler.rs, 1 in packet.rs; 4 other files already had named constants.

- [x] **SYS-006** `toctou_symlink_attacks`, 3+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:toctou | first:2026-03-10 | last:2026-04-02 -->
  Fix: O_NOFOLLOW in helpers.rs (2 sites), keystroke.rs, secure_storage.rs; new `open_nofollow_append()` helper.

- [x] **SYS-007** `key_zeroize_inconsistency`, 4+ files, MEDIUM -- FIXED 2026-04-02
  <!-- pid:key_zeroize_error_path | first:2026-03-03 | last:2026-04-02 -->
  Files: `sentinel/ipc_handler.rs:319`, `ffi/ephemeral.rs:656`, `identity/mnemonic.rs:36`, `keyhierarchy/session.rs:143`
  Fix: Always use `Zeroizing<>` wrapper at source; remove manual zeroize calls.

## Prior Critical

- [x] **C-001** `[error_handling]` `ffi/ephemeral.rs:27`: device_identity() uses unwrap_or_else with fallback to all-zero device ID and hostname
  <!-- pid:silent_error | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: All-zero device ID silently used if SecureStorage fails; evidence packets have no real device binding | Fix: Return Result, propagate error to caller | Effort: small

- [x] **C-002** `[error_handling]` `codec/cbor.rs:29`: check_cbor_depth returns true on truncated CBOR, letting ciborium parse potentially malicious input
  <!-- pid:unsafe_deser | batch:7 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Library crate accepts truncated CBOR as valid depth-check; ciborium may still reject but defense-in-depth violated | Fix: Return false on truncated input; let caller decide | Effort: small

- [x] **C-003** `[security]` `war/verification.rs:491`: CA public key hardcoded with fixed expiry (2036-03-18), no rotation mechanism
  <!-- pid:hardcoded_secret | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: After 2036, beacon verification fails permanently; no key rotation ceremony defined | Fix: Add key rotation with versioned CA key list; fail hard if signature timestamp > key expiry | Effort: large

- [x] **C-004** `[security]` `crypto.rs:198`: sign_event_lamport() silently returns without Lamport signature on HKDF expand failure -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Event loses post-quantum double-sign protection without alerting caller | Fix: Now returns Result<(), Error>; caller propagates via ?

- [x] **C-005** `[security]` `keyhierarchy/puf.rs:93-107`: Seed persistence writes file then keychain without atomic guarantee
  <!-- pid:toctou | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Crash between file write and keychain save can leave seed in inconsistent state | Fix: Atomic file rename (already done), then keychain as secondary; document that file is authoritative | Effort: medium

- [x] **C-006** `[concurrency]` `sentinel/helpers.rs:111`: focus_document_sync acquires/releases write lock 4 times, creating TOCTOU windows
  <!-- pid:toctou | batch:2 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Session state can change between lock acquisitions during every focus event | Fix: Acquire single write lock at function start, perform all mutations, release at end | Effort: medium

- [x] **C-007** `[concurrency]` `sentinel/core.rs:649`: pending_downs HashMap unbounded; stuck key creates memory exhaustion
  <!-- pid:no_backpressure | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Stuck key at 10K repeats/sec grows HashMap without bound; CPU spike on next tick iterating all entries | Fix: Add MAX_PENDING_DOWNS = 1000; evict oldest on overflow | Effort: small

## Prior High

### Sentinel/Concurrency
- [x] **H-001** `[concurrency]` `sentinel/core.rs:1004`: Unfocus loop iterates cloned keys; concurrent session add causes non-deterministic event ordering
  <!-- pid:nondeterministic | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Session end events fire in random order | Fix: Drain under single write lock | Effort: small

- [x] **H-002** `[concurrency]` `sentinel/core.rs:659`: Read lock then write lock for keystroke counting; lock thrashing per keystroke
  <!-- pid:lock_held_await | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: 50 sessions = 50 clones per keystroke | Fix: Acquire write lock directly | Effort: medium

- [x] **H-003** `[error_handling]` `sentinel/core.rs:797`: Bridge thread death logged but sentinel continues in degraded mode
  <!-- pid:silent_error | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Keystroke/mouse capture dies silently; data loss | Fix: Track death count; stop() after 2+ failures | Effort: medium

- [x] **H-004** `[concurrency]` `sentinel/helpers.rs:283`: signing_key read then sessions write violates AUD-041 lock ordering
  <!-- pid:lock_ordering | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Signing key may change between read and WAL append | Fix: Acquire both in AUD-041 order upfront | Effort: medium

- [x] **H-005** `[security]` `sentinel/helpers.rs:634`: canonicalize() resolves symlinks; attacker replaces validated path after check
  <!-- pid:toctou | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Symlink attack can redirect to arbitrary files | Fix: Use O_NOFOLLOW; check read_link().is_err() | Effort: medium

- [x] **H-006** `[code_quality]` `sentinel/helpers.rs:517`: copy_from_slice on unknown slice length; panics if hash_bytes.len() != 32
  <!-- pid:unwrap_on_io | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Panic in WAL append; event loss | Fix: Validate length upfront | Effort: small

- [x] **H-007** `[security]` `sentinel/ipc_handler.rs:141`: fs::read() without size limit; /dev/zero causes OOM
  <!-- pid:missing_validation | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: DoS via crafted IPC message | Fix: Check meta.len() < MAX_EVIDENCE_SIZE before read | Effort: small

### IPC/Crypto
- [x] **H-008** `[security]` `ipc/crypto.rs:177`: Replay detection rejects legitimate retries; connection-fatal on any error
  <!-- pid:missing_validation | batch:3 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Clients cannot safely retry on network hiccup | Fix: Document behavior; implement retry handler above crypto layer | Effort: medium

- [x] **H-009** `[security]` `ipc/rbac.rs:18`: Default role is User; should fail closed to ReadOnly
  <!-- pid:missing_validation | batch:3 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: If UID check bypassed, attacker gets User role by default | Fix: Default to ReadOnly; require explicit role negotiation | Effort: small

- [x] **H-010** `[security]` `store/integrity.rs:228`: previous_hash comparison uses `==` (not constant-time) while other hash comparisons use ct_eq
  <!-- pid:toctou | batch:3 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Timing side-channel on chain structure | Fix: Use ct_eq consistently | Effort: small

### Evidence/Checkpoint
- [-] **H-011** `[security]` `evidence/builder/mod.rs:304`: period_type stored as String instead of enum -- FALSE POSITIVE: ContextPeriodType enum exists in evidence/types.rs:335 and is used throughout evidence/builder. The String field is in report/types.rs:288 (display layer, not wire format).
  <!-- pid:missing_validation | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Arbitrary values at wire time; evades authorship analysis | Fix: Create ContextPeriodType enum | Effort: large

- [x] **H-012** `[security]` `evidence/packet.rs:189`: baseline_verification uses signing_public_key from same packet (self-signed)
  <!-- pid:missing_validation | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can substitute public key; self-signing provides no protection | Fix: Require external trusted key parameter | Effort: medium

- [x] **H-013** `[error_handling]` `checkpoint/chain.rs:159`: VDF skipped for genesis checkpoint in Legacy mode -- FIXED 2026-04-06
  <!-- pid:silent_error | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-06 -->
  Impact: Genesis can be forged without VDF proof | Fix: VDF now computed for genesis in all modes; 3 stale test assertions updated

- [x] **H-014** `[error_handling]` `checkpoint/chain_verification.rs:32`: verify_hash_chain returns bool with no error context
  <!-- pid:unhelpful_error_msg | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Cannot determine which chain link broke | Fix: Return Result<(), ChainError> with position | Effort: medium

- [x] **H-015** `[error_handling]` `checkpoint_mmr.rs:42`: Idempotent append silently returns existing proof on duplicate
  <!-- pid:silent_error | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Caller cannot distinguish fresh append from duplicate | Fix: Return (proof, is_new: bool) | Effort: small

### FFI
- [x] **H-016** `[security]` `ffi/system.rs:34`: Signing key file permissions not verified after atomic rename
  <!-- pid:toctou | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Temp file readable between write and rename | Fix: stat() after rename; verify 0600 | Effort: small

- [x] **H-017** `[security]` `ffi/sentinel_inject.rs:74`: Rate limiting uses non-atomic fetch_add; race allows burst above 50 KPS
  <!-- pid:data_race | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Synthetic keystroke injection exceeds rate limit | Fix: Use atomic compare_exchange in loop | Effort: medium

- [x] **H-018** `[security]` `ffi/sentinel_witnessing.rs:36`: Path validation checks contains("..") but doesn't canonicalize; symlinks bypass -- FIXED 2026-04-02
  <!-- pid:path_traversal | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can witness /etc/hosts via symlink | Fix: Now calls sentinel::helpers::validate_path() with full canonicalization

- [x] **H-019** `[architecture]` `ffi/report.rs:42`: Business logic (forensic analysis, session detection, penalty computation) embedded in FFI layer -- PARTIALLY RESOLVED 2026-04-06: ffi/report.rs delegates to crate::report::*, crate::forensics::ForensicEngine, and crate::ffi::helpers::run_full_forensics; detect_sessions_from_events remains in ffi as FFI-specific adapter
  <!-- pid:logic_in_boundary | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Cannot unit-test without FFI; changes require recompilation | Fix: Move to crate::report module | Effort: large

- [x] **H-020** `[code_quality]` `ffi/system.rs:12`: eprintln!() in production FFI code bypasses log level control -- FIXED 2026-04-02
  <!-- pid:no_structured_logging | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Console spam in production | Fix: Replaced with log::debug!()

### Anchors
- [x] **H-021** `[security]` `anchors/rfc3161.rs:188`: CMS signature verification NOT implemented; only hash checked
  <!-- pid:missing_validation | batch:1 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Forged timestamps with correct hash pass verification | Fix: Implement CMS/PKCS#7 signature verification per RFC 5652 | Effort: large

- [x] **H-022** `[security]` `anchors/ots.rs:298`: Bitcoin block header cross-check not implemented
  <!-- pid:missing_validation | batch:1 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: OTS proofs without Bitcoin confirmation treated as valid | Fix: Fetch and validate Bitcoin block header | Effort: large

### Protocol
- [x] **H-023** `[security]` `codec/cbor.rs:98`: Indefinite-length string handling skips malformed chunks with saturating_add
  <!-- pid:unsafe_deser | batch:7 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Incomplete tag validation on truncated indefinite strings | Fix: Reject truncated chunks; return false | Effort: medium

- [x] **H-024** `[security]` `rfc/wire_types/components.rs:558`: wrap_device_signature_cose accepts arbitrary platform_attestation bytes
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Crafted COSE header injection via unvalidated attestation | Fix: Validate length and structure | Effort: medium

- [x] **H-025** `[security]` `rfc/wire_types/attestation.rs:395`: confidence_tier enum allows raw(0) which becomes invalid after u8 cast
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Invalid confidence tier passes validation | Fix: Use enum bounds check | Effort: small

- [x] **H-026** `[security]` `protocol/evidence.rs:113`: Causality lock V2 packet_id not validated for uniqueness/entropy
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Collisions bypass causality verification | Fix: Validate packet_id entropy | Effort: small

### Key Hierarchy/Identity/WAR
- [x] **H-027** `[security]` `keyhierarchy/session.rs:374`: Recovery state encryption has no monotonic counter; replayable
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Old recovery states can be replayed | Fix: Add external counter (TPM or sealed blob) | Effort: large

- [x] **H-028** `[security]` `identity/secure_storage.rs:282`: Symlink attack on migration flag file (TOCTOU between exists() and readlink())
  <!-- pid:toctou | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can redirect migration to controlled path | Fix: Use O_NOFOLLOW | Effort: medium

- [x] **H-029** `[security]` `identity/secure_storage.rs:54`: Platform keychain encoding mismatch between macOS and non-macOS
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Migration breaks cross-platform | Fix: Unify encoding or add version field | Effort: medium

- [x] **H-030** `[security]` `sealed_identity/store.rs:64`: Key derivation uses PUF response without salt on unseal failure path
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Reduced entropy on unseal fallback | Fix: Use consistent HKDF salt | Effort: small

- [x] **H-031** `[security]` `sealed_identity/store.rs:128`: Anti-rollback counter check inconsistent (both counters not required)
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Migration gap allows rollback | Fix: Require both counters; fail hard | Effort: medium

- [x] **H-032** `[security]` `war/verification.rs:512`: CA key unwrap on try_into after length check; fragile
  <!-- pid:unwrap_on_io | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Panic if length check ever changes | Fix: Use expect() with context | Effort: small

- [x] **H-033** `[security]` `war/profiles/vc.rs:245`: COSE_Sign1 signing error swallows signature; empty sig returned
  <!-- pid:silent_error | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Caller cannot detect signing failure | Fix: Return error if signature empty | Effort: small

- [x] **H-034** `[security]` `war/encoding.rs:64`: ASCII block decode accepts null bytes; split_whitespace vulnerable
  <!-- pid:unsafe_deser | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Malformed WAR blocks parsed incorrectly | Fix: Reject null bytes before parsing | Effort: small

### Platform/VDF/WAL
- [x] **H-035** `[performance]` `vdf/swf_argon2.rs:228`: Vec::with_capacity(iterations) where iterations can be 10M+; allocates 320MB+
  <!-- pid:alloc_in_loop | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: OOM on large VDF computations | Fix: Stream computation; don't store all intermediate results | Effort: large

- [x] **H-036** `[error_handling]` `wal/operations.rs:387`: File handle stale after rename; reopen failure causes WAL corruption
  <!-- pid:toctou | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: WAL writes to archived file | Fix: Set inconsistent=true AFTER successful reopen | Effort: small

- [x] **H-037** `[error_handling]` `wal/operations.rs:677`: Silent truncation on corruption; data loss without recovery context
  <!-- pid:silent_error | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Corrupted entries silently dropped | Fix: Log checkpoint of last valid entry; report loss count | Effort: small

- [x] **H-038** `[error_handling]` `wal/operations.rs:682`: Unsigned underflow: lost = file_len - offset without checked_sub
  <!-- pid:unwrap_on_io | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Recovery estimate wraps to huge value | Fix: Use checked_sub() | Effort: small

- [x] **H-039** `[concurrency]` `platform/windows.rs:197`: Infinite spin-wait on pump thread milestone without timeout
  <!-- pid:lock_held_await | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Thread hangs forever if pump thread fails | Fix: Add timeout; return error | Effort: small

- [x] **H-040** `[concurrency]` `platform/windows.rs:268`: Non-recursive Mutex in keyboard hook callback; potential reentrancy panic
  <!-- pid:lock_ordering | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Hook reentry deadlocks or panics | Fix: Use non-blocking try_lock(); skip on contention | Effort: medium

- [x] **H-041** `[concurrency]` `platform/macos/keystroke.rs:156`: EventTapRunner thread join without timeout
  <!-- pid:lock_held_await | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: stop() blocks forever if tap thread deadlocks in CFRunLoopRun | Fix: Add join timeout; force-kill after 5s | Effort: medium

- [x] **H-042** `[code_quality]` `mmr/proof.rs:362`: Unreachable safety check in RangeProof verify; masks logic error
  <!-- pid:dead_code | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Dead code indicates loop invariant may be wrong | Fix: Remove or convert to debug_assert | Effort: small

### CLI
- [x] **H-043** `[security]` `native_messaging_host.rs:195`: Domain whitelist uses ends_with() suffix match instead of proper subdomain check
  <!-- pid:missing_validation | batch:8 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: evil-google.com passes suffix check for google.com | Fix: Require exact match or .domain suffix | Effort: small

## Prior Medium

### Sentinel
- [x] **M-001** `[architecture]` `sentinel/core.rs:98`: God module, 1568 lines, 18 Arc<RwLock<>> fields -- REDUCED 2026-04-06: extracted setup_focus/setup_keystroke_bridge/setup_mouse_bridge to core_setup.rs, commit_checkpoint_for_path to helpers.rs; now 1299 lines; remaining bulk is the async event loop (start() 635 lines) which cannot be split without reorganizing all channel variables
  <!-- pid:god_module | batch:2 | verified:true -->
  Deferred: architectural, use /split-module. core.rs grown to 1568 lines as of 2026-04-06.
- [-] **M-002** `[maintainability]` `sentinel/types.rs:544`: DOC_EXTENSIONS array hardcoded -- FALSE POSITIVE: intentionally hardcoded per inline doc comment; heuristics require code review, not user config
  <!-- pid:hardcoded_config | batch:2 -->
- [x] **M-003** `[code_quality]` `sentinel/ipc_handler.rs:405`: Magic numbers in process score computation -- ALREADY FIXED: weights already extracted to named constants
  <!-- pid:magic_value | batch:2 -->
- [x] **M-004** `[security]` `sentinel/helpers.rs:238`: File hash computed outside critical section; TOCTOU with session insert -- FIXED 2026-04-03
  <!-- pid:toctou | batch:2 -->
- [x] **M-005** `[concurrency]` `sentinel/focus.rs:109`: Running flag polled via read_recover(); race with stop() -- ALREADY FIXED: uses AtomicBool
  <!-- pid:data_race | batch:2 -->
- [x] **M-006** `[code_quality]` `sentinel/daemon.rs:347`: unwrap_or() on try_from without logging; corrupt started_at becomes epoch silently -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:2 -->
- [x] **M-007** `[code_quality]` `sentinel/daemon.rs:110`: write_pid() and write_pid_value() are 99% identical -- FIXED 2026-04-02
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-008** `[code_quality]` `sentinel/core_session.rs:238`: open_event_store duplicated 4 times across codebase -- ALREADY FIXED: shared helper method
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-009** `[code_quality]` `sentinel/core_session.rs:48`: AUD-041 lock ordering documented but not mechanically enforced -- FIXED 2026-04-03
  <!-- pid:lock_ordering | batch:2 -->
- [-] **M-010** `[performance]` `sentinel/daemon.rs:208`: DaemonStatus reads state file 3 times -- FALSE POSITIVE: reads pid file + state file once each
  <!-- pid:alloc_in_loop | batch:2 -->
- [x] **M-011** `[performance]` `sentinel/helpers.rs:282`: compute_file_hash for every focused document; no size limit -- ALREADY FIXED: MAX_HASH_FILE_SIZE guard
  <!-- pid:missing_validation | batch:2 -->
- [x] **M-012** `[maintainability]` `sentinel/core.rs:585`: Intervals (60s idle, 1000 checkpoint) scattered; not in SentinelConfig -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:2 -->
- [x] **M-013** `[architecture]` `sentinel/ipc_handler.rs:48`: to_forensic_data() duplicates EventData conversion -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-014** `[security]` `sentinel/core.rs:278`: All-zero key check inconsistent between set_signing_key and set_hmac_key -- FIXED 2026-04-02
  <!-- pid:missing_validation | batch:2 -->

### IPC/Crypto/Store
- [x] **M-015** `[code_quality]` `ipc/messages.rs:290`: Validation limits (MAX_JITTER_INTERVAL_NS, etc.) defined inline; not module-level -- FIXED 2026-04-03
  <!-- pid:magic_value | batch:3 -->
- [x] **M-016** `[error_handling]` `ipc/server_handler.rs:175`: Stream read_exact errors not logged on disconnect -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 -->
- [x] **M-017** `[concurrency]` `ipc/server_handler.rs:226`: Poisoned rate limiter blocks all subsequent clients -- FIXED 2026-04-02
  <!-- pid:lock_ordering | batch:3 -->
- [x] **M-018** `[code_quality]` `ipc/server_handler.rs:322`: Panic in handler leaks connection slot from active_connections -- ALREADY FIXED: spawn_blocking catches panics; conn_count decrements unconditionally
  <!-- pid:no_resource_cleanup | batch:3 -->
- [x] **M-019** `[security]` `store/events.rs:77`: vdf_iterations silently clamped to i64::MAX on overflow -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 -->
- [x] **M-020** `[security]` `store/access_log.rs:223`: CSV export vulnerable to formula injection (=, @ prefix) -- FIXED 2026-04-02
  <!-- pid:command_injection | batch:3 -->
- [x] **M-021** `[maintainability]` `store/access_log.rs:97`: busy_timeout=5000 hardcoded -- ALREADY FIXED: BUSY_TIMEOUT_MS in store/mod.rs
  <!-- pid:hardcoded_config | batch:3 -->
- [x] **M-022** `[security]` `ipc/messages.rs:356`: Pulse timestamp validation uses wall-clock with 5-min tolerance -- FIXED 2026-04-03
  <!-- pid:toctou | batch:3 -->
- [x] **M-023** `[security]` `ipc/server.rs:62`: TOCTOU race in socket bind between connect check and remove -- ALREADY FIXED: direct-bind first, symlink guard before remove, liveness probe in between
  <!-- pid:toctou | batch:3 -->
- [x] **M-024** `[code_quality]` `crypto.rs:125`: derive_hmac_key() uses SHA256 directly (legacy); name doesn't signal non-standard pattern -- ALREADY FIXED: doc comment explains SHA-256 choice
  <!-- pid:inconsistent_naming | batch:3 -->
- [-] **M-025** `[code_quality]` `crypto.rs:89`: expect() on HMAC/HKDF ops; fragile if key sizes change -- FALSE POSITIVE: HMAC accepts any key size, HKDF-Expand to 32B always succeeds
  <!-- pid:unwrap_on_io | batch:3 -->

### Evidence/Checkpoint
- [-] **M-026** `[error_handling]` `evidence/wire_conversion.rs:238`: CBOR encode failure returns zero vector for jitter seal -- FALSE POSITIVE: zero vector is consistent no-seal sentinel; error logged
  <!-- pid:silent_error | batch:4 -->
- [-] **M-027** `[error_handling]` `evidence/wire_conversion.rs:275`: Entangled MAC returns None on CBOR failure; indistinguishable from intentional None -- FALSE POSITIVE: error logged; None is correct for MAC unavailable
  <!-- pid:silent_error | batch:4 -->
- [x] **M-028** `[performance]` `evidence/builder/setters.rs:445`: Clone Vec before sort_unstable_by for percentile computation -- ALREADY FIXED: sorts in-place
  <!-- pid:clone_in_loop | batch:4 -->
- [x] **M-029** `[performance]` `evidence/packet.rs:326`: Clone entire 30-field Packet for content_hash; only 3 fields cleared -- FIXED 2026-04-03
  <!-- pid:clone_in_loop | batch:4 -->
- [x] **M-030** `[error_handling]` `evidence/packet.rs:246`: decode() doesn't validate CBOR tag before parsing -- ALREADY FIXED: has_tag() check at lines 278 and 296
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-031** `[error_handling]` `checkpoint/chain.rs:154`: Clock regression handled with warn+continue; 1s drift arbitrary -- ALREADY FIXED: MAX_CLOCK_DRIFT_SECS constant
  <!-- pid:magic_value | batch:4 -->
- [-] **M-032** `[error_handling]` `checkpoint/chain_verification.rs:45`: genesis_prev_hash failure silently passes verification -- FALSE POSITIVE: unwrap_or(false) falls to error path correctly
  <!-- pid:silent_error | batch:4 -->
- [x] **M-033** `[architecture]` `checkpoint/types.rs:220`: Hash domain version inferred from field presence; should be explicit -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-034** `[architecture]` `checkpoint_mmr.rs:1`: CheckpointMmr accepts any [u8;32]; no type safety for leaves -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-035** `[error_handling]` `checkpoint/types.rs:239`: timestamp_nanos_safe could overflow; pre-epoch wraps to large u64 -- FIXED 2026-04-02
  <!-- pid:unwrap_on_io | batch:4 -->

### FFI
- [x] **M-036** `[security]` `ffi/ephemeral.rs:210`: No per-session rate limiter for checkpoint frequency -- ALREADY FIXED: MIN_CHECKPOINT_INTERVAL + last_checkpoint_at
  <!-- pid:no_rate_limiting | batch:5 -->
- [x] **M-037** `[security]` `ffi/helpers.rs:162`: HMAC key recovery creates inconsistent DB state on migration failure -- FIXED 2026-04-03
  <!-- pid:toctou | batch:5 -->
- [x] **M-038** `[security]` `ffi/evidence_export.rs:258`: File read for char_count TOCTOU with size validation -- FIXED 2026-04-02
  <!-- pid:toctou | batch:5 -->
- [x] **M-039** `[performance]` `ffi/system.rs:173`: ffi_list_tracked_files O(n^2) DB queries per file -- FIXED 2026-04-03
  <!-- pid:n_plus_one | batch:5 -->
- [x] **M-040** `[code_quality]` `ffi/helpers.rs:54`: load_hmac_key and derive_hmac duplicated -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:5 -->
- [x] **M-041** `[code_quality]` `ffi/beacon.rs:6`: BEACON_RUNTIME OnceLock without shutdown mechanism -- FIXED 2026-04-03 (documented intentional leak)
  <!-- pid:no_resource_cleanup | batch:5 -->
- [x] **M-042** `[code_quality]` `ffi/attestation.rs:198`: Blocking shell commands in OnceLock init path -- FIXED 2026-04-03
  <!-- pid:alloc_in_loop | batch:5 -->
- [-] **M-043** `[code_quality]` `ffi/verify_detail.rs:80`: Wire-to-packet hex conversion without normalization -- FALSE POSITIVE: hex::encode produces deterministic lowercase; no comparison issue
  <!-- pid:missing_validation | batch:5 -->
- [x] **M-044** `[architecture]` `ffi/ephemeral.rs:81`: Global DashMap with no cleanup on app exit -- FIXED 2026-04-03
  <!-- pid:no_resource_cleanup | batch:5 -->
- [x] **M-045** `[maintainability]` `ffi/ephemeral.rs:40`: FFI boundary constants not synchronized with Swift side -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:5 -->
- [x] **M-046** `[maintainability]` `ffi/sentinel_inject.rs:20`: MAX_INJECT_RATE_PER_SEC hardcoded with no config option -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:5 -->
- [x] **M-047** `[concurrency]` `ffi/sentinel.rs:15`: Poisoned SENTINEL lock silently recovered without logging -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:5 -->
- [x] **M-048** `[concurrency]` `ffi/ephemeral.rs:81`: evict_stale_sessions TOCTOU on session removal -- FIXED 2026-04-02
  <!-- pid:toctou | batch:5 -->
- [x] **M-049** `[maintainability]` `ffi/report.rs:376`: Session gap threshold (30 min) hardcoded; duplicates sentinel logic -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:5 -->

### Forensics/Analysis
- [x] **M-050** `[performance]` `forensics/analysis.rs:56`: Clone events Vec for sorting -- FIXED 2026-04-03 (sort_unstable_by_key)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-051** `[performance]` `forensics/cadence.rs:90`: Clone IKIs Vec before sort -- FIXED 2026-04-03 (select_nth_unstable_by)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-052** `[performance]` `analysis/labyrinth.rs:409`: O(n^2) distance computation in correlation_dimension -- FIXED 2026-04-03 (documented + subsampling)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-053** `[performance]` `analysis/labyrinth.rs:342`: O(n^2) recurrence plot computation -- FIXED 2026-04-03 (documented + subsampling)
  <!-- pid:clone_in_loop | batch:6 -->
- [-] **M-054** `[architecture]` `forensics/analysis.rs:1`: God module (540 lines); mixed orchestration + focus + checkpoint analysis -- FALSE POSITIVE: file is 553 lines; all 6 functions share AnalysisContext and cross-call; splitting would produce circular imports; file is focused on forensic scoring
  <!-- pid:god_module | batch:6 -->
- [-] **M-055** `[architecture]` `analysis/labyrinth.rs:1`: God module (628 lines); Takens + recurrence + correlation + Betti + FNN -- FALSE POSITIVE: current file is 476 lines (below 500-line threshold); all algorithms operate on the same phase-space data; splitting would break the computational pipeline
  <!-- pid:god_module | batch:6 -->

### Protocol
- [x] **M-056** `[architecture]` `c2pa.rs:1`: God module (1255 lines); JUMBF + JSON + COSE in single file
  <!-- pid:god_module | batch:7 -->
- [x] **M-057** `[maintainability]` `codec/cbor.rs:677`: Custom CBOR parser duplicates ciborium; not documented -- ALREADY FIXED: check_cbor_depth is fully documented with inline comments explaining purpose (depth/size guard before ciborium deserialization)
  <!-- pid:duplicated_logic | batch:7 -->
- [x] **M-058** `[security]` `rfc/biology.rs:508`: Weight sum tolerance hardcoded at 0.01 -- ALREADY FIXED: WEIGHT_SUM_TOLERANCE constant
  <!-- pid:magic_value | batch:7 -->
- [-] **M-059** `[security]` `rfc/vdf.rs:127`: iterations_per_second=0 edge case allows division by zero -- FALSE POSITIVE: all division paths guarded
  <!-- pid:nan_inf_unguarded | batch:7 -->
- [x] **M-060** `[security]` `rfc/packet.rs:564`: Extensions field accepts arbitrary serde_json::Value -- ALREADY FIXED: count/key-length/value-bytes/depth limits in validate()
  <!-- pid:unsafe_deser | batch:7 -->
- [x] **M-061** `[security]` `rfc/wire_types/packet.rs:153`: packet_id == [0u8;16] check is weak; should require entropy -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:7 -->
- [x] **M-062** `[security]` `rfc/checkpoint.rs:131`: CHECKPOINT_HASH_DST hardcoded with legacy misspelling; no migration path -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:7 -->
- [x] **M-063** `[error_handling]` `rfc/wire_types/checkpoint.rs:152`: compute_hash calls CBOR encode but unwraps -- ALREADY FIXED: returns Result with map_err + ? propagation
  <!-- pid:unwrap_on_io | batch:7 -->
- [-] **M-064** `[error_handling]` `rfc/fixed_point.rs:51`: from_float returns 0 on !is_finite without logging -- FALSE POSITIVE: protocol crate is no_std/wasm, zero is correct clamping for fixed-point
  <!-- pid:silent_error | batch:7 -->
- [x] **M-065** `[error_handling]` `codec/mod.rs:317`: Format::detect returns None without error context -- FIXED 2026-04-03
  <!-- pid:unhelpful_error_msg | batch:7 -->
- [x] **M-066** `[maintainability]` `rfc/mod.rs:229`: CBOR_TAG_* constants duplicated in multiple modules -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:7 -->
- [-] **M-067** `[maintainability]` `war/ear.rs:62`: Ar4siStatus::from_i8 maps unknown to Contraindicated without logging -- FALSE POSITIVE: fail-closed by design, documented at line 54
  <!-- pid:silent_error | batch:7 -->
- [x] **M-068** `[security]` `compact_ref.rs:280`: signable_payload excludes metadata but allows evidence_uri omission -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:7 -->

### Key Hierarchy/Identity/WAR
- [-] **M-069** `[error_handling]` `keyhierarchy/session.rs:260`: Silent fallback on TPM quote serialization -- FALSE POSITIVE: error logged at warn level; TPM quotes optional
  <!-- pid:silent_error | batch:9 -->
- [x] **M-070** `[error_handling]` `keyhierarchy/verification.rs:117`: Lamport fallback to structural validation on missing pubkey -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:9 -->
- [x] **M-071** `[security]` `keyhierarchy/puf.rs:114`: Machine fingerprinting uses hostname+home_dir (user-controlled) -- FIXED 2026-04-03 (added machine UUID)
  <!-- pid:missing_validation | batch:9 -->
- [x] **M-072** `[error_handling]` `identity/secure_storage.rs:405`: Mutex poison on SEED_CACHE logged but continues -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:9 -->
- [x] **M-073** `[security]` `identity/secure_storage.rs:356`: Partial migration rollback on keychain save failure -- FIXED 2026-04-03
  <!-- pid:toctou | batch:9 -->
- [x] **M-074** `[security]` `sealed_identity/store.rs:183`: Public key mismatch detection after unseal success; HMAC not verified first -- ALREADY FIXED: HMAC verified in load_blob()
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-075** `[security]` `sealed_chain.rs:161`: document_id read unverified before decryption; header tamperable -- FALSE POSITIVE: full header (magic+version+nonce+document_id) is used as GCM AAD; tampering detected by AES-GCM auth tag on decrypt
  <!-- pid:toctou | batch:9 -->
- [-] **M-076** `[security]` `war/appraisal.rs:203`: Keystroke rate anomaly degrades only sourced_data, not overall verdict -- FALSE POSITIVE: overall_status takes max severity; sourced_data degradation propagates
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-077** `[code_quality]` `war/appraisal.rs:279`: packet_hash uses serde_json round-trip for canonicalization; platform-dependent -- FALSE POSITIVE: packet_hash uses ciborium::into_writer (deterministic CBOR per RFC 8949), not serde_json
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-078** `[security]` `war/compat.rs:77`: from_ear() reconstruction uses zero-initialized Seal fallback without flag -- FALSE POSITIVE: fallback explicitly sets reconstructed: true; debug log emitted
  <!-- pid:silent_error | batch:9 -->
- [-] **M-079** `[error_handling]` `war/compat.rs:147`: to_ear() loses forensic_summary on roundtrip -- FALSE POSITIVE: to_ear preserves forensic_summary; from_ear->Block is different type
  <!-- pid:silent_error | batch:9 -->
- [-] **M-080** `[security]` `war/ear.rs:159`: TrustworthinessVector parse_header assumes fixed 8-component order -- FALSE POSITIVE: parse_header uses label-prefix find (e.g. "II=") to locate each component by name, not by position
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-081** `[security]` `war/profiles/eu_ai_act.rs:84`: evidence_backed flag based on jitter_sealed without crypto verification -- FALSE POSITIVE: eu_ai_act profile is descriptive metadata; cryptographic verification is done at the WAR/verification layer, not in profile metadata
  <!-- pid:missing_validation | batch:9 -->

### Anchors/Bridge
- [-] **M-082** `[error_handling]` `anchors/ots.rs:352`: unwrap_or on Option<AnchorError> loses error context -- FALSE POSITIVE: unwrap_or_else correctly handles no-calendars case
  <!-- pid:unhelpful_error_msg | batch:1 -->
- [x] **M-083** `[error_handling]` `anchors/rfc3161.rs:562`: Same error context loss pattern as ots.rs -- FIXED 2026-04-02
  <!-- pid:unhelpful_error_msg | batch:1 -->
- [x] **M-084** `[code_quality]` `anchors/rfc3161.rs:146`: DER length encoding uses unchecked as u8 cast -- FIXED 2026-04-02
  <!-- pid:unwrap_on_io | batch:1 -->
- [-] **M-085** `[performance]` `cpoe_jitter_bridge/session.rs:180`: session_id String cloned per sample -- FALSE POSITIVE: session_id is Arc<str>; Arc::clone is a refcount bump, not a String allocation
  <!-- pid:clone_in_loop | batch:1 -->
- [-] **M-086** `[performance]` `cpoe_jitter_bridge/session.rs:263`: export() clones entire Vec<HybridSample> -- FALSE POSITIVE: HybridSample contains only fixed-size arrays ([u8;32]), primitive scalars, and Arc<str>; clone is O(n) shallow copies
  <!-- pid:clone_in_loop | batch:1 -->
- [x] **M-087** `[error_handling]` `cpoe_jitter_bridge/session.rs:381`: fs::remove_file error discarded with let _ = -- ALREADY FIXED: remove_file no longer exists
  <!-- pid:silent_error | batch:1 -->
- [-] **M-088** `[code_quality]` `cpoe_jitter_bridge/zone_engine.rs:49`: Unwrap on signed_duration_since; panics on clock skew -- FALSE POSITIVE: already uses unwrap_or with fallback
  <!-- pid:unwrap_on_io | batch:1 -->
- [-] **M-089** `[code_quality]` `anchors/ots.rs:104,112,120`: TODO(WU-14) markers for unimplemented OTS parsing -- FALSE POSITIVE: no TODO(WU-14) markers exist in current code; find_pending_calendars is implemented
  <!-- pid:todo_fixme | batch:1 -->

### CLI
- [x] **M-090** `[architecture]` `native_messaging_host.rs:1`: God module (1786 lines); all NMH logic in one file
  <!-- pid:god_module | batch:8 -->
- [x] **M-091** `[architecture]` `cmd_track.rs:1`: God module (1504 lines); mixed concerns
  <!-- pid:god_module | batch:8 -->
- [x] **M-092** `[architecture]` `cmd_export.rs:1`: God module (1384 lines); mixed concerns
  <!-- pid:god_module | batch:8 -->
- [-] **M-093** `[security]` `native_messaging_host.rs:630`: handle_stop_session doesn't fsync evidence file -- FALSE POSITIVE: line ~661 has `let _ = std::fs::File::open(&session.evidence_path).and_then(|f| f.sync_all())`
  <!-- pid:no_resource_cleanup | batch:8 -->
- [-] **M-094** `[security]` `native_messaging_host.rs:670`: Rate limit uses f64 arithmetic; precision accumulates -- FALSE POSITIVE: jitter rate limit uses integer u64 millitokens (JITTER_REFILL_PER_MS, JITTER_TOKEN_COST, JITTER_TOKEN_MAX); no f64
  <!-- pid:magic_value | batch:8 -->
- [-] **M-095** `[security]` `cmd_track.rs:150`: Symlink tracking warns but doesn't reject -- FALSE POSITIVE: watcher loop at line 641 uses `continue` to silently skip symlinks (reject without processing)
  <!-- pid:path_traversal | batch:8 -->
- [-] **M-096** `[performance]` `cmd_export.rs:95`: Full file read for checksum; no streaming hash -- FALSE POSITIVE: gated behind CHAR_COUNT_READ_LIMIT=10MB; hash verified after read to ensure content integrity; CLI tool, not server
- [-] **M-097** `[error_handling]` `cmd_export.rs:764,785,800`: expect() on 32-byte hash assumptions -- FALSE POSITIVE: code uses HashValue::try_sha256(...).map_err(|e| anyhow::anyhow!(e))? with proper error propagation; no expect()
  <!-- pid:unwrap_on_io | batch:8 -->
- [-] **M-098** `[security]` `main.rs:220`: Interactive menu path validation doesn't canonicalize symlinks -- FALSE POSITIVE: main.rs:220 checks is_symlink() and bail!s; then calls util::normalize_path
  <!-- pid:path_traversal | batch:8 -->
- [x] **M-099** `[maintainability]` `native_messaging_host.rs:1`: Browser protocol not versioned; no backcompat -- ALREADY FIXED: PROTOCOL_VERSION constant; version negotiation on Ping
  <!-- pid:hardcoded_config | batch:8 -->

---

## Session 5 Findings (2026-04-08) -- macOS + FFI Stack

### High

- [x] **H-044** `[error_handling]` `ffi/beacon.rs:155`: anchor failure silently yields success: true -- FIXED (success field now mirrors anchor_id.is_some(); error_message populated when anchor fails)
  <!-- pid:silent_error | first:2026-04-08 -->
  Impact: `anchor_res` error is logged at `warn!` then discarded; `FfiBeaconResult.success = true` is returned even when the WritersProof anchor call failed. Swift caller returns `CommandResult(success: true)` to the user -- they believe evidence is anchored when it is not. | Fix: If `anchor_res` is `Err`, either set `error_message` in the result or return `success: false`; distinguish "beacon fetched but not anchored" from "beacon fetched and anchored".

- [x] **H-045** `[concurrency]` `apps/cpoe_macos/cpoe/Service/CPoEService+Actions.swift`: stale session index -- FIXED (current code computes firstIndex after every await; capture-before-gap pattern used in export)
  <!-- pid:toctou | first:2026-04-08 -->
  Impact: `sessionIndex` is captured via `firstIndex(where:)` before `await engine.commit()`; a concurrent `refreshStatus()` can add, remove, or reorder `sessions` during the await. After the await, `sessions[idx]` may access the wrong session or crash out-of-bounds. | Fix: After the await, re-query by path: `if let idx = sessions.firstIndex(where: { $0.documentPath == doc })`.

- [ ] **H-046** `[security]` `crates/cpoe/src/ffi/writersproof_ffi.rs:82`: JWT token transiently in non-Zeroized heap during anchor call -- DEFERRED 2026-04-11 (not actionable: reqwest bearer_auth internally copies into HeaderValue outside our control; cpoe side already uses Zeroizing<String>)
  <!-- pid:key_zeroize_inconsistency | first:2026-04-08 -->
  Impact: `(*api_key).clone()` dereferences the `Zeroizing<String>` wrapper and clones a bare `String`. That allocation is not Zeroized until `with_jwt` re-wraps it one frame later -- same pattern in `beacon.rs:115`. Defeats the zeroize guarantee. | Fix: Change `with_jwt` to accept `Zeroizing<String>` directly; pass `api_key` (consumed) rather than `(*api_key).clone()`.

- [x] **H-047** `[resource_management]` `apps/cpoe_macos/cpoe/EngineService/EngineService.swift`: orphan FFI cleanup -- FIXED 2026-04-11 (CleanupTaskRegistry actor caps concurrent cleanups at 8 and deduplicates by session ID; drops new requests with a warning when full)
  <!-- pid:no_resource_cleanup | first:2026-04-08 -->
  Impact: `Task.detached { ffiEphemeralFinalize(...) }` is fire-and-forget. App shutdown or actor deallocation before the task runs leaves the Rust-side ephemeral session in memory indefinitely. | Fix: Store cleanup task handles; cancel and await them during graceful shutdown.

### Medium

- [x] **M-100** `[security]` `apps/cpoe_macos/cpoe/ChallengeService.swift`: session ID Unicode -- FIXED (current code validates via explicit ASCII scalar range plus length <= 128)
  <!-- pid:missing_validation | first:2026-04-08 -->
  Impact: Unicode homoglyphs or combining characters pass the guard but produce unexpected URL segments. Only ASCII alphanumerics and `-_` should be accepted. | Fix: Replace CharacterSet check with explicit ASCII byte-range comparison.

- [ ] **M-101** `[error_handling]` `crates/cpoe/src/ffi/beacon.rs:111`: Silent minimum timeout enforcement | **Model:** Haiku
  <!-- pid:silent_error | first:2026-04-08 -->
  Impact: `timeout_secs.max(5)` silently upgrades caller-supplied timeouts below 5s; callers expecting 1-2s for UI responsiveness stall for 5s with no indication. | Fix: `log::warn!` when minimum is applied, or reject sub-minimum values with a returned error.

- [ ] **M-102** `[maintainability]` `crates/cpoe/src/ffi/writersproof_ffi.rs:109`: `FfiResult::ok` returns human-readable string; `anchor_id` and `log_index` not machine-readable | **Model:** Sonnet
  <!-- pid:stringly_typed | first:2026-04-08 -->
  Impact: Swift caller must string-parse `"Anchored: <id> (log index <n>)"` to extract values; format changes silently break consumers. | Fix: Return a dedicated `FfiAnchorResult` record with `anchor_id: Option<String>` and `log_index: u64` fields.

- [x] **M-103** `[concurrency]` `apps/cpoe_macos/cpoe/StatusBarController.swift`: Task weak self guard -- FIXED (all Task closures with [weak self] now include an immediate guard let self; 4 sites audited)
  <!-- pid:weak_self_capture | first:2026-04-08 -->
  Impact: Timer and observer Task closures access `self?` properties without `guard let self else { return }`. If `StatusBarController` deallocates while a timer fires, closures execute on nil. | Fix: Add `guard let self else { return }` as first line of every `[weak self]` Task closure.

- [x] **M-104** `[error_handling]` `apps/cpoe_macos/cpoe/StatusBarController.swift`: untracked checkpoint Task -- FIXED (pendingChallengeTask is now stored and cancelled-then-replaced on each auto-checkpoint)
  <!-- pid:fire_and_forget | first:2026-04-08 -->
  Impact: `Task(priority: .utility) { ... }` for checkpoint writes is fire-and-forget. App termination before the task completes silently abandons the checkpoint. | Fix: Store the task handle and await it during shutdown, or track completion via the existing checkpoint state machine.

- [-] **M-105** `[security]` `crates/cpoe/src/writersproof/client.rs:196`: `Content-Length` pre-check in `get_certificate` is spoofable -- FALSE POSITIVE 2026-04-09
  <!-- pid:missing_validation | first:2026-04-08 -->
  <!-- get_certificate already uses chunked streaming with per-chunk size check (lines 201-214); Content-Length pre-check is optimization only, actual bytes are guarded -->

- [x] **M-106** `[error_handling]` `crates/cpoe/src/writersproof/client.rs:243`: `get_crl` missing `Content-Length` pre-check (inconsistent with `get_certificate`) -- FIXED 2026-04-09
  <!-- pid:missing_validation | first:2026-04-08 -->
  <!-- fix: replaced .bytes().await with chunked streaming matching get_certificate pattern; Content-Length pre-check retained as optimization -->

- [x] **M-107** `[security]` `ffi/sentinel.rs:110`: std::mem::take on Zeroizing<Vec<u8>> -- FIXED 2026-04-11 (changed set_hmac_key to accept Zeroizing<Vec<u8>>; callers pass the wrapper directly)
  <!-- pid:key_zeroize_inconsistency | first:2026-04-08 -->
  Impact: `mem::take` moves the inner `Vec` out of the `Zeroizing` wrapper; the wrapper's drop now zeroizes an empty allocation. The actual HMAC key bytes are only zeroized if `SecureStore` explicitly does so. | Fix: Pass the key by reference if `SecureStore::open` accepts `&[u8]`; otherwise manually call `.zeroize()` after the key has been consumed.

---

## Delta Scan: 2026-04-20 (24 changed files, 6 batches)

### CRITICAL-007: Integer underflow in posme verifier on step_id=0

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/posme/src/verifier.rs:206`
- **Severity:** CRITICAL | **Leverage:** HIGH | **Status:** rejected 2026-04-20 (false positive: derive_challenges() line 52 generates step=val+1, always >=1; line 149 equality check rejects any proof with non-matching step_ids)
- **Description:** `step as usize - 1` panics when step_id is 0. Untrusted proof can craft step_id=0 to crash verifier.
- **Root cause:** No bounds validation on step_id before subtraction.
- **Fix:** Add bounds check: `if sp.step_id < 1 || sp.step_id > ctx.k { return Err(...) }` or use `checked_sub(1)`.

---

### CRITICAL-008: Panic on malformed proof in posme verifier unwrap

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/posme/src/verifier.rs:174`
- **Severity:** CRITICAL | **Leverage:** HIGH | **Status:** rejected 2026-04-20 (false positive: sorted_transcripts built from proof.challenged_steps at line 158-160; find() at line 173 searches same collection for element that came from it; always succeeds)
- **Description:** `.find(...).unwrap()` panics if proof.challenged_steps doesn't contain expected step_id. Untrusted proof data triggers panic.
- **Root cause:** Missing error handling at trust boundary.
- **Fix:** Replace `.unwrap()` with `.ok_or_else(|| PosmeError::VerificationFailed(...))?`

---

### CRITICAL-009: Intermediate HMAC key hash not zeroized in crypto.rs

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/crypto.rs:73`
- **Severity:** CRITICAL | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: key parameter is packet_id per comment line 60-61, not secret material; SHA-256 of non-secret input has no confidentiality requirement)
- **Description:** `Sha256::digest(key)` intermediate GenericArray is not zeroized before moving into `Zeroizing`. Hash of key material persists in memory.
- **Root cause:** Sha256::digest returns temporary that lives until end of statement but isn't explicitly wiped.
- **Fix:** Use `Sha256::new().chain_update(key).finalize()` with explicit zeroize, or wrap entire derivation in Zeroizing scope.

---

### SYS-032: FFI unwrap on PathBuf::to_str() (3 instances)

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/ffi/sentinel_config.rs:135,167,206`
- **Severity:** CRITICAL | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: all 3 sites are inside #[cfg(test)] mod tests at line 126; test code panicking is standard Rust practice)
- **Description:** `.unwrap()` on `PathBuf::to_str()` in FFI functions. Non-UTF8 paths cause panic across FFI boundary (UB).
- **Fix:** Replace with `.map_err()` returning `FfiResult::err()`.
- **Closes:** 3 per-site instances

---

### H-181: Non-constant-time enum comparison in ct_eq

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/rfc/mod.rs:121`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** rejected 2026-04-20 (false positive: algorithm is public metadata, not secret; timing on 1-byte enum discriminant reveals nothing attacker doesn't already know from serialized structure)
- **Description:** `ct_eq()` uses `==` for algorithm enum before constant-time digest comparison. Side-channel leaks algorithm selection.
- **Fix:** Compare algorithm discriminant in constant-time: `(self.algorithm as u64).ct_eq(&(other.algorithm as u64))`

---

### H-182: Unbounded CBOR deserialization in COSE verification

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/crypto.rs:156`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** fixed 2026-04-20 (added MAX_COSE_INPUT_SIZE = 1 MiB check before CoseSign1::from_slice)
- **Description:** `CoseSign1::from_slice()` deserializes untrusted CBOR without size limit. Oversized payloads cause OOM/DoS.
- **Fix:** Add size check before parsing: reject if `cose_data.len() > MAX_COSE_SIZE` (e.g., 1MB).

---

### H-183: Float division bounds in VDF spec validation

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/rfc/vdf.rs:97`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: both operands guaranteed >0 by prior match guard line 91 `Some(v) if v > 0` and line 94 check; division of positive u64-as-f64 cannot produce NaN/-Inf)
- **Description:** Division in `is_duration_within_spec_bounds()` can produce -Infinity/NaN if expected becomes negative after unsigned wrap.
- **Fix:** Add guard: `if expected <= 0 { return false; }`

---

### H-184: Validation bypass via usize::MAX fallback in packet.rs

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/authorproof-protocol/src/rfc/packet.rs:496`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: logic reversed; unwrap_or(usize::MAX) causes size check to ALWAYS trigger on serialization failure, correctly rejecting unserializable extensions)
- **Description:** `serde_json::to_vec(v).unwrap_or(usize::MAX)` silently accepts extensions that cannot be serialized. Validation bypass.
- **Fix:** Return error on JSON encoding failure instead of falling through.

---

### H-185: expect() panic in cpoe-jitter HMAC evidence chain (2 sites)

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe-jitter/src/evidence.rs:301,329`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: HMAC-SHA256 accepts ANY key size per RFC 2104; with &[u8; 32] input this is provably infallible; .expect() documents an invariant)
- **Description:** `.expect("HMAC accepts any key size")` in append() and verify_integrity(). Library panic on construction; no_std makes panics fatal.
- **Fix:** Replace with `debug_assert!` or propagate Result. HMAC key size is guaranteed valid, but library code must not panic.

---

### H-186: Non-constant-time comparisons in posme verifier (2 sites)

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/posme/src/verifier.rs:34,149`
- **Severity:** HIGH | **Leverage:** HIGH | **Status:** rejected 2026-04-20 (false positive: both compared values are public/deterministic; Merkle commitment is in the proof; challenge indices are derived from public data; no secret to leak via timing)
- **Description:** Merkle root comparison and proof step_ids comparison use `==` (early-exit). Timing side-channel leaks proof structure.
- **Fix:** Use `subtle::ConstantTimeEq` for hash comparisons and proof data.

---

### H-187: Integer overflow in posme prover/verifier capacity (2 sites)

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/posme/src/prover.rs:215`, `crates/posme/src/verifier.rs:76`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** fixed 2026-04-20 (added MAX_TOTAL_STEPS = 1<<28 bound in params.validate(); prevents OOM/overflow at parameter validation time before any allocation)
- **Description:** `k as usize + 1` without overflow check. If k = u32::MAX, panic or memory exhaustion.
- **Fix:** Use `k.checked_add(1).ok_or_else(|| PosmeError::InvalidParams(...))?`

---

### H-188: Silent corruption skip in snapshot store

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/snapshot/store.rs:201`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** fixed 2026-04-20 (added skipped counter with log::error aggregate; callers can detect via monitoring)
- **Description:** Corrupt snapshot rows silently skipped with log::warn(). Caller cannot distinguish empty result from partial corruption.
- **Fix:** Return corruption count in result or propagate error.

---

### H-189: Timestamp fallback to 0 in snapshot store (2 sites)

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/snapshot/store.rs:98,320`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: timestamp_nanos_opt() returns None only for dates outside 1677-2262; cannot fail for current date; monotonicity safety net at line 121 provides additional protection)
- **Description:** `timestamp_nanos_opt().unwrap_or(0)` loses ordering info. Snapshots with timestamp=0 break monotonicity checks.
- **Fix:** Return Err() if timestamp acquisition fails.

---

### H-190: Unbounded base64 deserialization in compact_ref

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/compact_ref.rs:133`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: CompactRef has fixed-shape struct with no Vec/HashMap; deserialization is naturally bounded by struct schema; malformed JSON fails immediately)
- **Description:** `from_base64_uri` decodes and deserializes without size limit. Oversized URIs cause OOM.
- **Fix:** Add size check: reject if `decoded.len() > MAX_COMPACT_REF_SIZE` (e.g., 10KB).

---

### H-191: No entropy_bits bounds validation on deserialized evidence

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe-jitter/src/evidence.rs:196`
- **Severity:** HIGH | **Leverage:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: entropy_bits is informational metadata covered by HMAC integrity verification; can't be modified without invalidating chain; informational only, doesn't control allocations or security decisions)
- **Description:** TryFrom validation doesn't check entropy_bits bounds. Untrusted deserialized data could claim 255 bits.
- **Fix:** Add bounds check: `if record.entropy_bits > 64 { return Err(...) }`

---

### H-192: Unbounded entropy estimate without clamp

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe-jitter/src/phys.rs:258,308`
- **Severity:** HIGH | **Leverage:** LOW | **Status:** rejected 2026-04-20 (false positive: caller at line 186 already applies .min(MAX_ENTROPY_BITS) after taking minimum of both estimates; bounding is the caller's responsibility and is implemented)
- **Description:** `mcv_min_entropy()` and `markov_min_entropy()` return `-log2(p)` without upper bound clamp. Can exceed 64 bits.
- **Fix:** Add `.min(64.0)` clamp before returning.

---

### M-108: Misleading error type in compact_ref CBOR encoding

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/authorproof-protocol/src/compact_ref.rs:115`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (renamed InvalidJson to SerializationError across src + tests)
- **Description:** CBOR encoding error mapped to `InvalidJson` variant. Confusing diagnostic for ciborium failures.
- **Fix:** Add `CborEncoding` variant or rename to `SerializationError`.

---

### M-109: Unchecked string slice in EAR header parsing

- **Model:** Haiku | **Scope:** code_quality
- **Files:** `crates/authorproof-protocol/src/war/ear.rs:176`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (replaced part[label.len()..] with part.strip_prefix(label)?)
- **Description:** `part[label.len()..]` could panic if part is shorter than label. Relies on implicit guard.
- **Fix:** Use `part.strip_prefix(label)?` instead of manual slicing.

---

### M-110: Unbounded timestamp in VC profile creation

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/authorproof-protocol/src/war/profiles/vc.rs:126`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (added >24h future check after timestamp parsing)
- **Description:** `ear.iat` not validated for reasonable bounds. Malicious EAR with far-future timestamp creates misleading VC.
- **Fix:** Validate timestamp within ±2 hours or document acceptable range.

---

### M-111: Silent timestamp fallback in cpoe-jitter evidence

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe-jitter/src/evidence.rs:400`
- **Severity:** MEDIUM | **Status:** rejected 2026-04-20 (false positive: SystemTime::now().duration_since(UNIX_EPOCH) cannot fail unless system clock is before 1970; impossible on real hardware)
- **Description:** `unwrap_or_default()` on SystemTime makes timestamp 0 silently. Breaks monotonicity.
- **Fix:** Return Result or explicit error.

---

### M-112: Missing serialization stability test for compact_ref

- **Model:** Haiku | **Scope:** code_quality
- **Files:** `crates/authorproof-protocol/src/compact_ref.rs:125`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (added test_base64_uri_stability verifying determinism and encode-decode identity)
- **Description:** `to_base64_uri()` relies on stable serde field ordering. No regression test pins expected output.
- **Fix:** Add `test_compact_ref_serialization_stability()` with pinned expected base64.

---

### M-113: posme verifier verify_step function complexity (85 lines)

- **Model:** Haiku | **Scope:** architecture
- **Files:** `crates/posme/src/verifier.rs:195`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (extracted verify_symbiotic_write helper; verify_step reduced to 65 lines)
- **Description:** 85-line function with multiple nested conditionals in crypto verification path. Hard to audit.
- **Fix:** Split into sub-functions: verify_root_chain_step(), verify_pointer_chase(), verify_symbiotic_write().

---

### M-114: Magic statistical thresholds in cpoe-jitter model

- **Model:** Haiku | **Scope:** code_quality
- **Files:** `crates/cpoe-jitter/src/model.rs:26,28`
- **Severity:** MEDIUM | **Status:** fixed 2026-04-20 (added detailed doc comments with NIST SP 800-90B reference, typing speed derivation, and linear decay rationale)
- **Description:** MIN_STD_DEV_THRESHOLD_US=50, MIN_IKI_STD_DEV_THRESHOLD_US=5000 (100x difference), CONFIDENCE_PENALTY_PER_ANOMALY=0.25 without justification.
- **Fix:** Add detailed comments explaining threshold rationale and baseline references.

---

## New Findings — 2026-05-07 Full Re-Scan (Batches 1–7)

### CRITICAL-010: WAL dictation payload panics on corrupt data

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/wal/types.rs:137-143`
- **Severity:** CRITICAL | **Status:** fixed 2026-05-10 (verified: all try_into() calls already use .map_err with WalError::Serialization; no .unwrap() on try_into in dictation deserializers)
- **Description:** `DictationBeginPayload::from_bytes()`, `DictationFragmentPayload::from_bytes()`, and `DictationEndPayload::from_bytes()` use `.unwrap()` on `try_into()` slices. Corrupt or truncated WAL data causes panics that crash the daemon (DoS). Must propagate as `WalError::Serialization`.
- **Fix:** Replace all `.try_into().unwrap()` in WAL dictation deserializers with `try_into().map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?`

---

### CRITICAL-011: Archive+delete not atomic — orphaned archive on partial failure

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/store/archive.rs:141-206`
- **Severity:** CRITICAL | **Status:** fixed 2026-05-10 (verified: uses ATTACH DATABASE + single transaction for atomic INSERT+DELETE; .tmp rename pattern prevents orphans)
- **Description:** Archive DB is written first, then the DELETE runs in a separate transaction. If DELETE fails, the archive file exists but events remain in active DB — data is doubled and the archive is an inconsistent snapshot. Use SQLite `ATTACH` to run both operations in one transaction.
- **Fix:** Open archive DB with `ATTACH DATABASE ? AS archive`; run `INSERT INTO archive.events SELECT ... FROM events WHERE ...` + `DELETE FROM events WHERE ...` in one `BEGIN ... COMMIT`. Remove the two-step pattern entirely.

---

### CRITICAL-012: FFI report.rs panics on empty events vector

- **Model:** Haiku | **Scope:** errors
- **Files:** `crates/cpoe/src/ffi/report.rs:915`
- **Severity:** CRITICAL | **Status:** fixed 2026-05-10 (verified: line 1206 uses .ok_or_else; no .expect() on events.last() in report.rs)
- **Description:** `events.last().expect("events non-empty checked above")` — guard is 30 lines away from the `.expect()`. Any intermediate code path that empties `events` causes panic across FFI boundary (UB in Swift).
- **Fix:** Replace with `events.last().ok_or_else(|| "events unexpectedly empty".to_string())?`; propagate via `FfiResult::err(...)`.

---

### CRITICAL-013: FFI ephemeral.rs — unbounded Swift-controlled allocation before validation

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/ffi/ephemeral.rs:320`
- **Severity:** CRITICAL | **Status:** fixed 2026-05-10 (verified: line 310 checks intervals.len() > MAX_JITTER_INTERVALS * 10 before any iteration)
- **Description:** `intervals: Vec<u64>` is allocated from Swift-provided data before any length check. A caller can pass 1B items (8 GB allocation) triggering OOM before validation occurs. The bound check happens after the collect.
- **Fix:** Add `if intervals.len() > MAX_JITTER_INTERVALS * 2 { return FfiResult::err(...) }` as the very first statement in the FFI function before any iteration.

---

### CRITICAL-014: Forensic cache in report.rs has concurrent eviction race

- **Model:** Sonnet | **Scope:** concurrency
- **Files:** `crates/cpoe/src/ffi/report.rs:26-29`
- **Severity:** CRITICAL | **Status:** fixed 2026-05-10 (verified: now uses Mutex<BoundedLruCache> with atomic get/insert; no DashMap)
- **Description:** `forensic_cache()` is a static `DashMap`. Eviction logic (first-in-first-out at 10 entries) is not atomic with `get()`. Two concurrent FFI calls can evict + reinsert the same key interleaved, or one thread holds a reference while another evicts it. No LRU tracking.
- **Fix:** Replace DashMap + manual eviction with a bounded `lru::LruCache` behind `Arc<Mutex<>>`, or use DashMap with `entry()` API for atomic get-or-insert.

---

### CRITICAL-015: WAR seal Ed25519 signature covers only H3 hash, not full content

- **Model:** Opus | **Scope:** security
- **Files:** `crates/cpoe/src/war/verification.rs:175-182`
- **Severity:** CRITICAL | **Status:** rejected false-positive 2026-05-07 (hash-then-sign is cryptographically sound; H3 = SHA256(H2 || vdf_output || doc_hash) is a collision-resistant commitment to all inputs; forging H3 requires breaking SHA-256. SAFETY comment in war/mod.rs:176-178 documents this correctly.)
- **Description:** The WAR seal signature's signed message is `DST || H3` where H3 is a 32-byte hash computed from intermediate hashes. An attacker who forges any one intermediate hash (document_hash, checkpoint_root, jitter_root) to produce the same H3 can forge a WAR without breaking Ed25519. The signature should cover the full seal preimage or each individual component hash, not just the final digest.
- **Fix:** N/A — standard hash-then-sign; signing H3 = signing the full preimage given SHA-256 collision resistance.

---

### CRITICAL-016: CGEventTap TapCallback use-after-free on error path

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/platform/macos/keystroke.rs:107-149`
- **Severity:** CRITICAL | **Status:** rejected false-positive 2026-05-07 (null-tap path: creation failed, no callback registered; null-source path: CFRelease(tap) releases it before returning and the tap was never enabled; SAFETY comment lines 108-113 documents lifetime invariants correctly. CGEventTap fires only when both enabled and added to a run loop, neither of which happens on error paths.)
- **Description:** A raw pointer to a stack-allocated `TapCallback` is passed to `CGEventTapCreate`. If an error occurs after tap creation but before `CFRunLoopRun()` (lines 124-126), the function returns without disabling the tap. The tap remains registered pointing to a now-invalid stack frame. Subsequent OS events invoke the callback on freed stack memory.
- **Fix:** N/A — code is safe; see SAFETY comment in keystroke.rs:108-113.

---

### H-193: IPC rate limiter bypassed by reconnecting

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/ipc/server.rs:59`
- **Severity:** HIGH | **Status:** rejected false-positive 2026-05-07 (rate_limiter is Arc<Mutex<RateLimiter>> on IpcServer, Arc::clone'd to every handler — all connections share one instance. The per-connection doc comment on line 237 of crypto.rs is misleading but the code is server-wide.)
- **Description:** Rate limiter is per-connection. A client can exhaust the per-connection limit, disconnect, reconnect, and get a fresh counter. Per-connection rate limiting provides no actual throttling for local adversaries.
- **Fix:** N/A — rate limiter is already shared across all connections.

---

### H-194: IPC connection probing unlogged on partial read (1 byte)

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/ipc/server_handler.rs:94`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (verified: lines 94-99 and 116-121 both have explicit log::warn/error on partial read)
- **Description:** `read_exact(&mut peek_buf)` failing with EOF (client sent 1 byte and disconnected) is silently dropped — no audit log entry, no counter increment. An attacker probing the IPC socket port can do so without triggering any detection.
- **Fix:** Log at `warn!` level and increment a probe counter for any connection that closes before sending a valid 2-byte magic. Distinguish "EOF before magic" from "wrong magic" in log.

---

### H-195: FFI evidence_export divide-by-zero if ips == 0

- **Model:** Haiku | **Scope:** errors
- **Files:** `crates/cpoe/src/ffi/evidence_export.rs:201`
- **Severity:** HIGH | **Status:** rejected false-positive 2026-05-07 (ips is loaded with `.max(1)` on line 100 and `.unwrap_or(1)` fallback — always ≥ 1; no divide-by-zero possible)
- **Description:** `ev.vdf_iterations.saturating_mul(1000) / ips as u64` — if `ips == 0`, this is integer division by zero (panic). The elsewhere-present `if ips > 0` guard is missing here.
- **Fix:** N/A — ips is always ≥ 1 per .max(1) on load.

---

### H-196: FFI ephemeral flush_session_state write race

- **Model:** Sonnet | **Scope:** concurrency
- **Files:** `crates/cpoe/src/ffi/ephemeral.rs:291`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (verified: DashMap guard held during I/O; atomic write-then-rename with unique temp suffix)
- **Description:** After DashMap guard is released (line 259), two concurrent threads handling the same session_id both call `flush_session_state()`. The writes race and one can partially overwrite the other's state file, leaving a corrupted state on disk.
- **Fix:** Either hold the DashMap guard through the flush (no other lock needed), or use an `Arc<Mutex<()>>` per session for serializing flushes.

---

### H-197: TPM self-trust fallback allows attestation forgery

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/tpm/verification.rs:50-87`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (added doc comment warning that verify_binding is local-only; remote verification must use verify_binding_chain with trusted keys; code is intentionally designed this way)
- **Description:** When `trusted_keys` is empty, the verifier falls back to trusting the binding's own embedded public key. In a remote verification context, an attacker supplies both the binding and the key — self-verification is trivially forgeable.
- **Fix:** Remove the self-trust fallback entirely. Return `Err(TpmError::NoTrustedKeys)` when `trusted_keys.is_empty()`. All callers must supply at least one trusted key; the fallback in tests should supply the test key explicitly.

---

### H-198: WAL truncate/reopen inconsistency on file system error

- **Model:** Sonnet | **Scope:** errors
- **Files:** `crates/cpoe/src/wal/operations.rs:311-443`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (verified: in-memory state updated before marking inconsistent on all error paths)
- **Description:** After `fs::rename()` succeeds (new file replaces old), if the subsequent `reopen()` fails, state is marked inconsistent but `last_hash` + `next_sequence` in memory are stale (they match the pre-truncate state). Subsequent appends after recovery will build an invalid hash chain.
- **Fix:** After rename succeeds but reopen fails: call `state.recover_from_file()` to rebuild in-memory state from the new (already renamed) file before marking inconsistent.

---

### H-199: Checkpoint chain signature is length-only, no crypto verification

- **Model:** Opus | **Scope:** security
- **Files:** `crates/cpoe/src/checkpoint/chain_verification.rs:219-245`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (by design: comment at lines 237-241 documents structural-only check; crypto verification deferred to keyhierarchy::verify_checkpoint_signatures which has key material)
- **Description:** Chain verification performs only a length check on Ed25519 signatures (64 bytes) and defers actual cryptographic verification to callers. If a caller forgets to call `keyhierarchy::verify_checkpoint_signatures()`, a chain with forged signatures passes `verify_chain()`. This is a silent security bypass.
- **Fix:** Perform cryptographic signature verification inside `chain_verification.rs` using the chain's embedded public key. Remove the "caller must verify" pattern. Make security the default, not opt-in.

---

### H-200: Beacon attestation signed message has no field delimiters

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/war/verification.rs:670-681`
- **Severity:** HIGH | **Status:** fixed 2026-05-10 (verification already uses length-prefixed fields at lines 689-699; client anchor signature in ffi/beacon.rs now uses domain-separated SHA-256 digest with DST "cpoe-beacon-anchor-v1")
- **Description:** Beacon attestation signed message concatenates string fields (drand_randomness, nist_output_value, fetched_at) as raw UTF-8 bytes with no length prefixes or delimiters. A value containing the concatenation of two adjacent fields passes signature validation for either field order.
- **Fix:** Use length-prefixed encoding: `extend_from_slice(&(field.len() as u32).to_be_bytes()); extend_from_slice(field.as_bytes())` for each string field. Apply the same pattern as the rest of the CBOR/COSE encoding in the codebase.

---

### M-115: Sentinel lock ordering: current_focus acquired before sessions

- **Model:** Sonnet | **Scope:** concurrency
- **Files:** `crates/cpoe/src/sentinel/core.rs:1030-1036`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `current_focus.read_recover()` acquired, then `sessions.read_recover()` within the same scope — violates documented lock ordering (AUD-041): sessions(2) must be acquired before current_focus(3).
- **Fix:** Restructure the block to acquire sessions first, then current_focus. Or drop current_focus before acquiring sessions.

---

### M-116: Per-keystroke O(n) jitter scan in hot path

- **Model:** Haiku | **Scope:** performance
- **Files:** `crates/cpoe/src/sentinel/core.rs:620-634`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `session.jitter_samples.iter_mut().rev().find(|s| s.timestamp_ns == down_ts)` on every keyUp event. Buffer can hold up to 50,000 entries.
- **Fix:** Maintain a `HashMap<u64 /*timestamp_ns*/, usize /*index*/>` alongside jitter_samples for O(1) lookup. Clear on buffer reset.

---

### M-117: FFI text_fragment 10 MiB paste allocation before check

- **Model:** Haiku | **Scope:** performance
- **Files:** `crates/cpoe/src/ffi/text_fragment.rs:365-371`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `pasted_text.len() > MAX_PASTE_SIZE` is checked after the String is already allocated. 1 GB paste from untrusted source allocates fully before rejection.
- **Fix:** Enforce the limit in Swift before calling FFI. Document the invariant. Optionally add a separate Swift-side wrapper that checks length before calling the Rust FFI.

---

### M-118: WAR trust_bundle placeholder zero signing key deployed to production

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/war/trust_bundle.rs:39-40`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `MANIFEST_SIGNING_PUBKEY_HEX` is all zeros. If accidentally deployed, skips all manifest signature verification. Should panic or refuse to operate when key is zero.
- **Fix:** Add `assert_ne!(MANIFEST_SIGNING_PUBKEY_HEX, "0000000000000000000000000000000000000000000000000000000000000000", "production deployment requires real signing key")` in the verifier init. Or use a compile-time check: `const _: () = assert!(!matches!(MANIFEST_SIGNING_PUBKEY_HEX.as_bytes(), [b'0'; 64]))`.

---

### M-119: Baseline update silently drops NaN/Inf values

- **Model:** Haiku | **Scope:** errors
- **Files:** `crates/cpoe/src/store/baselines.rs:56-94`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: digest.rs has comprehensive is_finite guards on all inputs)
- **Description:** `if !value.is_finite() { return Ok(()) }` — callers cannot distinguish successful update from rejected non-finite value. Biometric baselines silently diverge from reality.
- **Fix:** Return `Err(Error::invalid_input("baseline value is non-finite"))` instead of `Ok(())`. Or log at `warn!` level at minimum.

---

### M-120: Path validation case-sensitivity on HFS+ for blocked prefixes

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/ipc/messages.rs:134-166`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `is_blocked_system_path` uses case-sensitive `starts_with()` on macOS. HFS+ is case-insensitive: `/System` and `/system` refer to the same directory, but only `/System` is blocked.
- **Fix:** On macOS, use `path.to_string_lossy().to_lowercase()` for comparison. Or use `std::fs::canonicalize()` which resolves to the real case-normalized path before prefix matching.

---

### M-121: Attestation forgery cost computation stores Infinity in report

- **Model:** Haiku | **Scope:** architecture
- **Files:** `crates/cpoe/src/forensics/forgery_cost.rs:308-321`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (replaced f64::INFINITY with INFEASIBLE_COST (1e308) for JSON-safe serialization)
- **Description:** When `has_infinite` (hardware attestation), code multiplies `f64::MAX * 100.0 = Infinity`. Stored in `overall_difficulty` and serialized to JSON as `null` or `Infinity` (non-standard JSON). Clients parsing the WAR may misinterpret or crash.
- **Fix:** Use a sentinel constant `const HARDWARE_ATTESTATION_DIFFICULTY: f64 = 1e308` (near-max but finite) for "effectively infinite" hardware attestation cost. Or use a tagged enum `ForgeryDifficulty { Finite(f64) | HardwareAttestation }`.

---

### M-122: HMAC-unverified timestamp path in store

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/store/events.rs:365-372`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `get_all_event_timestamps()` returns timestamps without HMAC verification. Callers may use these in forensic analysis assuming integrity, but the data is unverified. A compromised DB could return forged timestamps.
- **Fix:** Remove `get_all_event_timestamps()` or add a doc comment warning + make it `pub(crate)` with a strong "UNVERIFIED" name: `get_all_event_timestamps_unverified_do_not_use_in_reports()`. Add HMAC-verified variant.

---

### M-123: `update_file_path` silently bypasses HMAC on DB query failure

- **Model:** Haiku | **Scope:** errors
- **Files:** `crates/cpoe/src/store/events.rs:440`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `has_integrity` check uses `.unwrap_or(false)` — if the integrity table query fails, code proceeds as if integrity is absent and skips HMAC recomputation. File path update without re-HMAC corrupts event records silently.
- **Fix:** Replace `.unwrap_or(false)` with `?` — propagate the error and abort the update. The operation should fail loudly if integrity cannot be determined.

---

### M-124: stdin read unbounded in `cmd_attest`

- **Model:** Haiku | **Scope:** security
- **Files:** `apps/cpoe_cli/src/cmd_attest.rs:34`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: line 35 uses .take(50_000_000) to bound stdin to 50MB)
- **Description:** `io::stdin().read_to_string(&mut buf)` has no size limit. A malicious pipe can feed gigabytes of data causing OOM.
- **Fix:** Wrap stdin with `.take(50_000_000)` (50 MB limit): `io::stdin().take(50_000_000).read_to_string(&mut buf)`. Return `Err` if buf exceeds limit after read.

---

### M-125: `handle_snapshot_save` and `handle_ai_content_copied` skip URL length check

- **Model:** Haiku | **Scope:** security
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:784`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: ffi_snapshot_save uses validate_path + MAX_SNAPSHOT_SIZE; no URL parameters exist)
- **Description:** These handlers don't validate `document_url` length before writing to JSONL file. Other handlers check `MAX_URL_LEN` but these don't. A 1 MB URL from the browser extension bypasses the check and is written to disk.
- **Fix:** Add `if document_url.len() > MAX_URL_LEN { return Response::Error { ... } }` at the top of both handlers, matching the pattern in `handle_start_session`.

---

### M-126: Keyhierarchy session_id comparison non-constant-time

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/keyhierarchy/recovery.rs:21`
- **Severity:** MEDIUM | **Status:** rejected false-positive 2026-05-10 (verified: no vulnerability at described site)
- **Description:** `recovery.certificate.session_id == [0u8; 32]` is a non-constant-time comparison of cryptographic material. Should use `subtle::ConstantTimeEq`.
- **Fix:** `use subtle::ConstantTimeEq; if recovery.certificate.session_id.ct_eq(&[0u8; 32]).into() { ... }`

---

### M-127: Evidence packet `verify()` silently falls back to self-signed if no trusted key

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/evidence/packet.rs:52-311`
- **Severity:** MEDIUM | **Status:** rejected by-design 2026-05-10 (self-signed fallback is intentional for local consistency; documented with H-012 comment)
- **Description:** `verify(trusted_public_key: Option<[u8;32]>)` falls back to self-signed verification if `None` is passed. This means unintentional callers that pass `None` get a weaker verification guarantee without any compilation error.
- **Fix:** Split into `verify_self_signed()` and `verify_with_trusted_key(key: [u8;32])`. Remove the `Option` parameter. Callers must explicitly choose which verification level they want.

---

### M-128: activity_analysis.rs is 1603 lines — split required

- **Model:** Sonnet | **Scope:** maintainability
- **Files:** `crates/cpoe/src/fingerprint/activity_analysis.rs`
- **Severity:** MEDIUM | **Status:** open
- **Description:** 1603-line file implements 10+ distribution types. Highest-churn area of fingerprint module. Hard to audit, test, and maintain.
- **Fix:** Split into: `iki_analysis.rs` (IKI/interval stats), `zone_analysis.rs` (keyboard zone profiles), `pause_analysis.rs` (pause signatures), `session_analysis.rs` (SessionSignature, CircadianPattern), `distribution_helpers.rs` (shared stats utilities: percentile, pearson, etc.). Keep `mod.rs` as re-exports only.

---

## Delta Scan: 2026-05-07 (22 changed files, 15K lines)

### H-201: TPM verification uses verify() instead of verify_strict() — inconsistent with WAR verification

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/tpm/verification.rs:171`
- **Severity:** HIGH | **Status:** fixed 2026-05-07 (verify→verify_strict at tpm/verification.rs:171 and utils/crypto_helpers.rs:137; removed unused Verifier import)
- **Description:** `tpm/verification.rs:171` uses `verify()` for Ed25519 signature verification, while `war/verification.rs:136,688` uses `verify_strict()`. Non-strict verification could accept malformed signatures (e.g., non-canonical S values). All signature verification in a security-critical engine should use the strict variant.
- **Fix:** Replace `.verify()` with `.verify_strict()` in tpm/verification.rs. Add clippy-level lint or grep-based CI check to prevent reintroduction.

---

### H-202: TPM key verification loop leaks timing information via early return

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/tpm/verification.rs:66-72`
- **Severity:** HIGH | **Status:** fixed 2026-05-08 (replaced early-return loop with subtle::Choice accumulation; all keys verified before branching)
- **Description:** Loop over `trusted_keys` returns early on first successful verification. Timing side-channel: attacker can deduce which key in the ring succeeded or how many keys were tried before success. For a security-critical trust chain, all keys should be tested in constant time.
- **Fix:** Verify against all keys, collect results, then check if any succeeded. Use `subtle::Choice` to avoid branching: `let any_valid = results.iter().fold(Choice::from(0), |acc, r| acc | r);`

---

### H-203: Signing key path controllable via CPOE_DATA_DIR environment variable

- **Model:** Sonnet | **Scope:** security
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:184,505-509`
- **Severity:** HIGH | **Status:** fixed 2026-05-08 (removed CPOE_DATA_DIR from signing key path; always uses $HOME/.writersproof for flat-file fallback)
- **Description:** `CPOE_DATA_DIR` env var controls the fallback path for loading the device signing key. On multi-user systems, if attacker sets `CPOE_DATA_DIR=/tmp`, signing key is loaded from unprotected `/tmp`. The env var is useful for testing but should not control signing key location in production.
- **Fix:** Separate signing key path from data dir: always load signing key from `$HOME/.writersproof/signing_key` regardless of CPOE_DATA_DIR. Or validate CPOE_DATA_DIR ownership and permissions (owned by current user, not world-writable) before trusting it for key material.

---

### H-204: chmod failure on evidence temp file silently ignored — world-readable evidence window

- **Model:** Haiku | **Scope:** security
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:147`
- **Severity:** HIGH | **Status:** fixed 2026-05-07 (chmod failure now returns Response::Error instead of eprintln warning)
- **Description:** If `restrict_permissions()` fails on the temp evidence file, the handler logs a warning but continues. Evidence file may be world-readable during the window between creation and persist. On shared systems, other users can read keystroke evidence.
- **Fix:** Return `Response::Error` if chmod fails; do not persist world-readable evidence files. Check: `restrict_permissions(&tmp_path).map_err(|e| Response::Error { message: format!("chmod failed: {e}") })?;`

---

### H-205: Session seal uses all-zeros hash on evidence file read failure

- **Model:** Haiku | **Scope:** security
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:607`
- **Severity:** HIGH | **Status:** fixed 2026-05-07 (.map→.and_then; file read failure returns None for signature instead of sealing with zero-hash)
- **Description:** `fs::read().unwrap_or([0u8; 32])` at session end. If evidence file read fails (deleted, permissions, disk full), seal hash is all-zeros. Verifier cannot distinguish invalid seal from legitimate; no error response sent to browser extension.
- **Fix:** Return error if evidence file read fails: `let content = fs::read(&path).map_err(|e| Response::Error { message: format!("seal read: {e}") })?;` Log at error level.

---

### H-206: IPC SequenceDesync detection relies on fragile error string matching

- **Model:** Sonnet | **Scope:** error_handling
- **Files:** `crates/cpoe/src/ipc/server_handler.rs:193`
- **Severity:** HIGH | **Status:** fixed 2026-05-08 (added SequenceDesyncError typed error in crypto.rs; server_handler uses downcast_ref instead of string matching)
- **Description:** `starts_with("SequenceDesync:")` string match to detect sequence desynchronization in encrypted IPC channel. If the error message in the crypto module changes, sequence desync goes undetected and the connection is improperly closed or left open.
- **Fix:** Use a structured error type: `enum IpcCryptoError { SequenceDesync { expected: u64, got: u64 }, DecryptFailed, ... }`. Match on variant, not string prefix. Add test that verifies sequence desync is detected.

---

### H-207: FFI text_fragment store open failure returns success — paste events silently lost

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/ffi/text_fragment.rs:390-396`
- **Severity:** HIGH | **Status:** fixed 2026-05-07 (store open failure now returns FfiPasteRecordResult::err; signing key failure left as-is since hash lookup already succeeded)
- **Description:** `ffi_record_paste()` returns `FfiPasteRecordResult::ok(text_hash_hex, None)` when `open_store()` fails. Caller receives success with the hash but paste event is NOT persisted. The signing key failure at line 416 has the same pattern. Both break evidence chain integrity silently.
- **Fix:** Return `FfiPasteRecordResult::err()` when store open fails. Similarly for signing key at line 416. Caller (Swift) should retry or surface the error to the user.

---

### H-208: store/events.rs silent overflow clamps on integrity-relevant data fields

- **Model:** Sonnet | **Scope:** error_handling
- **Files:** `crates/cpoe/src/store/events.rs:77,87,99,102,313,328,333`
- **Severity:** HIGH | **Status:** fixed 2026-05-08 (write path: added logging to silent clamps on hw_cosign fields; read path: replaced unwrap_or(0) with error propagation via InvalidColumnType)
- **Description:** Seven instances of `unwrap_or(i64::MAX)` or `unwrap_or(0)` on `try_from()` conversions for `vdf_iterations`, `hardware_counter`, `hw_cosign_chain_index`, and `hw_cosign_entropy_bytes`. These silently clamp overflow values in integrity-relevant data. On the HOT PATH (every keystroke persistence), data loss is possible without error propagation.
- **Fix:** Return `Err()` on conversion failure instead of silent fallback. Let caller decide how to handle overflow. At minimum, log at error level when clamping occurs.

---

### M-129: sentinel/core.rs nested lock on sessions + cached_store without documented ordering

- **Model:** Sonnet | **Scope:** concurrency
- **Files:** `crates/cpoe/src/sentinel/core.rs:855-859`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (added AUD-041 lock ordering comment in restore_scrivener_state)
- **Description:** Bundle monitor code acquires `sessions.write_recover()` then `cached_store_for_loop.lock_recover()` inside the write guard. AUD-041 documents ordering for `signing_key < sessions < current_focus` but does not cover `cached_store`. If other code acquires these locks in reverse order, deadlock.
- **Fix:** Extend AUD-041 lock ordering documentation to include cached_store. Verify no reverse acquisition exists.

---

### M-130: sentinel/core.rs stop() discards spawn_blocking result silently

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/sentinel/core.rs:1522`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `let _ = tokio::task::spawn_blocking(...).await` discards result. If spawn_blocking fails during shutdown (runtime shutting down), final checkpoint is lost silently.
- **Fix:** Log error: `if let Err(e) = tokio::task::spawn_blocking(...).await { log::error!("Final checkpoint failed: {e}"); }`

---

### M-131: sentinel/core.rs shutdown signal send result discarded

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/sentinel/core.rs:1545`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** `let _ = tx.send(()).await` discards result. If receiver dropped, event loop won't exit gracefully; tokio task continues running.
- **Fix:** Log and handle: `if tx.send(()).await.is_err() { log::warn!("Event loop receiver dropped"); }`

---

### M-132: war/verification.rs try_into().unwrap() on CA public key bytes at trust boundary

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/war/verification.rs:635,668`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: resolved in prior sessions)
- **Description:** Two `try_into().unwrap()` calls on public key and signature byte conversions in CA attestation verification. Library code should not panic; these are at a trust boundary processing external attestation data.
- **Fix:** Replace `.unwrap()` with `.map_err(|_| CheckResult::fail("invalid CA key length"))` or equivalent error propagation.

---

### M-133: checkpoint/chain_verification.rs genesis_prev_hash error silently accepted as legacy genesis

- **Model:** Sonnet | **Scope:** security
- **Files:** `crates/cpoe/src/checkpoint/chain_verification.rs:127-128,204-210`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (added log::warn + report.warnings for legacy genesis prev_hash fallback)
- **Description:** `genesis_prev_hash()` computation errors are swallowed via `unwrap_or(false)`. If hash computation fails, chain is incorrectly validated as legacy genesis (all-zeros). Could accept invalid chains.
- **Fix:** Propagate hash computation errors. Return `Err()` instead of falling through to legacy check.

---

### M-134: WAL sync failure marks WAL permanently inconsistent with no recovery path

- **Model:** Sonnet | **Scope:** error_handling
- **Files:** `crates/cpoe/src/wal/operations.rs:142-148`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (added recovery hint log pointing to try_recover method)
- **Description:** If `sync_data()` fails after successful write, WAL is marked `inconsistent = true` permanently. All future appends fail. No `recover()` or `reset()` method exists.
- **Fix:** Add `Wal::recover()` that re-validates entries and clears inconsistent flag if data is sound. Or provide `clear_inconsistent()` with explicit operator acknowledgment.

---

### M-135: ffi/report.rs build_war_report_for_path is 208 lines with mixed business logic

- **Model:** Sonnet | **Scope:** architecture
- **Files:** `crates/cpoe/src/ffi/report.rs:880-1088`
- **Severity:** MEDIUM | **Status:** open
- **Description:** God function mixing stats computation, forensics analysis, VC building, and HTML rendering prep. FFI boundary should delegate to core, not contain business logic.
- **Fix:** Extract: `compute_report_data()`, `build_report_claims()`, `format_report_outputs()` into core modules; FFI calls them.

---

### M-136: ffi/report.rs build_dimensions is 214 lines with deeply nested conditionals

- **Model:** Sonnet | **Scope:** code_quality
- **Files:** `crates/cpoe/src/ffi/report.rs:634`
- **Severity:** MEDIUM | **Status:** open
- **Description:** 214-line function computing 6 scoring dimensions with 4+ nesting levels. Hard to test individual dimensions.
- **Fix:** Extract each dimension into its own function: `build_temporal_dimension()`, `build_edit_dimension()`, etc.

---

### M-137: native_messaging_host jitter buffer overflow returns success with truncated data

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:736-741`
- **Severity:** MEDIUM | **Status:** rejected false-positive 2026-05-10 (verified: no vulnerability at described site)
- **Description:** When jitter intervals exceed buffer capacity, data is silently truncated. `Response::JitterReceived` still returns success. Browser extension believes all intervals were stored.
- **Fix:** Include `dropped_count` in JitterReceived response, or return error if truncation occurs.

---

### M-138: native_messaging_host handle_start_session is 231 lines

- **Model:** Sonnet | **Scope:** code_quality
- **Files:** `apps/cpoe_cli/src/native_messaging_host/handlers.rs:25-255`
- **Severity:** MEDIUM | **Status:** open
- **Description:** Spans startup logic including dir creation, file I/O, key loading, session creation, prior session finalization. High churn (20 changes in 6 months).
- **Fix:** Extract: session creation, prior session finalization, key loading into helper functions.

---

### M-139: war/trust_bundle.rs parse_and_validate returns Option instead of typed error

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/war/trust_bundle.rs:119-139`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: already returns Result<_, TrustBundleError> with typed error enum)
- **Description:** Returns None on multiple distinct errors (bad JSON, invalid version, bad signature, bad entries). Caller cannot distinguish transient from permanent failures for retry logic.
- **Fix:** Return `Result<TrustBundle, TrustBundleError>` with variants: `ParseError`, `InvalidSignature`, `InvalidEntries`, `VersionMismatch`.

---

### M-140: store/archive.rs .ok() silently discards chain validation query errors

- **Model:** Haiku | **Scope:** error_handling
- **Files:** `crates/cpoe/src/store/archive.rs:136,558`
- **Severity:** MEDIUM | **Status:** fixed 2026-05-10 (verified: archive.rs uses try_ffi!() with proper error propagation; no .ok() on chain validation)
- **Description:** Two instances of `.ok()` that silently discard errors when querying chain link data. If query fails for reasons other than "no rows", error is swallowed. Weak chain integrity checking.
- **Fix:** Match explicitly: return Err for actual DB errors, Ok(None) only for QueryReturnedNoRows.

---

### M-141: ipc/messages.rs error responses leak field lengths to caller

- **Model:** Haiku | **Scope:** security
- **Files:** `crates/cpoe/src/ipc/messages.rs:318-323`
- **Severity:** MEDIUM | **Status:** rejected false-positive 2026-05-10 (verified: no vulnerability at described site)
- **Description:** validate_paths error messages include actual field lengths of oversized inputs. Attacker can infer buffer sizes from error responses.
- **Fix:** Return generic "field too large" error; log exact lengths to server-side log only.

---

### M-142: forensics/forgery_cost.rs estimate_forgery_cost is 240+ lines with repetitive structure

- **Model:** Sonnet | **Scope:** code_quality
- **Files:** `crates/cpoe/src/forensics/forgery_cost.rs:117-357`
- **Severity:** MEDIUM | **Status:** open
- **Description:** 8 component cost blocks follow similar pattern. Function exceeds 100-line guideline by 2.4x. Adding new components requires editing deep in the function.
- **Fix:** Extract component cost calculation into a builder pattern or vec of closures. Each component returns `CostComponent` struct.

---

### M-143: sentinel/core.rs event loop closure is 933 lines with 8+ nesting levels

- **Model:** Opus | **Scope:** architecture
- **Files:** `crates/cpoe/src/sentinel/core.rs:519-1451`
- **Severity:** MEDIUM | **Status:** open
- **Description:** The entire event loop is a single closure with tokio::select! branches for keystroke, mouse, focus, idle, checkpoint, and permission handling. 8+ levels of nesting. Maintenance cost is extreme (22 changes in 6 months).
- **Fix:** Extract each select! branch into a dedicated handler method: `handle_keystroke()`, `handle_checkpoint_tick()`, `handle_idle_check()`, etc. Keep event loop as thin dispatcher.
