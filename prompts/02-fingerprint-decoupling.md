# Session 2: Decouple Author Fingerprinting from Sentinel

## Project
Rust workspace at `/Volumes/A/writerslogic`. macOS SwiftUI app at `apps/cpoe_macos/`. Read CLAUDE.md and MEMORY.md for full context.

## Prerequisites
Complete Session 1 (bug fixes) first. Engine should have 1874+ tests passing, 0 clippy warnings.

## Goal
Make author fingerprinting collect typing dynamics across ALL apps (not just writing apps), independently of whether the sentinel is active. The fingerprint accumulator only needs raw timing data (IKI, dwell, flight, zone) — it does NOT need file attribution, focus tracking, or session management.

## Critical Design Constraint: Single Writer

ONE `ActivityFingerprintAccumulator` instance (global). At any moment, exactly ONE source feeds it:
- **Sentinel running:** sentinel feeds it (writing-app scoped). Fingerprint consumer pauses.
- **Sentinel not running:** fingerprint consumer feeds it (broad scope).

Enforced by `AtomicBool SENTINEL_IS_FEEDING`. This prevents double-counting which would corrupt IKI distributions (0ms intervals from duplicate timestamps).

## Architecture

```
CGEventTap (shared, app-level lifetime)
    |
    | std::sync::mpsc -> bridge thread -> tokio::sync::broadcast
    |
    |-> FingerprintCapture consumer (writes when SENTINEL_IS_FEEDING == false)
    |-> Sentinel event loop (writes when SENTINEL_IS_FEEDING == true, also does session mgmt)
```

`KeystrokeEvent` already derives `Clone` (`platform/events.rs:15`), so `broadcast` works.

## Part 1: SharedKeystrokeTap (Rust)

Extract the CGEventTap from sentinel-owned to app-level lifetime.

**Current:** `sentinel/core_setup.rs:76-160` creates `MacOSKeystrokeCapture`, starts tap, spawns bridge thread, returns `mpsc::Receiver`.

**New:** `platform/macos/shared_tap.rs` — global singleton owning the tap.

```rust
// crates/cpoe/src/platform/macos/shared_tap.rs
use std::sync::{Arc, OnceLock, atomic::{AtomicBool, AtomicU32, Ordering}};

pub struct SharedKeystrokeTap {
    capture: super::keystroke::MacOSKeystrokeCapture,
    bridge_thread: Option<std::thread::JoinHandle<()>>,
    broadcast_tx: tokio::sync::broadcast::Sender<super::events::KeystrokeEvent>,
    running: Arc<AtomicBool>,
    subscriber_count: Arc<AtomicU32>,
}

static SHARED_TAP: OnceLock<Arc<SharedKeystrokeTap>> = OnceLock::new();

pub fn get_or_start_shared_tap() -> crate::error::Result<Arc<SharedKeystrokeTap>> { ... }
pub fn get_shared_tap() -> Option<Arc<SharedKeystrokeTap>> { SHARED_TAP.get().cloned() }
```

**Bridge thread:** receives from `std::sync::mpsc::Receiver` (from MacOSKeystrokeCapture), broadcasts via `tokio::sync::broadcast::Sender`. Capacity 1024.

**Subscriber API:**
```rust
impl SharedKeystrokeTap {
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<KeystrokeEvent> { ... }
    pub fn unsubscribe(&self) { ... } // decrements ref count, stops tap if 0
}
```

**Changes to sentinel's `setup_keystroke_bridge()`:** Replace `self.platform.create_keystroke_capture()` + own bridge thread with `get_or_start_shared_tap()?.subscribe()`. The sentinel event loop changes from `keystroke_rx.recv()` to `broadcast_rx.recv().await`.

**Do NOT filter events at tap level.** Each consumer decides independently what to skip. Tap-level filtering would prevent sentinel from receiving events from apps a user adds to their custom allowlist.

## Part 2: FingerprintCapture Consumer (Rust)

New file: `crates/cpoe/src/fingerprint/capture.rs`

Subscribes to SharedKeystrokeTap, converts `KeystrokeEvent` -> `SimpleJitterSample`, feeds global accumulator. Only writes when `!sentinel_is_feeding()`.

```rust
pub struct FingerprintCapture {
    rx: tokio::sync::broadcast::Receiver<KeystrokeEvent>,
    accumulator: Arc<RwLock<ActivityFingerprintAccumulator>>,
    running: Arc<AtomicBool>,
    last_keydown_ts_ns: i64,
    last_keyup_ts_ns: i64,
    pending_downs: HashMap<u16, i64>,
    excluded_bundles: HashSet<String>,
    current_app_excluded: Arc<AtomicBool>,
    burst_buffer: VecDeque<i64>,
}
```

**IKI/dwell/flight computation MUST exactly match** `sentinel/event_handlers.rs:200-251`. Same dedup logic, same `ns_elapsed()` calls, same `dwell_time_ns: None` pattern. Add cross-reference comments in both files.

**Quality gate:** >=3 keystrokes within 2 seconds before samples count. Filters single-char searches.

**App exclusion via PID on KeystrokeEvent:**

In Part 1, add a `target_pid: i32` field to `KeystrokeEvent` (`platform/events.rs`). Populate it in the tap callback from `CGEventGetIntegerValueField(event, kCGEventTargetUnixProcessID)`. This requires no new dependencies — the CGEvent API is already used in the tap.

In the consumer, maintain a `pid_to_bundle: HashMap<i32, String>` cache. On cache miss, resolve PID to bundle ID via `NSRunningApplication(processIdentifier:)` (already used elsewhere in the codebase — check `sentinel/helpers.rs` for the pattern). Check against exclusion set. Cache entries expire after 60 seconds (processes can exit and PIDs can be reused).

Default exclusion list: Terminal, iTerm, Warp, 1Password, Keychain Access, System Preferences/Settings, Passwords.

This avoids needing an NSWorkspace observer from Rust and doesn't filter at tap level (each consumer decides independently).

**Secure input:** Check `IsSecureEventInputEnabled()` per-event in the consumer (NOT at tap level — tap-level blocking is too aggressive; macOS enables secure input globally when ANY password field exists in ANY window, even if user is typing elsewhere).

```rust
extern "C" { fn IsSecureEventInputEnabled() -> bool; }

// In the processing loop:
if unsafe { IsSecureEventInputEnabled() } { continue; }
```

**Tokio runtime:** Reuse the existing `FFI_RUNTIME` from `ffi/sentinel.rs:16`. The fingerprint capture task spawns on this runtime.

## Part 3: Global Accumulator + FFI (Rust)

New file: `crates/cpoe/src/fingerprint/global.rs`

```rust
use std::sync::{Arc, OnceLock, RwLock, atomic::{AtomicBool, Ordering}};

static SENTINEL_IS_FEEDING: AtomicBool = AtomicBool::new(false);
static GLOBAL_ACCUMULATOR: OnceLock<Arc<RwLock<ActivityFingerprintAccumulator>>> = OnceLock::new();

pub fn get_global_accumulator() -> Arc<RwLock<ActivityFingerprintAccumulator>> { ... }
pub fn set_sentinel_feeding(active: bool) { SENTINEL_IS_FEEDING.store(active, Ordering::SeqCst); }
pub fn sentinel_is_feeding() -> bool { SENTINEL_IS_FEEDING.load(Ordering::SeqCst) }
```

**New FFI functions** (proc macro, NOT UDL — codebase uses `#[uniffi::export]`):
```rust
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_start() -> FfiResult { ... }

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_stop() -> FfiResult { ... }

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_is_running() -> bool { ... }
```

**Sentinel changes:**
- `ffi_sentinel_start()`: add `set_sentinel_feeding(true)` after start
- `ffi_sentinel_stop()`: add `set_sentinel_feeding(false)` before stop
- Add `Drop` impl on sentinel's event loop context that calls `set_sentinel_feeding(false)` as crash recovery

**All files that read `sentinel.activity_accumulator` must switch to `get_global_accumulator()`:**

| File | Current | Change |
|------|---------|--------|
| `sentinel/core.rs:~112` | `pub(crate) activity_accumulator: Arc<RwLock<...>>` | Remove field |
| `sentinel/core.rs:~228` | Creates new accumulator | Pass `get_global_accumulator()` |
| `sentinel/core.rs:~305-324` | `self.activity_accumulator.read_recover()` | `get_global_accumulator().read_recover()` |
| `sentinel/event_handlers.rs:40-41` | `pub(super) activity_accumulator: Arc<RwLock<...>>` | Initialize from `get_global_accumulator()` |
| `ffi/sentinel_inject.rs:~393-395` | `sentinel.activity_accumulator.write_recover()` | `get_global_accumulator().write_recover()` |
| `ffi/fingerprint.rs:~60-65` | Reads sentinel accumulator for sample count | `get_global_accumulator().read_recover().sample_count()` |
| `ffi/fingerprint.rs:~478` | Reads sentinel accumulator for timing arrays | `get_global_accumulator().read_recover().samples()` |

**AUDIT each use:** If code uses `accumulator.sample_count()` for per-DOCUMENT evidence, it must use `session.keystroke_count` instead. Global accumulator count is for fingerprint maturity only.

**`FingerprintManager.reset_session()` must NOT clear the global accumulator.** Only `ffi_reset_fingerprint()` (explicit user action) may clear it.

**Sentinel stop must NOT clear the accumulator.** Verify `Sentinel::stop()` doesn't call `.clear()` or replace the Arc.

## Part 4: Swift UI

**FingerprintService additions** (`EngineService` extension):
```swift
func fingerprintCaptureStart() async -> CommandResult { await ffiWithTimeout("...") { ffiFingerprintCaptureStart() } }
func fingerprintCaptureStop() async -> CommandResult { await ffiWithTimeout("...") { ffiFingerprintCaptureStop() } }
func fingerprintCaptureIsRunning() -> Bool { ffiFingerprintCaptureIsRunning() }
```

**StyleFingerprintView.swift:**
- Add toggle for fingerprint capture (independent of sentinel)
- Persist state to `UserDefaults "fingerprintCaptureEnabled"`
- Auto-start on app launch if enabled (in `AppDelegate`, after FFI init, before sentinel auto-start)

**Live radar:** Poll `ffi_get_fingerprint_summary()` every 2s while fingerprint page is visible. RadarChartView already exists — just feed it updated dimensions.

## Part 5: EMA Consolidation (Intelligent Evolution)

Add periodic EMA merge into a canonical profile persisted to disk.

```
Ring buffer (10,000 samples) -> every 200 samples -> compute window fingerprint
    -> EMA merge into canonical profile -> save canonical_profile.json
```

**In FingerprintManager:** Add `canonical_profile: Option<AuthorFingerprint>`, load from disk on init. Add `maybe_consolidate()` called after samples accumulate.

**Alpha formula:** `1.0 / (1.0 + (consolidation_count + 1) as f64 * 0.5)` — at count=0, alpha=0.67 (NOT 1.0 — first merge blends, doesn't replace). This protects a canonical loaded from a previous session.

**Comparison/verification uses canonical profile** (falls back to window if canonical is None).

**Storage:** `fingerprints/canonical_profile.json`, atomic write via tmp+rename.

## Part 6: Supabase Sync

Upload full canonical profile JSON to `author_fingerprints.canonical_profile` (JSONB column).

**Migration:**
```sql
ALTER TABLE author_fingerprints ADD COLUMN canonical_profile JSONB DEFAULT NULL;
ALTER TABLE author_fingerprints ADD COLUMN lifetime_sample_count BIGINT DEFAULT 0;
ALTER TABLE author_fingerprints ADD COLUMN profile_version INTEGER DEFAULT 1;
CREATE INDEX idx_author_fingerprints_canonical ON author_fingerprints (user_id) WHERE canonical_profile IS NOT NULL;
```

**New FFI:** `ffi_export_canonical_fingerprint_json() -> Option<String>`

**Signature:** Sign canonical with device Ed25519 key before upload. Store public key alongside signature so other devices can verify. On download, verify signature — reject if tampered.

**CloudSyncService.swift:** After consolidation, upload canonical profile. On new device setup, download and install as local canonical.

## Dependency Order
```
Part 1 (shared tap) -> Part 2 (consumer) -> Part 3 (global + FFI) -> Part 4 (Swift UI)
                                                                   -> Part 5 (EMA consolidation)
                                                                   -> Part 6 (Supabase sync)
```

## Tests
```rust
test_quality_gate_filters_isolated_keystrokes
test_sentinel_feeding_flag_prevents_double_write
test_iki_computation_matches_sentinel  // feed same events, compare outputs
test_excluded_app_skips_events
test_shared_tap_ref_counting
test_keyup_dedup_and_dwell_tracking
test_canonical_persists_across_restart
test_alpha_decay_stabilizes_profile
```

## Constraints
- `GLOBAL_ACCUMULATOR` uses `std::sync::OnceLock` (MSRV 1.75)
- `SharedKeystrokeTap` and `FingerprintCapture` are `pub(crate)` — not public API
- CGEventTap mask stays `kCGEventKeyDown | kCGEventKeyUp` only
- Secure input check goes in the CONSUMER, not the tap (tap-level is too aggressive)
- FFI uses proc macros (`#[uniffi::export]`), NOT UDL declarations
- Reuse existing `FFI_RUNTIME` (`ffi/sentinel.rs:16`) for fingerprint capture tokio tasks
