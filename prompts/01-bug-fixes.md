# Session 1: Fix macOS App Live Metrics, Freeze, and Document List

## Project
Rust workspace at `/Volumes/A/writerslogic` (CPoE authorship witnessing engine). macOS SwiftUI app at `apps/cpoe_macos/`. Read CLAUDE.md and MEMORY.md for full context.

## What Was Already Done (do not redo)
- HTML forensic report template + `render_forensic_html()` + FFI export wired into macOS ExportFormView
- Fingerprint improvements (VelocityProfile dimension, maturity-aware thresholds, forgery tightening)
- C2PA validation + RFC 3161 TSA token in manifest builder
- Checkpoint forensic gating tests (10 new, all passing)
- NaN/Inf guards, silent error logging, SPKI pin rotation, debug log cleanup
- `CheckpointPolicy.recordKeystrokeHint` changed to `localKeystrokeCounter += 1`
- `LiveAnalysisPanel` has a fallback authenticity ring from `status.forensicScore`
- `accommodatePresentedItemDeletion` calls `completionHandler(nil)` before async work
- `presentedItemOperationQueue` changed to dedicated serial background queue
- `ffi_list_tracked_files` filters sessions with 0 keystrokes and no focus
- Static library rebuilt, FFI bindings regenerated
- Engine: 1874 tests passing, 0 clippy warnings. Protocol: 257 tests passing.

---

## Bug 1: Live analysis panel shows 0 WPM, 0% edits, 0% score, 0 baseline

### Root cause
`LiveAnalysisPanel.swift` line 25 wraps `realTimeStatsStrip`, `EvidenceStrengthCard`, and `baselineIndicators` inside `if let breakdown = service.liveBreakdown`. `liveBreakdown` requires >=2 stored checkpoint events. Checkpoints don't fire until the editor saves. A fallback score ring exists but the stats strip is still gated.

### Fix: 5 edits across Rust + Swift

**Edit 1 — Rust: Add `words_per_minute` to `FfiWitnessingStatus`**

File: `crates/cpoe/src/ffi/types.rs:318-343`
Add field: `pub words_per_minute: f64,`

File: `crates/cpoe/src/sentinel/types.rs` — add method to `DocumentSession`:
```rust
/// Real-time WPM from the last 60 seconds of jitter samples.
/// Iterates from the back (newest first) and stops as soon as
/// samples fall outside the 60-second window — O(window) not O(total).
pub fn recent_wpm(&self) -> f64 {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let window_ns = 60_000_000_000i64;
    let mut count = 0usize;
    let mut oldest_ns = now_ns;
    for s in self.jitter_samples.iter().rev() {
        if now_ns - s.timestamp_ns >= window_ns { break; }
        if now_ns - s.timestamp_ns < 0 { continue; } // clock skew guard
        count += 1;
        oldest_ns = s.timestamp_ns;
    }
    if count < 5 { return 0.0; }
    let window_secs = (now_ns - oldest_ns) as f64 / 1_000_000_000.0;
    if window_secs < 1.0 { return 0.0; }
    (count as f64 / 5.0) / (window_secs / 60.0)
}
```

File: `crates/cpoe/src/ffi/sentinel_witnessing.rs:340-362` — add to `FfiWitnessingStatus` construction:
```rust
words_per_minute: session.recent_wpm(),
```

Also add `words_per_minute: 0.0,` to the `not_tracking()` function (`sentinel_witnessing.rs:229`).

**Edit 2 — Swift: Add fields to `WitnessStatus`**

File: `apps/cpoe_macos/cpoe/EngineService/EngineTypes.swift:205-223`
Add after `keystrokeCaptureActive`:
```swift
var editingRatio: Double = 0.0
var sessionActivity: String = ""
var totalDeletions: Int = 0
var undoCount: Int = 0
var wordsPerMinute: Double = 0.0
```

**Edit 3 — Swift: Map FFI fields to WitnessStatus**

File: `apps/cpoe_macos/cpoe/EngineService/EngineService.swift:1221-1236`
After line 1227 (`status.keystrokeCaptureActive = witnessing.keystrokeCaptureActive`), add:
```swift
status.editingRatio = min(max(witnessing.editingRatio, 0.0), 1.0)
status.sessionActivity = witnessing.sessionActivity
status.totalDeletions = max(Int(witnessing.totalDeletions), 0)
status.undoCount = max(Int(witnessing.undoCount), 0)
status.wordsPerMinute = max(witnessing.wordsPerMinute, 0.0)
```

**Edit 4 — Swift: Update HMAC payload**

File: `apps/cpoe_macos/cpoe/Service/CPoEService+Polling.swift:500-503`
The `computeStatusHMAC` function builds a payload string by interpolating fields separated by `\0`. The current payload looks like:
```swift
let payload = "\(s.keystrokeCount)\0\(s.isTracking)\0\(s.trackingDocument ?? "")\0\(s.totalCheckpoints)\0\(s.swfCalibrated)\0\(s.tpmAvailable)\0\(s.forensicScore)\0\(s.databaseEvents)\0\(s.databaseFiles)\0\(s.trackingDuration)"
```
Find that string interpolation and append the new fields at the end, before the closing `"`:
```swift
\0\(s.editingRatio)\0\(s.sessionActivity)\0\(s.totalDeletions)\0\(s.undoCount)\0\(s.wordsPerMinute)
```
Without this, changes to these fields won't trigger UI updates (change detection compares HMAC of serialized status).

**Edit 5 — Swift: Add fallback stats strip to LiveAnalysisPanel**

File: `apps/cpoe_macos/cpoe/Popover/LiveAnalysisPanel.swift:25-33`
Replace the second `if let breakdown` block:
```swift
if let breakdown = service.liveBreakdown {
    realTimeStatsStrip(breakdown)
        .padding(.bottom, Design.Spacing.sm)
    EvidenceStrengthCard(breakdown: breakdown)
        .padding(.bottom, Design.Spacing.sm)
    baselineIndicators(breakdown)
} else if service.status.isTracking {
    fallbackStatsStrip
        .padding(.bottom, Design.Spacing.sm)
}
```

Add new computed property (after `realTimeStatsStrip`):
```swift
private var fallbackStatsStrip: some View {
    let s = service.status
    return HStack(spacing: 0) {
        statColumn(icon: "keyboard", value: formatCount(service.displayedKeystrokeCount),
                   label: String(localized: "Keys", comment: "Stat label"), pulse: service.keystrokePulse)
        statDivider
        statColumn(icon: "gauge.medium", value: "\(min(Int(s.wordsPerMinute), 999))",
                   label: String(localized: "WPM", comment: "Stat label"))
        statDivider
        statColumn(icon: "arrow.uturn.backward",
                   value: String(format: "%.1f%%", s.editingRatio * 100),
                   label: String(localized: "Edits", comment: "Stat label"))
        statDivider
        statColumn(icon: "shield.checkered", value: "\(Int(s.forensicScore * 100))%",
                   label: String(localized: "Score", comment: "Stat label"), tint: strengthColor(s.forensicScore))
    }
    .padding(.vertical, Design.Spacing.xs)
    .background(Design.Colors.tertiaryBackground.opacity(0.5),
                in: RoundedRectangle(cornerRadius: Design.Radius.sm))
}
```

---

## Bug 2: App freezes (pinwheel) on focus changes and document close

### Root cause
`ffiWithTimeout` (`SentinelService.swift:63`) uses `DispatchQueue.sync` inside a detached task, blocking a Swift Concurrency thread. Multiple concurrent FFI calls exhaust the thread pool.

### Fix: 3 edits

**Edit 1 — Replace sync with async + continuation**

File: `apps/cpoe_macos/cpoe/EngineService/SentinelService.swift:63-67`
Replace:
```swift
Task.detached(priority: .userInitiated) {
    let value = Self.ffiQueue.sync { operation() }
    continuation.yield(.value(value))
    continuation.finish()
}
```
With:
```swift
Task.detached(priority: .userInitiated) {
    let value = await withCheckedContinuation { (cont: CheckedContinuation<T, Never>) in
        Self.ffiQueue.async {
            cont.resume(returning: operation())
        }
    }
    continuation.yield(.value(value))
    continuation.finish()
}
```

**Edit 2 — Fix second .sync call**

File: `apps/cpoe_macos/cpoe/EngineService/SentinelService.swift:105`
Change `Self.ffiQueue.sync { ffiSetSnapshotsEnabled(enabled: snapshotsOn) }`
To: `Self.ffiQueue.async { ffiSetSnapshotsEnabled(enabled: snapshotsOn) }`

**Edit 3 — Cache cloudSyncWarning result**

File: `apps/cpoe_macos/cpoe/Popover/DashboardMonitoring.swift:374-386`
Currently calls `CloudSyncDetectionService.shared.cloudSyncWarning(for: docPath)` inside a `@ViewBuilder` on every SwiftUI redraw, doing filesystem I/O each time.

Add `@State private var cachedCloudWarning: String? = nil` to the view.
Replace the computed property body to read from cache.
Add `.task(id: service.trackingDocument)` to the parent view to recompute only on document change:
```swift
.task(id: service.trackingDocument) {
    cachedCloudWarning = service.trackingDocument.flatMap {
        CloudSyncDetectionService.shared.cloudSyncWarning(for: $0)
    }
}
```

---

## Bug 3: Document list accumulates closed files

### Root cause
`ffi_list_tracked_files` returns all sentinel sessions with keystrokes, even after the user closes the file. The sentinel's HashMap is append-only.

### Fix: 2 edits (Rust + Swift)

**Edit 1 — Rust: Add `is_active` field + fix timestamp**

File: `crates/cpoe/src/ffi/types.rs` — find `FfiTrackedFile` struct, add `pub is_active: bool,`

File: `crates/cpoe/src/ffi/system.rs:305-326` — when building FfiTrackedFile from sentinel sessions:
- Change `session.start_time` to `session.last_focus_time` for the timestamp
- Add `is_active: session.has_focus,`
- For database-sourced entries (earlier in the function), set `is_active: false,`

**Edit 2 — Swift: Filter by active status**

Find where `trackedFiles` is displayed (grep for `trackedFiles` in `DashboardMonitoring.swift` or `DashboardView.swift`). Filter to show only active files or the current tracking document:
```swift
let visibleFiles = trackedFiles.filter { $0.isActive || $0.path == service.status.trackingDocument }
```

---

## Build and Verify
```bash
cargo check -p cpoe --lib && cargo clippy -p cpoe --lib && cargo test -p cpoe --lib
# Then: rebuild static lib + FFI bindings
cargo build --release --features ffi,posme --target aarch64-apple-darwin -p cpoe
cp /Volumes/C/rust-target/aarch64-apple-darwin/release/libcpoe_engine.a apps/cpoe_macos/cpoe/CPoEEngineFFI/
cd apps/cpoe_macos && bash scripts/generate_ffi.sh
```

Test in Xcode: type 30+ chars in VS Code, verify WPM/edits/score show real values, close docs without pinwheel, only open docs in list.

## Constraints
- Batch edits, minimize cargo runs. Re-read files before editing.
- Don't revert parallel session or linter changes. Don't split working files.
- When adding fields to FfiWitnessingStatus, FFI bindings must be regenerated.
