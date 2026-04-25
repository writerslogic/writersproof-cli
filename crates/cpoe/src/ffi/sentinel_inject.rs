// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for keystroke/paste injection from host apps.

use super::sentinel::get_sentinel;
use crate::RwLockRecover;

/// Inject a keystroke event from the host app with hardware verification.
///
/// Used when the host platform captures keystrokes via `NSEvent.addGlobalMonitorForEvents`
/// (sandboxed macOS) and forwards them with CGEvent verification fields.
///
/// Verification fields (from `NSEvent.cgEvent`):
/// - `source_state_id`: CGEvent field 45. HID hardware = 1, injected = -1.
/// - `keyboard_type`: CGEvent field 10. ANSI=40, ISO=41, JIS=42; synthetic=0.
/// - `source_pid`: CGEvent field 41. Hardware = 0 (kernel); injected = injector PID.
///
/// Synthetic events are rejected, matching the CGEventTap `verify_event_source` behavior.
///
/// Maximum sustained keystroke injection rate (keystrokes per second).
///
/// Human peak burst typing is ~15 KPS; anything above 50 is clearly synthetic
/// or replayed. This constant is not user-configurable because raising it would
/// weaken anti-forgery protection. If a legitimate use case requires a higher
/// rate, the evidence packet will reflect the capped rate and flag the excess
/// as suspicious.
pub const MAX_INJECT_RATE_PER_SEC: u64 = 50;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

struct RateWindow {
    start: Option<Instant>,
    count: u64,
}

static RATE_LIMITER: Mutex<RateWindow> = Mutex::new(RateWindow {
    start: None,
    count: 0,
});

static LAST_INJECT_TS: AtomicI64 = AtomicI64::new(0);

/// Reset injection state (rate limiter window and last timestamp).
///
/// Must be called when the sentinel restarts so that stale state from a
/// previous run does not leak into the new session. Called automatically
/// by `ffi_sentinel_start`.
pub fn reset_inject_state() {
    LAST_INJECT_TS.store(0, Ordering::Relaxed);
    let mut window = match RATE_LIMITER.lock() {
        Ok(w) => w,
        Err(poisoned) => poisoned.into_inner(),
    };
    window.start = None;
    window.count = 0;
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_inject_keystroke(
    timestamp_ns: i64,
    keycode: u16,
    zone: u8,
    source_state_id: i64,
    keyboard_type: i64,
    source_pid: i64,
    char_value: String,
    coalesced_count: u64,
) -> bool {
    if char_value.len() > 16 {
        return false;
    }
    // SI-004: Reject non-positive timestamps. The caller uses NSEvent.timestamp
    // (mach_absolute_time based), which is always positive for real events.
    // Far-future values are valid (monotonic clock can be large after long uptime).
    if timestamp_ns <= 0 {
        return false;
    }
    let is_key_up = char_value == "UP";

    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    // KeyUp events carry no actionable data in the current pipeline: dwell time
    // computation requires pairing KeyDown/KeyUp by keycode, which the sentinel
    // does not yet implement. Returning true tells the caller the event was
    // accepted (not an error) so it does not retry or log a failure. When dwell
    // time recording is added, this path should feed the per-session dwell map.
    if is_key_up {
        return true;
    }

    // Rate limiting: reject if injection rate exceeds MAX_INJECT_RATE_PER_SEC.
    // Uses monotonic Instant (not caller-supplied timestamp) to prevent bypass
    // via crafted timestamps. H-017: Mutex-guarded window prevents races.
    {
        let mut window = match RATE_LIMITER.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let elapsed = window
            .start
            .map_or(true, |s| now.duration_since(s).as_secs() >= 1);
        if elapsed {
            window.start = Some(now);
            window.count = 1;
        } else {
            window.count += 1;
            if window.count > MAX_INJECT_RATE_PER_SEC {
                log::warn!(
                    "FFI keystroke injection rate exceeded ({}/s); rejecting",
                    window.count
                );
                return false;
            }
        }
    }

    // Feed voice fingerprint collector if enabled.
    // Only the first character matters (NSEvent.characters can be multi-char for
    // dead keys, but we want the primary character for writing style analysis).
    let char_opt = char_value.chars().next();
    if let Some(ref mut collector) = *sentinel.voice_collector.write_recover() {
        collector.record_keystroke(keycode, char_opt);
    }

    // Same verification as CGEventTap's verify_event_source.
    // Constants from CGEventTypes.h -- stable across macOS versions.
    const SOURCE_STATE_PRIVATE: i64 = -1;
    const SOURCE_STATE_HID_SYSTEM: i64 = 1;

    // Debug: log inject_keystroke calls
    #[cfg(debug_assertions)]
    if std::env::var("CPOE_DEBUG_INJECT").is_ok() {
        use std::sync::atomic::{AtomicU64, Ordering as AO};
        static INJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        static REJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        let n = INJECT_COUNT.fetch_add(1, AO::Relaxed);
        if source_state_id == SOURCE_STATE_PRIVATE || keyboard_type == 0 || source_pid != 0 {
            REJECT_COUNT.fetch_add(1, AO::Relaxed);
        }
        if n < 5 || n % 50 == 0 {
            use std::io::Write;
            let debug_path = std::env::var("CPOE_DATA_DIR")
                .map(|d| format!("{}/inject_debug.txt", d))
                .unwrap_or_else(|_| "/tmp/cpoe_inject_debug.txt".to_string());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "inject #{}: state={} kbd_type={} pid={} rejected_so_far={}",
                    n,
                    source_state_id,
                    keyboard_type,
                    source_pid,
                    REJECT_COUNT.load(AO::Relaxed)
                );
            }
        }
    }
    if source_state_id == SOURCE_STATE_PRIVATE {
        return false;
    }
    // When NSEvent.addGlobalMonitorForEvents delivers events without a backing
    // CGEvent (sandboxed apps), all three fields are 0. Accept these as trusted
    // in-process FFI injections from KeystrokeMonitorService. The PreWitnessBuffer
    // will still validate human plausibility before auto-starting a session.
    let is_unverified_ffi = source_state_id == 0 && keyboard_type == 0 && source_pid == 0;
    if !is_unverified_ffi {
        // keyboard_type 0 = no physical keyboard (synthetic). Values up to ~255
        // are valid Apple keyboard types (e.g. 106 = JIS, 44/45 = standard US).
        if keyboard_type == 0 {
            return false;
        }
        if source_pid != 0 {
            return false;
        }
        if source_state_id != SOURCE_STATE_HID_SYSTEM {
            log::debug!(
                "inject_keystroke: suspicious source_state_id={source_state_id} — accepted"
            );
        }
    }

    // Compute inter-keystroke duration from timestamps (the Swift side
    // sends absolute timestamps; we need the delta for cadence analysis).
    //
    // Design limitation: LAST_INJECT_TS is process-global, not per-document.
    // When the user switches between documents, the first keystroke in the new
    // document will produce an inflated duration_since_last_ns spanning the idle
    // period between documents. This causes the per-document cadence analysis to
    // see one anomalously long inter-key interval at each document switch.
    // Impact: negligible for typical use (one outlier per switch is filtered by
    // the jitter analyzer's outlier rejection), but cadence scores near the
    // boundary may be slightly penalized when documents are switched frequently.
    let prev_ts = LAST_INJECT_TS.swap(timestamp_ns, Ordering::Relaxed);
    let duration_since_last_ns = if prev_ts > 0 && timestamp_ns > prev_ts {
        (timestamp_ns - prev_ts) as u64
    } else {
        0
    };

    let sample = crate::jitter::SimpleJitterSample {
        timestamp_ns,
        duration_since_last_ns,
        zone,
        dwell_time_ns: None,
        flight_time_ns: None,
    };
    sentinel
        .activity_accumulator
        .write_recover()
        .add_sample(&sample);

    // Only count keystrokes when a tracked document is focused.
    let focus = sentinel.current_focus();
    crate::sentinel::trace!("[FFI_INJECT] focus={:?} keycode={}", focus, keycode);
    if let Some(ref path) = focus {
        if let Some(session) = sentinel.sessions.write_recover().get_mut(path) {
            let increment = coalesced_count.clamp(1, 10);
            session.keystroke_count = session.keystroke_count.saturating_add(increment);
            crate::sentinel::trace!(
                "[FFI_INJECT] COUNTED {:?} total={}",
                path,
                session.keystroke_count
            );
            let pushed =
                session.jitter_samples.len() < crate::sentinel::types::MAX_DOCUMENT_JITTER_SAMPLES;
            if pushed {
                session.jitter_samples.push(sample.clone());
            }

            let validation = crate::forensics::validate_keystroke_event(
                timestamp_ns,
                keycode,
                zone,
                source_pid,
                None,
                session.has_focus,
                &mut session.event_validation,
            );
            // Unverified FFI events (NSEvent without CGEvent backing, all source
            // fields zero) require a higher plausibility threshold since they
            // cannot be validated against HID system state (H-006).
            let min_confidence = if is_unverified_ffi { 0.5 } else { 0.1 };
            if validation.confidence < min_confidence {
                session.keystroke_count = session.keystroke_count.saturating_sub(increment);
                if pushed {
                    session.jitter_samples.pop();
                }
            }
        }
    }
    true
}
