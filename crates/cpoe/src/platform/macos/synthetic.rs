// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Synthetic event detection and dual-layer HID validation.
//!
//! Performance-critical: `verify_event_source` runs in the CGEventTap callback
//! on every keystroke. All stats use lock-free atomics to avoid serializing the
//! callback thread.

use super::ffi::*;
use super::EventVerificationResult;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::DualLayerValidation;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticEventStats {
    pub total_events: u64,
    pub verified_hardware: u64,
    pub rejected_synthetic: u64,
    pub suspicious_accepted: u64,
    pub rejected_bad_source_state: u64,
    pub rejected_bad_keyboard_type: u64,
    pub rejected_non_kernel_pid: u64,
    pub rejected_zero_timestamp: u64,
}

/// Lock-free atomic counters for synthetic event stats. Using Relaxed ordering
/// since these are diagnostic counters with no synchronization dependencies.
struct AtomicSyntheticStats {
    total_events: AtomicU64,
    verified_hardware: AtomicU64,
    rejected_synthetic: AtomicU64,
    suspicious_accepted: AtomicU64,
    rejected_bad_source_state: AtomicU64,
    rejected_bad_keyboard_type: AtomicU64,
    rejected_non_kernel_pid: AtomicU64,
    rejected_zero_timestamp: AtomicU64,
}

static SYNTHETIC_STATS: AtomicSyntheticStats = AtomicSyntheticStats {
    total_events: AtomicU64::new(0),
    verified_hardware: AtomicU64::new(0),
    rejected_synthetic: AtomicU64::new(0),
    suspicious_accepted: AtomicU64::new(0),
    rejected_bad_source_state: AtomicU64::new(0),
    rejected_bad_keyboard_type: AtomicU64::new(0),
    rejected_non_kernel_pid: AtomicU64::new(0),
    rejected_zero_timestamp: AtomicU64::new(0),
};

static STRICT_MODE: AtomicBool = AtomicBool::new(true);

/// In strict mode suspicious events are rejected; in permissive mode they're accepted but flagged.
pub fn set_strict_mode(strict: bool) {
    STRICT_MODE.store(strict, Ordering::SeqCst);
}

pub fn get_strict_mode() -> bool {
    STRICT_MODE.load(Ordering::SeqCst)
}

pub fn get_synthetic_stats() -> SyntheticEventStats {
    SyntheticEventStats {
        total_events: SYNTHETIC_STATS.total_events.load(Ordering::Relaxed),
        verified_hardware: SYNTHETIC_STATS.verified_hardware.load(Ordering::Relaxed),
        rejected_synthetic: SYNTHETIC_STATS.rejected_synthetic.load(Ordering::Relaxed),
        suspicious_accepted: SYNTHETIC_STATS.suspicious_accepted.load(Ordering::Relaxed),
        rejected_bad_source_state: SYNTHETIC_STATS
            .rejected_bad_source_state
            .load(Ordering::Relaxed),
        rejected_bad_keyboard_type: SYNTHETIC_STATS
            .rejected_bad_keyboard_type
            .load(Ordering::Relaxed),
        rejected_non_kernel_pid: SYNTHETIC_STATS
            .rejected_non_kernel_pid
            .load(Ordering::Relaxed),
        rejected_zero_timestamp: SYNTHETIC_STATS
            .rejected_zero_timestamp
            .load(Ordering::Relaxed),
    }
}

pub fn reset_synthetic_stats() {
    SYNTHETIC_STATS.total_events.store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .verified_hardware
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .rejected_synthetic
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .suspicious_accepted
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .rejected_bad_source_state
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .rejected_bad_keyboard_type
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .rejected_non_kernel_pid
        .store(0, Ordering::Relaxed);
    SYNTHETIC_STATS
        .rejected_zero_timestamp
        .store(0, Ordering::Relaxed);
}

/// Detects CGEventPost injection by checking source state, keyboard type, and PID.
///
/// # Safety
///
/// `event` must be a valid `CGEventRef` obtained from a CGEventTap callback.
pub unsafe fn verify_event_source(event: *mut std::ffi::c_void) -> EventVerificationResult {
    let strict = STRICT_MODE.load(Ordering::SeqCst);

    let source_state_id = CGEventGetIntegerValueField(event, K_CG_EVENT_SOURCE_STATE_ID);
    let keyboard_type = CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE);
    let source_pid = CGEventGetIntegerValueField(event, K_CG_EVENT_SOURCE_UNIX_PROCESS_ID);

    let mut suspicious = false;

    // Private source state = programmatic injection
    if source_state_id == K_CG_EVENT_SOURCE_STATE_PRIVATE {
        SYNTHETIC_STATS.total_events.fetch_add(1, Ordering::Relaxed);
        SYNTHETIC_STATS
            .rejected_synthetic
            .fetch_add(1, Ordering::Relaxed);
        SYNTHETIC_STATS
            .rejected_bad_source_state
            .fetch_add(1, Ordering::Relaxed);
        return EventVerificationResult::Synthetic;
    }

    if source_state_id != K_CG_EVENT_SOURCE_STATE_HID_SYSTEM {
        suspicious = true;
    }

    // Real keyboards report type (ANSI=40, ISO=41, JIS=42); synthetic events use 0
    if keyboard_type == 0 {
        if strict {
            SYNTHETIC_STATS.total_events.fetch_add(1, Ordering::Relaxed);
            SYNTHETIC_STATS
                .rejected_synthetic
                .fetch_add(1, Ordering::Relaxed);
            SYNTHETIC_STATS
                .rejected_bad_keyboard_type
                .fetch_add(1, Ordering::Relaxed);
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    if keyboard_type > 100 {
        SYNTHETIC_STATS.total_events.fetch_add(1, Ordering::Relaxed);
        SYNTHETIC_STATS
            .rejected_synthetic
            .fetch_add(1, Ordering::Relaxed);
        SYNTHETIC_STATS
            .rejected_bad_keyboard_type
            .fetch_add(1, Ordering::Relaxed);
        return EventVerificationResult::Synthetic;
    }

    // Hardware events have PID 0 (kernel); CGEventPost carries the injector's PID
    if source_pid != 0 {
        if strict {
            SYNTHETIC_STATS.total_events.fetch_add(1, Ordering::Relaxed);
            SYNTHETIC_STATS
                .rejected_synthetic
                .fetch_add(1, Ordering::Relaxed);
            SYNTHETIC_STATS
                .rejected_non_kernel_pid
                .fetch_add(1, Ordering::Relaxed);
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    SYNTHETIC_STATS.total_events.fetch_add(1, Ordering::Relaxed);
    if suspicious {
        SYNTHETIC_STATS
            .suspicious_accepted
            .fetch_add(1, Ordering::Relaxed);
        EventVerificationResult::Suspicious
    } else {
        SYNTHETIC_STATS
            .verified_hardware
            .fetch_add(1, Ordering::Relaxed);
        EventVerificationResult::Hardware
    }
}

/// Compares CGEventTap count against IOKit HID count to detect injected events.
///
/// When `hid_count` is 0 (HID capture not running), returns `synthetic_detected: false`
/// since there is no ground truth to compare against.
pub fn validate_dual_layer(cg_count: u64, hid_count: u64) -> DualLayerValidation {
    if hid_count == 0 {
        if cg_count > 0 {
            log::warn!(
                "HID capture inactive (count=0) while CGEventTap has {cg_count} events — \
                 synthetic keystroke detection disabled"
            );
        }
        return DualLayerValidation {
            high_level_count: cg_count,
            low_level_count: 0,
            synthetic_detected: false,
            discrepancy: 0,
        };
    }

    let cg_i64 = i64::try_from(cg_count).unwrap_or_else(|_| {
        log::warn!("cg_count {cg_count} exceeds i64::MAX, clamping");
        i64::MAX
    });
    let hid_i64 = i64::try_from(hid_count).unwrap_or_else(|_| {
        log::warn!("hid_count {hid_count} exceeds i64::MAX, clamping");
        i64::MAX
    });
    let discrepancy = cg_i64.saturating_sub(hid_i64);

    // Small discrepancies are normal due to timing; flag only >10% excess
    let synthetic_detected =
        discrepancy > 5 && (discrepancy as f64 / hid_count.max(1) as f64) > 0.1;

    DualLayerValidation {
        high_level_count: cg_count,
        low_level_count: hid_count,
        synthetic_detected,
        discrepancy,
    }
}
