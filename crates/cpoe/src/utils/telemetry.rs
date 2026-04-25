// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Internal performance telemetry for diagnostic monitoring.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global engine telemetry counters.
#[allow(missing_debug_implementations)]
pub struct Telemetry {
    pub vdf_verify_time_ms: AtomicU64,
    pub checkpoint_count: AtomicU64,
    pub total_bytes_hashed: AtomicU64,
}

static TELEMETRY: Telemetry = Telemetry {
    vdf_verify_time_ms: AtomicU64::new(0),
    checkpoint_count: AtomicU64::new(0),
    total_bytes_hashed: AtomicU64::new(0),
};

/// Record VDF verification time in milliseconds.
pub fn record_vdf_time(ms: u64) {
    TELEMETRY
        .vdf_verify_time_ms
        .fetch_add(ms, Ordering::Relaxed);
}

/// Record a new checkpoint created.
pub fn record_checkpoint() {
    TELEMETRY.checkpoint_count.fetch_add(1, Ordering::Relaxed);
}

/// Record bytes hashed for content integrity.
pub fn record_bytes_hashed(bytes: u64) {
    TELEMETRY
        .total_bytes_hashed
        .fetch_add(bytes, Ordering::Relaxed);
}

/// Return a snapshot of current telemetry metrics.
pub fn get_metrics() -> (u64, u64, u64) {
    (
        TELEMETRY.vdf_verify_time_ms.load(Ordering::Relaxed),
        TELEMETRY.checkpoint_count.load(Ordering::Relaxed),
        TELEMETRY.total_bytes_hashed.load(Ordering::Relaxed),
    )
}
