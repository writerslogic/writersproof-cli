// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Global fingerprint accumulator shared between sentinel and standalone capture.
//!
//! At any moment, exactly ONE source feeds the accumulator:
//! - Sentinel running: sentinel feeds it (writing-app scoped).
//! - Sentinel not running: fingerprint consumer feeds it (broad scope).
//!
//! The `SENTINEL_IS_FEEDING` flag prevents double-counting which would
//! corrupt IKI distributions (0ms intervals from duplicate timestamps).

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock, RwLock,
};

use super::ActivityFingerprintAccumulator;

static SENTINEL_IS_FEEDING: AtomicBool = AtomicBool::new(false);
static GLOBAL_ACCUMULATOR: OnceLock<Arc<RwLock<ActivityFingerprintAccumulator>>> = OnceLock::new();

/// Get or initialize the global fingerprint accumulator.
pub fn get_global_accumulator() -> Arc<RwLock<ActivityFingerprintAccumulator>> {
    Arc::clone(GLOBAL_ACCUMULATOR.get_or_init(|| {
        Arc::new(RwLock::new(ActivityFingerprintAccumulator::new()))
    }))
}

/// Set whether the sentinel is currently feeding the accumulator.
/// When true, the standalone fingerprint consumer pauses writing.
pub fn set_sentinel_feeding(active: bool) {
    SENTINEL_IS_FEEDING.store(active, Ordering::SeqCst);
}

/// Check whether the sentinel is currently feeding the accumulator.
pub fn sentinel_is_feeding() -> bool {
    SENTINEL_IS_FEEDING.load(Ordering::SeqCst)
}
