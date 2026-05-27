// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::time::Duration;

const INTERVAL_BUCKET_SIZE_MS: u64 = crate::jitter::INTERVAL_BUCKET_SIZE_MS as u64;
const NUM_INTERVAL_BUCKETS: u64 = crate::jitter::NUM_INTERVAL_BUCKETS as u64;
/// Intervals beyond this threshold are not typing behavior and should be discarded.
const MAX_TYPING_INTERVAL_MS: u64 = 30_000;

/// Map a duration to a 50ms-wide histogram bucket index (0-9).
/// Returns `None` for intervals beyond 30 seconds (not typing behavior).
pub fn interval_to_bucket(duration: Duration) -> Option<u8> {
    let ms = duration.as_millis();
    if ms > MAX_TYPING_INTERVAL_MS as u128 {
        return None;
    }
    let bucket = (ms as u64) / INTERVAL_BUCKET_SIZE_MS;
    if bucket >= NUM_INTERVAL_BUCKETS {
        Some((NUM_INTERVAL_BUCKETS - 1) as u8)
    } else {
        Some(bucket as u8)
    }
}
