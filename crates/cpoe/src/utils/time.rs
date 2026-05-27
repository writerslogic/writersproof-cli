// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared time and timestamp utilities.

use std::time::{Duration, SystemTime};

/// Return the current system time in nanoseconds since the UNIX epoch.
///
/// If the timestamp exceeds `i64::MAX` (~2262+), it falls back to
/// millisecond-precision nanoseconds via saturating multiplication.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| {
            let nanos = d.as_nanos();
            if nanos > i64::MAX as u128 {
                (d.as_millis() as i64).saturating_mul(1_000_000)
            } else {
                nanos as i64
            }
        })
        .unwrap_or_else(|_| {
            log::warn!("SystemTime before UNIX_EPOCH in now_ns(); falling back to 0");
            0
        })
}

/// Current time as seconds since the UNIX epoch.
#[inline]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current time as milliseconds since the UNIX epoch.
#[inline]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Convert nanoseconds to seconds as `f64`.
#[inline]
pub fn ns_to_secs(nanos: i64) -> f64 {
    nanos.max(0) as f64 / 1_000_000_000.0
}

/// Convert nanoseconds to milliseconds as `f64`.
#[inline]
pub fn ns_to_ms(nanos: i64) -> f64 {
    nanos.max(0) as f64 / 1_000_000.0
}

/// Elapsed nanoseconds between two timestamps, clamped to zero.
#[inline]
pub fn ns_elapsed(end_ns: i64, start_ns: i64) -> u64 {
    end_ns.saturating_sub(start_ns).max(0) as u64
}

/// Convert a `Duration` to milliseconds, capping at `u64::MAX`.
#[inline]
pub fn duration_to_ms(dur: Duration) -> u64 {
    dur.as_millis().min(u64::MAX as u128) as u64
}

pub(crate) trait DateTimeNanosExt {
    fn timestamp_nanos_safe(&self) -> i64;
}

impl DateTimeNanosExt for chrono::DateTime<chrono::Utc> {
    #[inline]
    fn timestamp_nanos_safe(&self) -> i64 {
        self.timestamp_nanos_opt()
            .unwrap_or_else(|| self.timestamp_millis().saturating_mul(1_000_000))
    }
}
