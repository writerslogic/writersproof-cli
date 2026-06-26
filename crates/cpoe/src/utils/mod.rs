// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared engine-wide utility functions.

pub mod crypto_helpers;
pub mod crypto_types;
pub mod error_context;
pub mod formatting;
pub mod fs;
pub mod key_derivation;
pub(crate) mod lock;
pub mod mlock;
pub mod probability;
pub mod stats;
pub mod telemetry;
pub mod time;
pub mod validation;

pub use crypto_helpers::{
    blake3_hash_bytes, blake3_hash_truncated_8, compute_content_hash, constant_time_eq,
    NonceManager, SignatureKey, SignedPayloadBuilder,
};
pub use crypto_types::{Ed25519Pubkey, Ed25519Sig, HexBytes, HexHash};
pub use error_context::{sanitize_for_user, ErrorContext};
pub use formatting::{
    format_bytes, format_duration_compact, format_duration_human, format_duration_verbose,
    format_number,
};
pub(crate) use lock::{MutexRecover, RwLockRecover};
pub use probability::Probability;
pub use stats::{
    coefficient_of_variation, lerp_score, mean, mean_and_sample_std_dev, mean_and_sample_variance,
    mean_and_std_dev, mean_and_std_dev_f32, mean_and_variance, median, std_dev,
};
pub(crate) use time::DateTimeNanosExt;
pub use time::{duration_to_ms, now_ms, now_ns, now_secs, ns_elapsed, ns_to_ms, ns_to_secs};
pub use validation::{BundleIdValidator, TextValidator, TimestampValidator};

/// Serde helper: skip serializing a `bool` field when it is `false`.
pub fn is_false(v: &bool) -> bool {
    !v
}

/// Minimum dictation duration considered meaningful (1 second).
///
/// Durations shorter than this are treated as incomplete or injected events
/// and produce a `0.0` WPM rather than an astronomically large value.
const MIN_DICTATION_DURATION_NS: i64 = 1_000_000_000;

/// Compute words per minute from a word count and a nanosecond duration.
///
/// Returns `0.0` for zero words, non-positive durations, or durations below
/// 1 second (too short to be a real dictation fragment; avoids inflated WPM
/// from injected or near-zero-duration events).
pub fn words_per_minute(word_count: u32, duration_ns: i64) -> f64 {
    if word_count == 0 || duration_ns < MIN_DICTATION_DURATION_NS {
        return 0.0;
    }
    let duration_minutes = duration_ns as f64 / (60.0 * 1_000_000_000.0);
    word_count as f64 / duration_minutes
}

/// Compute correction rate as a fraction of words corrected out of total words.
///
/// Returns `0.0` if `total_words` is zero (no output to measure against).
/// Clamps to `[0.0, 1.0]` — a correction count exceeding the word count is
/// treated as fully corrected (rate = 1.0).
pub fn correction_rate(corrections: u32, total_words: u32) -> f32 {
    if total_words == 0 {
        return 0.0;
    }
    (corrections as f32 / total_words as f32).min(1.0)
}

/// Duration between two nanosecond timestamps as seconds, floored at 1 ms.
///
/// The 1 ms floor prevents divide-by-zero in any rate calculation (WPM,
/// characters-per-second) when start and end are identical.
pub fn safe_duration_secs(start_ns: i64, end_ns: i64) -> f64 {
    let nanos = end_ns.saturating_sub(start_ns).max(1_000_000);
    nanos as f64 / 1_000_000_000.0
}

/// Platform-aware data directory for CPoE/WritersProof state files.
///
/// Checks `CPOE_DATA_DIR` env var first, then falls back to platform defaults:
/// - macOS: `~/Library/Application Support/WritersProof`
/// - Other: `{data_local_dir}/CPoE`
pub fn get_data_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return Some(std::path::PathBuf::from(dir));
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/WritersProof"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("CPoE"))
    }
}

/// Legacy data directory path (`~/.writersproof`).
///
/// Used by PUF seed storage and Secure Enclave counter files which predate the
/// platform-aware [`get_data_dir`] path. Checks `CPOE_DATA_DIR` first.
pub fn get_legacy_data_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return Some(std::path::PathBuf::from(dir));
    }
    dirs::home_dir().map(|h| h.join(".writersproof"))
}

/// Hash a filesystem path (its UTF-8 string representation) with SHA-256.
pub fn sha256_of_path(path: &std::path::Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

/// Derive a short hex document ID from a filesystem path.
///
/// Computes `hex(sha256(path)[0..8])`, producing a 16-char hex string.
pub fn document_id_from_path(path: &std::path::Path) -> String {
    hex::encode(&sha256_of_path(path)[..8])
}

/// Return an error if any value in `vals` is NaN or infinite.
pub fn require_all_finite(vals: &[f64], context: &str) -> crate::error::Result<()> {
    if vals.iter().any(|x| !x.is_finite()) {
        return Err(crate::error::Error::validation(format!(
            "{context}: contains NaN or infinity"
        )));
    }
    Ok(())
}

/// Return `fallback` when `v` is NaN or infinite.
pub fn finite_or(v: f64, fallback: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        fallback
    }
}

/// Return `Ok(x)` when `x` is finite, or a validation error when it is NaN or infinite.
pub fn finite(x: f64) -> crate::error::Result<f64> {
    if x.is_finite() {
        Ok(x)
    } else {
        Err(crate::error::Error::validation(format!(
            "non-finite value: {x}"
        )))
    }
}

/// Return a short hex string from the first 8 bytes (or fewer) of `hash`.
pub fn short_hex_id(hash: &[u8]) -> String {
    hex::encode(&hash[..hash.len().min(8)])
}

/// Decode a hex string and validate it decodes to exactly `N` bytes.
///
/// Returns `Err` on any of: invalid hex chars, odd-length input, wrong decoded length.
fn hex_decode_exact<const N: usize>(s: &str) -> crate::error::Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| crate::error::Error::validation(e.to_string()))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| crate::error::Error::validation(format!("expected {N} bytes, got {len}")))
}

/// Decode a hex string to a fixed 8-byte array.
pub fn hex_decode_8(s: &str) -> crate::error::Result<[u8; 8]> {
    hex_decode_exact::<8>(s)
}

/// Decode a hex string to a fixed 32-byte array.
pub fn hex_decode_32(s: &str) -> crate::error::Result<[u8; 32]> {
    hex_decode_exact::<32>(s)
}

/// Convert a byte slice to a fixed 32-byte array.
///
/// Returns `Err` if `slice` is not exactly 32 bytes.
pub fn to_array_32(slice: &[u8]) -> Result<[u8; 32], std::array::TryFromSliceError> {
    slice.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_or_returns_value_when_finite() {
        assert_eq!(finite_or(1.5, 0.0), 1.5);
        assert_eq!(finite_or(-3.0, 0.0), -3.0);
        assert_eq!(finite_or(0.0, 99.0), 0.0);
    }

    #[test]
    fn finite_or_returns_fallback_for_nan_and_inf() {
        assert_eq!(finite_or(f64::NAN, 42.0), 42.0);
        assert_eq!(finite_or(f64::INFINITY, -1.0), -1.0);
        assert_eq!(finite_or(f64::NEG_INFINITY, 0.0), 0.0);
    }

    #[test]
    fn finite_ok_for_finite_values() {
        assert_eq!(finite(1.5).unwrap(), 1.5);
        assert_eq!(finite(-3.0).unwrap(), -3.0);
        assert_eq!(finite(0.0).unwrap(), 0.0);
    }

    #[test]
    fn finite_err_for_nan_and_inf() {
        assert!(finite(f64::NAN).is_err());
        assert!(finite(f64::INFINITY).is_err());
        assert!(finite(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn short_hex_id_truncates_to_8_bytes() {
        let hash = [0xab; 32];
        assert_eq!(short_hex_id(&hash), "abababababababab");
    }

    #[test]
    fn short_hex_id_handles_short_input() {
        let hash = [0xff; 3];
        assert_eq!(short_hex_id(&hash), "ffffff");
    }

    #[test]
    fn short_hex_id_empty_input() {
        let hash: [u8; 0] = [];
        assert_eq!(short_hex_id(&hash), "");
    }

    #[test]
    fn to_array_32_exact_length() {
        let v = vec![0xabu8; 32];
        let arr = to_array_32(&v).unwrap();
        assert_eq!(arr, [0xabu8; 32]);
    }

    #[test]
    fn to_array_32_wrong_length() {
        assert!(to_array_32(&[0u8; 31]).is_err());
        assert!(to_array_32(&[0u8; 33]).is_err());
        assert!(to_array_32(&[]).is_err());
    }

    #[test]
    fn hex_decode_32_ok() {
        let hex = "ab".repeat(32);
        let arr = hex_decode_32(&hex).unwrap();
        assert_eq!(arr, [0xab; 32]);
    }

    #[test]
    fn hex_decode_32_wrong_length() {
        assert!(hex_decode_32(&"ab".repeat(16)).is_err());
        assert!(hex_decode_32(&"ab".repeat(33)).is_err());
    }

    #[test]
    fn hex_decode_32_odd_length() {
        assert!(hex_decode_32("abc").is_err());
    }

    #[test]
    fn hex_decode_32_invalid_chars() {
        assert!(hex_decode_32(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn hex_decode_32_empty_string() {
        assert!(hex_decode_32("").is_err());
    }

    #[test]
    fn words_per_minute_normal() {
        // 60 words in 30 seconds = 120 WPM
        let wpm = words_per_minute(60, 30 * 1_000_000_000);
        assert!((wpm - 120.0).abs() < 0.01, "expected 120 WPM, got {wpm}");
    }

    #[test]
    fn words_per_minute_zero_words() {
        assert_eq!(words_per_minute(0, 30 * 1_000_000_000), 0.0);
    }

    #[test]
    fn words_per_minute_zero_duration() {
        assert_eq!(words_per_minute(60, 0), 0.0);
    }

    #[test]
    fn words_per_minute_negative_duration() {
        assert_eq!(words_per_minute(60, -1_000_000_000), 0.0);
    }

    #[test]
    fn words_per_minute_sub_second_duration_returns_zero() {
        // 999ms is below the 1s minimum — returns 0.0 rather than inflated WPM.
        assert_eq!(words_per_minute(10, 999_999_999), 0.0);
    }

    #[test]
    fn words_per_minute_exactly_one_second_floor() {
        // Exactly 1s is the minimum valid duration.
        let wpm = words_per_minute(1, 1_000_000_000);
        assert!((wpm - 60.0).abs() < 0.01, "expected 60 WPM, got {wpm}");
    }

    #[test]
    fn correction_rate_zero_total() {
        assert_eq!(correction_rate(5, 0), 0.0);
    }

    #[test]
    fn correction_rate_no_corrections() {
        assert_eq!(correction_rate(0, 100), 0.0);
    }

    #[test]
    fn correction_rate_normal() {
        let r = correction_rate(25, 100);
        assert!((r - 0.25).abs() < 1e-6, "expected 0.25, got {r}");
    }

    #[test]
    fn correction_rate_clamped_at_one() {
        // More corrections than words (pathological input) clamps to 1.0.
        assert_eq!(correction_rate(200, 100), 1.0);
    }

    #[test]
    fn safe_duration_secs_normal() {
        let d = safe_duration_secs(0, 5_000_000_000);
        assert!((d - 5.0).abs() < 1e-9, "expected 5.0s, got {d}");
    }

    #[test]
    fn safe_duration_secs_equal_timestamps_floored() {
        // start == end → floor at 1ms = 0.001s
        let d = safe_duration_secs(100, 100);
        assert!((d - 0.001).abs() < 1e-9, "expected 0.001s floor, got {d}");
    }

    #[test]
    fn safe_duration_secs_reversed_timestamps_floored() {
        // end < start → saturating_sub gives 0 → floor at 1ms
        let d = safe_duration_secs(1_000_000_000, 500_000_000);
        assert!((d - 0.001).abs() < 1e-9, "expected 0.001s floor, got {d}");
    }
}
