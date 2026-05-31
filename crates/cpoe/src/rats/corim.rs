// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CoRIM (Concise Reference Integrity Manifest) support for CPoE.
//!
//! Publishes CPoE's appraisal reference values as a standards-compliant manifest
//! per draft-ietf-rats-corim, allowing third-party RATS Verifiers to appraise
//! CPoE evidence independently without hardcoded thresholds.

use crate::error::Result;
use ciborium::Value;

/// CPoE reference values for RATS Verifiers.
///
/// These thresholds define what constitutes valid human authorship evidence.
/// Published as a CoRIM manifest so third-party Verifiers can appraise independently.
#[derive(Debug, Clone, PartialEq)]
pub struct CpopReferenceValues {
    /// Minimum accumulated entropy bits per checkpoint trigger.
    /// Source: `timing::ENTROPY_THRESHOLD_STANDARD` (3.0) per draft-condrey-rats-pop.
    pub min_entropy_bits: f64,
    /// VDF timing bounds: (min_ratio, max_ratio) of claimed duration.
    /// Source: `verify::SWF_DURATION_RATIO_MIN` (0.5), `SWF_DURATION_RATIO_MAX` (3.0).
    pub vdf_duration_bounds: (f64, f64),
    /// Minimum checkpoint count for a valid appraisal.
    /// Source: `war::appraisal::MIN_CHECKPOINTS` (3).
    pub min_checkpoints_standard: u64,
    /// Minimum checkpoint count for Enhanced tier (jitter-bound evidence).
    /// Currently matches standard minimum; reserved for future differentiation.
    pub min_checkpoints_enhanced: u64,
    /// Human typing rate bounds in WPM: (slow_threshold, fast_threshold).
    /// Source: `forensics::dictation::WPM_SLOW_THRESHOLD` (40.0),
    /// `WPM_FAST_THRESHOLD` (200.0).
    pub typing_rate_bounds: (f64, f64),
    /// Inter-keystroke interval below which synthetic input is suspected (ms).
    /// Source: `platform::synthetic::MIN_HUMAN_IKI_MS` (35.0).
    pub synthetic_threshold_ms: f64,
    /// Minimum samples before creating a behavioral fingerprint profile.
    /// Source: `config::FingerprintConfig::min_samples` (100).
    pub min_jitter_samples: u64,
}

impl Default for CpopReferenceValues {
    fn default() -> Self {
        Self {
            min_entropy_bits: crate::checkpoint::timing::ENTROPY_THRESHOLD_STANDARD,
            vdf_duration_bounds: (0.5, 3.0),
            min_checkpoints_standard: 3,
            min_checkpoints_enhanced: 3,
            typing_rate_bounds: (40.0, 200.0),
            synthetic_threshold_ms: 35.0,
            min_jitter_samples: 100,
        }
    }
}

/// CBOR map keys for CoRIM reference value fields.
const KEY_MIN_ENTROPY_BITS: &str = "min-entropy-bits";
const KEY_VDF_DURATION_MIN: &str = "vdf-duration-ratio-min";
const KEY_VDF_DURATION_MAX: &str = "vdf-duration-ratio-max";
const KEY_MIN_CHECKPOINTS_STANDARD: &str = "min-checkpoints-standard";
const KEY_MIN_CHECKPOINTS_ENHANCED: &str = "min-checkpoints-enhanced";
const KEY_TYPING_RATE_MIN_WPM: &str = "typing-rate-min-wpm";
const KEY_TYPING_RATE_MAX_WPM: &str = "typing-rate-max-wpm";
const KEY_SYNTHETIC_THRESHOLD_MS: &str = "synthetic-threshold-ms";
const KEY_MIN_JITTER_SAMPLES: &str = "min-jitter-samples";

impl CpopReferenceValues {
    /// Serialize to a CBOR map with string keys.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let map = Value::Map(vec![
            (
                Value::Text(KEY_MIN_ENTROPY_BITS.to_string()),
                Value::Float(self.min_entropy_bits),
            ),
            (
                Value::Text(KEY_VDF_DURATION_MIN.to_string()),
                Value::Float(self.vdf_duration_bounds.0),
            ),
            (
                Value::Text(KEY_VDF_DURATION_MAX.to_string()),
                Value::Float(self.vdf_duration_bounds.1),
            ),
            (
                Value::Text(KEY_MIN_CHECKPOINTS_STANDARD.to_string()),
                Value::Integer(self.min_checkpoints_standard.into()),
            ),
            (
                Value::Text(KEY_MIN_CHECKPOINTS_ENHANCED.to_string()),
                Value::Integer(self.min_checkpoints_enhanced.into()),
            ),
            (
                Value::Text(KEY_TYPING_RATE_MIN_WPM.to_string()),
                Value::Float(self.typing_rate_bounds.0),
            ),
            (
                Value::Text(KEY_TYPING_RATE_MAX_WPM.to_string()),
                Value::Float(self.typing_rate_bounds.1),
            ),
            (
                Value::Text(KEY_SYNTHETIC_THRESHOLD_MS.to_string()),
                Value::Float(self.synthetic_threshold_ms),
            ),
            (
                Value::Text(KEY_MIN_JITTER_SAMPLES.to_string()),
                Value::Integer(self.min_jitter_samples.into()),
            ),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).map_err(|e| {
            crate::error::Error::evidence(format!("CoRIM CBOR serialization failed: {e}"))
        })?;
        Ok(buf)
    }

    /// Deserialize from a CBOR map with string keys.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|e| crate::error::Error::evidence(format!("CoRIM CBOR parse error: {e}")))?;

        let entries = match value {
            Value::Map(m) => m,
            _ => {
                return Err(crate::error::Error::evidence(
                    "CoRIM: expected CBOR map at top level",
                ))
            }
        };

        let mut result = Self::default();

        for (key, val) in entries {
            let key_str = match &key {
                Value::Text(s) => s.as_str(),
                _ => continue,
            };

            match key_str {
                KEY_MIN_ENTROPY_BITS => {
                    result.min_entropy_bits = extract_f64(&val, key_str)?;
                }
                KEY_VDF_DURATION_MIN => {
                    result.vdf_duration_bounds.0 = extract_f64(&val, key_str)?;
                }
                KEY_VDF_DURATION_MAX => {
                    result.vdf_duration_bounds.1 = extract_f64(&val, key_str)?;
                }
                KEY_MIN_CHECKPOINTS_STANDARD => {
                    result.min_checkpoints_standard = extract_u64(&val, key_str)?;
                }
                KEY_MIN_CHECKPOINTS_ENHANCED => {
                    result.min_checkpoints_enhanced = extract_u64(&val, key_str)?;
                }
                KEY_TYPING_RATE_MIN_WPM => {
                    result.typing_rate_bounds.0 = extract_f64(&val, key_str)?;
                }
                KEY_TYPING_RATE_MAX_WPM => {
                    result.typing_rate_bounds.1 = extract_f64(&val, key_str)?;
                }
                KEY_SYNTHETIC_THRESHOLD_MS => {
                    result.synthetic_threshold_ms = extract_f64(&val, key_str)?;
                }
                KEY_MIN_JITTER_SAMPLES => {
                    result.min_jitter_samples = extract_u64(&val, key_str)?;
                }
                _ => {} // ignore unknown keys for forward compatibility
            }
        }

        Ok(result)
    }
}

/// Extract an f64 from a CBOR value (Float or Integer).
fn extract_f64(val: &Value, key: &str) -> Result<f64> {
    match val {
        Value::Float(f) if f.is_finite() => Ok(*f),
        Value::Float(f) => Err(crate::error::Error::evidence(format!(
            "CoRIM: non-finite float ({f}) for key '{key}'"
        ))),
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            Ok(n as f64)
        }
        _ => Err(crate::error::Error::evidence(format!(
            "CoRIM: expected float for key '{key}'"
        ))),
    }
}

/// Extract a u64 from a CBOR Integer value.
fn extract_u64(val: &Value, key: &str) -> Result<u64> {
    match val {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            u64::try_from(n).map_err(|_| {
                crate::error::Error::evidence(format!(
                    "CoRIM: integer out of u64 range for key '{key}'"
                ))
            })
        }
        _ => Err(crate::error::Error::evidence(format!(
            "CoRIM: expected integer for key '{key}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_reference_values() {
        let rv = CpopReferenceValues::default();
        // Values must match the hardcoded constants in the codebase:
        // timing::ENTROPY_THRESHOLD_STANDARD (draft-condrey-rats-pop)
        assert_eq!(rv.min_entropy_bits, 3.0);
        // verify::SWF_DURATION_RATIO_MIN / SWF_DURATION_RATIO_MAX
        assert_eq!(rv.vdf_duration_bounds, (0.5, 3.0));
        // war::appraisal::MIN_CHECKPOINTS
        assert_eq!(rv.min_checkpoints_standard, 3);
        assert_eq!(rv.min_checkpoints_enhanced, 3);
        // forensics::dictation::WPM_SLOW_THRESHOLD / WPM_FAST_THRESHOLD
        assert_eq!(rv.typing_rate_bounds, (40.0, 200.0));
        // platform::synthetic::MIN_HUMAN_IKI_MS
        assert_eq!(rv.synthetic_threshold_ms, 35.0);
        // config::FingerprintConfig::min_samples
        assert_eq!(rv.min_jitter_samples, 100);
    }

    #[test]
    fn test_corim_cbor_roundtrip() {
        let original = CpopReferenceValues::default();
        let cbor_bytes = original.to_cbor().expect("serialize");
        assert!(!cbor_bytes.is_empty());

        let decoded = CpopReferenceValues::from_cbor(&cbor_bytes).expect("roundtrip decode failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_corim_cbor_roundtrip_custom_values() {
        let custom = CpopReferenceValues {
            min_entropy_bits: 64.0,
            vdf_duration_bounds: (0.25, 5.0),
            min_checkpoints_standard: 10,
            min_checkpoints_enhanced: 20,
            typing_rate_bounds: (30.0, 300.0),
            synthetic_threshold_ms: 20.0,
            min_jitter_samples: 500,
        };

        let cbor_bytes = custom.to_cbor().expect("serialize");
        let decoded = CpopReferenceValues::from_cbor(&cbor_bytes).expect("roundtrip decode failed");
        assert_eq!(decoded, custom);
    }

    #[test]
    fn test_corim_reference_values_match_codebase() {
        let rv = CpopReferenceValues::default();
        // Verify CoRIM defaults match the actual code constants they reference.
        assert!(
            (rv.min_entropy_bits - crate::checkpoint::timing::ENTROPY_THRESHOLD_STANDARD).abs() < f64::EPSILON,
            "min_entropy_bits should match timing::ENTROPY_THRESHOLD_STANDARD"
        );
        // VDF bounds: verify::SWF_DURATION_RATIO_MIN / MAX
        assert_eq!(rv.vdf_duration_bounds.0, 0.5);
        assert_eq!(rv.vdf_duration_bounds.1, 3.0);
        // war::appraisal::MIN_CHECKPOINTS
        assert_eq!(rv.min_checkpoints_standard, 3);
        // forensics::dictation thresholds
        assert_eq!(rv.typing_rate_bounds.0, 40.0);
        assert_eq!(rv.typing_rate_bounds.1, 200.0);
        // platform::synthetic::MIN_HUMAN_IKI_MS
        assert_eq!(rv.synthetic_threshold_ms, 35.0);
        // config::FingerprintConfig::min_samples
        assert_eq!(rv.min_jitter_samples, 100);
    }

    #[test]
    fn test_corim_custom_values_roundtrip() {
        let custom = CpopReferenceValues {
            min_entropy_bits: 7.5,
            vdf_duration_bounds: (0.1, 10.0),
            min_checkpoints_standard: 50,
            min_checkpoints_enhanced: 100,
            typing_rate_bounds: (10.0, 500.0),
            synthetic_threshold_ms: 5.0,
            min_jitter_samples: 2000,
        };
        let cbor = custom.to_cbor().expect("serialize");
        let decoded = CpopReferenceValues::from_cbor(&cbor).expect("custom roundtrip");
        assert!((decoded.min_entropy_bits - 7.5).abs() < f64::EPSILON);
        assert_eq!(decoded.vdf_duration_bounds, (0.1, 10.0));
        assert_eq!(decoded.min_checkpoints_standard, 50);
        assert_eq!(decoded.min_checkpoints_enhanced, 100);
        assert_eq!(decoded.typing_rate_bounds, (10.0, 500.0));
        assert!((decoded.synthetic_threshold_ms - 5.0).abs() < f64::EPSILON);
        assert_eq!(decoded.min_jitter_samples, 2000);
    }

    #[test]
    fn test_corim_from_cbor_rejects_non_map() {
        let not_a_map = {
            let mut buf = Vec::new();
            ciborium::into_writer(&Value::Integer(42.into()), &mut buf).unwrap();
            buf
        };
        assert!(CpopReferenceValues::from_cbor(&not_a_map).is_err());
    }
}
