// SPDX-License-Identifier: Apache-2.0

//! RFC-compliant VDF proof structures.
//!
//! Implements the CDDL-defined VDF structures from draft-condrey-rats-pop-01.
//! These structures ensure minimum elapsed time verification through
//! verifiable delay functions.

use serde::{Deserialize, Serialize};

use super::serde_helpers::{hex_bytes, hex_bytes_vec};
use super::wire_types::components::{SWF_MAX_DURATION_FACTOR, SWF_MIN_DURATION_FACTOR};

/// RFC-compliant VDF proof structure.
/// ```cddl
/// vdf-proof = {
///   1: bstr .size 32,          ; challenge (input)
///   2: bstr .size 64,          ; output (proof result)
///   3: uint,                   ; iterations (T parameter)
///   4: uint,                   ; duration-ms (measured wall time)
///   5: calibration-attestation ; calibration reference
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfProofRfc {
    #[serde(rename = "1", with = "hex_bytes")]
    pub challenge: [u8; 32],

    /// 64-byte Wesolowski proof output.
    #[serde(rename = "2", with = "hex_bytes")]
    pub output: [u8; 64],

    #[serde(rename = "3")]
    pub iterations: u64,

    #[serde(rename = "4")]
    pub duration_ms: u64,

    #[serde(rename = "5")]
    pub calibration: CalibrationAttestation,
}

impl VdfProofRfc {
    /// Create a VDF proof from all required fields.
    pub fn new(
        challenge: [u8; 32],
        output: [u8; 64],
        iterations: u64,
        duration_ms: u64,
        calibration: CalibrationAttestation,
    ) -> Self {
        Self {
            challenge,
            output,
            iterations,
            duration_ms,
            calibration,
        }
    }

    /// Compute the minimum expected wall time from calibration data.
    /// Returns `None` when `iterations_per_second` is zero (invalid calibration).
    pub fn minimum_elapsed_ms(&self) -> Option<u64> {
        if self.calibration.iterations_per_second == 0 {
            return None;
        }
        Some(
            self.iterations
                .saturating_mul(1000)
                .checked_div(self.calibration.iterations_per_second)
                .unwrap_or(u64::MAX),
        )
    }

    /// Return `true` if claimed duration is consistent with calibration (5% tolerance).
    /// Returns `false` when calibration is invalid (zero IPS).
    pub fn is_duration_consistent(&self) -> bool {
        let minimum = match self.minimum_elapsed_ms() {
            Some(v) => v,
            None => return false,
        };
        // 5% tolerance for timing variance
        let threshold = minimum.saturating_sub(minimum / 20);
        self.duration_ms >= threshold
    }

    /// IETF-mandated `[SWF_MIN_DURATION_FACTOR, SWF_MAX_DURATION_FACTOR]` bounds check.
    /// Returns `false` when calibration is invalid (zero IPS).
    pub fn is_duration_within_spec_bounds(&self) -> bool {
        let expected = match self.minimum_elapsed_ms() {
            Some(v) if v > 0 => v,
            _ => return false,
        };
        if self.duration_ms == 0 {
            return false;
        }
        let ratio = self.duration_ms as f64 / expected as f64;
        (SWF_MIN_DURATION_FACTOR..=SWF_MAX_DURATION_FACTOR).contains(&ratio)
    }

    /// Higher ratio = faster hardware (potential gaming).
    pub fn iterations_per_ms(&self) -> f64 {
        if self.duration_ms > 0 {
            self.iterations as f64 / self.duration_ms as f64
        } else {
            0.0
        }
    }

    /// Validate all fields and return a list of errors (empty if valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.challenge == [0u8; 32] {
            errors.push("challenge must be non-zero".to_string());
        }

        if self.output == [0u8; 64] {
            errors.push("output must be non-zero".to_string());
        }

        if self.iterations == 0 {
            errors.push("iterations must be non-zero".to_string());
        }

        if self.duration_ms == 0 {
            errors.push("duration_ms must be non-zero".to_string());
        }

        errors.extend(self.calibration.validate_structure());

        if self.calibration.iterations_per_second == 0
            && self.iterations > 0
            && self.duration_ms > 0
        {
            errors.push(
                "calibration.iterations_per_second is zero; duration consistency cannot be verified"
                    .to_string(),
            );
        }

        if self.iterations > 0 && self.duration_ms > 0 && self.calibration.iterations_per_second > 0
        {
            if !self.is_duration_consistent() {
                errors.push(format!(
                    "duration_ms ({}) is inconsistent with expected minimum ({} ms) based on calibration",
                    self.duration_ms,
                    self.minimum_elapsed_ms().unwrap_or(0)
                ));
            }
            if !self.is_duration_within_spec_bounds() {
                let expected = self.minimum_elapsed_ms().unwrap_or(0);
                let ratio = if expected > 0 {
                    self.duration_ms as f64 / expected as f64
                } else {
                    0.0
                };
                errors.push(format!(
                    "duration ratio {ratio:.2}x outside spec bounds [{SWF_MIN_DURATION_FACTOR}x, {SWF_MAX_DURATION_FACTOR}x]",
                ));
            }
        }

        errors
    }

    /// Return `true` if `validate()` produces no errors.
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Calibration reference per draft-condrey-rats-pop-01.
/// ```cddl
/// calibration-attestation = {
///   1: uint,                   ; iterations-per-second (baseline rate)
///   2: tstr,                   ; hardware-class (device classification)
///   3: bstr,                   ; calibration-signature (signed attestation)
///   4: uint,                   ; timestamp (calibration time)
///   ? 5: tstr                  ; calibration-authority (optional issuer)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalibrationAttestation {
    #[serde(rename = "1")]
    pub iterations_per_second: u64,

    /// E.g. "mobile-arm64", "desktop-x86_64", "server-xeon".
    #[serde(rename = "2")]
    pub hardware_class: String,

    #[serde(rename = "3", with = "hex_bytes_vec")]
    pub calibration_signature: Vec<u8>,

    #[serde(rename = "4")]
    pub timestamp: u64,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub calibration_authority: Option<String>,
}

impl CalibrationAttestation {
    /// Create a calibration attestation without authority.
    pub fn new(
        iterations_per_second: u64,
        hardware_class: String,
        calibration_signature: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            iterations_per_second,
            hardware_class,
            calibration_signature,
            timestamp,
            calibration_authority: None,
        }
    }

    /// Create a calibration attestation with a named authority.
    pub fn with_authority(
        iterations_per_second: u64,
        hardware_class: String,
        calibration_signature: Vec<u8>,
        timestamp: u64,
        authority: String,
    ) -> Self {
        Self {
            iterations_per_second,
            hardware_class,
            calibration_signature,
            timestamp,
            calibration_authority: Some(authority),
        }
    }

    /// Return the age of this calibration in seconds.
    pub fn age_seconds(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.timestamp)
    }

    /// 24-hour freshness window.
    pub fn is_fresh(&self, current_time: u64) -> bool {
        self.age_seconds(current_time) < 86400
    }

    /// Structural validation only — does NOT verify the signature.
    pub fn validate_structure(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.iterations_per_second == 0 {
            errors.push("calibration.iterations_per_second must be non-zero".to_string());
        }

        if self.hardware_class.is_empty() {
            errors.push("calibration.hardware_class must be non-empty".to_string());
        }

        if self.calibration_signature.is_empty() {
            errors.push("calibration.calibration_signature must be non-empty".to_string());
        }

        if self.timestamp == 0 {
            errors.push("calibration.timestamp must be non-zero".to_string());
        }

        errors
    }

    /// Return `true` if structural validation passes.
    pub fn is_valid(&self) -> bool {
        self.validate_structure().is_empty()
    }
}

/// VDF algorithm identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum VdfAlgorithm {
    /// Wesolowski VDF (default).
    #[default]
    Wesolowski,
    /// Pietrzak VDF.
    Pietrzak,
    /// RSA-2048 based VDF.
    Rsa2048,
}

/// Extended VDF proof with algorithm selection and optional checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfProofExtended {
    pub proof: VdfProofRfc,
    pub algorithm: VdfAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<Vec<VdfCheckpoint>>,
}

/// Intermediate checkpoint for partial verification of long VDF proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfCheckpoint {
    pub iteration: u64,
    #[serde(with = "hex_bytes")]
    pub value: [u8; 64],
    pub elapsed_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_proof_creation() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0u8; 64],
            1700000000,
        );

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

        assert_eq!(proof.iterations, 1_000_000);
        assert_eq!(proof.duration_ms, 1000);
    }

    #[test]
    fn test_minimum_elapsed_calculation() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 0);

        let proof = VdfProofRfc::new([0u8; 32], [0u8; 64], 2_000_000, 2500, calibration);

        assert_eq!(proof.minimum_elapsed_ms(), Some(2000));
        assert!(proof.is_duration_consistent());
    }

    #[test]
    fn test_duration_inconsistent_when_too_fast() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 0);

        let proof = VdfProofRfc::new(
            [0u8; 32],
            [0u8; 64],
            2_000_000,
            500, // Impossibly fast
            calibration,
        );

        assert!(!proof.is_duration_consistent());
    }

    #[test]
    fn test_calibration_freshness() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

        assert!(calibration.is_fresh(1700000000 + 3600));
        assert!(calibration.is_fresh(1700000000 + 86000));
        assert!(!calibration.is_fresh(1700000000 + 90000));
    }

    #[test]
    fn test_vdf_proof_serialization() {
        let calibration = CalibrationAttestation::with_authority(
            500_000,
            "mobile-arm64".to_string(),
            vec![0xAB; 32],
            1700000000,
            "writerslogic.com".to_string(),
        );

        let proof = VdfProofRfc::new([0xDE; 32], [0xAD; 64], 500_000, 1000, calibration);

        let json = serde_json::to_string(&proof).expect("JSON serialization failed");
        assert!(json.contains("\"1\""));
        assert!(json.contains("\"2\""));

        let decoded: VdfProofRfc =
            serde_json::from_str(&json).expect("JSON deserialization failed");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_iterations_per_ms() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1);

        let proof = VdfProofRfc::new([1u8; 32], [1u8; 64], 1_000_000, 1000, calibration);

        assert!((proof.iterations_per_ms() - 1000.0).abs() < 0.001);
    }

    #[test]
    fn test_vdf_proof_validate_valid() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0xAB; 64],
            1700000000,
        );

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

        assert!(proof.is_valid());
        assert!(proof.validate().is_empty());
    }

    #[test]
    fn test_vdf_proof_validate_zero_challenge() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([0u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("challenge must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_output() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([1u8; 32], [0u8; 64], 1_000_000, 1000, calibration);

        let errors = proof.validate();
        assert!(errors.iter().any(|e| e.contains("output must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_iterations() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 0, 1000, calibration);

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("iterations must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_duration() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 0, calibration);

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("duration_ms must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_inconsistent_duration() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            2_000_000,
            500, // Impossibly fast
            calibration,
        );

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("duration_ms") && e.contains("inconsistent")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_calibration_validate_valid() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0xAB; 64],
            1700000000,
        );

        assert!(calibration.is_valid());
        assert!(calibration.validate_structure().is_empty());
    }

    #[test]
    fn test_calibration_validate_zero_iterations_per_second() {
        let calibration = CalibrationAttestation::new(0, "test".to_string(), vec![1u8], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("iterations_per_second must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_hardware_class() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "".to_string(), vec![1u8], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("hardware_class must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_signature() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("calibration_signature must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_zero_timestamp() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 0);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("timestamp must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_multiple_errors() {
        let calibration = CalibrationAttestation::new(0, "".to_string(), vec![], 0);

        let proof = VdfProofRfc::new([0u8; 32], [0u8; 64], 0, 0, calibration);

        let errors = proof.validate();
        assert!(errors.len() >= 8);
        assert!(!proof.is_valid());
    }
}
