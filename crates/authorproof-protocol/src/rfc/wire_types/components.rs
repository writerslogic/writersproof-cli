// SPDX-License-Identifier: Apache-2.0

//! Evidence component types for wire-format structures.
//!
//! Implements `document-ref`, `edit-delta`, `proof-params`, `merkle-proof`,
//! `process-proof`, `jitter-binding`, `physical-state`, `physical-liveness`,
//! `presence-challenge`, `channel-binding`, `self-receipt`, `active-probe`,
//! `profile-declaration`, `baseline-verification`, `baseline-digest`,
//! `session-behavioral-summary`, and `streaming-stats` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::{BindingType, ConfidenceTier, HashSaltMode, ProbeType, ProofAlgorithm};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_32, fixed_bytes_32_opt, serde_bytes_opt};

/// Allowed salt commitment lengths per CDDL `bstr .size (32/48/64)`.
const ALLOWED_SALT_LENGTHS: &[usize] = &[32, 48, 64];

/// Minimum challenge nonce length per CDDL `.size (16..256)`.
const MIN_CHALLENGE_NONCE_LEN: usize = 16;
/// Maximum challenge nonce length per CDDL `.size (16..256)`.
const MAX_CHALLENGE_NONCE_LEN: usize = 256;

/// Minimum ratio of claimed SWF duration to expected duration.
/// Per draft-condrey-rats-pop: a proof claiming less than 0.5x the
/// expected execution time is considered impossibly fast.
pub const SWF_MIN_DURATION_FACTOR: f64 = 0.5;

/// Maximum ratio of claimed SWF duration to expected duration.
/// Per draft-condrey-rats-pop: a proof claiming more than 3.0x the
/// expected execution time is considered suspiciously slow.
pub const SWF_MAX_DURATION_FACTOR: f64 = 3.0;

/// Document reference per CDDL `document-ref`.
///
/// ```cddl
/// document-ref = {
///     1 => hash-value,
///     ? 2 => tstr,
///     3 => uint,
///     4 => uint,
///     ? 5 => hash-salt-mode,
///     ? 6 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentRef {
    #[serde(rename = "1")]
    pub content_hash: HashValue,

    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    #[serde(rename = "3")]
    pub byte_length: u64,

    #[serde(rename = "4")]
    pub char_count: u64,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub salt_mode: Option<HashSaltMode>,

    /// Hash of the author-provided salt
    #[serde(
        rename = "6",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub salt_commitment: Option<Vec<u8>>,
}

impl DocumentRef {
    /// Validate document-ref constraints per CDDL schema.
    pub fn validate(&self) -> Result<(), String> {
        self.content_hash.validate_digest_length()?;
        if let Some(ref salt) = self.salt_commitment {
            if !ALLOWED_SALT_LENGTHS.contains(&salt.len()) {
                return Err(format!(
                    "salt_commitment length {} invalid (must be {:?} bytes)",
                    salt.len(),
                    ALLOWED_SALT_LENGTHS
                ));
            }
        }
        Ok(())
    }
}

/// Edit delta per CDDL `edit-delta`.
///
/// ```cddl
/// edit-delta = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     ? 4 => [* edit-position],
///     ? 5 => hash-digest,
///     ? 9 => [8*8 uint],
///     ? 10 => [8*8 uint],
///     ? 11 => [8*8 uint],
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditDelta {
    #[serde(rename = "1")]
    pub chars_added: u64,

    #[serde(rename = "2")]
    pub chars_deleted: u64,

    #[serde(rename = "3")]
    pub op_count: u64,

    /// (offset, delta) pairs
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub positions: Option<Vec<(u64, i64)>>,

    /// Hash of the edit dependency graph
    #[serde(
        rename = "5",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub edit_graph_hash: Option<Vec<u8>>,

    /// 8-bin histogram of cursor trajectory distances
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub cursor_trajectory_histogram: Option<Vec<u64>>,

    /// 8-bin histogram of revision depths
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub revision_depth_histogram: Option<Vec<u64>>,

    /// 8-bin histogram of pause durations between edits
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub pause_duration_histogram: Option<Vec<u64>>,

    /// SHA-256 binding hash over quantized forensic metrics (RQA, Lyapunov,
    /// correlation dimension, etc.) at this checkpoint. Turns verification
    /// of independent metrics into a simultaneous constraint satisfaction
    /// problem: forging requires finding a keystroke sequence that produces
    /// ALL metric bins simultaneously, which is NP-hard (reducible to ILP).
    #[serde(
        rename = "12",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub metric_binding_hash: Option<Vec<u8>>,
}

/// Max edit positions per delta.
/// Per CDDL `edit-delta`: `positions` is `[* [uint, int]]` with practical
/// upper bound to prevent resource exhaustion during validation.
const MAX_EDIT_POSITIONS: usize = 100_000;

impl EditDelta {
    /// Validate edit-delta constraints per CDDL schema.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref positions) = self.positions {
            if positions.len() > MAX_EDIT_POSITIONS {
                return Err(format!(
                    "too many edit positions: {} (max {})",
                    positions.len(),
                    MAX_EDIT_POSITIONS
                ));
            }
            for (i, &(_offset, change)) in positions.iter().enumerate() {
                if change == 0 {
                    return Err(format!(
                        "edit position[{}] has zero change value (no-op not allowed)",
                        i
                    ));
                }
            }
        }
        // CDDL says [8*8 uint] for histogram fields (exactly 8 elements)
        for (name, hist) in [
            (
                "cursor_trajectory_histogram",
                &self.cursor_trajectory_histogram,
            ),
            ("revision_depth_histogram", &self.revision_depth_histogram),
            ("pause_duration_histogram", &self.pause_duration_histogram),
        ] {
            if let Some(h) = hist {
                if h.len() != 8 {
                    return Err(format!(
                        "{} must have exactly 8 elements, got {}",
                        name,
                        h.len()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Proof parameters per CDDL `proof-params`.
///
/// ```cddl
/// proof-params = {
///     1 => uint,  ; time-cost
///     2 => uint,  ; memory-cost (KiB)
///     3 => uint,  ; parallelism
///     4 => uint,  ; steps
///     ? 5 => uint, ; waypoint-interval (Mode 10 only)
///     ? 6 => uint, ; waypoint-memory (KiB, Mode 10 only)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofParams {
    #[serde(rename = "1")]
    pub time_cost: u64,

    /// In KiB
    #[serde(rename = "2")]
    pub memory_cost: u64,

    #[serde(rename = "3")]
    pub parallelism: u64,

    #[serde(rename = "4")]
    pub steps: u64,

    /// Waypoint interval (Mode 10 only)
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub waypoint_interval: Option<u64>,

    /// Waypoint memory in KiB (Mode 10 only)
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub waypoint_memory: Option<u64>,

    /// PoSME reads per step (d). Mode 30/31 only.
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub reads_per_step: Option<u64>,

    /// PoSME Fiat-Shamir challenge count (Q). Mode 30/31 only.
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<u64>,

    /// PoSME recursive provenance depth (R). Mode 30/31 only.
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub recursion_depth: Option<u64>,
}

/// Merkle proof per CDDL `merkle-proof`.
///
/// ```cddl
/// merkle-proof = {
///     1 => uint,
///     2 => [+ hash-digest],
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    #[serde(rename = "1")]
    pub leaf_index: u64,

    /// Ordered leaf-to-root
    #[serde(rename = "2")]
    pub sibling_path: Vec<serde_bytes::ByteBuf>,

    #[serde(rename = "3", with = "serde_bytes")]
    pub leaf_value: Vec<u8>,
}

/// Sequential work function proof per CDDL `process-proof`.
///
/// ```cddl
/// process-proof = {
///     1 => proof-algorithm,
///     2 => proof-params,
///     3 => hash-digest,
///     4 => hash-digest,
///     5 => [+ merkle-proof],
///     6 => uint,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessProof {
    #[serde(rename = "1")]
    pub algorithm: ProofAlgorithm,

    #[serde(rename = "2")]
    pub params: ProofParams,

    #[serde(rename = "3", with = "serde_bytes")]
    pub input: Vec<u8>,

    #[serde(rename = "4", with = "serde_bytes")]
    pub merkle_root: Vec<u8>,

    #[serde(rename = "5")]
    pub sampled_proofs: Vec<MerkleProof>,

    /// In milliseconds
    #[serde(rename = "6")]
    pub claimed_duration: u64,
}

/// Max sampled Merkle proofs per process-proof.
/// Per CDDL `process-proof`: `sampled-proofs` is `[* merkle-proof]`.
const MAX_SAMPLED_PROOFS: usize = 1000;
/// Max Merkle sibling path depth (log2 of max tree).
/// Per CDDL `merkle-proof`: `sibling-path` is `[* bstr]`; 64 covers 2^64 leaves.
const MAX_MERKLE_DEPTH: usize = 64;
/// Max hash digest length in bytes.
/// Per CDDL: digest fields are `bstr .size (32..64)` (SHA-256 through SHA-512).
const MAX_DIGEST_LEN: usize = 64;
/// Max jitter intervals per binding.
/// Per CDDL `jitter-binding`: `intervals` is `[* uint]` with practical cap.
pub(crate) const MAX_JITTER_INTERVALS: usize = 100_000;
/// Max thermal samples per physical-state.
/// Per CDDL `physical-state`: `thermal` is `[* float32]` with practical cap.
const MAX_THERMAL_SAMPLES: usize = 10_000;
/// Max thermal trajectory entries per physical-liveness.
/// Per CDDL `physical-liveness`: `thermal-trajectory` is `[* float32]` with practical cap.
const MAX_THERMAL_TRAJECTORY: usize = 10_000;
/// Max feature flags per profile-declaration.
/// Per CDDL `profile-declaration`: `feature-flags` is `[* uint]` with practical cap.
const MAX_FEATURE_FLAGS: usize = 100;
/// Expected SHA-256 digest size in bytes.
const SHA256_DIGEST_LEN: usize = 32;

impl ProcessProof {
    /// Returns `true` if `claimed_duration` falls within the IETF-mandated
    /// `[SWF_MIN_DURATION_FACTOR, SWF_MAX_DURATION_FACTOR]` range relative
    /// to `expected_duration_ms`.
    pub fn is_duration_within_bounds(&self, expected_duration_ms: u64) -> bool {
        if expected_duration_ms == 0 || self.claimed_duration == 0 {
            return false;
        }
        let ratio = self.claimed_duration as f64 / expected_duration_ms as f64;
        (SWF_MIN_DURATION_FACTOR..=SWF_MAX_DURATION_FACTOR).contains(&ratio)
    }

    /// Validate size limits on proof fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.input.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "process_proof input too long: {} (max {})",
                self.input.len(),
                MAX_DIGEST_LEN
            ));
        }
        if self.merkle_root.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "merkle_root too long: {} (max {})",
                self.merkle_root.len(),
                MAX_DIGEST_LEN
            ));
        }
        if self.sampled_proofs.len() > MAX_SAMPLED_PROOFS {
            return Err(format!(
                "too many sampled_proofs: {} (max {})",
                self.sampled_proofs.len(),
                MAX_SAMPLED_PROOFS
            ));
        }
        for (i, proof) in self.sampled_proofs.iter().enumerate() {
            proof
                .validate()
                .map_err(|e| format!("sampled_proofs[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

impl MerkleProof {
    /// Validate size limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.sibling_path.len() > MAX_MERKLE_DEPTH {
            return Err(format!(
                "sibling_path too deep: {} (max {})",
                self.sibling_path.len(),
                MAX_MERKLE_DEPTH
            ));
        }
        if self.leaf_value.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "leaf_value too long: {} (max {})",
                self.leaf_value.len(),
                MAX_DIGEST_LEN
            ));
        }
        for (i, sibling) in self.sibling_path.iter().enumerate() {
            if sibling.len() != SHA256_DIGEST_LEN {
                return Err(format!(
                    "sibling_path[{}] length {} != {} (expected SHA-256 digest)",
                    i,
                    sibling.len(),
                    SHA256_DIGEST_LEN
                ));
            }
        }
        Ok(())
    }
}

/// Jitter binding (behavioral entropy) per CDDL `jitter-binding`.
///
/// ```cddl
/// jitter-binding = {
///     1 => [+ uint],
///     2 => uint,
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitterBindingWire {
    /// In milliseconds
    #[serde(rename = "1")]
    pub intervals: Vec<u64>,

    /// In centibits
    #[serde(rename = "2")]
    pub entropy_estimate: u64,

    /// HMAC seal
    #[serde(rename = "3", with = "serde_bytes")]
    pub jitter_seal: Vec<u8>,
}

impl JitterBindingWire {
    /// Validate size limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.intervals.len() > MAX_JITTER_INTERVALS {
            return Err(format!(
                "too many jitter intervals: {} (max {})",
                self.intervals.len(),
                MAX_JITTER_INTERVALS
            ));
        }
        if self.jitter_seal.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "jitter_seal too long: {} (max {})",
                self.jitter_seal.len(),
                MAX_DIGEST_LEN
            ));
        }
        Ok(())
    }
}

/// Physical state binding per CDDL `physical-state`.
///
/// ```cddl
/// physical-state = {
///     1 => [+ int],
///     2 => int,
///     ? 3 => bstr .size 32,
///     ? 4 => [+ inertial-sample],
/// }
///
/// inertial-sample = [
///     cpoe-timestamp,
///     int,   ; x-axis (micro-g)
///     int,   ; y-axis (micro-g)
///     int,   ; z-axis (micro-g)
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalState {
    /// Relative millidegrees
    #[serde(rename = "1")]
    pub thermal: Vec<i64>,

    #[serde(rename = "2")]
    pub entropy_delta: i64,

    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "fixed_bytes_32_opt"
    )]
    pub kernel_commitment: Option<[u8; 32]>,

    /// Accelerometer / vibration samples (ENHANCED+).
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub inertial_samples: Option<Vec<InertialSample>>,
}

impl PhysicalState {
    /// Validate size limits on thermal samples.
    pub fn validate(&self) -> Result<(), String> {
        if self.thermal.len() > MAX_THERMAL_SAMPLES {
            return Err(format!(
                "too many thermal samples: {} (max {})",
                self.thermal.len(),
                MAX_THERMAL_SAMPLES
            ));
        }
        Ok(())
    }
}

/// A single tri-axis accelerometer reading at a point in time.
///
/// Units: timestamp in milliseconds (cpoe-timestamp), axes in micro-g (1e-6 * 9.81 m/s^2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InertialSample {
    /// Sample timestamp (milliseconds since epoch, cpoe-timestamp).
    pub timestamp: u64,
    /// X-axis acceleration (micro-g).
    pub x: i64,
    /// Y-axis acceleration (micro-g).
    pub y: i64,
    /// Z-axis acceleration (micro-g).
    pub z: i64,
}

/// Physical liveness markers per CDDL `physical-liveness`.
///
/// ```cddl
/// physical-liveness = {
///     1 => [+ thermal-sample],
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalLiveness {
    /// (timestamp, delta in millidegrees)
    #[serde(rename = "1")]
    pub thermal_trajectory: Vec<(u64, i64)>,

    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub entropy_anchor: [u8; 32],
}

impl PhysicalLiveness {
    /// Validate size limits on thermal trajectory.
    pub fn validate(&self) -> Result<(), String> {
        if self.thermal_trajectory.len() > MAX_THERMAL_TRAJECTORY {
            return Err(format!(
                "too many thermal_trajectory entries: {} (max {})",
                self.thermal_trajectory.len(),
                MAX_THERMAL_TRAJECTORY
            ));
        }
        Ok(())
    }
}

/// Presence challenge per CDDL `presence-challenge`.
///
/// ```cddl
/// presence-challenge = {
///     1 => bstr .size (16..256),
///     2 => bstr,
///     3 => cpoe-timestamp,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceChallenge {
    /// >= 128 bits
    #[serde(rename = "1", with = "serde_bytes")]
    pub challenge_nonce: Vec<u8>,

    /// COSE_Sign1-wrapped device signature per draft-condrey-rats-pop §4.5.
    /// Use `wrap_device_signature_cose` to produce this field.
    #[serde(rename = "2", with = "serde_bytes")]
    pub device_signature: Vec<u8>,

    /// Epoch ms
    #[serde(rename = "3")]
    pub response_time: u64,
}

impl PresenceChallenge {
    /// Wrap a raw device signature + optional platform attestation blob in
    /// COSE_Sign1 per draft-condrey-rats-pop.
    ///
    /// `payload` is the challenge nonce (or a serialized response).
    /// `signer` provides Ed25519 signing. The platform attestation (if any)
    /// MAY be carried as an unprotected header.
    pub fn wrap_device_signature_cose(
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
        platform_attestation: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
        use ed25519_dalek::Signer;

        const MAX_PLATFORM_ATTESTATION: usize = 64 * 1024; // 64 KiB
        if let Some(att) = platform_attestation {
            if att.len() > MAX_PLATFORM_ATTESTATION {
                return Err(format!(
                    "platform_attestation too large: {} bytes (max {})",
                    att.len(),
                    MAX_PLATFORM_ATTESTATION
                ));
            }
        }

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();

        let mut unprotected_builder = HeaderBuilder::new();
        if let Some(att) = platform_attestation {
            // Carry platform attestation as an unprotected header parameter.
            // Label -1 (private use) holds the raw attestation object.
            unprotected_builder = unprotected_builder
                .text_value("att".to_string(), ciborium::Value::Bytes(att.to_vec()));
        }
        let unprotected = unprotected_builder.build();

        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_vec())
            .create_signature(&[], |sig_data| {
                signing_key.sign(sig_data).to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .map_err(|e| format!("COSE_Sign1 serialization: {e}"))
    }

    /// Validate presence-challenge constraints per CDDL schema.
    /// challenge-nonce must be 16..256 bytes (`.size (16..256)`).
    pub fn validate(&self) -> Result<(), String> {
        if self.challenge_nonce.len() < MIN_CHALLENGE_NONCE_LEN
            || self.challenge_nonce.len() > MAX_CHALLENGE_NONCE_LEN
        {
            return Err(format!(
                "challenge_nonce length {} out of range (must be {}..={} bytes)",
                self.challenge_nonce.len(),
                MIN_CHALLENGE_NONCE_LEN,
                MAX_CHALLENGE_NONCE_LEN
            ));
        }
        Ok(())
    }
}

/// Channel binding per CDDL `channel-binding`.
///
/// ```cddl
/// channel-binding = {
///     1 => binding-type,
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelBinding {
    #[serde(rename = "1")]
    pub binding_type: BindingType,

    /// TLS Exporter Key Material output
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub binding_value: [u8; 32],
}

/// Self-receipt for cross-tool composition per CDDL `self-receipt`.
///
/// ```cddl
/// self-receipt = {
///     1 => tstr,
///     2 => hash-value / compact-ref,
///     3 => hash-value / compact-ref,
///     4 => cpoe-timestamp,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelfReceipt {
    #[serde(rename = "1")]
    pub tool_id: String,

    #[serde(rename = "2")]
    pub output_commit: HashValue,

    #[serde(rename = "3")]
    pub evidence_ref: HashValue,

    /// Epoch ms
    #[serde(rename = "4")]
    pub transfer_time: u64,
}

/// AI tool output receipt with COSE_Sign1 signature per CDDL `tool-receipt`.
///
/// ```cddl
/// tool-receipt = {
///     1 => tstr,
///     2 => hash-value,
///     ? 3 => hash-value,
///     4 => cpoe-timestamp,
///     5 => bstr,           ; COSE_Sign1 bytes
///     ? 6 => uint,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolReceipt {
    #[serde(rename = "1")]
    pub tool_id: String,

    #[serde(rename = "2")]
    pub output_commit: HashValue,

    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<HashValue>,

    /// Epoch ms
    #[serde(rename = "4")]
    pub issued_at: u64,

    /// COSE_Sign1 bytes
    #[serde(rename = "5", with = "serde_bytes")]
    pub tool_signature: Vec<u8>,

    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub output_char_count: Option<u64>,
}

/// Receipt type discriminated by presence of tool-signature (key 5).
///
/// Variant order matters: `Tool` must come first so serde tries to match
/// the superset type (which has required key 5) before falling back to
/// `SelfReceipt`. If key 5 is missing, `ToolReceipt` deserialization fails
/// and `SelfReceipt` is tried.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Receipt {
    /// AI tool output receipt with COSE_Sign1 signature.
    Tool(ToolReceipt),
    /// Cross-tool composition receipt without external signature.
    SelfReceipt(SelfReceipt),
}

/// Active liveness probe per CDDL `active-probe`.
///
/// ```cddl
/// active-probe = {
///     1 => probe-type,
///     2 => cpoe-timestamp,
///     3 => cpoe-timestamp,
///     4 => bstr,
///     5 => bstr,
///     ? 6 => uint,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveProbe {
    #[serde(rename = "1")]
    pub probe_type: ProbeType,

    /// Epoch ms
    #[serde(rename = "2")]
    pub stimulus_time: u64,

    /// Epoch ms
    #[serde(rename = "3")]
    pub response_time: u64,

    #[serde(rename = "4", with = "serde_bytes")]
    pub stimulus_data: Vec<u8>,

    #[serde(rename = "5", with = "serde_bytes")]
    pub response_data: Vec<u8>,

    /// In ms
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub response_latency: Option<u64>,
}

/// Hardware-anchored time proof per CDDL `hat-proof`.
///
/// ```cddl
/// hat-proof = {
///     1 => bstr,  ; time-before (TPMS_TIME_ATTEST_INFO)
///     2 => bstr,  ; time-after (TPMS_TIME_ATTEST_INFO)
///     3 => bstr,  ; sig-before (AIK signature)
///     4 => bstr,  ; sig-after (AIK signature)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HatProof {
    /// TPMS_TIME_ATTEST_INFO before SWF
    #[serde(rename = "1", with = "serde_bytes")]
    pub time_before: Vec<u8>,

    /// TPMS_TIME_ATTEST_INFO after SWF
    #[serde(rename = "2", with = "serde_bytes")]
    pub time_after: Vec<u8>,

    /// AIK signature over time-before
    #[serde(rename = "3", with = "serde_bytes")]
    pub sig_before: Vec<u8>,

    /// AIK signature over time-after
    #[serde(rename = "4", with = "serde_bytes")]
    pub sig_after: Vec<u8>,
}

/// Public randomness beacon anchor per CDDL `beacon-anchor`.
///
/// ```cddl
/// beacon-anchor = {
///     1 => tstr,          ; beacon-source (URI)
///     2 => uint,          ; beacon-round
///     3 => bstr .size 32, ; beacon-value
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconAnchor {
    /// URI of beacon service
    #[serde(rename = "1")]
    pub source_url: String,

    /// Beacon round number
    #[serde(rename = "2")]
    pub beacon_round: u64,

    /// Beacon randomness output (32 bytes)
    #[serde(rename = "3", with = "fixed_bytes_32")]
    pub beacon_value: [u8; 32],
}

/// Profile declaration per CDDL `profile-declaration`.
///
/// ```cddl
/// profile-declaration = {
///     1 => tstr,
///     2 => [+ uint],
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileDeclarationWire {
    #[serde(rename = "1")]
    pub profile_id: String,

    #[serde(rename = "2")]
    pub feature_flags: Vec<u64>,
}

impl ProfileDeclarationWire {
    /// Validate size limits on feature flags.
    pub fn validate(&self) -> Result<(), String> {
        if self.feature_flags.len() > MAX_FEATURE_FLAGS {
            return Err(format!(
                "too many feature_flags: {} (max {})",
                self.feature_flags.len(),
                MAX_FEATURE_FLAGS
            ));
        }
        Ok(())
    }
}

/// Streaming statistics per CDDL `streaming-stats`.
///
pub use crate::baseline::StreamingStats;

/// Aggregate baseline digest per CDDL `baseline-digest`.
///
/// ```cddl
/// baseline-digest = {
///     1  => uint,              ; version (MUST be 1)
///     2  => uint,              ; session-count
///     3  => uint,              ; total-keystrokes
///     4  => streaming-stats,   ; iki-stats
///     5  => streaming-stats,   ; cv-stats
///     6  => streaming-stats,   ; hurst-stats
///     7  => [9* float32],      ; aggregate-iki-histogram
///     8  => streaming-stats,   ; pause-stats
///     9  => bstr .size 32,     ; session-merkle-root (MMR)
///     10 => confidence-tier,   ; baseline maturity
///     11 => cpoe-timestamp,     ; computed-at
///     12 => bstr .size 32,     ; identity-fingerprint
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineDigest {
    #[serde(rename = "1")]
    pub version: u32,

    #[serde(rename = "2")]
    pub session_count: u64,

    #[serde(rename = "3")]
    pub total_keystrokes: u64,

    #[serde(rename = "4")]
    pub iki_stats: StreamingStats,

    #[serde(rename = "5")]
    pub cv_stats: StreamingStats,

    #[serde(rename = "6")]
    pub hurst_stats: StreamingStats,

    #[serde(rename = "7")]
    pub aggregate_iki_histogram: [f64; 9],

    #[serde(rename = "8")]
    pub pause_stats: StreamingStats,

    #[serde(rename = "9", with = "fixed_bytes_32")]
    pub session_merkle_root: [u8; 32],

    #[serde(rename = "10")]
    pub confidence_tier: ConfidenceTier,

    #[serde(rename = "11")]
    pub computed_at: u64,

    #[serde(rename = "12", with = "fixed_bytes_32")]
    pub identity_fingerprint: [u8; 32],
}

/// Session behavioral summary per CDDL `session-behavioral-summary`.
///
/// ```cddl
/// session-behavioral-summary = {
///     1 => [9* float32],   ; iki-histogram
///     2 => float32,        ; iki-cv
///     3 => float32,        ; hurst
///     4 => float32,        ; pause-frequency
///     5 => uint,           ; duration-secs
///     6 => uint,           ; keystroke-count
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBehavioralSummary {
    /// 9-bin IKI histogram (edges: 0, 50, 100, 150, 200, 300, 500, 1000, 2000ms)
    #[serde(rename = "1")]
    pub iki_histogram: [f64; 9],

    #[serde(rename = "2")]
    pub iki_cv: f64,

    /// Long-range dependency exponent
    #[serde(rename = "3")]
    pub hurst: f64,

    #[serde(rename = "4")]
    pub pause_frequency: f64,

    #[serde(rename = "5")]
    pub duration_secs: u64,

    #[serde(rename = "6")]
    pub keystroke_count: u64,
}

/// Baseline verification per CDDL `baseline-verification`.
///
/// ```cddl
/// baseline-verification = {
///     1 => baseline-digest / null,
///     2 => session-behavioral-summary,
///     ? 3 => bstr,   ; digest-signature (COSE_Sign1)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineVerification {
    /// None during enrollment phase.
    #[serde(rename = "1", default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<BaselineDigest>,

    #[serde(rename = "2")]
    pub session_summary: SessionBehavioralSummary,

    /// COSE_Sign1 over the CBOR-encoded digest.
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub digest_signature: Option<Vec<u8>>,
}

/// Wire-format anchor proof from an external timestamping provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProofWire {
    /// Provider identifier (e.g. "ots", "rfc3161", "notary").
    #[serde(rename = "1")]
    pub provider: String,
    /// Raw proof bytes (OTS file, RFC 3161 token, etc.).
    #[serde(rename = "2", with = "serde_bytes_opt", default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<u8>>,
    /// Submission timestamp (RFC 3339).
    #[serde(rename = "3")]
    pub timestamp: String,
    /// Proof status: "pending" or "confirmed".
    #[serde(rename = "4")]
    pub status: String,
}
