// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Single HMAC-protected event record in the hash chain.
#[derive(Debug, Clone)]
pub struct SecureEvent {
    pub id: Option<i64>,
    pub device_id: [u8; 16],
    pub machine_id: String,
    pub timestamp_ns: i64,
    pub file_path: String,
    pub content_hash: [u8; 32],
    pub file_size: i64,
    pub size_delta: i32,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub context_type: Option<String>,
    pub context_note: Option<String>,
    pub vdf_input: Option<[u8; 32]>,
    pub vdf_output: Option<[u8; 32]>,
    pub vdf_iterations: u64,
    pub forensic_score: f64,
    pub is_paste: bool,
    /// Hardware monotonic counter value at event time (None for software-only)
    pub hardware_counter: Option<u64>,
    /// Input method hint from the platform layer (e.g. "dictation", "ime")
    pub input_method: Option<String>,
    /// Lamport one-shot signature (8192 bytes) for double-sign detection.
    pub lamport_signature: Option<Vec<u8>>,
    /// Lamport public key fingerprint (8 bytes) for compact identification.
    pub lamport_pubkey_fingerprint: Option<Vec<u8>>,
    /// Timeline challenge nonce from WritersProof CA (30s TTL).
    pub challenge_nonce: Option<String>,
    /// Hardware co-signature: entangled hash signed by TPM/Secure Enclave.
    pub hw_cosign_signature: Option<Vec<u8>>,
    /// Hardware co-signature: public key of the signing hardware.
    pub hw_cosign_pubkey: Option<Vec<u8>>,
    /// Hardware co-signature: SHA-256 commitment to the SE-derived threshold salt.
    pub hw_cosign_salt_commitment: Option<Vec<u8>>,
    /// Hardware co-signature: chain index (0 = genesis).
    pub hw_cosign_chain_index: Option<u64>,
    /// Hardware co-signature: entangled hash bytes for verification.
    pub hw_cosign_entangled_hash: Option<Vec<u8>>,
    /// Hardware co-signature: SHA-256 digest of accumulated behavioral entropy.
    pub hw_cosign_entropy_digest: Option<Vec<u8>>,
    /// Hardware co-signature: byte count of accumulated entropy at co-sign time.
    pub hw_cosign_entropy_bytes: Option<u64>,
    /// PoSME proof bytes (CBOR-serialized PosmeProof).
    pub posme_proof: Option<Vec<u8>>,
    /// JSON-serialized semantic keystroke summary (SemanticAccumulator snapshot).
    pub semantic_summary: Option<String>,
}

/// Persisted state for a shadow session keyed by `(bundle_id, project_uuid)`.
///
/// Loaded on sentinel restart so bundle-app sessions (Scrivener, Vellum, Ulysses)
/// resume their checkpoint chain without resetting keystroke counts.
#[derive(Debug, Clone)]
pub struct ShadowSessionRow {
    pub bundle_id: String,
    pub project_uuid: String,
    pub session_id: String,
    pub wal_path: Option<String>,
    pub segment_counts_json: Option<String>,
    pub scrivx_hash: Option<String>,
    pub last_checkpoint_ns: i64,
    pub updated_at: i64,
}

impl SecureEvent {
    /// Create a new event with sensible defaults for most fields.
    ///
    /// Callers that need non-default values for `context_type`, `size_delta`,
    /// `forensic_score`, `is_paste`, or VDF fields should set them after construction.
    pub fn new(
        file_path: String,
        content_hash: [u8; 32],
        file_size: i64,
        context_note: Option<String>,
    ) -> Self {
        Self {
            id: None,
            device_id: [0u8; 16],
            machine_id: String::new(),
            timestamp_ns: crate::utils::now_ns(),
            file_path,
            content_hash,
            file_size,
            size_delta: 0,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: None,
            context_note,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: 0,
            forensic_score: 0.0,
            is_paste: false,
            hardware_counter: None,
            input_method: None,
            lamport_signature: None,
            lamport_pubkey_fingerprint: None,
            challenge_nonce: None,
            hw_cosign_signature: None,
            hw_cosign_pubkey: None,
            hw_cosign_salt_commitment: None,
            hw_cosign_chain_index: None,
            hw_cosign_entangled_hash: None,
            hw_cosign_entropy_digest: None,
            hw_cosign_entropy_bytes: None,
            posme_proof: None,
            semantic_summary: None,
        }
    }
}
