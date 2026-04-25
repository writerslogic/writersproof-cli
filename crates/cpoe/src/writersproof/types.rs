// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Request/response types for the WritersProof attestation API.

use serde::{Deserialize, Serialize};

/// A validated 64-character ASCII hex string (session ID or SHA-256 hash).
///
/// The only way to construct a `Hex64` is through `Hex64::new`, which enforces
/// the length and character-set invariants. This makes it impossible to pass
/// an unvalidated hash to `WritersProofClient` methods at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hex64(String);

impl Hex64 {
    /// Construct a `Hex64` from a string, validating length and charset.
    pub fn new(s: impl Into<String>) -> Result<Self, String> {
        let s = s.into();
        if s.len() != 64 {
            return Err(format!(
                "Hex64 must be exactly 64 chars, got {}: {}",
                s.len(),
                &s[..s.len().min(32)]
            ));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Hex64 must contain only hex digits, got: {}",
                &s[..s.len().min(32)]
            ));
        }
        Ok(Self(s))
    }

    /// Return the validated hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Hex64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Hex64 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Hex64 {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<String> for Hex64 {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
    /// 32-byte hex-encoded random nonce
    pub nonce: String,
    /// ISO 8601 expiration timestamp
    pub expires_at: String,
    pub nonce_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    /// Hex-encoded master public key
    pub public_key: String,
    /// SHA-256 of `public_key`
    pub device_id: String,
    pub platform: String,
    /// One of: `secure_enclave`, `tpm`, `software`
    pub attestation_type: String,
    /// Hardware attestation certificate (hex or base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub hardware_key_id: String,
    /// Trust tier: T1, T2, or T3
    pub assurance_tier: String,
    pub enrolled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    pub attestation_id: String,
    /// e.g. "accepted"
    pub status: String,
    /// One of: `pending`, `verified`, `failed`
    pub verification_status: String,
    /// Position in the hardware key's evidence chain
    pub chain_position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    /// SHA-256 hash of the evidence packet (hex-encoded).
    pub evidence_hash: String,
    /// Author DID (e.g. `did:cpoe:...`).
    pub author_did: String,
    /// Ed25519 signature over the evidence hash (hex-encoded).
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AnchorMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    pub anchor_id: String,
    pub timestamp: String,
    pub log_index: u64,
    pub inclusion_proof: Vec<String>,
    pub signed_tree_head: SignedTreeHead,
}

/// Signed Tree Head from the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishRequest {
    pub evidence_hash: String,
    pub author_did: String,
    pub signature: String,
    pub attestation: String,
    pub checkpoint_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_declaration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishResponse {
    pub record_id: String,
    pub canonical_url: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub verdict: String,
    pub confidence: f64,
    pub tier: String,
    pub anchored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparency_log: Option<TransparencyLogInfo>,
    pub evidence_summary: EvidenceSummary,
    /// Base64-encoded WAR (CBOR EAT Attestation Result).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub war: Option<String>,
}

impl VerifyResponse {
    /// Clamp fields to their valid ranges after deserialization.
    /// `confidence` must be in [0.0, 1.0]; values outside this range indicate
    /// a malformed or tampered server response.
    pub fn sanitize(&mut self) {
        self.confidence = crate::utils::Probability::clamp(self.confidence).get();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogInfo {
    pub log_index: u64,
    pub inclusion_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub duration: String,
    pub keystrokes: u64,
    pub sessions: u64,
    pub behavioral_plausibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_modal_consistency: Option<String>,
}

/// Request body for `/v1/beacon` -- fetch temporal beacon attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconRequest {
    /// SHA-256 hash of the checkpoint being attested (hex-encoded).
    pub checkpoint_hash: String,
}

/// Response from `/v1/beacon` — WritersProof-attested temporal beacon bundle.
///
/// WritersProof fetches the latest drand round and NIST pulse server-side,
/// then counter-signs the bundle. The `wp_signature` is an Ed25519 signature
/// over `(checkpoint_hash || drand_round || drand_randomness || nist_pulse_index
/// || nist_output_value || fetched_at)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconResponse {
    /// drand League of Entropy round number.
    pub drand_round: u64,
    /// drand randomness output (hex-encoded, 32 bytes).
    pub drand_randomness: String,
    /// NIST Randomness Beacon pulse index.
    pub nist_pulse_index: u64,
    /// NIST beacon output value (hex-encoded, 64 bytes).
    pub nist_output_value: String,
    /// NIST pulse timestamp.
    pub nist_timestamp: String,
    /// When WritersProof fetched the beacon values.
    pub fetched_at: String,
    /// WritersProof Ed25519 counter-signature over the bundle (hex-encoded, 64 bytes).
    pub wp_signature: String,
}

/// Response from `POST /v1/sessions/:id/challenge` -- 30-second timeline challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    /// 32-byte hex-encoded random challenge nonce.
    pub challenge: String,
    pub challenge_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub ttl_seconds: u32,
}

/// Queued attestation for offline submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedAttestation {
    pub id: String,
    /// Base64-encoded CBOR evidence packet
    pub evidence_b64: String,
    /// Hex-encoded pre-fetched nonce, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub hardware_key_id: String,
    /// Hex-encoded Ed25519 signature over DST + queue_nonce + evidence
    pub signature: String,
    /// Hex-encoded random nonce included in signature to prevent replay (EH-015)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_nonce: Option<String>,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}

/// Request body for `POST /v1/sessions/:id/pulse` -- real-time hash attestation.
/// Combines hash update and 30-second timeline challenge in one atomic call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PulseRequest {
    /// SHA-256 hash of the current document (hex-encoded, 64 chars).
    pub current_hash: String,
}

/// Response from `POST /v1/sessions/:id/pulse` -- fresh 30-second nonce for checkpoint binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PulseResponse {
    /// 32-byte hex-encoded random nonce for binding into next checkpoint.
    pub nonce: String,
    /// UUID of the issued nonce (for correlation audit).
    pub nonce_id: String,
    /// ISO 8601 timestamp when nonce was issued.
    pub issued_at: String,
    /// ISO 8601 timestamp when nonce expires (30 seconds after issued_at).
    pub expires_at: String,
    /// TTL in seconds (always 30).
    pub ttl_seconds: u32,
}

/// Request body for `POST /v1/sessions/:id/confirm` -- closes the nonce handshake loop.
///
/// After committing a checkpoint that binds a server nonce, the client sends this
/// request so the server can log that nonce X was consumed by checkpoint hash Y.
/// This lets verifiers confirm the checkpoint was built within the nonce's 30s window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmNonceRequest {
    /// UUID of the nonce that was bound into this checkpoint (from `PulseResponse.nonce_id`).
    pub nonce_id: String,
    /// SHA-256 of the committed checkpoint event, hex-encoded (64 chars).
    pub checkpoint_hash: String,
}

/// Request body for `POST /v1/text-attestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextAttestationRequest {
    pub content_hash: String,
    pub tier: String,
    pub writersproof_id: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub attested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// Response from `POST /v1/text-attestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextAttestationResponse {
    pub success: bool,
    pub writersproof_id: String,
}

/// A text attestation queued for later submission when offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedTextAttestation {
    pub id: String,
    pub request: TextAttestationRequest,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}

/// An anchor request queued for later submission when the initial attempt fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedAnchorRequest {
    pub id: String,
    pub evidence_hash: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}

/// Request body for `POST /v1/credentials/issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssueRequest {
    /// CBOR-encoded AuthorshipCredential (hex-encoded).
    pub credential_cbor: String,
    /// Ed25519 signature over the credential CBOR (hex-encoded).
    pub signature: String,
    /// Ed25519 public key of the issuing device (hex-encoded).
    pub public_key: String,
    /// Session ID the credential is derived from.
    pub session_id: String,
    /// Attestation tier: "verified", "corroborated", or "declared".
    pub attestation_tier: String,
}

/// Response from `POST /v1/credentials/issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssueResponse {
    /// Server-assigned credential identifier.
    pub credential_id: String,
    /// ISO 8601 timestamp when the credential was issued.
    pub issued_at: String,
    /// ISO 8601 timestamp when the credential expires.
    pub expires_at: String,
    /// Server-signed COSE_Sign1 envelope (hex-encoded).
    pub issuer_signed: String,
    /// Credential status: "active", "suspended", "revoked".
    pub status: String,
}

/// Response from `GET /v1/credentials/:id/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusResponse {
    pub credential_id: String,
    /// "active", "suspended", or "revoked".
    pub status: String,
    pub issued_at: String,
    pub expires_at: String,
    /// ISO 8601 timestamp of last status change, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Reason for revocation, if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}
