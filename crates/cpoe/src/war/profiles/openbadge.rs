// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Open Badges 3.0 (1EdTech) profile — projects an EAR token into an
//! `OpenBadgeCredential`.
//!
//! This is a conformance-targeted extension of the W3C Verifiable Credential
//! 2.0 projection in [`super::vc`]. It reuses the same EAR source, the same
//! Ed25519 / `eddsa-jcs-2022` Data Integrity proof, the same Bitstring Status
//! List revocation entry, and the same `.cpop` evidence reference — only the
//! credential *shape* differs to match the Open Badges 3.0 data model.
//!
//! Spec: <https://www.imsglobal.org/spec/ob/v3p0> (Open Badges Specification
//! v3.0). The credential class is normatively `AchievementCredential`, for
//! which `OpenBadgeCredential` is the well-known alias term defined in the OB
//! 3.0 JSON-LD context. We emit `OpenBadgeCredential` per the requested shape.
//!
//! Two securing mechanisms are offered, mirroring the VC profile:
//! - [`to_signed_open_badge_credential`]: embedded `eddsa-jcs-2022` Data
//!   Integrity proof.
//! - [`to_cose_secured_open_badge`]: COSE_Sign1 envelope.

use chrono::{DateTime, Utc};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::tpm;
use crate::war::common::{derive_attestation_tier, SerializedTrustVector};
use crate::war::ear::EarToken;
use crate::war::profiles::vc::{self, CredentialStatus, VcEvidence, VcForensicSignals, VcProof};

/// Pinned Open Badges 3.0 JSON-LD context URL (1EdTech, version 3.0.3).
pub const OB3_CONTEXT_URL: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";

/// W3C Verifiable Credentials v2 base context (shared with the VC profile).
pub const VC_V2_CONTEXT_URL: &str = "https://www.w3.org/ns/credentials/v2";

/// Maximum lifetime of an Open Badge credential in days, matching the VC
/// profile (W3C VC 2.0 §5.3). After this period the badge must be re-issued.
const MAX_BADGE_VALIDITY_DAYS: i64 = 365;

/// Issuer profile display name (the WritersProof certification authority).
const ISSUER_PROFILE_NAME: &str = "WritersProof";

/// Issuer profile canonical URL.
const ISSUER_PROFILE_URL: &str = "https://writersproof.com";

/// Base URL for the credential `id` — the verify portal landing page keyed by
/// the `WP-XXXX-XXXX` short-id. The id both links to verification and seeds the
/// deterministic badge fingerprint.
const VERIFY_CREDENTIAL_BASE_URL: &str = "https://verify.writersproof.com/c";

/// Stable base URI for achievement definitions. The achievement id is this base
/// plus the authorship-mode slug, so each mode (Human-Authored, AI-Assisted,
/// Human-Revised) is a distinct, dereferenceable achievement. The assurance
/// tier is carried as the achievement *level* (a `tag` + the credential name),
/// NOT as a separate achievement.
const ACHIEVEMENT_BASE_URI: &str = "https://writersproof.com/achievements";

/// Authorship mode — the badge *identity* axis (what the achievement attests),
/// orthogonal to the assurance tier (the *level* at which it is attested).
///
/// We never assert "AI-generated": the engine proves a human *process* and can
/// detect deviation from it, but cannot cryptographically prove that some text
/// was authored by an AI. `AiAssistedDisclosed` is therefore the honest framing
/// for author-declared AI use, and undisclosed AI-pattern composition reads as
/// `HumanRevised` (a human working over pre-existing material), never as a
/// fabricated disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorshipMode {
    /// Original human composition with no declared AI assistance.
    HumanAuthored,
    /// The author disclosed the use of AI tools.
    AiAssistedDisclosed,
    /// A human substantially revised pre-existing or imported content.
    HumanRevised,
}

impl AuthorshipMode {
    /// Stable URL slug used in the achievement id. Never rename (breaks the
    /// dereferenceable achievement URI).
    pub fn slug(&self) -> &'static str {
        match self {
            AuthorshipMode::HumanAuthored => "human-authored",
            AuthorshipMode::AiAssistedDisclosed => "ai-assisted-disclosed",
            AuthorshipMode::HumanRevised => "human-revised",
        }
    }

    /// Human-facing label shown on the badge and in the credential name.
    pub fn label(&self) -> &'static str {
        match self {
            AuthorshipMode::HumanAuthored => "Human-Authored",
            AuthorshipMode::AiAssistedDisclosed => "AI-Assisted (Disclosed)",
            AuthorshipMode::HumanRevised => "Human-Revised",
        }
    }

    /// Achievement description for this mode.
    pub fn description(&self) -> &'static str {
        match self {
            AuthorshipMode::HumanAuthored => {
                "Cryptographically witnessed evidence that a human composed this \
                 content through an observed, original writing process."
            }
            AuthorshipMode::AiAssistedDisclosed => {
                "The author disclosed the use of AI tools. The witnessed writing \
                 process documents the human's authorship over the disclosed \
                 assistance."
            }
            AuthorshipMode::HumanRevised => {
                "Cryptographically witnessed evidence that a human substantially \
                 revised pre-existing or imported content through an observed \
                 editing process."
            }
        }
    }
}

impl std::fmt::Display for AuthorshipMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Map forensic + disclosure signals to an [`AuthorshipMode`].
///
/// `writing_mode` / `composition_mode` are the lowercase forensic enum strings
/// (e.g. `"cognitive"`, `"paste_veneer"`); `ai_disclosed` is true when the
/// author's signed declaration names any AI tool.
///
/// Rules (disclosure is authoritative):
/// 1. Declared AI use → `AiAssistedDisclosed`, regardless of forensic signal.
/// 2. Heavy paste/import (`paste_domesticate`, `paste_veneer`) or undisclosed
///    AI-mediated composition (`ai_mediated`), or a transcriptive writing mode
///    → `HumanRevised` (a human working over pre-existing material).
/// 3. Otherwise → `HumanAuthored`.
pub fn infer_authorship_mode(
    writing_mode: Option<&str>,
    composition_mode: Option<&str>,
    ai_disclosed: bool,
) -> AuthorshipMode {
    if ai_disclosed {
        return AuthorshipMode::AiAssistedDisclosed;
    }
    match composition_mode {
        Some("paste_domesticate") | Some("paste_veneer") | Some("ai_mediated") => {
            AuthorshipMode::HumanRevised
        }
        _ => match writing_mode {
            Some("transcriptive") => AuthorshipMode::HumanRevised,
            _ => AuthorshipMode::HumanAuthored,
        },
    }
}

/// Open Badges 3.0 `OpenBadgeCredential` (alias of `AchievementCredential`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Credential identifier — the verify.writersproof.com URL carrying the
    /// `WP-XXXX-XXXX` short-id. The badge fingerprint is a visual commitment to
    /// this short-id, so the id both links to verification and seeds the badge.
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    /// Human-readable credential name (OB 3.0 recommends `name` on the credential).
    pub name: String,
    /// Issuer profile object — OB 3.0 requires a `Profile`, NOT a bare string.
    pub issuer: Profile,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: AchievementSubject,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<VcEvidence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
}

/// Open Badges 3.0 issuer `Profile` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    #[serde(rename = "type")]
    pub profile_type: Vec<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Open Badges 3.0 `AchievementSubject` — the recipient and the achievement
/// they earned, plus the preserved process-attestation claims as an extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AchievementSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub subject_type: Vec<String>,
    pub achievement: Achievement,
    /// Preserved CPoE process-attestation claims. Carried as an additional
    /// property on the subject so the behavioral evidence is not dropped when
    /// projecting into the OB 3.0 shape.
    #[serde(rename = "processAttestation", skip_serializing_if = "Option::is_none")]
    pub process_attestation: Option<OpenBadgeProcessAttestation>,
}

/// Process attestation claims carried alongside the achievement.
///
/// Field-compatible projection of the VC profile's `ProcessAttestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeProcessAttestation {
    pub status: String,
    #[serde(rename = "trustVector", skip_serializing_if = "Option::is_none")]
    pub trust_vector: Option<SerializedTrustVector>,
    #[serde(rename = "documentRef", skip_serializing_if = "Option::is_none")]
    pub document_ref: Option<String>,
    #[serde(rename = "chainDuration", skip_serializing_if = "Option::is_none")]
    pub chain_duration: Option<String>,
    #[serde(rename = "attestationTier", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<String>,
    #[serde(rename = "writingMode", skip_serializing_if = "Option::is_none")]
    pub writing_mode: Option<String>,
    #[serde(rename = "compositionMode", skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<String>,
    #[serde(rename = "forensicSignals", skip_serializing_if = "Option::is_none")]
    pub forensic_signals: Option<VcForensicSignals>,
}

/// Open Badges 3.0 `Achievement` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Achievement {
    pub id: String,
    #[serde(rename = "type")]
    pub achievement_type: Vec<String>,
    pub name: String,
    pub description: String,
    pub criteria: Criteria,
    /// OB 3.0 `achievementType` vocabulary term. "Badge" for a badge award.
    #[serde(rename = "achievementType")]
    pub achievement_type_value: String,
    /// OB 3.0 `tag` array. Carries the assurance tier as the achievement
    /// *level* (e.g. `"assurance:verified"`), keeping mode and tier orthogonal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<String>>,
}

/// Open Badges 3.0 `Criteria` object — how the achievement is earned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Criteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub narrative: String,
}

/// Map the internal attestation-tier string to a human-facing tier label
/// matching the Verified / Corroborated / Declared model.
fn tier_label(internal_tier: Option<&str>) -> &'static str {
    match internal_tier {
        Some("hardware_bound") => "Verified",
        Some("attested_software") => "Corroborated",
        _ => "Declared",
    }
}

/// Compose the human-readable credential name as "Mode — Tier" (e.g.
/// "Human-Authored — Verified"): the mode is the identity, the tier the level.
fn credential_name(mode: AuthorshipMode, tier_label: &str) -> String {
    format!("{} — {tier_label}", mode.label())
}

/// Compose the criteria narrative describing how the badge was earned, framed by
/// authorship mode and qualified by the assurance tier.
fn criteria_narrative(
    mode: AuthorshipMode,
    tier_label: &str,
    internal_tier: Option<&str>,
) -> String {
    let mode_clause = match mode {
        AuthorshipMode::HumanAuthored => {
            "Behavioral authorship evidence (keystroke timing, revision cadence, \
             and process checkpoints) was captured during original human \
             composition."
        }
        AuthorshipMode::AiAssistedDisclosed => {
            "The author disclosed the use of AI tools; behavioral evidence \
             (keystroke timing, revision cadence, and process checkpoints) \
             documents the human's authorship process over that assistance."
        }
        AuthorshipMode::HumanRevised => {
            "Behavioral evidence (keystroke timing, revision cadence, and process \
             checkpoints) documents a human substantially revising pre-existing \
             or imported content."
        }
    };
    let tier_clause = match internal_tier {
        Some("hardware_bound") => "The signing key is bound to hardware (TPM / Secure Enclave).",
        Some("attested_software") => "The evidence is signed by an attested software key.",
        _ => "The evidence is a cryptographically signed proof-of-process chain.",
    };
    format!(
        "Awarded at the \"{tier_label}\" assurance tier. {mode_clause} {tier_clause} \
         The evidence is packaged as a signed CPoE (Cryptographic Proof of Effort) \
         packet and is independently verifiable."
    )
}

/// Build the core OB 3.0 credential fields from an EAR token (shared by all
/// encoding paths). Mirrors the VC profile's `build_vc_core`.
fn build_open_badge_core(
    ear: &EarToken,
    author_did: &str,
    mode: AuthorshipMode,
) -> Result<OpenBadgeCredential> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let tv = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(SerializedTrustVector::from);

    let document_ref = appr.pop_evidence_ref.as_ref().map(hex::encode);

    let chain_duration = appr.pop_chain_duration.map(|secs| {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let remaining_secs = secs % 60;
        if hours > 0 {
            format!("PT{}H{}M{}S", hours, minutes, remaining_secs)
        } else if minutes > 0 {
            format!("PT{}M{}S", minutes, remaining_secs)
        } else {
            format!("PT{}S", remaining_secs)
        }
    });

    let internal_tier = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| derive_attestation_tier(tv).to_string());

    let label = tier_label(internal_tier.as_deref());

    let valid_from: DateTime<Utc> = DateTime::from_timestamp(ear.iat, 0)
        .ok_or_else(|| Error::evidence(format!("EAR iat {} is not a valid timestamp", ear.iat)))?;
    let valid_until = valid_from
        .checked_add_signed(chrono::Duration::days(MAX_BADGE_VALIDITY_DAYS))
        .map(|dt| dt.to_rfc3339());

    let seal_hash = appr
        .pop_seal
        .as_ref()
        .map(|s| crate::utils::crypto_types::HexHash::from_bytes(s.h3).to_hex());

    let evidence = vec![VcEvidence {
        evidence_type: "ProofOfProcessEvidence".to_string(),
        verifier: ear.ear_verifier_id.build.clone(),
        seal_hash,
    }];

    // Stable, mode-keyed achievement URI; the tier rides along as the level.
    let achievement_id = format!("{ACHIEVEMENT_BASE_URI}/{}", mode.slug());

    let achievement = Achievement {
        id: achievement_id,
        achievement_type: vec!["Achievement".to_string()],
        name: mode.label().to_string(),
        description: mode.description().to_string(),
        criteria: Criteria {
            id: None,
            narrative: criteria_narrative(mode, label, internal_tier.as_deref()),
        },
        achievement_type_value: "Badge".to_string(),
        tag: Some(vec![format!("assurance:{}", label.to_lowercase())]),
    };

    let process_attestation = OpenBadgeProcessAttestation {
        status: appr.ear_status.as_str().to_owned(),
        trust_vector: tv,
        document_ref,
        chain_duration,
        attestation_tier: internal_tier,
        writing_mode: None,
        composition_mode: None,
        forensic_signals: None,
    };

    // The credential id / verify URL uses the canonical PAYLOAD (the 9-symbol
    // Crockford lookup key), not the human display form `WP-XXX-XXX-XXX-C`: the
    // check symbol can be one of `* ~ $ =` which is unsafe in a URL path. The
    // badge text shows the full display form; the portal recomputes both from
    // this payload, keeping the fingerprint bound to a single identity system.
    let payload = badge_fingerprint::payload_from_identifier(author_did);
    let credential_id = format!("{VERIFY_CREDENTIAL_BASE_URL}/{payload}");

    Ok(OpenBadgeCredential {
        context: vec![VC_V2_CONTEXT_URL.to_string(), OB3_CONTEXT_URL.to_string()],
        id: credential_id,
        credential_type: vec![
            "VerifiableCredential".to_string(),
            "OpenBadgeCredential".to_string(),
        ],
        name: credential_name(mode, label),
        issuer: Profile {
            id: vc::issuer_did(),
            profile_type: vec!["Profile".to_string()],
            name: ISSUER_PROFILE_NAME.to_string(),
            url: Some(ISSUER_PROFILE_URL.to_string()),
        },
        valid_from: valid_from.to_rfc3339(),
        valid_until,
        credential_subject: AchievementSubject {
            id: author_did.to_string(),
            subject_type: vec!["AchievementSubject".to_string()],
            achievement,
            process_attestation: Some(process_attestation),
        },
        credential_status: None,
        evidence: Some(evidence),
        proof: None,
    })
}

/// Produce an unsigned Open Badges 3.0 credential with a placeholder Data
/// Integrity proof (empty `proofValue`).
pub fn to_open_badge_credential(
    ear: &EarToken,
    author_did: &str,
    mode: AuthorshipMode,
) -> Result<OpenBadgeCredential> {
    let mut badge = build_open_badge_core(ear, author_did, mode)?;
    badge.proof = Some(VcProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-jcs-2022".to_string(),
        verification_method: format!("{}#key-1", author_did),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: String::new(),
    });
    Ok(badge)
}

/// Produce a signed Open Badges 3.0 credential with an `eddsa-jcs-2022` Data
/// Integrity proof.
///
/// Identical proof construction to the VC profile: the signature is over
/// `SHA-256(proof_options_jcs) || SHA-256(document_jcs)`, and the `proofValue`
/// is multibase base16 (`f` + lowercase hex).
pub fn to_signed_open_badge_credential(
    ear: &EarToken,
    author_did: &str,
    mode: AuthorshipMode,
    signer: &dyn tpm::Provider,
) -> Result<OpenBadgeCredential> {
    let mut badge = build_open_badge_core(ear, author_did, mode)?;

    let proof_options = VcProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-jcs-2022".to_string(),
        verification_method: format!("{}#key-1", author_did),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: String::new(),
    };

    let proof_options_canon = serde_jcs::to_string(&proof_options)
        .map_err(|e| Error::evidence(format!("proof options JCS failed: {e}")))?;
    let proof_options_hash = Sha256::digest(proof_options_canon.as_bytes());

    let doc_canon = serde_jcs::to_string(&badge)
        .map_err(|e| Error::evidence(format!("badge JCS canonicalization failed: {e}")))?;
    let doc_hash = Sha256::digest(doc_canon.as_bytes());

    let mut signing_input = [0u8; 64];
    signing_input[..32].copy_from_slice(&proof_options_hash);
    signing_input[32..].copy_from_slice(&doc_hash);

    let signature = signer
        .sign(&signing_input)
        .map_err(|e| Error::crypto(format!("badge signing failed: {e}")))?;

    let proof_value = format!("f{}", hex::encode(&signature));

    badge.proof = Some(VcProof {
        proof_value,
        ..proof_options
    });

    Ok(badge)
}

/// COSE content type for Open Badges credentials. Reuses the VC+COSE content
/// type per the W3C VC+COSE Recommendation (May 2025); OB 3.0 credentials are
/// W3C Verifiable Credentials and share the same COSE securing mechanism.
const COSE_OB_CONTENT_TYPE: &str = "application/vc+cose";

/// Produce a COSE_Sign1-secured Open Badges 3.0 credential.
pub fn to_cose_secured_open_badge(
    ear: &EarToken,
    author_did: &str,
    mode: AuthorshipMode,
    signer: &dyn tpm::Provider,
) -> Result<Vec<u8>> {
    let badge = build_open_badge_core(ear, author_did, mode)?;

    let badge_json = serde_json::to_value(&badge)
        .map_err(|e| Error::evidence(format!("badge serialization failed: {e}")))?;
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&badge_json, &mut payload_bytes)
        .map_err(|e| Error::crypto(format!("CBOR encode error: {e}")))?;

    let kid = format!("{}#key-1", author_did);
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .content_type(COSE_OB_CONTENT_TYPE.to_string())
        .key_id(kid.into_bytes())
        .build();

    let mut sign_error: Option<Error> = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |sig_data| match signer.sign(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                sign_error = Some(Error::crypto(format!("COSE badge sign error: {e}")));
                Vec::new()
            }
        })
        .build();

    if let Some(e) = sign_error {
        return Err(e);
    }
    if sign1.signature.is_empty() {
        return Err(Error::crypto("COSE badge signing produced empty signature"));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::crypto(format!("COSE encoding error: {e}")))
}

/// Decode (without verifying) a COSE_Sign1-secured Open Badge credential.
pub fn from_cose_secured_open_badge(bytes: &[u8]) -> Result<OpenBadgeCredential> {
    let sign1 = coset::CoseSign1::from_slice(bytes)
        .map_err(|e| Error::crypto(format!("COSE decode error: {e}")))?;
    let payload = sign1
        .payload
        .ok_or_else(|| Error::crypto("missing COSE badge payload"))?;
    let json_value: serde_json::Value = ciborium::from_reader(payload.as_slice())
        .map_err(|e| Error::crypto(format!("CBOR payload decode error: {e}")))?;
    serde_json::from_value(json_value)
        .map_err(|e| Error::evidence(format!("badge deserialization failed: {e}")))
}

/// Decode and verify a COSE_Sign1-secured Open Badge credential.
pub fn verify_cose_secured_open_badge(
    bytes: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<OpenBadgeCredential> {
    use ed25519_dalek::Verifier;

    let sign1 = coset::CoseSign1::from_slice(bytes)
        .map_err(|e| Error::crypto(format!("COSE decode error: {e}")))?;

    let result = sign1.verify_signature(&[], |sig, sig_data| {
        let signature = ed25519_dalek::Signature::from_slice(sig)
            .map_err(|e| Error::crypto(format!("invalid signature: {e}")))?;
        verifying_key
            .verify(sig_data, &signature)
            .map_err(|e| Error::crypto(format!("COSE badge signature invalid: {e}")))
    });
    result.map_err(|e| Error::crypto(format!("COSE badge verification failed: {e}")))?;

    let payload = sign1
        .payload
        .ok_or_else(|| Error::crypto("missing COSE badge payload"))?;
    let json_value: serde_json::Value = ciborium::from_reader(payload.as_slice())
        .map_err(|e| Error::crypto(format!("CBOR payload decode error: {e}")))?;
    serde_json::from_value(json_value)
        .map_err(|e| Error::evidence(format!("badge deserialization failed: {e}")))
}

/// JOSE `typ` header value for an Open Badges 3.0 VC-JWT, per the OB 3.0
/// Implementation Guide (§8.2) JWT Proof Format examples.
const OB_JWT_TYP: &str = "JWT";

/// Registered media type for a JWT-secured Verifiable Credential.
pub const OB_JWT_MEDIA_TYPE: &str = "application/vc+ld+json+jwt";

/// Produce a VC-JWT (JOSE / `EdDSA`) secured Open Badges 3.0 credential.
///
/// This is the securing mechanism 1EdTech's OB 3.0 conformance certifies (the
/// JWT Proof Format), alongside Data Integrity `eddsa-rdfc-2022`. The embedded
/// `eddsa-jcs-2022` proof is NOT part of the 1EdTech-certified set, so this path
/// is what an OB 3.0 verifier / certification harness consumes.
///
/// The compact JWS is `base64url(header).base64url(payload).base64url(sig)`:
/// - Header: `{"alg":"EdDSA","typ":"JWT","kid":"<did>#key-1","jwk":{OKP/Ed25519}}`.
///   The signer's public key is embedded as a JWK so verification is
///   self-contained (mirroring the OB 3.0 impl-guide example).
/// - Payload: the credential object at the top level (VCDM 2.0 style), plus the
///   duplicated registered claims `iss` / `sub` / `jti` / `nbf` / `exp` / `iat`
///   per the OB 3.0 JWT serialization.
/// - Signature: `EdDSA` over the ASCII signing input by the device key.
pub fn to_jwt_secured_open_badge(
    ear: &EarToken,
    author_did: &str,
    mode: AuthorshipMode,
    signer: &dyn tpm::Provider,
) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let badge = build_open_badge_core(ear, author_did, mode)?;

    let pub_key = signer.public_key();
    if pub_key.len() != 32 {
        return Err(Error::crypto(format!(
            "expected 32-byte Ed25519 public key, got {}",
            pub_key.len()
        )));
    }
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(&pub_key),
    });
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": OB_JWT_TYP,
        "kid": format!("{author_did}#key-1"),
        "jwk": jwk,
    });

    // Credential object as the payload, augmented with the registered claims.
    let mut payload = serde_json::to_value(&badge)
        .map_err(|e| Error::evidence(format!("badge serialization failed: {e}")))?;
    let exp = ear
        .iat
        .checked_add(MAX_BADGE_VALIDITY_DAYS * 86_400)
        .ok_or_else(|| Error::evidence("EAR iat + validity overflows i64"))?;
    if let serde_json::Value::Object(map) = &mut payload {
        map.insert("iss".into(), serde_json::json!(badge.issuer.id));
        map.insert("sub".into(), serde_json::json!(badge.credential_subject.id));
        map.insert("jti".into(), serde_json::json!(badge.id));
        map.insert("iat".into(), serde_json::json!(ear.iat));
        map.insert("nbf".into(), serde_json::json!(ear.iat));
        map.insert("exp".into(), serde_json::json!(exp));
    } else {
        return Err(Error::evidence("badge did not serialize to a JSON object"));
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| Error::evidence(format!("JWT header serialization failed: {e}")))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload)
            .map_err(|e| Error::evidence(format!("JWT payload serialization failed: {e}")))?,
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| Error::crypto(format!("JWT signing failed: {e}")))?;
    if signature.len() != 64 {
        return Err(Error::crypto(format!(
            "expected 64-byte Ed25519 signature, got {}",
            signature.len()
        )));
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify a VC-JWT (JOSE / `EdDSA`) secured Open Badge and return the credential.
///
/// Verifies the `EdDSA` signature over the compact JWS with `verifying_key`,
/// then deserializes the payload into an [`OpenBadgeCredential`] (the registered
/// JWT claims are ignored by the credential deserializer).
pub fn verify_jwt_secured_open_badge(
    jwt: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<OpenBadgeCredential> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Verifier;

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::crypto(format!(
            "malformed JWT: expected 3 dot-separated parts, got {}",
            parts.len()
        )));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| Error::crypto(format!("JWT header base64url decode failed: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::crypto(format!("JWT header JSON decode failed: {e}")))?;
    match header.get("alg").and_then(|a| a.as_str()) {
        Some("EdDSA") => {}
        other => {
            return Err(Error::crypto(format!(
                "unsupported JWT alg: {other:?}; only EdDSA is supported"
            )))
        }
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| Error::crypto(format!("JWT signature base64url decode failed: {e}")))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::crypto(format!("invalid JWT signature: {e}")))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| Error::crypto(format!("JWT signature verification failed: {e}")))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| Error::crypto(format!("JWT payload base64url decode failed: {e}")))?;
    serde_json::from_slice(&payload_bytes).map_err(|e| {
        Error::evidence(format!(
            "JWT payload is not a valid OpenBadgeCredential: {e}"
        ))
    })
}

impl OpenBadgeCredential {
    /// Enrich the carried process-attestation claims with forensic signals,
    /// mirroring [`super::vc::VerifiableCredential::enrich_forensic_signals`].
    pub fn enrich_forensic_signals(
        &mut self,
        writing_mode: Option<String>,
        composition_mode: Option<String>,
        signals: Option<VcForensicSignals>,
    ) {
        if let Some(pa) = self.credential_subject.process_attestation.as_mut() {
            pa.writing_mode = writing_mode;
            pa.composition_mode = composition_mode;
            pa.forensic_signals = signals;
        }
    }

    /// Set the Bitstring Status List revocation entry (reused from the VC
    /// profile) so the badge is revocable.
    pub fn set_credential_status(&mut self, status_list_index: u64) {
        self.credential_status = Some(CredentialStatus {
            id: format!(
                "https://api.writersproof.com/v1/credentials/status/default#{}",
                status_list_index
            ),
            status_type: "BitstringStatusListEntry".to_string(),
            status_purpose: "revocation".to_string(),
            status_list_index: status_list_index.to_string(),
            status_list_credential: "https://api.writersproof.com/v1/credentials/status/default"
                .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint;
    use crate::declaration;
    use crate::evidence;
    use crate::tpm::{Provider, SoftwareProvider};
    use crate::trust_policy::profiles::basic;
    use crate::vdf;
    use crate::war::profiles::test_helpers::test_signing_key;
    use crate::war::Block;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_ear() -> (EarToken, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test_doc.txt");
        fs::write(&path, b"Test document for OpenBadge encoding").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();
        let decl = declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            "Test Badge Doc",
            "I wrote this.",
        )
        .sign(&signing_key)
        .expect("sign");

        let packet = evidence::Builder::new("Test Badge Doc", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let policy = basic();
        let block =
            Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
        let ear = block.ear.expect("EAR token");
        (ear, dir)
    }

    #[test]
    fn test_open_badge_conformance_shape() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkBadgeShape";

        let badge =
            to_open_badge_credential(&ear, did, AuthorshipMode::HumanAuthored).expect("badge");

        // @context: VC v2 base + pinned OB 3.0 context.
        assert_eq!(badge.context.len(), 2);
        assert_eq!(badge.context[0], VC_V2_CONTEXT_URL);
        assert_eq!(badge.context[1], OB3_CONTEXT_URL);
        assert_eq!(
            badge.context[1],
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
        );

        // id is the verify-portal URL carrying the canonical payload (the
        // 9-symbol Crockford lookup key), deterministically derived from the DID.
        let expected_payload = badge_fingerprint::payload_from_identifier(did);
        assert_eq!(
            badge.id,
            format!("https://verify.writersproof.com/c/{expected_payload}")
        );
        assert_eq!(expected_payload.len(), 9);

        // type: VerifiableCredential + OpenBadgeCredential.
        assert_eq!(
            badge.credential_type,
            vec![
                "VerifiableCredential".to_string(),
                "OpenBadgeCredential".to_string()
            ]
        );

        // Credential name is "Mode — Tier": mode identity, tier level.
        assert!(badge.name.starts_with("Human-Authored — "));

        // Issuer is a Profile OBJECT, not a bare string.
        assert_eq!(badge.issuer.profile_type, vec!["Profile".to_string()]);
        assert_eq!(badge.issuer.name, "WritersProof");
        assert_eq!(
            badge.issuer.url.as_deref(),
            Some("https://writersproof.com")
        );
        assert!(!badge.issuer.id.is_empty());

        // credentialSubject is an AchievementSubject with an achievement.
        let subject = &badge.credential_subject;
        assert_eq!(subject.subject_type, vec!["AchievementSubject".to_string()]);
        assert_eq!(subject.id, did);

        // Achievement is keyed off the mode (identity), not the tier.
        let ach = &subject.achievement;
        assert_eq!(ach.id, format!("{ACHIEVEMENT_BASE_URI}/human-authored"));
        assert_eq!(ach.achievement_type, vec!["Achievement".to_string()]);
        assert_eq!(ach.name, "Human-Authored");
        assert!(!ach.description.is_empty());
        assert!(!ach.criteria.narrative.is_empty());
        assert_eq!(ach.achievement_type_value, "Badge");
        // Tier rides as the achievement level via a tag.
        let tags = ach.tag.as_ref().expect("assurance tag present");
        assert!(tags.iter().any(|t| t.starts_with("assurance:")));

        // Process attestation must be preserved.
        let pa = subject
            .process_attestation
            .as_ref()
            .expect("process attestation preserved");
        assert!(!pa.status.is_empty());
        assert!(pa.attestation_tier.is_some());

        // Evidence (the .cpop reference) must be present.
        assert!(badge.evidence.is_some());
        assert_eq!(
            badge.evidence.as_ref().unwrap()[0].evidence_type,
            "ProofOfProcessEvidence"
        );

        // validFrom + validUntil present.
        assert!(!badge.valid_from.is_empty());
        assert!(badge.valid_until.is_some());
    }

    #[test]
    fn test_open_badge_field_names_in_json() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkBadgeJson";
        let badge =
            to_open_badge_credential(&ear, did, AuthorshipMode::HumanAuthored).expect("badge");
        let json = serde_json::to_string(&badge).expect("serialize");

        // Exact OB 3.0 JSON-LD field names must be present.
        assert!(json.contains("\"@context\""));
        assert!(json.contains("\"OpenBadgeCredential\""));
        assert!(json.contains("\"AchievementSubject\""));
        assert!(json.contains("\"achievement\""));
        assert!(json.contains("\"achievementType\":\"Badge\""));
        assert!(json.contains("\"criteria\""));
        assert!(json.contains("\"narrative\""));
        assert!(json.contains("\"Profile\""));
        assert!(json.contains("\"validFrom\""));
        assert!(json.contains("purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
    }

    #[test]
    fn test_signed_open_badge_has_proof() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeSigned";

        let badge =
            to_signed_open_badge_credential(&ear, did, AuthorshipMode::HumanAuthored, &provider)
                .expect("signed badge");
        let proof = badge.proof.expect("proof present");
        assert_eq!(proof.proof_type, "DataIntegrityProof");
        assert_eq!(proof.cryptosuite, "eddsa-jcs-2022");
        assert_eq!(proof.verification_method, format!("{}#key-1", did));
        assert_eq!(proof.proof_purpose, "assertionMethod");
        assert!(proof.proof_value.starts_with('f'));
        let hex_part = &proof.proof_value[1..];
        assert!(hex::decode(hex_part).is_ok());
        assert_eq!(hex_part.len(), 128);
    }

    #[test]
    fn test_signed_open_badge_proof_verifies() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeVerify";

        let badge =
            to_signed_open_badge_credential(&ear, did, AuthorshipMode::HumanAuthored, &provider)
                .expect("signed badge");
        let proof = badge.proof.as_ref().expect("proof");

        // Reconstruct the signing input and verify against the provider's key.
        let proof_options = VcProof {
            proof_value: String::new(),
            ..proof.clone()
        };
        let proof_options_canon = serde_jcs::to_string(&proof_options).expect("jcs");
        let mut doc_without_proof = badge.clone();
        doc_without_proof.proof = None;
        let doc_canon = serde_jcs::to_string(&doc_without_proof).expect("jcs");

        let mut signing_input = [0u8; 64];
        signing_input[..32].copy_from_slice(&Sha256::digest(proof_options_canon.as_bytes()));
        signing_input[32..].copy_from_slice(&Sha256::digest(doc_canon.as_bytes()));

        let hex_part = proof.proof_value.strip_prefix('f').expect("multibase f");
        let sig_bytes = hex::decode(hex_part).expect("hex");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("sig");

        use ed25519_dalek::Verifier;
        let pub_bytes = provider.public_key();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into().expect("32-byte key"),
        )
        .expect("verifying key");
        assert!(vk.verify(&signing_input, &signature).is_ok());
    }

    #[test]
    fn test_cose_open_badge_roundtrip() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeCose";

        let cose = to_cose_secured_open_badge(&ear, did, AuthorshipMode::HumanAuthored, &provider)
            .expect("cose");
        assert!(!cose.is_empty());

        let decoded = from_cose_secured_open_badge(&cose).expect("decode");
        assert_eq!(decoded.credential_subject.id, did);
        assert_eq!(
            decoded.credential_type[1],
            "OpenBadgeCredential".to_string()
        );
        // COSE-secured credentials carry the proof in the envelope, not inline.
        assert!(decoded.proof.is_none());
    }

    #[test]
    fn test_jwt_secured_open_badge_structure() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeJwt";

        let jwt = to_jwt_secured_open_badge(&ear, did, AuthorshipMode::HumanAuthored, &provider)
            .expect("jwt");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three parts");

        // Header: EdDSA / JWT / embedded OKP Ed25519 JWK.
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        assert!(header["jwk"]["x"].as_str().is_some());
        assert_eq!(header["kid"], format!("{did}#key-1"));

        // Payload: credential at top level + registered claims.
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["sub"], did);
        assert_eq!(
            payload["jti"],
            format!(
                "{VERIFY_CREDENTIAL_BASE_URL}/{}",
                badge_fingerprint::payload_from_identifier(did)
            )
        );
        assert!(payload["iss"].as_str().is_some());
        assert!(payload["nbf"].as_i64().is_some());
        assert!(payload["exp"].as_i64().unwrap() > payload["nbf"].as_i64().unwrap());
        // The OB 3.0 credential shape is preserved in the payload.
        assert_eq!(payload["type"][1], "OpenBadgeCredential");
    }

    #[test]
    fn test_jwt_secured_open_badge_verifies() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeJwtVerify";

        let jwt =
            to_jwt_secured_open_badge(&ear, did, AuthorshipMode::AiAssistedDisclosed, &provider)
                .expect("jwt");

        let pub_bytes = provider.public_key();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into().expect("32-byte key"),
        )
        .expect("verifying key");

        let badge = verify_jwt_secured_open_badge(&jwt, &vk).expect("verify");
        assert_eq!(badge.credential_subject.id, did);
        assert_eq!(badge.credential_type[1], "OpenBadgeCredential");
        assert_eq!(
            badge.credential_subject.achievement.name,
            "AI-Assisted (Disclosed)"
        );
    }

    #[test]
    fn test_jwt_tampered_payload_fails() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkBadgeJwtTamper";

        let jwt = to_jwt_secured_open_badge(&ear, did, AuthorshipMode::HumanAuthored, &provider)
            .expect("jwt");
        let pub_bytes = provider.public_key();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap())
            .unwrap();

        // Flip the last character of the payload segment.
        let mut parts: Vec<String> = jwt.split('.').map(String::from).collect();
        let p = &mut parts[1];
        let last = p.pop().unwrap();
        p.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = parts.join(".");

        assert!(verify_jwt_secured_open_badge(&tampered, &vk).is_err());
    }

    #[test]
    fn test_credential_status_revocable() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkBadgeStatus";
        let mut badge =
            to_open_badge_credential(&ear, did, AuthorshipMode::HumanAuthored).expect("badge");
        assert!(badge.credential_status.is_none());
        badge.set_credential_status(42);
        let status = badge.credential_status.expect("status set");
        assert_eq!(status.status_type, "BitstringStatusListEntry");
        assert_eq!(status.status_purpose, "revocation");
        assert_eq!(status.status_list_index, "42");
    }

    #[test]
    fn test_infer_authorship_mode_rules() {
        // Disclosure is authoritative and overrides any forensic signal.
        assert_eq!(
            infer_authorship_mode(Some("cognitive"), Some("pure_composition"), true),
            AuthorshipMode::AiAssistedDisclosed
        );
        // Heavy paste / AI-mediated composition (undisclosed) → Human-Revised.
        for cm in ["paste_domesticate", "paste_veneer", "ai_mediated"] {
            assert_eq!(
                infer_authorship_mode(Some("cognitive"), Some(cm), false),
                AuthorshipMode::HumanRevised,
                "composition_mode {cm}"
            );
        }
        // Transcriptive writing without disclosure → Human-Revised.
        assert_eq!(
            infer_authorship_mode(Some("transcriptive"), None, false),
            AuthorshipMode::HumanRevised
        );
        // Original cognitive composition, nothing disclosed → Human-Authored.
        assert_eq!(
            infer_authorship_mode(Some("cognitive"), Some("pure_composition"), false),
            AuthorshipMode::HumanAuthored
        );
        // No signals at all → Human-Authored (default identity).
        assert_eq!(
            infer_authorship_mode(None, None, false),
            AuthorshipMode::HumanAuthored
        );
    }

    #[test]
    fn test_achievement_keyed_off_mode() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkBadgeMode";
        for (mode, slug, label) in [
            (
                AuthorshipMode::HumanAuthored,
                "human-authored",
                "Human-Authored",
            ),
            (
                AuthorshipMode::AiAssistedDisclosed,
                "ai-assisted-disclosed",
                "AI-Assisted (Disclosed)",
            ),
            (
                AuthorshipMode::HumanRevised,
                "human-revised",
                "Human-Revised",
            ),
        ] {
            let badge = to_open_badge_credential(&ear, did, mode).expect("badge");
            let ach = &badge.credential_subject.achievement;
            assert_eq!(ach.id, format!("{ACHIEVEMENT_BASE_URI}/{slug}"));
            assert_eq!(ach.name, label);
            assert!(badge.name.starts_with(&format!("{label} — ")));
        }
    }
}
