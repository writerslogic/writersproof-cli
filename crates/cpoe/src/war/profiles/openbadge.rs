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

/// Stable base URI for the achievement definition. The achievement id is this
/// base plus the attestation tier so each tier is a distinct, dereferenceable
/// achievement.
const ACHIEVEMENT_BASE_URI: &str =
    "https://writersproof.com/achievements/verified-human-authorship";

/// Open Badges 3.0 `OpenBadgeCredential` (alias of `AchievementCredential`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
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

/// Compose the human-readable credential and achievement name from the tier.
fn achievement_name(tier_label: &str) -> String {
    format!("Verified Human Authorship ({tier_label})")
}

/// Compose the criteria narrative describing how the badge was earned.
fn criteria_narrative(tier_label: &str, internal_tier: Option<&str>) -> String {
    let basis = match internal_tier {
        Some("hardware_bound") => {
            "Behavioral authorship evidence (keystroke timing, revision cadence, \
             and process checkpoints) was captured during document creation and \
             bound to a hardware-backed key (TPM / Secure Enclave)."
        }
        Some("attested_software") => {
            "Behavioral authorship evidence (keystroke timing, revision cadence, \
             and process checkpoints) was captured during document creation and \
             signed by an attested software key."
        }
        _ => {
            "Authorship was declared by the author and accompanied by a \
             cryptographically signed proof-of-process evidence chain."
        }
    };
    format!(
        "Awarded at the \"{tier_label}\" attestation tier. {basis} The evidence \
         is packaged as a signed CPoE (Cryptographic Proof of Effort) packet and \
         is independently verifiable."
    )
}

/// Build the core OB 3.0 credential fields from an EAR token (shared by all
/// encoding paths). Mirrors the VC profile's `build_vc_core`.
fn build_open_badge_core(ear: &EarToken, author_did: &str) -> Result<OpenBadgeCredential> {
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

    // Stable, tier-specific achievement URI.
    let internal_tier_slug = internal_tier.as_deref().unwrap_or("software_only");
    let achievement_id = format!("{ACHIEVEMENT_BASE_URI}#{internal_tier_slug}");

    let achievement = Achievement {
        id: achievement_id,
        achievement_type: vec!["Achievement".to_string()],
        name: achievement_name(label),
        description: "Cryptographically witnessed evidence that this content was authored \
             by a human through an observed writing process."
            .to_string(),
        criteria: Criteria {
            id: None,
            narrative: criteria_narrative(label, internal_tier.as_deref()),
        },
        achievement_type_value: "Badge".to_string(),
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

    Ok(OpenBadgeCredential {
        context: vec![VC_V2_CONTEXT_URL.to_string(), OB3_CONTEXT_URL.to_string()],
        credential_type: vec![
            "VerifiableCredential".to_string(),
            "OpenBadgeCredential".to_string(),
        ],
        name: achievement_name(label),
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
pub fn to_open_badge_credential(ear: &EarToken, author_did: &str) -> Result<OpenBadgeCredential> {
    let mut badge = build_open_badge_core(ear, author_did)?;
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
    signer: &dyn tpm::Provider,
) -> Result<OpenBadgeCredential> {
    let mut badge = build_open_badge_core(ear, author_did)?;

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
    signer: &dyn tpm::Provider,
) -> Result<Vec<u8>> {
    let badge = build_open_badge_core(ear, author_did)?;

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

        let badge = to_open_badge_credential(&ear, did).expect("badge");

        // @context: VC v2 base + pinned OB 3.0 context.
        assert_eq!(badge.context.len(), 2);
        assert_eq!(badge.context[0], VC_V2_CONTEXT_URL);
        assert_eq!(badge.context[1], OB3_CONTEXT_URL);
        assert_eq!(
            badge.context[1],
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
        );

        // type: VerifiableCredential + OpenBadgeCredential.
        assert_eq!(
            badge.credential_type,
            vec![
                "VerifiableCredential".to_string(),
                "OpenBadgeCredential".to_string()
            ]
        );

        // Credential has a human-readable name.
        assert!(badge.name.starts_with("Verified Human Authorship"));

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

        // Achievement fields.
        let ach = &subject.achievement;
        assert!(ach.id.starts_with(ACHIEVEMENT_BASE_URI));
        assert_eq!(ach.achievement_type, vec!["Achievement".to_string()]);
        assert!(ach.name.starts_with("Verified Human Authorship"));
        assert!(!ach.description.is_empty());
        assert!(!ach.criteria.narrative.is_empty());
        assert_eq!(ach.achievement_type_value, "Badge");

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
        let badge = to_open_badge_credential(&ear, did).expect("badge");
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

        let badge = to_signed_open_badge_credential(&ear, did, &provider).expect("signed badge");
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

        let badge = to_signed_open_badge_credential(&ear, did, &provider).expect("signed badge");
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

        let cose = to_cose_secured_open_badge(&ear, did, &provider).expect("cose");
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
    fn test_credential_status_revocable() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkBadgeStatus";
        let mut badge = to_open_badge_credential(&ear, did).expect("badge");
        assert!(badge.credential_status.is_none());
        badge.set_credential_status(42);
        let status = badge.credential_status.expect("status set");
        assert_eq!(status.status_type, "BitstringStatusListEntry");
        assert_eq!(status.status_purpose, "revocation");
        assert_eq!(status.status_list_index, "42");
    }
}
