// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CAWG (Creator Assertions Working Group) profile projections.
//!
//! Maps CPoE evidence and declarations onto CAWG assertion structures:
//!
//! - **Identity Assertion v1.2**: projects an EAR token and author DID into
//!   a `cawg.identity` assertion with WritersProof as an Identity Claims
//!   Aggregator (ICA).
//!
//! - **Training and Data Mining Assertion v1.1**: projects a CPoE declaration
//!   into a `cawg.training-mining` assertion with per-use-type permissions.

use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};

use crate::declaration::{AiExtent, Declaration};
use crate::error::{Error, Result};
use crate::tpm;
use crate::war::ear::EarToken;
use ed25519_dalek::Signer as _;

/// CAWG assertion label for identity assertions.
pub const IDENTITY_LABEL: &str = "cawg.identity";

/// CAWG assertion label for training and data mining assertions.
pub const TDM_LABEL: &str = "cawg.training-mining";

/// WritersProof ICA provider URI.
pub const WRITERSPROOF_ICA_PROVIDER: &str = "https://writersproof.com";

// ---------------------------------------------------------------------------
// Identity Assertion v1.2
// ---------------------------------------------------------------------------

/// CAWG Identity Assertion v1.2 projection.
///
/// Follows the CAWG identity assertion specification with WritersProof
/// acting as an Identity Claims Aggregator (ICA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgIdentityAssertion {
    /// The signer payload containing credential and assertion type.
    pub signer_payload: CawgSignerPayload,
    /// Padding for JUMBF alignment (typically empty).
    #[serde(with = "serde_bytes", default)]
    pub pad1: Vec<u8>,
    /// COSE signature over the signer payload.
    #[serde(with = "serde_bytes", default)]
    pub signature: Vec<u8>,
    /// Padding for JUMBF alignment (typically empty).
    #[serde(with = "serde_bytes", default)]
    pub pad2: Vec<u8>,
}

/// Signer payload within a CAWG identity assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgSignerPayload {
    /// Assertion type: "cawg.identity".
    pub sig_type: String,
    /// The author's identity credential.
    pub credential: CawgCredential,
}

/// Identity credential type within a CAWG identity assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CawgCredential {
    /// WritersProof as Identity Claims Aggregator (ICA).
    /// This is the default for CAWG v1.2 which does not yet support W3C VCs directly.
    #[serde(rename = "ica")]
    Ica {
        /// ICA provider URI.
        provider: String,
        /// Identity claims aggregated by the provider.
        claims: Vec<CawgIdentityClaim>,
    },
    /// W3C Verifiable Credential (future, when CAWG ratifies VC support).
    #[serde(rename = "verifiable_credential")]
    VerifiableCredential {
        /// The VC as a JSON value.
        vc: serde_json::Value,
    },
}

/// A single identity claim within an ICA credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgIdentityClaim {
    /// Claim type (e.g., "did", "attestation_status", "evidence_tier").
    pub claim_type: String,
    /// Claim value.
    pub value: String,
}

/// Build a CAWG identity assertion from an EAR token and author DID.
///
/// The credential type defaults to ICA with WritersProof as the provider,
/// since CAWG v1.2 does not yet support W3C VCs directly.
pub fn to_cawg_identity(ear: &EarToken, author_did: &str) -> Result<CawgIdentityAssertion> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let mut claims = vec![
        CawgIdentityClaim {
            claim_type: "did".to_string(),
            value: author_did.to_string(),
        },
        CawgIdentityClaim {
            claim_type: "attestation_status".to_string(),
            value: appr.ear_status.as_str().to_owned(),
        },
    ];

    if let Some(chain_len) = appr.pop_chain_length {
        claims.push(CawgIdentityClaim {
            claim_type: "chain_length".to_string(),
            value: chain_len.to_string(),
        });
    }

    if let Some(chain_dur) = appr.pop_chain_duration {
        claims.push(CawgIdentityClaim {
            claim_type: "chain_duration_secs".to_string(),
            value: chain_dur.to_string(),
        });
    }

    Ok(CawgIdentityAssertion {
        signer_payload: CawgSignerPayload {
            sig_type: IDENTITY_LABEL.to_string(),
            credential: CawgCredential::Ica {
                provider: WRITERSPROOF_ICA_PROVIDER.to_string(),
                claims,
            },
        },
        pad1: Vec::new(),
        signature: Vec::new(),
        pad2: Vec::new(),
    })
}


/// Build a CAWG identity assertion enriched with entropy and forensic claims.
pub fn to_cawg_identity_enriched(
    ear: &EarToken,
    author_did: &str,
) -> Result<CawgIdentityAssertion> {
    let mut assertion = to_cawg_identity(ear, author_did)?;
    if let CawgCredential::Ica { ref mut claims, .. } = assertion.signer_payload.credential {
        if let Some(appr) = ear.pop_appraisal() {
            if let Some(entropy) = &appr.pop_entropy_report {
                claims.push(CawgIdentityClaim {
                    claim_type: "entropy_timing_bits".to_string(),
                    value: format!("{:.2}", entropy.timing_entropy),
                });
                claims.push(CawgIdentityClaim {
                    claim_type: "entropy_revision_bits".to_string(),
                    value: format!("{:.2}", entropy.revision_entropy),
                });
            }
            if let Some(forensic) = &appr.pop_forensic_summary {
                claims.push(CawgIdentityClaim {
                    claim_type: "forensic_flags_ratio".to_string(),
                    value: format!("{}/{}", forensic.flags_triggered, forensic.flags_evaluated),
                });
            }
            if let Some(forgery) = &appr.pop_forgery_cost {
                claims.push(CawgIdentityClaim {
                    claim_type: "forgery_cost_total".to_string(),
                    value: format!("{:.2}", forgery.c_total),
                });
            }
        }
    }
    Ok(assertion)
}

const COSE_CAWG_IDENTITY_CONTENT_TYPE: &str = "application/cawg.identity";

impl CawgIdentityAssertion {
    /// Sign the signer payload with the given Ed25519 key, populating `self.signature`.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        let payload_bytes = serde_json::to_vec(&self.signer_payload)
            .map_err(|e| Error::evidence(format!("CAWG payload serialization failed: {e}")))?;
        let sig = signing_key.sign(&payload_bytes);
        self.signature = sig.to_bytes().to_vec();
        Ok(())
    }

    /// Verify the signature against the provided public key.
    pub fn verify(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> Result<()> {
        if self.signature.is_empty() {
            return Err(Error::evidence("CAWG identity assertion is unsigned"));
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::evidence("CAWG signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let payload_bytes = serde_json::to_vec(&self.signer_payload)
            .map_err(|e| Error::evidence(format!("CAWG payload serialization failed: {e}")))?;
        verifying_key
            .verify_strict(&payload_bytes, &sig)
            .map_err(|e| Error::evidence(format!("CAWG signature verification failed: {e}")))
    }

    /// Sign the signer payload with COSE_Sign1.
    pub fn sign_cose(&mut self, signer: &dyn tpm::Provider) -> Result<()> {
        let mut payload_cbor = Vec::new();
        ciborium::into_writer(&self.signer_payload, &mut payload_cbor)
            .map_err(|e| Error::crypto(format!("CAWG CBOR encode error: {e}")))?;
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .content_type(COSE_CAWG_IDENTITY_CONTENT_TYPE.to_string())
            .build();
        let mut sign_error: Option<Error> = None;
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload_cbor)
            .create_signature(&[], |sig_data| match signer.sign(sig_data) {
                Ok(sig) => sig,
                Err(e) => {
                    sign_error = Some(Error::crypto(format!("CAWG COSE sign error: {e}")));
                    Vec::new()
                }
            })
            .build();
        if let Some(e) = sign_error {
            return Err(e);
        }
        if sign1.signature.is_empty() {
            return Err(Error::crypto("CAWG COSE signing produced empty signature"));
        }
        self.signature = sign1
            .to_vec()
            .map_err(|e| Error::crypto(format!("CAWG COSE encoding error: {e}")))?;
        Ok(())
    }

    /// Verify the COSE_Sign1 signature against the provided public key.
    pub fn verify_cose(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> Result<()> {
        if self.signature.is_empty() {
            return Err(Error::evidence("CAWG identity assertion is unsigned"));
        }
        let sign1 = coset::CoseSign1::from_slice(&self.signature)
            .map_err(|e| Error::crypto(format!("CAWG COSE decode error: {e}")))?;
        let mut expected_cbor = Vec::new();
        ciborium::into_writer(&self.signer_payload, &mut expected_cbor)
            .map_err(|e| Error::crypto(format!("CAWG CBOR encode error: {e}")))?;
        let actual_payload = sign1.payload.as_ref()
            .ok_or_else(|| Error::crypto("CAWG COSE missing payload"))?;
        if actual_payload != &expected_cbor {
            return Err(Error::evidence("CAWG COSE payload mismatch"));
        }
        let sig_data = sign1.tbs_data(&[]);
        let sig_bytes: [u8; 64] = sign1.signature.as_slice().try_into()
            .map_err(|_| Error::evidence("CAWG COSE signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify_strict(&sig_data, &sig)
            .map_err(|e| Error::evidence(format!("CAWG COSE signature verification failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Training and Data Mining Assertion v1.1
// ---------------------------------------------------------------------------

/// CAWG Training and Data Mining (TDM) Assertion v1.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgTdmAssertion {
    /// Assertion label: "cawg.training-mining".
    pub label: String,
    /// Per-use-type permission entries.
    pub entries: Vec<CawgTdmEntry>,
}

/// A single TDM permission entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgTdmEntry {
    /// Use type (e.g., "cawg.data_mining", "cawg.ai_inference",
    /// "cawg.ai_generative_training", "cawg.ai_training").
    pub use_type: String,
    /// Permission: "allowed", "notAllowed", or "constrained".
    pub permission: String,
    /// Optional constraint information when permission is "constrained".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_info: Option<String>,
    /// URI to the constraint policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_uri: Option<String>,
}

/// Build a CAWG TDM assertion from a CPoE declaration.
///
/// Mapping logic:
/// - `AiExtent::None` or `Minimal`: author owns the work fully; default to
///   "notAllowed" for generative training (protective stance), "allowed" for
///   inference and data mining.
/// - `AiExtent::Moderate` or `Substantial`: AI-generated content cannot
///   restrict training of the models that produced it; default to "allowed"
///   for all use types.
pub fn to_cawg_tdm(decl: &Declaration) -> CawgTdmAssertion {
    let max_extent = decl.max_ai_extent();
    let is_primarily_human = matches!(max_extent, AiExtent::None | AiExtent::Minimal);

    let entries = if is_primarily_human {
        vec![
            CawgTdmEntry {
                use_type: "cawg.data_mining".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_inference".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_generative_training".to_string(),
                permission: "notAllowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_training".to_string(),
                permission: "constrained".to_string(),
                constraint_info: Some(
                    "Human-authored content; generative training requires explicit license."
                        .to_string(),
                ),
                constraint_uri: None,
            },
        ]
    } else {
        vec![
            CawgTdmEntry {
                use_type: "cawg.data_mining".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_inference".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_generative_training".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_training".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
                constraint_uri: None,
            },
        ]
    };

    CawgTdmAssertion {
        label: TDM_LABEL.to_string(),
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::AiExtent;
    use crate::war::ear::{EarToken, VerifierId};
    use crate::war::profiles::test_helpers::{make_ai_tool, make_decl, make_ear};
    use chrono::Utc;
    use std::collections::BTreeMap;

    // -- Identity assertion tests --

    #[test]
    fn test_cawg_identity_has_did_claim() {
        let ear = make_ear(5, 3600);
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");
        assert_eq!(assertion.signer_payload.sig_type, IDENTITY_LABEL);

        if let CawgCredential::Ica { provider, claims } = &assertion.signer_payload.credential {
            assert_eq!(provider, WRITERSPROOF_ICA_PROVIDER);
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "did" && c.value == "did:key:z6MkTest"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_has_attestation_status() {
        let ear = make_ear(5, 3600);
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");

        if let CawgCredential::Ica { claims, .. } = &assertion.signer_payload.credential {
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "attestation_status" && c.value == "affirming"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_includes_chain_metadata() {
        let ear = make_ear(5, 3600);
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");

        if let CawgCredential::Ica { claims, .. } = &assertion.signer_payload.credential {
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "chain_length" && c.value == "5"));
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "chain_duration_secs" && c.value == "3600"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_missing_pop_submod() {
        let ear = EarToken {
            eat_profile: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
            iat: Utc::now().timestamp(),
            ear_verifier_id: VerifierId::default(),
            submods: BTreeMap::new(),
        };
        let result = to_cawg_identity(&ear, "did:key:z6MkTest");
        assert!(result.is_err());
    }

    #[test]
    fn test_cawg_identity_assertion_structure() {
        let ear = make_ear(5, 3600);
        let assertion =
            to_cawg_identity(&ear, "did:key:z6MkStructure").expect("identity assertion");
        // Label must be "cawg.identity".
        assert_eq!(assertion.signer_payload.sig_type, "cawg.identity");
        // Credential must be ICA type with WritersProof provider.
        match &assertion.signer_payload.credential {
            CawgCredential::Ica { provider, claims } => {
                assert_eq!(provider, "https://writersproof.com");
                // Must contain at least did and attestation_status claims.
                let claim_types: Vec<&str> = claims.iter().map(|c| c.claim_type.as_str()).collect();
                assert!(claim_types.contains(&"did"));
                assert!(claim_types.contains(&"attestation_status"));
            }
            _ => panic!("expected ICA credential type"),
        }
        // Padding should be empty by default.
        assert!(assertion.pad1.is_empty());
        assert!(assertion.pad2.is_empty());
    }

    #[test]
    fn test_cawg_tdm_human_authored_notallowed() {
        let decl = make_decl(Vec::new());
        let tdm = to_cawg_tdm(&decl);
        // Human-authored content: generative training is "notAllowed".
        let gen = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("missing generative training entry");
        assert_eq!(gen.permission, "notAllowed");
    }

    #[test]
    fn test_cawg_tdm_ai_generated_allowed() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let tdm = to_cawg_tdm(&decl);
        // AI-generated: all entries should be "allowed".
        for entry in &tdm.entries {
            assert_eq!(
                entry.permission, "allowed",
                "{} should be allowed for AI content",
                entry.use_type
            );
        }
    }

    // -- TDM assertion tests --

    #[test]
    fn test_cawg_tdm_human_authored() {
        let decl = make_decl(Vec::new());
        let tdm = to_cawg_tdm(&decl);
        assert_eq!(tdm.label, TDM_LABEL);
        assert_eq!(tdm.entries.len(), 4);

        // Human-authored: generative training is not allowed.
        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(gen_training.permission, "notAllowed");

        // General AI training is constrained.
        let training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_training")
            .expect("training entry");
        assert_eq!(training.permission, "constrained");
        assert!(training.constraint_info.is_some());
    }

    #[test]
    fn test_cawg_tdm_ai_generated() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let tdm = to_cawg_tdm(&decl);

        // AI-generated: all use types allowed.
        for entry in &tdm.entries {
            assert_eq!(
                entry.permission, "allowed",
                "AI-generated content should allow all TDM use types, but {} was {}",
                entry.use_type, entry.permission
            );
        }
    }

    #[test]
    fn test_cawg_tdm_minimal_ai_is_protective() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Minimal)]);
        let tdm = to_cawg_tdm(&decl);

        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(
            gen_training.permission, "notAllowed",
            "minimal AI assistance should still protect against generative training"
        );
    }

    #[test]
    fn test_cawg_tdm_moderate_ai_allows_training() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Moderate)]);
        let tdm = to_cawg_tdm(&decl);

        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(
            gen_training.permission, "allowed",
            "moderate AI content should allow generative training"
        );
    }

    #[test]
    fn test_cawg_identity_sign_verify_roundtrip() {
        let ear = make_ear(5, 3600);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();

        let mut assertion =
            to_cawg_identity(&ear, "did:key:z6MkSignTest").expect("identity assertion");
        assert!(assertion.signature.is_empty());

        assertion.sign(&sk).expect("sign");
        assert!(!assertion.signature.is_empty());
        assertion.verify(&vk).expect("verify");
    }

    #[test]
    fn test_cawg_identity_verify_rejects_unsigned() {
        let ear = make_ear(5, 3600);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let assertion = to_cawg_identity(&ear, "did:key:z6MkNoSig").expect("identity assertion");
        assert!(assertion.verify(&sk.verifying_key()).is_err());
    }
}
