// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Unified credential package — produces C2PA, W3C VC, CAWG, EU AI Act,
//! JPEG Trust, and standards compliance outputs from a single evidence source.
//!
//! All outputs share the same content hash, signing key, and timestamp,
//! creating cryptographic cross-references between standards.

use authorproof_protocol::crypto::EvidenceSigner;
use sha2::{Digest, Sha256};

use crate::declaration::Declaration;
use crate::error::{Error, Result};
use crate::tpm;
use crate::war::ear::EarToken;

/// Adapter that bridges `&dyn tpm::Provider` to `EvidenceSigner` without
/// requiring an `Arc`. Lifetime-bounded to the provider reference.
struct ProviderSigner<'a>(&'a dyn tpm::Provider);

impl EvidenceSigner for ProviderSigner<'_> {
    fn sign(&self, data: &[u8]) -> authorproof_protocol::error::Result<Vec<u8>> {
        self.0.sign(data).map_err(|e| {
            authorproof_protocol::error::Error::Crypto(format!("sign error: {e}"))
        })
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        self.0.algorithm()
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }
}

use super::cawg::{
    to_cawg_identity_enriched, to_cawg_tdm, CawgIdentityAssertion, CawgTdmAssertion,
};
use super::eu_ai_act::Article50Compliance;
use super::jpeg_trust::{cpop_trust_profile, JpegTrustProfile};
use super::standards::{
    standards_compliance_report, AiDisclosureLevel, StandardsComplianceReport,
};
use super::vc::{
    to_cose_secured_vc, to_signed_verifiable_credential, VerifiableCredential,
};

/// A unified credential package containing all standard outputs from
/// a single CPoE evidence source, cryptographically linked via shared
/// content hash and signing key.
#[derive(Debug)]
pub struct CredentialPackage {
    /// W3C Verifiable Credential 2.0 with JCS-signed Data Integrity proof.
    pub verifiable_credential: VerifiableCredential,
    /// COSE_Sign1-secured VC envelope (binary, for embedding or transport).
    pub vc_cose: Vec<u8>,
    /// SHA-256 hash of the JCS-canonicalized VC (for cross-referencing).
    pub vc_hash: [u8; 32],
    /// CAWG Identity Assertion v1.2 with enriched entropy/forensic claims.
    pub cawg_identity: CawgIdentityAssertion,
    /// CAWG Training and Data Mining Assertion v1.1 (present when declaration provided).
    pub cawg_tdm: Option<CawgTdmAssertion>,
    /// EU AI Act Article 50 compliance metadata (present when declaration provided).
    pub eu_ai_act: Option<Article50Compliance>,
    /// JPEG Trust profile (always present).
    pub jpeg_trust: &'static JpegTrustProfile,
    /// Multi-standard compliance report (NIST, ISO, IPTC, WGA, RATS).
    pub standards_report: StandardsComplianceReport,
    /// C2PA manifest as JUMBF bytes (present when evidence bytes provided).
    pub c2pa_jumbf: Option<Vec<u8>>,
}

/// Builder for constructing a unified credential package.
#[derive(Debug)]
pub struct CredentialPackageBuilder {
    ear: EarToken,
    author_did: String,
    dc_format: String,
    title: Option<String>,
    declaration: Option<Declaration>,
    content_hash: Option<[u8; 32]>,
    evidence_bytes: Option<Vec<u8>>,
    evidence_url: Option<String>,
    forensic_signals: Option<authorproof_protocol::c2pa::ForensicSignalScores>,
    composition_mode: Option<String>,
    writing_mode: Option<String>,
    checkpoints: Vec<crate::evidence::CheckpointProof>,
    max_ingredients: usize,
}

impl CredentialPackageBuilder {
    pub fn new(ear: EarToken, author_did: String, dc_format: String) -> Self {
        Self {
            ear,
            author_did,
            dc_format,
            title: None,
            declaration: None,
            content_hash: None,
            evidence_bytes: None,
            evidence_url: None,
            forensic_signals: None,
            composition_mode: None,
            writing_mode: None,
            checkpoints: Vec::new(),
            max_ingredients: 10,
        }
    }

    pub fn title(mut self, title: String) -> Self {
        self.title = Some(title);
        self
    }

    pub fn declaration(mut self, decl: Declaration) -> Self {
        self.declaration = Some(decl);
        self
    }

    pub fn content_hash(mut self, hash: [u8; 32]) -> Self {
        self.content_hash = Some(hash);
        self
    }

    pub fn evidence_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.evidence_bytes = Some(bytes);
        self
    }

    pub fn evidence_url(mut self, url: String) -> Self {
        self.evidence_url = Some(url);
        self
    }

    pub fn forensic_signals(
        mut self,
        signals: authorproof_protocol::c2pa::ForensicSignalScores,
        composition_mode: Option<String>,
        writing_mode: Option<String>,
    ) -> Self {
        self.forensic_signals = Some(signals);
        self.composition_mode = composition_mode;
        self.writing_mode = writing_mode;
        self
    }

    pub fn checkpoints(mut self, cps: Vec<crate::evidence::CheckpointProof>) -> Self {
        self.checkpoints = cps;
        self
    }

    pub fn max_ingredients(mut self, n: usize) -> Self {
        self.max_ingredients = n;
        self
    }

    /// Build the unified credential package, signing all outputs with the
    /// provided TPM/software provider.
    pub fn build(self, signer: &dyn tpm::Provider) -> Result<CredentialPackage> {
        // 1. W3C Verifiable Credential (JCS-signed Data Integrity proof)
        let vc = to_signed_verifiable_credential(&self.ear, &self.author_did, signer)?;

        // 2. COSE_Sign1-secured VC envelope
        let vc_cose = to_cose_secured_vc(&self.ear, &self.author_did, signer)?;

        // 3. Hash the VC for cross-referencing in C2PA manifest
        let vc_json = serde_jcs::to_string(&vc)
            .map_err(|e| Error::evidence(format!("VC JCS serialization failed: {e}")))?;
        let vc_hash: [u8; 32] = Sha256::digest(vc_json.as_bytes()).into();

        // 4. CAWG Identity Assertion (enriched with entropy/forensic claims)
        let mut cawg_identity = to_cawg_identity_enriched(&self.ear, &self.author_did)?;
        cawg_identity.sign_cose(signer)?;

        // 5. CAWG TDM + EU AI Act (require declaration)
        let cawg_tdm = self.declaration.as_ref().map(to_cawg_tdm);
        let eu_ai_act = self
            .declaration
            .as_ref()
            .map(Article50Compliance::from_declaration);

        // 6. Standards compliance report
        let ai_disclosure = self
            .declaration
            .as_ref()
            .map(|d| AiDisclosureLevel::from_ai_extent(d.max_ai_extent()));
        let standards_report = standards_compliance_report(
            self.declaration.as_ref(),
            Some(&self.ear),
            Some(&self.author_did),
        );

        // 7. C2PA manifest (requires evidence_bytes for the protocol builder)
        let c2pa_jumbf = self.build_c2pa_manifest(
            signer,
            &vc_hash,
            ai_disclosure.as_ref(),
            &cawg_identity,
            cawg_tdm.as_ref(),
        )?;

        Ok(CredentialPackage {
            verifiable_credential: vc,
            vc_cose,
            vc_hash,
            cawg_identity,
            cawg_tdm,
            eu_ai_act,
            jpeg_trust: cpop_trust_profile(),
            standards_report,
            c2pa_jumbf,
        })
    }

    fn build_c2pa_manifest(
        &self,
        signer: &dyn tpm::Provider,
        vc_hash: &[u8; 32],
        ai_disclosure: Option<&AiDisclosureLevel>,
        cawg_identity: &CawgIdentityAssertion,
        cawg_tdm: Option<&CawgTdmAssertion>,
    ) -> Result<Option<Vec<u8>>> {
        let evidence_bytes = match &self.evidence_bytes {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let content_hash = self
            .content_hash
            .ok_or_else(|| Error::evidence("content_hash required for C2PA manifest"))?;

        // Decode evidence packet from CBOR bytes
        let evidence_packet: authorproof_protocol::rfc::EvidencePacket =
            ciborium::from_reader(evidence_bytes.as_slice()).map_err(|e| {
                Error::evidence(format!("evidence packet CBOR decode failed: {e}"))
            })?;

        // Build ingredients from checkpoint history
        let ingredients = self.build_ingredients();

        // Serialize CAWG assertions for embedding
        let cawg_identity_json = serde_json::to_value(cawg_identity)
            .map_err(|e| Error::evidence(format!("CAWG identity serialization failed: {e}")))?;
        let cawg_tdm_json = cawg_tdm
            .map(|tdm| {
                serde_json::to_value(tdm)
                    .map_err(|e| Error::evidence(format!("CAWG TDM serialization failed: {e}")))
            })
            .transpose()?;

        // Build AI disclosure assertion from declaration
        let ai_disclosure_assertion = ai_disclosure.map(|level| {
            let (model_type, oversight) = match level {
                AiDisclosureLevel::None => ("none", "human_validated"),
                AiDisclosureLevel::AiAssisted => ("language_model", "human_validated"),
                AiDisclosureLevel::AiGenerated => ("language_model", "prompt_guided"),
            };
            authorproof_protocol::c2pa::AiDisclosureAssertion {
                model_type: model_type.to_string(),
                model_name: self.declaration.as_ref().and_then(|d| {
                    d.ai_tools.first().map(|t| t.tool.clone())
                }),
                content_profile: Some(authorproof_protocol::c2pa::AiContentProfile {
                    human_oversight_level: oversight.to_string(),
                }),
            }
        });

        let tpm_signer = ProviderSigner(signer);

        let mut builder = authorproof_protocol::c2pa::C2paManifestBuilder::new(
            evidence_packet,
            evidence_bytes.clone(),
            content_hash,
        )
        .format(&self.dc_format)
        .ingredients(ingredients)
        .cawg_identity(cawg_identity_json)
        .vc_reference(*vc_hash, None);

        if let Some(tdm_json) = cawg_tdm_json {
            builder = builder.cawg_tdm(tdm_json);
        }

        if let Some(title) = &self.title {
            builder = builder.title(title.clone());
        }
        if let Some(url) = &self.evidence_url {
            builder = builder.evidence_url(url.clone());
        }
        if let Some(signals) = &self.forensic_signals {
            builder = builder.forensic_signals(
                signals.clone(),
                self.composition_mode.clone(),
                self.writing_mode.clone(),
            );
        }
        if let Some(disclosure) = ai_disclosure_assertion {
            builder = builder.ai_disclosure(disclosure);
        }

        let jumbf = builder
            .build_jumbf(&tpm_signer)
            .map_err(|e| Error::evidence(format!("C2PA manifest build failed: {e}")))?;

        Ok(Some(jumbf))
    }

    fn build_ingredients(&self) -> Vec<authorproof_protocol::c2pa::C2paIngredient> {
        let count = self.checkpoints.len().min(self.max_ingredients);
        let start = self.checkpoints.len().saturating_sub(count);

        self.checkpoints[start..]
            .iter()
            .map(|cp| authorproof_protocol::c2pa::C2paIngredient {
                title: format!("Checkpoint #{}", cp.ordinal),
                relationship: "parentOf".to_string(),
                document_hash: Some(cp.content_hash.clone()),
                instance_id: Some(format!("cpoe:checkpoint:{}", cp.ordinal)),
                format: Some(self.dc_format.clone()),
                informational_uri: None,
                metadata: Some(authorproof_protocol::c2pa::IngredientMetadata {
                    checkpoint_ordinal: cp.ordinal,
                    timestamp: cp.timestamp.to_rfc3339(),
                    vdf_verified: cp.vdf_output.is_some(),
                    content_size: cp.content_size,
                }),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Cross-standard verification
// ---------------------------------------------------------------------------

/// Result of verifying a credential package across all embedded standards.
#[derive(Debug)]
pub struct PackageVerification {
    /// VC Data Integrity proof is valid.
    pub vc_proof_valid: bool,
    /// COSE_Sign1 VC envelope is structurally valid.
    pub vc_cose_valid: bool,
    /// VC hash matches the canonical VC content.
    pub vc_hash_consistent: bool,
    /// CAWG identity COSE_Sign1 signature is valid.
    pub cawg_signature_valid: bool,
    /// C2PA JUMBF structural validation passed (None if no JUMBF present).
    pub c2pa_valid: Option<bool>,
    /// All checks passed.
    pub all_valid: bool,
    /// Non-fatal warnings from validation.
    pub warnings: Vec<String>,
}

/// Verify all credentials in a package against the provided public key.
///
/// Checks the VC Data Integrity proof, COSE_Sign1 envelope, CAWG identity
/// signature, C2PA manifest structure, and cross-standard hash consistency.
pub fn verify_credential_package(
    package: &CredentialPackage,
    public_key: &[u8; 32],
) -> PackageVerification {
    let mut warnings = Vec::new();

    let vk = match ed25519_dalek::VerifyingKey::from_bytes(public_key) {
        Ok(vk) => vk,
        Err(e) => {
            warnings.push(format!("invalid public key: {e}"));
            return PackageVerification {
                vc_proof_valid: false,
                vc_cose_valid: false,
                vc_hash_consistent: false,
                cawg_signature_valid: false,
                c2pa_valid: None,
                all_valid: false,
                warnings,
            };
        }
    };

    // 1. Verify VC Data Integrity proof
    let vc_proof_valid = verify_vc_proof(&package.verifiable_credential, &vk);

    // 2. Verify COSE_Sign1 VC envelope is parseable
    let vc_cose_valid = {
        use coset::CborSerializable;
        coset::CoseSign1::from_slice(&package.vc_cose).is_ok()
    };

    // 3. Verify VC hash consistency
    let vc_hash_consistent = match serde_jcs::to_string(&package.verifiable_credential) {
        Ok(json) => {
            let computed: [u8; 32] = Sha256::digest(json.as_bytes()).into();
            computed == package.vc_hash
        }
        Err(_) => false,
    };

    // 4. Verify CAWG COSE_Sign1 signature
    let cawg_signature_valid = package.cawg_identity.verify_cose(&vk).is_ok();

    // 5. Verify C2PA manifest (if present)
    let c2pa_valid = if let Some(ref jumbf) = package.c2pa_jumbf {
        let structure_ok =
            authorproof_protocol::c2pa::verify_jumbf_structure(jumbf).is_ok();
        if !structure_ok {
            warnings.push("C2PA JUMBF structure validation failed".to_string());
        }
        Some(structure_ok)
    } else {
        None
    };

    let all_valid = vc_proof_valid
        && vc_cose_valid
        && vc_hash_consistent
        && cawg_signature_valid
        && c2pa_valid.unwrap_or(true);

    PackageVerification {
        vc_proof_valid,
        vc_cose_valid,
        vc_hash_consistent,
        cawg_signature_valid,
        c2pa_valid,
        all_valid,
        warnings,
    }
}

/// Verify the Data Integrity proof on a W3C VC.
fn verify_vc_proof(
    vc: &super::vc::VerifiableCredential,
    vk: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier;

    let proof = match &vc.proof {
        Some(p) if !p.proof_value.is_empty() => p,
        _ => return false,
    };

    // eddsa-jcs-2022: verify SHA-256(proof_options) || SHA-256(document)
    let mut vc_no_proof = vc.clone();
    vc_no_proof.proof = None;

    // Hash the proof options (with empty proofValue)
    let proof_options = super::vc::VcProof {
        proof_value: String::new(),
        ..proof.clone()
    };
    let proof_options_canon = match serde_jcs::to_string(&proof_options) {
        Ok(j) => j,
        Err(_) => return false,
    };
    let proof_options_hash = Sha256::digest(proof_options_canon.as_bytes());

    // Hash the document (without proof)
    let doc_canon = match serde_jcs::to_string(&vc_no_proof) {
        Ok(j) => j,
        Err(_) => return false,
    };
    let doc_hash = Sha256::digest(doc_canon.as_bytes());

    // Concatenate hashes as signing input
    let mut signing_input = [0u8; 64];
    signing_input[..32].copy_from_slice(&proof_options_hash);
    signing_input[32..].copy_from_slice(&doc_hash);

    // proofValue is multibase base16: 'f' prefix + hex
    let hex_part = match proof.proof_value.strip_prefix('f') {
        Some(h) => h,
        None => return false,
    };

    let sig_bytes = match hex::decode(hex_part) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    vk.verify(&signing_input, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::SoftwareProvider;
    use crate::war::ear::{Ar4siStatus, EarAppraisal, VerifierId};
    use std::collections::BTreeMap;

    fn make_ear() -> EarToken {
        let mut submods = BTreeMap::new();
        submods.insert(
            "pop".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Affirming,
                ear_trustworthiness_vector: None,
                ear_appraisal_policy_id: None,
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: Some(5),
                pop_chain_duration: Some(3600),
                pop_absence_claims: None,
                pop_warnings: None,
                pop_process_start: None,
                pop_process_end: None,
            },
        );
        EarToken {
            eat_profile: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
            iat: chrono::Utc::now().timestamp(),
            ear_verifier_id: VerifierId::default(),
            submods,
        }
    }

    #[test]
    fn test_package_produces_all_outputs() {
        let ear = make_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkPackageTest";

        let pkg = CredentialPackageBuilder::new(
            ear,
            did.to_string(),
            "application/pdf".to_string(),
        )
        .build(&provider)
        .expect("build package");

        // VC is present and signed
        let proof = pkg.verifiable_credential.proof.as_ref().expect("proof");
        assert_eq!(proof.cryptosuite, "eddsa-jcs-2022");
        assert!(!proof.proof_value.is_empty());

        // COSE VC envelope is non-empty
        assert!(!pkg.vc_cose.is_empty());

        // VC hash is non-zero
        assert_ne!(pkg.vc_hash, [0u8; 32]);

        // CAWG identity is signed (COSE_Sign1)
        assert!(!pkg.cawg_identity.signature.is_empty());

        // No declaration → no TDM, no EU AI Act
        assert!(pkg.cawg_tdm.is_none());
        assert!(pkg.eu_ai_act.is_none());

        // JPEG Trust profile always present
        assert_eq!(pkg.jpeg_trust.trust_indicators.len(), 3);

        // Standards report always present
        assert!(!pkg.standards_report.rats.eat_profile.is_empty());

        // No evidence bytes → no C2PA JUMBF
        assert!(pkg.c2pa_jumbf.is_none());
    }

    #[test]
    fn test_package_with_declaration() {
        use crate::declaration::{Declaration, InputModality, ModalityType};

        let ear = make_ear();
        let provider = SoftwareProvider::new();
        let decl = Declaration {
            document_hash: [1u8; 32],
            chain_hash: [2u8; 32],
            title: "Test Doc".to_string(),
            input_modalities: vec![InputModality {
                modality_type: ModalityType::Keyboard,
                percentage: 100.0,
                note: None,
            }],
            ai_tools: Vec::new(),
            collaborators: Vec::new(),
            statement: "I wrote this.".to_string(),
            created_at: chrono::Utc::now(),
            version: 1,
            author_public_key: Vec::new(),
            signature: Vec::new(),
            jitter_sealed: None,
        };

        let pkg = CredentialPackageBuilder::new(
            ear,
            "did:key:z6MkDeclTest".to_string(),
            "text/plain".to_string(),
        )
        .declaration(decl)
        .build(&provider)
        .expect("build package");

        // With declaration: TDM and EU AI Act present
        assert!(pkg.cawg_tdm.is_some());
        assert!(pkg.eu_ai_act.is_some());

        let eu = pkg.eu_ai_act.unwrap();
        assert!(!eu.ai_generated);
        assert_eq!(eu.machine_readable_label, "human-authored");
    }

    #[test]
    fn test_package_cross_standard_vc_hash() {
        let ear = make_ear();
        let provider = SoftwareProvider::new();

        let pkg = CredentialPackageBuilder::new(
            ear,
            "did:key:z6MkHashTest".to_string(),
            "application/pdf".to_string(),
        )
        .build(&provider)
        .expect("build package");

        // Verify the VC hash matches re-hashing the VC
        let vc_json = serde_jcs::to_string(&pkg.verifiable_credential).expect("serialize");
        let expected_hash: [u8; 32] = Sha256::digest(vc_json.as_bytes()).into();
        assert_eq!(pkg.vc_hash, expected_hash);
    }

    #[test]
    fn test_verify_credential_package_roundtrip() {
        use crate::tpm::Provider;

        let ear = make_ear();
        let provider = SoftwareProvider::new();
        let pk_bytes: [u8; 32] = provider.public_key().try_into().expect("32-byte pk");

        let pkg = CredentialPackageBuilder::new(
            ear,
            "did:key:z6MkVerifyTest".to_string(),
            "application/pdf".to_string(),
        )
        .build(&provider)
        .expect("build package");

        let result = verify_credential_package(&pkg, &pk_bytes);

        assert!(result.vc_proof_valid, "VC proof should be valid");
        assert!(result.vc_cose_valid, "VC COSE should be valid");
        assert!(result.vc_hash_consistent, "VC hash should be consistent");
        assert!(
            result.cawg_signature_valid,
            "CAWG signature should be valid"
        );
        assert!(result.all_valid, "all checks should pass");
        assert!(result.warnings.is_empty(), "no warnings: {:?}", result.warnings);
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        use crate::tpm::Provider;

        let ear = make_ear();
        let provider = SoftwareProvider::new();

        let pkg = CredentialPackageBuilder::new(
            ear,
            "did:key:z6MkWrongKey".to_string(),
            "text/plain".to_string(),
        )
        .build(&provider)
        .expect("build package");

        // Use a different key for verification
        let wrong_provider = SoftwareProvider::new();
        let wrong_pk: [u8; 32] = wrong_provider.public_key().try_into().expect("32-byte pk");

        // Extremely unlikely the two random keys are the same
        let our_pk: [u8; 32] = provider.public_key().try_into().expect("32-byte pk");
        assert_ne!(our_pk, wrong_pk);

        let result = verify_credential_package(&pkg, &wrong_pk);
        assert!(!result.all_valid, "should fail with wrong key");
        assert!(!result.vc_proof_valid);
        assert!(!result.cawg_signature_valid);
    }
}
