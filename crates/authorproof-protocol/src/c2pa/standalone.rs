// SPDX-License-Identifier: Apache-2.0

//! Standalone C2PA manifest builder for signing arbitrary files.
//!
//! Unlike [`C2paManifestBuilder`] which requires a CPoE `EvidencePacket`,
//! this builder creates C2PA manifests for any file with only a document
//! hash and signer identity. Used by the WritersProof file signing feature.

use crate::crypto::EvidenceSigner;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

use super::jumbf::{
    build_assertion_jumbf_cbor, build_assertion_jumbf_json, ciborium_to_vec, encode_jumbf,
};
use super::types::{
    Action, ActionParameters, ActionsAssertion, C2paClaim, C2paManifest, ClaimGeneratorInfo,
    ExclusionRange, HashDataAssertion, HashedUri, MetadataAssertion, SoftwareAgent,
};
use super::{
    ASSERTION_LABEL_ACTIONS, ASSERTION_LABEL_HASH_DATA, ASSERTION_LABEL_METADATA,
    ASSERTION_LABEL_VC_EMBEDDED,
};

/// C2PA 2.4 spec version.
const C2PA_SPEC_VERSION: &str = "2.4.0";

/// Builder for standalone C2PA manifests (no CPoE evidence required).
///
/// Creates a minimal, valid C2PA manifest with `c2pa.hash.data` and
/// `c2pa.actions.v2` assertions, plus optional metadata and embedded VC.
#[derive(Clone)]
pub struct StandaloneManifestBuilder {
    document_hash: [u8; 32],
    document_filename: String,
    format: Option<String>,
    title: Option<String>,
    action: String,
    action_description: Option<String>,
    exclusions: Vec<ExclusionRange>,
    vc_embedded_json: Option<String>,
    cert_der: Option<Vec<u8>>,
}

impl StandaloneManifestBuilder {
    /// Create a new standalone builder.
    ///
    /// `document_hash` is the SHA-256 of the original file bytes.
    /// `document_filename` is the original filename (e.g., "pitchdeck.pdf").
    pub fn new(document_hash: [u8; 32], document_filename: impl Into<String>) -> Self {
        Self {
            document_hash,
            document_filename: document_filename.into(),
            format: None,
            title: None,
            action: "c2pa.created".to_string(),
            action_description: None,
            exclusions: Vec::new(),
            vc_embedded_json: None,
            cert_der: None,
        }
    }

    /// Set the MIME type (dc:format).
    pub fn format(mut self, mime: &str) -> Self {
        self.format = Some(mime.to_string());
        self
    }

    /// Set the document title (dc:title).
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the C2PA action (default: "c2pa.created").
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    /// Set the action description.
    pub fn action_description(mut self, desc: impl Into<String>) -> Self {
        self.action_description = Some(desc.into());
        self
    }

    /// Replace the document hash (for two-pass PDF embedding).
    pub fn document_hash(mut self, hash: [u8; 32]) -> Self {
        self.document_hash = hash;
        self
    }

    /// Set byte-range exclusions for hash-data assertion.
    pub fn exclusions(mut self, exclusions: Vec<ExclusionRange>) -> Self {
        self.exclusions = exclusions;
        self
    }

    /// Embed a signed W3C Verifiable Credential (JSON) in the manifest.
    pub fn vc_embedded(mut self, vc_json: String) -> Self {
        self.vc_embedded_json = Some(vc_json);
        self
    }

    /// Set a DER-encoded X.509 certificate for the x5chain COSE header.
    pub fn cert_der(mut self, der: Vec<u8>) -> Self {
        self.cert_der = Some(der);
        self
    }

    /// Build the JUMBF-encoded manifest.
    pub fn build_jumbf(self, signer: &dyn EvidenceSigner) -> Result<Vec<u8>> {
        let manifest = self.build_manifest(signer)?;
        encode_jumbf(&manifest)
    }

    /// Build the manifest structure.
    pub fn build_manifest(self, signer: &dyn EvidenceSigner) -> Result<C2paManifest> {
        let now = chrono::Utc::now().to_rfc3339();

        // Generate a manifest label from the document hash.
        let manifest_label = format!(
            "urn:writersproof:sign:{}",
            hex::encode(&self.document_hash[..8])
        );

        let actions_assertion = ActionsAssertion {
            actions: vec![Action {
                action: self.action,
                when: Some(now),
                software_agent: Some(SoftwareAgent::Info(ClaimGeneratorInfo {
                    name: "WritersProof".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    spec_version: None,
                })),
                parameters: Some(ActionParameters {
                    description: self.action_description.or_else(|| {
                        Some("Signed with WritersProof content credentials".to_string())
                    }),
                }),
            }],
        };

        let hash_data_assertion = HashDataAssertion {
            name: self.document_filename.clone(),
            hash: self.document_hash.to_vec(),
            algorithm: "sha256".to_string(),
            exclusions: self.exclusions,
            pad: Vec::new(),
        };

        let hash_data_box =
            build_assertion_jumbf_cbor(ASSERTION_LABEL_HASH_DATA, &hash_data_assertion)?;
        let actions_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_ACTIONS, &actions_assertion)?;

        let mut assertion_boxes = Vec::new();
        let mut created_assertions = Vec::new();

        for (box_bytes, label) in [
            (hash_data_box, ASSERTION_LABEL_HASH_DATA),
            (actions_box, ASSERTION_LABEL_ACTIONS),
        ] {
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                box_bytes,
                &manifest_label,
                label,
            );
        }

        // Metadata assertion (title + format).
        if self.title.is_some() || self.format.is_some() {
            let metadata = MetadataAssertion {
                title: self.title,
                format: self.format,
            };
            let meta_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_METADATA, &metadata)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                meta_box,
                &manifest_label,
                ASSERTION_LABEL_METADATA,
            );
        }

        // Embedded Verifiable Credential.
        if let Some(ref vc_json) = self.vc_embedded_json {
            let vc_value: serde_json::Value = serde_json::from_str(vc_json)
                .map_err(|e| Error::Serialization(format!("VC JSON parse: {e}")))?;
            let vc_box = build_assertion_jumbf_json(ASSERTION_LABEL_VC_EMBEDDED, &vc_value)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                vc_box,
                &manifest_label,
                ASSERTION_LABEL_VC_EMBEDDED,
            );
        }

        let sig_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature");

        let claim = C2paClaim {
            claim_generator_info: ClaimGeneratorInfo {
                name: "WritersProof".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                spec_version: Some(C2PA_SPEC_VERSION.to_string()),
            },
            instance_id: format!("xmp:iid:{}", hex::encode(&self.document_hash[..16])),
            signature: sig_url,
            alg: Some("sha256".to_string()),
            created_assertions,
        };

        let cert_der = self.cert_der.as_deref();
        let claim_cbor = ciborium_to_vec(&claim)?;
        let signature = crate::crypto::cose_sign1_c2pa(&claim_cbor, signer, cert_der)?;

        Ok(C2paManifest {
            claim,
            claim_cbor,
            manifest_label,
            assertion_boxes,
            signature,
        })
    }
}

/// Hash an assertion box and push into running lists.
fn push_hashed_assertion(
    assertion_boxes: &mut Vec<Vec<u8>>,
    created_assertions: &mut Vec<HashedUri>,
    box_bytes: Vec<u8>,
    manifest_label: &str,
    label: &str,
) {
    if box_bytes.len() < 8 {
        return;
    }
    let hash = Sha256::digest(&box_bytes[8..]);
    created_assertions.push(HashedUri {
        url: format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}"),
        hash: hash.to_vec(),
        alg: Some("sha256".to_string()),
    });
    assertion_boxes.push(box_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_standalone_builder_minimal() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let doc_hash = sha2::Sha256::digest(b"hello world").into();

        let jumbf = StandaloneManifestBuilder::new(doc_hash, "test.txt")
            .build_jumbf(&key)
            .expect("standalone build should succeed");

        // Should be valid JUMBF starting with a superbox.
        assert!(jumbf.len() > 100);
        assert_eq!(&jumbf[4..8], b"jumb");

        // Decode and verify structure.
        let manifest =
            super::super::jumbf::decode_jumbf(&jumbf).expect("should decode as valid JUMBF");
        assert!(manifest
            .manifest_label
            .starts_with("urn:writersproof:sign:"));
        assert!(!manifest.assertion_boxes.is_empty());
        assert!(!manifest.signature.is_empty());
    }

    #[test]
    fn test_standalone_builder_with_vc() {
        let key = SigningKey::from_bytes(&[43u8; 32]);
        let doc_hash = sha2::Sha256::digest(b"document content").into();

        let vc_json = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DocumentSigningCredential"],
            "issuer": "did:web:api.writersproof.com",
            "credentialSubject": {
                "documentHash": "abc123"
            }
        });

        let jumbf = StandaloneManifestBuilder::new(doc_hash, "report.pdf")
            .format("application/pdf")
            .title("Quarterly Report")
            .vc_embedded(vc_json.to_string())
            .build_jumbf(&key)
            .expect("build with VC should succeed");

        let manifest = super::super::jumbf::decode_jumbf(&jumbf).unwrap();
        // hash.data + actions + metadata + vc = 4 assertion boxes
        assert_eq!(manifest.assertion_boxes.len(), 4);
    }

    #[test]
    fn test_standalone_builder_with_cert() {
        let key = SigningKey::from_bytes(&[44u8; 32]);
        let cert = super::super::cert::generate_self_signed_cert(&key)
            .expect("cert generation should succeed");
        let doc_hash = sha2::Sha256::digest(b"signed doc").into();

        let jumbf = StandaloneManifestBuilder::new(doc_hash, "contract.docx")
            .cert_der(cert)
            .build_jumbf(&key)
            .expect("build with cert should succeed");

        assert!(jumbf.len() > 200);
    }

    #[test]
    fn test_standalone_signature_verifies() {
        let key = SigningKey::from_bytes(&[45u8; 32]);
        let doc_hash = sha2::Sha256::digest(b"verify me").into();

        let jumbf = StandaloneManifestBuilder::new(doc_hash, "test.pdf")
            .build_jumbf(&key)
            .expect("build should succeed");

        let manifest = super::super::jumbf::decode_jumbf(&jumbf).unwrap();
        let result = super::super::validation::verify_manifest_signature(&manifest);
        assert!(result.is_ok(), "signature should verify: {:?}", result);
    }
}
