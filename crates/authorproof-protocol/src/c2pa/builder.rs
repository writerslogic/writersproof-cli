// SPDX-License-Identifier: Apache-2.0

use crate::crypto::EvidenceSigner;
use crate::error::{Error, Result};
use crate::rfc::EvidencePacket;
use sha2::{Digest, Sha256};

use super::jumbf::{
    build_assertion_jumbf_cbor, build_assertion_jumbf_json, ciborium_to_vec, encode_jumbf,
};
use super::types::{
    Action, ActionParameters, ActionsAssertion, AssertionMetadata, AssetType, C2paClaim,
    C2paManifest, ClaimGeneratorInfo, DataSource, ExternalReferenceAssertion, HashDataAssertion,
    HashedExtUri, HashedUri, MetadataAssertion, ProcessAssertion, SoftwareAgent,
};
use super::{
    ASSERTION_LABEL_ACTIONS, ASSERTION_LABEL_CPOE, ASSERTION_LABEL_EXTERNAL_REF,
    ASSERTION_LABEL_HASH_DATA, ASSERTION_LABEL_METADATA,
};

/// C2PA 2.4 spec version for claim_generator_info.
const C2PA_SPEC_VERSION: &str = "2.4.0";

/// Builder for constructing a C2PA manifest with CPoP evidence assertions (§15.6).
pub struct C2paManifestBuilder {
    document_hash: [u8; 32],
    document_filename: Option<String>,
    evidence_bytes: Vec<u8>,
    evidence_packet: EvidencePacket,
    title: Option<String>,
    format: Option<String>,
    evidence_url: Option<String>,
    manifest_label: String,
    cert_der: Option<Vec<u8>>,
}

impl C2paManifestBuilder {
    pub fn new(
        evidence_packet: EvidencePacket,
        evidence_bytes: Vec<u8>,
        document_hash: [u8; 32],
    ) -> Self {
        let manifest_label = format!("urn:cpoe:{}", hex::encode(&evidence_packet.packet_id));
        Self {
            document_hash,
            document_filename: None,
            evidence_bytes,
            evidence_packet,
            title: None,
            format: None,
            evidence_url: None,
            manifest_label,
            cert_der: None,
        }
    }

    /// Set a DER-encoded X.509 certificate for the x5chain COSE header.
    ///
    /// When set, the certificate bytes are placed in x5chain (label 33) instead
    /// of raw public key bytes. Use [`super::cert::generate_self_signed_cert`]
    /// to create one from an Ed25519 signing key.
    pub fn cert_der(mut self, der: Vec<u8>) -> Self {
        self.cert_der = Some(der);
        self
    }

    /// Set the filename used in the hash-data hard binding assertion (§9.1).
    pub fn document_filename(mut self, name: impl Into<String>) -> Self {
        self.document_filename = Some(name.into());
        self
    }

    /// Set the dc:title metadata field in the claim.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the dc:format (MIME type) metadata field.
    pub fn format(mut self, mime: &str) -> Self {
        self.format = Some(mime.to_string());
        self
    }

    /// Set the URL where the .cpoe evidence packet is hosted for external reference.
    pub fn evidence_url(mut self, url: impl Into<String>) -> Self {
        self.evidence_url = Some(url.into());
        self
    }

    pub fn build_jumbf(self, signer: &dyn EvidenceSigner) -> Result<Vec<u8>> {
        let manifest = self.build_manifest(signer)?;
        encode_jumbf(&manifest)
    }

    pub fn build_manifest(self, signer: &dyn EvidenceSigner) -> Result<C2paManifest> {
        let cpoe_assertion =
            ProcessAssertion::from_evidence(&self.evidence_packet, &self.evidence_bytes);

        let now = chrono::Utc::now().to_rfc3339();

        let actions_assertion = ActionsAssertion {
            actions: vec![Action {
                action: "c2pa.created".to_string(),
                when: Some(now),
                software_agent: Some(SoftwareAgent::Info(ClaimGeneratorInfo {
                    name: "CPoE".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    spec_version: None,
                })),
                parameters: Some(ActionParameters {
                    description: Some(
                        "Document authored with CPoE Proof-of-Process witnessing".to_string(),
                    ),
                }),
            }],
        };

        let hash_data_assertion = HashDataAssertion {
            name: self
                .document_filename
                .unwrap_or_else(|| "document".to_string()),
            hash: self.document_hash.to_vec(),
            algorithm: "sha256".to_string(),
            exclusions: vec![],
        };

        // Built once; same bytes are hashed for the claim and embedded in JUMBF.
        let hash_data_box =
            build_assertion_jumbf_cbor(ASSERTION_LABEL_HASH_DATA, &hash_data_assertion)?;
        let actions_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_ACTIONS, &actions_assertion)?;
        let cpoe_box = build_assertion_jumbf_json(ASSERTION_LABEL_CPOE, &cpoe_assertion)?;

        let manifest_label = &self.manifest_label;

        let mut assertion_boxes = vec![hash_data_box, actions_box, cpoe_box];
        let mut created_assertions = Vec::new();

        // §8.4.2.3: hash superbox contents, skipping 8-byte jumb header
        for (box_bytes, label) in assertion_boxes.iter().zip(&[
            ASSERTION_LABEL_HASH_DATA,
            ASSERTION_LABEL_ACTIONS,
            ASSERTION_LABEL_CPOE,
        ]) {
            let hash = Sha256::digest(&box_bytes[8..]);
            created_assertions.push(HashedUri {
                url: format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}"),
                hash: hash.to_vec(),
                alg: Some("sha256".to_string()),
            });
        }

        // c2pa.metadata assertion (replaces deprecated dc:title/dc:format in claim)
        if self.title.is_some() || self.format.is_some() {
            let metadata = MetadataAssertion {
                title: self.title,
                format: self.format,
            };
            let meta_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_METADATA, &metadata)?;
            let meta_hash = Sha256::digest(&meta_box[8..]);
            created_assertions.push(HashedUri {
                url: format!(
                    "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{ASSERTION_LABEL_METADATA}"
                ),
                hash: meta_hash.to_vec(),
                alg: Some("sha256".to_string()),
            });
            assertion_boxes.push(meta_box);
        }

        // c2pa.external-reference assertion (hashed link to .cpoe evidence packet)
        if let Some(ref url) = self.evidence_url {
            let evidence_hash = Sha256::digest(&self.evidence_bytes);
            let process_start = self.evidence_packet.checkpoints.first().and_then(|cp| {
                chrono::DateTime::from_timestamp_millis(cp.timestamp as i64)
                    .map(|dt| dt.to_rfc3339())
            });
            let process_end = self.evidence_packet.checkpoints.last().and_then(|cp| {
                chrono::DateTime::from_timestamp_millis(cp.timestamp as i64)
                    .map(|dt| dt.to_rfc3339())
            });
            let ext_ref = ExternalReferenceAssertion {
                location: HashedExtUri {
                    url: url.clone(),
                    alg: "sha256".to_string(),
                    hash: evidence_hash.to_vec(),
                    format: Some("application/vnd.writersproof.cpoe+cbor".to_string()),
                    data_types: Some(vec![AssetType {
                        type_id: "c2pa.types.audit-log".to_string(),
                    }]),
                },
                description: Some("CPoE proof-of-process evidence packet".to_string()),
                metadata: Some(AssertionMetadata {
                    process_start,
                    process_end,
                    data_source: Some(DataSource {
                        source_type: "localProvider.REE".to_string(),
                        details: None,
                    }),
                }),
            };
            let ext_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_EXTERNAL_REF, &ext_ref)?;
            let ext_hash = Sha256::digest(&ext_box[8..]);
            created_assertions.push(HashedUri {
                url: format!(
                    "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{ASSERTION_LABEL_EXTERNAL_REF}"
                ),
                hash: ext_hash.to_vec(),
                alg: Some("sha256".to_string()),
            });
            assertion_boxes.push(ext_box);
        }

        let sig_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature");

        let claim = C2paClaim {
            claim_generator_info: vec![
                ClaimGeneratorInfo {
                    name: "CPoE".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    spec_version: Some(C2PA_SPEC_VERSION.to_string()),
                },
                ClaimGeneratorInfo {
                    name: "authorproof_protocol".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    spec_version: None,
                },
            ],
            instance_id: format!("xmp:iid:{}", hex::encode(&self.evidence_packet.packet_id)),
            signature: sig_url,
            created_assertions,
        };

        // §13.2: COSE_Sign1 with x5chain in protected header (C2PA 2.4)
        let claim_cbor = ciborium_to_vec(&claim)?;
        let signature = sign_c2pa_claim(&claim_cbor, signer, self.cert_der.as_deref())?;

        Ok(C2paManifest {
            claim,
            claim_cbor,
            manifest_label: self.manifest_label.clone(),
            assertion_boxes,
            signature,
        })
    }
}

/// §13.2: COSE_Sign1 with x5chain in protected header (C2PA 2.4).
fn sign_c2pa_claim(
    claim_cbor: &[u8],
    signer: &dyn EvidenceSigner,
    cert_der: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let pk = signer.public_key();
    let algo = signer.algorithm();
    let expected_len = match algo {
        coset::iana::Algorithm::EdDSA => 32,
        _ => {
            return Err(Error::Crypto(format!(
                "unsupported COSE algorithm {:?}",
                algo
            )))
        }
    };
    if pk.len() != expected_len {
        return Err(Error::Crypto(format!(
            "public key must be {} bytes for {:?}, got {}",
            expected_len,
            algo,
            pk.len()
        )));
    }
    crate::crypto::cose_sign1_c2pa(claim_cbor, signer, cert_der)
}
