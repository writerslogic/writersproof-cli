// SPDX-License-Identifier: Apache-2.0

use crate::crypto::EvidenceSigner;
use crate::error::{Error, Result};
use crate::rfc::EvidencePacket;
use sha2::{Digest, Sha256};

use super::jumbf::{
    build_assertion_jumbf_cbor, build_assertion_jumbf_json, ciborium_to_vec, encode_jumbf,
};
use super::types::{
    Action, ActionParameters, ActionsAssertion, AiDisclosureAssertion, AssertionMetadata,
    AssetType, C2paClaim, C2paManifest, ClaimGeneratorInfo, CognitiveMarkersAssertion,
    DataSource, EvidenceChainAssertion, ExclusionRange, ExternalReferenceAssertion,
    ForensicSignalScores, HashDataAssertion, HashedExtUri, HashedUri, C2paIngredient,
    KeystrokeCadenceAssertion, LocalTimestampAssertion, MetadataAssertion,
    ProcessProofAssertion, SoftwareAgent, VcReferenceAssertion,
};
use super::{
    ASSERTION_LABEL_ACTIONS, ASSERTION_LABEL_AI_DISCLOSURE, ASSERTION_LABEL_CAWG_IDENTITY,
    ASSERTION_LABEL_CAWG_TDM, ASSERTION_LABEL_COGNITIVE_MARKERS,
    ASSERTION_LABEL_EVIDENCE_CHAIN, ASSERTION_LABEL_EXTERNAL_REF, ASSERTION_LABEL_HASH_DATA,
    ASSERTION_LABEL_INGREDIENT, ASSERTION_LABEL_KEYSTROKE_CADENCE, ASSERTION_LABEL_METADATA,
    ASSERTION_LABEL_PROCESS_PROOF, ASSERTION_LABEL_VC_EMBEDDED, ASSERTION_LABEL_VC_REFERENCE,
};

/// C2PA 2.4 spec version for claim_generator_info.
const C2PA_SPEC_VERSION: &str = "2.4.0";

/// Builder for constructing a C2PA manifest with CPoP evidence assertions (§15.6).
#[derive(Clone)]
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
    cert_chain: Vec<Vec<u8>>,
    exclusions: Vec<ExclusionRange>,
    local_timestamp: Option<LocalTimestampAssertion>,
    forensic_signals: Option<ForensicSignalScores>,
    composition_mode: Option<String>,
    writing_mode: Option<String>,
    ai_disclosure: Option<AiDisclosureAssertion>,
    ingredients: Vec<C2paIngredient>,
    cawg_identity: Option<serde_json::Value>,
    cawg_tdm: Option<serde_json::Value>,
    vc_reference: Option<VcReferenceAssertion>,
    keystroke_cadence: Option<KeystrokeCadenceAssertion>,
    cognitive_markers: Option<CognitiveMarkersAssertion>,
    evidence_chain: Option<EvidenceChainAssertion>,
    vc_embedded_json: Option<String>,
    timestamp_token: Option<Vec<u8>>,
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
            cert_chain: Vec::new(),
            exclusions: Vec::new(),
            local_timestamp: None,
            forensic_signals: None,
            composition_mode: None,
            writing_mode: None,
            ai_disclosure: None,
            ingredients: Vec::new(),
            cawg_identity: None,
            cawg_tdm: None,
            vc_reference: None,
            keystroke_cadence: None,
            cognitive_markers: None,
            evidence_chain: None,
            vc_embedded_json: None,
            timestamp_token: None,
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

    /// Set a DER-encoded X.509 certificate chain for the x5chain COSE header.
    ///
    /// The first element must be the end-entity certificate; subsequent elements
    /// are intermediate CAs up to (but not including) the trust anchor root.
    pub fn cert_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.cert_chain = chain;
        self
    }

    /// Replace the document hash (used in pass 2 of two-pass PDF embedding).
    pub fn document_hash(mut self, hash: [u8; 32]) -> Self {
        self.document_hash = hash;
        self
    }

    /// Set byte-range exclusions for the hash-data assertion (§9.1).
    ///
    /// Use this when embedding the manifest in the asset file so the manifest
    /// bytes themselves are excluded from the content hash.
    pub fn exclusions(mut self, exclusions: Vec<ExclusionRange>) -> Self {
        self.exclusions = exclusions;
        self
    }

    /// Set a local timestamp assertion as an offline TSA fallback.
    pub fn local_timestamp(mut self, ts: LocalTimestampAssertion) -> Self {
        self.local_timestamp = Some(ts);
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

    /// Set the URL where the evidence packet is hosted for external reference.
    pub fn evidence_url(mut self, url: impl Into<String>) -> Self {
        self.evidence_url = Some(url.into());
        self
    }

    /// Set forensic signal scores for the process assertion.
    pub fn forensic_signals(
        mut self,
        signals: ForensicSignalScores,
        composition_mode: Option<String>,
        writing_mode: Option<String>,
    ) -> Self {
        self.forensic_signals = Some(signals);
        self.composition_mode = composition_mode;
        self.writing_mode = writing_mode;
        self
    }

    /// Set the AI disclosure assertion (c2pa.ai-disclosure).
    pub fn ai_disclosure(mut self, disclosure: AiDisclosureAssertion) -> Self {
        self.ai_disclosure = Some(disclosure);
        self
    }


    /// Set C2PA ingredients representing revision history.
    pub fn ingredients(mut self, ingredients: Vec<C2paIngredient>) -> Self {
        self.ingredients = ingredients;
        self
    }

    /// Embed a CAWG identity assertion in the manifest.
    pub fn cawg_identity(mut self, assertion: serde_json::Value) -> Self {
        self.cawg_identity = Some(assertion);
        self
    }

    /// Embed a CAWG training-and-data-mining assertion in the manifest.
    pub fn cawg_tdm(mut self, assertion: serde_json::Value) -> Self {
        self.cawg_tdm = Some(assertion);
        self
    }

    /// Link a W3C Verifiable Credential to this manifest.
    pub fn vc_reference(mut self, vc_hash: [u8; 32], vc_url: Option<String>) -> Self {
        self.vc_reference = Some(VcReferenceAssertion {
            vc_hash: hex::encode(vc_hash),
            vc_url,
            algorithm: "sha256".to_string(),
        });
        self
    }

    /// Set the keystroke cadence assertion.
    pub fn keystroke_cadence(mut self, cadence: KeystrokeCadenceAssertion) -> Self {
        self.keystroke_cadence = Some(cadence);
        self
    }

    /// Set the cognitive markers assertion.
    pub fn cognitive_markers(mut self, markers: CognitiveMarkersAssertion) -> Self {
        self.cognitive_markers = Some(markers);
        self
    }

    /// Set the evidence chain assertion. If not set, one is built automatically
    /// from the evidence packet's checkpoints.
    pub fn evidence_chain(mut self, chain: EvidenceChainAssertion) -> Self {
        self.evidence_chain = Some(chain);
        self
    }

    /// Embed a signed W3C Verifiable Credential (JSON) directly in the manifest.
    pub fn vc_embedded(mut self, vc_json: String) -> Self {
        self.vc_embedded_json = Some(vc_json);
        self
    }

    /// Set a pre-fetched RFC 3161 `TimeStampToken` for the `sigTst` COSE header.
    ///
    /// The caller is responsible for obtaining the token from a TSA (e.g. by
    /// POSTing the output of [`super::timestamp::build_timestamp_request`] to
    /// a TSA URL and parsing the response with
    /// [`super::timestamp::parse_timestamp_response`]). This keeps the protocol
    /// crate HTTP-free for wasm compatibility.
    ///
    /// When set, the token is injected into the COSE_Sign1 unprotected header
    /// as `sigTst` per C2PA 2.4 Section 14.4.
    pub fn timestamp_token(mut self, token: Vec<u8>) -> Self {
        self.timestamp_token = Some(token);
        self
    }

    pub fn build_jumbf(self, signer: &dyn EvidenceSigner) -> Result<Vec<u8>> {
        let manifest = self.build_manifest(signer)?;
        encode_jumbf(&manifest)
    }

    pub fn build_manifest(self, signer: &dyn EvidenceSigner) -> Result<C2paManifest> {
        let mut process_proof =
            ProcessProofAssertion::from_evidence(&self.evidence_packet, &self.evidence_bytes);
        process_proof.signal_scores = self.forensic_signals;
        process_proof.composition_mode = self.composition_mode;
        process_proof.writing_mode = self.writing_mode;

        let now = chrono::Utc::now().to_rfc3339();

        let actions_assertion = ActionsAssertion {
            actions: vec![Action {
                action: "c2pa.created".to_string(),
                when: Some(now),
                software_agent: Some(SoftwareAgent::Info(ClaimGeneratorInfo {
                    name: "WritersProof".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    spec_version: None,
                })),
                parameters: Some(ActionParameters {
                    description: Some(
                        "Document authored with WritersProof Proof-of-Process witnessing".to_string(),
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
            exclusions: self.exclusions,
            pad: Vec::new(),
        };

        // Build the evidence chain from checkpoints (auto-generate if not set).
        let evidence_chain = self.evidence_chain
            .unwrap_or_else(|| EvidenceChainAssertion::from_evidence(&self.evidence_packet));

        // Built once; same bytes are hashed for the claim and embedded in JUMBF.
        let hash_data_box =
            build_assertion_jumbf_cbor(ASSERTION_LABEL_HASH_DATA, &hash_data_assertion)?;
        let actions_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_ACTIONS, &actions_assertion)?;
        let process_proof_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_PROCESS_PROOF, &process_proof)?;
        let evidence_chain_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_EVIDENCE_CHAIN, &evidence_chain)?;

        let manifest_label = &self.manifest_label;

        let mut assertion_boxes = Vec::new();
        let mut created_assertions = Vec::new();

        // §8.4.2.3: hash superbox contents, skipping 8-byte jumb header.
        // Core assertions always included.
        for (box_bytes, label) in [
            (hash_data_box, ASSERTION_LABEL_HASH_DATA),
            (actions_box, ASSERTION_LABEL_ACTIONS),
            (process_proof_box, ASSERTION_LABEL_PROCESS_PROOF),
            (evidence_chain_box, ASSERTION_LABEL_EVIDENCE_CHAIN),
        ] {
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                box_bytes,
                manifest_label,
                label,
            );
        }

        // Keystroke cadence assertion (optional, Pro tier).
        if let Some(ref cadence) = self.keystroke_cadence {
            let cadence_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_KEYSTROKE_CADENCE, cadence)?;
            push_hashed_assertion(
                &mut assertion_boxes, &mut created_assertions,
                cadence_box, manifest_label, ASSERTION_LABEL_KEYSTROKE_CADENCE,
            );
        }

        // Cognitive markers assertion (optional, Pro tier).
        if let Some(ref markers) = self.cognitive_markers {
            let markers_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_COGNITIVE_MARKERS, markers)?;
            push_hashed_assertion(
                &mut assertion_boxes, &mut created_assertions,
                markers_box, manifest_label, ASSERTION_LABEL_COGNITIVE_MARKERS,
            );
        }

        // Embedded W3C Verifiable Credential (JSON, always included when available).
        if let Some(ref vc_json) = self.vc_embedded_json {
            let vc_value: serde_json::Value = serde_json::from_str(vc_json)
                .map_err(|e| Error::Serialization(format!("VC JSON parse: {e}")))?;
            let vc_box = build_assertion_jumbf_json(ASSERTION_LABEL_VC_EMBEDDED, &vc_value)?;
            push_hashed_assertion(
                &mut assertion_boxes, &mut created_assertions,
                vc_box, manifest_label, ASSERTION_LABEL_VC_EMBEDDED,
            );
        }

        // c2pa.metadata assertion (replaces deprecated dc:title/dc:format in claim)
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
                manifest_label,
                ASSERTION_LABEL_METADATA,
            );
        }

        // c2pa.external-reference assertion (hashed link to evidence packet)
        if let Some(ref url) = self.evidence_url {
            // The external reference declares format application/c2pa,
            // so the hash must be over CBOR-tagged bytes (tag 0x43504F45). Re-encode from
            // the packet if the caller passed untagged bytes.
            let tagged_evidence = if is_cpoe_tagged(&self.evidence_bytes) {
                self.evidence_bytes.clone()
            } else {
                crate::codec::encode_evidence(&self.evidence_packet).map_err(|e| {
                    Error::Serialization(format!("C2PA: failed to re-encode evidence with tag: {e}"))
                })?
            };
            let evidence_hash = Sha256::digest(&tagged_evidence);
            if self.evidence_packet.checkpoints.is_empty() {
                log::warn!("C2PA embed: evidence packet has no checkpoints; process timestamps will be absent");
            }
            let process_start = self
                .evidence_packet
                .checkpoints
                .first()
                .and_then(|cp| millis_to_rfc3339(cp.timestamp));
            let process_end = self
                .evidence_packet
                .checkpoints
                .last()
                .and_then(|cp| millis_to_rfc3339(cp.timestamp));
            let ext_ref = ExternalReferenceAssertion {
                location: HashedExtUri {
                    url: url.clone(),
                    alg: "sha256".to_string(),
                    hash: evidence_hash.to_vec(),
                    format: Some("application/c2pa".to_string()),
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
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                ext_box,
                manifest_label,
                ASSERTION_LABEL_EXTERNAL_REF,
            );
        }

        // c2pa.ai-disclosure assertion (§12.8)
        if let Some(ref disclosure) = self.ai_disclosure {
            let ai_box =
                build_assertion_jumbf_json(ASSERTION_LABEL_AI_DISCLOSURE, disclosure)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                ai_box,
                manifest_label,
                ASSERTION_LABEL_AI_DISCLOSURE,
            );
        }


        for (i, ingredient) in self.ingredients.iter().enumerate() {
            let label = format!("{ASSERTION_LABEL_INGREDIENT}.{i}");
            let ing_box = build_assertion_jumbf_cbor(&label, ingredient)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                ing_box,
                manifest_label,
                &label,
            );
        }

        if let Some(ref identity) = self.cawg_identity {
            let cawg_box = build_assertion_jumbf_json(ASSERTION_LABEL_CAWG_IDENTITY, identity)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                cawg_box,
                manifest_label,
                ASSERTION_LABEL_CAWG_IDENTITY,
            );
        }

        if let Some(ref tdm) = self.cawg_tdm {
            let tdm_box = build_assertion_jumbf_json(ASSERTION_LABEL_CAWG_TDM, tdm)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                tdm_box,
                manifest_label,
                ASSERTION_LABEL_CAWG_TDM,
            );
        }

        if let Some(ref vc_ref) = self.vc_reference {
            let vc_box = build_assertion_jumbf_json(ASSERTION_LABEL_VC_REFERENCE, vc_ref)?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                vc_box,
                manifest_label,
                ASSERTION_LABEL_VC_REFERENCE,
            );
        }

        if let Some(ref local_ts) = self.local_timestamp {
            let ts_box = build_assertion_jumbf_json(
                super::ASSERTION_LABEL_LOCAL_TIMESTAMP,
                local_ts,
            )?;
            push_hashed_assertion(
                &mut assertion_boxes,
                &mut created_assertions,
                ts_box,
                manifest_label,
                super::ASSERTION_LABEL_LOCAL_TIMESTAMP,
            );
        }

        let sig_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature");

        let claim = C2paClaim {
            claim_generator_info: ClaimGeneratorInfo {
                name: "CPoE/authorproof_protocol".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                spec_version: Some(C2PA_SPEC_VERSION.to_string()),
            },
            instance_id: format!("xmp:iid:{}", hex::encode(&self.evidence_packet.packet_id)),
            signature: sig_url,
            alg: Some("sha256".to_string()),
            created_assertions,
        };

        // §13.2: COSE_Sign1 with x5chain in protected header (C2PA 2.4)
        // cert_der takes precedence; cert_chain[0] is used as fallback end-entity cert.
        let cert_der = self.cert_der.as_deref().or_else(|| self.cert_chain.first().map(|v| v.as_slice()));
        let claim_cbor = ciborium_to_vec(&claim)?;
        let mut signature = sign_c2pa_claim(&claim_cbor, signer, cert_der)?;

        // C2PA 2.4 §14.4: inject sigTst into the COSE unprotected header.
        if let Some(ref token) = self.timestamp_token {
            signature = super::timestamp::inject_timestamp_into_cose(&signature, token)?;
        }

        Ok(C2paManifest {
            claim,
            claim_cbor,
            manifest_label: self.manifest_label.clone(),
            assertion_boxes,
            signature,
        })
    }
}

/// Convert a millisecond timestamp to RFC 3339, returning `None` if out of range.
fn millis_to_rfc3339(millis: u64) -> Option<String> {
    match i64::try_from(millis) {
        Ok(ts) => chrono::DateTime::from_timestamp_millis(ts).map(|dt| dt.to_rfc3339()),
        Err(_) => {
            log::warn!(
                "timestamp {} exceeds i64::MAX; omitting from manifest",
                millis
            );
            None
        }
    }
}

/// Hash an assertion box (skipping 8-byte JUMBF header) and push the
/// HashedUri + box bytes into the running lists.
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

/// §13.2: COSE_Sign1 with x5chain in protected header (C2PA 2.4).
fn sign_c2pa_claim(
    claim_cbor: &[u8],
    signer: &dyn EvidenceSigner,
    cert_der: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let pk = signer.public_key();
    let algo = signer.algorithm();
    let valid_len = match algo {
        coset::iana::Algorithm::EdDSA => pk.len() == 32,
        coset::iana::Algorithm::ES256 => pk.len() == 65 || pk.len() == 33,
        coset::iana::Algorithm::ES384 => pk.len() == 97 || pk.len() == 49,
        _ => {
            return Err(Error::Crypto(format!(
                "unsupported COSE algorithm {:?}",
                algo
            )))
        }
    };
    if !valid_len {
        return Err(Error::Crypto(format!(
            "invalid public key length {} for {:?}",
            pk.len(),
            algo,
        )));
    }
    crate::crypto::cose_sign1_c2pa(claim_cbor, signer, cert_der)
}

/// Check whether raw bytes begin with the CPoE CBOR semantic tag header.
///
/// Tag 1129336645 (0x43504F45) is encoded as major type 6 with 4-byte value:
/// `[0xDA, 0x43, 0x50, 0x4F, 0x45]`.
fn is_cpoe_tagged(data: &[u8]) -> bool {
    data.len() >= 5 && data[..5] == [0xDA, 0x43, 0x50, 0x4F, 0x45]
}
