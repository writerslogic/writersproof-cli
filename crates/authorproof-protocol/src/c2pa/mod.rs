// SPDX-License-Identifier: Apache-2.0

//! C2PA (Coalition for Content Provenance and Authenticity) manifest generation.
//!
//! Produces sidecar `.c2pa` manifests containing CPoE evidence assertions
//! per C2PA 2.2 specification (2025-05-01). The manifest uses JUMBF
//! (ISO 19566-5) box format with COSE_Sign1 signatures.

mod builder;
pub mod cert;
pub mod embed;
mod jumbf;
pub mod standalone;
pub mod text_attest;
pub mod text_embed;
pub mod timestamp;
pub mod trust;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use builder::C2paManifestBuilder;
pub use embed::{
    embed_in_pdf, embed_manifest_in_pdf, hash_with_exclusions, sidecar_path, supports_embedding,
};
pub use jumbf::{decode_jumbf, encode_jumbf, verify_jumbf_structure};
pub use standalone::StandaloneManifestBuilder;
pub use text_attest::{attest_text, verify_text, TextVerification};
pub use trust::{evaluate_trust, TrustLevel};
pub use types::{
    Action, ActionParameters, ActionsAssertion, AiContentProfile, AiDisclosureAssertion,
    AssertionMetadata, AssetInfo, AssetType, C2paClaim, C2paIngredient, C2paManifest,
    CadenceCorrections, CadenceDwell, CadenceFatigue, CadenceSpectral, CadenceTiming,
    ClaimGeneratorInfo, CognitiveLoadSignals, CognitiveMarkersAssertion, DataSource,
    EditMetricSignals, ErrorEcologySignals, EvidenceChainAssertion, ExclusionRange,
    ExternalReferenceAssertion, FocusSignals, ForensicSignalScores, HashDataAssertion,
    HashExclusion, HashedExtUri, HashedUri, IngredientMetadata, JitterSeal, JumbfInfo,
    KeystrokeCadenceAssertion, LikelihoodModelSignals, LocalTimestampAssertion, MetadataAssertion,
    ProcessProofAssertion, RevisionTopologySignals, RevisionTypeBreakdown, SessionStatsSignals,
    SoftwareAgent, ValidationResult, VcReferenceAssertion,
};
pub use validation::{validate_manifest, verify_manifest_signature, verify_manifest_with_key};

// Legacy alias for backward compatibility during migration.
pub type ProcessAssertion = ProcessProofAssertion;

// Custom assertion labels (com.writerslogic.* namespace per C2PA §12.5).
pub const ASSERTION_LABEL_PROCESS_PROOF: &str = "com.writerslogic.process-proof";
pub const ASSERTION_LABEL_KEYSTROKE_CADENCE: &str = "com.writerslogic.keystroke-cadence";
pub const ASSERTION_LABEL_COGNITIVE_MARKERS: &str = "com.writerslogic.cognitive-markers";
pub const ASSERTION_LABEL_EVIDENCE_CHAIN: &str = "com.writerslogic.evidence-chain";
pub const ASSERTION_LABEL_VC_EMBEDDED: &str = "com.writerslogic.verifiable-credential";

// Legacy alias — old label used in manifests prior to namespace migration.
pub const ASSERTION_LABEL_CPOE: &str = ASSERTION_LABEL_PROCESS_PROOF;

// Standard C2PA assertion labels.
pub const ASSERTION_LABEL_ACTIONS: &str = "c2pa.actions.v2";
pub const ASSERTION_LABEL_HASH_DATA: &str = "c2pa.hash.data";
pub const ASSERTION_LABEL_METADATA: &str = "c2pa.metadata";
pub const ASSERTION_LABEL_EXTERNAL_REF: &str = "c2pa.external-reference";
pub const ASSERTION_LABEL_AI_DISCLOSURE: &str = "c2pa.ai-disclosure";
pub const ASSERTION_LABEL_INGREDIENT: &str = "c2pa.ingredient";
pub const ASSERTION_LABEL_CAWG_IDENTITY: &str = "cawg.identity";
pub const ASSERTION_LABEL_CAWG_TDM: &str = "cawg.training-mining";
pub const ASSERTION_LABEL_VC_REFERENCE: &str = "com.writerslogic.vc-reference.v1";
pub const ASSERTION_LABEL_LOCAL_TIMESTAMP: &str = "com.writerslogic.local-timestamp.v1";
