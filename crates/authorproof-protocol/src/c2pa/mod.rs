// SPDX-License-Identifier: Apache-2.0

//! C2PA (Coalition for Content Provenance and Authenticity) manifest generation.
//!
//! Produces sidecar `.c2pa` manifests containing CPoP evidence assertions
//! per C2PA 2.2 specification (2025-05-01). The manifest uses JUMBF
//! (ISO 19566-5) box format with COSE_Sign1 signatures.

pub mod cert;
pub mod embed;
pub mod trust;
mod builder;
mod jumbf;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use builder::C2paManifestBuilder;
pub use embed::{embed_in_pdf, embed_manifest_in_pdf, hash_with_exclusions, sidecar_path, supports_embedding};
pub use jumbf::{encode_jumbf, verify_jumbf_structure};
pub use trust::{evaluate_trust, TrustLevel};
pub use types::{
    Action, ActionParameters, ActionsAssertion, AiContentProfile, AiDisclosureAssertion,
    AssertionMetadata, AssetInfo, AssetType, C2paClaim, C2paManifest, ClaimGeneratorInfo,
    DataSource, ExclusionRange, ExternalReferenceAssertion, ForensicSignalScores,
    HashDataAssertion, HashedExtUri, HashedUri, HashExclusion, JitterSeal, JumbfInfo,
    LocalTimestampAssertion, MetadataAssertion, C2paIngredient, IngredientMetadata,
    ProcessAssertion, SoftwareAgent, ValidationResult, VcReferenceAssertion,
};
pub use validation::{validate_manifest, verify_manifest_signature, verify_manifest_with_key};

pub const ASSERTION_LABEL_CPOE: &str = "org.cpoe.evidence";
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
