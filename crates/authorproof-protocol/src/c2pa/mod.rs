// SPDX-License-Identifier: Apache-2.0

//! C2PA (Coalition for Content Provenance and Authenticity) manifest generation.
//!
//! Produces sidecar `.c2pa` manifests containing CPoP evidence assertions
//! per C2PA 2.2 specification (2025-05-01). The manifest uses JUMBF
//! (ISO 19566-5) box format with COSE_Sign1 signatures.

pub mod cert;
mod builder;
mod jumbf;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use builder::C2paManifestBuilder;
pub use jumbf::{encode_jumbf, verify_jumbf_structure};
pub use types::{
    Action, ActionParameters, ActionsAssertion, AssertionMetadata, AssetInfo, AssetType, C2paClaim,
    C2paManifest, ClaimGeneratorInfo, DataSource, ExclusionRange, ExternalReferenceAssertion,
    HashDataAssertion, HashedExtUri, HashedUri, JitterSeal, JumbfInfo, MetadataAssertion,
    ProcessAssertion, SoftwareAgent, ValidationResult,
};
pub use validation::{validate_manifest, verify_manifest_signature, verify_manifest_with_key};

pub const ASSERTION_LABEL_CPOE: &str = "org.cpoe.evidence";
pub const ASSERTION_LABEL_ACTIONS: &str = "c2pa.actions.v2";
pub const ASSERTION_LABEL_HASH_DATA: &str = "c2pa.hash.data";
pub const ASSERTION_LABEL_METADATA: &str = "c2pa.metadata";
pub const ASSERTION_LABEL_EXTERNAL_REF: &str = "c2pa.external-reference";
