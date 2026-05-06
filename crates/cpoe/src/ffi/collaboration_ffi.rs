// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for collaboration attestation signing and verification.
//!
//! Swift manages the collaboration session UI (presence, roles, audit trail),
//! but attestation signatures that enter the evidence packet MUST use Rust's
//! CBOR-based signing payloads so Rust's verifier can check them.

use crate::collaboration::CollaboratorRole;

/// Collaborator role as a string for FFI (matches Rust's serde rename_all = "snake_case").
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_collaboration_role_values() -> Vec<String> {
    vec![
        "primary_author".into(),
        "co_author".into(),
        "contributing_author".into(),
        "editor".into(),
        "reviewer".into(),
        "technical_contributor".into(),
        "translator".into(),
    ]
}

/// Generate the canonical CBOR signing payload for a collaborator attestation.
/// This MUST be used when signing attestations destined for evidence packets,
/// because Rust's verifier expects CBOR-encoded payloads.
///
/// Returns the raw bytes to sign with Ed25519.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_collaboration_signing_payload(
    public_key_hex: String,
    role: String,
    display_name: Option<String>,
    identifier: Option<String>,
    checkpoint_ranges: Vec<FfiCheckpointRange>,
) -> Vec<u8> {
    let role_enum: CollaboratorRole = match role.as_str() {
        "primary_author" => CollaboratorRole::PrimaryAuthor,
        "co_author" => CollaboratorRole::CoAuthor,
        "contributing_author" => CollaboratorRole::ContributingAuthor,
        "editor" => CollaboratorRole::Editor,
        "reviewer" => CollaboratorRole::Reviewer,
        "technical_contributor" => CollaboratorRole::TechnicalContributor,
        "translator" => CollaboratorRole::Translator,
        other => {
            log::warn!("Unknown collaboration role '{other}', defaulting to ContributingAuthor");
            CollaboratorRole::ContributingAuthor
        }
    };

    let ranges: Option<Vec<(u32, u32)>> = if checkpoint_ranges.is_empty() {
        None
    } else {
        Some(checkpoint_ranges.iter().map(|r| (r.start, r.end)).collect())
    };

    let collaborator = crate::collaboration::Collaborator {
        public_key: public_key_hex,
        role: role_enum,
        display_name,
        identifier,
        active_periods: Vec::new(),
        checkpoint_ranges: ranges,
        attestation_signature: String::new(),
        contribution_summary: None,
    };

    collaborator.signing_payload()
}

/// Verify a collaborator's Ed25519 attestation signature using the Rust verifier.
/// Returns true if the signature is valid over the CBOR signing payload.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_collaboration_verify_attestation(
    public_key_hex: String,
    role: String,
    display_name: Option<String>,
    identifier: Option<String>,
    checkpoint_ranges: Vec<FfiCheckpointRange>,
    signature_hex: String,
) -> bool {
    let role_enum: CollaboratorRole = match role.as_str() {
        "primary_author" => CollaboratorRole::PrimaryAuthor,
        "co_author" => CollaboratorRole::CoAuthor,
        "contributing_author" => CollaboratorRole::ContributingAuthor,
        "editor" => CollaboratorRole::Editor,
        "reviewer" => CollaboratorRole::Reviewer,
        "technical_contributor" => CollaboratorRole::TechnicalContributor,
        "translator" => CollaboratorRole::Translator,
        _ => return false,
    };

    let ranges: Option<Vec<(u32, u32)>> = if checkpoint_ranges.is_empty() {
        None
    } else {
        Some(checkpoint_ranges.iter().map(|r| (r.start, r.end)).collect())
    };

    let collaborator = crate::collaboration::Collaborator {
        public_key: public_key_hex,
        role: role_enum,
        display_name,
        identifier,
        active_periods: Vec::new(),
        checkpoint_ranges: ranges,
        attestation_signature: signature_hex,
        contribution_summary: None,
    };

    collaborator.verify_attestation().is_ok()
}

/// Checkpoint range for FFI (uniffi can't handle tuples directly).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCheckpointRange {
    pub start: u32,
    pub end: u32,
}
