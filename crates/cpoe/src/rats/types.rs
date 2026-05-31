// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! RATS architecture types per RFC 9334 (Remote Attestation Procedures).
//!
//! Defines the principal roles and data structures from the RATS
//! reference architecture for use in CPoE's proof-of-process flow.

use serde::{Deserialize, Serialize};

/// Principal roles in the RATS architecture (RFC 9334 Section 3).
///
/// In CPoE's mapping:
/// - **Attester**: the writing application that captures behavioral evidence
/// - **Verifier**: the CPoE engine that appraises evidence and produces an EAR
/// - **RelyingParty**: any consumer of the attestation result (publisher, court, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RatsRole {
    /// Produces evidence about its own trustworthiness (RFC 9334 Section 3.1).
    Attester,
    /// Appraises evidence and produces attestation results (RFC 9334 Section 3.2).
    Verifier,
    /// Consumes attestation results for trust decisions (RFC 9334 Section 3.3).
    RelyingParty,
}

impl RatsRole {
    /// Return the lowercase label used in protocol messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attester => "attester",
            Self::Verifier => "verifier",
            Self::RelyingParty => "relying-party",
        }
    }
}

/// RATS Evidence: a CBOR-encoded evidence packet produced by an Attester
/// (RFC 9334 Section 4, conveyed as an EAT per RFC 8392).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Raw CBOR bytes of the evidence packet (COSE_Sign1 envelope).
    pub cbor_bytes: Vec<u8>,
}

impl Evidence {
    /// C2PA evidence media type.
    pub const MEDIA_TYPE: &'static str = super::C2PA_MEDIA_TYPE;

    /// Wrap raw CBOR evidence bytes.
    pub fn new(cbor_bytes: Vec<u8>) -> Self {
        Self { cbor_bytes }
    }

    /// Return the raw CBOR payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.cbor_bytes
    }
}

/// RATS Attestation Result: an EAR token produced by a Verifier after
/// appraising evidence (RFC 9334 Section 4, encoded as CWT per draft-ietf-rats-ear).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationResult {
    /// Signed CWT bytes carrying the EAR token (COSE_Sign1 envelope).
    pub cwt_bytes: Vec<u8>,
}

impl AttestationResult {
    /// Attestation result media type (C2PA).
    pub const MEDIA_TYPE: &'static str = super::C2PA_MEDIA_TYPE;

    /// Wrap signed CWT bytes.
    pub fn new(cwt_bytes: Vec<u8>) -> Self {
        Self { cwt_bytes }
    }

    /// Return the raw CWT payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.cwt_bytes
    }
}
