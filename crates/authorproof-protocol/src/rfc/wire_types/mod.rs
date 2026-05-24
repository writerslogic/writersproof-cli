// SPDX-License-Identifier: Apache-2.0

//! Spec-conformant wire format types for draft-condrey-rats-pop CDDL schema.
//!
//! This module implements ALL CDDL-defined types from the writerslogic-pop.cddl schema
//! as Rust structs with serde + CBOR serialization. All map keys use integer encoding
//! per IETF CBOR conventions, matching the CDDL definitions exactly.
//!
//! These types are designed for wire-format serialization and are separate from the
//! internal types used by the engine. Conversion traits (`From`) bridge between
//! internal and wire representations.
//!
//! # CBOR Tags
//!
//! - Evidence Packet: `#6.1129336645` (IANA "CPoE")
//! - Attestation Result: `#6.1129791826` (IANA "CWAR")
//!
//! # Module Organization
//!
//! - `enums`: CDDL-defined enumerations (hash algorithms, tiers, verdicts, etc.)
//! - `hash`: Base hash types (HashValue, CompactRef, TimeWindow)
//! - `components`: Evidence component types (DocumentRef, EditDelta, proofs, etc.)
//! - `checkpoint`: Wire-format checkpoint structure
//! - `packet`: Wire-format evidence packet with CBOR encode/decode
//! - `attestation`: Forensic types and attestation result with CBOR encode/decode
//! - `serde_helpers`: Custom serde modules for fixed-size byte arrays

pub(crate) mod serde_helpers;

pub mod attestation;
pub mod checkpoint;
pub mod components;
pub mod enums;
pub mod hash;
pub mod packet;

#[cfg(test)]
mod tests;

use crate::codec::{CBOR_TAG_CPOE, CBOR_TAG_CWAR};

pub const CBOR_TAG_EVIDENCE_PACKET: u64 = CBOR_TAG_CPOE;
pub const CBOR_TAG_ATTESTATION_RESULT: u64 = CBOR_TAG_CWAR;

/// Maximum length of any single string field in wire types.
pub(super) const MAX_STRING_LEN: usize = 4096;

pub use attestation::{
    AbsenceClaim, AttestationResultWire, EffortAttribution, EntropyReport, ForensicFlag,
    ForensicSummary, ForgeryCostEstimate,
};
pub use checkpoint::CheckpointWire;
pub use components::{
    ActiveProbe, BaselineDigest, BaselineVerification, BeaconAnchor, ChannelBinding, DocumentRef,
    EditDelta, HatProof, InertialSample, JitterBindingWire, MerkleProof, PhysicalLiveness,
    PhysicalState, PresenceChallenge, ProcessProof, ProfileDeclarationWire, ProofParams, Receipt,
    SelfReceipt, SessionBehavioralSummary, StreamingStats, ToolReceipt, SWF_MAX_DURATION_FACTOR,
    SWF_MIN_DURATION_FACTOR,
};
pub use enums::{
    AbsenceType, AttestationTier, BindingType, ConfidenceTier, ContentTier, CostUnit, FeatureId,
    HashAlgorithm, HashSaltMode, ProbeType, ProofAlgorithm, Verdict,
};
pub use hash::{CompactRef, HashValue, TimeWindow};
pub use packet::{EvidencePacketWire, ForensicSummaryWire, ProjectFileRef};
