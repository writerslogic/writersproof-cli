// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence packet module: types, builder, verification, and RFC conversion.

mod builder;
pub mod hw_cosign;
mod packet;
mod rfc_conversion;
#[cfg(test)]
mod tests;
mod types;
pub mod wire_conversion;

pub use self::types::{
    compute_hw_entangled_hash, AccessControlInfo, AnchorProof, BehavioralEvidence, CheckpointProof,
    CheckpointSignature, Claim, ClaimType, ContextPeriod, ContextPeriodType, DictationEvent,
    DocumentInfo, DocumentStructureEntry, DocumentStructureSnapshot, EditRegion, ExternalAnchors,
    ForensicMetrics, HardwareCosignature, HardwareEvidence, InputDeviceInfo,
    KeyHierarchyEvidencePacket, KeystrokeEvidence, ManuscriptExportAttestation, OtsProof, Packet,
    RecordProvenance, Rfc3161Proof, TrustTier, WpBeaconAttestation, HW_COSIGN_DST,
};

pub use self::builder::{
    build_ephemeral_packet, compute_events_binding_hash, convert_anchor_proof, Builder,
    EphemeralSnapshot,
};

pub use self::rfc_conversion::RfcConversionError;
