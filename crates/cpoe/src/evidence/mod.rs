// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence packet module: types, builder, verification, and RFC conversion.

mod builder;
pub mod hw_cosign;
mod packet;
pub mod provenance;
mod rfc_conversion;
pub(crate) mod rfc_conversions;
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

/// Strip a COSE_Sign1 envelope if present, returning the inner payload.
/// If the data is not a valid COSE_Sign1 structure, returns the original bytes.
pub fn unwrap_cose_or_raw(data: &[u8]) -> Vec<u8> {
    use coset::CborSerializable;
    match coset::CoseSign1::from_slice(data) {
        Ok(sign1) => sign1.payload.unwrap_or_else(|| data.to_vec()),
        Err(_) => data.to_vec(),
    }
}
