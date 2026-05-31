// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use uuid::Uuid;

use crate::serde_utils::hex_bytes_32;
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationType {
    Continuation,
    Merge,
    Split,
    Rewrite,
    Translation,
    Fork,
    CitationOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationAspect {
    Structure,
    Content,
    Ideas,
    Data,
    Methodology,
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationExtent {
    None,
    Minimal,
    Partial,
    Substantial,
    Complete,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProvenanceExtra {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_description: Option<Box<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_checkpoints: Option<Vec<u32>>,
    #[serde(
        default,
        serialize_with = "crate::serde_utils::serialize_optional_signature",
        deserialize_with = "crate::serde_utils::deserialize_optional_signature",
        skip_serializing_if = "Option::is_none"
    )]
    pub cross_attestation: Option<[u8; 64]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProvenanceLink {
    pub parent_packet_id: Uuid,
    #[serde(with = "hex_bytes_32")]
    pub parent_chain_hash: [u8; 32],
    pub derivation_type: DerivationType,
    pub derivation_timestamp: DateTime<Utc>,
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Box<ProvenanceExtra>>,
}

impl Ord for ProvenanceLink {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.parent_packet_id
            .cmp(&other.parent_packet_id)
            .then_with(|| self.parent_chain_hash.cmp(&other.parent_chain_hash))
    }
}

impl PartialOrd for ProvenanceLink {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivationClaim {
    pub aspect: DerivationAspect,
    pub extent: DerivationExtent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Box<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_percentage: Option<f32>,
}

impl Eq for DerivationClaim {}

impl Ord for DerivationClaim {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.aspect
            .cmp(&other.aspect)
            .then_with(|| self.extent.cmp(&other.extent))
            .then_with(|| self.description.cmp(&other.description))
            .then_with(|| {
                let s_bits = self.estimated_percentage.map(f32::to_bits);
                let o_bits = other.estimated_percentage.map(f32::to_bits);
                s_bits.cmp(&o_bits)
            })
    }
}

impl PartialOrd for DerivationClaim {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<Box<str>>,
    pub all_parents_available: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_parent_reasons: Vec<Box<str>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceSection {
    pub parent_links: Vec<ProvenanceLink>,
    pub derivation_claims: Vec<DerivationClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProvenanceMetadata>,
}

impl ProvenanceSection {
    #[inline]
    pub fn new() -> Self {
        Self {
            parent_links: Vec::new(),
            derivation_claims: Vec::new(),
            metadata: Some(ProvenanceMetadata {
                version: PROVENANCE_SCHEMA_VERSION,
                ..Default::default()
            }),
        }
    }

    #[inline]
    pub fn canonicalize(&mut self) {
        self.parent_links.sort_unstable();
        self.derivation_claims.sort_unstable();
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let total_links = self.parent_links.len();
        if total_links == 0 {
            if !self.derivation_claims.is_empty() {
                return Err("Claims provided without associated parent links.");
            }
            return Ok(());
        }

        let mut has_merge = false;
        let mut has_cont = false;

        for link in &self.parent_links {
            match link.derivation_type {
                DerivationType::Merge => {
                    if has_cont {
                        return Err(
                            "Lineage ambiguity: 'Continuation' cannot span multiple parent UUIDs.",
                        );
                    }
                    has_merge = true;
                }
                DerivationType::Continuation => {
                    if has_merge || total_links > 1 {
                        return Err(
                            "Lineage ambiguity: 'Continuation' cannot span multiple parent UUIDs.",
                        );
                    }
                    has_cont = true;
                }
                _ => {}
            }
        }

        if has_merge && total_links < 2 {
            return Err("Derivation marked as 'Merge' but only one parent link provided.");
        }

        Ok(())
    }

    #[inline]
    pub fn add_link(mut self, link: ProvenanceLink) -> Self {
        self.parent_links.push(link);
        self
    }

    #[inline]
    pub fn add_claim(mut self, claim: DerivationClaim) -> Self {
        self.derivation_claims.push(claim);
        self
    }
}

impl ProvenanceLink {
    #[inline]
    pub fn new(parent_id: Uuid, parent_hash: [u8; 32], kind: DerivationType) -> Self {
        Self {
            parent_packet_id: parent_id,
            parent_chain_hash: parent_hash,
            derivation_type: kind,
            derivation_timestamp: Utc::now(),
            extra: None,
        }
    }

    #[inline]
    pub fn with_attestation(mut self, sig: [u8; 64]) -> Self {
        let mut e = self.extra.unwrap_or_default();
        e.cross_attestation = Some(sig);
        self.extra = Some(e);
        self
    }

    #[inline]
    pub fn with_description(mut self, desc: impl Into<Box<str>>) -> Self {
        let mut e = self.extra.unwrap_or_default();
        e.relationship_description = Some(desc.into());
        self.extra = Some(e);
        self
    }

    #[inline]
    pub fn with_inherited_checkpoints(mut self, checkpoints: Vec<u32>) -> Self {
        let mut e = self.extra.unwrap_or_default();
        e.inherited_checkpoints = Some(checkpoints);
        self.extra = Some(e);
        self
    }
}

impl ProvenanceSection {
    #[inline]
    pub fn with_metadata(mut self, metadata: ProvenanceMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalization_stability() {
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);

        let link_a = ProvenanceLink::new(id_a, [0x11; 32], DerivationType::Fork);
        let link_b = ProvenanceLink::new(id_b, [0x22; 32], DerivationType::Fork);

        let mut section_1 = ProvenanceSection::new()
            .add_link(link_a.clone())
            .add_link(link_b.clone());
        let mut section_2 = ProvenanceSection::new().add_link(link_b).add_link(link_a);

        section_1.canonicalize();
        section_2.canonicalize();

        assert_eq!(
            serde_json::to_vec(&section_1).unwrap(),
            serde_json::to_vec(&section_2).unwrap()
        );
    }

    #[test]
    fn test_semantic_validation_gates() {
        let mut section = ProvenanceSection::new().add_link(ProvenanceLink::new(
            Uuid::new_v4(),
            [0u8; 32],
            DerivationType::Merge,
        ));
        assert!(section.validate().is_err());

        section.parent_links.push(ProvenanceLink::new(
            Uuid::new_v4(),
            [1u8; 32],
            DerivationType::Merge,
        ));
        assert!(section.validate().is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let link = ProvenanceLink::new(Uuid::new_v4(), [0xAA; 32], DerivationType::Fork)
            .with_description("test link");
        let section = ProvenanceSection::new()
            .add_link(link)
            .add_claim(DerivationClaim {
                aspect: DerivationAspect::Content,
                extent: DerivationExtent::Partial,
                description: Some("partial content reuse".into()),
                estimated_percentage: Some(0.3),
            });
        let json = serde_json::to_string(&section).unwrap();
        let restored: ProvenanceSection = serde_json::from_str(&json).unwrap();
        assert_eq!(section.parent_links.len(), restored.parent_links.len());
        assert_eq!(
            section.derivation_claims.len(),
            restored.derivation_claims.len()
        );
        assert_eq!(
            section.parent_links[0].parent_chain_hash,
            restored.parent_links[0].parent_chain_hash
        );
    }
}
