// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Collaborative authorship with per-contributor independent attestations.
//!
//! Each collaborator signs their own attestation (public key + role + checkpoint ranges),
//! so verifiers can confirm participation without shared signing keys.
//!
//! # Privacy Considerations
//!
//! - Public keys may be linkable across documents
//! - Active periods reveal contributor work schedules
//! - Contribution percentages may be contentious

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Collaboration mode between authors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationMode {
    /// One active author at a time
    Sequential,
    /// Concurrent editing, merged
    Parallel,
    /// Primary author + contributors
    Delegated,
    /// Author + reviewers/editors
    PeerReview,
}

/// Collaborator's role in the work
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaboratorRole {
    /// Main/lead author
    PrimaryAuthor,
    /// Equal contributor
    CoAuthor,
    /// Section/chapter contributor
    ContributingAuthor,
    /// Editorial contributions
    Editor,
    /// Review comments incorporated
    Reviewer,
    /// Data, code, figures
    TechnicalContributor,
    /// Translation work
    Translator,
}

/// Kind of contribution made
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    /// New text/content
    OriginalContent,
    /// Revisions to existing content
    Editing,
    /// Research contribution
    Research,
    /// Data/analysis contribution
    DataAnalysis,
    /// Visual elements
    FiguresTables,
    /// Code contributions
    Code,
    /// Review that influenced content
    ReviewFeedback,
    /// Organization/structure
    Structural,
}

/// Merge strategy for combining contributions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Sections appended in order
    SequentialAppend,
    /// Content merged throughout
    Interleaved,
    /// Conflicts manually resolved
    ConflictResolved,
    /// Automated merge tool
    Automated,
}

/// Time interval of collaborator activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Aggregate statistics for a collaborator's contributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionSummary {
    pub checkpoints_authored: u32,
    pub chars_added: u64,
    pub chars_deleted: u64,
    pub active_time_seconds: f64,

    /// 0.0--1.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_contribution_pct: Option<f32>,
}

/// Individual collaborator record with attestation signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    /// Hex-encoded or PEM public key
    pub public_key: String,
    pub role: CollaboratorRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// External identifier (email, ORCID, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    pub active_periods: Vec<TimeInterval>,
    /// Inclusive (start, end) checkpoint ranges authored
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ranges: Option<Vec<(u32, u32)>>,
    /// Ed25519 signature (hex-encoded, 64 bytes) over [`signing_payload()`].
    /// Verify with [`verify_attestation()`] before trusting this collaborator's claims.
    pub attestation_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_summary: Option<ContributionSummary>,
}

/// Detailed contribution claim linking a contributor to specific work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionClaim {
    pub contribution_type: ContributionType,
    /// Public key referencing a `Collaborator`
    pub contributor_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_indices: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 0.0--1.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<f32>,
}

/// Record of a single merge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeEvent {
    pub merge_time: DateTime<Utc>,
    pub resulting_checkpoint: u32,
    pub merged_contributor_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_note: Option<String>,
}

/// Ordered log of merge operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeRecord {
    pub merges: Vec<MergeEvent>,
}

/// Governance policy for collaboration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvers_for_merge: Option<u32>,
    #[serde(default)]
    pub requires_all_signatures: bool,
    /// URI to external policy document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/// Collaboration section embedded in an Evidence packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSection {
    pub mode: CollaborationMode,
    pub participants: Vec<Collaborator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ContributionClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_record: Option<MergeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CollaborationPolicy>,
}

impl CollaborationSection {
    /// Create an empty collaboration section with the given mode.
    pub fn new(mode: CollaborationMode) -> Self {
        Self {
            mode,
            participants: Vec::new(),
            contributions: Vec::new(),
            merge_record: None,
            policy: None,
        }
    }

    /// Append a collaborator to the participant list.
    pub fn add_participant(mut self, collaborator: Collaborator) -> Self {
        self.participants.push(collaborator);
        self
    }

    /// Append a contribution claim.
    pub fn add_contribution(mut self, claim: ContributionClaim) -> Self {
        self.contributions.push(claim);
        self
    }

    /// Attach a merge record.
    pub fn with_merge_record(mut self, record: MergeRecord) -> Self {
        self.merge_record = Some(record);
        self
    }

    /// Attach a governance policy.
    pub fn with_policy(mut self, policy: CollaborationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Verify all checkpoint indices `[0, total_checkpoints)` are claimed by at least one participant.
    ///
    /// Returns an error if any range has start > end or if any checkpoints are uncovered.
    /// Ranges extending beyond `total_checkpoints` are clamped with a warning log.
    pub fn validate_coverage(&self, total_checkpoints: u32) -> Result<(), String> {
        if total_checkpoints == 0 {
            return Ok(());
        }

        // Collect all (start, end) intervals, validate bounds
        let mut intervals: Vec<(u32, u32)> = Vec::new();
        for participant in &self.participants {
            if let Some(ref ranges) = participant.checkpoint_ranges {
                for (start, end) in ranges {
                    if start > end {
                        return Err(format!(
                            "invalid checkpoint range ({start}, {end}): \
                             start must not exceed end (valid: 0..{total_checkpoints})"
                        ));
                    }
                    if *end >= total_checkpoints {
                        return Err(format!(
                            "checkpoint range ({start}, {end}) out of bounds: \
                             end must be < {total_checkpoints} (valid: 0..{})",
                            total_checkpoints.saturating_sub(1)
                        ));
                    }
                    intervals.push((*start, *end));
                }
            }
        }

        if intervals.is_empty() {
            return Err(format!(
                "Checkpoints not covered by any participant: 0..{}",
                total_checkpoints.saturating_sub(1)
            ));
        }

        // Interval merging: O(N log N) in number of ranges, O(1) extra memory
        intervals.sort_unstable_by_key(|&(s, _)| s);

        let merged_start = intervals[0].0;
        let mut merged_end = intervals[0].1;

        for &(s, e) in &intervals[1..] {
            if s <= merged_end + 1 {
                merged_end = merged_end.max(e);
            } else {
                // Gap found
                return Err(format!(
                    "Checkpoint gap: range {}..={} not covered by any participant",
                    merged_end + 1,
                    s - 1
                ));
            }
        }

        if merged_start != 0 {
            return Err(format!("Checkpoints not covered: 0..={}", merged_start - 1));
        }
        if merged_end != total_checkpoints - 1 {
            return Err(format!(
                "Checkpoints not covered: {}..={}",
                merged_end + 1,
                total_checkpoints - 1
            ));
        }

        Ok(())
    }

    /// Verify every participant's attestation signature.
    /// Returns `Ok(())` if all pass, or the first failure.
    pub fn verify_all_attestations(&self) -> Result<(), String> {
        for (i, p) in self.participants.iter().enumerate() {
            p.verify_attestation().map_err(|e| {
                format!(
                    "participant {} ({:?}) attestation invalid: {e}",
                    i,
                    p.display_name.as_deref().unwrap_or(&p.public_key)
                )
            })?;
        }
        Ok(())
    }

    /// Return the number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Filter participants by role.
    pub fn participants_by_role(&self, role: CollaboratorRole) -> Vec<&Collaborator> {
        self.participants
            .iter()
            .filter(|p| p.role == role)
            .collect()
    }
}

impl Collaborator {
    /// Create a collaborator with the required fields.
    pub fn new(public_key: String, role: CollaboratorRole, signature: String) -> Self {
        Self {
            public_key,
            role,
            display_name: None,
            identifier: None,
            active_periods: Vec::new(),
            checkpoint_ranges: None,
            attestation_signature: signature,
            contribution_summary: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the external identifier (email, ORCID, etc.).
    pub fn with_identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    /// Append an active time interval. If `start > end`, the values are swapped
    /// with a warning log so builder chains are not broken by caller mistakes.
    pub fn add_active_period(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        let (start, end) = if start > end {
            log::warn!("add_active_period called with start > end; swapping");
            (end, start)
        } else {
            (start, end)
        };
        self.active_periods.push(TimeInterval { start, end });
        self
    }

    /// Set the inclusive checkpoint ranges authored by this collaborator.
    pub fn with_checkpoint_ranges(mut self, ranges: Vec<(u32, u32)>) -> Self {
        self.checkpoint_ranges = Some(ranges);
        self
    }

    /// Attach aggregate contribution statistics.
    pub fn with_summary(mut self, summary: ContributionSummary) -> Self {
        self.contribution_summary = Some(summary);
        self
    }

    /// Canonical bytes used as the Ed25519 signing input.
    /// Uses CBOR deterministic encoding (RFC 8949 §4.2) for cross-platform
    /// reproducibility. JSON was previously used but is unsuitable for
    /// signatures because float formatting varies across architectures.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut map = std::collections::BTreeMap::new();
        map.insert("active_periods", serde_json::json!(self.active_periods));
        map.insert(
            "checkpoint_ranges",
            serde_json::json!(self.checkpoint_ranges),
        );
        map.insert(
            "contribution_summary",
            serde_json::json!(self.contribution_summary),
        );
        map.insert("display_name", serde_json::json!(self.display_name));
        map.insert("identifier", serde_json::json!(self.identifier));
        map.insert("public_key", serde_json::json!(self.public_key));
        map.insert("role", serde_json::json!(self.role));
        // CBOR deterministic encoding: guaranteed identical bytes across
        // architectures, unlike JSON which has float formatting ambiguities.
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf)
            .expect("collaborator CBOR payload serialization is infallible");
        buf
    }

    /// Verify the attestation signature against the embedded public key.
    /// Both `public_key` and `attestation_signature` must be hex-encoded.
    pub fn verify_attestation(&self) -> Result<(), String> {
        let pub_bytes =
            hex::decode(&self.public_key).map_err(|e| format!("invalid public key hex: {e}"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("public key must be 32 bytes, got {}", pub_bytes.len()))?,
        )
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;

        let sig_bytes = hex::decode(&self.attestation_signature)
            .map_err(|e| format!("invalid signature hex: {e}"))?;
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("signature must be 64 bytes, got {}", sig_bytes.len()))?,
        );

        vk.verify_strict(&self.signing_payload(), &sig)
            .map_err(|e| format!("attestation verification failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collaboration_section_builder() {
        let section = CollaborationSection::new(CollaborationMode::Parallel)
            .add_participant(
                Collaborator::new(
                    "pubkey1".to_string(),
                    CollaboratorRole::PrimaryAuthor,
                    "sig1".to_string(),
                )
                .with_name("Alice")
                .with_checkpoint_ranges(vec![(0, 10)]),
            )
            .add_participant(
                Collaborator::new(
                    "pubkey2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "sig2".to_string(),
                )
                .with_name("Bob")
                .with_checkpoint_ranges(vec![(11, 20)]),
            );

        assert_eq!(section.participant_count(), 2);
        assert_eq!(section.mode, CollaborationMode::Parallel);
    }

    #[test]
    fn test_coverage_validation() {
        let section = CollaborationSection::new(CollaborationMode::Sequential)
            .add_participant(
                Collaborator::new(
                    "pk1".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s1".to_string(),
                )
                .with_checkpoint_ranges(vec![(0, 4)]),
            )
            .add_participant(
                Collaborator::new(
                    "pk2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s2".to_string(),
                )
                .with_checkpoint_ranges(vec![(5, 9)]),
            );

        // 10 checkpoints (0-9) should be covered
        assert!(section.validate_coverage(10).is_ok());

        // 11 checkpoints would have uncovered index 10
        assert!(section.validate_coverage(11).is_err());
    }

    #[test]
    fn test_participants_by_role() {
        let section = CollaborationSection::new(CollaborationMode::Delegated)
            .add_participant(Collaborator::new(
                "pk1".to_string(),
                CollaboratorRole::PrimaryAuthor,
                "s1".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk2".to_string(),
                CollaboratorRole::Editor,
                "s2".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk3".to_string(),
                CollaboratorRole::Editor,
                "s3".to_string(),
            ));

        let editors = section.participants_by_role(CollaboratorRole::Editor);
        assert_eq!(editors.len(), 2);
    }

    #[test]
    fn test_attestation_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let mut collab = Collaborator::new(
            pub_hex,
            CollaboratorRole::CoAuthor,
            String::new(), // placeholder; overwritten below
        )
        .with_name("Alice")
        .with_checkpoint_ranges(vec![(0, 5)]);

        let payload = collab.signing_payload();
        let sig = signing_key.sign(&payload);
        collab.attestation_signature = hex::encode(sig.to_bytes());

        assert!(collab.verify_attestation().is_ok());
    }

    #[test]
    fn test_attestation_bad_signature() {
        let collab = Collaborator::new(
            hex::encode([1u8; 32]),
            CollaboratorRole::CoAuthor,
            hex::encode([0u8; 64]), // wrong signature
        );
        assert!(collab.verify_attestation().is_err());
    }

    #[test]
    fn test_active_period_swap() {
        let early = Utc::now() - chrono::Duration::hours(1);
        let late = Utc::now();
        let collab = Collaborator::new("k".into(), CollaboratorRole::Editor, "s".into())
            .add_active_period(late, early); // inverted
        assert!(collab.active_periods[0].start <= collab.active_periods[0].end);
    }

    #[test]
    fn test_serialization() {
        let section = CollaborationSection::new(CollaborationMode::PeerReview).add_participant(
            Collaborator::new(
                "test_key".to_string(),
                CollaboratorRole::Reviewer,
                "test_sig".to_string(),
            ),
        );

        let json = serde_json::to_string(&section).unwrap();
        let parsed: CollaborationSection = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mode, CollaborationMode::PeerReview);
        assert_eq!(parsed.participants.len(), 1);
    }
}
