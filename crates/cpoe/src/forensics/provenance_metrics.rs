// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Provenance metrics computation from text fragment evidence.
//!
//! Aggregates keystroke context across a session's text fragments to produce
//! composition ratios, source trustworthiness, and provenance chain depth.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::store::text_fragments::{KeystrokeContext, TextFragment};

/// Provenance metrics computed from a session's text fragments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceMetrics {
    /// Total text fragments analyzed.
    pub total_fragments: usize,
    /// Fraction of fragments that are original composition (0.0-1.0).
    pub original_composition_ratio: f64,
    /// Fraction of fragments pasted from an unknown/unverified source.
    pub sourced_unknown_ratio: f64,
    /// Fraction of fragments pasted from a verified source session.
    pub sourced_verified_ratio: f64,
    /// Number of distinct source sessions contributing content.
    pub chain_depth: u32,
    /// Trustworthiness of sourced content (verified / total sourced).
    pub source_trustworthiness: f64,
    /// Composite authenticity score (0.0-1.0).
    pub authenticity_score: f64,
    /// Breakdown by source session.
    pub source_sessions: Vec<SourceSessionInfo>,
}

/// Information about a single source session contributing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSessionInfo {
    pub session_id: String,
    pub app_bundle_id: Option<String>,
    pub fragment_count: usize,
    /// Whether the source has a verifiable evidence packet.
    pub verified: bool,
}

/// Weight of original composition in authenticity score.
const AUTHENTICITY_WEIGHT_ORIGINAL: f64 = 0.7;
/// Weight of source trustworthiness in authenticity score.
const AUTHENTICITY_WEIGHT_TRUST: f64 = 0.3;

impl ProvenanceMetrics {
    /// Compute provenance metrics from a session's text fragments.
    ///
    /// Aggregates keystroke context to classify fragments as original
    /// composition, pasted-from-verified, or pasted-from-unknown.
    pub fn compute(fragments: &[TextFragment]) -> Self {
        if fragments.is_empty() {
            return Self::default();
        }

        let total = fragments.len();
        let mut original_count = 0usize;
        let mut sourced_verified_count = 0usize;
        let mut sourced_unknown_count = 0usize;

        // Track distinct source sessions
        let mut source_map: HashMap<String, SourceSessionAccum> = HashMap::new();

        for frag in fragments {
            match frag.keystroke_context {
                Some(KeystrokeContext::PastedContent) => {
                    if let Some(ref src_session) = frag.source_session_id {
                        // Has a source session; check if evidence packet present
                        let verified = frag.source_evidence_packet.is_some();
                        if verified {
                            sourced_verified_count += 1;
                        } else {
                            sourced_unknown_count += 1;
                        }
                        let entry = source_map.entry(src_session.clone()).or_insert_with(|| {
                            SourceSessionAccum {
                                app_bundle_id: frag.source_app_bundle_id.clone(),
                                count: 0,
                                verified,
                            }
                        });
                        entry.count += 1;
                    } else {
                        // Pasted but no source session tracked
                        sourced_unknown_count += 1;
                    }
                }
                Some(KeystrokeContext::AfterPaste) => {
                    // After-paste is original composition following a paste
                    original_count += 1;
                }
                Some(KeystrokeContext::OriginalComposition) | None => {
                    original_count += 1;
                }
            }
        }

        let original_ratio = original_count as f64 / total as f64;
        let verified_ratio = sourced_verified_count as f64 / total as f64;
        let unknown_ratio = sourced_unknown_count as f64 / total as f64;

        let total_sourced = sourced_verified_count + sourced_unknown_count;
        let trust = if total_sourced > 0 {
            sourced_verified_count as f64 / total_sourced as f64
        } else {
            1.0 // No sourced content = fully trusted original
        };

        let authenticity =
            original_ratio * AUTHENTICITY_WEIGHT_ORIGINAL + trust * AUTHENTICITY_WEIGHT_TRUST;

        let source_sessions: Vec<SourceSessionInfo> = source_map
            .into_iter()
            .map(|(sid, accum)| SourceSessionInfo {
                session_id: sid,
                app_bundle_id: accum.app_bundle_id,
                fragment_count: accum.count,
                verified: accum.verified,
            })
            .collect();

        let chain_depth = source_sessions.len() as u32;

        Self {
            total_fragments: total,
            original_composition_ratio: original_ratio,
            sourced_unknown_ratio: unknown_ratio,
            sourced_verified_ratio: verified_ratio,
            chain_depth,
            source_trustworthiness: trust,
            authenticity_score: authenticity.clamp(0.0, 1.0),
            source_sessions,
        }
    }

    /// Quick check: is this session entirely original composition?
    pub fn is_fully_original(&self) -> bool {
        self.total_fragments > 0 && self.chain_depth == 0
    }

    /// Quick check: does this session contain any unverified sourced content?
    pub fn has_unverified_sources(&self) -> bool {
        self.sourced_unknown_ratio > 0.0
    }
}

/// Accumulator for per-source-session aggregation.
struct SourceSessionAccum {
    app_bundle_id: Option<String>,
    count: usize,
    verified: bool,
}
