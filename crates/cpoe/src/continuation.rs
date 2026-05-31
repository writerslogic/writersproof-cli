// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Continuation tokens for multi-packet Evidence series.
//!
//! Allows a single authorship effort (e.g., a novel spanning months) to be
//! documented across multiple Evidence packets with cryptographic continuity:
//! previous chain hash feeds into VDF input, series-id is bound into the chain,
//! and signing keys must be consistent (verified via series-binding-signature).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Comprehensive error type for Continuation logic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContinuationError {
    #[error("packet_sequence overflow: u32::MAX reached")]
    SequenceOverflow,
    #[error("packets_in_series overflow: u32::MAX reached")]
    PacketsInSeriesOverflow,
    #[error("Non-first packet must have prev_packet_chain_hash")]
    MissingPrevChainHash,
    #[error("Non-first packet must have prev_packet_id")]
    MissingPrevPacketId,
    #[error("prev_packet_chain_hash must not be empty")]
    EmptyChainHash,
    #[error("First packet (sequence 0) must not have prev_packet_chain_hash")]
    UnexpectedPrevChainHash,
    #[error("packets_in_series ({found}) does not match sequence + 1 ({expected})")]
    PacketCountMismatch { expected: u32, found: u32 },
}

/// Running totals across an Evidence series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSummary {
    pub total_checkpoints: u64,
    pub total_chars: u64,
    pub total_vdf_time_seconds: f64,
    /// Accumulated entropy in bits (f64 to avoid f32 precision loss over
    /// thousands of packets).
    pub total_entropy_bits: f64,
    /// Including current packet
    pub packets_in_series: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_elapsed_seconds: Option<f64>,
}

/// Continuation token linking an Evidence packet into a multi-packet series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSection {
    /// Stable across all packets in the series
    pub series_id: Uuid,
    /// Zero-indexed (first packet = 0)
    pub packet_sequence: u32,
    /// Required for `packet_sequence > 0`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_chain_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_id: Option<Uuid>,
    pub cumulative_summary: ContinuationSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_binding_signature: Option<String>,
}

impl ContinuationSection {
    /// Start a new series (sequence 0, no predecessor).
    pub fn new_series() -> Self {
        Self {
            series_id: Uuid::new_v4(),
            packet_sequence: 0,
            prev_packet_chain_hash: None,
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 1,
                series_started_at: Some(Utc::now()),
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        }
    }

    /// Build a continuation packet linked to the previous one.
    ///
    /// Returns `Err` if `prev_sequence` is `u32::MAX` (overflow).
    pub fn continue_from(
        prev_series_id: Uuid,
        prev_sequence: u32,
        prev_chain_hash: String,
        prev_packet_id: Uuid,
        prev_summary: &ContinuationSummary,
    ) -> Result<Self, ContinuationError> {
        let next_sequence = prev_sequence
            .checked_add(1)
            .ok_or(ContinuationError::SequenceOverflow)?;

        let next_packets = prev_summary
            .packets_in_series
            .checked_add(1)
            .ok_or(ContinuationError::PacketsInSeriesOverflow)?;

        Ok(Self {
            series_id: prev_series_id,
            packet_sequence: next_sequence,
            prev_packet_chain_hash: Some(prev_chain_hash),
            prev_packet_id: Some(prev_packet_id),
            cumulative_summary: ContinuationSummary {
                total_checkpoints: prev_summary.total_checkpoints,
                total_chars: prev_summary.total_chars,
                total_vdf_time_seconds: prev_summary.total_vdf_time_seconds,
                total_entropy_bits: prev_summary.total_entropy_bits,
                packets_in_series: next_packets,
                series_started_at: prev_summary.series_started_at,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        })
    }

    /// Accumulate this packet's statistics into the running totals.
    pub fn add_packet_stats(
        &mut self,
        checkpoints: u64,
        chars: u64,
        vdf_time: f64,
        entropy_bits: f64,
    ) {
        // Detect truncation *before* saturation to report how many were lost
        if let Some(new_checkpoints) = self
            .cumulative_summary
            .total_checkpoints
            .checked_add(checkpoints)
        {
            self.cumulative_summary.total_checkpoints = new_checkpoints;
        } else {
            let lost = checkpoints
                .saturating_sub(u64::MAX.saturating_sub(self.cumulative_summary.total_checkpoints));
            log::warn!(
                "checkpoint stats truncated: {} checkpoints lost, capping at u64::MAX",
                lost
            );
            self.cumulative_summary.total_checkpoints = u64::MAX;
        }

        if let Some(new_chars) = self.cumulative_summary.total_chars.checked_add(chars) {
            self.cumulative_summary.total_chars = new_chars;
        } else {
            let lost =
                chars.saturating_sub(u64::MAX.saturating_sub(self.cumulative_summary.total_chars));
            log::warn!(
                "char stats truncated: {} chars lost, capping at u64::MAX",
                lost
            );
            self.cumulative_summary.total_chars = u64::MAX;
        }

        if vdf_time.is_finite() {
            self.cumulative_summary.total_vdf_time_seconds += vdf_time;
        }
        if entropy_bits.is_finite() {
            self.cumulative_summary.total_entropy_bits += entropy_bits;
        }
    }

    /// Attach a series-binding signature.
    pub fn with_signature(mut self, signature: String) -> Self {
        self.series_binding_signature = Some(signature);
        self
    }

    /// Return true if this is the first packet in the series.
    pub fn is_first(&self) -> bool {
        self.packet_sequence == 0
    }

    /// Validate chain integrity: checks `prev_packet_chain_hash` presence
    /// and `packets_in_series` consistency.
    pub fn validate(&self) -> Result<(), ContinuationError> {
        if self.packet_sequence > 0 {
            if self.prev_packet_id.is_none() {
                return Err(ContinuationError::MissingPrevPacketId);
            }
            match &self.prev_packet_chain_hash {
                None => return Err(ContinuationError::MissingPrevChainHash),
                Some(h) if h.is_empty() => return Err(ContinuationError::EmptyChainHash),
                _ => {}
            }
        } else if self.prev_packet_chain_hash.is_some() {
            return Err(ContinuationError::UnexpectedPrevChainHash);
        }

        let expected = self
            .packet_sequence
            .checked_add(1)
            .ok_or(ContinuationError::SequenceOverflow)?;

        if self.cumulative_summary.packets_in_series != expected {
            return Err(ContinuationError::PacketCountMismatch {
                expected,
                found: self.cumulative_summary.packets_in_series,
            });
        }

        Ok(())
    }

    /// Generate VDF input binding this packet to previous chain hash + series
    /// identity.
    ///
    /// Encoding: every variable-length field is prefixed with its 4-byte
    /// big-endian length to prevent ambiguous concatenations. Fixed-size
    /// fields (`series_id` = 16 bytes, `packet_sequence` = 4 bytes) are
    /// appended without a prefix since their size is constant.
    pub fn generate_vdf_context(&self, content_hash: &[u8]) -> Vec<u8> {
        // Capacity: worst case prev_hash ~64 bytes + 4 prefix + content_hash ~32 + 4 prefix
        //           + series_id 16 + sequence 4 = ~124 bytes
        let mut context = Vec::with_capacity(256);

        if let Some(ref prev_hash) = self.prev_packet_chain_hash {
            let bytes = prev_hash.as_bytes();
            context.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            context.extend_from_slice(bytes);
        } else {
            context.extend_from_slice(&0u32.to_be_bytes());
        }

        // Length-prefix content_hash to prevent boundary ambiguity if hash
        // algorithm changes (e.g. SHA-256 32 bytes vs SHA-512 64 bytes).
        context.extend_from_slice(&(content_hash.len() as u32).to_be_bytes());
        context.extend_from_slice(content_hash);

        // Fixed-size fields: no prefix needed.
        context.extend_from_slice(self.series_id.as_bytes());
        context.extend_from_slice(&self.packet_sequence.to_be_bytes());

        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_series() {
        let section = ContinuationSection::new_series();
        assert_eq!(section.packet_sequence, 0);
        assert!(section.prev_packet_chain_hash.is_none());
        assert!(section.is_first());
        assert!(section.validate().is_ok());
    }

    #[test]
    fn test_continuation() {
        let first = ContinuationSection::new_series();

        let second = ContinuationSection::continue_from(
            first.series_id,
            first.packet_sequence,
            "chain_hash_abc".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        )
        .expect("continue_from should succeed");

        assert_eq!(second.packet_sequence, 1);
        assert!(!second.is_first());
        assert_eq!(second.series_id, first.series_id);
        assert_eq!(second.cumulative_summary.packets_in_series, 2);
        assert!(second.validate().is_ok());
    }

    #[test]
    fn test_continue_from_overflow() {
        let first = ContinuationSection::new_series();
        let result = ContinuationSection::continue_from(
            first.series_id,
            u32::MAX,
            "hash".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        );
        assert!(matches!(result, Err(ContinuationError::SequenceOverflow)));
    }

    #[test]
    fn test_invalid_first_packet() {
        let mut section = ContinuationSection::new_series();
        section.prev_packet_chain_hash = Some("should_not_exist".to_string());
        assert!(matches!(
            section.validate(),
            Err(ContinuationError::UnexpectedPrevChainHash)
        ));
    }

    #[test]
    fn test_invalid_continuation() {
        let section = ContinuationSection {
            series_id: Uuid::new_v4(),
            packet_sequence: 1,
            prev_packet_chain_hash: None,
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 2,
                series_started_at: None,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        };
        assert!(matches!(
            section.validate(),
            Err(ContinuationError::MissingPrevPacketId)
        ));
    }

    #[test]
    fn test_vdf_context_deterministic() {
        let section = ContinuationSection::new_series();
        let ctx1 = section.generate_vdf_context(b"test_content_hash");
        let ctx2 = section.generate_vdf_context(b"test_content_hash");
        assert_eq!(ctx1, ctx2);
        // zero sentinel (4) + content_hash length prefix (4) + content_hash (17) + series_id (16) + sequence (4) = 45
        assert_eq!(ctx1.len(), 45);
    }

    #[test]
    fn test_vdf_context_with_prev_hash() {
        let first = ContinuationSection::new_series();
        let second = ContinuationSection::continue_from(
            first.series_id,
            first.packet_sequence,
            "prev_chain".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        )
        .unwrap();

        let ctx = second.generate_vdf_context(b"content");
        // prev_hash prefix (4) + "prev_chain" (10) + content prefix (4) + "content" (7)
        // + series_id (16) + sequence (4) = 45
        assert_eq!(ctx.len(), 45);
    }

    #[test]
    fn test_vdf_context_no_boundary_ambiguity() {
        let section = ContinuationSection::new_series();
        let ctx_short = section.generate_vdf_context(b"ab");
        let ctx_long = section.generate_vdf_context(b"abc");
        // Different content_hash lengths must produce different contexts
        assert_ne!(ctx_short, ctx_long);
    }

    #[test]
    fn test_add_packet_stats_saturates() {
        let mut section = ContinuationSection::new_series();
        section.add_packet_stats(u64::MAX, 0, 0.0, 0.0);
        section.add_packet_stats(1, 0, 0.0, 0.0);
        assert_eq!(section.cumulative_summary.total_checkpoints, u64::MAX);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let section = ContinuationSection::new_series();
        let json = serde_json::to_string(&section).unwrap();
        let parsed: ContinuationSection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.series_id, section.series_id);
        assert_eq!(parsed.packet_sequence, section.packet_sequence);
        assert_eq!(
            parsed.cumulative_summary.packets_in_series,
            section.cumulative_summary.packets_in_series
        );
    }
}
