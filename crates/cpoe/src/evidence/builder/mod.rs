// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence packet builder with validation and claim generation.

mod helpers;
mod setters;

use std::time::Duration;

use crate::checkpoint;
use crate::error::Error;

use super::types::*;

pub use self::helpers::{
    build_ephemeral_packet, compute_events_binding_hash, convert_anchor_proof, EphemeralSnapshot,
};

/// Minimum number of jitter samples required to compute a jitter binding.
pub(super) const MIN_JITTER_SAMPLES_FOR_BINDING: usize = 10;

/// Maximum inter-keystroke interval in microseconds (5 seconds).
/// Intervals beyond this are treated as outliers and filtered out.
pub(super) const MAX_INTERVAL_US: f64 = 5_000_000.0;

/// Minimum number of interval samples for R/S Hurst exponent analysis.
pub(super) const MIN_SAMPLES_FOR_HURST: usize = 20;

/// Minimum hardware entropy ratio (phys_ratio) to qualify as genuine human input.
/// Above this threshold, a high-confidence claim is added for hardware entropy.
#[cfg(feature = "cpoe_jitter")]
pub(super) const HARDWARE_ENTROPY_RATIO_THRESHOLD: f64 = 0.8;

/// Accumulate evidence layers into a signed evidence packet.
#[derive(Debug)]
pub struct Builder {
    pub(super) packet: Packet,
    pub(super) errors: Vec<String>,
}

impl Builder {
    /// Create a builder from a document title and checkpoint chain.
    pub fn new(title: &str, chain: &checkpoint::Chain) -> Self {
        let mut packet = Packet {
            document: DocumentInfo {
                title: title.to_string(),
                path: chain.metadata.document_path.clone(),
                final_hash: String::new(),
                final_size: 0,
            },
            checkpoints: Vec::with_capacity(chain.checkpoints.len()),
            vdf_params: chain.metadata.vdf_params,
            ..Default::default()
        };

        if let Some(latest) = chain.latest() {
            packet.document.final_hash = hex::encode(latest.content_hash);
            packet.document.final_size = latest.content_size;
        }

        for cp in &chain.checkpoints {
            let mut proof = CheckpointProof {
                ordinal: cp.ordinal,
                content_hash: hex::encode(cp.content_hash),
                content_size: cp.content_size,
                timestamp: cp.timestamp,
                message: cp.message.clone(),
                vdf_input: None,
                vdf_output: None,
                vdf_iterations: None,
                elapsed_time: None,
                previous_hash: hex::encode(cp.previous_hash),
                hash: hex::encode(cp.hash),
                signature: None,
            };

            if let Some(sig) = &cp.signature {
                proof.signature = Some(hex::encode(sig));
            }

            if let Some(vdf_proof) = &cp.vdf {
                proof.vdf_input = Some(hex::encode(vdf_proof.input));
                proof.vdf_output = Some(hex::encode(vdf_proof.output));
                proof.vdf_iterations = Some(vdf_proof.iterations);
                proof.elapsed_time = Some(vdf_proof.min_elapsed_time(chain.metadata.vdf_params));
            }

            packet.checkpoints.push(proof);
        }

        if let Some(latest) = chain.latest() {
            packet.chain_hash = hex::encode(latest.hash);
        }

        Self {
            packet,
            errors: Vec::new(),
        }
    }

    pub(super) fn add_claim(
        &mut self,
        claim_type: ClaimType,
        description: impl Into<String>,
        confidence: &str,
    ) {
        self.packet.claims.push(Claim {
            claim_type,
            description: description.into(),
            confidence: confidence.to_string(),
        });
    }

    /// Finalize the packet, generating claims, limitations, and trust tier.
    pub fn build(mut self) -> crate::error::Result<Packet> {
        if self.packet.declaration.is_none() {
            self.errors.push("declaration is required".to_string());
        }
        if !self.errors.is_empty() {
            return Err(Error::evidence(format!("build errors: {:?}", self.errors)));
        }

        // Cross-verify RFC 3161 and Roughtime anchors when both are present.
        // 180s tolerance accommodates the sequential fetch order; tighter than
        // the default to catch clock-skew forgery at evidence assembly time.
        if let Some(te) = &self.packet.time_evidence {
            if let (Some(tsas), Some(roughtimes)) = (&te.tsa_responses, &te.roughtime_samples) {
                if let (Some(tsa), Some(rt)) = (tsas.first(), roughtimes.first()) {
                    let rfc3161_secs = (tsa.timestamp_ms / 1000) as i64;
                    let roughtime_secs = (rt.midpoint_us / 1_000_000) as i64;
                    crate::anchors::verify_dual_anchor(rfc3161_secs, roughtime_secs, 180).map_err(
                        |e| Error::evidence(format!("dual-anchor cross-verification failed: {e}")),
                    )?;
                }
            }
        }

        self.generate_claims();
        self.generate_limitations();
        self.packet.trust_tier = Some(self.packet.compute_trust_tier());
        Ok(self.packet)
    }

    fn generate_claims(&mut self) {
        self.add_chain_integrity_claims();
        self.add_temporal_claims();
        self.add_declaration_claims();
        self.add_behavioral_claims();
        self.add_hardware_claims();
        self.add_context_claims();
        self.add_identity_claims();
    }

    fn add_chain_integrity_claims(&mut self) {
        self.add_claim(
            ClaimType::ChainIntegrity,
            "Content states form an unbroken cryptographic chain",
            "cryptographic",
        );
    }

    fn add_temporal_claims(&mut self) {
        let mut total_time = Duration::from_secs(0);
        for cp in &self.packet.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total_time += elapsed;
            }
        }
        if total_time > Duration::from_secs(0) {
            self.add_claim(
                ClaimType::TimeElapsed,
                format!(
                    "At least {:?} elapsed during documented composition",
                    total_time
                ),
                "cryptographic",
            );
        }
    }

    fn add_declaration_claims(&mut self) {
        if let Some(decl) = &self.packet.declaration {
            let ai_desc = if decl.has_ai_usage() {
                format!(
                    "AI assistance declared: {} extent",
                    crate::declaration::ai_extent_str(&decl.max_ai_extent())
                )
            } else {
                "No AI tools declared".to_string()
            };
            self.add_claim(
                ClaimType::ProcessDeclared,
                format!("Author signed declaration of creative process. {ai_desc}"),
                "attestation",
            );
        }
    }

    fn add_behavioral_claims(&mut self) {
        if let Some(presence) = &self.packet.presence {
            self.add_claim(
                ClaimType::PresenceVerified,
                format!(
                    "Author presence verified {:.0}% of challenged sessions",
                    presence.overall_rate * 100.0
                ),
                "cryptographic",
            );
        }

        if let Some(keystroke) = &self.packet.keystroke {
            let mut desc = format!(
                "{} keystrokes recorded over {:?} ({:.0}/min)",
                keystroke.total_keystrokes, keystroke.duration, keystroke.keystrokes_per_minute
            );
            if keystroke.plausible_human_rate {
                desc.push_str(", consistent with human typing");
            }
            self.add_claim(ClaimType::KeystrokesVerified, desc, "cryptographic");
        }

        if self.packet.behavioral.is_some() {
            self.add_claim(
                ClaimType::BehaviorAnalyzed,
                "Edit patterns captured for forensic analysis",
                "statistical",
            );
        }

        if !self.packet.dictation_events.is_empty() {
            let total_words: u32 = self
                .packet
                .dictation_events
                .iter()
                .map(|d| d.word_count)
                .sum();
            let sum: f64 = self
                .packet
                .dictation_events
                .iter()
                .map(|d| {
                    if d.plausibility_score.is_finite() {
                        d.plausibility_score
                    } else {
                        0.0
                    }
                })
                .sum();
            let count = self.packet.dictation_events.len() as f64;
            let avg_plausibility = if count == 0.0 { 0.0 } else { sum / count };
            self.add_claim(
                ClaimType::DictationVerified,
                format!(
                    "{} dictation segment(s), {} words, avg plausibility {:.0}%",
                    self.packet.dictation_events.len(),
                    total_words,
                    avg_plausibility * 100.0
                ),
                if avg_plausibility > 0.7 {
                    "high"
                } else {
                    "medium"
                },
            );
        }
    }

    fn add_hardware_claims(&mut self) {
        if self.packet.hardware.is_some() {
            self.add_claim(
                ClaimType::HardwareAttested,
                "TPM attests chain was not rolled back or modified",
                "cryptographic",
            );
        }

        // Both physical_context and hardware use HardwareAttested; future: add
        // PhysicalContextCaptured variant to distinguish the two claim sources.
        if self.packet.physical_context.is_some() {
            self.add_claim(
                ClaimType::HardwareAttested,
                "Physical context captured: clock skew, thermal proxy, silicon PUF, I/O latency",
                "high",
            );
        }
    }

    fn add_context_claims(&mut self) {
        if !self.packet.contexts.is_empty() {
            let mut assisted = 0;
            let mut external = 0;
            for ctx in &self.packet.contexts {
                if ctx.period_type == ContextPeriodType::Assisted {
                    assisted += 1;
                }
                if ctx.period_type == ContextPeriodType::External {
                    external += 1;
                }
            }
            let mut desc = format!("{} context periods recorded", self.packet.contexts.len());
            if assisted > 0 {
                desc.push_str(&format!(" ({assisted} AI-assisted)"));
            }
            if external > 0 {
                desc.push_str(&format!(" ({external} external)"));
            }
            self.add_claim(ClaimType::ContextsRecorded, desc, "attestation");
        }

        if let Some(external) = &self.packet.external {
            let count =
                external.opentimestamps.len() + external.rfc3161.len() + external.proofs.len();
            self.add_claim(
                ClaimType::ExternalAnchored,
                format!("Chain anchored to {count} external timestamp authorities"),
                "cryptographic",
            );
        }
    }

    fn add_identity_claims(&mut self) {
        if let Some(kh) = &self.packet.key_hierarchy {
            let mut desc = format!(
                "Identity {} with {} ratchet generations",
                if kh.master_fingerprint.len() > 16 {
                    // Fingerprints are hex-encoded (ASCII-only), safe to slice
                    format!(
                        "{}...",
                        &kh.master_fingerprint[..kh
                            .master_fingerprint
                            .char_indices()
                            .nth(16)
                            .map_or(kh.master_fingerprint.len(), |(i, _)| i)]
                    )
                } else {
                    kh.master_fingerprint.clone()
                },
                kh.ratchet_count
            );
            if !kh.checkpoint_signatures.is_empty() {
                desc.push_str(&format!(
                    ", {} checkpoint signatures",
                    kh.checkpoint_signatures.len()
                ));
            }
            self.add_claim(ClaimType::KeyHierarchy, desc, "cryptographic");
        }
    }

    fn generate_limitations(&mut self) {
        self.packet
            .limitations
            .push("Cannot prove cognitive origin of ideas".to_string());
        self.packet
            .limitations
            .push("Cannot prove absence of AI involvement in ideation".to_string());

        if self.packet.presence.is_none() {
            self.packet.limitations.push(
                "No presence verification - cannot confirm human was at keyboard".to_string(),
            );
        }

        if self.packet.keystroke.is_none() {
            self.packet
                .limitations
                .push("No keystroke evidence - cannot verify real typing occurred".to_string());
        }

        if self.packet.hardware.is_none() {
            self.packet
                .limitations
                .push("No hardware attestation - software-only security".to_string());
        }

        if let Some(decl) = &self.packet.declaration {
            if decl.has_ai_usage() {
                self.packet.limitations.push(
                    "Author declares AI tool usage - verify institutional policy compliance"
                        .to_string(),
                );
            }
        }
    }
}
