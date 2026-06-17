// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Builder setter methods (`with_*`) for attaching evidence layers.

use base64::{engine::general_purpose, Engine as _};
use sha2::Digest;

use crate::analysis::BehavioralFingerprint;
use crate::anchors;
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::jitter;
use crate::keyhierarchy;
use crate::platform::HidDeviceInfo;
use crate::presence;
use crate::evidence::provenance;
use crate::evidence::rfc_conversions::BiologyInvariantClaimExt;
use crate::tpm;
use crate::vdf;
use authorproof_protocol::rfc::{
    self, BiologyInvariantClaim, BiologyMeasurements, JitterBinding, TimeEvidence,
};

use super::helpers::convert_anchor_proof;
use super::{Builder, MAX_INTERVAL_US, MIN_JITTER_SAMPLES_FOR_BINDING, MIN_SAMPLES_FOR_HURST};
use crate::analysis::compute_hurst_rs;
use crate::evidence::types::*;

const JITTER_ENTROPY_DST: &[u8] = b"cpoe-jitter-entropy-v1";
const BINDING_MAC_KEY_DST: &[u8] = b"cpoe-binding-mac-key-v1";

#[cfg(feature = "cpoe_jitter")]
use super::HARDWARE_ENTROPY_RATIO_THRESHOLD;

impl Builder {
    /// Attach a signed author declaration. Fails silently if signature is invalid.
    pub fn with_declaration(mut self, decl: &declaration::Declaration) -> Self {
        if decl.verify().is_err() {
            self.errors
                .push("declaration signature invalid".to_string());
            return self;
        }
        self.packet.declaration = Some(decl.clone());
        self
    }

    /// Attach presence verification evidence.
    pub fn with_presence(mut self, sessions: &[presence::Session]) -> Self {
        if sessions.is_empty() {
            return self;
        }
        let evidence = presence::compile_evidence(sessions);
        self.packet.presence = Some(evidence);
        self
    }

    /// Attach TPM hardware attestation evidence.
    pub fn with_hardware(
        mut self,
        bindings: Vec<tpm::Binding>,
        device_id: String,
        attestation_nonce: Option<[u8; 32]>,
    ) -> Self {
        if bindings.is_empty() {
            return self;
        }
        self.packet.hardware = Some(HardwareEvidence {
            bindings,
            device_id,
            attestation_nonce,
        });
        self
    }

    /// Attach keystroke timing evidence.
    pub fn with_keystroke(mut self, evidence: jitter::Evidence) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors.push("keystroke evidence invalid".to_string());
            return self;
        }

        let plausible_human_rate = evidence.is_plausible_human_typing();

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id,
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate,
            samples: evidence.samples,
            typing_samples: Vec::new(),
            phys_ratio: None,
        };

        self.packet.keystroke = Some(keystroke);
        self
    }

    /// Attach pre-built keystroke evidence directly.
    pub fn with_keystroke_evidence(mut self, evidence: KeystrokeEvidence) -> Self {
        self.packet.keystroke = Some(evidence);
        self
    }

    /// Attach per-keystroke behavioral timing data (zone, dwell, flight) to
    /// the keystroke evidence. Must be called after `with_keystroke` or
    /// `with_hybrid_keystroke`.
    pub fn with_typing_samples(mut self, samples: Vec<jitter::SimpleJitterSample>) -> Self {
        if let Some(ref mut ks) = self.packet.keystroke {
            ks.typing_samples = samples;
        }
        self
    }

    /// Attach hybrid keystroke evidence with hardware entropy metrics.
    ///
    /// Boosts to `Enhanced` when `phys_ratio > 0.8`, indicating genuine
    /// hardware input rather than software injection.
    #[cfg(feature = "cpoe_jitter")]
    pub fn with_hybrid_keystroke(
        mut self,
        evidence: crate::cpoe_jitter_bridge::HybridEvidence,
    ) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors
                .push("hybrid keystroke evidence invalid".to_string());
            return self;
        }

        let plausible_human_rate = evidence.is_plausible_human_typing();
        let phys_ratio = evidence.entropy_quality.phys_ratio;

        let samples: Vec<jitter::Sample> = evidence
            .samples
            .into_iter()
            .map(|hs| jitter::Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id,
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate,
            samples,
            typing_samples: Vec::new(),
            phys_ratio: Some(phys_ratio),
        };

        self.packet.keystroke = Some(keystroke);

        if phys_ratio.is_finite() && phys_ratio > HARDWARE_ENTROPY_RATIO_THRESHOLD {
            self.add_claim(
                ClaimType::KeystrokesVerified,
                format!(
                    "Hardware entropy ratio {:.0}% - strong assurance of genuine input",
                    phys_ratio * 100.0
                ),
                "high",
            );
        }

        self
    }

    /// Attach behavioral edit topology and forensic metrics.
    pub fn with_behavioral(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
    ) -> Self {
        if regions.is_empty() && metrics.is_none() {
            return self;
        }
        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint: None,
            forgery_analysis: None,
            fingerprint_maturity: None,
            paste_content_breakdown: None,
        });
        self
    }

    /// Attach behavioral evidence with fingerprint and forgery analysis from jitter samples.
    pub fn with_behavioral_full(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
        samples: &[jitter::SimpleJitterSample],
    ) -> Self {
        if regions.is_empty() && metrics.is_none() && samples.len() < 2 {
            return self;
        }
        let fingerprint = if samples.len() >= 2 {
            Some(BehavioralFingerprint::from_samples(samples))
        } else {
            None
        };

        let forgery_analysis = if samples.len() >= 10 {
            Some(BehavioralFingerprint::detect_forgery(samples))
        } else {
            None
        };

        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint,
            forgery_analysis,
            fingerprint_maturity: None,
            paste_content_breakdown: None,
        });

        self
    }

    /// Set the fingerprint maturity stage on an existing `BehavioralEvidence` layer.
    ///
    /// Must be called after `with_behavioral` or `with_behavioral_full`.
    /// No-ops silently when no behavioral layer has been attached yet.
    pub fn with_fingerprint_maturity(
        mut self,
        maturity: crate::fingerprint::FingerprintMaturity,
    ) -> Self {
        if let Some(ref mut beh) = self.packet.behavioral {
            beh.fingerprint_maturity = Some(maturity);
        }
        self
    }

    /// Attach paste content breakdown to an existing `BehavioralEvidence` layer.
    ///
    /// Must be called after `with_behavioral` or `with_behavioral_full`.
    /// No-ops silently when no behavioral layer has been attached yet.
    pub fn with_paste_content_breakdown(
        mut self,
        breakdown: crate::forensics::PasteContentBreakdown,
    ) -> Self {
        if let Some(ref mut beh) = self.packet.behavioral {
            beh.paste_content_breakdown = Some(breakdown);
        }
        self
    }

    /// Attach context periods (focused, assisted, external).
    pub fn with_contexts(mut self, contexts: Vec<ContextPeriod>) -> Self {
        if contexts.is_empty() {
            return self;
        }
        self.packet.contexts = contexts;
        self
    }

    /// Attach record provenance (OS, build version, device info).
    pub fn with_provenance(mut self, prov: RecordProvenance) -> Self {
        self.packet.provenance = Some(prov);
        self
    }

    /// Populate `input_devices` in provenance from HID enumeration.
    ///
    /// Requires `with_provenance` to have been called first.
    pub fn with_input_devices(mut self, devices: &[HidDeviceInfo]) -> Self {
        if let Some(ref mut prov) = self.packet.provenance {
            prov.input_devices = devices.iter().map(InputDeviceInfo::from).collect();
        } else {
            self.errors
                .push("with_input_devices requires with_provenance to be called first".to_string());
        }
        self
    }

    /// Attach OpenTimestamps and RFC 3161 external timestamp anchors.
    pub fn with_external_anchors(mut self, ots: Vec<OtsProof>, rfc: Vec<Rfc3161Proof>) -> Self {
        if ots.is_empty() && rfc.is_empty() {
            return self;
        }
        self.packet.external = Some(ExternalAnchors {
            opentimestamps: ots,
            rfc3161: rfc,
            proofs: Vec::new(),
        });
        self
    }

    /// Attach anchor proofs (TSA, notary, etc.).
    pub fn with_anchors(mut self, proofs: &[anchors::Proof]) -> Self {
        if proofs.is_empty() {
            return self;
        }

        if self.packet.external.is_none() {
            self.packet.external = Some(ExternalAnchors {
                opentimestamps: Vec::new(),
                rfc3161: Vec::new(),
                proofs: Vec::new(),
            });
        }

        let ext = self
            .packet
            .external
            .as_mut()
            .expect("just ensured Some above");
        for proof in proofs {
            ext.proofs.push(convert_anchor_proof(proof));
        }

        self
    }

    /// Attach key hierarchy evidence (master key, ratchet chain, checkpoint sigs).
    pub fn with_key_hierarchy(
        mut self,
        evidence: keyhierarchy::KeyHierarchyEvidence,
    ) -> crate::error::Result<Self> {
        let master_public_key = hex::encode(&evidence.master_public_key);
        let session_public_key = hex::encode(&evidence.session_public_key);
        let session_certificate =
            general_purpose::STANDARD.encode(&evidence.session_certificate_raw);
        let ratchet_public_keys: Vec<String> = evidence
            .ratchet_public_keys
            .iter()
            .map(hex::encode)
            .collect();
        let checkpoint_signatures = evidence
            .checkpoint_signatures
            .iter()
            .enumerate()
            .map(|(idx, sig)| {
                Ok(CheckpointSignature {
                    ordinal: sig.ordinal,
                    checkpoint_hash: hex::encode(sig.checkpoint_hash),
                    // Source keyhierarchy::CheckpointSignature has no ratchet_index field;
                    // enumerate position matches ratchet chain order by construction.
                    ratchet_index: i32::try_from(idx).map_err(|_| {
                        crate::error::Error::evidence(format!(
                            "ratchet index {idx} exceeds i32::MAX"
                        ))
                    })?,
                    signature: general_purpose::STANDARD.encode(sig.signature),
                })
            })
            .collect::<crate::error::Result<Vec<_>>>()?;
        let session_document_hash = evidence
            .session_certificate
            .as_ref()
            .map(|cert| hex::encode(cert.document_hash));

        let packet = KeyHierarchyEvidencePacket {
            version: evidence.version,
            master_fingerprint: evidence.master_fingerprint,
            master_public_key,
            device_id: evidence.device_id,
            session_id: evidence.session_id,
            session_public_key,
            session_started: evidence.session_started,
            session_certificate,
            ratchet_count: evidence.ratchet_count,
            ratchet_public_keys,
            checkpoint_signatures,
            session_document_hash,
        };

        self.packet.key_hierarchy = Some(packet);
        Ok(self)
    }

    /// Attach provenance parent links for derivative works.
    pub fn with_provenance_links(mut self, section: provenance::ProvenanceSection) -> Self {
        if section.parent_links.is_empty() {
            return self;
        }
        self.packet.provenance_links = Some(section);
        self
    }

    /// Attach continuation section linking to a previous evidence packet.
    pub fn with_continuation(mut self, section: continuation::ContinuationSection) -> Self {
        self.packet.continuation = Some(section);
        self
    }

    /// Attach multi-author collaboration section.
    pub fn with_collaboration(mut self, section: collaboration::CollaborationSection) -> Self {
        if section.participants.is_empty() {
            return self;
        }
        self.packet.collaboration = Some(section);
        self
    }

    /// Attach aggregate VDF proof covering the entire chain.
    pub fn with_vdf_aggregate(mut self, proof: vdf::VdfAggregateProof) -> Self {
        self.packet.vdf_aggregate = Some(proof);
        self
    }

    /// Attach a pre-built jitter binding.
    pub fn with_jitter_binding(mut self, binding: JitterBinding) -> Self {
        self.packet.jitter_binding = Some(binding);
        self
    }

    /// Attach RFC-compliant time evidence (TSA, Roughtime).
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.packet.time_evidence = Some(evidence);
        self
    }

    /// Attach RFC-compliant biology invariant claim.
    ///
    /// Millibits scoring from Hurst exponent, pink noise (1/f), and error topology.
    pub fn with_biology_claim(mut self, claim: BiologyInvariantClaim) -> Self {
        self.packet.biology_claim = Some(claim);
        self
    }

    /// Attach physical context evidence for machine binding and non-repudiation.
    ///
    /// Captures clock skew, thermal proxy, silicon PUF fingerprint, and I/O latency
    /// to bind the evidence session to specific physical hardware.
    pub fn with_physical_context(mut self, ctx: &crate::physics::PhysicalContext) -> Self {
        self.packet.physical_context = Some(PhysicalContextEvidence {
            clock_skew: ctx.clock_skew,
            thermal_proxy: ctx.thermal_proxy,
            silicon_puf_hash: hex::encode(ctx.silicon_puf),
            io_latency_ns: ctx.io_latency_ns,
            combined_hash: hex::encode(ctx.combined_hash),
        });
        if ctx.is_virtualized {
            self.packet.limitations.push(
                "Virtualized environment detected; physical hardware measurements may be \
                 unreliable"
                    .to_string(),
            );
        }
        self
    }

    /// Build jitter binding from keystroke evidence.
    ///
    /// Computes entropy commitment, statistical summary, Hurst exponent,
    /// and forgery analysis. Pass `None` for `previous_commitment_hash`
    /// on the first binding in a chain.
    pub fn with_jitter_from_keystroke(
        mut self,
        keystroke: &KeystrokeEvidence,
        document_hash: &[u8; 32],
        previous_commitment_hash: Option<[u8; 32]>,
    ) -> Self {
        if keystroke.samples.len() < MIN_JITTER_SAMPLES_FOR_BINDING {
            self.errors
                .push("insufficient jitter samples for binding".to_string());
            return self;
        }

        let mut intervals_us: Vec<f64> = keystroke
            .samples
            .iter()
            // jitter_micros is i64; negative values filtered by the > 0.0 check below
            .map(|s| s.jitter_micros as f64)
            .filter(|&i| i > 0.0 && i < MAX_INTERVAL_US)
            .collect();

        if intervals_us.is_empty() {
            self.errors
                .push("no valid jitter intervals found".to_string());
            return self;
        }

        // Population variance (N divisor) used intentionally; the full interval set is the
        // population of interest, not a sample from a larger one.
        let (mean, std_dev) = crate::utils::stats::mean_and_std_dev(&intervals_us);
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // Hurst exponent needs original (unsorted) order, so compute before sorting.
        let hurst_exponent = if intervals_us.len() >= MIN_SAMPLES_FOR_HURST {
            compute_hurst_rs(&intervals_us).ok().map(|h| h.exponent)
        } else {
            None
        };

        // Percentile selection via in-place sort (safe now that Hurst is done)
        let percentiles = if intervals_us.len() >= 10 {
            intervals_us.sort_unstable_by(|a, b| a.total_cmp(b));
            let n = intervals_us.len();
            [
                intervals_us[n / 10],
                intervals_us[n / 4],
                intervals_us[n / 2],
                intervals_us[3 * n / 4],
                intervals_us[9 * n / 10],
            ]
        } else {
            [mean; 5] // too few samples for meaningful percentiles
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(JITTER_ENTROPY_DST);
        for s in &keystroke.samples {
            hasher.update(s.timestamp.timestamp_millis().to_be_bytes());
        }
        let entropy_hash: [u8; 32] = hasher.finalize().into();

        let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis().max(0)).unwrap_or(0);

        let binding = JitterBinding {
            entropy_commitment: rfc::EntropyCommitment {
                hash: entropy_hash,
                timestamp_ms,
                previous_hash: previous_commitment_hash.unwrap_or([0u8; 32]),
            },
            sources: vec![rfc::jitter_binding::SourceDescriptor {
                source_type: authorproof_protocol::rfc::SourceType::Other("keyboard".to_string()),
                weight: 1000,
                device_fingerprint: None,
                transport_calibration: None,
            }],
            summary: rfc::JitterSummary {
                sample_count: u64::try_from(intervals_us.len()).unwrap_or(0),
                mean_interval_us: mean,
                std_dev,
                coefficient_of_variation: cv,
                percentiles,
                // Uses filtered interval count (outliers removed) for conservative entropy estimate.
                // Raw keystroke.samples.len() would overestimate entropy from timeout gaps.
                // Conservative lower bound: log2(n-1) bits from n independent samples
                // (n samples yield n-1 intervals). True Shannon entropy depends on the
                // interval distribution, but log2(n-1) is a defensible minimum without
                // distribution assumptions.
                entropy_bits: {
                    let n = intervals_us.len() as f64;
                    if n > 1.0 {
                        (n - 1.0).log2()
                    } else {
                        0.0
                    }
                },
                hurst_exponent,
            },
            binding_mac: {
                use hkdf::Hkdf;
                use zeroize::Zeroizing;
                let hk = Hkdf::<sha2::Sha256>::new(None, &entropy_hash);
                let mut mac_key = Zeroizing::new([0u8; 32]);
                hk.expand(BINDING_MAC_KEY_DST, mac_key.as_mut())
                    .expect("32 bytes is valid HKDF-Expand length");
                rfc::BindingMac::compute(
                    mac_key.as_ref(),
                    *document_hash,
                    keystroke.total_keystrokes,
                    timestamp_ms,
                    &entropy_hash,
                )
            },
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        };

        self.packet.jitter_binding = Some(binding);
        self
    }

    /// Attach active probes (Galton invariant, reflex gate) to jitter binding.
    ///
    /// Requires a prior call to `with_jitter_from_keystroke` or `with_jitter_binding`.
    pub fn with_active_probes(
        mut self,
        probes: &crate::analysis::active_probes::ActiveProbeResults,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.active_probes = Some(probes.into());
        } else {
            self.errors
                .push("jitter_binding required before active_probes".to_string());
        }
        self
    }

    /// Attach labyrinth structure (Takens embedding) to jitter binding.
    ///
    /// Requires a prior call to `with_jitter_from_keystroke` or `with_jitter_binding`.
    pub fn with_labyrinth_structure(
        mut self,
        analysis: &crate::analysis::labyrinth::LabyrinthAnalysis,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.labyrinth_structure = Some(analysis.into());
        } else {
            self.errors
                .push("jitter_binding required before labyrinth_structure".to_string());
        }
        self
    }

    /// Build biology invariant claim from Hurst, pink noise, and error topology analyses.
    pub fn with_biology_from_analysis(
        mut self,
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> Self {
        let claim =
            BiologyInvariantClaim::from_analysis(measurements, hurst, pink_noise, error_topology);
        self.packet.biology_claim = Some(claim);
        self
    }

    /// Attach MMR root hash and range proof for append-only verification.
    pub fn with_mmr_proof(mut self, mmr_root: [u8; 32], range_proof: &[u8]) -> Self {
        self.packet.mmr_root = Some(hex::encode(mmr_root));
        self.packet.mmr_proof = Some(hex::encode(range_proof));
        self
    }

    /// Attach authorship baseline verification (digest + session summary).
    pub fn with_baseline_verification(
        mut self,
        bv: authorproof_protocol::baseline::BaselineVerification,
    ) -> Self {
        self.packet.baseline_verification = Some(bv);
        self
    }

    /// Set a verifier-supplied nonce for freshness binding.
    pub fn with_writersproof_nonce(mut self, nonce: [u8; 32]) -> Self {
        self.packet.verifier_nonce = Some(nonce);
        self
    }

    /// Attach a WritersProof certificate ID for third-party attestation binding.
    pub fn with_writersproof_certificate(mut self, certificate_id: String) -> Self {
        self.packet.writersproof_certificate_id = Some(certificate_id);
        self
    }

    /// Attach dictation events with plausibility scoring.
    ///
    /// Each event is scored via `forensics::dictation::score_dictation_plausibility`.
    /// If any event scores above 0.7, strength is boosted to at least `Enhanced`.
    pub fn with_dictation_events(mut self, events: Vec<DictationEvent>) -> Self {
        if events.is_empty() {
            return self;
        }
        let mut scored = events;
        for event in &mut scored {
            if event.plausibility_score <= 0.0 || event.plausibility_score.is_nan() {
                event.plausibility_score =
                    crate::forensics::dictation::score_dictation_plausibility(event);
            }
        }
        self.packet.dictation_events = scored;
        self
    }

    /// Attach a WritersProof temporal beacon attestation.
    pub fn with_beacon_attestation(mut self, beacon: WpBeaconAttestation) -> Self {
        self.packet.beacon_attestation = Some(beacon);
        self
    }

    pub fn with_export_attestation(mut self, attestation: super::ManuscriptExportAttestation) -> Self {
        self.packet.export_attestation = Some(attestation);
        self
    }

    pub fn with_document_structure(mut self, snapshot: super::DocumentStructureSnapshot) -> Self {
        self.packet.document_structure = Some(snapshot);
        self
    }
}
