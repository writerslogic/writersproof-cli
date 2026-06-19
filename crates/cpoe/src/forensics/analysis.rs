// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Main orchestration functions for forensic analysis.

use chrono::DateTime;
use std::collections::HashMap;

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;
use crate::utils::stats::mean_and_std_dev;
use crate::utils::Probability;

use super::assessment::{
    apply_focus_penalties, compute_assessment_score, detect_anomalies, determine_assessment,
    determine_risk_level,
};
use super::cadence::analyze_cadence;
use super::topology::compute_primary_metrics;
use super::types::{
    Assessment, AuthorshipProfile, EventData, ForensicMetrics, RegionData, SortedEvents,
    DEFAULT_SESSION_GAP_SEC, MIN_EVENTS_FOR_ANALYSIS,
};
use super::velocity::{compute_session_stats, count_sessions_sorted};

use super::types::{AnalysisKind, CheckpointFlags, FocusMetrics, PerCheckpointResult};

/// Fork-join 3 closures on the rayon thread pool.
macro_rules! par_join3 {
    ($a:expr, $b:expr, $c:expr) => {{
        let (a, (b, c)) = rayon::join($a, || rayon::join($b, $c));
        (a, b, c)
    }};
}

/// Fork-join 7 closures on the rayon thread pool.
macro_rules! par_join7 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr) => {{
        let ((a, b, c), (d, e, f, g)) = rayon::join(
            || par_join3!($a, $b, $c),
            || {
                let ((d, e), (f, g)) = rayon::join(
                    || rayon::join($d, $e),
                    || rayon::join($f, $g),
                );
                (d, e, f, g)
            },
        );
        (a, b, c, d, e, f, g)
    }};
}
use crate::analysis::labyrinth::{analyze_labyrinth, LabyrinthParams};
use crate::analysis::{analyze_iki_compression, analyze_lyapunov, analyze_snr};
use crate::evidence::CheckpointProof;
use crate::sentinel::types::FocusSwitchRecord;

const PERPLEXITY_ANOMALY_THRESHOLD: f64 = 15.0;
/// Anomaly count above which expensive analyses (SNR, Lyapunov, Labyrinth, CLC)
/// are skipped — the session is already clearly anomalous.
const EARLY_EXIT_ANOMALY_THRESHOLD: usize = 5;
const MIN_IKI_FOR_HURST: usize = 50;
const STEG_LOW_CONF: f64 = 0.3;
const STEG_HIGH_CONF: f64 = 0.95;
const STEG_PENALTY: f64 = 0.20;
const STEG_ALERT_THRESHOLD: f64 = 0.8;
const MIN_IKI_FOR_LABYRINTH: usize = 50;
pub(crate) const PER_CHECKPOINT_SUSPICIOUS_THRESHOLD: f64 = 0.3;
const PER_CHECKPOINT_ROBOTIC_CV: f64 = 0.10;

/// Minimum plausible timestamp (2000-01-01 in nanoseconds).
const MIN_PLAUSIBLE_TS_NS: i64 = 946_684_800_000_000_000;
/// Maximum plausible timestamp (2100-01-01 in nanoseconds).
const MAX_PLAUSIBLE_TS_NS: i64 = 4_102_444_800_000_000_000;

/// Split text into sliding windows of approximately `window_chars` characters.
fn split_into_windows(text: &str, window_chars: usize) -> Vec<String> {
    if window_chars == 0 || text.is_empty() {
        return Vec::new();
    }

    let chars: Vec<char> = text.chars().collect();
    let mut windows = Vec::new();

    for i in (0..chars.len()).step_by((window_chars / 2).max(1)) {
        let end = (i + window_chars).min(chars.len());
        let window: String = chars[i..end].iter().collect();
        if !window.is_empty() {
            windows.push(window);
        }
        if end >= chars.len() {
            break;
        }
    }

    windows
}

pub fn build_profile(
    events: &[EventData],
    regions_by_event: &HashMap<i64, Vec<RegionData>>,
) -> AuthorshipProfile {
    if events.len() < MIN_EVENTS_FOR_ANALYSIS {
        return AuthorshipProfile {
            event_count: events.len(),
            assessment: Assessment::Insufficient,
            ..Default::default()
        };
    }

    // Clone + sort is required because the function takes &[EventData] (shared
    // reference) and callers rely on the original order being preserved.
    let mut sorted = events.to_vec();
    sorted.sort_unstable_by_key(|e| e.timestamp_ns);

    // Clamp implausible timestamps to prevent corrupt time_span calculations
    for event in &mut sorted {
        event.timestamp_ns = event
            .timestamp_ns
            .clamp(MIN_PLAUSIBLE_TS_NS, MAX_PLAUSIBLE_TS_NS);
    }

    let file_path = sorted
        .first()
        .map(|e| e.file_path.clone())
        .unwrap_or_default();
    let first_ts =
        DateTime::from_timestamp_nanos(sorted.first().map(|e| e.timestamp_ns).unwrap_or(0));
    let last_ts =
        DateTime::from_timestamp_nanos(sorted.last().map(|e| e.timestamp_ns).unwrap_or(0));
    let time_span = last_ts.signed_duration_since(first_ts);

    let sorted_ev = SortedEvents::new(&sorted);
    let session_count = count_sessions_sorted(sorted_ev, DEFAULT_SESSION_GAP_SEC);

    let metrics = match compute_primary_metrics(sorted_ev, regions_by_event) {
        Ok(m) => m,
        Err(_) => {
            return AuthorshipProfile {
                file_path,
                event_count: events.len(),
                time_span,
                session_count,
                first_event: first_ts,
                last_event: last_ts,
                assessment: Assessment::Insufficient,
                ..Default::default()
            };
        }
    };

    let anomalies = detect_anomalies(sorted_ev, regions_by_event, &metrics);
    let assessment = determine_assessment(&metrics, &anomalies, events.len());

    AuthorshipProfile {
        file_path,
        event_count: events.len(),
        time_span,
        session_count,
        first_event: first_ts,
        last_event: last_ts,
        metrics,
        anomalies,
        assessment,
    }
}

#[derive(Debug, Default)]
pub struct AnalysisContext {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub checkpoint_count: u64,
    /// Attestation tier for the session. When `Some(SoftwareFallback)`, a
    /// −0.25 penalty is applied to the assessment score.
    pub attestation_tier: Option<crate::tpm::AttestationTier>,
    /// VDF Merkle root for deriving session-unique labyrinth embedding
    /// parameters. When present, the phase-space (dim, delay) are derived
    /// from this root, forcing an attacker to re-run the VDF for each
    /// forgery attempt. When absent, default embedding params are used.
    pub vdf_merkle_root: Option<[u8; 32]>,
    /// Cross-window transcription matches detected during the session.
    pub cross_window_matches: Vec<crate::transcription::CrossWindowMatch>,
    /// Stored behavioral fingerprint baseline for comparison.
    pub baseline_fingerprint: Option<BehavioralFingerprint>,
}

pub fn analyze_forensics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
) -> ForensicMetrics {
    analyze_forensics_ext(
        events,
        regions,
        jitter_samples,
        perplexity_model,
        document_text,
        &AnalysisContext::default(),
    )
}

pub fn analyze_forensics_ext(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
    context: &AnalysisContext,
) -> ForensicMetrics {
    analyze_forensics_ext_with_focus(
        events,
        regions,
        jitter_samples,
        perplexity_model,
        document_text,
        context,
        None,
    )
}

pub fn analyze_forensics_ext_with_focus(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
    context: &AnalysisContext,
    focus_metrics: Option<FocusMetrics>,
) -> ForensicMetrics {
    let mut metrics = ForensicMetrics::default();

    // Sort once at pipeline entry; all analyzers receive the sorted invariant.
    // Avoid cloning when the input is already sorted AND timestamps are plausible.
    let already_sorted = events
        .windows(2)
        .all(|w| w[0].timestamp_ns <= w[1].timestamp_ns);
    let needs_clamp = events
        .iter()
        .any(|e| e.timestamp_ns < MIN_PLAUSIBLE_TS_NS || e.timestamp_ns > MAX_PLAUSIBLE_TS_NS);
    let owned_buf: Vec<EventData>;
    let sorted = if already_sorted && !needs_clamp {
        SortedEvents::new(events)
    } else {
        owned_buf = {
            let mut buf = events.to_vec();
            if needs_clamp {
                for event in &mut buf {
                    event.timestamp_ns = event
                        .timestamp_ns
                        .clamp(MIN_PLAUSIBLE_TS_NS, MAX_PLAUSIBLE_TS_NS);
                }
            }
            buf.sort_unstable_by_key(|e| e.timestamp_ns);
            buf
        };
        SortedEvents::new(&owned_buf)
    };

    // ── Batch A: independent pre-analysis probes (rayon parallel) ──────
    // primary_metrics, biological_cadence, and behavioral_fingerprint+forgery
    // are read-only over different inputs with no inter-dependencies.
    let (primary_r, bio_r, behav_r) = par_join3!(
        || compute_primary_metrics(sorted, regions),
        || jitter_samples.map(crate::physics::biological::BiologicalCadence::analyze),
        || {
            jitter_samples.map(|s| {
                let fp = BehavioralFingerprint::from_samples(s);
                let fg = BehavioralFingerprint::detect_forgery(s);
                (fp, fg)
            })
        }
    );

    if let Ok(primary) = primary_r {
        metrics.primary = primary;
        metrics.analysis_status.mark_completed(AnalysisKind::PrimaryMetrics);
    } else {
        metrics.analysis_status.mark_failed(AnalysisKind::PrimaryMetrics);
    }

    if let Some(bio_score) = bio_r {
        metrics.biological_cadence_score = Probability::clamp(bio_score);
        metrics.analysis_status.mark_completed(AnalysisKind::BiologicalCadence);
    }

    if let Some((fingerprint, forgery)) = behav_r {
        if let (Some(ref baseline), _) = (&context.baseline_fingerprint, &fingerprint) {
            metrics.baseline_comparison = fingerprint.compare_to_baseline(baseline);
        }
        metrics.behavioral = Some(fingerprint);
        metrics.analysis_status.mark_completed(AnalysisKind::Behavioral);
        metrics.forgery_analysis = Some(forgery);
    }

    // Active probes analysis (Galton invariant + reflex gate)
    metrics.active_probes = if let Some(samples) = jitter_samples {
        let probe_samples: Vec<crate::analysis::ProbeSample> = samples.iter()
            .map(|s| crate::analysis::ProbeSample {
                timestamp_ns: s.timestamp_ns,
                interval_ms: s.duration_since_last_ns as f64 / 1_000_000.0,
                is_perturbed: false,
                is_stimulus_response: s.duration_since_last_ns > 0,
            })
            .collect();
        if probe_samples.len() >= 30 {
            let mut ikis: Vec<f64> = samples.iter()
                .map(|s| s.duration_since_last_ns as f64 / 1_000_000.0)
                .filter(|&v| v > 0.0)
                .collect();
            ikis.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let baseline = ikis.get(ikis.len() / 2).copied().unwrap_or(150.0);
            let galton = crate::analysis::analyze_galton_invariant(&probe_samples, baseline).ok();
            let reflex = crate::analysis::analyze_reflex_gate(&probe_samples).ok();
            Some(crate::analysis::ActiveProbeResults::combine(galton, reflex))
        } else {
            None
        }
    } else {
        None
    };

    // Language classification scores
    if let Some(text) = document_text {
        if text.len() >= 50 {
            metrics.language_scores = Some(crate::analysis::LanguageClassifier::default().score_all(text));
        }
    }

    // Perplexity (trivial cost, sequential)
    if let (Some(model), Some(text)) = (perplexity_model, document_text) {
        let score = model.perplexity_or_default(text);
        metrics.perplexity_score = if score.is_finite() {
            metrics.analysis_status.mark_completed(AnalysisKind::Perplexity);
            score
        } else {
            log::warn!("perplexity_score is non-finite ({score}); substituting 1.0");
            metrics.analysis_status.mark_failed(AnalysisKind::Perplexity);
            1.0
        };
        if metrics.perplexity_score > PERPLEXITY_ANOMALY_THRESHOLD {
            metrics.anomaly_count += 1;
        }
    } else {
        metrics.perplexity_score = 1.0;
    }

    // AI fluency detection via word-trigram perplexity
    if let Some(text) = document_text {
        if text.len() >= 100 {
            let mut model = crate::analysis::perplexity::WordTrigramModel::new();
            model.train(text);
            metrics.ai_fluency_flag = model.is_suspiciously_fluent(text);
        }
    }

    // ── Cadence + IKI (sequential — downstream steg/entropy depend on it) ─
    if let Some(samples) = jitter_samples {
        metrics.cadence = analyze_cadence(samples);
        metrics.analysis_status.mark_completed(AnalysisKind::Cadence);

        let iki_intervals: Vec<f64> = samples
            .windows(2)
            .filter_map(|w| {
                w[1].timestamp_ns
                    .checked_sub(w[0].timestamp_ns)
                    .map(|d| d as f64)
            })
            .filter(|&d| d > 0.0)
            .collect();
        if iki_intervals.len() >= 2 {
            metrics.typing_metrics =
                Some(super::types::TypingMetrics::from_iki_ns(&iki_intervals));
        }

        // Per-type entropy (draft-condrey-rats-pop spec compliance).
        if iki_intervals.len() >= 10 {
            let mut timing_hist = [0usize; 20];
            for &iki_ns in &iki_intervals {
                let iki_ms = iki_ns / 1_000_000.0;
                let bin = if iki_ms <= 0.0 {
                    0
                } else {
                    ((iki_ms / 10.0).log2() * 2.0).floor().clamp(0.0, 19.0) as usize
                };
                timing_hist[bin] += 1;
            }
            metrics.primary.timing_entropy =
                super::topology::shannon_entropy(&timing_hist);

            let pause_threshold_ns = 1_000_000_000.0;
            let pauses: Vec<f64> = iki_intervals
                .iter()
                .copied()
                .filter(|&d| d >= pause_threshold_ns)
                .collect();
            if pauses.len() >= 3 {
                let mut pause_hist = [0usize; 10];
                for &p in &pauses {
                    let p_sec = p / 1_000_000_000.0;
                    let bin = ((p_sec - 1.0).max(0.0).floor() as usize).min(9);
                    pause_hist[bin] += 1;
                }
                metrics.primary.pause_entropy =
                    super::topology::shannon_entropy(&pause_hist);
            }
        }

        if iki_intervals.len() >= MIN_IKI_FOR_HURST {
            if let Ok(hurst) = crate::analysis::hurst::compute_hurst_rs(&iki_intervals) {
                metrics.hurst_exponent = Some(hurst.exponent);
                metrics.analysis_status.mark_completed(AnalysisKind::Hurst);
            } else {
                metrics.analysis_status.mark_failed(AnalysisKind::Hurst);
            }
        }

        // Steg confidence from cadence CV
        let cv = metrics.cadence.coefficient_of_variation;
        metrics.steg_confidence = Probability::clamp(if samples.len() < 2 || !cv.is_finite() {
            0.0
        } else if cv > STEG_LOW_CONF {
            STEG_HIGH_CONF
        } else {
            STEG_PENALTY
        });

        // Steg looks valid but behavioral is suspicious — likely a perfect replay attack
        if let Some(ref forgery) = metrics.forgery_analysis {
            if forgery.is_suspicious && metrics.steg_confidence > STEG_ALERT_THRESHOLD {
                metrics.anomaly_count += 1;
            }
        }

        // ── Batch B: expensive IKI probes (rayon parallel, gated) ────────
        if metrics.anomaly_count < EARLY_EXIT_ANOMALY_THRESHOLD {
            let run_labyrinth = iki_intervals.len() >= MIN_IKI_FOR_LABYRINTH;
            let file_sizes: Vec<i64> = events.iter().map(|e| e.file_size).collect();

            // All seven probes are independent reads over iki_intervals/samples.
            let (snr_r, lyap_r, comp_r, lab_r, clc_r, repair_r, fatigue_r) = par_join7!(
                || analyze_snr(&iki_intervals),
                || analyze_lyapunov(&iki_intervals),
                || analyze_iki_compression(&iki_intervals),
                || {
                    if run_labyrinth {
                        let params = if let Some(root) = context.vdf_merkle_root {
                            use sha2::{Sha256, Digest};
                            let derived = Sha256::new()
                                .chain_update(b"cpoe-takens-embedding-v1")
                                .chain_update(root)
                                .finalize();
                            LabyrinthParams {
                                max_embedding_dim: 3 + (derived[0] as usize % 8), // 3..10
                                max_delay: 2 + (derived[1] as usize % 19),        // 2..20
                                ..LabyrinthParams::default()
                            }
                        } else {
                            LabyrinthParams::default()
                        };
                        Some(analyze_labyrinth(&iki_intervals, &[], &params))
                    } else {
                        None
                    }
                },
                || {
                    document_text.and_then(|text| {
                        let windows = split_into_windows(text, 100);
                        if windows.is_empty() {
                            None
                        } else {
                            super::advanced_metrics::compute_clc_metrics(&windows, samples)
                        }
                    })
                },
                || super::advanced_metrics::analyze_repair_locality(samples, &file_sizes),
                || super::advanced_metrics::analyze_fatigue_trajectory(samples)
            );

            // Merge SNR
            match snr_r {
                Ok(snr) => {
                    if snr.flagged {
                        metrics.anomaly_count += 1;
                    }
                    metrics.snr = Some(snr);
                    metrics.analysis_status.mark_completed(AnalysisKind::Snr);
                }
                Err(e) => {
                    log::debug!("SNR analysis skipped: {}", e);
                    metrics.analysis_status.mark_failed(AnalysisKind::Snr);
                }
            }

            // Merge Lyapunov
            match lyap_r {
                Ok(lyap) => {
                    if lyap.flagged {
                        metrics.anomaly_count += 1;
                    }
                    metrics.lyapunov = Some(lyap);
                    metrics.analysis_status.mark_completed(AnalysisKind::Lyapunov);
                }
                Err(e) => {
                    log::debug!("Lyapunov analysis skipped: {}", e);
                    metrics.analysis_status.mark_failed(AnalysisKind::Lyapunov);
                }
            }

            // Merge IKI compression
            match comp_r {
                Ok(comp) => {
                    if comp.flagged {
                        metrics.anomaly_count += 1;
                    }
                    metrics.iki_compression = Some(comp);
                    metrics.analysis_status.mark_completed(AnalysisKind::IkiCompression);
                }
                Err(e) => {
                    log::debug!("IKI compression analysis skipped: {}", e);
                    metrics.analysis_status.mark_failed(AnalysisKind::IkiCompression);
                }
            }

            // Merge Labyrinth
            if let Some(Ok(lab)) = lab_r {
                if !lab.is_biologically_plausible() {
                    metrics.anomaly_count += 1;
                }
                metrics.labyrinth = Some(lab);
                metrics.analysis_status.mark_completed(AnalysisKind::Labyrinth);
            } else if let Some(Err(_)) = lab_r {
                metrics.analysis_status.mark_failed(AnalysisKind::Labyrinth);
            }

            // Merge CLC
            if let Some(clc) = clc_r {
                metrics.cadence.clc_surprisal_score = Some(clc.mean_surprisal_bpw);
                metrics.clc_metrics = Some(clc);
                metrics.analysis_status.mark_completed(AnalysisKind::Clc);
            }

            // Merge repair locality
            if let Some(repair) = repair_r {
                metrics.cadence.repair_locality_mean_offset = Some(repair.mean_offset_chars);
                metrics.cadence.repair_locality_cv = Some(repair.offset_cv);
                metrics.repair_locality = Some(repair);
                metrics.analysis_status.mark_completed(AnalysisKind::RepairLocality);
            }

            // Merge fatigue
            if let Some(fatigue) = fatigue_r {
                metrics.cadence.fatigue_trajectory_residual = Some(fatigue.residual_sse);
                metrics.cadence.fatigue_phase = Some(fatigue.dominant_phase);
                metrics.fatigue_trajectory = Some(fatigue);
                metrics.analysis_status.mark_completed(AnalysisKind::Fatigue);
            }

            // Error topology (correction patterns, key adjacency)
            metrics.error_topology = {
                let events: Vec<crate::analysis::TopologyEvent> = samples.iter()
                    .map(|s| crate::analysis::TopologyEvent {
                        timestamp_ns: s.timestamp_ns,
                        event_type: if s.zone == super::constants::CORRECTION_ZONE {
                            crate::analysis::EventType::Correction
                        } else {
                            crate::analysis::EventType::Normal
                        },
                        key_code: None,
                        gap_ns: s.duration_since_last_ns,
                    })
                    .collect();
                crate::analysis::analyze_error_topology(&events).ok()
            };
            if let Some(ref et) = metrics.error_topology {
                if !et.is_valid || et.score < 0.3 { metrics.anomaly_count += 1; }
            }
        }

        // ── Batch C: always-run probes (rayon parallel) ──────────────────
        let (cog_r, eco_r) = rayon::join(
            || super::cognitive_load::analyze_cognitive_load(document_text, samples),
            || super::error_ecology::analyze_error_ecology(samples),
        );
        metrics.cognitive_load = cog_r;
        if metrics.cognitive_load.is_some() {
            metrics.analysis_status.mark_completed(AnalysisKind::CognitiveLoad);
        }
        metrics.error_ecology = eco_r;
        if metrics.error_ecology.is_some() {
            metrics.analysis_status.mark_completed(AnalysisKind::ErrorEcology);
        }

        // Likelihood model (depends on behavioral fingerprint — sequential)
        metrics.likelihood_model =
            super::likelihood_model::analyze_likelihood_model_with_priors(
                samples,
                metrics.behavioral.as_ref(),
            );
        if metrics.likelihood_model.is_some() {
            metrics.analysis_status.mark_completed(AnalysisKind::LikelihoodModel);
        }

        // Spectral analysis (pink noise classification)
        if iki_intervals.len() >= 32 {
            metrics.spectral_analysis = crate::analysis::analyze_pink_noise(&iki_intervals, 1000.0).ok();
        }
        if let Some(ref pn) = metrics.spectral_analysis {
            if matches!(pn.noise_type, crate::analysis::NoiseType::White | crate::analysis::NoiseType::Black) {
                metrics.anomaly_count += 1;
            }
        }
    }

    metrics.velocity = super::velocity::analyze_velocity(sorted);
    metrics.analysis_status.mark_completed(AnalysisKind::Velocity);
    metrics.session_stats = compute_session_stats(sorted);
    metrics.checkpoint_count = context.checkpoint_count as usize;

    let anomalies = detect_anomalies(sorted, regions, &metrics.primary);
    let primary_anomaly_count = anomalies.len();
    metrics.anomaly_count += primary_anomaly_count;

    // Skip cross-modal when context is default/unpopulated to avoid false positives
    let skip_cross_modal = context.checkpoint_count == 0 && context.document_length == 0;

    if !skip_cross_modal {
        let cm_input = super::cross_modal::CrossModalInput {
            events,
            jitter_samples,
            document_length: context.document_length,
            total_keystrokes: context.total_keystrokes,
            checkpoint_count: context.checkpoint_count,
            session_duration_sec: metrics.session_stats.total_editing_time_sec,
        };
        let cm_result = super::cross_modal::analyze_cross_modal(&cm_input);

        let cm_penalty = match cm_result.verdict {
            super::cross_modal::CrossModalVerdict::Inconsistent => 2,
            super::cross_modal::CrossModalVerdict::Marginal => 1,
            _ => 0,
        };
        metrics.anomaly_count += cm_penalty;
        metrics.cross_modal = Some(cm_result);
        metrics.analysis_status.mark_completed(AnalysisKind::CrossModal);
    }

    // Exclude primary-metric anomalies from the score because compute_assessment_score
    // already directly penalizes for the same metrics (monotonic append, low entropy).
    let scoring_anomaly_count = metrics.anomaly_count.saturating_sub(primary_anomaly_count);
    metrics.assessment_score = Probability::clamp(compute_assessment_score(
        &metrics.primary,
        &metrics.cadence,
        scoring_anomaly_count,
        events.len(),
        metrics.biological_cadence_score.get(),
    ));
    if let Some(focus) = focus_metrics {
        metrics.focus = focus;
        apply_focus_penalties(&mut metrics.assessment_score, &metrics.focus);
    }

    if !context.cross_window_matches.is_empty() {
        metrics.cross_window_matches = context.cross_window_matches.clone();
    }
    if !metrics.cross_window_matches.is_empty() {
        super::assessment::apply_cross_window_penalties(
            &mut metrics.assessment_score,
            &metrics.cross_window_matches,
        );
    }

    if let Some(tier) = context.attestation_tier {
        super::scoring::apply_attestation_tier_penalty(&mut metrics.assessment_score, tier);
    }

    // Revision topology (depends on sorted events, needed before enrichment)
    metrics.revision_topology = super::revision_topology::analyze_revision_topology(sorted);
    if metrics.revision_topology.is_some() {
        metrics.analysis_status.mark_completed(AnalysisKind::RevisionTopology);
    }

    // Apply enhanced signal adjustments to assessment score
    super::assessment::apply_enhanced_signal_adjustments(
        &mut metrics.assessment_score,
        metrics.cognitive_load.as_ref(),
        metrics.revision_topology.as_ref(),
        metrics.error_ecology.as_ref(),
        metrics.likelihood_model.as_ref(),
    );

    {
        let mut s = metrics.assessment_score;
        if let Some(ref ap) = metrics.active_probes {
            if ap.combined_score > 0.7 {
                s = Probability::clamp(s.get() + 0.02);
            } else if ap.combined_score < 0.3 {
                s = Probability::clamp(s.get() - 0.03);
            }
        }
        if let Some(ref et) = metrics.error_topology {
            if et.is_valid && et.score < 0.3 {
                s = Probability::clamp(s.get() - 0.03);
            }
        }
        if let Some(ref pn) = metrics.spectral_analysis {
            match pn.noise_type {
                crate::analysis::NoiseType::Pink => {
                    s = Probability::clamp(s.get() + 0.02);
                }
                crate::analysis::NoiseType::White | crate::analysis::NoiseType::Black => {
                    s = Probability::clamp(s.get() - 0.04);
                }
                _ => {}
            }
        }
        if metrics.ai_fluency_flag {
            s = Probability::clamp(s.get() - 0.03);
        }
        metrics.assessment_score = s;
    }

    // Penalize when critical analyses failed — incomplete evidence is less trustworthy.
    // Only applies when analyses were attempted but errored (not skipped for low data).
    let failed = metrics.analysis_status.failed_count();
    if failed > 0 {
        let penalty = 0.03 * failed as f64; // 3% per failed analysis
        metrics.assessment_score =
            Probability::clamp(metrics.assessment_score.get() - penalty);
    }

    metrics.risk_level = determine_risk_level(metrics.assessment_score.get(), events.len());

    // Base writing mode classification
    let mut wm = super::writing_mode::classify_writing_mode(
        &metrics.primary,
        &metrics.cadence,
        sorted,
        events.len(),
    );

    // Enrich with enhanced signals
    let enhanced = super::writing_mode::EnhancedSignals {
        cognitive_load_score: metrics.cognitive_load.as_ref().map(|c| c.composite_score),
        revision_topology_score: metrics
            .revision_topology
            .as_ref()
            .map(|r| r.composite_score),
        error_ecology_score: metrics.error_ecology.as_ref().map(|e| e.composite_score),
        likelihood_p_cognitive: metrics.likelihood_model.as_ref().map(|l| l.composite_score),
        composition_mode_score: metrics
            .composition_mode
            .as_ref()
            .map(|c| c.composite_score),
    };
    super::writing_mode::enrich_writing_mode(&mut wm, &enhanced);
    metrics.writing_mode = Some(wm);

    metrics
}

/// Analyze events partitioned by checkpoint boundaries.
///
/// Accepts `SortedEvents` to avoid redundant clone+sort when the caller
/// already has sorted data (which is the common case in the forensics pipeline).
pub fn per_checkpoint_flags(
    sorted_events: SortedEvents<'_>,
    checkpoints: &[CheckpointProof],
) -> PerCheckpointResult {
    if checkpoints.is_empty() {
        return PerCheckpointResult {
            checkpoint_flags: Vec::new(),
            pct_flagged: Probability::ZERO,
            suspicious: false,
        };
    }

    let mut flags = Vec::with_capacity(checkpoints.len());

    for (idx, cp) in checkpoints.iter().enumerate() {
        let cp_ts = cp.timestamp.timestamp_nanos_opt().unwrap_or(0);
        let prev_ts = if idx > 0 {
            checkpoints[idx - 1]
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or(0)
        } else {
            0
        };

        let start_idx = sorted_events.partition_point(|e| e.timestamp_ns <= prev_ts);
        let end_idx = sorted_events.partition_point(|e| e.timestamp_ns <= cp_ts);
        let interval_events: Vec<&EventData> = sorted_events[start_idx..end_idx].iter().collect();

        let event_count = interval_events.len();

        let timing_cv = if event_count >= 2 {
            let intervals: Vec<f64> = interval_events
                .windows(2)
                .map(|w| w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns) as f64)
                .collect();
            crate::utils::stats::coefficient_of_variation(&intervals)
        } else {
            0.0
        };

        let max_velocity_bps = if event_count >= 2 {
            interval_events
                .windows(2)
                .map(|w| {
                    let dt = crate::utils::ns_to_secs(
                        w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns),
                    );
                    if dt > 0.0 {
                        w[1].size_delta.unsigned_abs() as f64 / dt
                    } else {
                        0.0
                    }
                })
                .fold(0.0f64, f64::max)
        } else {
            0.0
        };

        let all_append = if event_count > 0 {
            interval_events.iter().all(|e| e.size_delta >= 0)
        } else {
            false
        };

        let flagged = (timing_cv < PER_CHECKPOINT_ROBOTIC_CV && event_count >= 3)
            || (all_append && event_count >= 5);

        flags.push(CheckpointFlags {
            ordinal: cp.ordinal,
            event_count,
            timing_cv,
            max_velocity_bps,
            all_append,
            flagged,
        });
    }

    let flagged_count = flags.iter().filter(|f| f.flagged).count();
    let pct_flagged = Probability::clamp(if flags.is_empty() {
        0.0
    } else {
        flagged_count as f64 / flags.len() as f64
    });
    let suspicious = pct_flagged > PER_CHECKPOINT_SUSPICIOUS_THRESHOLD;

    PerCheckpointResult {
        checkpoint_flags: flags,
        pct_flagged,
        suspicious,
    }
}

use super::constants::{AI_APP_PATTERNS, BROWSER_BUNDLE_IDS};

/// Short away duration threshold (seconds) for browser-as-AI-reference heuristic.
const BROWSER_SHORT_AWAY_SEC: f64 = 30.0;

/// Short switch threshold (seconds) for reading-pattern detection.
const READING_PATTERN_SWITCH_SEC: f64 = 10.0;

/// Minimum repeated short switches to the same app to flag a reading pattern.
const READING_PATTERN_MIN_REPEATS: usize = 3;

/// Analyze focus-switching patterns for cognitive vs. transcriptive signals.
pub fn analyze_focus_patterns(
    switches: &[FocusSwitchRecord],
    total_session_ms: i64,
) -> FocusMetrics {
    if switches.is_empty() || total_session_ms <= 0 {
        return FocusMetrics::default();
    }

    let switch_count = switches.len();
    let mut total_away_sec = 0.0;
    let mut completed_count = 0usize;
    let mut ai_app_switch_count = 0usize;

    for sw in switches {
        let away_sec = sw
            .regained_at
            .and_then(|r| r.duration_since(sw.lost_at).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        if sw.regained_at.is_some() {
            total_away_sec += away_sec;
            completed_count += 1;
        }

        let bid_lower = sw.target_bundle_id.to_lowercase();
        let app_lower = sw.target_app.to_lowercase();

        let is_ai_app = AI_APP_PATTERNS
            .iter()
            .any(|pat| bid_lower.contains(pat) || app_lower.contains(pat));

        let is_browser_short = BROWSER_BUNDLE_IDS
            .iter()
            .any(|b| bid_lower.eq_ignore_ascii_case(b))
            && away_sec > 0.0
            && away_sec < BROWSER_SHORT_AWAY_SEC;

        if is_ai_app || is_browser_short {
            ai_app_switch_count += 1;
        }
    }

    let total_session_sec = total_session_ms as f64 / 1000.0;
    let out_of_focus_ratio = Probability::clamp(if total_session_sec > f64::EPSILON {
        total_away_sec / total_session_sec
    } else {
        0.0
    });
    let avg_away_duration_sec = if completed_count > 0 {
        total_away_sec / completed_count as f64
    } else {
        0.0
    };

    // Detect reading pattern: repeated short switches to the same app.
    let reading_pattern_detected = detect_reading_pattern(switches);

    // Compute mid-typing switch ratio: fraction of consecutive switches where
    // the gap between regaining focus and losing it again was <2s, indicating
    // the user was actively working (not idle) between focus changes.
    let mid_typing_switch_ratio = if switches.len() >= 2 {
        let mut mid_typing = 0usize;
        let mut pairs = 0usize;
        for pair in switches.windows(2) {
            if let Some(regained) = pair[0].regained_at {
                if let Ok(gap) = pair[1].lost_at.duration_since(regained) {
                    pairs += 1;
                    if gap.as_secs_f64() < 2.0 {
                        mid_typing += 1;
                    }
                }
            }
        }
        if pairs > 0 {
            mid_typing as f64 / pairs as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    FocusMetrics {
        switch_count,
        out_of_focus_ratio,
        ai_app_switch_count,
        avg_away_duration_sec,
        reading_pattern_detected,
        mid_typing_switch_ratio,
    }
}

/// Detect a copy-reference workflow: frequent short switches (<10s) to the same app.
fn detect_reading_pattern(switches: &[FocusSwitchRecord]) -> bool {
    // Group completed short switches by target bundle ID.
    let mut short_counts: HashMap<&str, usize> = HashMap::new();
    let mut short_durations: Vec<f64> = Vec::new();
    for sw in switches {
        let away_sec = sw
            .regained_at
            .and_then(|r| r.duration_since(sw.lost_at).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(f64::MAX);

        if away_sec < READING_PATTERN_SWITCH_SEC {
            *short_counts
                .entry(sw.target_bundle_id.as_str())
                .or_insert(0) += 1;
            short_durations.push(away_sec);
        }
    }

    let frequent = short_counts
        .values()
        .any(|&count| count >= READING_PATTERN_MIN_REPEATS);

    // Also detect regular-interval switching: if the CV of short switch
    // durations is very low, the pattern is mechanically regular (stronger
    // transcription signal than just frequency).
    let regular_interval = if short_durations.len() >= READING_PATTERN_MIN_REPEATS {
        let (mean, std) = mean_and_std_dev(&short_durations);
        if mean > 0.0 {
            let cv = std / mean;
            cv < 0.3 // Very regular intervals
        } else {
            false
        }
    } else {
        false
    };

    frequent || regular_interval
}
