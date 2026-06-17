// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::detect_attestation_tier_info;
use crate::ffi::report_types::*;
use crate::ffi::types::catch_ffi_panic;
use crate::report::*;
use crate::utils::finite_or;
use crate::war::ear::{
    engine_verifier_id, Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector,
};
use chrono::DateTime;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroize;

const PERCENTILE_IDX_MEDIAN: usize = 2;
const PERCENTILE_IDX_P90: usize = 4;
/// Average bytes per word (English prose including space separator).
/// Used as fallback when the document cannot be read as UTF-8.
const BYTES_PER_WORD_ESTIMATE: u64 = 5;

struct ForensicCacheEntry {
    event_count: usize,
    profile: Arc<crate::forensics::AuthorshipProfile>,
    metrics: Arc<crate::forensics::ForensicMetrics>,
    regions: Arc<std::collections::HashMap<i64, Vec<crate::forensics::RegionData>>>,
}

/// Bounded LRU cache for forensic results. Entries are evicted in least-recently-used
/// order when the cache exceeds `MAX_FORENSIC_CACHE` entries. The `order` VecDeque
/// tracks access recency (most recent at back); all mutations happen under a single
/// Mutex, eliminating the evict-reinsert race from the prior DashMap/HashMap design.
struct BoundedLruCache {
    map: std::collections::HashMap<String, ForensicCacheEntry>,
    order: std::collections::VecDeque<String>,
}

const MAX_FORENSIC_CACHE: usize = 10;

impl BoundedLruCache {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::with_capacity(MAX_FORENSIC_CACHE),
            order: std::collections::VecDeque::with_capacity(MAX_FORENSIC_CACHE),
        }
    }

    /// Look up an entry and promote it to most-recently-used if found.
    fn get(
        &mut self,
        key: &str,
    ) -> Option<&ForensicCacheEntry> {
        if self.map.contains_key(key) {
            // Promote to most-recently-used by moving to back of order queue.
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
            self.order.push_back(key.to_string());
            self.map.get(key)
        } else {
            None
        }
    }

    /// Insert an entry, evicting the least-recently-used entry if at capacity.
    fn insert(&mut self, key: String, value: ForensicCacheEntry) {
        if self.map.contains_key(&key) {
            // Update existing: remove old position, will re-add at back.
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        } else if self.map.len() >= MAX_FORENSIC_CACHE {
            // Evict least-recently-used (front of queue).
            if let Some(evict_key) = self.order.pop_front() {
                self.map.remove(&evict_key);
            }
        }
        self.map.insert(key.clone(), value);
        self.order.push_back(key);
    }
}

fn forensic_cache() -> &'static std::sync::Mutex<BoundedLruCache> {
    static CACHE: OnceLock<std::sync::Mutex<BoundedLruCache>> = OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(BoundedLruCache::new()))
}

#[allow(dead_code)] // fields used for future report sections
pub(crate) struct EventStats {
    pub(crate) avg_forensic: f64,
    pub(crate) total_iterations: u64,
    pub(crate) total_secs: f64,
    pub(crate) total_min: f64,
    pub(crate) paste_count: u64,
    pub(crate) avg_compute_ms: u64,
    pub(crate) backdating_hours: f64,
    pub(crate) size_delta_chars: i64,
    pub(crate) keystroke_estimate: u64,
    pub(crate) paste_ratio_pct: Option<f64>,
    pub(crate) doc_hash: String,
    pub(crate) doc_size: i64,
}

fn compute_event_stats(
    events: &[crate::store::SecureEvent],
    ips: u64,
) -> Option<EventStats> {
    let last = events.last()?;
    let doc_hash = hex::encode(last.content_hash);
    let doc_size = last.file_size;

    let avg_forensic: f64 = {
        let finite_scores: Vec<f64> = events
            .iter()
            .map(|e| e.forensic_score)
            .filter(|s| s.is_finite())
            .collect();
        let avg = finite_scores.iter().sum::<f64>() / finite_scores.len().max(1) as f64;
        if avg.is_finite() {
            avg
        } else {
            0.0
        }
    };

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_secs = if ips > 0 {
        total_iterations as f64 / ips as f64
    } else {
        0.0
    };
    let total_min = {
        let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
        let last_ns = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
        let wall_ns = last_ns.saturating_sub(first_ns);
        if wall_ns > 0 {
            wall_ns as f64 / 60_000_000_000.0
        } else {
            total_secs / 60.0
        }
    };

    let paste_count = events.iter().filter(|e| e.is_paste).count() as u64;
    let avg_compute_ms = if !events.is_empty() && ips > 0 {
        let avg_iters = total_iterations as f64 / events.len() as f64;
        (avg_iters / ips as f64 * 1000.0) as u64
    } else {
        0
    };
    let backdating_hours = if ips > 0 {
        total_iterations as f64 / ips as f64 / 3600.0
    } else {
        0.0
    };

    // .max(0) ensures each delta is non-negative before widening to i64, so the
    // sum is guaranteed non-negative. The 1.15x multiplier estimates actual keystrokes
    // (accounting for corrections). .clamp() prevents overflow on the f64->u64 cast.
    let size_delta_chars: i64 = events.iter().map(|e| e.size_delta.max(0) as i64).sum();
    let keystroke_estimate = ((size_delta_chars as f64 * 1.15)
        .ceil()
        .clamp(0.0, u64::MAX as f64) as u64)
        .max(events.len() as u64);

    let paste_chars: i64 = events
        .iter()
        .filter(|e| e.is_paste)
        .map(|e| e.size_delta.max(0) as i64)
        .sum();
    let paste_ratio_pct = if size_delta_chars > 0 {
        Some(paste_chars as f64 / size_delta_chars as f64 * 100.0)
    } else {
        None
    };

    Some(EventStats {
        avg_forensic,
        total_iterations,
        total_secs,
        total_min,
        paste_count,
        avg_compute_ms,
        backdating_hours,
        size_delta_chars,
        keystroke_estimate,
        paste_ratio_pct,
        doc_hash,
        doc_size,
    })
}

fn build_checkpoints(events: &[crate::store::SecureEvent], ips: u64) -> Vec<ReportCheckpoint> {
    events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_ms = if ips > 0 {
                (ev.vdf_iterations as f64 / ips as f64 * 1000.0) as u64
            } else {
                0
            };
            ReportCheckpoint {
                ordinal: i as u64,
                timestamp: DateTime::from_timestamp_nanos(ev.timestamp_ns),
                content_hash: hex::encode(ev.content_hash),
                content_size: ev.file_size.max(0) as u64,
                vdf_iterations: Some(ev.vdf_iterations),
                elapsed_ms: Some(elapsed_ms),
            }
        })
        .collect()
}

fn build_initial_process(stats: &EventStats, event_count: usize) -> ProcessEvidence {
    ProcessEvidence {
        paste_operations: Some(stats.paste_count),
        paste_ratio_pct: stats.paste_ratio_pct,
        total_keystrokes: Some(stats.keystroke_estimate),
        swf_checkpoints: Some(event_count as u64),
        swf_avg_compute_ms: Some(stats.avg_compute_ms),
        swf_chain_verified: true,
        swf_backdating_hours: Some(stats.backdating_hours),
        ..Default::default()
    }
}

fn build_process_flags(
    stats: &EventStats,
    event_count: usize,
    hardware_backed: bool,
    tier_label: &str,
) -> Vec<ReportFlag> {
    let mut flags = Vec::new();
    if stats.avg_forensic > 0.7 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Natural Editing Pattern".into(),
            detail: format!(
                "Forensic score {:.2} indicates human editing patterns",
                stats.avg_forensic
            ),
            signal: FlagSignal::Human,
        });
    }
    if stats.paste_count == 0 || (stats.paste_count as f64 / event_count.max(1) as f64) < 0.1 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Low Paste Ratio".into(),
            detail: format!(
                "{} paste operations in {} events ({:.1}%)",
                stats.paste_count,
                event_count,
                stats.paste_count as f64 / event_count.max(1) as f64 * 100.0,
            ),
            signal: FlagSignal::Human,
        });
    }
    if stats.total_min > 30.0 {
        flags.push(ReportFlag {
            category: "Duration".into(),
            flag: "Extended Writing Session".into(),
            detail: format!("{:.1} minutes of verified writing time", stats.total_min),
            signal: FlagSignal::Human,
        });
    }
    if stats.total_min < 5.0 && event_count > 1 {
        flags.push(ReportFlag {
            category: "Duration".into(),
            flag: "Short Session".into(),
            detail: format!(
                "{:.1} minutes \u{2014} limited evidence window",
                stats.total_min
            ),
            signal: FlagSignal::Neutral,
        });
    }
    {
        let estimated_kpm = if stats.total_min > 0.0 {
            stats.keystroke_estimate as f64 / stats.total_min
        } else {
            0.0
        };
        flags.push(ReportFlag {
            category: "Keystroke Activity".into(),
            flag: format!("{} Estimated Keystrokes", stats.keystroke_estimate),
            detail: format!(
                "{:.0} kpm average across {} checkpoint events",
                estimated_kpm, event_count
            ),
            signal: if stats.keystroke_estimate > 200 {
                FlagSignal::Human
            } else {
                FlagSignal::Neutral
            },
        });
    }
    if hardware_backed {
        flags.push(ReportFlag {
            category: "Attestation".into(),
            flag: format!("Hardware-Bound Key ({})", tier_label),
            detail:
                "Device signing key is bound to TPM/Secure Enclave; cannot be extracted or cloned."
                    .into(),
            signal: FlagSignal::Human,
        });
    }
    if stats.total_iterations > 0 {
        let vdf_secs = stats.total_secs;
        flags.push(ReportFlag {
            category: "Time Proof".into(),
            flag: format!("VDF Chain: {:.0}s elapsed proof", vdf_secs),
            detail: format!(
                "{} sequential iterations verify minimum elapsed wall-clock time.",
                stats.total_iterations
            ),
            signal: if vdf_secs > 60.0 {
                FlagSignal::Human
            } else {
                FlagSignal::Neutral
            },
        });
    }
    flags
}

fn load_signing_key_and_seed() -> (Option<ed25519_dalek::SigningKey>, String, String) {
    let loaded_key = crate::ffi::helpers::load_signing_key()
        .map_err(|e| log::warn!("load signing key for report: {e}"))
        .ok();
    let (key_fp, guilloche_seed_hex) = match loaded_key.as_ref() {
        Some(signing_key) => {
            let vk = signing_key.verifying_key();
            let fp = hex::encode(&vk.as_bytes()[..4]);

            let seed_hex = match crate::utils::key_derivation::derive_guilloche_seed(
                signing_key.as_bytes(),
            ) {
                Ok(mut seed) => {
                    let result = hex::encode(seed);
                    seed.zeroize();
                    result
                }
                Err(e) => {
                    log::error!("HKDF expand failed for guilloche seed: {e}");
                    String::new()
                }
            };

            (fp, seed_hex)
        }
        None => {
            log::error!("load signing key failed");
            ("unknown".to_string(), String::new())
        }
    };
    (loaded_key, key_fp, guilloche_seed_hex)
}

#[allow(clippy::type_complexity)]
fn get_forensics_cached(
    file_path_str: &str,
    events: &[crate::store::SecureEvent],
) -> (
    Arc<crate::forensics::AuthorshipProfile>,
    Arc<crate::forensics::ForensicMetrics>,
    Arc<std::collections::HashMap<i64, Vec<crate::forensics::RegionData>>>,
) {
    let cache_key = file_path_str.to_string();
    let hit = {
        let mut cache = forensic_cache()
            .lock()
            .unwrap_or_else(|p| {
                log::warn!("forensic_cache mutex poisoned; recovering cached value");
                p.into_inner()
            });
        cache
            .get(&cache_key)
            .filter(|e| e.event_count == events.len())
            .map(|e| {
                (
                    Arc::clone(&e.profile),
                    Arc::clone(&e.metrics),
                    Arc::clone(&e.regions),
                )
            })
    };
    match hit {
        Some(cached) => cached,
        None => {
            let p = Arc::new(crate::forensics::ForensicEngine::evaluate_authorship(
                file_path_str,
                events,
            ));
            let (m_raw, r_raw) = crate::ffi::helpers::run_full_forensics(events);
            let m = Arc::new(m_raw);
            let r = Arc::new(r_raw);
            let mut cache = forensic_cache()
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cache.insert(
                cache_key,
                ForensicCacheEntry {
                    event_count: events.len(),
                    profile: Arc::clone(&p),
                    metrics: Arc::clone(&m),
                    regions: Arc::clone(&r),
                },
            );
            (p, m, r)
        }
    }
}

fn populate_behavioral_fields(
    process: &mut ProcessEvidence,
    metrics: &crate::forensics::ForensicMetrics,
    keystroke_estimate: u64,
) {
    let c = &metrics.cadence;
    if c.mean_iki_ns > 0.0 && c.mean_iki_ns.is_finite() && c.std_dev_iki_ns.is_finite() {
        let cv = c.std_dev_iki_ns / c.mean_iki_ns;
        process.iki_cv = if cv.is_finite() { Some(cv) } else { None };
        if c.percentiles[PERCENTILE_IDX_MEDIAN] > 0.0
            && c.percentiles[PERCENTILE_IDX_MEDIAN].is_finite()
        {
            process.pause_median_sec = Some(c.percentiles[PERCENTILE_IDX_MEDIAN] / 1_000_000_000.0);
        }
        if c.percentiles[PERCENTILE_IDX_P90] > 0.0 && c.percentiles[PERCENTILE_IDX_P90].is_finite()
        {
            process.pause_p90_sec = Some(c.percentiles[PERCENTILE_IDX_P90] / 1_000_000_000.0);
        }
    }
    let append_ratio = metrics.primary.monotonic_append_ratio.get();
    process.revision_intensity = if append_ratio.is_finite() {
        Some(1.0 - append_ratio)
    } else {
        None
    };
    let correction_ratio = c.correction_ratio.get();
    if correction_ratio.is_finite() && correction_ratio > 0.0 && keystroke_estimate > 0 {
        let del_seqs = (correction_ratio * keystroke_estimate as f64) as u64;
        process.deletion_sequences = Some(del_seqs);
        if del_seqs > 0 {
            let total_deletions = correction_ratio * keystroke_estimate as f64;
            process.avg_deletion_length =
                Some((total_deletions / del_seqs as f64).clamp(1.0, 50.0));
        }
    }
    if let Some(wm) = &metrics.writing_mode {
        if let Some(cl) = &wm.cognitive_layer {
            if cl.bigram_fluency_ratio.is_finite() && cl.bigram_fluency_ratio > 0.0 {
                process.bigram_consistency = Some(cl.bigram_fluency_ratio);
            }
        }
    }
}

/// Weight for per-event forensic score in the blended verdict.
/// Calibrated against Crossley 2024 (N=998, AUC 0.88-0.95 on proxy metrics).
/// The forensic score captures IKI cadence, velocity, and cross-modal consistency;
/// topology captures revision structure (detour, LED, insertion entropy).
const W_FORENSIC: f64 = 0.6;
/// Weight for revision topology assessment in the blended verdict.
const W_TOPOLOGY: f64 = 0.4;

fn blend_topology_score(
    avg_forensic: f64,
    metrics: &crate::forensics::ForensicMetrics,
    event_count: usize,
    base_score: u32,
    base_verdict: Verdict,
    base_lr: f64,
    base_enfsi: EnfsiTier,
) -> (u32, Verdict, f64, EnfsiTier) {
    let topology_assessment = finite_or(metrics.assessment_score.get(), 0.0);
    if topology_assessment > 0.0 && event_count >= crate::report::MIN_VERDICT_EVENTS {
        let blended = (avg_forensic * W_FORENSIC + topology_assessment * W_TOPOLOGY).clamp(0.0, 1.0);
        let s = (blended * 100.0) as u32;
        let v = Verdict::from_score_with_events(s, event_count);
        let l = compute_likelihood_ratio(s);
        let e = EnfsiTier::from_lr(l);
        (s, v, l, e)
    } else {
        (base_score, base_verdict, base_lr, base_enfsi)
    }
}

fn build_forensic_flags(
    flags: &mut Vec<ReportFlag>,
    metrics: &crate::forensics::ForensicMetrics,
    profile: &crate::forensics::AuthorshipProfile,
) {
    let mean_bps = finite_or(metrics.velocity.mean_bps, 0.0);
    if mean_bps > 0.0 {
        let in_human_range = mean_bps > 0.3 && mean_bps < 25.0;
        flags.push(ReportFlag {
            category: "Velocity".into(),
            flag: format!("Mean Writing Rate: {:.1} B/s", mean_bps),
            detail: "Average content production speed across all sessions. Human prose range: 0.5-15 B/s.".into(),
            signal: if in_human_range { FlagSignal::Human } else { FlagSignal::Neutral },
        });
    }
    if let Some(cm) = &metrics.cross_modal {
        let passed = cm.checks.iter().filter(|c| c.passed).count();
        let total = cm.checks.len();
        if total > 0 {
            let verdict_label = match cm.verdict {
                crate::forensics::cross_modal::CrossModalVerdict::Consistent => "Consistent",
                crate::forensics::cross_modal::CrossModalVerdict::Marginal => "Marginal",
                crate::forensics::cross_modal::CrossModalVerdict::Inconsistent => "Inconsistent",
                crate::forensics::cross_modal::CrossModalVerdict::Insufficient => {
                    "Insufficient data"
                }
            };
            flags.push(ReportFlag {
                category: "Cross-Modal".into(),
                flag: format!("Evidence Coherence: {}", verdict_label),
                detail: format!(
                    "{}/{} cross-modal consistency checks passed.",
                    passed, total
                ),
                signal: match cm.verdict {
                    crate::forensics::cross_modal::CrossModalVerdict::Consistent => {
                        FlagSignal::Human
                    }
                    crate::forensics::cross_modal::CrossModalVerdict::Marginal => {
                        FlagSignal::Neutral
                    }
                    _ => FlagSignal::Synthetic,
                },
            });
        }
    }
    for anomaly in profile.anomalies.iter().take(3) {
        flags.push(ReportFlag {
            category: "Anomaly".into(),
            flag: anomaly.anomaly_type.to_string(),
            detail: anomaly.description.clone(),
            signal: match anomaly.severity {
                crate::forensics::Severity::Alert => FlagSignal::Synthetic,
                _ => FlagSignal::Neutral,
            },
        });
    }
}

fn compute_forgery_info(
    events: &[crate::store::SecureEvent],
    stats: &EventStats,
    ips: u64,
    hardware_backed: bool,
    metrics: &crate::forensics::ForensicMetrics,
) -> ForgeryInfo {
    use crate::forensics::{estimate_forgery_cost, ForgeryCostInput};

    let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
    let last_ns = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
    let chain_duration_sec =
        (last_ns.saturating_sub(first_ns).max(0) as f64 / 1_000_000_000.0) as u64;

    let (cm_passed, cm_total) = metrics
        .cross_modal
        .as_ref()
        .map(|cm| {
            let passed = cm.checks.iter().filter(|c| c.passed).count();
            (passed, cm.checks.len())
        })
        .unwrap_or((0, 0));
    let input = ForgeryCostInput {
        vdf_iterations: stats.total_iterations,
        vdf_rate: ips,
        checkpoint_count: events.len() as u64,
        chain_duration_sec,
        has_jitter_binding: stats.keystroke_estimate > 0,
        jitter_sample_count: stats.keystroke_estimate,
        has_hardware_attestation: hardware_backed,
        has_behavioral_fingerprint: metrics.behavioral.is_some(),
        cross_modal_consistent: cm_total > 0 && cm_passed == cm_total,
        cross_modal_passed: cm_passed,
        cross_modal_total: cm_total,
        has_external_time_anchor: events.iter().any(|e| e.challenge_nonce.is_some()),
        has_content_key_entanglement: events
            .iter()
            .any(|e| e.vdf_input.is_some() && e.vdf_output.is_some()),
    };
    let est = estimate_forgery_cost(&input);
    ForgeryInfo {
        tier: est.tier.to_string(),
        estimated_forge_time_sec: est.estimated_forge_time_sec,
        weakest_link: est.weakest_link,
        components: est
            .components
            .into_iter()
            .map(|c| ForgeryComponent {
                name: c.name,
                present: c.present,
                cost_cpu_sec: c.cost_cpu_sec,
                explanation: c.explanation,
            })
            .collect(),
    }
}

use super::report_dimensions::build_dimensions;

fn compute_provenance(
    store: &crate::store::SecureStore,
) -> Option<crate::report::ProvenanceBreakdown> {
    let fragments = store.get_all_fragments().unwrap_or_default();
    if fragments.is_empty() {
        return None;
    }
    let m = crate::forensics::ProvenanceMetrics::compute(&fragments);
    Some(crate::report::ProvenanceBreakdown {
        total_fragments: m.total_fragments,
        original_composition_pct: m.original_composition_ratio * 100.0,
        sourced_unknown_pct: m.sourced_unknown_ratio * 100.0,
        sourced_verified_pct: m.sourced_verified_ratio * 100.0,
        chain_depth: m.chain_depth,
        source_trustworthiness: m.source_trustworthiness,
        authenticity_score: m.authenticity_score,
        sources: m
            .source_sessions
            .into_iter()
            .map(|s| crate::report::ProvenanceSource {
                session_id: s.session_id,
                app_bundle_id: s.app_bundle_id,
                fragment_count: s.fragment_count,
                verified: s.verified,
            })
            .collect(),
    })
}

fn verdict_description(verdict: Verdict) -> String {
    match verdict {
        Verdict::InsufficientData => "Not enough evidence was collected to make a meaningful determination. More writing time and checkpoints are needed.".into(),
        Verdict::VerifiedHuman => "Strong evidence of human authorship with natural editing patterns, timing constraints, and behavioral consistency.".into(),
        Verdict::LikelyHuman => "Moderate evidence of human authorship with generally consistent patterns.".into(),
        Verdict::Inconclusive => "Insufficient evidence to make a determination about authorship.".into(),
        Verdict::Suspicious => "Process evidence shows patterns inconsistent with typical human composition. This may indicate transcription, heavy paste-and-edit, or insufficient evidence.".into(),
        Verdict::LikelySynthetic => "The captured process does not contain sufficient evidence of human composition. The writing may have been produced outside the monitoring window.".into(),
    }
}

fn compute_evidence_chain_hash(events: &[crate::store::SecureEvent]) -> String {
    let mut h = Sha256::new();
    for ev in events {
        h.update(ev.content_hash);
    }
    hex::encode(h.finalize())
}

fn build_activity_contexts(sessions: &[ReportSession]) -> Vec<ActivityContext> {
    sessions
        .iter()
        .map(|s| ActivityContext {
            period_type: "writing_session".into(),
            start: s.start,
            end: s.start
                + chrono::Duration::seconds(
                    (s.duration_min.clamp(0.0, 525_960.0) * 60.0) as i64,
                ),
            duration_min: s.duration_min,
            note: Some(s.summary.clone()),
        })
        .collect()
}

fn build_writing_flow(events: &[crate::store::SecureEvent]) -> Vec<FlowDataPoint> {
    let first_ns = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
    let max_delta = events
        .iter()
        .map(|e| e.size_delta.max(0))
        .max()
        .unwrap_or(1)
        .max(1);
    events
        .iter()
        .map(|e| FlowDataPoint {
            offset_min: e.timestamp_ns.saturating_sub(first_ns) as f64 / 60_000_000_000.0,
            intensity: e.size_delta.max(0) as f64 / max_delta as f64,
            phase: if e.size_delta > 0 { "active" } else { "pause" }.into(),
        })
        .collect()
}

/// Build the core WAR report data from stored events for a tracked file.
///
/// Returns `(WarReport, guilloche_seed_hex)` on success.
pub(crate) fn build_war_report_for_path(path: &str) -> Result<(WarReport, String), String> {
    const MAX_PATH_LEN: usize = 4096;
    if path.len() > MAX_PATH_LEN {
        return Err(format!("Path exceeds maximum length of {} bytes", MAX_PATH_LEN));
    }
    let (file_path_str, store, events) = crate::ffi::helpers::load_events_for_path(path)?;
    let file_path = std::path::PathBuf::from(&file_path_str);

    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()));
    }
    if events.is_empty() {
        return Err("No events found for this file".to_string());
    }

    let (_, tier_num, tier_label) = detect_attestation_tier_info();
    let hardware_backed = tier_num >= 2;

    let data_dir =
        crate::ffi::helpers::get_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::config::CpopConfig::load_or_default(&data_dir).unwrap_or_else(|e| {
        log::warn!("config load failed, using defaults: {e}");
        Default::default()
    });
    let ips = config.vdf.iterations_per_second.max(1);

    let stats = compute_event_stats(&events, ips)
        .ok_or_else(|| "No events found for this file".to_string())?;

    // Load real cumulative stats from the store (keystroke count, focus time, etc.)
    // These match what the bento dashboard displays. Fall back to estimates only
    // when the store has no stats (e.g., exported evidence without a live session).
    let doc_stats = store.load_document_stats(&file_path_str).ok().flatten();

    let base_score = (stats.avg_forensic * 100.0).clamp(0.0, 100.0) as u32;
    let base_verdict = Verdict::from_score_with_events(base_score, events.len());
    let base_lr = compute_likelihood_ratio(base_score);
    let base_enfsi = EnfsiTier::from_lr(base_lr);

    let sessions = detect_sessions_from_events(&events);
    let checkpoints = build_checkpoints(&events, ips);
    let mut process = build_initial_process(&stats, events.len());
    let mut flags = build_process_flags(&stats, events.len(), hardware_backed, &tier_label);

    let (loaded_key, key_fp, guilloche_seed_hex) = load_signing_key_and_seed();

    let last = events
        .last()
        .ok_or_else(|| "No events found for this file".to_string())?;
    // Intentional: device_id binds the evidence chain to a specific machine for
    // hardware attestation verification. It is a non-secret opaque identifier.
    let device_id = last.machine_id.clone();
    let device_attestation = if hardware_backed {
        format!("{} | TPM-bound Ed25519 key | {}", device_id, tier_label)
    } else {
        format!("{} | Software-only Ed25519 key", device_id)
    };

    let (profile, metrics, regions) = get_forensics_cached(&file_path_str, &events);
    let forensic_breakdown = super::forensic_fields::build_forensic_breakdown(&profile, &metrics);
    let real_keystrokes = doc_stats.as_ref()
        .map(|d| d.total_keystrokes.max(0) as u64)
        .filter(|&k| k > 0)
        .unwrap_or(stats.keystroke_estimate);
    populate_behavioral_fields(&mut process, &metrics, real_keystrokes);
    process.total_keystrokes = Some(real_keystrokes);

    let (score, verdict, lr, enfsi_tier) = blend_topology_score(
        stats.avg_forensic,
        &metrics,
        events.len(),
        base_score,
        base_verdict,
        base_lr,
        base_enfsi,
    );

    let edit_topology: Vec<EditRegion> = regions
        .values()
        .flatten()
        .map(|r| EditRegion {
            start_pct: r.start_pct as f64,
            end_pct: r.end_pct as f64,
            delta_sign: r.delta_sign as i32,
            byte_count: r.byte_count as i64,
        })
        .collect();

    let report_anomalies: Vec<ReportAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| ReportAnomaly {
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    build_forensic_flags(&mut flags, &metrics, &profile);

    // Check for skipped paste checkpoints from the live session.
    {
        use crate::RwLockRecover as _;
        if let Some(sentinel) = crate::ffi::sentinel::get_running_sentinel() {
            let sessions_guard = sentinel.sessions.read_recover();
            if let Some(session) = sessions_guard.get(&file_path_str) {
                if session.paste_checkpoint_skips > 0 {
                    flags.push(ReportFlag {
                        category: "Integrity".into(),
                        flag: "Paste Checkpoint Skipped".into(),
                        detail: format!(
                            "User skipped {} mandatory paste checkpoint{} during this session. \
                             Pasted content is undocumented.",
                            session.paste_checkpoint_skips,
                            if session.paste_checkpoint_skips == 1 { "" } else { "s" }
                        ),
                        signal: FlagSignal::Synthetic,
                    });
                }
            }
        }
    }

    let forgery = compute_forgery_info(&events, &stats, ips, hardware_backed, &metrics);
    let dimensions = build_dimensions(&stats, &process, &metrics, &sessions, &file_path_str);

    let verdict_desc = verdict_description(verdict);
    let evidence_chain_hash = compute_evidence_chain_hash(&events);
    let activity_contexts = build_activity_contexts(&sessions);
    let writing_flow = build_writing_flow(&events);

    let mut war_report = WarReport {
        report_id: WarReport::generate_id(),
        algorithm_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        generated_at: chrono::Utc::now(),
        schema_version: format!("WAR-v{}", env!("CARGO_PKG_VERSION")),
        is_sample: false,
        score,
        verdict,
        verdict_description: verdict_desc,
        likelihood_ratio: lr,
        enfsi_tier,
        document_hash: stats.doc_hash,
        evidence_hash: Some(evidence_chain_hash),
        evidence_cbor_b64: None,
        signing_key_fingerprint: key_fp,
        document_words: std::fs::read_to_string(&file_path)
            .ok()
            .map(|text| text.split_whitespace().count() as u64)
            .filter(|&w| w > 0)
            .or_else(|| {
                // Fallback: estimate from keystroke count or byte size.
                let real_ks = doc_stats.as_ref().map(|d| d.total_keystrokes).unwrap_or(0);
                if real_ks > 0 {
                    Some(real_ks as u64 / BYTES_PER_WORD_ESTIMATE)
                } else if stats.doc_size > 0 {
                    Some(stats.doc_size.max(0) as u64 / BYTES_PER_WORD_ESTIMATE)
                } else {
                    None
                }
            }),
        document_chars: Some(stats.doc_size.max(0) as u64),
        document_sentences: None,
        document_paragraphs: None,
        evidence_bundle_version: format!("Signed v{} (T{})", env!("CARGO_PKG_VERSION"), tier_num),
        session_count: doc_stats.as_ref()
            .map(|d| d.session_count as usize)
            .filter(|&c| c > 0)
            .unwrap_or(sessions.len()),
        total_duration_min: doc_stats.as_ref()
            .map(|d| d.total_focus_ms as f64 / 60_000.0)
            .filter(|&m| m > 0.0)
            .unwrap_or(stats.total_min),
        revision_events: events.len() as u64,
        device_attestation,
        checkpoints,
        sessions,
        process,
        flags,
        forgery,
        dimensions,
        writing_flow,
        methodology: None,
        limitations: vec![
            "Cannot prove cognitive origin of ideas".into(),
            "Cannot prove absence of AI involvement in ideation".into(),
        ],
        analyzed_text: None,
        forensic_metrics: Some(forensic_breakdown),
        edit_topology,
        activity_contexts,
        declaration_summary: None,
        key_hierarchy_summary: None,
        physical_context: None,
        beacon_info: None,
        anomalies: report_anomalies,
        verifiable_credential_json: None,
        author_did: {
            #[cfg(feature = "did-webvh")]
            {
                crate::identity::did_webvh::load_active_did()
                    .map_err(|e| log::debug!("DID not available for report: {e}"))
                    .ok()
            }
            #[cfg(not(feature = "did-webvh"))]
            {
                loaded_key.as_ref().and_then(|sk| {
                    crate::identity::did_key_from_public(sk.verifying_key().as_bytes())
                })
            }
        },
        provenance_breakdown: None,
    };

    war_report.verifiable_credential_json = build_vc_json(&war_report, loaded_key.as_ref(), &metrics);
    war_report.provenance_breakdown = compute_provenance(&store);

    // Sanity check: if the session recorded no paste events but provenance
    // shows 0% original composition, the fragment classification is wrong.
    // Override to reflect that content was typed live.
    if let Some(ref mut prov) = war_report.provenance_breakdown {
        if prov.original_composition_pct == 0.0 && stats.paste_count == 0 {
            prov.original_composition_pct = 100.0;
            prov.sourced_unknown_pct = 0.0;
            prov.sourced_verified_pct = 0.0;
            prov.authenticity_score = 1.0;
        }
    }

    // Gate evaluative output: if evidence is below validated thresholds,
    // refuse to issue a forensic finding. Override score/LR/ENFSI to
    // neutral and explain what minimums are not met. Also neutralize
    // per-dimension LRs so downstream renderers (Swift, HTML) cannot
    // display evaluative findings the methodology hasn't issued.
    if !war_report.evidence_is_sufficient() {
        let gaps = war_report.sufficiency_gaps();
        war_report.score = 0;
        war_report.verdict = Verdict::InsufficientData;
        war_report.verdict_description = verdict_description(Verdict::InsufficientData);
        war_report.likelihood_ratio = 1.0;
        war_report.enfsi_tier = EnfsiTier::Inconclusive;
        for dim in &mut war_report.dimensions {
            dim.lr = 1.0;
            dim.log_lr = 0.0;
        }
        // Clear human-signal flags that would contradict the InsufficientData verdict.
        war_report.flags.retain(|f| f.signal != FlagSignal::Human);
        war_report.limitations.insert(
            0,
            format!(
                "Evidence below validated thresholds for evaluative reporting. {}. \
                 No likelihood ratio, ENFSI tier, or forensic score is issued.",
                gaps.join("; ")
            ),
        );
    }

    Ok((war_report, guilloche_seed_hex))
}

/// Build a WAR report and return structured data suitable for native UI rendering.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_build_war_report(path: String) -> FfiWarReportResult {
    catch_ffi_panic!(FfiWarReportResult {
        success: false,
        report: None,
        error_message: Some("engine internal error".to_string()),
    }, {
    super::types::run_on_stack(move || {
    log::debug!("ffi_build_war_report: path={}", path);
    match build_war_report_for_path(&path) {
        Ok((report, guilloche_seed_hex)) => FfiWarReportResult {
            success: true,
            report: Some(convert_war_report(&report, &guilloche_seed_hex)),
            error_message: None,
        },
        Err(e) => FfiWarReportResult {
            success: false,
            report: None,
            error_message: Some(e),
        },
    }
    })
    })
}

/// Build a WAR report and render it as an HTML string.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_render_war_html(path: String) -> FfiHtmlResult {
    catch_ffi_panic!(FfiHtmlResult {
        success: false,
        html: None,
        error_message: Some("engine internal error".to_string()),
    }, {
    super::types::run_on_stack(move || {
    log::debug!("ffi_render_war_html: path={}", path);
    match build_war_report_for_path(&path) {
        Ok((report, _)) => {
            let html = render_html(&report);
            FfiHtmlResult {
                success: true,
                html: Some(html),
                error_message: None,
            }
        }
        Err(e) => FfiHtmlResult {
            success: false,
            html: None,
            error_message: Some(e),
        },
    }
    })
    })
}

/// Build a WAR report, render as PDF, and embed a C2PA manifest with VC.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_render_war_pdf(path: String) -> FfiPdfResult {
    catch_ffi_panic!(FfiPdfResult {
        success: false,
        pdf_bytes: None,
        error_message: Some("engine internal error".to_string()),
    }, {
    super::types::run_on_stack(move || {
    log::debug!("ffi_render_war_pdf: path={}", path);
    match build_war_report_for_path(&path) {
        Ok((report, guilloche_seed_hex)) => {
            let seed: Option<[u8; 64]> = hex::decode(&guilloche_seed_hex)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok());
            let pdf_bytes = match crate::report::pdf::render_pdf(&report, seed.as_ref()) {
                Ok(b) => b,
                Err(e) => return FfiPdfResult {
                    success: false,
                    pdf_bytes: None,
                    error_message: Some(format!("PDF rendering failed: {e}")),
                },
            };

            // Embed C2PA manifest in the PDF. Best-effort: if it fails,
            // return the unsigned PDF rather than failing the entire export.
            let final_pdf = embed_c2pa_in_report_pdf(&path, &pdf_bytes, &report)
                .unwrap_or_else(|e| {
                    log::warn!("C2PA embedding in PDF failed (returning unsigned PDF): {e}");
                    pdf_bytes
                });

            FfiPdfResult {
                success: true,
                pdf_bytes: Some(final_pdf),
                error_message: None,
            }
        }
        Err(e) => FfiPdfResult {
            success: false,
            pdf_bytes: None,
            error_message: Some(e),
        },
    }
    })
    })
}

/// Embed a C2PA JUMBF manifest directly into PDF bytes.
fn embed_c2pa_in_report_pdf(
    path: &str,
    pdf_bytes: &[u8],
    report: &WarReport,
) -> Result<Vec<u8>, String> {
    use authorproof_protocol::c2pa::C2paManifestBuilder;

    // Build an evidence packet for the document.
    let (_wire_packet, evidence_bytes, _) =
        crate::ffi::evidence_export::build_wire_packet(path.to_string(), "standard".into(), None, None)?;

    let evidence_packet = crate::ffi::evidence_derivative::decode_evidence_for_c2pa(&evidence_bytes)?;

    let doc_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(pdf_bytes);
        hasher.finalize().into()
    };

    let mut builder = C2paManifestBuilder::new(evidence_packet, evidence_bytes, doc_hash);
    builder = builder
        .document_filename(format!("{}-forensic.pdf", report.report_id))
        .format("application/pdf");

    // Load signing key and cert.
    let signing_key = crate::ffi::helpers::load_signing_key()
        .map_err(|e| format!("Failed to load signing key: {e}"))?;
    if let Ok(cert_der) = crate::ffi::helpers::load_or_generate_cert(&signing_key) {
        builder = builder.cert_der(cert_der);
    }

    // Enrich with forensic signals from stored events.
    let stored_events = crate::ffi::helpers::open_store()
        .and_then(|s| s.get_events_for_file(path).map_err(|e| format!("{e}")))
        .unwrap_or_default();
    if !stored_events.is_empty() {
        let (metrics, _) = crate::ffi::helpers::run_full_forensics(&stored_events);
        builder = crate::ffi::evidence_derivative::enrich_c2pa_builder(builder, &metrics);
    }

    // Build signed VC and embed in manifest.
    if let Ok((ear, author_did)) =
        crate::ffi::vc_export::build_ear_for_path(path, path, &signing_key)
    {
        let provider = crate::tpm::detect_provider();
        if let Ok(vc) = crate::war::profiles::vc::to_signed_verifiable_credential(
            &ear, &author_did, &*provider,
        ) {
            if let Ok(embed) = serde_json::to_string(&vc) {
                builder = builder.vc_embedded(embed);
            }
        }
    }

    // Embed JUMBF manifest directly in the PDF.
    authorproof_protocol::c2pa::embed_manifest_in_pdf(pdf_bytes, builder, &signing_key)
        .map_err(|e| format!("C2PA PDF embedding failed: {e}"))
}

fn convert_war_report(r: &WarReport, guilloche_seed_hex: &str) -> FfiWarReport {
    FfiWarReport {
        report_id: r.report_id.clone(),
        algorithm_version: r.algorithm_version.clone(),
        generated_at_epoch_ms: r.generated_at.timestamp_millis(),
        schema_version: r.schema_version.clone(),
        score: r.score,
        verdict: r.verdict.label().to_string(),
        verdict_description: r.verdict_description.clone(),
        likelihood_ratio: r.likelihood_ratio,
        enfsi_tier: r.enfsi_tier.label().to_string(),
        document_hash: r.document_hash.clone(),
        signing_key_fingerprint: r.signing_key_fingerprint.clone(),
        document_chars: r.document_chars,
        evidence_bundle_version: r.evidence_bundle_version.clone(),
        session_count: r.session_count as u32,
        total_duration_min: r.total_duration_min,
        revision_events: r.revision_events,
        device_attestation: r.device_attestation.clone(),
        checkpoints: r.checkpoints.iter().map(convert_checkpoint).collect(),
        sessions: r.sessions.iter().map(convert_session).collect(),
        process: convert_process(&r.process),
        flags: r.flags.iter().map(convert_flag).collect(),
        forgery: convert_forgery(&r.forgery),
        dimensions: r.dimensions.iter().map(convert_dimension).collect(),
        limitations: r.limitations.clone(),
        guilloche_seed_hex: guilloche_seed_hex.to_string(),
        provenance: r
            .provenance_breakdown
            .as_ref()
            .map(|p| FfiProvenanceBreakdown {
                total_fragments: p.total_fragments as u32,
                original_composition_pct: p.original_composition_pct,
                sourced_unknown_pct: p.sourced_unknown_pct,
                sourced_verified_pct: p.sourced_verified_pct,
                chain_depth: p.chain_depth,
                source_trustworthiness: p.source_trustworthiness,
                authenticity_score: p.authenticity_score,
                sources: p
                    .sources
                    .iter()
                    .map(|s| FfiProvenanceSource {
                        session_id: s.session_id.clone(),
                        app_bundle_id: s.app_bundle_id.clone().unwrap_or_default(),
                        fragment_count: s.fragment_count as u32,
                        verified: s.verified,
                    })
                    .collect(),
            }),
        document_words: r.document_words,
        document_sentences: r.document_sentences,
        document_paragraphs: r.document_paragraphs,
        writing_flow: r
            .writing_flow
            .iter()
            .map(|f| FfiFlowDataPoint {
                offset_min: f.offset_min,
                intensity: f.intensity,
                phase: f.phase.clone(),
            })
            .collect(),
        edit_topology: r
            .edit_topology
            .iter()
            .map(|e| FfiEditRegion {
                start_pct: e.start_pct,
                end_pct: e.end_pct,
                delta_sign: e.delta_sign,
                byte_count: e.byte_count,
            })
            .collect(),
        activity_contexts: r
            .activity_contexts
            .iter()
            .map(|a| FfiActivityContext {
                period_type: a.period_type.clone(),
                start_epoch_ms: a.start.timestamp_millis(),
                end_epoch_ms: a.end.timestamp_millis(),
                duration_min: a.duration_min,
                note: a.note.clone(),
            })
            .collect(),
        anomalies: r
            .anomalies
            .iter()
            .map(|a| FfiReportAnomaly {
                anomaly_type: a.anomaly_type.clone(),
                description: a.description.clone(),
                severity: a.severity.clone(),
            })
            .collect(),
        declaration_summary: r.declaration_summary.as_ref().map(|d| FfiDeclarationInfo {
            statement: d.statement.clone(),
            title: d.title.clone(),
            ai_tools: d.ai_tools.clone(),
            input_modalities: d.input_modalities.clone(),
            collaborator_count: d.collaborator_count as u32,
            signature_valid: d.signature_valid,
            created_at_epoch_ms: d.created_at.timestamp_millis(),
        }),
        key_hierarchy_summary: r.key_hierarchy_summary.as_ref().map(|k| FfiKeyHierarchyInfo {
            master_fingerprint: k.master_fingerprint.clone(),
            device_id: k.device_id.clone(),
            session_id: k.session_id.clone(),
            ratchet_count: k.ratchet_count,
            checkpoint_signatures: k.checkpoint_signatures as u32,
            session_started_epoch_ms: k.session_started.timestamp_millis(),
        }),
        physical_context: r.physical_context.as_ref().map(|p| FfiPhysicalContextInfo {
            clock_skew_ns: p.clock_skew_ns,
            thermal_proxy: p.thermal_proxy,
            silicon_puf_hash: p.silicon_puf_hash.clone(),
            io_latency_ns: p.io_latency_ns,
            combined_hash: p.combined_hash.clone(),
        }),
        beacon_info: r.beacon_info.as_ref().map(|b| FfiBeaconInfo {
            drand_round: b.drand_round,
            nist_pulse_index: b.nist_pulse_index,
            fetched_at: b.fetched_at.clone(),
            wp_key_id: b.wp_key_id.clone(),
        }),
        author_did: r.author_did.clone(),
        verifiable_credential_json: r.verifiable_credential_json.clone(),
        is_sample: r.is_sample,
        evidence_hash: r.evidence_hash.clone(),
        methodology: r.methodology.as_ref().map(|m| FfiStatisticalMethodology {
            lr_computation: m.lr_computation.clone(),
            confidence_interval: m.confidence_interval.clone(),
            calibration: m.calibration.clone(),
        }),
    }
}

fn convert_checkpoint(c: &ReportCheckpoint) -> FfiReportCheckpoint {
    FfiReportCheckpoint {
        ordinal: c.ordinal,
        timestamp_epoch_ms: c.timestamp.timestamp_millis(),
        content_hash: c.content_hash.clone(),
        content_size: c.content_size,
        vdf_iterations: c.vdf_iterations,
        elapsed_ms: c.elapsed_ms,
    }
}

fn convert_session(s: &ReportSession) -> FfiReportSession {
    FfiReportSession {
        index: s.index as u32,
        start_epoch_ms: s.start.timestamp_millis(),
        duration_min: s.duration_min,
        event_count: s.event_count as u32,
        words_drafted: s.words_drafted,
        device: s.device.clone(),
        summary: s.summary.clone(),
    }
}

fn convert_process(p: &ProcessEvidence) -> FfiProcessEvidence {
    FfiProcessEvidence {
        paste_operations: p.paste_operations,
        swf_checkpoints: p.swf_checkpoints,
        swf_avg_compute_ms: p.swf_avg_compute_ms,
        swf_chain_verified: p.swf_chain_verified,
        swf_backdating_hours: p.swf_backdating_hours,
        revision_intensity: p.revision_intensity,
        revision_baseline: p.revision_baseline.clone(),
        pause_median_sec: p.pause_median_sec,
        pause_p90_sec: p.pause_p90_sec,
        pause_max_sec: p.pause_max_sec,
        paste_ratio_pct: p.paste_ratio_pct,
        paste_max_chars: p.paste_max_chars,
        iki_cv: p.iki_cv,
        bigram_consistency: p.bigram_consistency,
        total_keystrokes: p.total_keystrokes,
        deletion_sequences: p.deletion_sequences,
        avg_deletion_length: p.avg_deletion_length,
        select_delete_ops: p.select_delete_ops,
    }
}

fn convert_flag(f: &ReportFlag) -> FfiReportFlag {
    FfiReportFlag {
        category: f.category.clone(),
        flag: f.flag.clone(),
        detail: f.detail.clone(),
        signal: f.signal.label().to_string(),
    }
}

fn convert_forgery(f: &ForgeryInfo) -> FfiForgeryInfo {
    FfiForgeryInfo {
        tier: f.tier.clone(),
        estimated_forge_time_sec: f.estimated_forge_time_sec,
        weakest_link: f.weakest_link.clone(),
        components: f
            .components
            .iter()
            .map(|c| FfiForgeryComponent {
                name: c.name.clone(),
                present: c.present,
                cost_cpu_sec: c.cost_cpu_sec,
                explanation: c.explanation.clone(),
            })
            .collect(),
    }
}

fn convert_dimension(d: &DimensionScore) -> FfiDimensionScore {
    FfiDimensionScore {
        name: d.name.clone(),
        score: d.score,
        lr: d.lr,
        log_lr: d.log_lr,
        confidence: d.confidence,
        key_discriminator: d.key_discriminator.clone(),
        color: d.color.clone(),
        analysis: d
            .analysis
            .iter()
            .map(|a| FfiDimensionDetail {
                label: a.label.clone(),
                text: a.text.clone(),
            })
            .collect(),
    }
}

/// Detect writing sessions from events using the default session gap heuristic.
pub(crate) fn detect_sessions_from_events(
    events: &[crate::store::SecureEvent],
) -> Vec<ReportSession> {
    if events.is_empty() {
        return vec![];
    }

    use crate::forensics::types::DEFAULT_SESSION_GAP_SEC;
    let gap_ns: i64 = (DEFAULT_SESSION_GAP_SEC * 1_000_000_000.0).clamp(0.0, i64::MAX as f64) as i64;
    let mut sessions = Vec::new();
    let mut session_start = 0usize;

    for i in 1..events.len() {
        let gap = events[i]
            .timestamp_ns
            .saturating_sub(events[i - 1].timestamp_ns);
        if gap > gap_ns {
            sessions.push(make_report_session(
                session_start,
                i - 1,
                events,
                sessions.len(),
            ));
            session_start = i;
        }
    }
    sessions.push(make_report_session(
        session_start,
        events.len() - 1,
        events,
        sessions.len(),
    ));

    sessions
}

fn make_report_session(
    start_idx: usize,
    end_idx: usize,
    events: &[crate::store::SecureEvent],
    session_num: usize,
) -> ReportSession {
    let first = &events[start_idx];
    let last = &events[end_idx];
    let duration_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns).max(0) as f64;
    let duration_min = duration_ns / 60_000_000_000.0;
    let event_count = end_idx - start_idx + 1;
    let size_change: i64 = events[start_idx..=end_idx]
        .iter()
        .map(|e| e.size_delta as i64)
        .sum();

    // When the delta sum is 0 but the document has content, use the final
    // file size as the net change. This happens when the initial checkpoint
    // was recorded before any size_delta tracking, or when deltas cancel out.
    let effective_change = if size_change == 0 && last.file_size > 0 {
        last.file_size
    } else {
        size_change
    };

    ReportSession {
        index: session_num + 1,
        start: DateTime::from_timestamp_nanos(first.timestamp_ns),
        duration_min,
        event_count,
        words_drafted: Some((effective_change.max(0) as u64) / BYTES_PER_WORD_ESTIMATE),
        device: Some(first.machine_id.clone()),
        summary: format!(
            "{} revision events, {} net characters changed",
            event_count, effective_change
        ),
    }
}

/// Map a report score to an AR4SI status value.
///
/// Score 0 with InsufficientData maps to `None` (not evaluated), not
/// `Contraindicated`, because the methodology has not issued a finding.
pub(crate) fn score_to_ar4si(score: u32, verdict: Verdict) -> Ar4siStatus {
    if verdict == Verdict::InsufficientData {
        return Ar4siStatus::None;
    }
    if score >= 60 {
        Ar4siStatus::Affirming
    } else if score >= 40 {
        Ar4siStatus::None
    } else if score >= 20 {
        Ar4siStatus::Warning
    } else {
        Ar4siStatus::Contraindicated
    }
}

/// Map a report score to a sourced_data AR4SI component value.
fn score_to_sourced_data(score: u32) -> i8 {
    if score >= 60 {
        Ar4siStatus::Affirming as i8
    } else if score >= 40 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    }
}

/// Map a hardware tier number to instance_identity AR4SI component value.
fn tier_to_instance_identity(tier_num: u8) -> i8 {
    if tier_num >= 3 {
        Ar4siStatus::Affirming as i8
    } else if tier_num >= 1 {
        Ar4siStatus::Warning as i8
    } else {
        Ar4siStatus::None as i8
    }
}

/// Build an AR4SI trust vector from report data and hardware tier.
pub(crate) fn build_trust_vector(report: &WarReport, tier_num: u8) -> TrustworthinessVector {
    TrustworthinessVector {
        sourced_data: score_to_sourced_data(report.score),
        hardware: if tier_num >= 2 {
            Ar4siStatus::Affirming as i8
        } else {
            Ar4siStatus::None as i8
        },
        instance_identity: tier_to_instance_identity(tier_num),
        storage_opaque: if report.key_hierarchy_summary.is_some() {
            Ar4siStatus::Affirming as i8
        } else {
            Ar4siStatus::None as i8
        },
        ..Default::default()
    }
}

/// Compute the cryptographic seal (h1/h2/h3) from a report's checkpoint chain.
///
/// Uses domain-separated SHA-256 hashing and signs h3 with Ed25519 using
/// the `cpoe-war-seal-v1` DST to match `Block::sign()`.
fn compute_report_seal(
    report: &WarReport,
    signing_key: &ed25519_dalek::SigningKey,
) -> Option<SealClaims> {
    use sha2::{Digest, Sha256};

    let pub_key = signing_key.verifying_key();
    let doc_bytes = match hex::decode(&report.document_hash) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("Invalid document_hash hex in report seal: {e}");
            return None;
        }
    };
    let chain_hash: [u8; 32] = report
        .checkpoints
        .iter()
        .fold(Sha256::new(), |mut h, cp| {
            h.update(cp.content_hash.as_bytes());
            h
        })
        .finalize()
        .into();

    let h1: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"cpoe-seal-h1-v1");
        h.update(&doc_bytes);
        h.update(chain_hash);
        h.finalize().into()
    };
    let h2: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"cpoe-seal-h2-v1");
        h.update(h1);
        h.update(pub_key.as_bytes());
        h.finalize().into()
    };
    let h3: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"cpoe-seal-h3-v1");
        h.update(h2);
        h.update(&doc_bytes);
        h.finalize().into()
    };

    // Domain-separated signature matching Block::sign() (cpoe-war-seal-v1 || h3).
    let mut sig_input = Vec::with_capacity(16 + 32);
    sig_input.extend_from_slice(crate::war::Block::SEAL_SIG_DST);
    sig_input.extend_from_slice(&h3);
    let sig = ed25519_dalek::Signer::sign(signing_key, &sig_input);

    Some(SealClaims {
        h1,
        h2,
        h3,
        signature: sig.to_bytes(),
        public_key: pub_key.to_bytes(),
    })
}

/// Collect anomaly warnings from a report.
fn collect_warnings(report: &WarReport) -> Vec<String> {
    report
        .anomalies
        .iter()
        .filter(|a| a.severity == "Alert" || a.severity == "Warning")
        .map(|a| format!("{}: {}", a.anomaly_type, a.description))
        .collect()
}

/// Build a W3C Verifiable Credential 2.0 JSON string from report data.
///
/// Constructs an EAR token with trust vector, seal, and chain metadata,
/// then projects it into an unsigned VC via the VC profile module.
/// Returns `None` if the signing key is unavailable or VC construction fails.
fn build_vc_json(
    report: &WarReport,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    metrics: &crate::forensics::ForensicMetrics,
) -> Option<String> {
    use std::collections::BTreeMap;

    let signing_key = signing_key?;
    let pub_key = signing_key.verifying_key();
    let author_did = crate::identity::did_key_from_public(pub_key.as_bytes())?;

    let (_, tier_num, _) = crate::ffi::helpers::detect_attestation_tier_info();
    let tv = build_trust_vector(report, tier_num);
    let seal = compute_report_seal(report, signing_key);
    let warnings = collect_warnings(report);

    let chain_duration = if report.total_duration_min > 0.0 {
        Some((report.total_duration_min * 60.0) as u64)
    } else {
        None
    };

    let evidence_ref = match hex::decode(&report.document_hash) {
        Ok(b) => Some(b),
        Err(e) => {
            log::warn!("Invalid document_hash hex in EAR evidence ref: {e}");
            None
        }
    };

    let appraisal = EarAppraisal {
        ear_status: score_to_ar4si(report.score, report.verdict),
        ear_trustworthiness_vector: Some(tv),
        ear_appraisal_policy_id: Some("urn:writerslogic:policy:pop-standard:1.0".to_string()),
        pop_seal: seal,
        pop_evidence_ref: evidence_ref,
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: None,
        pop_chain_length: Some(report.checkpoints.len() as u64),
        pop_chain_duration: chain_duration,
        pop_process_start: report
            .checkpoints
            .first()
            .map(|cp| cp.timestamp.to_rfc3339()),
        pop_process_end: report
            .checkpoints
            .last()
            .map(|cp| cp.timestamp.to_rfc3339()),
        pop_absence_claims: None,
        pop_warnings: if warnings.is_empty() {
            None
        } else {
            Some(warnings)
        },
    };

    let mut submods = BTreeMap::new();
    submods.insert("pop".to_string(), appraisal);

    let ear = EarToken {
        eat_profile: crate::war::ear::CPOE_EAR_PROFILE.to_string(),
        iat: chrono::Utc::now().timestamp(),
        ear_verifier_id: engine_verifier_id(),
        submods,
    };

    // SoftwareProvider takes ownership; the copy is zeroized when `signer` drops
    // at the end of this match block.
    let signer = crate::tpm::SoftwareProvider::from_signing_key(signing_key.clone());
    match crate::war::profiles::vc::to_signed_verifiable_credential(&ear, &author_did, &signer) {
        Ok(mut vc) => {
            let writing_mode = metrics
                .writing_mode
                .as_ref()
                .map(|wm| wm.mode.to_string());
            let comp_mode = metrics
                .composition_mode
                .as_ref()
                .and_then(|c| c.dominant_mode)
                .map(|m| m.to_string());
            let signals = build_vc_forensic_signals(metrics);
            vc.enrich_forensic_signals(writing_mode, comp_mode, signals);
            serde_json::to_string_pretty(&vc)
                .map_err(|e| log::warn!("VC JSON serialization failed: {e}"))
                .ok()
        }
        Err(e) => {
            log::warn!("VC construction failed: {e}");
            None
        }
    }
}

pub fn build_vc_forensic_signals(
    metrics: &crate::forensics::ForensicMetrics,
) -> Option<crate::war::profiles::vc::VcForensicSignals> {
    let has_any = metrics.cognitive_load.is_some()
        || metrics.revision_topology.is_some()
        || metrics.error_ecology.is_some()
        || metrics.likelihood_model.is_some()
        || metrics.composition_mode.is_some();
    if !has_any {
        return None;
    }
    Some(crate::war::profiles::vc::VcForensicSignals {
        cognitive_load_score: metrics
            .cognitive_load
            .as_ref()
            .map(|c| c.composite_score)
            .unwrap_or(0.0),
        revision_topology_score: metrics
            .revision_topology
            .as_ref()
            .map(|r| r.composite_score)
            .unwrap_or(0.0),
        error_ecology_score: metrics
            .error_ecology
            .as_ref()
            .map(|e| e.composite_score)
            .unwrap_or(0.0),
        likelihood_p_cognitive: metrics
            .likelihood_model
            .as_ref()
            .map(|l| l.session_p_cognitive)
            .unwrap_or(0.0),
        composition_mode_score: metrics
            .composition_mode
            .as_ref()
            .map(|c| c.composite_score)
            .unwrap_or(0.0),
        detour_ratio: metrics
            .revision_topology
            .as_ref()
            .map(|r| r.detour_ratio)
            .unwrap_or(0.0),
        leading_edge_divergence: metrics
            .revision_topology
            .as_ref()
            .map(|r| r.leading_edge_divergence)
            .unwrap_or(0.0),
        insertion_point_entropy: metrics
            .revision_topology
            .as_ref()
            .map(|r| r.insertion_point_entropy)
            .unwrap_or(0.0),
        words_per_minute: {
            let mean_iki_ms = metrics.cadence.mean_iki_ns / 1_000_000.0;
            if mean_iki_ms > 0.0 {
                Some((1000.0 / mean_iki_ms) * 12.0)
            } else {
                None
            }
        },
        mean_iki_ms: Some(metrics.cadence.mean_iki_ns / 1_000_000.0)
            .filter(|v| v.is_finite() && *v > 0.0),
        correction_ratio: Some(metrics.cadence.correction_ratio.get())
            .filter(|v| v.is_finite()),
        keystroke_count: Some(metrics.cadence.burst_count as u64 + metrics.cadence.pause_count as u64),
        hurst_exponent: metrics.hurst_exponent.filter(|h| h.is_finite()),
        forensic_score: Some(metrics.assessment_score.get())
            .filter(|v| v.is_finite()),
    })
}
