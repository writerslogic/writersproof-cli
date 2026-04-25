// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::baseline::streaming::StreamingStatsExt;
use authorproof_protocol::baseline::{
    BaselineDigest, ConfidenceTier, SessionBehavioralSummary, StreamingStats,
};

const IKI_BIN_CENTERS: [f64; 9] = [
    25.0, 75.0, 125.0, 175.0, 250.0, 400.0, 750.0, 1500.0, 2500.0,
];

pub fn compute_initial_digest(identity_fingerprint: Vec<u8>) -> BaselineDigest {
    BaselineDigest {
        version: 1,
        session_count: 0,
        total_keystrokes: 0,
        iki_stats: StreamingStats::new_empty(),
        cv_stats: StreamingStats::new_empty(),
        hurst_stats: StreamingStats::new_empty(),
        aggregate_iki_histogram: [0.0; 9],
        pause_stats: StreamingStats::new_empty(),
        session_merkle_root: vec![0u8; 32],
        confidence_tier: ConfidenceTier::PopulationReference,
        computed_at: now_as_secs(),
        identity_fingerprint,
    }
}

/// Incorporate a session's behavioral summary into the running digest in place.
///
/// Uses numerically stable running average: mu_n = mu_{n-1} + (x_n - mu_{n-1}) / n
pub fn update_digest_in_place(digest: &mut BaselineDigest, summary: &SessionBehavioralSummary) {
    digest.session_count += 1;
    digest.total_keystrokes = digest
        .total_keystrokes
        .saturating_add(summary.keystroke_count);

    let total_weight: f64 = summary.iki_histogram.iter().sum();
    let mean_iki = if total_weight > f64::EPSILON {
        summary
            .iki_histogram
            .iter()
            .zip(IKI_BIN_CENTERS.iter())
            .map(|(&w, &c)| w * c)
            .sum::<f64>()
            / total_weight
    } else {
        0.0
    };

    if mean_iki.is_finite() {
        digest.iki_stats.update(mean_iki);
    }
    if summary.iki_cv.is_finite() {
        digest.cv_stats.update(summary.iki_cv);
    }
    if summary.hurst.is_finite() {
        digest.hurst_stats.update(summary.hurst);
    }
    if summary.pause_frequency.is_finite() {
        digest.pause_stats.update(summary.pause_frequency);
    }

    let n_inv = 1.0 / (digest.session_count as f64);
    for (prev, &cur) in digest
        .aggregate_iki_histogram
        .iter_mut()
        .zip(summary.iki_histogram.iter())
    {
        *prev += (cur - *prev) * n_inv;
    }

    digest.confidence_tier = ConfidenceTier::from_session_count(digest.session_count);
    digest.computed_at = now_as_secs();
}

use crate::utils::now_secs as now_as_secs;
