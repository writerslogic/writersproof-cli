// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! ForensicEngine for physical context analysis.

use statrs::distribution::{ContinuousCDF, Normal};

use crate::jitter::SimpleJitterSample;
use crate::PhysicalContext;

use super::cadence::is_retyped_content;

/// Physical-context forensic analysis result.
#[derive(Debug, Clone)]
pub struct ForensicReport {
    pub confidence_score: f64,
    pub is_anomaly: bool,
    /// Retyped content detected via robotic IKI cadence.
    pub is_retyped_content: bool,
    pub details: Vec<SignalAnalysis>,
}

/// Single signal z-score analysis.
#[derive(Debug, Clone)]
pub struct SignalAnalysis {
    pub name: String,
    pub z_score: f64,
    pub probability: f64,
}

/// Physical context and cadence analysis engine.
#[derive(Debug)]
pub struct ForensicEngine;

impl ForensicEngine {
    /// Detect retyped content via cognitive cadence analysis.
    ///
    /// Original composition shows "cognitive bursts" (fast typing + long pauses).
    /// Retyped/transcribed content has unnaturally stable rhythm.
    pub fn evaluate_cadence(samples: &[SimpleJitterSample]) -> bool {
        is_retyped_content(samples)
    }

    /// Full forensic authorship analysis from `SecureEvent` sequence.
    pub fn evaluate_authorship(
        _file_path: &str,
        events: &[crate::store::SecureEvent],
    ) -> super::types::AuthorshipProfile {
        let event_data = super::types::EventData::from_secure_events(events);
        let regions = super::types::build_edit_regions(events);
        super::analysis::build_profile(&event_data, &regions)
    }

    /// Evaluate `PhysicalContext` signals against known `(name, mean, std_dev)` baselines.
    pub fn evaluate(
        ctx: &PhysicalContext,
        baselines: &[(String, f64, f64)], // (name, mean, std_dev)
    ) -> ForensicReport {
        let mut analyses = Vec::new();
        let mut total_prob = 0.0;
        let mut count = 0;

        for (name, mean, std_dev) in baselines {
            let val = match name.as_str() {
                "clock_skew" => ctx.clock_skew as f64,
                "thermal_proxy" => ctx.thermal_proxy as f64,
                "io_latency" => ctx.io_latency_ns as f64,
                _ => continue,
            };

            let z_score = if *std_dev > 0.0 {
                (val - *mean).abs() / *std_dev
            } else {
                0.0
            };

            let prob = if *std_dev > 0.0 {
                if let Ok(n) = Normal::new(*mean, *std_dev) {
                    2.0 * (1.0 - n.cdf(mean + (val - mean).abs()))
                } else {
                    1.0
                }
            } else {
                1.0
            };

            analyses.push(SignalAnalysis {
                name: name.clone(),
                z_score,
                probability: prob,
            });

            total_prob += prob;
            count += 1;
        }

        let confidence = if count > 0 {
            total_prob / count as f64
        } else {
            1.0
        };

        ForensicReport {
            confidence_score: confidence,
            is_anomaly: confidence < 0.01,
            is_retyped_content: false,
            details: analyses,
        }
    }
}
