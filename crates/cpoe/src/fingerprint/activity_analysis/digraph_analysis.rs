// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Digraph (zone-pair) IKI timing profile.

use std::collections::HashMap;

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

/// Per-digraph (zone pair) timing statistics computed via Welford's algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigraphTiming {
    pub count: u64,
    pub mean_ms: f64,
    pub std_dev_ms: f64,
}

impl Default for DigraphTiming {
    fn default() -> Self {
        Self {
            count: 0,
            mean_ms: 0.0,
            std_dev_ms: 0.0,
        }
    }
}

/// Top-N digraph (consecutive zone pair) IKI timing profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DigraphProfile {
    pub digraph_timings: HashMap<(u8, u8), DigraphTiming>,
}

impl DigraphProfile {
    /// Build digraph profile from consecutive sample pairs using Welford's
    /// online algorithm for per-digraph mean and variance.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self::default();
        }

        // Welford accumulators: (count, mean, M2)
        let mut accumulators: HashMap<(u8, u8), (u64, f64, f64)> = HashMap::new();

        for w in samples.windows(2) {
            let iki_ns = match w[1].timestamp_ns.checked_sub(w[0].timestamp_ns) {
                Some(d) if d > 0 => d,
                _ => continue,
            };
            let iki_ms = iki_ns as f64 / 1_000_000.0;
            if !iki_ms.is_finite() || iki_ms >= 10000.0 {
                continue;
            }

            let key = (w[0].zone.min(7), w[1].zone.min(7));
            let entry = accumulators.entry(key).or_insert((0, 0.0, 0.0));
            entry.0 += 1;
            let delta = iki_ms - entry.1;
            entry.1 += delta / entry.0 as f64;
            let delta2 = iki_ms - entry.1;
            entry.2 += delta * delta2;
        }

        let digraph_timings = accumulators
            .into_iter()
            .map(|(key, (count, mean, m2))| {
                let std_dev = if count > 1 {
                    (m2 / (count - 1) as f64).sqrt()
                } else {
                    0.0
                };
                (
                    key,
                    DigraphTiming {
                        count,
                        mean_ms: mean,
                        std_dev_ms: if std_dev.is_finite() { std_dev } else { 0.0 },
                    },
                )
            })
            .collect();

        Self { digraph_timings }
    }

    /// Weighted cosine similarity of mean_ms vectors over shared digraph keys.
    /// Returns 0.5 if fewer than 10 shared digraphs (inconclusive).
    pub fn similarity(&self, other: &Self) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for DigraphProfile {
    fn similarity(&self, other: &Self) -> f64 {
        let mut dot = 0.0f64;
        let mut norm_a = 0.0f64;
        let mut norm_b = 0.0f64;
        let mut shared = 0usize;

        for (key, timing_a) in &self.digraph_timings {
            if let Some(timing_b) = other.digraph_timings.get(key) {
                let w = (timing_a.count.min(timing_b.count)) as f64;
                let va = timing_a.mean_ms * w;
                let vb = timing_b.mean_ms * w;
                dot += va * vb;
                norm_a += va * va;
                norm_b += vb * vb;
                shared += 1;
            }
        }

        if shared < 10 {
            return 0.5;
        }

        if norm_a <= 0.0 || norm_b <= 0.0 {
            return 0.5;
        }

        let cosine = dot / (norm_a.sqrt() * norm_b.sqrt());
        if !cosine.is_finite() {
            return 0.5;
        }

        crate::utils::Probability::clamp(cosine).get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        for (key, other_timing) in &other.digraph_timings {
            let entry = self
                .digraph_timings
                .entry(*key)
                .or_default();
            let weighted_self = entry.count as f64 * self_weight;
            let weighted_other = other_timing.count as f64 * other_weight;
            let total = weighted_self + weighted_other;
            if total > 0.0 {
                let sw = weighted_self / total;
                let ow = weighted_other / total;
                entry.mean_ms = weighted_blend(entry.mean_ms, other_timing.mean_ms, sw, ow);
                entry.std_dev_ms =
                    weighted_blend(entry.std_dev_ms, other_timing.std_dev_ms, sw, ow);
            }
            entry.count = total.round() as u64;
        }
        // Scale counts for keys only in self
        for (key, timing) in &mut self.digraph_timings {
            if !other.digraph_timings.contains_key(key) {
                timing.count = (timing.count as f64 * self_weight).round() as u64;
            }
        }
        // Remove entries that rounded to zero
        self.digraph_timings.retain(|_, t| t.count > 0);
    }
}
