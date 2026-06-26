// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Ring-buffer accumulator for building fingerprints from streaming keystroke samples.

use super::activity::ActivityFingerprint;
use crate::jitter::SimpleJitterSample;
use crate::MutexRecover;
use authorproof_protocol::baseline::SessionBehavioralSummary;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
/// Ring-buffer accumulator for building fingerprints from streaming samples.
pub struct ActivityFingerprintAccumulator {
    samples: VecDeque<SimpleJitterSample>,
    max_samples: usize,
    cached_fingerprint: Mutex<Arc<ActivityFingerprint>>,
    cached_hurst: Mutex<Option<f64>>,
    dirty: AtomicBool,
}

impl ActivityFingerprintAccumulator {
    /// Default capacity: 10,000 samples.
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Downsample into a 9-bin `SessionBehavioralSummary` for wire protocol.
    pub fn to_session_summary(&self) -> SessionBehavioralSummary {
        let fp = self.current_fingerprint();

        // 50-bin (50ms each) -> 9-bin edges: 0,50,100,150,200,300,500,1000,2000ms
        let mut sum_hist = [0.0f64; 9];
        let h = &fp.iki_distribution.histogram;
        sum_hist[0] = h[0];
        sum_hist[1] = h[1];
        sum_hist[2] = h[2];
        sum_hist[3] = h[3];
        sum_hist[4] = h[4] + h[5];
        sum_hist[5] = h[6] + h[7] + h[8] + h[9];
        sum_hist[6] = h[10..20].iter().sum::<f64>();
        sum_hist[7] = h[20..40].iter().sum::<f64>();
        sum_hist[8] = h[40..50].iter().sum::<f64>();

        let duration_secs =
            if let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) {
                crate::utils::ns_elapsed(last.timestamp_ns, first.timestamp_ns) / 1_000_000_000
            } else {
                0
            };

        SessionBehavioralSummary {
            iki_histogram: sum_hist,
            iki_cv: if fp.iki_distribution.mean > 0.0 {
                fp.iki_distribution.std_dev / fp.iki_distribution.mean
            } else {
                0.0
            },
            hurst: {
                let mut cached = self.cached_hurst.lock_recover();
                if let Some(h) = *cached {
                    h
                } else {
                    let intervals: Vec<f64> = self
                        .samples
                        .iter()
                        .zip(self.samples.iter().skip(1))
                        .filter_map(|(a, b)| {
                            b.timestamp_ns
                                .checked_sub(a.timestamp_ns)
                                .map(crate::utils::ns_to_ms)
                        })
                        .filter(|&i| i > 0.0 && i < 5000.0)
                        .collect();
                    let h = if intervals.len() >= 20 {
                        crate::analysis::hurst::compute_hurst_rs(&intervals)
                            .map(|h| h.exponent)
                            .unwrap_or(0.5)
                    } else {
                        0.5
                    };
                    *cached = Some(h);
                    h
                }
            },
            pause_frequency: fp.pause_signature.sentence_pause_frequency
                + fp.pause_signature.paragraph_pause_frequency
                + fp.pause_signature.thinking_pause_frequency,
            duration_secs,
            keystroke_count: self.samples.len() as u64,
        }
    }

    /// Create an accumulator with the given maximum sample capacity.
    pub fn with_capacity(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            cached_fingerprint: Mutex::new(Arc::new(ActivityFingerprint::default())),
            cached_hurst: Mutex::new(None),
            dirty: AtomicBool::new(false),
        }
    }

    /// Push a sample, evicting the oldest if at capacity.
    ///
    /// Enforces monotonic timestamps to prevent replay attacks: any sample
    /// whose `timestamp_ns` is not strictly greater than the last accepted
    /// sample is silently dropped.  This makes it impossible to flood the
    /// accumulator with identical or out-of-order samples via any path.
    pub fn add_sample(&mut self, sample: &SimpleJitterSample) {
        // Reject duplicate and out-of-order samples.  A replayed sample would
        // share the same timestamp_ns as the original; a rewound sample would
        // have a strictly smaller one.  Both are invalid and indicate injection.
        if let Some(last) = self.samples.back() {
            if sample.timestamp_ns <= last.timestamp_ns {
                log::warn!(
                    "fingerprint: rejected out-of-order/replayed sample \
                     (sample_ts={}, last_ts={}); possible injection attempt",
                    sample.timestamp_ns,
                    last.timestamp_ns
                );
                return;
            }
        }
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(*sample);
        self.dirty.store(true, Ordering::Relaxed);
        *self.cached_hurst.lock_recover() = None;
    }

    /// Recompute fingerprint from buffered samples if dirty, caching the result.
    pub fn current_fingerprint(&self) -> Arc<ActivityFingerprint> {
        let mut cached = self.cached_fingerprint.lock_recover();
        if self.dirty.load(Ordering::Relaxed) || cached.sample_count == 0 {
            let samples: Vec<_> = self.samples.iter().cloned().collect();
            *cached = Arc::new(ActivityFingerprint::from_samples(&samples));
            self.dirty.store(false, Ordering::Relaxed);
        }
        Arc::clone(&*cached)
    }

    /// Snapshot of the current sample buffer for forensic analysis.
    pub fn samples(&self) -> Vec<SimpleJitterSample> {
        self.samples.iter().cloned().collect()
    }

    /// Return the number of samples currently buffered.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Clear all samples and reset the cached fingerprint.
    pub fn reset(&mut self) {
        self.samples.clear();
        *self.cached_fingerprint.lock_recover() = Arc::new(ActivityFingerprint::default());
        self.dirty.store(false, Ordering::Relaxed);
    }
}

impl Default for ActivityFingerprintAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
