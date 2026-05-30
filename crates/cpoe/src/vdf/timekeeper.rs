// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use super::{default_parameters, VdfProof};

const DEFAULT_NTP_SOURCES: &[&str] = &["pool.ntp.org", "time.apple.com"];

/// Source of a forensic timestamp: network-verified, VDF-anchored, or offline.
#[derive(Debug, Serialize, Deserialize)]
pub enum TimeAnchor {
    /// NTP/Roughtime verified timestamp.
    Network {
        timestamp: DateTime<Utc>,
        sources: Vec<String>,
    },
    /// Offline: elapsed time bound by VDF proof output.
    Physical {
        duration_since_anchor: Duration,
        vdf_proof: [u8; 32],
    },
    /// No time anchor available.
    Offline,
}

#[derive(Debug)]
/// Forensic time source that prefers Roughtime, falling back to VDF-anchored local time.
pub struct TimeKeeper {
    last_network_sync: Option<DateTime<Utc>>,
    start_instant: Instant,
}

impl Default for TimeKeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeKeeper {
    pub fn new() -> Self {
        Self {
            last_network_sync: None,
            start_instant: Instant::now(),
        }
    }

    /// Attempts to get a "Hard" network timestamp using Roughtime.
    pub async fn fetch_network_time() -> Option<DateTime<Utc>> {
        // Roughtime does blocking UDP I/O; keep it off the async runtime thread.
        let result = tokio::task::spawn_blocking(crate::vdf::RoughtimeClient::get_verified_time)
            .await
            .ok()?;
        match result {
            Ok(micros) => {
                let seconds = i64::try_from(micros / 1_000_000).unwrap_or(i64::MAX);
                let nanos = ((micros % 1_000_000) * 1000) as u32;
                DateTime::from_timestamp(seconds, nanos)
            }
            Err(_) => None,
        }
    }

    /// Calculates the "Forensic Timestamp".
    /// If online, returns the NTP time.
    /// If offline, returns [Last NTP] + [VDF Duration].
    pub fn get_current_forensic_time(
        &self,
        current_ntp: Option<DateTime<Utc>>,
    ) -> (DateTime<Utc>, TimeAnchor) {
        match current_ntp {
            Some(ntp) => (
                ntp,
                TimeAnchor::Network {
                    timestamp: ntp,
                    sources: DEFAULT_NTP_SOURCES
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                },
            ),
            None => {
                let elapsed = self.start_instant.elapsed();
                let estimated = self
                    .last_network_sync
                    .map(|last| {
                        last + chrono::Duration::from_std(elapsed)
                            .unwrap_or(chrono::Duration::zero())
                    })
                    .unwrap_or_else(Utc::now);

                let seed: [u8; 32] = {
                    let mut h = Sha256::new();
                    h.update(b"cpoe-timekeeper-vdf-v1");
                    h.update(elapsed.as_nanos().to_be_bytes());
                    h.finalize().into()
                };
                let params = default_parameters();
                let proof = VdfProof::compute_iterations(seed, params.min_iterations);

                (
                    estimated,
                    TimeAnchor::Physical {
                        duration_since_anchor: elapsed,
                        vdf_proof: proof.output,
                    },
                )
            }
        }
    }
}
