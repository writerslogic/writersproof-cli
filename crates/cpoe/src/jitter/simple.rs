// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Simple jitter session (legacy capture used by platform hooks).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::timestamp_nanos_u64;

/// Lightweight jitter sample used by platform hooks.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SimpleJitterSample {
    /// Absolute timestamp in nanoseconds since epoch (keyDown time).
    pub timestamp_ns: i64,
    /// Nanoseconds elapsed since the previous keyDown.
    pub duration_since_last_ns: u64,
    /// QWERTY keyboard zone index for this keystroke.
    pub zone: u8,
    /// How long the key was held down (keyDown to keyUp), in nanoseconds.
    /// None if keyUp was not captured for this key.
    /// Skipped in bincode IPC serialization for backward compatibility.
    #[serde(skip)]
    pub dwell_time_ns: Option<u64>,
    /// Time from the previous key's release to this key's press, in nanoseconds.
    /// None if the previous keyUp was not captured.
    #[serde(skip)]
    pub flight_time_ns: Option<u64>,
}

/// Legacy jitter session that collects simple timestamped samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleJitterSession {
    /// UUID session identifier.
    pub id: String,
    /// When this session began.
    pub start_time: DateTime<Utc>,
    /// Collected jitter samples.
    pub samples: Vec<SimpleJitterSample>,
}

impl Default for SimpleJitterSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleJitterSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            start_time: Utc::now(),
            samples: Vec::new(),
        }
    }

    /// Append a sample with the given nanosecond timestamp and keyboard zone.
    pub fn add_sample(&mut self, timestamp_ns: i64, zone: u8) {
        let start_nanos = timestamp_nanos_u64(self.start_time);
        let last_ts = self
            .samples
            .last()
            .map(|s| s.timestamp_ns)
            .unwrap_or(i64::try_from(start_nanos).unwrap_or(i64::MAX));
        let duration = crate::utils::ns_elapsed(timestamp_ns, last_ts);

        self.samples.push(SimpleJitterSample {
            timestamp_ns,
            duration_since_last_ns: duration,
            zone,
            dwell_time_ns: None,
            flight_time_ns: None,
        });
    }
}
