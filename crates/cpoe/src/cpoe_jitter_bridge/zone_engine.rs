// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::cpoe_jitter_bridge::helpers::interval_to_bucket;
use crate::jitter::{encode_zone_transition, keycode_to_zone, TypingProfile};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Track keyboard zone transitions and build a typing profile histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTrackingEngine {
    pub(crate) prev_zone: i32,
    pub(crate) profile: TypingProfile,
    #[serde(skip)]
    pub(crate) prev_instant: Option<Instant>,
}

impl Default for ZoneTrackingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneTrackingEngine {
    pub fn new() -> Self {
        Self {
            prev_zone: -1,
            profile: TypingProfile::default(),
            prev_instant: None,
        }
    }

    pub fn record_keycode(&mut self, keycode: u16) -> Option<u8> {
        let zone = keycode_to_zone(keycode);
        self.record_zone(zone)
    }

    pub fn record_zone(&mut self, zone: i32) -> Option<u8> {
        if zone < 0 {
            return None;
        }

        let now = Instant::now();
        let zone_transition = if self.prev_zone >= 0 {
            if let Some(prev) = self.prev_instant {
                let interval = now.duration_since(prev);
                let encoded = encode_zone_transition(self.prev_zone, zone);
                if let Some(bucket) = interval_to_bucket(interval) {
                    self.update_profile(self.prev_zone, zone, bucket);
                }
                Some(encoded)
            } else {
                None
            }
        } else {
            None
        };

        self.prev_zone = zone;
        self.prev_instant = Some(now);
        zone_transition
    }

    pub fn profile(&self) -> &TypingProfile {
        &self.profile
    }

    pub fn prev_zone(&self) -> i32 {
        self.prev_zone
    }

    fn update_profile(&mut self, from_zone: i32, to_zone: i32, bucket: u8) {
        self.profile.record_transition(from_zone, to_zone, bucket);
    }
}
