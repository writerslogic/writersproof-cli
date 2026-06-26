// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::fingerprint::activity::ActivityFingerprint;
use crate::fingerprint::voice::StyleFingerprint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type ProfileId = String;

/// Combined activity + optional style fingerprint for one author.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorFingerprint {
    pub id: ProfileId,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub activity: ActivityFingerprint,
    #[serde(alias = "voice")]
    pub style: Option<StyleFingerprint>,
    pub sample_count: u64,
    pub confidence: f64,
}

impl AuthorFingerprint {
    pub fn new(activity: ActivityFingerprint) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            style: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    pub fn with_id(id: ProfileId, activity: ActivityFingerprint) -> Self {
        Self {
            id,
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            style: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    pub fn with_style(mut self, style: StyleFingerprint) -> Self {
        self.style = Some(style);
        self
    }

    /// Multi-factor confidence using logarithmic saturation.
    pub fn update_confidence(&mut self) {
        let sample_conf = 1.0 - (-(self.sample_count as f64) / 500.0).exp();

        let session_bonus = if self.activity.session_signature.session_count > 1 {
            (1.0 - (-(self.activity.session_signature.session_count as f64) / 5.0).exp()) * 0.2
        } else {
            0.0
        };

        let style_bonus = if self.style.is_some() { 0.1 } else { 0.0 };

        self.confidence = (sample_conf + session_bonus + style_bonus).min(1.0);
    }

    /// Exponential moving average merge for temporal drift adaptation.
    ///
    /// `alpha` controls how much weight the `recent` fingerprint receives
    /// (0.0 = keep old, 1.0 = fully replace with recent).
    pub fn update_with_ema(&mut self, recent: &AuthorFingerprint, alpha: f64) {
        log::debug!(
            "AuthorFingerprint::update_with_ema: id={}, alpha={}",
            self.id,
            alpha
        );
        use super::activity::WeightedDistribution;

        let alpha = alpha.clamp(0.0, 1.0);
        let old_weight = 1.0 - alpha;

        self.activity.iki_distribution.weighted_merge(
            &recent.activity.iki_distribution,
            old_weight,
            alpha,
        );
        self.activity
            .zone_profile
            .weighted_merge(&recent.activity.zone_profile, old_weight, alpha);
        self.activity.pause_signature.weighted_merge(
            &recent.activity.pause_signature,
            old_weight,
            alpha,
        );
        self.activity.dwell_distribution.weighted_merge(
            &recent.activity.dwell_distribution,
            old_weight,
            alpha,
        );
        self.activity.flight_distribution.weighted_merge(
            &recent.activity.flight_distribution,
            old_weight,
            alpha,
        );
        self.activity.digraph_profile.weighted_merge(
            &recent.activity.digraph_profile,
            old_weight,
            alpha,
        );

        if let (Some(ref mut v), Some(rv)) = (&mut self.style, &recent.style) {
            v.merge(rv);
        } else if let Some(rv) = &recent.style {
            self.style = Some(rv.clone());
        }

        self.sample_count += recent.sample_count;
        self.updated_at = Utc::now();
        self.update_confidence();
    }

    pub fn merge(&mut self, other: &AuthorFingerprint) {
        log::debug!(
            "AuthorFingerprint::merge: self_id={}, other_id={}",
            self.id,
            other.id
        );
        self.activity.merge(&other.activity);
        if let Some(other_style) = &other.style {
            if let Some(ref mut style) = self.style {
                style.merge(other_style);
            } else {
                self.style = Some(other_style.clone());
            }
        }
        self.sample_count += other.sample_count;
        self.updated_at = Utc::now();
        self.update_confidence();
    }
}
