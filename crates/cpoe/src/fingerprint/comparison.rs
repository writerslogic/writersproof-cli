// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Fingerprint comparison, authorship probability, and profile clustering.

use super::{AuthorFingerprint, ProfileId};
use serde::{Deserialize, Serialize};

/// Similarity above this threshold yields a SameAuthor verdict.
const SAME_AUTHOR_THRESHOLD: f64 = 0.80;
/// Similarity above this threshold yields a LikelySameAuthor verdict.
const LIKELY_SAME_THRESHOLD: f64 = 0.60;
/// Similarity above this threshold yields an Inconclusive verdict.
const INCONCLUSIVE_THRESHOLD: f64 = 0.40;
/// Similarity above this threshold yields a LikelyDifferentAuthors verdict.
const LIKELY_DIFFERENT_THRESHOLD: f64 = 0.20;

/// Confidence scales linearly with sample count, saturating at this value.
pub(crate) const CONFIDENCE_SATURATION_SAMPLES: f64 = 200.0;

// --- Per-dimension weights (activity) ---
/// Inter-key interval distribution weight.
const W_IKI: f64 = 0.20;
/// Zone profile weight.
const W_ZONE: f64 = 0.15;
/// Pause signature weight.
const W_PAUSE: f64 = 0.10;
/// Dwell time distribution weight.
const W_DWELL: f64 = 0.10;
/// Flight time distribution weight.
const W_FLIGHT: f64 = 0.08;
/// Digraph profile weight.
const W_DIGRAPH: f64 = 0.12;
/// Hurst exponent weight.
const W_HURST: f64 = 0.05;

// --- Per-dimension weights (style) ---
/// Word length distribution weight.
const W_WORD_LEN: f64 = 0.05;
/// Punctuation signature weight.
const W_PUNCT: f64 = 0.05;
/// N-gram signature weight.
const W_NGRAM: f64 = 0.05;
/// Correction/backspace pattern weight.
const W_CORRECTION: f64 = 0.05;

/// Pairwise fingerprint comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintComparison {
    pub profile_a: ProfileId,
    pub profile_b: ProfileId,
    /// 0.0 - 1.0
    pub similarity: f64,
    pub activity_similarity: f64,
    #[serde(alias = "voice_similarity")]
    pub style_similarity: Option<f64>,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
    pub components: ComparisonComponents,
}

impl FingerprintComparison {
    /// Sigmoid-based probability that the two profiles share authorship.
    ///
    /// Maps similarity through a logistic curve centered on the likely-same
    /// threshold, then scales by confidence.
    pub fn match_probability(&self) -> f64 {
        let k = 10.0;
        let midpoint = LIKELY_SAME_THRESHOLD;
        let raw = 1.0 / (1.0 + (-k * (self.similarity - midpoint)).exp());
        let result = raw * self.confidence;
        if result.is_finite() {
            result.clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

/// Similarity-based authorship verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonVerdict {
    SameAuthor,
    LikelySameAuthor,
    Inconclusive,
    LikelyDifferentAuthors,
    DifferentAuthors,
}

impl ComparisonVerdict {
    /// Classify a similarity score into a verdict category.
    pub fn from_similarity(similarity: f64) -> Self {
        if similarity > SAME_AUTHOR_THRESHOLD {
            Self::SameAuthor
        } else if similarity > LIKELY_SAME_THRESHOLD {
            Self::LikelySameAuthor
        } else if similarity > INCONCLUSIVE_THRESHOLD {
            Self::Inconclusive
        } else if similarity > LIKELY_DIFFERENT_THRESHOLD {
            Self::LikelyDifferentAuthors
        } else {
            Self::DifferentAuthors
        }
    }

    /// Classify with hysteresis: if `previous` is provided and the similarity
    /// is within 0.05 of the threshold that *directly separates* `new` from
    /// `previous`, retain `previous` to avoid flip-flopping on boundary values.
    ///
    /// Only the specific threshold between the two adjacent verdicts is checked;
    /// checking all thresholds would lock in a far-off previous verdict when
    /// crossing an unrelated boundary.
    pub fn from_similarity_with_hysteresis(similarity: f64, previous: Option<Self>) -> Self {
        let new = Self::from_similarity(similarity);
        if let Some(prev) = previous {
            if new != prev {
                if let Some(t) = Self::threshold_between(new, prev) {
                    if (similarity - t).abs() < 0.05 {
                        return prev;
                    }
                }
            }
        }
        new
    }

    /// Return the threshold that directly separates two adjacent verdicts,
    /// or `None` if they are not adjacent (differ by more than one level).
    fn threshold_between(a: Self, b: Self) -> Option<f64> {
        let ord = |v: Self| -> u8 {
            match v {
                Self::DifferentAuthors => 0,
                Self::LikelyDifferentAuthors => 1,
                Self::Inconclusive => 2,
                Self::LikelySameAuthor => 3,
                Self::SameAuthor => 4,
            }
        };
        let (lo, hi) = if ord(a) < ord(b) { (a, b) } else { (b, a) };
        if ord(hi).saturating_sub(ord(lo)) != 1 {
            return None;
        }
        Some(match hi {
            Self::LikelyDifferentAuthors => LIKELY_DIFFERENT_THRESHOLD,
            Self::Inconclusive => INCONCLUSIVE_THRESHOLD,
            Self::LikelySameAuthor => LIKELY_SAME_THRESHOLD,
            Self::SameAuthor => SAME_AUTHOR_THRESHOLD,
            Self::DifferentAuthors => return None,
        })
    }

    /// Return a human-readable description of this verdict.
    pub fn description(&self) -> &'static str {
        match self {
            Self::SameAuthor => "Very likely the same author",
            Self::LikelySameAuthor => "Probably the same author",
            Self::Inconclusive => "Results inconclusive",
            Self::LikelyDifferentAuthors => "Probably different authors",
            Self::DifferentAuthors => "Very likely different authors",
        }
    }
}

/// Per-dimension similarity breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComparisonComponents {
    pub iki_similarity: f64,
    pub zone_similarity: f64,
    pub pause_similarity: f64,
    #[serde(default)]
    pub dwell_similarity: Option<f64>,
    #[serde(default)]
    pub flight_similarity: Option<f64>,
    #[serde(default)]
    pub digraph_similarity: Option<f64>,
    #[serde(default)]
    pub hurst_similarity: Option<f64>,
    #[serde(default)]
    pub correction_similarity: Option<f64>,
    pub word_length_similarity: Option<f64>,
    pub punctuation_similarity: Option<f64>,
    pub ngram_similarity: Option<f64>,
}

/// Full pairwise comparison of two author fingerprints.
pub fn compare_fingerprints(a: &AuthorFingerprint, b: &AuthorFingerprint) -> FingerprintComparison {
    let activity_similarity = a.activity.similarity(&b.activity);

    let iki_sim = a
        .activity
        .iki_distribution
        .similarity(&b.activity.iki_distribution);
    let zone_sim = a.activity.zone_profile.similarity(&b.activity.zone_profile);
    let pause_sim = a
        .activity
        .pause_signature
        .similarity(&b.activity.pause_signature);

    use super::activity::WeightedDistribution;
    let dwell_sim = Some(
        <super::activity_analysis::DwellDistribution as WeightedDistribution>::similarity(
            &a.activity.dwell_distribution,
            &b.activity.dwell_distribution,
        ),
    );
    let flight_sim = Some(
        <super::activity_analysis::FlightTimeDistribution as WeightedDistribution>::similarity(
            &a.activity.flight_distribution,
            &b.activity.flight_distribution,
        ),
    );
    let digraph_sim = Some(
        <super::activity_analysis::DigraphProfile as WeightedDistribution>::similarity(
            &a.activity.digraph_profile,
            &b.activity.digraph_profile,
        ),
    );
    let hurst_sim = match (a.activity.hurst_exponent, b.activity.hurst_exponent) {
        (Some(ha), Some(hb)) => {
            let sim = 1.0 - (ha - hb).abs().min(1.0);
            if sim.is_finite() {
                Some(sim)
            } else {
                None
            }
        }
        _ => None,
    };

    // Style dimensions (including correction similarity from backspace patterns).
    let (style_similarity, word_len_sim, punct_sim, ngram_sim, correction_sim) =
        if let (Some(va), Some(vb)) = (&a.style, &b.style) {
            let sim = va.similarity(vb);
            let word_len = super::voice::histogram_similarity(
                &va.word_length_distribution,
                &vb.word_length_distribution,
            );
            let punct = va
                .punctuation_signature
                .similarity(&vb.punctuation_signature);
            let ngram = va.ngram_signature.similarity(&vb.ngram_signature);
            let correction = va.backspace_signature.similarity(&vb.backspace_signature);
            (
                Some(sim),
                Some(word_len),
                Some(punct),
                Some(ngram),
                Some(correction),
            )
        } else {
            (None, None, None, None, None)
        };

    // Per-dimension weighted similarity with dynamic redistribution.
    let similarity = weighted_similarity(
        iki_sim,
        zone_sim,
        pause_sim,
        dwell_sim,
        flight_sim,
        digraph_sim,
        hurst_sim,
        word_len_sim,
        punct_sim,
        ngram_sim,
        correction_sim,
    );

    let min_samples = a.sample_count.min(b.sample_count);
    let confidence = confidence_from_samples(min_samples);

    FingerprintComparison {
        profile_a: a.id.clone(),
        profile_b: b.id.clone(),
        similarity,
        activity_similarity,
        style_similarity,
        confidence,
        verdict: ComparisonVerdict::from_similarity(similarity),
        components: ComparisonComponents {
            iki_similarity: iki_sim,
            zone_similarity: zone_sim,
            pause_similarity: pause_sim,
            dwell_similarity: dwell_sim,
            flight_similarity: flight_sim,
            digraph_similarity: digraph_sim,
            hurst_similarity: hurst_sim,
            correction_similarity: correction_sim,
            word_length_similarity: word_len_sim,
            punctuation_similarity: punct_sim,
            ngram_similarity: ngram_sim,
        },
    }
}

/// Compute weighted similarity across all available dimensions.
///
/// When a dimension is absent (None), its weight is redistributed
/// proportionally among the present dimensions.
#[allow(clippy::too_many_arguments)]
fn weighted_similarity(
    iki: f64,
    zone: f64,
    pause: f64,
    dwell: Option<f64>,
    flight: Option<f64>,
    digraph: Option<f64>,
    hurst: Option<f64>,
    word_len: Option<f64>,
    punct: Option<f64>,
    ngram: Option<f64>,
    correction: Option<f64>,
) -> f64 {
    // All dimensions: add if finite, skip and redistribute weight if NaN/inf/absent.
    let all: [(Option<f64>, f64); 11] = [
        (Some(iki), W_IKI),
        (Some(zone), W_ZONE),
        (Some(pause), W_PAUSE),
        (dwell, W_DWELL),
        (flight, W_FLIGHT),
        (digraph, W_DIGRAPH),
        (hurst, W_HURST),
        (word_len, W_WORD_LEN),
        (punct, W_PUNCT),
        (ngram, W_NGRAM),
        (correction, W_CORRECTION),
    ];

    let mut total_weight = 0.0;
    let mut weighted_sum = 0.0;
    for (value, weight) in &all {
        if let Some(v) = value {
            if v.is_finite() {
                weighted_sum += v * weight;
                total_weight += weight;
            }
        }
    }

    if total_weight > 0.0 {
        (weighted_sum / total_weight).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Linear confidence saturating at `CONFIDENCE_SATURATION_SAMPLES`.
fn confidence_from_samples(samples: u64) -> f64 {
    (samples as f64 / CONFIDENCE_SATURATION_SAMPLES).min(1.0)
}

#[derive(Debug)]
/// Threshold-based matcher for finding similar profiles.
pub struct ProfileMatcher {
    threshold: f64,
    max_results: usize,
}

impl ProfileMatcher {
    /// Default threshold: 0.5, max results: 10.
    pub fn new() -> Self {
        Self {
            threshold: 0.5,
            max_results: 10,
        }
    }

    /// Set the minimum similarity threshold (clamped to 0.0-1.0).
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = crate::utils::Probability::clamp(threshold).get();
        self
    }

    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Return candidates above threshold, sorted by descending similarity.
    pub fn find_matches(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Vec<MatchResult> {
        let mut results: Vec<_> = candidates
            .iter()
            .filter(|c| c.id != target.id)
            .map(|candidate| {
                let comparison = compare_fingerprints(target, candidate);
                MatchResult {
                    profile_id: candidate.id.clone(),
                    similarity: comparison.similarity,
                    confidence: comparison.confidence,
                    verdict: comparison.verdict,
                }
            })
            .filter(|r| r.similarity >= self.threshold)
            .collect();

        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(self.max_results);

        results
    }

    /// Return the single highest-similarity match, if any.
    pub fn find_best_match(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Option<MatchResult> {
        self.find_matches(target, candidates).into_iter().next()
    }

    /// 1:1 verification against a specific profile.
    pub fn verify_match(
        &self,
        target: &AuthorFingerprint,
        candidate: &AuthorFingerprint,
    ) -> VerificationResult {
        let comparison = compare_fingerprints(target, candidate);

        VerificationResult {
            matches: comparison.similarity >= self.threshold,
            similarity: comparison.similarity,
            confidence: comparison.confidence,
            verdict: comparison.verdict,
        }
    }
}

impl Default for ProfileMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Single match from a profile search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub profile_id: ProfileId,
    pub similarity: f64,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
}

/// 1:1 verification outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub matches: bool,
    pub similarity: f64,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
}

#[derive(Debug)]
/// Leader-based greedy clustering of fingerprints by similarity.
pub struct BatchComparator {
    cluster_threshold: f64,
}

impl BatchComparator {
    /// Default clustering threshold: 0.7.
    pub fn new() -> Self {
        Self {
            cluster_threshold: 0.7,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.cluster_threshold = crate::utils::Probability::clamp(threshold).get();
        self
    }

    /// Greedy leader-based clustering. O(n^2) pairwise comparisons.
    ///
    /// Truncates to 500 fingerprints with a warning if the input exceeds
    /// that limit. Callers with large datasets should sample first.
    pub fn find_clusters(&self, fingerprints: &[AuthorFingerprint]) -> Vec<Cluster> {
        let n = fingerprints.len();
        if n == 0 {
            return Vec::new();
        }
        if n > 500 {
            log::warn!(
                "find_clusters: {} fingerprints exceeds 500 limit, truncating",
                n
            );
            return self.find_clusters(&fingerprints[..500]);
        }

        let mut assigned = vec![false; n];
        let mut clusters = Vec::new();

        for i in 0..n {
            if assigned[i] {
                continue;
            }

            let mut cluster = Cluster {
                representative: fingerprints[i].id.clone(),
                members: vec![fingerprints[i].id.clone()],
                avg_internal_similarity: 1.0,
            };
            assigned[i] = true;

            // Cache leader→member similarities to avoid recomputation below.
            let mut member_indices: Vec<usize> = Vec::new();
            let mut leader_sims: Vec<f64> = Vec::new();

            for j in (i + 1)..n {
                if assigned[j] {
                    continue;
                }

                let comparison = compare_fingerprints(&fingerprints[i], &fingerprints[j]);
                if comparison.similarity >= self.cluster_threshold {
                    cluster.members.push(fingerprints[j].id.clone());
                    member_indices.push(j);
                    leader_sims.push(comparison.similarity);
                    assigned[j] = true;
                }
            }

            if cluster.members.len() > 1 {
                // Start with cached leader→member similarities.
                let mut total_sim: f64 = leader_sims.iter().copied().sum();
                let mut count = leader_sims.len();

                // Compute only member↔member (non-leader) pairs.
                for (idx_a, &ja) in member_indices.iter().enumerate() {
                    for &jb in member_indices.iter().skip(idx_a + 1) {
                        let sim =
                            compare_fingerprints(&fingerprints[ja], &fingerprints[jb]).similarity;
                        if sim.is_finite() {
                            total_sim += sim;
                            count += 1;
                        }
                    }
                }
                if count > 0 && total_sim.is_finite() {
                    cluster.avg_internal_similarity = total_sim / count as f64;
                }
            }

            clusters.push(cluster);
        }

        clusters
    }
}

impl Default for BatchComparator {
    fn default() -> Self {
        Self::new()
    }
}

/// Group of fingerprints above the clustering threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub representative: ProfileId,
    pub members: Vec<ProfileId>,
    pub avg_internal_similarity: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::activity::ActivityFingerprint;

    fn make_fingerprint(id: &str, sample_count: u64) -> AuthorFingerprint {
        let mut fp = AuthorFingerprint::with_id(id.to_string(), ActivityFingerprint::default());
        fp.sample_count = sample_count;
        fp.update_confidence();
        fp
    }

    #[test]
    fn test_verdict_from_similarity() {
        assert_eq!(
            ComparisonVerdict::from_similarity(0.9),
            ComparisonVerdict::SameAuthor
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.70),
            ComparisonVerdict::LikelySameAuthor
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.5),
            ComparisonVerdict::Inconclusive
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.3),
            ComparisonVerdict::LikelyDifferentAuthors
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.1),
            ComparisonVerdict::DifferentAuthors
        );
    }

    #[test]
    fn test_compare_fingerprints() {
        let fp1 = make_fingerprint("a", 100);
        let fp2 = make_fingerprint("b", 100);

        let comparison = compare_fingerprints(&fp1, &fp2);

        assert_eq!(comparison.profile_a, "a");
        assert_eq!(comparison.profile_b, "b");
        assert!(comparison.similarity >= 0.0 && comparison.similarity <= 1.0);
    }

    #[test]
    fn test_profile_matcher() {
        let target = make_fingerprint("target", 100);
        let candidates = vec![
            make_fingerprint("a", 100),
            make_fingerprint("b", 100),
            make_fingerprint("c", 100),
        ];

        let matcher = ProfileMatcher::new().with_threshold(0.0);
        let matches = matcher.find_matches(&target, &candidates);

        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_confidence_from_samples() {
        assert_eq!(confidence_from_samples(0), 0.0);
        assert!((confidence_from_samples(100) - 0.5).abs() < f64::EPSILON);
        assert_eq!(confidence_from_samples(200), 1.0);
        assert_eq!(confidence_from_samples(1000), 1.0);
    }

    #[test]
    fn test_match_probability_bounds() {
        let fp1 = make_fingerprint("a", 200);
        let fp2 = make_fingerprint("b", 200);
        let comparison = compare_fingerprints(&fp1, &fp2);
        let prob = comparison.match_probability();
        assert!(prob >= 0.0 && prob <= 1.0);
    }

    #[test]
    fn test_match_probability_low_confidence() {
        let fp1 = make_fingerprint("a", 1);
        let fp2 = make_fingerprint("b", 1);
        let comparison = compare_fingerprints(&fp1, &fp2);
        let prob = comparison.match_probability();
        assert!(
            prob < 0.5,
            "low sample count should reduce probability, got {}",
            prob
        );
    }

    #[test]
    fn test_match_probability_nan_safety() {
        let comparison = FingerprintComparison {
            profile_a: "a".to_string(),
            profile_b: "b".to_string(),
            similarity: f64::NAN,
            activity_similarity: 0.0,
            style_similarity: None,
            confidence: 1.0,
            verdict: ComparisonVerdict::Inconclusive,
            components: ComparisonComponents::default(),
        };
        let prob = comparison.match_probability();
        assert!(prob.is_finite(), "NaN input should produce finite output");
    }

    #[test]
    fn test_hysteresis_keeps_verdict_near_boundary() {
        let verdict = ComparisonVerdict::from_similarity_with_hysteresis(
            0.81,
            Some(ComparisonVerdict::LikelySameAuthor),
        );
        assert_eq!(verdict, ComparisonVerdict::LikelySameAuthor);
    }

    #[test]
    fn test_hysteresis_changes_verdict_far_from_boundary() {
        let verdict = ComparisonVerdict::from_similarity_with_hysteresis(
            0.90,
            Some(ComparisonVerdict::LikelySameAuthor),
        );
        assert_eq!(verdict, ComparisonVerdict::SameAuthor);
    }

    #[test]
    fn test_hysteresis_at_likely_same_boundary() {
        let verdict = ComparisonVerdict::from_similarity_with_hysteresis(
            0.62,
            Some(ComparisonVerdict::Inconclusive),
        );
        assert_eq!(verdict, ComparisonVerdict::Inconclusive);
    }

    #[test]
    fn test_hysteresis_none_previous() {
        let verdict = ComparisonVerdict::from_similarity_with_hysteresis(0.81, None);
        assert_eq!(verdict, ComparisonVerdict::SameAuthor);
    }

    #[test]
    fn test_weighted_similarity_no_style() {
        let sim = weighted_similarity(
            0.9, 0.8, 0.7, None, None, None, None, None, None, None, None,
        );
        assert!(sim >= 0.0 && sim <= 1.0);
        let expected = (0.9 * W_IKI + 0.8 * W_ZONE + 0.7 * W_PAUSE) / (W_IKI + W_ZONE + W_PAUSE);
        assert!(
            (sim - expected).abs() < 1e-10,
            "sim={} expected={}",
            sim,
            expected
        );
    }

    #[test]
    fn test_weights_sum_to_one() {
        let sum = W_IKI
            + W_ZONE
            + W_PAUSE
            + W_DWELL
            + W_FLIGHT
            + W_DIGRAPH
            + W_HURST
            + W_WORD_LEN
            + W_PUNCT
            + W_NGRAM
            + W_CORRECTION;
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "dimension weights must sum to 1.0, got {}",
            sum
        );
    }

    #[test]
    fn test_weighted_similarity_nan_guard() {
        // NaN in a required dimension: skip it, redistribute weight to others.
        let sim = weighted_similarity(
            f64::NAN,
            0.8,
            0.7,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            sim.is_finite(),
            "NaN in required dimension should be skipped"
        );
        let expected = (0.8 * W_ZONE + 0.7 * W_PAUSE) / (W_ZONE + W_PAUSE);
        assert!(
            (sim - expected).abs() < 1e-10,
            "sim={sim} expected={expected}"
        );

        // NaN in optional dimension: also skipped.
        let sim2 = weighted_similarity(
            0.9,
            0.8,
            0.7,
            Some(f64::NAN),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            sim2.is_finite(),
            "NaN in optional dimension should be skipped"
        );

        // All NaN: returns 0.0 (no valid dimensions).
        let sim3 = weighted_similarity(
            f64::NAN,
            f64::NAN,
            f64::NAN,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(sim3, 0.0, "all-NaN should return 0.0");
    }

    #[test]
    fn test_comparison_components_serde_default() {
        let json = r#"{"iki_similarity":0.5,"zone_similarity":0.5,"pause_similarity":0.5}"#;
        let components: ComparisonComponents = serde_json::from_str(json).unwrap();
        assert!(components.dwell_similarity.is_none());
        assert!(components.flight_similarity.is_none());
        assert!(components.digraph_similarity.is_none());
        assert!(components.hurst_similarity.is_none());
        assert!(components.correction_similarity.is_none());
    }
}
