# Behavioral Forensic Metrics Specification

**Version:** 2.0.0
**Status:** Draft
**Last Updated:** 2026-05-27

## Overview

This specification defines the behavioral forensic metrics used by CPoE to analyze edit patterns for consistency with human authorship. These metrics examine the spatial distribution and timing of document edits without capturing actual content.

**Important:** This specification covers edit topology and timing pattern analysis. For jitter seal keystroke watermarking (HMAC-based timing injection), see the research paper `paper/jitter-seal.md` and evidence format `specs/evidence-format.md`.

### Distinction from Jitter Seal

| Mechanism | What It Measures | Purpose |
|-----------|------------------|---------|
| **Jitter Seal** | Injected microsecond delays during typing | Cryptographic proof of real-time input |
| **Behavioral Metrics** | Edit positions and timing patterns | Forensic analysis of authorship patterns |

Behavioral metrics are statistical indicators. Jitter seal provides cryptographic proof.

## Forensic Metrics Suite

CPoE implements a tiered forensic evaluation suite that produces a composite **Authorship Score (PS)**.

### 1. Keystroke Cadence Analysis

Evaluates the rhythm and stability of inter-keystroke intervals (IKI).

- **Mean IKI (μ):** Average time between key presses.
- **Coefficient of Variation (CV):** Standard deviation divided by mean ($CV = \sigma / \mu$).
- **Robotic Detection:** A $CV < 0.15$ indicates unnatural consistency (robotic cadence), suggesting automated transcription or scripted injection.
- **Cognitive Bursts:** Human typing is characterized by high-velocity word bursts followed by pauses for thought. Stability analysis detects the absence of these bursts.

### 2. Edit Topology (The "Labyrinth")

Analyzes where and how document modifications occur over time.

- **Monotonic Append Ratio:** The percentage of edits occurring within the last 5% of the document. High ratios (>0.90) suggest sequential generation (typical of AI) rather than iterative revision.
- **Edit Entropy:** Shannon entropy of modification locations. Human revision is distributed throughout the text; low entropy indicates highly focused or programmatic edits.
- **Deletion Clustering:** Human authors tend to delete in contiguous blocks during revision. Scattered, single-character deletions are flagged as suspicious.

### 3. Composite Authorship Score (Process Score)

The system computes a final RFC-compliant Process Score using the following weighted formula:

$$PS = 0.3R + 0.3S + 0.4B$$

| Weight | Factor | Name | Description |
|:-------|:-------|:-----|:------------|
| 30% | **R** | **Residency** | Total duration and continuity of the editing session. |
| 30% | **S** | **Sequence** | Integrity of the hash-chain and edit topology entropy. |
| 40% | **B** | **Behavioral** | Keystroke cadence, CV analysis, and burst detection. |

**Verdict Thresholds:**
- **PS ≥ 0.90:** Manual Composition Consistent (Verified Human)
- **0.70 ≤ PS < 0.90:** Manual Composition Likely (Some Anomalies)
- **0.40 ≤ PS < 0.70:** Inconclusive Analysis
- **PS < 0.40:** Automated/Retyped Content Likely (Likely Synthetic)

## Terminology

| Term | Definition |
|------|------------|
| **Event** | A file modification detected by CPoE |
| **Interval** | Time between consecutive events (nanoseconds) |
| **Session** | A cluster of events separated by gaps > 30 minutes |
| **Flight Time** | Duration a key is held down (not directly measured; inferred) |
| **Dwell Time** | Time between key press and release |
| **Digraph** | A pair of consecutive keystrokes (timing pattern) |

## Core Metrics

### 1. Median Inter-Event Interval

**Purpose:** Distinguish human typing pace from automated generation.

**Calculation:**
```
Given events E = {e₁, e₂, ..., eₙ} sorted by timestamp
Intervals I = {(e₂.ts - e₁.ts), (e₃.ts - e₂.ts), ..., (eₙ.ts - eₙ₋₁.ts)}
MedianInterval = median(I) / 1e9  // Convert to seconds
```

**Interpretation:**
| Value (seconds) | Interpretation |
|-----------------|----------------|
| < 0.1 | Automated/pasted content |
| 0.1 - 1.0 | Fast typing (experienced typist) |
| 1.0 - 5.0 | Normal typing pace |
| 5.0 - 30.0 | Thoughtful/deliberate editing |
| > 30.0 | Extended pauses (reference lookup, thinking) |

**Human Baseline:** Studies show average inter-keystroke intervals of 150-300ms
for skilled typists, with significant variation for complex content.

### 2. Edit Entropy

**Purpose:** Measure the spatial distribution of edits within a document.

**Calculation:**
```
Given N regions R = {r₁, r₂, ..., rₙ} each with StartPct ∈ [0, 1]
Create histogram H with B=20 bins
For each region r:
    bin = floor(r.StartPct × B)
    H[bin]++

EditEntropy = -Σ (H[j]/N) × log₂(H[j]/N) for H[j] > 0
```

**Interpretation:**
| Value (bits) | Interpretation |
|--------------|----------------|
| < 1.0 | Highly concentrated (suspicious) |
| 1.0 - 2.0 | Focused editing (single area) |
| 2.0 - 3.5 | Normal editing pattern |
| > 3.5 | Well-distributed (active revision) |
| 4.32 (max) | Uniform distribution across document |

**Significance:** AI-generated content typically shows very low entropy
(sequential appending), while human editing shows moderate to high entropy
(jumping around the document).

### 3. Monotonic Append Ratio

**Purpose:** Detect sequential content generation vs. revision-based writing.

**Calculation:**
```
Given regions R with StartPct values
Threshold T = 0.95 (edits in final 5% of document)
AppendCount = |{r ∈ R : r.StartPct ≥ T}|
MonotonicAppendRatio = AppendCount / |R|
```

**Interpretation:**
| Value | Interpretation |
|-------|----------------|
| > 0.90 | Almost all edits at end (AI-like pattern) |
| 0.70 - 0.90 | Mostly appending with some revision |
| 0.40 - 0.70 | Balanced pattern (typical human) |
| < 0.40 | Heavy revision throughout document |

### 4. Positive/Negative Ratio

**Purpose:** Measure balance between insertions and deletions.

**Calculation:**
```
Insertions = |{r ∈ R : r.DeltaSign == "insert"}|
Deletions = |{r ∈ R : r.DeltaSign == "delete"}|
PositiveNegativeRatio = Insertions / (Insertions + Deletions)
```

Note: `r.DeltaSign` is a string enum: `"replace"`, `"insert"`, or `"delete"`.

**Interpretation:**
| Value | Interpretation |
|-------|----------------|
| > 0.95 | Almost all insertions (no revision) |
| 0.80 - 0.95 | Mostly insertions, limited revision |
| 0.60 - 0.80 | Typical drafting pattern |
| 0.40 - 0.60 | Active revision phase |
| < 0.40 | Heavy editing/deletion mode |

### 5. Deletion Clustering Coefficient

**Purpose:** Distinguish systematic revision passes from random deletions.

**Calculation:**
```
Given deletion positions D = {d₁, d₂, ..., dₘ} sorted ascending
For each dᵢ, find nearest neighbor distance:
    NND[i] = min(|dᵢ - dᵢ₋₁|, |dᵢ₊₁ - dᵢ|)

MeanNND = Σ NND[i] / m
ExpectedUniform = 1 / (m + 1)  // Expected for uniform distribution
DeletionClustering = MeanNND / ExpectedUniform
```

**Interpretation:**
| Value | Interpretation |
|-------|----------------|
| < 0.5 | Highly clustered (systematic revision pass) |
| 0.5 - 0.8 | Moderately clustered (natural editing) |
| 0.8 - 1.2 | Random distribution (suspicious) |
| > 1.2 | Overdispersed (possibly artificial) |

**Significance:** Human revision typically occurs in focused passes through
sections, creating clustered deletion patterns. Random or fake deletions
show uniform distribution.

## Derived Metrics

### Session Detection

Sessions are clusters of events separated by significant gaps:

```
GapThreshold = 1800 seconds (30 minutes)
For consecutive events (eᵢ, eᵢ₊₁):
    If (eᵢ₊₁.ts - eᵢ.ts) > GapThreshold:
        Start new session
```

### Burst Detection

High-velocity content addition:

```
VelocityThreshold = 100 bytes/second
For consecutive events (eᵢ, eᵢ₊₁):
    delta_t = (eᵢ₊₁.ts - eᵢ.ts) / 1e9
    delta_bytes = |eᵢ₊₁.size - eᵢ.size|
    velocity = delta_bytes / delta_t
    If velocity > VelocityThreshold:
        Flag as potential paste/AI insertion
```

## Anomaly Detection

### Flags

| Flag | Condition | Severity |
|------|-----------|----------|
| `monotonic_append` | MonotonicAppendRatio > 0.85 | Warning |
| `low_entropy` | EditEntropy < 1.5 | Warning |
| `high_velocity` | Velocity > 100 B/s | Warning |
| `no_revision` | PositiveNegativeRatio > 0.95 | Warning |
| `scattered_deletions` | 0.9 < DeletionClustering < 1.1 | Info |
| `long_gap` | Gap > 24 hours | Info |

### Assessment Algorithm

```
AlertCount = count(severity == "alert")
WarningCount = count(severity == "warning")
SuspiciousIndicators = 0

If MonotonicAppendRatio > 0.90: SuspiciousIndicators++
If EditEntropy < 1.0 and EditEntropy > 0: SuspiciousIndicators++
If PositiveNegativeRatio > 0.95: SuspiciousIndicators++
If 0.9 < DeletionClustering < 1.1: SuspiciousIndicators++

If AlertCount >= 2 or SuspiciousIndicators >= 3:
    Assessment = "SUSPICIOUS PATTERNS DETECTED"
Else If WarningCount >= 3 or SuspiciousIndicators >= 2:
    Assessment = "SUSPICIOUS PATTERNS DETECTED"
Else:
    Assessment = "CONSISTENT WITH HUMAN AUTHORSHIP"
```

## Scientific Basis

### Keystroke Dynamics Research

This specification draws from established keystroke dynamics research:

1. **Monrose & Rubin (2000):** "Keystroke dynamics as a biometric for
   authentication" - Established inter-keystroke timing as stable biometric.

2. **Bergadano et al. (2002):** "User authentication through keystroke
   dynamics" - Showed digraph timing patterns are user-specific.

3. **Killourhy & Maxion (2009):** "Comparing Anomaly-Detection Algorithms for
   Keystroke Dynamics" - Benchmarked detection algorithms.

### Limitations

1. **Indirect Measurement:** CPoE observes file save events, not actual
   keystrokes. Metrics are approximations based on observable behavior.

2. **Editor Variability:** Different editors have different auto-save behaviors,
   affecting observed patterns.

3. **Content Type:** Code, prose, and data entry have different natural patterns.

4. **Individual Variation:** Typing patterns vary significantly between
   individuals; metrics should be compared against user's own baseline.

## Privacy Considerations

This specification is designed to maximize forensic value while minimizing
privacy impact:

- **No Key Values:** Only timing between events is captured, never which keys.
- **Aggregate Statistics:** Metrics are derived statistics, not raw timings.
- **Local Processing:** All computation occurs on-device.
- **Normalized Positions:** Edit locations are percentages, not absolute.

See [PRIVACY.md](../PRIVACY.md) for full privacy policy.

## Advanced Forensic Signals (v2.0)

The following analysis modules extend the core metrics for deeper authorship assessment:

### Transcription Detection

Detects retyping of pre-existing content (dictation replay, transcription from AI output):

| Metric | Threshold | Meaning |
|--------|-----------|---------|
| `burst_speed_cv` | < 0.15 | Coefficient of variation within bursts; low = scripted |
| `zero_variance_windows` | > 3 | 500ms windows with < 5ms std dev |
| `focus_reference_pattern` | CV < 0.3 | Regular-interval app switching |

### Cross-Modal Consistency

Five checks comparing keystroke evidence against other signals:

1. **Timing vs. Content**: Do pause patterns match cognitive difficulty?
2. **Focus vs. Progress**: Does app-switching correlate with research phases?
3. **Mouse vs. Editing**: Do cursor movements match edit positions?
4. **Jitter vs. Fatigue**: Does timing entropy decrease over session duration?
5. **VDF vs. Velocity**: Does proven time match observed writing speed?

Cross-modal failures reduce verdict confidence by one tier.

### Forgery Cost Estimation

Eight-component model estimating the computational cost to forge equivalent evidence:

1. VDF recomputation cost
2. Jitter simulation complexity
3. Behavioral consistency difficulty
4. Cross-modal coherence cost
5. Checkpoint chain length factor
6. Hardware attestation bypass cost
7. Temporal beacon retroaction cost
8. Labyrinth entanglement reversal cost

Output: estimated USD cost to forge, factored into final verdict confidence.

### ForensicSummary Wire Fields (CBOR key 25)

Session-level metrics included in evidence packets:

| Field | Key | Description |
|-------|-----|-------------|
| `words_per_minute` | 1 | Average WPM during session |
| `mean_iki_ms` | 2 | Mean inter-key interval |
| `correction_ratio` | 3 | Deletions / total keystrokes |
| `writing_mode` | 5 | Detected mode (compose/edit/transcribe) |
| `hurst_exponent` | 7 | Long-range dependency measure |
| `keystroke_count` | 8 | Total keystrokes in session |
| `editing_ratio` | 9 | Edits / total operations |
| `checkpoint_count` | 10 | Checkpoints in session |
| `assessment_score` | 11 | Composite authorship score (0-1) |
| `coefficient_of_variation` | 12 | IKI variation |
| `biological_cadence_score` | 13 | 1/f noise conformance |
| `timing_entropy` | 14 | Shannon entropy of timing |
| `pause_entropy` | 15 | Shannon entropy of pauses |
| `cognitive_load_score` | 16 | Estimated cognitive effort |
| `revision_topology_score` | 17 | Non-linear editing patterns |
| `error_ecology_score` | 18 | Natural error/correction patterns |
| `likelihood_p_cognitive` | 19 | Bayesian P(human) |
| `forgery_difficulty` | 20 | Estimated forgery cost |
| `cross_modal_score` | 21 | Cross-modal consistency |
| `snr_db` | 22 | Signal-to-noise ratio |
| `lyapunov_exponent` | 23 | Chaotic dynamics measure |
| `transcription_suspicious` | 24 | Transcription detection flag |
| `active_probes_score` | 26 | Active challenge responses |
| `spectral_slope` | 28 | Power spectrum slope |
| `spectral_noise_type` | 29 | Noise color (pink/white/brown) |
| `baseline_deviation` | 30 | Deviation from user's baseline |
| `ai_fluency_flag` | 31 | AI-like fluency detected |

### Verdict Enum

The forensic analysis produces one of six verdicts:

| Verdict | Code | Meaning |
|---------|------|---------|
| V1VerifiedHuman | 1 | High entropy, valid causality, non-linear composition |
| V2LikelyHuman | 2 | Valid timing with minor causality drift |
| V3Suspicious | 3 | Low entropy or high linearity; potential transcription |
| V4LikelySynthetic | 4 | Perfect timing uniformity; histogram attack or bot |
| V5ConfirmedForgery | 5 | HMAC causality lock broken; confirmed tampering |
| V6InsufficientData | 6 | Not enough data to make a determination |

## References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) -
  Digital Identity Guidelines: Authentication
- [ISO/IEC 19795](https://www.iso.org/standard/73515.html) -
  Biometric Performance Testing and Reporting
- [IEEE 2410-2019](https://standards.ieee.org/standard/2410-2019.html) -
  Biometric Open Protocol Standard
