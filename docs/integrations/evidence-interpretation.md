# Evidence Interpretation Guide

**Version:** 1.0.0
**Status:** Stable
**Last Updated:** 2026-02-23

## Overview

This guide provides vendors and verifiers with criteria for interpreting CPoE evidence packets (`.c2pa`), identifying tampering, and differentiating legitimate creative actions from adversarial forgery.

## 1. Online Verification Portal (`writerslogic.com/verify`)

The most common way to verify a `.c2pa` evidence packet is through our web-based portal.

*   **Privacy-Preserving:** The portal performs verification **locally in your browser**. Your evidence files and document contents are never uploaded to our servers.
*   **WASM Engine:** The same Rust cryptographic engine used in the desktop apps is compiled to WebAssembly to power the portal, ensuring parity in verification results.
*   **Accessibility:** Users can simply drag and drop an evidence file onto the portal to see a human-readable report of the authorship metrics and cryptographic health.

## 2. The Process Score (PS)

The `forensic_score` (0.0 to 1.0) is the primary metric for authorship confidence.

| Score | Verdict | Recommendation |
|:------|:--------|:---------------|
| **0.90 - 1.0** | **Verified Human** | High confidence in manual authorship. |
| **0.70 - 0.89** | **Likely Human** | Human authorship with minor anomalies (e.g., occasional long pauses or large pastes). |
| **0.40 - 0.69** | **Inconclusive** | Requires manual review. May be a highly structured retyping of AI content. |
| **< 0.40** | **Likely Synthetic** | High probability of automated injection or scripted transcription. |

## 2. Differentiating Paste Events

Legitimate writing often involves pasting (quotes, references, moving blocks).

### Valid Paste Events
- **Context:** The paste is followed by immediate iterative editing/revision.
- **Score Impact:** A single large paste will slightly lower the `positive_negative_ratio` but is compensated for by the high `edit_entropy` of subsequent revisions.
- **Evidence:** `is_paste` flag is true, but `edit_entropy` remains > 2.0.

### Invalid/Adversarial Pastes
- **Context:** Large blocks of text appearing with no subsequent editing.
- **Score Impact:** Low `edit_entropy` combined with a high `monotonic_append_ratio`.
- **Evidence:** `is_paste` is true, and the `forensic_score` drops below 0.5 because no "Cognitive Bursts" were detected.

## 3. Identifying Potential Tampering

Even without a verifier tool, certain patterns in the JSON evidence packet suggest tampering attempts:

### 3.1 VDF "Fast-Forwarding"
- **Red Flag:** High iteration counts with very low `duration_ms` in the `process_proof`.
- **Detection:** If $iterations / duration > (1.2 	imes 	ext{calibration\_rate})$, the user likely utilized specialized hardware or parallelization to fake time.

### 3.2 Key Replay (The "Pre-computation" Attack)
- **Red Flag:** Identical `checkpoint_hash` across different documents or sessions.
- **Detection:** CPoE entangles the document hash into the session certificate. A mismatch indicates the user attempted to "replay" valid evidence from an old document onto a new one.

### 3.3 History Pruning
- **Red Flag:** Gaps in the `sequence` numbers or a broken `prev_hash` chain.
- **Detection:** Every checkpoint is bound to the terminal signature. A missing intermediate checkpoint will cause the final verification to fail.

## 4. Edge Cases

### 4.1 "The Super-Typist" (false synthetic detection)
Extremely fast or consistent typists (e.g., stenographers) may trigger the robotic cadence threshold ($CV < 0.15$).
- **Mitigation:** Look at the `entropy_bits`. Even consistent typists have high entropy in their *relative* micro-jitter, whereas scripts are perfectly quantized.

### 4.2 Power Loss / Crash
- **Red Flag:** A large time gap between checkpoints with a `message: "crash-recovery"`.
- **Interpretation:** This is a documented limitation. As long as the `chain_hash` remains intact, the evidence before the crash is still valid.

### 4.3 Collaborative Sessions
- **Red Flag:** Drastic shifts in the behavioral fingerprint within a single packet.
- **Interpretation:** Check the `collaboration` section. If multiple `public_key`s are present, the shifts indicate a hand-off between authors.

## 5. Security Limitations

- **White-Box Attack:** A user with kernel-level instrumentation can still potentially bypass Tier 1-3 protections. Tier 4 (Hardware Attestation) is required for absolute certainty in high-stakes environments (e.g., Legal, Medical).

---

*For technical schema details, see [Evidence Format](../specs/evidence-format.md).*
