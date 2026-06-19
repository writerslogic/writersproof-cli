# Philosophy of Authorship & AI Ethics

**Version:** 1.0.0
**Last Updated:** 2026-02-23

## The Authorship Gap

In the age of generative AI, the "Authorship Gap" is the growing distance between a digital signature (which proves key possession) and the creative process (which proves human effort). CPoE exists to bridge this gap through **Proof-of-Process (PoP)**.

## Responsible vs. Abusive AI Use

We distinguish between AI as a tool for human enhancement and AI as a mechanism for adversarial deception.

### 1. Responsible AI (Iterative Partnership)
Responsible use involves AI acting as a brainstorming partner, editor, or research assistant where the **human remains the primary causal agent**.
- **Characteristics:** Iterative editing, human-led structuring, and critical refinement.
- **Evidence Profile:** High `edit_entropy`, consistent `residency` over time, and a mix of human typing cadence punctuated by thoughtful pauses.

### 2. Abusive AI (Substitution & Deception)
Abusive use involves the wholesale substitution of human agency with generative models, presented as original human work.
- **Characteristics:** One-shot generation, "bulk injection" of text, and the intent to deceive a verifier regarding the origin of the thought.
- **Evidence Profile:** High `monotonic_append_ratio` (sequential generation), zero `edit_entropy` (no revision), and "robotic" timing markers.

## The Moral Right to Provenance

CPoE is built on the belief that human authors have a moral and intellectual right to prove their effort. In a world saturated with synthetic content, **unforgeable provenance** is the only way to protect the value of human creative labor.

- **Non-Surveillance:** We reject "proctoring" or screen-recording. Authenticity must be proven through cryptographic physics (VDFs, Jitter), not through the invasion of privacy.
- **Falsifiability:** Authorship should not be a "trust me" claim. It should be a testable, falsifiable cryptographic assertion.

---

*For technical details on how we detect these patterns, see [Behavioral Metrics](../specs/behavioral-metrics.md).*
