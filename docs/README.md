<p align="center">
  <strong>CPoE</strong><br>
  Documentation, schemas, and specifications for CPoE
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**CPoE** is a unified protocol suite for high-integrity authorship witnessing based on the **Proof-of-Process (PoP)** protocol (`draft-condrey-rats-pop`). This repository contains the core implementation, reference applications, and technical documentation.

| Component | Path | Description | License |
|:----------|:-----|:------------|:--------|
| **cpoe** | [`crates/cpoe`](../crates/cpoe) | Core cryptographic engine (lib: `cpoe_engine`) | SSPL-1.0 |
| **authorproof-protocol** | [`crates/authorproof-protocol`](../crates/authorproof-protocol) | Wire protocol (CBOR/COSE), wasm-ready | Apache-2.0 |
| **cpoe-jitter** | [`crates/cpoe-jitter`](../crates/cpoe-jitter) | Timing entropy primitive, `no_std` capable | Apache-2.0 |
| **cpoe_cli** | [`apps/cpoe_cli`](../apps/cpoe_cli) | CLI + native messaging host | AGPL-3.0-only |
| **cpoe_macos** | [`apps/cpoe_macos`](../apps/cpoe_macos) | Native macOS desktop application | Proprietary |
| **cpoe_windows** | [`apps/cpoe_windows`](../apps/cpoe_windows) | Native Windows desktop application | Proprietary |

## Technical Implementation

CPoE is built on a high-integrity cryptographic stack:

- **Streaming Evidence Engine:** Chunked SHA-256 hashing optimized for large files.
- **Adversarial Hardening:** Tier 4 protections including RAM-locking (`mlock`) and anti-debugging.
- **The Labyrinth:** Machine-wide Merkle Mountain Range (MMR) entanglement for global integrity.
- **Forensic Suite:** Real-time authorship scoring and robotic cadence detection.
- **PoSME:** Proof of Sequential Memory-bound Effort for unforgeable time commitment.

## Documentation Index

### Getting Started
- [Installation](user/getting-started.md#installation) — Homebrew, DMG, and Linux scripts.
- [Initial Setup](user/getting-started.md#initial-setup) — Creating your cryptographic identity.
- [First Checkpoint](user/getting-started.md#your-first-checkpoint) — Proving your creative process.

### User Guides
- [CLI Reference](user/cli-reference.md) — Command documentation.
- [GUI Guide](user/gui-guide.md) — macOS and Windows application walkthroughs.
- [Configuration](user/configuration.md) — Tuning the Sentinel and VDF parameters.
- [FAQ](user/faq.md) — Common questions about privacy, security, and usage.
- [Troubleshooting](user/troubleshooting.md) — Common issues and solutions.

### Integration
- [Vendor Integration](integrations/integration-guide.md) — Integrating into 3rd-party apps.
- [Evidence Interpretation](integrations/evidence-interpretation.md) — Criteria for verifying reports.

### Technical Specifications
- [Evidence Format](specs/evidence-format.md) — PoP wire format (CBOR/COSE).
- [Process Declaration](specs/process-declaration.md) — Signed author attestation format.
- [Ratchet Key Hierarchy](specs/ratchet-key-hierarchy.md) — Forward-secure key management.
- [Architectural Hardening](specs/architectural-hardening.md) — Tier 4 protection mechanisms.
- [Behavioral Metrics](specs/behavioral-metrics.md) — Forensic authorship analysis.
- [Persistence & Fault Tolerance](specs/persistence-fault-tolerance.md) — WAL and crash recovery.

### Operations
- [CA Key Rotation](ca_rotation.md) — Rotating the WritersProof attestation CA key.
- [Standards Alignment](standards-alignment.md) — NIST, ISO, IPTC, W3C compliance mapping.

### Reference
- [JSON Schemas](schemas/) — Formal data models (evidence, declaration, WAR block).
- [Philosophy & Ethics](philosophy/authorship-ethics.md) — Moral framework for PoP.
- [Man Page](man/cpoe.1) — Unix manual page.

## Citations

```bibtex
@article{condrey2026writerslogic,
  title={CPoE: Proof-of-process via Adversarial Collapse},
  author={Condrey, David},
  journal={arXiv preprint arXiv:2602.01663},
  year={2026},
  doi={10.48550/arXiv.2602.01663}
}
```

> **Abstract:** Digital signatures prove key possession but not authorship. We introduce *proof-of-process* — a mechanism combining jitter seals, Verifiable Delay Functions, timestamp anchors, keystroke validation, and optional hardware attestation.
>
> — [arXiv:2602.01663](https://arxiv.org/abs/2602.01663) [cs.CR]
