<p align="center">
  <strong>cpoe</strong><br>
  Cryptographic authorship witnessing CLI
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/writersproof-cli/actions"><img src="https://github.com/writerslogic/writersproof-cli/workflows/CI/badge.svg" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/writersproof-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**cpoe** is the command-line interface for [CPoE](https://github.com/writerslogic/writersproof-cli) — producing independently verifiable, tamper-evident process evidence constraining when and how a document could have been created. It implements the [draft-condrey-rats-pop](https://datatracker.ietf.org/doc/draft-condrey-rats-pop/) IETF protocol specification.

Part of the CPoE monorepo:

| Component | Description |
|:----------|:------------|
| [**cpoe_engine**](../../crates/cpoe_engine) | Cryptographic engine |
| [**cpoe_protocol**](../../crates/cpoe_protocol) | PoP wire format (CBOR/COSE) |
| [**cpoe_jitter**](../../crates/cpoe_jitter) | Hardware timing entropy |
| **cpoe_cli** (this crate) | CLI tool |

## Installation

**macOS (Homebrew):**
```bash
brew install writerslogic/tap/writersproof-cli
```

**Windows (Scoop):**
```powershell
scoop bucket add writerslogic https://github.com/writerslogic/scoop-bucket
scoop install writerslogic
```

**Linux / macOS (script):**
```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/writersproof-cli/main/apps/cpoe_cli/install.sh | sh
```

**From source:**
```bash
cargo install --git https://github.com/writerslogic/writersproof-cli --bin writersproof-cli
```

## Quick Start

```bash
# Start tracking a document (auto-initializes on first use)
writersproof-cli essay.md

# Create a checkpoint with a message
writersproof-cli commit essay.md -m "first draft complete"

# View checkpoint history
writersproof-cli log essay.md

# Export cryptographic evidence (.c2pa)
writersproof-cli export essay.md -t 2

# Verify evidence
writersproof-cli verify essay.c2pa
```

Run `writersproof-cli` with no arguments for an interactive menu, or `writersproof-cli --help` for the full command reference.

## Commands

| Command | Aliases | Description |
|:--------|:--------|:------------|
| `writersproof-cli <path>` | | Start tracking a file or directory |
| `writersproof-cli commit` | `checkpoint` | Create a checkpoint with VDF time proof |
| `writersproof-cli log` | `history`, `ls` | View history or list all tracked documents |
| `writersproof-cli export` | `prove` | Export evidence packet (.c2pa) |
| `writersproof-cli verify` | `check` | Verify evidence packet |
| `writersproof-cli status` | | Show system status |
| `writersproof-cli track` | | Session management (start/stop/status/list/show/export) |
| `writersproof-cli identity` | `id` | Identity management |
| `writersproof-cli config` | `cfg` | View and edit configuration |
| `writersproof-cli fingerprint` | `fp` | Behavioral fingerprinting (status/show/compare/list/delete) |
| `writersproof-cli presence` | | Physical presence verification |

All commands support `--json` for machine-readable output and `--quiet` for silent operation.

## Evidence Tiers

Per [draft-condrey-rats-pop](https://datatracker.ietf.org/doc/draft-condrey-rats-pop/):

| Tier | Content | Use Case |
|:-----|:--------|:---------|
| **1** (Core) | Checkpoint chain + VDF proofs + keystroke jitter | Default — recommended for most workflows |
| **2** (Enhanced) | + TPM/hardware attestation | Stronger claims with hardware backing |
| **3** (Maximum) | + behavioral analysis + external anchors | Maximum assurance |

## Evidence Formats

| Format | Extension | Description |
|:-------|:----------|:------------|
| C2PA | `.c2pa` | C2PA Content Credentials manifest (primary format) |
| JSON | `.json` | Human-readable evidence export |

## Verifying Evidence

Anyone can verify `.c2pa` evidence packets — no account or software required:

- **Web**: Upload at [writerslogic.com/verify](https://writerslogic.com/verify)
- **CLI**: `writersproof-cli verify proof.c2pa`

Verification checks the checkpoint chain, Ed25519 signatures, VDF timing proofs, and behavioral consistency. It runs entirely client-side — your evidence is never uploaded to our servers.

## Security

> [!IMPORTANT]
> CPoE provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

**Privacy-first design:**
- Keystroke tracking captures **timing only** — never the keys you press
- Voice fingerprinting is **off by default** and requires explicit consent
- All keys are stored with restrictive file permissions (0600)
- Database uses HMAC-based tamper detection
- Entirely offline-first — no network calls for core witnessing

## Development

```bash
cargo test -p cpoe_cli              # CLI tests (39 tests)
cargo test -p cpoe_engine --lib     # Engine tests (912 tests)
cargo test --workspace             # Full test suite
cargo clippy --workspace -- -D warnings  # Lint (zero warnings)
cargo fmt --all -- --check         # Format check
```

## Citation

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

## License

Licensed under [AGPL-3.0-only](../../LICENSE).

For commercial licensing inquiries, contact: licensing@writerslogic.com
