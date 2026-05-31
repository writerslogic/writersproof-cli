<p align="center">
  <strong>CPoE</strong><br>
  Cryptographic authorship witnessing for writers and creators
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/cpoe/actions"><img src="https://github.com/writerslogic/cpoe/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://github.com/writerslogic/cpoe/attestations"><img src="https://img.shields.io/badge/SLSA-Build_Provenance-blue" alt="SLSA Build Provenance"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/cpoe/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**CPoE** is a cryptographic engine and CLI that produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created. It implements the [draft-condrey-rats-pop](https://datatracker.ietf.org/doc/draft-condrey-rats-pop/) IETF protocol specification.

This monorepo contains the full CPoE ecosystem:

| Component | Path | Target | Description | License |
|:----------|:-----|:-------|:------------|:--------|
| **cpoe-engine** | [`crates/cpoe-engine`](crates/cpoe-engine) | Native | Cryptographic engine, FFI, platform captures, storage | SSPL-1.0 |
| **cpoe-protocol** | [`crates/cpoe-protocol`](crates/cpoe-protocol) | Native + **WASM** | Wire format (CBOR/COSE), forensic models, RFC types | Apache-2.0 |
| **cpoe-jitter** | [`crates/cpoe-jitter`](crates/cpoe-jitter) | Native + **no_std** | Timing entropy primitive for embedded and desktop use | Apache-2.0 |
| **cpoe_cli** | [`apps/cpoe_cli`](apps/cpoe_cli) | Native | CLI (`cpoe`) | AGPL-3.0-only |
| **cpoe_macos** | [`apps/cpoe_macos`](apps/cpoe_macos) | macOS | macOS desktop app (submodule) | Proprietary |
| **cpoe_windows** | [`apps/cpoe_windows`](apps/cpoe_windows) | Windows | Windows desktop app (submodule) | Proprietary |

The three library crates are split by **compilation target**:

- **cpoe-jitter** compiles to `no_std` (bare-metal, embedded microcontrollers with no OS)
- **cpoe-protocol** compiles to `wasm32` (browser extensions for client-side evidence verification)
- **cpoe-engine** compiles to native only (requires OS APIs: CGEventTap, TPM, SQLite, Unix sockets)

Dependencies flow one direction: `engine -> protocol -> jitter`. Merging them would break WASM and embedded compilation.

## Install

**macOS (Homebrew):**
```bash
brew install writerslogic/tap/writerslogic
```

**Windows (Scoop):**
```powershell
scoop bucket add writerslogic https://github.com/writerslogic/scoop-bucket
scoop install writerslogic
```

**Linux / macOS (script):**
```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/cpoe/main/apps/cpoe_cli/install.sh | sh
```

**From source:**
```bash
cargo install --git https://github.com/writerslogic/cpoe --bin cpoe
```

## Quick Start

```bash
# Start tracking a document
cpoe essay.md

# Create a checkpoint
cpoe commit essay.md -m "first draft complete"

# View history
cpoe log essay.md

# Export cryptographic evidence (.c2pa)
cpoe export essay.md -t 2

# Verify evidence
cpoe verify essay.c2pa
```

Run `cpoe` with no arguments for an interactive menu, or `cpoe --help` for full command reference.

## CLI Commands

| Command | Description |
|:--------|:------------|
| `cpoe <path>` | Start tracking a file or directory |
| `cpoe commit` | Create a checkpoint (alias: `checkpoint`) |
| `cpoe log` | View history or list tracked documents (alias: `history`, `ls`) |
| `cpoe export` | Export evidence packet (alias: `prove`) |
| `cpoe verify` | Verify evidence packet (alias: `check`) |
| `cpoe status` | Show current tracking status |
| `cpoe track` | Session management (start/stop/status/list/show/export) |
| `cpoe identity` | Identity management (alias: `id`) |
| `cpoe config` | Configuration (alias: `cfg`) |
| `cpoe fingerprint` | Behavioral fingerprinting (alias: `fp`) |
| `cpoe presence` | Physical presence verification |

All commands support `--json` for machine-readable output and `--quiet` for silent operation.

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
cpoe_engine = { git = "https://github.com/writerslogic/cpoe", branch = "main" }
```

## Features

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `cpoe_jitter` | Hardware entropy via PhysJitter |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Architecture

```
writerslogic/
├── crates/
│   ├── cpoe_engine/    High-performance cryptographic engine
│   │   └── src/
│   │       ├── analysis/   Signal analysis and behavioral metrics
│   │       ├── anchors/    Blockchain and timestamp anchoring
│   │       ├── crypto/     Cryptographic primitives
│   │       ├── evidence/   Evidence export/verify
│   │       ├── forensics/  Authorship analysis
│   │       ├── ipc/        Inter-process communication
│   │       ├── keyhierarchy/ Key derivation and ratcheting
│   │       ├── platform/   OS-specific code (macOS, Linux, Windows)
│   │       ├── sentinel/   Real-time monitoring
│   │       ├── rfc/        RFC wire types
│   │       ├── tpm/        TPM 2.0 / Secure Enclave
│   │       └── vdf/        Verifiable Delay Functions
│   ├── cpoe_protocol/  PoP wire format (CBOR/COSE)
│   └── cpoe_jitter/    Hardware timing entropy
├── apps/
│   ├── cpoe_cli/       Command-line interface
│   ├── cpoe_macos/     Native macOS app (submodule)
│   └── cpoe_windows/   Native Windows app (submodule)
└── docs/              Schemas, specs, and user guides
```

## Development

```bash
cargo test --workspace           # Run all tests
cargo test -p cpoe-engine --lib   # Fast engine tests (~1020 tests)
cargo clippy --workspace -- -D warnings  # Lint (zero warnings maintained)
cargo fmt --all -- --check       # Format check
cargo audit && cargo deny check  # Security audit
```

## Verifying Evidence

Anyone can verify `.c2pa` evidence packets — no account or software required:

- **Web**: Upload at [writerslogic.com/verify](https://writerslogic.com/verify)
- **CLI**: `cpoe verify proof.c2pa`

Verification checks the checkpoint chain, Ed25519 signatures, VDF timing proofs, and behavioral consistency. It runs entirely client-side — your evidence is never uploaded to our servers.

## Security & Privacy

> [!IMPORTANT]
> CPoE provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

### Privacy & External Interactions

CPoE is designed with a strictly **offline-first and privacy-preserving** architecture. Core witnessing, keystroke capture, and evidence generation occur entirely on your local machine.

The applications interact with the following external domains for specific enhanced features:

*   **Verification Portal (`writerslogic.com/verify`):** Browser-based tool for verifying `.c2pa` evidence packets. Runs client-side; evidence data is never uploaded.
*   **Attestation API (`writerslogic.com/api`):** Used for Tier 3 and Tier 4 evidence to request anti-replay nonces and receive cloud-signed attestation certificates.
*   **Schema Registry (`protocol.writerslogic.com`):** Hosts JSON schemas and DID resolution data for protocol compliance.

For a detailed breakdown, see the **[Privacy & External Interactions Wiki](https://github.com/writerslogic/cpoe/wiki/Privacy-&-External-Interactions)**.

See [SECURITY.md](SECURITY.md) for the security policy.

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

Licensed under [AGPL-3.0-only](LICENSE). See individual component licenses in the table above.
