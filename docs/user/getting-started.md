# Getting Started with CPoE

CPoE is a cryptographic authorship witnessing system that creates tamper-evident records of your creative process.

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | macOS 13.0+, Windows 10+, or Linux (kernel 5.0+) |
| CPU | 64-bit processor (x86_64 or ARM64) |
| RAM | 512 MB available |
| Storage | 100 MB for installation, plus space for evidence data |
| Rust | 1.75+ (for building from source) |

### Optional Hardware

- **TPM 2.0** (Windows/Linux) — Enables hardware-backed attestation (Tier 3+ evidence)
- **Secure Enclave** (Apple Silicon Macs) — Provides enhanced device binding

## Installation

### macOS App (Recommended)

1. Download `WritersProof.dmg` from the [releases page](https://github.com/writerslogic/cpoe/releases)
2. Drag **WritersProof** to Applications
3. Launch and follow the onboarding prompts

The app includes menu bar integration, automatic keystroke tracking, visual checkpoint history, and one-click evidence export.

### macOS CLI (Homebrew)

```bash
brew install writerslogic/tap/writerslogic
```

### Linux CLI

```bash
curl -fsSL https://writerslogic.com/install.sh | bash
```

### Building from Source

```bash
git clone https://github.com/writerslogic/cpoe.git
cd writerslogic
cargo build --release -p cpoe_cli
# Binary at target/release/writersproof-cli
```

### Verify Installation

```bash
cpoe --help
```

## Initial Setup

### Initialize

```bash
cpoe init
```

This creates:
- `~/.writersproof/` directory structure
- Ed25519 signing key pair (your cryptographic identity)
- Master identity derived from device hardware (PUF binding)
- Secure SQLite database for events
- Default `config.toml` configuration

### Calibrate VDF

The Verifiable Delay Function provides timing proofs. Calibration measures your CPU speed:

```bash
cpoe calibrate
```

Takes ~30 seconds. Only needs to be done once per machine.

### Configuration (Optional)

Edit `~/.writersproof/config.toml`:

```toml
[vdf]
iterations_per_second = 15000000   # Set by calibrate
min_iterations = 100000
max_iterations = 3600000000

[sentinel]
auto_start = false
heartbeat_interval_secs = 60
checkpoint_interval_secs = 60
```

See [Configuration Guide](configuration.md) for all options.

## Your First Checkpoint

### Basic Checkpoint

```bash
# Create or edit a document
echo "My first witnessed document" > mydoc.txt

# Create a checkpoint
cpoe commit mydoc.txt -m "Initial version"
```

### View Checkpoint History

```bash
cpoe log mydoc.txt
```

### Enhanced Workflow with Keystroke Tracking

For stronger evidence, track keystrokes during writing:

```bash
# Start tracking
cpoe track start mydoc.txt

# ... write your document ...
# The system counts keystrokes (not content!) in the background

# Create checkpoint with keystroke evidence
cpoe commit mydoc.txt -m "Draft with tracked keystrokes"

# Stop tracking
cpoe track stop
```

## Exporting Evidence

When you need to prove authorship:

```bash
cpoe export mydoc.txt -o mydoc.c2pa
```

This creates a self-contained evidence packet containing:
- Complete checkpoint chain with VDF proofs
- Key hierarchy with session certificates
- Signed declaration of creative process
- Forensic metrics (if keystroke tracking was active)

### Export Formats

```bash
cpoe export mydoc.txt -f json     # Human-readable JSON
cpoe export mydoc.txt -f html     # Self-contained HTML report
cpoe export mydoc.txt -f pdf      # Signed PDF with anti-forgery features
cpoe export mydoc.txt -f c2pa     # C2PA Content Credentials manifest with embedded VC
```

## Verifying Evidence

### For Authors: Sharing Your Evidence

```bash
cpoe export mydoc.txt -o mydoc.c2pa
# Share mydoc.c2pa with the recipient
```

The `.c2pa` file is self-contained. The recipient does not need access to your machine, database, or private key.

### For Recipients: Verifying a .c2pa File

**Option 1 -- Web (no install needed):**

Upload at [writerslogic.com/verify](https://writerslogic.com/verify). Verification runs entirely client-side; the file is never uploaded to a server.

**Option 2 -- CLI:**

```bash
cpoe verify mydoc.c2pa
```

Verification checks:
- Checkpoint chain integrity (no missing or reordered entries)
- Ed25519 signature validity on every checkpoint
- VDF timing proofs (confirms real time elapsed)
- Key hierarchy and session certificate authenticity
- Behavioral consistency (keystroke metrics, if present)

## Next Steps

1. [CLI Reference](cli-reference.md) — All available commands
2. [Configuration](configuration.md) — Customize sentinel, VDF, and beacon settings
3. [GUI Guide](gui-guide.md) — WritersProof macOS app walkthrough
4. [FAQ](faq.md) — Privacy, security, and legal questions
5. [Troubleshooting](troubleshooting.md) — Common issues and solutions

## Getting Help

- **Issues**: https://github.com/writerslogic/cpoe/issues
- **Website**: https://writerslogic.com
