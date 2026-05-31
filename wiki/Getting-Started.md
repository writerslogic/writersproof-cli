# Getting Started with CPoE

CPoE is a cryptographic authorship witnessing system that creates tamper-evident records of your creative process. This guide will help you install and configure CPoE for first use.

## Table of Contents

- [[System Requirements]]
- [[Installation]]
- [[Initial Setup]]
- [[Your First Checkpoint]]
- [[Exporting Evidence]]
- [[Next Steps]]

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|------------|
| Operating System | macOS 13.0+ or Linux (kernel 5.0+) |
| CPU | 64-bit processor (x86_64 or ARM64) |
| RAM | 512 MB available |
| Storage | 100 MB for installation, plus space for evidence data |
| Rust | 1.75+ (for building from source) |

### Optional Hardware

- **TPM 2.0**: Enables hardware-backed attestation (Tier 3 evidence)
- **Secure Enclave**: On Apple Silicon Macs, provides enhanced device binding

---

## Installation

### macOS (Recommended)

#### Using Homebrew

```bash
brew tap writerslogic/cpoe
brew install writerslogic
```

#### Using the macOS App

1. Download `CPoE.dmg` from the [releases page](https://github.com/writerslogic/cpoe/releases)
2. Open the DMG file
3. Drag **CPoE** to your Applications folder
4. Launch the app and follow the **Onboarding Guide** to initialize your identity and calibrate your machine.

The macOS app includes:
- Menu bar integration for quick access
- Automatic keystroke tracking
- Visual checkpoint history
- One-click evidence export

### Linux

#### Using the Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/writerslogic/cpoe/main/install.sh | bash
```

#### Building from Source

```bash
git clone https://github.com/writerslogic/cpoe.git
cd writerslogic
make build
sudo make install
```

### Verifying Installation

```bash
CPoE version
```

---

## Initial Setup

### 1. Initialize CPoE

Before creating checkpoints, you must initialize CPoE:

```bash
cpoe init
```

This creates your unique cryptographic identity bound to your device hardware via [[Glossary#PUF|Physically Unclonable Functions (PUF)]].

### 2. Calibrate Machine

Calibrate the [[Glossary#VDF|Verifiable Delay Function (VDF)]] to ensure accurate timing proofs for your specific CPU:

```bash
cpoe calibrate
```

### 3. Register Browser Extension (Optional)

If you want to witness your process in Google Docs, Overleaf, or Notion:

```bash
CPoE register-native-host
```

Then install the CPoE extension from your browser's extension store.

### Configuration (Optional)

See the **[[Configuration]]** guide for detailed options.

---

## Your First Checkpoint

### Basic Checkpoint

Create a checkpoint for any file:

```bash
# Create or edit a document
echo "My first witnessed document" > mydoc.txt

# Create a checkpoint
cpoe commit mydoc.txt -m "Initial version"
```

### Enhanced Workflow with Keystroke Tracking

For stronger evidence, track keystrokes during writing:

```bash
# Start tracking
cpoe track start mydoc.txt

# ... write your document ...

# Create checkpoint with keystroke evidence
cpoe commit mydoc.txt -m "Draft with tracked keystrokes"

# Stop tracking
cpoe track stop
```

---

## Exporting Evidence

### Export Evidence Packet

When you need to prove authorship:

```bash
cpoe export mydoc.txt
```

This creates `mydoc.c2pa` containing your evidence.

### Verify Evidence

Anyone can verify the evidence:

```bash
cpoe verify mydoc.c2pa
```

---

## Next Steps

1. **Read the [[CLI Reference]]** for all available commands
2. **Configure [[automatic tracking]]** with the sentinel daemon
3. **Try the [[GUI Guide]]** for a visual interface
4. **Understand [[Evidence Format]]** for stronger proofs
5. **Review [[FAQ]]** for common questions

---

*Patent Pending: USPTO Application No. 19/460,364*
