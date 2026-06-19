# Privacy Policy

**Effective Date:** January 2026
**Last Updated:** January 24, 2026

## Overview

CPoE is a local-first file witnessing daemon that creates cryptographic
evidence of file authorship and modification history. This privacy policy
explains what data CPoE collects, how it is processed, and your rights
regarding that data.

**Key Principle:** All data processing occurs exclusively on your local device.
No data is transmitted to external servers, cloud services, or third parties
by the CPoE software itself.

## Data Collection and Processing

### 1. File Content Hashes

**What is collected:**
- SHA-256 cryptographic hashes of monitored file contents
- File hashes are one-way transformations; original content cannot be recovered

**What is NOT collected:**
- Raw file contents (unless shadow cache is explicitly enabled)
- File names in hash computations (stored separately as metadata)

**Purpose:** To create tamper-evident records proving file state at specific times.

**Storage:** Local SQLite database at `~/.writersproof/events.db`

### 2. Keystroke Timing Metrics (Behavioral Biometrics)

**What is collected:**
- Inter-keystroke intervals (time between key presses), in milliseconds
- Key flight times (key press to release duration)
- Pause durations between editing sessions
- Aggregate statistical metrics (median, entropy, clustering coefficients)

**What is NOT collected:**
- Actual key values or characters typed
- Keyboard scan codes or key identifiers
- Screen content or clipboard data
- Any data that could reconstruct typed text

**Purpose:** To establish "kinetic integrity" - behavioral patterns that
distinguish human authorship from automated content generation.

**Legal Basis:** Keystroke dynamics constitute behavioral biometric data under:
- GDPR Article 9 (Special Categories of Personal Data)
- CCPA § 1798.140(b) (Biometric Information)
- Illinois BIPA (Biometric Information Privacy Act)

**Your Rights:**
- You may disable keystroke metrics collection via configuration
- All keystroke data remains on your local device
- No biometric templates are transmitted externally
- You may delete all collected data at any time

### 3. Edit Topology Data

**What is collected:**
- Normalized positions of edits within files (0.0-1.0 scale)
- Size changes (insertions/deletions) in bytes
- Temporal patterns of editing sessions

**What is NOT collected:**
- Actual text inserted or deleted
- Semantic content of changes
- Surrounding context of edits

**Purpose:** To detect patterns consistent with human authorship versus
automated content generation, without accessing actual content.

### 4. Cryptographic Signatures

**What is collected:**
- Ed25519 signatures over Merkle Mountain Range roots
- Timestamps of signature operations
- Optional: TPM-backed attestations binding signatures to hardware

**Purpose:** To create cryptographically verifiable evidence. Note: Legal
admissibility depends on jurisdiction and context; consult legal counsel.

## Data Storage and Security

### Local Storage Only

All CPoE data is stored locally in:
- `~/.writersproof/` - Configuration and databases
- `~/.writersproof/events.db` - Event store (SQLite, encrypted at rest optional)
- `~/.writersproof/mmr.bin` - Merkle Mountain Range (append-only)
- `~/.writersproof/shadows/` - Encrypted content cache (AES-256-GCM)

### Encryption

- Shadow cache: AES-256-GCM with keys derived from signing key
- Database: Optional SQLite encryption via SQLCipher
- Keys: File permissions (0600) or TPM-sealed storage

### No Network Transmission

CPoE does not:
- Connect to any remote servers
- Transmit telemetry or analytics
- Phone home for license verification
- Upload any collected data

**Exception:** If you explicitly configure external timestamping (RFC 3161 TSA
or OpenTimestamps), only cryptographic hashes are transmitted - never file
contents, keystroke data, or behavioral metrics.

## Data Retention

**Default:** Data is retained indefinitely to maintain complete audit trails.

**User Control:** You may:
- Delete the entire `~/.writersproof/` directory to remove all data
- Use `witnessctl prune` to remove events older than a specified date
- Disable specific collection features via configuration

## Your Rights

### Under GDPR (EU/EEA residents)

- **Right of Access:** All data is stored locally and accessible to you
- **Right to Erasure:** Delete `~/.writersproof/` to erase all data
- **Right to Restrict Processing:** Disable features via configuration
- **Right to Data Portability:** Export data via `witnessctl export`
- **Right to Object:** Stop the daemon to cease all processing

### Under CCPA (California residents)

- **Right to Know:** This policy describes all data collected
- **Right to Delete:** Delete local data directory
- **Right to Opt-Out:** No data is sold; not applicable
- **Right to Non-Discrimination:** Not applicable (no services contingent on data)

### Under BIPA (Illinois residents)

- **Written Policy:** This document serves as the required written policy
- **Consent:** By running CPoE, you consent to local biometric collection
- **Retention Schedule:** Data retained until manually deleted
- **Destruction Guidelines:** Delete `~/.writersproof/` directory
- **No Disclosure:** Biometric data is never disclosed to third parties

## Children's Privacy

CPoE does not knowingly collect data from children under 13. The software
is intended for use by adults in professional and legal contexts.

## Changes to This Policy

We will update this policy as needed. Changes will be documented in the
CHANGELOG and git history. Continued use after changes constitutes acceptance.

## Contact

For privacy inquiries:
- GitHub Issues: https://github.com/writerslogic/writersproof-cli/issues
- Email: privacy@writerslogic.com

## Technical Appendix: Data Minimization

CPoE implements privacy-by-design principles:

1. **Hash-Only Content Tracking:** File contents are never stored unless
   explicitly enabled. Only cryptographic hashes are retained.

2. **Timing-Only Keystroke Analysis:** We measure *when* keys are pressed,
   not *which* keys. This provides behavioral biometrics without capturing
   sensitive input.

3. **Normalized Topology:** Edit positions are stored as percentages (0.0-1.0),
   not absolute byte offsets, preventing reconstruction of document structure.

4. **Local-Only Processing:** All computation occurs on-device. No data
   leaves your machine unless you explicitly configure external anchoring.

5. **Encryption at Rest:** Sensitive caches use AES-256-GCM encryption
   with keys that never leave the local system (or TPM).
