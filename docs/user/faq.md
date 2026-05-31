# Frequently Asked Questions

## General

### What is CPoE?

CPoE (Cryptographic Proof of Effort) is an authorship witnessing system that creates tamper-evident records proving you created a document over time. It captures:
- **What**: Content hashes at each checkpoint
- **When**: VDF-based timing proofs that cannot be backdated
- **How**: Optional keystroke metrics showing real writing activity
- **Who**: Cryptographic identity tied to your device

### Why would I need this?

- **Writers**: Prove original authorship of manuscripts, articles, or scripts
- **Researchers**: Document the development of ideas and discoveries
- **Developers**: Track code evolution with cryptographic evidence
- **Legal/Compliance**: Meet FRE 902(13) self-authentication requirements
- **IP Protection**: Establish prior art or creation dates

### How is this different from version control?

| Feature | CPoE | Git |
|---------|------|-----|
| Time proofs | VDF, cannot be backdated | Timestamps can be faked |
| Author binding | Hardware-tied identity | Email-based (spoofable) |
| Keystroke evidence | Yes (proves real typing) | No |
| Forward secrecy | Ratcheting keys | No |
| Evidence packets | Self-contained, portable | Requires full repo |

### Is CPoE open source?

The project uses a multi-license structure:
- **cpoe engine**: SSPL-1.0 (Server Side Public License)
- **authorproof-protocol**: Apache-2.0 (wire format, wasm-ready)
- **cpoe-jitter**: Apache-2.0 (timing entropy, no_std)
- **CLI**: AGPL-3.0-only
- **macOS/Windows apps**: Proprietary

Source: https://github.com/writerslogic/writerslogic

---

## Privacy and Security

### Does CPoE record what I type?

**No.** CPoE does NOT capture:
- Which keys you press
- Keyboard content or characters
- Screen content
- Clipboard data
- Document text

It only records:
- **Count** of keystroke events
- **Timing** of keystrokes (nanosecond jitter)
- **Hashes** of file content (not content itself)

### Where is my data stored?

All data is stored locally on your machine:
- **CLI**: `~/.writersproof/`
- **macOS App**: `~/Library/Application Support/WritersProof/`

No data is sent to any server unless you explicitly export and share it.

### What data is in an evidence packet?

An exported `.c2pa` file contains:
- File content hashes (not content itself)
- Checkpoint timestamps and VDF proofs
- Keystroke counts and timing statistics
- Your public key and session certificates
- Signed declarations

**Not included** (by default): The actual content of your document.

### Can someone track my identity across documents?

Your master identity (public key fingerprint) is consistent across all documents. This is intentional for proving the same author created multiple works.

For unlinkability, generate a separate identity with a different `--config` directory.

### Is my signing key secure?

Your private key is stored with 0600 permissions. It:
- Never leaves your device
- Is derived from your device's PUF (hardware binding)
- Uses Ed25519 (state-of-the-art)
- Is zeroized from memory after use

---

## Technical

### What is a VDF?

A Verifiable Delay Function is a cryptographic function that:
- Takes a predictable amount of time to compute
- Cannot be parallelized or sped up
- Produces a proof that can be quickly verified

CPoE uses VDFs to prove that real time elapsed between checkpoints.

### What are the evidence tiers?

| Tier | Name | Requirements |
|------|------|-------------|
| T1 | Basic | VDF proof only (offline) |
| T2 | Standard | + keystrokes + timing (recommended) |
| T3 | Enhanced | + behavioral analysis + hardware attestation |
| T4 | Maximum | + all external anchors + full attestation |

### What are the security levels?

Security levels (T1-T4) are assigned based on which temporal witnesses were embedded:

| Level | Guarantee |
|-------|-----------|
| T1 | Minimum elapsed computation time. No absolute time claim. |
| T2 | Absolute time via Roughtime servers. |
| T3 | Creation anchored to drand/NIST randomness beacons. |
| T4 | Four independent time witnesses. Highest assurance. |

### What are temporal beacons?

Cryptographic randomness values published by independent public sources:
- **drand** (League of Entropy): BLS-signed random value every 30 seconds
- **NIST Randomness Beacon**: RSA-signed 512-bit value every 60 seconds

Including a beacon value in a checkpoint proves it was created *after* that value was published, regardless of the author's system clock.

### Can I use CPoE offline?

Yes. Core functionality (VDF proofs, keystroke capture, checkpoint chains) works without internet. Network-optional features:
- Temporal beacon attestation (drand + NIST)
- WritersProof certificate enrollment
- Transparency log anchoring

Disabling beacons caps evidence at T2.

### How much storage does CPoE use?

- Per checkpoint: ~500 bytes in database
- Per hour of writing: ~10 KB (with keystroke tracking)
- Evidence packet: 5-50 KB depending on checkpoints

---

## Legal

### Does this provide legal proof of authorship?

CPoE creates strong cryptographic evidence. Legal acceptance depends on jurisdiction, type of proceeding, and expert testimony. Evidence is designed to be admissible under FRE 902(13) for self-authentication of electronic records.

### Does CPoE guarantee I created the content?

CPoE proves:
- Content existed at specific times
- Real typing activity occurred
- The same device/identity signed all checkpoints

It cannot prove you didn't copy from elsewhere, but keystroke evidence, VDF timing, and consistent identity together create strong provenance.

---

## Practical Usage

### I received a .c2pa file. What do I do with it?

**Web (easiest):** Go to [writerslogic.com/verify](https://writerslogic.com/verify) and upload the file. Verification runs in your browser; nothing is sent to a server.

**CLI:** `cpoe verify proof.c2pa`

### How often should I create checkpoints?

| Use Case | Interval |
|----------|----------|
| Casual writing | Every session |
| Important documents | Every 15-30 minutes |
| Legal/compliance | Every 5-10 minutes |
| Automatic (sentinel) | Every 1-5 minutes |

### Can I export a PDF report?

Yes:
```bash
cpoe export manuscript.txt -f pdf
```

PDF reports include anti-forgery security features (guilloche patterns, microtext) cryptographically bound to the evidence packet, plus verdict, forensic score, writing flow visualization, and an embedded WAR block for independent verification.

### Can I verify evidence without CPoE installed?

Upload to [writerslogic.com/verify](https://writerslogic.com/verify) for browser-based verification (WASM engine, nothing uploaded).

---

## More Questions?

- **Issues**: https://github.com/writerslogic/writerslogic/issues
- **Website**: https://writerslogic.com
