# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Security updates are released as patch versions. We recommend always running
the latest version.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Preferred Method

Report vulnerabilities via email to: **admin@writerslogic.com**

Include:
- Type of issue (cryptographic weakness, privilege escalation, etc.)
- Full paths of affected source files
- Step-by-step reproduction instructions
- Proof-of-concept code (if available)
- Impact assessment

### Response Timeline

- **Initial Response:** Within 48 hours
- **Severity Assessment:** Within 5 business days
- **Fix Timeline:** Based on severity (Critical: 7 days, High: 30 days)

### Disclosure Policy

We follow coordinated disclosure:
1. Reporter notifies us privately
2. We acknowledge and assess
3. We develop and test a fix
4. We release the fix with credit to reporter (unless anonymity requested)
5. Public disclosure after users have time to update

## Security Model

### Threat Model

CPoE provides cryptographic evidence of file authorship. The security
model assumes:

**Trusted Components:**
- Local kernel and hardware (including TPM when used)
- The user account running CPoE
- The filesystem's access control enforcement

**Protected Against:**
- Post-hoc forgery of historical records
- Tampering with the append-only Merkle Mountain Range
- Undetected modification of witnessed file hashes
- Clock manipulation (when using external timestamping)

**Not Protected Against:**
- Kernel-level compromise or rootkits
- Physical access attacks on non-TPM systems
- Compromise of the signing key
- Real-time content interception (we don't prevent access, only prove state)

### Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Content Hashing | SHA-256 | FIPS 180-4 |
| Commitment Signing | Ed25519 | RFC 8032 |
| Shadow Encryption | AES-256-GCM | FIPS 197 + SP 800-38D |
| Key Derivation | SHA-256 HKDF-style | SP 800-56C |
| TPM Attestation | TPM 2.0 Quote | TCG TPM 2.0 Library |

All primitives use well-audited Rust crates from the [RustCrypto](https://github.com/RustCrypto)
project (`sha2`, `ed25519-dalek`, `aes-gcm`, `hkdf`, `hmac`), which follow FIPS standards.

### Domain Separation

All hash operations use domain-separated prefixes to prevent cross-protocol
attacks:

```
Leaf:     0x00 || content_hash || metadata_hash || regions_root
Internal: 0x01 || left_hash || right_hash
Root:     0x02 || peak_bag_hash
```

## Security Hardening

### Production Deployment

```bash
# Create dedicated system user
sudo useradd -r -s /sbin/nologin -d /var/lib/writerslogic writerslogic

# Restrictive permissions
chmod 700 /var/lib/writerslogic
chmod 600 /var/lib/writerslogic/config.toml
chmod 400 /var/lib/writerslogic/signing.key

# Use TPM-sealed keys (recommended)
writersproof-cli init --tpm-sealed

# Enable audit logging
writersproof-cli start --foreground  # daemon logs to ~/.writersproof/logs/daemon.log
```

### Linux Capabilities

Instead of running as root, grant specific capabilities:

```bash
# Required for TPM access
sudo setcap cap_sys_admin+ep /usr/local/bin/writersproof-cli

# Or use the provided udev rules for non-root TPM access
sudo cp rules.d/99-writerslogic-tpm.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

### Systemd Hardening

See `contrib/writerslogic.service` for a hardened systemd unit with:
- `ProtectSystem=strict`
- `PrivateTmp=true`
- `NoNewPrivileges=true`
- `CapabilityBoundingSet=CAP_SYS_ADMIN`

## Secure Development

### Code Review Requirements

- All cryptographic code requires review by a maintainer with security experience
- No custom cryptographic primitives (use standard libraries only)
- Constant-time comparisons for all secret-dependent operations

### Dependency Management

- Automated vulnerability scanning via Dependabot/Renovate
- SBOM generated for every release (SPDX format)
- SLSA Level 3 provenance for release binaries

### Testing

- Fuzzing for all parsing code
- Property-based testing for cryptographic operations
- Integration tests against TPM simulator

## Known Limitations

1. **Clock Skew:** Local timestamps can be manipulated. Use external
   timestamping (RFC 3161 or OpenTimestamps) for legally robust timing.

2. **Key Compromise:** If the Ed25519 signing key is compromised, an attacker
   can forge future signatures. Use TPM-sealed keys to mitigate.

3. **Pre-Image Attacks:** While SHA-256 is secure, an attacker with access
   to files before witnessing can create content with identical hashes to
   other content (not pre-images, but collision scenarios in controlled
   environments).

## Security Versioning

We follow semantic versioning with security implications:

- **PATCH (0.0.x):** Security fixes, no breaking changes
- **MINOR (0.x.0):** New features, may include security enhancements
- **MAJOR (x.0.0):** Breaking changes, may include cryptographic upgrades

Cryptographic algorithm changes are always MAJOR version bumps with extended
deprecation periods.

## Acknowledgments

We thank the following researchers for responsible disclosure:

*No vulnerabilities reported yet.*

If you report a valid vulnerability, we will acknowledge you here (unless you
prefer anonymity).
