// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::declaration::Declaration;
use crate::evidence::Packet;
use crate::vdf;
use crate::war::types::{Block, CheckResult, ForensicDetails, Seal, VerificationReport, Version};
use ed25519_dalek::{Signature, VerifyingKey};
use hex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

impl Block {
    /// Verify the WAR block and produce a verification report.
    ///
    /// When `expected_public_key` is `Some`, the seal's public key is compared
    /// against it in constant time before running signature verification. Pass
    /// `None` to skip the trusted-key check (self-consistency only).
    pub fn verify(&self, expected_public_key: Option<&[u8]>) -> VerificationReport {
        let mut checks = Vec::new();
        let mut all_passed = true;

        if let Some(trusted) = expected_public_key {
            // Use ct_eq directly; it handles different lengths in constant time.
            let key_matches = bool::from(trusted.ct_eq(&self.seal.public_key));
            let key_check = CheckResult {
                name: "trusted_key".to_string(),
                passed: key_matches,
                message: if key_matches {
                    "Seal public key matches trusted key".to_string()
                } else {
                    "Seal public key does not match trusted key".to_string()
                },
            };
            if !key_check.passed {
                checks.push(key_check);
                // Key mismatch: skip signature verification entirely — the key we
                // would verify against is untrusted, so the result is meaningless.
                return VerificationReport {
                    valid: false,
                    checks,
                    summary: "WAR block INVALID: failed checks: trusted_key".to_string(),
                    details: self.build_forensic_details(),
                };
            }
            checks.push(key_check);
        }

        let sig_check = self.verify_signature();
        if !sig_check.passed {
            all_passed = false;
        }
        checks.push(sig_check);

        if let Some(evidence) = &self.evidence {
            let chain_check = verify_hash_chain(&self.seal, evidence, self.version);
            if !chain_check.passed {
                all_passed = false;
            }
            checks.push(chain_check);

            let vdf_check = verify_vdf_proofs(evidence);
            if !vdf_check.passed {
                all_passed = false;
            }
            checks.push(vdf_check);

            let decl_check = verify_declaration(evidence);
            if !decl_check.passed {
                all_passed = false;
            }
            checks.push(decl_check);

            let beacon_check = verify_beacon_attestation(evidence);
            if !beacon_check.passed {
                all_passed = false;
            }
            checks.push(beacon_check);
        } else {
            checks.push(CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Cannot verify hash chain without full evidence".to_string(),
            });
        }

        let summary = if all_passed {
            format!(
                "WAR block VALID: {} evidence for document {}",
                self.version.as_str(),
                &hex::encode(self.document_id)[..16]
            )
        } else {
            let failed: Vec<_> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();
            format!("WAR block INVALID: failed checks: {}", failed.join(", "))
        };

        let details = self.build_forensic_details();

        VerificationReport {
            valid: all_passed,
            checks,
            summary,
            details,
        }
    }

    /// Verify the Ed25519 seal signature over H3.
    pub fn verify_signature(&self) -> CheckResult {
        if !self.signed {
            return CheckResult {
                name: "seal_signature".to_string(),
                passed: false,
                message: "Seal unsigned: block lacks cryptographic seal signature".to_string(),
            };
        }

        let public_key = match VerifyingKey::from_bytes(&self.seal.public_key) {
            Ok(key) => key,
            Err(e) => {
                return CheckResult {
                    name: "seal_signature".to_string(),
                    passed: false,
                    message: format!("Invalid public key: {e}"),
                };
            }
        };

        let signature = Signature::from_bytes(&self.seal.signature);
        let mut msg = Vec::with_capacity(Block::SEAL_SIG_DST.len() + 32);
        msg.extend_from_slice(Block::SEAL_SIG_DST);
        msg.extend_from_slice(&self.seal.h3);
        match public_key.verify_strict(&msg, &signature) {
            Ok(()) => CheckResult {
                name: "seal_signature".to_string(),
                passed: true,
                message: "Ed25519 seal signature valid (domain-separated H3)".to_string(),
            },
            Err(e) => CheckResult {
                name: "seal_signature".to_string(),
                passed: false,
                message: format!("Seal signature verification failed: {e}"),
            },
        }
    }

    /// Build detailed forensic information from the block and its evidence.
    pub fn build_forensic_details(&self) -> ForensicDetails {
        let mut components = vec!["document".to_string(), "declaration".to_string()];

        let (elapsed_time_secs, checkpoint_count, keystroke_count, has_jitter_seal, has_hw) =
            if let Some(evidence) = &self.evidence {
                let elapsed = evidence.total_elapsed_time().as_secs_f64();
                let cp_count = evidence.checkpoints.len();
                let ks_count = evidence.keystroke.as_ref().map(|k| k.total_keystrokes);

                if evidence.keystroke.is_some() {
                    components.push("keystroke_evidence".to_string());
                }
                if evidence.presence.is_some() {
                    components.push("presence".to_string());
                }
                if evidence.hardware.is_some() {
                    components.push("hardware_attestation".to_string());
                }
                if evidence.behavioral.is_some() {
                    components.push("behavioral".to_string());
                }

                let has_jitter = evidence
                    .declaration
                    .as_ref()
                    .map(|d| d.has_jitter_seal())
                    .unwrap_or(false);
                let has_hw_attest = evidence.hardware.is_some();

                (
                    Some(elapsed),
                    Some(cp_count),
                    ks_count,
                    has_jitter,
                    has_hw_attest,
                )
            } else {
                (
                    None,
                    None,
                    None,
                    matches!(self.version, Version::V1_1 | Version::V2_0),
                    false,
                )
            };

        ForensicDetails {
            version: self.version.as_str().to_owned(),
            author: self.author.clone(),
            document_id: hex::encode(self.document_id),
            timestamp: self.timestamp,
            components,
            elapsed_time_secs,
            checkpoint_count,
            keystroke_count,
            has_jitter_seal,
            has_hardware_attestation: has_hw,
            has_verifier_nonce: self.verifier_nonce.is_some(),
            verifier_nonce: self.verifier_nonce.map(hex::encode),
        }
    }
}

/// Compute the cryptographic seal for an evidence packet.
pub fn compute_seal(packet: &Packet, declaration: &Declaration) -> Result<Seal, String> {
    let doc_hash = hex::decode(&packet.document.final_hash)
        .map_err(|e| format!("invalid document hash: {e}"))?;

    let checkpoint_root =
        hex::decode(&packet.chain_hash).map_err(|e| format!("invalid chain hash: {e}"))?;

    let jitter_hash = declaration
        .jitter_sealed
        .as_ref()
        .map(|j| j.jitter_hash)
        .unwrap_or([0u8; 32]);

    let vdf_output = match packet
        .checkpoints
        .iter()
        .rev()
        .find_map(|cp| cp.vdf_output.as_ref())
    {
        Some(hex_str) => {
            hex::decode(hex_str).map_err(|e| format!("invalid VDF output hex: {e}"))?
        }
        None => vec![0u8; 32],
    };

    let declaration_bytes = declaration
        .encode()
        .map_err(|e| format!("failed to encode declaration: {e}"))?;
    let declaration_hash = Sha256::digest(&declaration_bytes);
    let mut h1_hasher = Sha256::new();
    h1_hasher.update(b"cpoe-seal-h1-v1");
    h1_hasher.update(&doc_hash);
    h1_hasher.update(&checkpoint_root);
    h1_hasher.update(declaration_hash);
    let h1: [u8; 32] = h1_hasher.finalize().into();

    // Beacon attestation binding: include WritersProof counter-signature in H2
    // when present. When absent, the hash computation is identical to the pre-beacon
    // code path — ensuring backward compatibility with existing evidence.
    // If beacon_attestation is Some but wp_signature is malformed, fail hard —
    // silent fallback would allow beacon stripping attacks.
    let beacon_sig = match &packet.beacon_attestation {
        Some(b) => {
            let decoded = hex::decode(&b.wp_signature)
                .map_err(|e| format!("invalid beacon wp_signature hex: {e}"))?;
            if decoded.is_empty() {
                return Err(
                    "beacon wp_signature is empty; cannot bind empty signature"
                        .to_string(),
                );
            }
            Some(decoded)
        }
        None => None,
    };

    let mut h2_hasher = Sha256::new();
    h2_hasher.update(b"cpoe-seal-h2-v1");
    h2_hasher.update(h1);
    h2_hasher.update(jitter_hash);
    h2_hasher.update(&declaration.author_public_key);
    if let Some(ref sig) = beacon_sig {
        h2_hasher.update(sig);
    }
    let h2: [u8; 32] = h2_hasher.finalize().into();

    let mut h3_hasher = Sha256::new();
    h3_hasher.update(b"cpoe-seal-h3-v1");
    h3_hasher.update(h2);
    h3_hasher.update(&vdf_output);
    h3_hasher.update(&doc_hash);
    let h3: [u8; 32] = h3_hasher.finalize().into();

    if declaration.author_public_key.len() != 32 {
        return Err(format!(
            "author_public_key must be 32 bytes, got {}",
            declaration.author_public_key.len()
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&declaration.author_public_key);

    Ok(Seal {
        h1,
        h2,
        h3,
        signature: [0u8; 64],
        public_key,
        reconstructed: false,
    })
}

/// Verify the H1/H2/H3 hash chain against the evidence packet.
pub fn verify_hash_chain(seal: &Seal, evidence: &Packet, version: Version) -> CheckResult {
    let declaration = match &evidence.declaration {
        Some(d) => d,
        None => {
            return CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Missing declaration".to_string(),
            };
        }
    };

    match compute_seal(evidence, declaration) {
        Ok(computed) => {
            if !bool::from(computed.h1.ct_eq(&seal.h1)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H1 mismatch: document/checkpoint binding failed".to_string(),
                };
            }
            if !bool::from(computed.h2.ct_eq(&seal.h2)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H2 mismatch: jitter/identity binding failed".to_string(),
                };
            }
            if !bool::from(computed.h3.ct_eq(&seal.h3)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H3 mismatch: VDF binding failed".to_string(),
                };
            }
            CheckResult {
                name: "hash_chain".to_string(),
                passed: true,
                message: format!("Hash chain valid ({} mode)", version.as_str()),
            }
        }
        Err(e) => CheckResult {
            name: "hash_chain".to_string(),
            passed: false,
            message: format!("Failed to compute seal: {e}"),
        },
    }
}

/// Maximum VDF iterations accepted during verification (1 hour at default rate).
const MAX_VERIFICATION_ITERATIONS: u64 = 3_600_000_000;

/// Verify all VDF proofs in the evidence packet's checkpoints.
pub fn verify_vdf_proofs(evidence: &Packet) -> CheckResult {
    let mut verified = 0;
    let mut total = 0;

    for (i, cp) in evidence.checkpoints.iter().enumerate() {
        if let (Some(input_hex), Some(output_hex), Some(iterations)) =
            (&cp.vdf_input, &cp.vdf_output, cp.vdf_iterations)
        {
            total += 1;
            if iterations > MAX_VERIFICATION_ITERATIONS {
                return CheckResult {
                    name: "vdf_proofs".to_string(),
                    passed: false,
                    message: format!(
                        "VDF iterations at checkpoint {i} exceed maximum: {iterations} > {MAX_VERIFICATION_ITERATIONS}"
                    ),
                };
            }
            let input = match hex::decode(input_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF input at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF input at checkpoint {i} decode error: {e}"),
                    };
                }
            };
            let output = match hex::decode(output_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF output at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF output at checkpoint {i} decode error: {e}"),
                    };
                }
            };

            let proof = vdf::VdfProof {
                input,
                output,
                iterations,
                duration: std::time::Duration::from_secs(0),
            };

            if proof.verify() {
                verified += 1;
            } else {
                return CheckResult {
                    name: "vdf_proofs".to_string(),
                    passed: false,
                    message: format!("VDF proof at checkpoint {i} failed verification"),
                };
            }
        }
    }

    if total == 0 {
        let passed = evidence.checkpoints.len() <= 1;
        let message = if passed {
            "No VDF proofs to verify (first checkpoint only)".to_string()
        } else {
            format!(
                "No VDF proofs found but {} checkpoints present",
                evidence.checkpoints.len()
            )
        };
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed,
            message,
        }
    } else {
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed: true,
            message: format!("All {verified}/{total} VDF proofs verified"),
        }
    }
}

/// Verify the declaration signature in the evidence packet.
pub fn verify_declaration(evidence: &Packet) -> CheckResult {
    match &evidence.declaration {
        Some(decl) => {
            if decl.verify().is_ok() {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: true,
                    message: "Declaration signature valid".to_string(),
                }
            } else {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: false,
                    message: "Declaration signature invalid".to_string(),
                }
            }
        }
        None => CheckResult {
            name: "declaration".to_string(),
            passed: false,
            message: "Missing declaration".to_string(),
        },
    }
}

/// A CA key entry in the WritersProof key ring. Each entry has a validity window;
/// attestations whose `fetched_at` falls outside the window are rejected.
#[derive(Debug)]
struct CaKeyEntry {
    /// Key ID (hex fingerprint, 8 bytes / 16 hex chars).
    kid: &'static str,
    /// Ed25519 public key (hex-encoded, 32 bytes / 64 hex chars).
    pubkey_hex: &'static str,
    /// Validity start (RFC 3339, inclusive).
    not_before: &'static str,
    /// Validity end (RFC 3339, inclusive).
    not_after: &'static str,
}

/// WritersProof CA key ring. Keys are ordered newest-first. When rotating,
/// add the new key at index 0 and leave old keys in place so that existing
/// evidence continues to verify. Remove a key only after its `not_after` has
/// passed AND all evidence signed by it has been re-anchored or expired.
const CA_KEY_RING: &[CaKeyEntry] = &[CaKeyEntry {
    kid: "e58a2aacaad69b37",
    pubkey_hex: "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053",
    not_before: "2026-03-19T00:00:00Z",
    not_after: "2036-03-18T23:59:59Z",
}];

/// Find the CA key for a given attestation, using `wp_key_id` if present,
/// otherwise falling back to timestamp-based selection on `fetched_at`.
fn find_ca_key<'a>(kid: Option<&str>, fetched_at: &str) -> Result<&'a CaKeyEntry, String> {
    use chrono::DateTime;

    let ts = DateTime::parse_from_rfc3339(fetched_at)
        .map_err(|e| format!("Invalid fetched_at timestamp: {e}"))?;

    // If a kid is provided, look it up directly.
    if let Some(kid_value) = kid {
        let entry = CA_KEY_RING
            .iter()
            .find(|k| k.kid == kid_value)
            .ok_or_else(|| format!("Unknown CA key ID: {kid_value}"))?;

        let nb = DateTime::parse_from_rfc3339(entry.not_before)
            .map_err(|e| format!("Internal error: bad not_before in key ring: {e}"))?;
        let na = DateTime::parse_from_rfc3339(entry.not_after)
            .map_err(|e| format!("Internal error: bad not_after in key ring: {e}"))?;

        if ts < nb || ts > na {
            return Err(format!(
                "CA key {} expired or not yet valid for timestamp {}",
                kid_value, fetched_at
            ));
        }
        return Ok(entry);
    }

    // No kid: find the first key whose validity window covers the timestamp.
    for entry in CA_KEY_RING {
        let nb = DateTime::parse_from_rfc3339(entry.not_before)
            .map_err(|e| format!("Internal error: bad not_before in key ring: {e}"))?;
        let na = DateTime::parse_from_rfc3339(entry.not_after)
            .map_err(|e| format!("Internal error: bad not_after in key ring: {e}"))?;

        if ts >= nb && ts <= na {
            return Ok(entry);
        }
    }

    Err(format!(
        "No valid CA key found for timestamp {fetched_at}; \
         evidence may predate the oldest key or postdate all key expiry dates"
    ))
}

/// Verify the WritersProof beacon counter-signature if present.
///
/// When `beacon_attestation` is present, the `wp_signature` must be a valid
/// Ed25519 signature by the WritersProof CA over the beacon bundle.
/// The CA key is selected from the key ring using `wp_key_id` (if present)
/// or `fetched_at` timestamp. Attestations outside any key's validity window
/// are rejected.
/// If no beacon attestation is present, this check passes (beacons are optional).
pub fn verify_beacon_attestation(evidence: &Packet) -> CheckResult {
    verify_beacon_attestation_with_bundle(evidence, None)
}

/// Like [`verify_beacon_attestation`] but accepts a runtime-loaded trust bundle.
///
/// When `bundle` is `Some` and non-empty, key lookup uses the supplied entries
/// instead of the compile-time `CA_KEY_RING`. Pass `None` to use the pinned
/// fallback (same as [`verify_beacon_attestation`]).
pub fn verify_beacon_attestation_with_bundle(
    evidence: &Packet,
    bundle: Option<&[crate::war::trust_bundle::CaBundleEntry]>,
) -> CheckResult {
    let attestation = match &evidence.beacon_attestation {
        Some(a) => a,
        None => {
            return CheckResult {
                name: "beacon_attestation".to_string(),
                passed: true,
                message: "No beacon attestation present (optional)".to_string(),
            };
        }
    };

    // Select the CA key: prefer runtime bundle when provided and non-empty,
    // otherwise fall back to the compile-time CA_KEY_RING.
    let (ca_kid, ca_pubkey_hex) = if let Some(b) = bundle.filter(|b| !b.is_empty()) {
        match crate::war::trust_bundle::find_in_bundle(
            attestation.wp_key_id.as_deref(),
            &attestation.fetched_at,
            b,
        ) {
            Ok(entry) => (entry.kid, entry.pubkey_hex),
            Err(msg) => {
                return CheckResult {
                    name: "beacon_attestation".to_string(),
                    passed: false,
                    message: msg,
                };
            }
        }
    } else {
        match find_ca_key(attestation.wp_key_id.as_deref(), &attestation.fetched_at) {
            Ok(entry) => (entry.kid.to_string(), entry.pubkey_hex.to_string()),
            Err(msg) => {
                return CheckResult {
                    name: "beacon_attestation".to_string(),
                    passed: false,
                    message: msg,
                };
            }
        }
    };

    let ca_pubkey =
        match crate::utils::crypto_types::Ed25519Pubkey::from_hex(&ca_pubkey_hex) {
            Ok(pk) => pk,
            Err(_) => {
                return CheckResult {
                    name: "beacon_attestation".to_string(),
                    passed: false,
                    message: format!("Internal error: invalid CA public key for kid {ca_kid}"),
                };
            }
        };
    let ca_verifying_key = match ca_pubkey.to_verifying_key() {
        Ok(key) => key,
        Err(e) => {
            return CheckResult {
                name: "beacon_attestation".to_string(),
                passed: false,
                message: format!("Invalid CA public key for kid {ca_kid}: {e}"),
            };
        }
    };

    let beacon_sig =
        match crate::utils::crypto_types::Ed25519Sig::from_hex(&attestation.wp_signature) {
            Ok(s) => s,
            Err(e) => {
                return CheckResult {
                    name: "beacon_attestation".to_string(),
                    passed: false,
                    message: format!("Invalid beacon signature hex: {e}"),
                };
            }
        };
    let signature = beacon_sig.to_signature();

    // Reconstruct the signed message: checkpoint_hash || drand fields || nist fields || fetched_at.
    // This must match what WritersProof signed server-side.
    // Variable-length string fields are length-prefixed (4-byte big-endian) to prevent
    // boundary ambiguity attacks where adjacent fields can be shifted across the boundary.
    let mut signed_msg = Vec::new();
    let drand_rand = attestation.drand_randomness.as_bytes();
    let nist_out = attestation.nist_output_value.as_bytes();
    let fetched_at = attestation.fetched_at.as_bytes();
    signed_msg.extend_from_slice(evidence.document.final_hash.as_bytes());
    signed_msg.extend_from_slice(&attestation.drand_round.to_be_bytes());
    signed_msg.extend_from_slice(&(drand_rand.len() as u32).to_be_bytes());
    signed_msg.extend_from_slice(drand_rand);
    signed_msg.extend_from_slice(&attestation.nist_pulse_index.to_be_bytes());
    signed_msg.extend_from_slice(&(nist_out.len() as u32).to_be_bytes());
    signed_msg.extend_from_slice(nist_out);
    signed_msg.extend_from_slice(&(fetched_at.len() as u32).to_be_bytes());
    signed_msg.extend_from_slice(fetched_at);

    match ca_verifying_key.verify_strict(&signed_msg, &signature) {
        Ok(()) => CheckResult {
            name: "beacon_attestation".to_string(),
            passed: true,
            message: format!(
                "Beacon attestation valid (kid {}): drand round {}, NIST pulse {}",
                ca_kid, attestation.drand_round, attestation.nist_pulse_index
            ),
        },
        Err(e) => CheckResult {
            name: "beacon_attestation".to_string(),
            passed: false,
            message: format!("Beacon counter-signature verification failed: {e}"),
        },
    }
}

#[cfg(test)]
mod ca_key_ring_tests {
    use super::*;

    #[test]
    fn test_find_ca_key_by_kid() {
        let entry = find_ca_key(Some("e58a2aacaad69b37"), "2026-06-01T12:00:00Z");
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().kid, "e58a2aacaad69b37");
    }

    #[test]
    fn test_find_ca_key_by_timestamp() {
        let entry = find_ca_key(None, "2030-01-01T00:00:00Z");
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().kid, "e58a2aacaad69b37");
    }

    #[test]
    fn test_find_ca_key_before_validity() {
        let entry = find_ca_key(None, "2025-01-01T00:00:00Z");
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("No valid CA key found"));
    }

    #[test]
    fn test_find_ca_key_after_expiry() {
        let entry = find_ca_key(None, "2037-01-01T00:00:00Z");
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("No valid CA key found"));
    }

    #[test]
    fn test_find_ca_key_unknown_kid() {
        let entry = find_ca_key(Some("0000000000000000"), "2030-01-01T00:00:00Z");
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("Unknown CA key ID"));
    }

    #[test]
    fn test_find_ca_key_kid_expired() {
        let entry = find_ca_key(Some("e58a2aacaad69b37"), "2037-01-01T00:00:00Z");
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("expired or not yet valid"));
    }

    #[test]
    fn test_find_ca_key_at_boundary_start() {
        let entry = find_ca_key(None, "2026-03-19T00:00:00Z");
        assert!(entry.is_ok());
    }

    #[test]
    fn test_find_ca_key_at_boundary_end() {
        let entry = find_ca_key(None, "2036-03-18T23:59:59Z");
        assert!(entry.is_ok());
    }

    #[test]
    fn test_find_ca_key_invalid_timestamp() {
        let entry = find_ca_key(None, "not-a-timestamp");
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("Invalid fetched_at"));
    }

    #[test]
    fn test_key_ring_entries_valid() {
        for entry in CA_KEY_RING {
            assert_eq!(hex::decode(entry.pubkey_hex).unwrap().len(), 32);
            assert!(chrono::DateTime::parse_from_rfc3339(entry.not_before).is_ok());
            assert!(chrono::DateTime::parse_from_rfc3339(entry.not_after).is_ok());
            assert!(!entry.kid.is_empty());
        }
    }
}
