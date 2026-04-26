// SPDX-License-Identifier: Apache-2.0

//! Jitter evidence encoding for embedding in packets

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Jitter, PhysHash};

/// A single jitter evidence record, either hardware-bound (`Phys`) with a
/// physical hash or software-only (`Pure`). Use `Phys` when HID/hardware
/// entropy is available; fall back to `Pure` for keystroke-only capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Evidence {
    Phys {
        phys_hash: PhysHash,
        jitter: Jitter,
        timestamp_us: u64,
        #[serde(default)]
        sequence: u64,
    },
    Pure {
        jitter: Jitter,
        timestamp_us: u64,
        #[serde(default)]
        sequence: u64,
    },
}

impl Evidence {
    pub fn phys_with_timestamp(phys_hash: PhysHash, jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Phys {
            phys_hash,
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    pub fn pure_with_timestamp(jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Pure {
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    #[cfg(feature = "std")]
    pub fn phys(phys_hash: PhysHash, jitter: Jitter) -> Self {
        Self::phys_with_timestamp(phys_hash, jitter, current_timestamp_us())
    }

    #[cfg(feature = "std")]
    pub fn pure(jitter: Jitter) -> Self {
        Self::pure_with_timestamp(jitter, current_timestamp_us())
    }
    #[inline]
    pub fn sequence(&self) -> u64 {
        match self {
            Evidence::Phys { sequence, .. } => *sequence,
            Evidence::Pure { sequence, .. } => *sequence,
        }
    }

    fn write_fields(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Evidence::Phys {
                phys_hash,
                jitter,
                timestamp_us,
                sequence,
            } => {
                f(&[0u8]);
                f(&phys_hash.hash);
                f(&[phys_hash.entropy_bits]);
                f(&jitter.to_le_bytes());
                f(&timestamp_us.to_le_bytes());
                f(&sequence.to_le_bytes());
            }
            Evidence::Pure {
                jitter,
                timestamp_us,
                sequence,
            } => {
                f(&[1u8]);
                f(&jitter.to_le_bytes());
                f(&timestamp_us.to_le_bytes());
                f(&sequence.to_le_bytes());
            }
        }
    }

    pub fn hash_into(&self, hasher: &mut sha2::Sha256) {
        use sha2::Digest;
        self.write_fields(|bytes| hasher.update(bytes));
    }

    pub fn hash_into_mac(&self, mac: &mut hmac::Hmac<sha2::Sha256>) {
        use hmac::Mac;
        self.write_fields(|bytes| mac.update(bytes));
    }
    #[inline]
    pub fn jitter(&self) -> Jitter {
        match self {
            Evidence::Phys { jitter, .. } => *jitter,
            Evidence::Pure { jitter, .. } => *jitter,
        }
    }
    #[inline]
    pub fn is_phys(&self) -> bool {
        matches!(self, Evidence::Phys { .. })
    }
    #[inline]
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Evidence::Phys { timestamp_us, .. } => *timestamp_us,
            Evidence::Pure { timestamp_us, .. } => *timestamp_us,
        }
    }

    /// Recompute the jitter value and compare in constant time via `subtle::ConstantTimeEq`.
    /// Returns `true` if the stored jitter matches the recomputed value.
    pub fn verify<E: crate::JitterEngine>(
        &self,
        secret: &[u8; 32],
        inputs: &[u8],
        engine: &E,
    ) -> bool {
        use subtle::ConstantTimeEq;
        match self {
            Evidence::Phys {
                phys_hash, jitter, ..
            } => {
                let recomputed = engine.compute_jitter(secret, inputs, *phys_hash);
                recomputed.ct_eq(jitter).into()
            }
            Evidence::Pure { jitter, .. } => {
                let recomputed = engine.compute_jitter(secret, inputs, PhysHash::from([0u8; 32]));
                recomputed.ct_eq(jitter).into()
            }
        }
    }
}

/// Prevents unbounded allocation on deserialization of untrusted data.
pub const MAX_EVIDENCE_RECORDS: usize = 100_000;

/// Append-only chain of evidence records with HMAC integrity protection.
///
/// In keyed mode (`with_secret`), each link is HMAC-SHA256(prev_mac || record).
/// In unkeyed mode (`new`), each link is SHA-256(prev_hash || record).
/// The `secret` field is `#[serde(skip)]`; after deserialization, call
/// `verify_integrity()` with the secret or `verify_integrity_unkeyed()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EvidenceChainRaw")]
pub struct EvidenceChain {
    pub version: u8,
    records: Vec<Evidence>,
    chain_mac: [u8; 32],
    #[serde(default)]
    next_sequence: u64,
    #[serde(skip)]
    secret: Option<Zeroizing<[u8; 32]>>,
}

/// Raw deserialization target for [`EvidenceChain`].
/// Bounds are validated via [`TryFrom`] so untrusted input cannot allocate
/// more than [`MAX_EVIDENCE_RECORDS`] entries.
#[derive(Deserialize)]
struct EvidenceChainRaw {
    version: u8,
    records: Vec<Evidence>,
    chain_mac: [u8; 32],
    #[serde(default)]
    next_sequence: u64,
}

impl TryFrom<EvidenceChainRaw> for EvidenceChain {
    type Error = &'static str;

    fn try_from(raw: EvidenceChainRaw) -> core::result::Result<Self, Self::Error> {
        if raw.version != 1 {
            return Err("unsupported evidence chain version");
        }
        if raw.records.len() > MAX_EVIDENCE_RECORDS {
            return Err("evidence chain exceeds MAX_EVIDENCE_RECORDS");
        }
        if raw.next_sequence != raw.records.len() as u64 {
            return Err("next_sequence does not match record count");
        }
        // Validate per-record sequence numbers match their index.
        for (i, record) in raw.records.iter().enumerate() {
            if record.sequence() != i as u64 {
                return Err("record sequence number does not match index");
            }
        }
        // MAC verification deferred to verify_integrity(); TryFrom only validates structure.
        Ok(Self {
            version: raw.version,
            records: raw.records,
            chain_mac: raw.chain_mac,
            next_sequence: raw.next_sequence,
            secret: None,
        })
    }
}

impl Default for EvidenceChain {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceChain {
    /// Read-only access to the evidence records.
    pub fn records(&self) -> &[Evidence] {
        &self.records
    }

    /// Mutable access to the evidence records for integrity tests that
    /// deliberately tamper with the chain. Not available in production builds.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn records_mut(&mut self) -> &mut Vec<Evidence> {
        &mut self.records
    }

    /// Read-only access to the chain MAC.
    pub fn chain_mac(&self) -> &[u8; 32] {
        &self.chain_mac
    }

    /// Number of evidence records in the chain.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the chain contains no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Create an empty unkeyed evidence chain (SHA-256 integrity).
    pub fn new() -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: None,
        }
    }

    /// Create an empty keyed evidence chain (HMAC-SHA256 integrity).
    pub fn with_secret(secret: &[u8; 32]) -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: Some(Zeroizing::new(*secret)),
        }
    }

    /// Check whether the chain exceeds [`MAX_EVIDENCE_RECORDS`].
    pub fn validate_bounds(&self) -> bool {
        self.records.len() <= MAX_EVIDENCE_RECORDS
    }

    /// Append an evidence record, assigning its sequence number and updating the chain MAC.
    ///
    /// Returns `Error::EvidenceOverflow` if the chain already has
    /// [`MAX_EVIDENCE_RECORDS`] entries.
    pub fn append(&mut self, mut evidence: Evidence) -> core::result::Result<(), crate::Error> {
        if self.records.len() >= MAX_EVIDENCE_RECORDS {
            return Err(crate::Error::EvidenceOverflow(MAX_EVIDENCE_RECORDS));
        }

        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        match &mut evidence {
            Evidence::Phys { sequence, .. } | Evidence::Pure { sequence, .. } => {
                *sequence = self.next_sequence;
            }
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(crate::Error::EvidenceOverflow(MAX_EVIDENCE_RECORDS))?;

        if let Some(secret) = &self.secret {
            let mut mac =
                HmacSha256::new_from_slice(secret.as_ref()).expect("HMAC accepts any key size");
            mac.update(&self.chain_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            self.chain_mac.copy_from_slice(&result);
        } else {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(self.chain_mac);
            evidence.hash_into(&mut hasher);
            let result = hasher.finalize();
            self.chain_mac.copy_from_slice(&result);
        }

        self.records.push(evidence);
        Ok(())
    }

    /// Verify the HMAC chain in constant time. Replays every record's MAC and
    /// compares the final value against the stored `chain_mac` via `subtle`.
    pub fn verify_integrity(&self, secret: &[u8; 32]) -> bool {
        use hmac::{Hmac, Mac};
        use subtle::ConstantTimeEq;

        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut expected_mac = [0u8; 32];
        for evidence in &self.records {
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
            mac.update(&expected_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            expected_mac.copy_from_slice(&result);
        }

        expected_mac.ct_eq(&self.chain_mac).into()
    }

    /// Verify the SHA-256 hash chain in constant time for unkeyed chains.
    pub fn verify_integrity_unkeyed(&self) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let mut expected_mac = [0u8; 32];
        for evidence in &self.records {
            let mut hasher = Sha256::new();
            hasher.update(expected_mac);
            evidence.hash_into(&mut hasher);
            let result = hasher.finalize();
            expected_mac.copy_from_slice(&result);
        }

        expected_mac.ct_eq(&self.chain_mac).into()
    }

    pub fn validate_timestamps(&self) -> bool {
        self.records
            .windows(2)
            .all(|w| w[0].timestamp_us() <= w[1].timestamp_us())
    }
    pub fn validate_sequences(&self) -> bool {
        self.records
            .iter()
            .enumerate()
            .all(|(i, e)| e.sequence() == i as u64)
    }

    pub fn phys_count(&self) -> usize {
        self.records.iter().filter(|e| e.is_phys()).count()
    }

    pub fn pure_count(&self) -> usize {
        self.records.len() - self.phys_count()
    }
    pub fn phys_ratio(&self) -> f64 {
        if self.records.is_empty() {
            0.0
        } else {
            self.phys_count() as f64 / self.records.len() as f64
        }
    }

    pub fn verify_chain<E: crate::JitterEngine>(
        &self,
        secret: &[u8; 32],
        inputs: &[&[u8]],
        engine: &E,
    ) -> bool {
        if inputs.len() != self.records.len() {
            return false;
        }
        self.records
            .iter()
            .zip(inputs.iter())
            .all(|(evidence, input)| evidence.verify(secret, input, engine))
    }
}

#[cfg(feature = "std")]
fn current_timestamp_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_chain_tamper_detection() {
        let secret = [99u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);

        for i in 0..10u32 {
            let evidence = Evidence::pure_with_timestamp(1000 + i * 100, (i as u64 + 1) * 1000);
            chain.append(evidence).unwrap();
        }
        assert!(chain.verify_integrity(&secret));

        // Tamper: modify a jitter value in the middle
        if let Evidence::Pure { jitter, .. } = &mut chain.records_mut()[5] {
            *jitter = 99999;
        }
        assert!(
            !chain.verify_integrity(&secret),
            "Tampered chain should fail integrity check"
        );

        // Tamper: swap two records
        let mut chain2 = EvidenceChain::with_secret(&secret);
        for i in 0..5u32 {
            chain2
                .append(Evidence::pure_with_timestamp(
                    1000 + i * 100,
                    (i as u64 + 1) * 1000,
                ))
                .unwrap();
        }
        assert!(chain2.verify_integrity(&secret));
        chain2.records_mut().swap(1, 3);
        assert!(
            !chain2.verify_integrity(&secret),
            "Swapped records should fail integrity"
        );
        assert!(
            !chain2.validate_sequences(),
            "Swapped records should fail sequence validation"
        );
    }
}
