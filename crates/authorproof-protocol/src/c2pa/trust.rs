// SPDX-License-Identifier: Apache-2.0

//! Certificate chain trust evaluation for C2PA manifests.
//!
//! Provides a lightweight `TrustLevel` classification based on the certificate
//! chain supplied in the x5chain COSE header. Full PKI validation (CRL, OCSP,
//! path-length constraints) is out of scope for the wasm32-compatible protocol
//! crate; that lives in the engine crate where platform APIs are available.

/// Trust level classification for a C2PA manifest's signing certificate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// No certificate provided, or certificate chain is empty.
    /// The public key was embedded as raw bytes — no identity binding.
    SelfSigned,
    /// A certificate chain was provided with two or more certificates,
    /// suggesting an issuing CA signed the end-entity certificate.
    /// Chain validity (signature, expiry, revocation) is not verified here.
    CertChain,
    /// The chain root matches a known C2PA trust anchor.
    /// Reserved for future use when a trust anchor list is available.
    TrustAnchored,
}

/// Evaluate the trust level of a certificate chain supplied as DER-encoded bytes.
///
/// This is a structural evaluation only:
/// - Empty slice → `SelfSigned`
/// - One certificate → `SelfSigned` (self-issued, no CA in chain)
/// - Two or more certificates → `CertChain`
///
/// `TrustAnchored` requires a trust anchor list and is not assigned here.
pub fn evaluate_trust(chain: &[Vec<u8>]) -> TrustLevel {
    match chain.len() {
        0 | 1 => TrustLevel::SelfSigned,
        _ => TrustLevel::CertChain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_evaluation() {
        assert_eq!(evaluate_trust(&[]), TrustLevel::SelfSigned);
        assert_eq!(evaluate_trust(&[vec![0x30, 0x00]]), TrustLevel::SelfSigned);
        assert_eq!(
            evaluate_trust(&[vec![0x30, 0x00], vec![0x30, 0x01]]),
            TrustLevel::CertChain
        );
        assert_eq!(
            evaluate_trust(&[vec![0x30, 0x00], vec![0x30, 0x01], vec![0x30, 0x02]]),
            TrustLevel::CertChain
        );
    }

    #[test]
    fn test_trust_level_ordering() {
        // TrustAnchored > CertChain > SelfSigned
        assert!(TrustLevel::TrustAnchored > TrustLevel::CertChain);
        assert!(TrustLevel::CertChain > TrustLevel::SelfSigned);
    }
}
