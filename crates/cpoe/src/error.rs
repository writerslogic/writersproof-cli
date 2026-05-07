// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Unified error type wrapping all subsystem errors for consistent handling
//! and pattern matching across the crate.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    System,
    Security,
    Logic,
    Protocol,
    Analysis,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("anchor: {0}")]
    Anchor(#[from] crate::anchors::AnchorError),

    #[error("codec: {0}")]
    Codec(#[from] authorproof_protocol::codec::CodecError),

    #[error("compact ref: {0}")]
    CompactRef(#[from] authorproof_protocol::compact_ref::CompactRefError),

    #[error("forensics: {0}")]
    Forensics(#[from] crate::forensics::ForensicsError),

    #[cfg(unix)]
    #[error("ipc unix: {0}")]
    IpcUnix(#[from] crate::ipc::unix_socket::IpcError),

    #[error("ipc: {0}")]
    Ipc(String),

    #[error("key hierarchy: {0}")]
    KeyHierarchy(#[from] crate::keyhierarchy::KeyHierarchyError),

    #[error("mmr: {0}")]
    Mmr(#[from] crate::mmr::errors::MmrError),

    #[error("sentinel: {0}")]
    Sentinel(#[from] crate::sentinel::SentinelError),

    #[error("tpm: {0}")]
    Tpm(#[from] crate::tpm::TpmError),

    #[error("vdf aggregate: {0}")]
    VdfAggregate(#[from] crate::vdf::AggregateError),

    #[error("wal: {0}")]
    Wal(#[from] crate::wal::WalError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("signature: {0}")]
    Signature(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("validation: {0}")]
    Validation(String),

    #[error("config: {0}")]
    Config(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("checkpoint: {0}")]
    Checkpoint(String),

    #[error("evidence: {0}")]
    Evidence(String),

    #[error("vdf: {0}")]
    Vdf(String),

    #[error("identity: {0}")]
    Identity(String),

    #[error("platform: {0}")]
    Platform(String),

    #[error("physics: {0}")]
    Physics(String),

    #[error("rfc: {0}")]
    Rfc(String),

    #[error("trust policy: {0}")]
    TrustPolicy(#[from] crate::trust_policy::TrustPolicyError),

    #[error("internal: {0}")]
    Internal(String),

    #[error("{0}")]
    Legacy(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::Io(_)
            | Error::Timeout(_)
            | Error::Ipc(_)
            | Error::Sentinel(_)
            | Error::Wal(_)
            | Error::Platform(_) => ErrorCategory::System,
            #[cfg(unix)]
            Error::IpcUnix(_) => ErrorCategory::System,
            Error::Crypto(_)
            | Error::Signature(_)
            | Error::HashMismatch { .. }
            | Error::Tpm(_)
            | Error::KeyHierarchy(_) => ErrorCategory::Security,
            Error::Validation(_)
            | Error::Config(_)
            | Error::NotFound(_)
            | Error::InvalidState(_)
            | Error::Internal(_)
            | Error::Identity(_)
            | Error::Legacy(_) => ErrorCategory::Logic,
            Error::Codec(_)
            | Error::CompactRef(_)
            | Error::Rfc(_)
            | Error::Anchor(_)
            | Error::Mmr(_) => ErrorCategory::Protocol,
            Error::VdfAggregate(_)
            | Error::Forensics(_)
            | Error::Checkpoint(_)
            | Error::Evidence(_)
            | Error::Vdf(_)
            | Error::Physics(_) => ErrorCategory::Analysis,
            Error::TrustPolicy(_) => ErrorCategory::Logic,
        }
    }

    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Io(_) | Error::Timeout(_) | Error::Anchor(_) | Error::Ipc(_)
        ) || {
            #[cfg(unix)]
            {
                matches!(self, Error::IpcUnix(_))
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    }

    pub fn is_validation(&self) -> bool {
        matches!(
            self,
            Error::Validation(_) | Error::HashMismatch { .. } | Error::Signature(_)
        )
    }

    pub fn checkpoint(m: impl Into<String>) -> Self {
        Error::Checkpoint(m.into())
    }
    pub fn evidence(m: impl Into<String>) -> Self {
        Error::Evidence(m.into())
    }
    pub fn vdf(m: impl Into<String>) -> Self {
        Error::Vdf(m.into())
    }
    pub fn validation(m: impl Into<String>) -> Self {
        Error::Validation(m.into())
    }
    pub fn crypto(m: impl Into<String>) -> Self {
        Error::Crypto(m.into())
    }
    pub fn config(m: impl Into<String>) -> Self {
        Error::Config(m.into())
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Error::NotFound(m.into())
    }
    pub fn invalid_state(m: impl Into<String>) -> Self {
        Error::InvalidState(m.into())
    }
    pub fn platform(m: impl Into<String>) -> Self {
        Error::Platform(m.into())
    }
    pub fn identity(m: impl Into<String>) -> Self {
        Error::Identity(m.into())
    }
    pub fn physics(m: impl Into<String>) -> Self {
        Error::Physics(m.into())
    }
    pub fn rfc(m: impl Into<String>) -> Self {
        Error::Rfc(m.into())
    }
    pub fn signature(m: impl Into<String>) -> Self {
        Error::Signature(m.into())
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Error::Internal(m.into())
    }
    pub fn ipc(m: impl Into<String>) -> Self {
        Error::Ipc(m.into())
    }
    pub fn io(m: impl Into<String>) -> Self {
        Error::Io(std::io::Error::other(m.into()))
    }

    /// Specialized constructor for hex-formatted hash mismatches.
    pub fn hash_mismatch(expected: &[u8], actual: &[u8]) -> Self {
        Error::HashMismatch {
            expected: hex::encode(expected),
            actual: hex::encode(actual),
        }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Legacy(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Legacy(s.to_string())
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::checkpoint("chain broken at index 5");
        assert_eq!(err.to_string(), "checkpoint: chain broken at index 5");
    }

    #[test]
    fn test_error_from_string() {
        let err: Error = "legacy error message".into();
        assert!(matches!(err, Error::Legacy(_)));
        assert_eq!(err.to_string(), "legacy error message");
    }

    #[test]
    fn test_error_to_string() {
        let err = Error::validation("invalid input");
        let s: String = err.into();
        assert_eq!(s, "validation: invalid input");
    }

    #[test]
    fn test_is_transient() {
        let timeout = Error::Timeout("operation timed out".into());
        assert!(timeout.is_transient());

        let validation = Error::Validation("bad input".into());
        assert!(!validation.is_transient());
    }

    #[test]
    fn test_is_validation() {
        let validation = Error::Validation("bad input".into());
        assert!(validation.is_validation());

        let hash_mismatch = Error::HashMismatch {
            expected: "abc".into(),
            actual: "def".into(),
        };
        assert!(hash_mismatch.is_validation());

        let io = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file"));
        assert!(!io.is_validation());
    }

    #[test]
    fn test_constructors() {
        assert!(matches!(Error::checkpoint("test"), Error::Checkpoint(_)));
        assert!(matches!(Error::evidence("test"), Error::Evidence(_)));
        assert!(matches!(Error::vdf("test"), Error::Vdf(_)));
        assert!(matches!(Error::validation("test"), Error::Validation(_)));
        assert!(matches!(Error::crypto("test"), Error::Crypto(_)));
        assert!(matches!(Error::config("test"), Error::Config(_)));
        assert!(matches!(Error::not_found("test"), Error::NotFound(_)));
        assert!(matches!(
            Error::invalid_state("test"),
            Error::InvalidState(_)
        ));
        assert!(matches!(Error::platform("test"), Error::Platform(_)));
        assert!(matches!(Error::identity("test"), Error::Identity(_)));
        assert!(matches!(Error::physics("test"), Error::Physics(_)));
        assert!(matches!(Error::rfc("test"), Error::Rfc(_)));
        assert!(matches!(Error::signature("test"), Error::Signature(_)));
        assert!(matches!(Error::internal("test"), Error::Internal(_)));
    }

    #[test]
    fn test_error_categorization() {
        let err = Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));
        assert_eq!(err.category(), ErrorCategory::System);
        let err = Error::signature("invalid curve point");
        assert_eq!(err.category(), ErrorCategory::Security);
    }

    #[test]
    fn test_hash_mismatch_formatting() {
        let err = Error::hash_mismatch(&[0xAA; 4], &[0xBB; 4]);
        if let Error::HashMismatch { expected, actual } = err {
            assert_eq!(expected, "aaaaaaaa");
            assert_eq!(actual, "bbbbbbbb");
        } else {
            panic!("Wrong variant");
        }
    }
}
