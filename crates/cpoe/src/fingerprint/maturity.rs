// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Lifecycle stage of the behavioral fingerprint for a given profile.
///
/// Anomaly detection enforcement increases as the model accumulates sessions:
///
/// | Stage       | Session range   | IDENTITY_ANOMALY effect                       |
/// |-------------|-----------------|-----------------------------------------------|
/// | Bootstrap   | 1 .. N          | Suppressed entirely; no anomaly flags emitted |
/// | Advisory    | N+1 .. 2N       | Anomaly detected and recorded; non-blocking   |
/// | Enforced    | > 2N            | Full enforcement; anomaly blocks export       |
///
/// N is `FingerprintConfig::bootstrap_sessions` (default 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FingerprintMaturity {
    /// Fewer than `bootstrap_sessions` completed. Anomaly detection is off.
    Bootstrap,
    /// Between `bootstrap_sessions` and `advisory_sessions`. Anomalies are
    /// advisory (recorded in evidence but do not prevent export).
    Advisory,
    /// More than `advisory_sessions` completed. Full enforcement is active.
    Enforced,
}

impl FingerprintMaturity {
    /// Derive maturity from a session count and the configured thresholds.
    pub fn from_session_count(count: u32, bootstrap_n: u32, advisory_n: u32) -> Self {
        log::debug!(
            "FingerprintMaturity::from_session_count: count={}, bootstrap_n={}, advisory_n={}",
            count,
            bootstrap_n,
            advisory_n
        );
        // Clamp advisory_n so it is always > bootstrap_n; if misconfigured, treat
        // both thresholds as bootstrap_n to avoid silent enforcement before readiness.
        let advisory_n = advisory_n.max(bootstrap_n + 1);
        if count <= bootstrap_n {
            FingerprintMaturity::Bootstrap
        } else if count <= advisory_n {
            FingerprintMaturity::Advisory
        } else {
            FingerprintMaturity::Enforced
        }
    }

    /// Returns `true` when IDENTITY_ANOMALY signals should be suppressed.
    pub fn suppress_anomaly(self) -> bool {
        self == FingerprintMaturity::Bootstrap
    }

    /// Returns `true` when anomaly signals are advisory-only (non-blocking).
    pub fn advisory_only(self) -> bool {
        self == FingerprintMaturity::Advisory
    }
}

impl std::fmt::Display for FingerprintMaturity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FingerprintMaturity::Bootstrap => f.write_str("BOOTSTRAP"),
            FingerprintMaturity::Advisory => f.write_str("ADVISORY"),
            FingerprintMaturity::Enforced => f.write_str("ENFORCED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_boundary() {
        assert_eq!(
            FingerprintMaturity::from_session_count(0, 5, 10),
            FingerprintMaturity::Bootstrap
        );
        assert_eq!(
            FingerprintMaturity::from_session_count(5, 5, 10),
            FingerprintMaturity::Bootstrap
        );
        assert_eq!(
            FingerprintMaturity::from_session_count(6, 5, 10),
            FingerprintMaturity::Advisory
        );
    }

    #[test]
    fn test_advisory_boundary() {
        assert_eq!(
            FingerprintMaturity::from_session_count(10, 5, 10),
            FingerprintMaturity::Advisory
        );
        assert_eq!(
            FingerprintMaturity::from_session_count(11, 5, 10),
            FingerprintMaturity::Enforced
        );
    }

    #[test]
    fn test_enforced() {
        assert_eq!(
            FingerprintMaturity::from_session_count(100, 5, 10),
            FingerprintMaturity::Enforced
        );
    }

    #[test]
    fn test_suppress_anomaly() {
        assert!(FingerprintMaturity::Bootstrap.suppress_anomaly());
        assert!(!FingerprintMaturity::Advisory.suppress_anomaly());
        assert!(!FingerprintMaturity::Enforced.suppress_anomaly());
    }

    #[test]
    fn test_advisory_only() {
        assert!(!FingerprintMaturity::Bootstrap.advisory_only());
        assert!(FingerprintMaturity::Advisory.advisory_only());
        assert!(!FingerprintMaturity::Enforced.advisory_only());
    }

    #[test]
    fn test_misconfigured_thresholds_clamp() {
        // advisory_n < bootstrap_n: clamp to bootstrap_n + 1
        // count=5 <= bootstrap_n=5 → Bootstrap
        assert_eq!(
            FingerprintMaturity::from_session_count(5, 5, 3),
            FingerprintMaturity::Bootstrap
        );
        // count=6 > bootstrap_n=5, <= clamped advisory_n=6 → Advisory
        assert_eq!(
            FingerprintMaturity::from_session_count(6, 5, 3),
            FingerprintMaturity::Advisory
        );
        // count=7 > clamped advisory_n=6 → Enforced
        assert_eq!(
            FingerprintMaturity::from_session_count(7, 5, 3),
            FingerprintMaturity::Enforced
        );
    }
}
