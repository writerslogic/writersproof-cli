// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod http;
mod notary;
mod ots;
mod rfc3161;
mod types;
mod verification;

#[cfg(test)]
mod tests;

pub use types::*;
pub use verification::verify_proof_format;

use async_trait::async_trait;
use std::sync::Arc;

/// Backend that can anchor content hashes to an external trust root.
#[async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Return the provider type identifier.
    fn provider_type(&self) -> ProviderType;
    /// Return a human-readable provider name.
    fn name(&self) -> &str;
    /// Check whether the provider backend is reachable.
    async fn is_available(&self) -> bool;
    /// Submit a content hash for anchoring.
    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError>;
    /// Poll for updated proof status (e.g., pending to confirmed).
    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError>;
    /// Verify a proof against the anchor backend.
    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError>;
    /// Attempt to upgrade a pending proof (e.g., OTS calendar to confirmed).
    async fn upgrade(&self, _proof: &Proof) -> Result<Option<Proof>, AnchorError> {
        Ok(None)
    }
}

/// Type-erased handle to an anchor provider.
pub type ProviderHandle = Arc<dyn AnchorProvider>;

/// Verify that two independent external timestamps agree within `tolerance_secs`.
///
/// Call this after fetching both an RFC 3161 TSA response and a Roughtime response
/// for the same checkpoint. If the two timestamps disagree by more than `tolerance_secs`,
/// one anchor may be compromised or the system clock was manipulated.
///
/// Returns `Ok(())` when both timestamps are within tolerance.
/// Returns `Err(AnchorError::Verification)` when the difference exceeds the tolerance
/// or when either timestamp is zero (missing / uninitialized).
pub fn verify_dual_anchor(
    rfc3161_unix_secs: i64,
    roughtime_unix_secs: i64,
    tolerance_secs: u64,
) -> Result<(), AnchorError> {
    if rfc3161_unix_secs == 0 || roughtime_unix_secs == 0 {
        return Err(AnchorError::Verification(
            "dual-anchor: one or both timestamps are zero (missing)".into(),
        ));
    }
    let diff = (rfc3161_unix_secs - roughtime_unix_secs).unsigned_abs();
    if diff > tolerance_secs {
        return Err(AnchorError::Verification(format!(
            "dual-anchor: RFC 3161 and Roughtime disagree by {diff}s (tolerance: {tolerance_secs}s)"
        )));
    }
    Ok(())
}

/// Coordinates multi-provider anchor submission, polling, and verification.
pub struct AnchorManager {
    providers: Vec<ProviderHandle>,
    config: AnchorManagerConfig,
}

impl std::fmt::Debug for AnchorManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorManager")
            .field("providers_count", &self.providers.len())
            .field("config", &self.config)
            .finish()
    }
}

/// Configuration for anchor manager behavior.
#[derive(Debug, Clone)]
pub struct AnchorManagerConfig {
    /// Submit to all available providers (true) or stop after first success (false).
    pub multi_anchor: bool,
    /// Per-provider request timeout.
    pub timeout: std::time::Duration,
    /// Number of submission retries on transient failure.
    pub retry_count: u32,
}

impl Default for AnchorManagerConfig {
    fn default() -> Self {
        Self {
            multi_anchor: true,
            timeout: std::time::Duration::from_secs(30),
            retry_count: 3,
        }
    }
}

impl AnchorManager {
    /// Create a manager with no providers and the given config.
    pub fn new(config: AnchorManagerConfig) -> Self {
        Self {
            providers: Vec::new(),
            config,
        }
    }

    /// Register an anchor provider.
    pub fn add_provider(&mut self, provider: ProviderHandle) {
        self.providers.push(provider);
    }

    /// Find a provider by its type using fast match-based lookup (max 3 providers).
    fn get_provider_by_type(&self, provider_type: ProviderType) -> Option<ProviderHandle> {
        self.providers
            .iter()
            .find(|p| p.provider_type() == provider_type)
            .cloned()
    }

    /// Create a manager pre-loaded with all providers available from environment.
    pub fn with_default_providers() -> Self {
        let mut manager = Self::new(AnchorManagerConfig::default());
        if let Ok(ots) = ots::OpenTimestampsProvider::new() {
            manager.add_provider(Arc::new(ots));
        }
        if let Ok(provider) = rfc3161::Rfc3161Provider::with_defaults() {
            manager.add_provider(Arc::new(provider));
        }
        if let Ok(notary) = notary::NotaryProvider::from_env() {
            manager.add_provider(Arc::new(notary));
        }
        manager
    }

    /// Submit a content hash to all available providers and return the anchor.
    pub async fn anchor(&self, hash: &[u8; 32]) -> Result<Anchor, AnchorError> {
        let mut anchor = Anchor::new(*hash);
        let mut last_error = None;

        for provider in &self.providers {
            if !provider.is_available().await {
                continue;
            }

            match provider.submit(hash).await {
                Ok(proof) => {
                    anchor.add_proof(proof);
                    if !self.config.multi_anchor {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("Provider {} failed: {e}", provider.name());
                    last_error = Some(e);
                }
            }
        }

        if anchor.proofs.is_empty() {
            return Err(
                last_error.unwrap_or(AnchorError::Unavailable("No providers available".into()))
            );
        }

        Ok(anchor)
    }

    /// Poll pending proofs for status updates and attempt upgrades.
    pub async fn refresh(&self, anchor: &mut Anchor) -> Result<(), AnchorError> {
        for proof in &mut anchor.proofs {
            if proof.status != ProofStatus::Pending {
                continue;
            }

            if let Some(provider) = self.get_provider_by_type(proof.provider) {
                match provider.check_status(proof).await {
                    Ok(updated) => *proof = updated,
                    Err(e) => log::warn!("Status check failed: {e}"),
                }

                if let Ok(Some(upgraded)) = provider.upgrade(proof).await {
                    *proof = upgraded;
                }
            }
        }

        if anchor
            .proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
        {
            anchor.status = ProofStatus::Confirmed;
        }

        Ok(())
    }

    /// Verify at least one confirmed proof against its provider backend.
    pub async fn verify_anchor(&self, anchor: &Anchor) -> Result<bool, AnchorError> {
        for proof in &anchor.proofs {
            if proof.status != ProofStatus::Confirmed {
                continue;
            }
            if proof.anchored_hash != anchor.hash {
                return Err(AnchorError::HashMismatch);
            }
            if let Some(provider) = self.get_provider_by_type(proof.provider) {
                if provider.verify(proof).await? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
