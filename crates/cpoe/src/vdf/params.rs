// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::vdf::VdfProof;
use crate::MutexRecover;

/// Minimum plausible SHA-256 iterations/sec from calibration.
/// Anything below this indicates broken hardware or a failed benchmark.
pub const CALIBRATION_MIN_ITERS_PER_SEC: u64 = 1_000;

/// Maximum plausible SHA-256 iterations/sec from calibration.
/// No current hardware exceeds ~100M SHA-256/s single-threaded; 10^9 is a
/// generous upper bound that catches overflow bugs and emulator artifacts.
pub const CALIBRATION_MAX_ITERS_PER_SEC: u64 = 1_000_000_000;

/// VDF/SWF computation parameters: iteration rate and bounds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Parameters {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

/// Return default VDF parameters (1M iter/s, 100K min, 3.6B max).
pub fn default_parameters() -> Parameters {
    Parameters {
        iterations_per_second: 1_000_000,
        min_iterations: 100_000,
        max_iterations: 3_600_000_000,
    }
}

/// Benchmark SHA-256 hash rate for the given duration, returning calibrated parameters.
///
/// Returns `Err` if the duration is too short or the measured rate falls outside
/// `[CALIBRATION_MIN_ITERS_PER_SEC, CALIBRATION_MAX_ITERS_PER_SEC]`.
pub fn calibrate(duration: Duration) -> Result<Parameters, String> {
    if duration < Duration::from_millis(100) {
        return Err("calibration duration too short".to_string());
    }

    let mut hash: [u8; 32] = Sha256::digest(b"cpoe-calibration-input-v1").into();

    let mut iterations = 0u64;
    let start = Instant::now();
    let deadline = start + duration;

    while Instant::now() < deadline {
        for _ in 0..1000 {
            hash = Sha256::digest(hash).into();
            iterations += 1;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 {
        iterations as f64 / elapsed
    } else {
        0.0
    };
    let iterations_per_second = if rate.is_finite() {
        rate.round() as u64
    } else {
        0
    };

    if iterations_per_second < CALIBRATION_MIN_ITERS_PER_SEC {
        return Err(format!(
            "calibration result too low ({} iter/s < {} minimum): hardware too slow or benchmark failed",
            iterations_per_second, CALIBRATION_MIN_ITERS_PER_SEC
        ));
    }
    if iterations_per_second > CALIBRATION_MAX_ITERS_PER_SEC {
        return Err(format!(
            "calibration result too high ({} iter/s > {} maximum): likely a measurement bug",
            iterations_per_second, CALIBRATION_MAX_ITERS_PER_SEC
        ));
    }

    Ok(Parameters {
        iterations_per_second,
        min_iterations: iterations_per_second / 10, // ~0.1 seconds of work
        max_iterations: iterations_per_second * 3600, // ~1 hour maximum
    })
}

/// Compute a VDF proof targeting the given wall-clock duration.
pub fn compute(
    input: [u8; 32],
    duration: Duration,
    params: Parameters,
) -> Result<VdfProof, String> {
    VdfProof::compute(input, duration, params)
}

/// Compute a VDF proof asynchronously, offloading CPU work to a blocking thread.
pub async fn compute_async(
    input: [u8; 32],
    duration: Duration,
    params: Parameters,
) -> Result<VdfProof, String> {
    VdfProof::compute_async(input, duration, params).await
}

/// Compute a VDF proof with an exact iteration count.
pub fn compute_iterations(input: [u8; 32], iterations: u64) -> VdfProof {
    VdfProof::compute_iterations(input, iterations)
}

/// Verify a VDF proof by recomputing the hash chain.
pub fn verify(proof: &VdfProof) -> bool {
    proof.verify()
}

/// Verify a VDF proof, reporting progress via callback.
pub fn verify_with_progress<F>(proof: &VdfProof, progress: Option<F>) -> bool
where
    F: FnMut(f64),
{
    proof.verify_with_progress(progress)
}

/// Derive VDF input from content hash, previous hash, and ordinal.
pub fn chain_input(content_hash: [u8; 32], previous_hash: [u8; 32], ordinal: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-vdf-v1");
    hasher.update(content_hash);
    hasher.update(previous_hash);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

/// Compute VDF input with full entanglement for WAR/1.1 chained evidence.
///
/// The entangled input combines:
/// - Previous checkpoint's VDF output (temporal chain)
/// - Current jitter evidence hash (behavioral entropy)
/// - Current document state hash (content binding)
/// - Ordinal (sequence position)
///
/// This creates a cryptographic entanglement where each checkpoint's VDF
/// depends on the previous checkpoint's computed output, making the chain
/// impossible to precompute and requiring genuine sequential authorship.
pub fn chain_input_entangled(
    previous_vdf_output: [u8; 32],
    jitter_hash: [u8; 32],
    content_hash: [u8; 32],
    ordinal: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-vdf-entangled-v1");
    hasher.update(previous_vdf_output);
    hasher.update(jitter_hash);
    hasher.update(content_hash);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

// --- Spec-conformant SWF seed derivation (draft-condrey-rats-pop) ---

/// Domain separation tag for SWF seed derivation per spec.
const SWF_SEED_DST: &[u8] = b"PoP-SWF-Seed-v1";

/// Genesis (first-checkpoint) SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || CBOR-encode(document-ref) || initial-jitter-sample)`.
///
/// When no jitter sample is available (CORE tier), `jitter_sample` should be
/// a 32-byte local nonce.
pub fn swf_seed_genesis(doc_ref_cbor: &[u8], jitter_or_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(doc_ref_cbor);
    hasher.update(jitter_or_nonce);
    hasher.finalize().into()
}

/// ENHANCED+ SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || prev-hash || CBOR-encode(jitter-binding.intervals) || CBOR-encode(physical-state))`.
///
/// `physical_state_cbor` may be empty if no physical state is available.
pub fn swf_seed_enhanced(
    prev_hash: &[u8; 32],
    jitter_intervals_cbor: &[u8],
    physical_state_cbor: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(jitter_intervals_cbor);
    hasher.update(physical_state_cbor);
    hasher.finalize().into()
}

/// CORE fallback SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || prev-hash || local-nonce)`.
pub fn swf_seed_core(prev_hash: &[u8; 32], local_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(local_nonce);
    hasher.finalize().into()
}

// PoSME seed derivation (draft-condrey-cfrg-posme)
#[cfg(feature = "posme")]
const POSME_SEED_DST: &[u8] = b"PoP-PoSME-Seed-v1";

/// Genesis PoSME seed: `H(DST || doc_ref_cbor || jitter_or_nonce || vdf_output [|| challenge])`.
///
/// `vdf_output` binds the PoSME proof to the VDF time anchor, forcing sequential
/// execution: VDF must complete first, then its output seeds the PoSME computation.
/// When a WritersProof server challenge nonce is present, it is mixed into the
/// seed to prevent pre-computation attacks.
#[cfg(feature = "posme")]
pub fn posme_seed_genesis(
    doc_ref_cbor: &[u8],
    jitter_or_nonce: &[u8; 32],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(doc_ref_cbor);
    hasher.update(jitter_or_nonce);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}

/// ENHANCED+ PoSME seed: `H(DST || prev_hash || jitter_cbor || phys_cbor || vdf_output [|| challenge])`.
#[cfg(feature = "posme")]
pub fn posme_seed_enhanced(
    prev_hash: &[u8; 32],
    jitter_intervals_cbor: &[u8],
    physical_state_cbor: &[u8],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(jitter_intervals_cbor);
    hasher.update(physical_state_cbor);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}

/// CORE fallback PoSME seed: `H(DST || prev_hash || local_nonce || vdf_output [|| challenge])`.
#[cfg(feature = "posme")]
pub fn posme_seed_core(
    prev_hash: &[u8; 32],
    local_nonce: &[u8; 32],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(local_nonce);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}

/// Maximum number of threads the batch verifier will spawn, regardless of
/// available parallelism, to prevent resource exhaustion on large proof sets.
const MAX_BATCH_THREADS: usize = 16;

#[derive(Debug)]
/// Parallel VDF proof verifier using a bounded worker thread pool.
pub struct BatchVerifier {
    workers: usize,
}

impl BatchVerifier {
    /// Create a verifier with the given worker count (0 = auto-detect).
    ///
    /// The effective worker count is capped at [`MAX_BATCH_THREADS`] (16).
    pub fn new(workers: usize) -> Self {
        let workers = if workers == 0 {
            std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(1)
        } else {
            workers
        };
        Self {
            workers: workers.min(MAX_BATCH_THREADS),
        }
    }

    /// Verify all proofs in parallel, returning per-index results.
    ///
    /// At most `self.workers` OS threads run concurrently; excess proofs
    /// wait on a semaphore rather than spawning unbounded threads.
    pub fn verify_all(&self, proofs: &[Option<VdfProof>]) -> Vec<VerifyResult> {
        let results = Arc::new(Mutex::new(vec![
            VerifyResult {
                index: 0,
                valid: false,
                error: None,
            };
            proofs.len()
        ]));

        let semaphore = Arc::new((Mutex::new(self.workers), Condvar::new()));
        let mut handles = Vec::new();

        // Cap spawned threads: we never need more threads than proofs,
        // and the semaphore ensures at most `self.workers` run at once.
        let max_threads = proofs.len().min(self.workers);

        // Partition work into chunks so each thread processes multiple proofs
        // instead of spawning one thread per proof.
        // Use saturating arithmetic to avoid underflow when proofs is empty.
        let chunk_size = proofs
            .len()
            .saturating_add(max_threads.saturating_sub(1))
            .checked_div(max_threads.max(1))
            .unwrap_or(1)
            .max(1);
        for chunk_start in (0..proofs.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(proofs.len());
            let chunk: Vec<(usize, Option<VdfProof>)> = proofs[chunk_start..chunk_end]
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, p)| (chunk_start + i, p))
                .collect();

            let results = Arc::clone(&results);
            let semaphore = Arc::clone(&semaphore);

            let handle = thread::spawn(move || {
                {
                    let (lock, cvar) = &*semaphore;
                    let mut count = cvar
                        .wait_while(lock.lock_recover(), |c| *c == 0)
                        .unwrap_or_else(|p| p.into_inner());
                    *count -= 1;
                }

                for (index, proof) in chunk {
                    let outcome = if let Some(p) = proof {
                        VerifyResult {
                            index,
                            valid: p.verify(),
                            error: None,
                        }
                    } else {
                        VerifyResult {
                            index,
                            valid: false,
                            error: Some("nil proof".to_string()),
                        }
                    };

                    let mut res = results.lock_recover();
                    res[index] = outcome;
                }

                let (lock, cvar) = &*semaphore;
                let mut count = lock.lock_recover();
                *count += 1;
                cvar.notify_one();
            });

            handles.push(handle);
        }

        for handle in handles {
            if handle.join().is_err() {
                // Worker thread panicked; mark all unprocessed results as errored
                let mut res = results.lock_recover();
                for r in res.iter_mut() {
                    if r.error.is_none() && !r.valid {
                        r.error = Some("worker thread panic".to_string());
                    }
                }
            }
        }

        match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|p| p.into_inner()),
            Err(arc) => arc.lock_recover().clone(),
        }
    }
}

/// Result of a single VDF proof verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub index: usize,
    pub valid: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_input_deterministic() {
        let input1 = chain_input([1u8; 32], [2u8; 32], 7);
        let input2 = chain_input([1u8; 32], [2u8; 32], 7);
        assert_eq!(input1, input2);
    }

    #[test]
    fn test_compute_verify_iterations() {
        let params = default_parameters();
        let input = [9u8; 32];
        let proof = compute(input, Duration::from_millis(5), params).expect("compute");
        assert!(verify(&proof));
    }

    #[test]
    fn test_chain_input_entangled_deterministic() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        assert_eq!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_differs_from_legacy() {
        let legacy = chain_input([1u8; 32], [2u8; 32], 7);
        let entangled = chain_input_entangled([2u8; 32], [3u8; 32], [1u8; 32], 7);
        assert_ne!(legacy, entangled);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_vdf_output() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([4u8; 32], [2u8; 32], [3u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_jitter() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [5u8; 32], [3u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_content() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [6u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_ordinal() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 8);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_swf_seed_genesis_deterministic() {
        let doc_cbor = b"fake-cbor-doc-ref";
        let nonce = [0xAA; 32];
        let s1 = swf_seed_genesis(doc_cbor, &nonce);
        let s2 = swf_seed_genesis(doc_cbor, &nonce);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_swf_seed_genesis_sensitive_to_nonce() {
        let doc_cbor = b"fake-cbor";
        let s1 = swf_seed_genesis(doc_cbor, &[1u8; 32]);
        let s2 = swf_seed_genesis(doc_cbor, &[2u8; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_swf_seed_enhanced_includes_all_fields() {
        let prev = [1u8; 32];
        let intervals = b"intervals-cbor";
        let phys = b"phys-cbor";
        let s1 = swf_seed_enhanced(&prev, intervals, phys);
        let s2 = swf_seed_enhanced(&prev, intervals, b"different-phys");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_swf_seed_core_deterministic() {
        let prev = [3u8; 32];
        let nonce = [4u8; 32];
        let s1 = swf_seed_core(&prev, &nonce);
        let s2 = swf_seed_core(&prev, &nonce);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_swf_seed_genesis_differs_from_core_with_different_structure() {
        // Genesis uses variable-length doc_cbor; core uses fixed 32-byte prev_hash.
        // With structurally different inputs they must diverge.
        let nonce = [5u8; 32];
        let genesis = swf_seed_genesis(b"short-cbor", &nonce);
        let core = swf_seed_core(&nonce, &nonce);
        assert_ne!(genesis, core);
    }

    #[test]
    fn test_calibrate_duration_too_short() {
        let err = calibrate(Duration::from_millis(50)).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn test_calibrate_succeeds_within_bounds() {
        // Real calibration on any modern machine should land well within bounds.
        let params = calibrate(Duration::from_millis(200)).expect("calibration should succeed");
        assert!(params.iterations_per_second >= CALIBRATION_MIN_ITERS_PER_SEC);
        assert!(params.iterations_per_second <= CALIBRATION_MAX_ITERS_PER_SEC);
    }

    #[test]
    fn test_calibration_bounds_constants_sane() {
        // Use const assertions to validate compile-time invariants.
        const _: () = assert!(CALIBRATION_MIN_ITERS_PER_SEC < CALIBRATION_MAX_ITERS_PER_SEC);
        const _: () = assert!(CALIBRATION_MIN_ITERS_PER_SEC >= 1_000);
        const _: () = assert!(CALIBRATION_MAX_ITERS_PER_SEC <= 1_000_000_000);
    }
}
