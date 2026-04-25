// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::vdf::{self, Parameters};
use authorproof_protocol::rfc::wire_types::components::DocumentRef;
use authorproof_protocol::rfc::wire_types::hash::HashValue;
use authorproof_protocol::rfc::{self, TimeEvidence, VdfProofRfc};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use super::chain_helpers::{genesis_prev_hash, mix_physics_seed};
use super::types::*;

const MAX_CLOCK_DRIFT_SECS: i64 = 2;
const MAX_CHAIN_FILE_SIZE: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    pub document_id: String,
    pub document_path: String,
    pub created_at: DateTime<Utc>,
    pub vdf_params: Parameters,
    pub entanglement_mode: EntanglementMode,
    #[serde(default)]
    pub signature_policy: SignaturePolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Chain {
    pub metadata: ChainMetadata,
    pub checkpoints: Vec<Checkpoint>,
    #[serde(skip)]
    storage_path: Option<PathBuf>,
    /// Optional MMR coordinator for anti-deletion anchoring.
    /// When present, each commit sets `checkpoint.mmr_root` and
    /// `checkpoint.mmr_inclusion_proof` before finalizing the hash.
    #[serde(skip)]
    mmr: Option<crate::checkpoint_mmr::CheckpointMmr>,
}

fn mac_sidecar_path(chain_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.mac", chain_path.display()))
}

fn compute_chain_mac(mac_key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut h = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|_| Error::checkpoint("invalid chain MAC key length"))?;
    h.update(data);
    Ok(h.finalize().into_bytes().into())
}

impl Chain {
    pub fn new(document_path: impl AsRef<Path>, vdf_params: Parameters) -> Result<Self> {
        Self::new_with_mode(document_path, vdf_params, EntanglementMode::Legacy)
    }

    /// Attach an MMR coordinator so each commit anchors its root in the signed hash.
    pub fn with_mmr(mut self, mmr: crate::checkpoint_mmr::CheckpointMmr) -> Self {
        self.mmr = Some(mmr);
        self
    }

    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.metadata.signature_policy = policy;
        self
    }

    pub fn new_with_mode(
        document_path: impl AsRef<Path>,
        vdf_params: Parameters,
        entanglement_mode: EntanglementMode,
    ) -> Result<Self> {
        if fs::symlink_metadata(document_path.as_ref())?
            .file_type()
            .is_symlink()
        {
            return Err(Error::checkpoint(
                "Symlinks not supported for document paths",
            ));
        }

        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_str = abs_path.to_string_lossy().to_string();
        let path_hash = crate::utils::sha256_of_path(&abs_path);
        let document_id = hex::encode(&path_hash[0..8]);

        Ok(Self {
            metadata: ChainMetadata {
                document_id,
                document_path: path_str,
                created_at: Utc::now(),
                vdf_params,
                entanglement_mode,
                signature_policy: SignaturePolicy::Required,
            },
            checkpoints: Vec::with_capacity(1024),
            storage_path: None,
            mmr: None,
        })
    }

    pub fn commit(&mut self, message: Option<String>) -> Result<Checkpoint> {
        self.commit_internal(message, None)
    }

    fn commit_internal(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_internal_locked(message, vdf_duration)
    }

    fn commit_internal_locked(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;

        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint ordinal overflow"))?;
        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
                None,
            )?,
        };

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);

        {
            // Invariant: min_iterations must always be > 0 to ensure minimum cost for
            // zero-duration VDFs (genesis and clock-regressed checkpoints).
            if self.metadata.vdf_params.min_iterations == 0 {
                return Err(Error::checkpoint(
                    "VDF parameters have min_iterations=0; refusing checkpoint (cost would be zero)",
                ));
            }

            let duration = if ordinal == 0 {
                // Genesis: no elapsed time; VDF uses min_iterations to prevent forgery.
                vdf_duration.unwrap_or(Duration::from_secs(0))
            } else if let Some(explicit) = vdf_duration {
                explicit
            } else {
                let delta = checkpoint
                    .timestamp
                    .signed_duration_since(last_cp.unwrap().timestamp);
                match delta.to_std() {
                    Ok(d) => d,
                    Err(_) => {
                        // delta is negative — the system clock moved backward.
                        // Small regressions (≤ MAX_CLOCK_DRIFT_SECS) can be NTP
                        // corrections; accept them with a zero-duration VDF so
                        // min_iterations still applies.  Larger regressions are
                        // refused entirely: they allow a forger to backdate a
                        // checkpoint and produce a trivially-cheap VDF proof.
                        let regression_secs = delta.num_seconds().abs();
                        if regression_secs > MAX_CLOCK_DRIFT_SECS {
                            return Err(Error::checkpoint(format!(
                                "clock regression of {regression_secs}s detected; \
                                 refusing to create checkpoint with zero-cost VDF proof"
                            )));
                        }
                        Duration::from_secs(0)
                    }
                }
            };
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            checkpoint.vdf = Some(vdf::compute(vdf_input, duration, self.metadata.vdf_params)?);
        }

        self.commit_finish(checkpoint)
    }

    fn commit_finish(&mut self, mut checkpoint: Checkpoint) -> Result<Checkpoint> {
        checkpoint.validate_timestamp()?;
        if checkpoint.explicit_hash_version.is_none() {
            checkpoint.explicit_hash_version = Some(checkpoint.hash_domain_version());
        }
        if let Some(mmr) = &self.mmr {
            let append = mmr.finalize_checkpoint(&mut checkpoint)?;
            checkpoint.mmr_inclusion_proof =
                Some(append.proof().serialize().map_err(|e| {
                    Error::checkpoint(format!("MMR proof serialization failed: {e}"))
                })?);
        } else {
            checkpoint.hash = checkpoint.compute_hash();
        }
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.storage_path = Some(path.to_path_buf());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::checkpoint(format!("failed to marshal chain: {e}")))?;
        let rand_suffix: String = format!("{:016x}", rand::random::<u64>());
        let tmp_name = format!(
            "{}.{}.tmp",
            path.display(),
            &rand_suffix[..8.min(rand_suffix.len())]
        );
        let tmp_path = PathBuf::from(tmp_name);
        fs::write(&tmp_path, &data)?;
        fs::File::open(&tmp_path)?.sync_all()?;
        fs::rename(&tmp_path, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(Error::checkpoint("chain file must not be a symlink"));
        }
        let file_len = fs::metadata(path)?.len();
        if file_len > MAX_CHAIN_FILE_SIZE {
            return Err(Error::checkpoint("Chain file exceeds safety limit"));
        }
        let data = fs::read(path)?;
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to deserialize chain: {e}")))?;
        chain.storage_path = Some(path.to_path_buf());
        Ok(chain)
    }

    /// Save the chain and write an HMAC-SHA256 sidecar (`{path}.mac`) over the
    /// serialized bytes.  The sidecar lets `load_with_mac` detect offline edits
    /// to the chain JSON before deserializing.
    ///
    /// Both the chain file and the sidecar are written atomically via temp-file
    /// rename so a crash between the two writes cannot leave them inconsistent.
    pub fn save_with_mac(&mut self, path: impl AsRef<Path>, mac_key: &[u8]) -> Result<()> {
        let path = path.as_ref();
        self.storage_path = Some(path.to_path_buf());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Serialize once; compute MAC on the same bytes we will write.
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::checkpoint(format!("failed to marshal chain: {e}")))?;
        let mac = compute_chain_mac(mac_key, &data)?;

        let rand_suffix = format!("{:08x}", rand::random::<u32>());
        let tmp_chain = PathBuf::from(format!("{}.{}.tmp", path.display(), rand_suffix));
        let mac_path = mac_sidecar_path(path);
        let tmp_mac = PathBuf::from(format!("{}.{}.tmp", mac_path.display(), rand_suffix));

        fs::write(&tmp_chain, &data)?;
        fs::File::open(&tmp_chain)?.sync_all()?;
        fs::write(&tmp_mac, mac)?;
        fs::File::open(&tmp_mac)?.sync_all()?;

        // Commit sidecar first so load_with_mac never sees a chain without
        // a matching sidecar (the converse is acceptable: MAC but no chain).
        fs::rename(&tmp_mac, &mac_path)
            .map_err(|e| Error::checkpoint(format!("failed to commit chain MAC: {e}")))?;
        fs::rename(&tmp_chain, path)
            .map_err(|e| Error::checkpoint(format!("failed to commit chain: {e}")))?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Load the chain, verifying the HMAC sidecar when present.
    ///
    /// If no sidecar exists (chains written before this change), falls back to
    /// `load()` for backward compatibility.  If the sidecar exists but the MAC
    /// fails, returns an error immediately without deserializing.
    pub fn load_with_mac(path: impl AsRef<Path>, mac_key: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(Error::checkpoint("chain file must not be a symlink"));
        }
        let mac_path = mac_sidecar_path(path);
        // Atomically try to read the MAC file; if NotFound, fall back to legacy load.
        // If it exists but fails to read, propagate the error.
        let stored_mac: [u8; 32] = match fs::read(&mac_path) {
            Ok(data) => data.try_into().map_err(|_| {
                Error::checkpoint("chain MAC file has wrong length (expected 32 bytes)")
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self::load(path); // No MAC sidecar → legacy fallback
            }
            Err(e) => return Err(Error::checkpoint(format!("failed to read chain MAC: {e}"))),
        };
        let file_len = fs::metadata(path)?.len();
        if file_len > MAX_CHAIN_FILE_SIZE {
            return Err(Error::checkpoint("chain file exceeds safety limit"));
        }
        let data = fs::read(path)
            .map_err(|e| Error::checkpoint(format!("failed to read chain file: {e}")))?;
        let computed = compute_chain_mac(mac_key, &data)?;
        if !bool::from(computed.ct_eq(&stored_mac)) {
            return Err(Error::checkpoint(
                "chain file HMAC verification failed — file may have been tampered with",
            ));
        }
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to deserialize chain: {e}")))?;
        chain.storage_path = Some(path.to_path_buf());
        Ok(chain)
    }

    #[cfg(unix)]
    fn acquire_lock(file: &fs::File) -> Result<()> {
        // SAFETY: flock() is a POSIX syscall that takes a valid fd and constant flags.
        // as_raw_fd() returns a valid descriptor while `file` is alive.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(Error::checkpoint("Concurrent commit blocked by file lock"));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn release_lock(file: &fs::File) {
        // SAFETY: flock(LOCK_UN) releases the advisory lock on a valid fd.
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    #[cfg(not(unix))]
    fn acquire_lock(_file: &fs::File) -> Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn release_lock(_file: &fs::File) {}

    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    pub fn total_elapsed_time(&self) -> Duration {
        self.checkpoints
            .iter()
            .filter_map(|cp| cp.vdf.as_ref())
            .map(|v| v.min_elapsed_time(self.metadata.vdf_params))
            .sum()
    }

    pub fn commit_with_vdf_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        self.commit_internal(message, Some(vdf_duration))
    }

    pub fn commit_entangled(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_entangled_locked(
            message,
            jitter_hash,
            jitter_session_id,
            keystroke_count,
            vdf_duration,
            physics,
        )
    }

    fn commit_entangled_locked(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        if self.metadata.entanglement_mode != EntanglementMode::Entangled {
            return Err(Error::invalid_state(
                "commit_entangled requires EntanglementMode::Entangled",
            ));
        }
        if jitter_session_id.is_empty() {
            return Err(Error::checkpoint("empty jitter_session_id"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
                None,
            )?,
        };

        let previous_vdf_output = match last_cp {
            None => [0u8; 32], // genesis: no prior checkpoint, zeros are the defined initial input
            Some(cp) => cp.vdf.as_ref().map(|v| v.output).ok_or_else(|| {
                Error::checkpoint(
                    "commit_entangled: prior checkpoint has no VDF proof; entangled chain broken",
                )
            })?,
        };

        let physics_seed = physics
            .map(|ctx| crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx));

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.jitter_binding = Some(JitterBinding {
            jitter_hash,
            session_id: jitter_session_id,
            keystroke_count,
            physics_seed,
        });

        let base_input =
            vdf::chain_input_entangled(previous_vdf_output, jitter_hash, content_hash, ordinal);
        let vdf_input = mix_physics_seed(base_input, physics_seed);
        let proof = vdf::compute(vdf_input, vdf_duration, self.metadata.vdf_params)?;
        checkpoint.vdf = Some(proof);

        self.commit_finish(checkpoint)
    }

    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }

    pub fn find_chain(
        document_path: impl AsRef<Path>,
        writersproof_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = crate::utils::sha256_of_path(&abs_path);
        let doc_id = hex::encode(&path_hash[0..8]);
        let chain_path = writersproof_dir
            .as_ref()
            .join("chains")
            .join(format!("{doc_id}.json"));
        if !chain_path.exists() {
            return Err(Error::not_found(format!(
                "no chain found for {}",
                abs_path.to_string_lossy()
            )));
        }
        Ok(chain_path)
    }

    pub fn get_or_create_chain(
        document_path: impl AsRef<Path>,
        writersproof_dir: impl AsRef<Path>,
        vdf_params: Parameters,
    ) -> Result<Self> {
        if let Ok(path) = Self::find_chain(&document_path, &writersproof_dir) {
            return Self::load(path);
        }

        let mut chain = Self::new(&document_path, vdf_params)?;
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = crate::utils::sha256_of_path(&abs_path);
        let doc_id = hex::encode(&path_hash[0..8]);
        chain.storage_path = Some(
            writersproof_dir
                .as_ref()
                .join("chains")
                .join(format!("{doc_id}.json")),
        );
        Ok(chain)
    }

    pub fn at(&self, ordinal: u64) -> Result<&Checkpoint> {
        let index = usize::try_from(ordinal)
            .map_err(|_| Error::checkpoint("ordinal too large for this platform"))?;
        self.checkpoints
            .get(index)
            .ok_or_else(|| Error::not_found(format!("checkpoint ordinal {ordinal} out of range")))
    }

    pub fn storage_path(&self) -> Option<&Path> {
        self.storage_path.as_deref()
    }

    pub fn summary(&self) -> ChainSummary {
        let mut summary = ChainSummary {
            document_path: self.metadata.document_path.clone(),
            checkpoint_count: self.checkpoints.len(),
            first_commit: None,
            last_commit: None,
            total_elapsed_time: self.total_elapsed_time(),
            final_content_hash: None,
            chain_valid: None,
        };

        if let Some(first) = self.checkpoints.first() {
            summary.first_commit = Some(first.timestamp);
        }
        if let Some(last) = self.checkpoints.last() {
            summary.last_commit = Some(last.timestamp);
            summary.final_content_hash = Some(hex::encode(last.content_hash));
        }

        summary
    }

    pub fn commit_rfc(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        self.commit_rfc_with_nonce(
            message,
            vdf_duration,
            rfc_jitter,
            time_evidence,
            calibration,
            physics,
            None,
            None,
        )
    }

    /// Commit an RFC checkpoint with optional challenge nonce and jitter sample hashes.
    ///
    /// `challenge_nonce`: 32-byte freshness nonce from the WritersProof server.
    /// Mixed into the PoSME seed to prevent pre-computation attacks.
    ///
    /// `jitter_sample_hashes`: per-sample BLAKE3 hashes for PoSME jitter entanglement.
    /// When present, the PoSME proof commits to these specific behavioral samples,
    /// making the proof inseparable from the keystroke timing evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_rfc_with_nonce(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
        challenge_nonce: Option<[u8; 32]>,
        jitter_sample_hashes: Option<&[[u8; 32]]>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_rfc_locked(
            message,
            vdf_duration,
            rfc_jitter,
            time_evidence,
            calibration,
            physics,
            challenge_nonce,
            jitter_sample_hashes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_rfc_locked(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
        challenge_nonce: Option<[u8; 32]>,
        jitter_sample_hashes: Option<&[[u8; 32]]>,
    ) -> Result<Checkpoint> {
        if matches!(self.metadata.entanglement_mode, EntanglementMode::Entangled)
            && rfc_jitter.is_none()
        {
            return Err(Error::checkpoint("entangled mode requires jitter data"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
                None,
            )?,
        };

        let physics_seed = if self.metadata.entanglement_mode == EntanglementMode::Entangled {
            physics.map(|ctx| {
                crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx)
            })
        } else {
            None
        };

        let vdf_input = match self.metadata.entanglement_mode {
            EntanglementMode::Legacy => vdf::chain_input(content_hash, previous_hash, ordinal),
            EntanglementMode::Entangled => {
                let previous_vdf_output = last_cp
                    .and_then(|cp| cp.vdf.as_ref())
                    .map(|v| v.output)
                    .unwrap_or([0u8; 32]);
                let jitter_hash = rfc_jitter
                    .as_ref()
                    .map(|j| j.entropy_commitment.hash)
                    .unwrap_or([0u8; 32]);
                let base_input = vdf::chain_input_entangled(
                    previous_vdf_output,
                    jitter_hash,
                    content_hash,
                    ordinal,
                );
                mix_physics_seed(base_input, physics_seed)
            }
        };

        let vdf_proof =
            if ordinal > 0 || self.metadata.entanglement_mode == EntanglementMode::Entangled {
                Some(vdf::compute(
                    vdf_input,
                    vdf_duration,
                    self.metadata.vdf_params,
                )?)
            } else {
                None
            };

        let rfc_vdf = vdf_proof.as_ref().map(|vdf| {
            use super::types::{
                VDF_RFC_FIELD_SIZE, VDF_RFC_INPUT_END, VDF_RFC_INPUT_OFFSET, VDF_RFC_OUTPUT_END,
                VDF_RFC_OUTPUT_OFFSET,
            };
            let mut output = [0u8; VDF_RFC_FIELD_SIZE];
            output[VDF_RFC_OUTPUT_OFFSET..VDF_RFC_OUTPUT_END].copy_from_slice(&vdf.output);
            output[VDF_RFC_INPUT_OFFSET..VDF_RFC_INPUT_END].copy_from_slice(&vdf.input);

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                crate::utils::duration_to_ms(vdf.duration),
                calibration.clone(),
            )
        });

        let jitter_binding = rfc_jitter.as_ref().map(|rj| JitterBinding {
            jitter_hash: rj.entropy_commitment.hash,
            session_id: format!("rfc-{}", ordinal),
            keystroke_count: rj.summary.sample_count,
            physics_seed,
        });

        // SWF seed derivation: shared between Argon2 and PoSME paths.
        // The doc_ref CBOR is needed for genesis seed in both cases.
        let doc_cbor_for_genesis = if ordinal == 0 {
            let doc_ref = DocumentRef {
                content_hash: HashValue::try_sha256(content_hash.to_vec())
                    .map_err(Error::crypto)?,
                filename: std::path::Path::new(&self.metadata.document_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string()),
                byte_length: content_size,
                char_count: content_size,
                salt_mode: None,
                salt_commitment: None,
            };
            Some(
                authorproof_protocol::codec::cbor::encode(&doc_ref)
                    .map_err(|e| Error::checkpoint(format!("genesis doc-ref CBOR: {e}")))?,
            )
        } else {
            None
        };

        let jitter_or_nonce = rfc_jitter
            .as_ref()
            .map(|j| j.entropy_commitment.hash)
            .unwrap_or(content_hash);

        let intervals_cbor = rfc_jitter
            .as_ref()
            .map(|jb| authorproof_protocol::codec::cbor::encode(&jb.summary.sample_count))
            .transpose()
            .map_err(|e| Error::checkpoint(format!("SWF intervals CBOR: {e}")))?;

        #[cfg(feature = "posme")]
        let (argon2_swf, posme_swf) = {
            let cn = challenge_nonce.as_ref();
            let vdf_output_bytes = vdf_proof.as_ref().map(|v| v.output).unwrap_or([0u8; 32]);
            let posme_seed = if ordinal == 0 {
                vdf::posme_seed_genesis(
                    doc_cbor_for_genesis.as_deref().unwrap_or(&[]),
                    &jitter_or_nonce,
                    &vdf_output_bytes,
                    cn,
                )
            } else if intervals_cbor.is_some() {
                let phys_cbor = match physics {
                    Some(p) => authorproof_protocol::codec::cbor::encode(&p.combined_hash.to_vec())
                        .map_err(|e| Error::checkpoint(format!("SWF physics CBOR: {e}")))?,
                    None => vec![],
                };
                vdf::posme_seed_enhanced(
                    &previous_hash,
                    intervals_cbor.as_deref().unwrap_or(&[]),
                    &phys_cbor,
                    &vdf_output_bytes,
                    cn,
                )
            } else {
                vdf::posme_seed_core(&previous_hash, &content_hash, &vdf_output_bytes, cn)
            };

            // Tier selection: jitter available → STANDARD (2), else CORE (1).
            // Higher tiers (3=ENHANCED, 4=MAXIMUM) are selected via config.
            // Physics context presence does not increase tier (it's mixed into
            // the seed regardless) but it does strengthen the proof.
            let tier = if rfc_jitter.is_some() { 2u8 } else { 1u8 };

            let proof_bytes = match jitter_sample_hashes {
                Some(hashes) if !hashes.is_empty() => {
                    vdf::swf_posme::compute_entangled(posme_seed, tier, hashes)
                        .map_err(|e| Error::checkpoint(format!("PoSME entangled: {e}")))?
                }
                _ => vdf::swf_posme::compute(posme_seed, tier)
                    .map_err(|e| Error::checkpoint(format!("PoSME: {e}")))?,
            };
            (None, Some(proof_bytes))
        };

        #[cfg(not(feature = "posme"))]
        let (argon2_swf, posme_swf) = {
            let _ = jitter_sample_hashes; // only used by posme feature
            let swf_seed = if ordinal == 0 {
                vdf::swf_seed_genesis(
                    doc_cbor_for_genesis.as_deref().unwrap_or(&[]),
                    &jitter_or_nonce,
                )
            } else if intervals_cbor.is_some() {
                let phys_cbor = match physics {
                    Some(p) => authorproof_protocol::codec::cbor::encode(&p.combined_hash.to_vec())
                        .map_err(|e| Error::checkpoint(format!("SWF physics CBOR: {e}")))?,
                    None => vec![],
                };
                vdf::swf_seed_enhanced(
                    &previous_hash,
                    intervals_cbor.as_deref().unwrap_or(&[]),
                    &phys_cbor,
                )
            } else {
                vdf::swf_seed_core(&previous_hash, &content_hash)
            };
            let swf_params = vdf::swf_argon2::Argon2SwfParams {
                iterations: self.metadata.vdf_params.min_iterations.max(3),
                ..vdf::swf_argon2::Argon2SwfParams::default()
            };
            let proof = vdf::swf_argon2::compute(swf_seed, swf_params)
                .map_err(|e| Error::checkpoint(format!("Argon2id SWF: {e}")))?;
            (Some(proof), None::<Vec<u8>>)
        };

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.vdf = vdf_proof;
        checkpoint.jitter_binding = jitter_binding;
        checkpoint.rfc_vdf = rfc_vdf;
        checkpoint.rfc_jitter = rfc_jitter;
        checkpoint.time_evidence = time_evidence;
        checkpoint.argon2_swf = argon2_swf;
        checkpoint.posme_swf = posme_swf;
        if challenge_nonce.is_some() {
            checkpoint.challenge_nonce = challenge_nonce.map(hex::encode);
        }

        self.commit_finish(checkpoint)
    }
}
