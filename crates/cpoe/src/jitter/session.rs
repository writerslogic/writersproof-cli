// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Jitter chain (Layer 4a) - Go parity.
//!
//! Contains the core jitter session types: `Parameters`, `Sample`, `Session`,
//! `Evidence`, `Statistics`, and `SessionData`, plus the seeded
//! `compute_jitter_value()` HMAC function.

use crate::error::Error;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::timestamp_nanos_u64;

pub(crate) const MIN_JITTER: u32 = cpoe_jitter::DEFAULT_JITTER_MIN_US;
#[allow(dead_code)] // used in tests only (via #[cfg(test)] re-export)
pub(crate) const MAX_JITTER: u32 = cpoe_jitter::DEFAULT_JITTER_MAX_US;
pub(crate) const JITTER_RANGE: u32 = cpoe_jitter::DEFAULT_JITTER_RANGE_US;
pub(crate) const INTERVAL_BUCKET_SIZE_MS: i64 = 50;
pub(crate) const NUM_INTERVAL_BUCKETS: i64 = 10;

/// Configuration for jitter chain sampling behavior.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Parameters {
    /// Minimum jitter delay in microseconds.
    pub min_jitter_micros: u32,
    /// Maximum jitter delay in microseconds.
    pub max_jitter_micros: u32,
    /// Record a sample every N keystrokes.
    pub sample_interval: u64,
    /// Whether to inject jitter delays into keystroke processing.
    pub inject_enabled: bool,
}

/// Return default jitter parameters (500-3000us range, 10-keystroke interval).
pub fn default_parameters() -> Parameters {
    Parameters {
        min_jitter_micros: 500,
        max_jitter_micros: 3000,
        sample_interval: 10,
        inject_enabled: true,
    }
}

/// Seeded jitter chain sample linking keystroke count, document state, and timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Wall-clock time when this sample was recorded.
    pub timestamp: DateTime<Utc>,
    /// Cumulative keystroke count at sample time.
    pub keystroke_count: u64,
    /// SHA-256 hash of the document at sample time.
    pub document_hash: [u8; 32],
    /// HMAC-derived jitter delay in microseconds.
    pub jitter_micros: u32,
    /// SHA-256 hash binding all sample fields.
    pub hash: [u8; 32],
    /// Hash of the preceding sample (zeros for the first sample).
    pub previous_hash: [u8; 32],
}

impl Sample {
    pub(super) fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-jitter-sample-v1");
        hasher.update(timestamp_nanos_u64(self.timestamp).to_be_bytes());
        hasher.update(self.keystroke_count.to_be_bytes());
        hasher.update(self.document_hash);
        hasher.update(self.jitter_micros.to_be_bytes());
        hasher.update(self.previous_hash);
        hasher.finalize().into()
    }
}

/// Active jitter chain recording session bound to a single document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique hex-encoded session identifier.
    pub id: String,
    /// When this session began.
    pub started_at: DateTime<Utc>,
    /// When this session was finalized, if at all.
    pub ended_at: Option<DateTime<Utc>>,
    /// Canonical path of the monitored document.
    pub document_path: String,
    #[serde(skip)]
    pub(crate) seed: [u8; 32],
    pub params: Parameters,
    pub samples: Vec<Sample>,
    keystroke_count: u64,
    last_jitter: u32,
    #[serde(skip)]
    last_mtime: Option<SystemTime>,
    #[serde(skip)]
    last_size: Option<u64>,
    #[serde(skip)]
    last_doc_hash: Option<[u8; 32]>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Session {
    /// Start a new jitter session for the given document path.
    pub fn new(document_path: impl AsRef<Path>, params: Parameters) -> crate::error::Result<Self> {
        if params.sample_interval == 0 {
            return Err(Error::validation("sample_interval must be > 0"));
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| Error::validation(format!("invalid document path: {e}")))?;

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        Ok(Self {
            id: hex::encode(rand::random::<[u8; 8]>()),
            started_at: Utc::now(),
            ended_at: None,
            document_path: abs_path.to_string_lossy().to_string(),
            seed,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        })
    }

    /// Start a new jitter session with a caller-specified session ID.
    pub fn new_with_id(
        document_path: impl AsRef<Path>,
        params: Parameters,
        session_id: impl Into<String>,
    ) -> crate::error::Result<Self> {
        if params.sample_interval == 0 {
            return Err(Error::validation("sample_interval must be > 0"));
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| Error::validation(format!("invalid document path: {e}")))?;

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        Ok(Self {
            id: session_id.into(),
            started_at: Utc::now(),
            ended_at: None,
            document_path: abs_path.to_string_lossy().to_string(),
            seed,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        })
    }

    /// Record a keystroke, returning (jitter_micros, sample_emitted).
    ///
    /// `keystroke_count` uses `saturating_add`; at human typing rates (~10 keys/s)
    /// u64::MAX would take ~58 billion years to reach, so saturation is unreachable
    /// in practice and sampling will never stall.
    pub fn record_keystroke(&mut self) -> crate::error::Result<(u32, bool)> {
        self.keystroke_count = self.keystroke_count.saturating_add(1);
        if !self
            .keystroke_count
            .checked_rem(self.params.sample_interval)
            .is_some_and(|r| r == 0)
        {
            return Ok((0, false));
        }

        let doc_hash = self.hash_document()?;
        let now = Utc::now();
        let previous_hash = self.samples.last().map(|s| s.hash).unwrap_or([0u8; 32]);
        let jitter = compute_jitter_value(
            &self.seed,
            doc_hash,
            self.keystroke_count,
            now,
            previous_hash,
            self.params,
        );

        let mut sample = Sample {
            timestamp: now,
            keystroke_count: self.keystroke_count,
            document_hash: doc_hash,
            jitter_micros: jitter,
            hash: [0u8; 32],
            previous_hash,
        };
        sample.hash = sample.compute_hash();

        self.samples.push(sample);
        self.last_jitter = jitter;

        Ok((jitter, true))
    }

    /// Finalize this session by recording the end timestamp.
    pub fn end(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    /// Return the total number of keystrokes recorded in this session.
    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count
    }

    /// Return the number of jitter samples in the chain.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Return the elapsed duration of this session.
    pub fn duration(&self) -> Duration {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0))
    }

    /// Export session data as a self-contained evidence packet.
    pub fn export(&self) -> Evidence {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let mut evidence = Evidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            statistics: Statistics::default(),
        };
        evidence.statistics = self.compute_stats();
        evidence
    }

    fn compute_stats(&self) -> Statistics {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let duration = end
            .signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        let keystrokes_per_min = {
            let secs = duration.as_secs_f64();
            if secs < 1.0 {
                0.0
            } else {
                self.keystroke_count as f64 / (secs / 60.0)
            }
        };

        let unique_doc_hashes = self
            .samples
            .iter()
            .map(|s| s.document_hash)
            .collect::<std::collections::HashSet<_>>()
            .len()
            .min(i32::MAX as usize) as i32;

        Statistics {
            total_keystrokes: self.keystroke_count,
            total_samples: self.samples.len().min(i32::MAX as usize) as i32,
            duration,
            keystrokes_per_min,
            unique_doc_hashes,
            chain_valid: self.verify_chain().is_ok(),
        }
    }

    pub(crate) fn verify_chain(&self) -> crate::error::Result<()> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash().ct_eq(&sample.hash).unwrap_u8() == 0 {
                return Err(Error::validation(format!("sample {i}: hash mismatch")));
            }
            if i > 0 {
                if sample
                    .previous_hash
                    .ct_eq(&self.samples[i - 1].hash)
                    .unwrap_u8()
                    == 0
                {
                    return Err(Error::validation(format!("sample {i}: broken chain link")));
                }
            } else if sample.previous_hash.ct_eq(&[0u8; 32]).unwrap_u8() == 0 {
                return Err(Error::validation("sample 0: non-zero previous hash"));
            }
        }
        Ok(())
    }

    /// Persist session state to disk atomically (write-then-rename).
    pub fn save(&self, path: impl AsRef<Path>) -> crate::error::Result<()> {
        let mut data = SessionData {
            id: self.id.clone(),
            started_at: self.started_at,
            ended_at: self.ended_at,
            document_path: self.document_path.clone(),
            seed: hex::encode(self.seed),
            params: self.params,
            samples: self.samples.clone(),
            keystroke_count: self.keystroke_count,
            last_jitter: self.last_jitter,
        };

        let bytes = Zeroizing::new(
            serde_json::to_vec_pretty(&data).map_err(|e| Error::validation(e.to_string()))?,
        );
        data.seed.zeroize();

        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| Error::validation(e.to_string()))?;
        }

        // Atomic write via tempfile (unpredictable name, auto-cleanup on error)
        let parent = path.as_ref().parent().unwrap_or(Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| Error::validation(e.to_string()))?;
        std::io::Write::write_all(&mut tmp, &bytes)
            .map_err(|e| Error::validation(e.to_string()))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Error::validation(e.to_string()))?;
        crate::crypto::restrict_permissions(tmp.path(), 0o600)
            .map_err(|e| Error::validation(e.to_string()))?;
        tmp.persist(path.as_ref())
            .map_err(|e| Error::validation(e.error.to_string()))?;
        Ok(())
    }

    /// Load and verify a session from a JSON file on disk.
    pub fn load(path: impl AsRef<Path>) -> crate::error::Result<Self> {
        let bytes = Zeroizing::new(fs::read(path).map_err(|e| Error::validation(e.to_string()))?);
        let mut data: SessionData =
            serde_json::from_slice(&bytes).map_err(|e| Error::validation(e.to_string()))?;
        let mut seed_bytes =
            hex::decode(&data.seed).map_err(|e| Error::validation(e.to_string()))?;
        data.seed.zeroize();
        if seed_bytes.len() != 32 {
            seed_bytes.zeroize();
            return Err(Error::validation("seed must be 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        seed_bytes.zeroize();

        let session = Self {
            id: data.id,
            started_at: data.started_at,
            ended_at: data.ended_at,
            document_path: data.document_path,
            seed,
            params: data.params,
            samples: data.samples,
            keystroke_count: data.keystroke_count,
            last_jitter: data.last_jitter,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        };

        session.verify_loaded_integrity()?;
        Ok(session)
    }

    fn verify_loaded_integrity(&self) -> crate::error::Result<()> {
        if self.params.sample_interval == 0 {
            return Err(Error::validation("sample_interval must be > 0"));
        }

        self.verify_chain()?;

        if let Some(ended) = self.ended_at {
            if ended < self.started_at {
                return Err(Error::validation("ended_at precedes started_at"));
            }
        }

        // 5 min tolerance for clock skew
        let ceiling = Utc::now() + chrono::Duration::minutes(5);
        if self.started_at > ceiling {
            return Err(Error::validation("started_at is in the future"));
        }
        if let Some(ended) = self.ended_at {
            if ended > ceiling {
                return Err(Error::validation("ended_at is in the future"));
            }
        }

        for (i, sample) in self.samples.iter().enumerate() {
            if i > 0 {
                let prev = &self.samples[i - 1];
                if sample.timestamp <= prev.timestamp {
                    return Err(Error::validation(format!(
                        "sample {i}: timestamp not monotonic"
                    )));
                }
                if sample.keystroke_count <= prev.keystroke_count {
                    return Err(Error::validation(format!(
                        "sample {i}: keystroke count not monotonic"
                    )));
                }
            }
            if sample.timestamp > ceiling {
                return Err(Error::validation(format!(
                    "sample {i}: timestamp is in the future"
                )));
            }
        }

        if let Some(last) = self.samples.last() {
            if self.keystroke_count < last.keystroke_count {
                return Err(Error::validation(
                    "keystroke_count is less than last sample's count",
                ));
            }
        }

        Ok(())
    }

    fn hash_document(&mut self) -> crate::error::Result<[u8; 32]> {
        let metadata =
            fs::metadata(&self.document_path).map_err(|e| Error::validation(e.to_string()))?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_doc_hash)
        {
            if mtime == last_mtime && size == last_size {
                return Ok(last_hash);
            }
        }

        // Use hash_file_with_size to get hash and actual byte count from the
        // same read pass, avoiding TOCTOU between metadata and hash.
        let (hash, actual_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))
                .map_err(|e| Error::validation(e.to_string()))?;

        self.last_mtime = Some(mtime);
        self.last_size = Some(actual_size);
        self.last_doc_hash = Some(hash);

        Ok(hash)
    }
}

/// Exported jitter session evidence with samples and computed statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Session identifier.
    pub session_id: String,
    /// When the session began.
    pub started_at: DateTime<Utc>,
    /// When the session ended.
    pub ended_at: DateTime<Utc>,
    /// Path of the monitored document.
    pub document_path: String,
    /// Jitter parameters used during capture.
    pub params: Parameters,
    /// Complete chain of jitter samples.
    pub samples: Vec<Sample>,
    /// Computed session statistics.
    pub statistics: Statistics,
}

/// Summary statistics computed from a jitter session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Statistics {
    /// Total keystrokes recorded during the session.
    pub total_keystrokes: u64,
    /// Number of jitter samples in the chain.
    pub total_samples: i32,
    /// Wall-clock duration of the session.
    pub duration: Duration,
    /// Average keystrokes per minute.
    pub keystrokes_per_min: f64,
    /// Count of distinct document hashes observed.
    pub unique_doc_hashes: i32,
    /// Whether the sample chain passed integrity verification.
    pub chain_valid: bool,
}

impl Evidence {
    /// Verify chain integrity: hashes, links, monotonic timestamps and counts.
    pub fn verify(&self) -> crate::error::Result<()> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash().ct_eq(&sample.hash).unwrap_u8() == 0 {
                return Err(Error::validation(format!("sample {i}: hash mismatch")));
            }
            if i > 0 {
                if sample
                    .previous_hash
                    .ct_eq(&self.samples[i - 1].hash)
                    .unwrap_u8()
                    == 0
                {
                    return Err(Error::validation(format!("sample {i}: broken chain link")));
                }
            } else if sample.previous_hash.ct_eq(&[0u8; 32]).unwrap_u8() == 0 {
                return Err(Error::validation("sample 0: non-zero previous hash"));
            }
            if i > 0 && sample.timestamp <= self.samples[i - 1].timestamp {
                return Err(Error::validation(format!(
                    "sample {i}: timestamp not monotonic"
                )));
            }
            if i > 0 && sample.keystroke_count <= self.samples[i - 1].keystroke_count {
                return Err(Error::validation(format!(
                    "sample {i}: keystroke count not monotonic"
                )));
            }
        }
        Ok(())
    }

    /// Serialize this evidence packet to pretty-printed JSON bytes.
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::validation(e.to_string()))
    }

    /// Deserialize an evidence packet from JSON bytes.
    pub fn decode(data: &[u8]) -> crate::error::Result<Evidence> {
        serde_json::from_slice(data).map_err(|e| Error::validation(e.to_string()))
    }

    /// Compute keystrokes per minute from session statistics.
    pub fn typing_rate(&self) -> f64 {
        if self.statistics.duration.as_secs_f64() > 0.0 {
            self.statistics.total_keystrokes as f64
                / (self.statistics.duration.as_secs_f64() / 60.0)
        } else {
            0.0
        }
    }

    /// Return the count of distinct document hashes observed during the session.
    pub fn document_evolution(&self) -> i32 {
        self.statistics.unique_doc_hashes
    }

    /// Check whether the typing rate and document evolution suggest human authorship.
    pub fn is_plausible_human_typing(&self) -> bool {
        let rate = self.typing_rate();
        if rate < 10.0 && self.statistics.total_keystrokes > 100 {
            return false;
        }
        if rate > 1000.0 {
            return false;
        }
        if self.statistics.unique_doc_hashes < 2 && self.statistics.total_keystrokes > 500 {
            return false;
        }
        true
    }
}

/// On-disk JSON representation of a jitter session (includes hex-encoded seed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session identifier.
    pub id: String,
    /// When the session began.
    pub started_at: DateTime<Utc>,
    /// When the session ended, if finalized.
    pub ended_at: Option<DateTime<Utc>>,
    /// Canonical path of the monitored document.
    pub document_path: String,
    pub(crate) seed: String,
    /// Jitter parameters used during capture.
    pub params: Parameters,
    /// Complete chain of jitter samples.
    pub samples: Vec<Sample>,
    /// Total keystrokes recorded.
    pub keystroke_count: u64,
    /// Most recent jitter value emitted.
    pub last_jitter: u32,
}

pub(super) fn compute_jitter_value(
    seed: &[u8],
    doc_hash: [u8; 32],
    keystroke_count: u64,
    timestamp: DateTime<Utc>,
    prev_jitter: [u8; 32],
    params: Parameters,
) -> u32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("hmac key");
    mac.update(&doc_hash);
    mac.update(&keystroke_count.to_be_bytes());
    mac.update(&timestamp_nanos_u64(timestamp).to_be_bytes());
    mac.update(&prev_jitter);

    let hash = mac.finalize().into_bytes();
    let raw = u32::from_be_bytes(hash[0..4].try_into().expect("4-byte slice"));
    let jitter_range = params
        .max_jitter_micros
        .saturating_sub(params.min_jitter_micros);
    if jitter_range == 0 {
        return params.min_jitter_micros;
    }
    params.min_jitter_micros + (raw % jitter_range)
}
