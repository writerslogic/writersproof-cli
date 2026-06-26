// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use blake3::Hasher;
use ed25519_dalek::SigningKey;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroize;

pub(super) const VERSION: u32 = 2;
pub(super) const MAGIC: &[u8; 4] = b"SWAL"; // Secure WAL
pub(super) const HEADER_SIZE: usize = 64;
pub(super) const MAX_ENTRY_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB
/// Reject WAL files claiming more entries than this to prevent OOM on corrupt data.
pub(super) const MAX_WAL_ENTRIES: u64 = 10_000_000;
/// Maximum WAL file size in bytes (256 MiB). Prevents unbounded disk growth.
pub(super) const MAX_WAL_SIZE: u64 = 256 * 1024 * 1024;

/// WAL entry type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    KeystrokeBatch = 1,
    DocumentHash = 2,
    JitterSample = 3,
    Heartbeat = 4,
    SessionStart = 5,
    SessionEnd = 6,
    Checkpoint = 7,
    PathChange = 8,
    TextFragmentInsert = 9,
    /// Manuscript export detected: a derived output file was created within 30s
    /// of the last active checkpoint (links source session → exported manuscript).
    ExportEvent = 10,
    /// App compile/compile-draft pipeline started (e.g. Scrivener Compile).
    CompileStarted = 11,
    /// App compile/compile-draft pipeline finished.
    CompileFinished = 12,
    /// Live dictation session started — microphone and ES speech PID captured.
    DictationBegin = 13,
    /// Dictation phrase fragment — interim SFSpeechRecognizer result with confidence.
    DictationFragment = 14,
    /// Dictation session ended — final summary with plausibility score.
    DictationEnd = 15,
}

impl TryFrom<u8> for EntryType {
    type Error = WalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EntryType::KeystrokeBatch),
            2 => Ok(EntryType::DocumentHash),
            3 => Ok(EntryType::JitterSample),
            4 => Ok(EntryType::Heartbeat),
            5 => Ok(EntryType::SessionStart),
            6 => Ok(EntryType::SessionEnd),
            7 => Ok(EntryType::Checkpoint),
            8 => Ok(EntryType::PathChange),
            9 => Ok(EntryType::TextFragmentInsert),
            10 => Ok(EntryType::ExportEvent),
            11 => Ok(EntryType::CompileStarted),
            12 => Ok(EntryType::CompileFinished),
            13 => Ok(EntryType::DictationBegin),
            14 => Ok(EntryType::DictationFragment),
            15 => Ok(EntryType::DictationEnd),
            _ => Err(WalError::InvalidEntryType(value)),
        }
    }
}

/// WAL payload for a `DictationBegin` entry.
#[derive(Debug, Clone)]
pub struct DictationBeginPayload {
    pub session_id: [u8; 32],
    pub start_ns: i64,
    pub es_speech_pid: u32,
    pub audio_transport_type: u8,
    pub device_uid_hash: [u8; 8],
    pub speaker_output_active: bool,
    pub ambient_noise_db: f32,
}

/// WAL payload for a `DictationFragment` entry (per-phrase interim result).
#[derive(Debug, Clone)]
pub struct DictationFragmentPayload {
    pub session_id: [u8; 32],
    pub fragment_index: u32,
    pub timestamp_ns: i64,
    pub word_count: u32,
    pub confidence: f32,
    pub speaker_output_active: bool,
    /// BLAKE3 of the transcript text — text content is never stored.
    pub text_hash: [u8; 32],
}

/// WAL payload for a `DictationEnd` entry.
#[derive(Debug, Clone)]
pub struct DictationEndPayload {
    pub session_id: [u8; 32],
    pub end_ns: i64,
    pub total_words: u32,
    pub total_fragments: u32,
    pub confidence_mean: f32,
    pub confidence_stddev: f32,
    pub keystrokes_during_dictation: u32,
    pub cross_window_similarity: f32,
    pub plausibility_score: f64,
}

impl DictationBeginPayload {
    /// Fixed wire size in bytes.
    pub const SIZE: usize = 32 + 8 + 4 + 1 + 8 + 1 + 4; // 58

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.start_ns.to_be_bytes());
        b.extend_from_slice(&self.es_speech_pid.to_be_bytes());
        b.push(self.audio_transport_type);
        b.extend_from_slice(&self.device_uid_hash);
        b.push(self.speaker_output_active as u8);
        b.extend_from_slice(&self.ambient_noise_db.to_be_bytes());
        b
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, WalError> {
        if data.len() < Self::SIZE {
            return Err(WalError::Serialization(format!(
                "DictationBeginPayload: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&data[0..32]);
        // SAFETY: all slice ranges are within [0..SIZE=58], guaranteed by the length check above.
        let start_ns = i64::from_be_bytes(
            data[32..40]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let es_speech_pid = u32::from_be_bytes(
            data[40..44]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let audio_transport_type = data[44];
        let mut device_uid_hash = [0u8; 8];
        device_uid_hash.copy_from_slice(&data[45..53]);
        let speaker_output_active = data[53] != 0;
        let ambient_noise_db = f32::from_be_bytes(
            data[54..58]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        Ok(Self {
            session_id,
            start_ns,
            es_speech_pid,
            audio_transport_type,
            device_uid_hash,
            speaker_output_active,
            ambient_noise_db,
        })
    }
}

impl DictationFragmentPayload {
    /// Fixed wire size in bytes.
    pub const SIZE: usize = 32 + 4 + 8 + 4 + 4 + 1 + 32; // 85

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.fragment_index.to_be_bytes());
        b.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        b.extend_from_slice(&self.word_count.to_be_bytes());
        b.extend_from_slice(&self.confidence.to_be_bytes());
        b.push(self.speaker_output_active as u8);
        b.extend_from_slice(&self.text_hash);
        b
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, WalError> {
        if data.len() < Self::SIZE {
            return Err(WalError::Serialization(format!(
                "DictationFragmentPayload: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&data[0..32]);
        // SAFETY: all slice ranges are within [0..SIZE=85], guaranteed by the length check above.
        let fragment_index = u32::from_be_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let timestamp_ns = i64::from_be_bytes(
            data[36..44]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let word_count = u32::from_be_bytes(
            data[44..48]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let confidence = f32::from_be_bytes(
            data[48..52]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let speaker_output_active = data[52] != 0;
        let mut text_hash = [0u8; 32];
        text_hash.copy_from_slice(&data[53..85]);
        Ok(Self {
            session_id,
            fragment_index,
            timestamp_ns,
            word_count,
            confidence,
            speaker_output_active,
            text_hash,
        })
    }
}

impl DictationEndPayload {
    /// Fixed wire size in bytes.
    pub const SIZE: usize = 32 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 8; // 72

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.end_ns.to_be_bytes());
        b.extend_from_slice(&self.total_words.to_be_bytes());
        b.extend_from_slice(&self.total_fragments.to_be_bytes());
        b.extend_from_slice(&self.confidence_mean.to_be_bytes());
        b.extend_from_slice(&self.confidence_stddev.to_be_bytes());
        b.extend_from_slice(&self.keystrokes_during_dictation.to_be_bytes());
        b.extend_from_slice(&self.cross_window_similarity.to_be_bytes());
        b.extend_from_slice(&self.plausibility_score.to_be_bytes());
        b
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, WalError> {
        if data.len() < Self::SIZE {
            return Err(WalError::Serialization(format!(
                "DictationEndPayload: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&data[0..32]);
        // SAFETY: all slice ranges are within [0..SIZE=72], guaranteed by the length check above.
        let end_ns = i64::from_be_bytes(
            data[32..40]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let total_words = u32::from_be_bytes(
            data[40..44]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let total_fragments = u32::from_be_bytes(
            data[44..48]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let confidence_mean = f32::from_be_bytes(
            data[48..52]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let confidence_stddev = f32::from_be_bytes(
            data[52..56]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let keystrokes_during_dictation = u32::from_be_bytes(
            data[56..60]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let cross_window_similarity = f32::from_be_bytes(
            data[60..64]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        let plausibility_score = f64::from_be_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| WalError::Serialization("corrupt dictation payload".into()))?,
        );
        Ok(Self {
            session_id,
            end_ns,
            total_words,
            total_fragments,
            confidence_mean,
            confidence_stddev,
            keystrokes_during_dictation,
            cross_window_similarity,
            plausibility_score,
        })
    }
}

/// Errors from WAL operations.
#[derive(Debug, Error)]
pub enum WalError {
    #[error("invalid magic number")]
    InvalidMagic,
    #[error("unsupported version {0}")]
    InvalidVersion(u32),
    #[error("corrupted entry")]
    CorruptedEntry,
    #[error("broken hash chain")]
    BrokenChain,
    #[error("cumulative hash mismatch")]
    CumulativeMismatch,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp regression")]
    TimestampRegression,
    #[error("log is closed")]
    Closed,
    #[error("sequence number gap detected")]
    SequenceGap,
    #[error("invalid entry type {0}")]
    InvalidEntryType(u8),
    #[error("entry count exceeds maximum ({0})")]
    TooManyEntries(u64),
    #[error("WAL size exceeds maximum ({0} bytes)")]
    TooLarge(u64),
    #[error("WAL session_id mismatch")]
    SessionMismatch,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("WAL is inconsistent and must be recovered or discarded")]
    Inconsistent,
    /// The WAL is corrupt before the first valid entry. Manual restore is required.
    /// Returned by [`Wal::recover`] when no entry can be validated.
    #[error("WAL is unrecoverable: corruption before first valid entry")]
    Unrecoverable,
}

/// WAL file header (64 bytes, written once at creation).
#[derive(Debug, Clone)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u32,
    pub session_id: [u8; 32],
    pub created_at: i64,
    pub last_checkpoint_seq: u64,
    pub reserved: [u8; 8],
}

/// Single WAL entry with hash-chain linkage and signature.
#[derive(Debug, Clone)]
pub struct Entry {
    pub length: u32,
    pub sequence: u64,
    pub timestamp: i64,
    pub entry_type: EntryType,
    pub payload: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub cumulative_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl Entry {
    pub(super) fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&[self.entry_type as u8]);
        hasher.update(&self.payload);
        hasher.update(&self.prev_hash);
        *hasher.finalize().as_bytes()
    }
}

/// Append-only write-ahead log with hash-chain integrity and Ed25519 signatures.
pub struct Wal {
    pub(super) inner: Mutex<WalState>,
}

/// Number of appends between automatic fdatasyncs when no force_sync is requested.
pub const DEFAULT_SYNC_INTERVAL: u64 = 10;

pub(super) struct WalState {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) session_id: [u8; 32],
    pub(super) signing_key: SigningKey,
    pub(super) next_sequence: u64,
    pub(super) last_hash: [u8; 32],
    pub(super) cumulative_hasher: Hasher,
    pub(super) closed: bool,
    pub(super) inconsistent: bool,
    pub(super) entry_count: u64,
    pub(super) byte_count: u64,
    pub(super) sync_interval: u64,
    pub(super) pending_syncs: u64,
}

impl Drop for WalState {
    fn drop(&mut self) {
        // Extract, zeroize, and replace to ensure secret bytes are wiped even
        // if SigningKey's own Drop is optimized away.
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
        self.signing_key = SigningKey::from_bytes(&bytes);
    }
}

/// Result returned by [`Wal::recover`].
#[derive(Debug, Clone)]
pub struct WalRecoveryReport {
    /// Estimated number of entries lost to truncation. Zero means the WAL was clean.
    pub lost_count: u64,
    /// Sequence number at which the WAL was truncated (= next writable sequence).
    pub truncated_at_sequence: u64,
    /// Nanosecond timestamp of when recovery ran.
    pub recovered_at: i64,
}

#[derive(Debug)]
/// Result of a full WAL integrity verification pass.
pub struct WalVerification {
    pub valid: bool,
    pub entries: u64,
    pub final_hash: [u8; 32],
    pub error: Option<WalError>,
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_type_roundtrip_dictation_variants() {
        assert_eq!(
            EntryType::try_from(13u8).unwrap(),
            EntryType::DictationBegin
        );
        assert_eq!(
            EntryType::try_from(14u8).unwrap(),
            EntryType::DictationFragment
        );
        assert_eq!(EntryType::try_from(15u8).unwrap(), EntryType::DictationEnd);
        assert!(EntryType::try_from(16u8).is_err());
    }

    #[test]
    fn dictation_begin_payload_roundtrip() {
        let p = DictationBeginPayload {
            session_id: [1u8; 32],
            start_ns: 1_700_000_000_000_000_000,
            es_speech_pid: 12345,
            audio_transport_type: 1,
            device_uid_hash: [0xAB; 8],
            speaker_output_active: true,
            ambient_noise_db: -42.5,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), DictationBeginPayload::SIZE);
        let p2 = DictationBeginPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.session_id, p.session_id);
        assert_eq!(p2.start_ns, p.start_ns);
        assert_eq!(p2.es_speech_pid, p.es_speech_pid);
        assert_eq!(p2.audio_transport_type, p.audio_transport_type);
        assert_eq!(p2.device_uid_hash, p.device_uid_hash);
        assert_eq!(p2.speaker_output_active, p.speaker_output_active);
        assert_eq!(p2.ambient_noise_db, p.ambient_noise_db);
    }

    #[test]
    fn dictation_begin_payload_too_short() {
        assert!(DictationBeginPayload::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn dictation_fragment_payload_roundtrip() {
        let p = DictationFragmentPayload {
            session_id: [2u8; 32],
            fragment_index: 7,
            timestamp_ns: 1_700_000_001_000_000_000,
            word_count: 12,
            confidence: 0.91,
            speaker_output_active: false,
            text_hash: [0xCCu8; 32],
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), DictationFragmentPayload::SIZE);
        let p2 = DictationFragmentPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.session_id, p.session_id);
        assert_eq!(p2.fragment_index, p.fragment_index);
        assert_eq!(p2.timestamp_ns, p.timestamp_ns);
        assert_eq!(p2.word_count, p.word_count);
        assert_eq!(p2.confidence, p.confidence);
        assert_eq!(p2.speaker_output_active, p.speaker_output_active);
        assert_eq!(p2.text_hash, p.text_hash);
    }

    #[test]
    fn dictation_fragment_payload_too_short() {
        assert!(DictationFragmentPayload::from_bytes(&[0u8; 20]).is_err());
    }

    #[test]
    fn dictation_end_payload_roundtrip() {
        let p = DictationEndPayload {
            session_id: [3u8; 32],
            end_ns: 1_700_000_060_000_000_000,
            total_words: 120,
            total_fragments: 8,
            confidence_mean: 0.88,
            confidence_stddev: 0.12,
            keystrokes_during_dictation: 0,
            cross_window_similarity: 0.05,
            plausibility_score: 0.93,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), DictationEndPayload::SIZE);
        let p2 = DictationEndPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.session_id, p.session_id);
        assert_eq!(p2.end_ns, p.end_ns);
        assert_eq!(p2.total_words, p.total_words);
        assert_eq!(p2.total_fragments, p.total_fragments);
        assert_eq!(p2.confidence_mean, p.confidence_mean);
        assert_eq!(p2.confidence_stddev, p.confidence_stddev);
        assert_eq!(
            p2.keystrokes_during_dictation,
            p.keystrokes_during_dictation
        );
        assert_eq!(p2.cross_window_similarity, p.cross_window_similarity);
        assert_eq!(p2.plausibility_score, p.plausibility_score);
    }

    #[test]
    fn dictation_end_payload_too_short() {
        assert!(DictationEndPayload::from_bytes(&[0u8; 40]).is_err());
    }
}
