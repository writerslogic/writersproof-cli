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
            _ => Err(WalError::InvalidEntryType(value)),
        }
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
