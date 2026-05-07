// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

fn deserialize_bounded_intervals<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, SeqAccess, Visitor};
    struct BoundedVec;
    impl<'de> Visitor<'de> for BoundedVec {
        type Value = Vec<u64>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "an array of at most {} u64 intervals", super::jitter::MAX_BATCH_SIZE)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u64>, A::Error> {
            let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(super::jitter::MAX_BATCH_SIZE));
            while let Some(val) = seq.next_element::<u64>()? {
                if v.len() >= super::jitter::MAX_BATCH_SIZE {
                    return Err(A::Error::custom(format!(
                        "intervals exceeds maximum length {}",
                        super::jitter::MAX_BATCH_SIZE
                    )));
                }
                v.push(val);
            }
            Ok(v)
        }
    }
    deserializer.deserialize_seq(BoundedVec)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Request {
    Hello {
        #[serde(default)]
        #[allow(dead_code)]
        protocol_version: Option<u8>,
        client_pubkey: String,
    },
    KeyConfirm {
        token: String,
    },
    Encrypted {
        payload: String,
    },
    StartSession {
        document_url: String,
        document_title: String,
        #[serde(default)]
        protocol_version: Option<u32>,
        /// Editor type detected by the browser extension (e.g., "google-docs", "notion").
        #[serde(default)]
        editor_type: Option<String>,
    },
    /// Resume a session after browser restart. Semantically identical to
    /// StartSession but signals that the browser expects continuity with a
    /// prior session indexed under the same URL.
    ResumeSession {
        document_url: String,
        document_title: String,
        #[serde(default)]
        editor_type: Option<String>,
    },
    Checkpoint {
        content_hash: String,
        char_count: u64,
        delta: i64,
        /// Browser-side commitment hash (optional for backward compat).
        #[serde(default)]
        commitment: Option<String>,
        /// Checkpoint ordinal from the browser (optional for backward compat).
        #[serde(default)]
        ordinal: Option<u64>,
        /// Tool category detected by the browser extension (e.g., "grammar", "ai", "writing", "none").
        #[serde(default)]
        tool_category: Option<String>,
        /// Hostname of the tool site (e.g., "app.grammarly.com").
        #[serde(default)]
        tool_host: Option<String>,
    },
    StopSession,
    GetStatus,
    InjectJitter {
        #[serde(deserialize_with = "deserialize_bounded_intervals")]
        intervals: Vec<u64>,
    },
    Ping {
        #[serde(default)]
        protocol_version: Option<u32>,
    },
    SnapshotSave {
        document_url: String,
        content_hash: String,
        char_count: u64,
    },
    AiContentCopied {
        source: String,
        char_count: u64,
        timestamp: u64,
    },
    OpenView {
        view: String,
    },
    TextAttestation {
        content_hash: String,
        tier: String,
        writersproof_id: String,
        attested_at: String,
        app_bundle_id: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Response {
    HelloAccept {
        server_pubkey: String,
        confirm: String,
    },
    KeyConfirmed {},
    Encrypted {
        payload: String,
    },
    SessionStarted {
        session_id: String,
        message: String,
        /// Session nonce the browser must include in commitments.
        session_nonce: String,
        /// Device Ed25519 public key (hex) for server-side signature verification.
        #[serde(skip_serializing_if = "Option::is_none")]
        device_public_key: Option<String>,
    },
    CheckpointCreated {
        hash: String,
        checkpoint_count: u64,
        message: String,
        /// Server-side commitment hash for the browser to chain.
        commitment: String,
        /// Ed25519 signature over the checkpoint payload (hex).
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    SessionStopped {
        message: String,
        /// Ed25519 signature over session-end record (hex).
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    Status {
        initialized: bool,
        active_session: bool,
        document_url: Option<String>,
        document_title: Option<String>,
        checkpoint_count: u64,
        tracked_files: u32,
        total_checkpoints: u64,
    },
    JitterReceived {
        count: usize,
    },
    Pong {
        version: String,
    },
    SnapshotSaved {
        message: String,
    },
    AiCopyRecorded {
        message: String,
    },
    ViewOpened {
        message: String,
    },
    TextAttestationResult {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Error {
        message: String,
        code: String,
    },
}

pub(crate) struct Session {
    pub(crate) id: String,
    pub(crate) document_url: String,
    pub(crate) document_title: String,
    pub(crate) checkpoint_count: u64,
    pub(crate) evidence_path: std::path::PathBuf,
    pub(crate) session_dir: std::path::PathBuf,
    pub(crate) jitter_intervals: Vec<u64>,
    pub(crate) prev_commitment: [u8; 32],
    pub(crate) expected_ordinal: u64,
    pub(crate) session_nonce: [u8; 16],
    pub(crate) last_char_count: u64,
    pub(crate) last_checkpoint_ts: u64,
    pub(crate) started_at_ns: u64,
    /// Token bucket in milli-batches (1 batch = 1000 units; refill at 10 batches/sec = 10 units/ms).
    pub(crate) bucket_millitokens: u64,
    pub(crate) last_refill: std::time::Instant,
    /// Running hash of accumulated jitter intervals, bound to checkpoint signatures.
    pub(crate) jitter_hash: [u8; 32],
    /// Device Ed25519 signing key for checkpoint signatures. ZeroizeOnDrop via ed25519-dalek.
    pub(crate) signing_key: Option<SigningKey>,
    /// Web editor type detected by the browser extension (e.g., "google-docs", "notion").
    #[allow(dead_code)]
    pub(crate) editor_type: Option<String>,
    /// Session ID of the most recent prior session for the same URL, if within MAX_AGE_NS.
    #[allow(dead_code)]
    pub(crate) prior_session_id: Option<String>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_nonce.zeroize();
        self.prev_commitment.zeroize();
        self.jitter_hash.zeroize();
        // SigningKey handles its own zeroization via ZeroizeOnDrop.
    }
}

static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

pub(crate) fn session() -> &'static Mutex<Option<Session>> {
    SESSION.get_or_init(|| Mutex::new(None))
}
