// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Instant;
use subtle::ConstantTimeEq;

use super::jitter::{
    compute_jitter_stats, JITTER_REFILL_PER_MS, JITTER_TOKEN_COST, JITTER_TOKEN_MAX, MAX_BATCH_SIZE,
};
use super::protocol::{is_domain_allowed, now_nanos, validate_content_hash};
use super::types::{session, Response, Session};

pub(crate) fn handle_start_session(document_url: String, document_title: String) -> Response {
    if !is_domain_allowed(&document_url) {
        let host = url::Url::parse(&document_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "(invalid URL)".to_string());
        return Response::Error {
            message: format!("Unsupported domain: {}", host),
            code: "DOMAIN_NOT_ALLOWED".into(),
        };
    }

    let init_result = cpoe::ffi::ffi_init();
    if !init_result.success {
        return Response::Error {
            message: init_result
                .error_message
                .unwrap_or_else(|| "Initialization failed".into()),
            code: "INIT_FAILED".into(),
        };
    }

    let data_dir = match dirs::data_local_dir().or_else(dirs::home_dir) {
        Some(dir) => dir,
        None => {
            return Response::Error {
                message: "Cannot determine data directory: no home or local data dir found".into(),
                code: "NO_DATA_DIR".into(),
            };
        }
    };

    let session_dir = data_dir.join("CPoE").join("browser-sessions");
    if let Err(e) = std::fs::create_dir_all(&session_dir) {
        return Response::Error {
            message: format!("create session dir: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let mut session_nonce = [0u8; 16];
    if let Err(e) = getrandom::getrandom(&mut session_nonce) {
        return Response::Error {
            message: format!("CSPRNG failure: {e}"),
            code: "CRYPTO_ERROR".into(),
        };
    }

    let mut hasher = Sha256::new();
    hasher.update(document_url.as_bytes());
    hasher.update(now_nanos().to_le_bytes());
    hasher.update(session_nonce);
    let hash = hasher.finalize();
    let session_id = hex::encode(&hash[..8]);

    let safe_title: String = document_title
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let evidence_path = session_dir.join(format!("{safe_title}_{session_id}.cpoe"));

    // Escape HTML comment delimiters to prevent evidence format corruption.
    let safe_title_html = document_title
        .replace("--", "\u{2014}")
        .replace('>', "\u{203A}");
    // Write to a temp file with restricted permissions first, then rename
    // to avoid a TOCTOU window where the file is world-readable.
    {
        let mut tmp = match tempfile::NamedTempFile::new_in(&session_dir) {
            Ok(t) => t,
            Err(e) => {
                return Response::Error {
                    message: format!("create temp evidence file: {e}"),
                    code: "IO_ERROR".into(),
                };
            }
        };
        // Restrict permissions on the temp file before writing content.
        if let Err(e) = cpoe::restrict_permissions(tmp.path(), 0o600) {
            eprintln!("Warning: chmod temp evidence file: {e}");
        }
        if let Err(e) = tmp.write_all(format!("<!-- {safe_title_html} -->\n").as_bytes()) {
            return Response::Error {
                message: format!("write evidence file: {e}"),
                code: "IO_ERROR".into(),
            };
        }
        if let Err(e) = tmp.persist(&evidence_path) {
            return Response::Error {
                message: format!("persist evidence file: {e}"),
                code: "IO_ERROR".into(),
            };
        }
    }

    let checkpoint_result = cpoe::ffi::ffi_create_checkpoint(
        evidence_path.display().to_string(),
        format!("Browser session started: {document_title}"),
    );

    if !checkpoint_result.success {
        return Response::Error {
            message: checkpoint_result
                .error_message
                .unwrap_or_else(|| "initial checkpoint failed".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    let signing_key = load_device_signing_key();

    let mut genesis_hasher = Sha256::new();
    genesis_hasher.update(session_id.as_bytes());
    genesis_hasher.update(session_nonce);
    if let Some(ref sk) = signing_key {
        genesis_hasher.update(sk.verifying_key().as_bytes());
    }
    genesis_hasher.update(b"genesis");
    let genesis: [u8; 32] = genesis_hasher.finalize().into();

    let now_ns = now_nanos();

    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });

    if let Some(prev) = session_lock.take() {
        eprintln!(
            "Finalizing previous session {} ('{}', {} checkpoints) before starting new session",
            prev.id, prev.document_title, prev.checkpoint_count
        );
        let final_result = cpoe::ffi::ffi_create_checkpoint(
            prev.evidence_path.display().to_string(),
            format!(
                "Browser session ended (superseded): {} ({} checkpoints)",
                prev.document_title, prev.checkpoint_count
            ),
        );
        if !final_result.success {
            eprintln!(
                "Warning: final checkpoint failed for previous session {}: {}",
                prev.id,
                final_result.error_message.as_deref().unwrap_or("unknown")
            );
        }
    }

    let device_public_key = signing_key
        .as_ref()
        .map(|sk: &ed25519_dalek::SigningKey| hex::encode(sk.verifying_key().as_bytes()));

    *session_lock = Some(Session {
        id: session_id.clone(),
        document_url: document_url.clone(),
        document_title: document_title.clone(),
        checkpoint_count: 1,
        evidence_path,
        jitter_intervals: Vec::new(),
        prev_commitment: genesis,
        expected_ordinal: 2, // Next expected (1 already created)
        session_nonce,
        last_char_count: 0,
        last_checkpoint_ts: now_ns,
        bucket_millitokens: JITTER_TOKEN_MAX,
        last_refill: Instant::now(),
        jitter_hash: [0u8; 32],
        signing_key,
    });

    Response::SessionStarted {
        session_id,
        message: format!("Now witnessing: {document_title}"),
        session_nonce: hex::encode(session_nonce),
        device_public_key,
    }
}

pub(crate) fn handle_checkpoint(
    content_hash: String,
    char_count: u64,
    delta: i64,
    commitment: Option<String>,
    ordinal: Option<u64>,
    tool_category: Option<String>,
    tool_host: Option<String>,
) -> Response {
    if let Err(msg) = validate_content_hash(&content_hash) {
        return Response::Error {
            message: msg,
            code: "INVALID_CONTENT_HASH".into(),
        };
    }

    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let now_ns = now_nanos();

    if session.checkpoint_count > 0 && ordinal.is_none() {
        return Response::Error {
            message: "Ordinal is required after genesis checkpoint".into(),
            code: "MISSING_ORDINAL".into(),
        };
    }

    if let Some(ord) = ordinal {
        if ord != session.expected_ordinal {
            eprintln!(
                "Ordinal mismatch: expected {}, got {}",
                session.expected_ordinal, ord
            );
            return Response::Error {
                message: format!(
                    "Ordinal mismatch: expected {}, got {}",
                    session.expected_ordinal, ord
                ),
                code: "ORDINAL_MISMATCH".into(),
            };
        }
    }

    // Allow up to 1 second backward tolerance for NTP clock adjustments.
    // SystemTime is not monotonic — laptops waking from sleep commonly see
    // small backward jumps. Reject only large backward jumps (>1s).
    const CLOCK_TOLERANCE_NS: u64 = 1_000_000_000;
    if now_ns
        < session
            .last_checkpoint_ts
            .saturating_sub(CLOCK_TOLERANCE_NS)
    {
        return Response::Error {
            message: format!(
                "Non-monotonic timestamp detected: clock moved backward by {:.1}s",
                (session.last_checkpoint_ts - now_ns) as f64 / 1e9
            ),
            code: "TIMESTAMP_NON_MONOTONIC".into(),
        };
    }
    // Ensure stored timestamp never goes backward even with tolerance.
    let now_ns = now_ns.max(session.last_checkpoint_ts + 1);

    // Allow char_count to decrease (user may delete text or undo).
    // This is normal editing behavior, not an integrity violation.

    // Browser commitment is an optional protocol-integrity check.
    // The daemon computes its own commitment (below) and signs it with Ed25519;
    // the browser's value is not security-critical against a local adversary.
    if let Some(ref browser_commitment) = commitment {
        let expected = compute_commitment(
            &session.prev_commitment,
            &content_hash,
            session.expected_ordinal,
            &session.session_nonce,
        );
        if let Ok(browser_bytes) = hex::decode(browser_commitment) {
            if browser_bytes.len() == 32 && expected.ct_eq(&browser_bytes).unwrap_u8() == 0 {
                eprintln!(
                    "Warning: browser commitment mismatch for ordinal {} (protocol integrity check)",
                    session.expected_ordinal,
                );
            }
        }
    }

    // Sanitize title for HTML comment context (same as initial evidence write).
    let safe_title = session
        .document_title
        .replace("--", "\u{2014}")
        .replace('>', "\u{203A}");
    let tool_cat = tool_category.as_deref().unwrap_or("none");
    let tool_h = tool_host.as_deref().unwrap_or("");
    // Sanitize tool fields for HTML comment context (strip -- and >)
    let safe_tool_cat: String = tool_cat.chars().filter(|c| c.is_alphanumeric() || *c == '_').take(32).collect();
    let safe_tool_host: String = tool_h.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(128).collect();
    let content = format!(
        "<!-- {} -->\n<!-- hash: {} chars: {} delta: {} ordinal: {} tool: {}:{} -->\n",
        safe_title, content_hash, char_count, delta, session.expected_ordinal, safe_tool_cat, safe_tool_host
    );
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&session.evidence_path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
    {
        return Response::Error {
            message: format!("update evidence file: {e}"),
            code: "IO_ERROR".into(),
        };
    }

    let result = cpoe::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!(
            "Browser checkpoint #{}: {} chars, delta {}",
            session.expected_ordinal, char_count, delta
        ),
    );

    if !result.success {
        return Response::Error {
            message: result
                .error_message
                .unwrap_or_else(|| "Checkpoint failed".into()),
            code: "CHECKPOINT_FAILED".into(),
        };
    }

    let new_commitment = compute_commitment(
        &session.prev_commitment,
        &content_hash,
        session.expected_ordinal,
        &session.session_nonce,
    );

    let signature = session.signing_key.as_ref().map(|sk| {
        let mut payload = Vec::with_capacity(160);
        payload.extend_from_slice(b"cpoe-checkpoint-sig-v1");
        payload.extend_from_slice(session.id.as_bytes());
        payload.extend_from_slice(&session.expected_ordinal.to_le_bytes());
        payload.extend_from_slice(content_hash.as_bytes());
        payload.extend_from_slice(&new_commitment);
        payload.extend_from_slice(&now_ns.to_le_bytes());
        payload.extend_from_slice(&session.jitter_hash);
        let sig_hex = hex::encode(sk.sign(&payload).to_bytes());
        let pubkey_hex = hex::encode(sk.verifying_key().as_bytes());
        // Persist signature to evidence file so it survives browser crashes
        let sig_line = format!(
            "<!-- sig: {} pubkey: {} ordinal: {} -->\n",
            sig_hex, pubkey_hex, session.expected_ordinal
        );
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| f.write_all(sig_line.as_bytes()));
        sig_hex
    });

    session.prev_commitment = new_commitment;
    session.expected_ordinal += 1;
    session.checkpoint_count += 1;
    session.last_char_count = char_count;
    session.last_checkpoint_ts = now_ns;

    Response::CheckpointCreated {
        hash: content_hash,
        checkpoint_count: session.checkpoint_count,
        message: result
            .message
            .unwrap_or_else(|| "Checkpoint created".into()),
        commitment: hex::encode(new_commitment),
        signature,
    }
}

fn load_device_signing_key() -> Option<ed25519_dalek::SigningKey> {
    use zeroize::Zeroize;

    // Prefer platform keychain (macOS Keychain, Linux keyring) over flat file.
    // SecureStorage keys are not extractable via filesystem access.
    if let Ok(Some(data)) = cpoe::identity::SecureStorage::load_signing_key() {
        if data.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data);
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            seed.zeroize();
            return Some(key);
        }
    }

    // Fall back to flat file for legacy installs; migrate to keychain on success.
    let dir = if let Ok(d) = std::env::var("CPOE_DATA_DIR") {
        std::path::PathBuf::from(d)
    } else {
        dirs::home_dir()?.join(".writersproof")
    };
    let key_path = dir.join("signing_key");
    let mut key_data = std::fs::read(&key_path).ok()?;
    if key_data.len() != 32 && key_data.len() != 64 {
        key_data.zeroize();
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_data[..32]);
    key_data.zeroize();

    // Migrate to keychain and remove the flat file
    if cpoe::identity::SecureStorage::save_signing_key(&seed).is_ok()
        && !cpoe::identity::SecureStorage::is_keychain_disabled()
    {
        let _ = std::fs::remove_file(&key_path);
    }

    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    seed.zeroize();
    Some(key)
}

/// Compute commitment hash: H(prev_commitment || content_hash || ordinal || session_nonce).
pub(crate) fn compute_commitment(
    prev: &[u8; 32],
    content_hash: &str,
    ordinal: u64,
    session_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(content_hash.as_bytes());
    hasher.update(ordinal.to_le_bytes());
    hasher.update(session_nonce);
    hasher.finalize().into()
}

pub(crate) fn handle_stop_session() -> Response {
    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.take() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let final_result = cpoe::ffi::ffi_create_checkpoint(
        session.evidence_path.display().to_string(),
        format!(
            "Browser session ended: {} ({} checkpoints)",
            session.document_title, session.checkpoint_count
        ),
    );
    if !final_result.success {
        eprintln!(
            "Warning: final checkpoint failed for session {}: {}",
            session.id,
            final_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    let signature = session.signing_key.as_ref().map(|sk| {
        // Hash the entire evidence file before appending the seal.
        // This makes any modification (including stripping signature lines) detectable.
        let file_hash = std::fs::read(&session.evidence_path)
            .map(|data| {
                let mut h = Sha256::new();
                h.update(&data);
                let result: [u8; 32] = h.finalize().into();
                result
            })
            .unwrap_or([0u8; 32]);

        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(b"cpoe-session-end-v1");
        payload.extend_from_slice(session.id.as_bytes());
        payload.extend_from_slice(&session.checkpoint_count.to_le_bytes());
        payload.extend_from_slice(&session.prev_commitment);
        payload.extend_from_slice(&session.jitter_hash);
        payload.extend_from_slice(&file_hash);
        let sig_hex = hex::encode(sk.sign(&payload).to_bytes());
        let pubkey_hex = hex::encode(sk.verifying_key().as_bytes());
        let seal_line = format!(
            "<!-- session-seal: {} pubkey: {} file_hash: {} checkpoints: {} -->\n",
            sig_hex,
            pubkey_hex,
            hex::encode(file_hash),
            session.checkpoint_count
        );
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| {
                f.write_all(seal_line.as_bytes())?;
                f.sync_all()
            });
        sig_hex
    });

    Response::SessionStopped {
        message: format!(
            "Session ended for '{}' with {} checkpoints",
            session.document_title, session.checkpoint_count
        ),
        signature,
    }
}

pub(crate) fn handle_get_status() -> Response {
    let status = cpoe::ffi::ffi_get_status();
    // Poison recovery — see handle_start_session for logging rationale
    let session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });

    Response::Status {
        initialized: status.initialized,
        active_session: session_lock.is_some(),
        document_url: session_lock.as_ref().map(|s| s.document_url.clone()),
        document_title: session_lock.as_ref().map(|s| s.document_title.clone()),
        checkpoint_count: session_lock
            .as_ref()
            .map(|s| s.checkpoint_count)
            .unwrap_or(0),
        tracked_files: status.tracked_file_count,
        total_checkpoints: status.total_checkpoints,
    }
}

pub(crate) fn handle_inject_jitter(intervals: Vec<u64>) -> Response {
    let count = intervals.len();

    if count == 0 {
        return Response::JitterReceived { count: 0 };
    }

    if count > MAX_BATCH_SIZE {
        return Response::Error {
            message: format!("Batch too large: {} (max {})", count, MAX_BATCH_SIZE),
            code: "BATCH_TOO_LARGE".into(),
        };
    }

    // Poison recovery — see handle_start_session for logging rationale
    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });
    let session = match session_lock.as_mut() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session. Call start_session first.".into(),
                code: "NO_SESSION".into(),
            }
        }
    };

    let now = Instant::now();
    let elapsed_ms = now.duration_since(session.last_refill).as_millis() as u64;
    let refill = elapsed_ms.saturating_mul(JITTER_REFILL_PER_MS);
    session.bucket_millitokens = session
        .bucket_millitokens
        .saturating_add(refill)
        .min(JITTER_TOKEN_MAX);
    session.last_refill = now;

    if session.bucket_millitokens < JITTER_TOKEN_COST {
        return Response::Error {
            message: "Jitter batch rate limit exceeded".into(),
            code: "RATE_LIMITED".into(),
        };
    }
    session.bucket_millitokens -= JITTER_TOKEN_COST;

    let valid: Vec<u64> = intervals
        .into_iter()
        .filter(|i| (10_000..=10_000_000).contains(i))
        .collect();

    const MAX_JITTER_INTERVALS: usize = 100_000;
    let accepted = valid.len();
    let remaining_cap = MAX_JITTER_INTERVALS.saturating_sub(session.jitter_intervals.len());
    let stored = accepted.min(remaining_cap);
    session.jitter_intervals.extend_from_slice(&valid[..stored]);

    if stored < accepted {
        eprintln!(
            "Jitter buffer full: dropped {} of {} accepted intervals",
            accepted - stored,
            accepted
        );
    }

    // Update running jitter hash: H(prev_jitter_hash || intervals)
    if stored > 0 {
        let mut jh = Sha256::new();
        jh.update(session.jitter_hash);
        for interval in &valid[..stored] {
            jh.update(interval.to_le_bytes());
        }
        session.jitter_hash = jh.finalize().into();
    }

    if !session.jitter_intervals.is_empty() {
        let stats = compute_jitter_stats(&session.jitter_intervals);
        let jitter_line = format!(
            "<!-- jitter: samples={} mean={:.0}us stddev={:.0}us min={}us max={}us -->\n",
            stats.count, stats.mean, stats.std_dev, stats.min, stats.max,
        );
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| f.write_all(jitter_line.as_bytes()))
        {
            return Response::Error {
                message: format!("Failed to write jitter evidence: {e}"),
                code: "JITTER_WRITE_FAILED".into(),
            };
        }
    }

    eprintln!(
        "Jitter: received {count}, accepted {accepted}, stored {stored}, total {}",
        session.jitter_intervals.len()
    );

    Response::JitterReceived { count: stored }
}

pub(crate) fn handle_snapshot_save(
    document_url: String,
    content_hash: String,
    char_count: u64,
) -> Response {
    if !is_domain_allowed(&document_url) {
        return Response::Error {
            message: "Unsupported domain".into(),
            code: "DOMAIN_NOT_ALLOWED".into(),
        };
    }
    if let Err(e) = validate_content_hash(&content_hash) {
        return Response::Error {
            message: e,
            code: "INVALID_HASH".into(),
        };
    }

    let guard = session().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref session) = *guard {
        if session.document_url != document_url {
            eprintln!(
                "Warning: snapshot document_url differs from session (browser may have navigated)"
            );
        }
        let note = format!(
            "browser-snapshot url={} hash={} chars={}",
            document_url,
            &content_hash[..16],
            char_count
        );
        let wal_path = session.evidence_path.join("browser_snapshots.jsonl");
        const MAX_JSONL_SIZE: u64 = 10 * 1024 * 1024;
        if std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0) >= MAX_JSONL_SIZE {
            return Response::Error {
                message: "Snapshot buffer full".into(),
                code: "BUFFER_FULL".into(),
            };
        }
        let entry = serde_json::json!({
            "document_url": document_url,
            "content_hash": content_hash,
            "char_count": char_count,
            "timestamp": now_nanos(),
            "session_id": session.id,
            "checkpoint_count": session.checkpoint_count,
        });
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .and_then(|mut f| writeln!(f, "{}", entry))
        {
            Ok(()) => Response::SnapshotSaved { message: note },
            Err(e) => Response::Error {
                message: format!("Snapshot write failed: {e}"),
                code: "IO_ERROR".into(),
            },
        }
    } else {
        Response::Error {
            message: "No active session".into(),
            code: "NO_SESSION".into(),
        }
    }
}

const KNOWN_AI_SOURCES: &[&str] = &[
    "chatgpt", "claude", "gemini", "copilot", "jasper", "copy-ai", "unknown",
];

pub(crate) fn handle_ai_content_copied(
    source: String,
    char_count: u64,
    timestamp: u64,
) -> Response {
    let sanitized_source = KNOWN_AI_SOURCES
        .iter()
        .find(|s| source.eq_ignore_ascii_case(s))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let now_ns = now_nanos();
    let timestamp = {
        let one_day_ago = now_ns.saturating_sub(86_400_000_000_000);
        let one_min_ahead = now_ns.saturating_add(60_000_000_000);
        if timestamp < one_day_ago || timestamp > one_min_ahead {
            now_ns
        } else {
            timestamp
        }
    };
    let guard = session().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref session) = *guard {
        // Write to session evidence directory (included in evidence export)
        let wal_path = session.evidence_path.join("tool_usage.jsonl");
        const MAX_JSONL_SIZE: u64 = 10 * 1024 * 1024;
        if std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0) >= MAX_JSONL_SIZE {
            return Response::Error {
                message: "Snapshot buffer full".into(),
                code: "BUFFER_FULL".into(),
            };
        }
        let entry = serde_json::json!({
            "type": "ai_content_copied",
            "source": sanitized_source,
            "char_count": char_count,
            "timestamp": timestamp,
            "session_id": session.id,
            "checkpoint_ordinal": session.checkpoint_count,
        });
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .and_then(|mut f| writeln!(f, "{}", entry))
        {
            eprintln!("Failed to write tool usage: {e}");
        }

        // Notify the sentinel for real-time tracking
        cpoe::ffi::sentinel_es::ffi_sentinel_es_ai_tool_detected(
            sanitized_source.clone(),
            0,
            0,
            String::new(),
        );

        Response::AiCopyRecorded {
            message: format!("Tool usage recorded: {sanitized_source} ({char_count} chars)"),
        }
    } else {
        Response::AiCopyRecorded {
            message: "No active session; tool usage noted".into(),
        }
    }
}

pub(crate) fn handle_text_attestation(
    content_hash: String,
    tier: String,
    writersproof_id: String,
    attested_at: String,
    app_bundle_id: String,
) -> Response {
    if let Err(msg) = validate_content_hash(&content_hash) {
        return Response::TextAttestationResult {
            success: false,
            error: Some(msg),
        };
    }

    if !matches!(tier.as_str(), "verified" | "corroborated" | "declared") {
        return Response::TextAttestationResult {
            success: false,
            error: Some(format!("Invalid tier: {tier}")),
        };
    }

    if !((writersproof_id.len() == 8 || writersproof_id.len() == 16)
        && writersproof_id.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Response::TextAttestationResult {
            success: false,
            error: Some("writersproof_id must be 8 or 16 hex characters".into()),
        };
    }

    // Validate ISO 8601 timestamp format (e.g. "2026-04-25T12:00:00Z").
    if attested_at.len() < 20
        || attested_at.len() > 30
        || !attested_at.ends_with('Z')
        || attested_at.as_bytes().get(4) != Some(&b'-')
        || attested_at.as_bytes().get(10) != Some(&b'T')
    {
        return Response::TextAttestationResult {
            success: false,
            error: Some("attested_at must be an ISO 8601 UTC timestamp".into()),
        };
    }

    // app_bundle_id is a hostname from the browser; sanity-check length.
    if app_bundle_id.len() > 253 {
        return Response::TextAttestationResult {
            success: false,
            error: Some("app_bundle_id exceeds maximum hostname length".into()),
        };
    }

    // Best-effort local store (sign + SQLite insert) so the attestation
    // persists even if the API sync below fails and the offline queue is lost.
    let _ =
        cpoe::ffi::text_fragment::store_attestation_from_hash(&content_hash, &app_bundle_id);

    let sync_result = cpoe::ffi::writersproof_ffi::ffi_sync_text_attestation(
        content_hash,
        tier,
        writersproof_id,
        attested_at,
        app_bundle_id,
    );

    if sync_result.success {
        Response::TextAttestationResult {
            success: true,
            error: None,
        }
    } else {
        Response::TextAttestationResult {
            success: false,
            error: sync_result.error_message,
        }
    }
}

const ALLOWED_VIEWS: &[&str] = &[
    "dashboard", "settings", "versionHistory", "history", "export", "checkpoint",
];

pub(crate) fn handle_open_view(view: String) -> Response {
    if !ALLOWED_VIEWS.iter().any(|v| *v == view) {
        return Response::Error {
            message: format!("Unknown view: {view}"),
            code: "INVALID_VIEW".into(),
        };
    }
    let url = format!("writersproof://view/{}", view);
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }
    Response::ViewOpened {
        message: format!("Opening {view}"),
    }
}
