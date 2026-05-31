// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Instant;
use subtle::ConstantTimeEq;

use super::jitter::{
    analyze_browser_jitter, compute_jitter_stats, JITTER_REFILL_PER_MS, JITTER_TOKEN_COST,
    JITTER_TOKEN_MAX, MAX_BATCH_SIZE,
};
use super::protocol::{is_url_acceptable, now_nanos, validate_content_hash};
use super::session_index;
use super::types::{session, Response, Session};

/// Maximum document title length accepted from the browser extension.
/// Matches common filesystem filename limits and prevents DoS via unbounded allocation.
const MAX_TITLE_LEN: usize = 255;

/// Maximum document URL length accepted from the browser extension.
/// 8192 bytes covers all practical URLs while bounding memory allocation.
const MAX_URL_LEN: usize = 8192;

pub(crate) fn handle_start_session(
    document_url: String,
    document_title: String,
    editor_type: Option<String>,
) -> Response {
    // Reject oversized URLs before any further allocation.
    if document_url.len() > MAX_URL_LEN {
        return Response::Error {
            message: format!("document_url exceeds maximum length ({MAX_URL_LEN} bytes)"),
            code: "URL_TOO_LONG".into(),
        };
    }

    // Truncate at a UTF-8 character boundary to avoid allocating unbounded memory
    // from a user-controlled browser field.
    let document_title: String = document_title
        .chars()
        .take(MAX_TITLE_LEN)
        .collect();

    if !is_url_acceptable(&document_url) {
        return Response::Error {
            message: "Only http and https URLs are accepted".into(),
            code: "INVALID_URL_SCHEME".into(),
        };
    }

    if let Err(resp) = ensure_engine_initialized() {
        return resp;
    }

    let session_dir = match resolve_session_dir() {
        Ok(dir) => dir,
        Err(resp) => return resp,
    };

    let session_nonce = match generate_session_nonce() {
        Ok(nonce) => nonce,
        Err(resp) => return resp,
    };

    let session_id = derive_session_id(&document_url, &session_nonce);

    let safe_editor_type = sanitize_editor_type(editor_type.as_deref());

    // Look up any recent prior session for this URL to chain evidence files.
    let lookup_now_ns = now_nanos();
    let prior_session_id: Option<String> = {
        let index = session_index::load(&session_dir);
        session_index::lookup_recent(&index, &document_url, lookup_now_ns)
            .map(|r| r.session_id.clone())
    };

    let evidence_path = build_evidence_path(
        &session_dir,
        &document_title,
        &session_id,
    );

    if let Err(resp) = write_evidence_header(
        &session_dir,
        &evidence_path,
        &document_title,
        safe_editor_type.as_deref(),
        prior_session_id.as_deref(),
    ) {
        return resp;
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
    let genesis = compute_genesis_hash(
        &session_id,
        &session_nonce,
        signing_key.as_ref(),
    );

    let now_ns = now_nanos();

    let mut session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Warning: session lock poisoned, recovering");
        p.into_inner()
    });

    finalize_prior_session(&mut session_lock);

    let device_public_key = signing_key
        .as_ref()
        .map(|sk: &ed25519_dalek::SigningKey| hex::encode(sk.verifying_key().as_bytes()));

    *session_lock = Some(Session {
        id: session_id.clone(),
        document_url: document_url.clone(),
        document_title: document_title.clone(),
        checkpoint_count: 1,
        evidence_path,
        session_dir: session_dir.clone(),
        jitter_intervals: Vec::new(),
        prev_commitment: genesis,
        expected_ordinal: 2, // Next expected (1 already created)
        session_nonce,
        last_char_count: 0,
        last_checkpoint_ts: now_ns,
        started_at_ns: now_ns,
        bucket_millitokens: JITTER_TOKEN_MAX,
        last_refill: Instant::now(),
        jitter_hash: [0u8; 32],
        signing_key,
        editor_type: safe_editor_type,
        prior_session_id,
        browser_keystroke_count: std::sync::atomic::AtomicU64::new(0),
    });

    Response::SessionStarted {
        session_id,
        message: format!("Now witnessing: {document_title}"),
        session_nonce: hex::encode(session_nonce),
        device_public_key,
    }
}

/// Initialize the CPoE engine, returning an error response on failure.
fn ensure_engine_initialized() -> Result<(), Response> {
    let init_result = cpoe::ffi::ffi_init();
    if !init_result.success {
        return Err(Response::Error {
            message: init_result
                .error_message
                .unwrap_or_else(|| "Initialization failed".into()),
            code: "INIT_FAILED".into(),
        });
    }
    Ok(())
}

/// Resolve and create the browser session directory.
fn resolve_session_dir() -> Result<std::path::PathBuf, Response> {
    let data_dir = dirs::data_local_dir().or_else(dirs::home_dir).ok_or_else(|| {
        Response::Error {
            message: "Cannot determine data directory: no home or local data dir found"
                .into(),
            code: "NO_DATA_DIR".into(),
        }
    })?;

    let session_dir = data_dir.join("CPoE").join("browser-sessions");
    std::fs::create_dir_all(&session_dir).map_err(|e| Response::Error {
        message: format!("create session dir: {e}"),
        code: "IO_ERROR".into(),
    })?;

    Ok(session_dir)
}

/// Generate a 16-byte cryptographic session nonce.
fn generate_session_nonce() -> Result<[u8; 16], Response> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| Response::Error {
        message: format!("CSPRNG failure: {e}"),
        code: "CRYPTO_ERROR".into(),
    })?;
    Ok(nonce)
}

/// Derive a hex session ID from the document URL, current time, and nonce.
fn derive_session_id(document_url: &str, session_nonce: &[u8; 16]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(document_url.as_bytes());
    hasher.update(now_nanos().to_le_bytes());
    hasher.update(session_nonce);
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

/// Sanitize editor_type: only alphanumeric and '-', max 32 chars.
fn sanitize_editor_type(editor_type: Option<&str>) -> Option<String> {
    editor_type.and_then(|et| {
        let s: String = et
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(32)
            .collect();
        if s.is_empty() { None } else { Some(s) }
    })
}

/// Build the evidence file path from a sanitized title and session ID.
fn build_evidence_path(
    session_dir: &std::path::Path,
    document_title: &str,
    session_id: &str,
) -> std::path::PathBuf {
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
    session_dir.join(format!("{safe_title}_{session_id}.cpoe"))
}

/// Write the initial evidence file header via a temp file with restricted
/// permissions to avoid a TOCTOU window where the file is world-readable.
fn write_evidence_header(
    session_dir: &std::path::Path,
    evidence_path: &std::path::Path,
    document_title: &str,
    editor_type: Option<&str>,
    prior_session_id: Option<&str>,
) -> Result<(), Response> {
    let safe_title_html = document_title
        .replace("--", "\u{2014}")
        .replace('>', "\u{203A}");

    let mut tmp = tempfile::NamedTempFile::new_in(session_dir).map_err(|e| {
        Response::Error {
            message: format!("create temp evidence file: {e}"),
            code: "IO_ERROR".into(),
        }
    })?;

    cpoe::restrict_permissions(tmp.path(), 0o600).map_err(|e| Response::Error {
        message: format!("chmod temp evidence file: {e}"),
        code: "IO_ERROR".into(),
    })?;

    let mut header = format!("<!-- {safe_title_html} -->\n");
    if let Some(et) = editor_type {
        header.push_str(&format!("<!-- editor_type: {et} -->\n"));
    }
    if let Some(prior_id) = prior_session_id {
        header.push_str(&format!("<!-- continues_from: {prior_id} -->\n"));
    }

    tmp.write_all(header.as_bytes()).map_err(|e| Response::Error {
        message: format!("write evidence file: {e}"),
        code: "IO_ERROR".into(),
    })?;

    tmp.persist(evidence_path).map_err(|e| Response::Error {
        message: format!("persist evidence file: {e}"),
        code: "IO_ERROR".into(),
    })?;

    Ok(())
}

/// Compute the genesis commitment hash for a new session.
fn compute_genesis_hash(
    session_id: &str,
    session_nonce: &[u8; 16],
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(session_nonce);
    if let Some(sk) = signing_key {
        hasher.update(sk.verifying_key().as_bytes());
    }
    hasher.update(b"genesis");
    hasher.finalize().into()
}

/// Finalize any prior session by creating a final checkpoint.
fn finalize_prior_session(
    session_lock: &mut Option<Session>,
) {
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

    // Server-side checkpoint rate guard: the browser enforces a 10s minimum
    // interval, so 5s here catches only floods from compromised pages or bugs.
    const MIN_CHECKPOINT_INTERVAL_NS: u64 = 5_000_000_000;
    if session.checkpoint_count > 1
        && now_ns.saturating_sub(session.last_checkpoint_ts) < MIN_CHECKPOINT_INTERVAL_NS
    {
        return Response::Error {
            message: "Checkpoint rate limit exceeded (min 5s between checkpoints)".into(),
            code: "RATE_LIMITED".into(),
        };
    }

    // Cap session lifetime at 24h to bound evidence file size. The browser
    // extension should stop and restart a session on this error.
    const MAX_SESSION_AGE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
    if now_ns.saturating_sub(session.started_at_ns) >= MAX_SESSION_AGE_NS {
        return Response::Error {
            message: "Session has exceeded the maximum duration (24h). Please start a new session.".into(),
            code: "SESSION_EXPIRED".into(),
        };
    }

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

    // Backward clock tolerance: 100ms accommodates NTP micro-adjustments
    // while rejecting replay attacks that rely on setting the clock back.
    // No forward check: normal typing sessions routinely exceed any fixed
    // forward window (idle time, copy-paste, long pauses between checkpoints).
    const BACKWARD_TOLERANCE_NS: u64 = 100_000_000; // 100ms
    if now_ns
        < session
            .last_checkpoint_ts
            .saturating_sub(BACKWARD_TOLERANCE_NS)
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
        // Constant-time comparison: decode unconditionally (fallback to zeros on
        // invalid hex), pad/truncate to 32 bytes, then fold the length check into
        // a subtle::Choice so no branch leaks timing information.
        let browser_bytes = hex::decode(browser_commitment).unwrap_or_else(|_| vec![0u8; 32]);
        let mut padded = [0u8; 32];
        let copy_len = browser_bytes.len().min(32);
        padded[..copy_len].copy_from_slice(&browser_bytes[..copy_len]);
        let length_ok = subtle::Choice::from((browser_bytes.len() == 32) as u8);
        let matches = length_ok & expected.ct_eq(&padded);
        if matches.unwrap_u8() == 0 {
            eprintln!( // intentional: daemon diagnostic log, not debug output
                "Warning: browser commitment mismatch for ordinal {} (protocol integrity check)",
                session.expected_ordinal,
            );
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
        .and_then(|mut f| {
            f.write_all(content.as_bytes())?;
            f.sync_all()
        })
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
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| {
                f.write_all(sig_line.as_bytes())?;
                f.sync_all()
            })
        {
            eprintln!("Failed to persist checkpoint signature: {e}");
        }
        sig_hex
    });

    let evidence_quality =
        analyze_browser_jitter(&session.jitter_intervals).map(|f| f.verdict.to_string());

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
        evidence_quality,
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
    let dir = dirs::home_dir()?.join(".writersproof");
    if !is_safe_key_dir(&dir) {
        return None;
    }
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

/// Reject key directories that are not owned by us or are world-writable.
#[cfg(unix)]
fn is_safe_key_dir(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let owned_by_us = meta.uid() == unsafe { libc::getuid() };
    let not_world_writable = meta.mode() & 0o002 == 0;
    owned_by_us && not_world_writable
}

#[cfg(not(unix))]
fn is_safe_key_dir(_dir: &std::path::Path) -> bool {
    true
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

    // Dual-source validation: compare browser vs native keystroke counts.
    let browser_count = session
        .browser_keystroke_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let native_count = session.jitter_intervals.len() as u64 + 1; // intervals = keystrokes - 1
    let (dual_verdict, dual_ratio) =
        super::jitter::validate_dual_source(browser_count, native_count);
    if dual_verdict == "native_excess" || dual_verdict == "browser_excess" {
        let line = format!(
            "<!-- dual-source: browser={} native={} ratio={:.2} verdict={} -->\n",
            browser_count, native_count, dual_ratio, dual_verdict,
        );
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
    }

    let jitter_verdict = analyze_browser_jitter(&session.jitter_intervals).map(|forensics| {
        let line = format!(
            "<!-- jitter-forensics: samples={} cv={:.3} regularity={:.3} rounding={:.3} verdict={} -->\n",
            forensics.sample_count,
            forensics.cv,
            forensics.regularity_ratio,
            forensics.rounding_ratio,
            forensics.verdict,
        );
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
        {
            eprintln!("Warning: failed to write jitter forensics: {e}");
        }
        forensics.verdict
    });

    let signature = session.signing_key.as_ref().and_then(|sk| {
        // Hash the entire evidence file before appending the seal.
        // This makes any modification (including stripping signature lines) detectable.
        let file_hash = match std::fs::read(&session.evidence_path) {
            Ok(data) => {
                let mut h = Sha256::new();
                h.update(&data);
                let result: [u8; 32] = h.finalize().into();
                result
            }
            Err(e) => {
                eprintln!("Error: cannot read evidence file for seal: {e}");
                return None;
            }
        };

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
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.evidence_path)
            .and_then(|mut f| {
                f.write_all(seal_line.as_bytes())?;
                f.sync_all()
            })
        {
            eprintln!("Warning: failed to write/sync session seal: {e}"); // intentional
        }
        Some(sig_hex)
    });

    session_index::upsert_and_save(
        &session.session_dir,
        &session.document_url,
        &session.id,
        session.last_char_count,
        session.expected_ordinal.saturating_sub(1),
        now_nanos(),
    );

    Response::SessionStopped {
        message: format!(
            "Session ended for '{}' with {} checkpoints",
            session.document_title, session.checkpoint_count
        ),
        signature,
        evidence_quality: jitter_verdict.map(|v| v.to_string()),
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
        return Response::JitterReceived { count: 0, dropped: 0 };
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

    let dropped = accepted.saturating_sub(stored);
    Response::JitterReceived { count: stored, dropped }
}

pub(crate) fn handle_snapshot_save(
    document_url: String,
    content_hash: String,
    char_count: u64,
) -> Response {
    if document_url.len() > MAX_URL_LEN {
        return Response::Error {
            message: format!("document_url exceeds maximum length ({MAX_URL_LEN} bytes)"),
            code: "URL_TOO_LONG".into(),
        };
    }
    if !is_url_acceptable(&document_url) {
        return Response::Error {
            message: "Only http and https URLs are accepted".into(),
            code: "INVALID_URL_SCHEME".into(),
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
            content_hash.get(..16).unwrap_or(&content_hash),
            char_count
        );
        let wal_path = session.session_dir.join("browser_snapshots.jsonl");
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
    "chatgpt", "claude", "gemini", "copilot", "jasper", "copy-ai",
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
    let mut guard = session().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref mut session) = *guard {
        // Write to session evidence directory (included in evidence export)
        let wal_path = session.session_dir.join("tool_usage.jsonl");
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

        // Bind the AI-copy event into the running jitter_hash so its
        // occurrence is covered by every subsequent checkpoint signature.
        {
            let mut jh = Sha256::new();
            jh.update(session.jitter_hash);
            jh.update(b"ai_content_copied:");
            jh.update(sanitized_source.as_bytes());
            jh.update(char_count.to_le_bytes());
            jh.update(timestamp.to_le_bytes());
            session.jitter_hash = jh.finalize().into();
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

    // Validate ISO 8601 timestamp — parse rejects structurally valid but
    // semantically invalid values like "0000-00-00T00:00:00Z".
    if chrono::DateTime::parse_from_rfc3339(&attested_at).is_err() {
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

/// Handle a batch of browser keystrokes for dual-source validation.
///
/// Each entry is (timestamp_ms, key, code) from the content script's keydown
/// listener. These are correlated with native CGEventTap/hook keystrokes by
/// the sentinel to detect injection or replay attacks.
pub(crate) fn handle_browser_keystroke_batch(
    keystrokes: Vec<(f64, String, String)>,
    _tab_id: u32,
) -> Response {
    let session_lock = session().lock().unwrap_or_else(|p| {
        eprintln!("Session mutex poisoned in browser_keystroke_batch, recovering");
        p.into_inner()
    });
    let sess = match session_lock.as_ref() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No active session".into(),
                code: "NO_SESSION".into(),
            };
        }
    };

    let count = keystrokes.len();
    if count == 0 {
        return Response::BrowserKeystrokesReceived { count: 0 };
    }

    // Record the browser keystroke count on the session for dual-source stats.
    sess.browser_keystroke_count
        .fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);

    Response::BrowserKeystrokesReceived { count }
}
