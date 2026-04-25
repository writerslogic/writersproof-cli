// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for text fragment evidence storage and retrieval.
//!
//! Swift captures text content natively (NSPasteboard, NSEvent) and pushes
//! it here for hashing, signing, and storage. Rust never reads the pasteboard
//! directly — the platform stubs in `sentinel/clipboard.rs` are intentional.

use super::helpers::{load_signing_key, open_store};
use crate::store::text_fragments::{KeystrokeContext, TextFragment};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTextFragment {
    pub id: i64,
    pub fragment_hash_hex: String,
    pub session_id: String,
    pub source_app_bundle_id: Option<String>,
    pub source_window_title: Option<String>,
    pub keystroke_context: Option<String>,
    pub keystroke_confidence: Option<f64>,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTextFragmentStoreResult {
    pub success: bool,
    pub fragment_hash_hex: Option<String>,
    pub fragment_id: i64,
    pub error_message: Option<String>,
}

impl FfiTextFragmentStoreResult {
    fn ok(hash_hex: String, id: i64) -> Self {
        Self { success: true, fragment_hash_hex: Some(hash_hex), fragment_id: id, error_message: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, fragment_hash_hex: None, fragment_id: -1, error_message: Some(msg.into()) }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPasteRecordResult {
    pub success: bool,
    pub text_hash_hex: Option<String>,
    pub matched_existing: bool,
    pub matched_session_id: Option<String>,
    pub error_message: Option<String>,
}

impl FfiPasteRecordResult {
    fn ok(hash_hex: String, matched_session_id: Option<String>) -> Self {
        Self {
            success: true,
            text_hash_hex: Some(hash_hex),
            matched_existing: matched_session_id.is_some(),
            matched_session_id,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            text_hash_hex: None,
            matched_existing: false,
            matched_session_id: None,
            error_message: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAttestTextResult {
    pub success: bool,
    pub tier: String,
    pub fragment_hash_hex: String,
    pub writersproof_id: String,
    pub attestation_text: String,
    pub error_message: Option<String>,
}

impl FfiAttestTextResult {
    fn ok(tier: String, hash_hex: String, wp_id: String, attestation: String) -> Self {
        Self {
            success: true,
            tier,
            fragment_hash_hex: hash_hex,
            writersproof_id: wp_id,
            attestation_text: attestation,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            tier: String::new(),
            fragment_hash_hex: String::new(),
            writersproof_id: String::new(),
            attestation_text: String::new(),
            error_message: Some(msg.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_ffi(f: &TextFragment) -> FfiTextFragment {
    FfiTextFragment {
        id: f.id.unwrap_or(-1),
        fragment_hash_hex: hex::encode(&f.fragment_hash),
        session_id: f.session_id.clone(),
        source_app_bundle_id: f.source_app_bundle_id.clone(),
        source_window_title: f.source_window_title.clone(),
        keystroke_context: f.keystroke_context.map(|c| c.as_str().to_string()),
        keystroke_confidence: f.keystroke_confidence,
        timestamp_ms: f.timestamp,
    }
}

fn hash_text(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Normalize text for attestation hashing: NFC-normalize, keep only Unicode
/// letters + ASCII digits, lowercase everything. Resilient to formatting
/// changes across platforms, apps, and sharing contexts.
pub fn normalize_for_attestation(text: &str) -> String {
    text.nfc()
        .filter(|c| c.is_alphabetic() || c.is_ascii_digit())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Hash text after normalization. Returns `(normalized, hash)` to avoid
/// recomputing the normalization.
fn hash_normalized_text(text: &str) -> (String, [u8; 32]) {
    let normalized = normalize_for_attestation(text);
    let hash = Sha256::digest(normalized.as_bytes()).into();
    (normalized, hash)
}

/// Sign the fragment payload with domain separation:
/// DST || len(session_id) || session_id || fragment_hash || timestamp || nonce.
fn sign_fragment(
    signing_key: &ed25519_dalek::SigningKey,
    session_id: &str,
    fragment_hash: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    const DST: &[u8] = b"witnessd-text-fragment-v1";
    let sid_len = (session_id.len() as u32).to_le_bytes();
    let mut payload = Vec::with_capacity(DST.len() + 4 + session_id.len() + 32 + 8 + 16);
    payload.extend_from_slice(DST);
    payload.extend_from_slice(&sid_len);
    payload.extend_from_slice(session_id.as_bytes());
    payload.extend_from_slice(fragment_hash);
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload.extend_from_slice(nonce);
    signing_key.sign(&payload).to_bytes()
}

fn current_timestamp_ms() -> i64 {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    if ts <= 0 {
        log::error!("System clock returned non-positive timestamp; evidence timing will be unreliable");
    }
    ts
}

fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    nonce
}

/// Generate a 64-hex-char ephemeral session ID for attestations without a
/// live sentinel session (matches the format of real session IDs).
fn generate_ephemeral_session_id() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    hex::encode(buf)
}

// ---------------------------------------------------------------------------
// Exported FFI functions
// ---------------------------------------------------------------------------

/// Store a text fragment with computed hash, signature, and nonce.
///
/// Called by Swift when text is typed or pasted. The `text_content` is hashed
/// (SHA-256) but NOT stored — only the hash persists for privacy.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_store(
    text_content: String,
    session_id: String,
    app_bundle_id: String,
    window_title: String,
    keystroke_context: String,
    confidence: f64,
) -> FfiTextFragmentStoreResult {
    if text_content.is_empty() {
        return FfiTextFragmentStoreResult::err("Text content is empty");
    }
    if session_id.is_empty() {
        return FfiTextFragmentStoreResult::err("Session ID is required");
    }
    if session_id.len() > 256 {
        return FfiTextFragmentStoreResult::err("Session ID too long");
    }

    let context = match keystroke_context.parse::<KeystrokeContext>() {
        Ok(c) => c,
        Err(_) => return FfiTextFragmentStoreResult::err(
            format!("Invalid keystroke_context: {keystroke_context}. Expected OriginalComposition, PastedContent, or AfterPaste")
        ),
    };

    if !confidence.is_finite() {
        return FfiTextFragmentStoreResult::err("Confidence must be a finite number");
    }
    let confidence = confidence.clamp(0.0, 1.0);
    let fragment_hash = hash_text(&text_content);
    let timestamp = current_timestamp_ms();
    if timestamp <= 0 {
        return FfiTextFragmentStoreResult::err("System clock unavailable");
    }
    let nonce = generate_nonce();

    let signing_key = match load_signing_key() {
        Ok(k) => zeroize::Zeroizing::new(k),
        Err(e) => return FfiTextFragmentStoreResult::err(format!("Signing key unavailable: {e}")),
    };

    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);
    drop(signing_key);

    let fragment = TextFragment {
        id: None,
        fragment_hash: fragment_hash.to_vec(),
        session_id,
        source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        source_window_title: Some(window_title).filter(|s| !s.is_empty()),
        source_signature: signature.to_vec(),
        nonce: nonce.to_vec(),
        timestamp,
        keystroke_context: Some(context),
        keystroke_confidence: Some(confidence),
        keystroke_sequence_hash: None,
        source_session_id: None,
        source_evidence_packet: None,
        wal_entry_hash: None,
        cloudkit_record_id: None,
        sync_state: None,
    };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiTextFragmentStoreResult::err(e),
    };

    match store.insert_text_fragment(&fragment) {
        Ok(id) => FfiTextFragmentStoreResult::ok(hex::encode(fragment_hash), id),
        Err(e) => FfiTextFragmentStoreResult::err(format!("Failed to store fragment: {e}")),
    }
}

/// Look up a text fragment by its hex-encoded SHA-256 hash.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_lookup(fragment_hash_hex: String) -> Option<FfiTextFragment> {
    let hash_bytes = match hex::decode(&fragment_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            log::warn!("ffi_text_fragment_lookup: invalid hash hex (expected 64 hex chars)");
            return None;
        }
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_text_fragment_lookup: failed to open store: {e}");
            return None;
        }
    };

    match store.lookup_fragment_by_hash(&hash_bytes) {
        Ok(Some(f)) => Some(to_ffi(&f)),
        Ok(None) => None,
        Err(e) => {
            log::warn!("ffi_text_fragment_lookup: query failed: {e}");
            None
        }
    }
}

/// Get all text fragments for a session, ordered by timestamp.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_list_for_session(session_id: String) -> Vec<FfiTextFragment> {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_text_fragment_list_for_session: failed to open store: {e}");
            return Vec::new();
        }
    };

    match store.get_fragments_for_session(&session_id) {
        Ok(frags) => frags.iter().map(to_ffi).collect(),
        Err(e) => {
            log::warn!("ffi_text_fragment_list_for_session: query failed: {e}");
            Vec::new()
        }
    }
}

/// Record a paste event with full text content for evidence tracking.
///
/// Replaces `ffi_sentinel_notify_paste`. Swift passes the pasted text, which
/// is hashed (SHA-256) and checked against existing fragments. The sentinel's
/// paste-char counter and keystroke context window are also updated.
///
/// The pasted text itself is NOT stored — only the hash.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_record_paste(
    char_count: i64,
    pasted_text: String,
    timestamp_ns: i64,
    app_bundle_id: String,
    window_title: String,
    detection_confidence: f64,
) -> FfiPasteRecordResult {
    if char_count < 0 {
        return FfiPasteRecordResult::err("char_count must be non-negative");
    }
    if timestamp_ns <= 0 {
        return FfiPasteRecordResult::err("timestamp_ns must be positive");
    }
    if !detection_confidence.is_finite() {
        return FfiPasteRecordResult::err("detection_confidence must be a finite number");
    }

    // Update sentinel paste counter (same as old ffi_sentinel_notify_paste).
    let sentinel_opt = super::sentinel::get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return FfiPasteRecordResult::err("Sentinel not running"),
    };
    sentinel.set_last_paste_chars(char_count);

    // Hash the pasted text.
    let text_hash = hash_text(&pasted_text);
    let text_hash_hex = hex::encode(text_hash);

    // Open store once for both lookup and insert.
    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Cannot open store for paste recording: {e}");
            return FfiPasteRecordResult::ok(text_hash_hex, None);
        }
    };

    // Check if this text matches an existing fragment (cross-session provenance).
    let matched_session_id = match store.lookup_fragment_by_hash(&text_hash) {
        Ok(Some(f)) => Some(f.session_id),
        _ => None,
    };

    // Store a fragment for this paste event in the current session.
    let focus = sentinel.current_focus();
    if let Some(ref focused_path) = focus {
        if let Ok(session) = sentinel.session(focused_path) {
            let signing_key = match load_signing_key() {
                Ok(k) => zeroize::Zeroizing::new(k),
                Err(e) => {
                    log::warn!("Cannot sign paste fragment: {e}");
                    return FfiPasteRecordResult::ok(text_hash_hex, matched_session_id);
                }
            };

            let timestamp_ms = timestamp_ns / 1_000_000;
            let nonce = generate_nonce();
            let signature = sign_fragment(
                &signing_key,
                &session.session_id,
                &text_hash,
                timestamp_ms,
                &nonce,
            );
            drop(signing_key);

            let fragment = TextFragment {
                id: None,
                fragment_hash: text_hash.to_vec(),
                session_id: session.session_id.clone(),
                source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
                source_window_title: Some(window_title).filter(|s| !s.is_empty()),
                source_signature: signature.to_vec(),
                nonce: nonce.to_vec(),
                timestamp: timestamp_ms,
                keystroke_context: Some(KeystrokeContext::PastedContent),
                keystroke_confidence: Some(detection_confidence.clamp(0.0, 1.0)),
                keystroke_sequence_hash: None,
                source_session_id: matched_session_id.clone(),
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: None,
                sync_state: None,
            };

            if let Err(e) = store.insert_text_fragment(&fragment) {
                log::warn!("Failed to store paste fragment: {e}");
            }
        }
    }

    FfiPasteRecordResult::ok(text_hash_hex, matched_session_id)
}

/// Create a tiered authorship attestation for selected text.
///
/// NFC-normalizes the text (letters + digits, lowercased), hashes it,
/// determines the attestation tier based on sentinel state, signs and stores
/// a fragment, and returns a formatted attestation block ready to paste.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_attest_text(
    text_content: String,
    app_bundle_id: String,
    window_title: String,
) -> FfiAttestTextResult {
    let (normalized, fragment_hash) = hash_normalized_text(&text_content);
    if normalized.is_empty() {
        return FfiAttestTextResult::err("No attestable content after normalization");
    }

    let fragment_hash_hex = hex::encode(fragment_hash);
    let writersproof_id = fragment_hash_hex[..16].to_string();

    // Determine tier from sentinel state. Snapshot capture_active before
    // sessions() to avoid TOCTOU (capture could stop between the two calls).
    let sentinel_opt = super::sentinel::get_sentinel();
    let (tier, session_id) = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => {
            let capture_active = s.is_keystroke_capture_active();
            let sessions = s.sessions();
            let matched = sessions
                .iter()
                .filter(|sess| {
                    sess.app_bundle_id == app_bundle_id && sess.keystroke_count > 0
                })
                .max_by_key(|sess| sess.keystroke_count);
            if capture_active {
                if let Some(sess) = matched {
                    ("verified", sess.session_id.clone())
                } else {
                    ("corroborated", generate_ephemeral_session_id())
                }
            } else {
                ("corroborated", generate_ephemeral_session_id())
            }
        }
        _ => ("declared", generate_ephemeral_session_id()),
    };

    // Sign and store as text fragment.
    let timestamp = current_timestamp_ms();
    if timestamp <= 0 {
        return FfiAttestTextResult::err("System clock error: unable to get current time");
    }
    let timestamp_iso = chrono::DateTime::from_timestamp_millis(timestamp)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();
    let nonce = generate_nonce();

    let signing_key = match load_signing_key() {
        Ok(k) => zeroize::Zeroizing::new(k),
        Err(e) => {
            return FfiAttestTextResult::err(format!("Signing key unavailable: {e}"));
        }
    };

    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);
    drop(signing_key);

    let fragment = TextFragment {
        id: None,
        fragment_hash: fragment_hash.to_vec(),
        session_id,
        source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        source_window_title: Some(window_title).filter(|s| !s.is_empty()),
        source_signature: signature.to_vec(),
        nonce: nonce.to_vec(),
        timestamp,
        keystroke_context: None,
        keystroke_confidence: None,
        keystroke_sequence_hash: None,
        source_session_id: None,
        source_evidence_packet: None,
        wal_entry_hash: None,
        cloudkit_record_id: None,
        sync_state: None,
    };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiAttestTextResult::err(e);
        }
    };

    if let Err(e) = store.insert_text_fragment(&fragment) {
        return FfiAttestTextResult::err(format!("Failed to store attestation: {e}"));
    }

    let tier_description = match tier {
        "verified" => "Cryptographic authorship attestation with keystroke evidence.",
        "corroborated" => "Authorship attestation, sentinel active during authoring.",
        _ => "Signed author declaration.",
    };

    let tier_label = match tier {
        "verified" => "Verified",
        "corroborated" => "Corroborated",
        _ => "Declared",
    };

    let attestation_text = format!(
        "WritersProof {tier_label} | ID: {writersproof_id} | {timestamp_iso}\n\
         {tier_description}\n\
         verify.writersproof.com"
    );

    FfiAttestTextResult::ok(
        tier.to_string(),
        fragment_hash_hex,
        writersproof_id,
        attestation_text,
    )
}

// ---------------------------------------------------------------------------
// CloudKit sync FFI functions
// ---------------------------------------------------------------------------

/// FFI result for sync operations that return a boolean success/failure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSyncResult {
    pub success: bool,
    pub error_message: Option<String>,
}

impl FfiSyncResult {
    fn ok() -> Self {
        Self { success: true, error_message: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, error_message: Some(msg.into()) }
    }
}

/// Mark a fragment as pending sync to CloudKit.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_mark_fragment_for_sync(fragment_id: i64) -> FfiSyncResult {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiSyncResult::err(e),
    };

    match store.mark_fragment_for_sync(fragment_id) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(
            format!("Failed to mark for sync: {e}"),
        ),
    }
}

/// Update a fragment's sync state with optional CloudKit record ID.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_update_fragment_sync_state(
    fragment_id: i64,
    state: String,
    cloudkit_record_id: Option<String>,
) -> FfiSyncResult {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiSyncResult::err(e),
    };

    const VALID_STATES: &[&str] = &["pending", "syncing", "synced", "failed", "conflict"];
    if !VALID_STATES.contains(&state.as_str()) {
        return FfiSyncResult::err(format!("Invalid sync state: {state}"));
    }

    match store.update_fragment_sync_state(
        fragment_id,
        &state,
        cloudkit_record_id.as_deref(),
    ) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(
            format!("Failed to update sync state: {e}"),
        ),
    }
}

/// Get count of fragments pending sync to CloudKit.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_pending_sync_count() -> i64 {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "ffi_get_pending_sync_count: failed to open store: {e}"
            );
            return -1;
        }
    };

    match store.get_pending_sync_count() {
        Ok(count) => count,
        Err(e) => {
            log::warn!(
                "ffi_get_pending_sync_count: query failed: {e}"
            );
            -1
        }
    }
}

/// Apply a remotely synced fragment received from CloudKit.
///
/// Verifies the Ed25519 signature over the domain-tagged payload before
/// storing, preventing injection of forged fragments via compromised sync.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_apply_remote_fragment(
    fragment_hash_hex: String,
    session_id: String,
    source_signature_hex: String,
    nonce_hex: String,
    timestamp_ms: i64,
    signing_public_key_hex: String,
    source_app_bundle_id: Option<String>,
    source_window_title: Option<String>,
    keystroke_context: Option<String>,
    keystroke_confidence: Option<f64>,
    cloudkit_record_id: Option<String>,
) -> FfiTextFragmentStoreResult {
    if timestamp_ms <= 0 {
        return FfiTextFragmentStoreResult::err("timestamp_ms must be positive");
    }

    let fragment_hash = match hex::decode(&fragment_hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return FfiTextFragmentStoreResult::err(
            "fragment_hash_hex must be 64 hex chars (32 bytes)",
        ),
    };
    let source_signature = match hex::decode(&source_signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return FfiTextFragmentStoreResult::err(
            "source_signature_hex must be 128 hex chars (64 bytes)",
        ),
    };
    let nonce = match hex::decode(&nonce_hex) {
        Ok(b) if b.len() == 16 => b,
        _ => return FfiTextFragmentStoreResult::err(
            "nonce_hex must be 32 hex chars (16 bytes)",
        ),
    };

    // Verify signature before accepting remote fragment.
    let pub_bytes = match hex::decode(&signing_public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return FfiTextFragmentStoreResult::err(
            "signing_public_key_hex must be 64 hex chars (32 bytes)",
        ),
    };
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into().expect("length validated at 32 bytes"),
        ) {
            Ok(k) => k,
            Err(e) => return FfiTextFragmentStoreResult::err(
                format!("Invalid public key: {e}"),
            ),
        };
        // Signature::from_bytes is infallible in ed25519-dalek v2.
        let sig_arr: &[u8; 64] = source_signature.as_slice().try_into().expect("length validated at 64 bytes");
        let sig = Signature::from_bytes(sig_arr);
        // Reconstruct the domain-tagged payload that was signed.
        const DST: &[u8] = b"witnessd-text-fragment-v1";
        let sid_len = (session_id.len() as u32).to_le_bytes();
        let mut payload = Vec::with_capacity(
            DST.len() + 4 + session_id.len() + 32 + 8 + 16,
        );
        payload.extend_from_slice(DST);
        payload.extend_from_slice(&sid_len);
        payload.extend_from_slice(session_id.as_bytes());
        payload.extend_from_slice(&fragment_hash);
        payload.extend_from_slice(&timestamp_ms.to_le_bytes());
        payload.extend_from_slice(&nonce);
        if vk.verify(&payload, &sig).is_err() {
            return FfiTextFragmentStoreResult::err(
                "Remote fragment signature verification failed",
            );
        }
    }

    let context = keystroke_context
        .as_deref()
        .and_then(|s| s.parse::<KeystrokeContext>().ok());

    let confidence = keystroke_confidence.map(|c| c.clamp(0.0, 1.0));

    let fragment = TextFragment {
        id: None,
        fragment_hash: fragment_hash.clone(),
        session_id,
        source_app_bundle_id,
        source_window_title,
        source_signature,
        nonce,
        timestamp: timestamp_ms,
        keystroke_context: context,
        keystroke_confidence: confidence,
        keystroke_sequence_hash: None,
        source_session_id: None,
        source_evidence_packet: None,
        wal_entry_hash: None,
        cloudkit_record_id,
        sync_state: Some("synced".to_string()),
    };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiTextFragmentStoreResult::err(e),
    };

    match store.apply_remote_fragment(&fragment) {
        Ok(id) => FfiTextFragmentStoreResult::ok(
            hex::encode(&fragment_hash),
            id,
        ),
        Err(e) => FfiTextFragmentStoreResult::err(
            format!("Failed to apply remote fragment: {e}"),
        ),
    }
}

/// Resolve a sync conflict for a fragment.
///
/// `strategy`: "keep_local", "keep_remote", or "keep_newest".
/// Remote fragment fields are required for "keep_remote"/"keep_newest".
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_resolve_sync_conflict(
    fragment_id: i64,
    strategy: String,
    remote_fragment_hash_hex: Option<String>,
    remote_session_id: Option<String>,
    remote_signature_hex: Option<String>,
    remote_nonce_hex: Option<String>,
    remote_timestamp_ms: Option<i64>,
    remote_cloudkit_record_id: Option<String>,
) -> FfiSyncResult {
    use crate::store::text_fragments::SyncResolutionStrategy;

    let strat = match strategy.as_str() {
        "keep_local" => SyncResolutionStrategy::KeepLocal,
        "keep_remote" => SyncResolutionStrategy::KeepRemote,
        "keep_newest" => SyncResolutionStrategy::KeepNewest,
        _ => return FfiSyncResult::err(format!(
            "Invalid strategy '{strategy}'; \
             expected keep_local, keep_remote, or keep_newest"
        )),
    };

    let remote_fragment =
        if strat != SyncResolutionStrategy::KeepLocal {
            let hash = match remote_fragment_hash_hex
                .as_deref()
                .map(hex::decode)
            {
                Some(Ok(b)) if b.len() == 32 => b,
                _ => return FfiSyncResult::err(
                    "Remote fragment hash required",
                ),
            };
            let sig = match remote_signature_hex
                .as_deref()
                .map(hex::decode)
            {
                Some(Ok(b)) if b.len() == 64 => b,
                _ => return FfiSyncResult::err(
                    "Remote signature required",
                ),
            };
            let nonce = match remote_nonce_hex
                .as_deref()
                .map(hex::decode)
            {
                Some(Ok(b)) if b.len() == 16 => b,
                _ => return FfiSyncResult::err(
                    "Remote nonce required",
                ),
            };
            let sid = match remote_session_id {
                Some(ref s) if !s.is_empty() => s.clone(),
                _ => return FfiSyncResult::err("Remote session ID required for KeepRemote/KeepNewest"),
            };
            let ts = match remote_timestamp_ms {
                Some(t) if t > 0 => t,
                _ => return FfiSyncResult::err("Remote timestamp required for KeepRemote/KeepNewest"),
            };
            Some(TextFragment {
                id: None,
                fragment_hash: hash,
                session_id: sid,
                source_app_bundle_id: None,
                source_window_title: None,
                source_signature: sig,
                nonce,
                timestamp: ts,
                keystroke_context: None,
                keystroke_confidence: None,
                keystroke_sequence_hash: None,
                source_session_id: None,
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: remote_cloudkit_record_id,
                sync_state: None,
            })
        } else {
            None
        };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiSyncResult::err(e),
    };

    // Verify remote fragment signature before accepting it
    if let Some(ref frag) = remote_fragment {
        let hash_arr: &[u8; 32] = frag.fragment_hash.as_slice()
            .try_into()
            .expect("length validated at 32 bytes");
        let sig_arr: &[u8; 64] = frag.source_signature.as_slice()
            .try_into()
            .expect("length validated at 64 bytes");
        let signing_key = match crate::ffi::helpers::load_signing_key() {
            Ok(k) => k,
            Err(e) => return FfiSyncResult::err(
                format!("Cannot verify remote signature: {e}"),
            ),
        };
        let pub_bytes = signing_key.verifying_key().to_bytes();
        match store.verify_fragment_signature(
            hash_arr,
            &frag.nonce,
            frag.timestamp,
            &frag.session_id,
            sig_arr,
            &pub_bytes,
        ) {
            Ok(true) => {}
            Ok(false) => return FfiSyncResult::err(
                "Remote fragment signature verification failed",
            ),
            Err(e) => return FfiSyncResult::err(
                format!("Signature verification error: {e}"),
            ),
        }
    }

    match store.resolve_sync_conflict(
        fragment_id,
        strat,
        remote_fragment.as_ref(),
    ) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(
            format!("Failed to resolve conflict: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_ascii() {
        assert_eq!(normalize_for_attestation("Hello, World!"), "helloworld");
    }

    #[test]
    fn test_normalize_unicode_precomposed() {
        assert_eq!(normalize_for_attestation("caf\u{00e9} r\u{00e9}sum\u{00e9}"), "caf\u{00e9}r\u{00e9}sum\u{00e9}");
    }

    #[test]
    fn test_normalize_nfc_nfd_equivalence() {
        let nfc = "caf\u{00e9}";          // precomposed é
        let nfd = "cafe\u{0301}";          // e + combining acute
        assert_eq!(
            normalize_for_attestation(nfc),
            normalize_for_attestation(nfd),
        );
    }

    #[test]
    fn test_normalize_digits() {
        assert_eq!(normalize_for_attestation("I wrote 5 chapters"), "iwrote5chapters");
    }

    #[test]
    fn test_normalize_whitespace_stripped() {
        assert_eq!(
            normalize_for_attestation("Hello\n\n  World\t!!"),
            "helloworld"
        );
    }

    #[test]
    fn test_normalize_cjk() {
        assert_eq!(normalize_for_attestation("写作 证明"), "写作证明");
    }

    #[test]
    fn test_normalize_empty_after_strip() {
        assert_eq!(normalize_for_attestation("!@#$%"), "");
    }

    #[test]
    fn test_hash_normalized_deterministic() {
        let (_, h1) = hash_normalized_text("Hello, World!");
        let (_, h2) = hash_normalized_text("hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_nfc_nfd_identical() {
        let (_, h1) = hash_normalized_text("caf\u{00e9}");
        let (_, h2) = hash_normalized_text("cafe\u{0301}");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ffi_attest_text_empty_input() {
        let result = ffi_attest_text(String::new(), String::new(), String::new());
        assert!(!result.success);
        assert_eq!(
            result.error_message.as_deref(),
            Some("No attestable content after normalization")
        );
    }

    #[test]
    fn test_ffi_attest_text_punctuation_only() {
        let result = ffi_attest_text("...!!!".to_string(), String::new(), String::new());
        assert!(!result.success);
        assert_eq!(
            result.error_message.as_deref(),
            Some("No attestable content after normalization")
        );
    }

    #[test]
    fn test_ffi_attest_text_declared_tier_and_lookup() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let tmp = std::env::temp_dir().join("cpoe_attest_test");
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("CPOE_DATA_DIR", tmp.to_str().unwrap());
        let init = crate::ffi::system::ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let result = ffi_attest_text(
            "This is my original text".to_string(),
            "com.apple.Notes".to_string(),
            "My Note".to_string(),
        );
        assert!(result.success, "attest failed: {:?}", result.error_message);
        assert_eq!(result.tier, "declared");
        assert!(!result.fragment_hash_hex.is_empty());
        assert_eq!(result.fragment_hash_hex.len(), 64);
        assert_eq!(result.writersproof_id.len(), 16);
        assert!(result.fragment_hash_hex.starts_with(&result.writersproof_id));
        assert!(result.attestation_text.contains("WritersProof Declared"));
        assert!(result.attestation_text.contains("verify.writersproof.com"));
        assert!(result.attestation_text.contains(&result.writersproof_id));

        // Verify the stored fragment is retrievable by hash.
        let lookup = ffi_text_fragment_lookup(result.fragment_hash_hex.clone());
        assert!(lookup.is_some(), "stored attestation fragment not found by hash");
        let frag = lookup.unwrap();
        assert_eq!(frag.fragment_hash_hex, result.fragment_hash_hex);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
