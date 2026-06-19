// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for text fragment evidence storage and retrieval.
//!
//! Swift captures text content natively (NSPasteboard, NSEvent) and pushes
//! it here for hashing, signing, and storage. Rust never reads the pasteboard
//! directly — the platform stubs in `sentinel/clipboard.rs` are intentional.

use super::helpers::{load_signing_key, open_store};
use super::types::{catch_ffi_panic, try_ffi};
use crate::store::text_fragments::TEXT_FRAGMENT_DST;
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

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTextFragmentStoreResult {
    pub success: bool,
    pub fragment_hash_hex: Option<String>,
    pub fragment_id: i64,
    pub error_message: Option<String>,
}

impl FfiTextFragmentStoreResult {
    fn ok(hash_hex: String, id: i64) -> Self {
        Self {
            success: true,
            fragment_hash_hex: Some(hash_hex),
            fragment_id: id,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            fragment_hash_hex: None,
            fragment_id: -1,
            error_message: Some(msg.into()),
        }
    }
}

crate::ffi::types::impl_ffi_err!(FfiTextFragmentStoreResult);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPasteRecordResult {
    pub success: bool,
    pub text_hash_hex: Option<String>,
    pub matched_existing: bool,
    pub matched_session_id: Option<String>,
    pub content_kind: Option<String>,
    pub error_message: Option<String>,
}

impl FfiPasteRecordResult {
    fn ok(hash_hex: String, matched_session_id: Option<String>, content_kind: &str) -> Self {
        Self {
            success: true,
            text_hash_hex: Some(hash_hex),
            matched_existing: matched_session_id.is_some(),
            matched_session_id,
            content_kind: Some(content_kind.to_string()),
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            text_hash_hex: None,
            matched_existing: false,
            matched_session_id: None,
            content_kind: None,
            error_message: Some(msg.into()),
        }
    }
}

crate::ffi::types::impl_ffi_err!(FfiPasteRecordResult);

#[derive(Debug, Clone, Default)]
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

crate::ffi::types::impl_ffi_err!(FfiAttestTextResult);

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

pub(crate) fn hash_text(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Normalize text for attestation hashing: NFC-normalize, keep only Unicode
/// letters + ASCII digits, lowercase everything. Resilient to formatting
/// changes across platforms, apps, and sharing contexts.
pub fn normalize_for_attestation(text: &str) -> String {
    // Lowercase first, then NFC again (to recombine chars that decompose
    // during lowercasing, e.g. İ → i+U+0307), then filter. This order
    // ensures idempotence — running the function twice yields the same
    // result. Both Rust and TS implementations must use this exact order.
    let lowered: String = text.nfc().flat_map(|c| c.to_lowercase()).collect();
    lowered
        .nfc()
        .filter(|c| c.is_alphabetic() || c.is_ascii_digit())
        .collect()
}

/// Hash text after normalization. Returns `(normalized, hash)` to avoid
/// recomputing the normalization.
fn hash_normalized_text(text: &str) -> (String, [u8; 32]) {
    let normalized = normalize_for_attestation(text);
    let hash = Sha256::digest(normalized.as_bytes()).into();
    (normalized, hash)
}

pub(crate) use crate::store::text_fragments::{
    current_timestamp_ms, generate_nonce, sign_fragment,
};

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
    catch_ffi_panic!(@err FfiTextFragmentStoreResult, {
    log::debug!("ffi_text_fragment_store: session_id={}, app_bundle_id={}", session_id, app_bundle_id);
    const MAX_TEXT_SIZE: usize = 10 * 1024 * 1024;
    if text_content.is_empty() {
        return FfiTextFragmentStoreResult::err("Text content is empty");
    }
    if text_content.len() > MAX_TEXT_SIZE {
        return FfiTextFragmentStoreResult::err(format!(
            "Text too large: {} bytes (max {MAX_TEXT_SIZE})",
            text_content.len()
        ));
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

    let signing_key = try_ffi!(
        load_signing_key().map_err(|e| format!("Signing key unavailable: {e}")),
        FfiTextFragmentStoreResult
    );

    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);
    drop(signing_key);

    let fragment = TextFragment {
        source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        source_window_title: Some(window_title).filter(|s| !s.is_empty()),
        keystroke_context: Some(context),
        keystroke_confidence: Some(confidence),
        ..TextFragment::new(fragment_hash.to_vec(), session_id, signature.to_vec(), nonce.to_vec(), timestamp)
    };

    let mut store = try_ffi!(open_store(), FfiTextFragmentStoreResult);

    match store.insert_text_fragment(&fragment) {
        Ok(id) => FfiTextFragmentStoreResult::ok(hex::encode(fragment_hash), id),
        Err(e) => FfiTextFragmentStoreResult::err(format!("Failed to store fragment: {e}")),
    }
    })
}

/// Look up a text fragment by its hex-encoded SHA-256 hash.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_lookup(fragment_hash_hex: String) -> Option<FfiTextFragment> {
    catch_ffi_panic!(None, {
    log::debug!("ffi_text_fragment_lookup: fragment_hash_hex={}", fragment_hash_hex);
    let hash_bytes = match crate::utils::crypto_types::HexHash::from_hex(&fragment_hash_hex) {
        Ok(h) => h.0,
        Err(_) => {
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
    })
}

/// Get all text fragments for a session, ordered by timestamp.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_list_for_session(session_id: String) -> Vec<FfiTextFragment> {
    catch_ffi_panic!(vec![], {
    log::debug!("ffi_text_fragment_list_for_session: session_id={}", session_id);
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
    })
}

/// Record a paste event with full text content for evidence tracking.
///
/// Replaces `ffi_sentinel_notify_paste`. Swift passes the pasted text, which
/// is hashed (SHA-256) and checked against existing fragments. The sentinel's
/// paste-char counter and keystroke context window are also updated.
///
/// Record that the user skipped a mandatory paste checkpoint.
///
/// Increments a per-session counter that is surfaced as a flag in the
/// forensic report. The skip does not block witnessing but reduces
/// evidence integrity since the pasted content is undocumented.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_record_paste_checkpoint_skipped() -> bool {
    use crate::ffi::types::catch_ffi_panic;
    catch_ffi_panic!(false, {
    let sentinel = match super::sentinel::get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };
    use crate::RwLockRecover as _;
    let focus = sentinel.current_focus()
        .or_else(|| sentinel.targeted_path());
    if let Some(ref path) = focus {
        let mut sessions = sentinel.sessions.write_recover();
        if let Some(session) = sessions.get_mut(path.as_str()) {
            session.paste_checkpoint_skips = session.paste_checkpoint_skips.saturating_add(1);
            log::info!(
                "Paste checkpoint skipped for {:?} (total skips: {})",
                path, session.paste_checkpoint_skips
            );
            return true;
        }
    }
    false
    })
}

/// The pasted text itself is NOT stored — only the hash.
///
/// **Caller contract**: Swift must check `pasted_text.utf8.count <= 10_485_760`
/// Record a cross-window transcription match detected by the Swift-side
/// `CrossWindowDetector`. Inserts a `CrossWindowMatch` into the focused
/// session's transcription detector so the live score immediately reflects it.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_cross_window_match(
    source_app: String,
    source_window_title: String,
    similarity_score: f64,
    matched_length: u32,
) -> bool {
    use crate::RwLockRecover as _;

    const MAX_STRING_LEN: usize = 1024;
    let source_app: String = source_app.chars().take(MAX_STRING_LEN).collect();
    let source_window_title: String =
        source_window_title.chars().take(MAX_STRING_LEN).collect();

    let sentinel = match super::sentinel::get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };
    let focus = sentinel.current_focus();
    let Some(ref path) = focus else { return false };

    let m = crate::transcription::CrossWindowMatch {
        source_app,
        source_window_title,
        similarity_score: similarity_score.clamp(0.0, 1.0),
        matched_length: matched_length as usize,
        detected_at: chrono::Utc::now(),
    };

    let mut sessions = sentinel.sessions.write_recover();
    if let Some(session) = sessions.get_mut(path.as_str()) {
        session.transcription_detector.matches_mut().push(m);
        true
    } else {
        false
    }
}

/// (10 MiB) before calling this function. UniFFI allocates the full String
/// before any Rust-side size check runs, so oversized pastes allocate memory
/// regardless of the guard below.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_record_paste(
    char_count: i64,
    pasted_text: String,
    timestamp_ns: i64,
    app_bundle_id: String,
    window_title: String,
    detection_confidence: f64,
    has_plain_text: bool,
    has_rtf: bool,
    has_html: bool,
    has_image: bool,
    has_spreadsheet: bool,
) -> FfiPasteRecordResult {
    catch_ffi_panic!(@err FfiPasteRecordResult, {
    super::types::run_on_stack(move || {
    use crate::RwLockRecover as _;
    log::debug!("ffi_sentinel_record_paste: char_count={}, app_bundle_id={}", char_count, app_bundle_id);
    if char_count < 0 {
        return FfiPasteRecordResult::err("char_count must be non-negative");
    }
    if timestamp_ns <= 0 {
        return FfiPasteRecordResult::err("timestamp_ns must be positive");
    }
    if !detection_confidence.is_finite() {
        return FfiPasteRecordResult::err("detection_confidence must be a finite number");
    }
    // F-001: Bound pasted text to 10 MB to prevent memory exhaustion.
    const MAX_PASTE_SIZE: usize = 10 * 1024 * 1024;
    if pasted_text.len() > MAX_PASTE_SIZE {
        return FfiPasteRecordResult::err(format!(
            "Pasted text too large: {} bytes (max {MAX_PASTE_SIZE})",
            pasted_text.len()
        ));
    }

    let sentinel = match super::sentinel::get_running_sentinel() {
        Some(s) => s,
        None => return FfiPasteRecordResult::err("Sentinel not running"),
    };
    sentinel.set_last_paste_chars(char_count);

    let text_hash = hash_text(&pasted_text);
    let text_hash_hex = hex::encode(text_hash);

    let inventory = crate::sentinel::types::PasteboardTypeInventory {
        utis: Vec::new(),
        has_plain_text,
        has_rtf,
        has_html,
        has_image,
        has_spreadsheet,
    };
    let content_kind = crate::sentinel::content_classifier::classify_paste_content_kind(
        &pasted_text,
        &inventory,
    );
    let content_kind_str = content_kind.to_string();

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiPasteRecordResult::err(format!(
                "Cannot open store for paste recording: {e}"
            ));
        }
    };

    let matched_session_id = match store.lookup_fragment_by_hash(&text_hash) {
        Ok(Some(f)) => Some(f.session_id),
        Ok(None) => None,
        Err(e) => {
            log::error!("ffi_record_paste: DB lookup failed: {e}");
            None
        }
    };

    let focus = sentinel.current_focus();
    if let Some(ref focused_path) = focus {
        if let Ok(session) = sentinel.session(focused_path) {
            let signing_key = match load_signing_key() {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("Cannot sign paste fragment: {e}");
                    return FfiPasteRecordResult::ok(text_hash_hex, matched_session_id, &content_kind_str);
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
                source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
                source_window_title: Some(window_title).filter(|s| !s.is_empty()),
                keystroke_context: Some(KeystrokeContext::PastedContent),
                keystroke_confidence: Some(detection_confidence.clamp(0.0, 1.0)),
                source_session_id: matched_session_id.clone(),
                ..TextFragment::new(text_hash.to_vec(), session.session_id.clone(), signature.to_vec(), nonce.to_vec(), timestamp_ms)
            };

            if let Err(e) = store.insert_text_fragment(&fragment) {
                let msg = e.to_string();
                if msg.contains("UNIQUE constraint") {
                    log::debug!("Paste fragment already stored (duplicate hash)");
                } else {
                    log::warn!("Failed to store paste fragment: {e}");
                }
            }

            let source = crate::sentinel::helpers::classify_paste_source(
                Some(&store),
                &text_hash,
                &session.session_id,
            );
            drop(store);
            {
                let mut sessions_guard = sentinel.sessions.write_recover();
                if let Some(s) = sessions_guard.get_mut(focused_path) {
                    crate::sentinel::helpers::update_keystroke_context_window(
                        s,
                        timestamp_ns,
                        30_000,
                        source,
                        content_kind,
                        char_count.max(0) as usize,
                    );
                }
            }
        }
    }

    FfiPasteRecordResult::ok(text_hash_hex, matched_session_id, &content_kind_str)
    })
    })
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
    catch_ffi_panic!(@err FfiAttestTextResult, {
    log::debug!("ffi_attest_text: app_bundle_id={}, text_len={}", app_bundle_id, text_content.len());
    const MAX_ATTEST_TEXT_SIZE: usize = 10 * 1024 * 1024;
    if text_content.len() > MAX_ATTEST_TEXT_SIZE {
        return FfiAttestTextResult::err(format!(
            "Text too large: {} bytes (max {MAX_ATTEST_TEXT_SIZE})",
            text_content.len()
        ));
    }
    let (normalized, fragment_hash) = hash_normalized_text(&text_content);
    if normalized.is_empty() {
        return FfiAttestTextResult::err("No attestable content after normalization");
    }
    const MIN_ATTEST_TEXT_CHARS: usize = 50;
    if normalized.len() < MIN_ATTEST_TEXT_CHARS {
        return FfiAttestTextResult::err(format!(
            "Text too short for attestation ({} chars, minimum {MIN_ATTEST_TEXT_CHARS} after normalization)",
            normalized.len()
        ));
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
                .filter(|sess| sess.app_bundle_id == app_bundle_id && sess.keystroke_count > 0)
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

    let signing_key = try_ffi!(
        load_signing_key().map_err(|e| format!("Signing key unavailable: {e}")),
        FfiAttestTextResult
    );

    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);

    // Build compact VC signature over the attestation claim.
    // Includes nonce for replay resistance.
    let nonce_hex = hex::encode(nonce);
    let author_did = crate::identity::did_key_from_public(
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap_or_default();
    let vc_claim = format!("{tier}:{fragment_hash_hex}:{timestamp_iso}:{nonce_hex}:{author_did}");
    let vc_sig = {
        use ed25519_dalek::Signer;
        let mut vc_payload = Vec::with_capacity(25 + vc_claim.len());
        vc_payload.extend_from_slice(b"witnessd-vc-attest-v1:");
        vc_payload.extend_from_slice(vc_claim.as_bytes());
        let sig = signing_key.sign(&vc_payload);
        hex::encode(sig.to_bytes())
    };
    drop(signing_key);

    let fragment = TextFragment {
        source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        source_window_title: Some(window_title).filter(|s| !s.is_empty()),
        ..TextFragment::new(fragment_hash.to_vec(), session_id, signature.to_vec(), nonce.to_vec(), timestamp)
    };

    let mut store = try_ffi!(open_store(), FfiAttestTextResult);

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
         VC-Sig: f{vc_sig}\n\
         verify.writersproof.com"
    );

    FfiAttestTextResult::ok(
        tier.to_string(),
        fragment_hash_hex,
        writersproof_id,
        attestation_text,
    )
    })
}

/// Embed a C2PA manifest into text content using invisible Unicode Variation
/// Selectors per the C2PA "Embedding Manifests into Unstructured Text" spec.
///
/// Builds an evidence packet + C2PA manifest + VC for the text, then encodes
/// the JUMBF as a `C2PATextManifestWrapper` appended to the text. The wrapper
/// is visually invisible but carries full provenance.
///
/// Returns the text with the embedded wrapper appended, or an error.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_embed_text_manifest(
    text_content: String,
    app_bundle_id: String,
    window_title: String,
) -> FfiAttestTextResult {
    catch_ffi_panic!(@err FfiAttestTextResult, {
    log::debug!(
        "ffi_embed_text_manifest: app_bundle_id={}, text_len={}",
        app_bundle_id,
        text_content.len()
    );

    const MAX_TEXT_SIZE: usize = 10 * 1024 * 1024;
    if text_content.len() > MAX_TEXT_SIZE {
        return FfiAttestTextResult::err(format!(
            "Text too large: {} bytes (max {MAX_TEXT_SIZE})",
            text_content.len()
        ));
    }

    // First, run the standard attestation to get tier, hash, signature.
    let attest_result = ffi_attest_text(
        text_content.clone(),
        app_bundle_id,
        window_title,
    );
    if !attest_result.success {
        return attest_result;
    }

    // Build a minimal C2PA JUMBF manifest for the text content.
    let signing_key = match load_signing_key() {
        Ok(sk) => sk,
        Err(e) => return FfiAttestTextResult::err(format!("Signing key unavailable: {e}")),
    };

    // NFC-normalize the text before hashing (per C2PA spec).
    let normalized: String = text_content.nfc().collect();
    let text_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.finalize().into()
    };

    // Build a minimal evidence packet for the text.
    let evidence_packet = authorproof_protocol::rfc::EvidencePacket {
        version: 1,
        profile_uri: crate::war::ear::CPOE_EVIDENCE_PROFILE.to_string(),
        packet_id: attest_result.fragment_hash_hex.as_bytes().iter().copied().take(16).collect(),
        created: current_timestamp_ms() as u64,
        document: authorproof_protocol::rfc::DocumentRef {
            content_hash: authorproof_protocol::rfc::HashValue {
                algorithm: authorproof_protocol::rfc::HashAlgorithm::Sha256,
                digest: text_hash.to_vec(),
            },
            filename: None,
            byte_length: normalized.len() as u64,
            char_count: normalized.chars().count() as u64,
        },
        checkpoints: Vec::new(),
        attestation_tier: match attest_result.tier.as_str() {
            "verified" => Some(authorproof_protocol::rfc::AttestationTier::HardwareBound),
            "corroborated" => Some(authorproof_protocol::rfc::AttestationTier::AttestedSoftware),
            _ => Some(authorproof_protocol::rfc::AttestationTier::SoftwareOnly),
        },
        baseline_verification: None,
    };

    let evidence_cbor = {
        let mut buf = Vec::new();
        match ciborium::ser::into_writer(&evidence_packet, &mut buf) {
            Ok(()) => buf,
            Err(e) => return FfiAttestTextResult::err(format!("CBOR encoding failed: {e}")),
        }
    };

    let mut builder = authorproof_protocol::c2pa::C2paManifestBuilder::new(
        evidence_packet,
        evidence_cbor,
        text_hash,
    );

    if let Ok(cert_der) = crate::ffi::helpers::load_or_generate_cert(&signing_key) {
        builder = builder.cert_der(cert_der);
    }

    let jumbf = match builder.build_jumbf(&signing_key) {
        Ok(j) => j,
        Err(e) => return FfiAttestTextResult::err(format!("Failed to build C2PA manifest: {e}")),
    };

    // Encode the JUMBF as invisible variation selectors appended to the text.
    let (wrapper, _exclusion_len) = authorproof_protocol::c2pa::text_embed::encode_text_manifest(&jumbf);
    let embedded_text = format!("{text_content}{wrapper}");

    FfiAttestTextResult::ok(
        attest_result.tier,
        attest_result.fragment_hash_hex,
        attest_result.writersproof_id,
        embedded_text,
    )
    })
}

/// Store a text attestation locally from a pre-computed content hash.
///
/// Used by the native messaging host where the browser has already hashed the
/// text. Signs the hash with the device key and inserts a TextFragment record.
pub fn store_attestation_from_hash(content_hash: &str, app_bundle_id: &str) -> Result<(), String> {
    let hash_bytes = crate::utils::crypto_types::HexHash::from_hex(content_hash)
        .map_err(|e| format!("Invalid content_hash hex: {e}"))?
        .0
        .to_vec();

    let session_id = generate_ephemeral_session_id();
    let timestamp = current_timestamp_ms();
    if timestamp <= 0 {
        return Err("System clock error".into());
    }
    let nonce = generate_nonce();

    let signing_key = load_signing_key().map_err(|e| format!("Signing key unavailable: {e}"))?;

    let mut fragment_hash = [0u8; 32];
    fragment_hash.copy_from_slice(&hash_bytes);
    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);
    drop(signing_key);

    let fragment = TextFragment {
        source_app_bundle_id: Some(app_bundle_id.to_string()).filter(|s| !s.is_empty()),
        ..TextFragment::new(hash_bytes, session_id, signature.to_vec(), nonce.to_vec(), timestamp)
    };

    let mut store = open_store().map_err(|e| e.to_string())?;
    store
        .insert_text_fragment(&fragment)
        .map_err(|e| format!("Failed to store attestation: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CloudKit sync FFI functions
// ---------------------------------------------------------------------------

/// FFI result for sync operations that return a boolean success/failure.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSyncResult {
    pub success: bool,
    pub error_message: Option<String>,
}

impl FfiSyncResult {
    fn ok() -> Self {
        Self {
            success: true,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            error_message: Some(msg.into()),
        }
    }
}

crate::ffi::types::impl_ffi_err!(FfiSyncResult);

/// Mark a fragment as pending sync to CloudKit.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_mark_fragment_for_sync(fragment_id: i64) -> FfiSyncResult {
    catch_ffi_panic!(@err FfiSyncResult, {
    log::debug!("ffi_mark_fragment_for_sync: fragment_id={}", fragment_id);
    let store = try_ffi!(open_store(), FfiSyncResult);

    match store.mark_fragment_for_sync(fragment_id) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(format!("Failed to mark for sync: {e}")),
    }
    })
}

/// Update a fragment's sync state with optional CloudKit record ID.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_update_fragment_sync_state(
    fragment_id: i64,
    state: String,
    cloudkit_record_id: Option<String>,
) -> FfiSyncResult {
    catch_ffi_panic!(@err FfiSyncResult, {
    log::debug!("ffi_update_fragment_sync_state: fragment_id={}, state={}", fragment_id, state);
    let store = try_ffi!(open_store(), FfiSyncResult);

    const VALID_STATES: &[&str] = &["pending", "syncing", "synced", "failed", "conflict"];
    if !VALID_STATES.contains(&state.as_str()) {
        return FfiSyncResult::err(format!("Invalid sync state: {state}"));
    }

    match store.update_fragment_sync_state(fragment_id, &state, cloudkit_record_id.as_deref()) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(format!("Failed to update sync state: {e}")),
    }
    })
}

/// Get count of fragments pending sync to CloudKit.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_pending_sync_count() -> i64 {
    catch_ffi_panic!(-1, {
    log::debug!("ffi_get_pending_sync_count");
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_get_pending_sync_count: failed to open store: {e}");
            return -1;
        }
    };

    match store.get_pending_sync_count() {
        Ok(count) => count,
        Err(e) => {
            log::warn!("ffi_get_pending_sync_count: query failed: {e}");
            -1
        }
    }
    })
}

/// Apply a remotely synced fragment received from CloudKit.
///
/// Verifies the Ed25519 signature over the domain-tagged payload before
/// storing, preventing injection of forged fragments via compromised sync.
#[allow(clippy::too_many_arguments)]
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
    catch_ffi_panic!(@err FfiTextFragmentStoreResult, {
    log::debug!("ffi_apply_remote_fragment: session_id={}, fragment_hash_hex={}", session_id, fragment_hash_hex);
    if timestamp_ms <= 0 {
        return FfiTextFragmentStoreResult::err("timestamp_ms must be positive");
    }

    let fragment_hash = match crate::utils::crypto_types::HexHash::from_hex(&fragment_hash_hex) {
        Ok(h) => h.0.to_vec(),
        Err(_) => {
            return FfiTextFragmentStoreResult::err(
                "fragment_hash_hex must be 64 hex chars (32 bytes)",
            )
        }
    };
    let source_signature =
        match crate::utils::crypto_types::Ed25519Sig::from_hex(&source_signature_hex) {
            Ok(s) => s,
            _ => {
                return FfiTextFragmentStoreResult::err(
                    "source_signature_hex must be 128 hex chars (64 bytes)",
                )
            }
        };
    let nonce = match hex::decode(&nonce_hex) {
        Ok(b) if b.len() == 16 => b,
        _ => return FfiTextFragmentStoreResult::err("nonce_hex must be 32 hex chars (16 bytes)"),
    };

    // Verify signature before accepting remote fragment.
    let pubkey = match crate::utils::crypto_types::Ed25519Pubkey::from_hex(&signing_public_key_hex)
    {
        Ok(pk) => pk,
        _ => {
            return FfiTextFragmentStoreResult::err(
                "signing_public_key_hex must be 64 hex chars (32 bytes)",
            )
        }
    };
    {
        use ed25519_dalek::Verifier;
        let vk = match pubkey.to_verifying_key() {
            Ok(k) => k,
            Err(e) => return FfiTextFragmentStoreResult::err(format!("Invalid public key: {e}")),
        };
        let sig = source_signature.to_signature();
        // Reconstruct the domain-tagged payload that was signed.
        let dst = TEXT_FRAGMENT_DST;
        let sid_len = (session_id.len() as u32).to_le_bytes();
        let mut payload = Vec::with_capacity(dst.len() + 4 + session_id.len() + 32 + 8 + 16);
        payload.extend_from_slice(dst);
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
        source_app_bundle_id,
        source_window_title,
        keystroke_context: context,
        keystroke_confidence: confidence,
        cloudkit_record_id,
        sync_state: Some("synced".to_string()),
        ..TextFragment::new(fragment_hash.clone(), session_id, source_signature.0.to_vec(), nonce, timestamp_ms)
    };

    let mut store = try_ffi!(open_store(), FfiTextFragmentStoreResult);

    match store.apply_remote_fragment(&fragment) {
        Ok(id) => FfiTextFragmentStoreResult::ok(hex::encode(&fragment_hash), id),
        Err(e) => FfiTextFragmentStoreResult::err(format!("Failed to apply remote fragment: {e}")),
    }
    })
}

/// Resolve a sync conflict for a fragment.
///
/// `strategy`: "keep_local", "keep_remote", or "keep_newest".
/// Remote fragment fields are required for "keep_remote"/"keep_newest".
#[allow(clippy::too_many_arguments)]
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
    remote_signing_public_key_hex: Option<String>,
) -> FfiSyncResult {
    catch_ffi_panic!(@err FfiSyncResult, {
    log::debug!("ffi_resolve_sync_conflict: fragment_id={}, strategy={}", fragment_id, strategy);
    use crate::store::text_fragments::SyncResolutionStrategy;

    let strat = match strategy.as_str() {
        "keep_local" => SyncResolutionStrategy::KeepLocal,
        "keep_remote" => SyncResolutionStrategy::KeepRemote,
        "keep_newest" => SyncResolutionStrategy::KeepNewest,
        _ => {
            return FfiSyncResult::err(format!(
                "Invalid strategy '{strategy}'; \
             expected keep_local, keep_remote, or keep_newest"
            ))
        }
    };

    let remote_fragment = if strat != SyncResolutionStrategy::KeepLocal {
        let hash = match remote_fragment_hash_hex.as_deref().map(crate::utils::crypto_types::HexHash::from_hex) {
            Some(Ok(h)) => h.0.to_vec(),
            _ => return FfiSyncResult::err("Remote fragment hash required"),
        };
        let sig = match remote_signature_hex.as_deref().map(crate::utils::crypto_types::Ed25519Sig::from_hex) {
            Some(Ok(s)) => s.0.to_vec(),
            _ => return FfiSyncResult::err("Remote signature required"),
        };
        let nonce = match remote_nonce_hex.as_deref().map(hex::decode) {
            Some(Ok(b)) if b.len() == 16 => b,
            _ => return FfiSyncResult::err("Remote nonce required"),
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
            cloudkit_record_id: remote_cloudkit_record_id,
            ..TextFragment::new(hash, sid, sig, nonce, ts)
        })
    } else {
        None
    };

    let mut store = try_ffi!(open_store(), FfiSyncResult);

    // Verify remote fragment signature before accepting it
    if let Some(ref frag) = remote_fragment {
        let hash_arr: &[u8; 32] = match frag.fragment_hash.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return FfiSyncResult::err(format!(
                "fragment_hash length {} != 32",
                frag.fragment_hash.len()
            )),
        };
        let sig_arr: &[u8; 64] = match frag.source_signature.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return FfiSyncResult::err(format!(
                "source_signature length {} != 64",
                frag.source_signature.len()
            )),
        };
        let pub_bytes = match remote_signing_public_key_hex.as_deref() {
            Some(hex_str) => {
                match crate::utils::crypto_types::Ed25519Pubkey::from_hex(hex_str) {
                    Ok(pk) => pk.0,
                    _ => return FfiSyncResult::err(
                        "remote_signing_public_key_hex must be 64 hex chars (32 bytes)",
                    ),
                }
            }
            None => return FfiSyncResult::err(
                "remote_signing_public_key_hex is required to verify remote fragment signature",
            ),
        };
        match store.verify_fragment_signature(
            hash_arr,
            &frag.nonce,
            frag.timestamp,
            &frag.session_id,
            sig_arr,
            &pub_bytes,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return FfiSyncResult::err("Remote fragment signature verification failed")
            }
            Err(e) => return FfiSyncResult::err(format!("Signature verification error: {e}")),
        }
    }

    match store.resolve_sync_conflict(fragment_id, strat, remote_fragment.as_ref()) {
        Ok(()) => FfiSyncResult::ok(),
        Err(e) => FfiSyncResult::err(format!("Failed to resolve conflict: {e}")),
    }
    })
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
        assert_eq!(
            normalize_for_attestation("caf\u{00e9} r\u{00e9}sum\u{00e9}"),
            "caf\u{00e9}r\u{00e9}sum\u{00e9}"
        );
    }

    #[test]
    fn test_normalize_nfc_nfd_equivalence() {
        let nfc = "caf\u{00e9}"; // precomposed é
        let nfd = "cafe\u{0301}"; // e + combining acute
        assert_eq!(
            normalize_for_attestation(nfc),
            normalize_for_attestation(nfd),
        );
    }

    #[test]
    fn test_normalize_digits() {
        assert_eq!(
            normalize_for_attestation("I wrote 5 chapters"),
            "iwrote5chapters"
        );
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

    // -- Cross-platform parity tests (must match TS normalizeForAttestation) --

    #[test]
    fn test_normalize_roman_numerals_kept() {
        // U+2160 (Nl category) — is_alphabetic() = true, lowercases to U+2170
        assert_eq!(
            normalize_for_attestation("Chapter\u{2160}"),
            "chapter\u{2170}"
        );
    }

    #[test]
    fn test_normalize_arabic_superscript_alef() {
        // U+0670 — Other_Alphabetic, is_alphabetic() = true
        assert_eq!(
            normalize_for_attestation("\u{0627}\u{0670}"),
            "\u{0627}\u{0670}"
        );
    }

    #[test]
    fn test_normalize_combining_grave_stripped() {
        // U+0300 — combining mark, NOT alphabetic, stripped
        assert_eq!(normalize_for_attestation("a\u{0300}b"), "àb");
        // NFC merges a+U+0300 → à, then à is alphabetic → kept
    }

    #[test]
    fn test_normalize_orphan_combining_mark_stripped() {
        // Standalone U+0301 without preceding base — not alphabetic
        assert_eq!(normalize_for_attestation("\u{0301}"), "");
    }

    #[test]
    fn test_normalize_turkish_i_dot() {
        // İ (U+0130) → lowercase → 'i' + U+0307, second NFC keeps them
        // separate (no precomposed form), filter strips U+0307 → 'i'.
        assert_eq!(normalize_for_attestation("\u{0130}"), "i");
    }

    #[test]
    fn test_normalize_turkish_istanbul_idempotent() {
        let once = normalize_for_attestation("\u{0130}stanbul");
        let twice = normalize_for_attestation(&once);
        assert_eq!(once, "istanbul");
        assert_eq!(once, twice);
    }

    #[test]
    fn test_normalize_sharp_s() {
        // ẞ (U+1E9E) lowercases to ß (U+00DF)
        assert_eq!(normalize_for_attestation("\u{1E9E}"), "\u{00DF}");
    }

    #[test]
    fn test_normalize_ligature_fi() {
        // ﬁ (U+FB01) — stays as ligature in NFC, is alphabetic
        assert_eq!(normalize_for_attestation("\u{FB01}"), "\u{FB01}");
    }

    #[test]
    fn test_normalize_fullwidth_digit_stripped() {
        // ５ (U+FF15) — NOT is_ascii_digit(), stripped
        assert_eq!(normalize_for_attestation("test\u{FF15}"), "test");
    }

    #[test]
    fn test_normalize_emoji_stripped() {
        assert_eq!(
            normalize_for_attestation("I \u{2764}\u{FE0F} writing"),
            "iwriting"
        );
    }

    #[test]
    fn test_normalize_idempotent() {
        let input = "Hello, World! café 写作 5";
        let once = normalize_for_attestation(input);
        let twice = normalize_for_attestation(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_normalize_cross_platform_hash_helloworld() {
        // Reference hash shared with TS tests
        let (_, hash) = hash_normalized_text("Hello, World!");
        assert_eq!(
            hex::encode(hash),
            "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
        );
    }

    #[test]
    fn test_normalize_cross_platform_hash_cafe() {
        let (_, h1) = hash_normalized_text("café résumé");
        assert_eq!(
            hex::encode(h1),
            "c4bc0b6f3d833fa42940859cc9721c284bc847442d35eb425eb8168196fa5c76"
        );
    }

    #[test]
    fn test_normalize_cross_platform_hash_cjk() {
        let (_, hash) = hash_normalized_text("写作 证明");
        assert_eq!(
            hex::encode(hash),
            "aa701320ed4fb3e8c8d478c6a92f5aee53a50bc3d4c1adf8dac226f554923f55"
        );
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
        std::env::set_var("CPOE_DATA_DIR", tmp.to_str().expect("test temp dir path must be valid UTF-8"));
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
        assert!(result
            .fragment_hash_hex
            .starts_with(&result.writersproof_id));
        assert!(result.attestation_text.contains("WritersProof Declared"));
        assert!(result.attestation_text.contains("verify.writersproof.com"));
        assert!(result.attestation_text.contains(&result.writersproof_id));

        // Verify the stored fragment is retrievable by hash.
        let lookup = ffi_text_fragment_lookup(result.fragment_hash_hex.clone());
        assert!(
            lookup.is_some(),
            "stored attestation fragment not found by hash"
        );
        let frag = lookup.unwrap();
        assert_eq!(frag.fragment_hash_hex, result.fragment_hash_hex);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
