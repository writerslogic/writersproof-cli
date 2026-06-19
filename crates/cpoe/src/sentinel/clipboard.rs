// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Clipboard interception and text fragment evidence generation.
//!
//! Monitors clipboard for copy events and generates evidence packets for pasted text
//! that matches text fragments from active sessions. Supports macOS NSPasteboard
//! with platform-specific implementations.
//!
//! # Architecture
//! - Polling-based pasteboard monitoring (100ms interval)
//! - Async broadcast channel for evidence events
//! - Deduplication via change count and timestamp throttling
//! - Text validation (size, encoding, content filters)
//! - App filtering (only monitored apps)
//!
//! # Evidence Attachment
//! When copied text matches a fragment in an active session:
//! 1. Build evidence packet with keystroke confidence
//! 2. Sign with COSE_Sign1 (Ed25519)
//! 3. Write to pasteboard as "com.writersproof.evidence"
//! 4. Emit EvidenceEvent to broadcast channel

use crate::error::Error;
use crate::sentinel::types::{DocumentSession, PasteContentKind, PasteboardTypeInventory};
use crate::utils::crypto_helpers;
use crate::utils::DateTimeNanosExt;
use crate::{MutexRecover, RwLockRecover};
use chrono::Utc;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

/// Maximum clipboard text size (1MB).
const MAX_CLIPBOARD_TEXT_SIZE: usize = 1_000_000;

/// Minimum time between copy events (100ms debounce).
const CLIPBOARD_DEBOUNCE_MS: u64 = 100;

/// Maximum monitored apps to prevent resource exhaustion.
const MAX_MONITORED_APPS: usize = 50;

use crate::forensics::constants::KNOWN_AI_APP_BUNDLE_IDS;

/// Default monitored applications (writing apps).
fn default_monitored_apps() -> Vec<String> {
    vec![
        "com.apple.Notes".to_string(),
        "com.apple.iWork.Pages".to_string(),
        "com.microsoft.Word".to_string(),
        "com.ulyssesapp.mac".to_string(),
        "com.literatureandlatte.scrivener3".to_string(),
        "net.shinyfrog.bear".to_string(),
        "com.bloombuilt.dayone-mac".to_string(),
        "md.obsidian".to_string(),
    ]
}

/// Clipboard monitoring errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClipboardError {
    /// NSPasteboard access denied (macOS only).
    #[error("Pasteboard access denied")]
    PasteboardAccessDenied,
    /// Text encoding failed (non-UTF8 content).
    #[error("Text encoding failed")]
    TextEncodingFailed,
    /// Clipboard data is invalid or corrupted.
    #[error("Invalid pasteboard data")]
    InvalidPasteboardData,
    /// No monitored app is in focus.
    #[error("No monitored app in focus")]
    NoMonitoredAppInFocus,
    /// Text fragment not found in store.
    #[error("Text fragment not found")]
    NoFragmentFound,
    /// Session not active or not found.
    #[error("Session not active")]
    SessionNotActive,
    /// Evidence serialization failed.
    #[error("Evidence serialization failed")]
    EvidenceSerializationFailed,
    /// Monitoring limit exceeded (max apps).
    #[error("Monitoring limit exceeded")]
    MonitoringLimitExceeded,
    /// Generic error with context.
    #[error("{0}")]
    Other(String),
}

impl From<ClipboardError> for crate::error::Error {
    fn from(e: ClipboardError) -> Self {
        crate::error::Error::Platform(e.to_string())
    }
}

/// Copy event captured from clipboard.
#[derive(Debug, Clone)]
pub struct CopyEvent {
    /// Milliseconds since UNIX epoch.
    pub timestamp: i64,
    /// App bundle ID (e.g., "com.apple.Notes").
    pub app_bundle_id: String,
    /// Active window title.
    pub window_title: String,
    /// Copied text (up to 1MB).
    pub text: String,
    /// SHA256 hash of copied text.
    pub text_hash: [u8; 32],
    /// macOS NSPasteboard change counter for deduplication.
    pub pasteboard_change_count: i32,
    /// Semantic type of the clipboard content.
    pub content_kind: PasteContentKind,
    /// Pasteboard types present at capture time.
    pub pasteboard_types: PasteboardTypeInventory,
}

/// Evidence event for async broadcast to other subscribers.
#[derive(Debug, Clone)]
pub struct EvidenceEvent {
    /// SHA256 hash of text fragment.
    pub fragment_hash: [u8; 32],
    /// Evidence packet (signed).
    pub evidence: Vec<u8>,
    /// Source app bundle ID.
    pub source_app: String,
    /// Timestamp (nanos).
    pub timestamp: i64,
    /// True when the paste originated from a known AI assistant application.
    pub from_ai_tool: bool,
    /// Semantic type of the pasted content.
    pub content_kind: PasteContentKind,
}

/// Returns `true` if the given bundle ID matches a known AI assistant app.
pub fn is_ai_tool_bundle_id(bundle_id: &str) -> bool {
    KNOWN_AI_APP_BUNDLE_IDS.contains(&bundle_id)
}

/// Clipboard monitor for detecting copy events and generating evidence.
#[derive(Debug)]
pub struct ClipboardMonitor {
    /// Monitored app bundle IDs (protected by RwLock).
    monitored_apps: Arc<RwLock<Vec<String>>>,
    /// Last recorded pasteboard change count (atomic for lock-free dedup).
    last_change_count: Arc<std::sync::atomic::AtomicI32>,
    /// Timestamp of last copy event in millis (atomic for lock-free debounce).
    last_copy_time: Arc<std::sync::atomic::AtomicI64>,
    /// Broadcast sender for evidence events.
    pending_evidence_tx: broadcast::Sender<EvidenceEvent>,
}

impl ClipboardMonitor {
    /// Initialize clipboard monitor with default monitored apps.
    ///
    /// Returns an error only if initialization fails critically.
    /// Safe to call multiple times.
    pub fn new() -> std::result::Result<Self, ClipboardError> {
        log::debug!("ClipboardMonitor::new");
        Ok(ClipboardMonitor {
            monitored_apps: Arc::new(RwLock::new(default_monitored_apps())),
            last_change_count: Arc::new(std::sync::atomic::AtomicI32::new(0)),
            last_copy_time: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            pending_evidence_tx: broadcast::channel(100).0,
        })
    }

    /// Add an app bundle ID to the monitoring list.
    ///
    /// Returns error if limit (50 apps) exceeded.
    pub fn add_monitored_app(&self, bundle_id: String) -> std::result::Result<(), ClipboardError> {
        log::debug!("add_monitored_app: bundle_id={bundle_id}");
        if bundle_id.is_empty() || bundle_id.len() > 256 {
            return Err(ClipboardError::Other("Invalid bundle ID length".into()));
        }
        if !bundle_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(ClipboardError::Other("Invalid bundle ID format".into()));
        }

        let mut apps = self.monitored_apps.write_recover();

        if apps.len() >= MAX_MONITORED_APPS {
            return Err(ClipboardError::MonitoringLimitExceeded);
        }

        if !apps.contains(&bundle_id) {
            apps.push(bundle_id);
        }

        Ok(())
    }

    /// Get broadcast receiver for evidence events.
    pub fn subscribe(&self) -> broadcast::Receiver<EvidenceEvent> {
        self.pending_evidence_tx.subscribe()
    }

    /// Main clipboard monitoring loop.
    ///
    /// Polls pasteboard every 100ms for changes, extracts text, matches to sessions,
    /// and emits evidence events. Runs as async task spawned in sentinel.
    ///
    /// # Error Handling
    /// - Pasteboard access denied: log warning, continue
    /// - Text encoding failed: log debug, skip
    /// - No monitored app: silently skip (expected for most copies)
    /// - Evidence attachment fails: log debug, continue
    pub async fn monitor_loop(
        self: Arc<Self>,
        sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
        cached_store: Arc<std::sync::Mutex<Option<crate::store::SecureStore>>>,
        signing_key: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
        cancel: CancellationToken,
    ) -> std::result::Result<(), ClipboardError> {
        log::debug!("ClipboardMonitor::monitor_loop started");
        loop {
            match self.check_clipboard_change().await {
                Ok(Some(mut copy_event)) => {
                    // Try to attach evidence if text matches a session fragment
                    match self
                        .try_attach_evidence(&copy_event, &sessions, &cached_store, &signing_key)
                        .await
                    {
                        Ok(signed) => {
                            // Emit to broadcast channel only on successful attachment
                            let evidence = signed.unwrap_or_else(|| copy_event.text_hash.to_vec());
                            let from_ai_tool = is_ai_tool_bundle_id(&copy_event.app_bundle_id);
                            if from_ai_tool {
                                log::warn!(
                                    "Paste from known AI tool: {}",
                                    copy_event.app_bundle_id
                                );
                            }
                            if let Err(e) = self.pending_evidence_tx.send(EvidenceEvent {
                                fragment_hash: copy_event.text_hash,
                                evidence,
                                source_app: copy_event.app_bundle_id.clone(),
                                timestamp: copy_event.timestamp,
                                from_ai_tool,
                                content_kind: copy_event.content_kind,
                            }) {
                                log::debug!("No evidence subscribers: {e}");
                            }
                        }
                        Err(e) => {
                            log::trace!("Evidence attachment skipped: {}", e);
                        }
                    }
                    copy_event.text.zeroize();
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("Clipboard monitor error: {}", e);
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                _ = cancel.cancelled() => {
                    log::info!("Clipboard monitor cancelled");
                    return Ok(());
                }
            }
        }
    }

    /// Check if pasteboard contents have changed and extract text.
    ///
    /// Returns Some(CopyEvent) if change detected and text valid, None if unchanged.
    /// Deduplication via change count and timestamp throttling (100ms).
    async fn check_clipboard_change(
        &self,
    ) -> std::result::Result<Option<CopyEvent>, ClipboardError> {
        use std::sync::atomic::Ordering;

        let now = Utc::now().timestamp_millis();

        let prev_time = self.last_copy_time.load(Ordering::Acquire);
        if now.saturating_sub(prev_time) < CLIPBOARD_DEBOUNCE_MS as i64 {
            return Ok(None);
        }

        let (current_count, text) = self.read_pasteboard().await?;

        let prev_count = self.last_change_count.load(Ordering::Acquire);
        if current_count == prev_count {
            return Ok(None);
        }

        let pasteboard_types = super::platform_pasteboard_types().await;

        if text.len() > MAX_CLIPBOARD_TEXT_SIZE {
            return Ok(None);
        }
        // Allow empty text through for media-only pastes (images with no text).
        if text.is_empty() && !pasteboard_types.has_image {
            return Ok(None);
        }

        let app_bundle_id = self.get_focused_app_bundle_id().await?;

        if !self.verify_paste_source_bundle_id(&app_bundle_id)? {
            return Ok(None);
        }

        let window_title = self.get_focused_window_title().await?;

        if self
            .last_change_count
            .compare_exchange(prev_count, current_count, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        self.last_copy_time.store(now, Ordering::Release);

        let content_kind = super::content_classifier::classify_paste_content_kind(
            &text,
            &pasteboard_types,
        );
        let text_hash = crypto_helpers::compute_content_hash(text.as_bytes());

        Ok(Some(CopyEvent {
            timestamp: now,
            app_bundle_id,
            window_title,
            text,
            text_hash,
            pasteboard_change_count: current_count,
            content_kind,
            pasteboard_types,
        }))
    }

    async fn try_attach_evidence(
        &self,
        copy_event: &CopyEvent,
        sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
        cached_store: &Arc<std::sync::Mutex<Option<crate::store::SecureStore>>>,
        signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    ) -> std::result::Result<Option<Vec<u8>>, ClipboardError> {
        let text_hex = hex::encode(copy_event.text_hash);

        let focused_ids: Vec<String> = {
            let sessions_guard = sessions.read_recover();
            sessions_guard
                .iter()
                .filter(|(_, s)| s.is_focused())
                .map(|(id, _)| id.clone())
                .collect()
        };

        for session_id in &focused_ids {
            let matches = {
                let guard = cached_store.lock_recover();
                match guard.as_ref() {
                    Some(store) => self.fragment_matches_hash(store, session_id, &copy_event.text_hash)?,
                    None => false,
                }
            };

            if matches {
                log::debug!("Text matched fragment in session {}", session_id);

                let signed_evidence = {
                    let guard = signing_key.read_recover();
                    guard.key().and_then(|sk| {
                        let mut nonce = [0u8; 16];
                        use rand::RngCore;
                        rand::rng().fill_bytes(&mut nonce);
                        let mut payload =
                            Vec::with_capacity(32 + copy_event.app_bundle_id.len() + 8);
                        payload.extend_from_slice(&copy_event.text_hash);
                        payload.extend_from_slice(copy_event.app_bundle_id.as_bytes());
                        payload.extend_from_slice(&copy_event.timestamp.to_le_bytes());
                        match wrap_clipboard_cose_sign1(&payload, &sk, &nonce) {
                            Ok(signed) => Some(signed),
                            Err(e) => {
                                log::warn!("Clipboard COSE signing failed: {e}");
                                None
                            }
                        }
                    })
                };

                {
                    let guard = cached_store.lock_recover();
                    if let Some(store) = guard.as_ref() {
                        self.persist_clipboard_event(
                            store,
                            copy_event,
                            &copy_event.text_hash,
                            signed_evidence.as_deref(),
                        )?;
                    }
                }
                return Ok(signed_evidence);
            }
        }

        log::trace!("No matching fragment found for hash: {}", text_hex);
        Err(ClipboardError::NoFragmentFound)
    }

    /// Check if text hash matches a fragment in the given session.
    fn fragment_matches_hash(
        &self,
        store: &crate::store::SecureStore,
        session_id: &str,
        text_hash: &[u8; 32],
    ) -> std::result::Result<bool, ClipboardError> {
        match store.lookup_fragment_by_hash(text_hash) {
            Ok(Some(f)) if f.session_id == session_id => Ok(true),
            Ok(Some(_)) => Ok(false),
            Ok(None) => Ok(false),
            Err(e) => Err(ClipboardError::Other(format!(
                "Fragment lookup failed: {}",
                e
            ))),
        }
    }

    /// Persist clipboard event to database.
    fn persist_clipboard_event(
        &self,
        store: &crate::store::SecureStore,
        copy_event: &CopyEvent,
        fragment_hash: &[u8; 32],
        signed_evidence: Option<&[u8]>,
    ) -> std::result::Result<(), ClipboardError> {
        let now = Utc::now().timestamp_nanos_safe();

        store
            .insert_clipboard_event(
                fragment_hash,
                &copy_event.app_bundle_id,
                &copy_event.window_title,
                &copy_event.text_hash,
                copy_event.pasteboard_change_count,
                copy_event.timestamp,
                now,
                signed_evidence,
                Some(copy_event.content_kind as u8),
                Some(&copy_event.pasteboard_types.utis.join(",")),
            )
            .map_err(|e| ClipboardError::Other(format!("Database persist failed: {}", e)))?;

        Ok(())
    }

    async fn read_pasteboard(&self) -> std::result::Result<(i32, String), ClipboardError> {
        super::platform_clipboard_read().await
    }

    async fn get_focused_app_bundle_id(&self) -> std::result::Result<String, ClipboardError> {
        super::platform_clipboard_bundle_id().await
    }

    async fn get_focused_window_title(&self) -> std::result::Result<String, ClipboardError> {
        super::platform_clipboard_window_title().await
    }

    /// Check if a bundle ID is in the trusted monitored apps list.
    ///
    /// Returns Ok(true) if the app is monitored, Ok(false) otherwise.
    pub fn verify_paste_source_bundle_id(
        &self,
        bundle_id: &str,
    ) -> std::result::Result<bool, ClipboardError> {
        log::debug!("verify_paste_source_bundle_id: bundle_id={bundle_id}");
        if bundle_id.is_empty() {
            return Ok(false);
        }
        Ok(crate::sentinel::app_registry::is_known(bundle_id))
    }
}

/// Wrap clipboard text content in a COSE_Sign1 envelope with Ed25519 signature.
///
/// Protected header contains Algorithm::EdDSA. The `nonce` is included in
/// the unprotected header for replay prevention. Payload is the raw text bytes.
pub fn wrap_clipboard_cose_sign1(
    content: &[u8],
    signing_key: &SigningKey,
    nonce: &[u8],
) -> crate::error::Result<Vec<u8>> {
    if nonce.len() < 16 {
        return Err(crate::error::Error::crypto(
            "Nonce must be at least 16 bytes",
        ));
    }

    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .build();

    let unprotected = HeaderBuilder::new().iv(nonce.to_vec()).build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(content.to_vec())
        .create_signature(&[], |sig_data| {
            let sig = signing_key.sign(sig_data);
            sig.to_bytes().to_vec()
        })
        .build();

    if sign1.signature.is_empty() {
        return Err(Error::crypto(
            "COSE_Sign1 clipboard wrapping produced empty signature",
        ));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::crypto(format!("COSE encoding error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_monitor_creation() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let apps = monitor.monitored_apps.read_recover();
        assert!(apps.len() > 0);
        assert!(apps.contains(&"com.apple.Notes".to_string()));
    }

    #[test]
    fn test_add_monitored_app() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let result = monitor.add_monitored_app("com.example.App".to_string());
        assert!(result.is_ok());

        let apps = monitor.monitored_apps.read_recover();
        assert!(apps.contains(&"com.example.App".to_string()));
    }

    #[test]
    fn test_add_monitored_app_duplicate() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let result1 = monitor.add_monitored_app("com.example.Unique".to_string());
        assert!(result1.is_ok());

        let result2 = monitor.add_monitored_app("com.example.Unique".to_string());
        assert!(result2.is_ok());

        let apps = monitor.monitored_apps.read_recover();
        let count = apps.iter().filter(|a| *a == "com.example.Unique").count();
        assert_eq!(count, 1, "Duplicate apps should not be added");
    }

    #[test]
    fn test_add_monitored_app_limit() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let defaults = monitor.monitored_apps.read_recover().len();

        // Fill remaining slots up to limit
        for i in 0..(MAX_MONITORED_APPS - defaults) {
            let result = monitor.add_monitored_app(format!("com.example.App{}", i));
            assert!(result.is_ok());
        }

        // Next add should fail
        let result = monitor.add_monitored_app("com.example.TooMany".to_string());
        assert!(matches!(
            result,
            Err(ClipboardError::MonitoringLimitExceeded)
        ));
    }

    #[test]
    fn test_copy_event_hash() {
        let text = "Hello World";
        let expected_hash = crypto_helpers::compute_content_hash(text.as_bytes());

        let event = CopyEvent {
            timestamp: 1000,
            app_bundle_id: "com.apple.Notes".to_string(),
            window_title: "Untitled".to_string(),
            text: text.to_string(),
            text_hash: expected_hash,
            pasteboard_change_count: 1,
            content_kind: PasteContentKind::default(),
            pasteboard_types: PasteboardTypeInventory::default(),
        };

        assert_eq!(event.text_hash, expected_hash);
    }

    #[test]
    fn test_evidence_event_creation() {
        let hash = [0u8; 32];
        let event = EvidenceEvent {
            fragment_hash: hash,
            evidence: vec![1, 2, 3],
            source_app: "com.apple.Notes".to_string(),
            timestamp: 1000,
            from_ai_tool: false,
            content_kind: PasteContentKind::default(),
        };

        assert_eq!(event.fragment_hash, hash);
        assert_eq!(event.evidence.len(), 3);
    }

    #[test]
    fn test_is_ai_tool_bundle_id() {
        assert!(is_ai_tool_bundle_id("com.anthropic.claudefordesktop"));
        assert!(is_ai_tool_bundle_id("com.openai.chat"));
        assert!(is_ai_tool_bundle_id("com.cursor.Cursor"));
        assert!(!is_ai_tool_bundle_id("com.apple.Notes"));
        assert!(!is_ai_tool_bundle_id("com.microsoft.Word"));
        assert!(!is_ai_tool_bundle_id(""));
    }

    #[tokio::test]
    async fn test_subscribe_broadcast() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let mut rx = monitor.subscribe();

        let event = EvidenceEvent {
            fragment_hash: [0u8; 32],
            evidence: vec![],
            source_app: "test".to_string(),
            timestamp: 1000,
            from_ai_tool: false,
            content_kind: PasteContentKind::default(),
        };

        let _ = monitor.pending_evidence_tx.send(event.clone());

        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(received)) => {
                assert_eq!(received.source_app, event.source_app);
            }
            _ => panic!("Failed to receive broadcast event"),
        }
    }

    #[test]
    fn test_clipboard_error_display() {
        let err = ClipboardError::PasteboardAccessDenied;
        assert_eq!(err.to_string(), "Pasteboard access denied");

        let err = ClipboardError::MonitoringLimitExceeded;
        assert_eq!(err.to_string(), "Monitoring limit exceeded");
    }
}
