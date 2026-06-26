// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::{
    commit_checkpoint_for_path, end_session_sync, handle_change_event_sync,
    handle_focus_event_sync, try_hw_cosign,
};
use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::platform::KeystrokeCapture;
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};

use super::core::CGEVENTTAP_VERIFIED_PID;

/// Captured state for the sentinel event loop, passed to per-branch handlers.
///
/// Groups all `Arc`-cloned references that the `tokio::select!` loop needs so
/// that each handler method can borrow only what it requires without a 20+
/// argument function signature. The mutable timing fields (`last_keydown_ts_ns`,
/// `pending_downs`, etc.) live here because they are local to the loop.
pub(super) struct EventLoopCtx {
    pub(super) sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    pub(super) current_focus: Arc<RwLock<Option<String>>>,
    pub(super) targeted_path: Arc<RwLock<Option<String>>>,
    pub(super) config: Arc<SentinelConfig>,
    pub(super) shadow: Arc<ShadowManager>,
    pub(super) signing_key: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    pub(super) signing_key_for_cp: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    pub(super) session_events_tx: broadcast::Sender<SessionEvent>,
    pub(super) running: Arc<AtomicBool>,
    pub(super) idle_timeout: Duration,
    pub(super) wal_dir: std::path::PathBuf,
    pub(super) activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    pub(super) style_collector: Arc<RwLock<Option<crate::fingerprint::StyleCollector>>>,
    pub(super) mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    pub(super) mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    pub(super) writersproof_dir: std::path::PathBuf,
    pub(super) stopping_flag: Arc<AtomicBool>,
    #[allow(clippy::type_complexity)]
    pub(super) pending_challenge: Arc<RwLock<Option<(String, Option<String>)>>>,
    pub(super) nonce_notify: Arc<tokio::sync::Notify>,
    pub(super) entropy_checkpoint_notify: Arc<tokio::sync::Notify>,
    pub(super) tpm_provider: Option<Arc<dyn crate::tpm::Provider>>,
    pub(super) tap_check_capture: Arc<Mutex<Option<Box<dyn KeystrokeCapture>>>>,
    pub(super) tap_check_active: Arc<AtomicBool>,
    pub(super) bridge_health_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    pub(super) bridge_healthy_flag: Arc<AtomicBool>,
    pub(super) snapshots_flag: Arc<AtomicBool>,
    pub(super) cached_store: Arc<Mutex<Option<crate::store::SecureStore>>>,
    pub(super) permission_state: Arc<Mutex<super::permission_monitor::PermissionState>>,
    pub(super) keystroke_event_tx:
        Arc<Mutex<Option<mpsc::Sender<crate::platform::KeystrokeEvent>>>>,
    pub(super) platform: Arc<dyn crate::platform::PlatformProvider>,
    pub(super) bundle_monitors: Arc<Mutex<HashMap<String, super::bundle_monitor::BundleMonitor>>>,
    pub(super) bundle_change_tx: Arc<Mutex<Option<mpsc::Sender<ChangeEvent>>>>,
    pub(super) document_watcher:
        Arc<Mutex<Option<super::document_watcher::DocumentDirectoryWatcher>>>,
    pub(super) content_fingerprints: Arc<
        Mutex<
            Vec<(
                String,
                String,
                super::content_fingerprint::ContentFingerprint,
            )>,
        >,
    >,
    pub(super) anchor_manager: Option<Arc<crate::anchors::AnchorManager>>,
    // Per-loop mutable timing state
    pub(super) last_keystroke_time: std::time::Instant,
    pub(super) last_keydown_ts_ns: i64,
    pub(super) last_mouse_ts_ns: i64,
    pub(super) pending_downs: HashMap<u16, i64>,
    pub(super) last_keyup_ts_ns: i64,
    /// Debounce: last time content fingerprint was computed per path.
    pub(super) last_fingerprint_time: HashMap<String, std::time::Instant>,
    /// Cooldown: last time capture auto-recovery was attempted.
    pub(super) last_capture_restart: Option<std::time::Instant>,
    /// Local cache of current_focus to avoid RwLock read per-keystroke.
    /// Updated by focus/change event handlers; the single-threaded
    /// tokio::select! loop ensures consistency without the lock.
    pub(super) cached_focus: Option<String>,
    /// Bounded channel for cross-window transcription check requests.
    /// Capacity 1: at most one check in flight, extras silently dropped.
    pub(super) xwin_check_tx: Option<std::sync::mpsc::SyncSender<(u32, Option<u32>, String)>>,
    pub(super) xwin_check_handle: Option<std::thread::JoinHandle<()>>,
    /// Local keystroke counter for cross-window check scheduling.
    /// Independent of session.keystroke_count (which is incremented by FFI).
    pub(super) xwin_keystroke_counter: u64,
}

/// Duration after last keystroke within which mouse micro-movements are recorded.
const TYPING_PROXIMITY_SECS: u64 = 2;

impl EventLoopCtx {
    /// Forward session lifecycle events (document watcher, content fingerprints).
    /// API calls (session create/end, nonce challenge/confirm) are handled by the
    /// Swift layer which owns authentication.
    pub(super) fn handle_session_event(&self, event: SessionEvent) {
        match event.event_type {
            SessionEventType::Started => {}
            SessionEventType::Ended => {
                // Unwatch document directory and remove content fingerprint.
                let doc_path = std::path::Path::new(&event.document_path);
                if doc_path.is_absolute() {
                    {
                        let mut guard = self.document_watcher.lock_recover();
                        if let Some(ref mut dw) = *guard {
                            dw.unwatch_document(doc_path);
                        }
                    }
                }
                self.content_fingerprints
                    .lock_recover()
                    .retain(|(sid, _, _)| *sid != event.session_id);
            }
            _ => {}
        }
    }

    /// Process a keystroke event (keyDown or keyUp).
    pub(super) fn handle_keystroke_event(&mut self, event: crate::platform::KeystrokeEvent) {
        let bridge_healthy = self.bridge_healthy_flag.load(Ordering::Acquire);

        // Handle keyUp: compute dwell time, backfill the matching
        // keyDown sample in the focused session's jitter buffer, and
        // update last_keyup_ts for flight-time computation.
        if event.event_type == crate::platform::KeyEventType::Up {
            if let Some(down_ts) = self.pending_downs.remove(&event.keycode) {
                let dwell = crate::utils::ns_elapsed(event.timestamp_ns, down_ts);
                if let Some(ref path) = self.cached_focus {
                    let mut map = self.sessions.write_recover();
                    if self.bridge_healthy_flag.load(Ordering::Acquire) {
                        if let Some(session) = map.get_mut(path.as_str()) {
                            // Fast path: most keyUp events match the most recent keyDown.
                            let matched = session
                                .jitter_ring
                                .last_mut()
                                .filter(|s| s.timestamp_ns == down_ts);
                            if let Some(sample) = matched {
                                sample.dwell_time_ns = Some(dwell);
                            } else if let Some(sample) =
                                session.jitter_ring.find_recent_mut(down_ts, 50)
                            {
                                sample.dwell_time_ns = Some(dwell);
                            }
                        }
                    }
                }
            }
            self.last_keyup_ts_ns = event.timestamp_ns;
            return;
        }

        // keyDown processing — dedup
        if event.timestamp_ns == self.last_keydown_ts_ns {
            return;
        }

        // Track this keyDown for dwell time (computed when keyUp arrives).
        // Evict stale entries (keys held > 10s are likely stuck).
        self.pending_downs
            .retain(|_, ts| *ts > 0 && event.timestamp_ns.saturating_sub(*ts) < 10_000_000_000);
        if self.pending_downs.len() < 256 {
            self.pending_downs.insert(event.keycode, event.timestamp_ns);
        }

        let duration_since_last_ns: u64 = if self.last_keydown_ts_ns > 0 {
            crate::utils::ns_elapsed(event.timestamp_ns, self.last_keydown_ts_ns)
        } else {
            0
        };

        let flight_time_ns: Option<u64> = if self.last_keyup_ts_ns > 0 {
            Some(crate::utils::ns_elapsed(
                event.timestamp_ns,
                self.last_keyup_ts_ns,
            ))
        } else {
            None
        };

        self.last_keydown_ts_ns = event.timestamp_ns;
        let sample = crate::jitter::SimpleJitterSample {
            timestamp_ns: event.timestamp_ns,
            duration_since_last_ns,
            zone: event.zone,
            dwell_time_ns: None,
            flight_time_ns,
        };

        // Feed global accumulator only for plausibly-human keystrokes.
        // Impossibly fast events (< 10ms IKI) are likely synthetic or
        // auto-repeat; skip them to avoid polluting biometric profile.
        let plausible = duration_since_last_ns == 0 || duration_since_last_ns >= 10_000_000;
        if plausible {
            self.activity_accumulator
                .write_recover()
                .add_sample(&sample);
        }

        if plausible {
            // EH-041: Add behavioral entropy to signing key to keep it hot.
            {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(b"witnessd-keystroke-entropy-v1");
                hasher.update(event.timestamp_ns.to_le_bytes());
                let entropy_hash = hasher.finalize();
                self.signing_key
                    .write_recover()
                    .add_entropy(&entropy_hash[..8]);
            }

            if let Some(ref mut collector) = *self.style_collector.write_recover() {
                collector.record_keystroke(event.keycode, event.char_value);
            }
        }

        if !bridge_healthy {
            log::warn!("Skipping session recording: bridge unhealthy");
            return;
        }

        self.record_keystroke_to_session(&event, &sample, duration_since_last_ns);
        self.last_keystroke_time = std::time::Instant::now();
    }

    /// Attribute a validated keyDown to the focused document session.
    fn record_keystroke_to_session(
        &mut self,
        event: &crate::platform::KeystrokeEvent,
        sample: &crate::jitter::SimpleJitterSample,
        duration_since_last_ns: u64,
    ) {
        let Some(ref path) = self.cached_focus else {
            return;
        };
        log::trace!("record_keystroke_to_session: path={}", path);
        let mut map = self.sessions.write_recover();
        super::trace!(
            "[KEYSTROKE] focus={:?} sessions={:?} kc={}",
            path,
            map.keys(),
            event.keycode
        );
        let Some(session) = map.get_mut(path.as_str()) else {
            super::trace!("[KEYSTROKE] NO SESSION for path={:?}", path);
            return;
        };
        // Note: keystroke_count is incremented ONLY by ffi_sentinel_inject_keystroke
        // (the Swift FFI path), not here. The CGEventTap feeds jitter samples only.
        // This prevents double-counting when both capture paths are active.
        super::trace!(
            "[KEYSTROKE] JITTER {:?} total={}",
            path,
            session.keystroke_count
        );
        // When the FFI inject path is active (keystroke_count > 0), it owns
        // per-document jitter samples. Skip the CGEventTap push to avoid
        // duplicates (the two paths use different timestamp domains so
        // timestamp-based dedup cannot work).
        let was_buffered = session.keystroke_count == 0;
        if was_buffered {
            session.jitter_ring.push(*sample);
        }
        let validation = crate::forensics::validate_keystroke_event(
            event.timestamp_ns,
            event.keycode,
            sample.zone,
            CGEVENTTAP_VERIFIED_PID,
            None,
            session.has_focus,
            &mut session.event_validation,
        );
        if validation.confidence < 0.1 {
            if was_buffered {
                session.jitter_ring.undo_last();
            }
            super::trace!("[KEYSTROKE] REJECTED conf={:.2}", validation.confidence);
            return;
        }

        session.cognitive.record_keystroke(
            event.char_value,
            event.timestamp_ns,
            duration_since_last_ns,
            0, // size_delta populated at checkpoint time
            0, // file_size populated at checkpoint time
        );

        // Scroll-before-edit: count recent scroll events that preceded this keystroke.
        // A scroll within 3s before a keystroke indicates re-reading before editing.
        {
            let threshold_ns = 3_000_000_000i64;
            let sa = &mut session.scroll_attention;
            while let Some(&ts) = sa.recent_scroll_timestamps.front() {
                if event.timestamp_ns.saturating_sub(ts) > threshold_ns {
                    sa.recent_scroll_timestamps.pop_front();
                } else {
                    break;
                }
            }
            let count = sa.recent_scroll_timestamps.len() as u64;
            sa.scroll_before_edit_count += count;
            sa.recent_scroll_timestamps.clear();
        }

        // Advance incremental jitter hash chain for all accepted
        // keystrokes, even those beyond the sample buffer capacity,
        // so the hash covers the full session.
        {
            let mut h = sha2::Sha256::new();
            use sha2::Digest as _;
            h.update(session.jitter_hash_state);
            h.update(sample.timestamp_ns.to_be_bytes());
            h.update(sample.duration_since_last_ns.to_be_bytes());
            h.update([sample.zone]);
            session.jitter_hash_state = h.finalize().into();
        }

        // Entropy-triggered checkpoint: test if jitter hash chain crossed
        // the trigger threshold. Only fires if MIN_NS has elapsed since
        // the last checkpoint to protect the write lock budget.
        {
            let elapsed_ns = sample
                .timestamp_ns
                .saturating_sub(session.last_checkpoint_ns);
            if elapsed_ns >= super::types::ENTROPY_CHECKPOINT_MIN_NS {
                let trigger =
                    u32::from_be_bytes(session.jitter_hash_state[..4].try_into().unwrap());
                if trigger < super::types::ENTROPY_TRIGGER_THRESHOLD {
                    log::debug!(
                        "Entropy trigger fired: trigger={trigger} threshold={} elapsed={}ms",
                        super::types::ENTROPY_TRIGGER_THRESHOLD,
                        elapsed_ns / 1_000_000,
                    );
                    session.last_checkpoint_ns = sample.timestamp_ns;
                    self.entropy_checkpoint_notify.notify_one();
                }
            }
        }

        // Feed typed character to cross-window transcription detector.
        if let Some(ch) = event.char_value {
            session.transcription_detector.record_keystroke(ch);
        }

        // Periodically assess transcription suspicion (every 100 keystrokes).
        // Uses a local counter on EventLoopCtx rather than session.keystroke_count
        // because the FFI path increments keystroke_count asynchronously, causing
        // the modulo check to miss multiples of 100 from this code path.
        self.xwin_keystroke_counter += 1;
        let should_cross_check =
            self.xwin_keystroke_counter % 50 == 0 && session.jitter_ring.len() >= 20;
        let cross_check_ready =
            should_cross_check && session.transcription_detector.buffer_len() >= 100;
        let (exclude_pid, exclude_window_id) = if cross_check_ready && event.target_pid > 0 {
            (Some(event.target_pid as u32), session.window_id)
        } else {
            (None, None)
        };

        // Snapshot trailing samples for deferred suspicion assessment (computed outside the lock).
        let deferred_suspicion_samples = if should_cross_check {
            Some(session.jitter_ring.trailing(200))
        } else {
            None
        };

        if let Some(ref tpm) = self.tpm_provider {
            if session.hw_cosign_scheduler.is_none() {
                match crate::evidence::hw_cosign::HwCosignScheduler::with_defaults(
                    tpm.as_ref(),
                    &session.session_id,
                ) {
                    Ok(sched) => {
                        session.hw_cosign_scheduler = Some(sched);
                    }
                    Err(e) => {
                        log::trace!("HW co-sign scheduler init failed: {e}");
                    }
                }
            }
            if let Some(ref mut sched) = session.hw_cosign_scheduler {
                let entropy = duration_since_last_ns.to_le_bytes();
                sched.record_entropy(&entropy);
            }
        }

        drop(map);

        // Deferred transcription suspicion assessment (computed outside the lock).
        if let Some(samples) = deferred_suspicion_samples {
            let suspicion =
                crate::forensics::error_ecology::assess_transcription_suspicion(&samples);
            let mut map = self.sessions.write_recover();
            if let Some(session) = map.get_mut(path.as_str()) {
                session.transcription_suspicion = suspicion;
            }
        }

        // Cross-window comparison runs on a single background worker thread
        // to avoid blocking keystroke processing (AX IPC can take 50-200ms).
        // Bounded channel (capacity 1): at most one check in flight, extras dropped.
        if let Some(excl_pid) = exclude_pid {
            if self.xwin_check_tx.is_none() {
                let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Option<u32>, String)>(1);
                let sessions = Arc::clone(&self.sessions);
                match std::thread::Builder::new()
                    .name("cpoe-xwin-check".into())
                    .spawn(move || {
                        while let Ok((pid, win_id, check_path)) = rx.recv() {
                            let visible =
                                crate::platform::window_text::WindowTextCapture::capture_visible_windows(
                                    Some(pid),
                                    win_id,
                                );
                            if visible.is_empty() {
                                continue;
                            }
                            let mut map = sessions.write_recover();
                            if let Some(session) = map.get_mut(check_path.as_str()) {
                                for wt in &visible {
                                    if wt.text_content.len() >= 50 {
                                        session.transcription_detector.check_against_text(
                                            &wt.text_content,
                                            &wt.app_name,
                                            &wt.window_title,
                                        );
                                    }
                                }
                            }
                        }
                    }) {
                    Ok(handle) => {
                        self.xwin_check_tx = Some(tx);
                        self.xwin_check_handle = Some(handle);
                    }
                    Err(e) => log::warn!("failed to spawn xwin-check worker: {e}"),
                }
            }
            if let Some(tx) = &self.xwin_check_tx {
                if let Err(std::sync::mpsc::TrySendError::Disconnected(_)) =
                    tx.try_send((excl_pid, exclude_window_id, path.clone()))
                {
                    self.xwin_check_tx = None;
                    self.xwin_check_handle = None;
                }
            }
        }
    }

    /// Process a mouse movement event.
    pub(super) fn handle_mouse_event(&mut self, event: crate::platform::MouseEvent) {
        let mouse_duration_ns: u64 = if self.last_mouse_ts_ns > 0 {
            crate::utils::ns_elapsed(event.timestamp_ns, self.last_mouse_ts_ns)
        } else {
            0
        };
        self.last_mouse_ts_ns = event.timestamp_ns;

        let is_during_typing =
            self.last_keystroke_time.elapsed() < Duration::from_secs(TYPING_PROXIMITY_SECS);
        if is_during_typing && event.is_micro_movement() {
            self.mouse_idle_stats.write_recover().record(&event);
        }

        // Accumulate scroll and position data for cursor attention analysis.
        // Only take the sessions write lock when we actually have data to record.
        let is_scroll = event.is_scroll();
        let should_sample_position = mouse_duration_ns >= 100_000_000;
        if is_scroll || should_sample_position {
            if let Some(ref path) = self.cached_focus {
                let mut map = self.sessions.write_recover();
                if let Some(session) = map.get_mut(path.as_str()) {
                    let sa = &mut session.scroll_attention;
                    if is_scroll {
                        let delta_v = event.scroll_delta_v.unwrap_or(0);
                        sa.total_scroll_events += 1;
                        sa.record_scroll_magnitude((delta_v as f64).abs());

                        if delta_v > 0 {
                            sa.scroll_up_count += 1;
                            if sa.last_scroll_sign == -1 {
                                sa.direction_reversals += 1;
                            }
                            sa.last_scroll_sign = 1;
                        } else if delta_v < 0 {
                            sa.scroll_down_count += 1;
                            if sa.last_scroll_sign == 1 {
                                sa.direction_reversals += 1;
                            }
                            sa.last_scroll_sign = -1;
                        }

                        sa.last_scroll_ts_ns = event.timestamp_ns;
                        if is_during_typing {
                            sa.scroll_near_edit_count += 1;
                        }

                        if sa.recent_scroll_timestamps.len() >= 64 {
                            sa.recent_scroll_timestamps.pop_front();
                        }
                        sa.recent_scroll_timestamps.push_back(event.timestamp_ns);
                    }

                    if should_sample_position {
                        let y = event.y;
                        sa.record_position(y);
                        sa.record_direction(y);

                        // Dwell in screen thirds
                        let y_range = sa.position_y_max - sa.position_y_min;
                        if sa.last_sample_ts_ns > 0 && y_range > 1.0 {
                            let elapsed_ns =
                                crate::utils::ns_elapsed(event.timestamp_ns, sa.last_sample_ts_ns);
                            let frac = ((sa.last_sample_y - sa.position_y_min) / y_range)
                                .clamp(0.0, 0.999);
                            let third = (frac * 3.0) as usize;
                            sa.dwell_thirds_ns[third] += elapsed_ns;
                        }

                        sa.last_sample_y = y;
                        sa.last_sample_ts_ns = event.timestamp_ns;
                    }
                }
            }
        }

        // Throttle stego jitter to ~20 Hz to reduce write lock contention
        if mouse_duration_ns >= 50_000_000 {
            self.mouse_stego_engine.write_recover().next_jitter();
        }
    }

    /// Handle a focus event and optionally start a bundle monitor.
    pub(super) fn handle_focus_branch(&mut self, event: FocusEvent) {
        log::debug!(
            "handle_focus_branch: type={:?} app={}",
            event.event_type,
            event.app_bundle_id
        );

        // ValueChanged events from kAXValueChangedNotification: correlate with
        // recent keystrokes to detect non-keyboard text input.
        if event.event_type == FocusEventType::ValueChanged {
            let recent_keystroke = self.last_keydown_ts_ns > 0
                && self.last_keystroke_time.elapsed() < std::time::Duration::from_millis(500);
            if !recent_keystroke {
                if let Some(ref path) = self.cached_focus {
                    let mut map = self.sessions.write_recover();
                    if let Some(session) = map.get_mut(path.as_str()) {
                        session.non_keyboard_change_count += 1;
                        if let Some(delta) = event.char_count_delta {
                            session.non_keyboard_chars_inserted += delta;
                        }
                    }
                }
            }
            return;
        }

        handle_focus_event_sync(
            event,
            &self.sessions,
            &self.config,
            &self.shadow,
            &self.signing_key,
            &self.current_focus,
            &self.targeted_path,
            &self.wal_dir,
            &self.session_events_tx,
        );
        // Clone focus path out of the lock so we never hold current_focus(4)
        // while acquiring sessions(2) or cached_store(3) (AUD-041).
        let focus_path = self.current_focus.read_recover().clone();

        // Start a BundleMonitor for newly-focused bundle documents
        // (Scrivener .scriv, Ulysses .ulysses) if not already watching.
        if let Some(ref path) = focus_path {
            let bundle_path = std::path::Path::new(path.as_str());
            if super::bundle_monitor::is_bundle_document(bundle_path) {
                let mut monitors = self.bundle_monitors.lock_recover();
                if !monitors.contains_key(path) {
                    if let Some(ref tx) = *self.bundle_change_tx.lock_recover() {
                        match super::bundle_monitor::start_bundle_monitor(bundle_path, tx.clone()) {
                            Ok(monitor) => {
                                self.restore_scrivener_state(bundle_path, path);
                                monitors.insert(path.clone(), monitor);
                            }
                            Err(e) => {
                                log::warn!(
                                    "bundle_monitor: failed to start for \
                                     {path:?}: {e}"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Register the focused document's directory for file-save correlation.
        if let Some(ref path) = focus_path {
            let doc_path = std::path::Path::new(path.as_str());
            if doc_path.is_absolute()
                && !path.starts_with("title://")
                && !path.starts_with("shadow://")
            {
                {
                    let mut guard = self.document_watcher.lock_recover();
                    if let Some(ref mut dw) = *guard {
                        if let Err(e) = dw.watch_document(doc_path) {
                            log::debug!("document_watcher: watch failed for {path:?}: {e}");
                        }
                    }
                }

                // Debounce: skip fingerprint if same path was computed < 30s ago.
                let should_fingerprint = self
                    .last_fingerprint_time
                    .get(path.as_str())
                    .map_or(true, |t| t.elapsed() >= Duration::from_secs(30));

                if should_fingerprint {
                    self.last_fingerprint_time
                        .insert(path.clone(), std::time::Instant::now());

                    // Compute content fingerprint for cross-app session linking.
                    // File I/O runs on the blocking pool to avoid stalling the event loop.
                    let fp_doc = match crate::utils::fs::open_validated(doc_path) {
                        Ok(v) => v,
                        Err(e) => {
                            log::debug!(
                                "content_fingerprint: open_validated failed for {path:?}: {e}"
                            );
                            // Don't return — cached_focus update below must still run.
                            self.cached_focus = self.current_focus.read_recover().clone();
                            return;
                        }
                    };
                    let fp_sessions = Arc::clone(&self.sessions);
                    let fp_store = Arc::clone(&self.content_fingerprints);
                    let fp_path = path.clone();
                    tokio::task::spawn_blocking(move || {
                        let (_canonical, file) = fp_doc;
                        // Reject files >10 MB to avoid memory exhaustion.
                        match file.metadata() {
                            Ok(m) if m.len() > 10 * 1024 * 1024 => return,
                            Err(e) => {
                                log::debug!("content_fingerprint: metadata failed: {e}");
                                return;
                            }
                            _ => {}
                        }
                        use std::io::Read;
                        let mut content = String::new();
                        if let Err(e) = std::io::BufReader::new(file).read_to_string(&mut content) {
                            log::debug!("content_fingerprint: read failed: {e}");
                            return;
                        }
                        let fp =
                            super::content_fingerprint::ContentFingerprint::from_text(&content);
                        let sessions_guard = fp_sessions.read_recover();
                        if let Some(session) = sessions_guard.get(fp_path.as_str()) {
                            let sid = session.session_id.clone();
                            let app = session.app_bundle_id.clone();
                            drop(sessions_guard);

                            // Single lock acquisition for read + write to avoid TOCTOU.
                            let mut store = fp_store.lock_recover();
                            if let Some(link) = super::content_fingerprint::find_cross_app_match(
                                &sid, &app, &fp, &store,
                            ) {
                                log::info!(
                                    "cross-app link detected: {} ({}) <-> {} ({}) distance={}",
                                    link.app_a,
                                    link.session_a_id,
                                    link.app_b,
                                    link.session_b_id,
                                    link.fingerprint_distance,
                                );
                            }
                            if store.len() >= 1000 {
                                store.drain(..100);
                            }
                            store.push((sid, app, fp));
                        }
                    });
                } // should_fingerprint
            }
        }
        self.cached_focus = self.current_focus.read_recover().clone();
    }

    /// Parse Scrivener project map and restore segment counts from shadow.
    fn restore_scrivener_state(&self, bundle_path: &std::path::Path, path: &str) {
        if let Some(map) = super::helpers::parse_scrivener_project_map(bundle_path) {
            let project_uuid = map.uuid_to_title.keys().next().cloned();
            // AUD-041: sessions(2) before cached_store(3).
            let mut sessions_map = self.sessions.write_recover();
            if let Some(session) = sessions_map.get_mut(path) {
                if session.segment_counts.is_empty() {
                    if let Some(ref proj_uuid) = project_uuid {
                        let app_bid = session.app_bundle_id.clone();
                        if let Some(ref store) = *self.cached_store.lock_recover() {
                            if let Ok(Some(shadow)) = store.load_shadow_session(&app_bid, proj_uuid)
                            {
                                if let Some(ref json) = shadow.segment_counts_json {
                                    if let Ok(counts) = serde_json::from_str(json) {
                                        session.segment_counts = counts;
                                    }
                                }
                            }
                        }
                    }
                }
                session.scrivener_project_map = Some(map);
            }
        }
    }

    /// Forward a file-change event to the synchronous handler.
    pub(super) fn handle_change_branch(&mut self, event: &ChangeEvent) {
        handle_change_event_sync(
            event,
            &self.sessions,
            &self.config,
            &self.signing_key,
            &self.wal_dir,
            &self.session_events_tx,
            Some(&self.current_focus),
        );
        self.cached_focus = self.current_focus.read_recover().clone();
    }

    /// Auto-checkpoint and end idle sessions; check capture health.
    pub(super) async fn handle_idle_check(&mut self) {
        let idle_paths: Vec<String> = {
            let map = self.sessions.read_recover();
            map.iter()
                .filter(|(_, s)| {
                    !s.is_focused()
                        && s.last_focused_at
                            .elapsed()
                            .map(|d| d > self.idle_timeout)
                            .unwrap_or(false)
                })
                .map(|(p, _)| p.clone())
                .collect()
        };
        for path in &idle_paths {
            self.checkpoint_idle_session(path).await;
            self.persist_idle_session_stats(path);
            end_session_sync(path, &self.sessions, &self.session_events_tx);
            self.bundle_monitors.lock_recover().remove(path);
            self.last_fingerprint_time.remove(path.as_str());
        }
        // Prune stale sessions: unfocused, zero keystrokes, created >1 hour ago.
        {
            let mut map = self.sessions.write_recover();
            map.retain(|_, s| {
                s.is_focused()
                    || s.keystroke_count > 0
                    || s.start_time.elapsed().unwrap_or_default() < Duration::from_secs(3600)
            });
        }

        // Auto-archive if the event database exceeds the 1.5 GiB threshold.
        {
            let db_path = self.writersproof_dir.join("events.db");
            if let Some(ref mut store) = *self.cached_store.lock_recover() {
                match store.auto_archive_if_needed(&db_path) {
                    Ok(Some(result)) => {
                        log::info!(
                            "Auto-archived {} events to {}",
                            result.events_archived,
                            result.archive_path.display(),
                        );
                    }
                    Ok(None) => {}
                    Err(e) => log::warn!("Auto-archive check failed: {e}"),
                }
            }
        }

        self.check_capture_health();
    }

    /// Commit a checkpoint for a session about to be ended due to idle timeout.
    async fn checkpoint_idle_session(&self, path: &str) {
        let needs_checkpoint = {
            let map = self.sessions.read_recover();
            map.get(path).is_some_and(|s| {
                s.keystroke_count > s.last_checkpoint_keystrokes && !path.starts_with("shadow://")
            })
        };
        if !needs_checkpoint {
            return;
        }
        let cp_path = path.to_string();
        let cp_key = Arc::clone(&self.signing_key_for_cp);
        let cp_dir = self.writersproof_dir.clone();
        let cp_stop = Arc::clone(&self.stopping_flag);
        let cp_anchor = self.anchor_manager.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            commit_checkpoint_for_path(
                &cp_path,
                "Auto-checkpoint on idle end",
                &cp_key,
                &cp_dir,
                &None,
                &cp_stop,
                &cp_anchor,
            )
        })
        .await
        {
            log::error!("Idle-end checkpoint task panicked: {e}");
        }
    }

    /// Persist cumulative stats for an idle session before ending it.
    fn persist_idle_session_stats(&self, path: &str) {
        let map = self.sessions.read_recover();
        let Some(session) = map.get(path) else {
            return;
        };
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let stats = crate::store::DocumentStats {
            file_path: path.to_string(),
            total_keystrokes: i64::try_from(session.total_keystrokes()).unwrap_or(i64::MAX),
            total_focus_ms: session.total_focus_ms_cumulative(),
            session_count: i64::from(session.session_number + 1),
            total_duration_secs: session
                .start_time
                .elapsed()
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            first_tracked_at: session
                .first_tracked_at
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(now_secs),
            last_tracked_at: now_secs,
            total_checkpoints: i64::try_from(session.checkpoint_count).unwrap_or(i64::MAX),
        };
        drop(map);
        if let Some(ref store) = *self.cached_store.lock_recover() {
            if let Err(e) = store.save_document_stats(&stats) {
                log::warn!("Idle-end stats persist failed: {e}");
            }
        }
    }

    /// Check CGEventTap and bridge thread health; auto-recover if dead.
    ///
    /// Cooldown: at most one restart attempt per 30 seconds to prevent
    /// infinite restart loops when the tap dies immediately after creation.
    fn check_capture_health(&mut self) {
        let mut needs_restart = false;
        {
            let tap_dead = {
                let guard = self.tap_check_capture.lock_recover();
                guard.as_ref().is_some_and(|cap| !cap.is_tap_alive())
            };
            if tap_dead && self.tap_check_active.load(Ordering::SeqCst) {
                log::error!("CGEventTap died; attempting automatic recovery");
                self.tap_check_active.store(false, Ordering::SeqCst);
                needs_restart = true;
            }
        }
        {
            let mut threads = self.bridge_health_threads.lock_recover();
            let had = threads.len();
            threads.retain(|t| !t.is_finished());
            let dead_count = had - threads.len();
            if dead_count > 0 {
                log::error!("{dead_count} bridge thread(s) died; attempting automatic recovery");
                self.bridge_healthy_flag.store(false, Ordering::SeqCst);
                needs_restart = true;
            }
        }
        if let Some(ref h) = self.xwin_check_handle {
            if h.is_finished() {
                log::warn!(
                    "cpoe-xwin-check worker thread exited; will respawn on next focus event"
                );
                self.xwin_check_tx = None;
                self.xwin_check_handle = None;
            }
        }
        if needs_restart {
            // Cooldown: skip if last restart was < 30s ago.
            let now = std::time::Instant::now();
            let cooldown_ok = self
                .last_capture_restart
                .map_or(true, |t| now.duration_since(t) >= Duration::from_secs(30));
            if cooldown_ok {
                self.last_capture_restart = Some(now);
                self.restart_capture_after_permission_grant();
            } else {
                log::warn!("Capture restart skipped: cooldown active");
            }
        }
    }

    /// Challenge nonce tick — no-op in the engine.
    /// Nonce fetching is handled by the Swift layer via `ChallengeService`,
    /// which pushes nonces to the engine via `ffi_sentinel_set_challenge_nonce`.
    pub(super) fn handle_challenge_tick(&self) {
        let has_nonce = self.pending_challenge.read_recover().is_some();
        if !has_nonce {
            log::trace!("Witness pulse skipped: no nonce available (Swift ChallengeService provides nonces)");
        }
    }

    /// Compute the next checkpoint interval from nonce + jitter entropy.
    ///
    /// The interval is drawn from `[base/2, 2*base)` milliseconds using
    /// `BLAKE3(DST || nonce || jitter_hash_state || monotonic_counter)`.
    /// Neither the server (nonce) nor the client (jitter chain) alone can
    /// predict the result.  The monotonic counter prevents identical outputs
    /// when the jitter chain hasn't advanced (idle periods).
    ///
    /// Falls back to the configured fixed interval when no nonce is available.
    pub(super) fn compute_next_checkpoint_interval(&self, base_secs: u64) -> Duration {
        static ENTROPY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let counter = ENTROPY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let nonce_bytes = {
            let guard = self.pending_challenge.read_recover();
            guard.as_ref().map(|(n, _)| n.as_bytes().to_vec())
        };

        let jitter_entropy: [u8; 32] = {
            let map = self.sessions.read_recover();
            map.values()
                .filter(|s| s.has_focus)
                .max_by_key(|s| s.keystroke_count)
                .map(|s| s.jitter_hash_state)
                .unwrap_or([0u8; 32])
        };

        let Some(nonce) = nonce_bytes else {
            return Duration::from_secs(base_secs);
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"cpoe-checkpoint-entropy-v1");
        hasher.update(&nonce);
        hasher.update(&jitter_entropy);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        let hash_bytes: [u8; 8] = hash.as_bytes()[..8].try_into().unwrap();
        let raw = u64::from_le_bytes(hash_bytes);

        // Map into [base/2, 2*base) milliseconds — 4x spread.
        let base_ms = base_secs * 1000;
        let min_ms = base_ms / 2;
        let window_ms = base_ms.saturating_mul(3).saturating_div(2); // 1.5 * base
        let offset_ms = if window_ms > 0 { raw % window_ms } else { 0 };
        let interval_ms = min_ms + offset_ms;

        log::debug!(
            "Entropy checkpoint interval: {}ms (base={}s, range=[{}ms,{}ms))",
            interval_ms,
            base_secs,
            min_ms,
            min_ms + window_ms
        );
        Duration::from_millis(interval_ms)
    }

    /// Commit checkpoints for all sessions with pending keystrokes.
    pub(super) async fn handle_checkpoint_tick(&self) {
        // All sessions with pending keystrokes are candidates.  Checkpoint
        // frequency is governed by the entropy-derived interval, not per-session
        // tick skipping, so every candidate is included on every fire.
        let candidates: Vec<String> = {
            let map = self.sessions.read_recover();
            map.iter()
                .filter(|(p, s)| {
                    s.keystroke_count > s.last_checkpoint_keystrokes && !p.starts_with("shadow://")
                })
                .map(|(p, _)| p.clone())
                .collect()
        };

        // Probe unknown apps to detect AX capabilities (title inference,
        // storage pattern). This is metadata-only — per-session forensic
        // scoring determines whether a session is real authorship, not
        // app-level registration. Probe outside the session lock since
        // AX queries and probe_app can block for seconds.
        let unknown_apps: Vec<(String, String)> = {
            let map = self.sessions.read_recover();
            map.values()
                .filter(|s| !super::app_registry::is_known(&s.app_bundle_id))
                .map(|s| (s.app_bundle_id.clone(), s.app_name.clone()))
                .collect()
        };
        for (bundle_id, app_name) in &unknown_apps {
            super::app_registry::probe_and_cache(bundle_id, app_name);
        }

        let pending_taken = self.pending_challenge.write_recover().take();
        let challenge_nonce = pending_taken.as_ref().map(|(n, _)| n.clone());
        let nonce_id = pending_taken.and_then(|(_, id)| id);

        for path in &candidates {
            let skip_rest = self
                .checkpoint_one_session(path, &challenge_nonce, &nonce_id)
                .await;
            if skip_rest {
                break;
            }
        }
    }

    /// Run a checkpoint for a single session. Returns `true` if the
    /// caller should stop iterating candidates (used for HW co-sign
    /// file-read failures that `continue 'candidates`).
    async fn checkpoint_one_session(
        &self,
        path: &str,
        challenge_nonce: &Option<String>,
        nonce_id: &Option<String>,
    ) -> bool {
        let cp_path = path.to_string();
        let cp_key = Arc::clone(&self.signing_key_for_cp);
        let cp_dir = self.writersproof_dir.clone();
        let nonce_for_closure = challenge_nonce.clone();
        let cp_stop = Arc::clone(&self.stopping_flag);
        let cp_anchor = self.anchor_manager.clone();
        // For virtual title:// sessions, capture compose window text via AX
        // for content-level witnessing (MMR) and content hash binding.
        // We target the specific compose window by title to avoid capturing
        // text from the wrong window (e.g. inbox instead of compose).
        let captured_text = if path.starts_with("title://") {
            let session_info = {
                let map = self.sessions.read_recover();
                map.get(path)
                    .map(|s| (s.app_bundle_id.clone(), s.window_title.reveal().to_string()))
            };
            session_info.and_then(|(bid, title)| {
                let text = crate::platform::window_text::WindowTextCapture::capture_text_for_bundle_id_and_title(
                    &bid,
                    if title.is_empty() { None } else { Some(&title) },
                );
                if text.is_none() {
                    log::debug!("AX text capture returned None for virtual session {path}");
                }
                // Cap at 10 MiB to prevent OOM from malicious/buggy AX responses.
                text.filter(|t| t.len() <= 10 * 1024 * 1024)
            })
        } else {
            None
        };

        let (semantic_json, checkpoint_reason) = {
            let map = self.sessions.read_recover();
            let sem = map
                .get(path)
                .and_then(|s| serde_json::to_string(&s.semantic_counts).ok());
            // Build checkpoint reason with forensic context from session state.
            let reason = if let Some(s) = map.get(path) {
                let mut parts = vec!["Auto-checkpoint".to_string()];
                if s.transcription_suspicion.is_suspicious {
                    parts.push(format!(
                        "[transcription-flagged: correction_ratio={:.2}%, ecology={:.2}]",
                        s.transcription_suspicion.unexplained_correction_ratio * 100.0,
                        s.transcription_suspicion.ecology_score,
                    ));
                }
                if s.transcription_suspicion.sample_count >= 20 {
                    let multiplier: f64 = if s.transcription_suspicion.ecology_score > 0.7 {
                        1.5
                    } else if s.transcription_suspicion.ecology_score < 0.3 {
                        0.5
                    } else {
                        1.0
                    };
                    if (multiplier - 1.0).abs() > f64::EPSILON {
                        parts.push(format!("[interval-multiplier: {multiplier:.1}x]"));
                    }
                }
                parts.join(" ")
            } else {
                "Auto-checkpoint".to_string()
            };
            (sem, reason)
        };
        let sessions_ref = &self.sessions;
        let committed = tokio::task::spawn_blocking(move || {
            super::helpers::commit_checkpoint_for_path_with_semantics(
                &cp_path,
                &checkpoint_reason,
                &cp_key,
                &cp_dir,
                &nonce_for_closure,
                &cp_stop,
                semantic_json,
                &cp_anchor,
                captured_text,
            )
        })
        .await
        .unwrap_or_else(|e| {
            log::error!("Checkpoint task panicked for {}: {e}", path);
            let mut map = sessions_ref.write_recover();
            if let Some(session) = map.get_mut(path) {
                session.last_checkpoint_keystrokes = session.keystroke_count;
            }
            None
        });

        if let Some(event_hash) = committed {
            self.confirm_nonce_for_checkpoint(path, &event_hash, nonce_id);
        }
        if committed.is_some() {
            return self.post_checkpoint_work(path, challenge_nonce);
        }
        false
    }

    /// Nonce confirmation is handled by the Swift layer.  This stub
    /// preserves the call site so checkpoint code doesn't need to change.
    fn confirm_nonce_for_checkpoint(
        &self,
        _path: &str,
        _event_hash: &[u8; 32],
        _nonce_id: &Option<String>,
    ) {
    }

    /// Persist stats, create text fragment, save snapshot, and HW co-sign
    /// after a successful checkpoint. Returns `true` to signal breaking out
    /// of the candidates loop (HW co-sign file-read failure).
    fn post_checkpoint_work(&self, path: &str, challenge_nonce: &Option<String>) -> bool {
        // AUD-041: signing_key must be acquired before sessions.
        let sk_opt = {
            let guard = self.signing_key_for_cp.read_recover();
            guard.key()
        };
        let session_snapshot = {
            let mut map = self.sessions.write_recover();
            map.get_mut(path).map(|session| {
                session.last_checkpoint_keystrokes = session.keystroke_count;
                session.checkpoint_count += 1;
                (
                    session.total_keystrokes(),
                    session.total_focus_ms_cumulative(),
                    session.session_number,
                    session
                        .start_time
                        .elapsed()
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    session
                        .first_tracked_at
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    session.last_checkpoint_keystrokes,
                    session.hw_cosign_scheduler.is_some(),
                    session.session_id.clone(),
                    !session.paste_context.is_empty(),
                    session.app_bundle_id.clone(),
                    session.window_title.reveal().to_string(),
                    session.transcription_suspicion.ecology_score,
                    session.checkpoint_count,
                )
            })
        };
        let Some((
            total_ks,
            focus_ms,
            session_num,
            duration_secs,
            first_at,
            _ordinal,
            has_hw_sched,
            session_id,
            has_paste_ctx,
            app_bundle_id,
            window_title,
            ecology_score,
            checkpoint_count,
        )) = session_snapshot
        else {
            return false;
        };

        // Hash the file ONCE for text fragment + HW co-sign + snapshot.
        let content_hash_opt = if !path.starts_with("shadow://") {
            crate::crypto::hash_file_with_size(std::path::Path::new(path))
                .map(|(h, _)| h)
                .ok()
        } else {
            None
        };

        let sk_for_frag = sk_opt.clone();
        // Lock ordering note: cached_store(3) is acquired here WITHOUT
        // sessions(2) because sessions was already dropped above and is
        // not re-acquired in this scope. This block ends before the
        // hw_cosign path below, which acquires sessions(2) then
        // cached_store(3) per AUD-041. No overlapping holds, no cycle.
        if let Some(ref mut store) = *self.cached_store.lock_recover() {
            let stats = crate::store::DocumentStats {
                file_path: path.to_string(),
                total_keystrokes: i64::try_from(total_ks).unwrap_or(i64::MAX),
                total_focus_ms: focus_ms,
                session_count: i64::from(session_num + 1),
                total_duration_secs: duration_secs,
                first_tracked_at: first_at,
                last_tracked_at: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                total_checkpoints: i64::try_from(checkpoint_count).unwrap_or(i64::MAX),
            };
            if let Err(e) = store.save_document_stats(&stats) {
                log::warn!("Failed to save document stats for {path}: {e}");
            }

            if let Some(frag_hash) = content_hash_opt {
                self.save_text_fragment(
                    store,
                    path,
                    &session_id,
                    has_paste_ctx,
                    &app_bundle_id,
                    &window_title,
                    sk_for_frag.as_ref(),
                    frag_hash,
                    ecology_score,
                );
            }
        }

        if self.snapshots_flag.load(Ordering::SeqCst) && !path.starts_with("shadow://") {
            if let Some(ref sk) = sk_opt {
                let snap_db = self.writersproof_dir.join("snapshots.db");
                match crate::snapshot::SnapshotStore::open(&snap_db, sk) {
                    Ok(mut snap_store) => {
                        let src = std::path::Path::new(path);
                        match std::fs::read_to_string(src) {
                            Ok(content) => {
                                if let Err(e) = snap_store.save(path, &content, false) {
                                    log::debug!(
                                        "Snapshot save failed for \
                                         {path}: {e}"
                                    );
                                }
                            }
                            Err(e) => {
                                log::debug!("Snapshot read failed for {path}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to open snapshot store: {e}");
                    }
                }
            }
        }

        if has_hw_sched {
            if let Some(ref tpm) = self.tpm_provider {
                let Some(content_hash) = content_hash_opt else {
                    log::warn!("Skipping HW co-sign: content hash unavailable for {}", path);
                    return true;
                };
                let nonce_bytes_opt =
                    challenge_nonce
                        .as_ref()
                        .and_then(|nonce_hex| match hex::decode(nonce_hex) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                Some(arr)
                            }
                            _ => {
                                log::debug!(
                                    "Failed to decode challenge nonce \
                                     for binding"
                                );
                                None
                            }
                        });

                // AUD-041: sessions(2) before cached_store(3).
                let mut map = self.sessions.write_recover();
                let store_guard = self.cached_store.lock_recover();
                if let Some(session) = map.get_mut(path) {
                    try_hw_cosign(
                        session,
                        tpm.as_ref(),
                        &content_hash,
                        nonce_bytes_opt.as_ref(),
                        store_guard.as_ref().map(|s| (s, path)),
                    );
                }
            }
        }
        false
    }

    /// Create and insert a text fragment for a checkpoint window.
    #[allow(clippy::too_many_arguments)]
    fn save_text_fragment(
        &self,
        store: &mut crate::store::SecureStore,
        path: &str,
        session_id: &str,
        has_paste_ctx: bool,
        app_bundle_id: &str,
        window_title: &str,
        sk: Option<&SigningKey>,
        frag_hash: [u8; 32],
        ecology_score: f64,
    ) {
        let ts = crate::store::text_fragments::current_timestamp_ms();
        let nonce = crate::store::text_fragments::generate_nonce();
        let ctx = if has_paste_ctx {
            crate::store::text_fragments::KeystrokeContext::PastedContent
        } else {
            crate::store::text_fragments::KeystrokeContext::OriginalComposition
        };
        let Some(sk) = sk else {
            return;
        };
        let sig =
            crate::store::text_fragments::sign_fragment(sk, session_id, &frag_hash, ts, &nonce);
        let fragment = crate::store::text_fragments::TextFragment {
            id: None,
            fragment_hash: frag_hash.to_vec(),
            session_id: session_id.to_string(),
            source_app_bundle_id: Some(app_bundle_id.to_string()).filter(|s| !s.is_empty()),
            source_window_title: Some(window_title.to_string()).filter(|s| !s.is_empty()),
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: ts,
            keystroke_context: Some(ctx),
            // ecology_score is 0.0 before first assessment (at 100 keystrokes);
            // default to 1.0 (assume genuine) until enough samples exist.
            keystroke_confidence: Some(
                if ecology_score.is_finite() && ecology_score > f64::EPSILON {
                    ecology_score.clamp(0.0, 1.0)
                } else {
                    1.0
                },
            ),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };
        if let Err(e) = store.insert_text_fragment(&fragment) {
            log::warn!("Failed to insert text fragment for {path}: {e}");
        }
    }

    /// React to permission state changes (revoked / restored).
    pub(super) fn handle_permission_check(&self) {
        let current = super::permission_monitor::PermissionState::current();
        let mut guard = self.permission_state.lock_recover();
        let prev = *guard;
        if current == prev {
            return;
        }
        *guard = current;
        drop(guard);
        if !current.keystroke_capture_allowed() && prev.keystroke_capture_allowed() {
            log::warn!(
                "Permission revoked ({} → {}); stopping keystroke capture",
                prev.as_str(),
                current.as_str()
            );
            *self.tap_check_capture.lock_recover() = None;
            self.tap_check_active.store(false, Ordering::SeqCst);
        } else if current.keystroke_capture_allowed() && !prev.keystroke_capture_allowed() {
            log::info!(
                "Permission restored ({} → {}); restarting keystroke capture",
                prev.as_str(),
                current.as_str()
            );
            self.restart_capture_after_permission_grant();
        }
    }

    /// Re-create keystroke capture after accessibility permission is restored.
    fn restart_capture_after_permission_grant(&self) {
        let tx_opt = self.keystroke_event_tx.lock_recover().clone();
        let Some(tx) = tx_opt else { return };
        match self.platform.create_keystroke_capture() {
            Ok(mut cap) => match cap.start() {
                Ok(sync_rx) => {
                    *self.tap_check_capture.lock_recover() = Some(cap);
                    self.tap_check_active.store(true, Ordering::SeqCst);
                    let r = Arc::clone(&self.running);
                    let a = Arc::clone(&self.tap_check_active);
                    let h = std::thread::Builder::new()
                        .name("cpoe-keystroke-resume".into())
                        .spawn(move || {
                            while r.load(Ordering::SeqCst) && a.load(Ordering::SeqCst) {
                                match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                                    Ok(ev) => {
                                        if tx.try_send(ev).is_err() {
                                            break;
                                        }
                                    }
                                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                                }
                            }
                        });
                    match h {
                        Ok(handle) => {
                            let mut ts = self.bridge_health_threads.lock_recover();
                            ts.retain(|t| !t.is_finished());
                            ts.push(handle);
                            self.bridge_healthy_flag.store(true, Ordering::SeqCst);
                        }
                        Err(e) => log::error!("Failed to spawn keystroke-resume bridge: {e}"),
                    }
                }
                Err(e) => log::warn!("Keystroke restart failed after permission grant: {e}"),
            },
            Err(e) => log::warn!("Keystroke unavailable after permission grant: {e}"),
        }
    }
}
