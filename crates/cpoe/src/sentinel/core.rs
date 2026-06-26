// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::helpers::*;
use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::platform::{KeystrokeCapture, MouseCapture};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
use zeroize::{Zeroize, Zeroizing};

/// Sentinel source PID for events pre-verified by CGEventTap.
///
/// Negative value distinguishes pre-verified tap events from real PIDs (>0)
/// and synthetic/injected events (0). The validation layer does not penalize
/// negative PIDs.
pub(super) const CGEVENTTAP_VERIFIED_PID: i64 = -1;

/// Async channel buffer size for keystroke and mouse bridge threads.
pub(super) const EVENT_CHANNEL_BUFFER: usize = 1000;

use super::event_handlers::EventLoopCtx;

/// Lock ordering levels for AUD-041 enforcement.
/// Lower values must be acquired before higher values.
#[cfg(debug_assertions)]
pub(super) mod lock_order {
    use std::cell::RefCell;

    /// Ordering: signing_key(1) < sessions(2) < cached_store(3) < current_focus(4).
    pub const SIGNING_KEY: u8 = 1;
    pub const SESSIONS: u8 = 2;
    #[allow(dead_code)]
    pub const CACHED_STORE: u8 = 3;

    thread_local! {
        /// Stack of currently-held lock levels (in acquisition order).
        static HELD_STACK: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    /// Assert that acquiring a lock at `level` does not violate ordering.
    /// Panics in debug builds if a higher-or-equal-ordered lock is already held.
    pub fn assert_order(level: u8) -> LockOrderGuard {
        HELD_STACK.with(|stack| {
            let s = stack.borrow();
            let held = s.last().copied().unwrap_or(0);
            debug_assert!(
                held < level,
                "Lock ordering violation (AUD-041): attempted to acquire level {level} \
                 while level {held} is held. Order: signing_key(1) < sessions(2) < cached_store(3) < focus(4)."
            );
        });
        HELD_STACK.with(|stack| stack.borrow_mut().push(level));
        LockOrderGuard { level }
    }

    /// RAII guard to ensure lock level is released on drop.
    pub struct LockOrderGuard {
        level: u8,
    }

    impl Drop for LockOrderGuard {
        fn drop(&mut self) {
            release(self.level);
        }
    }

    /// Release: pop the most recently acquired matching level off the stack.
    pub fn release(level: u8) {
        HELD_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            if let Some(pos) = s.iter().rposition(|&l| l == level) {
                s.remove(pos);
            }
        });
    }
}

/// Core sentinel daemon for document focus tracking and session management.
///
/// # Lock ordering convention (AUD-041)
///
/// When acquiring multiple locks, always acquire in this order to prevent deadlocks:
///   1. `signing_key` (RwLock)
///   2. `sessions` (RwLock)
///   3. `cached_store` (Mutex)
///   4. `current_focus` (RwLock)
///   5. All other Mutex-protected fields (no ordering between them)
///
/// Never acquire `sessions` before `signing_key`, or `cached_store` before `sessions`.
/// In debug builds, `lock_order::assert_order` enforces this at runtime.
pub struct Sentinel {
    pub(crate) config: Arc<SentinelConfig>,
    /// Runtime toggle for document snapshots (can be changed without restart).
    pub(crate) snapshots_enabled: Arc<AtomicBool>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    pub(crate) shadow: Arc<ShadowManager>,
    pub(crate) current_focus: Arc<RwLock<Option<String>>>,
    /// When set, only this document path is monitored; focus events for other
    /// documents are silently ignored. Set by `start_witnessing()`, cleared by
    /// `stop_witnessing()` or `clear_targeted_mode()`.
    pub(crate) targeted_path: Arc<RwLock<Option<String>>>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) signing_key: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    pub(crate) activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    pub(crate) session_events_tx: broadcast::Sender<SessionEvent>,
    pub(crate) shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    pub(crate) style_collector: Arc<RwLock<Option<crate::fingerprint::StyleCollector>>>,
    mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    session_nonce: Arc<RwLock<Option<[u8; 32]>>>,
    pub(super) bridge_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /// Handle for the main event loop task; aborted on Drop if stop() was never called.
    event_loop_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Active keystroke capture; stored so stop() can clean up CGEventTap threads.
    pub(super) keystroke_capture: Arc<Mutex<Option<Box<dyn KeystrokeCapture>>>>,
    /// Active mouse capture; stored so stop() can clean up CGEventTap threads.
    pub(super) mouse_capture: Arc<Mutex<Option<Box<dyn MouseCapture>>>>,
    /// Whether keystroke capture is active (false = degraded/focus-only mode).
    pub(crate) keystroke_capture_active: Arc<AtomicBool>,
    /// Last paste character count reported by the host app.
    last_paste_chars: Arc<std::sync::atomic::AtomicI64>,
    /// Pre-fetched challenge nonce from the host app, consumed by the next checkpoint.
    /// Tuple: (nonce_value, nonce_id). `nonce_id` is `None` for FFI-sourced nonces
    /// (which arrive without a server-side UUID for confirmation).
    #[allow(clippy::type_complexity)]
    pub(crate) pending_challenge: Arc<RwLock<Option<(String, Option<String>)>>>,
    /// Signaled when a new nonce arrives so the checkpoint timer can recalculate.
    pub(crate) nonce_notify: Arc<tokio::sync::Notify>,
    /// Signaled by the keystroke handler when the jitter hash chain crosses
    /// the entropy trigger threshold. The select loop fires a checkpoint.
    entropy_checkpoint_notify: Arc<tokio::sync::Notify>,
    /// Timestamp when the sentinel was started via start().
    pub(crate) start_time: Arc<Mutex<Option<SystemTime>>>,
    /// False when any bridge thread has died; checked before processing events.
    bridge_healthy: Arc<AtomicBool>,
    /// Set to `true` when `stop()` begins; checked by checkpoint tasks to bail
    /// before opening SQLite, preventing a `findReusableFd` mutex deadlock.
    stopping: Arc<AtomicBool>,
    /// Hardware TPM/Secure Enclave provider for co-sign scheduling.
    pub(crate) tpm_provider: Option<Arc<dyn crate::tpm::Provider>>,
    /// Platform-specific hardware and OS feature provider.
    pub(crate) platform: Arc<dyn crate::platform::PlatformProvider>,
    /// Unified app registry (built-in + user-added writing apps).
    #[allow(dead_code)]
    pub(crate) app_registry: Arc<RwLock<super::app_registry::AppRegistry>>,
    /// Cached SQLite event store; lazily opened when the signing key is first
    /// available, invalidated on key change. Eliminates per-checkpoint connection
    /// churn (WAL init, HMAC key derivation, integrity verification on every open).
    pub(crate) cached_store: Arc<Mutex<Option<crate::store::SecureStore>>>,
    /// Current OS permission state for keystroke capture; updated every 30 s.
    pub(crate) permission_state: Arc<Mutex<super::permission_monitor::PermissionState>>,
    /// Sender half of the keystroke async channel kept alive so new bridge
    /// threads spawned by `restart_keystroke_capture` write to the same
    /// receiver that the event loop already holds.
    pub(super) keystroke_event_tx:
        Arc<Mutex<Option<mpsc::Sender<crate::platform::KeystrokeEvent>>>>,
    /// Cancellation token for the clipboard monitor task; set in start(), cancelled in stop().
    clipboard_cancel: Arc<Mutex<Option<tokio_util::sync::CancellationToken>>>,
    /// Active `BundleMonitor`s keyed by bundle root path; started on first focus of a bundle doc.
    bundle_monitors: Arc<Mutex<HashMap<String, super::bundle_monitor::BundleMonitor>>>,
    /// Sender into the main change-event channel; shared with bundle monitors.
    bundle_change_tx: Arc<Mutex<Option<mpsc::Sender<super::types::ChangeEvent>>>>,
    /// Directory watcher for active document sessions (file-save correlation).
    document_watcher: Arc<Mutex<Option<super::document_watcher::DocumentDirectoryWatcher>>>,
    /// Content fingerprints for active sessions, used for cross-app linking.
    content_fingerprints: Arc<
        Mutex<
            Vec<(
                String,
                String,
                super::content_fingerprint::ContentFingerprint,
            )>,
        >,
    >,
    /// Anchor manager for OTS/RFC 3161/notary timestamping after checkpoint commits.
    pub(crate) anchor_manager: Option<Arc<crate::anchors::AnchorManager>>,
}

impl Sentinel {
    /// Create a new sentinel from the given configuration using the default platform provider.
    pub fn new(config: SentinelConfig) -> Result<Self> {
        Self::with_platform(config, Arc::new(crate::platform::DefaultPlatformProvider))
    }

    /// Create a new sentinel from the given configuration and a custom platform provider.
    pub fn with_platform(
        config: SentinelConfig,
        platform: Arc<dyn crate::platform::PlatformProvider>,
    ) -> Result<Self> {
        config
            .validate()
            .map_err(|e| SentinelError::InvalidConfig(e.to_string()))?;
        config
            .ensure_directories()
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;

        let shadow = ShadowManager::new(&config.shadow_dir)?;
        let (session_events_tx, _) = broadcast::channel(256);

        let mut mouse_stego_seed = Zeroizing::new([0u8; 32]);
        use rand::RngCore;
        rand::rng().fill_bytes(mouse_stego_seed.as_mut());

        let snapshots_default = config.snapshots_enabled;

        let tpm_provider = platform.get_tpm_provider();

        let app_registry = super::app_registry::AppRegistry::load(&config.writersproof_dir);
        // Install a clone as the global so static lookup()/needs_title_inference()
        // functions consult user-added apps without threading the registry instance.
        super::app_registry::install_global(app_registry.clone());

        let sentinel = Self {
            config: Arc::new(config),
            snapshots_enabled: Arc::new(AtomicBool::new(snapshots_default)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shadow: Arc::new(shadow),
            current_focus: Arc::new(RwLock::new(None)),
            targeted_path: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            signing_key: Arc::new(RwLock::new(super::behavioral_key::BehavioralKey::new(
                std::time::Duration::from_secs(30),
            ))),
            session_events_tx,
            shutdown_tx: Arc::new(Mutex::new(None)),
            activity_accumulator: crate::fingerprint::global::get_global_accumulator(),
            style_collector: Arc::new(RwLock::new(None)),
            mouse_idle_stats: Arc::new(RwLock::new(crate::platform::MouseIdleStats::new())),
            mouse_stego_engine: Arc::new(RwLock::new(crate::platform::MouseStegoEngine::new(
                *mouse_stego_seed,
            ))),
            session_nonce: Arc::new(RwLock::new(None)),
            bridge_threads: Arc::new(Mutex::new(Vec::new())),
            event_loop_handle: Arc::new(Mutex::new(None)),
            keystroke_capture: Arc::new(Mutex::new(None)),
            mouse_capture: Arc::new(Mutex::new(None)),
            keystroke_capture_active: Arc::new(AtomicBool::new(false)),
            last_paste_chars: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            pending_challenge: Arc::new(RwLock::new(None)),
            nonce_notify: Arc::new(tokio::sync::Notify::new()),
            entropy_checkpoint_notify: Arc::new(tokio::sync::Notify::new()),
            start_time: Arc::new(Mutex::new(None)),
            bridge_healthy: Arc::new(AtomicBool::new(true)),
            stopping: Arc::new(AtomicBool::new(false)),
            tpm_provider,
            platform,
            app_registry: Arc::new(RwLock::new(app_registry)),
            cached_store: Arc::new(Mutex::new(None)),
            permission_state: Arc::new(Mutex::new(
                super::permission_monitor::PermissionState::default(),
            )),
            keystroke_event_tx: Arc::new(Mutex::new(None)),
            clipboard_cancel: Arc::new(Mutex::new(None)),
            bundle_monitors: Arc::new(Mutex::new(HashMap::new())),
            bundle_change_tx: Arc::new(Mutex::new(None)),
            document_watcher: Arc::new(Mutex::new(None)),
            content_fingerprints: Arc::new(Mutex::new(Vec::new())),
            anchor_manager: None,
        };
        Ok(sentinel)
    }

    /// Enable external timestamping anchors for checkpoint commits.
    pub fn set_anchor_manager(&mut self, manager: crate::anchors::AnchorManager) {
        self.anchor_manager = Some(Arc::new(manager));
    }

    /// Return the session nonce, generating one if not yet set.
    pub fn get_or_generate_nonce(&self) -> [u8; 32] {
        let mut nonce_lock = self.session_nonce.write_recover();
        if let Some(nonce) = *nonce_lock {
            nonce
        } else {
            let mut nonce = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut nonce);
            *nonce_lock = Some(nonce);
            nonce
        }
    }

    /// Clear the session nonce so a new one will be generated on next access.
    pub fn reset_nonce(&self) {
        let mut nonce_lock = self.session_nonce.write_recover();
        if let Some(ref mut nonce) = *nonce_lock {
            nonce.zeroize();
        }
        *nonce_lock = None;
    }

    /// Enable style fingerprint collection for behavioral biometrics.
    pub fn enable_style_fingerprinting(&self) {
        let mut collector = self.style_collector.write_recover();
        if collector.is_none() {
            *collector = Some(crate::fingerprint::StyleCollector::new());
        }
    }

    /// Disable style fingerprint collection and discard the collector.
    pub fn disable_style_fingerprinting(&self) {
        let mut collector = self.style_collector.write_recover();
        *collector = None;
    }

    /// Return a snapshot of the current activity fingerprint.
    pub fn current_activity_fingerprint(&self) -> Arc<crate::fingerprint::ActivityFingerprint> {
        self.activity_accumulator
            .read_recover()
            .current_fingerprint()
    }

    /// Toggle document snapshot saving at runtime.
    pub fn set_snapshots_enabled(&self, enabled: bool) {
        self.snapshots_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn keystroke_count(&self) -> u64 {
        self.activity_accumulator
            .read_recover()
            .to_session_summary()
            .keystroke_count
    }

    /// Inject a jitter sample into the activity accumulator (for testing).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn inject_sample(&self, sample: &crate::jitter::SimpleJitterSample) {
        self.activity_accumulator.write_recover().add_sample(sample);
    }

    /// Return the current style fingerprint, if collection is enabled.
    pub fn current_style_fingerprint(&self) -> Option<crate::fingerprint::StyleFingerprint> {
        self.style_collector
            .read_recover()
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

    /// Return a snapshot of mouse idle statistics during typing.
    pub fn mouse_idle_stats(&self) -> crate::platform::MouseIdleStats {
        self.mouse_idle_stats.read_recover().clone()
    }

    /// Reset mouse idle statistics to initial state.
    pub fn reset_mouse_idle_stats(&self) {
        *self.mouse_idle_stats.write_recover() = crate::platform::MouseIdleStats::new();
    }

    /// Update the mouse stego engine from the given key bytes (avoids re-acquiring signing_key lock).
    fn update_mouse_stego_seed_from(&self, key_bytes: &[u8; 32]) {
        let seed = Zeroizing::new(*key_bytes);
        let mut engine = self.mouse_stego_engine.write_recover();
        engine.reset();
        *engine = crate::platform::MouseStegoEngine::new(*seed);
    }

    /// Set the Ed25519 signing key and update the mouse stego seed.
    ///
    /// Rejects all-zero keys as invalid (likely uninitialized).
    pub fn set_signing_key(&self, key: SigningKey) {
        let key_bytes = Zeroizing::new(key.to_bytes());
        if key_bytes.iter().all(|&b| b == 0) {
            log::error!(
                "Rejected all-zero signing key — likely uninitialized; evidence will not be signed"
            );
            return;
        }
        self.signing_key.write_recover().set_key(key);
        // Invalidate cached store — the HMAC key derives from the signing key.
        *self.cached_store.lock_recover() = None;
        // Update stego seed without re-acquiring the signing_key lock
        self.update_mouse_stego_seed_from(&key_bytes);
    }

    /// Set the signing key from raw HMAC key bytes (must be exactly 32 bytes).
    ///
    /// Takes `Zeroizing<Vec<u8>>` so the key buffer is zeroed on drop even if
    /// this function panics or returns early before the explicit zeroize calls.
    pub fn set_hmac_key(&self, key: Zeroizing<Vec<u8>>) {
        if key.len() != 32 {
            log::warn!("HMAC key length {} is not 32 bytes, ignoring", key.len());
            return;
        }
        if key.iter().all(|&b| b == 0) {
            log::warn!("Rejected all-zero HMAC key — likely uninitialized");
            return;
        }
        let bytes: Zeroizing<[u8; 32]> = match key.as_slice().try_into() {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                log::error!("HMAC key must be exactly 32 bytes");
                return;
            }
        };
        let signing_key = SigningKey::from_bytes(&bytes);
        self.signing_key.write_recover().set_key(signing_key);
        *self.cached_store.lock_recover() = None;
        self.update_mouse_stego_seed_from(&bytes);
    }

    /// Get or lazily open the cached SecureStore connection.
    ///
    /// Returns `None` if the signing key is not yet available. The store is
    /// invalidated automatically when the signing key changes via
    /// `set_signing_key` / `set_hmac_key`.
    ///
    /// AUD-041: signing_key is read *before* cached_store is locked to
    /// preserve the ordering signing_key(1) < sessions(2) < cached_store(3).
    pub(crate) fn get_or_open_store(
        &self,
    ) -> Option<std::sync::MutexGuard<'_, Option<crate::store::SecureStore>>> {
        // Fast path: store already open — only needs the Mutex.
        {
            let guard = self.cached_store.lock_recover();
            if guard.is_some() {
                return Some(guard);
            }
        }
        // Slow path: read signing_key *first* (AUD-041), then re-acquire
        // cached_store to populate it.
        let sk = self.signing_key.read_recover().key()?;
        let db_path = self.config.writersproof_dir.join("events.db");
        let mut guard = self.cached_store.lock_recover();
        // Re-check after re-acquiring — another thread may have opened it.
        if guard.is_some() {
            return Some(guard);
        }
        match crate::store::open_store_with_signing_key(&sk, &db_path) {
            Ok(store) => {
                *guard = Some(store);
                Some(guard)
            }
            Err(e) => {
                log::warn!("Failed to open cached store: {e}");
                None
            }
        }
    }

    /// Start the sentinel event loop (focus, keystroke, mouse monitoring).
    ///
    /// The `running` flag is set **after** all subsystems have initialized successfully
    /// so that `is_running()` only returns `true` when the sentinel is fully operational.
    pub async fn start(&self) -> Result<()> {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SentinelError::AlreadyRunning);
        }

        *self.start_time.lock_recover() = Some(SystemTime::now());

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock_recover() = Some(shutdown_tx);

        let (focus_monitor, mut focus_rx, mut change_rx, change_tx_for_bundles) =
            match self.setup_focus_tracker() {
                Ok(f) => f,
                Err(e) => {
                    self.running.store(false, Ordering::SeqCst);
                    return Err(e);
                }
            };
        *self.bundle_change_tx.lock_recover() = Some(change_tx_for_bundles.clone());

        match super::document_watcher::DocumentDirectoryWatcher::new(change_tx_for_bundles) {
            Ok(dw) => {
                *self.document_watcher.lock_recover() = Some(dw);
            }
            Err(e) => {
                log::warn!("document_watcher: failed to initialize: {e}");
            }
        }

        self.bridge_healthy.store(true, Ordering::SeqCst);
        self.stopping.store(false, Ordering::SeqCst);

        let sessions = Arc::clone(&self.sessions);
        let current_focus = Arc::clone(&self.current_focus);
        let targeted_path = Arc::clone(&self.targeted_path);
        let config = self.config.clone();
        let shadow = Arc::clone(&self.shadow);
        let signing_key = Arc::clone(&self.signing_key);
        let session_events_tx = self.session_events_tx.clone();
        let running = Arc::clone(&self.running);
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        let wal_dir = config.wal_dir.clone();

        let mut keystroke_rx = self.setup_keystroke_bridge(&running);
        let mut mouse_rx = self.setup_mouse_bridge(&running);

        let activity_accumulator = Arc::clone(&self.activity_accumulator);
        let style_collector = Arc::clone(&self.style_collector);
        let mouse_idle_stats = Arc::clone(&self.mouse_idle_stats);
        let mouse_stego_engine = Arc::clone(&self.mouse_stego_engine);

        let checkpoint_interval_secs = config.checkpoint_interval_secs;
        let idle_check_interval_secs = config.idle_check_interval_secs;
        let writersproof_dir = config.writersproof_dir.clone();
        let signing_key_for_cp = Arc::clone(&self.signing_key);
        let stopping_flag = Arc::clone(&self.stopping);
        let pending_challenge = Arc::clone(&self.pending_challenge);
        let nonce_notify = Arc::clone(&self.nonce_notify);
        let entropy_checkpoint_notify = Arc::clone(&self.entropy_checkpoint_notify);

        // Re-focus preserved sessions from a prior run so that keystrokes
        // are attributed immediately, without waiting for the focus probe.
        // Also reset EventValidationState to avoid stale clock_discontinuity
        // and burst penalties from the pre-restart timestamps.
        {
            let focus = self.current_focus.read_recover().clone();
            if let Some(ref path) = focus {
                if let Some(session) = self.sessions.write_recover().get_mut(path.as_str()) {
                    session.focus_gained();
                    session.event_validation = Default::default();
                }
            }
        }

        let tpm_provider_for_loop = self.tpm_provider.clone();

        let tap_check_capture = Arc::clone(&self.keystroke_capture);
        let tap_check_active = Arc::clone(&self.keystroke_capture_active);
        let bridge_health_threads = Arc::clone(&self.bridge_threads);
        let bridge_healthy_flag = Arc::clone(&self.bridge_healthy);
        let snapshots_flag = Arc::clone(&self.snapshots_enabled);

        let cached_store_for_loop = Arc::clone(&self.cached_store);
        let permission_state_for_loop = Arc::clone(&self.permission_state);
        let keystroke_event_tx_for_loop = Arc::clone(&self.keystroke_event_tx);
        let platform_for_loop = Arc::clone(&self.platform);
        let mut session_events_rx = self.session_events_tx.subscribe();
        let bundle_monitors_for_loop = Arc::clone(&self.bundle_monitors);
        let bundle_change_tx_for_loop = Arc::clone(&self.bundle_change_tx);
        let document_watcher_for_loop = Arc::clone(&self.document_watcher);
        let content_fingerprints_for_loop = Arc::clone(&self.content_fingerprints);
        let anchor_manager_for_loop = self.anchor_manager.clone();

        let event_loop_handle_ref = Arc::clone(&self.event_loop_handle);
        let handle = tokio::spawn(async move {
            let mut ctx = EventLoopCtx {
                sessions,
                current_focus,
                targeted_path,
                config,
                shadow,
                signing_key,
                signing_key_for_cp,
                session_events_tx,
                running,
                idle_timeout,
                wal_dir,
                activity_accumulator,
                style_collector,
                mouse_idle_stats,
                mouse_stego_engine,
                writersproof_dir,
                stopping_flag,
                pending_challenge,
                nonce_notify,
                entropy_checkpoint_notify,
                tpm_provider: tpm_provider_for_loop,
                tap_check_capture,
                tap_check_active,
                bridge_health_threads,
                bridge_healthy_flag,
                snapshots_flag,
                cached_store: cached_store_for_loop,
                permission_state: permission_state_for_loop,
                keystroke_event_tx: keystroke_event_tx_for_loop,
                platform: platform_for_loop,
                bundle_monitors: bundle_monitors_for_loop,
                bundle_change_tx: bundle_change_tx_for_loop,
                document_watcher: document_watcher_for_loop,
                content_fingerprints: content_fingerprints_for_loop,
                anchor_manager: anchor_manager_for_loop,
                last_keystroke_time: std::time::Instant::now(),
                last_keydown_ts_ns: 0,
                last_mouse_ts_ns: 0,
                pending_downs: HashMap::new(),
                last_keyup_ts_ns: 0,
                last_fingerprint_time: HashMap::new(),
                last_capture_restart: None,
                cached_focus: None,
                xwin_check_tx: None,
                xwin_check_handle: None,
                xwin_keystroke_counter: 0,
            };

            ctx.cached_focus = ctx.current_focus.read_recover().clone();

            let mut idle_check_interval = interval(Duration::from_secs(idle_check_interval_secs));
            let checkpoint_sleep =
                tokio::time::sleep(ctx.compute_next_checkpoint_interval(checkpoint_interval_secs));
            tokio::pin!(checkpoint_sleep);
            let mut challenge_interval = interval(Duration::from_secs(30));
            let mut permission_check_interval = interval(Duration::from_secs(30));

            super::trace!("[EVENT_LOOP] started");
            log::debug!("sentinel event loop entering main select loop");

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    result = session_events_rx.recv() => {
                        match result {
                            Ok(event) => ctx.handle_session_event(event),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("Session event receiver lagged, missed {n} events");
                                let focus = ctx.current_focus.read_recover().clone();
                                if let Some(ref path) = focus {
                                    if let Some(session) = ctx.sessions.write_recover().get_mut(path.as_str()) {
                                        session.capture_gaps = session.capture_gaps.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Some(event) = keystroke_rx.recv() => {
                        ctx.handle_keystroke_event(event);
                    }
                    Some(event) = mouse_rx.recv() => {
                        ctx.handle_mouse_event(event);
                    }
                    Some(event) = focus_rx.recv() => {
                        ctx.handle_focus_branch(event);
                    }
                    Some(event) = change_rx.recv() => {
                        ctx.handle_change_branch(&event);
                    }
                    _ = idle_check_interval.tick() => {
                        ctx.handle_idle_check().await;
                    }
                    _ = challenge_interval.tick() => {
                        ctx.handle_challenge_tick();
                    }
                    _ = &mut checkpoint_sleep => {
                        ctx.handle_checkpoint_tick().await;
                        // Recompute next interval from fresh entropy + nonce.
                        checkpoint_sleep.as_mut().reset(
                            tokio::time::Instant::now()
                                + ctx.compute_next_checkpoint_interval(checkpoint_interval_secs),
                        );
                    }
                    _ = ctx.entropy_checkpoint_notify.notified() => {
                        // Entropy-triggered: jitter hash chain crossed threshold.
                        // The keystroke handler already enforced the MIN_NS floor.
                        log::debug!("Entropy-triggered checkpoint firing");
                        ctx.handle_checkpoint_tick().await;
                        checkpoint_sleep.as_mut().reset(
                            tokio::time::Instant::now()
                                + ctx.compute_next_checkpoint_interval(checkpoint_interval_secs),
                        );
                    }
                    _ = ctx.nonce_notify.notified() => {
                        // Nonce arrived — recalculate checkpoint deadline so the
                        // checkpoint fires within the nonce's TTL window.
                        checkpoint_sleep.as_mut().reset(
                            tokio::time::Instant::now()
                                + ctx.compute_next_checkpoint_interval(checkpoint_interval_secs),
                        );
                        log::debug!("Checkpoint timer reset: nonce arrived");
                    }
                    _ = permission_check_interval.tick() => {
                        ctx.handle_permission_check();
                    }
                }

                if !ctx.running.load(Ordering::SeqCst) {
                    break;
                }
            }

            log::debug!("sentinel event loop exited main select loop");
            if let Err(e) = focus_monitor.stop() {
                log::debug!("focus monitor stop: {e}");
            }
            // Session unfocus is now handled by Sentinel::stop() directly
            // (not here) to avoid the abort race where this cleanup code
            // might never run if the event loop handle is aborted first.
        });

        *event_loop_handle_ref.lock_recover() = Some(handle);

        let clipboard_cancel = tokio_util::sync::CancellationToken::new();
        *self.clipboard_cancel.lock_recover() = Some(clipboard_cancel.clone());
        match super::clipboard::ClipboardMonitor::new() {
            Ok(monitor) => {
                let monitor = Arc::new(monitor);
                let cb_sessions = Arc::clone(&self.sessions);
                let cb_store = Arc::clone(&self.cached_store);
                let cb_key = Arc::clone(&self.signing_key);
                tokio::spawn(async move {
                    if let Err(e) = monitor
                        .monitor_loop(cb_sessions, cb_store, cb_key, clipboard_cancel)
                        .await
                    {
                        log::warn!("Clipboard monitor exited: {e}");
                    }
                });
            }
            Err(e) => {
                log::warn!("Clipboard monitor init failed: {e}");
            }
        }

        Ok(())
    }

    /// Stop the sentinel, joining bridge threads and cleaning up captures.
    pub async fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        // H-NEW-1: Commit final checkpoints for all sessions with pending
        // keystrokes BEFORE setting stopping=true (which blocks checkpoints).
        {
            let candidates: Vec<String> = {
                let map = self.sessions.read_recover();
                map.iter()
                    .filter(|(p, s)| {
                        s.keystroke_count > s.last_checkpoint_keystrokes
                            && !p.starts_with("shadow://")
                    })
                    .map(|(p, _)| p.clone())
                    .collect()
            };
            let semantic_map: std::collections::HashMap<String, Option<String>> = {
                let map = self.sessions.read_recover();
                candidates
                    .iter()
                    .map(|p| {
                        let json = map
                            .get(p.as_str())
                            .and_then(|s| serde_json::to_string(&s.semantic_counts).ok());
                        (p.clone(), json)
                    })
                    .collect()
            };
            let sk = Arc::clone(&self.signing_key);
            let dir = self.config.writersproof_dir.clone();
            let stop_flag = Arc::clone(&self.stopping);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
            let mut checkpoint_tasks = tokio::task::JoinSet::new();
            let anchor_mgr = self.anchor_manager.clone();
            for path in candidates {
                let sk_c = Arc::clone(&sk);
                let dir_c = dir.clone();
                let stop_c = Arc::clone(&stop_flag);
                let p = path.clone();
                let sem = semantic_map.get(&path).cloned().flatten();
                let permit = Arc::clone(&semaphore);
                let am_c = anchor_mgr.clone();
                checkpoint_tasks.spawn(async move {
                    let _permit = permit.acquire().await;
                    tokio::task::spawn_blocking(move || {
                        super::helpers::commit_checkpoint_for_path_with_semantics(
                            &p,
                            "Final-checkpoint",
                            &sk_c,
                            &dir_c,
                            &None,
                            &stop_c,
                            sem,
                            &am_c,
                            None,
                        )
                    })
                    .await
                });
            }
            if tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(result) = checkpoint_tasks.join_next().await {
                    if let Err(e) = result {
                        log::error!("Final checkpoint task failed: {e}");
                    }
                }
            })
            .await
            .is_err()
            {
                log::warn!("Final checkpoint tasks timed out after 5s; aborting remaining");
                checkpoint_tasks.abort_all();
            }
        }

        // Set stopping flag FIRST so in-flight spawn_blocking checkpoint
        // tasks bail before opening SQLite (prevents findReusableFd deadlock).
        self.stopping.store(true, Ordering::SeqCst);

        let tx = self.shutdown_tx.lock_recover().take();
        if let Some(tx) = tx {
            if tx.send(()).await.is_err() {
                log::warn!("Shutdown signal receiver already dropped");
            }
        }

        if let Some(cancel) = self.clipboard_cancel.lock_recover().take() {
            cancel.cancel();
        }

        let handle = self.event_loop_handle.lock_recover().take();
        if let Some(mut handle) = handle {
            match tokio::time::timeout(std::time::Duration::from_millis(500), &mut handle).await {
                Ok(_) => {} // exited gracefully
                Err(_) => handle.abort(),
            }
        }

        // Stop CGEventTap threads (keystroke + mouse captures) so
        // the std::sync::mpsc senders are dropped, causing bridge threads
        // to receive Disconnected and exit their recv_timeout loops.
        if let Some(mut cap) = self.keystroke_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);
        if let Some(mut cap) = self.mouse_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        super::stop_hid_capture();
        self.bundle_monitors.lock_recover().clear();
        *self.bundle_change_tx.lock_recover() = None;

        // Now join bridge threads (senders dropped, so they will exit)
        let handles: Vec<_> = self.bridge_threads.lock_recover().drain(..).collect();
        for handle in handles {
            // Intentionally ignored: thread panic during shutdown is non-recoverable
            let _ = handle.join();
        }

        // Persist cumulative stats so keystroke counts survive across
        // stop/start cycles. Run in spawn_blocking with a timeout because
        // in-flight checkpoint tasks may still hold the SQLite fd mutex.
        {
            // AUD-041: signing_key before sessions.
            #[cfg(debug_assertions)]
            let _sk_guard = lock_order::assert_order(lock_order::SIGNING_KEY);
            let sk_clone = self.signing_key.read_recover().key();
            #[cfg(debug_assertions)]
            let _sess_guard = lock_order::assert_order(lock_order::SESSIONS);
            let stats_list: Vec<_> = self
                .sessions
                .read_recover()
                .iter()
                .filter(|(p, _)| !p.starts_with("shadow://"))
                .map(|(path, session)| {
                    let now_secs = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                        .unwrap_or(0);
                    crate::store::DocumentStats {
                        file_path: path.clone(),
                        total_keystrokes: i64::try_from(session.total_keystrokes())
                            .unwrap_or(i64::MAX),
                        total_focus_ms: session.total_focus_ms_cumulative(),
                        session_count: i64::from(session.session_number.saturating_add(1)),
                        total_duration_secs: session
                            .start_time
                            .elapsed()
                            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                            .unwrap_or(0),
                        first_tracked_at: session
                            .first_tracked_at
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                            .unwrap_or(now_secs),
                        last_tracked_at: now_secs,
                        total_checkpoints: i64::try_from(session.checkpoint_count)
                            .unwrap_or(i64::MAX),
                    }
                })
                .collect();

            if let Some(sk) = sk_clone {
                // Derive HMAC key now and drop the SigningKey immediately
                // so it is not held alive inside the spawn_blocking closure.
                let key_bytes = Zeroizing::new(sk.to_bytes());
                let hmac_key = crate::crypto::derive_hmac_key(key_bytes.as_slice());
                drop(key_bytes);
                drop(sk);
                let db = self.config.writersproof_dir.join("events.db");
                let save_result = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::task::spawn_blocking(move || {
                        if let Ok(store) = crate::store::SecureStore::open(&db, hmac_key) {
                            for stats in &stats_list {
                                if let Err(e) = store.save_document_stats(stats) {
                                    log::warn!("Failed to persist document stats: {e}");
                                }
                            }
                        }
                    }),
                )
                .await;
                if save_result.is_err() {
                    log::warn!(
                        "Stats persistence timed out during stop; \
                         stats will be recovered on next session start"
                    );
                }
            }

            // Unfocus all sessions so they are preserved for restart.
            let mut paths: Vec<String> = self.sessions.read_recover().keys().cloned().collect();
            paths.sort();
            for path in paths {
                unfocus_document_sync(&path, &self.sessions, &self.session_events_tx);
            }
        }
        // current_focus is NOT cleared so run_event_loop() can re-focus
        // the same document on restart. The sessions above are unfocused
        // (has_focus = false) but still present in the map.

        self.shadow.cleanup_all();

        // Zeroize key material. SigningKey has ZeroizeOnDrop; take() drops
        // it now rather than waiting for Arc refcount to reach zero.
        self.signing_key.write_recover().reset();
        *self.cached_store.lock_recover() = None;
        // session_nonce is [u8; 32]; zeroize under a single lock hold.
        {
            let mut guard = self.session_nonce.write_recover();
            if let Some(nonce) = guard.as_mut() {
                nonce.zeroize();
            }
            *guard = None;
        }

        // Reset stopping flag so the sentinel can be restarted.
        self.stopping.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// Return `true` if the sentinel event loop is active.
    /// Checks both the running flag AND whether the event loop task is alive.
    /// If the task panicked or exited, clears the running flag so callers
    /// know to restart.
    pub fn is_running(&self) -> bool {
        if !self.running.load(Ordering::SeqCst) {
            return false;
        }
        // Check if the event loop task is still alive
        let task_alive = {
            let guard = self.event_loop_handle.lock_recover();
            match guard.as_ref() {
                Some(handle) => !handle.is_finished(),
                None => false,
            }
        };
        if !task_alive {
            log::error!("Sentinel event loop task exited unexpectedly; clearing running flag");
            self.running.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Whether keystroke capture is active (false = degraded/focus-only mode).
    pub fn is_keystroke_capture_active(&self) -> bool {
        self.keystroke_capture_active.load(Ordering::SeqCst)
    }

    /// Whether all bridge threads are alive. Returns false after any bridge
    /// thread exits unexpectedly; the sentinel drops events in this state.
    pub fn is_bridge_healthy(&self) -> bool {
        self.bridge_healthy.load(Ordering::SeqCst)
    }

    /// Restart keystroke capture without stopping the event loop.
    ///
    /// Stops the existing capture (if any), starts a fresh one, and spawns a
    /// new bridge thread that forwards events to the same async channel the
    /// event loop already holds, keeping the receiver alive via the stored
    /// `keystroke_event_tx` clone.  Returns `true` when capture is active on
    /// return.
    pub fn restart_keystroke_capture(&self) -> bool {
        let tx = match self.keystroke_event_tx.lock_recover().as_ref().cloned() {
            Some(t) => t,
            None => return self.is_keystroke_capture_active(),
        };

        {
            let mut cap = self.keystroke_capture.lock_recover();
            *cap = None;
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);

        #[cfg(target_os = "macos")]
        {
            match crate::platform::macos::shared_tap::get_or_start_shared_tap() {
                Ok(tap) => {
                    self.keystroke_capture_active.store(true, Ordering::SeqCst);
                    let mut broadcast_rx = tap.subscribe();
                    let running = Arc::clone(&self.running);
                    let active = Arc::clone(&self.keystroke_capture_active);
                    tokio::spawn(async move {
                        while running.load(Ordering::SeqCst) && active.load(Ordering::SeqCst) {
                            match broadcast_rx.recv().await {
                                Ok(ev) => {
                                    if tx.try_send(ev).is_err() {
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    log::warn!("sentinel tap restart: lagged {n}");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    });
                    self.bridge_healthy.store(true, Ordering::SeqCst);
                    return true;
                }
                Err(e) => {
                    log::warn!("SharedKeystrokeTap restart failed: {e}; trying direct capture");
                }
            }
        }

        match self.platform.create_keystroke_capture() {
            Ok(mut cap) => match cap.start() {
                Ok(sync_rx) => {
                    *self.keystroke_capture.lock_recover() = Some(cap);
                    self.keystroke_capture_active.store(true, Ordering::SeqCst);
                    let running = Arc::clone(&self.running);
                    let active = Arc::clone(&self.keystroke_capture_active);
                    let h = std::thread::Builder::new()
                        .name("cpoe-keystroke-restart".into())
                        .spawn(move || {
                            while running.load(Ordering::SeqCst) && active.load(Ordering::SeqCst) {
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
                            let mut threads = self.bridge_threads.lock_recover();
                            threads.retain(|t| !t.is_finished());
                            threads.push(handle);
                            self.bridge_healthy.store(true, Ordering::SeqCst);
                            true
                        }
                        Err(e) => {
                            log::error!("Failed to spawn keystroke-restart bridge: {e}");
                            false
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Keystroke capture restart failed: {e}");
                    false
                }
            },
            Err(e) => {
                log::warn!("Keystroke capture unavailable for restart: {e}");
                false
            }
        }
    }

    /// Record a paste event from the host app.
    pub fn set_last_paste_chars(&self, chars: i64) {
        self.last_paste_chars.store(chars, Ordering::SeqCst);
    }

    /// Read and clear the last paste character count.
    pub fn take_last_paste_chars(&self) -> i64 {
        self.last_paste_chars.swap(0, Ordering::SeqCst)
    }

    /// Return a snapshot of all active document sessions.
    pub fn sessions(&self) -> Vec<DocumentSession> {
        self.sessions.read_recover().values().cloned().collect()
    }

    /// Look up a session by document path.
    pub fn session(&self, path: &str) -> Result<DocumentSession> {
        self.sessions
            .read_recover()
            .get(path)
            .cloned()
            .ok_or_else(|| SentinelError::SessionNotFound(path.to_string()))
    }

    /// Return per-document jitter samples for forensic analysis.
    pub fn document_jitter_samples(&self, path: &str) -> Vec<crate::jitter::SimpleJitterSample> {
        self.sessions
            .read_recover()
            .get(path)
            .map(|s| s.jitter_ring.to_vec_chronological())
            .unwrap_or_default()
    }

    /// Compute cadence score under the session lock without cloning samples.
    pub fn document_cadence_score(&self, path: &str) -> f64 {
        self.sessions
            .read_recover()
            .get(path)
            .map(|s| crate::forensics::cadence_score_from_samples(&s.jitter_ring.as_slice()))
            .unwrap_or(0.0)
    }

    /// Return the path of the currently focused document, if any.
    pub fn current_focus(&self) -> Option<String> {
        self.current_focus.read_recover().clone()
    }

    /// Returns the targeted document path, if set.
    pub fn targeted_path(&self) -> Option<String> {
        self.targeted_path.read_recover().clone()
    }

    /// Exit targeted mode so the sentinel resumes tracking all focused documents.
    pub fn clear_targeted_mode(&self) {
        *self.targeted_path.write_recover() = None;
    }

    /// Subscribe to session lifecycle events (started, ended, idle).
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.session_events_tx.subscribe()
    }

    /// Create a shadow buffer for apps that don't expose file paths directly.
    pub fn create_shadow(&self, app_name: &str, window_title: &str) -> Result<String> {
        self.shadow.create(app_name, window_title)
    }

    /// Write new content to an existing shadow buffer.
    pub fn update_shadow_content(&self, shadow_id: &str, content: &[u8]) -> Result<()> {
        self.shadow.update(shadow_id, content)
    }

    /// Synthesise a focus-gained event for a terminal editor opened via ES exec.
    ///
    /// Called by `ffi_sentinel_es_terminal_editor_exec` when Endpoint Security
    /// detects a known terminal editor (vim, nvim, emacs, nano, helix, …)
    /// being exec'd with a file argument. Creates a tracking session for the
    /// document so keystrokes captured while the terminal is focused are
    /// attributed to that file.
    pub fn inject_terminal_editor_session(&self, file_path: &str, editor_name: &str) -> bool {
        use super::types::{FocusEvent, FocusEventType};
        use crate::crypto::ObfuscatedString;

        let path = match super::helpers::validate_path(file_path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                log::warn!("inject_terminal_editor_session: invalid path {file_path:?}: {e}");
                return false;
            }
        };

        let event = FocusEvent {
            event_type: FocusEventType::FocusGained,
            path: path.clone(),
            shadow_id: String::new(),
            app_bundle_id: format!("terminal.editor.{editor_name}"),
            app_name: editor_name.to_string(),
            window_title: ObfuscatedString::default(),
            timestamp: SystemTime::now(),
            window_id: None,
            char_count_delta: None,
        };

        let wal_dir = self.config.wal_dir.clone();
        focus_document_sync(
            &path,
            &event,
            &self.sessions,
            &self.config,
            &self.shadow,
            &self.signing_key,
            &wal_dir,
            &self.session_events_tx,
        );
        log::info!("terminal editor session started: editor={editor_name} path={path}");
        true
    }

    /// Check whether the sentinel can run on the current platform.
    pub fn available(&self) -> (bool, String) {
        #[cfg(target_os = "macos")]
        {
            if super::macos_focus::check_accessibility_permissions() {
                (true, "macOS Accessibility API available".to_string())
            } else {
                (false, "Accessibility permission required".to_string())
            }
        }

        #[cfg(target_os = "windows")]
        {
            (true, "Windows Focus API available".to_string())
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            (false, "Sentinel not available on this platform".to_string())
        }
    }

    // Session management methods (start_witnessing, stop_witnessing, tracked_files,
    // start_time, update_baseline) are in core_session.rs.
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // Signal all bridge threads and the event loop to exit.
        self.running.store(false, Ordering::SeqCst);
        self.stopping.store(true, Ordering::SeqCst);

        // Stop CGEventTap threads so they don't leak.
        if let Some(mut cap) = self.keystroke_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);
        if let Some(mut cap) = self.mouse_capture.lock_recover().take() {
            let _ = cap.stop();
        }

        // Join bridge threads with a tight timeout to minimize async runtime blocking.
        // Bridge threads check the running flag on 100ms recv_timeout, so 50ms
        // after signalling is sufficient for the in-flight recv to return.
        for handle in self.bridge_threads.lock_recover().drain(..) {
            let start = std::time::Instant::now();
            while !handle.is_finished() {
                if start.elapsed() > std::time::Duration::from_millis(50) {
                    log::warn!("Bridge thread did not exit within 50ms; detaching");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }

        // Stop HID capture so the global callback doesn't leak.
        super::stop_hid_capture();

        // Abort the event loop task as a final safety net.
        if let Some(handle) = self.event_loop_handle.lock_recover().take() {
            handle.abort();
        }

        // Zeroize key material (safety net if stop() was never called).
        self.signing_key.write_recover().reset();
        {
            let mut guard = self.session_nonce.write_recover();
            if let Some(nonce) = guard.as_mut() {
                nonce.zeroize();
            }
            *guard = None;
        }
    }
}

impl std::fmt::Debug for Sentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sentinel").finish_non_exhaustive()
    }
}
