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
const CGEVENTTAP_VERIFIED_PID: i64 = -1;

/// Async channel buffer size for keystroke and mouse bridge threads.
pub(super) const EVENT_CHANNEL_BUFFER: usize = 1000;

/// Duration after last keystroke within which mouse micro-movements are recorded.
const TYPING_PROXIMITY_SECS: u64 = 2;

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
    /// Timestamp when the sentinel was started via start().
    pub(crate) start_time: Arc<Mutex<Option<SystemTime>>>,
    /// False when any bridge thread has died; checked before processing events.
    bridge_healthy: Arc<AtomicBool>,
    /// Set to `true` when `stop()` begins; checked by checkpoint tasks to bail
    /// before opening SQLite, preventing a `findReusableFd` mutex deadlock.
    stopping: Arc<AtomicBool>,
    /// Hardware TPM/Secure Enclave provider for co-sign scheduling.
    pub(crate) tpm_provider: Option<Arc<dyn crate::tpm::Provider>>,
    /// Client for WritersProof service (freshness nonces, attestation).
    pub(crate) writersproof_client: Arc<crate::writersproof::WritersProofClient>,
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
    pub(crate) permission_state:
        Arc<Mutex<super::permission_monitor::PermissionState>>,
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

        let mut mouse_stego_seed = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut mouse_stego_seed);

        let snapshots_default = config.snapshots_enabled;

        let tpm_provider = platform.get_tpm_provider();

        let writersproof_client = Arc::new(
            crate::writersproof::WritersProofClient::new(
                crate::writersproof::client::DEFAULT_API_URL,
            )
            .map_err(|e| SentinelError::Anyhow(anyhow::anyhow!(e)))?,
        );

        let app_registry = super::app_registry::AppRegistry::load(&config.writersproof_dir);

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
            activity_accumulator: Arc::new(RwLock::new(
                crate::fingerprint::ActivityFingerprintAccumulator::new(),
            )),
            style_collector: Arc::new(RwLock::new(None)),
            mouse_idle_stats: Arc::new(RwLock::new(crate::platform::MouseIdleStats::new())),
            mouse_stego_engine: Arc::new(RwLock::new(crate::platform::MouseStegoEngine::new(
                mouse_stego_seed,
            ))),
            session_nonce: Arc::new(RwLock::new(None)),
            bridge_threads: Arc::new(Mutex::new(Vec::new())),
            event_loop_handle: Arc::new(Mutex::new(None)),
            keystroke_capture: Arc::new(Mutex::new(None)),
            mouse_capture: Arc::new(Mutex::new(None)),
            keystroke_capture_active: Arc::new(AtomicBool::new(false)),
            last_paste_chars: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            pending_challenge: Arc::new(RwLock::new(None)),
            start_time: Arc::new(Mutex::new(None)),
            bridge_healthy: Arc::new(AtomicBool::new(true)),
            stopping: Arc::new(AtomicBool::new(false)),
            tpm_provider,
            writersproof_client,
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
        };
        mouse_stego_seed.zeroize();
        Ok(sentinel)
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

    /// Return the current keystroke count from the activity accumulator.
    pub fn config(&self) -> &SentinelConfig {
        &self.config
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

    /// Return a shared reference to the mouse steganography engine.
    pub fn mouse_stego_engine(&self) -> &Arc<RwLock<crate::platform::MouseStegoEngine>> {
        &self.mouse_stego_engine
    }

    /// Update the mouse stego engine from the given key bytes (avoids re-acquiring signing_key lock).
    fn update_mouse_stego_seed_from(&self, key_bytes: &[u8; 32]) {
        let mut seed = *key_bytes;
        let mut engine = self.mouse_stego_engine.write_recover();
        engine.reset();
        *engine = crate::platform::MouseStegoEngine::new(seed);
        seed.zeroize();
    }

    /// Set the Ed25519 signing key and update the mouse stego seed.
    ///
    /// Rejects all-zero keys as invalid (likely uninitialized).
    pub fn set_signing_key(&self, key: SigningKey) {
        if key.to_bytes().iter().all(|&b| b == 0) {
            log::error!(
                "Rejected all-zero signing key — likely uninitialized; evidence will not be signed"
            );
            return;
        }
        let mut key_bytes = key.to_bytes();
        self.signing_key.write_recover().set_key(key);
        // Invalidate cached store — the HMAC key derives from the signing key.
        *self.cached_store.lock_recover() = None;
        // Update stego seed without re-acquiring the signing_key lock
        self.update_mouse_stego_seed_from(&key_bytes);
        key_bytes.zeroize();
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
        let mut bytes: [u8; 32] = match key.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                log::error!("HMAC key must be exactly 32 bytes");
                return;
            }
        };
        let mut seed_copy = bytes;
        let signing_key = SigningKey::from_bytes(&bytes);
        self.signing_key.write_recover().set_key(signing_key);
        *self.cached_store.lock_recover() = None;
        bytes.zeroize();
        self.update_mouse_stego_seed_from(&seed_copy);
        seed_copy.zeroize();
    }

    /// Get or lazily open the cached SecureStore connection.
    ///
    /// Returns `None` if the signing key is not yet available. The store is
    /// invalidated automatically when the signing key changes via
    /// `set_signing_key` / `set_hmac_key`.
    ///
    /// AUD-041: signing_key is read *before* cached_store is locked to
    /// preserve the ordering signing_key(1) < sessions(2) < cached_store(3).
    pub(crate) fn get_or_open_store(&self) -> Option<std::sync::MutexGuard<'_, Option<crate::store::SecureStore>>> {
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
        *self.bundle_change_tx.lock_recover() = Some(change_tx_for_bundles);

        // Reset bridge health and stopping flag on (re-)start.
        // running is already true from the compare_exchange above.
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

        let writersproof_client_for_loop = Arc::clone(&self.writersproof_client);
        let cached_store_for_loop = Arc::clone(&self.cached_store);
        let permission_state_for_loop = Arc::clone(&self.permission_state);
        let keystroke_event_tx_for_loop = Arc::clone(&self.keystroke_event_tx);
        let platform_for_loop = Arc::clone(&self.platform);
        let mut session_events_rx = self.session_events_tx.subscribe();
        let bundle_monitors_for_loop = Arc::clone(&self.bundle_monitors);
        let bundle_change_tx_for_loop = Arc::clone(&self.bundle_change_tx);

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
                tpm_provider: tpm_provider_for_loop,
                tap_check_capture,
                tap_check_active,
                bridge_health_threads,
                bridge_healthy_flag,
                snapshots_flag,
                writersproof_client: writersproof_client_for_loop,
                cached_store: cached_store_for_loop,
                permission_state: permission_state_for_loop,
                keystroke_event_tx: keystroke_event_tx_for_loop,
                platform: platform_for_loop,
                bundle_monitors: bundle_monitors_for_loop,
                bundle_change_tx: bundle_change_tx_for_loop,
                last_keystroke_time: std::time::Instant::now(),
                last_keydown_ts_ns: 0,
                last_mouse_ts_ns: 0,
                pending_downs: HashMap::new(),
                last_keyup_ts_ns: 0,
            };

            let mut idle_check_interval = interval(Duration::from_secs(idle_check_interval_secs));
            let mut checkpoint_interval = interval(Duration::from_secs(checkpoint_interval_secs));
            let mut challenge_interval = interval(Duration::from_secs(30));
            let mut permission_check_interval = interval(Duration::from_secs(30));

            super::trace!("[EVENT_LOOP] started");

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    result = session_events_rx.recv() => {
                        match result {
                            Ok(event) => ctx.handle_session_event(event),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("Session event receiver lagged, missed {n} events");
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
                    _ = checkpoint_interval.tick() => {
                        ctx.handle_checkpoint_tick().await;
                    }
                    _ = permission_check_interval.tick() => {
                        ctx.handle_permission_check();
                    }
                }

                if !ctx.running.load(Ordering::SeqCst) {
                    break;
                }
            }

            if let Err(e) = focus_monitor.stop() {
                log::debug!("focus monitor stop: {e}");
            }
            // Session unfocus is now handled by Sentinel::stop() directly
            // (not here) to avoid the abort race where this cleanup code
            // might never run if the event loop handle is aborted first.
        });

        // Store the event loop handle so it can be aborted on Drop
        *event_loop_handle_ref.lock_recover() = Some(handle);

        // Spawn clipboard monitor with its own cancellation token.
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
                        let json = map.get(p.as_str()).and_then(|s| {
                            serde_json::to_string(&s.semantic_counts).ok()
                        });
                        (p.clone(), json)
                    })
                    .collect()
            };
            let sk = Arc::clone(&self.signing_key);
            let dir = self.config.writersproof_dir.clone();
            let stop_flag = Arc::clone(&self.stopping);
            for path in candidates {
                let sk_c = Arc::clone(&sk);
                let dir_c = dir.clone();
                let stop_c = Arc::clone(&stop_flag);
                let p = path.clone();
                let sem = semantic_map.get(&path).cloned().flatten();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    super::helpers::commit_checkpoint_for_path_with_semantics(
                        &p,
                        "Final-checkpoint",
                        &sk_c,
                        &dir_c,
                        &None,
                        &stop_c,
                        sem,
                    )
                })
                .await
                {
                    log::error!("Final checkpoint task failed: {e}");
                }
            }
        }

        // Set stopping flag FIRST so in-flight spawn_blocking checkpoint
        // tasks bail before opening SQLite (prevents findReusableFd deadlock).
        self.stopping.store(true, Ordering::SeqCst);

        // Send shutdown signal first so the event loop can run cleanup (focus_monitor.stop()).
        // take() under lock, then await outside to avoid holding lock across .await.
        let tx = self.shutdown_tx.lock_recover().take();
        if let Some(tx) = tx {
            if tx.send(()).await.is_err() {
                log::warn!("Shutdown signal receiver already dropped");
            }
        }

        // Cancel the clipboard monitor task.
        if let Some(cancel) = self.clipboard_cancel.lock_recover().take() {
            cancel.cancel();
        }

        // Give the event loop a short window to exit gracefully, then force-abort.
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
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    crate::store::DocumentStats {
                        file_path: path.clone(),
                        total_keystrokes: i64::try_from(session.total_keystrokes())
                            .unwrap_or(i64::MAX),
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
                    }
                })
                .collect();

            if let Some(sk) = sk_clone {
                // Derive HMAC key now and drop the SigningKey immediately
                // so it is not held alive inside the spawn_blocking closure.
                let mut key_bytes = sk.to_bytes();
                let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
                key_bytes.zeroize();
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
                            while running.load(Ordering::SeqCst)
                                && active.load(Ordering::SeqCst)
                            {
                                match sync_rx.recv_timeout(
                                    std::time::Duration::from_millis(100),
                                ) {
                                    Ok(ev) => {
                                        if tx.try_send(ev).is_err() {
                                            break;
                                        }
                                    }
                                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                        continue
                                    }
                                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                        break
                                    }
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
            .map(|s| s.jitter_samples.clone())
            .unwrap_or_default()
    }

    /// Compute cadence score under the session lock without cloning samples.
    pub fn document_cadence_score(&self, path: &str) -> f64 {
        self.sessions
            .read_recover()
            .get(path)
            .map(|s| crate::forensics::cadence_score_from_samples(&s.jitter_samples))
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

/// Captured state for the sentinel event loop, passed to per-branch handlers.
///
/// Groups all `Arc`-cloned references that the `tokio::select!` loop needs so
/// that each handler method can borrow only what it requires without a 20+
/// argument function signature. The mutable timing fields (`last_keydown_ts_ns`,
/// `pending_downs`, etc.) live here because they are local to the loop.
struct EventLoopCtx {
    sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    current_focus: Arc<RwLock<Option<String>>>,
    targeted_path: Arc<RwLock<Option<String>>>,
    config: Arc<SentinelConfig>,
    shadow: Arc<ShadowManager>,
    signing_key: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    signing_key_for_cp: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    session_events_tx: broadcast::Sender<SessionEvent>,
    running: Arc<AtomicBool>,
    idle_timeout: Duration,
    wal_dir: std::path::PathBuf,
    activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    style_collector: Arc<RwLock<Option<crate::fingerprint::StyleCollector>>>,
    mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    writersproof_dir: std::path::PathBuf,
    stopping_flag: Arc<AtomicBool>,
    #[allow(clippy::type_complexity)]
    pending_challenge: Arc<RwLock<Option<(String, Option<String>)>>>,
    tpm_provider: Option<Arc<dyn crate::tpm::Provider>>,
    tap_check_capture: Arc<Mutex<Option<Box<dyn KeystrokeCapture>>>>,
    tap_check_active: Arc<AtomicBool>,
    bridge_health_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    bridge_healthy_flag: Arc<AtomicBool>,
    snapshots_flag: Arc<AtomicBool>,
    writersproof_client: Arc<crate::writersproof::WritersProofClient>,
    cached_store: Arc<Mutex<Option<crate::store::SecureStore>>>,
    permission_state: Arc<Mutex<super::permission_monitor::PermissionState>>,
    keystroke_event_tx:
        Arc<Mutex<Option<mpsc::Sender<crate::platform::KeystrokeEvent>>>>,
    platform: Arc<dyn crate::platform::PlatformProvider>,
    bundle_monitors:
        Arc<Mutex<HashMap<String, super::bundle_monitor::BundleMonitor>>>,
    bundle_change_tx: Arc<Mutex<Option<mpsc::Sender<ChangeEvent>>>>,
    // Per-loop mutable timing state
    last_keystroke_time: std::time::Instant,
    last_keydown_ts_ns: i64,
    last_mouse_ts_ns: i64,
    pending_downs: HashMap<u16, i64>,
    last_keyup_ts_ns: i64,
}

impl EventLoopCtx {
    /// Forward session lifecycle events to the WritersProof service.
    fn handle_session_event(&self, event: SessionEvent) {
        let client = Arc::clone(&self.writersproof_client);
        match event.event_type {
            SessionEventType::Started => {
                if let Some(hash) = event.hash {
                    let sid = event.session_id;
                    let sid_hex = match crate::writersproof::Hex64::new(sid.clone()) {
                        Ok(h) => h,
                        Err(e) => {
                            log::debug!(
                                "WritersProof start_session: invalid session_id: {}", e
                            );
                            return;
                        }
                    };
                    let hash_hex = match crate::writersproof::Hex64::new(hash) {
                        Ok(h) => h,
                        Err(e) => {
                            log::debug!(
                                "WritersProof start_session: invalid initial_hash: {}", e
                            );
                            return;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) =
                            client.start_session(&sid_hex, &hash_hex).await
                        {
                            log::debug!(
                                "WritersProof start_session failed for {}: {}", sid, e
                            );
                        }
                    });
                }
            }
            SessionEventType::Ended => {
                if let Some(hash) = event.hash {
                    let sid = event.session_id;
                    let sid_hex = match crate::writersproof::Hex64::new(sid.clone()) {
                        Ok(h) => h,
                        Err(e) => {
                            log::debug!(
                                "WritersProof end_session: invalid session_id: {}", e
                            );
                            return;
                        }
                    };
                    let hash_hex = match crate::writersproof::Hex64::new(hash) {
                        Ok(h) => h,
                        Err(e) => {
                            log::debug!(
                                "WritersProof end_session: invalid final_hash: {}", e
                            );
                            return;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) =
                            client.end_session(&sid_hex, &hash_hex).await
                        {
                            log::debug!(
                                "WritersProof end_session failed for {}: {}", sid, e
                            );
                        }
                    });
                }
            }
            _ => {}
        }
    }

    /// Process a keystroke event (keyDown or keyUp).
    fn handle_keystroke_event(
        &mut self,
        event: crate::platform::KeystrokeEvent,
    ) {
        // Skip event processing when bridge is unhealthy to avoid
        // silently operating in a degraded state.
        if !self.bridge_healthy_flag.load(Ordering::SeqCst) {
            log::warn!("Dropping keystroke event: bridge unhealthy");
            return;
        }

        // Handle keyUp: compute dwell time, backfill the matching
        // keyDown sample in the focused session's jitter buffer, and
        // update last_keyup_ts for flight-time computation.
        if event.event_type == crate::platform::KeyEventType::Up {
            if let Some(down_ts) = self.pending_downs.remove(&event.keycode) {
                let dwell = crate::utils::ns_elapsed(event.timestamp_ns, down_ts);
                let focused_path = self.current_focus.read_recover().clone();
                if let Some(ref path) = focused_path {
                    let mut map = self.sessions.write_recover();
                    if let Some(session) = map.get_mut(path.as_str()) {
                        if let Some(&idx) =
                            session.jitter_sample_index.get(&down_ts)
                        {
                            if let Some(sample) =
                                session.jitter_samples.get_mut(idx)
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
        self.pending_downs.retain(|_, ts| {
            *ts > 0
                && event.timestamp_ns.saturating_sub(*ts) < 10_000_000_000
        });
        if self.pending_downs.len() < 256 {
            self.pending_downs
                .insert(event.keycode, event.timestamp_ns);
        }

        let duration_since_last_ns: u64 = if self.last_keydown_ts_ns > 0 {
            crate::utils::ns_elapsed(
                event.timestamp_ns,
                self.last_keydown_ts_ns,
            )
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
        self.activity_accumulator
            .write_recover()
            .add_sample(&sample);

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

        if let Some(ref mut collector) =
            *self.style_collector.write_recover()
        {
            collector.record_keystroke(event.keycode, event.char_value);
        }

        self.record_keystroke_to_session(
            &event,
            &sample,
            duration_since_last_ns,
        );
        self.last_keystroke_time = std::time::Instant::now();
    }

    /// Attribute a validated keyDown to the focused document session.
    fn record_keystroke_to_session(
        &self,
        event: &crate::platform::KeystrokeEvent,
        sample: &crate::jitter::SimpleJitterSample,
        duration_since_last_ns: u64,
    ) {
        let focused_path = self.current_focus.read_recover().clone();
        let Some(ref path) = focused_path else {
            return;
        };
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
        session.keystroke_count += 1;
        super::trace!(
            "[KEYSTROKE] COUNTED {:?} total={}",
            path,
            session.keystroke_count
        );
        let was_buffered =
            session.jitter_samples.len() < MAX_DOCUMENT_JITTER_SAMPLES;
        if was_buffered {
            let idx = session.jitter_samples.len();
            session.jitter_samples.push(sample.clone());
            session
                .jitter_sample_index
                .insert(sample.timestamp_ns, idx);
        }
        session.cognitive.record_keystroke(
            event.char_value,
            event.timestamp_ns,
            duration_since_last_ns,
            0, // size_delta populated at checkpoint time
            0, // file_size populated at checkpoint time
        );

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
            session.keystroke_count -= 1;
            if was_buffered {
                if let Some(last) = session.jitter_samples.last() {
                    session.jitter_sample_index.remove(&last.timestamp_ns);
                }
                session.jitter_samples.pop();
            }
            super::trace!(
                "[KEYSTROKE] REJECTED conf={:.2}",
                validation.confidence
            );
            return;
        }

        // Advance incremental jitter hash chain only for accepted
        // samples that were actually buffered.
        if was_buffered {
            let mut h = sha2::Sha256::new();
            use sha2::Digest as _;
            h.update(session.jitter_hash_state);
            h.update(sample.timestamp_ns.to_be_bytes());
            h.update(sample.duration_since_last_ns.to_be_bytes());
            h.update([sample.zone]);
            session.jitter_hash_state = h.finalize().into();
        }

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
    }

    /// Process a mouse movement event.
    fn handle_mouse_event(
        &mut self,
        event: crate::platform::MouseEvent,
    ) {
        let mouse_duration_ns: u64 = if self.last_mouse_ts_ns > 0 {
            crate::utils::ns_elapsed(event.timestamp_ns, self.last_mouse_ts_ns)
        } else {
            0
        };
        self.last_mouse_ts_ns = event.timestamp_ns;

        let is_during_typing = self.last_keystroke_time.elapsed()
            < Duration::from_secs(TYPING_PROXIMITY_SECS);
        if is_during_typing && event.is_micro_movement() {
            self.mouse_idle_stats.write_recover().record(&event);
        }

        // Throttle stego jitter to ~20 Hz to reduce write lock contention
        if mouse_duration_ns >= 50_000_000 {
            self.mouse_stego_engine.write_recover().next_jitter();
        }
    }

    /// Handle a focus event and optionally start a bundle monitor.
    fn handle_focus_branch(&self, event: FocusEvent) {
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
        // Start a BundleMonitor for newly-focused bundle documents
        // (Scrivener .scriv, Ulysses .ulysses) if not already watching.
        if let Some(ref path) = *self.current_focus.read_recover() {
            let bundle_path = std::path::Path::new(path.as_str());
            if super::bundle_monitor::is_bundle_document(bundle_path) {
                let mut monitors = self.bundle_monitors.lock_recover();
                if !monitors.contains_key(path) {
                    if let Some(ref tx) =
                        *self.bundle_change_tx.lock_recover()
                    {
                        match super::bundle_monitor::start_bundle_monitor(
                            bundle_path,
                            tx.clone(),
                        ) {
                            Ok(monitor) => {
                                self.restore_scrivener_state(
                                    bundle_path, path,
                                );
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
    }

    /// Parse Scrivener project map and restore segment counts from shadow.
    fn restore_scrivener_state(
        &self,
        bundle_path: &std::path::Path,
        path: &str,
    ) {
        if let Some(map) =
            super::helpers::parse_scrivener_project_map(bundle_path)
        {
            let project_uuid =
                map.uuid_to_title.keys().next().cloned();
            let mut sessions_map = self.sessions.write_recover();
            if let Some(session) = sessions_map.get_mut(path) {
                if session.segment_counts.is_empty() {
                    if let Some(ref proj_uuid) = project_uuid {
                        let app_bid = session.app_bundle_id.clone();
                        if let Some(ref store) =
                            *self.cached_store.lock_recover()
                        {
                            if let Ok(Some(shadow)) =
                                store.load_shadow_session(
                                    &app_bid, proj_uuid,
                                )
                            {
                                if let Some(ref json) =
                                    shadow.segment_counts_json
                                {
                                    if let Ok(counts) =
                                        serde_json::from_str(json)
                                    {
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
    fn handle_change_branch(&self, event: &ChangeEvent) {
        handle_change_event_sync(
            event,
            &self.sessions,
            &self.config,
            &self.signing_key,
            &self.wal_dir,
            &self.session_events_tx,
            Some(&self.current_focus),
        );
    }

    /// Auto-checkpoint and end idle sessions; check capture health.
    async fn handle_idle_check(&self) {
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
            end_session_sync(
                path,
                &self.sessions,
                &self.session_events_tx,
            );
            self.bundle_monitors.lock_recover().remove(path);
        }
        self.check_capture_health();
    }

    /// Commit a checkpoint for a session about to be ended due to idle timeout.
    async fn checkpoint_idle_session(&self, path: &str) {
        let needs_checkpoint = {
            let map = self.sessions.read_recover();
            map.get(path).is_some_and(|s| {
                s.keystroke_count > s.last_checkpoint_keystrokes
                    && !path.starts_with("shadow://")
            })
        };
        if !needs_checkpoint {
            return;
        }
        let cp_path = path.to_string();
        let cp_key = Arc::clone(&self.signing_key_for_cp);
        let cp_dir = self.writersproof_dir.clone();
        let cp_stop = Arc::clone(&self.stopping_flag);
        if let Err(e) = tokio::task::spawn_blocking(move || {
            commit_checkpoint_for_path(
                &cp_path,
                "Auto-checkpoint on idle end",
                &cp_key,
                &cp_dir,
                &None,
                &cp_stop,
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
            total_keystrokes: i64::try_from(session.total_keystrokes())
                .unwrap_or(i64::MAX),
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
        };
        drop(map);
        let sk_opt = self.signing_key_for_cp.read_recover().key();
        if let Some(sk) = sk_opt {
            let mut key_bytes = sk.to_bytes();
            let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
            key_bytes.zeroize();
            drop(sk);
            let db = self.writersproof_dir.join("events.db");
            if let Ok(store) =
                crate::store::SecureStore::open(&db, hmac_key)
            {
                if let Err(e) = store.save_document_stats(&stats) {
                    log::warn!("Idle-end stats persist failed: {e}");
                }
            }
        }
    }

    /// Check CGEventTap and bridge thread health.
    fn check_capture_health(&self) {
        {
            let tap_dead = {
                let guard = self.tap_check_capture.lock_recover();
                guard.as_ref().is_some_and(|cap| !cap.is_tap_alive())
            };
            if tap_dead && self.tap_check_active.load(Ordering::SeqCst) {
                log::error!(
                    "CGEventTap died; marking keystroke capture inactive"
                );
                self.tap_check_active.store(false, Ordering::SeqCst);
            }
        }
        {
            let threads = self.bridge_health_threads.lock_recover();
            for (i, handle) in threads.iter().enumerate() {
                if handle.is_finished() {
                    log::error!(
                        "Bridge thread {i} died; keystroke capture \
                         is stopped. Restart sentinel to resume \
                         keystroke capture."
                    );
                    self.bridge_healthy_flag
                        .store(false, Ordering::SeqCst);
                }
            }
        }
    }

    /// Send a pulse to WritersProof and stash the returned nonce.
    fn handle_challenge_tick(&self) {
        let focused_data = {
            let focused_path = self.current_focus.read_recover().clone();
            if let Some(path) = focused_path {
                self.sessions
                    .read_recover()
                    .get(&path)
                    .map(|s| (s.session_id.clone(), s.current_hash.clone()))
            } else {
                None
            }
        };

        if let Some((sid, hash_opt)) = focused_data {
            let client = Arc::clone(&self.writersproof_client);
            let pending = Arc::clone(&self.pending_challenge);
            tokio::spawn(async move {
                if let Some(h) = hash_opt {
                    let sid_hex =
                        match crate::writersproof::Hex64::new(sid.clone()) {
                            Ok(h) => h,
                            Err(e) => {
                                log::debug!(
                                    "Pulse: invalid session_id: {}", e
                                );
                                return;
                            }
                        };
                    let hash_hex =
                        match crate::writersproof::Hex64::new(h) {
                            Ok(h) => h,
                            Err(e) => {
                                log::debug!(
                                    "Pulse: invalid current_hash: {}", e
                                );
                                return;
                            }
                        };
                    match client.pulse(&sid_hex, &hash_hex).await {
                        Ok(resp) => {
                            *pending.write_recover() = Some((
                                resp.nonce,
                                Some(resp.nonce_id.clone()),
                            ));
                            log::debug!(
                                "Pulse sent for session {}: nonce_id={}",
                                sid,
                                resp.nonce_id
                            );
                        }
                        Err(e) => {
                            log::debug!(
                                "Pulse failed for session {}: {}", sid, e
                            );
                        }
                    }
                }
            });
        }
    }

    /// Commit checkpoints for all sessions with pending keystrokes.
    async fn handle_checkpoint_tick(&self) {
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

        let pending_taken =
            self.pending_challenge.write_recover().take();
        let challenge_nonce =
            pending_taken.as_ref().map(|(n, _)| n.clone());
        let nonce_id = pending_taken.and_then(|(_, id)| id);

        for path in &candidates {
            let skip_rest = self
                .checkpoint_one_session(
                    path,
                    &challenge_nonce,
                    &nonce_id,
                )
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
        let semantic_json = {
            let map = self.sessions.read_recover();
            map.get(path).and_then(|s| {
                serde_json::to_string(&s.semantic_counts).ok()
            })
        };
        let sessions_ref = &self.sessions;
        let committed = tokio::task::spawn_blocking(move || {
            super::helpers::commit_checkpoint_for_path_with_semantics(
                &cp_path,
                "Auto-checkpoint",
                &cp_key,
                &cp_dir,
                &nonce_for_closure,
                &cp_stop,
                semantic_json,
            )
        })
        .await
        .unwrap_or_else(|e| {
            log::error!("Checkpoint task panicked for {}: {e}", path);
            let mut map = sessions_ref.write_recover();
            if let Some(session) = map.get_mut(path) {
                session.last_checkpoint_keystrokes = 0;
            }
            None
        });

        if let Some(event_hash) = committed {
            self.confirm_nonce_for_checkpoint(
                path, &event_hash, nonce_id,
            );
        }
        if committed.is_some() {
            return self.post_checkpoint_work(
                path,
                challenge_nonce,
            );
        }
        false
    }

    /// Tell WritersProof which checkpoint consumed its nonce.
    fn confirm_nonce_for_checkpoint(
        &self,
        path: &str,
        event_hash: &[u8; 32],
        nonce_id: &Option<String>,
    ) {
        let Some(ref nid) = nonce_id else { return };
        let session_id = self
            .sessions
            .read_recover()
            .get(path)
            .map(|s| s.session_id.clone());
        let Some(sid) = session_id else { return };
        let nid = nid.clone();
        let cp_hash = hex::encode(event_hash);
        let sid_hex =
            match crate::writersproof::Hex64::new(sid.clone()) {
                Ok(h) => Some(h),
                Err(e) => {
                    log::debug!(
                        "confirm_nonce: invalid session_id: {}", e
                    );
                    None
                }
            };
        let cp_hex = match crate::writersproof::Hex64::new(cp_hash) {
            Ok(h) => Some(h),
            Err(e) => {
                log::debug!(
                    "confirm_nonce: invalid checkpoint_hash: {}", e
                );
                None
            }
        };
        if let (Some(sid_hex), Some(cp_hex)) = (sid_hex, cp_hex) {
            let confirm_client = Arc::clone(&self.writersproof_client);
            tokio::spawn(async move {
                if let Err(e) = confirm_client
                    .confirm_nonce(&sid_hex, &nid, &cp_hex)
                    .await
                {
                    log::debug!(
                        "confirm_nonce failed for session {sid}: {e}"
                    );
                }
            });
        }
    }

    /// Persist stats, create text fragment, save snapshot, and HW co-sign
    /// after a successful checkpoint. Returns `true` to signal breaking out
    /// of the candidates loop (HW co-sign file-read failure).
    fn post_checkpoint_work(
        &self,
        path: &str,
        challenge_nonce: &Option<String>,
    ) -> bool {
        // AUD-041: signing_key must be acquired before sessions.
        let sk_opt = {
            let guard = self.signing_key_for_cp.read_recover();
            guard.key()
        };
        let session_snapshot = {
            let mut map = self.sessions.write_recover();
            map.get_mut(path).map(|session| {
                session.last_checkpoint_keystrokes =
                    session.keystroke_count;
                (
                    session.total_keystrokes(),
                    session.total_focus_ms_cumulative(),
                    session.session_number,
                    session.start_time
                        .elapsed()
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    session.first_tracked_at
                        .and_then(|t| {
                            t.duration_since(std::time::UNIX_EPOCH).ok()
                        })
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    session.last_checkpoint_keystrokes,
                    session.hw_cosign_scheduler.is_some(),
                    session.session_id.clone(),
                    session.paste_context.is_some(),
                    session.app_bundle_id.clone(),
                    session.window_title.reveal().to_string(),
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
        )) = session_snapshot
        else {
            return false;
        };

        let sk_for_frag = sk_opt.clone();
        if let Some(ref mut store) = *self.cached_store.lock_recover() {
            let stats = crate::store::DocumentStats {
                file_path: path.to_string(),
                total_keystrokes: i64::try_from(total_ks)
                    .unwrap_or(i64::MAX),
                total_focus_ms: focus_ms,
                session_count: i64::from(session_num + 1),
                total_duration_secs: duration_secs,
                first_tracked_at: first_at,
                last_tracked_at: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            };
            if let Err(e) = store.save_document_stats(&stats) {
                log::warn!(
                    "Failed to save document stats for {path}: {e}"
                );
            }

            self.save_text_fragment(
                store,
                path,
                &session_id,
                has_paste_ctx,
                &app_bundle_id,
                &window_title,
                sk_for_frag.as_ref(),
            );
        }

        if self.snapshots_flag.load(Ordering::SeqCst)
            && !path.starts_with("shadow://")
        {
            if let Some(ref sk) = sk_opt {
                let snap_db =
                    self.writersproof_dir.join("snapshots.db");
                match crate::snapshot::SnapshotStore::open(&snap_db, sk)
                {
                    Ok(mut snap_store) => {
                        let src = std::path::Path::new(path);
                        match std::fs::read_to_string(src) {
                            Ok(content) => {
                                if let Err(e) =
                                    snap_store.save(path, &content, false)
                                {
                                    log::debug!(
                                        "Snapshot save failed for \
                                         {path}: {e}"
                                    );
                                }
                            }
                            Err(e) => {
                                log::debug!(
                                    "Snapshot read failed for {path}: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to open snapshot store: {e}"
                        );
                    }
                }
            }
        }

        if has_hw_sched {
            if let Some(ref tpm) = self.tpm_provider {
                let content_hash: [u8; 32] = {
                    use sha2::Digest;
                    let src = std::path::Path::new(path);
                    match std::fs::read(src) {
                        Ok(data) => {
                            sha2::Sha256::digest(&data).into()
                        }
                        Err(e) => {
                            log::warn!(
                                "Skipping HW co-sign: file read \
                                 failed for {}: {e}",
                                path
                            );
                            return true; // break candidates loop
                        }
                    }
                };
                let nonce_bytes_opt =
                    challenge_nonce.as_ref().and_then(|nonce_hex| {
                        match hex::decode(nonce_hex) {
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
                        store_guard
                            .as_ref()
                            .map(|s| (s, path)),
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
    ) {
        let content_hash = match crate::crypto::hash_file_with_size(
            std::path::Path::new(path),
        ) {
            Ok((h, _)) => Some(h),
            Err(e) => {
                log::debug!(
                    "Text fragment hash failed for {path}: {e}"
                );
                None
            }
        };
        let Some(frag_hash) = content_hash else {
            return;
        };
        let ts =
            crate::store::text_fragments::current_timestamp_ms();
        let nonce =
            crate::store::text_fragments::generate_nonce();
        let ctx = if has_paste_ctx {
            crate::store::text_fragments::KeystrokeContext::PastedContent
        } else {
            crate::store::text_fragments::KeystrokeContext::OriginalComposition
        };
        let sig = if let Some(sk) = sk {
            crate::store::text_fragments::sign_fragment(
                sk,
                session_id,
                &frag_hash,
                ts,
                &nonce,
            )
        } else {
            [0u8; 64]
        };
        let fragment = crate::store::text_fragments::TextFragment {
            id: None,
            fragment_hash: frag_hash.to_vec(),
            session_id: session_id.to_string(),
            source_app_bundle_id: Some(app_bundle_id.to_string())
                .filter(|s| !s.is_empty()),
            source_window_title: Some(window_title.to_string())
                .filter(|s| !s.is_empty()),
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: ts,
            keystroke_context: Some(ctx),
            keystroke_confidence: Some(1.0),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };
        if let Err(e) = store.insert_text_fragment(&fragment) {
            log::warn!(
                "Failed to insert text fragment for {path}: {e}"
            );
        }
    }

    /// React to permission state changes (revoked / restored).
    fn handle_permission_check(&self) {
        let current =
            super::permission_monitor::PermissionState::current();
        let prev = *self.permission_state.lock_recover();
        if current == prev {
            return;
        }
        *self.permission_state.lock_recover() = current;
        if !current.keystroke_capture_allowed()
            && prev.keystroke_capture_allowed()
        {
            log::warn!(
                "Permission revoked ({} → {}); stopping keystroke capture",
                prev.as_str(),
                current.as_str()
            );
            *self.tap_check_capture.lock_recover() = None;
            self.tap_check_active.store(false, Ordering::SeqCst);
        } else if current.keystroke_capture_allowed()
            && !prev.keystroke_capture_allowed()
        {
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
                            while r.load(Ordering::SeqCst)
                                && a.load(Ordering::SeqCst)
                            {
                                match sync_rx.recv_timeout(
                                    std::time::Duration::from_millis(100),
                                ) {
                                    Ok(ev) => {
                                        if tx.try_send(ev).is_err() {
                                            break;
                                        }
                                    }
                                    Err(
                                        std::sync::mpsc::RecvTimeoutError::Timeout,
                                    ) => continue,
                                    Err(
                                        std::sync::mpsc::RecvTimeoutError::Disconnected,
                                    ) => break,
                                }
                            }
                        });
                    match h {
                        Ok(handle) => {
                            let mut ts =
                                self.bridge_health_threads.lock_recover();
                            ts.retain(|t| !t.is_finished());
                            ts.push(handle);
                            self.bridge_healthy_flag
                                .store(true, Ordering::SeqCst);
                        }
                        Err(e) => log::error!(
                            "Failed to spawn keystroke-resume bridge: {e}"
                        ),
                    }
                }
                Err(e) => log::warn!(
                    "Keystroke restart failed after permission grant: {e}"
                ),
            },
            Err(e) => log::warn!(
                "Keystroke unavailable after permission grant: {e}"
            ),
        }
    }
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
