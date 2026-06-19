// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use crate::MutexRecover;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};

/// Platform-specific focus monitoring trait.
pub trait SentinelFocusTracker: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn active_window(&self) -> Option<WindowInfo>;
    fn available(&self) -> (bool, String);
    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>>;
    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>>;
    /// Return a cloneable sender that delivers events into the same channel as `change_events()`.
    /// Used by `BundleMonitor` to inject FSEvents into the main event loop.
    fn change_sender(&self) -> mpsc::Sender<ChangeEvent>;
}

/// Provider for active window information. Implemented per-platform.
pub trait WindowProvider: Send + Sync + 'static {
    fn get_active_window(&self) -> Option<WindowInfo>;
}

#[derive(Debug)]
/// Polling-based focus monitor backed by a `WindowProvider`.
pub struct PollingSentinelFocusTracker<P: WindowProvider + ?Sized> {
    provider: Arc<P>,
    config: Arc<SentinelConfig>,
    running: Arc<AtomicBool>,
    focus_tx: mpsc::Sender<FocusEvent>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    change_tx: mpsc::Sender<ChangeEvent>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    poll_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

/// Returns true when Stage Manager (WindowManager process) is active on macOS.
/// Cached for 5 seconds to avoid repeated process table scans.
#[cfg(target_os = "macos")]
fn is_stage_manager_active() -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static CACHED: AtomicBool = AtomicBool::new(false);
    static LAST_CHECK_SECS: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_CHECK_SECS.load(Ordering::Relaxed);

    if now.saturating_sub(last) < 5 {
        return CACHED.load(Ordering::Relaxed);
    }
    LAST_CHECK_SECS.store(now, Ordering::Relaxed);

    let active = std::process::Command::new("pgrep")
        .args(["-x", "WindowManager"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    CACHED.store(active, Ordering::Relaxed);
    active
}

#[cfg(not(target_os = "macos"))]
fn is_stage_manager_active() -> bool {
    false
}

impl<P: WindowProvider + ?Sized> PollingSentinelFocusTracker<P> {
    pub fn new(provider: Arc<P>, config: Arc<SentinelConfig>) -> Self {
        let (focus_tx, focus_rx) = mpsc::channel(100);
        let (change_tx, change_rx) = mpsc::channel(100);

        Self {
            provider,
            config,
            running: Arc::new(AtomicBool::new(false)),
            focus_tx,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_tx,
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            poll_handle: Arc::new(Mutex::new(None)),
        }
    }
}

impl<P: WindowProvider + ?Sized> SentinelFocusTracker for PollingSentinelFocusTracker<P> {
    fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Err(SentinelError::AlreadyRunning);
        }

        let running_clone = Arc::clone(&self.running);
        let focus_tx = self.focus_tx.clone();
        let config = self.config.clone();
        let provider = Arc::clone(&self.provider);
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        let debounce_dur = Duration::from_millis(config.focus_debounce_ms);

        let handle = tokio::spawn(async move {
            let mut last_app = String::new();
            let mut last_path: Option<String> = None;
            let mut last_window_number: Option<u32> = None;
            let mut interval_timer = interval(poll_interval);

            // Adaptive debounce: increase after rapid focus bounces, return to
            // baseline after stable focus.
            const BOUNCE_WINDOW: Duration = Duration::from_millis(500);
            const BOUNCE_THRESHOLD: u32 = 3;
            const ELEVATED_DEBOUNCE: Duration = Duration::from_millis(300);
            const STABLE_THRESHOLD: Duration = Duration::from_secs(5);
            let mut bounce_count: u32 = 0;
            let mut last_focus_change = Instant::now();
            let mut elevated_since: Option<Instant> = None;

            // Pending focus-loss state: (app_bundle_id, when_detected).
            // FocusLost is only emitted once the debounce timer expires, which
            // suppresses spurious losses during Mission Control, Stage Manager,
            // and full-screen transitions.
            let mut pending_loss: Option<(String, Instant)> = None;

            // Apps discovered at runtime via accessibility probing.
            let mut discovered_apps: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            // Probe the currently focused window immediately on startup so
            // the sentinel knows what document is active before keystrokes
            // arrive.  This is critical after a stop/restart cycle where the
            // document was already open and no OS focus event will fire.
            let initial_info = {
                let p = Arc::clone(&provider);
                tokio::task::spawn_blocking(move || p.get_active_window())
                    .await
                    .ok()
                    .flatten()
            };
            if let Some(info) = initial_info {
                let app = if !info.application.is_empty() {
                    info.application.clone()
                } else {
                    "unknown".to_string()
                };
                let app_name = info.application.clone();
                if config.is_app_allowed(&info.application, &app_name) {
                    if focus_tx
                        .send(FocusEvent {
                            event_type: FocusEventType::FocusGained,
                            path: info.path.clone().unwrap_or_default(),
                            shadow_id: String::new(),
                            app_bundle_id: info.application.clone(),
                            app_name: info.application.clone(),
                            window_title: info.title.clone(),
                            timestamp: SystemTime::now(),
                            window_id: info.window_number,
                            char_count_delta: None,
                        })
                        .await
                        .is_err()
                    {
                        log::warn!("Focus event channel closed, stopping poll");
                        return;
                    }
                    last_path = info.path.clone();
                }
                last_app = app;
                last_window_number = info.window_number;
            }

            // Helper macro to send a focus event, breaking on channel close.
            macro_rules! send_or_break {
                ($event:expr) => {
                    if focus_tx.send($event).await.is_err() {
                        log::warn!("Focus event channel closed, stopping poll");
                        break;
                    }
                };
            }

            loop {
                interval_timer.tick().await;

                if !running_clone.load(Ordering::Acquire) {
                    break;
                }

                let info = {
                    let p = Arc::clone(&provider);
                    tokio::task::spawn_blocking(move || p.get_active_window())
                        .await
                        .ok()
                        .flatten()
                };

                if info.is_none() {
                    log::trace!("[POLL] no active window (transient UI / Mission Control)");
                    if !last_app.is_empty() && pending_loss.is_none() {
                        log::trace!("[POLL] starting pending loss timer for {}", last_app);
                        pending_loss = Some((last_app.clone(), Instant::now()));
                    }
                    // Check if pending loss has expired past the debounce window.
                    // Stage Manager switches windows rapidly; use a shorter debounce
                    // to avoid merging distinct window-switch events.
                    let effective_debounce = if is_stage_manager_active() {
                        Duration::from_millis(30)
                    } else if elevated_since.is_some() {
                        ELEVATED_DEBOUNCE
                    } else {
                        debounce_dur
                    };
                    if let Some((ref lost_app, started)) = pending_loss {
                        if started.elapsed() >= effective_debounce {
                            send_or_break!(FocusEvent {
                                event_type: FocusEventType::FocusLost,
                                path: String::new(),
                                shadow_id: String::new(),
                                app_bundle_id: lost_app.clone(),
                                app_name: String::new(),
                                window_title: ObfuscatedString::default(),
                                timestamp: SystemTime::now(),
                                window_id: None,
                                char_count_delta: None,
                            });
                            last_app.clear();
                            last_path = None;
                            last_window_number = None;
                            pending_loss = None;
                        }
                    }
                    continue;
                }
                let mut info = info.unwrap();

                let current_app = if !info.application.is_empty() {
                    info.application.clone()
                } else {
                    "unknown".to_string()
                };

                // Terminal editor detection: override path/app when an editor
                // is running inside a terminal, regardless of app-switch state.
                let is_terminal = super::terminal_editors::is_terminal_emulator_bundle(&current_app)
                    || super::terminal_editors::is_terminal_emulator_name(&current_app);
                if is_terminal {
                    if let Some(pid) = info.pid {
                        if let Some(editor_info) = super::terminal_editors::detect_editor_in_terminal(pid) {
                            info.application = format!("terminal.editor.{}", editor_info.editor);
                            if let Some(ref fp) = editor_info.file_path {
                                info.path = Some(fp.clone());
                            }
                        }
                    } else {
                        let title_revealed = info.title.reveal();
                        if let Some((editor, file)) = super::terminal_editors::parse_terminal_title_for_editor(&title_revealed) {
                            let p = std::path::Path::new(&file);
                            if !p.is_absolute() || p.exists() {
                                info.application = format!("terminal.editor.{}", editor);
                                info.path = Some(file);
                            }
                        }
                    }
                }

                if current_app == last_app {
                    // Same app — cancel any pending loss (was a transient bounce).
                    pending_loss = None;

                    // Check for intra-app document switch.
                    if info.path.is_some() && info.path != last_path {
                        log::debug!(
                            "[POLL] intra-app doc switch: {:?} -> {:?} (win {:?} -> {:?})",
                            last_path, info.path, last_window_number, info.window_number
                        );
                    }

                    // Check for Space transition: same app but different window visible.
                    if info.window_number.is_some()
                        && info.window_number != last_window_number
                        && info.path.is_some()
                        && info.path != last_path
                    {
                        let app_name = info.application.clone();
                        if is_terminal || config.is_app_allowed(&info.application, &app_name) {
                            if let Some(ref old_path) = last_path {
                                send_or_break!(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: old_path.clone(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                    window_id: None,
                                    char_count_delta: None,
                                });
                            }
                            send_or_break!(FocusEvent {
                                event_type: FocusEventType::FocusGained,
                                path: info.path.clone().unwrap_or_default(),
                                shadow_id: String::new(),
                                app_bundle_id: info.application.clone(),
                                app_name: info.application.clone(),
                                window_title: info.title.clone(),
                                timestamp: SystemTime::now(),
                                window_id: info.window_number,
                                char_count_delta: None,
                            });
                            last_path = info.path.clone();
                        }
                        last_window_number = info.window_number;
                    } else if info.path.is_some() && info.path != last_path {
                        log::debug!(
                            "[POLL] intra-app path change: {:?} -> {:?}",
                            last_path, info.path
                        );
                        let app_name = info.application.clone();
                        if is_terminal || config.is_app_allowed(&info.application, &app_name) {
                            if let Some(ref old_path) = last_path {
                                send_or_break!(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: old_path.clone(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                    window_id: None,
                                    char_count_delta: None,
                                });
                            }
                            send_or_break!(FocusEvent {
                                event_type: FocusEventType::FocusGained,
                                path: info.path.clone().unwrap_or_default(),
                                shadow_id: String::new(),
                                app_bundle_id: info.application.clone(),
                                app_name: info.application.clone(),
                                window_title: info.title.clone(),
                                timestamp: SystemTime::now(),
                                window_id: info.window_number,
                                char_count_delta: None,
                            });
                            last_path = info.path.clone();
                        }
                        last_window_number = info.window_number;
                    }
                } else {
                    // Different app detected.
                    log::debug!(
                        "[POLL] app switch: {} -> {} (path={:?})",
                        last_app, current_app, info.path
                    );
                    if pending_loss.is_none() {
                        pending_loss = Some((last_app.clone(), Instant::now()));
                    }

                    let effective_debounce = if is_stage_manager_active() {
                        Duration::from_millis(30)
                    } else if elevated_since.is_some() {
                        ELEVATED_DEBOUNCE
                    } else {
                        debounce_dur
                    };
                    if let Some((ref lost_app, started)) = pending_loss {
                        if started.elapsed() >= effective_debounce {
                            log::debug!(
                                "[POLL] debounce expired: {} -> {} (elapsed={:?}ms)",
                                lost_app, current_app, started.elapsed().as_millis()
                            );
                            if !lost_app.is_empty() {
                                send_or_break!(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: String::new(),
                                    shadow_id: String::new(),
                                    app_bundle_id: lost_app.clone(),
                                    app_name: String::new(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                    window_id: None,
                                    char_count_delta: None,
                                });
                            }
                            pending_loss = None;

                            // info.application and info.path are already
                            // overridden by terminal editor detection above.
                            let effective_path = info.path.clone();
                            let effective_app = info.application.clone();
                            let effective_app_name = effective_app.clone();

                            let app_allowed = if config.is_app_allowed(&effective_app, &effective_app_name)
                                || discovered_apps.contains(&current_app)
                                || discovered_apps.contains(&effective_app)
                            {
                                true
                            } else if is_terminal {
                                effective_path.is_some()
                            } else if let Some(pid) = info.pid {
                                if super::app_discovery::probe_runtime_text_editing(
                                    &current_app, pid,
                                ).is_some() {
                                    discovered_apps.insert(current_app.clone());
                                    log::info!(
                                        "auto-discovered writing app: {}",
                                        current_app,
                                    );
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            log::debug!(
                                "[POLL] app_allowed={} app={} path={:?}",
                                app_allowed, effective_app, effective_path
                            );
                            if app_allowed {
                                send_or_break!(FocusEvent {
                                    event_type: FocusEventType::FocusGained,
                                    path: effective_path.clone().unwrap_or_default(),
                                    shadow_id: String::new(),
                                    app_bundle_id: effective_app,
                                    app_name: effective_app_name,
                                    window_title: info.title.clone(),
                                    timestamp: SystemTime::now(),
                                    window_id: info.window_number,
                                    char_count_delta: None,
                                });
                                last_path = effective_path;
                            } else {
                                log::trace!("[POLL] app NOT allowed, clearing last_path");
                                last_path = None;
                            }

                            // Track focus bounces for adaptive debounce.
                            let now = Instant::now();
                            if now.duration_since(last_focus_change) < BOUNCE_WINDOW {
                                bounce_count += 1;
                                if bounce_count >= BOUNCE_THRESHOLD {
                                    elevated_since = Some(now);
                                }
                            } else {
                                bounce_count = 1;
                            }
                            last_focus_change = now;
                            // Return to baseline after stable focus.
                            if let Some(since) = elevated_since {
                                if now.duration_since(since) >= STABLE_THRESHOLD {
                                    elevated_since = None;
                                    bounce_count = 0;
                                }
                            }

                            last_app = current_app;
                            last_window_number = info.window_number;
                        }
                    }
                }
            }
        });

        *self.poll_handle.lock_recover() = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        if let Some(handle) = self.poll_handle.lock_recover().take() {
            handle.abort();
        }

        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        self.provider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (true, "Polling monitor available".to_string())
    }

    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>> {
        self.focus_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("focus receiver already consumed".to_string()))
    }

    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>> {
        self.change_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("change receiver already consumed".to_string()))
    }

    fn change_sender(&self) -> mpsc::Sender<ChangeEvent> {
        self.change_tx.clone()
    }
}

// ---------------------------------------------------------------------------
// HybridFocusTracker: AXObserver push + reduced-frequency polling watchdog.
// ---------------------------------------------------------------------------

/// Focus tracker that combines AXObserver push notifications with a low-frequency
/// polling watchdog. AX notifications provide near-instant focus detection while
/// the polling fallback catches apps that do not emit AX events.
#[cfg(target_os = "macos")]
pub struct HybridFocusTracker {
    ax_provider: super::macos_focus::AXObserverFocusProvider,
    poller: PollingSentinelFocusTracker<dyn WindowProvider>,
    running: Arc<AtomicBool>,
    focus_tx: mpsc::Sender<FocusEvent>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    change_tx: mpsc::Sender<ChangeEvent>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    merge_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    bridge_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for HybridFocusTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridFocusTracker")
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(target_os = "macos")]
impl HybridFocusTracker {
    /// Attempt to create a hybrid tracker. Returns `None` if AXObserver cannot
    /// be initialized (falls back to pure polling in the caller).
    pub fn try_new(config: Arc<SentinelConfig>) -> Option<Self> {
        let window_provider = Arc::new(super::macos_focus::MacOSFocusMonitor::new(
            Arc::clone(&config),
        ));

        let ax_provider =
            super::macos_focus::AXObserverFocusProvider::try_new(Arc::clone(&window_provider))?;

        // Watchdog poller at 2000ms instead of the default 100ms.
        let watchdog_config = Arc::new(SentinelConfig {
            poll_interval_ms: 2000,
            ..(*config).clone()
        });
        let poller = PollingSentinelFocusTracker::new(
            window_provider as Arc<dyn WindowProvider>,
            watchdog_config,
        );

        let (focus_tx, focus_rx) = mpsc::channel(100);
        let (change_tx, change_rx) = mpsc::channel(100);

        Some(Self {
            ax_provider,
            poller,
            running: Arc::new(AtomicBool::new(false)),
            focus_tx,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_tx,
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            merge_handle: Arc::new(Mutex::new(None)),
            bridge_handle: Arc::new(Mutex::new(None)),
        })
    }
}

#[cfg(target_os = "macos")]
impl SentinelFocusTracker for HybridFocusTracker {
    fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Err(SentinelError::AlreadyRunning);
        }

        // Start the AXObserver push provider.
        self.ax_provider.start();

        // Start the polling watchdog.
        self.poller.start()?;

        // Take receivers from both sources.
        let ax_rx = self.ax_provider.take_receiver();
        let mut poll_rx = self.poller.focus_events()?;

        let focus_tx = self.focus_tx.clone();
        let running = Arc::clone(&self.running);

        // Bridge AX events (std::sync::mpsc) into a tokio channel so we can
        // select! over both sources in the merge task.
        let (ax_bridge_tx, mut ax_bridge_rx) = mpsc::channel::<FocusEvent>(100);
        if let Some(ax_rx) = ax_rx {
            let bridge_running = Arc::clone(&running);
            let handle = std::thread::Builder::new()
                .name("ax-bridge".into())
                .spawn(move || {
                    while bridge_running.load(Ordering::Acquire) {
                        match ax_rx.recv_timeout(std::time::Duration::from_millis(200)) {
                            Ok(event) => {
                                if ax_bridge_tx.blocking_send(event).is_err() {
                                    break;
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
            match handle {
                Ok(h) => {
                    *self.bridge_handle.lock_recover() = Some(h);
                }
                Err(e) => {
                    log::error!("Failed to spawn ax-bridge thread: {e}");
                }
            }
        }

        // AX-primary architecture: AXObserver is the authoritative source.
        // Polling only acts as a corrector/watchdog.
        //
        // - AX events are forwarded immediately (they fire within ms of
        //   the actual app/document switch).
        // - Polling FocusGained events are forwarded ONLY if AXObserver
        //   hasn't fired in the last AX_SILENCE_THRESHOLD (watchdog mode),
        //   or if the polling event reveals a different path than the last
        //   AX event (correction mode for intra-app tab switches that AX
        //   doesn't capture).
        // - Polling FocusLost events are ALWAYS dropped — unfocusing is
        //   handled implicitly when a new FocusGained arrives (the
        //   handle_focus_event_sync handler unfocuses the old session
        //   before focusing the new one).
        let merge_handle = tokio::spawn(async move {
            let mut last_ax_event_at: Option<Instant> = None;
            let mut last_emitted_path: Option<String> = None;
            const AX_SILENCE_THRESHOLD: Duration = Duration::from_secs(5);

            loop {
                if !running.load(Ordering::Acquire) {
                    break;
                }

                let event = tokio::select! {
                    Some(e) = ax_bridge_rx.recv() => {
                        // AX event: always forward, always authoritative.
                        last_ax_event_at = Some(Instant::now());
                        last_emitted_path = Some(e.path.clone());
                        log::debug!(
                            "hybrid: AX event {:?} path={:?} app={}",
                            e.event_type, e.path, e.app_bundle_id
                        );
                        if focus_tx.send(e).await.is_err() { break; }
                        continue;
                    },
                    Some(e) = poll_rx.recv() => e,
                    else => break,
                };

                // Polling event received. Decide whether to forward.
                if event.event_type == FocusEventType::FocusLost {
                    // Never forward polling FocusLost — unfocusing is handled
                    // by the FocusGained handler's path_to_unfocus logic.
                    log::debug!(
                        "hybrid: dropped polling FocusLost for {}",
                        event.app_bundle_id
                    );
                    continue;
                }

                // Polling FocusGained: forward if AX is silent (watchdog) or
                // if polling found a different path (correction).
                let ax_silent = last_ax_event_at
                    .map(|t| t.elapsed() >= AX_SILENCE_THRESHOLD)
                    .unwrap_or(true);

                let path_differs = last_emitted_path.as_ref()
                    .map(|p| *p != event.path)
                    .unwrap_or(true);

                if ax_silent || path_differs {
                    log::debug!(
                        "hybrid: forwarding poll FocusGained (ax_silent={} path_differs={}) path={:?}",
                        ax_silent, path_differs, event.path
                    );
                    last_emitted_path = Some(event.path.clone());
                    if focus_tx.send(event).await.is_err() {
                        break;
                    }
                } else {
                    log::debug!(
                        "hybrid: dropped redundant poll FocusGained (AX already handled) path={:?}",
                        event.path
                    );
                }
            }
        });

        *self.merge_handle.lock_recover() = Some(merge_handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        self.ax_provider.stop();
        if let Err(e) = self.poller.stop() {
            log::warn!("poller stop failed: {e}");
        }
        if let Some(handle) = self.bridge_handle.lock_recover().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.merge_handle.lock_recover().take() {
            handle.abort();
        }
        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        self.poller.active_window()
    }

    fn available(&self) -> (bool, String) {
        (true, "Hybrid AXObserver + polling monitor".to_string())
    }

    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>> {
        self.focus_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("focus receiver already consumed".to_string()))
    }

    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>> {
        self.change_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("change receiver already consumed".to_string()))
    }

    fn change_sender(&self) -> mpsc::Sender<ChangeEvent> {
        self.change_tx.clone()
    }
}

#[cfg(target_os = "macos")]
impl Drop for HybridFocusTracker {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.ax_provider.stop();
        if let Some(handle) = self.bridge_handle.lock_recover().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.merge_handle.lock_recover().take() {
            handle.abort();
        }
    }
}

impl<P: WindowProvider + ?Sized> Drop for PollingSentinelFocusTracker<P> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.poll_handle.lock_recover().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Mock provider that returns a programmable sequence of WindowInfo values.
    struct MockWindowProvider {
        sequence: Vec<Option<WindowInfo>>,
        index: AtomicUsize,
    }

    impl MockWindowProvider {
        fn new(sequence: Vec<Option<WindowInfo>>) -> Self {
            Self {
                sequence,
                index: AtomicUsize::new(0),
            }
        }
    }

    impl WindowProvider for MockWindowProvider {
        fn get_active_window(&self) -> Option<WindowInfo> {
            let i = self.index.fetch_add(1, Ordering::SeqCst);
            if i < self.sequence.len() {
                self.sequence[i].clone()
            } else {
                // After sequence exhausted, keep returning the last value.
                self.sequence.last().cloned().flatten()
            }
        }
    }

    fn make_window(app: &str, path: Option<&str>, win_num: Option<u32>) -> Option<WindowInfo> {
        Some(WindowInfo {
            application: app.to_string(),
            path: path.map(|s| s.to_string()),
            title: ObfuscatedString::new("test"),
            pid: Some(123),
            timestamp: SystemTime::now(),
            is_document: path.is_some(),
            is_unsaved: false,
            project_root: None,
            window_number: win_num,
        })
    }

    fn test_config(debounce_ms: u64) -> Arc<SentinelConfig> {
        Arc::new(SentinelConfig {
            poll_interval_ms: 10,
            focus_debounce_ms: debounce_ms,
            ..SentinelConfig::default()
        })
    }

    /// Collect focus events from a tracker for a bounded duration.
    async fn collect_events(
        provider: MockWindowProvider,
        config: Arc<SentinelConfig>,
        collect_ms: u64,
    ) -> Vec<FocusEvent> {
        let tracker = PollingSentinelFocusTracker::new(Arc::new(provider), config);
        let mut rx = tracker.focus_events().unwrap();
        tracker.start().unwrap();

        let mut events = Vec::new();
        let deadline = tokio::time::sleep(Duration::from_millis(collect_ms));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    events.push(event);
                }
                () = &mut deadline => break,
            }
        }

        tracker.stop().unwrap();
        events
    }

    #[tokio::test]
    async fn test_mission_control_debounce_suppresses_spurious_loss() {
        // Sequence: App_A -> None (MC) -> None -> App_A (user cancels MC)
        // With 50ms debounce and 10ms poll, the None gap is 20ms < 50ms debounce.
        let seq = vec![
            make_window("com.app.editor", Some("/doc.txt"), Some(1)),
            None,
            None,
            make_window("com.app.editor", Some("/doc.txt"), Some(1)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(50), 200).await;

        // Should only see the initial FocusGained, no FocusLost.
        assert!(
            events.iter().all(|e| e.event_type != FocusEventType::FocusLost),
            "Spurious FocusLost during Mission Control bounce"
        );
        assert_eq!(events.first().unwrap().event_type, FocusEventType::FocusGained);
    }

    #[tokio::test]
    async fn test_real_app_switch_after_debounce() {
        // Sequence: App_A -> None -> None -> ... -> App_B
        // None gap long enough to expire debounce (6 Nones * 10ms = 60ms > 50ms debounce)
        let seq = vec![
            make_window("com.app.a", Some("/a.txt"), Some(1)),
            None,
            None,
            None,
            None,
            None,
            None,
            make_window("com.app.b", Some("/b.txt"), Some(2)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(50), 300).await;

        let types: Vec<_> = events.iter().map(|e| &e.event_type).collect();
        assert!(
            types.contains(&&FocusEventType::FocusLost),
            "Should emit FocusLost for app.a after debounce"
        );
        assert!(
            types.iter().filter(|t| ***t == FocusEventType::FocusGained).count() >= 2,
            "Should emit FocusGained for both app.a (initial) and app.b"
        );
    }

    #[tokio::test]
    async fn test_stage_manager_dock_bounce_filtered() {
        // Stage Manager bounce: App_A -> Dock (filtered to None) -> App_B
        // Dock is filtered by TRANSIENT_BUNDLES in macos_focus.rs, so the
        // mock simulates this as None. With debounce, the Dock gap is suppressed.
        let seq = vec![
            make_window("com.app.a", Some("/a.txt"), Some(1)),
            None, // Dock filtered
            make_window("com.app.b", Some("/b.txt"), Some(2)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(5), 200).await;

        // No event should reference com.apple.dock
        assert!(
            events.iter().all(|e| e.app_bundle_id != "com.apple.dock"),
            "Dock should never appear in focus events"
        );
    }

    #[tokio::test]
    async fn test_space_switch_same_app_different_window() {
        // Same app frontmost on both Spaces, but different window (different doc).
        let seq = vec![
            make_window("com.app.editor", Some("/space1.txt"), Some(100)),
            make_window("com.app.editor", Some("/space2.txt"), Some(200)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(50), 200).await;

        let gained_paths: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == FocusEventType::FocusGained)
            .map(|e| e.path.as_str())
            .collect();
        assert!(
            gained_paths.contains(&"/space1.txt"),
            "Initial FocusGained for space1"
        );
        assert!(
            gained_paths.contains(&"/space2.txt"),
            "FocusGained for space2 after Space switch"
        );
    }

    #[tokio::test]
    async fn test_fullscreen_transition_no_false_boundary() {
        // Full-screen animation: App_A -> None -> None -> App_A
        // Identical to MC test — debounce should suppress.
        let seq = vec![
            make_window("com.app.editor", Some("/doc.txt"), Some(1)),
            None,
            None,
            make_window("com.app.editor", Some("/doc.txt"), Some(1)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(50), 200).await;

        assert!(
            events.iter().all(|e| e.event_type != FocusEventType::FocusLost),
            "Full-screen transition should not cause FocusLost"
        );
    }

    #[tokio::test]
    async fn test_debounce_zero_immediate_emission() {
        // With debounce=0, FocusLost should fire immediately on app change.
        let seq = vec![
            make_window("com.app.a", Some("/a.txt"), Some(1)),
            make_window("com.app.b", Some("/b.txt"), Some(2)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(0), 200).await;

        let types: Vec<_> = events.iter().map(|e| &e.event_type).collect();
        assert!(
            types.contains(&&FocusEventType::FocusLost),
            "debounce=0 should emit FocusLost immediately"
        );
        assert!(
            types.contains(&&FocusEventType::FocusGained),
            "debounce=0 should emit FocusGained immediately"
        );
    }

    #[tokio::test]
    async fn test_rapid_switching_coalesces() {
        // Rapid A->B->C->D within debounce window — should coalesce to A lost, D gained.
        let seq = vec![
            make_window("com.app.a", Some("/a.txt"), Some(1)),
            make_window("com.app.b", Some("/b.txt"), Some(2)),
            make_window("com.app.c", Some("/c.txt"), Some(3)),
            make_window("com.app.d", Some("/d.txt"), Some(4)),
        ];
        let events = collect_events(MockWindowProvider::new(seq), test_config(50), 300).await;

        // Should NOT see FocusGained for B or C — they were transient.
        let gained_apps: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == FocusEventType::FocusGained)
            .map(|e| e.app_bundle_id.as_str())
            .collect();
        assert!(
            !gained_apps.contains(&"com.app.b"),
            "Transient app B should be coalesced"
        );
        assert!(
            !gained_apps.contains(&"com.app.c"),
            "Transient app C should be coalesced"
        );
        assert!(
            gained_apps.contains(&"com.app.d"),
            "Final app D should have FocusGained"
        );
    }
}
