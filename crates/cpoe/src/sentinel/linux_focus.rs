// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Linux focus tracking via X11, Wayland, and DBus.
//!
//! Fallback chain: Wayland -> X11 -> DBus -> Stub
//!
//! Each provider is feature-gated and only compiled on `target_os = "linux"`.
//! The factory function [`LinuxFocusMonitor::new_monitor`] probes the runtime
//! environment (WAYLAND_DISPLAY, DISPLAY) and selects the best available
//! provider, wrapping it in a [`PollingSentinelFocusTracker`].

use super::focus::{PollingSentinelFocusTracker, SentinelFocusTracker, WindowProvider};
use super::types::{infer_document_path_from_title, WindowInfo};
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use std::sync::Arc;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// X11 Window Provider
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "x11"))]
mod x11_provider {
    use super::*;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{Atom, AtomEnum, ConnectionExt, GetPropertyReply, Window};
    use x11rb::rust_connection::RustConnection;

    /// Cached X11 atom identifiers for window properties.
    struct X11Atoms {
        net_active_window: Atom,
        net_wm_name: Atom,
        net_wm_pid: Atom,
        utf8_string: Atom,
        wm_name: Atom,
    }

    /// X11 focus provider using `_NET_ACTIVE_WINDOW` on the root window.
    pub struct X11WindowProvider {
        conn: RustConnection,
        root: Window,
        atoms: X11Atoms,
    }

    impl X11WindowProvider {
        /// Connect to the X server and intern required atoms.
        /// Returns `None` if the connection or atom interning fails.
        pub fn new() -> Option<Self> {
            let (conn, screen_num) = match RustConnection::connect(None) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("X11: failed to connect to X server: {e}");
                    return None;
                }
            };
            let screen = &conn.setup().roots[screen_num];
            let root = screen.root;

            match Self::intern_atoms(&conn) {
                Some(atoms) => Some(Self { conn, root, atoms }),
                None => {
                    log::warn!("X11: failed to intern required atoms");
                    None
                }
            }
        }

        fn intern_atoms(conn: &RustConnection) -> Option<X11Atoms> {
            let net_active_window = Self::intern(conn, b"_NET_ACTIVE_WINDOW")?;
            let net_wm_name = Self::intern(conn, b"_NET_WM_NAME")?;
            let net_wm_pid = Self::intern(conn, b"_NET_WM_PID")?;
            let utf8_string = Self::intern(conn, b"UTF8_STRING")?;
            let wm_name = Self::intern(conn, b"WM_NAME")?;
            Some(X11Atoms {
                net_active_window,
                net_wm_name,
                net_wm_pid,
                utf8_string,
                wm_name,
            })
        }

        fn intern(conn: &RustConnection, name: &[u8]) -> Option<Atom> {
            conn.intern_atom(false, name)
                .ok()?
                .reply()
                .ok()
                .map(|r| r.atom)
        }

        /// Read a 32-bit property value from a window.
        fn get_property_u32(&self, window: Window, property: Atom) -> Option<u32> {
            let reply = self
                .conn
                .get_property(false, window, property, AtomEnum::ANY, 0, 1)
                .ok()?
                .reply()
                .ok()?;

            if reply.value_len == 0 || reply.value.len() < 4 {
                return None;
            }
            Some(u32::from_ne_bytes([
                reply.value[0],
                reply.value[1],
                reply.value[2],
                reply.value[3],
            ]))
        }

        /// Read the window title (_NET_WM_NAME or WM_NAME fallback).
        fn get_window_title(&self, window: Window) -> Option<String> {
            // Try _NET_WM_NAME (UTF-8) first.
            if let Some(title) = self.get_text_property(window, self.atoms.net_wm_name) {
                if !title.is_empty() {
                    return Some(title);
                }
            }
            // Fallback to WM_NAME (Latin-1/UTF-8).
            self.get_text_property(window, self.atoms.wm_name)
        }

        fn get_text_property(&self, window: Window, property: Atom) -> Option<String> {
            let reply: GetPropertyReply = self
                .conn
                .get_property(false, window, property, AtomEnum::ANY, 0, 1024)
                .ok()?
                .reply()
                .ok()?;

            if reply.value_len == 0 {
                return None;
            }
            Some(String::from_utf8_lossy(&reply.value).into_owned())
        }

        /// Get _NET_WM_PID from a window.
        fn get_window_pid(&self, window: Window) -> Option<u32> {
            self.get_property_u32(window, self.atoms.net_wm_pid)
        }

        /// Try to read /proc/<pid>/comm to get the process name.
        fn process_name_from_pid(pid: u32) -> Option<String> {
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .ok()
                .map(|s| s.trim().to_string())
        }
    }

    impl WindowProvider for X11WindowProvider {
        fn get_active_window(&self) -> Option<WindowInfo> {
            let active_window = self.get_property_u32(self.root, self.atoms.net_active_window)?;
            if active_window == 0 {
                return None;
            }

            let title_raw = self.get_window_title(active_window)?;
            if title_raw.is_empty() {
                return None;
            }

            let pid = self.get_window_pid(active_window);
            let app_name = pid
                .and_then(Self::process_name_from_pid)
                .unwrap_or_else(|| "unknown".to_string());

            let path = infer_document_path_from_title(&title_raw);
            let is_document = path.is_some();

            Some(WindowInfo {
                path,
                application: app_name,
                title: ObfuscatedString::new(&title_raw),
                pid,
                timestamp: SystemTime::now(),
                is_document,
                is_unsaved: false,
                project_root: None,
                window_number: Some(active_window),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Wayland Window Provider (wlr-foreign-toplevel-management)
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "wayland"))]
mod wayland_provider {
    use super::*;
    use std::sync::Mutex;
    use wayland_client::{protocol::wl_registry, Connection, Dispatch, EventQueue, QueueHandle};
    use wayland_protocols_wlr::foreign_toplevel::v1::client::{
        zwlr_foreign_toplevel_handle_v1::{self, ZwlrForeignToplevelHandleV1},
        zwlr_foreign_toplevel_manager_v1::{self, ZwlrForeignToplevelManagerV1},
    };

    /// Cached state from wlr-foreign-toplevel events.
    struct ToplevelState {
        title: Option<String>,
        app_id: Option<String>,
        focused: bool,
    }

    /// Internal state for the Wayland event dispatch.
    struct WaylandState {
        /// Currently focused toplevel info.
        focused_title: Arc<Mutex<Option<String>>>,
        focused_app_id: Arc<Mutex<Option<String>>>,
        /// All known toplevels indexed by object ID for state tracking.
        toplevels: Vec<ToplevelState>,
    }

    impl Dispatch<wl_registry::WlRegistry, ()> for WaylandState {
        fn event(
            state: &mut Self,
            registry: &wl_registry::WlRegistry,
            event: wl_registry::Event,
            _data: &(),
            _conn: &Connection,
            qh: &QueueHandle<Self>,
        ) {
            if let wl_registry::Event::Global {
                name,
                interface,
                version,
            } = event
            {
                if interface == "zwlr_foreign_toplevel_manager_v1" {
                    registry.bind::<ZwlrForeignToplevelManagerV1, _, _>(
                        name,
                        version.min(3),
                        qh,
                        (),
                    );
                }
            }
        }
    }

    impl Dispatch<ZwlrForeignToplevelManagerV1, ()> for WaylandState {
        fn event(
            _state: &mut Self,
            _proxy: &ZwlrForeignToplevelManagerV1,
            _event: zwlr_foreign_toplevel_manager_v1::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<Self>,
        ) {
            // Toplevel handles are dispatched separately.
        }
    }

    impl Dispatch<ZwlrForeignToplevelHandleV1, ()> for WaylandState {
        fn event(
            state: &mut Self,
            _proxy: &ZwlrForeignToplevelHandleV1,
            event: zwlr_foreign_toplevel_handle_v1::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<Self>,
        ) {
            match event {
                zwlr_foreign_toplevel_handle_v1::Event::Title { title } => {
                    if let Some(last) = state.toplevels.last_mut() {
                        last.title = Some(title);
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                    if let Some(last) = state.toplevels.last_mut() {
                        last.app_id = Some(app_id);
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::State { state: wl_state } => {
                    // State is a list of u32 flags; 2 = activated/focused.
                    let focused = wl_state
                        .chunks_exact(4)
                        .any(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]) == 2);
                    if let Some(last) = state.toplevels.last_mut() {
                        last.focused = focused;
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::Done => {
                    // Update cached focus info.
                    if let Some(toplevel) = state.toplevels.last() {
                        if toplevel.focused {
                            if let Ok(mut t) = state.focused_title.lock() {
                                *t = toplevel.title.clone();
                            }
                            if let Ok(mut a) = state.focused_app_id.lock() {
                                *a = toplevel.app_id.clone();
                            }
                        }
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                    state.toplevels.pop();
                }
                _ => {}
            }
        }
    }

    /// Wayland focus provider using wlr-foreign-toplevel-management.
    pub struct WaylandWindowProvider {
        focused_title: Arc<Mutex<Option<String>>>,
        focused_app_id: Arc<Mutex<Option<String>>>,
    }

    impl WaylandWindowProvider {
        /// Connect to the Wayland compositor and start a background listener thread.
        /// Returns `None` if the connection fails or the compositor does not support
        /// `zwlr_foreign_toplevel_manager_v1`.
        pub fn new() -> Option<Self> {
            let conn = Connection::connect_to_env().ok()?;
            let focused_title = Arc::new(Mutex::new(None));
            let focused_app_id = Arc::new(Mutex::new(None));

            let ft = Arc::clone(&focused_title);
            let fa = Arc::clone(&focused_app_id);

            std::thread::Builder::new()
                .name("wayland-focus-listener".into())
                .spawn(move || {
                    let mut state = WaylandState {
                        focused_title: ft,
                        focused_app_id: fa,
                        toplevels: Vec::new(),
                    };

                    let display = conn.display();
                    let mut event_queue: EventQueue<WaylandState> = conn.new_event_queue();
                    let qh = event_queue.handle();
                    display.get_registry(&qh, ());

                    // Roundtrip to bind the toplevel manager.
                    if event_queue.roundtrip(&mut state).is_err() {
                        log::warn!("Wayland roundtrip failed; focus listener exiting");
                        return;
                    }

                    loop {
                        if event_queue.blocking_dispatch(&mut state).is_err() {
                            log::warn!("Wayland dispatch error; focus listener exiting");
                            break;
                        }
                    }
                })
                .ok()?;

            Some(Self {
                focused_title,
                focused_app_id,
            })
        }
    }

    impl WindowProvider for WaylandWindowProvider {
        fn get_active_window(&self) -> Option<WindowInfo> {
            let title_raw = self.focused_title.lock().ok()?.clone()?;
            let app_id = self
                .focused_app_id
                .lock()
                .ok()?
                .clone()
                .unwrap_or_else(|| "unknown".to_string());

            if title_raw.is_empty() {
                return None;
            }

            let path = infer_document_path_from_title(&title_raw);
            let is_document = path.is_some();

            Some(WindowInfo {
                path,
                application: app_id,
                title: ObfuscatedString::new(&title_raw),
                pid: None,
                timestamp: SystemTime::now(),
                is_document,
                is_unsaved: false,
                project_root: None,
                window_number: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// DBus Window Provider (GNOME / KDE)
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "dbus"))]
mod dbus_provider {
    use super::*;

    /// DBus-based focus provider for GNOME Shell and KDE KWin.
    pub struct DbusWindowProvider {
        /// Cached desktop environment identifier.
        desktop: DesktopEnvironment,
    }

    #[derive(Debug, Clone, Copy)]
    enum DesktopEnvironment {
        Gnome,
        Kde,
        Unknown,
    }

    impl DbusWindowProvider {
        pub fn new() -> Option<Self> {
            // Detect desktop environment from XDG_CURRENT_DESKTOP.
            let desktop = std::env::var("XDG_CURRENT_DESKTOP")
                .map(|d| {
                    let lower = d.to_lowercase();
                    if lower.contains("gnome") {
                        DesktopEnvironment::Gnome
                    } else if lower.contains("kde") || lower.contains("plasma") {
                        DesktopEnvironment::Kde
                    } else {
                        DesktopEnvironment::Unknown
                    }
                })
                .unwrap_or(DesktopEnvironment::Unknown);

            // Only useful if we can identify the desktop.
            if matches!(desktop, DesktopEnvironment::Unknown) {
                return None;
            }

            Some(Self { desktop })
        }

        /// Query GNOME Shell for the focused window title via the Eval interface.
        fn query_gnome(&self) -> Option<(String, Option<u32>)> {
            // Use synchronous zbus blocking connection.
            let conn = zbus::blocking::Connection::session().ok()?;
            let reply = conn
                .call_method(
                    Some("org.gnome.Shell"),
                    "/org/gnome/Shell",
                    Some("org.gnome.Shell"),
                    "Eval",
                    &("global.display.focus_window ? global.display.focus_window.get_title() : ''",),
                )
                .ok()?;

            let body = reply.body();
            let (success, result): (bool, String) = body.deserialize().ok()?;
            if !success || result.is_empty() {
                return None;
            }
            // Strip surrounding quotes from JS eval result.
            let title = result.trim_matches('"').to_string();

            // Try to get PID.
            let pid_reply = conn
                .call_method(
                    Some("org.gnome.Shell"),
                    "/org/gnome/Shell",
                    Some("org.gnome.Shell"),
                    "Eval",
                    &("global.display.focus_window ? global.display.focus_window.get_pid() : 0",),
                )
                .ok();
            let pid = pid_reply.and_then(|r| {
                let b = r.body();
                let (ok, val): (bool, String) = b.deserialize().ok()?;
                if ok {
                    val.parse::<u32>().ok()
                } else {
                    None
                }
            });

            Some((title, pid))
        }

        /// Query KDE KWin for the focused window title via scripting interface.
        fn query_kde(&self) -> Option<(String, Option<u32>)> {
            let conn = zbus::blocking::Connection::session().ok()?;

            // KDE KWin scripting: evaluate a script that returns the active client title.
            let script = "var c = workspace.activeClient; \
                          if (c) { print(c.caption + '\\n' + c.pid); } \
                          else { print('\\n0'); }";
            let reply = conn
                .call_method(
                    Some("org.kde.KWin"),
                    "/Scripting",
                    Some("org.kde.kwin.Scripting"),
                    "loadScript",
                    &(script, "cpoe-focus-query"),
                )
                .ok()?;

            // The result format varies by KDE version; try to parse title and PID.
            let body = reply.body();
            let output: String = body.deserialize().ok().unwrap_or_default();
            let mut lines = output.lines();
            let title = lines.next().unwrap_or("").to_string();
            let pid = lines.next().and_then(|s| s.parse::<u32>().ok());

            if title.is_empty() {
                return None;
            }
            Some((title, pid))
        }
    }

    impl WindowProvider for DbusWindowProvider {
        fn get_active_window(&self) -> Option<WindowInfo> {
            let (title_raw, pid) = match self.desktop {
                DesktopEnvironment::Gnome => self.query_gnome()?,
                DesktopEnvironment::Kde => self.query_kde()?,
                DesktopEnvironment::Unknown => return None,
            };

            if title_raw.is_empty() {
                return None;
            }

            let app_name = pid
                .and_then(|p| {
                    std::fs::read_to_string(format!("/proc/{}/comm", p))
                        .ok()
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|| "unknown".to_string());

            let path = infer_document_path_from_title(&title_raw);
            let is_document = path.is_some();

            Some(WindowInfo {
                path,
                application: app_name,
                title: ObfuscatedString::new(&title_raw),
                pid,
                timestamp: SystemTime::now(),
                is_document,
                is_unsaved: false,
                project_root: None,
                window_number: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Factory: LinuxFocusMonitor
// ---------------------------------------------------------------------------

/// Linux focus monitor factory with automatic backend selection.
///
/// Probes the runtime environment and selects the best available provider:
/// 1. Wayland (if `wayland` feature enabled and `WAYLAND_DISPLAY` set)
/// 2. X11 (if `x11` feature enabled and `DISPLAY` set)
/// 3. DBus (if `dbus` feature enabled and GNOME/KDE detected)
/// 4. Stub fallback (terminal/process heuristics)
pub struct LinuxFocusMonitor;

impl LinuxFocusMonitor {
    /// Create the best available focus tracker for the current Linux environment.
    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        // 1. Try Wayland
        #[cfg(all(target_os = "linux", feature = "wayland"))]
        {
            if std::env::var("WAYLAND_DISPLAY").is_ok() {
                if let Some(provider) = wayland_provider::WaylandWindowProvider::new() {
                    log::info!("Linux focus: using Wayland (wlr-foreign-toplevel) provider");
                    return Box::new(PollingSentinelFocusTracker::new(Arc::new(provider), config));
                }
                log::warn!(
                    "WAYLAND_DISPLAY set but wlr-foreign-toplevel connection failed; \
                     trying next provider"
                );
            }
        }

        // 2. Try X11
        #[cfg(all(target_os = "linux", feature = "x11"))]
        {
            if std::env::var("DISPLAY").is_ok() {
                if let Some(provider) = x11_provider::X11WindowProvider::new() {
                    log::info!("Linux focus: using X11 (_NET_ACTIVE_WINDOW) provider");
                    return Box::new(PollingSentinelFocusTracker::new(Arc::new(provider), config));
                }
                log::warn!("DISPLAY set but X11 connection failed; trying next provider");
            }
        }

        // 3. Try DBus
        #[cfg(all(target_os = "linux", feature = "dbus"))]
        {
            if let Some(provider) = dbus_provider::DbusWindowProvider::new() {
                log::info!("Linux focus: using DBus (GNOME/KDE) provider");
                return Box::new(PollingSentinelFocusTracker::new(Arc::new(provider), config));
            }
        }

        // 4. Stub fallback
        log::info!(
            "Linux focus: no X11/Wayland/DBus provider available; \
             using degraded stub monitor"
        );
        super::stub_focus::StubSentinelFocusTracker::new_monitor(config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_chain_no_display() {
        // When neither WAYLAND_DISPLAY nor DISPLAY are set in the test environment,
        // the factory should return a working tracker (the stub).
        // We cannot easily unset env vars in a test (they are process-global),
        // but we can verify the factory function does not panic and returns
        // a tracker that reports available.
        let config = Arc::new(SentinelConfig::default());
        let tracker = LinuxFocusMonitor::new_monitor(config);
        let (available, _reason) = tracker.available();
        assert!(available, "Fallback tracker should report as available");
    }

    #[test]
    fn test_title_parsing_integration() {
        // Verify that titles in the format Linux window managers produce
        // are correctly parsed by infer_document_path_from_title.
        let cases = vec![
            // gedit style
            ("report.md - gedit", Some("report.md")),
            // VS Code on Linux
            ("main.rs - project - Visual Studio Code", Some("main.rs")),
            // Kate (KDE)
            (
                "/home/user/document.txt - Kate",
                Some("/home/user/document.txt"),
            ),
            // No document
            ("Terminal", None),
            // Absolute path as title
            ("/home/user/notes.md", Some("/home/user/notes.md")),
        ];

        for (title, expected) in cases {
            let result = infer_document_path_from_title(title);
            assert_eq!(result.as_deref(), expected, "Failed for title: {title:?}");
        }
    }

    #[cfg(all(target_os = "linux", feature = "x11"))]
    #[test]
    fn test_x11_atoms_intern() {
        // This test only runs on Linux with x11 feature.
        // It verifies that atom interning does not panic when a display is available.
        // If DISPLAY is not set, this test is effectively a no-op.
        if std::env::var("DISPLAY").is_err() {
            return;
        }
        let provider = x11_provider::X11WindowProvider::new();
        // If we connected, the provider should be Some.
        assert!(
            provider.is_some(),
            "X11 provider should initialize when DISPLAY is set"
        );
    }
}
