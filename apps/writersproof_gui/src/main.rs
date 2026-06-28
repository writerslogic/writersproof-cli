// SPDX-License-Identifier: AGPL-3.0-only

//! WritersProof desktop GUI (Linux).
//!
//! A thin GTK4/libadwaita client over the witnessing daemon's Unix-socket IPC
//! (`cpoe::ipc`). A tokio worker thread owns the `AsyncIpcClient` connection and
//! forwards daemon state to the GTK main loop over a `glib` channel; the UI is
//! never blocked on IPC.
//!
//! P2.2: read-only live status (running / tracked files / uptime).

use cpoe::ipc::AsyncIpcClient;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Application, Box as GtkBox, Orientation};
use libadwaita as adw;
use std::path::PathBuf;
use std::time::Duration;

/// Reverse-DNS application id (company namespace `writerslogic`, product
/// `WritersProof`).
const APP_ID: &str = "com.writerslogic.WritersProof";
/// How often to poll the daemon for status while connected.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How long to wait before retrying a failed connection.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(3);

/// Daemon state pushed from the IPC worker to the UI thread.
#[derive(Debug, Clone)]
enum DaemonState {
    Connected {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    Disconnected(String),
}

/// Resolve the witnessing data directory the same way the CLI does:
/// `$CPOE_DATA_DIR`, else `~/.writersproof`.
fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".writersproof")
}

/// The daemon's IPC socket (`<data_dir>/sentinel.sock`).
fn socket_path() -> PathBuf {
    data_dir().join("sentinel.sock")
}

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    // libadwaita 1.1 has no AdwApplication, so init Adwaita on startup.
    app.connect_startup(|_| {
        adw::init().expect("failed to initialize libadwaita");
    });
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    let header = adw::HeaderBar::new();

    let status_page = adw::StatusPage::builder()
        .icon_name("content-loading-symbolic")
        .title("WritersProof")
        .description("Connecting to the witnessing daemon…")
        .vexpand(true)
        .build();

    let content = GtkBox::new(Orientation::Vertical, 0);
    content.append(&header);
    content.append(&status_page);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("WritersProof")
        .default_width(420)
        .default_height(640)
        .content(&content)
        .build();

    // Channel: IPC worker thread -> GTK main loop.
    let (tx, rx) = glib::MainContext::channel::<DaemonState>(glib::PRIORITY_DEFAULT);

    std::thread::Builder::new()
        .name("wp-ipc".into())
        .spawn(move || ipc_worker(tx))
        .expect("failed to spawn IPC worker thread");

    let page = status_page.clone();
    rx.attach(None, move |state| {
        render_state(&page, &state);
        glib::Continue(true)
    });

    window.present();
}

/// Reflect a daemon state into the status page.
fn render_state(page: &adw::StatusPage, state: &DaemonState) {
    match state {
        DaemonState::Connected {
            running,
            tracked_files,
            uptime_secs,
        } => {
            page.set_title(if *running {
                "Witnessing active"
            } else {
                "Daemon idle"
            });
            page.set_icon_name(Some(if *running {
                "security-high-symbolic"
            } else {
                "security-medium-symbolic"
            }));
            let uptime = format_uptime(*uptime_secs);
            let description = if tracked_files.is_empty() {
                format!("No documents tracked · up {uptime}")
            } else {
                format!(
                    "{} document(s) tracked · up {uptime}\n\n{}",
                    tracked_files.len(),
                    tracked_files.join("\n")
                )
            };
            page.set_description(Some(&description));
        }
        DaemonState::Disconnected(reason) => {
            page.set_title("Daemon not running");
            page.set_icon_name(Some("security-low-symbolic"));
            page.set_description(Some(&format!(
                "{reason}\n\nStart it with:  writersproof-cli start"
            )));
        }
    }
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// IPC worker: owns a single-threaded tokio runtime and the daemon connection.
/// Reconnects indefinitely; pushes every status poll (or a disconnect) to the UI.
fn ipc_worker(tx: glib::Sender<DaemonState>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = tx.send(DaemonState::Disconnected(format!("runtime error: {e}")));
            return;
        }
    };

    rt.block_on(async move {
        loop {
            match AsyncIpcClient::connect(socket_path()).await {
                Ok(mut client) => {
                    // Handshake is best-effort; status still works without it.
                    let _ = client.handshake(env!("CARGO_PKG_VERSION")).await;
                    loop {
                        match client.get_status().await {
                            Ok((running, tracked_files, uptime_secs)) => {
                                if tx
                                    .send(DaemonState::Connected {
                                        running,
                                        tracked_files,
                                        uptime_secs,
                                    })
                                    .is_err()
                                {
                                    return; // UI gone
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(DaemonState::Disconnected(format!(
                                    "lost connection to daemon: {e}"
                                )));
                                break; // drop client, reconnect
                            }
                        }
                        tokio::time::sleep(POLL_INTERVAL).await;
                    }
                }
                Err(e) => {
                    if tx
                        .send(DaemonState::Disconnected(format!(
                            "daemon not reachable: {e}"
                        )))
                        .is_err()
                    {
                        return;
                    }
                }
            }
            tokio::time::sleep(RECONNECT_INTERVAL).await;
        }
    });
}
