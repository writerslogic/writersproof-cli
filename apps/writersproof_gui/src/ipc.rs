// SPDX-License-Identifier: AGPL-3.0-only

//! IPC worker: bridges the daemon's async Unix-socket protocol to the GTK main
//! loop. A dedicated thread runs a single-threaded tokio runtime that owns the
//! `AsyncIpcClient`. The UI sends [`Command`]s in (tokio mpsc, whose `send` is
//! sync and callable from GTK callbacks) and receives [`UiEvent`]s out (glib
//! channel, delivered on the GTK main loop). The UI never blocks on IPC.

use cpoe::ipc::{AsyncIpcClient, IpcMessage};
use gtk4::glib;
use std::path::PathBuf;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Resolve the witnessing data directory the same way the CLI does:
/// `$CPOE_DATA_DIR`, else `~/.writersproof`.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".writersproof")
}

fn socket_path() -> PathBuf {
    data_dir().join("sentinel.sock")
}

/// Commands sent from the UI to the IPC worker.
#[derive(Debug)]
pub enum Command {
    Track(PathBuf),
    Untrack(PathBuf),
    Export { path: PathBuf, tier: String },
    Verify(PathBuf),
}

/// Events sent from the IPC worker to the UI.
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Latest daemon status (running, tracked file paths, uptime seconds).
    Status {
        running: bool,
        tracked: Vec<String>,
        uptime: u64,
    },
    /// Not connected to a daemon; carries a human-readable reason.
    Disconnected(String),
    /// Transient notification to surface as a toast.
    Toast(String),
}

/// Spawn the worker thread. Returns immediately.
pub fn spawn_worker(
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Command>,
    evt_tx: glib::Sender<UiEvent>,
) {
    std::thread::Builder::new()
        .name("wp-ipc".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = evt_tx.send(UiEvent::Disconnected(format!("runtime error: {e}")));
                    return;
                }
            };

            rt.block_on(async move {
                let mut client: Option<AsyncIpcClient> = None;
                let mut poll = tokio::time::interval(POLL_INTERVAL);

                loop {
                    tokio::select! {
                        _ = poll.tick() => {
                            ensure_connected(&mut client, &evt_tx).await;
                            if let Some(c) = client.as_mut() {
                                match c.get_status().await {
                                    Ok((running, tracked, uptime)) => {
                                        let _ = evt_tx.send(UiEvent::Status { running, tracked, uptime });
                                    }
                                    Err(e) => {
                                        let _ = evt_tx.send(UiEvent::Disconnected(
                                            format!("lost connection to daemon: {e}"),
                                        ));
                                        client = None;
                                    }
                                }
                            }
                        }
                        cmd = cmd_rx.recv() => {
                            let Some(cmd) = cmd else { return }; // UI gone
                            ensure_connected(&mut client, &evt_tx).await;
                            match client.as_mut() {
                                Some(c) => handle_command(c, cmd, &evt_tx).await,
                                None => {
                                    let _ = evt_tx.send(UiEvent::Toast(
                                        "Daemon not running — start it first".into(),
                                    ));
                                }
                            }
                        }
                    }
                }
            });
        })
        .expect("failed to spawn IPC worker thread");
}

/// Connect + handshake if not already connected. On failure, emits a
/// `Disconnected` event and leaves `client` as `None`.
async fn ensure_connected(client: &mut Option<AsyncIpcClient>, evt_tx: &glib::Sender<UiEvent>) {
    if client.is_some() {
        return;
    }
    match AsyncIpcClient::connect(socket_path()).await {
        Ok(mut c) => {
            // Handshake is best-effort; status still works without it.
            let _ = c.handshake(env!("CARGO_PKG_VERSION")).await;
            *client = Some(c);
        }
        Err(e) => {
            let _ = evt_tx.send(UiEvent::Disconnected(format!("daemon not reachable: {e}")));
        }
    }
}

async fn handle_command(client: &mut AsyncIpcClient, cmd: Command, evt_tx: &glib::Sender<UiEvent>) {
    match cmd {
        Command::Track(path) => {
            let name = base_name(&path);
            match client.start_witnessing(path).await {
                Ok(()) => send_toast(evt_tx, format!("Now witnessing {name}")),
                Err(e) => send_toast(evt_tx, format!("Couldn’t track {name}: {e}")),
            }
        }
        Command::Untrack(path) => {
            let name = base_name(&path);
            match client.stop_witnessing(Some(path)).await {
                Ok(()) => send_toast(evt_tx, format!("Stopped witnessing {name}")),
                Err(e) => send_toast(evt_tx, format!("Couldn’t untrack {name}: {e}")),
            }
        }
        Command::Export { path, tier } => {
            let name = base_name(&path);
            let output = path.with_extension("evidence.json");
            let resp = client
                .request(&IpcMessage::ExportFile {
                    path,
                    tier,
                    output: output.clone(),
                })
                .await;
            match resp {
                Ok(IpcMessage::ExportFileResponse { success: true, .. }) => {
                    send_toast(evt_tx, format!("Exported evidence → {}", output.display()))
                }
                Ok(IpcMessage::ExportFileResponse {
                    error: Some(err), ..
                }) => send_toast(evt_tx, format!("Export of {name} failed: {err}")),
                Ok(other) => send_toast(evt_tx, format!("Unexpected export response: {other:?}")),
                Err(e) => send_toast(evt_tx, format!("Export of {name} failed: {e}")),
            }
        }
        Command::Verify(path) => {
            let name = base_name(&path);
            let resp = client.request(&IpcMessage::VerifyFile { path }).await;
            match resp {
                Ok(IpcMessage::VerifyFileResponse {
                    success: true,
                    checkpoint_count,
                    signature_valid,
                    chain_integrity,
                    ..
                }) => send_toast(
                    evt_tx,
                    format!(
                        "{name}: {checkpoint_count} checkpoints · signature {} · chain {}",
                        ok_word(signature_valid),
                        ok_word(chain_integrity)
                    ),
                ),
                Ok(IpcMessage::VerifyFileResponse {
                    error: Some(err), ..
                }) => send_toast(evt_tx, format!("Verify of {name} failed: {err}")),
                Ok(IpcMessage::VerifyFileResponse { success: false, .. }) => {
                    send_toast(evt_tx, format!("{name}: verification FAILED"))
                }
                Ok(other) => send_toast(evt_tx, format!("Unexpected verify response: {other:?}")),
                Err(e) => send_toast(evt_tx, format!("Verify of {name} failed: {e}")),
            }
        }
    }
}

fn send_toast(evt_tx: &glib::Sender<UiEvent>, msg: String) {
    let _ = evt_tx.send(UiEvent::Toast(msg));
}

fn ok_word(b: bool) -> &'static str {
    if b {
        "valid"
    } else {
        "INVALID"
    }
}

/// File name for display, falling back to the full path.
pub fn base_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
