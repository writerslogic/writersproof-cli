// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use cpoe::DaemonManager;
use std::fs;
use std::time::Duration;

use crate::util::ensure_dirs;

/// How long to wait for a backgrounded daemon to report ready before failing.
const DAEMON_START_TIMEOUT_MS: u64 = 4000;
/// Poll interval while waiting for the daemon to come up.
const DAEMON_POLL_MS: u64 = 100;

fn report_already_running(daemon_manager: &DaemonManager) {
    let status = daemon_manager.status();
    if let Some(pid) = status.pid {
        println!("Daemon is already running (PID: {}).", pid);
    } else {
        println!("Daemon is already running.");
    }
    println!();
    println!("Use 'cpoe status' for details or 'cpoe stop' to stop.");
}

pub(crate) async fn cmd_start(foreground: bool) -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(&config.data_dir);

    // The daemon *process* (setup_daemon) is the sole owner of the PID-file
    // flock. The CLI must NOT acquire that lock here: in foreground mode the
    // daemon runs in this same process, so a second acquisition deadlocks on
    // the flock and falsely reports "already running" against our own PID; in
    // background mode it would race the child. So we only do a liveness check
    // for reporting, and let the daemon acquire the lock itself.
    if daemon_manager.is_running() {
        report_already_running(&daemon_manager);
        return Ok(());
    }
    // Clear any stale PID/state left by a crashed daemon so the lock is free.
    daemon_manager.cleanup();

    if foreground {
        eprintln!("Starting CPoE daemon in foreground...");
        eprintln!("Press Ctrl+C to stop.");
        eprintln!();

        let result = cpoe::sentinel::daemon::cmd_start_foreground(&config.data_dir)
            .await
            .map_err(|e| anyhow!("Daemon error: {}", e));
        if result.is_err() {
            daemon_manager.cleanup();
        }
        return result;
    }

    // Background: spawn a detached `start --foreground`. The child acquires the
    // PID-file lock and writes its own PID via setup_daemon; we just wait for it
    // to come up (or fail fast).
    eprintln!("Starting CPoE daemon...");

    let exe = std::env::current_exe().context("cannot resolve executable path")?;

    let log_dir = config.data_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    if let Err(e) = cpoe::restrict_permissions(&log_dir, 0o700) {
        eprintln!("Warning: failed to set log directory permissions: {e}");
    }
    let log_path = log_dir.join("daemon.log");
    let log_file = fs::File::create(&log_path).context("cannot create daemon log")?;
    if let Err(e) = cpoe::restrict_permissions(&log_path, 0o600) {
        eprintln!("Warning: failed to set log file permissions: {e}");
    }
    let stderr_file = log_file.try_clone().context("log file clone")?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("start")
        .arg("--foreground")
        .stdout(log_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn daemon: {}", e))?;
    let pid = child.id();

    // Poll until the daemon reports ready (it writes its PID file early in
    // setup_daemon), bailing out immediately if the child exits first.
    let mut ready = false;
    for _ in 0..(DAEMON_START_TIMEOUT_MS / DAEMON_POLL_MS) {
        tokio::time::sleep(Duration::from_millis(DAEMON_POLL_MS)).await;
        if let Ok(Some(status)) = child.try_wait() {
            let log_hint = format!("Check log file: {}", log_path.display());
            return Err(anyhow::anyhow!(
                "Daemon failed to start (exit code {:?}). {log_hint}",
                status.code()
            ));
        }
        if daemon_manager.is_running() {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err(anyhow::anyhow!(
            "Daemon {} did not report ready in {}ms. Check log: {}",
            pid,
            DAEMON_START_TIMEOUT_MS,
            log_path.display()
        ));
    }

    eprintln!("Daemon started (PID: {})", pid);
    eprintln!("Log file: {}", log_path.display());
    eprintln!();
    eprintln!("Use 'cpoe status' for details or 'cpoe stop' to stop.");

    Ok(())
}

pub(crate) fn cmd_stop() -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(&config.data_dir);
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            // Negative/zero PID would signal all processes in a group — reject it
            if pid <= 0 {
                return Err(anyhow!("Invalid PID {} in PID file.", pid));
            }

            println!("Stopping daemon (PID: {})...", pid);

            #[cfg(unix)]
            {
                // H-012: Verify process name matches before sending SIGTERM to avoid
                // killing an unrelated process that reused the PID after daemon exit.
                let expected = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
                let actual = std::process::Command::new("ps")
                    .args(["-p", &pid.to_string(), "-o", "comm="])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                if let Some(ref exp) = expected {
                    if !actual.is_empty()
                        && !actual.contains(exp.as_str())
                        && !exp.contains(actual.as_str())
                    {
                        return Err(anyhow!(
                            "PID {} belongs to '{}', not the daemon; refusing to send SIGTERM.",
                            pid,
                            actual
                        ));
                    }
                }

                match std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()
                {
                    Ok(s) if !s.success() => {
                        eprintln!("Warning: kill -TERM failed with exit code {:?}", s.code());
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to send SIGTERM: {e}");
                    }
                    _ => {}
                }
            }

            #[cfg(windows)]
            {
                match std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status()
                {
                    Ok(s) if !s.success() => {
                        eprintln!("Warning: taskkill failed with exit code {:?}", s.code());
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to run taskkill: {e}");
                    }
                    _ => {}
                }
            }

            std::thread::sleep(Duration::from_millis(500));
            let new_status = daemon_manager.status();
            if !new_status.running {
                daemon_manager.cleanup();
                println!("Daemon stopped.");
            } else {
                println!("Daemon may still be stopping...");
            }
        } else {
            println!("Daemon appears to be running but PID unknown.");
        }
    } else {
        // Clean up any stale PID/state files left behind by a crashed daemon.
        daemon_manager.cleanup();
        println!("Daemon is not running.");
    }

    Ok(())
}
