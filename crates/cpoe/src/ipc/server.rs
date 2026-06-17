// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IPC server: struct, bind, and run methods.

use super::crypto::RateLimiter;
use super::messages::{IpcMessageHandler, MAX_CONCURRENT_CONNECTIONS};
use super::rbac::IpcRole;
use super::server_handler::handle_connection_inner;
use crate::store::access_log::AccessLog;
use anyhow::{anyhow, Result};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Convert a length to a u32 for the wire protocol, returning an error if it overflows.
pub(super) fn len_to_u32(len: usize) -> Result<[u8; 4]> {
    Ok(u32::try_from(len)
        .map_err(|_| anyhow!("Response too large"))?
        .to_le_bytes())
}

/// Executables allowed to connect over the IPC socket.
#[cfg(unix)]
const ALLOWED_PEER_EXECUTABLES: &[&str] = &[
    "cpoe",              // CLI binary
    "cpoe_cli",          // CLI binary (alt name)
    "WritersLogic",      // macOS GUI app
    "writerslogic",      // Linux GUI
];

/// Platform-aware IPC server (Unix socket or Windows named pipe).
pub struct IpcServer {
    #[cfg(not(target_os = "windows"))]
    listener: UnixListener,
    #[cfg(target_os = "windows")]
    pipe_name: String,
    socket_path: PathBuf,
    access_log: Option<Arc<Mutex<AccessLog>>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl IpcServer {
    /// Bind to a Unix domain socket at the given path (mode 0600).
    ///
    /// Attempts bind first to avoid a TOCTOU race between remove_file and bind.
    /// On EADDRINUSE, checks whether the socket is live (another server) or stale,
    /// then retries once after removing the stale socket.
    #[cfg(not(target_os = "windows"))]
    pub fn bind(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            crate::crypto::restrict_permissions(parent, 0o700)?;
        }

        // Set umask to 0o177 so the socket is created with 0o600 atomically,
        // eliminating the TOCTOU window between bind and chmod.
        let old_umask = unsafe { libc::umask(0o177) };
        let bind_result = UnixListener::bind(&path);
        unsafe { libc::umask(old_umask) };

        match bind_result {
            Ok(listener) => {
                return Ok(Self {
                    listener,
                    socket_path: path,
                    access_log: None,
                    rate_limiter: Arc::new(Mutex::new(RateLimiter::new(60))),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // Socket file exists; check if another server is actively listening.
                if let Ok(stream) = std::os::unix::net::UnixStream::connect(&path) {
                    drop(stream); // explicitly close the probe connection
                    return Err(anyhow!(
                        "Another IPC server is already listening on {}",
                        path.display()
                    ));
                }
                // Verify it's actually a socket before removing (symlink guard).
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_socket() => {}
                    Ok(_) => {
                        return Err(anyhow!(
                            "IPC path {} is not a socket; refusing to remove",
                            path.display()
                        ))
                    }
                    Err(e) => return Err(e.into()),
                }
                // Second liveness check immediately before removal to narrow the TOCTOU
                // window: a server that started between our first connect() and here
                // would succeed now.
                if let Ok(stream) = std::os::unix::net::UnixStream::connect(&path) {
                    drop(stream);
                    return Err(anyhow!(
                        "Another IPC server is already listening on {}",
                        path.display()
                    ));
                }
                // Stale socket; remove and retry.
                std::fs::remove_file(&path)?;
            }
            Err(e) => return Err(e.into()),
        }

        let old_umask2 = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(&path)?;
        unsafe { libc::umask(old_umask2) };
        Ok(Self {
            listener,
            socket_path: path,
            access_log: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(60))),
        })
    }

    /// Bind to a Windows named pipe derived from the given path.
    #[cfg(target_os = "windows")]
    pub fn bind(path: PathBuf) -> Result<Self> {
        let pipe_name = format!(
            r"\\.\pipe\writerslogic-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "sentinel".to_string())
        );
        Ok(Self {
            pipe_name,
            socket_path: path,
            access_log: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(60))),
        })
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Attach an access log for administrative audit logging of IPC requests.
    pub fn set_access_log(&mut self, log: AccessLog) {
        self.access_log = Some(Arc::new(Mutex::new(log)));
    }

    /// Run the IPC server with a message handler
    pub async fn run_with_handler<H: IpcMessageHandler>(self, handler: Arc<H>) -> Result<()> {
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let active_connections = Arc::new(AtomicUsize::new(0));
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                let stream = match self.listener.accept().await {
                    Ok((s, _)) => s,
                    Err(e) => {
                        log::error!("IPC: accept error in run_with_handler: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acquired =
                    active_connections.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                        if n < MAX_CONCURRENT_CONNECTIONS {
                            Some(n + 1)
                        } else {
                            None
                        }
                    });
                if acquired.is_err() {
                    let cur = active_connections.load(Ordering::Relaxed);
                    log::warn!(
                        "IPC: rejecting connection ({cur}/{MAX_CONCURRENT_CONNECTIONS} active)",
                    );
                    drop(stream);
                    continue;
                }
                let handler_clone = Arc::clone(&handler);
                let rl = Arc::clone(&rate_limiter);
                let conn_count = Arc::clone(&active_connections);
                let al = self.access_log.clone();
                tokio::spawn(async move {
                    handle_connection(stream, handler_clone, rl, al).await;
                    conn_count.fetch_sub(1, Ordering::AcqRel);
                });
            }
        }
        #[cfg(target_os = "windows")]
        {
            let mut is_first = true;
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(is_first)
                    .create(&self.pipe_name)?;
                is_first = false;

                if let Err(e) = server.connect().await {
                    log::error!("IPC: Windows named pipe connect error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                let acquired =
                    active_connections.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                        if n < MAX_CONCURRENT_CONNECTIONS {
                            Some(n + 1)
                        } else {
                            None
                        }
                    });
                if acquired.is_err() {
                    let cur = active_connections.load(Ordering::Relaxed);
                    log::warn!(
                        "IPC: rejecting connection ({cur}/{MAX_CONCURRENT_CONNECTIONS} active)",
                    );
                    drop(server);
                    continue;
                }
                let handler_clone = Arc::clone(&handler);
                let rl = Arc::clone(&rate_limiter);
                let conn_count = Arc::clone(&active_connections);
                let al = self.access_log.clone();
                tokio::spawn(async move {
                    super::server_windows::handle_windows_connection(server, handler_clone, rl, al)
                        .await;
                    conn_count.fetch_sub(1, Ordering::AcqRel);
                });
            }
        }
    }

    /// Maximum time to wait for in-flight connections to finish during shutdown.
    const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Run the IPC server with a message handler, with shutdown signal.
    ///
    /// On shutdown, stops accepting new connections, then waits up to
    /// [`SHUTDOWN_DRAIN_TIMEOUT`](Self::SHUTDOWN_DRAIN_TIMEOUT) for in-flight
    /// handlers to complete before returning.
    pub async fn run_with_shutdown<H: IpcMessageHandler>(
        self,
        handler: Arc<H>,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<()> {
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let active_connections = Arc::new(AtomicUsize::new(0));
        let mut pending = tokio::task::JoinSet::new();
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                tokio::select! {
                    result = self.listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let acquired = active_connections.fetch_update(
                                    Ordering::AcqRel, Ordering::Relaxed, |n| {
                                        if n < MAX_CONCURRENT_CONNECTIONS { Some(n + 1) } else { None }
                                    });
                                if acquired.is_err() {
                                    let cur = active_connections.load(Ordering::Relaxed);
                                    log::warn!("IPC: rejecting connection ({cur}/{MAX_CONCURRENT_CONNECTIONS} active)");
                                    drop(stream);
                                    continue;
                                }
                                let handler_clone = Arc::clone(&handler);
                                let rl = Arc::clone(&rate_limiter);
                                let conn_count = Arc::clone(&active_connections);
                                let al = self.access_log.clone();
                                pending.spawn(async move {
                                    handle_connection(stream, handler_clone, rl, al).await;
                                    conn_count.fetch_sub(1, Ordering::AcqRel);
                                });
                            }
                            Err(e) => {
                                log::error!("IPC: accept error: {}", e);
                                // Backoff to prevent tight error loop (e.g. fd exhaustion)
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        if let Err(e) = std::fs::remove_file(&self.socket_path) {
                            log::debug!("socket cleanup on shutdown: {e}");
                        }
                        break;
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let mut is_first = true;
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(is_first)
                    .create(&self.pipe_name)?;
                is_first = false;

                tokio::select! {
                    result = server.connect() => {
                        if result.is_ok() {
                            let acquired = active_connections.fetch_update(
                                Ordering::AcqRel, Ordering::Relaxed, |n| {
                                    if n < MAX_CONCURRENT_CONNECTIONS { Some(n + 1) } else { None }
                                });
                            if acquired.is_err() {
                                let cur = active_connections.load(Ordering::Relaxed);
                                log::warn!("IPC: rejecting connection ({cur}/{MAX_CONCURRENT_CONNECTIONS} active)");
                                continue;
                            }
                            let handler_clone = Arc::clone(&handler);
                            let rl = Arc::clone(&rate_limiter);
                            let conn_count = Arc::clone(&active_connections);
                            let al = self.access_log.clone();
                            pending.spawn(async move {
                                super::server_windows::handle_windows_connection(server, handler_clone, rl, al).await;
                                conn_count.fetch_sub(1, Ordering::AcqRel);
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        }

        // Drain in-flight connection handlers with a bounded timeout.
        if !pending.is_empty() {
            let n = pending.len();
            log::info!("IPC: shutdown draining {n} in-flight connection(s)");
            let drain = async {
                while pending.join_next().await.is_some() {}
            };
            if tokio::time::timeout(Self::SHUTDOWN_DRAIN_TIMEOUT, drain)
                .await
                .is_err()
            {
                let remaining = pending.len();
                log::warn!(
                    "IPC: shutdown drain timed out after {:?} with {remaining} connection(s) still active",
                    Self::SHUTDOWN_DRAIN_TIMEOUT
                );
                pending.abort_all();
            }
        }
        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        #[cfg(not(target_os = "windows"))]
        {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                log::debug!("socket cleanup on drop: {e}");
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
async fn handle_connection<H: IpcMessageHandler>(
    mut stream: UnixStream,
    handler: Arc<H>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    access_log: Option<Arc<Mutex<AccessLog>>>,
) {
    // H-012: reject connections from different UIDs on Unix sockets.
    let peer_pid = match stream.peer_cred() {
        Ok(cred) => {
            // SAFETY: getuid() is a no-arg POSIX syscall with no preconditions.
            let my_uid = unsafe { libc::getuid() };
            let peer_uid = cred.uid();
            if peer_uid != my_uid {
                log::error!(
                    "IPC: rejecting unix-socket connection from UID {} (server UID {})",
                    peer_uid,
                    my_uid
                );
                return;
            }
            cred.pid()
        }
        Err(e) => {
            log::error!(
                "IPC: failed to get peer credentials on unix-socket: {} (rejecting)",
                e
            );
            return;
        }
    };

    // Verify the peer executable (Linux: /proc path check, macOS: PID validation).
    if let Some(pid) = peer_pid {
        if let Err(e) = super::unix_socket::verify_peer_executable(pid, ALLOWED_PEER_EXECUTABLES)
        {
            log::error!("IPC: peer executable verification failed: {e}");
            return;
        }
    }

    handle_connection_inner(
        &mut stream,
        handler as Arc<dyn IpcMessageHandler>,
        "unix-socket",
        &rate_limiter,
        IpcRole::User, // Authenticated via peer credentials; explicit User role
        access_log.as_ref(),
    )
    .await;
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer").finish_non_exhaustive()
    }
}
