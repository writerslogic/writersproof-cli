// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Unix domain socket IPC with peer credential verification

use nix::sys::socket::getsockopt;
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("unauthorized peer: expected uid {expected_uid}, got {actual_uid}")]
    UnauthorizedPeer { expected_uid: u32, actual_uid: u32 },
    #[error("invalid peer executable")]
    InvalidPeerExecutable,
    #[error("unauthorized executable: expected one of {expected:?}, got {actual}")]
    UnauthorizedExecutable {
        expected: Vec<String>,
        actual: String,
    },
}

#[derive(Debug)]
pub struct PeerCreds {
    pub uid: u32,
    pub pid: i32,
}

#[cfg(target_os = "linux")]
fn get_peer_creds(stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    use nix::sys::socket::sockopt::PeerCredentials;
    let creds = getsockopt(&stream.as_fd(), PeerCredentials)?;
    Ok(PeerCreds {
        uid: creds.uid(),
        pid: creds.pid(),
    })
}

#[cfg(target_os = "macos")]
fn get_peer_creds(stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    use nix::sys::socket::sockopt::{LocalPeerCred, LocalPeerPid};
    let creds = getsockopt(&stream.as_fd(), LocalPeerCred)?;
    let pid = getsockopt(&stream.as_fd(), LocalPeerPid).unwrap_or_else(|e| {
        log::warn!("Failed to get peer PID: {:?}", e);
        0
    });
    if pid == 0 {
        log::warn!("Could not determine peer PID, proceeding with caution");
    }
    Ok(PeerCreds {
        uid: creds.uid(),
        pid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_peer_creds(_stream: &UnixStream) -> Result<PeerCreds, IpcError> {
    let uid = nix::unistd::getuid().as_raw();
    Ok(PeerCreds { uid, pid: 0 })
}

#[derive(Debug)]
pub struct SecureUnixSocket {
    listener: UnixListener,
    allowed_uid: u32,
}

impl SecureUnixSocket {
    pub fn bind(path: &Path) -> Result<Self, IpcError> {
        // Try bind first; only remove-and-retry on EADDRINUSE to avoid a
        // TOCTOU race between exists() and remove_file().
        let listener = match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // Verify it's actually a socket before removing (symlink guard).
                match std::fs::symlink_metadata(path) {
                    Ok(meta) if meta.file_type().is_socket() => {}
                    Ok(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            format!(
                                "IPC path {} is not a socket; refusing to remove",
                                path.display()
                            ),
                        )
                        .into())
                    }
                    Err(e) => return Err(e.into()),
                }
                std::fs::remove_file(path)?;
                UnixListener::bind(path)?
            }
            Err(e) => return Err(e.into()),
        };

        crate::crypto::restrict_permissions(path, 0o600)?;

        let allowed_uid = nix::unistd::getuid().as_raw();

        Ok(Self {
            listener,
            allowed_uid,
        })
    }

    pub fn accept(&self) -> Result<VerifiedConnection, IpcError> {
        let (stream, _addr) = self.listener.accept()?;

        let creds = get_peer_creds(&stream)?;

        if creds.uid != self.allowed_uid {
            return Err(IpcError::UnauthorizedPeer {
                expected_uid: self.allowed_uid,
                actual_uid: creds.uid,
            });
        }

        Ok(VerifiedConnection {
            stream,
            peer_pid: creds.pid,
            peer_uid: creds.uid,
        })
    }
}

#[derive(Debug)]
pub struct VerifiedConnection {
    pub stream: UnixStream,
    pub peer_pid: i32,
    pub peer_uid: u32,
}

impl VerifiedConnection {
    /// Verify that the connected peer is an expected executable.
    ///
    /// Delegates to [`verify_peer_executable`] with the connection's PID.
    pub fn verify_peer_executable(&self, allowed_names: &[&str]) -> Result<(), IpcError> {
        verify_peer_executable(self.peer_pid, allowed_names)
    }
}

/// Verify that a peer process identified by `peer_pid` is an expected executable.
///
/// On Linux this resolves `/proc/<pid>/exe` and checks against `allowed_names`.
/// On macOS, executable path resolution requires `proc_pidpath` via unsafe FFI
/// which is not yet available; only basic PID validation is performed.
pub fn verify_peer_executable(peer_pid: i32, allowed_names: &[&str]) -> Result<(), IpcError> {
    #[cfg(target_os = "linux")]
    {
        let exe_path = format!("/proc/{}/exe", peer_pid);
        let exe = std::fs::read_link(&exe_path)?;

        let exe_name = exe
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(IpcError::InvalidPeerExecutable)?;

        let exe_path_str = exe.to_string_lossy();

        if !allowed_names.contains(&exe_name)
            && !allowed_names.iter().any(|n| exe_path_str.ends_with(n))
        {
            return Err(IpcError::UnauthorizedExecutable {
                expected: allowed_names.iter().map(|s| s.to_string()).collect(),
                actual: exe_path_str.into_owned(),
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        if peer_pid <= 0 {
            log::warn!(
                "Invalid peer PID: {}, skipping executable verification",
                peer_pid
            );
            return Err(IpcError::InvalidPeerExecutable);
        }
        if peer_pid == 1 {
            log::warn!("Peer PID is 1 (launchd), rejecting as likely invalid client");
            return Err(IpcError::InvalidPeerExecutable);
        }
        if !allowed_names.is_empty() {
            log::warn!(
                "macOS peer verification: allowed_names {:?} ignored; \
                 executable path resolution not yet available",
                allowed_names
            );
        }
        log::debug!(
            "macOS peer verification: PID {} accepted (UID check only, no path check)",
            peer_pid
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (peer_pid, allowed_names);
    }

    Ok(())
}
