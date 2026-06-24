// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows named pipe connection handling for IPC server.

#[cfg(target_os = "windows")]
use super::crypto::RateLimiter;
#[cfg(target_os = "windows")]
use super::messages::IpcMessageHandler;
#[cfg(target_os = "windows")]
use super::rbac::IpcRole;
#[cfg(target_os = "windows")]
use super::server_handler::handle_connection_inner;
#[cfg(target_os = "windows")]
use crate::store::access_log::AccessLog;
#[cfg(target_os = "windows")]
use anyhow::Result;
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;

/// Verify that a Windows named pipe client is running as the same user as the server.
/// Returns Ok(()) if the client's user SID matches, Err otherwise.
#[cfg(target_os = "windows")]
pub(super) fn verify_windows_pipe_peer(pipe: &named_pipe::NamedPipeServer) -> Result<()> {
    use anyhow::anyhow;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// RAII wrapper for Windows HANDLEs to prevent leaks on error paths.
    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: Handle was obtained from a Win32 API that returns valid
                // handles on success, and OwnedHandle is only constructed with such.
                unsafe {
                    // Intentionally ignored: CloseHandle in Drop; nothing to do on failure
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    // SAFETY: All HANDLE values are obtained from Win32 APIs that guarantee
    // valid handles on success. OwnedHandle ensures CloseHandle on all paths.
    // pipe_handle is a non-owning copy; the caller retains ownership.
    unsafe {
        let pipe_handle = HANDLE(pipe.as_raw_handle());
        let mut client_pid: u32 = 0;
        GetNamedPipeClientProcessId(pipe_handle, &mut client_pid)
            .map_err(|e| anyhow!("GetNamedPipeClientProcessId failed: {}", e))?;

        if client_pid == 0 {
            return Err(anyhow!(
                "IPC peer has PID 0 (System Idle Process); rejecting"
            ));
        }

        let mut server_token_raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut server_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (server) failed: {}", e))?;
        let server_token = OwnedHandle(server_token_raw);
        let server_sid = get_token_user_sid(server_token.0)?;

        let client_process_raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|e| anyhow!("OpenProcess (client PID {}) failed: {}", client_pid, e))?;
        let client_process = OwnedHandle(client_process_raw);

        let mut client_token_raw = HANDLE::default();
        OpenProcessToken(client_process.0, TOKEN_QUERY, &mut client_token_raw)
            .map_err(|e| anyhow!("OpenProcessToken (client) failed: {}", e))?;
        let client_token = OwnedHandle(client_token_raw);
        let client_sid = get_token_user_sid(client_token.0)?;

        if server_sid != client_sid {
            return Err(anyhow!(
                "IPC peer SID mismatch: client SID {} != server SID {}",
                client_sid,
                server_sid
            ));
        }

        Ok(())
    }
}

/// RAII wrapper for memory allocated by `LocalAlloc` (or Win32 APIs that
/// require `LocalFree`). Guarantees cleanup on all paths including panics.
#[cfg(target_os = "windows")]
struct LocalAllocGuard(windows::Win32::Foundation::HLOCAL);

#[cfg(target_os = "windows")]
impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        // SAFETY: The pointer was returned by a Win32 API that documents
        // LocalFree as the correct deallocation function.
        unsafe {
            windows::Win32::Foundation::LocalFree(Some(self.0));
        }
    }
}

/// Extract user SID string from a process token.
#[cfg(target_os = "windows")]
fn get_token_user_sid(token: windows::Win32::Foundation::HANDLE) -> Result<String> {
    use anyhow::anyhow;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    let mut size: u32 = 0;
    // SAFETY: First call with null buffer retrieves the required size.
    // GetTokenInformation is safe to call with None/0; it writes only to `size`.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
    }

    if size == 0 {
        return Err(anyhow!(
            "GetTokenInformation returned zero size; token may be invalid"
        ));
    }

    // `Vec<u64>` backing storage is 8-byte aligned by the allocator, which
    // satisfies TOKEN_USER's alignment requirement on both 32-bit and 64-bit
    // Windows (TOKEN_USER contains pointer-sized fields, max align = pointer
    // size ≤ 8). Vec's Drop frees memory automatically, including on panic.
    let num_u64s = (size as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buffer: Vec<u64> = vec![0; num_u64s];
    let buffer_ptr = buffer.as_mut_ptr() as *mut u8;

    // SAFETY: buffer_ptr points to `size` writable bytes with 8-byte alignment.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer_ptr as *mut _),
            size,
            &mut size,
        )
        .map_err(|e| anyhow!("GetTokenInformation failed: {}", e))?;
    }

    // SAFETY: buffer_ptr is 8-byte aligned (Vec<u64> guarantee) and was just
    // filled by GetTokenInformation(TokenUser) with a valid TOKEN_USER layout.
    // `buffer` is kept alive through the ConvertSidToStringSidW call below.
    let sid = unsafe {
        let token_user = &*(buffer_ptr as *const TOKEN_USER);
        token_user.User.Sid
    };

    let sid_string = unsafe {
        let mut raw_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut raw_ptr)
            .map_err(|e| anyhow!("ConvertSidToStringSid failed: {}", e))?;
        raw_ptr
    };

    // Ensure LocalFree runs even if to_string() panics on malformed UTF-16.
    let _sid_guard = LocalAllocGuard(windows::Win32::Foundation::HLOCAL(
        sid_string.as_ptr() as *mut _
    ));

    // SAFETY: raw_ptr was written by ConvertSidToStringSidW as a valid,
    // null-terminated wide string; it remains live until LocalFree, which
    // _sid_guard defers to the end of this scope.
    unsafe { sid_string.to_string() }.map_err(|e| anyhow!("SID string conversion failed: {}", e))
}

#[cfg(target_os = "windows")]
pub(super) async fn handle_windows_connection<H: IpcMessageHandler>(
    mut pipe: named_pipe::NamedPipeServer,
    handler: Arc<H>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    access_log: Option<Arc<Mutex<AccessLog>>>,
) {
    if let Err(e) = verify_windows_pipe_peer(&pipe) {
        log::error!(
            "IPC: peer SID verification failed: {} (rejecting connection)",
            e
        );
        return;
    }

    handle_connection_inner(
        &mut pipe,
        handler as Arc<dyn IpcMessageHandler>,
        "named-pipe",
        &rate_limiter,
        IpcRole::User, // Authenticated via SID verification; explicit User role
        access_log.as_ref(),
    )
    .await;
}
