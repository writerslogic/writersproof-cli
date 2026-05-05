// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Connection handling, message dispatch, and the generic connection handler loop.

use super::crypto::{
    decode_for_protocol, encode_for_protocol, encode_message_json, rate_limit_key,
    secure_handshake_server, send_encrypted, RateLimitConfig, RateLimiter, WireProtocol,
    SECURE_JSON_PROTOCOL_MAGIC,
};
use super::messages::{IpcErrorCode, IpcMessage, IpcMessageHandler, MAX_MESSAGE_SIZE};
use super::rbac::{check_authorization, required_role, IpcRole};
use super::server::len_to_u32;
use crate::store::access_log::{new_access_entry, AccessAction, AccessLog, AccessResult};
use crate::MutexRecover;
use std::sync::{Arc, Mutex};

/// Map an IPC message to an access action and resource string for audit logging.
fn ipc_access_info(msg: &IpcMessage) -> (AccessAction, String) {
    match msg {
        IpcMessage::GetStatus
        | IpcMessage::GetAttestationNonce
        | IpcMessage::Heartbeat
        | IpcMessage::Handshake { .. } => (AccessAction::Read, "status".to_string()),
        IpcMessage::StartWitnessing { file_path } => {
            (AccessAction::Write, file_path.display().to_string())
        }
        IpcMessage::StopWitnessing { file_path } => {
            let resource = file_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "all".to_string());
            (AccessAction::Write, resource)
        }
        IpcMessage::ExportWithNonce { file_path, .. }
        | IpcMessage::ExportFile {
            path: file_path, ..
        } => (AccessAction::Export, file_path.display().to_string()),
        IpcMessage::VerifyFile { path }
        | IpcMessage::VerifyWithNonce {
            evidence_path: path,
            ..
        } => (AccessAction::Verify, path.display().to_string()),
        _ => (AccessAction::Read, "ipc".to_string()),
    }
}

/// Record an access event to the audit log, if one is configured.
pub(super) fn record_access(
    access_log: Option<&Arc<Mutex<AccessLog>>>,
    msg: &IpcMessage,
    client_role: IpcRole,
    transport_label: &str,
    result: AccessResult,
) {
    if let Some(al) = access_log {
        let (action, resource) = ipc_access_info(msg);
        let mut entry = new_access_entry(
            format!("{:?}", client_role),
            action,
            resource,
            result,
            transport_label,
        );
        if let Err(e) = al.lock_recover().log_access(&mut entry) {
            log::warn!("IPC: access log write failed: {}", e);
        }
    }
}

/// Generic connection handler for both Unix and Windows streams.
/// Extracts the common message loop logic shared by both platform-specific handlers.
///
/// Plaintext fallback branches are kept for protocol version negotiation;
/// they will be removed when v2 is enforced.
///
/// **Known limitation:** The rate limiter is shared across all connections, keyed by
/// message type rather than by client identity. A single malicious local client can
/// exhaust the rate limit for a message type and deny service to other local clients.
/// This is acceptable for local-only IPC where all clients run under the same user,
/// but should be revisited if the IPC transport is ever exposed beyond localhost.
pub(super) async fn handle_connection_inner<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    stream: &mut S,
    handler: Arc<dyn IpcMessageHandler>,
    transport_label: &str,
    shared_rate_limiter: &Arc<Mutex<RateLimiter>>,
    client_role: IpcRole,
    access_log: Option<&Arc<Mutex<AccessLog>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut peek_buf = [0u8; 2];
    if stream.read_exact(&mut peek_buf).await.is_err() {
        return;
    }

    let protocol = if peek_buf == SECURE_JSON_PROTOCOL_MAGIC {
        WireProtocol::SecureJson
    } else {
        log::error!(
            "IPC: Rejected insecure connection attempt (magic: 0x{:02x}{:02x}) on {}. Only secure JSON protocol (WS) is allowed.",
            peek_buf[0],
            peek_buf[1],
            transport_label
        );
        return;
    };

    let secure_session = if protocol == WireProtocol::SecureJson {
        let mut version_buf = [0u8; 1];
        if stream.read_exact(&mut version_buf).await.is_err() {
            log::error!(
                "IPC: failed to read protocol version byte on {}",
                transport_label
            );
            return;
        }
        let version = version_buf[0];

        match secure_handshake_server(stream, version).await {
            Ok(session) => {
                log::info!(
                    "IPC: secure handshake v{} completed on {} (AES-256-GCM, channel-bound)",
                    version,
                    transport_label
                );
                Some(session)
            }
            Err(e) => {
                log::error!(
                    "IPC: secure handshake failed on {}: {} (rejecting)",
                    transport_label,
                    e
                );
                return;
            }
        }
    } else {
        None
    };

    let mut len_buf = [0u8; 4];
    /// Idle timeout for IPC connections: close after this many seconds of no messages.
    const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    loop {
        let msg_len = {
            match tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => {
                    log::debug!("IPC: header read failed on {}: {e}", transport_label);
                    break;
                }
                Err(_) => {
                    log::info!(
                        "IPC: idle timeout ({}s) on {}, closing connection",
                        IDLE_TIMEOUT.as_secs(),
                        transport_label
                    );
                    break;
                }
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_MESSAGE_SIZE {
                log::warn!(
                    "IPC: message too large: {} bytes on {} (dropping)",
                    len,
                    transport_label
                );
                break;
            }
            len
        };

        let mut msg_buf = vec![0u8; msg_len];
        if let Err(e) = stream.read_exact(&mut msg_buf).await {
            log::debug!("IPC: read_exact failed on {}: {e}", transport_label);
            break;
        }

        let plaintext = if let Some(ref session) = secure_session {
            match session.decrypt(&msg_buf) {
                Ok(pt) => pt,
                // Coupled to the anyhow!("SequenceDesync: ...") string in
                // SecureSession::decrypt (crypto.rs). Not a typed variant; update
                // both sites together if the prefix changes.
                Err(e) if e.to_string().starts_with("SequenceDesync:") => {
                    log::warn!(
                        "IPC: sequence desync on {}: {} (closing session)",
                        transport_label,
                        e
                    );
                    break;
                }
                Err(e) => {
                    log::error!(
                        "IPC: decrypt failed on {}: {} (closing, possible tampering)",
                        transport_label,
                        e
                    );
                    break;
                }
            }
        } else {
            msg_buf
        };

        // Decode (inner payload is always JSON for SecureJson mode)
        let decode_protocol = match protocol {
            WireProtocol::SecureJson => WireProtocol::Json,
            other => other,
        };

        match decode_for_protocol(&plaintext, decode_protocol) {
            Ok(msg) => {
                if let Err(e) = msg.validate_paths() {
                    log::warn!(
                        "IPC: path validation failed on {}: {} (rejecting)",
                        transport_label,
                        e
                    );
                    let error_response = IpcMessage::Error {
                        code: IpcErrorCode::PermissionDenied,
                        message: e,
                    };
                    // Best-effort error response; client may have disconnected
                    if let Ok(response_bytes) = encode_message_json(&error_response) {
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, &response_bytes).await;
                        } else if let Ok(len_bytes) = len_to_u32(response_bytes.len()) {
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(&response_bytes).await;
                        }
                    }
                    continue;
                }

                let key = rate_limit_key(&msg);
                let allowed = {
                    let mut guard = shared_rate_limiter.lock().unwrap_or_else(|p| {
                        log::warn!(
                            "IPC: rate limiter mutex poisoned on {}, recovering",
                            transport_label
                        );
                        p.into_inner()
                    });
                    guard.check(key)
                };
                if !allowed {
                    log::warn!(
                        "IPC: rate limit exceeded for '{:?}' on {} (limit: {}/60s)",
                        key,
                        transport_label,
                        RateLimitConfig::max_ops(key)
                    );
                    let error_response = IpcMessage::Error {
                        code: IpcErrorCode::RateLimited,
                        message: format!("Rate limit exceeded for operation: {:?}", key),
                    };
                    // Best-effort error response; client may have disconnected
                    if let Ok(response_bytes) = encode_message_json(&error_response) {
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, &response_bytes).await;
                        } else if let Ok(len_bytes) = len_to_u32(response_bytes.len()) {
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(&response_bytes).await;
                        }
                    }
                    continue;
                }

                let msg_required_role = required_role(&msg);
                if !check_authorization(client_role, msg_required_role) {
                    log::warn!(
                        "IPC: unauthorized {:?} for role {:?} on {} (requires {:?})",
                        msg,
                        client_role,
                        transport_label,
                        msg_required_role
                    );
                    record_access(
                        access_log,
                        &msg,
                        client_role,
                        transport_label,
                        AccessResult::Denied,
                    );
                    let error_response = IpcMessage::Error {
                        code: IpcErrorCode::PermissionDenied,
                        message: format!(
                            "Insufficient permissions: requires {:?}, client has {:?}",
                            msg_required_role, client_role
                        ),
                    };
                    if let Ok(response_bytes) = encode_message_json(&error_response) {
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, &response_bytes).await;
                        } else if let Ok(len_bytes) = len_to_u32(response_bytes.len()) {
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(&response_bytes).await;
                        }
                    }
                    continue;
                }

                // Audit log: record each authorized IPC request.
                record_access(
                    access_log,
                    &msg,
                    client_role,
                    transport_label,
                    AccessResult::Success,
                );

                let handler_ref = Arc::clone(&handler);
                let response = match tokio::task::spawn_blocking(move || -> IpcMessage {
                    handler_ref.handle(msg)
                })
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("IPC: handler panicked: {e}");
                        IpcMessage::Error {
                            code: IpcErrorCode::InternalError,
                            message: "Internal processing error".to_string(),
                        }
                    }
                };

                let encode_protocol = match protocol {
                    WireProtocol::SecureJson => WireProtocol::Json,
                    other => other,
                };
                match encode_for_protocol(&response, encode_protocol) {
                    Ok(response_bytes) => {
                        if let Some(ref session) = secure_session {
                            if send_encrypted(stream, session, &response_bytes)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            let len_bytes = match len_to_u32(response_bytes.len()) {
                                Ok(b) => b,
                                Err(e) => {
                                    log::error!("IPC: response too large: {}", e);
                                    break;
                                }
                            };
                            if stream.write_all(&len_bytes).await.is_err() {
                                break;
                            }
                            if stream.write_all(&response_bytes).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "IPC: failed to serialize response on {}: {}",
                            transport_label,
                            e
                        );
                        // Best-effort fallback error so client isn't left hanging
                        let fallback = br#"{"type":"Error","code":"InternalError","message":"Internal serialization error"}"#;
                        if let Some(ref session) = secure_session {
                            let _ = send_encrypted(stream, session, fallback).await;
                        } else if let Ok(len_bytes) = len_to_u32(fallback.len()) {
                            let _ = stream.write_all(&len_bytes).await;
                            let _ = stream.write_all(fallback.as_slice()).await;
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "IPC: failed to deserialize message on {}: {}",
                    transport_label,
                    e
                );
                let error_response = IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: "Invalid message format".to_string(),
                };
                // Best-effort error response; client may have disconnected
                if let Ok(response_bytes) = encode_for_protocol(&error_response, decode_protocol) {
                    if let Some(ref session) = secure_session {
                        let _ = send_encrypted(stream, session, &response_bytes).await;
                    } else if let Ok(len_bytes) = len_to_u32(response_bytes.len()) {
                        let _ = stream.write_all(&len_bytes).await;
                        let _ = stream.write_all(&response_bytes).await;
                    }
                }
            }
        }
    }
}
