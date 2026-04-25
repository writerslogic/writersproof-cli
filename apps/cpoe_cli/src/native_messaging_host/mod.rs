// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for CPoE Browser Extension
//!
//! Implements the Chrome/Firefox Native Messaging protocol:
//! - Reads 4-byte LE length-prefixed JSON from stdin
//! - Writes 4-byte LE length-prefixed JSON to stdout
//! - Translates browser extension messages to cpoe_engine FFI calls
//!
//! Install manifests are in `../../apps/cpoe_browser_extension/native-manifests/`.

mod handlers;
mod jitter;
mod protocol;
mod tests;
pub(crate) mod types;

use handlers::{
    handle_ai_content_copied, handle_checkpoint, handle_get_status, handle_inject_jitter,
    handle_open_view, handle_snapshot_save, handle_start_session, handle_stop_session,
    handle_text_attestation,
};
use protocol::{read_message, request_type_name, write_message, PROTOCOL_VERSION};
use types::{Request, Response};

use std::sync::Mutex;
static SECURE_SESSION: Mutex<Option<cpoe::ipc::crypto::SecureSession>> = Mutex::new(None);

fn main() {
    eprintln!(
        "writerslogic-native-messaging-host v{}",
        env!("CARGO_PKG_VERSION")
    );

    let init_result = cpoe::ffi::ffi_init();
    if !init_result.success {
        eprintln!(
            "Warning: cpoe init failed: {}",
            init_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    loop {
        let request = match read_message() {
            Ok(Some(req)) => req,
            Ok(None) => {
                eprintln!("Connection closed (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                let _ = write_message(&Response::Error {
                    message: format!("Invalid message: {e}"),
                    code: "PARSE_ERROR".into(),
                });
                // Stream may be desynchronized after a framing error — terminate
                // to prevent parsing garbage as the next length prefix.
                break;
            }
        };

        eprintln!("Received: {}", request_type_name(&request));

        let response = match request {
            Request::Hello { client_pubkey, .. } => handle_hello(&client_pubkey),
            Request::KeyConfirm { token } => handle_key_confirm(&token),
            Request::Encrypted { payload } => match decrypt_and_dispatch(&payload) {
                Ok(resp) => encrypt_response(&resp).unwrap_or(resp),
                Err(e) => {
                    let err = Response::Error {
                        message: format!("Decryption failed: {e}"),
                        code: "DECRYPT_ERROR".into(),
                    };
                    encrypt_response(&err).unwrap_or(err)
                }
            },
            Request::StartSession {
                document_url,
                document_title,
                protocol_version,
            } => {
                if let Some(v) = protocol_version {
                    if v != PROTOCOL_VERSION {
                        eprintln!(
                            "protocol_version mismatch: client={v} server={PROTOCOL_VERSION}"
                        ); // intentional
                    }
                }
                handle_start_session(document_url, document_title)
            }
            Request::Checkpoint {
                content_hash,
                char_count,
                delta,
                commitment,
                ordinal,
                tool_category,
                tool_host,
            } => handle_checkpoint(content_hash, char_count, delta, commitment, ordinal, tool_category, tool_host),
            Request::StopSession => handle_stop_session(),
            Request::GetStatus => handle_get_status(),
            Request::InjectJitter { intervals } => handle_inject_jitter(intervals),
            Request::SnapshotSave {
                document_url,
                content_hash,
                char_count,
            } => handle_snapshot_save(document_url, content_hash, char_count),
            Request::AiContentCopied {
                source,
                char_count,
                timestamp,
            } => handle_ai_content_copied(source, char_count, timestamp),
            Request::OpenView { view } => handle_open_view(view),
            Request::TextAttestation {
                content_hash,
                tier,
                writersproof_id,
                attested_at,
                app_bundle_id,
            } => handle_text_attestation(content_hash, tier, writersproof_id, attested_at, app_bundle_id),
            Request::Ping { protocol_version } => {
                if let Some(v) = protocol_version {
                    if v != PROTOCOL_VERSION {
                        eprintln!(
                            "protocol_version mismatch: client={v} server={PROTOCOL_VERSION}"
                        ); // intentional
                    }
                }
                Response::Pong {
                    version: env!("CARGO_PKG_VERSION").into(),
                }
            }
        };

        if let Err(e) = write_message(&response) {
            eprintln!("Write error: {e}");
            break;
        }
    }
}

fn handle_hello(client_pubkey_b64: &str) -> Response {
    use base64::Engine;
    use cpoe::ipc::crypto::{SecureSession, KEY_CONFIRM_PLAINTEXT, P256_PUBLIC_KEY_SIZE};
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};

    let client_pubkey_bytes =
        match base64::engine::general_purpose::STANDARD.decode(client_pubkey_b64) {
            Ok(b) if b.len() == P256_PUBLIC_KEY_SIZE => b,
            _ => {
                return Response::Error {
                    message: "Invalid client public key".into(),
                    code: "HANDSHAKE_ERROR".into(),
                }
            }
        };

    let client_pubkey = match PublicKey::from_sec1_bytes(&client_pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return Response::Error {
                message: "Invalid P-256 public key".into(),
                code: "HANDSHAKE_ERROR".into(),
            }
        }
    };

    let server_secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let server_pubkey_point = server_secret.public_key().to_encoded_point(false);
    let server_pubkey_bytes = server_pubkey_point.as_bytes();

    let shared_secret = server_secret.diffie_hellman(&client_pubkey);

    let session = match SecureSession::from_shared_secret(
        shared_secret.raw_secret_bytes().as_slice(),
        &client_pubkey_bytes,
        server_pubkey_bytes,
        true,
    ) {
        Ok(s) => s,
        Err(e) => {
            return Response::Error {
                message: format!("Key derivation failed: {e}"),
                code: "HANDSHAKE_ERROR".into(),
            }
        }
    };

    let confirm = match session.encrypt(KEY_CONFIRM_PLAINTEXT) {
        Ok(c) => c,
        Err(e) => {
            return Response::Error {
                message: format!("Key confirm encrypt failed: {e}"),
                code: "HANDSHAKE_ERROR".into(),
            }
        }
    };

    let server_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(server_pubkey_bytes);
    let confirm_b64 = base64::engine::general_purpose::STANDARD.encode(&confirm);

    *SECURE_SESSION.lock().unwrap_or_else(|p| p.into_inner()) = Some(session);

    Response::HelloAccept {
        server_pubkey: server_pubkey_b64,
        confirm: confirm_b64,
    }
}

fn handle_key_confirm(token_b64: &str) -> Response {
    use base64::Engine;
    use cpoe::ipc::crypto::KEY_CONFIRM_PLAINTEXT;

    let token_bytes = match base64::engine::general_purpose::STANDARD.decode(token_b64) {
        Ok(b) => b,
        Err(_) => {
            return Response::Error {
                message: "Invalid key confirm token".into(),
                code: "HANDSHAKE_ERROR".into(),
            }
        }
    };

    let guard = SECURE_SESSION.lock().unwrap_or_else(|p| p.into_inner());
    let session = match guard.as_ref() {
        Some(s) => s,
        None => {
            return Response::Error {
                message: "No handshake in progress".into(),
                code: "HANDSHAKE_ERROR".into(),
            }
        }
    };

    match session.decrypt(&token_bytes) {
        Ok(plaintext) if plaintext == KEY_CONFIRM_PLAINTEXT => Response::KeyConfirmed {},
        _ => Response::Error {
            message: "Key confirmation failed".into(),
            code: "HANDSHAKE_ERROR".into(),
        },
    }
}

fn decrypt_and_dispatch(payload_b64: &str) -> anyhow::Result<Response> {
    use base64::Engine;

    let ciphertext = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
    let plaintext = {
        let guard = SECURE_SESSION.lock().unwrap_or_else(|p| p.into_inner());
        let session = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No secure session"))?;
        session.decrypt(&ciphertext)?
    };
    let inner_request: Request = serde_json::from_slice(&plaintext)?;

    Ok(match inner_request {
        Request::StartSession {
            document_url,
            document_title,
            ..
        } => handle_start_session(document_url, document_title),
        Request::Checkpoint {
            content_hash,
            char_count,
            delta,
            commitment,
            ordinal,
            tool_category,
            tool_host,
        } => handle_checkpoint(content_hash, char_count, delta, commitment, ordinal, tool_category, tool_host),
        Request::StopSession => handle_stop_session(),
        Request::GetStatus => handle_get_status(),
        Request::InjectJitter { intervals } => handle_inject_jitter(intervals),
        Request::SnapshotSave {
            document_url,
            content_hash,
            char_count,
        } => handle_snapshot_save(document_url, content_hash, char_count),
        Request::AiContentCopied {
            source,
            char_count,
            timestamp,
        } => handle_ai_content_copied(source, char_count, timestamp),
        Request::OpenView { view } => handle_open_view(view),
        Request::TextAttestation {
            content_hash,
            tier,
            writersproof_id,
            attested_at,
            app_bundle_id,
        } => handle_text_attestation(content_hash, tier, writersproof_id, attested_at, app_bundle_id),
        Request::Ping { .. } => Response::Pong {
            version: env!("CARGO_PKG_VERSION").into(),
        },
        _ => Response::Error {
            message: "Cannot nest handshake messages inside encrypted envelope".into(),
            code: "INVALID_REQUEST".into(),
        },
    })
}

fn encrypt_response(response: &Response) -> Option<Response> {
    use base64::Engine;

    let guard = SECURE_SESSION.lock().unwrap_or_else(|p| p.into_inner());
    let session = guard.as_ref()?;
    let json = serde_json::to_vec(response).ok()?;
    let ciphertext = session.encrypt(&json).ok()?;
    Some(Response::Encrypted {
        payload: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    })
}
