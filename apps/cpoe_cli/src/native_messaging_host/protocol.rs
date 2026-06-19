// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io::{self, Read, Write};

use super::types::{Request, Response};

/// Maximum allowed message length (1 MiB).
pub(crate) const MAX_MESSAGE_LENGTH: usize = 1_048_576;

pub(crate) const PROTOCOL_VERSION: u32 = 1;


/// Return request type name without PII (document URLs/titles).
pub(crate) fn request_type_name(req: &Request) -> &'static str {
    match req {
        Request::Hello { .. } => "Hello",
        Request::KeyConfirm { .. } => "KeyConfirm",
        Request::Encrypted { .. } => "Encrypted",
        Request::StartSession { .. } => "StartSession",
        Request::Checkpoint { .. } => "Checkpoint",
        Request::StopSession => "StopSession",
        Request::GetStatus => "GetStatus",
        Request::InjectJitter { .. } => "InjectJitter",
        Request::Ping { .. } => "Ping",
        Request::SnapshotSave { .. } => "SnapshotSave",
        Request::AiContentCopied { .. } => "AiContentCopied",
        Request::OpenView { .. } => "OpenView",
        Request::TextAttestation { .. } => "TextAttestation",
        Request::ResumeSession { .. } => "ResumeSession",
        Request::BrowserKeystrokeBatch { .. } => "BrowserKeystrokeBatch",
        Request::SignVcClaim { .. } => "SignVcClaim",
    }
}

/// Read a length-prefixed NMH message from a generic reader.
pub(crate) fn read_message_from<R: Read>(reader: &mut R) -> io::Result<Option<Request>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid message length: {len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub(crate) fn read_message() -> io::Result<Option<Request>> {
    read_message_from(&mut io::stdin().lock())
}

/// Write a length-prefixed NMH response to a generic writer.
pub(crate) fn write_message_to<W: Write>(writer: &mut W, response: &Response) -> io::Result<()> {
    let mut map = serde_json::to_value(response)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(obj) = map.as_object_mut() {
        obj.insert(
            "protocol_version".to_string(),
            serde_json::json!(PROTOCOL_VERSION),
        );
    }
    let json =
        serde_json::to_vec(&map).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if json.len() > MAX_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Response too large: {} bytes (max {})",
                json.len(),
                MAX_MESSAGE_LENGTH
            ),
        ));
    }
    let len = json.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&json)?;
    writer.flush()
}

pub(crate) fn write_message(response: &Response) -> io::Result<()> {
    write_message_to(&mut io::stdout().lock(), response)
}

/// Check whether a document URL uses a safe scheme (http or https).
/// Domain filtering is handled by the browser extension; the NMH accepts
/// any domain the extension forwards.
pub(crate) fn is_url_acceptable(document_url: &str) -> bool {
    if let Ok(url) = url::Url::parse(document_url) {
        matches!(url.scheme(), "http" | "https")
    } else {
        false
    }
}

/// Validate a content hash is a 64-char hex string (SHA-256 = 32 bytes).
///
/// Note: short-circuit validation is acceptable here because this checks
/// format of a user-supplied value for lookup, not comparison against a secret.
pub(crate) fn validate_content_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 {
        return Err(format!(
            "Invalid content_hash: expected 64 hex characters, got {} chars",
            hash.len()
        ));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid content_hash: contains non-hex characters".into());
    }
    Ok(())
}

/// Get current time as nanoseconds since Unix epoch, with saturating u128→u64 cast.
/// Returns 0 only if the system clock is before the Unix epoch (shouldn't happen).
pub(crate) fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}
