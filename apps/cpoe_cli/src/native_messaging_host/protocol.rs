// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io::{self, Read, Write};

use super::types::{Request, Response};

/// Maximum allowed message length (1 MiB).
pub(crate) const MAX_MESSAGE_LENGTH: usize = 1_048_576;

pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// Allowed domains for browser extension sessions.
/// Must match the host_permissions in the browser extension manifest.
pub(crate) const ALLOWED_DOMAINS: &[&str] = &[
    // Editors
    "docs.google.com",
    "www.overleaf.com",
    "medium.com",
    "notion.so",
    "www.notion.so",
    "www.craft.do",
    "coda.io",
    "app.clickup.com",
    "app.nuclino.com",
    "stackedit.io",
    "hackmd.io",
    // Publishing
    "substack.com",
    "wordpress.com",
    "ghost.io",
    "write.as",
    "www.wattpad.com",
    "archiveofourown.org",
    "www.scribophile.com",
    // Writing tools
    "hemingwayapp.com",
    "quillbot.com",
    "prowritingaid.com",
    "app.grammarly.com",
    "languagetool.org",
    "www.deepl.com",
    "www.writefull.com",
    // Office
    "docs.google.com",
    "www.office.com",
    "onedrive.live.com",
    "www.icloud.com",
    "www.dropbox.com",
    // Collaboration
    "pad.riseup.net",
];

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

/// Check whether a document URL is from an allowed domain.
/// Exact matches and proper subdomains are accepted; suffix attacks are not.
/// For example, `sub.docs.google.com` matches `docs.google.com`, but
/// `evilnotion.so` does NOT match `notion.so`.
pub(crate) fn is_domain_allowed(document_url: &str) -> bool {
    if let Ok(url) = url::Url::parse(document_url) {
        if let Some(host) = url.host_str() {
            ALLOWED_DOMAINS
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
        } else {
            false
        }
    } else {
        false
    }
}

/// Validate a content hash is a 64-char hex string (SHA-256 = 32 bytes).
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
