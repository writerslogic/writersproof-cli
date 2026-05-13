// SPDX-License-Identifier: Apache-2.0

use super::types::{Block, Seal, Version};
use chrono::{DateTime, Utc};
use hex;

impl Block {
    /// Encode the WAR block as ASCII-armored text.
    ///
    /// Newlines and control characters are stripped from header values
    /// to prevent header injection attacks.
    pub fn encode_ascii(&self) -> String {
        let mut output = String::new();

        // Sanitize header values: strip newlines and control chars
        let safe_author: String = self.author.chars().filter(|c| !c.is_control()).collect();

        output.push_str("-----BEGIN CPoE WAR-----\n");
        output.push_str(&format!("Version: {}\n", self.version.as_str()));
        output.push_str(&format!("Author: {}\n", safe_author));
        output.push_str(&format!("Document-ID: {}\n", hex::encode(self.document_id)));
        output.push_str(&format!("Timestamp: {}\n", self.timestamp.to_rfc3339()));
        if let Some(nonce) = &self.verifier_nonce {
            output.push_str(&format!("Verifier-Nonce: {}\n", hex::encode(nonce)));
        }
        output.push('\n');

        for line in word_wrap(&self.statement, 72) {
            output.push_str(&line);
            output.push('\n');
        }

        output.push('\n');
        output.push_str("-----BEGIN SEAL-----\n");

        let seal_hex = self.seal.encode_hex();
        // hex::encode produces pure ASCII; slice directly in 64-byte chunks.
        for start in (0..seal_hex.len()).step_by(64) {
            let end = (start + 64).min(seal_hex.len());
            output.push_str(&seal_hex[start..end]);
            output.push('\n');
        }

        output.push_str("-----END SEAL-----\n");
        output.push_str("-----END CPoE WAR-----\n");

        output
    }

    /// Decode a WAR block from ASCII-armored text.
    pub fn decode_ascii(text: &str) -> Result<Self, String> {
        let lines: Vec<&str> = text.lines().collect();

        // Accept CPoE WAR (current), POP WAR (previous), and legacy format
        let start = lines
            .iter()
            .position(|l| {
                l.contains("BEGIN CPoE WAR")
                    || l.contains("BEGIN POP WAR")
                    || l.contains("BEGIN WRITTEN AUTHORSHIP REPORT")
            })
            .ok_or("missing WAR block header")?;
        let end = lines
            .iter()
            .position(|l| {
                l.contains("END CPoE WAR")
                    || l.contains("END POP WAR")
                    || l.contains("END WRITTEN AUTHORSHIP REPORT")
            })
            .ok_or("missing WAR block footer")?;

        if start >= end {
            return Err("invalid block structure".to_string());
        }

        let mut version: Option<Version> = None;
        let mut author: Option<String> = None;
        let mut document_id: Option<[u8; 32]> = None;
        let mut timestamp: Option<DateTime<Utc>> = None;
        let mut verifier_nonce: Option<[u8; 32]> = None;
        let mut header_end = start + 1;

        for (i, line) in lines[start + 1..end].iter().enumerate() {
            if line.trim().is_empty() {
                header_end = start + 1 + i;
                break;
            }

            if let Some(val) = line.strip_prefix("Version: ") {
                version = Some(
                    Version::parse(val.trim()).ok_or_else(|| format!("unknown version: {val}"))?,
                );
            } else if let Some(val) = line.strip_prefix("Author: ") {
                author = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Document-ID: ") {
                let bytes =
                    hex::decode(val.trim()).map_err(|e| format!("invalid document ID: {e}"))?;
                if bytes.len() != 32 {
                    return Err("document ID must be 32 bytes".to_string());
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                document_id = Some(id);
            } else if let Some(val) = line.strip_prefix("Timestamp: ") {
                timestamp = Some(
                    DateTime::parse_from_rfc3339(val.trim())
                        .map_err(|e| format!("invalid timestamp: {e}"))?
                        .with_timezone(&Utc),
                );
            } else if let Some(val) = line.strip_prefix("Verifier-Nonce: ") {
                let bytes =
                    hex::decode(val.trim()).map_err(|e| format!("invalid verifier nonce: {e}"))?;
                if bytes.len() != 32 {
                    return Err("verifier nonce must be 32 bytes".to_string());
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&bytes);
                verifier_nonce = Some(nonce);
            }
        }

        let version = version.ok_or("missing required header: Version")?;
        let author = author.ok_or("missing required header: Author")?;
        let document_id = document_id.ok_or("missing required header: Document-ID")?;
        let timestamp = timestamp.ok_or("missing required header: Timestamp")?;

        let seal_start = lines[start..end]
            .iter()
            .position(|l| l.contains("BEGIN SEAL"))
            .map(|pos| start + pos)
            .ok_or("missing seal header")?;
        let seal_end = lines[start..end]
            .iter()
            .position(|l| l.contains("END SEAL"))
            .map(|pos| start + pos)
            .ok_or("missing seal footer")?;

        if header_end + 1 > seal_start {
            return Err("malformed WAR block: no separator between headers and seal".into());
        }
        let statement_lines: Vec<&str> = lines[header_end + 1..seal_start]
            .iter()
            .filter(|l| !l.is_empty())
            .copied()
            .collect();
        let statement = statement_lines.join(" ");

        let seal_hex: String = lines[seal_start + 1..seal_end]
            .iter()
            .map(|l| l.trim())
            .collect();
        let seal = Seal::decode_hex(&seal_hex)?;
        // A valid Ed25519 signature that is exactly all-zero bytes is
        // cryptographically negligible (probability ~2^-512). Safe to
        // use as the unsigned sentinel value.
        let signed = seal.signature != [0u8; 64];

        Ok(Self {
            version,
            author,
            document_id,
            timestamp,
            statement,
            seal,
            signed,
            verifier_nonce,
            ear: None,
        })
    }
}

impl Seal {
    /// Encode the seal as a hex string.
    pub fn encode_hex(&self) -> String {
        let mut data = Vec::with_capacity(32 * 3 + 64 + 32);
        data.extend_from_slice(&self.h1);
        data.extend_from_slice(&self.h2);
        data.extend_from_slice(&self.h3);
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.public_key);
        hex::encode(data)
    }

    /// Decode the seal from a hex string.
    pub fn decode_hex(hex_str: &str) -> Result<Self, String> {
        let data = hex::decode(hex_str).map_err(|e| format!("invalid seal hex: {e}"))?;
        if data.len() != 32 * 3 + 64 + 32 {
            return Err(format!(
                "invalid seal length: expected {}, got {}",
                32 * 3 + 64 + 32,
                data.len()
            ));
        }

        let mut h1 = [0u8; 32];
        let mut h2 = [0u8; 32];
        let mut h3 = [0u8; 32];
        let mut signature = [0u8; 64];
        let mut public_key = [0u8; 32];

        h1.copy_from_slice(&data[0..32]);
        h2.copy_from_slice(&data[32..64]);
        h3.copy_from_slice(&data[64..96]);
        signature.copy_from_slice(&data[96..160]);
        public_key.copy_from_slice(&data[160..192]);

        Ok(Self {
            h1,
            h2,
            h3,
            signature,
            public_key,
        })
    }
}

/// Word wrap text at specified width.
fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}
