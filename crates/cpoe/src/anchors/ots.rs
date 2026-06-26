// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{
    AnchorError, AnchorProvider, AttestationOp, AttestationStep, Proof, ProofStatus, ProviderType,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

const OTS_CALENDAR_URLS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

const OTS_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// 8-byte tag identifying a Bitcoin attestation in the OTS binary format.
const OTS_BITCOIN_ATTESTATION_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Public Bitcoin block explorer API base URLs, tried in order for fallback.
const BITCOIN_BLOCK_APIS: &[&str] = &["https://blockstream.info/api", "https://mempool.space/api"];

/// Maximum HTTP response size (1 MiB) to prevent memory exhaustion from
/// malicious or misconfigured servers.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum length for varint-prefixed data fields (1 MiB) to prevent
/// unbounded allocation from crafted proofs.
const MAX_DATA_LEN: usize = 1024 * 1024;

/// Size of a serialized Bitcoin block header in bytes.
const BITCOIN_BLOCK_HEADER_SIZE: usize = 80;

/// Byte offset of the 32-byte merkle root within a Bitcoin block header.
const HEADER_MERKLE_ROOT_OFFSET: usize = 36;

/// Byte offset of the 4-byte difficulty bits field within a Bitcoin block header.
const HEADER_BITS_OFFSET: usize = 72;

/// Anchor provider using OpenTimestamps calendar servers for Bitcoin attestation.
pub struct OpenTimestampsProvider {
    calendar_urls: Vec<String>,
    client: reqwest::Client,
    /// Cache of verified Bitcoin block headers, keyed by block height.
    header_cache: std::sync::Mutex<std::collections::HashMap<u64, [u8; BITCOIN_BLOCK_HEADER_SIZE]>>,
}

impl OpenTimestampsProvider {
    /// Create a provider using the default public calendar servers.
    pub fn new() -> Result<Self, AnchorError> {
        Ok(Self {
            calendar_urls: OTS_CALENDAR_URLS
                .iter()
                .copied()
                .map(String::from)
                .collect(),
            client: super::http::build_http_client(None)?,
            header_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Create a provider using custom calendar server URLs.
    #[allow(dead_code)]
    pub fn with_calendars(urls: Vec<String>) -> Result<Self, AnchorError> {
        for url in &urls {
            super::rfc3161::validate_tsa_url(url)?;
        }
        Ok(Self {
            calendar_urls: urls,
            client: super::http::build_http_client(None)?,
            header_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Read an HTTP response body up to `MAX_RESPONSE_SIZE`, rejecting
    /// responses that exceed the limit regardless of Content-Length.
    async fn read_response_bounded(
        mut response: reqwest::Response,
    ) -> Result<Vec<u8>, AnchorError> {
        // Early reject if Content-Length advertises too much data.
        if let Some(cl) = response.content_length() {
            if cl as usize > MAX_RESPONSE_SIZE {
                return Err(AnchorError::InvalidFormat(format!(
                    "Response too large: {cl} bytes exceeds {MAX_RESPONSE_SIZE} limit"
                )));
            }
        }

        let mut buf = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?
        {
            if buf.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(AnchorError::InvalidFormat(format!(
                    "Response exceeded {MAX_RESPONSE_SIZE} byte limit"
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }

    async fn submit_to_calendar(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let endpoint = format!("{}/digest", url);

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/octet-stream")
            .body(hash.to_vec())
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AnchorError::Submission(format!(
                "Calendar returned {}",
                response.status()
            )));
        }

        Self::read_response_bounded(response).await
    }

    async fn upgrade_proof(
        &self,
        proof_data: &[u8],
        anchored_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, AnchorError> {
        let pending_urls = self.find_pending_calendars(proof_data)?;
        if pending_urls.is_empty() {
            return Ok(None);
        }

        let mut all_server_errors = true;

        for url in &pending_urls {
            // Only contact calendar URLs that were provided at construction time.
            // URLs in the proof body come from a (partially) untrusted server response;
            // allowing arbitrary URLs would enable SSRF. CWE-918.
            if !self.calendar_urls.iter().any(|allowed| {
                let a = allowed.as_str();
                url.starts_with(a)
                    && (a.ends_with('/')
                        || url
                            .as_bytes()
                            .get(a.len())
                            .map_or(true, |&c| c == b'/' || c == b'?' || c == b'#'))
            }) {
                log::warn!("Proof contains unrecognized calendar URL {}; skipping", url);
                all_server_errors = false;
                continue;
            }

            let endpoint = format!("{}/timestamp", url);
            let commitment = self.extract_commitment(proof_data, url, anchored_hash)?;

            let response = self
                .client
                .get(&endpoint)
                .query(&[("commitment", hex::encode(&commitment))])
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let upgraded = Self::read_response_bounded(resp).await?;
                        return Ok(Some(self.merge_proofs(proof_data, &upgraded, url)?));
                    }
                    let status = resp.status();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        // 404 = attestation not yet ready; not a server error.
                        all_server_errors = false;
                        log::debug!("Calendar {} returned 404 (not ready)", url);
                    } else if status.is_server_error() {
                        log::warn!("Calendar {} returned server error {}", url, status);
                    } else {
                        all_server_errors = false;
                        log::debug!("Calendar {} returned {} during upgrade", url, status);
                    }
                }
                Err(e) => {
                    log::debug!("Calendar {} upgrade request failed: {e}", url);
                }
            }
        }

        if all_server_errors {
            return Err(AnchorError::Network(
                "All calendar servers returned errors during upgrade".into(),
            ));
        }

        Ok(None)
    }

    /// Parse OTS proof data to find calendar URLs whose attestations are still pending.
    fn find_pending_calendars(&self, proof_data: &[u8]) -> Result<Vec<String>, AnchorError> {
        let mut urls = Vec::new();
        if proof_data.len() < OTS_MAGIC.len() {
            return Ok(urls);
        }

        if &proof_data[..OTS_MAGIC.len()] != OTS_MAGIC {
            return Err(AnchorError::InvalidFormat("Invalid OTS magic".into()));
        }

        let mut pos = OTS_MAGIC.len();
        while pos < proof_data.len() {
            let op = proof_data[pos];
            pos += 1;

            match op {
                0x08 | 0x02 => {} // sha256, ripemd160
                0xf0 | 0xf1 => {
                    let _ = Self::read_data(proof_data, &mut pos)?;
                }
                0x00 => {
                    // Pending attestation: URL followed by 8-byte tag + payload
                    let url = Self::read_string(proof_data, &mut pos)?;
                    urls.push(url);
                    // Advance past the attestation tag and payload if present
                    if pos + 8 <= proof_data.len() {
                        pos += 8; // 8-byte attestation type tag
                        let _ = Self::read_data(proof_data, &mut pos)?;
                    }
                }
                _ => break, // Unknown or terminal
            }
        }
        Ok(urls)
    }

    /// Extract the calendar-specific commitment hash from an OTS proof
    /// by replaying operations starting from the anchored hash.
    fn extract_commitment(
        &self,
        proof_data: &[u8],
        url: &str,
        anchored_hash: &[u8; 32],
    ) -> Result<Vec<u8>, AnchorError> {
        if proof_data.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Proof too short".into()));
        }

        let mut current_hash = anchored_hash.to_vec();
        let mut pos = OTS_MAGIC.len();

        while pos < proof_data.len() {
            let op = proof_data[pos];
            pos += 1;

            match op {
                0x08 => {
                    // sha256
                    current_hash = Sha256::digest(&current_hash).to_vec();
                }
                0x02 => {
                    // ripemd160
                    use ripemd::Ripemd160;
                    current_hash = Ripemd160::digest(&current_hash).to_vec();
                }
                0xf0 => {
                    // append
                    let data = Self::read_data(proof_data, &mut pos)?;
                    current_hash.extend_from_slice(&data);
                }
                0xf1 => {
                    // prepend
                    let data = Self::read_data(proof_data, &mut pos)?;
                    let mut new = data;
                    new.extend_from_slice(&current_hash);
                    current_hash = new;
                }
                0x00 => {
                    let found_url = Self::read_string(proof_data, &mut pos)?;
                    if found_url == url {
                        return Ok(current_hash);
                    }
                }
                _ => break,
            }
        }

        Err(AnchorError::Unavailable(format!(
            "URL {url} not found in proof"
        )))
    }

    /// Merge an upgraded calendar response into the original OTS proof.
    fn merge_proofs(
        &self,
        original: &[u8],
        upgrade: &[u8],
        url: &str,
    ) -> Result<Vec<u8>, AnchorError> {
        if original.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat(
                "Original proof too short".into(),
            ));
        }

        let mut result = original[..OTS_MAGIC.len()].to_vec();
        let mut pos = OTS_MAGIC.len();

        while pos < original.len() {
            let op_pos = pos;
            let op = original[pos];
            pos += 1;

            match op {
                0x08 | 0x02 => {
                    result.push(op);
                }
                0xf0 | 0xf1 => {
                    result.push(op);
                    let data_start = pos;
                    let _ = Self::read_data(original, &mut pos)?;
                    result.extend_from_slice(&original[data_start..pos]);
                }
                0x00 => {
                    let url_start = pos;
                    let found_url = Self::read_string(original, &mut pos)?;
                    if found_url == url {
                        // Strip magic from upgrade if present
                        if upgrade.starts_with(OTS_MAGIC) {
                            result.extend_from_slice(&upgrade[OTS_MAGIC.len()..]);
                        } else {
                            result.extend_from_slice(upgrade);
                        }
                    } else {
                        result.push(0x00);
                        result.extend_from_slice(&original[url_start..pos]);
                    }
                }
                _ => {
                    result.extend_from_slice(&original[op_pos..]);
                    break;
                }
            }
        }
        Ok(result)
    }

    /// Read a Bitcoin-style varint (compact size) from `data` at `pos`,
    /// advancing `pos` past the encoded integer.
    fn read_varint(data: &[u8], pos: &mut usize) -> Result<usize, AnchorError> {
        if *pos >= data.len() {
            return Err(AnchorError::InvalidFormat(
                "Truncated proof: expected varint".into(),
            ));
        }
        let first = data[*pos];
        *pos += 1;
        match first {
            0x00..=0xfc => Ok(first as usize),
            0xfd => {
                if *pos + 2 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 2-byte varint".into(),
                    ));
                }
                let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
                *pos += 2;
                Ok(v)
            }
            0xfe => {
                if *pos + 4 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 4-byte varint".into(),
                    ));
                }
                let v = u32::from_le_bytes([
                    data[*pos],
                    data[*pos + 1],
                    data[*pos + 2],
                    data[*pos + 3],
                ]) as usize;
                *pos += 4;
                Ok(v)
            }
            0xff => {
                if *pos + 8 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 8-byte varint".into(),
                    ));
                }
                let v64 = u64::from_le_bytes([
                    data[*pos],
                    data[*pos + 1],
                    data[*pos + 2],
                    data[*pos + 3],
                    data[*pos + 4],
                    data[*pos + 5],
                    data[*pos + 6],
                    data[*pos + 7],
                ]);
                let v = usize::try_from(v64).map_err(|_| {
                    AnchorError::InvalidFormat("Varint exceeds addressable range".into())
                })?;
                *pos += 8;
                Ok(v)
            }
        }
    }

    /// Read a varint-prefixed byte slice from `data` at `pos`,
    /// advancing `pos` past both the length and the payload.
    fn read_data(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, AnchorError> {
        let len = Self::read_varint(data, pos)?;
        if len > MAX_DATA_LEN {
            return Err(AnchorError::InvalidFormat(format!(
                "Data field length {len} exceeds maximum {MAX_DATA_LEN}"
            )));
        }
        let end = pos
            .checked_add(len)
            .ok_or_else(|| AnchorError::InvalidFormat("Proof data length overflow".into()))?;
        if end > data.len() {
            return Err(AnchorError::InvalidFormat(format!(
                "Truncated proof: need {} bytes at offset {}, have {}",
                len,
                *pos,
                data.len() - *pos
            )));
        }
        let result = data[*pos..end].to_vec();
        *pos += len;
        Ok(result)
    }

    /// Read a varint-prefixed UTF-8 string from `data` at `pos`.
    fn read_string(data: &[u8], pos: &mut usize) -> Result<String, AnchorError> {
        let bytes = Self::read_data(data, pos)?;
        String::from_utf8(bytes)
            .map_err(|e| AnchorError::InvalidFormat(format!("Invalid UTF-8: {e}")))
    }

    fn parse_attestation_path(
        &self,
        proof_data: &[u8],
    ) -> Result<Vec<AttestationStep>, AnchorError> {
        let mut steps = Vec::new();
        if proof_data.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Proof too short".into()));
        }

        if &proof_data[..OTS_MAGIC.len()] != OTS_MAGIC {
            return Err(AnchorError::InvalidFormat("Invalid OTS magic".into()));
        }

        let mut pos: usize = OTS_MAGIC.len();

        while pos < proof_data.len() {
            let op_byte = proof_data[pos];
            pos += 1;

            let step = match op_byte {
                0x08 => AttestationStep {
                    operation: AttestationOp::Sha256,
                    data: Vec::new(),
                },
                0x02 => AttestationStep {
                    operation: AttestationOp::Ripemd160,
                    data: Vec::new(),
                },
                0xf0 => {
                    let data = Self::read_data(proof_data, &mut pos)?;
                    AttestationStep {
                        operation: AttestationOp::Append,
                        data,
                    }
                }
                0xf1 => {
                    let data = Self::read_data(proof_data, &mut pos)?;
                    AttestationStep {
                        operation: AttestationOp::Prepend,
                        data,
                    }
                }
                0x00 => {
                    // Attestation marker is terminal in OTS; remaining bytes
                    // are attestation metadata (type tag + payload).
                    steps.push(AttestationStep {
                        operation: AttestationOp::Verify,
                        data: Vec::new(),
                    });
                    break;
                }
                0xff => {
                    return Err(AnchorError::InvalidFormat(
                        "Branching proofs (fork opcode 0xff) are not supported".into(),
                    ));
                }
                unknown => {
                    return Err(AnchorError::InvalidFormat(format!(
                        "Unknown OTS opcode: 0x{:02x}",
                        unknown
                    )));
                }
            };

            steps.push(step);
        }

        Ok(steps)
    }

    fn verify_attestation_path(
        &self,
        hash: &[u8; 32],
        steps: &[AttestationStep],
    ) -> Result<Vec<u8>, AnchorError> {
        let mut current = hash.to_vec();

        for step in steps {
            current = match step.operation {
                AttestationOp::Sha256 => Sha256::digest(&current).to_vec(),
                AttestationOp::Ripemd160 => {
                    use ripemd::Ripemd160;
                    Ripemd160::digest(&current).to_vec()
                }
                AttestationOp::Append => {
                    let mut new = current.clone();
                    new.extend_from_slice(&step.data);
                    new
                }
                AttestationOp::Prepend => {
                    let mut new = step.data.clone();
                    new.extend_from_slice(&current);
                    new
                }
                // Verify is a terminal attestation marker; it does not transform
                // the hash. Actual block header validation is deferred to the
                // `verify()` trait method.
                AttestationOp::Verify => current.clone(),
            };
        }

        Ok(current)
    }

    /// Extract the Bitcoin block height from an OTS proof's attestation data.
    ///
    /// Scans the raw proof bytes for the 8-byte Bitcoin attestation tag and
    /// reads the block height from the little-endian payload that follows.
    fn extract_bitcoin_block_height(proof_data: &[u8]) -> Result<Option<u64>, AnchorError> {
        if proof_data.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Proof too short".into()));
        }
        if &proof_data[..OTS_MAGIC.len()] != OTS_MAGIC {
            return Err(AnchorError::InvalidFormat("Invalid OTS magic".into()));
        }

        let mut pos = OTS_MAGIC.len();
        while pos < proof_data.len() {
            let op = proof_data[pos];
            pos += 1;

            match op {
                0x08 | 0x02 => {}
                0xf0 | 0xf1 => {
                    let _ = Self::read_data(proof_data, &mut pos)?;
                }
                0x00 => {
                    if pos + 8 > proof_data.len() {
                        break;
                    }
                    let mut tag = [0u8; 8];
                    tag.copy_from_slice(&proof_data[pos..pos + 8]);
                    pos += 8;
                    let payload = Self::read_data(proof_data, &mut pos)?;

                    if tag == OTS_BITCOIN_ATTESTATION_TAG {
                        if payload.len() > 8 {
                            return Err(AnchorError::InvalidFormat(
                                "Block height exceeds 8 bytes".into(),
                            ));
                        }
                        let height = payload
                            .iter()
                            .enumerate()
                            .fold(0u64, |acc, (i, &b)| acc | ((b as u64) << (8 * i)));
                        return Ok(Some(height));
                    }
                }
                _ => break,
            }
        }

        Ok(None)
    }

    /// Fetch the raw 80-byte block header for a Bitcoin block at the given
    /// height. Tries multiple block explorer APIs and caches results.
    async fn fetch_block_header(
        &self,
        height: u64,
    ) -> Result<[u8; BITCOIN_BLOCK_HEADER_SIZE], AnchorError> {
        {
            let cache = self.header_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(header) = cache.get(&height) {
                return Ok(*header);
            }
        }

        let mut last_error = None;

        for base_url in BITCOIN_BLOCK_APIS {
            match self.fetch_block_header_from(base_url, height).await {
                Ok(header) => {
                    if !Self::verify_block_pow(&header) {
                        log::warn!(
                            "Block header at height {} from {} fails PoW; \
                             trying next API",
                            height,
                            base_url
                        );
                        last_error = Some(AnchorError::Verification(format!(
                            "Block header at height {height} fails proof-of-work"
                        )));
                        continue;
                    }

                    let mut cache = self.header_cache.lock().unwrap_or_else(|e| e.into_inner());
                    if cache.len() >= 1000 {
                        cache.clear();
                    }
                    cache.insert(height, header);

                    return Ok(header);
                }
                Err(e) => {
                    log::debug!("Block explorer {} failed: {e}", base_url);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| AnchorError::Unavailable("All block explorer APIs failed".into())))
    }

    async fn fetch_block_header_from(
        &self,
        base_url: &str,
        height: u64,
    ) -> Result<[u8; BITCOIN_BLOCK_HEADER_SIZE], AnchorError> {
        // GET /block-height/{h} -> block hash (64 hex chars)
        let hash_url = format!("{}/block-height/{}", base_url, height);
        let hash_resp = self
            .client
            .get(&hash_url)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !hash_resp.status().is_success() {
            return Err(AnchorError::Network(format!(
                "Block height lookup returned {}",
                hash_resp.status()
            )));
        }

        let hash_bytes = Self::read_response_bounded(hash_resp).await?;
        let block_hash = String::from_utf8(hash_bytes)
            .map_err(|e| AnchorError::InvalidFormat(format!("Invalid block hash UTF-8: {e}")))?;
        let block_hash = block_hash.trim();

        if block_hash.len() != 64 || !block_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AnchorError::InvalidFormat(format!(
                "Invalid block hash: {}",
                &block_hash[..block_hash.len().min(80)]
            )));
        }

        // GET /block/{hash}/header -> hex-encoded 80-byte header
        let header_url = format!("{}/block/{}/header", base_url, block_hash);
        let header_resp = self
            .client
            .get(&header_url)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !header_resp.status().is_success() {
            return Err(AnchorError::Network(format!(
                "Block header lookup returned {}",
                header_resp.status()
            )));
        }

        let header_raw = Self::read_response_bounded(header_resp).await?;
        let header_hex = String::from_utf8(header_raw)
            .map_err(|e| AnchorError::InvalidFormat(format!("Invalid header hex UTF-8: {e}")))?;
        let header_bytes = hex::decode(header_hex.trim())
            .map_err(|e| AnchorError::InvalidFormat(format!("Invalid header hex: {e}")))?;

        if header_bytes.len() != BITCOIN_BLOCK_HEADER_SIZE {
            return Err(AnchorError::InvalidFormat(format!(
                "Block header is {} bytes, expected {}",
                header_bytes.len(),
                BITCOIN_BLOCK_HEADER_SIZE
            )));
        }

        let mut header = [0u8; BITCOIN_BLOCK_HEADER_SIZE];
        header.copy_from_slice(&header_bytes);
        Ok(header)
    }

    /// Extract the 32-byte merkle root from a raw Bitcoin block header.
    fn parse_merkle_root(header: &[u8; BITCOIN_BLOCK_HEADER_SIZE]) -> [u8; 32] {
        let mut root = [0u8; 32];
        root.copy_from_slice(&header[HEADER_MERKLE_ROOT_OFFSET..HEADER_MERKLE_ROOT_OFFSET + 32]);
        root
    }

    /// Verify a Bitcoin block header's proof-of-work by checking that
    /// double-SHA256(header), as a LE 256-bit integer, is below the
    /// target derived from the compact `bits` field.
    fn verify_block_pow(header: &[u8; BITCOIN_BLOCK_HEADER_SIZE]) -> bool {
        let hash1 = Sha256::digest(header);
        let hash2 = Sha256::digest(hash1);

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&hash2);

        let bits = u32::from_le_bytes([
            header[HEADER_BITS_OFFSET],
            header[HEADER_BITS_OFFSET + 1],
            header[HEADER_BITS_OFFSET + 2],
            header[HEADER_BITS_OFFSET + 3],
        ]);

        let target = Self::compact_to_target(bits);
        Self::le_u256_lte(&block_hash, &target)
    }

    /// Convert Bitcoin compact target (nBits) to a 32-byte LE representation.
    fn compact_to_target(bits: u32) -> [u8; 32] {
        let mut target = [0u8; 32];
        let size = (bits >> 24) as usize;
        let mut word = bits & 0x007F_FFFF;

        // Reject negative targets (sign bit set) per Bitcoin Core.
        if bits & 0x0080_0000 != 0 {
            return target;
        }

        if size == 0 || word == 0 {
            return target;
        }

        // Size > 32 would place mantissa bytes outside the 32-byte target.
        if size > 32 {
            return target;
        }

        if size <= 3 {
            word >>= 8 * (3 - size);
            target[0] = (word & 0xFF) as u8;
            target[1] = ((word >> 8) & 0xFF) as u8;
            target[2] = ((word >> 16) & 0xFF) as u8;
        } else {
            let pos = size - 3;
            if pos < 32 {
                target[pos] = (word & 0xFF) as u8;
            }
            if pos + 1 < 32 {
                target[pos + 1] = ((word >> 8) & 0xFF) as u8;
            }
            if pos + 2 < 32 {
                target[pos + 2] = ((word >> 16) & 0xFF) as u8;
            }
        }

        target
    }

    /// Compare two 32-byte values as LE 256-bit unsigned integers.
    /// Returns true if a <= b.
    fn le_u256_lte(a: &[u8; 32], b: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if a[i] < b[i] {
                return true;
            }
            if a[i] > b[i] {
                return false;
            }
        }
        true // equal
    }
}

/// The `verify` method performs a full Bitcoin block header cross-check when
/// a block explorer is reachable, and falls back to `AnchorError::Unavailable`
/// when offline. Structural sanity (Verify step present, 32-byte result) is
/// always checked first.
#[async_trait]
impl AnchorProvider for OpenTimestampsProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::OpenTimestamps
    }

    fn name(&self) -> &str {
        "OpenTimestamps"
    }

    async fn is_available(&self) -> bool {
        // Use a shorter timeout than the shared client's 30s default
        // to avoid blocking callers on a simple availability check.
        let timeout = std::time::Duration::from_secs(5);
        for url in &self.calendar_urls {
            let result = tokio::time::timeout(timeout, self.client.get(url).send()).await;
            if let Ok(Ok(resp)) = result {
                if resp.status().is_success() {
                    return true;
                }
            }
        }
        false
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let mut last_error = None;

        for url in &self.calendar_urls {
            match self.submit_to_calendar(url, hash).await {
                Ok(proof_data) => {
                    return Ok(Proof {
                        id: format!("ots-{}", crate::utils::short_hex_id(hash)),
                        provider: ProviderType::OpenTimestamps,
                        status: ProofStatus::Pending,
                        anchored_hash: *hash,
                        submitted_at: chrono::Utc::now(),
                        confirmed_at: None,
                        proof_data,
                        location: Some(url.clone()),
                        attestation_path: None,
                        extra: Default::default(),
                    });
                }
                Err(e) => {
                    log::debug!("Calendar {} failed: {e}", url);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            log::warn!("OTS submit failed: no calendar URLs configured");
            AnchorError::Unavailable("All calendars failed".into())
        }))
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        if let Some(upgraded_data) = self
            .upgrade_proof(&proof.proof_data, &proof.anchored_hash)
            .await?
        {
            let path = self.parse_attestation_path(&upgraded_data)?;
            let has_bitcoin = path.iter().any(|s| s.operation == AttestationOp::Verify);

            let mut updated = proof.clone();
            updated.proof_data = upgraded_data;
            updated.attestation_path = Some(path);

            if has_bitcoin {
                updated.status = ProofStatus::Confirmed;
                updated.confirmed_at = Some(chrono::Utc::now());
            }

            return Ok(updated);
        }

        Ok(proof.clone())
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let path = if let Some(ref path) = proof.attestation_path {
            path.clone()
        } else {
            self.parse_attestation_path(&proof.proof_data)?
        };

        let has_verify = path.iter().any(|s| s.operation == AttestationOp::Verify);
        if !has_verify {
            return Ok(false);
        }

        let result = self.verify_attestation_path(&proof.anchored_hash, &path)?;
        if result.len() != 32 {
            return Ok(false);
        }

        // Attempt Bitcoin block header cross-check
        let height = match Self::extract_bitcoin_block_height(&proof.proof_data) {
            Ok(Some(h)) => h,
            Ok(None) => {
                log::warn!("No Bitcoin attestation tag in proof; structural check only");
                return Err(AnchorError::Unavailable(
                    "No Bitcoin block height in attestation; \
                     structural check passed"
                        .into(),
                ));
            }
            Err(e) => return Err(e),
        };

        let header = match self.fetch_block_header(height).await {
            Ok(h) => h,
            Err(AnchorError::Network(_) | AnchorError::Unavailable(_)) => {
                log::warn!(
                    "Block explorer unreachable for height {}; \
                     structural check passed",
                    height
                );
                return Err(AnchorError::Unavailable(format!(
                    "Block explorer unreachable for height {height}; \
                     structural check passed"
                )));
            }
            Err(e) => return Err(e),
        };

        let merkle_root = Self::parse_merkle_root(&header);
        use subtle::ConstantTimeEq;
        if bool::from(result.as_slice().ct_eq(merkle_root.as_slice())) {
            log::info!(
                "OTS proof verified against Bitcoin block {} merkle root",
                height
            );
            Ok(true)
        } else {
            log::warn!(
                "OTS proof REJECTED: hash mismatch with block {} merkle root",
                height
            );
            Ok(false)
        }
    }

    async fn upgrade(&self, proof: &Proof) -> Result<Option<Proof>, AnchorError> {
        if proof.status == ProofStatus::Confirmed {
            return Ok(None);
        }

        if let Some(upgraded_data) = self
            .upgrade_proof(&proof.proof_data, &proof.anchored_hash)
            .await?
        {
            let mut updated = proof.clone();
            updated.proof_data = upgraded_data;
            updated.attestation_path = Some(self.parse_attestation_path(&updated.proof_data)?);

            if let Some(ref path) = updated.attestation_path {
                if path.iter().any(|s| s.operation == AttestationOp::Verify) {
                    updated.status = ProofStatus::Confirmed;
                    updated.confirmed_at = Some(chrono::Utc::now());
                }
            }

            return Ok(Some(updated));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ots_proof_with_bitcoin(height: u64) -> Vec<u8> {
        let mut proof = OTS_MAGIC.to_vec();
        proof.push(0x08); // SHA256 op
                          // Bitcoin attestation: marker + tag + varint-len + height LE bytes
        proof.push(0x00);
        proof.extend_from_slice(&OTS_BITCOIN_ATTESTATION_TAG);
        let mut height_bytes = Vec::new();
        let mut h = height;
        if h == 0 {
            height_bytes.push(0);
        } else {
            while h > 0 {
                height_bytes.push((h & 0xFF) as u8);
                h >>= 8;
            }
        }
        proof.push(height_bytes.len() as u8);
        proof.extend_from_slice(&height_bytes);
        proof
    }

    fn genesis_block_header() -> [u8; BITCOIN_BLOCK_HEADER_SIZE] {
        let hex_str = "\
            01000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a\
            29ab5f49\
            ffff001d\
            1dac2b7c";
        let bytes = hex::decode(hex_str).unwrap();
        let mut header = [0u8; BITCOIN_BLOCK_HEADER_SIZE];
        header.copy_from_slice(&bytes);
        header
    }

    #[test]
    fn extract_bitcoin_height_valid() {
        let proof = make_ots_proof_with_bitcoin(100_000);
        let height = OpenTimestampsProvider::extract_bitcoin_block_height(&proof)
            .unwrap()
            .unwrap();
        assert_eq!(height, 100_000);
    }

    #[test]
    fn extract_bitcoin_height_zero() {
        let proof = make_ots_proof_with_bitcoin(0);
        let height = OpenTimestampsProvider::extract_bitcoin_block_height(&proof)
            .unwrap()
            .unwrap();
        assert_eq!(height, 0);
    }

    #[test]
    fn extract_bitcoin_height_large() {
        let proof = make_ots_proof_with_bitcoin(800_000);
        let height = OpenTimestampsProvider::extract_bitcoin_block_height(&proof)
            .unwrap()
            .unwrap();
        assert_eq!(height, 800_000);
    }

    #[test]
    fn extract_bitcoin_height_none_when_no_attestation() {
        let mut proof = OTS_MAGIC.to_vec();
        proof.push(0x08);
        let result = OpenTimestampsProvider::extract_bitcoin_block_height(&proof).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_bitcoin_height_rejects_bad_magic() {
        let proof = vec![0x00; 32];
        let err = OpenTimestampsProvider::extract_bitcoin_block_height(&proof).unwrap_err();
        assert!(matches!(err, AnchorError::InvalidFormat(_)));
    }

    #[test]
    fn parse_merkle_root_genesis() {
        let header = genesis_block_header();
        let root = OpenTimestampsProvider::parse_merkle_root(&header);
        let expected =
            hex::decode("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
                .unwrap();
        assert_eq!(root.as_slice(), expected.as_slice());
    }

    #[test]
    fn compact_to_target_genesis() {
        let target = OpenTimestampsProvider::compact_to_target(0x1d00ffff);
        assert_eq!(target[26], 0xff);
        assert_eq!(target[27], 0xff);
        for i in 0..26 {
            assert_eq!(target[i], 0, "target[{i}] should be 0");
        }
        for i in 28..32 {
            assert_eq!(target[i], 0, "target[{i}] should be 0");
        }
    }

    #[test]
    fn compact_to_target_zero_mantissa() {
        let target = OpenTimestampsProvider::compact_to_target(0x1d000000);
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    fn compact_to_target_zero_size() {
        let target = OpenTimestampsProvider::compact_to_target(0x00ffffff);
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    fn compact_to_target_block_100000() {
        // Block 100000 bits: 0x1b04864c
        let target = OpenTimestampsProvider::compact_to_target(0x1b04864c);
        assert_eq!(target[24], 0x4c);
        assert_eq!(target[25], 0x86);
        assert_eq!(target[26], 0x04);
        for i in 0..24 {
            assert_eq!(target[i], 0, "target[{i}] should be 0");
        }
        for i in 27..32 {
            assert_eq!(target[i], 0, "target[{i}] should be 0");
        }
    }

    #[test]
    fn verify_block_pow_genesis() {
        let header = genesis_block_header();
        assert!(OpenTimestampsProvider::verify_block_pow(&header));
    }

    #[test]
    fn verify_block_pow_rejects_tampered_header() {
        let mut header = genesis_block_header();
        header[79] ^= 0x01; // flip nonce bit
        assert!(!OpenTimestampsProvider::verify_block_pow(&header));
    }

    #[test]
    fn le_u256_lte_equal() {
        let a = [0u8; 32];
        assert!(OpenTimestampsProvider::le_u256_lte(&a, &a));
    }

    #[test]
    fn le_u256_lte_less() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert!(OpenTimestampsProvider::le_u256_lte(&a, &b));
    }

    #[test]
    fn le_u256_lte_greater() {
        let mut a = [0u8; 32];
        a[31] = 1;
        let b = [0u8; 32];
        assert!(!OpenTimestampsProvider::le_u256_lte(&a, &b));
    }

    #[test]
    fn le_u256_lte_low_byte_difference() {
        let mut a = [0u8; 32];
        a[0] = 0xff;
        let mut b = [0u8; 32];
        b[1] = 0x01;
        // a = 0x00..00ff, b = 0x00..0100 => a < b
        assert!(OpenTimestampsProvider::le_u256_lte(&a, &b));
    }

    #[test]
    fn parse_attestation_path_handles_bitcoin_attestation() {
        let proof = make_ots_proof_with_bitcoin(100_000);
        let provider = OpenTimestampsProvider::new().unwrap();
        let steps = provider.parse_attestation_path(&proof).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].operation, AttestationOp::Sha256);
        assert_eq!(steps[1].operation, AttestationOp::Verify);
    }

    #[test]
    fn parse_attestation_path_no_error_on_trailing_attestation_data() {
        // Previously, bytes after 0x00 would error as unknown opcodes.
        // Now 0x00 is terminal and parsing stops cleanly.
        let mut proof = OTS_MAGIC.to_vec();
        proof.push(0xf0); // append
        proof.push(0x02); // varint len=2
        proof.extend_from_slice(&[0xAA, 0xBB]);
        proof.push(0x08); // sha256
        proof.push(0x00); // attestation marker
        proof.extend_from_slice(&[0x99; 20]); // trailing metadata

        let provider = OpenTimestampsProvider::new().unwrap();
        let steps = provider.parse_attestation_path(&proof).unwrap();
        assert_eq!(steps.len(), 3); // Append, Sha256, Verify
        assert_eq!(steps[2].operation, AttestationOp::Verify);
    }
}
