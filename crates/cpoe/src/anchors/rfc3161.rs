// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;
use subtle::ConstantTimeEq;

const DEFAULT_TSA_URLS: &[&str] = &[
    "https://timestamp.digicert.com",
    "https://timestamp.sectigo.com",
    "https://freetsa.org/tsr",
    "https://timestamp.globalsign.com/tsa/r6advanced1",
];

/// Anchor provider using RFC 3161 Time-Stamp Authorities.
pub struct Rfc3161Provider {
    tsa_urls: Vec<String>,
    client: reqwest::Client,
}

impl Rfc3161Provider {
    /// Create a provider with explicit TSA endpoint URLs.
    ///
    /// Only HTTPS URLs are accepted. HTTP, file, and loopback/private addresses are
    /// rejected to prevent SSRF.
    pub fn new(tsa_urls: Vec<String>) -> Result<Self, AnchorError> {
        for url in &tsa_urls {
            validate_tsa_url(url)?;
        }
        let client = super::http::build_http_client(None)?;
        Ok(Self { tsa_urls, client })
    }

    async fn request_timestamp(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let (request, nonce_sent) = self.build_timestamp_request(hash)?;

        let mut response = self
            .client
            .post(url)
            .header("Content-Type", "application/timestamp-query")
            .body(request)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AnchorError::Submission(format!(
                "TSA returned {}",
                response.status()
            )));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("timestamp-reply") {
            return Err(AnchorError::InvalidFormat(format!(
                "Unexpected content type: {}",
                content_type
            )));
        }

        const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB

        // Pre-flight check on Content-Length header when present.
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_RESPONSE_SIZE as u64 {
                return Err(AnchorError::InvalidFormat(format!(
                    "TSA response too large: {} bytes (max {})",
                    content_length, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Stream the body in chunks to enforce the size cap even when the
        // server uses chunked transfer-encoding (no Content-Length header).
        let mut body = Vec::new();
        loop {
            // reqwest's Response exposes chunk() which returns Option<Bytes>
            let chunk = response
                .chunk()
                .await
                .map_err(|e| AnchorError::Network(e.to_string()))?;
            match chunk {
                Some(bytes) => {
                    body.extend_from_slice(&bytes);
                    if body.len() > MAX_RESPONSE_SIZE {
                        return Err(AnchorError::InvalidFormat(format!(
                            "TSA response too large: >{} bytes (max {})",
                            body.len(),
                            MAX_RESPONSE_SIZE
                        )));
                    }
                }
                None => break,
            }
        }
        // H-051: Verify the nonce in the response matches the request nonce
        let tst_info = extract_tst_info(&body)?;
        let response_nonce = extract_nonce(&tst_info)
            .ok_or_else(|| AnchorError::InvalidFormat("TSA response missing nonce".into()))?;
        // Canonicalize sent nonce the same way extract_nonce does: strip leading
        // 0x00 bytes so both sides represent the same numeric value before comparing.
        let mut sent_canonical = nonce_sent.as_slice();
        while sent_canonical.len() > 1 && sent_canonical[0] == 0x00 {
            sent_canonical = &sent_canonical[1..];
        }
        if response_nonce.ct_eq(sent_canonical).unwrap_u8() != 1 {
            return Err(AnchorError::InvalidFormat(
                "TSA response nonce does not match request nonce".into(),
            ));
        }

        Ok(body)
    }

    #[allow(clippy::vec_init_then_push)]
    fn build_timestamp_request(&self, hash: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), AnchorError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| AnchorError::Submission("Failed to generate nonce".into()))?;
        let nonce_vec = nonce.to_vec();

        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];

        // MessageImprint SEQUENCE wraps AlgorithmIdentifier (OID + NULL) + OCTET STRING (hash)
        let mi_content_len = sha256_oid.len() + 2 + 2 + 32; // OID + NULL tag/len + OCTET STRING tag/len + hash
        debug_assert!(
            mi_content_len <= 127,
            "DER short form requires length <= 127"
        );
        let mut message_imprint = Vec::new();
        message_imprint.push(0x30);
        message_imprint.push(
            u8::try_from(mi_content_len)
                .map_err(|_| AnchorError::Submission("DER length overflow".into()))?,
        );
        message_imprint.extend_from_slice(sha256_oid);
        message_imprint.push(0x05);
        message_imprint.push(0x00);
        message_imprint.push(0x04);
        message_imprint.push(32);
        message_imprint.extend_from_slice(hash);

        let mut request = Vec::new();
        request.push(0x02);
        request.push(0x01);
        request.push(0x01);
        request.push(0x30);
        request.push(
            u8::try_from(message_imprint.len())
                .map_err(|_| AnchorError::Submission("DER length overflow".into()))?,
        );
        request.extend_from_slice(&message_imprint);
        // DER INTEGER: prepend 0x00 sign byte when high bit is set so the
        // value is unambiguously positive (RFC 5280 §4.1, X.690 §8.3.2).
        request.push(0x02);
        if nonce[0] >= 0x80 {
            request.push(0x11); // length = 17 (with sign byte)
            request.push(0x00);
        } else {
            request.push(0x10); // length = 16
        }
        request.extend_from_slice(&nonce);
        request.push(0x01);
        request.push(0x01);
        request.push(0xFF);

        let mut final_request = Vec::new();
        final_request.push(0x30);
        if request.len() < 128 {
            final_request.push(request.len() as u8);
        } else if request.len() <= 0xFF {
            final_request.push(0x81);
            final_request.push(request.len() as u8);
        } else if request.len() <= 0xFFFF {
            final_request.push(0x82);
            final_request.push((request.len() >> 8) as u8);
            final_request.push((request.len() & 0xFF) as u8);
        } else {
            return Err(AnchorError::Submission(
                "DER request length exceeds 2-byte encoding limit".into(),
            ));
        }
        final_request.extend_from_slice(&request);

        Ok((final_request, nonce_vec))
    }

    /// Extract timestamp, serial, and TSA name from a TimeStampResp (RFC 3161 s2.4.2).
    fn parse_timestamp_response(&self, response: &[u8]) -> Result<TimestampInfo, AnchorError> {
        if response.len() < 10 {
            return Err(AnchorError::InvalidFormat("Response too short".into()));
        }

        let tst_info = extract_tst_info(response)?;
        let gen_time = extract_generalized_time(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract genTime from TSTInfo".into())
        })?;
        let serial = extract_serial_number(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract serialNumber from TSTInfo".into())
        })?;

        let tsa_name = extract_tsa_name(&tst_info).unwrap_or_else(|| "RFC 3161 TSA".to_string());

        Ok(TimestampInfo {
            timestamp: gen_time,
            serial_number: serial,
            tsa_name,
        })
    }

    /// Verify the RFC 3161 timestamp token: MessageImprint hash + CMS RSA-SHA256 signature.
    ///
    /// Supports sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11) with SHA-256 digest.
    /// Returns `Err(AnchorError::Unavailable)` for unsupported algorithms so callers can
    /// distinguish "verified" from "algorithm not supported".
    fn verify_timestamp_token(&self, token: &[u8], hash: &[u8; 32]) -> Result<bool, AnchorError> {
        if token.len() < 100 {
            return Err(AnchorError::InvalidFormat("Token too short".into()));
        }
        if token[0] != 0x30 {
            return Err(AnchorError::InvalidFormat("Invalid ASN.1 structure".into()));
        }

        let tst_info = extract_tst_info(token)?;
        let imprint_hash = extract_message_imprint_hash(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract MessageImprint hash from TSTInfo".into())
        })?;
        if imprint_hash.ct_eq(hash).unwrap_u8() != 1 {
            return Err(AnchorError::HashMismatch);
        }

        verify_cms_signature(token, &tst_info)
    }
}

/// Validate that a TSA URL uses HTTPS and does not point to loopback or private addresses.
pub(super) fn validate_tsa_url(url: &str) -> Result<(), AnchorError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| AnchorError::Configuration(format!("Invalid TSA URL: {url}")))?;

    if parsed.scheme() != "https" {
        return Err(AnchorError::Configuration(format!(
            "TSA URL must use HTTPS scheme: {url}"
        )));
    }

    if let Some(host) = parsed.host_str() {
        let lower = host.to_lowercase();
        let blocked = lower == "localhost"
            || lower == "127.0.0.1"
            || lower == "::1"
            || lower == "[::1]"
            || lower == "0.0.0.0"
            || lower.starts_with("10.")
            || lower.starts_with("192.168.")
            || lower.starts_with("169.254.")
            || lower.starts_with("fe80:")
            || lower.starts_with("[fe80:")
            || lower.starts_with("[fc")
            || lower.starts_with("[fd");
        if blocked {
            return Err(AnchorError::Configuration(format!(
                "TSA URL must not point to loopback or private address: {url}"
            )));
        }
        // Check 172.16.0.0/12 range
        if let Some(rest) = lower.strip_prefix("172.") {
            if let Some(octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
                if (16..=31).contains(&octet) {
                    return Err(AnchorError::Configuration(format!(
                        "TSA URL must not point to loopback or private address: {url}"
                    )));
                }
            }
        }
        // Check 100.64.0.0/10 CGNAT range
        if let Some(rest) = lower.strip_prefix("100.") {
            if let Some(octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
                if (64..=127).contains(&octet) {
                    return Err(AnchorError::Configuration(format!(
                        "TSA URL must not point to loopback or private address: {url}"
                    )));
                }
            }
        }
        // Check IPv4-mapped IPv6 (::ffff:127.x.x.x loopback and private ranges)
        if let Some(ipv4_part) = lower
            .strip_prefix("::ffff:")
            .or_else(|| lower.strip_prefix("[::ffff:").and_then(|s| s.strip_suffix(']')))
        {
            if ipv4_part.starts_with("127.")
                || ipv4_part.starts_with("10.")
                || ipv4_part.starts_with("192.168.")
                || ipv4_part.starts_with("169.254.")
                || ipv4_part == "0.0.0.0"
            {
                return Err(AnchorError::Configuration(format!(
                    "TSA URL must not point to loopback or private address: {url}"
                )));
            }
        }
    } else {
        return Err(AnchorError::Configuration(format!(
            "TSA URL has no host: {url}"
        )));
    }

    Ok(())
}

// DER/CMS parsing uses byte-range offsets to sidestep lifetime issues
// with closure-based iteration.

/// DER TLV as byte-range offsets into the source buffer.
#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    /// Byte offset of the tag byte (start of the full TLV encoding).
    start: usize,
    content_start: usize,
    content_end: usize,
}

impl Tlv {
    fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.content_start..self.content_end]
    }

    /// Full TLV bytes: tag + length + content.
    fn as_bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.start..self.content_end]
    }
}

/// Read a single DER TLV at `offset`.
fn read_tlv(data: &[u8], offset: usize) -> Option<Tlv> {
    if offset >= data.len() {
        return None;
    }
    let tag = data[offset];
    let length_offset = offset.checked_add(1)?;
    let (length, header_len) = read_der_length(data, length_offset)?;
    let content_start = length_offset.checked_add(header_len)?;
    let content_end = content_start.checked_add(length)?;
    if content_end > data.len() {
        return None;
    }
    Some(Tlv {
        tag,
        start: offset,
        content_start,
        content_end,
    })
}

/// Parse DER definite-length at `offset`. Returns `(value, header_bytes)`.
fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x80 {
        None // indefinite-length not supported
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length
                .checked_shl(8)
                .and_then(|l| l.checked_add(data[offset + 1 + i] as usize))?;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Iterate child TLVs within a constructed content region.
fn children(data: &[u8], start: usize, end: usize) -> Vec<Tlv> {
    let mut result = Vec::new();
    let mut pos = start;
    while pos < end {
        if let Some(tlv) = read_tlv(data, pos) {
            result.push(tlv);
            pos = tlv.content_end;
        } else {
            break;
        }
    }
    result
}

/// Children of a TLV (offsets relative to `data`).
fn children_of(data: &[u8], tlv: &Tlv) -> Vec<Tlv> {
    children(data, tlv.content_start, tlv.content_end)
}

/// First child matching `tag`, if any.
fn find_child_by_tag(data: &[u8], parent: &Tlv, tag: u8) -> Option<Tlv> {
    children_of(data, parent).into_iter().find(|c| c.tag == tag)
}

/// Extract TSTInfo from a TimeStampResp or bare ContentInfo.
///
/// Path: TimeStampResp -> ContentInfo -> SignedData -> EncapContentInfo -> eContent.
fn extract_tst_info(data: &[u8]) -> Result<Vec<u8>, AnchorError> {
    let outer = read_tlv(data, 0)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot parse outer SEQUENCE".into()))?;
    if outer.tag != 0x30 {
        return Err(AnchorError::InvalidFormat("Expected SEQUENCE".into()));
    }

    let outer_kids = children_of(data, &outer);
    if outer_kids.is_empty() {
        return Err(AnchorError::InvalidFormat("Empty outer SEQUENCE".into()));
    }

    // First child SEQUENCE => TimeStampResp wrapper; otherwise bare ContentInfo
    let content_info_tlv = if outer_kids[0].tag == 0x30 && outer_kids.len() > 1 {
        // PKIStatusInfo is the first SEQUENCE child; its first child is the status INTEGER.
        let status_seq = &outer_kids[0];
        let status_kids = children_of(data, status_seq);
        if !status_kids.is_empty() && status_kids[0].tag == 0x02 {
            let status_bytes = status_kids[0].content(data);
            let status_val = status_bytes
                .iter()
                .fold(0u32, |acc, &b| acc.saturating_mul(256).saturating_add(b as u32));
            // RFC 3161 s2.4.2: 0 = granted, 1 = grantedWithMods, 2-5 = failure
            if status_val >= 2 {
                return Err(AnchorError::InvalidFormat(format!(
                    "TSA returned failure status {status_val} in PKIStatusInfo"
                )));
            }
        }
        &outer_kids[1]
    } else {
        &outer
    };

    // ContentInfo: SEQUENCE { OID, [0] EXPLICIT content }
    let explicit0 = find_child_by_tag(data, content_info_tlv, 0xA0).ok_or_else(|| {
        AnchorError::InvalidFormat("Cannot find [0] content in ContentInfo".into())
    })?;

    // SignedData SEQUENCE inside [0]
    let signed_data = children_of(data, &explicit0)
        .into_iter()
        .find(|c| c.tag == 0x30)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot find SignedData SEQUENCE".into()))?;

    // Walk SignedData children to find encapContentInfo -> [0] -> OCTET STRING
    for child in children_of(data, &signed_data) {
        if child.tag == 0x30 {
            if let Some(econtent_explicit) = find_child_by_tag(data, &child, 0xA0) {
                if let Some(octet) = find_child_by_tag(data, &econtent_explicit, 0x04) {
                    return Ok(octet.content(data).to_vec());
                }
                return Err(AnchorError::InvalidFormat(
                    "encapContentInfo [0] has no OCTET STRING for TSTInfo".into(),
                ));
            }
        }
    }

    Err(AnchorError::InvalidFormat(
        "Cannot find TSTInfo in CMS envelope".into(),
    ))
}

/// Extract `genTime` (tag 0x18) from TSTInfo.
fn extract_generalized_time(tst_info: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    for child in children(tst_info, inner_start, inner_end) {
        if child.tag == 0x18 {
            if let Ok(s) = std::str::from_utf8(child.content(tst_info)) {
                return parse_generalized_time(s);
            }
        }
    }
    None
}

/// Parse ASN.1 GeneralizedTime (`YYYYMMDDHHMMSS[.frac]Z`) to `DateTime<Utc>`.
fn parse_generalized_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone};
    let s = s.trim_end_matches('Z');

    if let Some((base, frac)) = s.split_once('.') {
        if base.len() == 14 {
            let naive = NaiveDateTime::parse_from_str(base, "%Y%m%d%H%M%S").ok()?;
            let dt = chrono::Utc.from_utc_datetime(&naive);
            // Parse fractional seconds: pad or truncate to 9 digits (nanoseconds)
            let frac_digits: String = frac.chars().take(9).collect();
            let padded = format!("{:0<9}", frac_digits);
            let nanos: u32 = padded.parse().unwrap_or(0);
            return Some(
                dt + chrono::Duration::nanoseconds(i64::from(nanos)),
            );
        }
    }

    if s.len() >= 14 {
        let naive = NaiveDateTime::parse_from_str(&s[..14], "%Y%m%d%H%M%S").ok()?;
        return Some(chrono::Utc.from_utc_datetime(&naive));
    }

    None
}

/// Extract `serialNumber` (4th field, INTEGER) from TSTInfo.
fn extract_serial_number(tst_info: &[u8]) -> Option<String> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    if kids.len() > 3 && kids[3].tag == 0x02 {
        return Some(hex::encode(kids[3].content(tst_info)));
    }
    None
}

/// Extract `nonce` (INTEGER) from TSTInfo.
///
/// TSTInfo fields: version, policy, messageImprint, serialNumber, genTime, [accuracy],
/// [ordering], [nonce]. The nonce is the first INTEGER (tag 0x02) after genTime (tag 0x18).
///
/// RFC 3161 permits nonces of 1-64 bytes. The returned `Vec<u8>` contains the canonical
/// value (leading zero padding from DER encoding is stripped).
fn extract_nonce(tst_info: &[u8]) -> Option<Vec<u8>> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    // Walk past genTime (0x18) and find the next INTEGER (0x02) which is the nonce
    let mut past_gentime = false;
    for child in &kids {
        if child.tag == 0x18 {
            past_gentime = true;
            continue;
        }
        if past_gentime && child.tag == 0x02 {
            let content = child.content(tst_info);
            // RFC 3161 nonces may be 1-64 bytes; reject obviously invalid lengths.
            if content.is_empty() || content.len() > 65 {
                return None;
            }
            // DER INTEGER may have a leading 0x00 sign byte; strip it.
            let canonical = if content.len() > 1 && content[0] == 0x00 {
                &content[1..]
            } else {
                content
            };
            if canonical.is_empty() || canonical.len() > 64 {
                return None;
            }
            return Some(canonical.to_vec());
        }
    }
    None
}

/// Extract `hashedMessage` from the MessageImprint (3rd child) of TSTInfo.
fn extract_message_imprint_hash(tst_info: &[u8]) -> Option<[u8; 32]> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    if kids.len() <= 2 || kids[2].tag != 0x30 {
        return None;
    }

    let imprint_kids = children_of(tst_info, &kids[2]);
    if imprint_kids.len() > 1 && imprint_kids[1].tag == 0x04 {
        let content = imprint_kids[1].content(tst_info);
        if content.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(content);
            return Some(hash);
        }
    }
    None
}

/// Extract `tsa` GeneralName from TSTInfo, if present.
///
/// The tsa field is `[1] GeneralName` (context tag 0xA1). We look for a
/// directoryName (tag 0xA4) or dNSName/rfc822Name (tag 0x82/0x81) inside it.
fn extract_tsa_name(tst_info: &[u8]) -> Option<String> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 { outer.content_start } else { 0 };
    let inner_end = if outer.tag == 0x30 { outer.content_end } else { tst_info.len() };

    for child in children(tst_info, inner_start, inner_end) {
        if child.tag == 0xA1 {
            // Try to find a UTF8String (0x0C) or PrintableString (0x13) inside
            let inner_kids = children_of(tst_info, &child);
            for kid in &inner_kids {
                // directoryName [4] wraps RDNSequence
                if kid.tag == 0xA4 {
                    // Walk RDNSequence → SET → SEQUENCE → value string
                    for rdn_set in children_of(tst_info, kid) {
                        for attr_seq in children_of(tst_info, &rdn_set) {
                            let attr_kids = children_of(tst_info, &attr_seq);
                            if attr_kids.len() >= 2 {
                                let val = &attr_kids[attr_kids.len() - 1];
                                if matches!(val.tag, 0x0C | 0x13 | 0x16) {
                                    if let Ok(s) = std::str::from_utf8(val.content(tst_info)) {
                                        if !s.is_empty() {
                                            return Some(s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // dNSName [2] or rfc822Name [1]
                if matches!(kid.tag, 0x82 | 0x81) {
                    if let Ok(s) = std::str::from_utf8(kid.content(tst_info)) {
                        if !s.is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

// OID content bytes (sans tag+length) for the algorithms we support.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// Navigate from a TimeStampResp or bare ContentInfo to the SignedData SEQUENCE.
fn find_signed_data(data: &[u8]) -> Option<Tlv> {
    let outer = read_tlv(data, 0)?;
    if outer.tag != 0x30 {
        return None;
    }
    let outer_kids = children_of(data, &outer);
    if outer_kids.is_empty() {
        return None;
    }
    // First child SEQUENCE => TimeStampResp; otherwise bare ContentInfo
    let content_info = if outer_kids[0].tag == 0x30 && outer_kids.len() > 1 {
        &outer_kids[1]
    } else {
        &outer
    };
    let explicit0 = find_child_by_tag(data, content_info, 0xA0)?;
    children_of(data, &explicit0)
        .into_iter()
        .find(|c| c.tag == 0x30)
}

/// All Certificate SEQUENCE TLVs from SignedData.certificates [0] IMPLICIT.
fn extract_certs(data: &[u8], signed_data: &Tlv) -> Vec<Tlv> {
    // SignedData [0] IMPLICIT (tag 0xA0) holds certificates; [1] IMPLICIT (0xA1) holds CRLs.
    // The encapContentInfo SEQUENCE also uses child tag 0xA0, but it appears earlier;
    // we want the *last* 0xA0 child that follows the encapContentInfo.
    let kids = children_of(data, signed_data);
    // certificates [0] comes after encapContentInfo (3rd child: version, digestAlgs, encapCI)
    for kid in kids.iter().skip(3) {
        if kid.tag == 0xA0 {
            return children_of(data, kid)
                .into_iter()
                .filter(|c| c.tag == 0x30)
                .collect();
        }
    }
    Vec::new()
}

/// Extract SubjectPublicKeyInfo TLV from a Certificate SEQUENCE.
///
/// Path: Certificate → TBSCertificate → subjectPublicKeyInfo
fn extract_spki(data: &[u8], cert: &Tlv) -> Option<Tlv> {
    let tbs = children_of(data, cert)
        .into_iter()
        .find(|c| c.tag == 0x30)?;
    // subjectPublicKeyInfo is a SEQUENCE { SEQUENCE(AlgId), BIT STRING }
    for child in children_of(data, &tbs) {
        if child.tag == 0x30 {
            let sub = children_of(data, &child);
            if sub.len() >= 2 && sub[0].tag == 0x30 && sub[1].tag == 0x03 {
                return Some(child);
            }
        }
    }
    None
}

struct SignerInfoFields {
    digest_alg_oid: Vec<u8>,
    sig_alg_oid: Vec<u8>,
    /// signedAttrs re-encoded with SET tag (0x31) for signature verification.
    signed_attrs: Option<Vec<u8>>,
    signature: Vec<u8>,
}

fn parse_signer_info(data: &[u8], si: &Tlv) -> Option<SignerInfoFields> {
    let kids = children_of(data, si);
    // version, sid, digestAlgorithm, [signedAttrs], signatureAlgorithm, signature
    if kids.len() < 5 {
        return None;
    }
    if kids[2].tag != 0x30 {
        return None;
    }
    let dig_oid = find_child_by_tag(data, &kids[2], 0x06)?;

    let mut idx = 3;
    let signed_attrs = if idx < kids.len() && kids[idx].tag == 0xA0 {
        let content = kids[idx].content(data);
        let mut sa = Vec::with_capacity(4 + content.len());
        sa.push(0x31); // re-encode as SET for signature verification (RFC 5652 §5.4)
        if !encode_der_length(&mut sa, content.len()) {
            return None;
        }
        sa.extend_from_slice(content);
        idx += 1;
        Some(sa)
    } else {
        None
    };

    if idx >= kids.len() || kids[idx].tag != 0x30 {
        return None;
    }
    let sig_oid = find_child_by_tag(data, &kids[idx], 0x06)?;
    idx += 1;

    if idx >= kids.len() || kids[idx].tag != 0x04 {
        return None;
    }
    let signature = kids[idx].content(data).to_vec();

    Some(SignerInfoFields {
        digest_alg_oid: dig_oid.content(data).to_vec(),
        sig_alg_oid: sig_oid.content(data).to_vec(),
        signed_attrs,
        signature,
    })
}

fn encode_der_length(out: &mut Vec<u8>, len: usize) -> bool {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        return false;
    }
    true
}

fn verify_rsa_pkcs1v15_sha256(
    spki_der: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, AnchorError> {
    use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier, traits::PublicKeyParts};
    let pub_key = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| {
        AnchorError::Verification(format!("Invalid RSA public key DER: {e}"))
    })?;
    if pub_key.size() < 256 {
        return Err(AnchorError::Verification(format!(
            "RSA key too small: {} bits (minimum 2048)",
            pub_key.size() * 8
        )));
    }
    let verifying_key: VerifyingKey<sha2::Sha256> = VerifyingKey::new(pub_key);
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| {
        AnchorError::Verification(format!("Invalid RSA signature encoding: {e}"))
    })?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}

// OID for id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
const OID_KP_TIMESTAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
// OID for id-messageDigest (1.2.840.113549.1.9.4)
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// Check that a certificate's validity period covers `now`.
fn check_cert_validity(data: &[u8], cert: &Tlv) -> Result<(), AnchorError> {
    let tbs = children_of(data, cert)
        .into_iter()
        .find(|c| c.tag == 0x30)
        .ok_or_else(|| AnchorError::Verification("No TBSCertificate".into()))?;
    let tbs_kids = children_of(data, &tbs);
    // Validity is the SEQUENCE after subject/issuer — search for a SEQUENCE containing
    // two time values (UTCTime 0x17 or GeneralizedTime 0x18).
    for kid in &tbs_kids {
        if kid.tag == 0x30 {
            let time_kids = children_of(data, kid);
            if time_kids.len() == 2 && matches!(time_kids[0].tag, 0x17 | 0x18) {
                let not_before = parse_cert_time(data, &time_kids[0]);
                let not_after = parse_cert_time(data, &time_kids[1]);
                if let (Some(nb), Some(na)) = (not_before, not_after) {
                    let now = chrono::Utc::now();
                    if now < nb {
                        return Err(AnchorError::Verification(
                            "TSA certificate not yet valid".into(),
                        ));
                    }
                    if now > na {
                        return Err(AnchorError::Verification(
                            "TSA certificate has expired".into(),
                        ));
                    }
                    return Ok(());
                }
            }
        }
    }
    Err(AnchorError::Verification(
        "Could not parse certificate validity period".into(),
    ))
}

/// Parse a UTCTime (0x17) or GeneralizedTime (0x18) from a cert field.
fn parse_cert_time(data: &[u8], tlv: &Tlv) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(tlv.content(data)).ok()?;
    if tlv.tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ
        use chrono::{NaiveDateTime, TimeZone};
        let s = s.trim_end_matches('Z');
        if s.len() >= 12 {
            let naive = NaiveDateTime::parse_from_str(&s[..12], "%y%m%d%H%M%S").ok()?;
            return Some(chrono::Utc.from_utc_datetime(&naive));
        }
    } else if tlv.tag == 0x18 {
        return parse_generalized_time(s);
    }
    None
}

/// Check that a certificate has id-kp-timeStamping in its extKeyUsage extension.
fn check_cert_ext_key_usage(data: &[u8], cert: &Tlv) -> Result<(), AnchorError> {
    let tbs = children_of(data, cert)
        .into_iter()
        .find(|c| c.tag == 0x30)
        .ok_or_else(|| AnchorError::Verification("No TBSCertificate".into()))?;
    // Extensions are in [3] EXPLICIT (tag 0xA3)
    let ext_wrapper = match find_child_by_tag(data, &tbs, 0xA3) {
        Some(w) => w,
        None => {
            log::warn!(
                "TSA certificate has no extensions; cannot verify extKeyUsage"
            );
            return Ok(());
        }
    };
    // Extensions SEQUENCE inside [3]
    let ext_seq = match children_of(data, &ext_wrapper)
        .into_iter()
        .find(|c| c.tag == 0x30)
    {
        Some(s) => s,
        None => return Ok(()),
    };

    // OID for extKeyUsage: 2.5.29.37
    let oid_eku: &[u8] = &[0x55, 0x1D, 0x25];

    for ext in children_of(data, &ext_seq) {
        if ext.tag != 0x30 {
            continue;
        }
        let ext_kids = children_of(data, &ext);
        if ext_kids.is_empty() || ext_kids[0].tag != 0x06 {
            continue;
        }
        if ext_kids[0].content(data) != oid_eku {
            continue;
        }
        // Found extKeyUsage extension; parse the OCTET STRING value
        for ek in &ext_kids {
            if ek.tag == 0x04 {
                let inner = ek.content(data);
                // Inner is a SEQUENCE of OIDs
                if let Some(seq) = read_tlv(inner, 0) {
                    for oid_tlv in children_of(inner, &seq) {
                        if oid_tlv.tag == 0x06
                            && oid_tlv.content(inner) == OID_KP_TIMESTAMPING
                        {
                            return Ok(());
                        }
                    }
                }
                return Err(AnchorError::Verification(
                    "TSA certificate lacks id-kp-timeStamping in extKeyUsage".into(),
                ));
            }
        }
    }
    // No extKeyUsage extension found — reject per RFC 3161 §2.3
    Err(AnchorError::Verification(
        "TSA certificate missing required extKeyUsage extension (RFC 3161 §2.3)".into(),
    ))
}

/// Extract the messageDigest attribute value from re-encoded signedAttrs bytes.
///
/// The signedAttrs have already been re-encoded with a SET (0x31) tag. We parse the
/// inner Attribute SEQUENCEs looking for OID id-messageDigest (1.2.840.113549.1.9.4)
/// and return the OCTET STRING value.
fn extract_message_digest_from_signed_attrs(signed_attrs: &[u8]) -> Option<Vec<u8>> {
    let outer = read_tlv(signed_attrs, 0)?;
    for attr in children_of(signed_attrs, &outer) {
        if attr.tag != 0x30 {
            continue;
        }
        let attr_kids = children_of(signed_attrs, &attr);
        if attr_kids.len() < 2 || attr_kids[0].tag != 0x06 {
            continue;
        }
        if attr_kids[0].content(signed_attrs) != OID_MESSAGE_DIGEST {
            continue;
        }
        // Value is in a SET (0x31) containing an OCTET STRING (0x04)
        for val_kid in &attr_kids[1..] {
            if val_kid.tag == 0x31 {
                if let Some(octet) = find_child_by_tag(signed_attrs, val_kid, 0x04) {
                    return Some(octet.content(signed_attrs).to_vec());
                }
            }
        }
    }
    None
}

/// Verify the CMS SignedData wrapper: locate SignerInfos, extract the TSA certificate's
/// SubjectPublicKeyInfo, and check the RSA-SHA256 signature over signedAttrs (or eContent).
///
/// NOTE: Full PKIX chain-of-trust validation (path building, revocation checking) is NOT
/// implemented here. That requires a dedicated PKIX library (e.g., webpki or x509-cert).
/// We do check: (a) certificate validity period, (b) extKeyUsage for id-kp-timeStamping,
/// and (c) messageDigest attribute matches SHA-256(TSTInfo).
fn verify_cms_signature(token: &[u8], tst_info: &[u8]) -> Result<bool, AnchorError> {
    let signed_data = find_signed_data(token)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot locate SignedData".into()))?;

    let certs = extract_certs(token, &signed_data);

    // signerInfos is a SET (tag 0x31); it's the last SET child of SignedData
    let signer_infos_set = children_of(token, &signed_data)
        .into_iter()
        .rfind(|c| c.tag == 0x31)
        .ok_or_else(|| AnchorError::InvalidFormat("No signerInfos in SignedData".into()))?;

    let signer_infos: Vec<Tlv> = children_of(token, &signer_infos_set)
        .into_iter()
        .filter(|c| c.tag == 0x30)
        .collect();

    if signer_infos.is_empty() {
        return Err(AnchorError::InvalidFormat("Empty signerInfos".into()));
    }

    let mut last_error: Option<AnchorError> = None;

    for si in &signer_infos {
        let fields = match parse_signer_info(token, si) {
            Some(f) => f,
            None => continue,
        };

        if fields.sig_alg_oid != OID_SHA256_WITH_RSA || fields.digest_alg_oid != OID_SHA256 {
            last_error = Some(AnchorError::Unavailable(
                "TSA uses non-RSA/SHA256 algorithm; CMS signature verification not supported"
                    .into(),
            ));
            continue;
        }

        // Verify messageDigest attribute matches SHA-256(TSTInfo) when signedAttrs present
        if let Some(ref sa) = fields.signed_attrs {
            if let Some(md) = extract_message_digest_from_signed_attrs(sa) {
                use sha2::Digest;
                let computed = sha2::Sha256::digest(tst_info);
                if md.ct_eq(computed.as_slice()).unwrap_u8() != 1 {
                    last_error = Some(AnchorError::Verification(
                        "messageDigest attribute does not match SHA-256(TSTInfo)".into(),
                    ));
                    continue;
                }
            }
        }

        let message: &[u8] = fields.signed_attrs.as_deref().unwrap_or(tst_info);

        for cert in &certs {
            if let Some(spki) = extract_spki(token, cert) {
                match verify_rsa_pkcs1v15_sha256(
                    spki.as_bytes(token),
                    message,
                    &fields.signature,
                ) {
                    Ok(true) => {
                        // Signature matches this cert — validate cert properties
                        check_cert_validity(token, cert)?;
                        check_cert_ext_key_usage(token, cert)?;
                        return Ok(true);
                    }
                    Ok(false) => continue,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                }
            }
        }

        if last_error.is_none() {
            last_error = Some(AnchorError::Verification(
                "CMS signature verification failed: no matching TSA certificate".into(),
            ));
        }
    }

    Err(last_error.unwrap_or_else(|| {
        AnchorError::InvalidFormat("No parseable SignerInfo found".into())
    }))
}

struct TimestampInfo {
    timestamp: chrono::DateTime<chrono::Utc>,
    serial_number: String,
    tsa_name: String,
}

#[async_trait]
impl AnchorProvider for Rfc3161Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Rfc3161
    }

    fn name(&self) -> &str {
        "RFC 3161 TSA"
    }

    async fn is_available(&self) -> bool {
        // Use a shorter timeout than the shared client's 30s default
        // to avoid blocking callers on a simple availability check.
        let timeout = std::time::Duration::from_secs(5);
        for url in &self.tsa_urls {
            let result = tokio::time::timeout(timeout, self.client.head(url).send()).await;
            if let Ok(Ok(resp)) = result {
                if resp.status().is_success() || resp.status().as_u16() == 405 {
                    return true;
                }
            }
        }
        false
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let mut last_error = None;

        for url in &self.tsa_urls {
            match self.request_timestamp(url, hash).await {
                Ok(token) => {
                    let info = self.parse_timestamp_response(&token)?;
                    return Ok(Proof {
                        id: format!("rfc3161-{}", info.serial_number),
                        provider: ProviderType::Rfc3161,
                        status: ProofStatus::Confirmed,
                        anchored_hash: *hash,
                        // Local clock time of submission; TSA-attested time is in confirmed_at.
                        submitted_at: chrono::Utc::now(),
                        confirmed_at: Some(info.timestamp),
                        proof_data: token,
                        location: Some(url.clone()),
                        attestation_path: None,
                        extra: [
                            ("tsa".to_string(), serde_json::json!(info.tsa_name)),
                            ("serial".to_string(), serde_json::json!(info.serial_number)),
                        ]
                        .into_iter()
                        .collect(),
                    });
                }
                Err(e) => {
                    log::debug!("TSA {} failed: {e}", url);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            log::warn!("RFC 3161 submit failed: no TSA URLs configured");
            AnchorError::Unavailable("All TSAs failed".into())
        }))
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        Ok(proof.clone())
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        self.verify_timestamp_token(&proof.proof_data, &proof.anchored_hash)
    }
}

impl Rfc3161Provider {
    /// Create a provider using well-known public TSA endpoints.
    pub fn with_defaults() -> Result<Self, AnchorError> {
        Self::new(DEFAULT_TSA_URLS.iter().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_default_provider_init() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        assert!(!provider.tsa_urls.is_empty());
        assert!(provider.tsa_urls[0].contains("http"));
    }

    #[test]
    fn test_verify_token_too_short() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let token = vec![0u8; 50];
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Token too short"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_invalid_asn1() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0xFF;
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Invalid ASN.1 structure"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_unparseable_tst_info_returns_err() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0x30;
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_length_parsing() {
        assert_eq!(read_der_length(&[0x05], 0), Some((5, 1)));
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00], 0), Some((256, 3)));
        assert_eq!(read_der_length(&[0x81, 0x80], 0), Some((128, 2)));
    }

    #[test]
    fn test_der_length_overflow() {
        // 4-byte length 0xFF_FF_FF_FF overflows on 32-bit targets
        let data = [0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = read_der_length(&data, 0);
        if usize::BITS == 32 {
            assert_eq!(result, None, "should reject overflow on 32-bit");
        } else {
            // 64-bit: length parses but read_tlv rejects (exceeds buffer)
            assert!(result.is_some());
            let tlv = read_tlv(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], 0);
            assert!(tlv.is_none(), "content_end exceeds data length");
        }
    }

    #[test]
    fn test_parse_generalized_time() {
        let dt = parse_generalized_time("20250101120000Z");
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 2025);

        let dt2 = parse_generalized_time("20250615153045.123Z");
        assert!(dt2.is_some());
    }
}
