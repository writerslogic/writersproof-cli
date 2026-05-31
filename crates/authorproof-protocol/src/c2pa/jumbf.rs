// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use serde::Serialize;

use super::types::{C2paManifest, JumbfInfo};

/// C2PA manifest store superbox UUID (C2PA 2.2 §8.1).
const C2PA_MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, // "c2pa"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_MANIFEST_UUID: [u8; 16] = [
    0x63, 0x32, 0x6D, 0x61, // "c2ma"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_CLAIM_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x6C, // "c2cl"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_ASSERTION_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x61, 0x73, // "c2as"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_SIGNATURE_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x73, // "c2cs"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// ISO 19566-5
const JUMBF_CBOR_UUID: [u8; 16] = [
    0x63, 0x62, 0x6F, 0x72, // "cbor"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// ISO 19566-5
const JUMBF_JSON_UUID: [u8; 16] = [
    0x6A, 0x73, 0x6F, 0x6E, // "json"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// Minimal JUMBF box writer (ISO 19566-5).
struct JumbfWriter {
    buf: Vec<u8>,
}

impl JumbfWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    fn write_description(
        &mut self,
        uuid: &[u8; 16],
        label: Option<&str>,
        toggles: u8,
    ) -> std::result::Result<(), Error> {
        let label_bytes = label.map(|l| l.as_bytes());
        let label_len = label_bytes.map_or(0, |b| b.len() + 1); // NUL terminator
        let box_len = 8usize
            .checked_add(16 + 1 + label_len)
            .and_then(|sum| u32::try_from(sum).ok())
            .ok_or_else(|| Error::Validation("JUMBF box too large".into()))?;
        self.write_box_header(box_len, b"jumd");
        self.buf.extend_from_slice(uuid);
        self.buf.push(toggles);
        if let Some(bytes) = label_bytes {
            self.buf.extend_from_slice(bytes);
            self.buf.push(0);
        }
        Ok(())
    }

    fn write_content(&mut self, data: &[u8], box_type: &[u8; 4]) -> std::result::Result<(), Error> {
        let box_len = 8usize
            .checked_add(data.len())
            .and_then(|sum| u32::try_from(sum).ok())
            .ok_or_else(|| Error::Validation("JUMBF box too large".into()))?;
        self.write_box_header(box_len, box_type);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn write_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns offset for back-patching length.
    fn begin_superbox(&mut self) -> usize {
        let offset = self.buf.len();
        self.write_box_header(0, b"jumb");
        offset
    }

    fn end_superbox(&mut self, offset: usize) -> std::result::Result<(), Error> {
        let total_len = u32::try_from(self.buf.len() - offset)
            .map_err(|_| Error::Validation("JUMBF box too large".into()))?;
        self.buf[offset..offset + 4].copy_from_slice(&total_len.to_be_bytes());
        Ok(())
    }

    fn write_box_header(&mut self, size: u32, box_type: &[u8; 4]) {
        self.buf.extend_from_slice(&size.to_be_bytes());
        self.buf.extend_from_slice(box_type);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub fn build_assertion_jumbf_json<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    let content = serde_json::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))?;
    build_assertion_jumbf(label, &JUMBF_JSON_UUID, &content, false)
}

pub fn build_assertion_jumbf_cbor<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    let content = ciborium_to_vec(value)?;
    build_assertion_jumbf(label, &JUMBF_CBOR_UUID, &content, true)
}

fn build_assertion_jumbf(
    label: &str,
    uuid: &[u8; 16],
    content: &[u8],
    is_cbor: bool,
) -> Result<Vec<u8>> {
    let mut w = JumbfWriter::new();
    let off = w.begin_superbox();
    w.write_description(uuid, Some(label), 0x03)?;
    if is_cbor {
        w.write_content(content, b"cbor")?;
    } else {
        w.write_content(content, b"json")?;
    }
    w.end_superbox(off)?;
    Ok(w.finish())
}

pub fn ciborium_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Error::Serialization(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

pub fn encode_jumbf(manifest: &C2paManifest) -> Result<Vec<u8>> {
    let mut w = JumbfWriter::new();

    let store_off = w.begin_superbox();
    w.write_description(&C2PA_MANIFEST_STORE_UUID, Some("c2pa"), 0x03)?;

    let manifest_off = w.begin_superbox();
    w.write_description(&C2PA_MANIFEST_UUID, Some(&manifest.manifest_label), 0x03)?;

    // §15.6: Use pre-serialized claim bytes to match signed payload exactly.
    let claim_off = w.begin_superbox();
    w.write_description(&C2PA_CLAIM_UUID, Some("c2pa.claim.v2"), 0x03)?;
    w.write_content(&manifest.claim_cbor, b"cbor")?;
    w.end_superbox(claim_off)?;

    let astore_off = w.begin_superbox();
    w.write_description(&C2PA_ASSERTION_STORE_UUID, Some("c2pa.assertions"), 0x03)?;
    for assertion_box in &manifest.assertion_boxes {
        w.write_raw(assertion_box);
    }
    w.end_superbox(astore_off)?;

    let sig_off = w.begin_superbox();
    w.write_description(&C2PA_SIGNATURE_UUID, Some("c2pa.signature"), 0x03)?;
    w.write_content(&manifest.signature, b"cbor")?;
    w.end_superbox(sig_off)?;

    w.end_superbox(manifest_off)?;
    w.end_superbox(store_off)?;

    Ok(w.finish())
}

/// Decode a JUMBF manifest store into a `C2paManifest`.
///
/// Parses the box hierarchy produced by `encode_jumbf`, extracting the claim
/// CBOR, assertion boxes, signature, and manifest label.
pub fn decode_jumbf(data: &[u8]) -> Result<C2paManifest> {
    use super::types::C2paClaim;

    fn read_box(data: &[u8], offset: usize) -> Result<(usize, &[u8], &[u8])> {
        if offset + 8 > data.len() {
            return Err(Error::Validation("Truncated JUMBF box header".into()));
        }
        let compact = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        let (box_len, hdr) = if compact == 1 {
            if offset + 16 > data.len() {
                return Err(Error::Validation("Truncated extended-size box".into()));
            }
            let ext = u64::from_be_bytes([
                data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
            ]) as usize;
            (ext, 16)
        } else {
            (compact as usize, 8)
        };
        if box_len < hdr || offset + box_len > data.len() {
            return Err(Error::Validation(format!(
                "Invalid box length {box_len} at offset {offset}"
            )));
        }
        let box_type = &data[offset + 4..offset + 8];
        let body = &data[offset + hdr..offset + box_len];
        Ok((box_len, box_type, body))
    }

    fn extract_uuid_from_jumd(body: &[u8]) -> Result<[u8; 16]> {
        if body.len() < 17 {
            return Err(Error::Validation("jumd box too short for UUID".into()));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&body[..16]);
        Ok(uuid)
    }

    fn extract_label_from_jumd(body: &[u8]) -> Option<String> {
        if body.len() <= 17 {
            return None;
        }
        let label_start = 17; // 16 UUID + 1 toggles
        let label_bytes = &body[label_start..];
        let end = label_bytes.iter().position(|&b| b == 0).unwrap_or(label_bytes.len());
        if end == 0 {
            return None;
        }
        String::from_utf8(label_bytes[..end].to_vec()).ok()
    }

    fn find_content_in_superbox<'a>(body: &'a [u8], content_type: &[u8; 4]) -> Option<&'a [u8]> {
        let mut off = 0;
        while off + 8 <= body.len() {
            let len = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]) as usize;
            if len < 8 || off + len > body.len() {
                break;
            }
            let btype = &body[off + 4..off + 8];
            if btype == content_type {
                return Some(&body[off + 8..off + len]);
            }
            off += len;
        }
        None
    }

    // Parse outer store superbox.
    let (_store_len, store_type, _) = read_box(data, 0)?;
    if store_type != b"jumb" {
        return Err(Error::Validation("Expected JUMBF superbox at start".into()));
    }

    // Iterate children of the store to find the manifest superbox.
    let mut pos = 8; // skip store box header
    // Skip store's jumd description.
    let (jumd_len, jumd_type, _) = read_box(data, pos)?;
    if jumd_type != b"jumd" {
        return Err(Error::Validation("Store missing description box".into()));
    }
    pos += jumd_len;

    // The next jumb child is the manifest superbox.
    let (manifest_len, manifest_type, _) = read_box(data, pos)?;
    if manifest_type != b"jumb" {
        return Err(Error::Validation("Expected manifest superbox".into()));
    }
    let manifest_end = pos + manifest_len;

    // Parse manifest children: jumd (label), then claim/assertion-store/signature superboxes.
    let mut mpos = pos + 8; // skip manifest box header

    // Manifest jumd.
    let (mjumd_len, mjumd_type, mjumd_body) = read_box(data, mpos)?;
    if mjumd_type != b"jumd" {
        return Err(Error::Validation("Manifest missing description box".into()));
    }
    let manifest_label = extract_label_from_jumd(mjumd_body)
        .unwrap_or_else(|| "self#jumbf=c2pa/urn:uuid:unknown".to_string());
    mpos += mjumd_len;

    let mut claim_cbor: Option<Vec<u8>> = None;
    let mut assertion_boxes: Vec<Vec<u8>> = Vec::new();
    let mut signature: Option<Vec<u8>> = None;

    while mpos + 8 <= manifest_end {
        let (child_len, child_type, child_body) = read_box(data, mpos)?;
        if child_type == b"jumb" {
            // Identify by jumd UUID.
            if child_body.len() >= 8 {
                let (jumd_l, jumd_t, jumd_b) = read_box(data, mpos + 8)?;
                if jumd_t == b"jumd" {
                    if let Ok(uuid) = extract_uuid_from_jumd(jumd_b) {
                        if uuid == C2PA_CLAIM_UUID {
                            if let Some(content) = find_content_in_superbox(child_body, b"cbor") {
                                claim_cbor = Some(content.to_vec());
                            }
                        } else if uuid == C2PA_ASSERTION_STORE_UUID {
                            // Extract individual assertion superboxes after jumd.
                            let mut apos = jumd_l;
                            while apos + 8 <= child_body.len() {
                                let alen = u32::from_be_bytes([
                                    child_body[apos], child_body[apos + 1],
                                    child_body[apos + 2], child_body[apos + 3],
                                ]) as usize;
                                if alen < 8 || apos + alen > child_body.len() {
                                    break;
                                }
                                assertion_boxes.push(child_body[apos..apos + alen].to_vec());
                                apos += alen;
                            }
                        } else if uuid == C2PA_SIGNATURE_UUID {
                            if let Some(content) = find_content_in_superbox(child_body, b"cbor") {
                                signature = Some(content.to_vec());
                            }
                        }
                    }
                }
            }
        }
        mpos += child_len;
    }

    let claim_cbor = claim_cbor.ok_or_else(|| Error::Validation("Missing claim box".into()))?;
    let signature = signature.ok_or_else(|| Error::Validation("Missing signature box".into()))?;

    let claim: C2paClaim = ciborium::from_reader(claim_cbor.as_slice())
        .map_err(|e| Error::Serialization(format!("Failed to decode claim CBOR: {e}")))?;

    Ok(C2paManifest {
        claim,
        claim_cbor,
        manifest_label,
        assertion_boxes,
        signature,
    })
}

pub fn verify_jumbf_structure(data: &[u8]) -> Result<JumbfInfo> {
    if data.len() < 8 {
        return Err(Error::Validation("JUMBF data too short".to_string()));
    }

    let compact_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // ISO 14496-12: box_len == 1 means extended size in the next 8 bytes.
    let (box_len, header_size) = if compact_len == 1 {
        if data.len() < 16 {
            return Err(Error::Validation(
                "JUMBF extended-size box too short".to_string(),
            ));
        }
        let ext = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]) as usize;
        (ext, 16usize)
    } else {
        (compact_len as usize, 8usize)
    };

    if box_len > data.len() {
        return Err(Error::Validation(
            "JUMBF box length exceeds data".to_string(),
        ));
    }

    let box_type = &data[4..8];
    if box_type != b"jumb" {
        return Err(Error::Validation(format!(
            "Expected JUMBF superbox, got {:?}",
            String::from_utf8_lossy(box_type)
        )));
    }

    let mut offset = header_size;
    let mut found_jumd = false;
    let mut child_count = 0u32;

    while offset + 8 <= box_len {
        let child_compact = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        // Handle extended-size child boxes (ISO 14496-12).
        let (child_len, child_header) = if child_compact == 1 {
            if offset + 16 > box_len {
                return Err(Error::Validation(format!(
                    "Extended-size child box truncated at offset {offset}"
                )));
            }
            let ext = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]) as usize;
            (ext, 16usize)
        } else {
            (child_compact as usize, 8usize)
        };
        if child_len < child_header || offset + child_len > box_len {
            return Err(Error::Validation(format!(
                "Invalid child box length {child_len} at offset {offset}"
            )));
        }
        let child_type = &data[offset + 4..offset + 8];
        if child_type == b"jumd" {
            found_jumd = true;
        }
        child_count += 1;
        offset = offset
            .checked_add(child_len)
            .ok_or_else(|| Error::Validation("JUMBF child box offset overflow".into()))?;
    }

    if !found_jumd {
        return Err(Error::Validation(
            "Manifest store missing description box".to_string(),
        ));
    }

    Ok(JumbfInfo {
        total_size: box_len,
        child_boxes: child_count,
    })
}
