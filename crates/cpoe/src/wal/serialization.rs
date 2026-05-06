// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::types::*;

pub(super) fn serialize_header(header: &Header) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0..4].copy_from_slice(&header.magic);
    buf[4..8].copy_from_slice(&header.version.to_be_bytes());
    buf[8..40].copy_from_slice(&header.session_id);
    buf[40..48].copy_from_slice(&header.created_at.to_be_bytes());
    buf[48..56].copy_from_slice(&header.last_checkpoint_seq.to_be_bytes());
    buf[56..64].copy_from_slice(&header.reserved);
    buf
}

pub(super) fn deserialize_header(data: &[u8]) -> Result<Header, WalError> {
    if data.len() < HEADER_SIZE {
        return Err(WalError::Serialization("header too short".to_string()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);
    let version = u32::from_be_bytes(
        data[4..8]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    );
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[8..40]);
    let created_at = i64::from_be_bytes(
        data[40..48]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    );
    let last_checkpoint_seq = u64::from_be_bytes(
        data[48..56]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    );
    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&data[56..64]);

    Ok(Header {
        magic,
        version,
        session_id,
        created_at,
        last_checkpoint_seq,
        reserved,
    })
}

pub(super) fn serialize_entry(entry: &Entry) -> Result<Vec<u8>, WalError> {
    let payload_len = entry.payload.len();
    if payload_len > u32::MAX as usize {
        return Err(WalError::Serialization(format!(
            "payload too large: {} bytes exceeds u32::MAX",
            payload_len
        )));
    }
    // sequence(8) + timestamp(8) + type(1) + payload_len(4) + payload(N) + prev_hash(32) + cumulative_hash(32) + signature(64)
    let size = 8 + 8 + 1 + 4 + payload_len + 32 + 32 + 64;
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;

    buf[offset..offset + 8].copy_from_slice(&entry.sequence.to_be_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&entry.timestamp.to_be_bytes());
    offset += 8;
    buf[offset] = entry.entry_type as u8;
    offset += 1;
    buf[offset..offset + 4].copy_from_slice(&(payload_len as u32).to_be_bytes());
    offset += 4;
    buf[offset..offset + payload_len].copy_from_slice(&entry.payload);
    offset += payload_len;
    buf[offset..offset + 32].copy_from_slice(&entry.prev_hash);
    offset += 32;
    buf[offset..offset + 32].copy_from_slice(&entry.cumulative_hash);
    offset += 32;
    buf[offset..offset + 64].copy_from_slice(&entry.signature);

    Ok(buf)
}

pub(super) fn deserialize_entry(data: &[u8]) -> Result<Entry, WalError> {
    if data.len() < 8 + 8 + 1 + 4 + 32 + 32 + 64 {
        return Err(WalError::Serialization("entry too short".to_string()));
    }
    let mut offset = 0usize;
    let sequence = u64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    );
    offset += 8;
    let timestamp = i64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    );
    offset += 8;
    let entry_type = EntryType::try_from(data[offset])?;
    offset += 1;
    let payload_len = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| WalError::Serialization(e.to_string()))?,
    ) as usize;
    offset += 4;

    if data.len() < offset + payload_len + 32 + 32 + 64 {
        return Err(WalError::Serialization("entry truncated".to_string()));
    }

    let payload = data[offset..offset + payload_len].to_vec();
    offset += payload_len;
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut cumulative_hash = [0u8; 32];
    cumulative_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[offset..offset + 64]);

    Ok(Entry {
        length: (offset + 64) as u32,
        sequence,
        timestamp,
        entry_type,
        payload,
        prev_hash,
        cumulative_hash,
        signature,
    })
}

pub(super) fn now_nanos() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    i64::try_from(dur.as_nanos()).unwrap_or_else(|_| {
        log::error!("WAL timestamp overflow: system clock beyond year 2262, using i64::MAX");
        i64::MAX
    })
}
