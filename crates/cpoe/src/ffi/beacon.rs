// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{
    load_api_key, load_did, load_events_for_path, load_signing_key, open_store, validate_path_str,
};
use crate::ffi::types::{catch_ffi_panic, try_ffi};
use std::sync::OnceLock;

/// Maximum evidence file size for FFI reads (64 MB).
const MAX_EVIDENCE_FILE_SIZE: u64 = 64 * 1024 * 1024;

fn read_bounded(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;
    let len = file
        .metadata()
        .map_err(|e| format!("Failed to stat file: {e}"))?
        .len();
    if len > MAX_EVIDENCE_FILE_SIZE {
        return Err(format!(
            "File too large ({} bytes, max {})",
            len, MAX_EVIDENCE_FILE_SIZE
        ));
    }
    let mut buf = Vec::with_capacity(len as usize);
    file.take(MAX_EVIDENCE_FILE_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read file: {e}"))?;
    if buf.len() as u64 > MAX_EVIDENCE_FILE_SIZE {
        return Err(format!("File grew during read ({} bytes)", buf.len()));
    }
    Ok(buf)
}

static BEACON_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Returns a shared tokio runtime for beacon/anchor network operations.
/// Note: the early-return `get()` + fallback `get_or_init` pattern has a benign
/// race where two concurrent callers may both build a runtime, but only one is
/// stored; the other is dropped. This wastes a runtime construction but is safe.
/// Replace with `get_or_try_init` when MSRV reaches 1.82.
pub(crate) fn beacon_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    if let Some(rt) = BEACON_RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("cpoe-beacon")
        .build()
        .map_err(|e| format!("Failed to create beacon tokio runtime: {e}"))?;
    Ok(BEACON_RUNTIME.get_or_init(|| rt))
}

// BEACON_RUNTIME is intentionally leaked (process-lifetime static).
// `OnceLock` does not support `take`, and both `shutdown_background()`
// and `shutdown_timeout()` consume `self` by value, so there is no way
// to shut down a `&Runtime` obtained from `OnceLock::get()`.
// Tokio runtimes clean up their worker threads when dropped, which
// happens at process exit when the static is reclaimed.

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBeaconResult {
    pub success: bool,
    pub anchor_id: Option<String>,
    pub timestamp_epoch_ms: Option<i64>,
    pub drand_round: Option<u64>,
    pub nist_pulse: Option<u64>,
    pub wp_signature_hex: Option<String>,
    pub verification_url: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBeaconListResult {
    pub success: bool,
    pub beacons: Vec<FfiBeaconResult>,
    pub error_message: Option<String>,
}

fn err_beacon(msg: String) -> FfiBeaconResult {
    FfiBeaconResult {
        success: false,
        anchor_id: None,
        timestamp_epoch_ms: None,
        drand_round: None,
        nist_pulse: None,
        wp_signature_hex: None,
        verification_url: None,
        error_message: Some(msg),
    }
}

crate::ffi::types::impl_ffi_err!(FfiBeaconResult);
crate::ffi::types::impl_ffi_err!(FfiBeaconListResult);

fn beacon_sidecar_path(document_path: &str) -> Option<std::path::PathBuf> {
    let data_dir = crate::ffi::helpers::get_data_dir()?;
    let doc_id = crate::utils::document_id_from_path(std::path::Path::new(document_path));
    Some(data_dir.join(format!("{doc_id}.beacon.json")))
}

fn save_beacon_attestation(
    document_path: &str,
    attestation: &crate::evidence::WpBeaconAttestation,
) -> Result<(), String> {
    let sidecar =
        beacon_sidecar_path(document_path).ok_or_else(|| "data dir not configured".to_string())?;
    let json = serde_json::to_vec(attestation)
        .map_err(|e| format!("beacon JSON serialization failed: {e}"))?;
    crate::ffi::helpers::atomic_write(&sidecar, &json)
}

pub(crate) fn load_beacon_attestation(
    document_path: &str,
) -> Option<crate::evidence::WpBeaconAttestation> {
    let sidecar = beacon_sidecar_path(document_path)?;
    let data = std::fs::read(&sidecar).ok()?;
    serde_json::from_slice(&data)
        .map_err(|e| log::warn!("beacon sidecar parse failed: {e}"))
        .ok()
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_submit_beacon(document_path: String, timeout_secs: u64) -> FfiBeaconResult {
    catch_ffi_panic!(@err FfiBeaconResult, {
    log::debug!("ffi_submit_beacon: document_path={} timeout_secs={}", document_path, timeout_secs);
    let (canonical, _store, events) =
        try_ffi!(load_events_for_path(&document_path), FfiBeaconResult);

    let latest = match events.last() {
        Some(ev) => ev,
        None => return err_beacon("No checkpoints found for this document".to_string()),
    };

    let checkpoint_hash = hex::encode(latest.event_hash);
    // EH-011: evidence_hash must bind to the document content, not duplicate event_hash.
    let evidence_hash = hex::encode(latest.content_hash);

    let (signature, verifying_key_bytes) = {
        let signing_key = try_ffi!(load_signing_key(), FfiBeaconResult);
        use sha2::{Digest, Sha256};
        // Domain-separated signing over evidence_hash (content_hash). The server
        // receives evidence_hash in AnchorRequest and can reconstruct this message
        // to verify the signature. The DST prevents cross-context replay.
        let mut msg = Sha256::new();
        msg.update(b"cpoe-beacon-anchor-v1");
        msg.update(latest.content_hash.as_slice());
        let digest = msg.finalize();
        let sig = super::conv::sign_hex(&signing_key, &digest);
        let vk = *signing_key.verifying_key().as_bytes();
        (sig, vk)
        // signing_key drops and zeroizes here
    };

    let did = match load_did() {
        Ok(d) => d,
        Err(e) => {
            log::debug!("DID from identity.json unavailable: {e}; deriving from signing key");
            crate::identity::did_key_from_public(&verifying_key_bytes)
                .unwrap_or_else(|| "unknown".into())
        }
    };
    let api_key = try_ffi!(
        load_api_key().map_err(|e| format!("WritersProof API key not configured. {e}")),
        FfiBeaconResult
    );
    if api_key.trim().is_empty() {
        return err_beacon("WritersProof API key is empty".to_string());
    }

    let rt = try_ffi!(
        beacon_runtime().map_err(|e| format!("Failed to create async runtime: {e}")),
        FfiBeaconResult
    );

    if timeout_secs < 5 {
        log::warn!("ffi_submit_beacon: timeout_secs {timeout_secs} below minimum 5; using 5");
    }
    let effective_timeout = timeout_secs.clamp(5, 120);

    let client = try_ffi!(
        crate::writersproof::WritersProofClient::new(crate::writersproof::client::DEFAULT_API_URL)
            .map_err(|e| format!("Failed to create API client: {e}")),
        FfiBeaconResult
    )
    .with_jwt(api_key);

    let result = rt.block_on(async {
        let beacon_future = client.fetch_beacon(&checkpoint_hash, effective_timeout);

        let anchor_future = async {
            use crate::writersproof::{AnchorMetadata, AnchorRequest};

            let doc_name = std::path::Path::new(&canonical)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());

            client
                .anchor(AnchorRequest {
                    evidence_hash: evidence_hash.clone(),
                    author_did: did.clone(),
                    signature: signature.clone(),
                    metadata: Some(AnchorMetadata {
                        document_name: doc_name,
                        tier: Some("beacon".into()),
                    }),
                })
                .await
        };

        let timeout = std::time::Duration::from_secs(effective_timeout);
        tokio::time::timeout(timeout, async {
            let (beacon_res, anchor_res) = tokio::join!(beacon_future, anchor_future);
            (beacon_res, anchor_res)
        })
        .await
    });

    match result {
        Err(_) => err_beacon(format!(
            "Beacon request timed out after {effective_timeout}s"
        )),
        Ok((beacon_res, anchor_res)) => {
            let anchor_id = anchor_res
                .map_err(|e| log::warn!("beacon anchor request failed: {e}"))
                .ok()
                .map(|r| r.anchor_id);

            match beacon_res {
                Err(e) => err_beacon(format!("Beacon fetch failed: {e}")),
                Ok(beacon) => {
                    let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
                        .map(|dt| dt.timestamp_millis())
                        .map_err(|e| log::warn!("beacon timestamp parse failed: {e}"))
                        .ok();

                    // Persist beacon attestation so evidence export can attach it.
                    let attestation = crate::evidence::WpBeaconAttestation {
                        drand_round: beacon.drand_round,
                        drand_randomness: beacon.drand_randomness.clone(),
                        nist_pulse_index: beacon.nist_pulse_index,
                        nist_output_value: beacon.nist_output_value.clone(),
                        nist_timestamp: beacon.nist_timestamp.clone(),
                        fetched_at: beacon.fetched_at.clone(),
                        wp_signature: beacon.wp_signature.clone(),
                        wp_key_id: None,
                    };
                    if let Err(e) = save_beacon_attestation(&canonical, &attestation) {
                        log::warn!("Failed to persist beacon attestation for {canonical}: {e}");
                    }

                    let anchor_error = if anchor_id.is_none() {
                        Some("Beacon fetched but anchor submission failed; evidence not yet in transparency log".to_string())
                    } else {
                        None
                    };

                    FfiBeaconResult {
                        success: anchor_id.is_some(),
                        verification_url: anchor_id
                            .as_ref()
                            .map(|id| format!("https://verify.writersproof.com/{id}")),
                        anchor_id,
                        timestamp_epoch_ms: ts_ms,
                        drand_round: Some(beacon.drand_round),
                        nist_pulse: Some(beacon.nist_pulse_index),
                        wp_signature_hex: Some(beacon.wp_signature),
                        error_message: anchor_error,
                    }
                }
            }
        }
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_check_beacon_status(document_path: String) -> FfiBeaconResult {
    catch_ffi_panic!(@err FfiBeaconResult, {
    log::debug!("ffi_check_beacon_status: document_path={}", document_path);
    let canonical = try_ffi!(validate_path_str(&document_path), FfiBeaconResult);
    let data = try_ffi!(read_bounded(&canonical), FfiBeaconResult);
    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(&data);

    let packet = match crate::evidence::Packet::decode(&cbor_payload) {
        Ok(p) => p,
        Err(_) => {
            return check_beacon_from_store(&canonical);
        }
    };

    match packet.beacon_attestation {
        Some(beacon) => {
            let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
                .map(|dt| dt.timestamp_millis())
                .map_err(|e| log::warn!("beacon timestamp parse failed: {e}"))
                .ok();

            FfiBeaconResult {
                success: true,
                anchor_id: None,
                timestamp_epoch_ms: ts_ms,
                drand_round: Some(beacon.drand_round),
                nist_pulse: Some(beacon.nist_pulse_index),
                wp_signature_hex: Some(beacon.wp_signature),
                verification_url: None,
                error_message: None,
            }
        }
        None => FfiBeaconResult {
            success: false,
            anchor_id: None,
            timestamp_epoch_ms: None,
            drand_round: None,
            nist_pulse: None,
            wp_signature_hex: None,
            verification_url: None,
            error_message: Some("No beacon attestation found in evidence".to_string()),
        },
    }
    })
}

fn check_beacon_from_store(canonical: &str) -> FfiBeaconResult {
    let store = try_ffi!(open_store(), FfiBeaconResult);
    let events = try_ffi!(
        store
            .get_events_for_file(canonical)
            .map_err(|e| format!("Failed to load events: {e}")),
        FfiBeaconResult
    );

    if events.is_empty() {
        return err_beacon("No checkpoints found for this document".to_string());
    }

    FfiBeaconResult {
        success: false,
        anchor_id: None,
        timestamp_epoch_ms: None,
        drand_round: None,
        nist_pulse: None,
        wp_signature_hex: None,
        verification_url: None,
        error_message: Some("No beacon attestation submitted yet".to_string()),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_beacons(document_path: String) -> FfiBeaconListResult {
    catch_ffi_panic!(@err FfiBeaconListResult, {
    log::debug!("ffi_list_beacons: document_path={}", document_path);
    let canonical = try_ffi!(validate_path_str(&document_path), FfiBeaconListResult);
    let data = try_ffi!(read_bounded(&canonical), FfiBeaconListResult);

    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(&data);
    let packet = match crate::evidence::Packet::decode(&cbor_payload) {
        Ok(p) => p,
        Err(e) => {
            return FfiBeaconListResult {
                success: false,
                beacons: vec![],
                error_message: Some(format!("Failed to decode evidence packet: {e}")),
            };
        }
    };

    let mut beacons = Vec::new();
    if let Some(beacon) = packet.beacon_attestation {
        let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
            .map(|dt| dt.timestamp_millis())
            .map_err(|e| log::warn!("beacon timestamp parse failed: {e}"))
            .ok();

        beacons.push(FfiBeaconResult {
            success: true,
            anchor_id: None,
            timestamp_epoch_ms: ts_ms,
            drand_round: Some(beacon.drand_round),
            nist_pulse: Some(beacon.nist_pulse_index),
            wp_signature_hex: Some(beacon.wp_signature),
            verification_url: None,
            error_message: None,
        });
    }

    FfiBeaconListResult {
        success: true,
        beacons,
        error_message: None,
    }
    })
}
