// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, open_store};
use crate::ffi::sentinel::get_sentinel;
use crate::ffi::types::{try_ffi, FfiResult};
use crate::RwLockRecover;
use authorproof_protocol::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, HashValue, ProcessProof,
    ProofAlgorithm, ProofParams,
};
use sha2::{Digest, Sha256};

/// Export stored events as a human-readable JSON evidence packet.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence_json(path: String, tier: String, output: String) -> FfiResult {
    // Build the same wire packet as the CBOR export, then serialize to JSON.
    let cbor_result = ffi_export_evidence(path.clone(), tier, output.clone());
    if !cbor_result.success {
        return cbor_result;
    }
    // Read the CBOR file we just wrote, decode, re-encode as JSON
    let output_path = std::path::Path::new(&output);
    let data = match std::fs::read(output_path) {
        Ok(d) => d,
        Err(e) => {
            return FfiResult::err(format!("Failed to read exported file: {e}"));
        }
    };
    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(&data);
    // Decode without validation: we just wrote this file ourselves, and packets
    // with fewer than MIN_CHECKPOINTS are valid for export even if they don't
    // meet the full wire-format spec threshold.
    let wire: EvidencePacketWire = match authorproof_protocol::codec::cbor::decode_tagged(
        &cbor_payload,
        authorproof_protocol::codec::CBOR_TAG_CPOE,
    ) {
        Ok(w) => w,
        Err(_) => match authorproof_protocol::codec::cbor::decode(&cbor_payload) {
            Ok(w) => w,
            Err(e) => {
                return FfiResult::err(format!("Evidence packet could not be decoded: {e}"));
            }
        },
    };
    match serde_json::to_string_pretty(&wire) {
        Ok(json) => {
            if let Err(e) = std::fs::write(output_path, json.as_bytes()) {
                return FfiResult::err(format!("Failed to write JSON: {e}"));
            }
            FfiResult::ok(format!("Exported JSON to {}", output_path.display()))
        }
        Err(e) => FfiResult::err(format!("JSON serialization failed: {e}")),
    }
}

/// Export stored events for a file as a CBOR evidence packet at the given tier.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence(path: String, tier: String, output: String) -> FfiResult {
    let file_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid source path: {e}")),
        FfiResult
    );
    let output_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&output)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    if !file_path.exists() {
        return FfiResult::err(format!("File not found: {}", file_path.display()));
    }

    let store = try_ffi!(open_store(), FfiResult);

    let file_path_str = file_path.to_string_lossy().into_owned();
    let events = try_ffi!(
        store
            .get_events_for_file(&file_path_str)
            .map_err(|e| format!("Failed to load events: {e}")),
        FfiResult
    );

    if events.is_empty() {
        return FfiResult::err("No events found for this file".to_string());
    }

    let latest = &events[events.len() - 1];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(crate::utils::duration_to_ms)
        .unwrap_or(0);

    let data_dir =
        crate::ffi::helpers::get_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let ips = crate::config::CpopConfig::load_or_default(&data_dir)
        .map(|c| c.vdf.iterations_per_second.max(1))
        .unwrap_or(1);

    let content_tier = match tier.to_lowercase().as_str() {
        "basic" | "core" => Some(authorproof_protocol::rfc::wire_types::ContentTier::Core),
        "standard" | "enhanced" => {
            Some(authorproof_protocol::rfc::wire_types::ContentTier::Enhanced)
        }
        "maximum" => Some(authorproof_protocol::rfc::wire_types::ContentTier::Maximum),
        _ => Some(authorproof_protocol::rfc::wire_types::ContentTier::Core),
    };

    // Random salt so each export produces unique packet/checkpoint IDs.
    let export_nonce = rand::random::<[u8; 8]>();

    let checkpoints: Vec<CheckpointWire> = match events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let timestamp_ms = if ev.timestamp_ns < 0 {
                log::warn!(
                    "Negative timestamp_ns {} at index {i}, clamping to 0",
                    ev.timestamp_ns
                );
                0u64
            } else {
                (ev.timestamp_ns / 1_000_000) as u64
            };
            let vdf_input_bytes = ev
                .vdf_input
                .map(|b| b.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]);
            let vdf_output_bytes = ev.vdf_output.map(|b| b.to_vec());
            let merkle_root = vdf_output_bytes.clone().unwrap_or_else(|| vec![0u8; 32]);

            let checkpoint_id = {
                let mut h = Sha256::new();
                h.update(b"cpoe-checkpoint-id-v1");
                h.update(ev.content_hash);
                h.update((i as u64).to_le_bytes());
                h.update(export_nonce);
                let d = h.finalize();
                let mut id = [0u8; 16];
                id.copy_from_slice(&d[..16]);
                id
            };

            Ok(CheckpointWire {
                sequence: i as u64,
                checkpoint_id,
                timestamp: timestamp_ms,
                content_hash: HashValue::try_sha256(ev.content_hash.to_vec())?,
                char_count: ev.file_size.max(0) as u64,
                delta: EditDelta {
                    chars_added: ev.size_delta.max(0) as u64,
                    // Widen to i64 before negating to avoid overflow on i32::MIN
                    chars_deleted: (-(ev.size_delta as i64)).max(0) as u64,
                    op_count: 1,
                    positions: None,
                    edit_graph_hash: None,
                    cursor_trajectory_histogram: None,
                    revision_depth_histogram: None,
                    pause_duration_histogram: None,
                },
                prev_hash: HashValue::try_sha256(ev.previous_hash.to_vec())?,
                checkpoint_hash: HashValue::try_sha256(
                    Sha256::new()
                        .chain_update(ev.content_hash)
                        .chain_update(ev.previous_hash)
                        .chain_update((i as u64).to_le_bytes())
                        .chain_update(timestamp_ms.to_le_bytes())
                        .finalize()
                        .to_vec(),
                )?,
                process_proof: ProcessProof {
                    algorithm: if ev.posme_proof.is_some() {
                        ProofAlgorithm::SwfPosme
                    } else {
                        ProofAlgorithm::SwfSha256
                    },
                    params: ProofParams {
                        time_cost: 1,
                        memory_cost: 0,
                        parallelism: 1,
                        steps: ev.vdf_iterations,
                        waypoint_interval: None,
                        waypoint_memory: None,
                        reads_per_step: None,
                        challenges: None,
                        recursion_depth: None,
                    },
                    input: vdf_input_bytes,
                    merkle_root,
                    sampled_proofs: vec![],
                    claimed_duration: ev.vdf_iterations.saturating_mul(1000) / ips as u64,
                },
                jitter_binding: None,
                physical_state: None,
                entangled_mac: None,
                receipts: None,
                active_probes: None,
                hat_proof: None,
                beacon_anchor: None,
                verifier_nonce: None,
                lamport_signature: ev.lamport_signature.clone(),
                lamport_pubkey_fingerprint: ev.lamport_pubkey_fingerprint.clone(),
                posme_proof: ev.posme_proof.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(mut c) => {
            // Attach beacon attestation to the last checkpoint if available.
            if let Some(beacon) = crate::ffi::beacon::load_beacon_attestation(&file_path_str) {
                if let Some(last_cp) = c.last_mut() {
                    let drand_bytes = hex::decode(&beacon.drand_randomness)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .unwrap_or([0u8; 32]);
                    last_cp.beacon_anchor = Some(
                        authorproof_protocol::rfc::wire_types::components::BeaconAnchor {
                            source_url: "https://drand.cloudflare.com".to_string(),
                            beacon_round: beacon.drand_round,
                            beacon_value: drand_bytes,
                        },
                    );
                }
            }
            c
        }
        Err(e) => {
            return FfiResult::err(format!("Invalid hash in event data: {e}"));
        }
    };

    let doc_content_hash = match HashValue::try_sha256(latest.content_hash.to_vec()) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult::err(format!("Invalid document content hash: {e}"));
        }
    };

    let packet_id = {
        let mut h = Sha256::new();
        h.update(b"cpoe-packet-id-v1");
        h.update(latest.content_hash);
        h.update(export_nonce);
        let d = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&d[..16]);
        id
    };

    // Read file content once for char count, hash verification, and embedding.
    let byte_length = latest.file_size.max(0) as u64;
    let file_bytes = std::fs::read(&file_path)
        .map_err(|e| log::warn!("read file for export failed: {e}"))
        .ok();
    let content_verified = file_bytes.as_ref().is_some_and(|bytes| {
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        hash == latest.content_hash
    });
    let char_count = file_bytes
        .as_ref()
        .filter(|_| content_verified)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(|s| s.chars().count() as u64)
        .unwrap_or(byte_length);
    let is_maximum = matches!(
        content_tier,
        Some(authorproof_protocol::rfc::wire_types::ContentTier::Maximum)
    );
    let embedded_content = if is_maximum && content_verified {
        file_bytes.map(serde_bytes::ByteBuf::from)
    } else {
        None
    };
    let embedded_filename = if embedded_content.is_some() {
        file_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    // Load the signing key once for both public key embedding and COSE signing.
    let signing_key = crate::ffi::helpers::load_signing_key()
        .map_err(|e| log::warn!("load signing key for evidence export failed: {e}"))
        .ok();
    let signing_pub = signing_key
        .as_ref()
        .map(|sk| serde_bytes::ByteBuf::from(sk.verifying_key().to_bytes().to_vec()));

    let wire_packet = EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        packet_id,
        created: now_ms,
        document: DocumentRef {
            content_hash: doc_content_hash,
            filename: file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string()),
            byte_length,
            char_count,
            salt_mode: None,
            salt_commitment: None,
        },
        checkpoints,
        attestation_tier: Some(detect_attestation_tier()),
        limitations: collect_ai_tool_limitations(&path),
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        signing_public_key: signing_pub,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
        author_did: {
            #[cfg(feature = "did-webvh")]
            {
                crate::identity::did_webvh::load_active_did().ok()
            }
            #[cfg(not(feature = "did-webvh"))]
            {
                None
            }
        },
        document_content: embedded_content,
        document_filename: embedded_filename,
        project_files: collect_project_files(&file_path, &store),
    };

    match wire_packet.encode_cbor() {
        Ok(encoded) => {
            // Sign the CBOR payload with COSE_Sign1 using the device signing key.
            // This prevents tampering, replay, and evidence reuse; any modification
            // to the packet content invalidates the signature.
            let mut is_signed = false;
            let signed_bytes = match signing_key {
                Some(ref sk) => {
                    match authorproof_protocol::crypto::sign_evidence_cose(&encoded, sk) {
                        Ok(cose) => {
                            is_signed = true;
                            cose
                        }
                        Err(e) => {
                            log::warn!("COSE signing failed, exporting unsigned: {e}");
                            encoded
                        }
                    }
                }
                None => {
                    log::warn!("Signing key unavailable, exporting unsigned");
                    encoded
                }
            };

            let parent = output_path.parent().unwrap_or(std::path::Path::new("."));
            let write_result = (|| -> std::io::Result<()> {
                let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
                std::io::Write::write_all(&mut tmp, &signed_bytes)?;
                tmp.as_file().sync_all()?;
                tmp.persist(&output_path).map_err(|e| e.error)?;
                Ok(())
            })();
            match write_result {
                Ok(()) => {
                    let label = if is_signed {
                        "signed CBOR"
                    } else {
                        "unsigned CBOR (signing unavailable)"
                    };
                    FfiResult::ok(format!("Exported {} to {}", label, output_path.display()))
                }
                Err(e) => FfiResult::err(format!("Failed to write output: {}", e)),
            }
        }
        Err(e) => FfiResult::err(format!("Failed to encode CBOR packet: {}", e)),
    }
}

/// Collect AI tool limitations from the sentinel session matching `path`.
///
/// Returns `Some(vec)` when at least one AI tool was detected, `None` otherwise.
pub(crate) fn collect_ai_tool_limitations(path: &str) -> Option<Vec<String>> {
    use crate::sentinel::types::ObservationBasis;

    let sentinel = get_sentinel()?;
    let sessions = sentinel.sessions.read_recover();
    let session = sessions.get(path)?;
    if session.ai_tools_detected.is_empty() && session.capture_gaps == 0 {
        return None;
    }
    let mut limitations: Vec<String> = session
        .ai_tools_detected
        .iter()
        .map(|tool| {
            let verb = match tool.basis {
                ObservationBasis::Observed => "detected",
                ObservationBasis::Inferred => "possibly active",
                ObservationBasis::Correlated => "running concurrently",
            };
            format!(
                "AI tool {} during session: {} [{}, {}]",
                verb, tool.signing_id, tool.category, tool.basis,
            )
        })
        .collect();
    if session.capture_gaps > 0 {
        limitations.push(format!(
            "ES capture degraded: {} event(s) dropped by kernel",
            session.capture_gaps,
        ));
    }
    Some(limitations)
}

/// Return a compact reference string for the latest event on a tracked file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_compact_ref(path: String) -> String {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return String::new(),
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    if events.is_empty() {
        return String::new();
    }

    let last_event = &events[events.len() - 1];
    let hash_hex = hex::encode(last_event.event_hash);

    format!(
        "cpoe-ref:writerslogic:{}:{}",
        &hash_hex[..hash_hex.len().min(12)],
        events.len()
    )
}

/// Extract the embedded document from a .cpoe evidence package.
/// Returns an FfiResult with the output path on success.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_extract_document(cpoe_path: String, output_path: String) -> FfiResult {
    let cpoe_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&cpoe_path)
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|e| format!("Invalid cpoe path: {e}")),
        FfiResult
    );
    const MAX_CPOE_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MB
    let meta = try_ffi!(
        std::fs::metadata(&cpoe_path).map_err(|e| format!("Failed to stat .cpoe file: {e}")),
        FfiResult
    );
    if meta.len() > MAX_CPOE_FILE_SIZE {
        return FfiResult::err(format!(
            "File too large: {} bytes (max {})",
            meta.len(),
            MAX_CPOE_FILE_SIZE
        ));
    }
    let data = try_ffi!(
        std::fs::read(&cpoe_path).map_err(|e| format!("Failed to read .cpoe file: {e}")),
        FfiResult
    );

    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(&data);
    let wire: EvidencePacketWire = match authorproof_protocol::codec::cbor::decode_tagged(
        &cbor_payload,
        authorproof_protocol::codec::CBOR_TAG_CPOE,
    ) {
        Ok(w) => w,
        Err(_) => match authorproof_protocol::codec::cbor::decode(&cbor_payload) {
            Ok(w) => w,
            Err(e) => return FfiResult::err(format!("Invalid .cpoe file: {e}")),
        },
    };

    let content = match wire.document_content {
        Some(c) => c,
        None => {
            return FfiResult::err(
                "This .cpoe file does not contain an embedded document.".to_string(),
            )
        }
    };

    // Verify content hash matches
    let hash: [u8; 32] = Sha256::digest(&content).into();
    if wire.document.content_hash.digest.len() != 32 {
        return FfiResult::err("Invalid content hash length in evidence packet.".to_string());
    }
    if hash[..] != wire.document.content_hash.digest[..] {
        return FfiResult::err(
            "Document content hash mismatch — file may be corrupted.".to_string(),
        );
    }

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );
    {
        use std::io::Write;
        let dir = out.parent().unwrap_or(std::path::Path::new("."));
        let mut tmp = match tempfile::NamedTempFile::new_in(dir) {
            Ok(t) => t,
            Err(e) => return FfiResult::err(format!("Failed to create temp file: {e}")),
        };
        if let Err(e) = tmp.write_all(&content) {
            return FfiResult::err(format!("Failed to write document: {e}"));
        }
        if let Err(e) = tmp.persist(&out) {
            return FfiResult::err(format!("Failed to finalize document: {e}"));
        }
    }

    FfiResult::ok(format!("Document extracted to {}", out.display()))
}

/// Collect project file references for all tracked files under the same
/// root directory as the primary document. Walks up to find the project
/// root (looks for .scriv, .git, or stops at the parent of the source).
/// Scans recursively so subdirectories (Draft/, Research/) are included.
fn collect_project_files(
    primary_path: &std::path::Path,
    store: &crate::store::SecureStore,
) -> Option<Vec<authorproof_protocol::rfc::wire_types::ProjectFileRef>> {
    let project_root = find_project_root(primary_path);
    let root_str = project_root.to_string_lossy();
    let primary_str = primary_path.to_string_lossy();

    let all_files = match store.list_files() {
        Ok(files) => files,
        Err(e) => {
            log::debug!("Failed to list project files: {e}");
            return None;
        }
    };

    let siblings: Vec<_> = all_files
        .into_iter()
        .filter(|(path, _, _)| path != primary_str.as_ref() && path.starts_with(root_str.as_ref()))
        .collect();

    if siblings.is_empty() {
        return None;
    }

    let refs: Vec<_> = siblings
        .iter()
        .map(|(path, _last_ts, event_count)| {
            // Relative path from project root for cleaner display
            let rel_path = std::path::Path::new(path)
                .strip_prefix(&project_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| {
                    std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone())
                });

            // Get content hash and keystroke count from events
            let events = store.get_events_for_file(path).unwrap_or_default();
            let content_hash = events
                .last()
                .map(|e| hex::encode(e.content_hash))
                .unwrap_or_default();
            let keystroke_count: u64 = events
                .iter()
                .map(|e| e.size_delta.unsigned_abs() as u64)
                .sum();

            authorproof_protocol::rfc::wire_types::ProjectFileRef {
                filename: rel_path,
                content_hash,
                checkpoint_count: *event_count as u64,
                keystroke_count,
            }
        })
        .collect();

    Some(refs)
}

/// Walk up from the file to find the project root directory.
/// Looks for common project markers; falls back to the file's parent.
fn find_project_root(file_path: &std::path::Path) -> std::path::PathBuf {
    let markers = [
        ".git",
        ".scriv",
        "Package.swift",
        "Cargo.toml",
        ".writerslogic",
    ];
    let mut dir = file_path.parent().unwrap_or(file_path).to_path_buf();

    // Walk up at most 5 levels looking for a project marker
    for _ in 0..5 {
        for marker in &markers {
            if dir.join(marker).exists() {
                return dir;
            }
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p.to_path_buf(),
            _ => break,
        }
    }

    // No marker found — use the immediate parent directory
    file_path.parent().unwrap_or(file_path).to_path_buf()
}
