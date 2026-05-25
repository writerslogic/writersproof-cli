// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, open_store};
use crate::ffi::sentinel::get_sentinel;
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiResult};
use crate::jitter::SimpleJitterSample;
use crate::RwLockRecover;
use authorproof_protocol::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, ForensicSummaryWire, HashValue,
    ProcessProof, ProofAlgorithm, ProofParams,
};
use sha2::{Digest, Sha256};

/// Export stored events as a human-readable JSON evidence packet.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence_json(path: String, tier: String, output: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_export_evidence_json: path={} tier={} output={}", path, tier, output);
    let output_path = match crate::sentinel::helpers::validate_path(&output) {
        Ok(p) => p,
        Err(e) => return FfiResult::err(format!("Invalid output path: {e}")),
    };
    // Build the packet in memory and serialize directly to JSON — no temp-file round-trip.
    let (packet, _, _) = match build_wire_packet(path, tier, None, None) {
        Ok(x) => x,
        Err(e) => return FfiResult::err(e),
    };
    match serde_json::to_string_pretty(&packet) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&output_path, json.as_bytes()) {
                return FfiResult::err(format!("Failed to write JSON: {e}"));
            }
            FfiResult::ok(format!("Exported JSON to {}", output_path.display()))
        }
        Err(e) => FfiResult::err(format!("JSON serialization failed: {e}")),
    }
    })
}

/// Export stored events for a file as a CBOR evidence packet at the given tier.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence(path: String, tier: String, output: String) -> FfiResult {
    log::debug!("ffi_export_evidence: path={} tier={} output={}", path, tier, output);
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
        super::types::run_on_stack(move || export_evidence_inner(path, tier, output, None, None))
    })
}

/// Export stored events for a file within a date range as a CBOR evidence packet.
/// `start_ns` and `end_ns` are inclusive nanosecond timestamps. Pass 0 for unbounded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence_range(
    path: String,
    tier: String,
    output: String,
    start_ns: i64,
    end_ns: i64,
) -> FfiResult {
    log::debug!("ffi_export_evidence_range: path={} tier={} output={} start_ns={} end_ns={}", path, tier, output, start_ns, end_ns);
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
        super::types::run_on_stack(move || export_evidence_inner(path, tier, output, Some(start_ns), Some(end_ns)))
    })
}

/// Build an [`EvidencePacketWire`] from stored events, encode to CBOR, and sign.
///
/// Returns `(packet, signed_bytes, is_signed)` on success, or an error string.
fn build_wire_packet(
    path: String,
    tier: String,
    start_ns: Option<i64>,
    end_ns: Option<i64>,
) -> Result<(EvidencePacketWire, Vec<u8>, bool), String> {
    let file_path = crate::utils::fs::canonicalize_validated(std::path::Path::new(&path))
        .map_err(|e| format!("Invalid source path: {e}"))?;

    let store = open_store()?;

    let file_path_str = file_path.to_string_lossy().into_owned();
    let events = if let (Some(start), Some(end)) = (start_ns, end_ns) {
        store
            .get_events_for_file_in_range(&file_path_str, start, end)
            .map_err(|e| format!("Failed to load events: {e}"))?
    } else {
        store
            .get_events_for_file(&file_path_str)
            .map_err(|e| format!("Failed to load events: {e}"))?
    };

    if events.is_empty() {
        return Err("No events found for this file".to_string());
    }

    let latest = &events[events.len() - 1];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(crate::utils::duration_to_ms)
        .unwrap_or_else(|_| {
            log::warn!("System clock before UNIX epoch; using 0 for export timestamp");
            0
        });

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
        other => {
            log::warn!("Unknown export tier {:?}; defaulting to Core", other);
            Some(authorproof_protocol::rfc::wire_types::ContentTier::Core)
        }
    };

    // Random salt so each export produces unique packet/checkpoint IDs.
    let export_nonce = rand::random::<[u8; 8]>();

    let mut checkpoints: Vec<CheckpointWire> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            // Clamp to 1ms minimum so CheckpointWire::validate() (which rejects
            // timestamp == 0) does not fail when the JSON re-decode path runs.
            let timestamp_ms = if ev.timestamp_ns <= 0 {
                if ev.timestamp_ns < 0 {
                    log::warn!(
                        "Negative timestamp_ns {} at index {i}, clamping to 1ms",
                        ev.timestamp_ns
                    );
                }
                1u64
            } else {
                (ev.timestamp_ns / 1_000_000).max(1) as u64
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
                    metric_binding_hash: None,
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
        .map_err(|e| format!("Invalid hash in event data: {e}"))?;

    // Enrich checkpoints with behavioral data from sentinel session.
    enrich_checkpoints(&mut checkpoints, &events, &path);

    // Attach beacon attestation to the last checkpoint if available.
    if let Some(beacon) = crate::ffi::beacon::load_beacon_attestation(&file_path_str) {
        if let Some(last_cp) = checkpoints.last_mut() {
            match hex::decode(&beacon.drand_randomness)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(drand_bytes) => {
                    last_cp.beacon_anchor = Some(
                        authorproof_protocol::rfc::wire_types::components::BeaconAnchor {
                            source_url: "https://drand.cloudflare.com".to_string(),
                            beacon_round: beacon.drand_round,
                            beacon_value: drand_bytes,
                        },
                    );
                }
                None => {
                    log::warn!(
                        "Beacon randomness decode failed for round {}; skipping beacon anchor",
                        beacon.drand_round
                    );
                }
            }
        }
    }

    let doc_content_hash = HashValue::try_sha256(latest.content_hash.to_vec())
        .map_err(|e| format!("Invalid document content hash: {e}"))?;

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
    const MAX_EMBEDDED_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
    let is_maximum = matches!(
        content_tier,
        Some(authorproof_protocol::rfc::wire_types::ContentTier::Maximum)
    );
    let embedded_content = if is_maximum && content_verified {
        file_bytes.and_then(|b| {
            if b.len() > MAX_EMBEDDED_BYTES {
                log::warn!(
                    "File too large to embed ({} bytes > {MAX_EMBEDDED_BYTES}); skipping embed",
                    b.len()
                );
                None
            } else {
                Some(serde_bytes::ByteBuf::from(b))
            }
        })
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

    let forensic_summary = build_forensic_summary(&path, &events);

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
        limitations: {
            let mut lims = collect_ai_tool_limitations(&path).unwrap_or_default();
            lims.extend(collect_repair_history(&data_dir));
            lims.extend(collect_dictation_limitations(&path));
            lims.extend(collect_composition_mode_limitations(&path, events.len()));
            if lims.is_empty() { None } else { Some(lims) }
        },
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        signing_public_key: signing_pub,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: build_baseline_verification(&path, &events),
        author_did: {
            #[cfg(feature = "did-webvh")]
            {
                crate::identity::did_webvh::load_active_did()
                    .map_err(|e| log::debug!("DID not available for evidence export: {e}"))
                    .ok()
            }
            #[cfg(not(feature = "did-webvh"))]
            {
                None
            }
        },
        document_content: embedded_content,
        document_filename: embedded_filename,
        project_files: collect_project_files(&file_path, &store),
        session_counter: events.last().and_then(|e| e.hardware_counter),
        forensic_summary,
    };

    let encoded = wire_packet
        .encode_cbor()
        .map_err(|e| format!("Failed to encode CBOR packet: {e}"))?;

    // Sign the CBOR payload with COSE_Sign1 using the device signing key.
    // This prevents tampering, replay, and evidence reuse; any modification
    // to the packet content invalidates the signature.
    let mut is_signed = false;
    let signed_bytes = match signing_key {
        Some(ref sk) => match authorproof_protocol::crypto::sign_evidence_cose(&encoded, sk) {
            Ok(cose) => {
                is_signed = true;
                cose
            }
            Err(e) => {
                log::warn!("COSE signing failed, exporting unsigned: {e}");
                encoded
            }
        },
        None => {
            log::warn!("Signing key unavailable, exporting unsigned");
            encoded
        }
    };

    Ok((wire_packet, signed_bytes, is_signed))
}

fn export_evidence_inner(
    path: String,
    tier: String,
    output: String,
    start_ns: Option<i64>,
    end_ns: Option<i64>,
) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    let output_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&output)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let (_, signed_bytes, is_signed) = match build_wire_packet(path, tier, start_ns, end_ns) {
        Ok(x) => x,
        Err(e) => return FfiResult::err(e),
    };

    if !is_signed {
        return FfiResult::err(
            "Evidence export requires COSE signing but signing key is unavailable".to_string(),
        );
    }

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
    })
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

/// Read `repair-log.json` from the data directory and return limitation strings
/// for each recorded integrity repair event.
fn collect_repair_history(data_dir: &std::path::Path) -> Vec<String> {
    let log_path = data_dir.join("repair-log.json");
    let bytes = match std::fs::read(&log_path) {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse repair-log.json: {e}");
            return vec![];
        }
    };
    let repairs = match parsed.get("repairs").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return vec![],
    };
    repairs
        .iter()
        .filter_map(|entry| {
            entry
                .get("timestamp")
                .and_then(|t| t.as_str())
                .map(|ts| format!("Integrity repair performed at {ts}"))
        })
        .collect()
}

/// Provision an X.509 certificate from the WritersProof CA.
///
/// Enrolls the device with the WritersProof CA (if not already enrolled),
/// fetches the signed certificate, and caches it locally for use in C2PA
/// manifest x5chain headers. Safe to call multiple times — returns early
/// if a cached cert already exists.
///
/// Returns an FfiResult with the certificate fingerprint on success.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_provision_ca_cert() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_provision_ca_cert");
    use crate::ffi::types::try_ffi;

    let signing_key = try_ffi!(
        crate::ffi::helpers::load_signing_key(),
        FfiResult
    );

    // Check if we already have a cached CA cert.
    let data_dir = try_ffi!(
        crate::ffi::helpers::get_data_dir()
            .ok_or_else(|| "Data directory not found".to_string()),
        FfiResult
    );
    let cert_path = data_dir.join("ca_cert.der");
    if cert_path.is_file() {
        if let Ok(der) = std::fs::read(&cert_path) {
            if der.len() > 100 {
                let fp = hex::encode(&sha2::Sha256::digest(&der)[..8]);
                return FfiResult::ok(format!("CA cert already cached (fingerprint: {fp})"));
            }
        }
    }

    // Run enrollment + cert fetch on a blocking tokio runtime.
    let rt = try_ffi!(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create async runtime: {e}")),
        FfiResult
    );

    let result = rt.block_on(async {
        let base_url = std::env::var("WRITERSPROOF_API_URL")
            .unwrap_or_else(|_| "https://api.writersproof.com".to_string());
        if !base_url.starts_with("https://") {
            let preview: String = base_url.chars().take(40).collect();
            return Err(format!(
                "WRITERSPROOF_API_URL must use HTTPS: {preview}"
            ));
        }
        let client = crate::writersproof::WritersProofClient::new(&base_url)
            .map_err(|e| format!("Failed to create WritersProof client: {e}"))?;

        let pub_key_hex = super::conv::pubkey_hex(&signing_key);
        let device_id = hex::encode(&sha2::Sha256::digest(
            signing_key.verifying_key().as_bytes(),
        )[..16]);

        // Enroll with the CA.
        let enroll_resp = client
            .enroll(crate::writersproof::types::EnrollRequest {
                public_key: pub_key_hex,
                device_id: device_id.clone(),
                platform: std::env::consts::OS.to_string(),
                attestation_type: {
                    let caps = crate::tpm::detect_provider().capabilities();
                    if caps.hardware_backed {
                        "secure_enclave"
                    } else {
                        "software"
                    }
                    .to_string()
                },
                attestation_certificate: None,
            })
            .await
            .map_err(|e| format!("Enrollment failed: {e}"))?;

        if !enroll_resp.enrolled {
            return Err("CA enrollment was rejected".to_string());
        }

        // Fetch the signed certificate.
        let cert_der = client
            .get_certificate(&enroll_resp.hardware_key_id)
            .await
            .map_err(|e| format!("Certificate fetch failed: {e}"))?;

        // Cache locally.
        crate::ffi::helpers::cache_ca_cert(&cert_der)?;

        let fp = hex::encode(&sha2::Sha256::digest(&cert_der)[..8]);
        Ok(format!(
            "CA cert provisioned (fingerprint: {fp}, tier: {})",
            enroll_resp.assurance_tier
        ))
    });

    match result {
        Ok(msg) => FfiResult::ok(msg),
        Err(e) => FfiResult::err(e),
    }
    })
}

// ---------------------------------------------------------------------------
// Checkpoint behavioral enrichment
// ---------------------------------------------------------------------------

/// IKI histogram bin edges (ms): 0, 50, 100, 150, 200, 300, 500, 1000, 2000
const IKI_HIST_EDGES_MS: [u64; 9] = [0, 50, 100, 150, 200, 300, 500, 1000, 2000];

/// 8-bin pause duration histogram edges (ms): 0, 500, 1000, 2000, 3000, 5000, 10000, 30000
const PAUSE_HIST_EDGES_MS: [u64; 8] = [0, 500, 1000, 2000, 3000, 5000, 10000, 30000];

/// Enrich checkpoints with behavioral data from sentinel session.
///
/// Populates: EditDelta histograms, positions, edit_graph_hash, op_count,
/// and per-checkpoint jitter binding.
fn enrich_checkpoints(
    checkpoints: &mut [CheckpointWire],
    events: &[crate::store::SecureEvent],
    path: &str,
) {
    if checkpoints.is_empty() || events.is_empty() {
        return;
    }

    // Get jitter samples from live sentinel session (if available).
    let sentinel_jitter: Vec<SimpleJitterSample> = get_sentinel()
        .map(|s| {
            let sessions = s.sessions.read_recover();
            sessions
                .get(path)
                .map(|sess| sess.jitter_samples.clone())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let max_file_size = events.iter().map(|e| e.file_size).max().unwrap_or(1).max(1) as f64;

    // Cumulative state maintained across checkpoints to avoid O(n^2) recomputation.
    let mut cumulative_revision_hist = vec![0u64; 8];
    let mut cumulative_graph_hasher = Sha256::new();
    cumulative_graph_hasher.update(b"cpoe-edit-graph-v1");

    // Build per-checkpoint enrichment.
    for (i, (cp, ev)) in checkpoints.iter_mut().zip(events.iter()).enumerate() {
        // Fix op_count: count actual operations (not hardcoded 1).
        // Each event is one operation; for windowed checkpoints this would be the count
        // of events in the window. Currently 1:1 event:checkpoint mapping.
        cp.delta.op_count = 1;

        // Populate positions: (estimated_offset, delta).
        let cursor_offset = if ev.size_delta >= 0 {
            ev.file_size.max(0) as u64
        } else {
            (ev.file_size - ev.size_delta.abs() as i64).max(0) as u64
        };
        cp.delta.positions = Some(vec![(cursor_offset, ev.size_delta as i64)]);

        // Cursor trajectory histogram: bin the cursor position relative to file size.
        // 8 bins spanning [0, max_file_size].
        let cursor_frac = cursor_offset as f64 / max_file_size;
        let cursor_bin = crate::analysis::histogram::bin_linear_normalized(cursor_frac, 8);
        let mut cursor_hist = vec![0u64; 8];
        cursor_hist[cursor_bin] = 1;
        cp.delta.cursor_trajectory_histogram = Some(cursor_hist);

        // Revision depth: how many times this position bin has been edited so far.
        let pos = ev.file_size.max(0) as f64 / max_file_size;
        let bin = crate::analysis::histogram::bin_linear_normalized(pos, 8);
        cumulative_revision_hist[bin] += 1;
        cp.delta.revision_depth_histogram = Some(cumulative_revision_hist.clone());

        // Pause duration histogram from jitter samples in this checkpoint window.
        let cp_ts_ns = ev.timestamp_ns;
        let prev_ts_ns = if i > 0 { events[i - 1].timestamp_ns } else { 0 };
        let window_jitter: Vec<&SimpleJitterSample> = sentinel_jitter
            .iter()
            .filter(|s| s.timestamp_ns > prev_ts_ns && s.timestamp_ns <= cp_ts_ns)
            .collect();

        if !window_jitter.is_empty() {
            let pause_ms: Vec<u64> = window_jitter
                .iter()
                .map(|s| s.duration_since_last_ns / 1_000_000)
                .collect();
            let pause_hist =
                crate::analysis::histogram::edge_histogram(&pause_ms, &PAUSE_HIST_EDGES_MS, 8);
            cp.delta.pause_duration_histogram = Some(pause_hist);

            // Jitter binding: IKI intervals + entropy estimate + HMAC seal.
            let intervals: Vec<u64> = window_jitter
                .iter()
                .map(|s| s.duration_since_last_ns / 1_000_000) // ns → ms
                .collect();
            let entropy_centibits = estimate_entropy_centibits(&intervals);
            cp.jitter_binding = compute_jitter_seal(&intervals, ev.content_hash)
                .map(|jitter_seal| {
                    authorproof_protocol::rfc::wire_types::JitterBindingWire {
                        intervals,
                        entropy_estimate: entropy_centibits,
                        jitter_seal,
                    }
                });
        }

        // Edit graph hash: SHA-256 of cumulative edit positions up to this checkpoint.
        cumulative_graph_hasher.update(ev.timestamp_ns.to_le_bytes());
        cumulative_graph_hasher.update(ev.size_delta.to_le_bytes());
        cumulative_graph_hasher.update((ev.file_size as u64).to_le_bytes());
        let graph_hash = cumulative_graph_hasher.clone().finalize();
        cp.delta.edit_graph_hash = Some(graph_hash.to_vec());

        // Metric binding hash: couples edit topology, revision distribution,
        // and jitter seal into a single SHA-256. Forging any channel requires
        // satisfying all simultaneously (NP-hard constraint satisfaction).
        let mut binding = Sha256::new();
        binding.update(b"cpoe-metric-binding-v1");
        binding.update(graph_hash);
        for &bin in &cumulative_revision_hist {
            binding.update(bin.to_le_bytes());
        }
        if let Some(ref jb) = cp.jitter_binding {
            binding.update(&jb.jitter_seal);
            binding.update(jb.entropy_estimate.to_le_bytes());
        }
        binding.update(ev.content_hash);
        cp.delta.metric_binding_hash = Some(binding.finalize().to_vec());
    }
}

/// Estimate Shannon entropy of IKI intervals in centibits.
fn estimate_entropy_centibits(intervals_ms: &[u64]) -> u64 {
    if intervals_ms.is_empty() {
        return 0;
    }
    let hist = crate::analysis::histogram::edge_histogram(intervals_ms, &IKI_HIST_EDGES_MS, 9);
    crate::analysis::histogram::shannon_entropy_centibits(&hist)
}

/// HMAC-SHA256 seal over jitter intervals bound to content hash.
fn compute_jitter_seal(intervals_ms: &[u64], content_hash: [u8; 32]) -> Option<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256 as HmacSha256;

    type HmacSha = Hmac<HmacSha256>;
    let mut mac = match HmacSha::new_from_slice(&content_hash) {
        Ok(m) => m,
        Err(e) => {
            log::error!("HMAC init failed for jitter seal: {e}");
            return None;
        }
    };
    mac.update(b"cpoe-jitter-seal-v1");
    for &iki in intervals_ms {
        mac.update(&iki.to_le_bytes());
    }
    Some(mac.finalize().into_bytes().to_vec())
}

/// Build baseline verification from sentinel session behavioral data.
fn build_baseline_verification(
    path: &str,
    _events: &[crate::store::SecureEvent],
) -> Option<authorproof_protocol::rfc::wire_types::BaselineVerification> {
    let sentinel = get_sentinel()?;
    let sessions = sentinel.sessions.read_recover();
    let session = sessions.get(path)?;

    if session.jitter_samples.len() < 30 {
        return None;
    }

    // Build 9-bin IKI histogram, normalized to proportions.
    let iki_ms_vals: Vec<u64> = session
        .jitter_samples
        .iter()
        .map(|s| s.duration_since_last_ns / 1_000_000)
        .collect();
    let iki_counts = crate::analysis::histogram::edge_histogram(&iki_ms_vals, &IKI_HIST_EDGES_MS, 9);
    let mut iki_histogram = [0.0f64; 9];
    let total_samples = iki_ms_vals.len() as f64;
    if total_samples > 0.0 {
        for (i, &c) in iki_counts.iter().enumerate() {
            iki_histogram[i] = c as f64 / total_samples;
        }
    }

    // Compute IKI CV.
    let cadence = crate::forensics::analyze_cadence(&session.jitter_samples);
    let iki_cv = if cadence.coefficient_of_variation.is_finite() {
        cadence.coefficient_of_variation
    } else {
        0.0
    };

    // Hurst exponent.
    let iki_intervals: Vec<f64> = session
        .jitter_samples
        .windows(2)
        .filter_map(|w| {
            w[1].timestamp_ns
                .checked_sub(w[0].timestamp_ns)
                .map(|d| d as f64)
        })
        .filter(|&d| d > 0.0)
        .collect();
    let hurst = if iki_intervals.len() >= 50 {
        crate::analysis::hurst::compute_hurst_rs(&iki_intervals)
            .map(|h| h.exponent)
            .unwrap_or(0.5)
    } else {
        0.5
    };

    let duration_secs = session
        .start_time
        .elapsed()
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let summary = authorproof_protocol::rfc::wire_types::SessionBehavioralSummary {
        iki_histogram,
        iki_cv,
        hurst,
        pause_frequency: cadence.pause_depth_distribution[2], // deep pause fraction
        duration_secs,
        keystroke_count: session.jitter_samples.len() as u64,
    };

    Some(authorproof_protocol::rfc::wire_types::BaselineVerification {
        digest: None, // Populated by cross-session baseline manager (not available at export)
        session_summary: summary,
        digest_signature: None, // Signed by baseline manager
    })
}

/// Collect dictation-related limitations from sentinel session.
fn collect_dictation_limitations(path: &str) -> Vec<String> {
    let sentinel = match get_sentinel() {
        Some(s) => s,
        None => return vec![],
    };
    let sessions = sentinel.sessions.read_recover();
    let session = match sessions.get(path) {
        Some(s) => s,
        None => return vec![],
    };
    if session.dictation_events.is_empty() {
        return vec![];
    }

    let total_words: u32 = session.dictation_events.iter().map(|e| e.word_count).sum();
    let typed_words = (session.cognitive.word_boundary_count() as u32).saturating_sub(total_words);
    let ratio = if total_words + typed_words > 0 {
        total_words as f64 / (total_words + typed_words) as f64
    } else {
        0.0
    };

    let mut lims = vec![format!(
        "Dictation detected: {} events, {} words ({:.0}% of content)",
        session.dictation_events.len(),
        total_words,
        ratio * 100.0,
    )];

    // Flag suspicious dictation characteristics.
    let has_virtual_audio = session
        .dictation_events
        .iter()
        .any(|e| e.audio_transport_type == 7);
    if has_virtual_audio {
        lims.push("Dictation used virtual audio device (possible replay attack)".into());
    }
    let has_speaker_output = session
        .dictation_events
        .iter()
        .any(|e| e.speaker_output_active);
    if has_speaker_output {
        lims.push("Speaker output was active during dictation (possible audio loopback)".into());
    }

    lims
}

/// Collect composition mode as a limitation/attestation claim.
fn collect_composition_mode_limitations(path: &str, event_count: usize) -> Vec<String> {
    let sentinel = match get_sentinel() {
        Some(s) => s,
        None => return vec![],
    };
    let sessions = sentinel.sessions.read_recover();
    let session = match sessions.get(path) {
        Some(s) => s,
        None => return vec![],
    };

    let switches: Vec<_> = session.focus_switches.iter().cloned().collect();
    let pastes: Vec<_> = session.paste_context.iter().cloned().collect();
    let cm = match crate::forensics::composition_mode::analyze_composition_mode(
        &switches,
        &pastes,
        event_count,
    ) {
        Some(c) => c,
        None => return vec![],
    };

    let mut lims = Vec::new();

    if cm.ai_cycle_count > 0 {
        lims.push(format!(
            "AI-mediated composition cycles detected: {}",
            cm.ai_cycle_count
        ));
    }

    if cm.distribution.paste_veneer > 0.2 {
        lims.push(format!(
            "Paste-veneer pattern: {:.0}% of session",
            cm.distribution.paste_veneer * 100.0
        ));
    }

    if cm.distribution.ai_mediated > 0.1 {
        lims.push(format!(
            "AI-mediated mode: {:.0}% of session",
            cm.distribution.ai_mediated * 100.0
        ));
    }

    // Always report dominant mode for transparency.
    if let Some(mode) = cm.dominant_mode {
        lims.push(format!("Dominant composition mode: {mode}"));
    }

    lims
}

/// Return a compact reference string for the latest event on a tracked file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_compact_ref(path: String) -> String {
    catch_ffi_panic!(String::new(), {
    log::debug!("ffi_get_compact_ref: path={}", path);
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
    })
}

/// Extract the embedded document from a .cpoe evidence package.
/// Returns an FfiResult with the output path on success.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_extract_document(cpoe_path: String, output_path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_extract_document: cpoe_path={} output_path={}", cpoe_path, output_path);
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
        if let Err(e) = tmp.as_file().sync_all() {
            return FfiResult::err(format!("Failed to sync document to disk: {e}"));
        }
        if let Err(e) = tmp.persist(&out) {
            return FfiResult::err(format!("Failed to finalize document: {e}"));
        }
    }

    FfiResult::ok(format!("Document extracted to {}", out.display()))
    })
}

/// Collect project file references for all tracked files under the same
/// Compute session-level forensic metrics for embedding in the evidence packet.
fn build_forensic_summary(
    path: &str,
    events: &[crate::store::SecureEvent],
) -> Option<ForensicSummaryWire> {
    if events.len() < 2 {
        return None;
    }
    let (metrics, _regions) = crate::ffi::helpers::run_full_forensics(events);
    let mean_iki_ms = metrics.cadence.mean_iki_ns / 1_000_000.0;
    let wpm = if mean_iki_ms > 0.0 {
        (1000.0 / mean_iki_ms) * 12.0 // chars/sec * 60 / 5 chars-per-word
    } else {
        0.0
    };

    let writing_mode = metrics
        .writing_mode
        .as_ref()
        .map(|wm| wm.mode.to_string())
        .unwrap_or_else(|| "insufficient".to_string());

    let (editing_ratio, session_keystroke_count) = if let Some(sentinel) = super::sentinel::get_sentinel() {
        let sessions = sentinel.sessions();
        let session = sessions
            .iter()
            .find(|s| s.path == path);
        (
            session.map(|s| s.semantic_counts.editing_ratio()).unwrap_or(0.0),
            session.map(|s| s.keystroke_count),
        )
    } else {
        (0.0, None)
    };

    let keystroke_count = session_keystroke_count.unwrap_or_else(|| {
        crate::ffi::helpers::open_store()
            .ok()
            .and_then(|store| store.load_document_stats(path).ok().flatten())
            .map(|stats| stats.total_keystrokes as u64)
            .unwrap_or(events.len() as u64)
    });

    use crate::utils::finite_or;
    let cv = if mean_iki_ms > 0.0 && metrics.cadence.std_dev_iki_ns.is_finite() {
        finite_or(metrics.cadence.std_dev_iki_ns / metrics.cadence.mean_iki_ns, 0.0)
    } else {
        0.0
    };

    Some(ForensicSummaryWire {
        words_per_minute: finite_or(wpm, 0.0),
        mean_iki_ms: finite_or(mean_iki_ms, 0.0),
        correction_ratio: finite_or(metrics.cadence.correction_ratio.get(), 0.0),
        writing_mode,
        hurst_exponent: metrics.hurst_exponent.filter(|h| h.is_finite()),
        keystroke_count,
        editing_ratio: finite_or(editing_ratio, 0.0),
        checkpoint_count: events.iter().filter(|e| e.context_type.as_deref() == Some("checkpoint")).count() as u64,
        assessment_score: finite_or(metrics.assessment_score.get(), 0.0),
        coefficient_of_variation: finite_or(cv, 0.0),
        biological_cadence_score: finite_or(metrics.biological_cadence_score.get(), 0.0),
        timing_entropy: finite_or(metrics.primary.timing_entropy, 0.0),
        pause_entropy: finite_or(metrics.primary.pause_entropy, 0.0),
        cognitive_load_score: metrics.cognitive_load.as_ref().map(|cl| cl.composite_score),
        revision_topology_score: metrics.revision_topology.as_ref().map(|rt| rt.composite_score),
        error_ecology_score: metrics.error_ecology.as_ref().map(|ee| ee.composite_score),
        likelihood_p_cognitive: metrics.likelihood_model.as_ref().map(|lm| lm.session_p_cognitive),
        forgery_difficulty: metrics.forgery_cost.as_ref().map(|f| f.overall_difficulty),
        cross_modal_score: metrics.cross_modal.as_ref().map(|cm| cm.score),
        snr_db: metrics.snr.as_ref().map(|s| s.snr_db),
        lyapunov_exponent: metrics.lyapunov.as_ref().map(|l| l.exponent),
        transcription_suspicious: metrics.transcription_suspicion.as_ref().is_some_and(|t| t.is_suspicious),
        composition_mode: metrics.composition_mode.as_ref().and_then(|cm| cm.dominant_mode.map(|m| m.to_string())),
    })
}

/// root directory as the primary document. Walks up to find the project
/// root (looks for .scriv, .git, or stops at the parent of the source).
/// Scans recursively so subdirectories (Draft/, Research/) are included.
fn collect_project_files(
    primary_path: &std::path::Path,
    store: &crate::store::SecureStore,
) -> Option<Vec<authorproof_protocol::rfc::wire_types::ProjectFileRef>> {
    let project_root = find_project_root(primary_path);
    let canonical_root =
        std::fs::canonicalize(&project_root).unwrap_or_else(|_| project_root.clone());

    let all_files = match store.list_files() {
        Ok(files) => files,
        Err(e) => {
            log::debug!("Failed to list project files: {e}");
            return None;
        }
    };

    const MAX_SIBLINGS: usize = 50;
    let canonical_primary =
        std::fs::canonicalize(primary_path).unwrap_or_else(|_| primary_path.to_path_buf());
    let siblings: Vec<_> = all_files
        .into_iter()
        .filter(|(path, _, _)| {
            let canonical = std::fs::canonicalize(path)
                .unwrap_or_else(|_| std::path::PathBuf::from(path));
            if canonical == canonical_primary {
                return false;
            }
            canonical.starts_with(&canonical_root)
        })
        .take(MAX_SIBLINGS)
        .collect();

    if siblings.is_empty() {
        return None;
    }

    let refs: Vec<_> = siblings
        .iter()
        .map(|(path, _last_ts, event_count)| {
            // Relative path from project root for cleaner display
            let canonical_path = std::fs::canonicalize(path)
                .unwrap_or_else(|_| std::path::PathBuf::from(path));
            let rel_path = canonical_path
                .strip_prefix(&canonical_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| {
                    std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone())
                });

            // Get content hash from events and keystroke count from document stats
            let events = store.get_events_for_file(path).unwrap_or_default();
            let content_hash = events
                .last()
                .map(|e| hex::encode(e.content_hash))
                .unwrap_or_default();
            let keystroke_count: u64 = store
                .load_document_stats(path)
                .ok()
                .flatten()
                .map(|stats| stats.total_keystrokes as u64)
                .unwrap_or(0);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SecureEvent;

    fn make_event(index: usize, file_path: &str) -> SecureEvent {
        let ts = 1_700_000_000_000_000_000i64 + (index as i64 * 5_000_000_000);
        SecureEvent {
            id: None,
            device_id: [1u8; 16],
            machine_id: "test-machine".to_string(),
            timestamp_ns: ts,
            file_path: file_path.to_string(),
            content_hash: {
                let mut h = [0u8; 32];
                h[0] = index as u8;
                h
            },
            file_size: 100 + index as i64 * 50,
            size_delta: if index % 3 == 2 { -20 } else { 50 },
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: Some("test".to_string()),
            context_note: None,
            vdf_input: Some([0xAAu8; 32]),
            vdf_output: Some([0xBBu8; 32]),
            vdf_iterations: 1000,
            forensic_score: 0.9,
            is_paste: false,
            hardware_counter: None,
            input_method: None,
            lamport_signature: None,
            lamport_pubkey_fingerprint: None,
            challenge_nonce: None,
            hw_cosign_signature: None,
            hw_cosign_pubkey: None,
            hw_cosign_salt_commitment: None,
            hw_cosign_chain_index: None,
            hw_cosign_entangled_hash: None,
            hw_cosign_entropy_digest: None,
            hw_cosign_entropy_bytes: None,
            posme_proof: None,
            semantic_summary: None,
        }
    }

    fn make_checkpoints(events: &[SecureEvent]) -> Vec<CheckpointWire> {
        events
            .iter()
            .enumerate()
            .map(|(i, ev)| {
                let ts_ms = (ev.timestamp_ns / 1_000_000).max(1) as u64;
                CheckpointWire {
                    sequence: i as u64,
                    checkpoint_id: [i as u8; 16],
                    timestamp: ts_ms,
                    content_hash: HashValue::try_sha256(ev.content_hash.to_vec()).unwrap(),
                    char_count: ev.file_size.max(0) as u64,
                    delta: EditDelta {
                        chars_added: ev.size_delta.max(0) as u64,
                        chars_deleted: (-(ev.size_delta as i64)).max(0) as u64,
                        op_count: 1,
                        positions: None,
                        edit_graph_hash: None,
                        cursor_trajectory_histogram: None,
                        revision_depth_histogram: None,
                        pause_duration_histogram: None,
                        metric_binding_hash: None,
                    },
                    prev_hash: HashValue::try_sha256(ev.previous_hash.to_vec()).unwrap(),
                    checkpoint_hash: HashValue::try_sha256(vec![i as u8; 32]).unwrap(),
                    process_proof: ProcessProof {
                        algorithm: ProofAlgorithm::SwfSha256,
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
                        input: vec![0u8; 32],
                        merkle_root: vec![0u8; 32],
                        sampled_proofs: vec![],
                        claimed_duration: 1000,
                    },
                    jitter_binding: None,
                    physical_state: None,
                    entangled_mac: None,
                    receipts: None,
                    active_probes: None,
                    hat_proof: None,
                    beacon_anchor: None,
                    verifier_nonce: None,
                    lamport_signature: None,
                    lamport_pubkey_fingerprint: None,
                    posme_proof: None,
                }
            })
            .collect()
    }

    #[test]
    fn enrich_populates_positions_and_histograms() {
        let events: Vec<_> = (0..5).map(|i| make_event(i, "/tmp/test.txt")).collect();
        let mut checkpoints = make_checkpoints(&events);

        enrich_checkpoints(&mut checkpoints, &events, "/tmp/test.txt");

        for (i, cp) in checkpoints.iter().enumerate() {
            assert!(
                cp.delta.positions.is_some(),
                "checkpoint {i} should have positions"
            );
            let positions = cp.delta.positions.as_ref().unwrap();
            assert_eq!(positions.len(), 1, "one position per checkpoint");

            assert!(
                cp.delta.cursor_trajectory_histogram.is_some(),
                "checkpoint {i} should have cursor histogram"
            );
            let cursor_hist = cp.delta.cursor_trajectory_histogram.as_ref().unwrap();
            assert_eq!(cursor_hist.len(), 8);
            assert_eq!(
                cursor_hist.iter().sum::<u64>(),
                1,
                "exactly one cursor position per checkpoint"
            );

            assert!(
                cp.delta.revision_depth_histogram.is_some(),
                "checkpoint {i} should have revision depth histogram"
            );
            let rev_hist = cp.delta.revision_depth_histogram.as_ref().unwrap();
            assert_eq!(rev_hist.len(), 8);
            assert_eq!(
                rev_hist.iter().sum::<u64>(),
                (i + 1) as u64,
                "revision depth accumulates"
            );

            assert!(
                cp.delta.edit_graph_hash.is_some(),
                "checkpoint {i} should have edit graph hash"
            );
            assert_eq!(cp.delta.edit_graph_hash.as_ref().unwrap().len(), 32);
        }
    }

    #[test]
    fn enrich_edit_graph_hash_is_deterministic() {
        let events: Vec<_> = (0..3).map(|i| make_event(i, "/tmp/det.txt")).collect();
        let mut cp1 = make_checkpoints(&events);
        let mut cp2 = make_checkpoints(&events);

        enrich_checkpoints(&mut cp1, &events, "/tmp/det.txt");
        enrich_checkpoints(&mut cp2, &events, "/tmp/det.txt");

        for (a, b) in cp1.iter().zip(cp2.iter()) {
            assert_eq!(a.delta.edit_graph_hash, b.delta.edit_graph_hash);
        }
    }

    #[test]
    fn enrich_handles_negative_size_delta() {
        let mut events: Vec<_> = (0..3).map(|i| make_event(i, "/tmp/neg.txt")).collect();
        events[1].size_delta = -100;
        events[1].file_size = 50;
        let mut checkpoints = make_checkpoints(&events);

        enrich_checkpoints(&mut checkpoints, &events, "/tmp/neg.txt");

        let pos = checkpoints[1].delta.positions.as_ref().unwrap();
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0].1, -100, "negative delta preserved");
    }

    #[test]
    fn enrich_empty_inputs_is_noop() {
        let events: Vec<SecureEvent> = vec![];
        let mut checkpoints: Vec<CheckpointWire> = vec![];
        enrich_checkpoints(&mut checkpoints, &events, "/tmp/empty.txt");
        assert!(checkpoints.is_empty());
    }

    #[test]
    fn enrich_no_sentinel_means_no_jitter_binding() {
        let events: Vec<_> = (0..3).map(|i| make_event(i, "/tmp/nojitter.txt")).collect();
        let mut checkpoints = make_checkpoints(&events);

        enrich_checkpoints(&mut checkpoints, &events, "/tmp/nojitter.txt");

        for cp in &checkpoints {
            assert!(
                cp.jitter_binding.is_none(),
                "no jitter binding without sentinel"
            );
            assert!(
                cp.delta.pause_duration_histogram.is_none(),
                "no pause histogram without sentinel jitter data"
            );
        }
    }

    #[test]
    fn baseline_verification_none_without_sentinel() {
        let events: Vec<_> = (0..5).map(|i| make_event(i, "/tmp/baseline.txt")).collect();
        let result = build_baseline_verification("/tmp/baseline.txt", &events);
        assert!(result.is_none(), "no baseline without sentinel");
    }

    #[test]
    fn entropy_centibits_empty_returns_zero() {
        assert_eq!(estimate_entropy_centibits(&[]), 0);
    }

    #[test]
    fn entropy_centibits_uniform_has_max_entropy() {
        // Spread across all bins for high entropy.
        let intervals: Vec<u64> = (0..100)
            .map(|i| IKI_HIST_EDGES_MS[(i % 9) as usize] + 10)
            .collect();
        let e = estimate_entropy_centibits(&intervals);
        assert!(e > 200, "uniform distribution should have high entropy, got {e}");
    }

    #[test]
    fn entropy_centibits_constant_has_low_entropy() {
        // All same value → single bin → zero entropy.
        let intervals = vec![100u64; 50];
        let e = estimate_entropy_centibits(&intervals);
        assert_eq!(e, 0, "constant intervals should have zero entropy");
    }
}
