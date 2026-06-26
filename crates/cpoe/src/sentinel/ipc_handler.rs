// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::core::Sentinel;
use crate::ipc::{IpcErrorCode, IpcMessage, IpcMessageHandler};
use crate::RwLockRecover;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Debug)]
/// IPC message handler that dispatches requests to the sentinel.
pub struct SentinelIpcHandler {
    sentinel: Arc<Sentinel>,
    start_time: SystemTime,
    version: String,
}

impl SentinelIpcHandler {
    /// Create a handler backed by the given sentinel instance.
    pub fn new(sentinel: Arc<Sentinel>) -> Self {
        Self {
            sentinel,
            start_time: SystemTime::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn open_db(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<crate::store::SecureStore>>, String> {
        self.sentinel
            .get_or_open_store()
            .ok_or_else(|| "Signing key not initialized (or locked)".to_string())
    }

    fn load_events(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<crate::store::SecureEvent>, String> {
        let guard = self.open_db()?;
        let db = guard.as_ref().ok_or("Store not available")?;
        db.get_events_for_file(path)
            .map_err(|e| format!("Failed to load events: {e}"))
    }

    fn analyze_file(
        &self,
        path: &PathBuf,
    ) -> Result<
        (
            Vec<crate::store::SecureEvent>,
            crate::forensics::ForensicMetrics,
        ),
        String,
    > {
        let path = super::helpers::validate_path(path)?;
        let events = self.load_events(&path)?;
        if events.is_empty() {
            return Err("No events found for file".to_string());
        }
        let event_data = crate::forensics::EventData::from_secure_events(&events);
        let regions = std::collections::HashMap::new();

        let accumulator = crate::fingerprint::global::get_global_accumulator();
        let accumulator = accumulator.read_recover();
        let jitter_samples = if accumulator.sample_count() > 0 {
            Some(accumulator.samples())
        } else {
            None
        };

        let metrics = crate::forensics::analyze_forensics(
            &event_data,
            &regions,
            jitter_samples.as_deref(),
            None,
            None,
        );
        Ok((events, metrics))
    }

    fn handle_export_with_nonce(
        &self,
        file_path: PathBuf,
        verifier_nonce: [u8; 32],
    ) -> Result<IpcMessage, String> {
        let file_path = super::helpers::validate_path(&file_path)?;
        let guard = self.open_db()?;
        let db = guard.as_ref().ok_or("Store not available")?;
        let events = db
            .get_events_for_file(&file_path)
            .map_err(|e| format!("Failed to load events: {e}"))?;

        let evidence_hash = crate::evidence::compute_events_binding_hash(&events);
        let attestation_nonce = self.sentinel.get_or_generate_nonce();

        let provider = crate::tpm::detect_provider();
        let report = crate::tpm::generate_attestation_report(
            &*provider,
            &verifier_nonce,
            &attestation_nonce,
            evidence_hash,
        )
        .map_err(|e| format!("Hardware quote failed: {e}"))?;

        Ok(IpcMessage::NonceExportResponse {
            success: true,
            output_path: None,
            packet_hash: Some(hex::encode(evidence_hash)),
            verifier_nonce: Some(hex::encode(verifier_nonce)),
            attestation_nonce: Some(hex::encode(attestation_nonce)),
            attestation_report: Some(
                serde_json::to_string(&report)
                    .map_err(|e| format!("Failed to serialize attestation report: {e}"))?,
            ),
            error: None,
        })
    }

    fn handle_verify_with_nonce(
        &self,
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    ) -> Result<IpcMessage, String> {
        let path = super::helpers::validate_path(&evidence_path)?;
        const MAX_EVIDENCE_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
        let meta =
            std::fs::metadata(&path).map_err(|e| format!("Failed to stat evidence file: {e}"))?;
        if meta.len() > MAX_EVIDENCE_FILE_SIZE {
            return Err(format!(
                "Evidence file too large: {} bytes (limit {})",
                meta.len(),
                MAX_EVIDENCE_FILE_SIZE
            ));
        }
        let data =
            std::fs::read(&path).map_err(|e| format!("Failed to read evidence file: {e}"))?;
        let cbor_payload = crate::evidence::unwrap_cose_or_raw(&data);
        let packet = crate::evidence::Packet::decode(&cbor_payload)
            .map_err(|e| format!("Failed to decode evidence: {e}"))?;

        let vdf_params = packet.vdf_params;
        let chain_ok = packet.verify_self_signed(vdf_params).is_ok();
        let sig_ok = packet.verify_signature(expected_nonce.as_ref()).is_ok();
        let nonce_valid = match (&expected_nonce, packet.verifier_nonce.as_ref()) {
            (Some(expected), Some(actual)) => *actual == *expected,
            (None, None) => true,
            _ => false,
        };

        let mut errors = Vec::new();
        if !chain_ok {
            errors.push("Chain integrity verification failed".to_string());
        }
        if !sig_ok {
            errors.push(
                "Signature verification failed (nonce mismatch or invalid signature)".to_string(),
            );
        }
        if !nonce_valid {
            errors.push("Verifier nonce does not match expected nonce".to_string());
        }

        Ok(IpcMessage::NonceVerifyResponse {
            valid: chain_ok && sig_ok && nonce_valid,
            nonce_valid,
            checkpoint_count: packet.checkpoints.len() as u64,
            total_elapsed_time_secs: packet.total_elapsed_time().as_secs_f64(),
            verifier_nonce: packet.verifier_nonce.as_ref().map(hex::encode),
            attestation_nonce: packet
                .hardware
                .as_ref()
                .and_then(|hw| hw.attestation_nonce)
                .map(hex::encode),
            errors,
        })
    }

    fn handle_create_checkpoint(
        &self,
        path: PathBuf,
        message: String,
    ) -> Result<IpcMessage, String> {
        if message.len() > 4096 {
            return Err("Checkpoint message too long (max 4096 bytes)".to_string());
        }
        if message
            .bytes()
            .any(|b| b < 0x20 && b != b'\n' && b != b'\t')
        {
            return Err("Checkpoint message contains invalid control characters".to_string());
        }
        let path = super::helpers::validate_path(&path)?;
        let writersproof_dir = &self.sentinel.config.writersproof_dir;
        let vdf_params = crate::vdf::default_parameters();

        let doc_id = crate::utils::document_id_from_path(&path);
        let chain_path = writersproof_dir
            .join("chains")
            .join(format!("{doc_id}.json"));

        let chain_mac_key = {
            let guard = self.sentinel.signing_key.read_recover();
            match guard.key() {
                Some(k) => {
                    let bytes = Zeroizing::new(k.to_bytes());
                    crate::crypto::derive_hmac_key(bytes.as_ref())
                }
                None => {
                    return Err("Checkpoint requires an initialized signing key".to_string());
                }
            }
        };

        let mut chain = if chain_path.exists() {
            crate::checkpoint::Chain::load_with_mac(&chain_path, &chain_mac_key)
                .map_err(|e| format!("Failed to load chain: {e}"))?
        } else {
            crate::checkpoint::Chain::new(&path, vdf_params)
                .map_err(|e| format!("Failed to create chain: {e}"))?
        };

        let checkpoint =
            if chain.metadata.entanglement_mode == crate::checkpoint::EntanglementMode::Entangled {
                let path_str = path.to_string_lossy().to_string();
                let (jitter_hash, keystroke_count, session_id, samples) = {
                    let sessions = self.sentinel.sessions.read_recover();
                    match sessions.get(&path_str) {
                        Some(s) => (
                            s.jitter_hash_state,
                            s.jitter_ring.len() as u64,
                            s.session_id.clone(),
                            s.jitter_ring.to_vec_chronological(),
                        ),
                        None => {
                            // No active session: derive a document-specific fallback
                            // so the jitter binding is not a known constant.
                            let fallback = {
                                let mut h = Sha256::new();
                                h.update(b"cpoe-jitter-fallback-v1");
                                h.update(path_str.as_bytes());
                                h.finalize().into()
                            };
                            (fallback, 0u64, uuid::Uuid::new_v4().to_string(), Vec::new())
                        }
                    }
                };

                let physics = crate::physics::PhysicalContext::capture(&samples);

                chain
                    .commit_entangled(
                        Some(message),
                        jitter_hash,
                        session_id,
                        keystroke_count,
                        std::time::Duration::from_secs(1),
                        Some(&physics),
                    )
                    .map_err(|e| format!("Entangled commit failed: {e}"))?
            } else {
                chain
                    .commit(Some(message))
                    .map_err(|e| format!("Commit failed: {e}"))?
            };
        chain
            .save_with_mac(&chain_path, &chain_mac_key)
            .map_err(|e| format!("Failed to save chain: {e}"))?;

        Ok(IpcMessage::CheckpointResponse {
            success: true,
            hash: Some(hex::encode(checkpoint.hash)),
            error: None,
        })
    }

    fn handle_verify_file(&self, path: PathBuf) -> Result<IpcMessage, String> {
        let validated_path = super::helpers::validate_path(&path)?;
        const MAX_EVIDENCE_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
        let meta =
            std::fs::metadata(&validated_path).map_err(|e| format!("Failed to stat file: {e}"))?;
        if meta.len() > MAX_EVIDENCE_FILE_SIZE {
            return Err(format!(
                "File too large: {} bytes (limit {})",
                meta.len(),
                MAX_EVIDENCE_FILE_SIZE
            ));
        }
        let data =
            std::fs::read(&validated_path).map_err(|e| format!("Failed to read file: {e}"))?;
        let cbor_payload = crate::evidence::unwrap_cose_or_raw(&data);
        let packet = crate::evidence::Packet::decode(&cbor_payload)
            .map_err(|e| format!("Failed to decode evidence: {e}"))?;

        let vdf_params = packet.vdf_params;
        let chain_ok = packet.verify_self_signed(vdf_params).is_ok();
        let sig_ok = packet.verify_signature(None).is_ok();

        Ok(IpcMessage::VerifyFileResponse {
            success: chain_ok && sig_ok,
            checkpoint_count: packet.checkpoints.len() as u32,
            signature_valid: sig_ok,
            chain_integrity: chain_ok,
            vdf_iterations_per_second: vdf_params.iterations_per_second,
            error: None,
        })
    }

    fn handle_export_file(&self, path: PathBuf, output: PathBuf) -> Result<IpcMessage, String> {
        let writersproof_dir = &self.sentinel.config.writersproof_dir;

        let validated_path = super::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid source path: {e}"))?;
        let validated_output = super::helpers::validate_path(&output)
            .map_err(|e| format!("Invalid output path: {e}"))?;

        let chain_path = crate::checkpoint::Chain::find_chain(&validated_path, writersproof_dir)
            .map_err(|e| format!("No chain found: {e}"))?;
        let chain = crate::checkpoint::Chain::load(&chain_path)
            .map_err(|e| format!("Failed to load chain: {e}"))?;

        if chain.checkpoints.is_empty() {
            return Err("Chain has no checkpoints".to_string());
        }
        chain
            .verify()
            .map_err(|e| format!("Chain integrity check failed before export: {e}"))?;

        let title = validated_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Untitled".to_string());
        let mut builder = crate::evidence::Builder::new(&title, &chain);

        let latest = chain
            .latest()
            .ok_or("Chain reported non-empty but latest() returned None")?;

        let (decl, identity_fingerprint, hmac_key) = {
            let signing_key_guard = self.sentinel.signing_key.read_recover();
            let signing_key = signing_key_guard
                .key()
                .ok_or("Signing key not initialized (or locked)")?;
            let decl = crate::declaration::no_ai_declaration(
                latest.content_hash,
                latest.hash,
                &title,
                "Exported via IPC",
            )
            .sign(&signing_key)
            .map_err(|e| format!("Declaration signing failed: {e}"))?;
            let mut hasher = Sha256::new();
            hasher.update(signing_key.verifying_key().to_bytes());
            let fingerprint = hasher.finalize().to_vec();
            let key_bytes = Zeroizing::new(signing_key.to_bytes());
            let hmac = crate::crypto::derive_hmac_key(key_bytes.as_ref());
            (decl, fingerprint, hmac)
        };
        builder = builder.with_declaration(&decl);

        let summary = crate::fingerprint::global::get_global_accumulator()
            .read_recover()
            .to_session_summary();
        let mut bv = authorproof_protocol::baseline::BaselineVerification {
            digest: None,
            session_summary: summary,
            digest_signature: None,
        };

        let db_path = self.sentinel.config.writersproof_dir.join("events.db");
        let store_opt = crate::store::SecureStore::open(&db_path, hmac_key).ok();

        if let Some(ref store) = store_opt {
            if let Ok(Some((cbor, sig))) = store.get_baseline_digest(&identity_fingerprint) {
                if let Ok(digest) =
                    serde_json::from_slice::<authorproof_protocol::baseline::BaselineDigest>(&cbor)
                {
                    bv.digest = Some(digest);
                    bv.digest_signature = Some(sig);
                }
            }
        }
        builder = builder.with_baseline_verification(bv);

        let jitter_samples = crate::fingerprint::global::get_global_accumulator()
            .read_recover()
            .samples();
        let physics = crate::physics::PhysicalContext::capture(&jitter_samples);
        builder = builder.with_physical_context(&physics);

        // Attach per-document behavioral and keystroke evidence.
        let path_str = validated_path.to_string_lossy().to_string();

        // Per-document typing samples from the active session (if any).
        let typing_samples = {
            let sessions = self.sentinel.sessions.read_recover();
            sessions
                .get(&path_str)
                .filter(|s| !s.jitter_ring.is_empty())
                .map(|s| s.jitter_ring.to_vec_chronological())
                .unwrap_or_default()
        };

        // Load stored events for edit topology and keystroke statistics.
        let store_events = store_opt
            .as_ref()
            .and_then(|s| s.get_events_for_file(&path_str).ok())
            .unwrap_or_default();

        if !store_events.is_empty() {
            // Edit topology from size_delta sequences.
            let max_size = store_events
                .iter()
                .map(|e| e.file_size.max(1))
                .max()
                .unwrap_or(1) as f64;
            let edit_regions: Vec<crate::evidence::EditRegion> = store_events
                .iter()
                .map(|e| {
                    let delta = e.size_delta;
                    let cursor = crate::utils::Probability::clamp(
                        (e.file_size as f64 - delta.abs() as f64) / max_size,
                    )
                    .get();
                    let extent =
                        crate::utils::Probability::clamp(delta.abs() as f64 / max_size).get();
                    crate::evidence::EditRegion {
                        start_pct: cursor,
                        end_pct: (cursor + extent).min(1.0),
                        delta_sign: if delta > 0 {
                            1i32
                        } else if delta < 0 {
                            -1i32
                        } else {
                            0i32
                        },
                        byte_count: delta.abs(),
                    }
                })
                .collect();

            builder = builder.with_behavioral_full(edit_regions, None, &typing_samples);

            // Attach fingerprint maturity so verifiers know the enforcement stage.
            let profile_id = hex::encode(&identity_fingerprint);
            let fp_defaults = crate::config::FingerprintConfig::default();
            let session_count = store_opt
                .as_ref()
                .and_then(|s| s.get_fingerprint_session_count(&profile_id).ok())
                .unwrap_or(0);
            let maturity = crate::fingerprint::FingerprintMaturity::from_session_count(
                session_count,
                fp_defaults.bootstrap_sessions,
                fp_defaults.advisory_sessions,
            );
            builder = builder.with_fingerprint_maturity(maturity);

            // Build KeystrokeEvidence from session or store events.
            let first_ts = store_events.first().map(|e| e.timestamp_ns).unwrap_or(0);
            let last_ts = store_events.last().map(|e| e.timestamp_ns).unwrap_or(0);
            let started_at = chrono::DateTime::from_timestamp_nanos(first_ts);
            let ended_at = chrono::DateTime::from_timestamp_nanos(last_ts);
            let elapsed_ns = crate::utils::ns_elapsed(last_ts, first_ts);
            let duration_secs = crate::utils::ns_to_secs(elapsed_ns as i64);

            let (session_id, total_keystrokes, unique_states) = {
                let sessions = self.sentinel.sessions.read_recover();
                if let Some(session) = sessions.get(&path_str) {
                    (
                        session.session_id.clone(),
                        session.total_keystrokes(),
                        session.save_count,
                    )
                } else {
                    // Session inactive; get accumulated stats from store.
                    let stored_keystrokes = store_opt
                        .as_ref()
                        .and_then(|s| s.load_document_stats(&path_str).ok().flatten())
                        .map(|ds| ds.total_keystrokes as u64)
                        .unwrap_or(0);
                    (
                        crate::utils::short_hex_id(&latest.hash),
                        stored_keystrokes,
                        store_events.iter().filter(|e| e.size_delta != 0).count() as u32,
                    )
                }
            };

            let kpm = if duration_secs > 0.0 {
                (total_keystrokes as f64 / duration_secs) * 60.0
            } else {
                0.0
            };

            let ks = crate::evidence::KeystrokeEvidence {
                session_id,
                started_at,
                ended_at,
                duration: std::time::Duration::from_nanos(elapsed_ns),
                total_keystrokes,
                total_samples: i32::try_from(typing_samples.len()).unwrap_or(i32::MAX),
                keystrokes_per_minute: kpm,
                unique_doc_states: i32::try_from(unique_states).unwrap_or(i32::MAX),
                chain_valid: !chain.checkpoints.is_empty(),
                plausible_human_rate: (1.0..=600.0).contains(&kpm) || total_keystrokes < 10,
                samples: Vec::new(),
                typing_samples,
                phys_ratio: None,
            };
            builder = builder.with_keystroke_evidence(ks);
        }

        #[cfg(feature = "ffi")]
        if let Some(beacon) = crate::ffi::beacon::load_beacon_attestation(&path_str) {
            builder = builder.with_beacon_attestation(beacon);
        }

        let packet = builder
            .build()
            .map_err(|e| format!("Failed to build packet: {e}"))?;

        let format = if output.extension().map(|e| e == "json").unwrap_or(false) {
            authorproof_protocol::codec::Format::Json
        } else {
            authorproof_protocol::codec::Format::Cbor
        };
        let encoded = packet
            .encode_with_format(format)
            .map_err(|e| format!("Failed to encode packet: {e}"))?;

        {
            use std::io::Write;
            let parent = validated_output
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let mut tmp = tempfile::NamedTempFile::new_in(parent)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;
            tmp.write_all(&encoded)
                .map_err(|e| format!("Failed to write temp file: {e}"))?;
            tmp.as_file()
                .sync_all()
                .map_err(|e| format!("Failed to sync temp file: {e}"))?;
            tmp.persist(&validated_output)
                .map_err(|e| format!("Failed to rename output: {e}"))?;
        }

        Ok(IpcMessage::ExportFileResponse {
            success: true,
            error: None,
        })
    }

    fn handle_get_forensics(&self, path: PathBuf) -> Result<IpcMessage, String> {
        let (_events, metrics) = self.analyze_file(&path)?;

        Ok(IpcMessage::ForensicsResponse {
            assessment_score: metrics.assessment_score.get(),
            risk_level: metrics.risk_level.to_string(),
            anomaly_count: metrics.anomaly_count as u32,
            monotonic_append_ratio: metrics.primary.monotonic_append_ratio.get(),
            edit_entropy: metrics.primary.edit_entropy,
            median_interval: metrics.primary.median_interval,
            biological_cadence_score: metrics.biological_cadence_score.get(),
            error: None,
        })
    }

    fn handle_process_score(&self, path: PathBuf) -> Result<IpcMessage, String> {
        /// Maximum edit entropy used for sequence score normalization.
        const SEQUENCE_ENTROPY_CAP: f64 = 3.0;
        /// Weight of entropy component in sequence sub-score.
        const SEQUENCE_ENTROPY_WEIGHT: f64 = 0.5;
        /// Weight of append-ratio component in sequence sub-score.
        const SEQUENCE_APPEND_WEIGHT: f64 = 0.5;

        let (events, metrics) = self.analyze_file(&path)?;

        let residency = if events.len() >= crate::forensics::MIN_EVENTS_FOR_RESIDENCY {
            1.0
        } else {
            events.len() as f64 / crate::forensics::MIN_EVENTS_FOR_RESIDENCY as f64
        };
        let edit_entropy = if metrics.primary.edit_entropy.is_finite() {
            metrics.primary.edit_entropy
        } else {
            0.0
        };
        let append_ratio = if metrics.primary.monotonic_append_ratio.is_finite() {
            metrics.primary.monotonic_append_ratio.get()
        } else {
            0.0
        };
        let sequence = (edit_entropy.min(SEQUENCE_ENTROPY_CAP) / SEQUENCE_ENTROPY_CAP
            * SEQUENCE_ENTROPY_WEIGHT)
            + (append_ratio * SEQUENCE_APPEND_WEIGHT);
        let behavioral = if metrics.assessment_score.is_finite() {
            metrics.assessment_score.get()
        } else {
            0.0
        };
        let composite = crate::forensics::PROCESS_SCORE_WEIGHT_RESIDENCY * residency
            + crate::forensics::PROCESS_SCORE_WEIGHT_SEQUENCE * sequence
            + crate::forensics::PROCESS_SCORE_WEIGHT_BEHAVIORAL * behavioral;

        Ok(IpcMessage::ProcessScoreResponse {
            residency,
            sequence,
            behavioral,
            composite,
            meets_threshold: composite >= crate::forensics::PROCESS_SCORE_PASS_THRESHOLD,
            error: None,
        })
    }
}

impl IpcMessageHandler for SentinelIpcHandler {
    fn handle(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Handshake { version } => IpcMessage::HandshakeAck {
                version,
                server_version: self.version.clone(),
            },

            IpcMessage::Heartbeat => IpcMessage::HeartbeatAck {
                timestamp_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            },

            IpcMessage::StartWitnessing { file_path } => {
                let file_path = match super::helpers::validate_path(&file_path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: IpcErrorCode::PermissionDenied,
                            message: format!("Invalid path: {e}"),
                        }
                    }
                };
                match self.sentinel.start_witnessing(&file_path) {
                    Ok(()) => IpcMessage::Ok {
                        message: Some(format!("Now tracking: {}", file_path.display())),
                    },
                    Err((code, message)) => IpcMessage::Error { code, message },
                }
            }

            IpcMessage::StopWitnessing { file_path } => match file_path {
                Some(path) => {
                    let path = match super::helpers::validate_path(&path) {
                        Ok(p) => p,
                        Err(e) => {
                            return IpcMessage::Error {
                                code: IpcErrorCode::PermissionDenied,
                                message: format!("Invalid path: {e}"),
                            }
                        }
                    };
                    match self.sentinel.stop_witnessing(&path) {
                        Ok(()) => IpcMessage::Ok {
                            message: Some(format!("Stopped tracking: {}", path.display())),
                        },
                        Err((code, message)) => IpcMessage::Error { code, message },
                    }
                }
                None => IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: "Must specify a file path to stop witnessing".into(),
                },
            },

            IpcMessage::GetStatus => {
                let tracked_files = self.sentinel.tracked_files();
                let uptime_secs = self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                IpcMessage::StatusResponse {
                    running: self.sentinel.is_running(),
                    tracked_files,
                    uptime_secs,
                }
            }

            IpcMessage::GetAttestationNonce => IpcMessage::AttestationNonceResponse {
                nonce: self.sentinel.get_or_generate_nonce(),
            },

            IpcMessage::ExportWithNonce {
                file_path,
                verifier_nonce,
                ..
            } => self
                .handle_export_with_nonce(file_path, verifier_nonce)
                .unwrap_or_else(|e| IpcMessage::NonceExportResponse {
                    success: false,
                    output_path: None,
                    packet_hash: None,
                    verifier_nonce: None,
                    attestation_nonce: None,
                    attestation_report: None,
                    error: Some(e),
                }),

            IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            } => self
                .handle_verify_with_nonce(evidence_path, expected_nonce)
                .unwrap_or_else(|e| IpcMessage::NonceVerifyResponse {
                    valid: false,
                    nonce_valid: false,
                    checkpoint_count: 0,
                    total_elapsed_time_secs: 0.0,
                    verifier_nonce: None,
                    attestation_nonce: None,
                    errors: vec![e],
                }),

            IpcMessage::CreateFileCheckpoint { path, message } => self
                .handle_create_checkpoint(path, message)
                .unwrap_or_else(|e| IpcMessage::CheckpointResponse {
                    success: false,
                    hash: None,
                    error: Some(e),
                }),

            IpcMessage::VerifyFile { path } => {
                self.handle_verify_file(path)
                    .unwrap_or_else(|e| IpcMessage::VerifyFileResponse {
                        success: false,
                        checkpoint_count: 0,
                        signature_valid: false,
                        chain_integrity: false,
                        vdf_iterations_per_second: 0,
                        error: Some(e),
                    })
            }

            IpcMessage::ExportFile { path, output, .. } => self
                .handle_export_file(path, output)
                .unwrap_or_else(|e| IpcMessage::ExportFileResponse {
                    success: false,
                    error: Some(e),
                }),

            IpcMessage::GetFileForensics { path } => self
                .handle_get_forensics(path)
                .unwrap_or_else(|e| IpcMessage::ForensicsResponse {
                    assessment_score: 0.0,
                    risk_level: "INSUFFICIENT DATA".to_string(),
                    anomaly_count: 0,
                    monotonic_append_ratio: 0.0,
                    edit_entropy: 0.0,
                    median_interval: 0.0,
                    biological_cadence_score: 0.0,
                    error: Some(e),
                }),

            IpcMessage::ComputeProcessScore { path } => self
                .handle_process_score(path)
                .unwrap_or_else(|e| IpcMessage::ProcessScoreResponse {
                    residency: 0.0,
                    sequence: 0.0,
                    behavioral: 0.0,
                    composite: 0.0,
                    meets_threshold: false,
                    error: Some(e),
                }),

            IpcMessage::Ok { .. }
            | IpcMessage::Error { .. }
            | IpcMessage::HandshakeAck { .. }
            | IpcMessage::HeartbeatAck { .. }
            | IpcMessage::StatusResponse { .. }
            | IpcMessage::AttestationNonceResponse { .. }
            | IpcMessage::NonceExportResponse { .. }
            | IpcMessage::NonceVerifyResponse { .. }
            | IpcMessage::VerifyFileResponse { .. }
            | IpcMessage::ExportFileResponse { .. }
            | IpcMessage::ForensicsResponse { .. }
            | IpcMessage::ProcessScoreResponse { .. }
            | IpcMessage::CheckpointResponse { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Unexpected response message received as request".into(),
            },

            IpcMessage::Pulse(_)
            | IpcMessage::CheckpointCreated { .. }
            | IpcMessage::SystemAlert { .. }
            | IpcMessage::BrowserKeystroke { .. }
            | IpcMessage::BrowserKeystrokeBatch { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Push events cannot be sent to the server".into(),
            },
        }
    }
}
