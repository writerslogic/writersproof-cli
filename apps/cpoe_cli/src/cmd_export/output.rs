// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use sha2::Digest;

use cpoe::authorproof_protocol::crypto::EvidenceSigner;
use cpoe::authorproof_protocol::rfc::CBOR_TAG_EVIDENCE_PACKET;
use cpoe::evidence;
use cpoe::report::{self, WarReport};
use cpoe::war;

use crate::output::OutputMode;



/// Parameters for evidence output.
pub(super) struct EvidenceOutputContext<'a> {
    pub(super) format_lower: &'a str,
    pub(super) out_path: &'a Path,
    pub(super) file_path: &'a Path,
    pub(super) events: &'a [cpoe::SecureEvent],
    pub(super) packet: &'a serde_json::Value,
    pub(super) signer: &'a dyn EvidenceSigner,
    pub(super) vdf_params: &'a cpoe::vdf::params::Parameters,
    pub(super) tier: &'a str,
    pub(super) tier_lower: &'a str,
    pub(super) spec_content_tier: u8,
    pub(super) spec_profile_uri: &'a str,
    pub(super) spec_attestation_tier: u8,
    pub(super) total_vdf_time: &'a Duration,
    pub(super) caps: &'a cpoe::tpm::Capabilities,
    pub(super) tpm_device_id: &'a str,
    pub(super) out: &'a OutputMode,
}

pub(super) fn write_atomic(out_path: &Path, data: &[u8]) -> Result<()> {
    let dir = out_path.parent().unwrap_or(Path::new("."));
    cpoe::store::check_disk_space(dir)
        .context("pre-write disk space check")?;
    let mut tmp =
        tempfile::NamedTempFile::new_in(dir).context("create temp file for atomic write")?;
    tmp.write_all(data).context("write evidence data")?;
    tmp.as_file().sync_all().context("fsync evidence data")?;
    tmp.persist(out_path)
        .context("atomic rename to final path")?;
    // Flush the parent directory entry so the rename survives a crash (Unix only).
    #[cfg(unix)]
    {
        if let Ok(dir_file) = std::fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }
    Ok(())
}

pub(super) fn write_evidence_output(ctx: &EvidenceOutputContext<'_>) -> Result<()> {
    let EvidenceOutputContext {
        format_lower,
        out_path,
        file_path,
        events,
        packet,
        signer,
        vdf_params,
        tier,
        tier_lower,
        spec_content_tier,
        spec_profile_uri,
        spec_attestation_tier,
        total_vdf_time,
        caps,
        tpm_device_id,
        out,
    } = ctx;

    let verbose = !out.quiet && !out.json;

    match *format_lower {
        "html" | "report" => {
            let pub_key = signer.public_key();
            let key_fp = if pub_key.len() >= 8 {
                format!(
                    "{}...{}",
                    hex::encode(&pub_key[..4]),
                    hex::encode(&pub_key[pub_key.len() - 4..])
                )
            } else {
                hex::encode(&pub_key)
            };
            let mut war_report = build_war_report(
                events,
                vdf_params,
                tier,
                total_vdf_time,
                caps.hardware_backed,
                tpm_device_id,
                &key_fp,
            );
            enrich_report_vc(&mut war_report, events, ctx.signer, ctx.packet);
            let html = report::render_html(&war_report);

            write_atomic(out_path, html.as_bytes())?;

            if verbose {
                println!();
                println!("Authorship report exported to: {}", out_path.display());
                println!("  Report ID: {}", war_report.report_id);
                println!(
                    "  Score: {}/100 ({})",
                    war_report.score,
                    war_report.verdict.label()
                );
                println!("  Checkpoints: {}", events.len());
                println!("  Open in a browser to view, or print to PDF.");
            }
        }
        "pdf" => {
            let pub_key = signer.public_key();
            let key_fp = if pub_key.len() >= 8 {
                format!(
                    "{}...{}",
                    hex::encode(&pub_key[..4]),
                    hex::encode(&pub_key[pub_key.len() - 4..])
                )
            } else {
                hex::encode(&pub_key)
            };
            let mut war_report = build_war_report(
                events,
                vdf_params,
                tier,
                total_vdf_time,
                caps.hardware_backed,
                tpm_device_id,
                &key_fp,
            );
            enrich_report_vc(&mut war_report, events, ctx.signer, ctx.packet);

            // Compute security feature seed: sign("cpoe-security-v1" || H3)
            // This binds the guilloché/microtext patterns to this specific evidence.
            let security_seed = {
                let evidence_packet: evidence::Packet = serde_json::from_value(ctx.packet.clone())
                    .context("create evidence packet for security seed")?;
                if let Ok(block) = war::Block::from_packet_signed(&evidence_packet, ctx.signer) {
                    let mut msg = b"cpoe-security-v1".to_vec();
                    msg.extend_from_slice(&block.seal.h3);
                    ctx.signer.sign(&msg).ok().and_then(|sig| {
                        let mut seed = [0u8; 64];
                        if sig.len() == 64 {
                            seed.copy_from_slice(&sig);
                            Some(seed)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            };
            let pdf_bytes = report::render_pdf(&war_report, security_seed.as_ref())
                .map_err(|e| anyhow!("PDF generation failed: {e}"))?;

            write_atomic(out_path, &pdf_bytes)?;

            if verbose {
                println!();
                println!("PDF report exported to: {}", out_path.display());
                println!("  Report ID: {}", war_report.report_id);
                println!(
                    "  Score: {}/100 ({})",
                    war_report.score,
                    war_report.verdict.label()
                );
                println!("  Checkpoints: {}", events.len());
                println!(
                    "  SHA-256: {}",
                    hex::encode(sha2::Sha256::digest(&pdf_bytes))
                );
            }
        }
        "c2pa" => {
            use cpoe::authorproof_protocol::c2pa::C2paManifestBuilder;
            use cpoe::authorproof_protocol::rfc::{
                self as proto_rfc, Checkpoint as ProtoCheckpoint,
                DocumentRef as ProtoDocumentRef, HashValue as ProtoHashValue,
            };
            use std::io::Read as _;

            let latest = events
                .last()
                .ok_or_else(|| anyhow!("No events for C2PA export"))?;

            let document = ProtoDocumentRef {
                content_hash: ProtoHashValue {
                    algorithm: proto_rfc::HashAlgorithm::Sha256,
                    digest: latest.content_hash.to_vec(),
                },
                filename: file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string()),
                byte_length: latest.file_size.max(0) as u64,
                char_count: latest.file_size.max(0) as u64,
            };

            let proto_checkpoints: Vec<ProtoCheckpoint> = events
                .iter()
                .enumerate()
                .map(|(i, ev)| {
                    let mut cp_id = vec![0u8; 16];
                    cp_id[..16].copy_from_slice(&ev.event_hash[..16]);
                    ProtoCheckpoint {
                        sequence: i as u64,
                        checkpoint_id: cp_id,
                        timestamp: (ev.timestamp_ns / 1_000_000).max(0) as u64,
                        content_hash: ProtoHashValue {
                            algorithm: proto_rfc::HashAlgorithm::Sha256,
                            digest: ev.content_hash.to_vec(),
                        },
                        char_count: ev.file_size.max(0) as u64,
                        prev_hash: ProtoHashValue {
                            algorithm: proto_rfc::HashAlgorithm::Sha256,
                            digest: ev.previous_hash.to_vec(),
                        },
                        checkpoint_hash: ProtoHashValue {
                            algorithm: proto_rfc::HashAlgorithm::Sha256,
                            digest: ev.event_hash.to_vec(),
                        },
                        jitter_hash: None,
                    }
                })
                .collect();

            let mut packet_id = vec![0u8; 16];
            getrandom::getrandom(&mut packet_id)
                .context("generate random packet ID for C2PA export")?;

            let proto_packet = proto_rfc::EvidencePacket {
                version: 1,
                profile_uri: spec_profile_uri.to_string(),
                packet_id,
                created: chrono::Utc::now().timestamp_millis() as u64,
                document,
                checkpoints: proto_checkpoints,
                attestation_tier: Some(match *spec_attestation_tier {
                    4 => proto_rfc::AttestationTier::HardwareHardened,
                    3 => proto_rfc::AttestationTier::HardwareBound,
                    2 => proto_rfc::AttestationTier::AttestedSoftware,
                    _ => proto_rfc::AttestationTier::SoftwareOnly,
                }),
                baseline_verification: None,
            };

            let evidence_cbor =
                cpoe::authorproof_protocol::encode_evidence(&proto_packet)
                    .map_err(|e| anyhow!("CBOR encode evidence packet: {}", e))?;

            let mut doc_file = std::fs::File::open(file_path).with_context(|| {
                format!("open document for hashing: {}", file_path.display())
            })?;
            let mut hasher = sha2::Sha256::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = doc_file
                    .read(&mut buf)
                    .context("read document for hash")?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let doc_hash: [u8; 32] = hasher.finalize().into();

            let doc_filename = file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "document".to_string());

            let mut builder = C2paManifestBuilder::new(
                proto_packet,
                evidence_cbor.clone(),
                doc_hash,
            )
            .document_filename(&doc_filename)
            .title(&doc_filename);

            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                let mime = match ext.to_lowercase().as_str() {
                    "txt" | "text" => "text/plain",
                    "md" | "markdown" => "text/markdown",
                    "html" | "htm" => "text/html",
                    "pdf" => "application/pdf",
                    "docx" => {
                        "application/vnd.openxmlformats-officedocument\
                         .wordprocessingml.document"
                    }
                    "doc" => "application/msword",
                    "rtf" => "application/rtf",
                    "odt" => "application/vnd.oasis.opendocument.text",
                    _ => "application/octet-stream",
                };
                builder = builder.format(mime);
            }

            // Enrich C2PA manifest with forensic signals from the event data.
            let event_data = cpoe::forensics::EventData::from_secure_events(events);
            let regions = cpoe::forensics::build_edit_regions(events);
            let analysis_ctx = cpoe::forensics::AnalysisContext::default();
            let metrics = cpoe::forensics::analyze_forensics_ext(
                &event_data, &regions, None, None, None, &analysis_ctx,
            );
            builder = cpoe::ffi::evidence_derivative::enrich_c2pa_builder(builder, &metrics);

            // Build signed VC and embed in manifest (matches FFI path).
            let evidence_packet_engine: evidence::Packet =
                serde_json::from_value(ctx.packet.clone())
                    .context("create evidence packet for assertion")?;
            let policy = cpoe::trust_policy::profiles::basic();
            if let Ok(block) = war::Block::from_packet_appraised(
                &evidence_packet_engine,
                ctx.signer,
                &policy,
            ) {
                if let Some(ear) = block.ear.as_ref() {
                    let provider = cpoe::tpm::detect_provider();
                    if let Some(did_suffix) =
                        cpoe::identity::did_key_from_public(
                            &ctx.signer.public_key(),
                        )
                    {
                        let author_did =
                            format!("did:key:{}", did_suffix);
                        if let Ok(vc) =
                            war::profiles::vc::to_signed_verifiable_credential(
                                ear, &author_did, &*provider,
                            )
                        {
                            if let Ok(vc_json) =
                                serde_json::to_string(&vc)
                            {
                                builder = builder.vc_embedded(vc_json);
                            }
                        }
                    }
                }
            }

            let jumbf_bytes = builder
                .build_jumbf(ctx.signer)
                .map_err(|e| anyhow!("C2PA JUMBF build failed: {}", e))?;

            write_atomic(out_path, &jumbf_bytes)?;

            if verbose {
                println!();
                println!(
                    "C2PA JUMBF manifest exported to: {}",
                    out_path.display()
                );
                println!("  Format: JUMBF binary sidecar (ISO 19566-5)");
                println!("  Document hash: {}", hex::encode(doc_hash));
                println!("  Checkpoints: {}", events.len());
                println!("  Manifest size: {} bytes", jumbf_bytes.len());
                println!("  Evidence CBOR: {} bytes", evidence_cbor.len());
            }
        }
        "md" | "markdown" => {
            let doc_name = file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "document".to_string());

            let first_ts = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
            let last_ts = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
            let first_date = chrono::DateTime::from_timestamp(first_ts / 1_000_000_000, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let last_date = chrono::DateTime::from_timestamp(last_ts / 1_000_000_000, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let content_hash = events
                .last()
                .map(|e| hex::encode(e.content_hash))
                .unwrap_or_default();

            let md = format!(
                "## Authorship Evidence — {doc_name}\n\
                 \n\
                 | Field | Value |\n\
                 |-------|-------|\n\
                 | Document | `{doc_name}` |\n\
                 | Checkpoints | {checkpoints} |\n\
                 | Period | {first_date} — {last_date} |\n\
                 | Content SHA-256 | `{hash}` |\n\
                 | Evidence Tier | {tier} (T{attest}) |\n\
                 | VDF Duration | {vdf:?} |\n\
                 \n\
                 <details><summary>Verification</summary>\n\
                 \n\
                 ```\n\
                 cpoe verify {out}\n\
                 ```\n\
                 \n\
                 Evidence format: CPoE CBOR (tag {tag}), profile `{profile}`\n\
                 </details>\n",
                checkpoints = events.len(),
                hash = &content_hash[..content_hash.len().min(16)],
                tier = tier_lower,
                attest = spec_attestation_tier,
                vdf = total_vdf_time,
                out = out_path.file_name().unwrap_or_default().to_string_lossy(),
                tag = CBOR_TAG_EVIDENCE_PACKET,
                profile = spec_profile_uri,
            );

            write_atomic(out_path, md.as_bytes())?;

            if verbose {
                println!();
                println!("Markdown hash block exported to: {}", out_path.display());
                println!("  Document: {}", doc_name);
                println!("  Checkpoints: {}", events.len());
                println!("  Size: {} bytes", md.len());
            }
        }
        _ => {
            let data = serde_json::to_string_pretty(packet)?;
            write_atomic(out_path, data.as_bytes())?;

            if verbose {
                println!();
                println!("Evidence exported to: {}", out_path.display());
                println!("  Checkpoints: {}", events.len());
                println!("  Total VDF time: {:?}", total_vdf_time);
                println!(
                    "  Tier: {} (content-tier: {})",
                    tier_lower, spec_content_tier
                );
                println!("  Profile: {}", spec_profile_uri);
                println!("  Attestation tier: T{}", spec_attestation_tier);
                println!("  CBOR tag: {} (evidence packet)", CBOR_TAG_EVIDENCE_PACKET);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_war_report(
    events: &[cpoe::store::SecureEvent],
    vdf_params: &cpoe::vdf::params::Parameters,
    tier: &str,
    total_vdf_time: &Duration,
    hardware_backed: bool,
    device_id: &str,
    signing_key_fingerprint: &str,
) -> WarReport {
    use cpoe::report::*;

    let now = Utc::now();
    let report_id = WarReport::generate_id();

    let last = events.last();

    let doc_hash = last
        .map(|e| hex::encode(e.content_hash))
        .unwrap_or_default();
    let doc_size = last.map(|e| e.file_size).unwrap_or(0);

    let avg_forensic: f64 = if events.is_empty() {
        0.0
    } else {
        let s = events.iter().map(|e| e.forensic_score).sum::<f64>() / events.len() as f64;
        if s.is_finite() { s } else { 0.0 }
    };
    let score = (avg_forensic * 100.0).clamp(0.0, 100.0) as u32;
    let verdict = Verdict::from_score_with_events(score, events.len());
    let lr = compute_likelihood_ratio(score);
    let enfsi_tier = EnfsiTier::from_lr(lr);

    let total_secs = total_vdf_time.as_secs_f64();
    let total_min = total_secs / 60.0;

    let sessions = detect_sessions(events);

    let checkpoints: Vec<ReportCheckpoint> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_ms = if vdf_params.iterations_per_second > 0 {
                (ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64 * 1000.0) as u64
            } else {
                0
            };
            ReportCheckpoint {
                ordinal: i as u64,
                timestamp: DateTime::from_timestamp_nanos(ev.timestamp_ns),
                content_hash: hex::encode(ev.content_hash),
                content_size: ev.file_size.max(0) as u64,
                vdf_iterations: Some(ev.vdf_iterations),
                elapsed_ms: Some(elapsed_ms),
            }
        })
        .collect();

    let paste_count = events.iter().filter(|e| e.is_paste).count() as u64;
    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let avg_compute_ms = if !events.is_empty() && vdf_params.iterations_per_second > 0 {
        let avg_iters = total_iterations as f64 / events.len() as f64;
        (avg_iters / vdf_params.iterations_per_second as f64 * 1000.0) as u64
    } else {
        0
    };
    let backdating_hours = if vdf_params.iterations_per_second > 0 {
        total_iterations as f64 / vdf_params.iterations_per_second as f64 / 3600.0
    } else {
        0.0
    };

    let process = ProcessEvidence {
        paste_operations: Some(paste_count),
        swf_checkpoints: Some(events.len() as u64),
        swf_avg_compute_ms: Some(avg_compute_ms),
        swf_chain_verified: true,
        swf_backdating_hours: Some(backdating_hours),
        ..Default::default()
    };

    let flags = build_report_flags(avg_forensic, paste_count, events.len(), total_min);

    let device_attestation = if hardware_backed {
        format!("{} | TPM-bound Ed25519 key | Device ID verified", device_id)
    } else {
        format!("{} | Software-only Ed25519 key", device_id)
    };

    let verdict_desc = verdict_description(&verdict);

    WarReport {
        report_id,
        algorithm_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        generated_at: now,
        schema_version: "WAR-v1.4".into(),
        is_sample: false,
        score,
        verdict,
        verdict_description: verdict_desc,
        likelihood_ratio: lr,
        enfsi_tier,
        document_hash: doc_hash,
        evidence_hash: None,
        evidence_cbor_b64: None,
        signing_key_fingerprint: signing_key_fingerprint.to_string(),
        document_words: None,
        document_chars: Some(doc_size.max(0) as u64),
        document_sentences: None,
        document_paragraphs: None,
        evidence_bundle_version: format!("Signed v1.4 ({})", tier),
        session_count: sessions.len(),
        total_duration_min: total_min,
        revision_events: events.len() as u64,
        device_attestation,
        checkpoints,
        sessions,
        process,
        flags,
        forgery: ForgeryInfo::default(),
        dimensions: Vec::new(),
        writing_flow: Vec::new(),
        methodology: None,
        limitations: vec![
            "Cannot prove cognitive origin of ideas".into(),
            "Cannot prove absence of AI involvement in ideation".into(),
        ],
        analyzed_text: None,
        forensic_metrics: None,
        edit_topology: Vec::new(),
        activity_contexts: Vec::new(),
        declaration_summary: None,
        key_hierarchy_summary: None,
        physical_context: None,
        beacon_info: None,
        anomalies: Vec::new(),
        verifiable_credential_json: None,
        author_did: None,
        provenance_breakdown: None,
    }
}

fn build_report_flags(
    avg_forensic: f64,
    paste_count: u64,
    event_count: usize,
    total_min: f64,
) -> Vec<report::ReportFlag> {
    use cpoe::report::*;

    let mut flags = Vec::new();
    if avg_forensic > 0.7 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Natural Editing Pattern".into(),
            detail: format!(
                "Forensic score {:.2} indicates human editing patterns",
                avg_forensic
            ),
            signal: FlagSignal::Human,
        });
    }
    if paste_count == 0 || (paste_count as f64 / event_count.max(1) as f64) < 0.1 {
        flags.push(ReportFlag {
            category: "Process".into(),
            flag: "Low Paste Ratio".into(),
            detail: format!(
                "{} paste operations across {} checkpoints",
                paste_count, event_count
            ),
            signal: FlagSignal::Human,
        });
    }
    if event_count >= 3 {
        flags.push(ReportFlag {
            category: "Cryptographic".into(),
            flag: "Chain Integrity".into(),
            detail: format!("{} checkpoints with verified hash chain", event_count),
            signal: FlagSignal::Human,
        });
    }
    if total_min > 5.0 {
        flags.push(ReportFlag {
            category: "Temporal".into(),
            flag: "Extended Composition".into(),
            detail: format!("Writing spanned {:.0} minutes with VDF proof", total_min),
            signal: FlagSignal::Human,
        });
    }
    flags
}

fn verdict_description(verdict: &report::Verdict) -> String {
    use cpoe::report::Verdict;
    match verdict {
        Verdict::VerifiedHuman => "Analysis indicates strong evidence of human authorship based on behavioral timing and revision patterns.".into(),
        Verdict::LikelyHuman => "Evidence suggests human authorship with moderate constraint indicators.".into(),
        Verdict::Inconclusive => "Insufficient evidence for a confident determination. Additional checkpoints recommended.".into(),
        Verdict::Suspicious => "Detected anomalies inconsistent with typical human composition behavior.".into(),
        Verdict::LikelySynthetic => "Evidence patterns strongly suggest synthetic or automated content generation.".into(),
        Verdict::InsufficientData => "Insufficient data to make a determination. More writing activity is needed.".into(),
    }
}

fn detect_sessions(events: &[cpoe::store::SecureEvent]) -> Vec<report::ReportSession> {
    if events.is_empty() {
        return vec![];
    }

    let gap_ns: i64 = 30 * 60 * 1_000_000_000;
    let mut sessions = Vec::new();
    let mut session_start = 0usize;

    for i in 1..events.len() {
        let gap = events[i]
            .timestamp_ns
            .saturating_sub(events[i - 1].timestamp_ns);
        if gap > gap_ns {
            sessions.push(make_session(session_start, i - 1, events, sessions.len()));
            session_start = i;
        }
    }
    sessions.push(make_session(
        session_start,
        events.len() - 1,
        events,
        sessions.len(),
    ));

    sessions
}

fn make_session(
    start_idx: usize,
    end_idx: usize,
    events: &[cpoe::store::SecureEvent],
    session_num: usize,
) -> report::ReportSession {
    let first = &events[start_idx];
    let last = &events[end_idx];
    let duration_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns).max(0) as f64;
    let duration_min = duration_ns / 60_000_000_000.0;
    let event_count = end_idx - start_idx + 1;
    let size_change: i64 = events[start_idx..=end_idx]
        .iter()
        .map(|e| e.size_delta as i64)
        .sum();

    report::ReportSession {
        index: session_num + 1,
        start: DateTime::from_timestamp_nanos(first.timestamp_ns),
        duration_min,
        event_count,
        words_drafted: Some((size_change.max(0) as u64) / 5),
        device: Some(first.machine_id.clone()),
        summary: format!(
            "{} revision events, {} net characters changed",
            event_count, size_change
        ),
    }
}

fn enrich_report_vc(
    report: &mut WarReport,
    events: &[cpoe::SecureEvent],
    signer: &dyn EvidenceSigner,
    packet: &serde_json::Value,
) {
    let evidence_packet: evidence::Packet = match serde_json::from_value(packet.clone()) {
        Ok(p) => p,
        Err(_) => return,
    };
    let policy = cpoe::trust_policy::profiles::basic();
    let block = match war::Block::from_packet_appraised(&evidence_packet, signer, &policy) {
        Ok(b) => b,
        Err(_) => return,
    };
    let ear = match block.ear.as_ref() {
        Some(e) => e,
        None => return,
    };
    let author_did = war::profiles::vc::issuer_did();
    let mut vc = match war::profiles::vc::to_verifiable_credential(ear, &author_did) {
        Ok(v) => v,
        Err(_) => return,
    };

    let event_data = cpoe::forensics::EventData::from_secure_events(events);
    let regions = cpoe::forensics::build_edit_regions(events);
    let analysis_ctx = cpoe::forensics::AnalysisContext::default();
    let metrics = cpoe::forensics::analyze_forensics_ext(
        &event_data, &regions, None, None, None, &analysis_ctx,
    );
    let writing_mode = metrics.writing_mode.as_ref().map(|wm| wm.mode.to_string());
    let comp_mode = metrics
        .composition_mode.as_ref()
        .and_then(|c| c.dominant_mode)
        .map(|m| m.to_string());
    let signals = cpoe::ffi::report::build_vc_forensic_signals(&metrics);
    vc.enrich_forensic_signals(writing_mode, comp_mode, signals);

    report.author_did = Some(author_did);
    report.verifiable_credential_json = serde_json::to_string_pretty(&vc).ok();
}

#[allow(dead_code)] // Wired once C2PA manifest embedding is complete
fn build_c2pa_forensic_signals(
    metrics: &cpoe::forensics::ForensicMetrics,
) -> Option<war::profiles::c2pa::C2paForensicSignals> {
    let has_any = metrics.cognitive_load.is_some()
        || metrics.revision_topology.is_some()
        || metrics.error_ecology.is_some()
        || metrics.likelihood_model.is_some()
        || metrics.composition_mode.is_some();
    if !has_any {
        return None;
    }
    Some(war::profiles::c2pa::C2paForensicSignals {
        cognitive_load: metrics
            .cognitive_load.as_ref().map(|c| c.composite_score).unwrap_or(0.0),
        revision_topology: metrics
            .revision_topology.as_ref().map(|r| r.composite_score).unwrap_or(0.0),
        error_ecology: metrics
            .error_ecology.as_ref().map(|e| e.composite_score).unwrap_or(0.0),
        likelihood_model: metrics
            .likelihood_model.as_ref().map(|l| l.session_p_cognitive).unwrap_or(0.0),
        composition_mode: metrics
            .composition_mode.as_ref().map(|c| c.composite_score).unwrap_or(0.0),
        detour_ratio: metrics
            .revision_topology.as_ref().map(|r| r.detour_ratio).unwrap_or(0.0),
        leading_edge_divergence: metrics
            .revision_topology.as_ref().map(|r| r.leading_edge_divergence).unwrap_or(0.0),
        insertion_point_entropy: metrics
            .revision_topology.as_ref().map(|r| r.insertion_point_entropy).unwrap_or(0.0),
    })
}
