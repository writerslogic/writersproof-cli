// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::open_store;
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiResult};

use super::evidence::device_identity;

/// Link a derivative export (PDF, EPUB, DOCX, etc.) to a tracked source document.
///
/// Creates a "derivative" context event in the source's evidence chain that
/// binds the export hash, path, and optional message. The binding is VDF-timed
/// to prove temporal ordering.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_link_derivative(source_path: String, export_path: String, message: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_link_derivative: source_path={}, export_path={}", source_path, export_path);
    let source = try_ffi!(
        crate::sentinel::helpers::validate_path(&source_path)
            .map_err(|e| format!("Invalid source path: {e}")),
        FfiResult
    );
    let export = try_ffi!(
        crate::sentinel::helpers::validate_path(&export_path)
            .map_err(|e| format!("Invalid export path: {e}")),
        FfiResult
    );

    if !source.exists() {
        return FfiResult::err(format!("Source file not found: {}", source.display()));
    }
    if !export.exists() {
        return FfiResult::err(format!("Export file not found: {}", export.display()));
    }

    if let (Ok(cs), Ok(ce)) = (source.canonicalize(), export.canonicalize()) {
        if cs == ce {
            return FfiResult::err("Source and export paths resolve to the same file".to_string());
        }
    }

    let mut store = try_ffi!(open_store(), FfiResult);

    let source_str = source.to_string_lossy().to_string();
    let events = try_ffi!(
        store
            .get_events_for_file(&source_str)
            .map_err(|e| format!("Failed to load events: {e}")),
        FfiResult
    );

    if events.is_empty() {
        return FfiResult::err("No evidence chain for source. Track the file first.".to_string());
    }

    // Note: inherent TOCTOU between size check and hashing below. The file
    // could change between operations, but this is a best-effort guard against
    // accidentally processing very large files, not a security boundary.
    for (label, p) in [("Export", &export), ("Source", &source)] {
        match std::fs::metadata(p) {
            Ok(m) if m.len() > crate::MAX_FILE_SIZE => {
                return FfiResult::err(format!(
                    "{} file too large ({:.0} MB, max {} MB)",
                    label,
                    m.len() as f64 / 1_000_000.0,
                    crate::MAX_FILE_SIZE / 1_000_000
                ));
            }
            Err(e) => {
                return FfiResult::err(format!("{} file metadata error: {e}", label));
            }
            _ => {}
        }
    }

    // Hash both files
    let export_hash = match crate::crypto::hash_file(&export) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult::err(format!("Failed to hash export: {e}"));
        }
    };
    let content_hash = match crate::crypto::hash_file(&source) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult::err(format!("Failed to hash source: {e}"));
        }
    };

    let file_size = std::fs::metadata(&source)
        .map(|m| i64::try_from(m.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);

    let note = if message.is_empty() {
        format!(
            "Derived from {}",
            source.file_name().unwrap_or_default().to_string_lossy()
        )
    } else {
        message
    };
    let context_note = format!(
        "export_hash={};export_path={};{}",
        hex::encode(export_hash),
        export.to_string_lossy(),
        note
    );

    let last = &events[events.len() - 1];
    let size_delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    let vdf_input = last.event_hash;

    // Load VDF params
    let data_dir =
        crate::ffi::helpers::get_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::config::CpopConfig::load_or_default(&data_dir).unwrap_or_else(|e| {
        log::warn!("config load failed, using defaults: {e}");
        Default::default()
    });
    let vdf_params = crate::vdf::params::Parameters {
        iterations_per_second: config.vdf.iterations_per_second.max(1),
        min_iterations: config.vdf.min_iterations,
        max_iterations: config.vdf.max_iterations,
    };

    let vdf_proof =
        match crate::vdf::compute(vdf_input, std::time::Duration::from_secs(1), vdf_params) {
            Ok(p) => p,
            Err(e) => {
                return FfiResult::err(format!("VDF computation failed: {e}"));
            }
        };

    let (dev_id, mach_id) = device_identity();
    let mut event = crate::store::SecureEvent::new(
        source_str.clone(),
        content_hash,
        file_size,
        Some(context_note),
    );
    event.device_id = dev_id;
    event.machine_id = mach_id.clone();
    event.size_delta = size_delta;
    event.context_type = Some("derivative".to_string());
    event.vdf_input = Some(vdf_input);
    event.vdf_output = Some(vdf_proof.output);
    event.vdf_iterations = vdf_proof.iterations;
    event.forensic_score = 1.0;

    match store.add_secure_event(&mut event) {
        Ok(_) => FfiResult::ok(format!(
            "Linked {} to evidence chain (hash: {}...)",
            export.file_name().unwrap_or_default().to_string_lossy(),
            crate::utils::short_hex_id(&export_hash)
        )),
        Err(e) => FfiResult::err(format!("Failed to save link event: {e}")),
    }
    })
}

/// Single-step C2PA export: build evidence, C2PA manifest, and VC, then
/// bundle the original asset + `.c2pa` sidecar manifest + `.vc.json` into
/// a ZIP archive per the C2PA sidecar distribution model.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_c2pa(path: String, tier: String, output: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    super::types::run_on_stack(move || {
    log::debug!("ffi_export_c2pa: path={} tier={} output={}", path, tier, output);

    let doc_file = try_ffi!(
        crate::sentinel::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid document path: {e}")),
        FfiResult
    );
    let out_file = try_ffi!(
        crate::sentinel::helpers::validate_path(&output)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    if !doc_file.exists() {
        return FfiResult::err(format!("Document not found: {}", doc_file.display()));
    }

    // Build evidence packet in memory.
    let (_packet, evidence_bytes, _is_signed) = try_ffi!(
        crate::ffi::evidence_export::build_wire_packet(path.clone(), tier, None, None),
        FfiResult
    );

    let evidence_packet = try_ffi!(
        decode_evidence_for_c2pa(&evidence_bytes),
        FfiResult
    );

    let doc_hash = try_ffi!(
        crate::crypto::hash_file(&doc_file).map_err(|e| format!("Failed to hash document: {e}")),
        FfiResult
    );

    let doc_name = doc_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("document");

    let mime_type = doc_file
        .extension()
        .and_then(|ext| ext.to_str())
        .map(detect_mime_type);

    let mut builder = authorproof_protocol::c2pa::C2paManifestBuilder::new(
        evidence_packet,
        evidence_bytes,
        doc_hash,
    );
    builder = builder.document_filename(doc_name);
    if let Some(ref mime) = mime_type {
        builder = builder.format(mime);
    }

    let signing_key = try_ffi!(
        crate::ffi::helpers::load_signing_key().map_err(|e| format!("Failed to load signing key: {e}")),
        FfiResult
    );
    if let Ok(cert_der) = crate::ffi::helpers::load_or_generate_cert(&signing_key) {
        builder = builder.cert_der(cert_der);
    }

    // Enrich with forensic signals.
    let doc_path_string = doc_file.to_string_lossy().to_string();
    let stored_events = crate::ffi::helpers::open_store()
        .and_then(|s| {
            s.get_events_for_file(&doc_path_string)
                .map_err(|e| format!("{e}"))
        })
        .unwrap_or_default();
    if !stored_events.is_empty() {
        let (metrics, _) = crate::ffi::helpers::run_full_forensics(&stored_events);
        builder = enrich_c2pa_builder(builder, &metrics);
    }

    // Build signed VC (both embedded in C2PA manifest and as standalone JSON).
    let vc_json = if let Ok((ear, author_did)) = crate::ffi::vc_export::build_ear_for_path(
        &doc_path_string, &doc_path_string, &signing_key,
    ) {
        let provider = crate::tpm::detect_provider();
        if let Ok(vc) = crate::war::profiles::vc::to_signed_verifiable_credential(
            &ear, &author_did, &*provider,
        ) {
            let json = serde_json::to_string_pretty(&vc).ok();
            if let Ok(embed) = serde_json::to_string(&vc) {
                builder = builder.vc_embedded(embed);
            }
            json
        } else {
            None
        }
    } else {
        None
    };

    let jumbf = try_ffi!(
        builder.build_jumbf(&signing_key).map_err(|e| format!("Failed to build C2PA manifest: {e}")),
        FfiResult
    );

    // Read the original asset for bundling.
    let doc_bytes = try_ffi!(
        std::fs::read(&doc_file).map_err(|e| format!("Failed to read document: {e}")),
        FfiResult
    );

    // Build ZIP: asset + .c2pa sidecar + .vc.json
    let c2pa_name = format!("{doc_name}.c2pa");
    let vc_name = format!(
        "{}.vc.json",
        doc_file.file_stem().and_then(|s| s.to_str()).unwrap_or("document")
    );

    let zip_bytes = try_ffi!(
        build_c2pa_zip(doc_name, &doc_bytes, &c2pa_name, &jumbf, &vc_name, vc_json.as_deref()),
        FfiResult
    );

    // Atomic write.
    let parent = out_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = try_ffi!(
        tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| format!("Failed to create temp file: {e}")),
        FfiResult
    );
    try_ffi!(
        std::io::Write::write_all(&mut tmp, &zip_bytes)
            .and_then(|_| tmp.as_file().sync_all())
            .map_err(|e| format!("Failed to write ZIP: {e}")),
        FfiResult
    );
    try_ffi!(
        tmp.persist(&out_file)
            .map_err(|e| format!("Failed to persist ZIP: {e}")),
        FfiResult
    );

    // Register for stripping detection.
    if let Ok(content) = std::fs::read_to_string(&doc_file) {
        let fp = crate::sentinel::content_fingerprint::ContentFingerprint::from_text(&content);
        let manifest_hash = hex::encode(doc_hash);
        if let Ok(store) = crate::ffi::helpers::open_store() {
            if let Err(e) = store.insert_manifest_registry(
                fp.simhash as i64,
                &manifest_hash,
                &doc_path_string,
            ) {
                log::warn!("manifest_registry insert failed: {e}");
            }
        }
    }

    FfiResult::ok(format!(
        "C2PA evidence exported to {} ({} bytes, {} files)",
        out_file.display(),
        zip_bytes.len(),
        if vc_json.is_some() { 3 } else { 2 }
    ))
    })
    })
}

/// Build a ZIP archive containing the asset, C2PA sidecar manifest, and optional VC.
fn build_c2pa_zip(
    asset_name: &str,
    asset_bytes: &[u8],
    c2pa_name: &str,
    c2pa_bytes: &[u8],
    vc_name: &str,
    vc_json: Option<&str>,
) -> Result<Vec<u8>, String> {
    use std::io::{Cursor, Write};

    let buf = Vec::with_capacity(asset_bytes.len() + c2pa_bytes.len() + 4096);
    let cursor = Cursor::new(buf);
    let mut zip = zip::ZipWriter::new(cursor);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);

    zip.start_file(asset_name, options)
        .map_err(|e| format!("ZIP: failed to add asset: {e}"))?;
    zip.write_all(asset_bytes)
        .map_err(|e| format!("ZIP: failed to write asset: {e}"))?;

    zip.start_file(c2pa_name, options)
        .map_err(|e| format!("ZIP: failed to add manifest: {e}"))?;
    zip.write_all(c2pa_bytes)
        .map_err(|e| format!("ZIP: failed to write manifest: {e}"))?;

    if let Some(vc) = vc_json {
        zip.start_file(vc_name, options)
            .map_err(|e| format!("ZIP: failed to add VC: {e}"))?;
        zip.write_all(vc.as_bytes())
            .map_err(|e| format!("ZIP: failed to write VC: {e}"))?;
    }

    let cursor = zip.finish()
        .map_err(|e| format!("ZIP: failed to finalize: {e}"))?;
    Ok(cursor.into_inner())
}

/// Export a C2PA sidecar manifest (.c2pa) for an evidence packet.
///
/// The manifest contains a signed claim binding the PoP evidence to the
/// original document, with standard `c2pa.actions` and custom `org.pop.evidence`
/// assertions in JUMBF format per ISO 19566-5.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_c2pa_manifest(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_export_c2pa_manifest: evidence_path={}, document_path={}", evidence_path, document_path);
    let evidence_file = try_ffi!(
        crate::sentinel::helpers::validate_path(&evidence_path)
            .map_err(|e| format!("Invalid evidence path: {e}")),
        FfiResult
    );
    let doc_file = try_ffi!(
        crate::sentinel::helpers::validate_path(&document_path)
            .map_err(|e| format!("Invalid document path: {e}")),
        FfiResult
    );
    let out_file = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    if !evidence_file.exists() {
        return FfiResult::err(format!(
            "Evidence file not found: {}",
            evidence_file.display()
        ));
    }
    const MAX_EVIDENCE_FILE_SIZE: u64 = 100_000_000;
    match std::fs::metadata(&evidence_file) {
        Ok(m) if m.len() > MAX_EVIDENCE_FILE_SIZE => {
            return FfiResult::err(format!(
                "Evidence file too large: {} bytes (max {})",
                m.len(),
                MAX_EVIDENCE_FILE_SIZE
            ));
        }
        Err(e) => {
            return FfiResult::err(format!("Cannot stat evidence file: {e}"));
        }
        _ => {}
    }
    if !doc_file.exists() {
        return FfiResult::err(format!("Document not found: {}", doc_file.display()));
    }

    let evidence_bytes = match std::fs::read(&evidence_file) {
        Ok(b) => b,
        Err(e) => {
            return FfiResult::err(format!("Failed to read evidence: {e}"));
        }
    };

    let evidence_packet = match decode_evidence_for_c2pa(&evidence_bytes) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult::err(format!("Failed to decode evidence: {e}"));
        }
    };

    let doc_hash = match crate::crypto::hash_file(&doc_file) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult::err(format!("Failed to hash document: {e}"));
        }
    };

    let doc_filename = doc_file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    // Detect MIME type from file extension for C2PA dc:format compliance.
    // Sidecar manifests use c2pa.hash.data for all formats (no exclusion ranges needed).
    let mime_type = doc_file
        .extension()
        .and_then(|ext| ext.to_str())
        .map(detect_mime_type);

    let mut builder = authorproof_protocol::c2pa::C2paManifestBuilder::new(
        evidence_packet,
        evidence_bytes,
        doc_hash,
    );
    if let Some(ref name) = doc_filename {
        builder = builder.document_filename(name);
    }
    if let Some(ref mime) = mime_type {
        builder = builder.format(mime);
    }

    // Load the evidence signing key for COSE_Sign1. The same key that signed
    // checkpoints must sign the C2PA claim so the cert matches the signature.
    let signing_key = match crate::ffi::helpers::load_signing_key() {
        Ok(sk) => sk,
        Err(e) => {
            return FfiResult::err(format!("Failed to load signing key: {e}"));
        }
    };
    if let Ok(cert_der) = crate::ffi::helpers::load_or_generate_cert(&signing_key) {
        builder = builder.cert_der(cert_der);
    }

    // Enrich C2PA manifest with forensic signals.
    let doc_path_string = doc_file.to_string_lossy().to_string();
    let stored_events = crate::ffi::helpers::open_store()
        .and_then(|s| {
            s.get_events_for_file(&doc_path_string)
                .map_err(|e| format!("{e}"))
        })
        .unwrap_or_default();
    if !stored_events.is_empty() {
        let (metrics, _) = crate::ffi::helpers::run_full_forensics(&stored_events);
        builder = enrich_c2pa_builder(builder, &metrics);
    }

    // Build signed VC and embed in manifest.
    if let Ok((ear, author_did)) = crate::ffi::vc_export::build_ear_for_path(
        &evidence_path, &doc_path_string, &signing_key,
    ) {
        let provider = crate::tpm::detect_provider();
        if let Ok(vc) = crate::war::profiles::vc::to_signed_verifiable_credential(
            &ear, &author_did, &*provider,
        ) {
            if let Ok(vc_json) = serde_json::to_string(&vc) {
                builder = builder.vc_embedded(vc_json);
            }
        }
    }

    let jumbf = match builder.build_jumbf(&signing_key) {
        Ok(j) => j,
        Err(e) => {
            return FfiResult::err(format!("Failed to build C2PA manifest: {e}"));
        }
    };

    // Atomic write: tempfile + fsync + rename
    let parent = out_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    match tempfile::NamedTempFile::new_in(parent) {
        Ok(mut tmp) => {
            use std::io::Write;
            if let Err(e) = tmp.write_all(&jumbf).and_then(|_| tmp.as_file().sync_all()) {
                return FfiResult::err(format!("Failed to write C2PA manifest: {e}"));
            }
            match tmp.persist(&out_file) {
                Ok(_) => {
                    // Register this manifest for stripping detection.
                    // Read document content to compute SimHash; non-fatal on failure.
                    if let Ok(content) = std::fs::read_to_string(&doc_file) {
                        let fp = crate::sentinel::content_fingerprint::ContentFingerprint::from_text(&content);
                        let manifest_hash = hex::encode(doc_hash);
                        let doc_path_str = doc_file.to_string_lossy().to_string();
                        if let Ok(store) = crate::ffi::helpers::open_store() {
                            if let Err(e) = store.insert_manifest_registry(
                                fp.simhash as i64,
                                &manifest_hash,
                                &doc_path_str,
                            ) {
                                log::warn!("manifest_registry insert failed: {e}");
                            }
                        }
                    }
                    FfiResult::ok(format!(
                        "C2PA manifest exported to {} ({} bytes)",
                        out_file.display(),
                        jumbf.len()
                    ))
                }
                Err(e) => FfiResult::err(format!("Failed to persist C2PA manifest: {e}")),
            }
        }
        Err(e) => FfiResult::err(format!("Failed to create temp file for C2PA manifest: {e}")),
    }
    })
}

/// Detect MIME type from file extension per IANA media type registry.
/// Returns the standard dc:format value for C2PA manifests.
fn detect_mime_type(ext: &str) -> String {
    match ext.to_ascii_lowercase().as_str() {
        // Images
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "tiff" | "tif" => "image/tiff",
        "dng" => "image/tiff",
        "heif" | "heic" => "image/heif",
        "avif" => "image/avif",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "jxl" => "image/jxl",
        // Video
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "webm" => "video/webm",
        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" | "m4a" => "audio/mp4",
        "ogg" | "oga" => "audio/ogg",
        // Documents
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "html" | "htm" => "text/html",
        // Fonts
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        // Archives
        "epub" => "application/epub+zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        // Default
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Decode evidence bytes into the protocol-level EvidencePacket for C2PA.
///
/// Returns an error if any hash field fails to decode; never silently
/// substitutes zero-filled hashes, which would produce a corrupt manifest.
pub(crate) fn decode_evidence_for_c2pa(
    data: &[u8],
) -> std::result::Result<authorproof_protocol::rfc::EvidencePacket, String> {
    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(data);
    let packet = crate::evidence::Packet::decode(&cbor_payload)
        .map_err(|e| format!("Evidence decode failed: {e}"))?;

    let mut checkpoints = Vec::with_capacity(packet.checkpoints.len());
    for (i, cp) in packet.checkpoints.iter().enumerate() {
        let ctx = |field: &str, e: &hex::FromHexError| {
            format!("checkpoint[{i}].{field}: invalid hex: {e}")
        };

        let hash_bytes = hex::decode(&cp.hash).map_err(|e| ctx("hash", &e))?;
        let checkpoint_id: Vec<u8> = hash_bytes.iter().copied().take(16).collect();

        checkpoints.push(authorproof_protocol::rfc::Checkpoint {
            sequence: cp.ordinal,
            checkpoint_id,
            timestamp: cp.timestamp.timestamp_millis().max(0) as u64,
            content_hash: authorproof_protocol::rfc::HashValue {
                algorithm: authorproof_protocol::rfc::HashAlgorithm::Sha256,
                digest: hex::decode(&cp.content_hash).map_err(|e| ctx("content_hash", &e))?,
            },
            char_count: cp.content_size,
            prev_hash: authorproof_protocol::rfc::HashValue {
                algorithm: authorproof_protocol::rfc::HashAlgorithm::Sha256,
                digest: hex::decode(&cp.previous_hash).map_err(|e| ctx("previous_hash", &e))?,
            },
            checkpoint_hash: authorproof_protocol::rfc::HashValue {
                algorithm: authorproof_protocol::rfc::HashAlgorithm::Sha256,
                digest: hash_bytes,
            },
            jitter_hash: None,
        });
    }

    let doc = &packet.document;
    let doc_hash = hex::decode(&doc.final_hash)
        .map_err(|e| format!("document.final_hash: invalid hex: {e}"))?;

    let packet_id = {
        use sha2::{Digest, Sha256};
        let full_hash = Sha256::digest(data);
        full_hash[..16].to_vec()
    };

    Ok(authorproof_protocol::rfc::EvidencePacket {
        version: 1,
        profile_uri: crate::war::ear::CPOE_EVIDENCE_PROFILE.to_string(),
        packet_id,
        created: packet.exported_at.timestamp_millis().max(0) as u64,
        document: authorproof_protocol::rfc::DocumentRef {
            content_hash: authorproof_protocol::rfc::HashValue {
                algorithm: authorproof_protocol::rfc::HashAlgorithm::Sha256,
                digest: doc_hash,
            },
            filename: Some(doc.title.clone()),
            byte_length: doc.final_size,
            char_count: std::fs::metadata(&doc.path)
                .ok()
                .filter(|m| m.len() <= 50_000_000) // cap at 50MB to avoid OOM
                .and_then(|_| std::fs::read(&doc.path).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|s| s.chars().count() as u64)
                .unwrap_or(doc.final_size),
        },
        checkpoints,
        attestation_tier: None,
        baseline_verification: None,
    })
}

/// Enrich a C2PA manifest builder with forensic signal scores from computed metrics.
///
/// Shared by FFI and CLI export paths to avoid duplication.
pub fn enrich_c2pa_builder(
    builder: authorproof_protocol::c2pa::C2paManifestBuilder,
    metrics: &crate::forensics::ForensicMetrics,
) -> authorproof_protocol::c2pa::C2paManifestBuilder {
    use authorproof_protocol::c2pa::*;

    let signals = ForensicSignalScores {
        cognitive_load: metrics.cognitive_load.as_ref().map(|c| c.composite_score).unwrap_or(0.0),
        revision_topology: metrics.revision_topology.as_ref().map(|r| r.composite_score).unwrap_or(0.0),
        error_ecology: metrics.error_ecology.as_ref().map(|e| e.composite_score).unwrap_or(0.0),
        likelihood_model: metrics.likelihood_model.as_ref().map(|l| l.session_p_cognitive).unwrap_or(0.0),
        composition_mode: metrics.composition_mode.as_ref().map(|c| c.composite_score).unwrap_or(0.0),
    };
    let writing_mode = metrics.writing_mode.as_ref().map(|wm| wm.mode.to_string());
    let comp_mode = metrics.composition_mode.as_ref().and_then(|c| c.dominant_mode).map(|m| m.to_string());

    let mut builder = builder.forensic_signals(signals, comp_mode, writing_mode);

    // Keystroke cadence assertion.
    let cadence = &metrics.cadence;
    let cadence_assertion = KeystrokeCadenceAssertion {
        version: 1,
        keystroke_count: cadence.burst_count as u64 * cadence.avg_burst_length.max(1.0) as u64
            + cadence.pause_count as u64,
        session_duration_sec: metrics.session_stats.total_editing_time_sec,
        timing: CadenceTiming {
            mean_iki_ms: cadence.mean_iki_ns / 1_000_000.0,
            median_iki_ms: cadence.median_iki_ns / 1_000_000.0,
            coefficient_of_variation: cadence.coefficient_of_variation,
            iki_percentiles: [
                cadence.percentiles[0] / 1_000_000.0,
                cadence.percentiles[1] / 1_000_000.0,
                cadence.percentiles[2] / 1_000_000.0,
                cadence.percentiles[3] / 1_000_000.0,
                cadence.percentiles[4] / 1_000_000.0,
            ],
            burst_count: cadence.burst_count as u64,
            avg_burst_length: cadence.avg_burst_length,
            pause_count: cadence.pause_count as u64,
            avg_pause_duration_ms: cadence.avg_pause_duration_ns / 1_000_000.0,
            pause_depth_distribution: cadence.pause_depth_distribution,
        },
        dwell: CadenceDwell {
            mean_dwell_ms: cadence.mean_dwell_ns / 1_000_000.0,
            dwell_cv: cadence.dwell_cv,
            mean_flight_ms: cadence.mean_flight_ns / 1_000_000.0,
            flight_cv: cadence.flight_cv,
        },
        corrections: CadenceCorrections {
            correction_ratio: cadence.correction_ratio.get(),
            cross_hand_timing_ratio: cadence.cross_hand_timing_ratio,
            post_pause_cv: cadence.post_pause_cv,
            iki_autocorrelation: cadence.iki_autocorrelation,
        },
        fatigue: cadence.fatigue_phase.map(|phase| CadenceFatigue {
            phase,
            trajectory_residual: cadence.fatigue_trajectory_residual.unwrap_or(0.0),
        }),
        spectral: metrics.spectral_analysis.as_ref().map(|s| CadenceSpectral {
            slope: s.spectral_slope,
            noise_type: format!("{:?}", s.noise_type).to_lowercase(),
        }),
        hurst_exponent: metrics.hurst_exponent,
        biological_cadence_score: Some(metrics.biological_cadence_score.get()),
    };
    builder = builder.keystroke_cadence(cadence_assertion);

    // Cognitive markers assertion.
    let mut markers = CognitiveMarkersAssertion {
        version: 1,
        cognitive_load: None,
        revision_topology: None,
        error_ecology: None,
        likelihood_model: None,
        focus: None,
        edit_metrics: None,
    };

    if let Some(ref cl) = metrics.cognitive_load {
        markers.cognitive_load = Some(CognitiveLoadSignals {
            iki_surprisal_rho: cl.iki_surprisal_rho,
            sentence_arc_r_squared: cl.sentence_arc_r_squared,
            structural_pause_concentration: cl.structural_pause_concentration,
            composite_score: cl.composite_score,
            deep_pause_count: cl.deep_pause_count as u64,
            boundary_count: cl.boundary_count as u64,
            word_count: cl.word_count as u64,
        });
    }

    if let Some(ref rt) = metrics.revision_topology {
        markers.revision_topology = Some(RevisionTopologySignals {
            mean_branching_factor: rt.graph.mean_branching_factor,
            mean_revisit_depth: rt.graph.mean_revisit_depth,
            mean_frontier_distance: rt.graph.mean_frontier_distance,
            active_region_count: rt.graph.active_region_count as u64,
            detour_ratio: rt.detour_ratio,
            leading_edge_divergence: rt.leading_edge_divergence,
            insertion_point_entropy: rt.insertion_point_entropy,
            revision_types: RevisionTypeBreakdown {
                sub_word_motor_pct: rt.revision_types.sub_word_motor_pct,
                word_substitution_pct: rt.revision_types.word_substitution_pct,
                clause_restructuring_pct: rt.revision_types.clause_restructuring_pct,
                positional_insertion_pct: rt.revision_types.positional_insertion_pct,
                total_revisions: rt.revision_types.total_revisions as u64,
            },
            composite_score: rt.composite_score,
        });
    }

    if let Some(ref ee) = metrics.error_ecology {
        markers.error_ecology = Some(ErrorEcologySignals {
            rapid_self_correction_pct: ee.rapid_self_correction_pct,
            immediate_small_correction_pct: ee.immediate_small_correction_pct,
            delayed_correction_pct: ee.delayed_correction_pct,
            bulk_correction_pct: ee.bulk_correction_pct,
            false_start_pct: ee.false_start_pct,
            total_corrections: ee.total_corrections as u64,
            correction_rate: ee.correction_rate,
            jsd_from_cognitive: ee.jsd_from_cognitive,
            jsd_from_transcriptive: ee.jsd_from_transcriptive,
            composite_score: ee.composite_score,
        });
    }

    if let Some(ref lm) = metrics.likelihood_model {
        markers.likelihood_model = Some(LikelihoodModelSignals {
            session_llr: lm.session_llr,
            session_p_cognitive: lm.session_p_cognitive,
            window_count: lm.window_count as u64,
            cognitive_window_count: lm.cognitive_window_count as u64,
            transcriptive_window_count: lm.transcriptive_window_count as u64,
            mean_window_llr: lm.mean_window_llr,
            llr_std_dev: lm.llr_std_dev,
            composite_score: lm.composite_score,
        });
    }

    let focus = &metrics.focus;
    markers.focus = Some(FocusSignals {
        switch_count: focus.switch_count as u64,
        out_of_focus_ratio: focus.out_of_focus_ratio.get(),
        ai_app_switch_count: focus.ai_app_switch_count as u64,
        mid_typing_switch_ratio: focus.mid_typing_switch_ratio,
    });

    let primary = &metrics.primary;
    markers.edit_metrics = Some(EditMetricSignals {
        monotonic_append_ratio: primary.monotonic_append_ratio.get(),
        edit_entropy: primary.edit_entropy,
        timing_entropy: primary.timing_entropy,
        pause_entropy: primary.pause_entropy,
        positive_negative_ratio: primary.positive_negative_ratio.get(),
        deletion_clustering: primary.deletion_clustering,
    });

    builder = builder.cognitive_markers(markers);

    // Add AI disclosure if AI-mediated composition detected.
    if let Some(ref cm) = metrics.composition_mode {
        if cm.ai_cycle_count > 0 || cm.distribution.ai_mediated > 0.1 {
            let oversight = if cm.distribution.ai_mediated > 0.5 {
                "prompt_guided"
            } else {
                "human_validated"
            };
            builder = builder.ai_disclosure(AiDisclosureAssertion {
                model_type: "language_model".to_string(),
                model_name: None,
                content_profile: Some(AiContentProfile {
                    human_oversight_level: oversight.to_string(),
                }),
            });
        }
    }

    builder
}

/// Result of a C2PA manifest stripping check.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiStrippingResult {
    /// One of: "no_manifest_expected", "manifest_present", "manifest_stripped".
    pub status: String,
    /// SHA-256 hex of the document hash at export time, when a manifest was registered.
    pub original_manifest_hash: Option<String>,
    /// Document path stored at export time, when a manifest was registered.
    pub document_path: Option<String>,
}

/// Check whether a C2PA manifest that was previously exported for a document
/// has been stripped from the sidecar location.
///
/// 1. Reads the document at `document_path` and computes its SimHash.
/// 2. Queries `manifest_registry` for a previously registered manifest within
///    the similarity threshold (Hamming distance ≤ 11 bits).
/// 3. If no registration found → "no_manifest_expected".
/// 4. If a registration found → checks for a `.c2pa` sidecar next to the document.
///    - Sidecar present → "manifest_present".
///    - Sidecar absent  → "manifest_stripped".
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_check_manifest_stripping(document_path: String) -> FfiStrippingResult {
    let no_manifest = FfiStrippingResult {
        status: "no_manifest_expected".to_string(),
        original_manifest_hash: None,
        document_path: None,
    };

    let doc_file = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("ffi_check_manifest_stripping: invalid path: {e}");
            return no_manifest;
        }
    };

    if !doc_file.is_file() {
        return no_manifest;
    }

    // Bound read to 50 MB to avoid OOM on accidentally large files.
    const MAX_READ: u64 = 50_000_000;
    let meta = match std::fs::metadata(&doc_file) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("ffi_check_manifest_stripping: stat failed: {e}");
            return no_manifest;
        }
    };
    if meta.len() > MAX_READ {
        log::warn!("ffi_check_manifest_stripping: file too large to SimHash");
        return no_manifest;
    }

    let content = match std::fs::read_to_string(&doc_file) {
        Ok(c) => c,
        Err(_) => return no_manifest,
    };

    let fp = crate::sentinel::content_fingerprint::ContentFingerprint::from_text(&content);

    let store = match crate::ffi::helpers::open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_check_manifest_stripping: store open failed: {e}");
            return no_manifest;
        }
    };

    // Hamming distance threshold: mirrors ContentFingerprint::SIMILARITY_THRESHOLD (11).
    const SIMHASH_MAX_DISTANCE: u32 = 11;
    let row = match store.lookup_manifest_by_simhash(fp.simhash as i64, SIMHASH_MAX_DISTANCE) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("ffi_check_manifest_stripping: lookup failed: {e}");
            return no_manifest;
        }
    };

    let (manifest_hash, reg_doc_path) = match row {
        Some(r) => r,
        None => return no_manifest,
    };

    // Check for a .c2pa sidecar alongside the document.
    let sidecar = doc_file.with_extension("c2pa");
    let status = if sidecar.is_file() {
        "manifest_present"
    } else {
        "manifest_stripped"
    };

    FfiStrippingResult {
        status: status.to_string(),
        original_manifest_hash: Some(manifest_hash),
        document_path: Some(reg_doc_path),
    }
}
