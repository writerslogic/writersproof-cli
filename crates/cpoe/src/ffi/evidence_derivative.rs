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
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
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
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
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

    let provider = crate::tpm::detect_provider();
    let signer = crate::tpm::TpmSigner::new(provider);

    let jumbf = match builder.build_jumbf(&signer) {
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
                Ok(_) => FfiResult::ok(format!(
                    "C2PA manifest exported to {} ({} bytes)",
                    out_file.display(),
                    jumbf.len()
                )),
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
fn decode_evidence_for_c2pa(
    data: &[u8],
) -> std::result::Result<authorproof_protocol::rfc::EvidencePacket, String> {
    let packet = crate::evidence::Packet::decode(data)
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
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
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
